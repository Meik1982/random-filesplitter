//! Streaming Split & Restore Engine with Zero-Allocation Double/Triple Buffering,
//! In-Flight BLKS-384 / SHA-256 Hashing and Plausible Deniability Footers.

use crate::crypto::{xor_buffers, ChaChaRng};
use crate::entropy::UniversalEntropyHarvester;
use crate::format::{decode_footer, encode_rfs3_footer, RfsMetadata};
use crate::types::RFS3_FOOTER_SIZE;
use blks_core::{BlksHasher, Digest as BlksDigest};
use crossbeam_channel::{bounded, Receiver, Sender};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use zeroize::Zeroize;

/// Nachricht für den asynchronen I/O-Schreiber
struct WriteJob {
    buf1: Vec<u8>,
    buf2: Vec<u8>,
    valid_len: usize,
}

/// Führt das kryptografische Splitten einer Datei in 2 Teile (RFS3-Format mit BLKS-384) durch.
pub fn split_file(
    input_path: &Path,
    output_prefix: Option<&str>,
    block_size: usize,
    silent: bool,
) -> Result<(PathBuf, PathBuf), String> {
    let mut in_file =
        File::open(input_path).map_err(|e| format!("Kann Eingabedatei nicht öffnen: {}", e))?;
    let file_size = in_file
        .metadata()
        .map_err(|e| format!("Kann Dateimetadaten nicht lesen: {}", e))?
        .len();

    let base_name = output_prefix.unwrap_or_else(|| input_path.to_str().unwrap_or("output"));
    let out1_path = PathBuf::from(format!("{}.rfs1", base_name));
    let out2_path = PathBuf::from(format!("{}.rfs2", base_name));

    let f1 = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out1_path)
        .map_err(|e| format!("Kann Ausgabedatei 1 nicht erstellen: {}", e))?;
    let f2 = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out2_path)
        .map_err(|e| format!("Kann Ausgabedatei 2 nicht erstellen: {}", e))?;

    // 1. Initialisiere Entropie & ChaCha20 CSPRNG
    let (master_key, master_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&master_key, &master_nonce);

    // 2. Initialisiere den High-Speed Streaming BLKS-384 Hasher (6,3 GB/s)
    let mut blks_hasher = BlksHasher::new();

    // 3. Puffer-Allokation für Zero-Copy Triple-Buffering
    // Wir nutzen gepoolte Puffer über Kanäle, um Heap-Allokationen in der Schleife komplett zu eliminieren.
    let (job_tx, job_rx): (Sender<WriteJob>, Receiver<WriteJob>) = bounded(2);
    let (free_tx, free_rx): (Sender<(Vec<u8>, Vec<u8>)>, Receiver<(Vec<u8>, Vec<u8>)>) = bounded(2);

    // Initialisiere den Puffer-Pool (2 Slot-Paare)
    free_tx
        .send((vec![0u8; block_size], vec![0u8; block_size]))
        .unwrap();
    free_tx
        .send((vec![0u8; block_size], vec![0u8; block_size]))
        .unwrap();

    // 4. Starte den dedizierten Hintergrund-Schreib-Thread
    let mut writer_f1 = BufWriter::with_capacity(block_size, f1);
    let mut writer_f2 = BufWriter::with_capacity(block_size, f2);

    let writer_handle = thread::spawn(move || -> Result<(), String> {
        while let Ok(job) = job_rx.recv() {
            let WriteJob {
                buf1,
                buf2,
                valid_len,
            } = job;
            writer_f1
                .write_all(&buf1[..valid_len])
                .map_err(|e| format!("Schreibfehler auf Teil 1: {}", e))?;
            writer_f2
                .write_all(&buf2[..valid_len])
                .map_err(|e| format!("Schreibfehler auf Teil 2: {}", e))?;

            // Puffer zurück in den Pool geben
            let _ = free_tx.send((buf1, buf2));
        }
        writer_f1
            .flush()
            .map_err(|e| format!("Flush-Fehler auf Teil 1: {}", e))?;
        writer_f2
            .flush()
            .map_err(|e| format!("Flush-Fehler auf Teil 2: {}", e))?;
        Ok(())
    });

    // 5. Haupt-Transformations-Schleife (Streaming)
    let mut in_buf = vec![0u8; block_size];
    let mut total_processed: u64 = 0;

    loop {
        let n = in_file
            .read(&mut in_buf)
            .map_err(|e| format!("Lesefehler auf Eingabedatei: {}", e))?;
        if n == 0 {
            break;
        }

        // Hashe die Originaldaten direkt im CPU-Cache (Cache-Hot)
        blks_hasher.update(&in_buf[..n]);

        // Hole freie Puffer aus dem Pool (blockiert nur, falls Disk hinterherhinkt)
        let (mut part1_buf, mut part2_buf) = free_rx
            .recv()
            .map_err(|_| "Worker-Thread vorzeitig beendet".to_string())?;

        // Part 2 mit ChaCha20 füllen
        rng.fill_bytes(&mut part2_buf[..n]);

        // Part 1 = Original XOR Part 2 (SIMD-beschleunigt)
        xor_buffers(&mut part1_buf[..n], &in_buf[..n], &part2_buf[..n]);

        total_processed += n as u64;

        // Übergib Job an Writer-Thread
        job_tx
            .send(WriteJob {
                buf1: part1_buf,
                buf2: part2_buf,
                valid_len: n,
            })
            .map_err(|_| "Worker-Thread vorzeitig beendet".to_string())?;

        if !silent && file_size > 0 {
            let pct = (total_processed as f64 / file_size as f64) * 100.0;
            print!(
                "\r[RFS3 Split] Fortschritt: {:5.1}% ({}/{} Bytes)",
                pct, total_processed, file_size
            );
            let _ = std::io::stdout().flush();
        }
    }

    if !silent && file_size > 0 {
        println!();
    }

    // Signalisiere Ende der Nutzdaten an Writer
    drop(job_tx);
    writer_handle
        .join()
        .map_err(|_| "Writer-Thread abgestürzt".to_string())??;

    // 6. BLKS-384 Hash finalisieren & ge-XORten 60-Byte RFS3-Footer schreiben
    let digest = blks_hasher.finalize();
    let (footer1, footer2) = encode_rfs3_footer(&digest, file_size, &mut rng);

    // Footer an beide Dateien anhängen
    let mut append_f1 = OpenOptions::new()
        .append(true)
        .open(&out1_path)
        .map_err(|e| format!("Kann Teil 1 für Footer nicht öffnen: {}", e))?;
    let mut append_f2 = OpenOptions::new()
        .append(true)
        .open(&out2_path)
        .map_err(|e| format!("Kann Teil 2 für Footer nicht öffnen: {}", e))?;

    append_f1
        .write_all(&footer1)
        .map_err(|e| format!("Fehler beim Schreiben des Footers 1: {}", e))?;
    append_f2
        .write_all(&footer2)
        .map_err(|e| format!("Fehler beim Schreiben des Footers 2: {}", e))?;

    append_f1.flush().map_err(|e| format!("Flush 1: {}", e))?;
    append_f2.flush().map_err(|e| format!("Flush 2: {}", e))?;

    // Sichere Speicherhygiene
    in_buf.zeroize();

    if !silent {
        println!(
            "Erfolgreich gesplittet:\n  Teil 1: {}\n  Teil 2: {}\n  Originalgröße: {} Bytes\n  BLKS-384: {}",
            out1_path.display(),
            out2_path.display(),
            file_size,
            BlksDigest(digest).to_base64()
        );
    }

    Ok((out1_path, out2_path))
}

/// Rekonstruiert eine Originaldatei aus zwei Split-Teilen.
/// Erkennt automatisch RFS3 (BLKS-384) und RFS2 (SHA-256) und verifiziert die Integrität.
pub fn restore_file(
    part1_path: &Path,
    part2_path: &Path,
    output_path: Option<&str>,
    force: bool,
    silent: bool,
    verify_only: bool,
) -> Result<PathBuf, String> {
    let mut f1 = File::open(part1_path).map_err(|e| format!("Kann Teil 1 nicht öffnen: {}", e))?;
    let mut f2 = File::open(part2_path).map_err(|e| format!("Kann Teil 2 nicht öffnen: {}", e))?;

    let len1 = f1.metadata().map_err(|e| e.to_string())?.len();
    let len2 = f2.metadata().map_err(|e| e.to_string())?.len();

    if len1 != len2 {
        return Err(
            "Dateigrößen stimmen nicht überein (Teile beschädigt oder unvollständig).".to_string(),
        );
    }

    if len1 < RFS3_FOOTER_SIZE as u64 {
        return Err("Dateigröße kleiner als RFS-Footer.".to_string());
    }

    // 1. Footer lesen (letzte 60 Bytes)
    let tail_len = RFS3_FOOTER_SIZE;
    f1.seek(SeekFrom::End(-(tail_len as i64)))
        .map_err(|e| format!("Seek 1: {}", e))?;
    f2.seek(SeekFrom::End(-(tail_len as i64)))
        .map_err(|e| format!("Seek 2: {}", e))?;

    let mut tail1 = vec![0u8; tail_len];
    let mut tail2 = vec![0u8; tail_len];
    f1.read_exact(&mut tail1)
        .map_err(|e| format!("Read tail 1: {}", e))?;
    f2.read_exact(&mut tail2)
        .map_err(|e| format!("Read tail 2: {}", e))?;

    // Auto-Detecting Decode
    let meta = decode_footer(&tail1, &tail2)?;
    let footer_size = meta.footer_size();
    let original_size = meta.original_size();

    let data_len = len1
        .checked_sub(footer_size as u64)
        .ok_or_else(|| "Ungültige Dateilänge".to_string())?;

    if original_size > data_len {
        return Err("Rekonstruierte Dateigröße unplausibel. Dateien sind beschädigt.".to_string());
    }

    // Bestimme Zieldateipfad
    let target_out_path = if let Some(p) = output_path {
        PathBuf::from(p)
    } else {
        let p_str = part1_path.to_str().unwrap_or("restored.bin");
        if let Some(stripped) = p_str.strip_suffix(".rfs1") {
            PathBuf::from(stripped)
        } else if let Some(stripped) = p_str.strip_suffix(".part1.rfs") {
            PathBuf::from(stripped)
        } else {
            PathBuf::from(format!("{}.restored", p_str))
        }
    };

    if !verify_only && target_out_path.exists() && !force {
        return Err(format!(
            "Zieldatei '{}' existiert bereits. Verwenden Sie --force zum Überschreiben.",
            target_out_path.display()
        ));
    }

    // 2. Zurück an den Datenanfang springen
    f1.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek 0 (1): {}", e))?;
    f2.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek 0 (2): {}", e))?;

    let mut out_writer = if !verify_only {
        Some(BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&target_out_path)
                .map_err(|e| format!("Kann Zieldatei nicht erstellen: {}", e))?,
        ))
    } else {
        None
    };

    // Initialisiere Prüfsummen-Hasher je nach Format
    let mut blks_hasher = match meta {
        RfsMetadata::Rfs3 { .. } => Some(BlksHasher::new()),
        _ => None,
    };
    let mut sha256_hasher = match meta {
        RfsMetadata::Rfs2 { .. } => Some(Sha256::new()),
        _ => None,
    };

    // 3. Streaming Rekonstruktion
    const CHUNK_SIZE: usize = 4 * 1024 * 1024;
    let mut b1 = vec![0u8; CHUNK_SIZE];
    let mut b2 = vec![0u8; CHUNK_SIZE];
    let mut b_out = vec![0u8; CHUNK_SIZE];

    let mut remaining = original_size;
    let mut total_processed: u64 = 0;

    let mut r1 = BufReader::new(f1);
    let mut r2 = BufReader::new(f2);

    while remaining > 0 {
        let to_read = (CHUNK_SIZE as u64).min(remaining) as usize;
        r1.read_exact(&mut b1[..to_read])
            .map_err(|e| format!("Lesefehler Teil 1: {}", e))?;
        r2.read_exact(&mut b2[..to_read])
            .map_err(|e| format!("Lesefehler Teil 2: {}", e))?;

        // Rekonstruktion via SIMD-XOR
        xor_buffers(&mut b_out[..to_read], &b1[..to_read], &b2[..to_read]);

        // Hashen im selben Durchlauf
        if let Some(ref mut h) = blks_hasher {
            h.update(&b_out[..to_read]);
        }
        if let Some(ref mut h) = sha256_hasher {
            h.update(&b_out[..to_read]);
        }

        // Schreiben
        if let Some(ref mut w) = out_writer {
            w.write_all(&b_out[..to_read])
                .map_err(|e| format!("Schreibfehler auf Zieldatei: {}", e))?;
        }

        remaining -= to_read as u64;
        total_processed += to_read as u64;

        if !silent {
            let pct = (total_processed as f64 / original_size as f64) * 100.0;
            print!(
                "\r[RFS Restore] Fortschritt: {:5.1}% ({}/{} Bytes)",
                pct, total_processed, original_size
            );
            let _ = std::io::stdout().flush();
        }
    }

    if !silent {
        println!();
    }

    if let Some(ref mut w) = out_writer {
        w.flush().map_err(|e| format!("Flush Zieldatei: {}", e))?;
    }

    // 4. Integritätsprüfung
    let integrity_ok = match meta {
        RfsMetadata::Rfs3 { expected_blks, .. } => {
            let actual_bytes = blks_hasher.unwrap().finalize();
            let actual = BlksDigest(actual_bytes);
            let expected_digest = BlksDigest(expected_blks);
            if actual.ct_eq(&expected_digest) {
                if !silent {
                    println!("Integritätsprüfung [OK] (BLKS-384: {})", actual.to_base64());
                }
                true
            } else {
                eprintln!("\nWARNUNG: Integritätsfehler! BLKS-384 Prüfsumme stimmt nicht überein.");
                eprintln!("  Erwartet:  {}", expected_digest.to_base64());
                eprintln!("  Berechnet: {}", actual.to_base64());
                false
            }
        }
        RfsMetadata::Rfs2 {
            expected_sha256, ..
        } => {
            let actual = sha256_hasher.unwrap().finalize();
            if actual.as_slice() == expected_sha256 {
                if !silent {
                    println!("Integritätsprüfung [OK] (Legacy RFS2 SHA-256 verifiziert)");
                }
                true
            } else {
                eprintln!("\nWARNUNG: Integritätsfehler! SHA-256 Prüfsumme stimmt nicht überein.");
                false
            }
        }
    };

    if !integrity_ok {
        if !verify_only && target_out_path.exists() {
            let _ = std::fs::remove_file(&target_out_path);
        }
        return Err(
            "Integritätsfehler! Die Datei ist möglicherweise beschädigt oder manipuliert."
                .to_string(),
        );
    }

    Ok(target_out_path)
}
