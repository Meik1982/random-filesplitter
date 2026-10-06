//! Streaming Split & Restore Engine with Zero-Allocation Triple-Buffering,
//! In-Flight BLKS-384 / SHA-256 Hashing, Unix Pipe Support, and Plausible Deniability Footers.

#![allow(clippy::type_complexity)]

use crate::crypto::{xor_buffers, ChaChaRng};
use crate::entropy::UniversalEntropyHarvester;
use crate::format::{decode_footer, encode_rfs3_footer, RfsMetadata};
use crate::types::{BLKS_DIGEST_SIZE, RFS3_FOOTER_SIZE};
use blks_core::{BlksHasher, Digest as BlksDigest};
use crossbeam_channel::{bounded, Receiver, Sender};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

/// Puffer-Poolgröße für Triple-Buffering (3 Puffer-Slots in-flight)
const BUFFER_POOL_SIZE: usize = 3;

/// Job für den asynchronen I/O-Schreiber im Split-Modus
struct WriteJob {
    buf1: Vec<u8>,
    buf2: Vec<u8>,
    valid_len: usize,
}

/// Hilfsfunktion zur Ausgabe des Split-Fortschritts auf stderr (stört keine stdout-Pipes).
fn print_split_progress(processed: u64, total: Option<u64>, elapsed_secs: f64) {
    let speed_mb = if elapsed_secs > 0.001 {
        (processed as f64 / 1_048_576.0) / elapsed_secs
    } else {
        0.0
    };
    match total {
        Some(tot) if tot > 0 => {
            let pct = (processed as f64 / tot as f64) * 100.0;
            eprint!(
                "\r[RFS3 Split] {:5.1}% ({}/{} Bytes, {:.1} MB/s)",
                pct, processed, tot, speed_mb
            );
        }
        _ => {
            let processed_mb = processed as f64 / 1_048_576.0;
            eprint!(
                "\r[RFS3 Split Stream] {:.2} MB übertragen ({:.1} MB/s)",
                processed_mb, speed_mb
            );
        }
    }
    let _ = io::stderr().flush();
}

/// Hilfsfunktion zur Ausgabe des Restore-Fortschritts auf stderr.
fn print_restore_progress(processed: u64, total: u64, elapsed_secs: f64) {
    let speed_mb = if elapsed_secs > 0.001 {
        (processed as f64 / 1_048_576.0) / elapsed_secs
    } else {
        0.0
    };
    if total > 0 {
        let pct = (processed as f64 / total as f64) * 100.0;
        eprint!(
            "\r[RFS Restore] {:5.1}% ({}/{} Bytes, {:.1} MB/s)",
            pct, processed, total, speed_mb
        );
    } else {
        let processed_mb = processed as f64 / 1_048_576.0;
        eprint!(
            "\r[RFS Restore Stream] {:.2} MB ({:.1} MB/s)",
            processed_mb, speed_mb
        );
    }
    let _ = io::stderr().flush();
}

/// Führt das kryptografische Splitten einer Datei oder eines Unix-Stdin-Streams durch.
///
/// Unterstützt:
/// - Reguläre Dateien (`input_source` != `"-"`)
/// - Unix Stdin Pipes (`input_source` == `"-"`)
/// - Explizite Ausgabepfade oder automatische Präfix-Generierung
/// - Entkoppelte 3-Stufen Pipeline (Reader ➔ Crypto/SIMD ➔ Writer) mit Zero-Copy Puffer-Pooling
pub fn split_stream_or_file(
    input_source: &str,
    output_parts: Option<(&Path, &Path)>,
    output_prefix: Option<&str>,
    block_size: usize,
    silent: bool,
    force: bool,
) -> Result<(PathBuf, PathBuf), String> {
    // 1. Zielpfade bestimmen
    let (out1_path, out2_path) = if let Some((p1, p2)) = output_parts {
        (p1.to_path_buf(), p2.to_path_buf())
    } else if let Some(prefix) = output_prefix {
        (
            PathBuf::from(format!("{}.rfs1", prefix)),
            PathBuf::from(format!("{}.rfs2", prefix)),
        )
    } else if input_source == "-" {
        (PathBuf::from("stdin.rfs1"), PathBuf::from("stdin.rfs2"))
    } else {
        (
            PathBuf::from(format!("{}.rfs1", input_source)),
            PathBuf::from(format!("{}.rfs2", input_source)),
        )
    };

    if !force && (out1_path.exists() || out2_path.exists()) {
        return Err(format!(
            "Eine der Ausgabedateien ('{}', '{}') existiert bereits. Nutzen Sie --force zum Überschreiben.",
            out1_path.display(),
            out2_path.display()
        ));
    }

    // 2. Eingabe vorbereiten (Stdin oder Datei)
    let is_stdin = input_source == "-";
    let (input_reader, known_size): (Box<dyn Read + Send>, Option<u64>) = if is_stdin {
        (
            Box::new(BufReader::with_capacity(block_size, io::stdin())),
            None,
        )
    } else {
        let in_path = Path::new(input_source);
        if !in_path.exists() {
            return Err(format!(
                "Eingabedatei '{}' existiert nicht.",
                in_path.display()
            ));
        }
        let f =
            File::open(in_path).map_err(|e| format!("Kann Eingabedatei nicht öffnen: {}", e))?;
        let len = f
            .metadata()
            .map_err(|e| format!("Kann Dateimetadaten nicht lesen: {}", e))?
            .len();
        (Box::new(BufReader::with_capacity(block_size, f)), Some(len))
    };

    // 3. Ausgabedateien öffnen
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

    // 4. Initialisiere Entropie & ChaCha20 CSPRNG
    let (master_key, master_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&master_key, &master_nonce);

    // 5. Kanäle für entkoppelte 3-Stufen-Pipeline & Puffer-Pools
    let (free_in_tx, free_in_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(BUFFER_POOL_SIZE);
    for _ in 0..BUFFER_POOL_SIZE {
        free_in_tx.send(vec![0u8; block_size]).unwrap();
    }

    let (data_tx, data_rx): (
        Sender<Result<(Vec<u8>, usize), String>>,
        Receiver<Result<(Vec<u8>, usize), String>>,
    ) = bounded(2);

    let (free_out_tx, free_out_rx): (Sender<(Vec<u8>, Vec<u8>)>, Receiver<(Vec<u8>, Vec<u8>)>) =
        bounded(BUFFER_POOL_SIZE);
    for _ in 0..BUFFER_POOL_SIZE {
        free_out_tx
            .send((vec![0u8; block_size], vec![0u8; block_size]))
            .unwrap();
    }

    let (job_tx, job_rx): (
        Sender<Result<WriteJob, String>>,
        Receiver<Result<WriteJob, String>>,
    ) = bounded(2);

    // Stufe 1: Reader Thread
    let reader_handle = thread::spawn(move || -> Result<(), String> {
        let mut reader = input_reader;
        while let Ok(mut buf) = free_in_rx.recv() {
            match reader.read(&mut buf) {
                Ok(0) => {
                    drop(data_tx);
                    break;
                }
                Ok(n) => {
                    if data_tx.send(Ok((buf, n))).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = data_tx.send(Err(format!("Lesefehler auf Eingabe: {}", e)));
                    break;
                }
            }
        }
        Ok(())
    });

    // Stufe 2: Crypto & Hash Worker Thread
    let worker_handle = thread::spawn(move || -> Result<(u64, [u8; BLKS_DIGEST_SIZE]), String> {
        let mut total_processed: u64 = 0;
        let mut blks_hasher = BlksHasher::new();
        let start_time = Instant::now();
        let mut last_progress = Instant::now();

        while let Ok(msg) = data_rx.recv() {
            let (in_buf, len) = msg?;

            // 1. In-flight BLKS-384 Hashing
            blks_hasher.update(&in_buf[..len]);

            // 2. Freie Ausgabepuffer anfordern
            let (mut p1, mut p2) = free_out_rx
                .recv()
                .map_err(|_| "Schreib-Thread vorzeitig beendet".to_string())?;

            // 3. ChaCha20 Keystream generieren
            rng.fill_bytes(&mut p2[..len]);

            // 4. SIMD XOR: p1 = in_buf ^ p2
            xor_buffers(&mut p1[..len], &in_buf[..len], &p2[..len]);

            // 5. Eingabepuffer zurück in den Reader-Pool (Zero-Allocation)
            let _ = free_in_tx.send(in_buf);

            total_processed += len as u64;

            // 6. Job an Writer-Thread weiterreichen
            if job_tx
                .send(Ok(WriteJob {
                    buf1: p1,
                    buf2: p2,
                    valid_len: len,
                }))
                .is_err()
            {
                return Err("Schreib-Thread vorzeitig beendet".to_string());
            }

            if !silent && last_progress.elapsed().as_millis() >= 100 {
                print_split_progress(
                    total_processed,
                    known_size,
                    start_time.elapsed().as_secs_f64(),
                );
                last_progress = Instant::now();
            }
        }

        if !silent {
            print_split_progress(
                total_processed,
                known_size,
                start_time.elapsed().as_secs_f64(),
            );
            eprintln!();
        }

        drop(job_tx);
        let digest = blks_hasher.finalize();
        Ok((total_processed, digest))
    });

    // Stufe 3: Writer Thread
    let writer_handle = thread::spawn(move || -> Result<(), String> {
        let mut w1 = BufWriter::with_capacity(block_size, f1);
        let mut w2 = BufWriter::with_capacity(block_size, f2);

        while let Ok(job_res) = job_rx.recv() {
            let WriteJob {
                buf1,
                buf2,
                valid_len,
            } = job_res?;

            w1.write_all(&buf1[..valid_len])
                .map_err(|e| format!("Schreibfehler auf Teil 1: {}", e))?;
            w2.write_all(&buf2[..valid_len])
                .map_err(|e| format!("Schreibfehler auf Teil 2: {}", e))?;

            let _ = free_out_tx.send((buf1, buf2));
        }

        w1.flush()
            .map_err(|e| format!("Flush-Fehler auf Teil 1: {}", e))?;
        w2.flush()
            .map_err(|e| format!("Flush-Fehler auf Teil 2: {}", e))?;
        Ok(())
    });

    // Warten auf Abschluss aller Threads
    let reader_res = reader_handle
        .join()
        .map_err(|_| "Reader-Thread abgestürzt".to_string())?;
    let worker_res = worker_handle
        .join()
        .map_err(|_| "Worker-Thread abgestürzt".to_string())?;
    let writer_res = writer_handle
        .join()
        .map_err(|_| "Writer-Thread abgestürzt".to_string())?;

    reader_res?;
    let (total_processed, digest) = worker_res?;
    writer_res?;

    // 6. RFS3-Stealth-Footer codieren & anhängen
    let (post_rng_key, post_rng_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut footer_rng = ChaChaRng::new(&post_rng_key, &post_rng_nonce);
    let (footer1, footer2) = encode_rfs3_footer(&digest, total_processed, &mut footer_rng);

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

    if !silent {
        eprintln!(
            "Erfolgreich gesplittet:\n  Teil 1: {}\n  Teil 2: {}\n  Originalgröße: {} Bytes\n  BLKS-384: {}",
            out1_path.display(),
            out2_path.display(),
            total_processed,
            BlksDigest(digest).to_base64()
        );
    }

    Ok((out1_path, out2_path))
}

/// Convenience-Wrapper für Abwärtskompatibilität
#[allow(dead_code)]
pub fn split_file(
    input_path: &Path,
    output_prefix: Option<&str>,
    block_size: usize,
    silent: bool,
) -> Result<(PathBuf, PathBuf), String> {
    split_stream_or_file(
        input_path.to_str().unwrap_or("-"),
        None,
        output_prefix,
        block_size,
        silent,
        false,
    )
}

/// Rekonstruiert eine Originaldatei aus zwei Split-Teilen.
///
/// Unterstützt:
/// - Schreiben auf Festplatte (`output_target` != `"-"`)
/// - Unix-Piping nach `stdout` (`output_target` == `"-"`)
/// - Fast-Verify im RAM (`verify_only` == true)
/// - Auto-Erkennung von RFS3 (BLKS-384) und RFS2 (SHA-256)
/// - Entkoppelte Triple-Buffering Streaming-Pipeline
pub fn restore_file(
    part1_path: &Path,
    part2_path: &Path,
    output_target: Option<&str>,
    force: bool,
    silent: bool,
    verify_only: bool,
    block_size: usize,
) -> Result<Option<PathBuf>, String> {
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

    // 2. Bestimme Ausgabeziel
    let is_stdout = matches!(output_target, Some("-"));

    let target_out_path = if is_stdout || verify_only {
        None
    } else if let Some(p) = output_target {
        Some(PathBuf::from(p))
    } else {
        let p_str = part1_path.to_str().unwrap_or("restored.bin");
        let deduced = if let Some(stripped) = p_str.strip_suffix(".rfs1") {
            PathBuf::from(stripped)
        } else if let Some(stripped) = p_str.strip_suffix(".part1.rfs") {
            PathBuf::from(stripped)
        } else {
            PathBuf::from(format!("{}.restored", p_str))
        };
        Some(deduced)
    };

    if let Some(ref target) = target_out_path {
        if target.exists() && !force {
            return Err(format!(
                "Zieldatei '{}' existiert bereits. Verwenden Sie --force zum Überschreiben.",
                target.display()
            ));
        }
    }

    // Zurück an Dateianfang springen
    f1.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek 0 (1): {}", e))?;
    f2.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek 0 (2): {}", e))?;

    // 3. Ausgabeschreiber initialisieren
    let out_writer: Option<Box<dyn Write + Send>> = if verify_only {
        None
    } else if is_stdout {
        Some(Box::new(BufWriter::with_capacity(block_size, io::stdout())))
    } else {
        let target = target_out_path.as_ref().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(target)
            .map_err(|e| format!("Kann Zieldatei nicht erstellen: {}", e))?;
        Some(Box::new(BufWriter::with_capacity(block_size, file)))
    };

    // 4. Entkoppelte Pipeline mit Puffer-Pools
    let (free_pair_tx, free_pair_rx): (Sender<(Vec<u8>, Vec<u8>)>, Receiver<(Vec<u8>, Vec<u8>)>) =
        bounded(BUFFER_POOL_SIZE);
    for _ in 0..BUFFER_POOL_SIZE {
        free_pair_tx
            .send((vec![0u8; block_size], vec![0u8; block_size]))
            .unwrap();
    }

    let (data_tx, data_rx): (
        Sender<Result<(Vec<u8>, Vec<u8>, usize), String>>,
        Receiver<Result<(Vec<u8>, Vec<u8>, usize), String>>,
    ) = bounded(2);

    let (free_out_tx, free_out_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
        bounded(BUFFER_POOL_SIZE);
    for _ in 0..BUFFER_POOL_SIZE {
        free_out_tx.send(vec![0u8; block_size]).unwrap();
    }

    let (job_tx, job_rx): (
        Sender<Result<(Vec<u8>, usize), String>>,
        Receiver<Result<(Vec<u8>, usize), String>>,
    ) = bounded(2);

    // Stufe 1: Dual-Reader Thread
    let reader_handle = thread::spawn(move || -> Result<(), String> {
        let mut r1 = BufReader::with_capacity(block_size, f1);
        let mut r2 = BufReader::with_capacity(block_size, f2);
        let mut remaining = original_size;

        while remaining > 0 {
            let to_read = (block_size as u64).min(remaining) as usize;
            let (mut b1, mut b2) = match free_pair_rx.recv() {
                Ok(pair) => pair,
                Err(_) => break,
            };

            if let Err(e) = r1.read_exact(&mut b1[..to_read]) {
                let _ = data_tx.send(Err(format!("Lesefehler Teil 1: {}", e)));
                return Err(format!("Lesefehler Teil 1: {}", e));
            }
            if let Err(e) = r2.read_exact(&mut b2[..to_read]) {
                let _ = data_tx.send(Err(format!("Lesefehler Teil 2: {}", e)));
                return Err(format!("Lesefehler Teil 2: {}", e));
            }

            remaining -= to_read as u64;
            if data_tx.send(Ok((b1, b2, to_read))).is_err() {
                break;
            }
        }
        drop(data_tx);
        Ok(())
    });

    // Stufe 2: Compute Worker (SIMD XOR & Hashing)
    let meta_clone = meta.clone();
    let worker_free_out_tx = free_out_tx.clone();
    let worker_handle = thread::spawn(move || -> Result<(), String> {
        let mut blks_hasher = match meta_clone {
            RfsMetadata::Rfs3 { .. } => Some(BlksHasher::new()),
            _ => None,
        };
        let mut sha256_hasher = match meta_clone {
            RfsMetadata::Rfs2 { .. } => Some(Sha256::new()),
            _ => None,
        };

        let start_time = Instant::now();
        let mut last_progress = Instant::now();
        let mut total_processed: u64 = 0;

        while let Ok(msg) = data_rx.recv() {
            let (b1, b2, len) = msg?;
            let mut b_out = free_out_rx
                .recv()
                .map_err(|_| "Writer vorzeitig beendet".to_string())?;

            // SIMD XOR: b_out = b1 ^ b2
            xor_buffers(&mut b_out[..len], &b1[..len], &b2[..len]);

            // In-flight Hashing
            if let Some(ref mut h) = blks_hasher {
                h.update(&b_out[..len]);
            }
            if let Some(ref mut h) = sha256_hasher {
                h.update(&b_out[..len]);
            }

            // Pufferpaar zurück an Reader
            let _ = free_pair_tx.send((b1, b2));

            total_processed += len as u64;

            if !verify_only {
                if job_tx.send(Ok((b_out, len))).is_err() {
                    return Err("Writer vorzeitig beendet".to_string());
                }
            } else {
                let _ = worker_free_out_tx.send(b_out);
            }

            if !silent && last_progress.elapsed().as_millis() >= 100 {
                print_restore_progress(
                    total_processed,
                    original_size,
                    start_time.elapsed().as_secs_f64(),
                );
                last_progress = Instant::now();
            }
        }

        if !silent {
            print_restore_progress(
                total_processed,
                original_size,
                start_time.elapsed().as_secs_f64(),
            );
            eprintln!();
        }

        drop(job_tx);

        // Integritätsprüfung
        let integrity_ok = match meta_clone {
            RfsMetadata::Rfs3 { expected_blks, .. } => {
                let actual_bytes = blks_hasher.unwrap().finalize();
                let actual = BlksDigest(actual_bytes);
                let expected_digest = BlksDigest(expected_blks);
                if actual.ct_eq(&expected_digest) {
                    if !silent {
                        eprintln!("Integritätsprüfung [OK] (BLKS-384: {})", actual.to_base64());
                    }
                    true
                } else {
                    eprintln!(
                        "\nWARNUNG: Integritätsfehler! BLKS-384 Prüfsumme stimmt nicht überein."
                    );
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
                        eprintln!("Integritätsprüfung [OK] (Legacy RFS2 SHA-256 verifiziert)");
                    }
                    true
                } else {
                    eprintln!(
                        "\nWARNUNG: Integritätsfehler! SHA-256 Prüfsumme stimmt nicht überein."
                    );
                    false
                }
            }
        };

        if !integrity_ok {
            return Err(
                "Integritätsfehler! Die Datei ist möglicherweise beschädigt oder manipuliert."
                    .to_string(),
            );
        }

        Ok(())
    });

    // Stufe 3: Writer Thread (nur aktiv wenn !verify_only)
    let writer_handle = thread::spawn(move || -> Result<(), String> {
        if let Some(mut writer) = out_writer {
            while let Ok(msg) = job_rx.recv() {
                let (b_out, len) = msg?;
                if let Err(e) = writer.write_all(&b_out[..len]) {
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        return Err("Ausgabepipe wurde vom Empfänger geschlossen (Broken Pipe)."
                            .to_string());
                    }
                    return Err(format!("Schreibfehler auf Ziel: {}", e));
                }
                let _ = free_out_tx.send(b_out);
            }
            writer.flush().map_err(|e| format!("Flush-Fehler: {}", e))?;
        }
        Ok(())
    });

    let reader_res = reader_handle
        .join()
        .map_err(|_| "Reader-Thread abgestürzt".to_string())?;
    let worker_res = worker_handle
        .join()
        .map_err(|_| "Worker-Thread abgestürzt".to_string())?;
    let writer_res = writer_handle
        .join()
        .map_err(|_| "Writer-Thread abgestürzt".to_string())?;

    reader_res?;
    if let Err(e) = worker_res {
        if let Some(ref target) = target_out_path {
            if target.exists() {
                let _ = std::fs::remove_file(target);
            }
        }
        return Err(e);
    }
    writer_res?;

    Ok(target_out_path)
}
