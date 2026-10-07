//! Streaming Split & Restore Engine with Zero-Allocation Triple-Buffering,
//! In-Flight BLKS-384 / SHA-256 Hashing, Unix Pipe Support, N-Way OTP Splitting,
//! and Plausible Deniability Footers.

#![allow(clippy::type_complexity)]

use crate::crypto::{xor_in_place, ChaChaRng};
use crate::entropy::UniversalEntropyHarvester;
use crate::format::{decode_footer_n_way, encode_rfs3_footer_n_way, RfsMetadata};
use crate::telemetry::{Telemetry, TelemetryMode};
use crate::types::{self, BLKS_DIGEST_SIZE, RFS3_FOOTER_SIZE};
use blks_core::{BlksHasher, Digest as BlksDigest};
use crossbeam_channel::{bounded, Receiver, Sender};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use zeroize::Zeroize;

/// Puffer-Poolgröße für Triple-Buffering (3 Puffer-Slots in-flight)
const BUFFER_POOL_SIZE: usize = 3;

/// Job für den asynchronen I/O-Schreiber im Split-Modus
struct WriteJob {
    bufs: Vec<Vec<u8>>,
    valid_len: usize,
}

/// Führt das kryptografische Splitten einer Datei oder eines Unix-Stdin-Streams in $N$ Teile durch ($N \ge 2$).
///
/// Unterstützt:
/// - Reguläre Dateien (`input_source` != `"-"`)
/// - Unix Stdin Pipes (`input_source` == `"-"`)
/// - $N$-Way One-Time-Pad Chain: $P = C_1 \oplus C_2 \oplus \dots \oplus C_N$
/// - Entkoppelte 3-Stufen Pipeline (Reader ➔ Crypto/SIMD ➔ Writer) mit Zero-Copy Puffer-Pooling
/// - Maschinenlesbare NDJSON-Telemetrie (`--json`) und interaktive ANSI-Fortschrittsbalken
#[allow(clippy::too_many_arguments)]
pub fn split_stream_or_file(
    input_source: &str,
    output_parts: Option<&[PathBuf]>,
    num_parts: usize,
    num_decoys: usize,
    output_prefix: Option<&str>,
    block_size: usize,
    telemetry_mode: TelemetryMode,
    force: bool,
    direct_io: bool,
) -> Result<Vec<PathBuf>, String> {
    // 1. Zielpfade bestimmen
    let (out_paths, n_parts) = if let Some(parts) = output_parts {
        if parts.len() < 2 || parts.len() > 64 {
            return Err(
                "Anzahl der expliziten Ausgabeteile muss zwischen 2 und 64 liegen.".to_string(),
            );
        }
        (parts.to_vec(), parts.len())
    } else {
        let count = num_parts.clamp(2, 64);
        let paths: Vec<PathBuf> = (1..=count)
            .map(|i| {
                if let Some(prefix) = output_prefix {
                    PathBuf::from(format!("{}.rfs{}", prefix, i))
                } else if input_source == "-" {
                    PathBuf::from(format!("stdin.rfs{}", i))
                } else {
                    PathBuf::from(format!("{}.rfs{}", input_source, i))
                }
            })
            .collect();
        (paths, count)
    };

    if !force {
        for path in &out_paths {
            if path.exists() {
                return Err(format!(
                    "Ausgabedatei '{}' existiert bereits. Nutzen Sie --force zum Überschreiben.",
                    path.display()
                ));
            }
        }
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
        crate::fadvise::advise_sequential(&f);
        let len = f
            .metadata()
            .map_err(|e| format!("Kann Dateimetadaten nicht lesen: {}", e))?
            .len();
        (Box::new(f), Some(len))
    };

    // 3. Ausgabedateien öffnen
    let mut files: Vec<File> = Vec::with_capacity(n_parts);
    for (idx, p) in out_paths.iter().enumerate() {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(p)
            .map_err(|e| {
                format!(
                    "Kann Ausgabedatei {} ('{}') nicht erstellen: {}",
                    idx + 1,
                    p.display(),
                    e
                )
            })?;
        crate::fadvise::advise_sequential(&f);
        files.push(f);
    }

    // 4. Initialisiere Entropie & ChaCha20 CSPRNG
    let (mut master_key, mut master_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&master_key, &master_nonce);
    master_key.zeroize();
    master_nonce.zeroize();

    // 5. Kanäle für entkoppelte 3-Stufen-Pipeline & Puffer-Pools
    let (free_in_tx, free_in_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(BUFFER_POOL_SIZE);
    for _ in 0..BUFFER_POOL_SIZE {
        free_in_tx.send(vec![0u8; block_size]).unwrap();
    }

    let (data_tx, data_rx): (
        Sender<Result<(Vec<u8>, usize), String>>,
        Receiver<Result<(Vec<u8>, usize), String>>,
    ) = bounded(2);

    let (free_out_tx, free_out_rx): (Sender<Vec<Vec<u8>>>, Receiver<Vec<Vec<u8>>>) =
        bounded(BUFFER_POOL_SIZE);
    for _ in 0..BUFFER_POOL_SIZE {
        let mut slot = Vec::with_capacity(n_parts);
        for _ in 0..n_parts {
            slot.push(vec![0u8; block_size]);
        }
        free_out_tx.send(slot).unwrap();
    }

    let (job_tx, job_rx): (
        Sender<Result<WriteJob, String>>,
        Receiver<Result<WriteJob, String>>,
    ) = bounded(2);

    // Stufe 1: Reader Thread (füllt Puffer bis zur vollen Blockgröße oder EOF)
    let reader_handle = thread::spawn(move || -> Result<(), String> {
        let mut reader = input_reader;
        while let Ok(mut buf) = free_in_rx.recv() {
            let mut n_read = 0;
            while n_read < buf.len() {
                match reader.read(&mut buf[n_read..]) {
                    Ok(0) => break,
                    Ok(n) => n_read += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        let _ = data_tx.send(Err(format!("Lesefehler auf Eingabe: {}", e)));
                        return Err(format!("Lesefehler auf Eingabe: {}", e));
                    }
                }
            }

            if n_read == 0 {
                drop(data_tx);
                break;
            }

            if data_tx.send(Ok((buf, n_read))).is_err() {
                break;
            }
        }
        Ok(())
    });

    // Stufe 2: Crypto & Hash Worker Thread (N-Way OTP)
    let mut telemetry = Telemetry::new(telemetry_mode, "Split", known_size);
    let worker_handle = thread::spawn(move || -> Result<(u64, [u8; BLKS_DIGEST_SIZE]), String> {
        let mut total_processed: u64 = 0;
        let mut blks_hasher = BlksHasher::new();

        while let Ok(msg) = data_rx.recv() {
            let (mut in_buf, len) = msg?;

            // 1. In-flight BLKS-384 Hashing
            blks_hasher.update(&in_buf[..len]);

            // 2. Freie Ausgabepuffer anfordern (N Puffer)
            let mut part_bufs = free_out_rx
                .recv()
                .map_err(|_| "Schreib-Thread vorzeitig beendet".to_string())?;

            // 3. Teile 2..N mit ChaCha20-CSPRNG füllen
            for buf in part_bufs.iter_mut().take(n_parts).skip(1) {
                rng.fill_bytes(&mut buf[..len]);
            }

            // 4. Teil 1 schließt die XOR-Kette: part_bufs[0] = in_buf ^ part_bufs[1] ^ ... ^ part_bufs[N-1]
            part_bufs[0][..len].copy_from_slice(&in_buf[..len]);
            for k in 1..n_parts {
                let (first, rest) = part_bufs.split_at_mut(k);
                xor_in_place(&mut first[0][..len], &rest[0][..len]);
            }

            // 5. Eingabepuffer zurück in den Reader-Pool (Zero-Allocation & Zeroize)
            in_buf.as_mut_slice().zeroize();
            let _ = free_in_tx.send(in_buf);

            total_processed += len as u64;

            // 6. Job an Writer-Thread weiterreichen
            if job_tx
                .send(Ok(WriteJob {
                    bufs: part_bufs,
                    valid_len: len,
                }))
                .is_err()
            {
                return Err("Schreib-Thread vorzeitig beendet".to_string());
            }

            telemetry.update(total_processed);
        }

        drop(job_tx);
        let digest = blks_hasher.finalize();
        telemetry.finish(
            total_processed,
            n_parts,
            Some(("blks-384", &BlksDigest(digest).to_base64())),
        );
        Ok((total_processed, digest))
    });

    // Stufe 3: Writer Thread (Schreibt alle N Dateien)
    let writer_handle = thread::spawn(move || -> Result<(), String> {
        let mut writers: Vec<BufWriter<File>> = files
            .into_iter()
            .map(|f| BufWriter::with_capacity(block_size, f))
            .collect();
        let mut total_written: u64 = 0;

        while let Ok(job_res) = job_rx.recv() {
            let WriteJob { bufs, valid_len } = job_res?;

            for k in 0..n_parts {
                writers[k]
                    .write_all(&bufs[k][..valid_len])
                    .map_err(|e| format!("Schreibfehler auf Teil {}: {}", k + 1, e))?;
                if direct_io {
                    crate::fadvise::advise_drop_cache(
                        writers[k].get_ref(),
                        total_written as i64,
                        valid_len as i64,
                    );
                }
            }

            total_written += valid_len as u64;
            let _ = free_out_tx.send(bufs);
        }

        for (k, w) in writers.iter_mut().enumerate() {
            w.flush()
                .map_err(|e| format!("Flush-Fehler auf Teil {}: {}", k + 1, e))?;
        }
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

    // 6. RFS3-Stealth-Footers codieren & an alle N Dateien anhängen
    let (mut post_rng_key, mut post_rng_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut footer_rng = ChaChaRng::new(&post_rng_key, &post_rng_nonce);
    post_rng_key.zeroize();
    post_rng_nonce.zeroize();
    let footers = encode_rfs3_footer_n_way(&digest, total_processed, n_parts, &mut footer_rng);

    for (k, path) in out_paths.iter().enumerate() {
        let mut append_file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| format!("Kann Teil {} für Footer nicht öffnen: {}", k + 1, e))?;
        append_file
            .write_all(&footers[k])
            .map_err(|e| format!("Fehler beim Schreiben des Footers {}: {}", k + 1, e))?;
        append_file
            .flush()
            .map_err(|e| format!("Flush {}: {}", k + 1, e))?;
    }

    if telemetry_mode == TelemetryMode::Interactive {
        eprintln!("Erfolgreich in {} Teile gesplittet (N-Way OTP):", n_parts);
        for (i, p) in out_paths.iter().enumerate() {
            eprintln!("  Teil {}: {}", i + 1, p.display());
        }
        eprintln!(
            "  Originalgröße: {} Bytes\n  BLKS-384: {}",
            total_processed,
            BlksDigest(digest).to_base64()
        );
    }

    if num_decoys > 0 {
        let share_size = total_processed + RFS3_FOOTER_SIZE as u64;
        let base_name = if input_source == "-" {
            Some("stdin")
        } else {
            Some(input_source)
        };
        let decoy_paths = generate_decoy_files(
            share_size,
            num_decoys,
            output_prefix,
            base_name,
            block_size,
            telemetry_mode,
            force,
            direct_io,
        )?;
        if telemetry_mode == TelemetryMode::Interactive {
            eprintln!(
                "  Zusätzliche Köderdateien (Decoys, exakt {} Bytes):",
                share_size
            );
            for (i, p) in decoy_paths.iter().enumerate() {
                eprintln!("    Köder {}: {}", i + 1, p.display());
            }
        }
    }

    Ok(out_paths)
}

/// Analysiert eine Musterdatei oder Größenangabe und berechnet transparent die Zielgröße für Decoys.
pub fn determine_decoy_size(
    template_path: Option<&Path>,
    explicit_size: Option<u64>,
    interactive: bool,
) -> Result<(u64, Option<String>), String> {
    if let Some(target) = explicit_size {
        if interactive {
            eprintln!(
                "[Decoy-Analyse] Explizite Zielgröße vorgegeben: {} Bytes ({}).",
                target,
                crate::telemetry::format_bytes(target)
            );
        }
        return Ok((target, None));
    }

    if let Some(path) = template_path {
        if !path.exists() {
            return Err(format!("Musterdatei '{}' existiert nicht.", path.display()));
        }
        let meta = fs::metadata(path)
            .map_err(|e| format!("Kann Metadaten von '{}' nicht lesen: {}", path.display(), e))?;
        let file_size = meta.len();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let is_rfs = if file_name.ends_with(".rfs")
            || (file_name.contains(".part") && file_name.ends_with(".rfs"))
        {
            true
        } else if let Some(idx) = file_name.rfind(".rfs") {
            let suffix = &file_name[idx + 4..];
            !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
        } else {
            false
        };

        let (target_size, rfs_detected) = if is_rfs {
            (file_size, true)
        } else {
            (file_size + RFS3_FOOTER_SIZE as u64, false)
        };

        if interactive {
            eprintln!(
                "[Decoy-Analyse] Musterdatei: '{}' ({} Bytes / {})",
                path.display(),
                file_size,
                crate::telemetry::format_bytes(file_size)
            );
            if rfs_detected {
                eprintln!(
                    "[Decoy-Erkennung] Typ: Bestehende RFS-Split-Datei (.rfs-Dateiendung erkannt)."
                );
                eprintln!(
                    "[Decoy-Berechnung] Exakte 1:1 Übernahme der Share-Größe: {} Bytes.",
                    target_size
                );
            } else {
                eprintln!("[Decoy-Erkennung] Typ: Rohdatei (Original-Klartext).");
                eprintln!(
                    "[Decoy-Berechnung] +{} Bytes für RFS3-Stealth-Footer einkalkuliert: {} + {} = {} Bytes.",
                    RFS3_FOOTER_SIZE,
                    file_size,
                    RFS3_FOOTER_SIZE,
                    target_size
                );
                eprintln!(
                    "[Decoy-Begründung] Köderdateien müssen im Transportnetzwerk exakt dieselbe Bytegröße wie echte RFS-Shares besitzen."
                );
            }
        }

        let base_name = if is_rfs {
            if let Some(idx) = file_name.rfind(".rfs") {
                let suffix = &file_name[idx + 4..];
                if suffix.chars().all(|c| c.is_ascii_digit()) {
                    file_name[..idx].to_string()
                } else {
                    file_name.to_string()
                }
            } else {
                file_name.to_string()
            }
        } else {
            file_name.to_string()
        };

        return Ok((target_size, Some(base_name)));
    }

    Err("Bitte geben Sie entweder eine Musterdatei (-t <DATEI>) oder eine explizite Größe (-s <GRÖSSE>) an.".to_string())
}

/// Erzeugt eine beliebige Anzahl von Köderdateien (Decoys) gefüllt mit ChaCha20-CSPRNG-Zufallsrauschen.
#[allow(clippy::too_many_arguments)]
pub fn generate_decoy_files(
    target_size: u64,
    count: usize,
    output_prefix: Option<&str>,
    template_base: Option<&str>,
    block_size: usize,
    telemetry_mode: TelemetryMode,
    force: bool,
    direct_io: bool,
) -> Result<Vec<PathBuf>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > 1000 {
        return Err("Anzahl der Köderdateien darf höchstens 1000 betragen.".to_string());
    }

    // 1. Zieldateipfade ableiten
    let mut decoy_paths: Vec<PathBuf> = Vec::with_capacity(count);
    for idx in 1..=count {
        let path = if let Some(prefix) = output_prefix {
            if count == 1 && prefix.contains('.') {
                PathBuf::from(prefix)
            } else {
                PathBuf::from(format!("{}.decoy{}.rfs", prefix, idx))
            }
        } else if let Some(base) = template_base {
            PathBuf::from(format!("{}.decoy{}.rfs", base, idx))
        } else {
            PathBuf::from(format!("decoy_{}.rfs", idx))
        };
        decoy_paths.push(path);
    }

    // 2. Kollisionsprüfung
    for p in &decoy_paths {
        if p.exists() && !force {
            return Err(format!(
                "Köderdatei '{}' existiert bereits. Verwenden Sie -f / --force zum Überschreiben.",
                p.display()
            ));
        }
    }

    // 3. Entropie & CSPRNG Initialisierung
    let (mut key, mut nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&key, &nonce);
    key.zeroize();
    nonce.zeroize();

    let chunk_size = block_size.clamp(types::MIN_BLOCK_SIZE, types::MAX_BLOCK_SIZE);
    let mut buffer = vec![0u8; chunk_size];
    let total_all_decoys = target_size.saturating_mul(count as u64);

    let mut telemetry = Telemetry::new(telemetry_mode, "Decoy", Some(total_all_decoys));
    let mut processed_total: u64 = 0;

    for path in &decoy_paths {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| {
                format!(
                    "Kann Köderdatei '{}' nicht erstellen: {}",
                    path.display(),
                    e
                )
            })?;

        if direct_io {
            crate::fadvise::advise_sequential(&f);
        }

        let mut writer = BufWriter::with_capacity(chunk_size, f);
        let mut remaining = target_size;
        let mut file_written: u64 = 0;

        while remaining > 0 {
            let to_write = std::cmp::min(remaining, chunk_size as u64) as usize;
            rng.fill_bytes(&mut buffer[..to_write]);

            writer
                .write_all(&buffer[..to_write])
                .map_err(|e| format!("Schreibfehler auf Köderdatei '{}': {}", path.display(), e))?;

            if direct_io {
                crate::fadvise::advise_drop_cache(
                    writer.get_ref(),
                    file_written as i64,
                    to_write as i64,
                );
            }

            file_written += to_write as u64;
            remaining -= to_write as u64;
            processed_total += to_write as u64;
            telemetry.update(processed_total);
        }

        writer
            .flush()
            .map_err(|e| format!("Flush-Fehler auf Köderdatei '{}': {}", path.display(), e))?;
    }

    buffer.as_mut_slice().zeroize();
    telemetry.finish(processed_total, count, None);

    if telemetry_mode == TelemetryMode::Interactive {
        eprintln!(
            "Erfolgreich {} Köderdatei(en) (Decoys) generiert (100% ChaCha20-Zufallsrauschen):",
            count
        );
        for (i, p) in decoy_paths.iter().enumerate() {
            eprintln!("  Köder {}: {} ({} Bytes)", i + 1, p.display(), target_size);
        }
    }

    Ok(decoy_paths)
}

/// Convenience-Wrapper für Abwärtskompatibilität (2 Teile)
#[allow(dead_code)]
pub fn split_file(
    input_path: &Path,
    output_prefix: Option<&str>,
    block_size: usize,
    silent: bool,
) -> Result<(PathBuf, PathBuf), String> {
    let mode = if silent {
        TelemetryMode::Silent
    } else {
        TelemetryMode::Interactive
    };
    let parts = split_stream_or_file(
        input_path.to_str().unwrap_or("-"),
        None,
        2,
        0,
        output_prefix,
        block_size,
        mode,
        false,
        false,
    )?;
    Ok((parts[0].clone(), parts[1].clone()))
}

/// Führt die kryptografische Wiederherstellung oder Verifikation von $N$ Split-Dateien durch.
///
/// Unterstützt:
/// - Reguläre Wiederherstellung in Zieldatei
/// - Unix-Piping nach `stdout` (`output_target` == `"-"`)
/// - Fast-Verify im RAM (`verify_only` == true)
/// - $N$-Way SIMD-XOR Wiederherstellung ($P = C_1 \oplus C_2 \oplus \dots \oplus C_N$)
/// - Auto-Erkennung von RFS3 (BLKS-384) und RFS2 (SHA-256)
pub fn restore_file(
    part_paths: &[PathBuf],
    output_target: Option<&str>,
    force: bool,
    telemetry_mode: TelemetryMode,
    verify_only: bool,
    block_size: usize,
    direct_io: bool,
) -> Result<Option<PathBuf>, String> {
    let n_parts = part_paths.len();
    if n_parts < 2 {
        return Err("Mindestens 2 Teile für die Wiederherstellung erforderlich.".to_string());
    }

    let mut files: Vec<File> = Vec::with_capacity(n_parts);
    let mut file_len: Option<u64> = None;

    for (idx, p) in part_paths.iter().enumerate() {
        let f = File::open(p).map_err(|e| {
            format!(
                "Kann Teil {} ('{}') nicht öffnen: {}",
                idx + 1,
                p.display(),
                e
            )
        })?;
        let len = f.metadata().map_err(|e| e.to_string())?.len();
        if let Some(fl) = file_len {
            if fl != len {
                return Err(format!(
                    "Dateigrößen stimmen nicht überein (Teil {} weicht von Teil 1 ab).",
                    idx + 1
                ));
            }
        } else {
            file_len = Some(len);
        }
        crate::fadvise::advise_sequential(&f);
        files.push(f);
    }

    let len1 = file_len.unwrap();
    if len1 < RFS3_FOOTER_SIZE as u64 {
        return Err("Dateigröße kleiner als RFS-Footer.".to_string());
    }

    // 1. Footer lesen (letzte 60 Bytes von allen N Dateien)
    let tail_len = RFS3_FOOTER_SIZE;
    let mut tails: Vec<Vec<u8>> = Vec::with_capacity(n_parts);

    for (idx, f) in files.iter_mut().enumerate() {
        f.seek(SeekFrom::End(-(tail_len as i64)))
            .map_err(|e| format!("Seek Teil {}: {}", idx + 1, e))?;
        let mut t = vec![0u8; tail_len];
        f.read_exact(&mut t)
            .map_err(|e| format!("Read tail Teil {}: {}", idx + 1, e))?;
        tails.push(t);
    }

    // N-Way Decode
    let tail_refs: Vec<&[u8]> = tails.iter().map(|t| t.as_slice()).collect();
    let meta = decode_footer_n_way(&tail_refs)?;
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
        let p_str = part_paths[0].to_str().unwrap_or("restored.bin");
        let deduced = if let Some(idx) = p_str.rfind(".rfs") {
            let suffix = &p_str[idx + 4..];
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                PathBuf::from(&p_str[..idx])
            } else {
                PathBuf::from(format!("{}.restored", p_str))
            }
        } else if let Some(stripped) = p_str.strip_suffix(".part1.rfs") {
            PathBuf::from(stripped)
        } else {
            PathBuf::from(format!("{}.restored", p_str))
        };
        Some(deduced)
    };

    if let Some(ref target) = target_out_path {
        // Schutz: Ziel darf niemals eine der Quell-Split-Dateien sein
        for (idx, p) in part_paths.iter().enumerate() {
            if target == p {
                return Err(format!(
                    "Zieldatei '{}' darf nicht identisch mit Quellteil {} sein (Gefahr des Datenverlusts).",
                    target.display(),
                    idx + 1
                ));
            }
        }

        if target.exists() && !force {
            return Err(format!(
                "Zieldatei '{}' existiert bereits. Verwenden Sie --force zum Überschreiben.",
                target.display()
            ));
        }
    }

    // Zurück an Dateianfang springen
    for (idx, f) in files.iter_mut().enumerate() {
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Seek 0 Teil {}: {}", idx + 1, e))?;
    }

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
    let (free_in_tx, free_in_rx): (Sender<Vec<Vec<u8>>>, Receiver<Vec<Vec<u8>>>) =
        bounded(BUFFER_POOL_SIZE);
    for _ in 0..BUFFER_POOL_SIZE {
        let mut slot = Vec::with_capacity(n_parts);
        for _ in 0..n_parts {
            slot.push(vec![0u8; block_size]);
        }
        free_in_tx.send(slot).unwrap();
    }

    let (data_tx, data_rx): (
        Sender<Result<(Vec<Vec<u8>>, usize), String>>,
        Receiver<Result<(Vec<Vec<u8>>, usize), String>>,
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

    // Stufe 1: N-Way Reader Thread
    let reader_handle = thread::spawn(move || -> Result<(), String> {
        let mut readers: Vec<BufReader<File>> = files
            .into_iter()
            .map(|f| BufReader::with_capacity(block_size, f))
            .collect();
        let mut remaining = original_size;

        while remaining > 0 {
            let to_read = (block_size as u64).min(remaining) as usize;
            let mut in_bufs = match free_in_rx.recv() {
                Ok(slot) => slot,
                Err(_) => break,
            };

            for (k, r) in readers.iter_mut().enumerate() {
                if let Err(e) = r.read_exact(&mut in_bufs[k][..to_read]) {
                    let _ = data_tx.send(Err(format!("Lesefehler Teil {}: {}", k + 1, e)));
                    return Err(format!("Lesefehler Teil {}: {}", k + 1, e));
                }
                if direct_io {
                    crate::fadvise::advise_drop_cache(
                        r.get_ref(),
                        (original_size - remaining) as i64,
                        to_read as i64,
                    );
                }
            }

            remaining -= to_read as u64;
            if data_tx.send(Ok((in_bufs, to_read))).is_err() {
                break;
            }
        }
        drop(data_tx);
        Ok(())
    });

    // Stufe 2: Compute Worker (N-Way SIMD XOR & Hashing)
    let meta_clone = meta.clone();
    let worker_free_out_tx = free_out_tx.clone();
    let action_name = if verify_only { "Verify" } else { "Restore" };
    let mut telemetry = Telemetry::new(telemetry_mode, action_name, Some(original_size));
    let worker_handle = thread::spawn(move || -> Result<(), String> {
        let mut blks_hasher = match meta_clone {
            RfsMetadata::Rfs3 { .. } => Some(BlksHasher::new()),
            _ => None,
        };
        let mut sha256_hasher = match meta_clone {
            RfsMetadata::Rfs2 { .. } => Some(Sha256::new()),
            _ => None,
        };

        let mut total_processed: u64 = 0;

        while let Ok(msg) = data_rx.recv() {
            let (in_bufs, len) = msg?;
            let mut b_out = free_out_rx
                .recv()
                .map_err(|_| "Writer vorzeitig beendet".to_string())?;

            // SIMD XOR über alle N Teile: b_out = in_bufs[0] ^ in_bufs[1] ^ ... ^ in_bufs[N-1]
            b_out[..len].copy_from_slice(&in_bufs[0][..len]);
            for in_buf in in_bufs.iter().take(n_parts).skip(1) {
                xor_in_place(&mut b_out[..len], &in_buf[..len]);
            }

            // In-flight Hashing
            if let Some(ref mut h) = blks_hasher {
                h.update(&b_out[..len]);
            }
            if let Some(ref mut h) = sha256_hasher {
                h.update(&b_out[..len]);
            }

            // Puffer-Slot zurück an Reader
            let _ = free_in_tx.send(in_bufs);

            total_processed += len as u64;

            if !verify_only {
                if job_tx.send(Ok((b_out, len))).is_err() {
                    return Err("Writer vorzeitig beendet".to_string());
                }
            } else {
                b_out.as_mut_slice().zeroize();
                let _ = worker_free_out_tx.send(b_out);
            }
            telemetry.update(total_processed);
        }

        drop(job_tx);

        // Integritätsprüfung
        match meta_clone {
            RfsMetadata::Rfs3 { expected_blks, .. } => {
                let actual_bytes = blks_hasher.unwrap().finalize();
                let actual = BlksDigest(actual_bytes);
                let expected_digest = BlksDigest(expected_blks);
                if actual.ct_eq(&expected_digest) {
                    let dig_str = actual.to_base64();
                    telemetry.finish(total_processed, n_parts, Some(("blks-384", &dig_str)));
                    if telemetry_mode == TelemetryMode::Interactive {
                        eprintln!("Integritätsprüfung [OK] (BLKS-384: {})", dig_str);
                    }
                    Ok(())
                } else {
                    telemetry.error("Integritätsfehler! BLKS-384 Prüfsumme stimmt nicht überein.");
                    if telemetry_mode == TelemetryMode::Interactive {
                        eprintln!(
                            "\nWARNUNG: Integritätsfehler! BLKS-384 Prüfsumme stimmt nicht überein."
                        );
                        eprintln!("  Erwartet:  {}", expected_digest.to_base64());
                        eprintln!("  Berechnet: {}", actual.to_base64());
                    }
                    Err(
                        "Integritätsfehler! Die Datei ist möglicherweise beschädigt oder manipuliert."
                            .to_string(),
                    )
                }
            }
            RfsMetadata::Rfs2 {
                expected_sha256, ..
            } => {
                let actual = sha256_hasher.unwrap().finalize();
                let mut ct_diff = 0u8;
                for (a, b) in actual.as_slice().iter().zip(expected_sha256.iter()) {
                    ct_diff |= a ^ b;
                }
                if ct_diff == 0 {
                    let hex_str = expected_sha256
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();
                    telemetry.finish(total_processed, n_parts, Some(("sha256", &hex_str)));
                    if telemetry_mode == TelemetryMode::Interactive {
                        eprintln!("Integritätsprüfung [OK] (Legacy RFS2 SHA-256 verifiziert)");
                    }
                    Ok(())
                } else {
                    telemetry.error("Integritätsfehler! SHA-256 Prüfsumme stimmt nicht überein.");
                    if telemetry_mode == TelemetryMode::Interactive {
                        eprintln!(
                            "\nWARNUNG: Integritätsfehler! SHA-256 Prüfsumme stimmt nicht überein."
                        );
                    }
                    Err(
                        "Integritätsfehler! Die Datei ist möglicherweise beschädigt oder manipuliert."
                            .to_string(),
                    )
                }
            }
        }
    });

    // Stufe 3: Writer Thread (nur aktiv wenn !verify_only)
    let writer_handle = thread::spawn(move || -> Result<(), String> {
        if let Some(mut writer) = out_writer {
            while let Ok(msg) = job_rx.recv() {
                let (mut b_out, len) = msg?;
                if let Err(e) = writer.write_all(&b_out[..len]) {
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        return Err("Ausgabepipe wurde vom Empfänger geschlossen (Broken Pipe)."
                            .to_string());
                    }
                    return Err(format!("Schreibfehler auf Ziel: {}", e));
                }
                b_out.as_mut_slice().zeroize();
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
