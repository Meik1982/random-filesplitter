//! Streaming Split & Restore Engine with Zero-Allocation Triple-Buffering,
//! In-Flight BLKS-384 / SHA-256 Hashing, Unix Pipe Support, N-Way OTP Splitting,
//! and Plausible Deniability Footers.

#![allow(clippy::type_complexity)]

use crate::crypto::{xor_in_place, ChaChaRng};
use crate::decoy::write_decoy_files_to_paths;
use crate::entropy::UniversalEntropyHarvester;
use crate::format::{decode_footer_n_way, encode_rfs4_footer_n_way, RfsMetadata};
use crate::naming::{check_destination_collision, deduce_restore_target, determine_split_paths};
use crate::telemetry::{Telemetry, TelemetryMode};
use crate::types::{
    BLKS_DIGEST_SIZE, RFS2_FOOTER_SIZE, RFS3_FOOTER_SIZE, RFS4_MAGIC, RFS4_TRAILER_SIZE,
};

#[allow(unused_imports)]
pub use crate::decoy::{determine_decoy_size, generate_decoy_files};
#[allow(unused_imports)]
pub use crate::naming::{generate_unique_hex_tokens, shuffle_paths};

use blks_core::{BlksHasher, Digest as BlksDigest};
use crossbeam_channel::{bounded, Receiver, Sender};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs::{File, OpenOptions};
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

/// - $N$-Way One-Time-Pad Chain: $P = C_1 \oplus C_2 \oplus \dots \oplus C_N$
/// - Entkoppelte 3-Stufen Pipeline (Reader ➔ Crypto/SIMD ➔ Writer) mit Zero-Copy Puffer-Pooling
/// - RFS4-Format mit eingebettetem Originaldateinamen, 4 KiB Cluster-Padding und optionalem `--pad-to`
/// - Maschinenlesbare NDJSON-Telemetrie (`--json`) und interaktive ANSI-Fortschrittsbalken
#[allow(clippy::too_many_arguments)]
pub fn split_stream_or_file(
    input_source: &str,
    output_parts: Option<&[PathBuf]>,
    num_parts: usize,
    num_decoys: usize,
    pad_to_target: Option<u64>,
    output_prefix: Option<&str>,
    block_size: usize,
    telemetry_mode: TelemetryMode,
    force: bool,
    direct_io: bool,
) -> Result<Vec<PathBuf>, String> {
    // 1. Zielpfade bestimmen (<token6>.rfs als Standard für maximale OPSEC)
    let (real_paths, decoy_paths, n_parts) = determine_split_paths(
        input_source,
        output_parts,
        num_parts,
        num_decoys,
        output_prefix,
    )?;

    let out_paths = real_paths.clone();

    if !force {
        for path in real_paths.iter().chain(decoy_paths.iter()) {
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

    // 6. RFS4-Stealth-Footer & Padding codieren & an alle N Dateien anhängen
    let original_filename = if input_source == "-" {
        output_prefix.unwrap_or("stdin.bin")
    } else {
        Path::new(input_source)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin")
    };

    let (mut post_rng_key, mut post_rng_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut footer_rng = ChaChaRng::new(&post_rng_key, &post_rng_nonce);
    post_rng_key.zeroize();
    post_rng_nonce.zeroize();
    let footers = encode_rfs4_footer_n_way(
        &digest,
        total_processed,
        original_filename,
        n_parts,
        pad_to_target,
        &mut footer_rng,
    )?;

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

    let share_size = total_processed + footers[0].len() as u64;

    if !decoy_paths.is_empty() {
        write_decoy_files_to_paths(
            &decoy_paths,
            share_size,
            block_size,
            telemetry_mode,
            direct_io,
        )?;
    }

    if telemetry_mode == TelemetryMode::Interactive {
        eprintln!(
            "Erfolgreich in {} Teile gesplittet (N-Way OTP, RFS4):",
            n_parts
        );
        eprintln!("  Eingebetteter Name: {}", original_filename);
        eprintln!("  Originalgröße: {} Bytes", total_processed);
        eprintln!(
            "  Share-Größe (4 KiB-Cluster-Padding): {} Bytes",
            share_size
        );
        eprintln!("  BLKS-384: {}", BlksDigest(digest).to_base64());

        if !decoy_paths.is_empty() {
            eprintln!("\nEchte Shares (N={}, zufällig im Set verteilt):", n_parts);
            for (i, p) in out_paths.iter().enumerate() {
                eprintln!("  Teil {}: {}", i + 1, p.display());
            }

            eprintln!(
                "\nKöderdateien (Decoys, D={}, 100% ChaCha20-Zufallsrauschen):",
                decoy_paths.len()
            );
            for (i, p) in decoy_paths.iter().enumerate() {
                eprintln!("  Köder {}: {} ({} Bytes)", i + 1, p.display(), share_size);
            }
        } else {
            eprintln!("\nGenerierte Shares:");
            for (i, p) in out_paths.iter().enumerate() {
                eprintln!("  Teil {}: {}", i + 1, p.display());
            }
        }
    }

    Ok(out_paths)
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
        None,
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
    let trailer_len = RFS4_TRAILER_SIZE;
    if len1 < trailer_len as u64 {
        return Err("Dateigröße kleiner als RFS-Trailer.".to_string());
    }

    // 1. Letzte 64 Bytes aller N Dateien lesen
    let mut trailers: Vec<Vec<u8>> = Vec::with_capacity(n_parts);
    for (idx, f) in files.iter_mut().enumerate() {
        f.seek(SeekFrom::End(-(trailer_len as i64)))
            .map_err(|e| format!("Seek Teil {}: {}", idx + 1, e))?;
        let mut t = vec![0u8; trailer_len];
        f.read_exact(&mut t)
            .map_err(|e| format!("Read tail Teil {}: {}", idx + 1, e))?;
        trailers.push(t);
    }

    // XOR der letzten 64 Bytes
    let mut xor64 = [0u8; RFS4_TRAILER_SIZE];
    xor64.copy_from_slice(&trailers[0]);
    for t in &trailers[1..] {
        for i in 0..RFS4_TRAILER_SIZE {
            xor64[i] ^= t[i];
        }
    }

    let meta = if xor64[0..4] == RFS4_MAGIC {
        let size = u64::from_le_bytes(xor64[6..14].try_into().unwrap());
        let mut blks = [0u8; BLKS_DIGEST_SIZE];
        blks.copy_from_slice(&xor64[14..62]);
        let fn_len = u16::from_le_bytes(xor64[62..64].try_into().unwrap()) as usize;

        let filename = if fn_len > 0 {
            if len1 < (trailer_len + fn_len) as u64 {
                return Err("Dateigröße zu klein für RFS4-Dateinamen.".to_string());
            }
            let mut fn_tails: Vec<Vec<u8>> = Vec::with_capacity(n_parts);
            for (idx, f) in files.iter_mut().enumerate() {
                f.seek(SeekFrom::End(-((trailer_len + fn_len) as i64)))
                    .map_err(|e| format!("Seek Filename Teil {}: {}", idx + 1, e))?;
                let mut fn_buf = vec![0u8; fn_len];
                f.read_exact(&mut fn_buf)
                    .map_err(|e| format!("Read Filename Teil {}: {}", idx + 1, e))?;
                fn_tails.push(fn_buf);
            }
            let mut xor_fn = fn_tails[0].clone();
            for t in &fn_tails[1..] {
                for i in 0..fn_len {
                    xor_fn[i] ^= t[i];
                }
            }
            String::from_utf8(xor_fn).unwrap_or_else(|_| "restored.bin".to_string())
        } else {
            "restored.bin".to_string()
        };

        xor64.zeroize();
        RfsMetadata::Rfs4 {
            expected_blks: blks,
            original_size: size,
            filename,
            filename_len: fn_len as u16,
        }
    } else {
        xor64.zeroize();
        let tail_refs: Vec<&[u8]> = trailers.iter().map(|t| t.as_slice()).collect();
        decode_footer_n_way(&tail_refs)?
    };

    let original_size = meta.original_size();
    let min_needed_len = match meta {
        RfsMetadata::Rfs4 { filename_len, .. } => {
            original_size + filename_len as u64 + RFS4_TRAILER_SIZE as u64
        }
        RfsMetadata::Rfs3 { .. } => original_size + RFS3_FOOTER_SIZE as u64,
        RfsMetadata::Rfs2 { .. } => original_size + RFS2_FOOTER_SIZE as u64,
    };

    if len1 < min_needed_len {
        return Err("Rekonstruierte Dateigröße unplausibel. Dateien sind beschädigt.".to_string());
    }

    // 2. Bestimme Ausgabeziel
    let is_stdout = matches!(output_target, Some("-"));
    let target_out_path = deduce_restore_target(
        part_paths,
        output_target,
        meta.filename(),
        is_stdout,
        verify_only,
    );

    if let Some(ref target) = target_out_path {
        check_destination_collision(target, part_paths)?;

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
            RfsMetadata::Rfs3 { .. } | RfsMetadata::Rfs4 { .. } => Some(BlksHasher::new()),
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
            RfsMetadata::Rfs3 { expected_blks, .. } | RfsMetadata::Rfs4 { expected_blks, .. } => {
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
