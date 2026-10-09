//! 3-stage streaming restore & verify pipeline with triple-buffering and SIMD-XOR.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::thread;
use zeroize::Zeroize;

use blks_core::{BlksHasher, Digest as BlksDigest};
use crossbeam_channel::{bounded, Receiver, Sender};
use sha2::{Digest as Sha2Digest, Sha256};

use super::BUFFER_POOL_SIZE;
use crate::crypto::xor_in_place;
use crate::format::{decode_footer_n_way, RfsMetadata};
use crate::naming::{check_destination_collision, deduce_restore_target};
use crate::telemetry::{Telemetry, TelemetryMode};
use crate::types::{
    BLKS_DIGEST_SIZE, RFS2_FOOTER_SIZE, RFS3_FOOTER_SIZE, RFS4_MAGIC, RFS4_TRAILER_SIZE,
};

/// Performs cryptographic reconstruction or integrity verification of N share files.
///
/// Supports:
/// - Standard file restoration to destination path
/// - Unix streaming pipe to stdout (`output_target` == `"-"`)
/// - In-memory fast verification (`verify_only` == true)
/// - $N$-Way SIMD-XOR reconstruction ($P = C_1 \oplus C_2 \oplus \dots \oplus C_N$)
/// - Auto-detection of RFS4 (BLKS-384, embedded filename), RFS3 (BLKS-384), and legacy RFS2 (SHA-256)
#[allow(clippy::too_many_arguments)]
pub fn restore_file(
    part_paths: &[PathBuf],
    output_target: Option<&str>,
    force: bool,
    telemetry_mode: TelemetryMode,
    verify_only: bool,
    block_size: usize,
    direct_io: bool,
    mlock: bool,
) -> Result<Option<PathBuf>, String> {
    let n_parts = part_paths.len();
    if n_parts < 2 {
        return Err("At least 2 shares required for restoration.".to_string());
    }

    let mut files: Vec<File> = Vec::with_capacity(n_parts);
    let mut file_len: Option<u64> = None;

    for (idx, p) in part_paths.iter().enumerate() {
        let f = File::open(p)
            .map_err(|e| format!("Cannot open share {} ('{}'): {}", idx + 1, p.display(), e))?;
        let len = f.metadata().map_err(|e| e.to_string())?.len();
        if let Some(fl) = file_len {
            if fl != len {
                return Err(format!(
                    "File sizes do not match (share {} differs from share 1).",
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
        return Err("File size smaller than RFS trailer.".to_string());
    }

    // 1. Read last 64 bytes of all N files
    let mut trailers: Vec<Vec<u8>> = Vec::with_capacity(n_parts);
    for (idx, f) in files.iter_mut().enumerate() {
        f.seek(SeekFrom::End(-(trailer_len as i64)))
            .map_err(|e| format!("Seek share {}: {}", idx + 1, e))?;
        let mut t = vec![0u8; trailer_len];
        f.read_exact(&mut t)
            .map_err(|e| format!("Read tail share {}: {}", idx + 1, e))?;
        trailers.push(t);
    }

    // XOR the last 64 bytes
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
                return Err("File size too small for embedded RFS4 filename.".to_string());
            }
            let mut fn_tails: Vec<Vec<u8>> = Vec::with_capacity(n_parts);
            for (idx, f) in files.iter_mut().enumerate() {
                f.seek(SeekFrom::End(-((trailer_len + fn_len) as i64)))
                    .map_err(|e| format!("Seek filename share {}: {}", idx + 1, e))?;
                let mut fn_buf = vec![0u8; fn_len];
                f.read_exact(&mut fn_buf)
                    .map_err(|e| format!("Read filename share {}: {}", idx + 1, e))?;
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
        return Err("Reconstructed file size implausible. Shares are corrupted.".to_string());
    }

    // 2. Deduce target output destination
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
                "Target file '{}' already exists. Use --force to overwrite.",
                target.display()
            ));
        }
    }

    // Seek back to start of all files
    for (idx, f) in files.iter_mut().enumerate() {
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Seek 0 share {}: {}", idx + 1, e))?;
    }

    // 3. Initialize output writer
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
            .map_err(|e| format!("Cannot create target file: {}", e))?;
        Some(Box::new(BufWriter::with_capacity(block_size, file)))
    };

    // 4. Decoupled pipeline with buffer pools
    let (free_in_tx, free_in_rx): (Sender<Vec<Vec<u8>>>, Receiver<Vec<Vec<u8>>>) =
        bounded(BUFFER_POOL_SIZE);
    let mut locked_in_count = 0;
    for _ in 0..BUFFER_POOL_SIZE {
        let mut slot = Vec::with_capacity(n_parts);
        for _ in 0..n_parts {
            let buf = vec![0u8; block_size];
            if mlock && crate::memlock::lock_memory(&buf) {
                locked_in_count += 1;
            }
            slot.push(buf);
        }
        free_in_tx.send(slot).unwrap();
    }

    let (data_tx, data_rx): (
        Sender<Result<(Vec<Vec<u8>>, usize), String>>,
        Receiver<Result<(Vec<Vec<u8>>, usize), String>>,
    ) = bounded(2);

    let (free_out_tx, free_out_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
        bounded(BUFFER_POOL_SIZE);
    let mut locked_out_count = 0;
    for _ in 0..BUFFER_POOL_SIZE {
        let buf = vec![0u8; block_size];
        if mlock && crate::memlock::lock_memory(&buf) {
            locked_out_count += 1;
        }
        free_out_tx.send(buf).unwrap();
    }

    if mlock && telemetry_mode == TelemetryMode::Interactive {
        let total_locked = (locked_in_count + locked_out_count) * block_size;
        if total_locked > 0 {
            eprintln!(
                "[OPSEC] Memory locking active: {} buffers locked in RAM ({}) - swap paging protected.",
                locked_in_count + locked_out_count,
                crate::telemetry::format_bytes(total_locked as u64)
            );
        } else {
            eprintln!("[WARNING] mlock denied (check ulimit -l). Continuing without swap locking.");
        }
    }

    let (job_tx, job_rx): (
        Sender<Result<(Vec<u8>, usize), String>>,
        Receiver<Result<(Vec<u8>, usize), String>>,
    ) = bounded(2);

    // Stage 1: Parallel N-Way reader worker pool (Parallel Disk Fanin)
    let reader_handle = thread::spawn(move || -> Result<(), String> {
        let mut part_txs = Vec::with_capacity(n_parts);
        let (done_tx, done_rx) =
            bounded::<(usize, Result<Vec<u8>, String>)>(n_parts * BUFFER_POOL_SIZE);
        let mut worker_handles = Vec::with_capacity(n_parts);

        for (k, file) in files.into_iter().enumerate() {
            let (tx, rx): (
                Sender<Option<(Vec<u8>, usize, u64)>>,
                Receiver<Option<(Vec<u8>, usize, u64)>>,
            ) = bounded(2);
            part_txs.push(tx);
            let done_tx_clone = done_tx.clone();

            let handle = thread::spawn(move || -> Result<(), String> {
                let mut reader = BufReader::with_capacity(block_size, file);
                while let Ok(Some((mut buf, to_read, offset))) = rx.recv() {
                    if let Err(e) = reader.read_exact(&mut buf[..to_read]) {
                        let err_msg = format!("Read error on share {}: {}", k + 1, e);
                        let _ = done_tx_clone.send((k, Err(err_msg.clone())));
                        return Err(err_msg);
                    }
                    if direct_io {
                        crate::fadvise::advise_drop_cache(
                            reader.get_ref(),
                            offset as i64,
                            to_read as i64,
                        );
                    }
                    let _ = done_tx_clone.send((k, Ok(buf)));
                }
                Ok(())
            });
            worker_handles.push(handle);
        }
        drop(done_tx);

        let mut remaining = original_size;

        while remaining > 0 {
            let to_read = (block_size as u64).min(remaining) as usize;
            let in_bufs = match free_in_rx.recv() {
                Ok(slot) => slot,
                Err(_) => break,
            };

            let current_offset = original_size - remaining;

            // 1. Distribute read jobs concurrently to all N reader workers
            for (k, buf) in in_bufs.into_iter().enumerate() {
                if part_txs[k]
                    .send(Some((buf, to_read, current_offset)))
                    .is_err()
                {
                    let err = format!("Reader worker for share {} terminated prematurely", k + 1);
                    let _ = data_tx.send(Err(err.clone()));
                    return Err(err);
                }
            }

            // 2. Await completion of all N reader workers for this block
            let mut collected_bufs = vec![Vec::new(); n_parts];
            for _ in 0..n_parts {
                match done_rx.recv() {
                    Ok((k, Ok(buf))) => {
                        collected_bufs[k] = buf;
                    }
                    Ok((_k, Err(e))) => {
                        let _ = data_tx.send(Err(e.clone()));
                        return Err(e);
                    }
                    Err(_) => {
                        let err = "Unexpected channel disconnect during disk fanin".to_string();
                        let _ = data_tx.send(Err(err.clone()));
                        return Err(err);
                    }
                }
            }

            remaining -= to_read as u64;
            if data_tx.send(Ok((collected_bufs, to_read))).is_err() {
                break;
            }
        }
        drop(data_tx);

        // Signal EOF to all workers
        for tx in part_txs {
            let _ = tx.send(None);
        }

        // Await clean exit of all worker threads
        for (k, handle) in worker_handles.into_iter().enumerate() {
            handle
                .join()
                .map_err(|_| format!("Reader worker for share {} panicked", k + 1))??;
        }

        Ok(())
    });

    // Stage 2: Compute worker (N-Way SIMD XOR & Hashing)
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
                .map_err(|_| "Writer terminated prematurely".to_string())?;

            // SIMD XOR across all N shares: b_out = in_bufs[0] ^ in_bufs[1] ^ ... ^ in_bufs[N-1]
            b_out[..len].copy_from_slice(&in_bufs[0][..len]);
            for in_buf in in_bufs.iter().take(n_parts).skip(1) {
                xor_in_place(&mut b_out[..len], &in_buf[..len]);
            }

            // In-flight hashing
            if let Some(ref mut h) = blks_hasher {
                h.update(&b_out[..len]);
            }
            if let Some(ref mut h) = sha256_hasher {
                h.update(&b_out[..len]);
            }

            // Recycle buffer slot to reader pool
            let _ = free_in_tx.send(in_bufs);

            total_processed += len as u64;

            if !verify_only {
                if job_tx.send(Ok((b_out, len))).is_err() {
                    return Err("Writer terminated prematurely".to_string());
                }
            } else {
                b_out.as_mut_slice().zeroize();
                let _ = worker_free_out_tx.send(b_out);
            }
            telemetry.update(total_processed);
        }

        drop(job_tx);

        // Integrity verification
        match meta_clone {
            RfsMetadata::Rfs3 { expected_blks, .. } | RfsMetadata::Rfs4 { expected_blks, .. } => {
                let actual_bytes = blks_hasher.unwrap().finalize();
                let actual = BlksDigest(actual_bytes);
                let expected_digest = BlksDigest(expected_blks);
                if actual.ct_eq(&expected_digest) {
                    let dig_str = actual.to_base64();
                    telemetry.finish(total_processed, n_parts, Some(("blks-384", &dig_str)));
                    if telemetry_mode == TelemetryMode::Interactive {
                        eprintln!("Integrity check [OK] (BLKS-384: {})", dig_str);
                    }
                    Ok(())
                } else {
                    telemetry.error("Integrity error! BLKS-384 checksum does not match.");
                    if telemetry_mode == TelemetryMode::Interactive {
                        eprintln!("\nWARNING: Integrity error! BLKS-384 checksum does not match.");
                        eprintln!("  Expected:   {}", expected_digest.to_base64());
                        eprintln!("  Calculated: {}", actual.to_base64());
                    }
                    Err("Integrity error! File may be corrupted or tampered with.".to_string())
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
                        eprintln!("Integrity check [OK] (Legacy RFS2 SHA-256 verified)");
                    }
                    Ok(())
                } else {
                    telemetry.error("Integrity error! SHA-256 checksum does not match.");
                    if telemetry_mode == TelemetryMode::Interactive {
                        eprintln!("\nWARNING: Integrity error! SHA-256 checksum does not match.");
                    }
                    Err("Integrity error! File may be corrupted or tampered with.".to_string())
                }
            }
        }
    });

    // Stage 3: Writer thread (only active when !verify_only)
    let writer_handle = thread::spawn(move || -> Result<(), String> {
        if let Some(mut writer) = out_writer {
            while let Ok(msg) = job_rx.recv() {
                let (mut b_out, len) = msg?;
                if let Err(e) = writer.write_all(&b_out[..len]) {
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        return Err("Output pipe closed by receiver (Broken Pipe).".to_string());
                    }
                    return Err(format!("Write error on destination: {}", e));
                }
                b_out.as_mut_slice().zeroize();
                let _ = free_out_tx.send(b_out);
            }
            writer.flush().map_err(|e| format!("Flush error: {}", e))?;
        }
        Ok(())
    });

    let reader_res = reader_handle
        .join()
        .map_err(|_| "Reader thread panicked".to_string())?;
    let worker_res = worker_handle
        .join()
        .map_err(|_| "Worker thread panicked".to_string())?;
    let writer_res = writer_handle
        .join()
        .map_err(|_| "Writer thread panicked".to_string())?;

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
