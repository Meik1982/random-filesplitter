//! 3-stage streaming split pipeline with triple-buffering and ChaCha20-CSPRNG.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use zeroize::Zeroize;

use blks_core::{BlksHasher, Digest as BlksDigest};
use crossbeam_channel::{bounded, Receiver, Sender};

use super::BUFFER_POOL_SIZE;
use crate::crypto::{xor_in_place, ChaChaRng};
use crate::decoy::write_decoy_files_to_paths;
use crate::entropy::UniversalEntropyHarvester;
use crate::format::encode_rfs4_footer_n_way;
use crate::naming::determine_split_paths;
use crate::telemetry::{Telemetry, TelemetryMode};
use crate::types::BLKS_DIGEST_SIZE;

/// Job for the asynchronous I/O writer in split mode
pub(crate) struct WriteJob {
    pub(crate) bufs: Vec<Vec<u8>>,
    pub(crate) valid_len: usize,
}

/// Splits a file or stream into N One-Time-Pad shares with plausible deniability.
///
/// - $N$-Way One-Time-Pad Chain: $P = C_1 \oplus C_2 \oplus \dots \oplus C_N$
/// - Decoupled 3-stage pipeline (Reader ➔ Crypto/SIMD ➔ Writer) with zero-allocation buffer pooling
/// - RFS4 format with embedded original filename, 4 KiB cluster padding, and optional `--pad-to`
/// - Machine-readable NDJSON telemetry (`--json`) and interactive ANSI progress bars
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
    mlock: bool,
) -> Result<Vec<PathBuf>, String> {
    // 1. Determine destination paths (<token6>.rfs default for maximum OPSEC)
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
                    "Output file '{}' already exists. Use --force to overwrite.",
                    path.display()
                ));
            }
        }
    }

    // 2. Prepare input (stdin or file)
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
                "Input file '{}' does not exist.",
                in_path.display()
            ));
        }
        let f = File::open(in_path).map_err(|e| format!("Cannot open input file: {}", e))?;
        crate::fadvise::advise_sequential(&f);
        let len = f
            .metadata()
            .map_err(|e| format!("Cannot read file metadata: {}", e))?
            .len();
        (Box::new(f), Some(len))
    };

    // 3. Open output files
    let mut files: Vec<File> = Vec::with_capacity(n_parts);
    for (idx, p) in out_paths.iter().enumerate() {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(p)
            .map_err(|e| {
                format!(
                    "Cannot create output file {} ('{}'): {}",
                    idx + 1,
                    p.display(),
                    e
                )
            })?;
        crate::fadvise::advise_sequential(&f);
        files.push(f);
    }

    // 4. Initialize entropy & ChaCha20 CSPRNG
    let (mut master_key, mut master_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&master_key, &master_nonce);
    master_key.zeroize();
    master_nonce.zeroize();

    // 5. Channels for decoupled 3-stage pipeline & buffer pools
    let (free_in_tx, free_in_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(BUFFER_POOL_SIZE);
    let mut locked_in_count = 0;
    for _ in 0..BUFFER_POOL_SIZE {
        let buf = vec![0u8; block_size];
        if mlock && crate::memlock::lock_memory(&buf) {
            locked_in_count += 1;
        }
        free_in_tx.send(buf).unwrap();
    }

    let (data_tx, data_rx): (
        Sender<Result<(Vec<u8>, usize), String>>,
        Receiver<Result<(Vec<u8>, usize), String>>,
    ) = bounded(2);

    let (free_out_tx, free_out_rx): (Sender<Vec<Vec<u8>>>, Receiver<Vec<Vec<u8>>>) =
        bounded(BUFFER_POOL_SIZE);
    let mut locked_out_count = 0;
    for _ in 0..BUFFER_POOL_SIZE {
        let mut slot = Vec::with_capacity(n_parts);
        for _ in 0..n_parts {
            let buf = vec![0u8; block_size];
            if mlock && crate::memlock::lock_memory(&buf) {
                locked_out_count += 1;
            }
            slot.push(buf);
        }
        free_out_tx.send(slot).unwrap();
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
        Sender<Result<WriteJob, String>>,
        Receiver<Result<WriteJob, String>>,
    ) = bounded(2);

    // Stage 1: Reader thread (fills buffers up to full block size or EOF)
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
                        let _ = data_tx.send(Err(format!("Read error on input: {}", e)));
                        return Err(format!("Read error on input: {}", e));
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

    // Stage 2: Crypto & Hash worker thread (N-Way OTP)
    let mut telemetry = Telemetry::new(telemetry_mode, "Split", known_size);
    let worker_handle = thread::spawn(move || -> Result<(u64, [u8; BLKS_DIGEST_SIZE]), String> {
        let mut total_processed: u64 = 0;
        let mut blks_hasher = BlksHasher::new();

        while let Ok(msg) = data_rx.recv() {
            let (mut in_buf, len) = msg?;

            // 1. In-flight BLKS-384 hashing
            blks_hasher.update(&in_buf[..len]);

            // 2. Request free output buffers (N buffers)
            let mut part_bufs = free_out_rx
                .recv()
                .map_err(|_| "Writer thread terminated prematurely".to_string())?;

            // 3. Fill shares 2..N with ChaCha20-CSPRNG keystream
            for buf in part_bufs.iter_mut().take(n_parts).skip(1) {
                rng.fill_bytes(&mut buf[..len]);
            }

            // 4. Share 1 completes XOR chain: part_bufs[0] = in_buf ^ part_bufs[1] ^ ... ^ part_bufs[N-1]
            part_bufs[0][..len].copy_from_slice(&in_buf[..len]);
            for k in 1..n_parts {
                let (first, rest) = part_bufs.split_at_mut(k);
                xor_in_place(&mut first[0][..len], &rest[0][..len]);
            }

            // 5. Recycle input buffer to reader pool (zeroization)
            in_buf.as_mut_slice().zeroize();
            let _ = free_in_tx.send(in_buf);

            total_processed += len as u64;

            // 6. Forward job to writer thread
            if job_tx
                .send(Ok(WriteJob {
                    bufs: part_bufs,
                    valid_len: len,
                }))
                .is_err()
            {
                return Err("Writer thread terminated prematurely".to_string());
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

    // Stage 3: Parallel N-Way writer worker pool (Parallel Disk Fanout)
    let writer_handle = thread::spawn(move || -> Result<(), String> {
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
                let mut writer = BufWriter::with_capacity(block_size, file);
                while let Ok(Some((buf, valid_len, offset))) = rx.recv() {
                    if let Err(e) = writer.write_all(&buf[..valid_len]) {
                        let err_msg = format!("Write error on share {}: {}", k + 1, e);
                        let _ = done_tx_clone.send((k, Err(err_msg.clone())));
                        return Err(err_msg);
                    }
                    if direct_io {
                        crate::fadvise::advise_drop_cache(
                            writer.get_ref(),
                            offset as i64,
                            valid_len as i64,
                        );
                    }
                    let _ = done_tx_clone.send((k, Ok(buf)));
                }
                writer
                    .flush()
                    .map_err(|e| format!("Flush error on share {}: {}", k + 1, e))?;
                Ok(())
            });
            worker_handles.push(handle);
        }
        drop(done_tx);

        let mut total_written: u64 = 0;

        while let Ok(job_res) = job_rx.recv() {
            let WriteJob { bufs, valid_len } = job_res?;

            // 1. Distribute chunks concurrently to all N workers
            for (k, buf) in bufs.into_iter().enumerate() {
                if part_txs[k]
                    .send(Some((buf, valid_len, total_written)))
                    .is_err()
                {
                    return Err(format!(
                        "Worker thread for share {} terminated prematurely",
                        k + 1
                    ));
                }
            }

            // 2. Await completion of all N workers for this block
            let mut collected_bufs = vec![Vec::new(); n_parts];
            for _ in 0..n_parts {
                match done_rx.recv() {
                    Ok((k, Ok(buf))) => {
                        collected_bufs[k] = buf;
                    }
                    Ok((_k, Err(e))) => {
                        return Err(e);
                    }
                    Err(_) => {
                        return Err("Unexpected channel disconnect during disk fanout".to_string());
                    }
                }
            }

            total_written += valid_len as u64;
            let _ = free_out_tx.send(collected_bufs);
        }

        // Signal EOF to all workers
        for tx in part_txs {
            let _ = tx.send(None);
        }

        // Await clean exit of all worker threads
        for (k, handle) in worker_handles.into_iter().enumerate() {
            handle
                .join()
                .map_err(|_| format!("Writer worker for share {} panicked", k + 1))??;
        }

        Ok(())
    });

    // Await completion of all main pipeline threads
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
    let (total_processed, digest) = worker_res?;
    writer_res?;

    // 6. Encode RFS4 stealth footer & padding, then append to all N shares
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
            .map_err(|e| format!("Cannot open share {} for footer: {}", k + 1, e))?;
        append_file
            .write_all(&footers[k])
            .map_err(|e| format!("Error writing footer on share {}: {}", k + 1, e))?;
        append_file
            .flush()
            .map_err(|e| format!("Flush error on footer {}: {}", k + 1, e))?;
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
            "Successfully split into {} shares (N-Way OTP, RFS4):",
            n_parts
        );
        eprintln!("  Embedded name: {}", original_filename);
        eprintln!("  Original size: {} bytes", total_processed);
        eprintln!("  Share size (4 KiB cluster padding): {} bytes", share_size);
        eprintln!("  BLKS-384: {}", BlksDigest(digest).to_base64());

        if !decoy_paths.is_empty() {
            eprintln!("\nReal shares (N={}, randomized across set):", n_parts);
            for (i, p) in out_paths.iter().enumerate() {
                eprintln!("  Share {}: {}", i + 1, p.display());
            }

            eprintln!(
                "\nDecoy chaff files (D={}, 100% ChaCha20 random noise):",
                decoy_paths.len()
            );
            for (i, p) in decoy_paths.iter().enumerate() {
                eprintln!("  Decoy {}: {} ({} bytes)", i + 1, p.display(), share_size);
            }
        } else {
            eprintln!("\nGenerated shares:");
            for (i, p) in out_paths.iter().enumerate() {
                eprintln!("  Share {}: {}", i + 1, p.display());
            }
        }
    }

    Ok(out_paths)
}

/// Convenience wrapper for backward compatibility (2 shares).
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
        false,
    )?;
    Ok((parts[0].clone(), parts[1].clone()))
}
