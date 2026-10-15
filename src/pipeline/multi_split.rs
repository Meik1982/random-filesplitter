//! Multi-Payload Streaming Pipeline for RFS-Matrix over GF(2).
//! Simultaneously embeds K arbitrary plaintext files into M shares such that
//! each specified T-sized subset reconstructs its assigned payload with 100% BLKS-384 integrity.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::{xor_in_place, ChaChaRng};
use crate::decoy::write_decoy_files_to_paths;
use crate::entropy::UniversalEntropyHarvester;
use crate::matrix::policy::MatrixPolicy;
use crate::matrix::solver::solve_matrix_policy;
use crate::matrix::trailer::{synthesize_multi_target_trailers, TargetPayloadMeta};
use crate::naming::{generate_unique_hex_tokens, shuffle_paths};
use crate::telemetry::{format_bytes, Telemetry, TelemetryMode};
use crate::types::{RFS4_ALIGN_BLOCK_SIZE, RFS4_TRAILER_SIZE};
use blks_core::BlksHasher;

/// Result of a multi-payload split operation.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MultiSplitResult {
    pub share_paths: Vec<PathBuf>,
    pub payload_subsets: Vec<(String, Vec<PathBuf>)>,
    pub share_size: u64,
    pub decoy_paths: Vec<PathBuf>,
}

#[allow(clippy::too_many_arguments)]
pub fn split_multi_payloads(
    payload_paths: &[PathBuf],
    num_shares: usize,
    threshold: Option<usize>,
    num_decoys: usize,
    output_dir: Option<&Path>,
    block_size: usize,
    telemetry_mode: TelemetryMode,
    force: bool,
    direct_io: bool,
    mlock: bool,
) -> Result<MultiSplitResult, String> {
    if payload_paths.is_empty() {
        return Err("At least 1 payload file required for split".to_string());
    }

    let k = payload_paths.len();
    let m = num_shares;
    let t = threshold.unwrap_or_else(|| {
        if k == 1 {
            m
        } else {
            (m.saturating_sub(1)).max(2)
        }
    });

    if t < 2 || t > m {
        return Err(format!(
            "Threshold T ({}) must be between 2 and total shares M ({})",
            t, m
        ));
    }
    if k > m {
        return Err(format!(
            "Cannot embed {} payloads into {} shares over GF(2) (maximum is M = {})",
            k, m, m
        ));
    }

    // 1. Inspect input files
    let mut payload_names = Vec::new();
    let mut payload_sizes = Vec::new();

    for path in payload_paths {
        if !path.exists() {
            return Err(format!("Payload file '{}' does not exist.", path.display()));
        }
        let meta = fs::metadata(path)
            .map_err(|e| format!("Cannot read metadata of '{}': {}", path.display(), e))?;
        payload_sizes.push(meta.len());
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("payload.bin")
            .to_string();
        payload_names.push(name);
    }

    let max_payload_size = *payload_sizes.iter().max().unwrap_or(&0);

    // 2. Compute aligned share size (4 KiB cluster padding)
    let min_tail_len = payload_names
        .iter()
        .map(|n| n.len() + RFS4_TRAILER_SIZE)
        .max()
        .unwrap_or(RFS4_TRAILER_SIZE);

    let min_total_size = max_payload_size + min_tail_len as u64;
    let rem = min_total_size % RFS4_ALIGN_BLOCK_SIZE as u64;
    let share_size = if rem == 0 {
        min_total_size + RFS4_ALIGN_BLOCK_SIZE as u64
    } else {
        min_total_size + (RFS4_ALIGN_BLOCK_SIZE as u64 - rem)
    };
    let payload_stream_size = share_size - min_tail_len as u64;

    // 3. Design Matrix Policy and solve linear system over GF(2)
    let (policy, subsets) = MatrixPolicy::create_multi_payload_policy(m, t, &payload_names)?;
    let solved = solve_matrix_policy(&policy)?;

    // 4. Generate destination share paths (<token6>.rfs)
    let default_parent = payload_paths[0]
        .parent()
        .filter(|p| !p.as_os_str().is_empty());
    let out_dir = output_dir
        .or(default_parent)
        .unwrap_or_else(|| Path::new("."));
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)
            .map_err(|e| format!("Cannot create output dir '{}': {}", out_dir.display(), e))?;
    }

    let total_files = m + num_decoys;
    let tokens = generate_unique_hex_tokens(total_files);
    let mut all_paths: Vec<PathBuf> = tokens
        .into_iter()
        .map(|tok| out_dir.join(format!("{}.rfs", tok)))
        .collect();

    if num_decoys > 0 {
        shuffle_paths(&mut all_paths);
    }

    let share_paths = all_paths[0..m].to_vec();
    let decoy_paths = all_paths[m..total_files].to_vec();

    if !force {
        for path in share_paths.iter().chain(decoy_paths.iter()) {
            if path.exists() {
                return Err(format!(
                    "Output file '{}' already exists. Use --force to overwrite.",
                    path.display()
                ));
            }
        }
    }

    // 5. Open output writers
    let mut share_writers = Vec::new();
    for path in &share_paths {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("Cannot open share '{}': {}", path.display(), e))?;
        crate::fadvise::advise_sequential(&file);
        share_writers.push(BufWriter::with_capacity(block_size.min(1024 * 1024), file));
    }

    // 6. Open input readers and initialize hashers
    let mut payload_readers = Vec::new();
    let mut hashers = Vec::new();
    for path in payload_paths {
        let f = File::open(path)
            .map_err(|e| format!("Cannot open input '{}': {}", path.display(), e))?;
        crate::fadvise::advise_sequential(&f);
        payload_readers.push(BufReader::with_capacity(block_size.min(1024 * 1024), f));
        hashers.push(BlksHasher::new());
    }

    let (mut rng_key, mut rng_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut csprng = ChaChaRng::new(&rng_key, &rng_nonce);
    rng_key.zeroize();
    rng_nonce.zeroize();

    let num_bases = solved.num_random_bases;
    let mut bytes_processed = 0u64;

    let mut chunk_p = vec![vec![0u8; block_size]; k];
    let mut chunk_b = vec![vec![0u8; block_size]; num_bases];
    let mut chunk_c = vec![vec![0u8; block_size]; m];

    if mlock {
        let mut locked_count = 0usize;
        for buf in chunk_p.iter().chain(chunk_b.iter()).chain(chunk_c.iter()) {
            if crate::memlock::lock_memory(buf) {
                locked_count += 1;
            }
        }
        if telemetry_mode == TelemetryMode::Interactive {
            if locked_count > 0 {
                eprintln!(
                    "[OPSEC] Memory locking active: {} matrix buffers locked in RAM ({}) - swap paging protected.",
                    locked_count,
                    format_bytes((locked_count * block_size) as u64)
                );
            } else {
                eprintln!(
                    "[WARNING] mlock denied (check ulimit -l). Continuing without swap locking."
                );
            }
        }
    }

    let mut telemetry = Telemetry::new(telemetry_mode, "MultiSplit", Some(payload_stream_size));

    // 7. Stream payload blocks and compute matrix shares
    while bytes_processed < payload_stream_size {
        let chunk_len = ((payload_stream_size - bytes_processed) as usize).min(block_size);

        // Read or pad each payload chunk
        for (i, reader) in payload_readers.iter_mut().enumerate() {
            let orig_len = payload_sizes[i];
            let buf = &mut chunk_p[i][..chunk_len];

            if bytes_processed < orig_len {
                let to_read = ((orig_len - bytes_processed) as usize).min(chunk_len);
                reader.read_exact(&mut buf[..to_read]).map_err(|e| {
                    format!("Read error on '{}': {}", payload_paths[i].display(), e)
                })?;
                hashers[i].update(&buf[..to_read]);
                if to_read < chunk_len {
                    csprng.fill_bytes(&mut buf[to_read..]);
                }
            } else {
                csprng.fill_bytes(buf);
            }
        }

        // Generate random basis blocks
        for b_buf in &mut chunk_b {
            csprng.fill_bytes(&mut b_buf[..chunk_len]);
        }

        // Compute linear combination for each share C_i:
        // C_i = XOR_{j: G[i,j]=1} b_j  XOR  XOR_{p: H[i,p]=1} p
        for i in 0..m {
            let out_slice = &mut chunk_c[i][..chunk_len];
            out_slice.fill(0);

            // Accumulate random bases
            for (j, b_buf) in chunk_b.iter().enumerate().take(num_bases) {
                if solved.g_matrix.get(i, j) {
                    xor_in_place(out_slice, &b_buf[..chunk_len]);
                }
            }

            // Accumulate payloads
            for (p, p_buf) in chunk_p.iter().enumerate().take(k) {
                if solved.h_matrix.get(i, p) {
                    xor_in_place(out_slice, &p_buf[..chunk_len]);
                }
            }

            share_writers[i]
                .write_all(out_slice)
                .map_err(|e| format!("Write error to '{}': {}", share_paths[i].display(), e))?;
            if direct_io {
                crate::fadvise::advise_drop_cache(
                    share_writers[i].get_ref(),
                    bytes_processed as i64,
                    chunk_len as i64,
                );
            }
        }

        bytes_processed += chunk_len as u64;
        telemetry.update(bytes_processed);
    }

    telemetry.finish(bytes_processed, m, None);

    // 8. Finalize BLKS-384 digests and prepare target trailer specifications
    let mut target_specs = Vec::new();
    for (i, hasher) in hashers.into_iter().enumerate() {
        let digest_bytes = hasher.finalize();

        target_specs.push(TargetPayloadMeta {
            original_size: payload_sizes[i],
            blks_digest: digest_bytes,
            filename: payload_names[i].clone(),
        });
    }

    // 9. Synthesize multi-target superposition trailers over GF(2)^512
    let share_trailers = synthesize_multi_target_trailers(&policy, &target_specs, &mut csprng)?;

    // 10. Append 64-byte trailers to each share and flush
    for i in 0..m {
        share_writers[i]
            .write_all(&share_trailers[i])
            .map_err(|e| {
                format!(
                    "Failed to write trailer to '{}': {}",
                    share_paths[i].display(),
                    e
                )
            })?;
        share_writers[i]
            .flush()
            .map_err(|e| format!("Flush error on '{}': {}", share_paths[i].display(), e))?;
    }

    // Cleanup buffers
    for buf in &mut chunk_p {
        buf.zeroize();
        if mlock {
            crate::memlock::unlock_memory(buf);
        }
    }
    for buf in &mut chunk_b {
        buf.zeroize();
        if mlock {
            crate::memlock::unlock_memory(buf);
        }
    }
    for buf in &mut chunk_c {
        buf.zeroize();
        if mlock {
            crate::memlock::unlock_memory(buf);
        }
    }

    // 10b. Write Chaff Decoys to pre-shuffled paths (if requested)
    if !decoy_paths.is_empty() {
        write_decoy_files_to_paths(
            &decoy_paths,
            share_size,
            block_size,
            telemetry_mode,
            direct_io,
        )?;
    }

    // 11. Prepare return data & user-facing report
    let mut payload_subsets: Vec<(String, Vec<PathBuf>)> = Vec::new();
    for (i, comb) in subsets.iter().enumerate() {
        let assigned_shares: Vec<PathBuf> =
            comb.iter().map(|&idx| share_paths[idx].clone()).collect();
        payload_subsets.push((payload_names[i].clone(), assigned_shares));
    }

    if telemetry_mode == TelemetryMode::Interactive {
        println!("============================================================");
        println!(
            " RFS Multi-Payload Split: {} Payloads -> {} Shares ({}-of-{})",
            k, m, t, m
        );
        println!("============================================================");
        println!(
            "Uniform share size (4 KiB cluster aligned): {}",
            format_bytes(share_size)
        );
        println!("\nGenerated Anonymous Shares:");
        for (i, p) in share_paths.iter().enumerate() {
            println!("  Share [{}]: {}", i + 1, p.display());
        }
        println!("\nCombinatorial Access Allocation:");
        for (name, shares) in &payload_subsets {
            let names_list = shares
                .iter()
                .map(|p| p.file_name().and_then(|n| n.to_str()).unwrap_or(""))
                .collect::<Vec<_>>()
                .join(", ");
            println!("  🎯 Payload: \"{}\"", name);
            println!(
                "     Required Shares ({}-Way): [{}]\n",
                shares.len(),
                names_list
            );
        }

        if !decoy_paths.is_empty() {
            println!(
                "\n🎭 Generated Decoy Chaff Files ({} noise files):",
                decoy_paths.len()
            );
            for (i, p) in decoy_paths.iter().enumerate() {
                println!("  Decoy [{}]: {}", i + 1, p.display());
            }
        }
    }

    Ok(MultiSplitResult {
        share_paths,
        payload_subsets,
        share_size,
        decoy_paths,
    })
}
