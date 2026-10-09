use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::ChaChaRng;
use crate::entropy::UniversalEntropyHarvester;
use crate::naming::generate_unique_hex_tokens;
use crate::telemetry::{Telemetry, TelemetryMode};
use crate::types::{self, RFS4_ALIGN_BLOCK_SIZE, RFS4_TRAILER_SIZE};

/// Analyzes a template file or explicit size specification to compute target decoy file size.
pub fn determine_decoy_size(
    template_path: Option<&Path>,
    explicit_size: Option<u64>,
    interactive: bool,
) -> Result<(u64, Option<String>), String> {
    if let Some(target) = explicit_size {
        if interactive {
            eprintln!(
                "[Decoy Analysis] Explicit target size specified: {} bytes ({}).",
                target,
                crate::telemetry::format_bytes(target)
            );
        }
        return Ok((target, None));
    }

    if let Some(path) = template_path {
        if !path.exists() {
            return Err(format!(
                "Template file '{}' does not exist.",
                path.display()
            ));
        }
        let meta = fs::metadata(path)
            .map_err(|e| format!("Cannot read metadata of '{}': {}", path.display(), e))?;
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
            let fn_len = file_name.len() as u64;
            let min_size = file_size + fn_len + RFS4_TRAILER_SIZE as u64;
            let rem = min_size % RFS4_ALIGN_BLOCK_SIZE as u64;
            let aligned = if rem == 0 {
                min_size + RFS4_ALIGN_BLOCK_SIZE as u64
            } else {
                min_size + (RFS4_ALIGN_BLOCK_SIZE as u64 - rem)
            };
            (aligned, false)
        };

        if interactive {
            eprintln!(
                "[Decoy Analysis] Template file: '{}' ({} bytes / {})",
                path.display(),
                file_size,
                crate::telemetry::format_bytes(file_size)
            );
            if rfs_detected {
                eprintln!("[Decoy Detection] Type: Existing RFS share (.rfs extension detected).");
                eprintln!(
                    "[Decoy Computation] Exact 1:1 match of share size: {} bytes.",
                    target_size
                );
            } else {
                eprintln!("[Decoy Detection] Type: Raw file (original plaintext).");
                eprintln!(
                    "[Decoy Computation] Factoring in RFS4 footer + 4 KiB cluster padding: {} bytes -> Target size: {} bytes.",
                    file_size, target_size
                );
                eprintln!(
                    "[Decoy Rationale] Decoy chaff files must have the exact same byte size as genuine RFS shares across transport networks."
                );
            }
        }

        let base_name = if is_rfs {
            if let Some(idx) = file_name.rfind(".rfs") {
                let suffix = &file_name[idx + 4..];
                if suffix.chars().all(|c| c.is_ascii_digit()) {
                    file_name[..idx].to_string()
                } else if let Some(before) = file_name.strip_suffix(".rfs") {
                    if let Some(dot_idx) = before.rfind('.') {
                        let tok = &before[dot_idx + 1..];
                        if (tok.len() == 4 || tok.len() == 6)
                            && tok.chars().all(|c| c.is_ascii_hexdigit())
                            || tok.starts_with("part")
                            || tok.starts_with("decoy")
                        {
                            before[..dot_idx].to_string()
                        } else {
                            before.to_string()
                        }
                    } else {
                        before.to_string()
                    }
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

    Err(
        "Please provide either a template file (-t <FILE>) or an explicit size (-s <SIZE>)."
            .to_string(),
    )
}

/// Writes pure ChaCha20 random noise to the specified destination file paths.
pub fn write_decoy_files_to_paths(
    decoy_paths: &[PathBuf],
    target_size: u64,
    block_size: usize,
    telemetry_mode: TelemetryMode,
    direct_io: bool,
) -> Result<(), String> {
    if decoy_paths.is_empty() {
        return Ok(());
    }
    let count = decoy_paths.len();

    let (mut key, mut nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&key, &nonce);
    key.zeroize();
    nonce.zeroize();

    let chunk_size = block_size.clamp(types::MIN_BLOCK_SIZE, types::MAX_BLOCK_SIZE);
    let mut buffer = vec![0u8; chunk_size];
    let total_all_decoys = target_size.saturating_mul(count as u64);

    let mut telemetry = Telemetry::new(telemetry_mode, "Decoy", Some(total_all_decoys));
    let mut processed_total: u64 = 0;

    for path in decoy_paths {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("Cannot create decoy file '{}': {}", path.display(), e))?;

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
                .map_err(|e| format!("Write error on decoy file '{}': {}", path.display(), e))?;

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
            .map_err(|e| format!("Flush error on decoy file '{}': {}", path.display(), e))?;
    }

    buffer.as_mut_slice().zeroize();
    telemetry.finish(processed_total, count, None);
    Ok(())
}

/// Generates an arbitrary number of decoy files filled with ChaCha20-CSPRNG random noise.
#[allow(clippy::too_many_arguments)]
pub fn generate_decoy_files(
    target_size: u64,
    count: usize,
    token_mode: bool,
    output_prefix: Option<&str>,
    _template_base: Option<&str>,
    block_size: usize,
    telemetry_mode: TelemetryMode,
    force: bool,
    direct_io: bool,
) -> Result<Vec<PathBuf>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > 1000 {
        return Err("Number of decoy files must not exceed 1000.".to_string());
    }

    let tokens = generate_unique_hex_tokens(count);

    // 1. Derive destination paths (<token6>.rfs for maximum OPSEC)
    let mut decoy_paths: Vec<PathBuf> = Vec::with_capacity(count);
    for idx in 1..=count {
        let t = &tokens[idx - 1];
        let path = if let Some(prefix) = output_prefix {
            if count == 1 && prefix.contains('.') {
                PathBuf::from(prefix)
            } else {
                let p = Path::new(prefix);
                if p.is_dir() || prefix.ends_with('/') {
                    p.join(format!("{}.rfs", t))
                } else {
                    PathBuf::from(format!("{}.{}.rfs", prefix, t))
                }
            }
        } else {
            PathBuf::from(format!("{}.rfs", t))
        };
        decoy_paths.push(path);
    }

    // 2. Collision detection
    for p in &decoy_paths {
        if p.exists() && !force {
            return Err(format!(
                "Decoy file '{}' already exists. Use -f / --force to overwrite.",
                p.display()
            ));
        }
    }

    write_decoy_files_to_paths(
        &decoy_paths,
        target_size,
        block_size,
        telemetry_mode,
        direct_io,
    )?;

    if telemetry_mode == TelemetryMode::Interactive {
        let mode_desc = if token_mode {
            "Token Mode"
        } else {
            "100% ChaCha20 random noise"
        };
        eprintln!(
            "Successfully generated {} decoy file(s) ({}):",
            count, mode_desc
        );
        for (i, p) in decoy_paths.iter().enumerate() {
            eprintln!("  Decoy {}: {} ({} bytes)", i + 1, p.display(), target_size);
        }
    }

    Ok(decoy_paths)
}
