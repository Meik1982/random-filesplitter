use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::ChaChaRng;
use crate::entropy::UniversalEntropyHarvester;
use crate::naming::generate_unique_hex_tokens;
use crate::telemetry::{Telemetry, TelemetryMode};
use crate::types::{self, RFS4_ALIGN_BLOCK_SIZE, RFS4_TRAILER_SIZE};

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
                    "[Decoy-Berechnung] RFS4-Footer + 4 KiB Cluster-Padding einkalkuliert: {} Bytes -> Zielgröße: {} Bytes.",
                    file_size, target_size
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

    Err("Bitte geben Sie entweder eine Musterdatei (-t <DATEI>) oder eine explizite Größe (-s <GRÖSSE>) an.".to_string())
}

/// Schreibt reines ChaCha20-Zufallsrauschen in die angegebenen Zieldateipfade.
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
    Ok(())
}

/// Erzeugt eine beliebige Anzahl von Köderdateien (Decoys) gefüllt mit ChaCha20-CSPRNG-Zufallsrauschen.
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
        return Err("Anzahl der Köderdateien darf höchstens 1000 betragen.".to_string());
    }

    let tokens = generate_unique_hex_tokens(count);

    // 1. Zieldateipfade ableiten (<token6>.rfs für maximale OPSEC)
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

    // 2. Kollisionsprüfung
    for p in &decoy_paths {
        if p.exists() && !force {
            return Err(format!(
                "Köderdatei '{}' existiert bereits. Verwenden Sie -f / --force zum Überschreiben.",
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
            "Token-Modus"
        } else {
            "100% ChaCha20-Zufallsrauschen"
        };
        eprintln!(
            "Erfolgreich {} Köderdatei(en) (Decoys) generiert ({}):",
            count, mode_desc
        );
        for (i, p) in decoy_paths.iter().enumerate() {
            eprintln!("  Köder {}: {} ({} Bytes)", i + 1, p.display(), target_size);
        }
    }

    Ok(decoy_paths)
}
