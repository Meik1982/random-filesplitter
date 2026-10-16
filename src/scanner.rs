//! Combinatorial Auto-Discovery and Assembly Engine (`rfs scan`).
//! Rapidly evaluates combinations of candidate files via tail-seeking (64-byte trailer XOR)
//! to detect valid N-Way OTP shares and reconstruct original files without brute-force I/O.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::format::{decode_footer_n_way, RfsMetadata};
use crate::telemetry::format_bytes;

/// Maximum tail bytes read from each file for footer and embedded filename inspection.
const SCAN_TAIL_SIZE: usize = 1024;

/// Represents a validated combinatorial match found among candidate files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredMatch {
    /// Full paths to the real shares that compose this payload
    pub shares: Vec<PathBuf>,
    /// Decoded RFS metadata (filename, original size, BLKS-384 hash)
    pub metadata: RfsMetadata,
    /// Size of each share in bytes
    pub share_size: u64,
}

struct Candidate {
    path: PathBuf,
    size: u64,
    tail: Vec<u8>,
}

/// Expands any directory paths in `input_paths` into their direct regular file entries,
/// while keeping explicit file paths intact.
pub fn expand_candidate_paths(input_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut expanded = Vec::new();
    for p in input_paths {
        if p.is_dir() {
            if let Ok(entries) = fs::read_dir(p) {
                let mut dir_files: Vec<PathBuf> = entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|ep| ep.is_file())
                    .collect();
                dir_files.sort();
                expanded.extend(dir_files);
            }
        } else if p.is_file() {
            expanded.push(p.clone());
        }
    }
    expanded
}

/// Scans a list of candidate files (or directories), tests combinations, and returns all validated matches.
pub fn scan_candidate_files(candidate_paths: &[PathBuf]) -> Result<Vec<DiscoveredMatch>, String> {
    let expanded_paths = expand_candidate_paths(candidate_paths);
    if expanded_paths.len() < 2 {
        return Err("At least 2 candidate files required for scanning.".to_string());
    }

    // 1. Ingest tails: Read only the last 1024 bytes of each file
    let mut candidates: Vec<Candidate> = Vec::with_capacity(expanded_paths.len());
    for p in &expanded_paths {
        if !p.is_file() {
            continue;
        }
        let meta = match fs::metadata(p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let size = meta.len();
        if size < 64 {
            continue;
        }

        let mut f = match File::open(p) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let tail_len = (size as usize).min(SCAN_TAIL_SIZE);
        if f.seek(SeekFrom::End(-(tail_len as i64))).is_err() {
            continue;
        }

        let mut tail = vec![0u8; tail_len];
        if f.read_exact(&mut tail).is_err() {
            continue;
        }

        candidates.push(Candidate {
            path: p.clone(),
            size,
            tail,
        });
    }

    if candidates.len() < 2 {
        return Ok(Vec::new());
    }

    // 2. Group by identical file size
    // In RFS4, genuine shares of the same split have 100% identical byte sizes due to 4 KiB padding.
    let mut size_groups: HashMap<u64, Vec<Candidate>> = HashMap::new();
    for c in candidates {
        size_groups.entry(c.size).or_default().push(c);
    }

    let mut discovered: Vec<DiscoveredMatch> = Vec::new();

    // 3. Test combinations within each size group
    for (&share_size, group) in &size_groups {
        let m = group.len();
        if m < 2 {
            continue;
        }

        // Limit k to avoid excessive combinatorial growth if large groups exist
        let max_k = m.min(16);
        for k in 2..=max_k {
            test_combinations(group, k, share_size, &mut discovered);
        }
    }

    Ok(discovered)
}

fn test_combinations(
    group: &[Candidate],
    k: usize,
    share_size: u64,
    results: &mut Vec<DiscoveredMatch>,
) {
    let n = group.len();
    let mut indices: Vec<usize> = (0..k).collect();

    loop {
        // Fast 64-byte tail check before running full decoder
        let tails: Vec<&[u8]> = indices
            .iter()
            .map(|&idx| group[idx].tail.as_slice())
            .collect();

        if let Ok(meta) = decode_footer_n_way(&tails) {
            // Verify sanity: Original size must not exceed share size (0-byte files are valid)
            if meta.original_size() <= share_size {
                let valid_fn = if let Some(fn_str) = meta.filename() {
                    !fn_str.is_empty()
                        && fn_str.len() <= 255
                        && fn_str != "."
                        && fn_str != ".."
                        && !fn_str.chars().any(|c| {
                            c.is_control()
                                || c == '/'
                                || c == '\\'
                                || c == '?'
                                || c == '<'
                                || c == '>'
                                || c == ':'
                                || c == ';'
                                || c == '='
                        })
                } else {
                    true
                };

                if valid_fn {
                    let shares: Vec<PathBuf> =
                        indices.iter().map(|&idx| group[idx].path.clone()).collect();

                    // Cryptographic validation: verify that the XORed data actually matches the BLKS-384 hash.
                    // This strictly eliminates linear ghost/phantom combinations over GF(2).
                    let is_authentic = crate::pipeline::restore_file(
                        &shares,
                        None,
                        false,
                        crate::telemetry::TelemetryMode::Silent,
                        true,
                        crate::types::DEFAULT_BLOCK_SIZE,
                        false,
                        false,
                    )
                    .is_ok();

                    if is_authentic {
                        // Prevent duplicate subsets
                        let already_found = results.iter().any(|r| {
                            r.shares.len() == shares.len()
                                && r.shares.iter().all(|s| shares.contains(s))
                        });

                        if !already_found {
                            results.push(DiscoveredMatch {
                                shares,
                                metadata: meta,
                                share_size,
                            });
                        }
                    }
                }
            }
        }

        // Move to next combination in lexicographical order
        let mut i = k;
        while i > 0 && indices[i - 1] == n - k + (i - 1) {
            i -= 1;
        }
        if i == 0 {
            break;
        }
        indices[i - 1] += 1;
        for j in i..k {
            indices[j] = indices[j - 1] + 1;
        }
    }
}

/// Runs full CLI scan and formats output report.
pub fn run_cli_scan(
    paths: &[PathBuf],
    restore: bool,
    output_dir: Option<&Path>,
    force: bool,
) -> Result<i32, String> {
    let lang = crate::i18n::current_lang();
    let tr = lang.tr();
    let expanded = expand_candidate_paths(paths);
    let n_cand = expanded.len();

    println!("============================================================");
    match lang {
        crate::i18n::Lang::En => {
            println!(" RFS Combinatorial Scanner (Auto-Discovery & Assembly)");
            println!("============================================================\n");
            println!(
                "Scanning {} candidate files for valid N-Way OTP sets...",
                n_cand
            );
        }
        crate::i18n::Lang::De => {
            println!(" RFS Kombinatorischer Scanner (Auto-Erkennung & Rekonstruktion)");
            println!("============================================================\n");
            println!(
                "Scanne {} Kandidatendateien nach gültigen N-Way OTP Sets...",
                n_cand
            );
        }
        crate::i18n::Lang::Es => {
            println!(" Escáner Combinatorio RFS (Auto-Descubrimiento y Ensamblaje)");
            println!("============================================================\n");
            println!(
                "Escaneando {} archivos candidatos en busca de conjuntos OTP válidos...",
                n_cand
            );
        }
        crate::i18n::Lang::Fr => {
            println!(" Scanner Combinatoire RFS (Auto-Découverte & Assemblage)");
            println!("============================================================\n");
            println!(
                "Analyse de {} fichiers candidats pour trouver des ensembles OTP valides...",
                n_cand
            );
        }
        crate::i18n::Lang::Ja => {
            println!(" RFS 組み合わせスキャナ (自動検出 & アセンブリ)");
            println!("============================================================\n");
            println!(
                "{} 個の候補ファイルから有効な N-Way OTP セットをスキャン中...",
                n_cand
            );
        }
        crate::i18n::Lang::Zh => {
            println!(" RFS 组合扫描器（自动发现与重组）");
            println!("============================================================\n");
            println!(
                "正在扫描 {} 个候选文件以寻找有效的 N-Way OTP 分片组合...",
                n_cand
            );
        }
        crate::i18n::Lang::Tok => {
            println!(" ilo alasa RFS (alasa & wan sin)");
            println!("============================================================\n");
            println!("ilo li alasa e kulupu kipisi pona lon lipu {}...", n_cand);
        }
        crate::i18n::Lang::Sp => {
            println!(" 󱤎 󱤃 RFS (󱤃 & 󱥳 󱥝)");
            println!("============================================================\n");
            println!("󱤎 󱤧 󱤃 󱤉 󱤟 󱥻 󱥔 󱤬 󱤪 {}...", n_cand);
        }
    }

    let matches = scan_candidate_files(paths)?;

    if matches.is_empty() {
        println!("\n{}", tr.restore_status_no_sets);
        println!("{}", tr.restore_detected_all_noise);
        return Ok(0);
    }

    match lang {
        crate::i18n::Lang::En => println!(
            "\n🎯 Discovered Payloads ({} valid sets detected):\n",
            matches.len()
        ),
        crate::i18n::Lang::De => println!(
            "\n🎯 Entdeckte Payloads ({} gültige Sets erkannt):\n",
            matches.len()
        ),
        crate::i18n::Lang::Es => println!(
            "\n🎯 Archivos descubiertos ({} conjuntos válidos detectados):\n",
            matches.len()
        ),
        crate::i18n::Lang::Fr => println!(
            "\n🎯 Fichiers découverts ({} ensembles valides détectés) :\n",
            matches.len()
        ),
        crate::i18n::Lang::Ja => println!(
            "\n🎯 検出されたペイロード ({} 個の有効なセットを検出):\n",
            matches.len()
        ),
        crate::i18n::Lang::Zh => println!(
            "\n🎯 发现的载荷文件（检测到 {} 个有效组合）：\n",
            matches.len()
        ),
        crate::i18n::Lang::Tok => {
            println!("\n🎯 lipu len li lon (kulupu pona {}):\n", matches.len())
        }
        crate::i18n::Lang::Sp => println!("\n🎯 󱤪 󱤥 󱤧 󱤬 (󱤟 󱥔 {}):\n", matches.len()),
    }

    for (idx, m) in matches.iter().enumerate() {
        println!("------------------------------------------------------------");
        let orig_name = m.metadata.filename().unwrap_or("unnamed");
        let orig_size_fmt = format_bytes(m.metadata.original_size());
        let share_size_fmt = format_bytes(m.share_size);

        match lang {
            crate::i18n::Lang::En => {
                println!(
                    " Set #{}: Original: \"{}\" ({})",
                    idx + 1,
                    orig_name,
                    orig_size_fmt
                );
                println!(
                    "       Share size:  {} (4 KiB cluster padding)",
                    share_size_fmt
                );
            }
            crate::i18n::Lang::De => {
                println!(
                    " Set #{}: Original: \"{}\" ({})",
                    idx + 1,
                    orig_name,
                    orig_size_fmt
                );
                println!(
                    "       Share-Größe: {} (4 KiB Cluster-Padding)",
                    share_size_fmt
                );
            }
            crate::i18n::Lang::Es => {
                println!(
                    " Conjunto #{}: Original: \"{}\" ({})",
                    idx + 1,
                    orig_name,
                    orig_size_fmt
                );
                println!(
                    "       Tamaño parte: {} (relleno de bloque 4 KiB)",
                    share_size_fmt
                );
            }
            crate::i18n::Lang::Fr => {
                println!(
                    " Ensemble #{} : Original : \"{}\" ({})",
                    idx + 1,
                    orig_name,
                    orig_size_fmt
                );
                println!("       Taille part : {} (alignement 4 Kio)", share_size_fmt);
            }
            crate::i18n::Lang::Ja => {
                println!(
                    " セット #{}: 元ファイル: \"{}\" ({})",
                    idx + 1,
                    orig_name,
                    orig_size_fmt
                );
                println!("       シェアサイズ: {} (4 KiB パディング)", share_size_fmt);
            }
            crate::i18n::Lang::Zh => {
                println!(
                    " 组合 #{}: 原始文件: \"{}\" ({})",
                    idx + 1,
                    orig_name,
                    orig_size_fmt
                );
                println!("       分片大小:    {} (4 KiB 簇对齐)", share_size_fmt);
            }
            crate::i18n::Lang::Tok => {
                println!(
                    " kulupu #{}: lipu open: \"{}\" ({})",
                    idx + 1,
                    orig_name,
                    orig_size_fmt
                );
                println!("       suli kipisi: {} (4 KiB)", share_size_fmt);
            }
            crate::i18n::Lang::Sp => {
                println!(
                    " 󱤟 #{}: 󱤪 󱥇: \"{}\" ({})",
                    idx + 1,
                    orig_name,
                    orig_size_fmt
                );
                println!("       󱥣 󱥻:        {} (4 KiB)", share_size_fmt);
            }
        }

        match &m.metadata {
            RfsMetadata::Rfs4 { expected_blks, .. } | RfsMetadata::Rfs3 { expected_blks, .. } => {
                println!(
                    "       BLKS-384:    {}",
                    blks_core::encode_base64_url(expected_blks)
                );
            }
            RfsMetadata::Rfs2 {
                expected_sha256, ..
            } => {
                let hex_str: String = expected_sha256
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                println!("       SHA-256:     {}", hex_str);
            }
        }

        match lang {
            crate::i18n::Lang::En => println!("       Valid shares ({} parts):", m.shares.len()),
            crate::i18n::Lang::De => println!("       Gültige Shares ({} Teile):", m.shares.len()),
            crate::i18n::Lang::Es => println!("       Partes válidas ({} partes):", m.shares.len()),
            crate::i18n::Lang::Fr => println!("       Parts valides ({} parts) :", m.shares.len()),
            crate::i18n::Lang::Ja => println!("       有効なシェア ({} 個):", m.shares.len()),
            crate::i18n::Lang::Zh => println!("       有效分片（{} 个分片）：", m.shares.len()),
            crate::i18n::Lang::Tok => println!("       kipisi pona (kipisi {}):", m.shares.len()),
            crate::i18n::Lang::Sp => println!("       󱥻 󱥔 (󱥻 {}):", m.shares.len()),
        }
        for (si, sp) in m.shares.iter().enumerate() {
            println!("         [{}] {}", si + 1, sp.display());
        }

        if restore {
            match lang {
                crate::i18n::Lang::En => println!("\n       Reconstructing Set #{}...", idx + 1),
                crate::i18n::Lang::De => println!("\n       Rekonstruiere Set #{}...", idx + 1),
                crate::i18n::Lang::Es => {
                    println!("\n       Reconstruyendo Conjunto #{}...", idx + 1)
                }
                crate::i18n::Lang::Fr => {
                    println!("\n       Reconstruction de l'ensemble #{}...", idx + 1)
                }
                crate::i18n::Lang::Ja => println!("\n       セット #{} を復元中...", idx + 1),
                crate::i18n::Lang::Zh => println!("\n       正在重构组合 #{}...", idx + 1),
                crate::i18n::Lang::Tok => {
                    println!("\n       ilo li wan sin e kulupu #{}...", idx + 1)
                }
                crate::i18n::Lang::Sp => println!("\n       󱤎 󱤧 󱥳 󱥝 󱤉 󱤟 #{}...", idx + 1),
            }
            let out_target = output_dir.map(|d| d.join(orig_name));
            let out_target_str = out_target.as_ref().map(|p| p.to_string_lossy().to_string());

            match crate::pipeline::restore_file(
                &m.shares,
                out_target_str.as_deref(),
                force,
                crate::telemetry::TelemetryMode::Silent,
                false,
                crate::types::DEFAULT_BLOCK_SIZE,
                false,
                false,
            ) {
                Ok(Some(restored)) => {
                    println!(
                        "       ✅ {}",
                        tr.format_cli_restored(lang, &restored.display().to_string())
                    );
                }
                Ok(None) => {
                    println!("       ✅ {}", tr.restore_badge_valid);
                }
                Err(e) => {
                    eprintln!("       ❌ {}: {}", tr.restore_badge_mismatch, e);
                }
            }
        }
    }
    println!("------------------------------------------------------------\n");

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_combinatorial_scanner_detects_real_and_ignores_decoys() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secret.txt");
        fs::write(&file_path, b"Top secret document contents for scanning!").unwrap();

        // Split into 3 real shares + 2 decoys
        let split_res = crate::pipeline::split_stream_or_file(
            file_path.to_str().unwrap(),
            None,
            3,
            2,
            None,
            None,
            None,
            crate::types::MIN_BLOCK_SIZE,
            crate::telemetry::TelemetryMode::Silent,
            false,
            false,
            false,
        )
        .unwrap();

        assert_eq!(split_res.real_shares.len(), 3);
        assert_eq!(split_res.decoy_shares.len(), 2);

        // Mix real shares and decoys together
        let mut all_files = split_res.real_shares.clone();
        all_files.extend(split_res.decoy_shares.clone());
        assert_eq!(all_files.len(), 5);

        // Scan all 5 files: Must find exactly the 1 real 3-way combination!
        let discovered = scan_candidate_files(&all_files).unwrap();
        assert_eq!(discovered.len(), 1, "Must find exactly 1 valid payload set");
        assert_eq!(
            discovered[0].shares.len(),
            3,
            "Payload set must consist of 3 shares"
        );
        assert_eq!(discovered[0].metadata.filename(), Some("secret.txt"));
        assert_eq!(discovered[0].metadata.original_size(), 42);
    }

    #[test]
    fn test_scanner_accepts_directory_path_and_zero_byte_payload() {
        let dir = tempdir().unwrap();
        let empty_file = dir.path().join("empty_marker.dat");
        fs::write(&empty_file, b"").unwrap();

        let shares_dir = dir.path().join("shares_out");
        fs::create_dir_all(&shares_dir).unwrap();

        let split_res = crate::pipeline::split_stream_or_file(
            empty_file.to_str().unwrap(),
            None,
            2,
            1,
            None,
            None,
            Some(shares_dir.to_str().unwrap()),
            crate::types::MIN_BLOCK_SIZE,
            crate::telemetry::TelemetryMode::Silent,
            false,
            false,
            false,
        )
        .unwrap();

        assert_eq!(split_res.real_shares.len(), 2);

        // Pass the directory path itself (not expanded glob files) to scan_candidate_files
        let discovered = scan_candidate_files(&[shares_dir]).unwrap();
        assert_eq!(
            discovered.len(),
            1,
            "Scanner must expand directory and discover 0-byte payload"
        );
        assert_eq!(discovered[0].metadata.filename(), Some("empty_marker.dat"));
        assert_eq!(discovered[0].metadata.original_size(), 0);
    }

    #[test]
    fn test_single_file_split_rejects_mismatched_threshold() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("single.bin");
        fs::write(&f, b"hello").unwrap();

        let res = crate::cli::parser::parse_args([
            "rfs",
            "split",
            f.to_str().unwrap(),
            "-n",
            "5",
            "-T",
            "3",
        ]);
        assert!(
            res.is_err(),
            "Single-file split with -T 3 != -n 5 must return an error instead of silently creating a 5-of-5 split"
        );
    }
}
