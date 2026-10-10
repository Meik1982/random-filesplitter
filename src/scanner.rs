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

/// Scans a list of candidate files, tests combinations, and returns all validated matches.
pub fn scan_candidate_files(candidate_paths: &[PathBuf]) -> Result<Vec<DiscoveredMatch>, String> {
    if candidate_paths.len() < 2 {
        return Err("At least 2 candidate files required for scanning.".to_string());
    }

    // 1. Ingest tails: Read only the last 1024 bytes of each file
    let mut candidates: Vec<Candidate> = Vec::with_capacity(candidate_paths.len());
    for p in candidate_paths {
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
            // Verify sanity: Original size must not exceed share size
            if meta.original_size() <= share_size {
                let shares: Vec<PathBuf> =
                    indices.iter().map(|&idx| group[idx].path.clone()).collect();

                // Prevent duplicate subsets
                let already_found = results.iter().any(|r| {
                    r.shares.len() == shares.len() && r.shares.iter().all(|s| shares.contains(s))
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
) -> Result<i32, String> {
    println!("============================================================");
    println!(" RFS Combinatorial Scanner (Auto-Discovery & Assembly)");
    println!("============================================================\n");
    println!(
        "Scanning {} candidate files for valid N-Way OTP sets...",
        paths.len()
    );

    let matches = scan_candidate_files(paths)?;

    if matches.is_empty() {
        println!("\n[Result] Keine passenden RFS-Kombinationen gefunden.");
        println!("Alle geprüften Dateien verhalten sich wie unkorreliertes Rauschen oder unvollständige Sets.");
        return Ok(0);
    }

    println!(
        "\n🎯 Gefundene Payloads ({} gültige Sets entdeckt):\n",
        matches.len()
    );

    for (idx, m) in matches.iter().enumerate() {
        println!("------------------------------------------------------------");
        let orig_name = m.metadata.filename().unwrap_or("unbenannt");
        println!(
            " Set #{}: Original: \"{}\" ({})",
            idx + 1,
            orig_name,
            format_bytes(m.metadata.original_size())
        );
        println!(
            "       Share-Größe: {} (4 KiB Cluster-Padding)",
            format_bytes(m.share_size)
        );
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
        println!("       Gültige Shares ({} Teile):", m.shares.len());
        for (si, sp) in m.shares.iter().enumerate() {
            println!("         [{}] {}", si + 1, sp.display());
        }

        if restore {
            println!("\n       Rekonstruiere Set #{}...", idx + 1);
            let out_target = output_dir.map(|d| d.join(orig_name));
            let out_target_str = out_target.as_ref().map(|p| p.to_string_lossy().to_string());

            match crate::pipeline::restore_file(
                &m.shares,
                out_target_str.as_deref(),
                true,
                crate::telemetry::TelemetryMode::Silent,
                false,
                crate::types::DEFAULT_BLOCK_SIZE,
                false,
                false,
            ) {
                Ok(Some(restored)) => {
                    println!(
                        "       ✅ Erfolgreich wiederhergestellt: {}",
                        restored.display()
                    );
                }
                Ok(None) => {
                    println!("       ✅ Verifikation erfolgreich.");
                }
                Err(e) => {
                    eprintln!("       ❌ Fehler bei der Wiederherstellung: {}", e);
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
}
