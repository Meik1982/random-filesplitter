use std::collections::HashSet;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::ChaChaRng;
use crate::entropy::UniversalEntropyHarvester;

/// Generiert `count` kryptografisch unkorrelierte, eindeutige 6-stellige Hex-Tokens (z. B. "a9f4c2").
pub fn generate_unique_hex_tokens(count: usize) -> Vec<String> {
    let (mut key, mut nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&key, &nonce);
    key.zeroize();
    nonce.zeroize();

    let mut set = HashSet::with_capacity(count);
    let mut tokens = Vec::with_capacity(count);
    while tokens.len() < count {
        let mut rnd = [0u8; 3];
        rng.fill_bytes(&mut rnd);
        let tok = format!("{:02x}{:02x}{:02x}", rnd[0], rnd[1], rnd[2]);
        if set.insert(tok.clone()) {
            tokens.push(tok);
        }
    }
    tokens
}

/// Verwürfelt Pfade in-place via ChaCha20 Fisher-Yates Shuffle.
pub fn shuffle_paths(paths: &mut [PathBuf]) {
    if paths.len() <= 1 {
        return;
    }
    let (mut key, mut nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&key, &nonce);
    key.zeroize();
    nonce.zeroize();

    for i in (1..paths.len()).rev() {
        let mut rnd_u32 = [0u8; 4];
        rng.fill_bytes(&mut rnd_u32);
        let j = (u32::from_le_bytes(rnd_u32) as usize) % (i + 1);
        paths.swap(i, j);
    }
}

/// Bestimmt alle Ausgabepfade für Shares und Köderdateien (Decoys).
///
/// Liefert ein Tupel `(real_paths, decoy_paths, n_parts)`.
pub fn determine_split_paths(
    input_source: &str,
    output_parts: Option<&[PathBuf]>,
    num_parts: usize,
    num_decoys: usize,
    output_prefix: Option<&str>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>, usize), String> {
    if let Some(parts) = output_parts {
        if parts.len() < 2 || parts.len() > 64 {
            return Err(
                "Anzahl der expliziten Ausgabeteile muss zwischen 2 und 64 liegen.".to_string(),
            );
        }
        Ok((parts.to_vec(), Vec::new(), parts.len()))
    } else {
        let count = num_parts.clamp(2, 64);
        let total_files = count + num_decoys;
        let tokens = generate_unique_hex_tokens(total_files);

        let parent = if input_source != "-" {
            Path::new(input_source).parent().unwrap_or(Path::new(""))
        } else {
            Path::new("")
        };

        let mut all_paths: Vec<PathBuf> = tokens
            .into_iter()
            .map(|t| {
                if let Some(prefix) = output_prefix {
                    let p = Path::new(prefix);
                    if p.is_dir() || prefix.ends_with('/') {
                        p.join(format!("{}.rfs", t))
                    } else {
                        PathBuf::from(format!("{}.{}.rfs", prefix, t))
                    }
                } else if parent.as_os_str().is_empty() {
                    PathBuf::from(format!("{}.rfs", t))
                } else {
                    parent.join(format!("{}.rfs", t))
                }
            })
            .collect();

        if num_decoys > 0 {
            shuffle_paths(&mut all_paths);
        }

        let real = all_paths[0..count].to_vec();
        let decoys = all_paths[count..total_files].to_vec();
        Ok((real, decoys, count))
    }
}

/// Ermittelt den Zielpfad für die Wiederherstellung (`restore`).
pub fn deduce_restore_target(
    part_paths: &[PathBuf],
    output_target: Option<&str>,
    filename_from_meta: Option<&str>,
    is_stdout: bool,
    verify_only: bool,
) -> Option<PathBuf> {
    if is_stdout || verify_only {
        None
    } else if let Some(p) = output_target {
        Some(PathBuf::from(p))
    } else if let Some(meta_fn) = filename_from_meta {
        let parent = part_paths[0].parent().unwrap_or(Path::new(""));
        if parent.as_os_str().is_empty() {
            Some(PathBuf::from(meta_fn))
        } else {
            Some(parent.join(meta_fn))
        }
    } else {
        let p_str = part_paths[0].to_str().unwrap_or("restored.bin");
        let deduced = if let Some(idx) = p_str.rfind(".rfs") {
            let suffix = &p_str[idx + 4..];
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                PathBuf::from(&p_str[..idx])
            } else if let Some(before) = p_str.strip_suffix(".rfs") {
                if let Some(dot_idx) = before.rfind('.') {
                    let token_candidate = &before[dot_idx + 1..];
                    let is_hex_token = (token_candidate.len() == 4 || token_candidate.len() == 6)
                        && token_candidate.chars().all(|c| c.is_ascii_hexdigit());
                    let is_part_token = token_candidate.starts_with("part")
                        || token_candidate.starts_with("rfs")
                        || token_candidate.starts_with("decoy");
                    if is_hex_token || is_part_token {
                        PathBuf::from(&before[..dot_idx])
                    } else {
                        PathBuf::from(before)
                    }
                } else {
                    PathBuf::from(before)
                }
            } else {
                PathBuf::from(format!("{}.restored", p_str))
            }
        } else if let Some(stripped) = p_str.strip_suffix(".part1.rfs") {
            PathBuf::from(stripped)
        } else {
            PathBuf::from(format!("{}.restored", p_str))
        };
        Some(deduced)
    }
}

/// Prüft, ob der Zielpfad mit einer der Quelldateien kollidiert.
pub fn check_destination_collision(target: &Path, part_paths: &[PathBuf]) -> Result<(), String> {
    for (idx, p) in part_paths.iter().enumerate() {
        if target == p {
            return Err(format!(
                "Zieldatei '{}' darf nicht identisch mit Quellteil {} sein (Gefahr des Datenverlusts).",
                target.display(),
                idx + 1
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_tokens() {
        let tokens = generate_unique_hex_tokens(100);
        assert_eq!(tokens.len(), 100);
        let set: HashSet<_> = tokens.iter().collect();
        assert_eq!(set.len(), 100);
        for t in tokens {
            assert_eq!(t.len(), 6);
            assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_shuffle_paths() {
        let mut paths: Vec<PathBuf> = (0..20)
            .map(|i| PathBuf::from(format!("{}.rfs", i)))
            .collect();
        let original = paths.clone();
        shuffle_paths(&mut paths);
        assert_eq!(paths.len(), original.len());
        // Wahrscheinlichkeit für identische Permutation bei 20 Elementen ist ~ 1 / 20!
        assert_ne!(paths, original);
    }

    #[test]
    fn test_collision_detection() {
        let parts = vec![PathBuf::from("a.rfs"), PathBuf::from("b.rfs")];
        assert!(check_destination_collision(Path::new("a.rfs"), &parts).is_err());
        assert!(check_destination_collision(Path::new("c.bin"), &parts).is_ok());
    }
}
