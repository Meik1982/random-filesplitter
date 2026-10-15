use std::collections::HashSet;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::ChaChaRng;
use crate::entropy::UniversalEntropyHarvester;

/// Generates `count` cryptographically uncorrelated, unique 6-character hex tokens (e.g., "a9f4c2").
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

/// Shuffles paths in-place via unbiased ChaCha20 Fisher-Yates shuffle (rejection sampling).
pub fn shuffle_paths(paths: &mut [PathBuf]) {
    if paths.len() <= 1 {
        return;
    }
    let (mut key, mut nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&key, &nonce);
    key.zeroize();
    nonce.zeroize();

    for i in (1..paths.len()).rev() {
        let bound = (i + 1) as u32;
        let threshold = u32::MAX - (u32::MAX % bound);
        let j = loop {
            let mut rnd_u32 = [0u8; 4];
            rng.fill_bytes(&mut rnd_u32);
            let val = u32::from_le_bytes(rnd_u32);
            if val < threshold {
                break (val % bound) as usize;
            }
        };
        paths.swap(i, j);
    }
}

/// Sanitizes an embedded filename from an RFS4 footer to prevent path traversal (`../`, `/`, `\`)
/// or control-character injection when restoring files without an explicit `-o` target.
pub fn sanitize_embedded_filename(raw: &str) -> String {
    // Normalise Windows and Unix separators to '/' and take the last non-empty segment
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let basename = cleaned
        .rsplit(['/', '\\'])
        .find(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .unwrap_or("restored.bin")
        .trim();

    if basename.is_empty() || basename == "." || basename == ".." {
        "restored.bin".to_string()
    } else {
        basename.to_string()
    }
}

/// Determines all output paths for shares and decoy files.
///
/// Returns a tuple `(real_paths, decoy_paths, n_parts)`.
pub fn determine_split_paths(
    input_source: &str,
    output_parts: Option<&[PathBuf]>,
    num_parts: usize,
    num_decoys: usize,
    output_prefix: Option<&str>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>, usize), String> {
    if let Some(parts) = output_parts {
        if parts.len() < 2 || parts.len() > 64 {
            return Err("Number of explicit output shares must be between 2 and 64.".to_string());
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

/// Strips known RFS suffixes (`.rfs`, `.rfs<N>`, `.<hex6>.rfs`, `.part<N>.rfs`, `.decoy<N>.rfs`)
/// from a filename or path string and returns the base stem if an RFS suffix was matched.
pub fn strip_rfs_suffix(p_str: &str) -> Option<&str> {
    if let Some(idx) = p_str.rfind(".rfs") {
        let suffix = &p_str[idx + 4..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            return Some(&p_str[..idx]);
        }
        if let Some(before) = p_str.strip_suffix(".rfs") {
            if let Some(dot_idx) = before.rfind('.') {
                let tok = &before[dot_idx + 1..];
                let is_hex_token = (tok.len() == 4 || tok.len() == 6)
                    && tok.chars().all(|c| c.is_ascii_hexdigit());
                let is_part_token =
                    tok.starts_with("part") || tok.starts_with("rfs") || tok.starts_with("decoy");
                if is_hex_token || is_part_token {
                    return Some(&before[..dot_idx]);
                }
            }
            return Some(before);
        }
    }
    p_str.strip_suffix(".part1.rfs")
}

/// Deduces target output path for restoration (`restore`).
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
        let safe_fn = sanitize_embedded_filename(meta_fn);
        let parent = part_paths[0].parent().unwrap_or(Path::new(""));
        if parent.as_os_str().is_empty() {
            Some(PathBuf::from(safe_fn))
        } else {
            Some(parent.join(safe_fn))
        }
    } else {
        let p_str = part_paths[0].to_str().unwrap_or("restored.bin");
        let deduced = strip_rfs_suffix(p_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("{}.restored", p_str)));
        Some(deduced)
    }
}

/// Checks whether destination target path collides with any input share file.
pub fn check_destination_collision(target: &Path, part_paths: &[PathBuf]) -> Result<(), String> {
    for (idx, p) in part_paths.iter().enumerate() {
        if target == p {
            return Err(format!(
                "Target file '{}' must not be identical to source share {} (risk of data loss).",
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
        // Probability of identical permutation with 20 elements is ~ 1 / 20!
        assert_ne!(paths, original);
    }

    #[test]
    fn test_collision_detection() {
        let parts = vec![PathBuf::from("a.rfs"), PathBuf::from("b.rfs")];
        assert!(check_destination_collision(Path::new("a.rfs"), &parts).is_err());
        assert!(check_destination_collision(Path::new("c.bin"), &parts).is_ok());
    }

    #[test]
    fn test_sanitize_embedded_filename_prevents_path_traversal() {
        assert_eq!(sanitize_embedded_filename("document.pdf"), "document.pdf");
        assert_eq!(sanitize_embedded_filename("../../etc/passwd"), "passwd");
        assert_eq!(
            sanitize_embedded_filename("/tmp/evil/payload.sh"),
            "payload.sh"
        );
        assert_eq!(
            sanitize_embedded_filename("..\\..\\Windows\\System32\\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(sanitize_embedded_filename("../../.."), "restored.bin");
        assert_eq!(sanitize_embedded_filename("."), "restored.bin");
        assert_eq!(sanitize_embedded_filename(""), "restored.bin");
        assert_eq!(sanitize_embedded_filename("///"), "restored.bin");

        let parts = vec![
            PathBuf::from("/safe/dir/a1b2c3.rfs"),
            PathBuf::from("/safe/dir/d4e5f6.rfs"),
        ];
        let target =
            deduce_restore_target(&parts, None, Some("../../../etc/shadow"), false, false).unwrap();
        assert_eq!(target, PathBuf::from("/safe/dir/shadow"));
    }
}
