//! Type definitions, format constants, and parsing utilities for RFS.

/// Magic bytes for legacy RFS2 format (4 bytes)
pub const RFS2_MAGIC: [u8; 4] = *b"RFS2";

/// Magic bytes for post-quantum RFS3 format (4 bytes)
pub const RFS3_MAGIC: [u8; 4] = *b"RFS3";

/// Magic bytes for post-quantum RFS4 format with embedded filename & block padding (4 bytes)
pub const RFS4_MAGIC: [u8; 4] = *b"RFS4";

/// Size of SHA-256 digest in RFS2 (32 bytes)
pub const SHA256_DIGEST_SIZE: usize = 32;

/// Size of BLKS-384 digest in RFS3 and RFS4 (48 bytes)
pub const BLKS_DIGEST_SIZE: usize = 48;

/// Size of original file length field (8 bytes little-endian)
pub const SIZE_HEADER_SIZE: usize = 8;

/// Total size of legacy RFS2 footer (4B magic + 32B hash + 8B size = 44 bytes)
pub const RFS2_FOOTER_SIZE: usize = 4 + SHA256_DIGEST_SIZE + SIZE_HEADER_SIZE;

/// Total size of RFS3 footer (4B magic + 48B BLKS-384 + 8B size = 60 bytes)
pub const RFS3_FOOTER_SIZE: usize = 4 + BLKS_DIGEST_SIZE + SIZE_HEADER_SIZE;

/// Fixed size of RFS4 trailer at end of file (64 bytes)
/// [0..4] Magic ("RFS4")
/// [4..6] Version (0x04, 0x00)
/// [6..14] Original size (u64 LE, 8 bytes)
/// [14..62] BLKS-384 hash (48 bytes)
/// [62..64] Filename length L (u16 LE, 2 bytes)
pub const RFS4_TRAILER_SIZE: usize = 4 + 2 + SIZE_HEADER_SIZE + BLKS_DIGEST_SIZE + 2;

/// Default alignment block size for RFS4 (4 KiB = 4096 bytes cluster alignment)
pub const RFS4_ALIGN_BLOCK_SIZE: usize = 4096;

/// Default buffer block size (4 MiB)
pub const DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Minimum allowed block size (64 KiB)
pub const MIN_BLOCK_SIZE: usize = 64 * 1024;

/// Maximum allowed block size (256 MiB)
pub const MAX_BLOCK_SIZE: usize = 256 * 1024 * 1024;

/// Parses human-readable block size strings such as "64K", "1M", "4M", "16M" into bytes.
pub fn parse_block_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty block size specification".to_string());
    }

    let (num_part, multiplier) = if s.ends_with(|c: char| c.is_ascii_alphabetic()) {
        let (num, suffix) = s.split_at(s.len() - 1);
        let m = match suffix.to_ascii_uppercase().as_str() {
            "K" => 1024usize,
            "M" => 1024 * 1024,
            "G" => 1024 * 1024 * 1024,
            _ => {
                return Err(format!(
                    "Unknown size suffix: '{}'. Allowed are K, M, G.",
                    suffix
                ))
            }
        };
        (num, m)
    } else {
        (s, 1usize)
    };

    let val = num_part
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("Invalid number in block size: '{}'", s))?;

    let bytes = val
        .checked_mul(multiplier)
        .ok_or_else(|| "Block size exceeds address space".to_string())?;

    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&bytes) {
        return Err(format!(
            "Block size {} bytes outside allowed range (64 KiB - 256 MiB)",
            bytes
        ));
    }

    Ok(bytes)
}

/// Parses an arbitrary file size string (e.g. "1024", "64K", "10M", "4G", "1T").
pub fn parse_file_size(s: &str) -> Result<u64, String> {
    let s_clean = s.trim();
    if s_clean.is_empty() {
        return Err("File size specification must not be empty.".to_string());
    }

    let (num_part, multiplier) = if s_clean.ends_with(|c: char| c.is_ascii_alphabetic()) {
        let (num, suffix) = s_clean.split_at(s_clean.len() - 1);
        let m = match suffix.to_ascii_uppercase().as_str() {
            "B" => 1u64,
            "K" => 1024u64,
            "M" => 1024 * 1024,
            "G" => 1024 * 1024 * 1024,
            "T" => 1024 * 1024 * 1024 * 1024,
            _ => {
                return Err(format!(
                    "Unknown size suffix: '{}'. Allowed are B, K, M, G, T.",
                    suffix
                ))
            }
        };
        (num, m)
    } else {
        (s_clean, 1u64)
    };

    let val = num_part
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("Invalid number in size: '{}'", s))?;

    val.checked_mul(multiplier)
        .ok_or_else(|| "File size exceeds 64-bit address space".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_file_size() {
        assert_eq!(parse_file_size("0").unwrap(), 0);
        assert_eq!(parse_file_size("100B").unwrap(), 100);
        assert_eq!(parse_file_size("64K").unwrap(), 65536);
        assert_eq!(parse_file_size("10M").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_file_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_file_size("invalid").is_err());
        assert!(parse_file_size("10X").is_err());
    }

    #[test]
    fn test_parse_block_size() {
        assert_eq!(parse_block_size("64K").unwrap(), 64 * 1024);
        assert_eq!(parse_block_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_block_size("4M").unwrap(), 4 * 1024 * 1024);
        assert_eq!(parse_block_size("16M").unwrap(), 16 * 1024 * 1024);
        assert_eq!(parse_block_size("256M").unwrap(), 256 * 1024 * 1024);
        assert!(parse_block_size("32K").is_err());
        assert!(parse_block_size("512M").is_err());
        assert!(parse_block_size("invalid").is_err());
    }
}
