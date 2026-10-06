//! Type definitions, format constants, and parsing utilities for RFS.

/// Magic-Bytes für das historische RFS2-Format (4 Bytes)
pub const RFS2_MAGIC: [u8; 4] = *b"RFS2";

/// Magic-Bytes für das neue Post-Quantum RFS3-Format (4 Bytes)
pub const RFS3_MAGIC: [u8; 4] = *b"RFS3";

/// Größe des SHA-256 Hashes in RFS2 (32 Bytes)
pub const SHA256_DIGEST_SIZE: usize = 32;

/// Größe des BLKS-384 Hashes in RFS3 (48 Bytes)
pub const BLKS_DIGEST_SIZE: usize = 48;

/// Größe des Dateigrößen-Feldes (8 Bytes Little-Endian)
pub const SIZE_HEADER_SIZE: usize = 8;

/// Gesamtgröße des RFS2 Footers (4B Magic + 32B Hash + 8B Size = 44 Bytes)
pub const RFS2_FOOTER_SIZE: usize = 4 + SHA256_DIGEST_SIZE + SIZE_HEADER_SIZE;

/// Gesamtgröße des RFS3 Footers (4B Magic + 48B BLKS-384 + 8B Size = 60 Bytes)
pub const RFS3_FOOTER_SIZE: usize = 4 + BLKS_DIGEST_SIZE + SIZE_HEADER_SIZE;

/// Standard-Puffergröße (4 MiB)
pub const DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Minimale erlaubte Blockgröße (64 KiB)
pub const MIN_BLOCK_SIZE: usize = 64 * 1024;

/// Maximale erlaubte Blockgröße (256 MiB)
pub const MAX_BLOCK_SIZE: usize = 256 * 1024 * 1024;

/// Parst menschenlesbare Größenangaben wie "64K", "1M", "4M", "16M" in Bytes.
pub fn parse_block_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Leere Blockgrößenangabe".to_string());
    }

    let (num_part, multiplier) = if s.ends_with(|c: char| c.is_ascii_alphabetic()) {
        let (num, suffix) = s.split_at(s.len() - 1);
        let m = match suffix.to_ascii_uppercase().as_str() {
            "K" => 1024usize,
            "M" => 1024 * 1024,
            "G" => 1024 * 1024 * 1024,
            _ => {
                return Err(format!(
                    "Unbekannter Größensuffix: '{}'. Erlaubt sind K, M, G.",
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
        .map_err(|_| format!("Ungültige Zahl in Blockgrößenangabe: '{}'", s))?;

    let bytes = val
        .checked_mul(multiplier)
        .ok_or_else(|| "Blockgröße überschreitet Adressbereich".to_string())?;

    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&bytes) {
        return Err(format!(
            "Blockgröße {} Bytes außerhalb des erlaubten Bereichs (64 KiB - 256 MiB)",
            bytes
        ));
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_block_size() {
        assert_eq!(parse_block_size("64K").unwrap(), 64 * 1024);
        assert_eq!(parse_block_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_block_size("4M").unwrap(), 4 * 1024 * 1024);
        assert_eq!(parse_block_size("16M").unwrap(), 16 * 1024 * 1024);
        assert_eq!(parse_block_size("256M").unwrap(), 256 * 1024 * 1024);
        assert!(parse_block_size("32K").is_err()); // Zu klein (< 64 KiB)
        assert!(parse_block_size("512M").is_err()); // Zu groß (> 256 MiB)
        assert!(parse_block_size("invalid").is_err());
    }
}
