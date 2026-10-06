//! RFS Format Specification, Footer Encoding, and Auto-Detecting Metadata Parsing.

use crate::crypto::ChaChaRng;
use crate::types::{
    BLKS_DIGEST_SIZE, RFS2_FOOTER_SIZE, RFS2_MAGIC, RFS3_FOOTER_SIZE, RFS3_MAGIC,
    SHA256_DIGEST_SIZE, SIZE_HEADER_SIZE,
};
use zeroize::Zeroize;

/// Unterstützte RFS-Metadatenformate
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RfsMetadata {
    /// Historisches RFS2-Format (SHA-256)
    Rfs2 {
        expected_sha256: [u8; SHA256_DIGEST_SIZE],
        original_size: u64,
    },
    /// Neues Post-Quantum RFS3-Format (BLKS-384)
    Rfs3 {
        expected_blks: [u8; BLKS_DIGEST_SIZE],
        original_size: u64,
    },
}

impl RfsMetadata {
    /// Liefert die Roh-Größe des Footers in Bytes.
    pub fn footer_size(&self) -> usize {
        match self {
            RfsMetadata::Rfs2 { .. } => RFS2_FOOTER_SIZE,
            RfsMetadata::Rfs3 { .. } => RFS3_FOOTER_SIZE,
        }
    }

    /// Liefert die erwartete Originalgröße der Datei.
    pub fn original_size(&self) -> u64 {
        match *self {
            RfsMetadata::Rfs2 { original_size, .. } => original_size,
            RfsMetadata::Rfs3 { original_size, .. } => original_size,
        }
    }
}

/// Codiert den RFS3-Metadaten-Footer und verschleiert ihn per ChaCha20-XOR
/// für 100% plausible Abstreitbarkeit (Plausible Deniability).
///
/// Liefert `(footer_part1, footer_part2)` jeweils 60 Bytes lang.
pub fn encode_rfs3_footer(
    blks_digest: &[u8; BLKS_DIGEST_SIZE],
    original_size: u64,
    rng: &mut ChaChaRng,
) -> ([u8; RFS3_FOOTER_SIZE], [u8; RFS3_FOOTER_SIZE]) {
    let mut plain_footer = [0u8; RFS3_FOOTER_SIZE];
    plain_footer[0..4].copy_from_slice(&RFS3_MAGIC);
    plain_footer[4..4 + BLKS_DIGEST_SIZE].copy_from_slice(blks_digest);
    plain_footer[4 + BLKS_DIGEST_SIZE..4 + BLKS_DIGEST_SIZE + SIZE_HEADER_SIZE]
        .copy_from_slice(&original_size.to_le_bytes());

    let mut part1 = [0u8; RFS3_FOOTER_SIZE];
    let mut part2 = [0u8; RFS3_FOOTER_SIZE];

    for i in 0..RFS3_FOOTER_SIZE {
        let rnd = rng.next_u8();
        part1[i] = plain_footer[i] ^ rnd;
        part2[i] = rnd;
    }

    plain_footer.zeroize();
    (part1, part2)
}

/// Codiert den RFS2-Metadaten-Footer (Legacy-Format) für Rückwärtskompatibilität.
#[allow(dead_code)]
pub fn encode_rfs2_footer(
    sha256_digest: &[u8; SHA256_DIGEST_SIZE],
    original_size: u64,
    rng: &mut ChaChaRng,
) -> ([u8; RFS2_FOOTER_SIZE], [u8; RFS2_FOOTER_SIZE]) {
    let mut plain_footer = [0u8; RFS2_FOOTER_SIZE];
    plain_footer[0..4].copy_from_slice(&RFS2_MAGIC);
    plain_footer[4..4 + SHA256_DIGEST_SIZE].copy_from_slice(sha256_digest);
    plain_footer[4 + SHA256_DIGEST_SIZE..4 + SHA256_DIGEST_SIZE + SIZE_HEADER_SIZE]
        .copy_from_slice(&original_size.to_le_bytes());

    let mut part1 = [0u8; RFS2_FOOTER_SIZE];
    let mut part2 = [0u8; RFS2_FOOTER_SIZE];

    for i in 0..RFS2_FOOTER_SIZE {
        let rnd = rng.next_u8();
        part1[i] = plain_footer[i] ^ rnd;
        part2[i] = rnd;
    }

    plain_footer.zeroize();
    (part1, part2)
}

/// Liest und analysiert den Footer aus den End-Bytes zweier Split-Dateien.
/// Erkennt automatisch RFS3 (60B BLKS-384) und RFS2 (44B SHA-256).
pub fn decode_footer(part1_tail: &[u8], part2_tail: &[u8]) -> Result<RfsMetadata, String> {
    if part1_tail.len() < RFS2_FOOTER_SIZE || part2_tail.len() < RFS2_FOOTER_SIZE {
        return Err("Dateiende ist zu kurz für einen gültigen RFS-Footer".to_string());
    }

    if part1_tail.len() != part2_tail.len() {
        return Err("Footer-Pufferlängen stimmen nicht überein".to_string());
    }

    // 1. Prüfe zuerst RFS3 (60 Bytes), falls genug Bytes übergeben wurden
    if part1_tail.len() >= RFS3_FOOTER_SIZE {
        let offset = part1_tail.len() - RFS3_FOOTER_SIZE;
        let mut xor60 = [0u8; RFS3_FOOTER_SIZE];
        for i in 0..RFS3_FOOTER_SIZE {
            xor60[i] = part1_tail[offset + i] ^ part2_tail[offset + i];
        }

        if xor60[0..4] == RFS3_MAGIC {
            let mut blks = [0u8; BLKS_DIGEST_SIZE];
            blks.copy_from_slice(&xor60[4..4 + BLKS_DIGEST_SIZE]);
            let size = u64::from_le_bytes(
                xor60[4 + BLKS_DIGEST_SIZE..4 + BLKS_DIGEST_SIZE + SIZE_HEADER_SIZE]
                    .try_into()
                    .unwrap(),
            );
            xor60.zeroize();
            return Ok(RfsMetadata::Rfs3 {
                expected_blks: blks,
                original_size: size,
            });
        }
        xor60.zeroize();
    }

    // 2. Prüfe RFS2 (44 Bytes Legacy)
    let offset = part1_tail.len() - RFS2_FOOTER_SIZE;
    let mut xor44 = [0u8; RFS2_FOOTER_SIZE];
    for i in 0..RFS2_FOOTER_SIZE {
        xor44[i] = part1_tail[offset + i] ^ part2_tail[offset + i];
    }

    if xor44[0..4] == RFS2_MAGIC {
        let mut sha256 = [0u8; SHA256_DIGEST_SIZE];
        sha256.copy_from_slice(&xor44[4..4 + SHA256_DIGEST_SIZE]);
        let size = u64::from_le_bytes(
            xor44[4 + SHA256_DIGEST_SIZE..4 + SHA256_DIGEST_SIZE + SIZE_HEADER_SIZE]
                .try_into()
                .unwrap(),
        );
        xor44.zeroize();
        return Ok(RfsMetadata::Rfs2 {
            expected_sha256: sha256,
            original_size: size,
        });
    }

    xor44.zeroize();
    Err("Ungültige oder nicht zusammengehörige RFS-Dateien (Magic-Tag Mismatch)!".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfs3_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut rng = ChaChaRng::new(&key, &nonce);

        let blks_digest = [0x77u8; 48];
        let original_size = 123456789012345u64;

        let (p1, p2) = encode_rfs3_footer(&blks_digest, original_size, &mut rng);
        let meta = decode_footer(&p1, &p2).expect("RFS3 Decode fehlgeschlagen");

        match meta {
            RfsMetadata::Rfs3 {
                expected_blks,
                original_size: s,
            } => {
                assert_eq!(expected_blks, blks_digest);
                assert_eq!(s, original_size);
            }
            _ => panic!("Erwartete Rfs3-Metadaten"),
        }
    }

    #[test]
    fn test_rfs2_legacy_roundtrip() {
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        let mut rng = ChaChaRng::new(&key, &nonce);

        let sha_digest = [0x55u8; 32];
        let original_size = 987654321u64;

        let (p1, p2) = encode_rfs2_footer(&sha_digest, original_size, &mut rng);
        let meta = decode_footer(&p1, &p2).expect("RFS2 Decode fehlgeschlagen");

        match meta {
            RfsMetadata::Rfs2 {
                expected_sha256,
                original_size: s,
            } => {
                assert_eq!(expected_sha256, sha_digest);
                assert_eq!(s, original_size);
            }
            _ => panic!("Erwartete Rfs2-Metadaten"),
        }
    }

    #[test]
    fn test_mismatch_error() {
        let p1 = vec![0xAAu8; 64];
        let p2 = vec![0xBBu8; 64];
        assert!(decode_footer(&p1, &p2).is_err());
    }
}
