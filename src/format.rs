//! RFS Format Specification, Footer Encoding, and Auto-Detecting Metadata Parsing.
//! Supports 2-Way as well as N-Way One-Time-Pad stealth footers.

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

/// Codiert den RFS3-Metadaten-Footer für beliebig viele $N$ Teile ($N \ge 2$).
///
/// Jeder Teil $k \in 2..=N$ erhält 60 Bytes kryptografisches Rauschen.
/// Teil 1 schließt die One-Time-Pad-Kette:
///   Footer_1 = Plain_Footer ^ Footer_2 ^ ... ^ Footer_N.
///
/// Dadurch ist JEDER Teil isoliert zu 100 % ununterscheidbar von weißem Rauschen.
pub fn encode_rfs3_footer_n_way(
    blks_digest: &[u8; BLKS_DIGEST_SIZE],
    original_size: u64,
    num_parts: usize,
    rng: &mut ChaChaRng,
) -> Vec<[u8; RFS3_FOOTER_SIZE]> {
    assert!(num_parts >= 2, "Mindestens 2 Teile erforderlich");

    let mut plain_footer = [0u8; RFS3_FOOTER_SIZE];
    plain_footer[0..4].copy_from_slice(&RFS3_MAGIC);
    plain_footer[4..4 + BLKS_DIGEST_SIZE].copy_from_slice(blks_digest);
    plain_footer[4 + BLKS_DIGEST_SIZE..4 + BLKS_DIGEST_SIZE + SIZE_HEADER_SIZE]
        .copy_from_slice(&original_size.to_le_bytes());

    let mut footers: Vec<[u8; RFS3_FOOTER_SIZE]> = Vec::with_capacity(num_parts);
    let mut part1 = plain_footer;

    // Erzeuge Zufalls-Footer für Teile 2..N
    for _ in 1..num_parts {
        let mut part_k = [0u8; RFS3_FOOTER_SIZE];
        for b in part_k.iter_mut() {
            *b = rng.next_u8();
        }
        for i in 0..RFS3_FOOTER_SIZE {
            part1[i] ^= part_k[i];
        }
        footers.push(part_k);
    }

    // Teil 1 als erstes Element einfügen
    footers.insert(0, part1);
    plain_footer.zeroize();
    footers
}

/// Codiert den RFS3-Metadaten-Footer für 2 Teile (Standard-Fall).
#[allow(dead_code)]
pub fn encode_rfs3_footer(
    blks_digest: &[u8; BLKS_DIGEST_SIZE],
    original_size: u64,
    rng: &mut ChaChaRng,
) -> ([u8; RFS3_FOOTER_SIZE], [u8; RFS3_FOOTER_SIZE]) {
    let mut footers = encode_rfs3_footer_n_way(blks_digest, original_size, 2, rng);
    let f2 = footers.pop().unwrap();
    let f1 = footers.pop().unwrap();
    (f1, f2)
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

/// Liest und analysiert den Footer aus den End-Bytes von $N$ Split-Dateien ($N \ge 2$).
/// Erkennt automatisch RFS3 (60B BLKS-384) und RFS2 (44B SHA-256).
pub fn decode_footer_n_way(tails: &[&[u8]]) -> Result<RfsMetadata, String> {
    if tails.len() < 2 {
        return Err("Mindestens 2 Teile für die Footer-Dekodierung erforderlich".to_string());
    }

    let first_len = tails[0].len();
    if first_len < RFS2_FOOTER_SIZE {
        return Err("Dateiende ist zu kurz für einen gültigen RFS-Footer".to_string());
    }

    for tail in tails {
        if tail.len() != first_len {
            return Err("Footer-Pufferlängen der Teile stimmen nicht überein".to_string());
        }
    }

    // 1. Prüfe RFS3 (60 Bytes)
    if first_len >= RFS3_FOOTER_SIZE {
        let offset = first_len - RFS3_FOOTER_SIZE;
        let mut xor60 = [0u8; RFS3_FOOTER_SIZE];
        xor60.copy_from_slice(&tails[0][offset..offset + RFS3_FOOTER_SIZE]);

        for tail in &tails[1..] {
            for i in 0..RFS3_FOOTER_SIZE {
                xor60[i] ^= tail[offset + i];
            }
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
    let offset = first_len - RFS2_FOOTER_SIZE;
    let mut xor44 = [0u8; RFS2_FOOTER_SIZE];
    xor44.copy_from_slice(&tails[0][offset..offset + RFS2_FOOTER_SIZE]);

    for tail in &tails[1..] {
        for i in 0..RFS2_FOOTER_SIZE {
            xor44[i] ^= tail[offset + i];
        }
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

/// Liest und analysiert den Footer zweier Split-Dateien (2-Way Convenience).
#[allow(dead_code)]
pub fn decode_footer(part1_tail: &[u8], part2_tail: &[u8]) -> Result<RfsMetadata, String> {
    decode_footer_n_way(&[part1_tail, part2_tail])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfs3_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x19u8; 12];
        let mut rng = ChaChaRng::new(&key, &nonce);

        let dummy_digest = [0x77u8; BLKS_DIGEST_SIZE];
        let original_size = 1024 * 1024 + 42;

        let (f1, f2) = encode_rfs3_footer(&dummy_digest, original_size, &mut rng);

        let meta = decode_footer(&f1, &f2).expect("Decoding RFS3 fehlgeschlagen");
        match meta {
            RfsMetadata::Rfs3 {
                expected_blks,
                original_size: size,
            } => {
                assert_eq!(expected_blks, dummy_digest);
                assert_eq!(size, original_size);
            }
            _ => panic!("Erwartete RFS3 Metadata"),
        }
    }

    #[test]
    fn test_rfs3_n_way_roundtrip_3_parts() {
        let key = [0x55u8; 32];
        let nonce = [0x22u8; 12];
        let mut rng = ChaChaRng::new(&key, &nonce);

        let dummy_digest = [0xAAu8; BLKS_DIGEST_SIZE];
        let original_size = 987654321;

        let footers = encode_rfs3_footer_n_way(&dummy_digest, original_size, 3, &mut rng);
        assert_eq!(footers.len(), 3);

        let tails: Vec<&[u8]> = footers.iter().map(|f| f.as_slice()).collect();
        let meta = decode_footer_n_way(&tails).expect("Decoding 3-way RFS3 fehlgeschlagen");
        match meta {
            RfsMetadata::Rfs3 {
                expected_blks,
                original_size: size,
            } => {
                assert_eq!(expected_blks, dummy_digest);
                assert_eq!(size, original_size);
            }
            _ => panic!("Erwartete RFS3 Metadata"),
        }

        // Test: Nur 2 von 3 Teilen übergeben muss fehlschlagen
        let incomplete_tails = &[tails[0], tails[1]];
        assert!(decode_footer_n_way(incomplete_tails).is_err());
    }

    #[test]
    fn test_rfs3_n_way_roundtrip_5_parts() {
        let key = [0x11u8; 32];
        let nonce = [0x33u8; 12];
        let mut rng = ChaChaRng::new(&key, &nonce);

        let dummy_digest = [0xBBu8; BLKS_DIGEST_SIZE];
        let original_size = 12345;

        let footers = encode_rfs3_footer_n_way(&dummy_digest, original_size, 5, &mut rng);
        assert_eq!(footers.len(), 5);

        let tails: Vec<&[u8]> = footers.iter().map(|f| f.as_slice()).collect();
        let meta = decode_footer_n_way(&tails).expect("Decoding 5-way RFS3 fehlgeschlagen");
        match meta {
            RfsMetadata::Rfs3 {
                expected_blks,
                original_size: size,
            } => {
                assert_eq!(expected_blks, dummy_digest);
                assert_eq!(size, original_size);
            }
            _ => panic!("Erwartete RFS3 Metadata"),
        }
    }

    #[test]
    fn test_rfs2_legacy_roundtrip() {
        let key = [0x33u8; 32];
        let nonce = [0x77u8; 12];
        let mut rng = ChaChaRng::new(&key, &nonce);

        let dummy_sha = [0x55u8; SHA256_DIGEST_SIZE];
        let original_size = 654321;

        let (f1, f2) = encode_rfs2_footer(&dummy_sha, original_size, &mut rng);

        let meta = decode_footer(&f1, &f2).expect("Decoding RFS2 fehlgeschlagen");
        match meta {
            RfsMetadata::Rfs2 {
                expected_sha256,
                original_size: size,
            } => {
                assert_eq!(expected_sha256, dummy_sha);
                assert_eq!(size, original_size);
            }
            _ => panic!("Erwartete RFS2 Metadata"),
        }
    }

    #[test]
    fn test_mismatch_error() {
        let garbage1 = [0x11u8; 60];
        let garbage2 = [0x22u8; 60];
        assert!(decode_footer(&garbage1, &garbage2).is_err());
    }
}
