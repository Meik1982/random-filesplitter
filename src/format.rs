//! RFS Format Specification, Footer Encoding, and Auto-Detecting Metadata Parsing.
//! Supports 2-Way as well as N-Way One-Time-Pad stealth footers.

use crate::crypto::{xor_in_place, ChaChaRng};
use crate::types::{
    BLKS_DIGEST_SIZE, RFS2_FOOTER_SIZE, RFS2_MAGIC, RFS3_FOOTER_SIZE, RFS3_MAGIC,
    RFS4_ALIGN_BLOCK_SIZE, RFS4_MAGIC, RFS4_TRAILER_SIZE, SHA256_DIGEST_SIZE, SIZE_HEADER_SIZE,
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
    /// Post-Quantum RFS3-Format (BLKS-384)
    Rfs3 {
        expected_blks: [u8; BLKS_DIGEST_SIZE],
        original_size: u64,
    },
    /// Post-Quantum RFS4-Format mit eingebettetem Dateinamen & Block-Padding
    Rfs4 {
        expected_blks: [u8; BLKS_DIGEST_SIZE],
        original_size: u64,
        filename: String,
        filename_len: u16,
    },
}

impl RfsMetadata {
    /// Liefert die Roh-Größe des Footers in Bytes.
    #[allow(dead_code)]
    pub fn footer_size(&self) -> usize {
        match self {
            RfsMetadata::Rfs2 { .. } => RFS2_FOOTER_SIZE,
            RfsMetadata::Rfs3 { .. } => RFS3_FOOTER_SIZE,
            RfsMetadata::Rfs4 { filename_len, .. } => RFS4_TRAILER_SIZE + *filename_len as usize,
        }
    }

    /// Liefert die erwartete Originalgröße der Datei.
    pub fn original_size(&self) -> u64 {
        match *self {
            RfsMetadata::Rfs2 { original_size, .. } => original_size,
            RfsMetadata::Rfs3 { original_size, .. } => original_size,
            RfsMetadata::Rfs4 { original_size, .. } => original_size,
        }
    }

    /// Liefert den eingebetteten Dateinamen (nur bei RFS4).
    pub fn filename(&self) -> Option<&str> {
        match self {
            RfsMetadata::Rfs4 { filename, .. } => Some(filename.as_str()),
            _ => None,
        }
    }
}

/// Berechnet das nötige Padding und codiert den RFS4-Trailer + Dateinamen für N Teile ($N \ge 2$).
/// Liefert für jeden Teil die anzuhängenden Bytes (Zufalls-Padding + UTF8-Dateiname + 64B Trailer).
pub fn encode_rfs4_footer_n_way(
    blks_digest: &[u8; BLKS_DIGEST_SIZE],
    original_size: u64,
    filename: &str,
    num_parts: usize,
    pad_to_target: Option<u64>,
    rng: &mut ChaChaRng,
) -> Result<Vec<Vec<u8>>, String> {
    assert!(num_parts >= 2, "Mindestens 2 Teile erforderlich");

    let filename_bytes = filename.as_bytes();
    if filename_bytes.len() > 65535 {
        return Err("Dateiname ist zu lang für RFS4-Footer (maximal 65535 Bytes).".to_string());
    }
    let filename_len = filename_bytes.len();

    // 1. Fester 64-Byte Trailer
    let mut plain_trailer = [0u8; RFS4_TRAILER_SIZE];
    plain_trailer[0..4].copy_from_slice(&RFS4_MAGIC);
    plain_trailer[4..6].copy_from_slice(&[0x04, 0x00]);
    plain_trailer[6..14].copy_from_slice(&original_size.to_le_bytes());
    plain_trailer[14..62].copy_from_slice(blks_digest);
    plain_trailer[62..64].copy_from_slice(&(filename_len as u16).to_le_bytes());

    // 2. Mindestgröße für den gesamten Share: Originalgröße + Dateiname + 64B Trailer
    let min_share_size = original_size
        .checked_add((filename_len + RFS4_TRAILER_SIZE) as u64)
        .ok_or_else(|| "Dateigrößen-Überlauf bei Footer-Berechnung".to_string())?;

    // 3. Ziel-Share-Größe berechnen
    let total_share_size = if let Some(target) = pad_to_target {
        if target < min_share_size {
            return Err(format!(
                "Gewünschte Zielgröße ({} Bytes) ist kleiner als die Mindestgröße für RFS4 ({} Bytes).",
                target, min_share_size
            ));
        }
        target
    } else {
        // Standard: Auf volle 4 KiB (4096 Bytes) aufrunden
        let rem = min_share_size % RFS4_ALIGN_BLOCK_SIZE as u64;
        if rem == 0 {
            // Wenn exakt aligned, einen vollen 4 KiB Block Padding ergänzen, damit immer Rauschen vor dem Namen liegt
            min_share_size + RFS4_ALIGN_BLOCK_SIZE as u64
        } else {
            min_share_size + (RFS4_ALIGN_BLOCK_SIZE as u64 - rem)
        }
    };

    let tail_len = (total_share_size - original_size) as usize;
    let padding_len = tail_len - filename_len - RFS4_TRAILER_SIZE;

    // 4. Zusammensetzen des unverschlüsselten Endbereichs (Padding + Dateiname + Trailer)
    let mut plain_tail = vec![0u8; tail_len];
    for b in &mut plain_tail[0..padding_len] {
        *b = rng.next_u8();
    }
    plain_tail[padding_len..padding_len + filename_len].copy_from_slice(filename_bytes);
    plain_tail[padding_len + filename_len..tail_len].copy_from_slice(&plain_trailer);

    // 5. N-Way One-Time-Pad Verteilung
    let mut footers: Vec<Vec<u8>> = Vec::with_capacity(num_parts);
    let mut part1 = plain_tail.clone();

    for _ in 1..num_parts {
        let mut part_k = vec![0u8; tail_len];
        for b in part_k.iter_mut() {
            *b = rng.next_u8();
        }
        xor_in_place(&mut part1, &part_k);
        footers.push(part_k);
    }

    footers.insert(0, part1);
    plain_tail.zeroize();
    plain_trailer.zeroize();

    Ok(footers)
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

    // 1. Prüfe RFS4 (64 Bytes Trailer + variabler Dateiname)
    if first_len >= RFS4_TRAILER_SIZE {
        let offset = first_len - RFS4_TRAILER_SIZE;
        let mut xor64 = [0u8; RFS4_TRAILER_SIZE];
        xor64.copy_from_slice(&tails[0][offset..offset + RFS4_TRAILER_SIZE]);

        for tail in &tails[1..] {
            for i in 0..RFS4_TRAILER_SIZE {
                xor64[i] ^= tail[offset + i];
            }
        }

        if xor64[0..4] == RFS4_MAGIC {
            let size = u64::from_le_bytes(xor64[6..14].try_into().unwrap());
            let mut blks = [0u8; BLKS_DIGEST_SIZE];
            blks.copy_from_slice(&xor64[14..62]);
            let fn_len = u16::from_le_bytes(xor64[62..64].try_into().unwrap()) as usize;

            let filename = if fn_len > 0 && offset >= fn_len {
                let fn_offset = offset - fn_len;
                let mut xor_fn = vec![0u8; fn_len];
                xor_fn.copy_from_slice(&tails[0][fn_offset..fn_offset + fn_len]);
                for tail in &tails[1..] {
                    for i in 0..fn_len {
                        xor_fn[i] ^= tail[fn_offset + i];
                    }
                }
                String::from_utf8(xor_fn).unwrap_or_else(|_| "restored.bin".to_string())
            } else {
                "restored.bin".to_string()
            };

            xor64.zeroize();
            return Ok(RfsMetadata::Rfs4 {
                expected_blks: blks,
                original_size: size,
                filename,
                filename_len: fn_len as u16,
            });
        }
        xor64.zeroize();
    }

    // 2. Prüfe RFS3 (60 Bytes)
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
    fn test_rfs4_n_way_roundtrip() {
        let key = [0x77u8; 32];
        let nonce = [0x88u8; 12];
        let mut rng = ChaChaRng::new(&key, &nonce);

        let dummy_digest = [0xCCu8; BLKS_DIGEST_SIZE];
        let original_size = 5000;
        let filename = "geheimes_dokument_äöü.pdf";

        let footers =
            encode_rfs4_footer_n_way(&dummy_digest, original_size, filename, 3, None, &mut rng)
                .expect("Encoding RFS4 fehlgeschlagen");
        assert_eq!(footers.len(), 3);

        // Prüfe 4 KiB Ausrichtung: original_size + tail_len muss Vielfaches von 4096 sein
        let tail_len = footers[0].len();
        assert_eq!((original_size + tail_len as u64) % 4096, 0);

        let tails: Vec<&[u8]> = footers.iter().map(|f| f.as_slice()).collect();
        let meta = decode_footer_n_way(&tails).expect("Decoding RFS4 fehlgeschlagen");
        match meta {
            RfsMetadata::Rfs4 {
                expected_blks,
                original_size: size,
                filename: fn_res,
                filename_len,
            } => {
                assert_eq!(expected_blks, dummy_digest);
                assert_eq!(size, original_size);
                assert_eq!(fn_res, filename);
                assert_eq!(filename_len as usize, filename.len());
            }
            _ => panic!("Erwartete RFS4 Metadata"),
        }

        // Test mit explizitem Zielpadding
        let target_pad = 65536; // 64 KiB
        let padded_footers = encode_rfs4_footer_n_way(
            &dummy_digest,
            original_size,
            filename,
            3,
            Some(target_pad),
            &mut rng,
        )
        .unwrap();
        assert_eq!(original_size + padded_footers[0].len() as u64, target_pad);
    }

    #[test]
    fn test_mismatch_error() {
        let garbage1 = [0x11u8; 60];
        let garbage2 = [0x22u8; 60];
        assert!(decode_footer(&garbage1, &garbage2).is_err());
    }
}
