//! Multi-Target Stealth Footer & Trailer Obfuscation over GF(2).
//! Solves for M share tail blocks (filename + 64-byte trailer) such that each
//! authorized access subset XOR-reconstructs its distinct authentic filename and RFS4 trailer
//! with 100% BLKS-384 integrity, while unauthorized combinations yield uncorrelated noise.

use zeroize::Zeroize;

use crate::crypto::ChaChaRng;
use crate::matrix::gf2::{BitMatrix, BitVector};
use crate::matrix::policy::MatrixPolicy;
use crate::types::{BLKS_DIGEST_SIZE, RFS4_MAGIC, RFS4_TRAILER_SIZE};

/// Target metadata specification for one payload in the matrix system.
#[derive(Debug, Clone)]
pub struct TargetPayloadMeta {
    pub original_size: u64,
    pub blks_digest: [u8; BLKS_DIGEST_SIZE],
    pub filename: String,
}

impl TargetPayloadMeta {
    /// Formats the authentic 64-byte plaintext RFS4 trailer for this payload.
    pub fn build_plaintext_trailer(&self) -> Result<[u8; RFS4_TRAILER_SIZE], String> {
        let fn_bytes = self.filename.as_bytes();
        if fn_bytes.len() > u16::MAX as usize {
            return Err("Filename exceeds maximum length of 65535 bytes".to_string());
        }
        let fn_len = fn_bytes.len() as u16;

        let mut trailer = [0u8; RFS4_TRAILER_SIZE];
        trailer[0..4].copy_from_slice(&RFS4_MAGIC);
        trailer[4..6].copy_from_slice(&[0x04, 0x00]);
        trailer[6..14].copy_from_slice(&self.original_size.to_le_bytes());
        trailer[14..62].copy_from_slice(&self.blks_digest);
        trailer[62..64].copy_from_slice(&fn_len.to_le_bytes());

        Ok(trailer)
    }
}

/// Solves for M tail blocks (filename bytes + 64-byte trailer) satisfying all subset XOR constraints.
pub fn synthesize_multi_target_trailers(
    policy: &MatrixPolicy,
    targets: &[TargetPayloadMeta],
    rng: &mut ChaChaRng,
) -> Result<Vec<Vec<u8>>, String> {
    let m = policy.num_shares;
    let num_payloads = policy.payloads.len();

    if targets.len() != num_payloads {
        return Err(format!(
            "Mismatch: policy defines {} payloads, but {} targets provided",
            num_payloads,
            targets.len()
        ));
    }

    let max_fn_len = targets.iter().map(|t| t.filename.len()).max().unwrap_or(0);
    let full_tail_len = max_fn_len + RFS4_TRAILER_SIZE;

    // Build plaintext full tails [padding/random | filename | 64B trailer] for all targets
    let mut target_tails = Vec::with_capacity(num_payloads);
    for t in targets {
        let mut tail = vec![0u8; full_tail_len];
        // Fill prefix with random noise
        for b in &mut tail[..max_fn_len] {
            *b = rng.next_u8();
        }

        let trailer_64 = t.build_plaintext_trailer()?;
        tail[full_tail_len - RFS4_TRAILER_SIZE..full_tail_len].copy_from_slice(&trailer_64);

        let fn_bytes = t.filename.as_bytes();
        let fn_offset = full_tail_len - RFS4_TRAILER_SIZE - fn_bytes.len();
        tail[fn_offset..fn_offset + fn_bytes.len()].copy_from_slice(fn_bytes);

        target_tails.push(tail);
    }

    // Build constraint matrix rows: each authorized subset forms a row in A
    let mut constraint_rows: Vec<u64> = Vec::new();
    let mut row_payload_idx: Vec<usize> = Vec::new();

    for payload in &policy.payloads {
        for &subset in &payload.authorized_subsets {
            constraint_rows.push(subset.0);
            row_payload_idx.push(payload.id);
        }
    }

    let num_constraints = constraint_rows.len();
    if num_constraints == 0 {
        return Err("Policy must declare at least 1 subset constraint".to_string());
    }

    // Constraint matrix A: (num_constraints x m)
    let a_matrix = BitMatrix::from_rows(&constraint_rows, m);
    let nullspace_basis = a_matrix.nullspace();

    // Result: M tails of full_tail_len bytes each
    let mut share_trailers = vec![vec![0u8; full_tail_len]; m];

    // Total bits per tail block: full_tail_len * 8
    let total_bits = full_tail_len * 8;
    for bit_idx in 0..total_bits {
        let byte_pos = bit_idx / 8;
        let bit_in_byte = bit_idx % 8;

        // Build target bit vector for this position: length num_constraints
        let mut aug_rows = Vec::with_capacity(num_constraints);
        for r in 0..num_constraints {
            let p_idx = row_payload_idx[r];
            let target_byte = target_tails[p_idx][byte_pos];
            let target_bit = ((target_byte >> bit_in_byte) & 1) as u64;

            let aug_row = constraint_rows[r] | (target_bit << m);
            aug_rows.push(aug_row);
        }

        let mut aug = BitMatrix::from_rows(&aug_rows, m + 1);
        let (_rank, pivots) = aug.gauss_jordan_rref();

        if pivots.contains(&m) {
            return Err(format!(
                "Linearly conflicting trailer constraints at trailer bit {}",
                bit_idx
            ));
        }

        // Extract particular solution
        let mut sol = BitVector::ZERO;
        for (row_idx, &pivot_col) in pivots.iter().enumerate() {
            if pivot_col < m {
                let target_bit = (aug.rows[row_idx] >> m) & 1;
                sol.set(pivot_col, target_bit == 1);
            }
        }

        // Add random linear combinations from nullspace basis for white-noise degrees of freedom
        for basis_vec in &nullspace_basis {
            if rng.next_u8() & 1 == 1 {
                sol = BitVector(sol.0 ^ basis_vec.0);
            }
        }

        // Assign solution bits to each share trailer
        for (share_idx, trailer) in share_trailers.iter_mut().enumerate().take(m) {
            if sol.get(share_idx) {
                trailer[byte_pos] |= 1 << bit_in_byte;
            }
        }
    }

    // Zeroize sensitive plaintext targets
    for mut tail in target_tails {
        tail.zeroize();
    }

    Ok(share_trailers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::decode_footer_n_way;
    use crate::format::RfsMetadata;

    #[test]
    fn test_multi_target_trailer_synthesis_and_reconstruction() {
        let mut policy = MatrixPolicy::new(4);
        policy.add_payload("payload_alpha.txt", &[&[0, 1, 2]], true);
        policy.add_payload("payload_beta.pdf", &[&[1, 2, 3]], false);

        let targets = vec![
            TargetPayloadMeta {
                original_size: 1024,
                blks_digest: [0x11; BLKS_DIGEST_SIZE],
                filename: "payload_alpha.txt".to_string(),
            },
            TargetPayloadMeta {
                original_size: 2048,
                blks_digest: [0x22; BLKS_DIGEST_SIZE],
                filename: "payload_beta.pdf".to_string(),
            },
        ];

        let mut rng = ChaChaRng::new(&[0x33; 32], &[0x44; 12]);
        let trailers = synthesize_multi_target_trailers(&policy, &targets, &mut rng)
            .expect("Trailer synthesis failed");

        assert_eq!(trailers.len(), 4);

        // Check authorized subset 1: {0, 1, 2}
        let set1_slices: Vec<&[u8]> = vec![&trailers[0], &trailers[1], &trailers[2]];
        let meta1 = decode_footer_n_way(&set1_slices).expect("Failed to decode subset 1");
        match meta1 {
            RfsMetadata::Rfs4 {
                expected_blks,
                original_size,
                filename,
                ..
            } => {
                assert_eq!(expected_blks, [0x11; BLKS_DIGEST_SIZE]);
                assert_eq!(original_size, 1024);
                assert_eq!(filename, "payload_alpha.txt");
            }
            _ => panic!("Expected RFS4 metadata"),
        }

        // Check authorized subset 2: {1, 2, 3}
        let set2_slices: Vec<&[u8]> = vec![&trailers[1], &trailers[2], &trailers[3]];
        let meta2 = decode_footer_n_way(&set2_slices).expect("Failed to decode subset 2");
        match meta2 {
            RfsMetadata::Rfs4 {
                expected_blks,
                original_size,
                filename,
                ..
            } => {
                assert_eq!(expected_blks, [0x22; BLKS_DIGEST_SIZE]);
                assert_eq!(original_size, 2048);
                assert_eq!(filename, "payload_beta.pdf");
            }
            _ => panic!("Expected RFS4 metadata"),
        }

        // Check unauthorized subset: {0, 3}
        let unauth_slices: Vec<&[u8]> = vec![&trailers[0], &trailers[3]];
        assert!(decode_footer_n_way(&unauth_slices).is_err());
    }
}
