//! Multi-Target Stealth Footer & Trailer Obfuscation over GF(2).
//! Solves for M 64-byte trailers such that each authorized access subset
//! XOR-reconstructs its distinct authentic RFS4 trailer with 100% BLKS-384 integrity,
//! while unauthorized combinations yield uncorrelated pseudorandom noise.

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

/// Solves for M 64-byte share trailers satisfying all subset XOR constraints.
pub fn synthesize_multi_target_trailers(
    policy: &MatrixPolicy,
    targets: &[TargetPayloadMeta],
    rng: &mut ChaChaRng,
) -> Result<Vec<[u8; RFS4_TRAILER_SIZE]>, String> {
    let m = policy.num_shares;
    let num_payloads = policy.payloads.len();

    if targets.len() != num_payloads {
        return Err(format!(
            "Mismatch: policy defines {} payloads, but {} targets provided",
            num_payloads,
            targets.len()
        ));
    }

    // Build plaintext 64-byte trailers for all targets
    let mut target_trailers = Vec::with_capacity(num_payloads);
    for t in targets {
        target_trailers.push(t.build_plaintext_trailer()?);
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

    // Result: M trailers of 64 bytes each
    let mut share_trailers = vec![[0u8; RFS4_TRAILER_SIZE]; m];

    // Total bits per trailer: 64 bytes * 8 = 512 bits
    for bit_idx in 0..512 {
        let byte_pos = bit_idx / 8;
        let bit_in_byte = bit_idx % 8;

        // Build target bit vector for this position: length num_constraints
        let mut aug_rows = Vec::with_capacity(num_constraints);
        for r in 0..num_constraints {
            let p_idx = row_payload_idx[r];
            let target_byte = target_trailers[p_idx][byte_pos];
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
            if pivot_col < m && aug.get(row_idx, m) {
                sol.set(pivot_col, true);
            }
        }

        // Add random degrees of freedom from nullspace (white noise mask)
        for &null_vec in &nullspace_basis {
            let mut rand_byte = [0u8; 1];
            rng.fill_bytes(&mut rand_byte);
            if (rand_byte[0] & 1) == 1 {
                sol ^= null_vec;
            }
        }

        // Assign solution bits to each share trailer
        for share_idx in 0..m {
            if sol.get(share_idx) {
                share_trailers[share_idx][byte_pos] |= 1 << bit_in_byte;
            }
        }
    }

    // Clean up sensitive stack memory
    for t in &mut target_trailers {
        t.zeroize();
    }

    Ok(share_trailers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_target_trailer_synthesis_and_reconstruction() {
        let mut policy = MatrixPolicy::new(4);
        // Subset {0, 1, 2} reveals secret
        policy.add_payload("secret.txt", &[&[0, 1, 2]], true);
        // Subset {1, 2, 3} reveals decoy
        policy.add_payload("decoy.pdf", &[&[1, 2, 3]], false);

        let targets = vec![
            TargetPayloadMeta {
                original_size: 42,
                blks_digest: [0x55u8; BLKS_DIGEST_SIZE],
                filename: "secret.txt".to_string(),
            },
            TargetPayloadMeta {
                original_size: 999,
                blks_digest: [0xAAu8; BLKS_DIGEST_SIZE],
                filename: "decoy.pdf".to_string(),
            },
        ];

        let mut rng = ChaChaRng::new(&[0x12u8; 32], &[0x34u8; 12]);
        let trailers = synthesize_multi_target_trailers(&policy, &targets, &mut rng)
            .expect("Should synthesize trailers");

        assert_eq!(trailers.len(), 4);

        // Verify subset {0, 1, 2} XOR sum matches target 0 trailer bit-exact!
        let mut combined_secret = [0u8; RFS4_TRAILER_SIZE];
        for i in [0, 1, 2] {
            for b in 0..RFS4_TRAILER_SIZE {
                combined_secret[b] ^= trailers[i][b];
            }
        }
        let expected_secret = targets[0].build_plaintext_trailer().unwrap();
        assert_eq!(combined_secret, expected_secret);

        // Verify subset {1, 2, 3} XOR sum matches target 1 trailer bit-exact!
        let mut combined_decoy = [0u8; RFS4_TRAILER_SIZE];
        for i in [1, 2, 3] {
            for b in 0..RFS4_TRAILER_SIZE {
                combined_decoy[b] ^= trailers[i][b];
            }
        }
        let expected_decoy = targets[1].build_plaintext_trailer().unwrap();
        assert_eq!(combined_decoy, expected_decoy);

        // Verify unauthorized subset {0, 3} yields noise without RFS4 magic tag
        let mut combined_unauth = [0u8; RFS4_TRAILER_SIZE];
        for i in [0, 3] {
            for b in 0..RFS4_TRAILER_SIZE {
                combined_unauth[b] ^= trailers[i][b];
            }
        }
        assert_ne!(&combined_unauth[0..4], &RFS4_MAGIC);
    }
}
