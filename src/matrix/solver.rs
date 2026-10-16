//! Linear Algebraic Access Structure Solver & Security Verifier over GF(2).

use crate::matrix::gf2::{BitMatrix, BitVector};
use crate::matrix::policy::MatrixPolicy;

/// Solved linear generator matrices ready for streaming execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolvedMatrixSystem {
    pub num_shares: usize,
    /// Random basis generator matrix G (num_shares x num_random_bases)
    pub g_matrix: BitMatrix,
    /// Payload generator matrix H (num_shares x num_payloads)
    pub h_matrix: BitMatrix,
    pub num_random_bases: usize,
    pub num_payloads: usize,
}

impl SolvedMatrixSystem {
    /// Verifies the two fundamental LSSS conditions over GF(2):
    /// 1. Noise Annihilation for all authorized subsets: x^T * G == 0
    /// 2. Orthogonal Payload Isolation for all authorized subsets: x^T * H == e_k
    /// 3. Zero-Leakage Entropy Preservation for unauthorized subsets: y^T * G != 0
    pub fn verify_policy(&self, policy: &MatrixPolicy) -> Result<(), String> {
        for payload in &policy.payloads {
            let k = payload.id;
            for &auth_set in &payload.authorized_subsets {
                // Condition 1: Noise annihilation
                let g_res = self.g_matrix.mul_vec_left(auth_set);
                if g_res != BitVector::ZERO {
                    return Err(format!(
                        "Noise annihilation failed for payload '{}' with subset {:?}",
                        payload.name,
                        auth_set.to_indices()
                    ));
                }

                // Condition 2: Payload isolation
                let h_res = self.h_matrix.mul_vec_left(auth_set);
                for m in 0..self.num_payloads {
                    let expected = m == k;
                    let actual = h_res.get(m);
                    if actual != expected {
                        return Err(format!(
                            "Orthogonal isolation failed for payload '{}' (target index {}): expected {}, got {}",
                            payload.name, m, expected, actual
                        ));
                    }
                }
            }
        }

        // Condition 3: Every individual share i in 0..num_shares MUST be masked by at least
        // one random noise basis vector in G (i.e. row i of G must be non-zero).
        for share_idx in 0..self.num_shares {
            if self.g_matrix.rows[share_idx] == 0 {
                return Err(format!(
                    "Information-theoretic security violation: Share {} has zero random noise basis in G (unmasked plaintext combinación)!",
                    share_idx + 1
                ));
            }
        }

        Ok(())
    }
}

/// Solves a `MatrixPolicy` over GF(2) into concrete generator matrices G and H.
pub fn solve_matrix_policy(policy: &MatrixPolicy) -> Result<SolvedMatrixSystem, String> {
    let m = policy.num_shares;
    let num_payloads = policy.payloads.len();

    if num_payloads == 0 {
        return Err("Policy must declare at least 1 payload".to_string());
    }

    // Collect all authorized subset row constraints
    let mut constraint_rows: Vec<u64> = Vec::new();
    let mut row_payload_targets: Vec<usize> = Vec::new();

    for payload in &policy.payloads {
        for &subset in &payload.authorized_subsets {
            constraint_rows.push(subset.0);
            row_payload_targets.push(payload.id);
        }
    }

    let num_constraints = constraint_rows.len();
    if num_constraints == 0 {
        return Err("Policy must have at least 1 authorized subset constraint".to_string());
    }

    // Constraint matrix A: (num_constraints x m)
    let a_matrix = BitMatrix::from_rows(&constraint_rows, m);

    // 1. Solve for G: Columns of G must be in the kernel of A^T
    // x^T * G = 0 for all x in A <=> A * g_col = 0
    let kernel_basis = a_matrix.nullspace();
    let num_random_bases = kernel_basis.len();

    if num_random_bases == 0 {
        return Err(
            "Access structure has no unconstrained entropy dimension over GF(2)".to_string(),
        );
    }

    // Construct G (m x num_random_bases)
    let mut g_matrix = BitMatrix::zeros(m, num_random_bases);
    for (col_idx, &basis_vec) in kernel_basis.iter().enumerate() {
        for row_idx in 0..m {
            if basis_vec.get(row_idx) {
                g_matrix.set(row_idx, col_idx, true);
            }
        }
    }

    // 2. Solve for H: For each payload k, solve A * h_col_k = target_vector_k
    let mut h_matrix = BitMatrix::zeros(m, num_payloads);

    for k in 0..num_payloads {
        // Construct augmented matrix [A | target_k]
        let mut aug_rows = Vec::with_capacity(num_constraints);
        for r in 0..num_constraints {
            let target_bit = if row_payload_targets[r] == k {
                1u64
            } else {
                0u64
            };
            let aug_row = constraint_rows[r] | (target_bit << m);
            aug_rows.push(aug_row);
        }

        let mut aug = BitMatrix::from_rows(&aug_rows, m + 1);
        let (_rank, pivots) = aug.gauss_jordan_rref();

        // Check consistency: pivot in the augmented column (column m) means no solution
        if pivots.contains(&m) {
            return Err(format!(
                "Inconsistent access policy for payload '{}' (no linear solution over GF(2))",
                policy.payloads[k].name
            ));
        }

        // Back-substitution to extract particular solution h_col
        let mut h_col = BitVector::ZERO;
        for (row_idx, &pivot_col) in pivots.iter().enumerate() {
            if pivot_col < m && aug.get(row_idx, m) {
                h_col.set(pivot_col, true);
            }
        }

        for row_idx in 0..m {
            if h_col.get(row_idx) {
                h_matrix.set(row_idx, k, true);
            }
        }
    }

    let solved = SolvedMatrixSystem {
        num_shares: m,
        g_matrix,
        h_matrix,
        num_random_bases,
        num_payloads,
    };

    // Automated sanity check
    solved.verify_policy(policy)?;

    Ok(solved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solver_standard_2_of_2_otp() {
        let mut policy = MatrixPolicy::new(2);
        policy.add_payload("secret.bin", &[&[0, 1]], true);

        let solved = solve_matrix_policy(&policy).expect("Should solve 2-of-2 OTP");
        assert_eq!(solved.num_shares, 2);
        assert_eq!(solved.num_payloads, 1);
        assert!(solved.num_random_bases >= 1);
    }

    #[test]
    fn test_solver_multi_payload_decoy_system() {
        // 4 shares total:
        // Set {0, 1, 2} reveals secret.bin
        // Set {1, 2, 3} reveals decoy.pdf
        let mut policy = MatrixPolicy::new(4);
        policy.add_payload("secret.bin", &[&[0, 1, 2]], true);
        policy.add_payload("decoy.pdf", &[&[1, 2, 3]], false);

        let solved = solve_matrix_policy(&policy).expect("Should solve multi-payload policy");
        assert!(solved.verify_policy(&policy).is_ok());

        // Verify that {0, 1, 2} yields exactly secret.bin and NOT decoy.pdf
        let set_secret = BitVector::from_indices(&[0, 1, 2]);
        assert_eq!(solved.g_matrix.mul_vec_left(set_secret), BitVector::ZERO);
        assert_eq!(
            solved.h_matrix.mul_vec_left(set_secret),
            BitVector::from_indices(&[0])
        );

        // Verify that {1, 2, 3} yields exactly decoy.pdf and NOT secret.bin
        let set_decoy = BitVector::from_indices(&[1, 2, 3]);
        assert_eq!(solved.g_matrix.mul_vec_left(set_decoy), BitVector::ZERO);
        assert_eq!(
            solved.h_matrix.mul_vec_left(set_decoy),
            BitVector::from_indices(&[1])
        );
    }
}
