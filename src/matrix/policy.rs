//! Access Structure Policies for RFS-Matrix over GF(2).

use crate::matrix::gf2::{BitMatrix, BitVector};

/// Specification for a single payload (genuine secret or decoy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadSpec {
    pub id: usize,
    pub name: String,
    pub authorized_subsets: Vec<BitVector>,
    pub is_secret: bool,
}

/// A comprehensive access policy defining which subsets reconstruct which payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixPolicy {
    pub num_shares: usize,
    pub payloads: Vec<PayloadSpec>,
}

impl MatrixPolicy {
    pub fn new(num_shares: usize) -> Self {
        assert!(
            (2..=64).contains(&num_shares),
            "Number of shares must be between 2 and 64"
        );
        MatrixPolicy {
            num_shares,
            payloads: Vec::new(),
        }
    }

    pub fn add_payload(
        &mut self,
        name: impl Into<String>,
        authorized_subsets: &[&[usize]],
        is_secret: bool,
    ) -> usize {
        let id = self.payloads.len();
        let subsets = authorized_subsets
            .iter()
            .map(|&s| BitVector::from_indices(s))
            .collect();

        self.payloads.push(PayloadSpec {
            id,
            name: name.into(),
            authorized_subsets: subsets,
            is_secret,
        });
        id
    }

    /// Automatically designs an optimal, linearly independent access policy
    /// distributing K payloads across M shares with subset size T (threshold).
    pub fn create_multi_payload_policy(
        num_shares: usize,
        threshold: usize,
        payload_names: &[String],
    ) -> Result<(MatrixPolicy, Vec<Vec<usize>>), String> {
        let k = payload_names.len();
        if k == 0 {
            return Err("At least 1 payload required".to_string());
        }
        if threshold < 2 || threshold > num_shares {
            return Err(format!(
                "Threshold T ({}) must be between 2 and total shares M ({})",
                threshold, num_shares
            ));
        }
        if num_shares < k + 1 {
            return Err(format!(
                "Information-Theoretic Constraint (Shannon Secrecy over GF(2)):\n\
                 Cannot embed {} payloads into {} shares.\n\
                 At least M >= N + 1 shares are mathematically required (for {} files: minimum M = {} shares).\n\
                 At least 1 share dimension must remain unconstrained as a pure ChaCha20 random noise basis.",
                k, num_shares, k, k + 1
            ));
        }

        let (min_valid_t, max_valid_t) = calculate_valid_threshold_range(k, num_shares);
        if threshold < min_valid_t || threshold > max_valid_t {
            let count = binomial_coefficient(num_shares, threshold);
            return Err(format!(
                "Combinatorial Constraint:\n\
                 Threshold T = {} is impossible for {} files on {} shares.\n\
                 Subsets of size {} on {} shares yield only {} combination(s) (C({}, {}) = {}), but {} files must be assigned.\n\
                 Mathematically valid threshold range for {} files on {} shares: T in {}..={}.",
                threshold, k, num_shares,
                threshold, num_shares, count, num_shares, threshold, count, k,
                k, num_shares, min_valid_t, max_valid_t
            ));
        }

        // Generate candidate combinations of size T
        let all_combinations = generate_combinations(num_shares, threshold);

        // Find K combinations with balanced share distribution and linear independence over GF(2)
        let mut chosen_subsets: Vec<Vec<usize>> = Vec::new();
        let mut chosen_vectors: Vec<BitVector> = Vec::new();
        let mut share_usage = vec![0usize; num_shares];

        while chosen_subsets.len() < k {
            let mut best_cand: Option<(Vec<usize>, BitVector)> = None;
            let mut best_score = usize::MAX;

            for comb in &all_combinations {
                if chosen_subsets.contains(comb) {
                    continue;
                }
                let vec = BitVector::from_indices(comb);

                // Check linear independence via rank increase
                let mut rows: Vec<u64> = chosen_vectors.iter().map(|v| v.0).collect();
                rows.push(vec.0);

                let mut test_matrix = BitMatrix::from_rows(&rows, num_shares);
                let (rank, _) = test_matrix.gauss_jordan_rref();

                if rank == chosen_vectors.len() + 1 {
                    let score: usize = comb.iter().map(|&idx| share_usage[idx]).sum();
                    if score < best_score {
                        best_score = score;
                        best_cand = Some((comb.clone(), vec));
                    }
                }
            }

            if let Some((cand, vec)) = best_cand {
                for &idx in &cand {
                    share_usage[idx] += 1;
                }
                chosen_subsets.push(cand);
                chosen_vectors.push(vec);
            } else {
                break;
            }
        }

        if chosen_subsets.len() < k {
            return Err(format!(
                "Could not find {} linearly independent subsets of size {} on {} shares over GF(2)",
                k, threshold, num_shares
            ));
        }

        let mut policy = MatrixPolicy::new(num_shares);
        for (i, name) in payload_names.iter().enumerate() {
            let slice: &[usize] = &chosen_subsets[i];
            policy.add_payload(name, &[slice], true);
        }

        Ok((policy, chosen_subsets))
    }
}

/// Generates all combinations of size k from 0..n.
fn generate_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    combinations_recurse(0, n, k, &mut current, &mut result);
    result
}

fn combinations_recurse(
    start: usize,
    n: usize,
    k: usize,
    current: &mut Vec<usize>,
    result: &mut Vec<Vec<usize>>,
) {
    if current.len() == k {
        result.push(current.clone());
        return;
    }
    for i in start..n {
        current.push(i);
        combinations_recurse(i + 1, n, k, current, result);
        current.pop();
    }
}

/// Calculates the binomial coefficient C(n, k) = n! / (k! * (n - k)!).
pub fn binomial_coefficient(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    if k == 0 || k == n {
        return 1;
    }
    let k = k.min(n - k);
    let mut c = 1usize;
    for i in 0..k {
        c = c.saturating_mul(n - i) / (i + 1);
    }
    c
}

/// Calculates the mathematically valid [min_T, max_T] threshold range
/// such that C(M, T) >= N files and linear secret sharing over GF(2) is feasible.
pub fn calculate_valid_threshold_range(n_files: usize, m_shares: usize) -> (usize, usize) {
    if n_files <= 1 {
        return (2, m_shares);
    }
    if m_shares < n_files + 1 {
        return (2, 2);
    }

    let mut min_t = 2;
    for t in 2..m_shares {
        if binomial_coefficient(m_shares, t) >= n_files {
            min_t = t;
            break;
        }
    }

    let mut max_t = (m_shares - 1).max(2);
    for t in (min_t..m_shares).rev() {
        if binomial_coefficient(m_shares, t) >= n_files {
            max_t = t;
            break;
        }
    }

    (min_t.min(max_t), max_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix::solver::solve_matrix_policy;

    #[test]
    fn test_multi_payload_policy_design_and_solution() {
        let names = vec![
            "vault.kdbx".to_string(),
            "vacation.pdf".to_string(),
            "invoice.xlsx".to_string(),
        ];
        // 3 payloads on 5 shares, 3-out-of-5 threshold
        let (policy, subsets) = MatrixPolicy::create_multi_payload_policy(5, 3, &names).unwrap();

        assert_eq!(subsets.len(), 3);
        assert_eq!(policy.payloads.len(), 3);

        // Verify that the policy solves cleanly and satisfies all GF(2) conditions
        let solved = solve_matrix_policy(&policy).unwrap();
        solved.verify_policy(&policy).unwrap();
    }
}
