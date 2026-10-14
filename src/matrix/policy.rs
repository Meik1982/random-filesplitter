//! Access Structure Policies for RFS-Matrix over GF(2).

use crate::matrix::gf2::BitVector;

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
}
