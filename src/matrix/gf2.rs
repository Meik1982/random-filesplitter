//! Bit-parallel Linear Algebra over the Galois Field GF(2) ({0, 1}, XOR, AND).
//! Highly optimized for 64-bit word-level CPU instructions (up to 64 shares).

/// Represents an element of (GF(2))^M encoded into a single 64-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BitVector(pub u64);

impl BitVector {
    pub const ZERO: Self = BitVector(0);

    #[inline(always)]
    pub fn new(val: u64) -> Self {
        BitVector(val)
    }

    #[inline(always)]
    pub fn from_indices(indices: &[usize]) -> Self {
        let mut mask = 0u64;
        for &idx in indices {
            if idx < 64 {
                mask |= 1u64 << idx;
            }
        }
        BitVector(mask)
    }

    #[inline(always)]
    pub fn get(&self, index: usize) -> bool {
        if index < 64 {
            (self.0 >> index) & 1 == 1
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn set(&mut self, index: usize, value: bool) {
        if index < 64 {
            if value {
                self.0 |= 1u64 << index;
            } else {
                self.0 &= !(1u64 << index);
            }
        }
    }

    #[inline(always)]
    pub fn dot(&self, other: BitVector) -> bool {
        (self.0 & other.0).count_ones() % 2 == 1
    }

    #[inline(always)]
    pub fn hamming_weight(&self) -> u32 {
        self.0.count_ones()
    }

    pub fn to_indices(&self) -> Vec<usize> {
        let mut list = Vec::new();
        for i in 0..64 {
            if self.get(i) {
                list.push(i);
            }
        }
        list
    }
}

impl std::ops::BitXor for BitVector {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        BitVector(self.0 ^ rhs.0)
    }
}

impl std::ops::BitXorAssign for BitVector {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

/// A dense matrix over GF(2) with row-major `u64` bitboard representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitMatrix {
    pub rows: Vec<u64>,
    pub num_rows: usize,
    pub num_cols: usize,
}

impl BitMatrix {
    pub fn zeros(num_rows: usize, num_cols: usize) -> Self {
        assert!(
            num_cols <= 64,
            "BitMatrix columns capped at 64 for word-level parallelism"
        );
        BitMatrix {
            rows: vec![0u64; num_rows],
            num_rows,
            num_cols,
        }
    }

    pub fn from_rows(rows: &[u64], num_cols: usize) -> Self {
        assert!(num_cols <= 64, "BitMatrix columns capped at 64");
        BitMatrix {
            rows: rows.to_vec(),
            num_rows: rows.len(),
            num_cols,
        }
    }

    #[inline(always)]
    pub fn get(&self, r: usize, c: usize) -> bool {
        (self.rows[r] >> c) & 1 == 1
    }

    #[inline(always)]
    pub fn set(&mut self, r: usize, c: usize, val: bool) {
        if val {
            self.rows[r] |= 1u64 << c;
        } else {
            self.rows[r] &= !(1u64 << c);
        }
    }

    /// Transpose of the matrix: (num_rows x num_cols) -> (num_cols x num_rows)
    pub fn transpose(&self) -> Self {
        assert!(self.num_rows <= 64, "Transpose requires num_rows <= 64");
        let mut res = BitMatrix::zeros(self.num_cols, self.num_rows);
        for r in 0..self.num_rows {
            for c in 0..self.num_cols {
                if self.get(r, c) {
                    res.set(c, r, true);
                }
            }
        }
        res
    }

    /// Multiplies matrix with right column vector: M * v -> res
    pub fn mul_vec_right(&self, v: BitVector) -> Vec<bool> {
        let mut out = Vec::with_capacity(self.num_rows);
        for r in 0..self.num_rows {
            let dot = (self.rows[r] & v.0).count_ones() % 2 == 1;
            out.push(dot);
        }
        out
    }

    /// Multiplies left row vector with matrix: v^T * M -> res (1 x num_cols)
    pub fn mul_vec_left(&self, v: BitVector) -> BitVector {
        let mut res = 0u64;
        for (r, &row) in self.rows.iter().enumerate() {
            if v.get(r) {
                res ^= row;
            }
        }
        BitVector(res)
    }

    /// Performs Gauss-Jordan elimination to compute Reduced Row Echelon Form (RREF).
    /// Returns (rank, pivot_columns).
    pub fn gauss_jordan_rref(&mut self) -> (usize, Vec<usize>) {
        let mut lead = 0;
        let mut pivots = Vec::new();

        for r in 0..self.num_rows {
            if lead >= self.num_cols {
                break;
            }

            // Find pivot in current lead column
            let mut i = r;
            while ((self.rows[i] >> lead) & 1) == 0 {
                i += 1;
                if i == self.num_rows {
                    i = r;
                    lead += 1;
                    if lead == self.num_cols {
                        return (pivots.len(), pivots);
                    }
                }
            }

            // Swap rows
            self.rows.swap(i, r);

            // Eliminate all other rows in this column
            let pivot_row = self.rows[r];
            for j in 0..self.num_rows {
                if j != r && (((self.rows[j] >> lead) & 1) == 1) {
                    self.rows[j] ^= pivot_row;
                }
            }

            pivots.push(lead);
            lead += 1;
        }

        (pivots.len(), pivots)
    }

    /// Computes the kernel / nullspace basis {x | M * x = 0} over GF(2).
    pub fn nullspace(&self) -> Vec<BitVector> {
        let mut rref = self.clone();
        let (_rank, pivots) = rref.gauss_jordan_rref();

        let mut free_vars = Vec::new();
        for c in 0..self.num_cols {
            if !pivots.contains(&c) {
                free_vars.push(c);
            }
        }

        let mut basis = Vec::new();
        for &free_col in &free_vars {
            let mut vec = BitVector::ZERO;
            vec.set(free_col, true);

            for (row_idx, &pivot_col) in pivots.iter().enumerate() {
                if rref.get(row_idx, free_col) {
                    vec.set(pivot_col, true);
                }
            }
            basis.push(vec);
        }

        basis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitvector_basic_operations() {
        let v1 = BitVector::from_indices(&[0, 2, 4]);
        assert_eq!(v1.0, 1 | 4 | 16);
        assert!(v1.get(0));
        assert!(!v1.get(1));
        assert!(v1.get(2));
        assert_eq!(v1.hamming_weight(), 3);
        assert_eq!(v1.to_indices(), vec![0, 2, 4]);

        let v2 = BitVector::from_indices(&[2, 3]);
        let xor = v1 ^ v2;
        assert_eq!(xor.to_indices(), vec![0, 3, 4]);
        assert!(v1.dot(v2)); // overlap at 2 -> 1 (odd)
    }

    #[test]
    fn test_bitmatrix_gauss_jordan_and_nullspace() {
        // Linear system:
        // x0 ^ x1 = 0
        // x1 ^ x2 = 0
        // 2 rows, 3 cols
        // Kernel should be span([1, 1, 1])
        let m = BitMatrix::from_rows(
            &[
                0b011, // x0 ^ x1
                0b110, // x1 ^ x2
            ],
            3,
        );

        let null = m.nullspace();
        assert_eq!(null.len(), 1);
        assert_eq!(null[0].to_indices(), vec![0, 1, 2]);
    }
}
