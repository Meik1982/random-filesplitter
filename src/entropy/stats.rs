//! Statistical mathematics & NIST SP 800-22 distribution functions.

/// High-precision complementary error function erfc(x) (Abramowitz & Stegun 7.1.26).
/// Maximum error: < 1.5e-7 across full domain.
pub fn erfc(x: f64) -> f64 {
    if x < 0.0 {
        return 2.0 - erfc(-x);
    }
    let p = 0.3275911;
    let t = 1.0 / (1.0 + p * x);
    let poly = t
        * (0.254829592
            + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    poly * (-x * x).exp()
}

/// Calculates p-value for Chi-Square distribution with k degrees of freedom via Wilson-Hilferty transformation.
pub fn chi_square_p_value(chi_square: f64, k: f64) -> f64 {
    if k <= 0.0 || chi_square < 0.0 {
        return 0.0;
    }
    let q = 2.0 / (9.0 * k);
    let z = ((chi_square / k).powf(1.0 / 3.0) - (1.0 - q)) / q.sqrt();
    (0.5 * erfc(z / std::f64::consts::SQRT_2)).clamp(0.0, 1.0)
}

/// Calculates NIST SP 800-22 Runs Test p-value (bit transitions).
///
/// Returns `(p_value, passed)`.
pub fn calculate_runs_test(pi_ones: f64, transitions: u64, total_bits: f64) -> (f64, bool) {
    if total_bits <= 0.0 {
        return (0.0, false);
    }
    let tau = 2.0 / total_bits.sqrt();
    let p_value = if (pi_ones - 0.5).abs() >= tau {
        0.0
    } else {
        let v_n = 1.0 + transitions as f64;
        let numer = (v_n - 2.0 * total_bits * pi_ones * (1.0 - pi_ones)).abs();
        let denom = 2.0 * (2.0 * total_bits).sqrt() * pi_ones * (1.0 - pi_ones);
        if denom == 0.0 {
            0.0
        } else {
            erfc(numer / denom)
        }
    };
    (p_value, p_value >= 0.01)
}

/// Calculates NIST SP 800-22 Block Frequency Test p-value ($M=128$).
///
/// Returns `(p_value, passed)`.
pub fn calculate_block_frequency_test(block_chi_sum: f64, num_blocks: u64) -> (f64, bool) {
    if num_blocks == 0 {
        return (1.0, true);
    }
    let block_chi_obs = 512.0 * block_chi_sum;
    let p_value = chi_square_p_value(block_chi_obs, num_blocks as f64);
    (p_value, p_value >= 0.01)
}

/// Comprehensive statistical & NIST SP 800-22 metrics for a byte stream.
#[derive(Debug, Clone)]
pub struct EntropyMetrics {
    pub total_bytes: u64,
    pub shannon_entropy: f64,
    pub entropy_ratio_pct: f64,
    pub chi_square: f64,
    pub mean: f64,
    pub bit_balance_pct: f64,
    pub serial_correlation: f64,
    pub pi_estimate: f64,
    pub pi_error_pct: f64,
    pub runs_p_value: f64,
    pub runs_ok: bool,
    pub block_p_value: f64,
    pub block_ok: bool,
    pub shannon_ok: bool,
    pub chi_ok: bool,
    pub mean_ok: bool,
    pub bit_ok: bool,
    pub corr_ok: bool,
    pub is_cryptographic: bool,
}

/// Streaming accumulator for NIST SP 800-22 and cryptanalytic byte-stream statistics.
pub struct EntropyAccumulator {
    byte_counts: [u64; 256],
    total_bytes: u64,
    total_ones: u64,
    sum_bytes: f64,
    sum_prod: f64,
    sum_sq: f64,
    prev_byte: Option<u8>,
    mc_in_circle: u64,
    mc_total_pairs: u64,
    mc_pending_x: Option<u8>,
    transitions: u64,
    prev_bit: Option<u8>,
    block_chi_sum: f64,
    num_blocks: u64,
    block_buf: [u8; 16],
    block_pos: usize,
}

impl Default for EntropyAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyAccumulator {
    pub fn new() -> Self {
        Self {
            byte_counts: [0u64; 256],
            total_bytes: 0,
            total_ones: 0,
            sum_bytes: 0.0,
            sum_prod: 0.0,
            sum_sq: 0.0,
            prev_byte: None,
            mc_in_circle: 0,
            mc_total_pairs: 0,
            mc_pending_x: None,
            transitions: 0,
            prev_bit: None,
            block_chi_sum: 0.0,
            num_blocks: 0,
            block_buf: [0u8; 16],
            block_pos: 0,
        }
    }

    /// Feeds a slice of bytes into the statistical and NIST SP 800-22 accumulators.
    pub fn update(&mut self, chunk: &[u8]) {
        for &b in chunk {
            self.byte_counts[b as usize] += 1;
            self.sum_bytes += b as f64;
            let ones = b.count_ones();
            self.total_ones += ones as u64;

            if let Some(prev) = self.prev_byte {
                let x = prev as f64 - 127.5;
                let y = b as f64 - 127.5;
                self.sum_prod += x * y;
                self.sum_sq += x * x;
            }
            self.prev_byte = Some(b);

            if let Some(x_val) = self.mc_pending_x {
                let x = (x_val as f64 + 0.5) / 256.0;
                let y = (b as f64 + 0.5) / 256.0;
                if (x * x + y * y) <= 1.0 {
                    self.mc_in_circle += 1;
                }
                self.mc_total_pairs += 1;
                self.mc_pending_x = None;
            } else {
                self.mc_pending_x = Some(b);
            }

            for bit_idx in 0..8 {
                let bit = (b >> bit_idx) & 1;
                if let Some(p) = self.prev_bit {
                    if bit != p {
                        self.transitions += 1;
                    }
                }
                self.prev_bit = Some(bit);
            }

            self.block_buf[self.block_pos] = b;
            self.block_pos += 1;
            if self.block_pos == 16 {
                let b_ones: u64 = self.block_buf.iter().map(|&x| x.count_ones() as u64).sum();
                let diff = (b_ones as f64 / 128.0) - 0.5;
                self.block_chi_sum += diff * diff;
                self.num_blocks += 1;
                self.block_pos = 0;
            }
        }
        self.total_bytes += chunk.len() as u64;
    }

    /// Finalizes all statistical metrics and NIST SP 800-22 p-values.
    pub fn finalize(&self) -> Option<EntropyMetrics> {
        if self.total_bytes == 0 {
            return None;
        }

        let total_f = self.total_bytes as f64;
        let expected = total_f / 256.0;
        let mut shannon_entropy = 0.0;
        let mut chi_square = 0.0;

        for &c in &self.byte_counts {
            if c > 0 {
                let p = c as f64 / total_f;
                shannon_entropy -= p * p.log2();
            }
            let diff = c as f64 - expected;
            chi_square += (diff * diff) / expected;
        }

        let entropy_ratio_pct = (shannon_entropy / 8.0) * 100.0;
        let mean = self.sum_bytes / total_f;
        let total_bits = total_f * 8.0;
        let pi_ones = self.total_ones as f64 / total_bits;
        let bit_balance_pct = pi_ones * 100.0;
        let serial_correlation = if self.sum_sq > 0.0 {
            self.sum_prod / self.sum_sq
        } else {
            0.0
        };

        let pi_estimate = if self.mc_total_pairs > 0 {
            4.0 * (self.mc_in_circle as f64 / self.mc_total_pairs as f64)
        } else {
            0.0
        };
        let pi_error_pct =
            ((pi_estimate - std::f64::consts::PI).abs() / std::f64::consts::PI) * 100.0;

        let (runs_p_value, runs_ok) = calculate_runs_test(pi_ones, self.transitions, total_bits);
        let (block_p_value, block_ok) =
            calculate_block_frequency_test(self.block_chi_sum, self.num_blocks);

        let shannon_ok = shannon_entropy >= (7.9990 - (200.0 / total_f)).max(7.90);
        let chi_ok = (180.0..=330.0).contains(&chi_square);
        let mean_bound = (4.0 * 73.9 / total_f.sqrt()).max(0.25);
        let mean_ok = (mean - 127.5).abs() <= mean_bound;
        let bit_bound = (4.0 * 50.0 / total_bits.sqrt()).max(0.08);
        let bit_ok = (bit_balance_pct - 50.0).abs() <= bit_bound;
        let corr_bound = (4.0 / total_f.sqrt()).max(0.002);
        let corr_ok = serial_correlation.abs() < corr_bound;
        let is_cryptographic = shannon_ok && chi_ok && mean_ok && corr_ok && runs_ok && block_ok;

        Some(EntropyMetrics {
            total_bytes: self.total_bytes,
            shannon_entropy,
            entropy_ratio_pct,
            chi_square,
            mean,
            bit_balance_pct,
            serial_correlation,
            pi_estimate,
            pi_error_pct,
            runs_p_value,
            runs_ok,
            block_p_value,
            block_ok,
            shannon_ok,
            chi_ok,
            mean_ok,
            bit_ok,
            corr_ok,
            is_cryptographic,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_erfc_accuracy() {
        assert!((erfc(0.0) - 1.0).abs() < 1e-6);
        assert!((erfc(1.0) - 0.157299).abs() < 1e-4);
        assert!(erfc(5.0) < 1e-10);
    }

    #[test]
    pub fn test_chi_square_p_value() {
        // When chi_square == k, the p-value should be approximately 0.5
        let p = chi_square_p_value(100.0, 100.0);
        assert!((p - 0.5).abs() < 0.05);
    }
}
