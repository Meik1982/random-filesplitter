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
        // Bei chi_square == k sollte der p-Wert ca. 0.5 sein
        let p = chi_square_p_value(100.0, 100.0);
        assert!((p - 0.5).abs() < 0.05);
    }
}
