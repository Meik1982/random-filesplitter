//! Interactive and machine-readable entropy diagnostics and cryptanalytic reports.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;
use zeroize::Zeroize;

use super::harvester::{
    init_permutation_pool, CacheLineNode, UniversalEntropyHarvester, POOL_NODES,
};
use super::stats::EntropyAccumulator;

/// Number of jitter samples for Phase 1
const JITTER_SAMPLES: usize = 2048;

/// Size of test keystream for Phase 2 (1 MiB)
const PHASE2_STREAM_SIZE: usize = 1024 * 1024;

/// Runs the two-phase system entropy diagnostics.
pub fn run_entropy_diagnostics() -> i32 {
    println!("============================================================");
    println!(" RFS Two-Phase Entropy & Jitter Diagnostics");
    println!("============================================================");

    // Phase 1: CPU Jitter Analysis (2 MB Cache-Line Permutation Pool)
    println!("\n[Phase 1] CPU Cache & Hardware Jitter Harvesting:");
    let mut pool: Vec<CacheLineNode> = (0..POOL_NODES)
        .map(|_| CacheLineNode {
            next: 0,
            _pad: [0u8; 60],
        })
        .collect();
    init_permutation_pool(&mut pool, 1337);

    let mut deltas = Vec::with_capacity(JITTER_SAMPLES);
    let mut curr_node = 0usize;
    for _ in 0..JITTER_SAMPLES {
        let t1 = Instant::now();
        for _ in 0..64 {
            curr_node = std::hint::black_box(pool[curr_node].next as usize);
        }
        let t2 = Instant::now();
        deltas.push(t2.duration_since(t1).as_nanos());
    }

    let mut varying_bits: u128 = 0;
    for i in 1..JITTER_SAMPLES {
        let diff = deltas[i].abs_diff(deltas[i - 1]);
        varying_bits |= diff;
    }
    let shift = if varying_bits != 0 {
        varying_bits.trailing_zeros()
    } else {
        0
    };

    let mut buckets = std::collections::HashMap::new();
    let mut bit_flips = 0;
    let mut last_bit = 0;

    for &d in &deltas[1..] {
        let val = (d >> shift) as u8;
        *buckets.entry(val).or_insert(0usize) += 1;
        let lsb = val & 1;
        if lsb != last_bit {
            bit_flips += 1;
        }
        last_bit = lsb;
    }

    let n = (JITTER_SAMPLES - 1) as f64;
    let mut raw_entropy = 0.0;
    for &count in buckets.values() {
        let p = count as f64 / n;
        raw_entropy -= p * p.log2();
    }

    let mean_delta = deltas.iter().sum::<u128>() as f64 / deltas.len() as f64;
    let variance = deltas
        .iter()
        .map(|&d| {
            let diff = d as f64 - mean_delta;
            diff * diff
        })
        .sum::<f64>()
        / deltas.len() as f64;
    let stddev = variance.sqrt();
    let bit_flip_ratio = (bit_flips as f64 / n) * 100.0;

    let jitter_variance_ok = stddev >= 1.0;
    let jitter_buckets_ok = buckets.len() >= 8;
    let jitter_bit_flips_ok =
        (10.0..=90.0).contains(&bit_flip_ratio) || (raw_entropy >= 1.2 && stddev >= 5.0);
    let jitter_entropy_ok = raw_entropy >= 1.2;
    let phase1_ok =
        jitter_variance_ok && jitter_buckets_ok && jitter_bit_flips_ok && jitter_entropy_ok;

    println!(
        "  - Timing Variance (StdDev):   {:.2} ns  {}",
        stddev,
        if jitter_variance_ok { "[OK]" } else { "[LOW]" }
    );
    println!(
        "  - Distinct Timing States:     {} Buckets  {}",
        buckets.len(),
        if jitter_buckets_ok { "[OK]" } else { "[LOW]" }
    );
    println!(
        "  - LSB Bit-Flip Ratio:         {:.1} %  {}",
        bit_flip_ratio,
        if jitter_bit_flips_ok {
            "[OK]"
        } else {
            "[WARNING]"
        }
    );
    println!(
        "  - Estimated Jitter Entropy:   {:.3} Bits/Sample  {}",
        raw_entropy,
        if jitter_entropy_ok {
            "[OK]"
        } else {
            "[WARNING]"
        }
    );
    println!(
        "  ➔ Phase 1 Status:             {}",
        if phase1_ok {
            "PASSED [OK]"
        } else {
            "FAILED [WARNING]"
        }
    );

    // Phase 2: CSPRNG & NIST SP 800-22 Tests on 1 MiB keystream
    println!("\n[Phase 2] NIST SP 800-22 & Statistical Analysis on 1 MiB CSPRNG Stream:");
    let (key, nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = crate::crypto::ChaChaRng::new(&key, &nonce);
    let mut stream = vec![0u8; PHASE2_STREAM_SIZE];
    rng.fill_bytes(&mut stream);

    let mut acc = EntropyAccumulator::new();
    acc.update(&stream);
    stream.zeroize();

    let m = acc.finalize().expect("non-empty stream");
    let phase2_ok = m.shannon_ok && m.chi_ok && m.mean_ok && m.bit_ok && m.runs_ok && m.block_ok;

    println!(
        "  - Shannon Entropy:            {:.6} / 8.000000  {}",
        m.shannon_entropy,
        if m.shannon_ok { "[OK]" } else { "[FAIL]" }
    );
    println!(
        "  - Chi-Square Goodness-of-Fit: {:.2} (180..330)  {}",
        m.chi_square,
        if m.chi_ok { "[OK]" } else { "[FAIL]" }
    );
    println!(
        "  - Arithmetic Mean:            {:.3} (Ideal: 127.5)  {}",
        m.mean,
        if m.mean_ok { "[OK]" } else { "[FAIL]" }
    );
    println!(
        "  - Bit Balance (1/0):          {:.3} % (Ideal: 50.0%)  {}",
        m.bit_balance_pct,
        if m.bit_ok { "[OK]" } else { "[FAIL]" }
    );
    println!(
        "  - NIST SP 800-22 Runs Test:   P-Value = {:.6}  {}",
        m.runs_p_value,
        if m.runs_ok { "[OK]" } else { "[FAIL]" }
    );
    println!(
        "  - NIST Block Frequency Test:  P-Value = {:.6}  {}",
        m.block_p_value,
        if m.block_ok { "[OK]" } else { "[FAIL]" }
    );
    println!(
        "  ➔ Phase 2 Status:             {}",
        if phase2_ok {
            "PASSED [OK]"
        } else {
            "FAILED [WARNING]"
        }
    );

    if phase1_ok && phase2_ok {
        println!("\n============================================================");
        println!(" OVERALL RESULT: ALL NIST & CRYPTOGRAPHIC TESTS PASSED [OK]");
        println!("============================================================\n");
        0
    } else {
        println!("\n============================================================");
        println!(" OVERALL RESULT: STATISTICAL ANOMALIES DETECTED [WARNING]");
        println!("============================================================\n");
        1
    }
}

/// Performs cryptanalytic file entropy analysis on a given file.
/// Supports both human-readable terminal output and machine-readable JSON.
pub fn analyze_file_entropy(path: &Path, json_mode: bool) -> Result<(), String> {
    let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut reader = BufReader::new(file);
    let mut acc = EntropyAccumulator::new();

    let mut buf = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Read error: {}", e))?;
        if n == 0 {
            break;
        }
        acc.update(&buf[..n]);
    }

    let m = acc
        .finalize()
        .ok_or_else(|| "File is empty (0 bytes). Analysis not possible.".to_string())?;

    let classification = if m.is_cryptographic {
        "VERY_HIGH_CRYPTOGRAPHIC"
    } else if m.shannon_entropy >= 7.9500 {
        "HIGH_COMPRESSED_OR_CIPHER"
    } else if m.shannon_entropy >= 6.5000 {
        "MEDIUM_BINARY_CODE"
    } else {
        "LOW_STRUCTURED_TEXT"
    };

    if json_mode {
        println!(
            "{{\"event\":\"file_entropy\",\"file\":\"{}\",\"size_bytes\":{},\"shannon_entropy\":{:.6},\"entropy_ratio_percent\":{:.2},\"chi_square\":{:.2},\"mean\":{:.4},\"bit_balance_percent\":{:.4},\"serial_correlation\":{:.6},\"pi_estimate\":{:.6},\"pi_error_percent\":{:.3},\"nist_runs\":{{\"p_value\":{:.6},\"passed\":{}}},\"nist_block_frequency\":{{\"p_value\":{:.6},\"passed\":{}}},\"is_cryptographic\":{},\"classification\":\"{}\"}}",
            path.display(),
            m.total_bytes,
            m.shannon_entropy,
            m.entropy_ratio_pct,
            m.chi_square,
            m.mean,
            m.bit_balance_pct,
            m.serial_correlation,
            m.pi_estimate,
            m.pi_error_pct,
            m.runs_p_value,
            m.runs_ok,
            m.block_p_value,
            m.block_ok,
            m.is_cryptographic,
            classification
        );
        return Ok(());
    }

    println!("============================================================");
    println!(" RFS Extended Cryptanalytic Entropy & NIST SP 800-22 Suite");
    println!("============================================================");
    println!(" File:   {}", path.display());
    println!(
        " Size:   {} Bytes ({:.2} MB)",
        m.total_bytes,
        m.total_bytes as f64 / (1024.0 * 1024.0)
    );
    println!("------------------------------------------------------------");
    println!(
        " [1] Shannon Entropy:\n     Measured:        {:.6} Bits / Byte  {}\n     Entropy Density: {:.2} % of theoretical maximum (8.000000)\n",
        m.shannon_entropy,
        if m.shannon_ok { "[OK]" } else { "[LOW]" },
        m.entropy_ratio_pct
    );
    println!(
        " [2] Chi-Square Goodness-of-Fit (df = 255):\n     Value:           {:.2}  {}\n     Ideal Range:     180.00 - 330.00 (for 95% uniform distribution)\n",
        m.chi_square,
        if m.chi_ok { "[PASSED]" } else { "[DEVIATION]" }
    );
    println!(
        " [3] Arithmetic Mean:\n     Measured:        {:.3}  {}\n     Ideal:           127.500 (Deviation: {:.3})\n",
        m.mean,
        if m.mean_ok { "[PASSED]" } else { "[DEVIATION]" },
        (m.mean - 127.5).abs()
    );
    println!(
        " [4] Bit Balance (1-Bits to 0-Bits):\n     Measured:        {:.3} %\n     Ideal:           50.000 % (Deviation: {:.3} %)\n",
        m.bit_balance_pct,
        (m.bit_balance_pct - 50.0).abs()
    );
    println!(
        " [5] Serial Autocorrelation (Lag-1):\n     Measured:        {:.6}  {}\n     Ideal:           0.000000\n",
        m.serial_correlation,
        if m.corr_ok { "[PASSED]" } else { "[CORRELATED]" }
    );
    println!(
        " [6] Monte Carlo Estimation of Pi:\n     Estimated:       {:.6}\n     Error:           {:.3} % from Pi\n",
        m.pi_estimate, m.pi_error_pct
    );
    println!(
        " [7] NIST SP 800-22 Runs Test (Bit Dynamics):\n     P-Value:         {:.6}  {}\n     Threshold:       p >= 0.01\n",
        m.runs_p_value,
        if m.runs_ok { "[PASSED]" } else { "[FAILED]" }
    );
    println!(
        " [8] NIST SP 800-22 Block Frequency Test (M=128):\n     P-Value:         {:.6}  {}\n     Threshold:       p >= 0.01\n",
        m.block_p_value,
        if m.block_ok { "[PASSED]" } else { "[FAILED]" }
    );
    println!("============================================================");
    println!(" CRYPTANALYTIC ASSESSMENT:");
    println!("============================================================");

    if m.is_cryptographic {
        println!(" Rating:   VERY HIGH ENTROPY (Cryptographic Grade)");
        println!(" Analysis: Data satisfies all NIST SP 800-22 thresholds and is");
        println!("           statistically indistinguishable from true white noise.");
        println!("           Typical for ChaCha20/AES ciphertexts or CSPRNG streams.");
    } else if m.shannon_entropy >= 7.9500 {
        println!(" Rating:   HIGH ENTROPY (Ciphertext or Strong Compression)");
        println!(" Analysis: High uniformity. Typical for compressed archives (gzip, zstd, xz)");
        println!("           or partially encrypted payloads.");
    } else if m.shannon_entropy >= 6.5000 {
        println!(" Rating:   MEDIUM ENTROPY (Binary Code / Semi-Structured)");
        println!(" Analysis: Typical for ELF/PE binaries, machine code, or media containers.");
    } else {
        println!(" Rating:   LOW ENTROPY (Plaintext / Structured Data)");
        println!(" Analysis: High redundancy and recognizable patterns. Typical for source code,");
        println!("           text, JSON, XML, databases, or zero-padded data.");
    }
    println!("============================================================\n");

    Ok(())
}
