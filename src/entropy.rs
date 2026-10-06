//! Universal High-Resolution Entropy Harvesting, NIST SP 800-22 Test Suite,
//! and Deep Cryptographic Randomness Diagnostics.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;
use zeroize::Zeroize;

/// Anzahl der Jitter-Stichproben für Phase 1
const JITTER_SAMPLES: usize = 2048;

/// Größe des Teststroms für Phase 2 (1 MiB)
const PHASE2_STREAM_SIZE: usize = 1024 * 1024;

/// Universeller Entropie-Harvester: Erntet hochwertige 256-Bit Schlüssel und 96-Bit Nonce.
pub struct UniversalEntropyHarvester;

impl UniversalEntropyHarvester {
    /// Erntet kryptografisch sichere 32-Byte Key und 12-Byte Nonce
    pub fn harvest_seed() -> ([u8; 32], [u8; 12]) {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];

        // 1. Primärquelle: OS-Kernel CSPRNG (getrandom)
        getrandom::getrandom(&mut key).expect("OS CSPRNG Fehler bei Key");
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG Fehler bei Nonce");

        // 2. Defence-in-Depth: CPU-Jitter und High-Res Clock einmischen
        let now = Instant::now();
        let nanos = now.elapsed().as_nanos();
        let jitter = Self::sample_cpu_jitter();

        for (i, b) in key.iter_mut().enumerate() {
            *b ^= ((nanos >> (i * 2)) as u8) ^ jitter[i % jitter.len()];
        }
        for (i, b) in nonce.iter_mut().enumerate() {
            *b ^= ((nanos >> (i * 3 + 1)) as u8) ^ jitter[(i + 7) % jitter.len()];
        }

        (key, nonce)
    }

    /// Schneller CPU-Jitter-Sampler für Entropie-Mischung
    fn sample_cpu_jitter() -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut prev = Instant::now();
        for (i, b) in out.iter_mut().enumerate() {
            let mut acc = 0u64;
            for _ in 0..64 {
                let curr = Instant::now();
                let delta = curr.duration_since(prev).as_nanos() as u64;
                acc = acc.wrapping_mul(6364136223846793005).wrapping_add(delta);
                prev = curr;
            }
            *b = (acc ^ (acc >> 8) ^ (acc >> 16) ^ (acc >> 24) ^ (i as u64)) as u8;
        }
        out
    }
}

/// Komplementäre Fehlerfunktion erfc(x) mit hoher Präzision (Abramowitz & Stegun 7.1.26).
/// Maximaler Fehler: < 1.5e-7 über den gesamten Definitionsbereich.
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

/// Berechnet den P-Wert für Chi-Quadrat mit $k$ Freiheitsgraden via Wilson-Hilferty Transformation.
pub fn chi_square_p_value(chi_square: f64, k: f64) -> f64 {
    if k <= 0.0 || chi_square < 0.0 {
        return 0.0;
    }
    let q = 2.0 / (9.0 * k);
    let z = ((chi_square / k).powf(1.0 / 3.0) - (1.0 - q)) / q.sqrt();
    (0.5 * erfc(z / std::f64::consts::SQRT_2)).clamp(0.0, 1.0)
}

/// Führt die zweiphasige Entropiediagnose der lokalen Systemumgebung aus.
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn run_entropy_diagnostics() -> i32 {
    println!("============================================================");
    println!(" RFS Zweiphasige Entropie- & Jitter-Diagnose");
    println!("============================================================");

    // Phase 1: CPU Jitter Analyse
    println!("\n[Phase 1] CPU-Cache- & Hardware-Jitter-Ernte:");
    let mut deltas = Vec::with_capacity(JITTER_SAMPLES);
    let mut prev = Instant::now();
    for _ in 0..JITTER_SAMPLES {
        let curr = Instant::now();
        deltas.push(curr.duration_since(prev).as_nanos());
        prev = curr;
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
        (20.0..=80.0).contains(&bit_flip_ratio) || (raw_entropy >= 1.5 && stddev >= 5.0);
    let jitter_entropy_ok = raw_entropy >= 1.2;
    let phase1_ok =
        jitter_variance_ok && jitter_buckets_ok && jitter_bit_flips_ok && jitter_entropy_ok;

    println!(
        "  - Zeit-Varianz (StdDev):      {:.2} ns  {}",
        stddev,
        if jitter_variance_ok {
            "[OK]"
        } else {
            "[GERING]"
        }
    );
    println!(
        "  - Eindeutige Zeitstufen:      {} Buckets  {}",
        buckets.len(),
        if jitter_buckets_ok {
            "[OK]"
        } else {
            "[GERING]"
        }
    );
    println!(
        "  - LSB Bit-Flip-Verhaeltnis:   {:.1} %  {}",
        bit_flip_ratio,
        if jitter_bit_flips_ok {
            "[OK]"
        } else {
            "[WARNUNG]"
        }
    );
    println!(
        "  - Geschaetzte Jitter-Entropie: {:.3} Bits/Sample  {}",
        raw_entropy,
        if jitter_entropy_ok {
            "[OK]"
        } else {
            "[WARNUNG]"
        }
    );
    println!(
        "  ➔ Phase 1 Status:             {}",
        if phase1_ok {
            "BESTANDEN [OK]"
        } else {
            "FEHLGESCHLAGEN [WARNUNG]"
        }
    );

    // Phase 2: CSPRNG & NIST SP 800-22 Tests auf 1 MiB Datenstrom
    println!("\n[Phase 2] NIST SP 800-22 & Statistische Analyse auf 1 MiB CSPRNG-Strom:");
    let (key, nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = crate::crypto::ChaChaRng::new(&key, &nonce);
    let mut stream = vec![0u8; PHASE2_STREAM_SIZE];
    rng.fill_bytes(&mut stream);

    let mut byte_counts = [0usize; 256];
    let mut ones_count = 0u64;
    let mut sum_val = 0u64;
    let mut transitions = 0u64;
    let mut prev_bit = None;

    // Block-Frequenztest Vorbereitung (M = 128 Bits / 16 Bytes)
    const BLOCK_BYTES: usize = 16;
    let num_blocks = PHASE2_STREAM_SIZE / BLOCK_BYTES;
    let mut block_chi_sum = 0.0;

    for chunk in stream.chunks_exact(BLOCK_BYTES) {
        let mut block_ones = 0u32;
        for &b in chunk {
            byte_counts[b as usize] += 1;
            let ones = b.count_ones();
            ones_count += ones as u64;
            sum_val += b as u64;
            block_ones += ones;

            for bit_idx in 0..8 {
                let bit = (b >> bit_idx) & 1;
                if let Some(p) = prev_bit {
                    if bit != p {
                        transitions += 1;
                    }
                }
                prev_bit = Some(bit);
            }
        }
        let pi = block_ones as f64 / 128.0;
        let diff = pi - 0.5;
        block_chi_sum += diff * diff;
    }

    let total = PHASE2_STREAM_SIZE as f64;
    let mut shannon = 0.0;
    let mut chi_square = 0.0;
    let expected = total / 256.0;

    for &c in &byte_counts {
        if c > 0 {
            let p = c as f64 / total;
            shannon -= p * p.log2();
        }
        let d = c as f64 - expected;
        chi_square += (d * d) / expected;
    }

    let mean = sum_val as f64 / total;
    let total_bits = (PHASE2_STREAM_SIZE * 8) as f64;
    let pi_ones = ones_count as f64 / total_bits;
    let bit_balance_pct = pi_ones * 100.0;

    // NIST Runs Test P-Wert
    let tau = 2.0 / total_bits.sqrt();
    let runs_p_value = if (pi_ones - 0.5).abs() >= tau {
        0.0
    } else {
        let v_n = 1.0 + transitions as f64;
        let numer = (v_n - 2.0 * total_bits * pi_ones * (1.0 - pi_ones)).abs();
        let denom = 2.0 * (2.0 * total_bits).sqrt() * pi_ones * (1.0 - pi_ones);
        erfc(numer / denom)
    };
    let runs_ok = runs_p_value >= 0.01;

    // NIST Block Frequency Test P-Wert
    let block_chi_obs = 512.0 * block_chi_sum;
    let block_p_value = chi_square_p_value(block_chi_obs, num_blocks as f64);
    let block_ok = block_p_value >= 0.01;

    let shannon_ok = shannon >= 7.9999;
    let chi_ok = (180.0..=330.0).contains(&chi_square);
    let mean_ok = (mean - 127.5).abs() <= 0.1;
    let bit_ok = (bit_balance_pct - 50.0).abs() <= 0.05;

    let phase2_ok = shannon_ok && chi_ok && mean_ok && bit_ok && runs_ok && block_ok;

    println!(
        "  - Shannon-Entropie:           {:.6} / 8.000000  {}",
        shannon,
        if shannon_ok { "[OK]" } else { "[FEHLER]" }
    );
    println!(
        "  - Chi-Quadrat Anpassung:      {:.2} (180..330)  {}",
        chi_square,
        if chi_ok { "[OK]" } else { "[FEHLER]" }
    );
    println!(
        "  - Arithmetischer Mittelwert:  {:.3} (Ideal: 127.5)  {}",
        mean,
        if mean_ok { "[OK]" } else { "[FEHLER]" }
    );
    println!(
        "  - Bit-Verhaeltnis (1/0):      {:.3} % (Ideal: 50.0%)  {}",
        bit_balance_pct,
        if bit_ok { "[OK]" } else { "[FEHLER]" }
    );
    println!(
        "  - NIST SP 800-22 Runs-Test:   P-Wert = {:.6}  {}",
        runs_p_value,
        if runs_ok { "[OK]" } else { "[FEHLER]" }
    );
    println!(
        "  - NIST Block-Frequenztest:    P-Wert = {:.6}  {}",
        block_p_value,
        if block_ok { "[OK]" } else { "[FEHLER]" }
    );
    println!(
        "  ➔ Phase 2 Status:             {}",
        if phase2_ok {
            "BESTANDEN [OK]"
        } else {
            "FEHLGESCHLAGEN [WARNUNG]"
        }
    );

    stream.zeroize();

    if phase1_ok && phase2_ok {
        println!("\n============================================================");
        println!(" GESAMTFAZIT: ALLE NIST- & KRYPTOTESTS BESTANDEN [OK]");
        println!("============================================================\n");
        0
    } else {
        println!("\n============================================================");
        println!(" GESAMTFAZIT: STATISTISCHE ANOMALIEN ENTDECKT [WARNUNG]");
        println!("============================================================\n");
        1
    }
}

/// Führt eine kryptoanalytische Datei-Entropieanalyse für eine gegebene Datei durch.
/// Unterstützt sowohl interaktiven Klartext als auch maschinenlesbares JSON.
pub fn analyze_file_entropy(path: &Path, json_mode: bool) -> Result<(), String> {
    let file = File::open(path).map_err(|e| format!("Fehler beim Öffnen der Datei: {}", e))?;
    let mut reader = BufReader::new(file);

    let mut byte_counts = [0u64; 256];
    let mut total_bytes: u64 = 0;
    let mut total_ones: u64 = 0;
    let mut sum_bytes: f64 = 0.0;

    let mut sum_prod: f64 = 0.0;
    let mut sum_sq: f64 = 0.0;
    let mut prev_byte: Option<u8> = None;

    let mut mc_in_circle: u64 = 0;
    let mut mc_total_pairs: u64 = 0;
    let mut mc_pending_x: Option<u8> = None;

    // NIST SP 800-22 Runs Test Akkumulator
    let mut transitions: u64 = 0;
    let mut prev_bit: Option<u8> = None;

    // NIST SP 800-22 Block-Frequenztest (M = 128 Bits / 16 Bytes)
    const BLOCK_LEN: usize = 16;
    let mut block_chi_sum = 0.0;
    let mut num_blocks: u64 = 0;
    let mut block_buf = [0u8; BLOCK_LEN];
    let mut block_pos = 0;

    let mut buf = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Fehler beim Lesen: {}", e))?;
        if n == 0 {
            break;
        }

        for &b in &buf[..n] {
            byte_counts[b as usize] += 1;
            sum_bytes += b as f64;
            let ones = b.count_ones();
            total_ones += ones as u64;

            // Autokorrelation
            if let Some(prev) = prev_byte {
                let x = prev as f64 - 127.5;
                let y = b as f64 - 127.5;
                sum_prod += x * y;
                sum_sq += x * x;
            }
            prev_byte = Some(b);

            // Monte Carlo Pi
            if let Some(x_val) = mc_pending_x {
                let x = (x_val as f64 + 0.5) / 256.0;
                let y = (b as f64 + 0.5) / 256.0;
                if (x * x + y * y) <= 1.0 {
                    mc_in_circle += 1;
                }
                mc_total_pairs += 1;
                mc_pending_x = None;
            } else {
                mc_pending_x = Some(b);
            }

            // NIST Runs-Bitübergänge
            for bit_idx in 0..8 {
                let bit = (b >> bit_idx) & 1;
                if let Some(p) = prev_bit {
                    if bit != p {
                        transitions += 1;
                    }
                }
                prev_bit = Some(bit);
            }

            // NIST Block-Frequenz Puffer
            block_buf[block_pos] = b;
            block_pos += 1;
            if block_pos == BLOCK_LEN {
                let b_ones = block_buf
                    .iter()
                    .map(|&x| x.count_ones() as u64)
                    .sum::<u64>();
                let pi = b_ones as f64 / 128.0;
                let diff = pi - 0.5;
                block_chi_sum += diff * diff;
                num_blocks += 1;
                block_pos = 0;
            }
        }
        total_bytes += n as u64;
    }

    if total_bytes == 0 {
        return Err("Datei ist leer (0 Bytes). Analyse nicht möglich.".to_string());
    }

    let mut shannon_entropy = 0.0;
    let mut chi_square = 0.0;
    let expected = total_bytes as f64 / 256.0;

    for &c in &byte_counts {
        if c > 0 {
            let p = c as f64 / total_bytes as f64;
            shannon_entropy -= p * p.log2();
        }
        let diff = c as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    let entropy_ratio = (shannon_entropy / 8.0) * 100.0;
    let mean = sum_bytes / total_bytes as f64;
    let total_bits = (total_bytes * 8) as f64;
    let pi_ones = total_ones as f64 / total_bits;
    let bit_balance = pi_ones * 100.0;
    let serial_corr = if sum_sq > 0.0 { sum_prod / sum_sq } else { 0.0 };

    let pi_est = if mc_total_pairs > 0 {
        4.0 * (mc_in_circle as f64 / mc_total_pairs as f64)
    } else {
        0.0
    };
    let pi_err = ((pi_est - std::f64::consts::PI).abs() / std::f64::consts::PI) * 100.0;

    // NIST SP 800-22 Runs Test P-Wert
    let tau = 2.0 / total_bits.sqrt();
    let runs_p_value = if (pi_ones - 0.5).abs() >= tau {
        0.0
    } else {
        let v_n = 1.0 + transitions as f64;
        let numer = (v_n - 2.0 * total_bits * pi_ones * (1.0 - pi_ones)).abs();
        let denom = 2.0 * (2.0 * total_bits).sqrt() * pi_ones * (1.0 - pi_ones);
        erfc(numer / denom)
    };
    let runs_ok = runs_p_value >= 0.01;

    // NIST SP 800-22 Block-Frequenztest P-Wert
    let (block_p_value, block_ok) = if num_blocks > 0 {
        let obs = 512.0 * block_chi_sum;
        let p_val = chi_square_p_value(obs, num_blocks as f64);
        (p_val, p_val >= 0.01)
    } else {
        (1.0, true)
    };

    let shannon_ok = shannon_entropy >= 7.9990;
    let chi_ok = (180.0..=330.0).contains(&chi_square);
    let mean_ok = (mean - 127.5).abs() <= 0.25;
    let corr_ok = serial_corr.abs() < 0.002;

    let is_cryptographic = shannon_ok && chi_ok && mean_ok && corr_ok && runs_ok && block_ok;

    let classification = if is_cryptographic {
        "SEHR_HOCH_KRYPTOGRAFISCH"
    } else if shannon_entropy >= 7.9500 {
        "HOCH_KOMPRIMIERT_ODER_CIPHER"
    } else if shannon_entropy >= 6.5000 {
        "MITTEL_BINAERCODE"
    } else {
        "NIEDRIG_STRUKTURIERT_TEXT"
    };

    if json_mode {
        println!(
            "{{\"event\":\"file_entropy\",\"file\":\"{}\",\"size_bytes\":{},\"shannon_entropy\":{:.6},\"entropy_ratio_percent\":{:.2},\"chi_square\":{:.2},\"mean\":{:.4},\"bit_balance_percent\":{:.4},\"serial_correlation\":{:.6},\"pi_estimate\":{:.6},\"pi_error_percent\":{:.3},\"nist_runs\":{{\"p_value\":{:.6},\"passed\":{}}},\"nist_block_frequency\":{{\"p_value\":{:.6},\"passed\":{}}},\"is_cryptographic\":{},\"classification\":\"{}\"}}",
            path.display(),
            total_bytes,
            shannon_entropy,
            entropy_ratio,
            chi_square,
            mean,
            bit_balance,
            serial_corr,
            pi_est,
            pi_err,
            runs_p_value,
            runs_ok,
            block_p_value,
            block_ok,
            is_cryptographic,
            classification
        );
        return Ok(());
    }

    println!("============================================================");
    println!(" RFS Erweiterte Kryptoanalytische Entropie- & NIST-Suite");
    println!("============================================================");
    println!(" Datei:   {}", path.display());
    println!(
        " Groesse: {} Bytes ({:.2} MB)",
        total_bytes,
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    println!("------------------------------------------------------------");
    println!(
        " [1] Shannon-Entropie:\n     Gemessen:        {:.6} Bits / Byte  {}\n     Entropiedichte:  {:.2} % des theoretischen Maximums (8.000000)\n",
        shannon_entropy, if shannon_ok { "[OK]" } else { "[NIEDRIG]" }, entropy_ratio
    );
    println!(
        " [2] Chi-Quadrat Anpassungstest (df = 255):\n     Wert:            {:.2}  {}\n     Idealbereich:    180.00 - 330.00 (fuer 95 % Gleichverteilung)\n",
        chi_square, if chi_ok { "[BESTANDEN]" } else { "[ABWEICHUNG]" }
    );
    println!(
        " [3] Arithmetischer Mittelwert:\n     Gemessen:        {:.3}  {}\n     Ideal:           127.500 (Abweichung: {:.3})\n",
        mean, if mean_ok { "[BESTANDEN]" } else { "[ABWEICHUNG]" }, (mean - 127.5).abs()
    );
    println!(
        " [4] Bit-Balance (1-Bits zu 0-Bits):\n     Gemessen:        {:.3} %\n     Ideal:           50.000 % (Abweichung: {:.3} %)\n",
        bit_balance, (bit_balance - 50.0).abs()
    );
    println!(
        " [5] Serielle Autokorrelation (Lag-1):\n     Gemessen:        {:.6}  {}\n     Ideal:           0.000000\n",
        serial_corr, if corr_ok { "[BESTANDEN]" } else { "[KORRELIERT]" }
    );
    println!(
        " [6] Monte-Carlo-Schaetzung von Pi:\n     Geschaetzt:      {:.6}\n     Abweichung:      {:.3} % von Pi\n",
        pi_est, pi_err
    );
    println!(
        " [7] NIST SP 800-22 Runs-Test (Bit-Dynamik):\n     P-Wert:          {:.6}  {}\n     Schwellenwert:   p >= 0.01\n",
        runs_p_value, if runs_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN]" }
    );
    println!(
        " [8] NIST SP 800-22 Block-Frequenztest (M=128):\n     P-Wert:          {:.6}  {}\n     Schwellenwert:   p >= 0.01\n",
        block_p_value, if block_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN]" }
    );
    println!("============================================================");
    println!(" KRYPTOANALYTISCHE BEWERTUNG:");
    println!("============================================================");

    if is_cryptographic {
        println!(" Einstufung: SEHR HOHE ENTROPIE (Kryptografische Guete)");
        println!(" Analyse:    Die Daten erfuellen alle NIST SP 800-22 Schwellenwerte und sind");
        println!("             statistisch ununterscheidbar von echtem weissen Rauschen.");
        println!("             Typisch fuer ChaCha20/AES-Ciphertexte oder CSPRNG-Stroeme.");
    } else if shannon_entropy >= 7.9500 {
        println!(" Einstufung: HOHE ENTROPIE (Ciphertext oder starke Kompression)");
        println!(" Analyse:    Sehr hohe Gleichverteilung. Typisch fuer Archive (gzip, zstd, xz)");
        println!("             oder partiell verschluesselte Daten.");
    } else if shannon_entropy >= 6.5000 {
        println!(" Einstufung: MITTLERE ENTROPIE (Binaercode / Teilstrukturiert)");
        println!(" Analyse:    Typisch fuer ELF/PE Binaries, Maschinencode oder Bytecode.");
    } else {
        println!(" Einstufung: NIEDRIGE ENTROPIE (Klartext / Strukturierte Daten)");
        println!(" Analyse:    Hohe Redundanz und erkennbare Muster. Typisch fuer Quellcode,");
        println!("             Text, JSON, XML, Datenbanken oder Null-Bytes.");
    }
    println!("============================================================\n");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erfc_accuracy() {
        assert!((erfc(0.0) - 1.0).abs() < 1e-6);
        assert!((erfc(1.0) - 0.157299).abs() < 1e-4);
        assert!(erfc(5.0) < 1e-10);
    }

    #[test]
    fn test_chi_square_p_value() {
        // Bei chi_square == k sollte der p-Wert ca. 0.5 sein
        let p = chi_square_p_value(100.0, 100.0);
        assert!((p - 0.5).abs() < 0.05);
    }
}
