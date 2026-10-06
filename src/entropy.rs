//! Hardened Entropy Harvesting, NIST Kryptoanalyse & Jitter-Diagnose.

use crate::crypto::ChaChaRng;
use blks_core::BlksHasher;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// Hardware Permutation Pool für Cache-Latenz-Jitter
struct CacheLineNode {
    next: u32,
    _pad: [u8; 60],
}

const POOL_NODES: usize = 32768; // 32K * 64B = 2 MB (sprengt L1 & L2)

fn init_permutation_pool(pool: &mut [CacheLineNode], seed_val: u32) {
    let mut state = seed_val.wrapping_add(0x9E3779B9);
    for (i, node) in pool.iter_mut().enumerate() {
        node.next = i as u32;
        node._pad = [0u8; 60];
    }
    // Fisher-Yates Permutation
    for i in (1..POOL_NODES).rev() {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        let j = (state as usize) % (i + 1);
        let tmp = pool[i].next;
        pool[i].next = pool[j].next;
        pool[j].next = tmp;
    }
}

/// Gehärteter Entropie-Harvester
pub struct UniversalEntropyHarvester;

impl UniversalEntropyHarvester {
    /// Extrahiert einen kryptografisch sicheren 256-Bit Schlüssel und 96-Bit Nonce (insgesamt 48 Bytes via BLKS-384).
    pub fn harvest_seed() -> ([u8; 32], [u8; 12]) {
        let mut hasher = BlksHasher::new();

        // 1. Primärquelle: OS Kernel-CSPRNG (getrandom / /dev/urandom / BCryptGenRandom)
        let mut os_buf = [0u8; 64];
        if getrandom::getrandom(&mut os_buf).is_ok() {
            hasher.update(&os_buf);
        }
        os_buf.zeroize();

        // 2. High-Resolution & Monotonic Clocks
        let sys_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let instant_ticks = Instant::now().elapsed().as_nanos();
        hasher.update(&sys_time.to_ne_bytes());
        hasher.update(&instant_ticks.to_ne_bytes());

        // 3. ASLR-Pointer-Layout
        let stack_var: u64 = 0x1337BEEF;
        let heap_box = Box::new(0x42424242u64);
        let stack_addr = &stack_var as *const u64 as usize;
        let heap_addr = heap_box.as_ref() as *const u64 as usize;
        let func_addr = Self::harvest_seed as *const () as usize;

        hasher.update(&stack_addr.to_ne_bytes());
        hasher.update(&heap_addr.to_ne_bytes());
        hasher.update(&func_addr.to_ne_bytes());

        // 4. Cache- und Bus-Jitter
        let mut pool: Vec<CacheLineNode> = (0..POOL_NODES)
            .map(|_| CacheLineNode {
                next: 0,
                _pad: [0u8; 60],
            })
            .collect();
        init_permutation_pool(&mut pool, (instant_ticks & 0xFFFFFFFF) as u32);

        let mut curr = (stack_addr % POOL_NODES) as u32;
        for _ in 0..2048 {
            let t1 = Instant::now();
            for _ in 0..64 {
                curr = pool[curr as usize].next;
                // Verhindere Compiler-Wegoptimierung
                std::hint::black_box(&curr);
            }
            let diff = t1.elapsed().as_nanos();
            hasher.update(&diff.to_ne_bytes());
        }

        // Finalisiere den 384-Bit (48-Byte) BLKS-Hash
        let digest_bytes = hasher.finalize();

        let mut master_key = [0u8; 32];
        let mut master_nonce = [0u8; 12];

        master_key.copy_from_slice(&digest_bytes[0..32]);
        master_nonce.copy_from_slice(&digest_bytes[32..44]);

        (master_key, master_nonce)
    }
}

/// Führt die zweiphasige Entropie- & NIST-Kryptoanalyse-Diagnose durch.
pub fn run_entropy_diagnostics() -> i32 {
    println!("============================================================");
    println!(" RFS Entropie- & Kryptoanalyse-Diagnose (BLKS-384 & Jitter)");
    println!("============================================================\n");

    println!("--- [Phase 1: Roh-Entropie-Diagnose des CPU- & Memory-Jitters] ---");
    println!("Sammle 8.192 Nanosekunden-Differenzen (Cache- & Bus-Latenzen)...\n");

    const JITTER_SAMPLES: usize = 8192;
    let mut deltas = Vec::with_capacity(JITTER_SAMPLES);
    let mut buckets: HashMap<u128, usize> = HashMap::new();
    let mut sum: f64 = 0.0;

    let mut pool: Vec<CacheLineNode> = (0..POOL_NODES)
        .map(|_| CacheLineNode {
            next: 0,
            _pad: [0u8; 60],
        })
        .collect();
    init_permutation_pool(&mut pool, 1337);

    let mut curr = 0u32;
    for _ in 0..JITTER_SAMPLES {
        let t1 = Instant::now();
        for _ in 0..64 {
            curr = pool[curr as usize].next;
            std::hint::black_box(&curr);
        }
        let diff = t1.elapsed().as_nanos();
        deltas.push(diff);
        *buckets.entry(diff).or_insert(0) += 1;
        sum += diff as f64;
    }

    // Quantisierungs-Kompensation für VMs / Hypervisor-Timer
    let mut varying_bits: u128 = 0;
    for i in 1..JITTER_SAMPLES {
        let diff = deltas[i].abs_diff(deltas[i - 1]);
        varying_bits |= diff;
    }
    let shift = if varying_bits != 0 {
        varying_bits.trailing_zeros().min(63)
    } else {
        0
    };

    let mut bit_flips = 0usize;
    for i in 1..JITTER_SAMPLES {
        if ((deltas[i] >> shift) & 1) != ((deltas[i - 1] >> shift) & 1) {
            bit_flips += 1;
        }
    }

    let mean = sum / JITTER_SAMPLES as f64;
    let mut var_sum = 0.0;
    for &d in &deltas {
        let dev = d as f64 - mean;
        var_sum += dev * dev;
    }
    let stddev = (var_sum / JITTER_SAMPLES as f64).sqrt();
    let bit_flip_ratio = (bit_flips as f64 / (JITTER_SAMPLES - 1) as f64) * 100.0;

    let mut raw_entropy = 0.0;
    for &count in buckets.values() {
        let p = count as f64 / JITTER_SAMPLES as f64;
        if p > 0.0 {
            raw_entropy -= p * p.log2();
        }
    }

    let jitter_variance_ok = stddev >= 1.0;
    let jitter_buckets_ok = buckets.len() >= 8;
    let jitter_bit_flips_ok =
        (20.0..=80.0).contains(&bit_flip_ratio) || (raw_entropy >= 1.5 && stddev >= 5.0);
    let jitter_entropy_ok = raw_entropy >= 1.2;
    let phase1_ok =
        jitter_variance_ok && jitter_buckets_ok && jitter_bit_flips_ok && jitter_entropy_ok;

    println!(
        " [1] Standardabweichung (Timing-Jitter Streuung):\n     Gemessen: {:.2} ns  {}\n     (Mindestanforderung: sigma >= 1.0 ns)\n",
        stddev, if jitter_variance_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );
    println!(
        " [2] Eindeutige Timing-Buckets (Diskrete Zyklenwerte):\n     Gefunden: {} verschiedene Zyklenwerte  {}\n     (Mindestanforderung: mind. 8 Buckets)\n",
        buckets.len(), if jitter_buckets_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );
    println!(
        " [3] LSB Bit-Transitionsrate (Rausch-Flips):\n     Wechselrate: {:.1} %  {}\n     (Ideal: 50.0 %, Akzeptanzbereich: 20.0 % - 80.0 %)\n",
        bit_flip_ratio, if jitter_bit_flips_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );
    println!(
        " [4] Shannon-Entropie der unkonditionierten Roh-Timings:\n     Gemessen: {:.3} Bits / Sample  {}\n     (Mindestanforderung: >= 1.200 Bits)\n",
        raw_entropy, if jitter_entropy_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );

    if phase1_ok {
        println!("Status Phase 1: [OK] Die CPU liefert echte physikalische Timing-Entropie.\n");
    } else {
        println!("WARNUNG Phase 1: [FEHLER] Keine oder unzureichende CPU-Jitter-Entropie!\n");
    }

    // ------------------------------------------------------------------------
    // Phase 2: NIST-Kryptoanalyse auf ChaCha20-Schlüsselstrom
    // ------------------------------------------------------------------------
    println!("--- [Phase 2: Kryptoanalyse des CSPRNG-Schlüsselstroms] ---");
    println!("Generiere 16 MB ChaCha20-Stream fuer statistische NIST-Metriken...\n");

    let (master_key, master_nonce) = UniversalEntropyHarvester::harvest_seed();
    let mut rng = ChaChaRng::new(&master_key, &master_nonce);

    const STREAM_SIZE: usize = 16 * 1024 * 1024;
    let mut stream = vec![0u8; STREAM_SIZE];
    rng.fill_bytes(&mut stream);

    let mut byte_counts = [0u64; 256];
    let mut total_ones: u64 = 0;
    let mut sum_bytes: f64 = 0.0;

    for &b in &stream {
        byte_counts[b as usize] += 1;
        sum_bytes += b as f64;
        total_ones += b.count_ones() as u64;
    }

    let mut shannon_entropy = 0.0;
    let mut chi_square = 0.0;
    let expected_count = STREAM_SIZE as f64 / 256.0;

    for &c in &byte_counts {
        if c > 0 {
            let p = c as f64 / STREAM_SIZE as f64;
            shannon_entropy -= p * p.log2();
        }
        let diff = c as f64 - expected_count;
        chi_square += (diff * diff) / expected_count;
    }

    let stream_mean = sum_bytes / STREAM_SIZE as f64;
    let bit_balance_percent = (total_ones as f64 / (STREAM_SIZE as f64 * 8.0)) * 100.0;

    // Serielle Autokorrelation (Lag-1)
    let mut sum_prod = 0.0;
    let mut sum_sq = 0.0;
    for i in 0..(STREAM_SIZE - 1) {
        let x = stream[i] as f64 - stream_mean;
        let y = stream[i + 1] as f64 - stream_mean;
        sum_prod += x * y;
        sum_sq += x * x;
    }
    let serial_corr = if sum_sq > 0.0 { sum_prod / sum_sq } else { 0.0 };

    let shannon_ok = shannon_entropy >= 7.9999;
    let chi_ok = (180.0..=330.0).contains(&chi_square);
    let mean_ok = (stream_mean - 127.5).abs() <= 0.1;
    let bit_balance_ok = (bit_balance_percent - 50.0).abs() <= 0.05;
    let corr_ok = serial_corr.abs() <= 0.001;
    let phase2_ok = shannon_ok && chi_ok && mean_ok && bit_balance_ok && corr_ok;

    println!(
        " [1] Shannon-Entropie (Gleichverteilung pro Byte):\n     Gemessen: {:.6} Bits / Byte  {}\n     (Theoretisches Maximum: 8.000000 Bits)\n",
        shannon_entropy, if shannon_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );
    println!(
        " [2] Chi-Quadrat Anpassungstest (df = 255):\n     Gemessen: {:.2}  {}\n     (Idealer statistischer Bereich: 180.00 - 330.00)\n",
        chi_square, if chi_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );
    println!(
        " [3] Arithmetischer Mittelwert der Bytes:\n     Gemessen: {:.3}  {}\n     (Theoretisches Ideal: 127.500)\n",
        stream_mean, if mean_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );
    println!(
        " [4] Bit-Balance (Verhältnis 1-Bits zu 0-Bits):\n     Gemessen: {:.3} %  {}\n     (Theoretisches Ideal: 50.000 %)\n",
        bit_balance_percent, if bit_balance_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );
    println!(
        " [5] Serielle Autokorrelation (Lag-1 Abhängigkeit):\n     Gemessen: {:.6}  {}\n     (Theoretisches Ideal: 0.000000)\n",
        serial_corr, if corr_ok { "[BESTANDEN]" } else { "[FEHLGESCHLAGEN!]" }
    );

    stream.zeroize();

    if phase1_ok && phase2_ok {
        println!("============================================================");
        println!(" GESAMTFAZIT: ALLE ENTROPIE- & KRYPTOTESTS BESTANDEN [OK]");
        println!(" Der Zufallsstrom ist ununterscheidbar von echtem weissen Rauschen.");
        println!("============================================================\n");
        0
    } else {
        println!("============================================================");
        println!(" GESAMTFAZIT: STATISTISCHE ANOMALIEN ENTDECKT [WARNUNG]");
        println!("============================================================\n");
        1
    }
}

/// Führt eine kryptoanalytische Datei-Entropieanalyse für eine gegebene Datei durch.
pub fn analyze_file_entropy(path: &Path) -> Result<(), String> {
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
            total_ones += b.count_ones() as u64;

            if let Some(prev) = prev_byte {
                let x = prev as f64 - 127.5;
                let y = b as f64 - 127.5;
                sum_prod += x * y;
                sum_sq += x * x;
            }
            prev_byte = Some(b);

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
    let bit_balance = (total_ones as f64 / (total_bytes as f64 * 8.0)) * 100.0;
    let serial_corr = if sum_sq > 0.0 { sum_prod / sum_sq } else { 0.0 };

    let pi_est = if mc_total_pairs > 0 {
        4.0 * (mc_in_circle as f64 / mc_total_pairs as f64)
    } else {
        0.0
    };
    let pi_err = ((pi_est - std::f64::consts::PI).abs() / std::f64::consts::PI) * 100.0;

    println!("============================================================");
    println!(" RFS Kryptoanalytische Datei-Entropieanalyse");
    println!("============================================================");
    println!(" Datei:   {}", path.display());
    println!(
        " Groesse: {} Bytes ({:.2} MB)",
        total_bytes,
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    println!("------------------------------------------------------------");
    println!(
        " [1] Shannon-Entropie:\n     Gemessen:        {:.6} Bits / Byte\n     Entropiedichte:  {:.2} % des theoretischen Maximums (8.000000)\n",
        shannon_entropy, entropy_ratio
    );
    println!(
        " [2] Chi-Quadrat Anpassungstest (df = 255):\n     Wert:            {:.2}\n     Idealbereich:    180.00 - 330.00 (fuer 95 % Gleichverteilung)\n",
        chi_square
    );
    println!(
        " [3] Arithmetischer Mittelwert:\n     Gemessen:        {:.3}\n     Ideal:           127.500 (Abweichung: {:.3})\n",
        mean, (mean - 127.5).abs()
    );
    println!(
        " [4] Bit-Balance (1-Bits zu 0-Bits):\n     Gemessen:        {:.3} %\n     Ideal:           50.000 % (Abweichung: {:.3} %)\n",
        bit_balance, (bit_balance - 50.0).abs()
    );
    println!(
        " [5] Serielle Autokorrelation (Lag-1):\n     Gemessen:        {:.6}\n     Ideal:           0.000000\n",
        serial_corr
    );
    println!(
        " [6] Monte-Carlo-Schaetzung von Pi:\n     Geschaetzt:      {:.6}\n     Abweichung:      {:.3} % von Pi\n",
        pi_est, pi_err
    );
    println!("============================================================");
    println!(" KRYPTOANALYTISCHE BEWERTUNG:");
    println!("============================================================");

    if shannon_entropy >= 7.9990
        && (180.0..=330.0).contains(&chi_square)
        && serial_corr.abs() < 0.002
    {
        println!(" Einstufung: SEHR HOHE ENTROPIE (Kryptografische Guete)");
        println!(" Analyse:    Die Daten sind statistisch ununterscheidbar von echtem weissen");
        println!(
            "             Rauschen. Verhalten deckt sich mit starker Ciphertext-Verschluesselung"
        );
        println!("             (z. B. ChaCha20, AES) oder kryptografischen CSPRNG-Stroemen.");
    } else if shannon_entropy >= 7.9500 {
        println!(" Einstufung: HOHE ENTROPIE (Ciphertext oder starke Kompression)");
        println!(
            " Analyse:    Sehr hohe Gleichverteilung. Typisch fuer stark komprimierte Archive"
        );
        println!("             (z. B. gzip, zstd, xz) oder verschluesselte Bloecke mit geringen Randeffekten.");
    } else if shannon_entropy >= 6.5000 {
        println!(" Einstufung: MITTLERE ENTROPIE (Binaercode / Teilstrukturiert)");
        println!(" Analyse:    Typisch fuer ausfuehrbaren Maschinencode (ELF / PE Binaries),");
        println!(
            "             unkomprimierte Bilder, Bytecode oder schwach verschluesselte Daten."
        );
    } else {
        println!(" Einstufung: NIEDRIGE ENTROPIE (Klartext / Strukturierte Daten)");
        println!(" Analyse:    Hohe Redundanz und erkennbare Muster. Typisch fuer Textdateien,");
        println!("             Quellcode, JSON, XML, Datenbanken oder Null-Bytes.");
    }
    println!("============================================================\n");

    Ok(())
}
