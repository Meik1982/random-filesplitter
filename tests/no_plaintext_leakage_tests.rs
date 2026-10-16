//! Forensic & Information-Theoretic Zero-Leakage Tests.
//!
//! Verifies that NO plaintext fragments, embedded filenames, magic headers (`RFS4`/`RFS3`/`RFS2`),
//! zero-padding runs, or statistical correlations ever leak into individual `.rfs` shares or into
//! any unauthorized subset of shares (up to $T - 1$ shares XORed together).

use std::fs;
use tempfile::tempdir;

use rfs_core::crypto::xor_in_place;
use rfs_core::entropy::EntropyAccumulator;
use rfs_core::forge::forge_decoy_share;
use rfs_core::pipeline::{restore_file, split_multi_payloads, split_stream_or_file};
use rfs_core::telemetry::TelemetryMode;
use rfs_core::types::MIN_BLOCK_SIZE;

/// Searches `haystack` for any contiguous slice of `needle` of length `min_frag_len` or greater.
/// Returns `Some(fragment)` if any fragment of `needle` is found verbatim inside `haystack`.
fn find_any_fragment<'a>(
    haystack: &[u8],
    needle: &'a [u8],
    min_frag_len: usize,
) -> Option<&'a [u8]> {
    if needle.len() < min_frag_len {
        return None;
    }
    needle
        .windows(min_frag_len)
        .find(|&window| haystack.windows(min_frag_len).any(|h| h == window))
}

/// Asserts that `buf` behaves as high-entropy cryptographic noise and contains zero fragments
/// of any forbidden canary, filename, or RFS magic identifier.
fn assert_zero_leakage_and_high_entropy(
    buf: &[u8],
    label: &str,
    forbidden_canaries: &[&[u8]],
    forbidden_filenames: &[&str],
) {
    // 1. Check that no RFS magic tags appear anywhere in the buffer
    for magic in [b"RFS4", b"RFS3", b"RFS2"] {
        assert!(
            !buf.windows(4).any(|w| w == magic),
            "[LEAK DETECTED in {}] Magic tag {:?} found in raw share data!",
            label,
            std::str::from_utf8(magic).unwrap()
        );
    }

    // 2. Check that no 8-byte fragment of any canary string appears anywhere
    for canary in forbidden_canaries {
        if let Some(leaked) = find_any_fragment(buf, canary, 8) {
            panic!(
                "[LEAK DETECTED in {}] Plaintext canary fragment {:?} leaked into share!",
                label,
                String::from_utf8_lossy(leaked)
            );
        }
    }

    // 3. Check that no 6-byte fragment of any original filename appears anywhere
    for fname in forbidden_filenames {
        if let Some(leaked) = find_any_fragment(buf, fname.as_bytes(), 6) {
            panic!(
                "[LEAK DETECTED in {}] Filename fragment {:?} (from '{}') leaked into share!",
                label,
                String::from_utf8_lossy(leaked),
                fname
            );
        }
    }

    // 4. Check that no 8-byte run of 0x00 or 0xFF (from zero/one blocks or padding) exists
    assert!(
        !buf.windows(8).any(|w| w == [0x00; 8]),
        "[LEAK DETECTED in {}] 8-byte zero run (0x0000000000000000) found — unmasked padding or zero-block leak!",
        label
    );
    assert!(
        !buf.windows(8).any(|w| w == [0xFF; 8]),
        "[LEAK DETECTED in {}] 8-byte 0xFF run found — unmasked pattern leak!",
        label
    );

    // 5. Statistical entropy & bit-balance verification
    let mut acc = EntropyAccumulator::new();
    acc.update(buf);
    let metrics = acc.finalize().expect("non-empty share");

    assert!(
        metrics.shannon_entropy >= 7.90,
        "[ENTROPY ANOMALY in {}] Shannon entropy too low: {:.6} bits/byte",
        label,
        metrics.shannon_entropy
    );
    assert!(
        (48.5..=51.5).contains(&metrics.bit_balance_pct),
        "[BIT BALANCE ANOMALY in {}] Bit balance {:.3}% deviates from 50%",
        label,
        metrics.bit_balance_pct
    );
    assert!(
        metrics.corr_ok,
        "[AUTOCORRELATION ANOMALY in {}] Serial correlation {:.6} too high",
        label, metrics.serial_correlation
    );
}

/// Computes the normalized Hamming distance (fraction of differing bits, ideal = 0.50)
/// between two equal-length slices.
fn normalized_hamming_distance(a: &[u8], b: &[u8]) -> f64 {
    assert_eq!(a.len(), b.len());
    let total_bits = (a.len() * 8) as f64;
    let diff_bits: u64 = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x ^ y).count_ones() as u64)
        .sum();
    diff_bits as f64 / total_bits
}

#[test]
#[allow(clippy::needless_range_loop)]
fn test_single_split_zero_plaintext_or_filename_leakage() {
    let dir = tempdir().unwrap();
    let secret_name = "streng_geheimer_finanzbericht_2026.xlsx";
    let secret_path = dir.path().join(secret_name);

    let canary_1 = b"TOP_SECRET_CANARY_PAYLOAD_2026_DO_NOT_LEAK_ALPHA_OMEGA";
    let canary_2 = b"-----BEGIN OPENSSH PRIVATE KEY-----SUPER_SENSITIVE_KEY_MATERIAL";
    let canary_3 = b"MYSQL_ROOT_PASSWORD=CorrectHorseBatteryStaple999!";

    // Construct a highly structured, low-entropy 64 KiB payload containing:
    // - 16 KiB of all-zero bytes (0x00)
    // - Repeated ASCII canary strings
    // - 16 KiB of all-0xFF bytes
    // - 16 KiB of repeating 0xAA55 pattern
    let mut payload = Vec::with_capacity(65536);
    payload.extend_from_slice(&vec![0x00u8; 16384]);
    for _ in 0..64 {
        payload.extend_from_slice(canary_1);
        payload.extend_from_slice(b"\n");
        payload.extend_from_slice(canary_2);
        payload.extend_from_slice(b"\n");
        payload.extend_from_slice(canary_3);
        payload.extend_from_slice(b"\n");
    }
    payload.extend_from_slice(&vec![0xFFu8; 16384]);
    payload.extend_from_slice(&vec![0xAAu8; 16384]);

    fs::write(&secret_path, &payload).unwrap();

    // Split into N = 4 shares + D = 2 decoys
    let split_res = split_stream_or_file(
        secret_path.to_str().unwrap(),
        None,
        4,
        2,
        None,
        None,
        Some(dir.path().join("out").to_str().unwrap()),
        MIN_BLOCK_SIZE,
        TelemetryMode::Silent,
        true,
        false,
        false,
    )
    .unwrap();

    let canaries: &[&[u8]] = &[canary_1, canary_2, canary_3];
    let filenames = &[secret_name];

    let mut share_buffers = Vec::new();
    for (idx, p) in split_res.real_shares.iter().enumerate() {
        let data = fs::read(p).unwrap();
        assert_eq!(data.len() % 4096, 0, "Share must be 4 KiB cluster-aligned");
        assert_zero_leakage_and_high_entropy(
            &data,
            &format!("SingleSplit Real Share #{}", idx + 1),
            canaries,
            filenames,
        );

        // Check that the share has ~50% bit-level Hamming distance to the original plaintext
        let hd = normalized_hamming_distance(&data[..payload.len()], &payload);
        assert!(
            (0.485..=0.515).contains(&hd),
            "Hamming distance between Share #{} and plaintext is {:.4} (expected ~0.50)",
            idx + 1,
            hd
        );
        share_buffers.push(data);
    }

    // Also inspect all Decoy shares
    for (idx, p) in split_res.decoy_shares.iter().enumerate() {
        let data = fs::read(p).unwrap();
        assert_zero_leakage_and_high_entropy(
            &data,
            &format!("SingleSplit Decoy Share #{}", idx + 1),
            canaries,
            filenames,
        );
    }

    // CRITICAL: Test all 2-way and 3-way (N-1) XOR combinations of real shares!
    // In a 4-of-4 OTP split, combining ANY 2 or 3 shares must STILL yield pure random noise
    // with ZERO fragments of the plaintext or filename!
    for i in 0..4 {
        for j in (i + 1)..4 {
            let mut xor_2 = share_buffers[i].clone();
            xor_in_place(&mut xor_2, &share_buffers[j]);
            assert_zero_leakage_and_high_entropy(
                &xor_2,
                &format!("2-of-4 Partial XOR (Share {} ^ Share {})", i + 1, j + 1),
                canaries,
                filenames,
            );

            for k in (j + 1)..4 {
                let mut xor_3 = xor_2.clone();
                xor_in_place(&mut xor_3, &share_buffers[k]);
                assert_zero_leakage_and_high_entropy(
                    &xor_3,
                    &format!(
                        "3-of-4 Partial XOR (Share {} ^ Share {} ^ Share {})",
                        i + 1,
                        j + 1,
                        k + 1
                    ),
                    canaries,
                    filenames,
                );
            }
        }
    }
}

#[test]
fn test_multi_payload_gf2_zero_leakage_across_unequal_file_sizes() {
    let dir = tempdir().unwrap();
    let shares_dir = dir.path().join("shares");
    fs::create_dir_all(&shares_dir).unwrap();

    // Three payloads of drastically different sizes (to test that zero-padding of shorter files
    // in multi_split never leaks into shares or unauthorized combinations)
    let name_a = "projekt_atombunker_bauplan.dwg";
    let name_b = "geheime_zeugenliste_2026.csv";
    let name_c = "master_seed_bip39_wallet.txt";

    let path_a = dir.path().join(name_a);
    let path_b = dir.path().join(name_b);
    let path_c = dir.path().join(name_c);

    let canary_a = b"CANARY_ALPHA_BLUEPRINT_COORDINATES_52.5200N_13.4050E";
    let canary_b = b"CANARY_BETA_WITNESS_PROTECTION_IDENTITY_RECORDS_987654";
    let canary_c = b"CANARY_GAMMA_BIP39_MNEMONIC_abandon_ability_able_about_above";

    // File A: tiny (156 bytes)
    let mut data_a = Vec::new();
    for _ in 0..3 {
        data_a.extend_from_slice(canary_a);
    }
    // File B: medium (6,000 bytes with zero-blocks)
    let mut data_b = vec![0x00u8; 3000];
    for _ in 0..50 {
        data_b.extend_from_slice(canary_b);
    }
    // File C: larger (45,000 bytes with 0xFF-blocks and canary)
    let mut data_c = vec![0xFFu8; 20000];
    for _ in 0..400 {
        data_c.extend_from_slice(canary_c);
    }

    fs::write(&path_a, &data_a).unwrap();
    fs::write(&path_b, &data_b).unwrap();
    fs::write(&path_c, &data_c).unwrap();

    // Split 3 files into M = 5 shares with threshold T = 3
    let res = split_multi_payloads(
        &[path_a, path_b, path_c],
        5,
        Some(3),
        1,
        Some(&shares_dir),
        MIN_BLOCK_SIZE,
        TelemetryMode::Silent,
        true,
        false,
        false,
    )
    .unwrap();

    let canaries: &[&[u8]] = &[canary_a, canary_b, canary_c];
    let filenames = &[name_a, name_b, name_c];

    let mut share_bufs = Vec::new();
    for (idx, p) in res.share_paths.iter().enumerate() {
        let buf = fs::read(p).unwrap();
        assert_zero_leakage_and_high_entropy(
            &buf,
            &format!("MultiSplit Share #{}", idx + 1),
            canaries,
            filenames,
        );
        share_bufs.push(buf);
    }

    // Check every unauthorized 2-Way (T-1) XOR combination of the 5 shares:
    // Even if two 3-way subsets overlap in 2 shares (so C_i ^ C_j = P_a ^ P_b),
    // NO RFS magic tag, NO canary fragment, and NO filename fragment may ever appear!
    for i in 0..5 {
        for j in (i + 1)..5 {
            let mut pair_xor = share_bufs[i].clone();
            xor_in_place(&mut pair_xor, &share_bufs[j]);
            for magic in [b"RFS4", b"RFS3", b"RFS2"] {
                assert!(
                    !pair_xor.windows(4).any(|w| w == magic),
                    "Magic tag leaked in 2-of-5 XOR ({} ^ {})",
                    i + 1,
                    j + 1
                );
            }
            for canary in canaries {
                assert!(
                    find_any_fragment(&pair_xor, canary, 8).is_none(),
                    "Canary fragment leaked in 2-of-5 XOR ({} ^ {})",
                    i + 1,
                    j + 1
                );
            }
            for fname in filenames {
                assert!(
                    find_any_fragment(&pair_xor, fname.as_bytes(), 6).is_none(),
                    "Filename fragment leaked in 2-of-5 XOR ({} ^ {})",
                    i + 1,
                    j + 1
                );
            }
        }
    }
}

#[test]
fn test_decoy_reveal_and_forge_zero_cross_leakage() {
    let dir = tempdir().unwrap();
    let real_name = "echter_krypto_schluessel.pem";
    let decoy_name = "harmlose_einkaufsliste.txt";
    let forge_name = "urlaubsfoto_strand.jpg";

    let real_path = dir.path().join(real_name);
    let decoy_path = dir.path().join(decoy_name);
    let forge_path = dir.path().join(forge_name);

    let canary_real = b"REAL_SECRET_PRIVATE_KEY_99887766554433221100_NEVER_REVEAL";
    let canary_decoy = b"DECOY_SHOPPING_LIST_MILK_BREAD_BUTTER_APPLES_COFFEE_TEA";
    let canary_forge = b"FORGED_BEACH_VACATION_METADATA_SUNSHINE_PALM_TREES_2026";

    let mut real_data = vec![0x00u8; 8192];
    for _ in 0..80 {
        real_data.extend_from_slice(canary_real);
    }
    let mut decoy_data = Vec::new();
    for _ in 0..50 {
        decoy_data.extend_from_slice(canary_decoy);
    }
    let mut forge_data = Vec::new();
    for _ in 0..40 {
        forge_data.extend_from_slice(canary_forge);
    }

    fs::write(&real_path, &real_data).unwrap();
    fs::write(&decoy_path, &decoy_data).unwrap();
    fs::write(&forge_path, &forge_data).unwrap();

    // 1. Split with --decoy-reveal (N = 3 real shares + 1 decoy-reveal share)
    let split_res = split_stream_or_file(
        real_path.to_str().unwrap(),
        None,
        3,
        0,
        Some(&decoy_path),
        None,
        Some(dir.path().join("shares").to_str().unwrap()),
        MIN_BLOCK_SIZE,
        TelemetryMode::Silent,
        true,
        false,
        false,
    )
    .unwrap();

    let forged_share_path = dir.path().join("forged_counterpart.rfs");
    forge_decoy_share(
        &split_res.real_shares[..2],
        &forge_path,
        &forged_share_path,
        MIN_BLOCK_SIZE,
        false,
        true,
    )
    .unwrap();

    let all_canaries: &[&[u8]] = &[canary_real, canary_decoy, canary_forge];
    let all_names = &[real_name, decoy_name, forge_name];

    // Inspect all generated shares (real, decoy-reveal, and forged share) individually
    for p in split_res
        .real_shares
        .iter()
        .chain(split_res.decoy_shares.iter())
        .chain(std::iter::once(&forged_share_path))
    {
        let buf = fs::read(p).unwrap();
        assert_zero_leakage_and_high_entropy(
            &buf,
            &format!("Share {}", p.file_name().unwrap().to_string_lossy()),
            all_canaries,
            all_names,
        );
    }

    // Verify that restoring the forged combination (Share 1 + Share 2 + Forged Share)
    // produces ONLY `forge_data` and contains ZERO fragments of `real_data` or `real_name`!
    let restored_forged_out = dir.path().join("restored_forged.bin");
    restore_file(
        &[
            split_res.real_shares[0].clone(),
            split_res.real_shares[1].clone(),
            forged_share_path,
        ],
        Some(restored_forged_out.to_str().unwrap()),
        true,
        TelemetryMode::Silent,
        false,
        MIN_BLOCK_SIZE,
        false,
        false,
    )
    .unwrap();

    let restored_forged_bytes = fs::read(&restored_forged_out).unwrap();
    assert_eq!(restored_forged_bytes, forge_data);
    assert!(
        find_any_fragment(&restored_forged_bytes, canary_real, 6).is_none(),
        "Real secret leaked into forged restoration!"
    );
}
