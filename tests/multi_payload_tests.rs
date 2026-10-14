//! End-to-End Integration Tests for Multi-Payload Splitting & Combinatorial Assembly over GF(2).

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn rfs_bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe failed");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("rfs")
}

#[test]
fn test_multi_payload_split_scan_and_bit_exact_restore() {
    let dir = tempdir().unwrap();
    let temp_path = dir.path();

    // 1. Create 3 distinct plaintext payloads of varying sizes
    let file1 = temp_path.join("tresor.kdbx");
    let data1 = b"PRIMARY ENCRYPTED KEYSTORE DATABASE CONTENT 2026".repeat(30);
    fs::write(&file1, &data1).unwrap();

    let file2 = temp_path.join("urlaub.pdf");
    let data2 = b"%PDF-1.7 Family vacation photos and flight receipts 2026".repeat(70);
    fs::write(&file2, &data2).unwrap();

    let file3 = temp_path.join("rechnung.xlsx");
    let data3 = b"TAX AUDIT REPORT AND PAYROLL INVOICE TOTALS 2026".repeat(12);
    fs::write(&file3, &data3).unwrap();

    let out_dir = temp_path.join("shares");
    fs::create_dir(&out_dir).unwrap();

    // 2. Execute Multi-Payload Split: 3 Payloads -> 5 Shares (3-out-of-5 threshold)
    let split_status = Command::new(rfs_bin())
        .arg("split")
        .arg(&file1)
        .arg(&file2)
        .arg(&file3)
        .arg("-n")
        .arg("5")
        .arg("-T")
        .arg("3")
        .arg("-o")
        .arg(&out_dir)
        .status()
        .expect("Multi-payload split failed");
    assert!(
        split_status.success(),
        "rfs split with multiple payloads must succeed"
    );

    // 3. Inspect generated shares
    let mut shares: Vec<PathBuf> = fs::read_dir(&out_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "rfs"))
        .collect();
    shares.sort();

    // Must generate exactly 5 shares
    assert_eq!(shares.len(), 5, "Must produce exactly 5 shares for M=5");

    // All 5 shares must have identical byte size (4 KiB cluster aligned)
    let s0_len = fs::metadata(&shares[0]).unwrap().len();
    assert_eq!(s0_len % 4096, 0);
    for s in &shares {
        assert_eq!(fs::metadata(s).unwrap().len(), s0_len);
    }

    // 4. Run `rfs scan` to verify auto-discovery of all 3 payloads
    let scan_output = Command::new(rfs_bin())
        .arg("scan")
        .args(&shares)
        .output()
        .expect("Scan failed");
    assert!(scan_output.status.success());
    let scan_stdout = String::from_utf8_lossy(&scan_output.stdout);

    assert!(
        scan_stdout.contains("tresor.kdbx"),
        "Scan must discover tresor.kdbx"
    );
    assert!(
        scan_stdout.contains("urlaub.pdf"),
        "Scan must discover urlaub.pdf"
    );
    assert!(
        scan_stdout.contains("rechnung.xlsx"),
        "Scan must discover rechnung.xlsx"
    );

    // 5. Delete source files to verify recovery
    fs::remove_file(&file1).unwrap();
    fs::remove_file(&file2).unwrap();
    fs::remove_file(&file3).unwrap();

    // 6. Auto-reconstruct all discovered payloads via `rfs scan -r`
    let restore_dir = temp_path.join("recovered");
    fs::create_dir(&restore_dir).unwrap();

    let scan_restore = Command::new(rfs_bin())
        .arg("scan")
        .arg("-r")
        .arg("-o")
        .arg(&restore_dir)
        .args(&shares)
        .status()
        .expect("Scan restore failed");
    assert!(scan_restore.success());

    // 7. Verify bit-exact restoration of all 3 files
    let res1 = restore_dir.join("tresor.kdbx");
    let res2 = restore_dir.join("urlaub.pdf");
    let res3 = restore_dir.join("rechnung.xlsx");

    assert!(res1.exists(), "tresor.kdbx must be restored");
    assert!(res2.exists(), "urlaub.pdf must be restored");
    assert!(res3.exists(), "rechnung.xlsx must be restored");

    assert_eq!(fs::read(&res1).unwrap(), data1);
    assert_eq!(fs::read(&res2).unwrap(), data2);
    assert_eq!(fs::read(&res3).unwrap(), data3);
}
