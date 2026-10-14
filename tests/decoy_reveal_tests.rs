//! Integration Tests for Plaintext Decoy Reveal during `rfs split`.

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
fn test_split_with_plaintext_decoy_reveal() {
    let dir = tempdir().unwrap();
    let temp_path = dir.path();

    // 1. Secret payload (original master file)
    let secret_file = temp_path.join("confidential_payroll.xlsx");
    let secret_data = b"CONFIDENTIAL PAYROLL DATA: EMPLOYEE BONUSES AND SALARIES 2026".repeat(15);
    fs::write(&secret_file, &secret_data).unwrap();

    // 2. Harmless plaintext decoy
    let decoy_file = temp_path.join("harmless_recipe.txt");
    let decoy_data =
        b"Chocolate cake recipe: 200g flour, 100g sugar, 50g cocoa, 2 eggs, 100ml milk.".to_vec();
    fs::write(&decoy_file, &decoy_data).unwrap();

    // 3. Output directory for shares
    let out_dir = temp_path.join("shares");
    fs::create_dir(&out_dir).unwrap();

    // 4. Run `rfs split` with 3 shares AND --decoy-reveal
    let split_res = Command::new(rfs_bin())
        .arg("split")
        .arg(&secret_file)
        .arg("-n")
        .arg("3")
        .arg("--decoy-reveal")
        .arg(&decoy_file)
        .arg("-o")
        .arg(&out_dir)
        .status()
        .expect("Split failed");
    assert!(
        split_res.success(),
        "Split with --decoy-reveal must succeed"
    );

    // Gather generated shares
    let mut share_files: Vec<PathBuf> = fs::read_dir(&out_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "rfs"))
        .collect();
    share_files.sort();

    // Exactly 3 real shares + 1 decoy share = 4 shares total
    assert_eq!(
        share_files.len(),
        4,
        "Must generate exactly 3 genuine shares + 1 reveal decoy share"
    );

    // All 4 shares must have identical byte size (aligned to 4 KiB cluster)
    let s0_len = fs::metadata(&share_files[0]).unwrap().len();
    assert_eq!(s0_len % 4096, 0);
    for p in &share_files {
        assert_eq!(fs::metadata(p).unwrap().len(), s0_len);
    }

    // 5. Run `rfs scan` to verify both sets are automatically discovered
    let scan_res = Command::new(rfs_bin())
        .arg("scan")
        .args(&share_files)
        .output()
        .expect("Scan failed");
    assert!(scan_res.status.success());
    let scan_out = String::from_utf8_lossy(&scan_res.stdout);

    // Scan must discover both payloads!
    assert!(
        scan_out.contains("confidential_payroll.xlsx"),
        "Scan output must detect original secret: {}",
        scan_out
    );
    assert!(
        scan_out.contains("harmless_recipe.txt"),
        "Scan output must detect harmless decoy: {}",
        scan_out
    );

    // 6. Delete source files to verify clean restoration
    fs::remove_file(&secret_file).unwrap();
    fs::remove_file(&decoy_file).unwrap();

    // 7. Auto-reconstruct all discovered payloads via `rfs scan -r`
    let restore_dir = temp_path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    let scan_restore = Command::new(rfs_bin())
        .arg("scan")
        .arg("-r")
        .arg("-o")
        .arg(&restore_dir)
        .args(&share_files)
        .status()
        .expect("Scan restore failed");
    assert!(scan_restore.success());

    // Both files must be reconstructed bit-exact!
    let restored_secret = restore_dir.join("confidential_payroll.xlsx");
    let restored_decoy = restore_dir.join("harmless_recipe.txt");

    assert!(restored_secret.exists(), "Restored secret must exist");
    assert!(restored_decoy.exists(), "Restored decoy must exist");

    assert_eq!(fs::read(&restored_secret).unwrap(), secret_data);
    assert_eq!(fs::read(&restored_decoy).unwrap(), decoy_data);
}
