//! Integration Tests for Deniable Decoy Forge Engine (`rfs forge` / Rubber-Hose Resilience).

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
fn test_forge_rubber_hose_deniability_roundtrip() {
    let dir = tempdir().unwrap();
    let temp_path = dir.path();

    // 1. Create a highly sensitive original secret (500 bytes)
    let secret_file = temp_path.join("confidential_database.kdbx");
    let secret_payload = b"CLASSIFIED DOCUMENTS: TOP SECRET ARCHIVE CONTENT 1234567890".repeat(10);
    fs::write(&secret_file, &secret_payload).unwrap();

    // 2. Split secret into 2 shares (RFS4 with 4 KiB cluster padding)
    let p1 = temp_path.join("share_alpha.rfs");
    let p2 = temp_path.join("share_beta.rfs");
    let split_res = Command::new(rfs_bin())
        .arg("split")
        .arg(&secret_file)
        .arg(&p1)
        .arg(&p2)
        .status()
        .expect("Split failed");
    assert!(split_res.success());
    assert!(p1.exists());
    assert!(p2.exists());

    let share_len = fs::metadata(&p1).unwrap().len();
    assert_eq!(share_len % 4096, 0);

    // 3. Create a harmless decoy file (e.g. vacation itinerary, 120 bytes)
    let decoy_file = temp_path.join("family_vacation.pdf");
    let decoy_payload = b"Harmless vacation itinerary for summer 2026: Flight LH402, Hotel Sunshine, Beach excursion.".to_vec();
    fs::write(&decoy_file, &decoy_payload).unwrap();

    // 4. Forge a counterpart fake share matching share_alpha.rfs that reveals the decoy
    let fake_share = temp_path.join("counterpart_fake.rfs");
    let forge_res = Command::new(rfs_bin())
        .arg("forge")
        .arg(&p1)
        .arg("--reveal-as")
        .arg(&decoy_file)
        .arg("-o")
        .arg(&fake_share)
        .status()
        .expect("Forge failed");
    assert!(forge_res.success(), "Forge command must succeed");
    assert!(fake_share.exists());

    // Both shares must have 100% identical byte length on disk (indistinguishable from noise)
    assert_eq!(fs::metadata(&fake_share).unwrap().len(), share_len);

    // 5. Adversary runs `rfs verify` with seized share_alpha.rfs and counterpart_fake.rfs
    let verify_res = Command::new(rfs_bin())
        .arg("verify")
        .arg(&p1)
        .arg(&fake_share)
        .output()
        .expect("Verify failed");
    assert!(
        verify_res.status.success(),
        "Adversary verification must report full BLKS-384 integrity"
    );
    let verify_stderr = String::from_utf8_lossy(&verify_res.stderr);
    assert!(
        verify_stderr.contains("Integrity check [OK]"),
        "Integrity check must pass with green status: {}",
        verify_stderr
    );

    // 6. Adversary runs `rfs restore`
    // Delete decoy template file to test clean recreation from RFS4 footer
    fs::remove_file(&decoy_file).unwrap();
    assert!(!decoy_file.exists());

    let restore_res = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&fake_share)
        .current_dir(temp_path)
        .output()
        .expect("Restore failed");
    if !restore_res.status.success() {
        panic!(
            "Restore failed with stderr:\n{}\nstdout:\n{}",
            String::from_utf8_lossy(&restore_res.stderr),
            String::from_utf8_lossy(&restore_res.stdout)
        );
    }
    assert!(restore_res.status.success());

    // The restored file must automatically carry the original decoy filename
    let restored_file = temp_path.join("family_vacation.pdf");
    assert!(restored_file.exists(), "Restored decoy file must exist");
    let restored_content = fs::read(&restored_file).unwrap();
    assert_eq!(
        restored_content, decoy_payload,
        "Decoy content must match bit-exact with zero corruption"
    );

    // 7. Legitimate user restores original secret with true shares p1 and p2
    let true_restore = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg("-o")
        .arg(temp_path.join("restored_secret.kdbx"))
        .output()
        .expect("True restore failed");
    assert!(true_restore.status.success());
    let true_content = fs::read(temp_path.join("restored_secret.kdbx")).unwrap();
    assert_eq!(
        true_content, secret_payload,
        "True secret must remain intact"
    );
}

#[test]
fn test_forge_multi_share_3way_rubber_hose_deniability() {
    let dir = tempdir().unwrap();
    let temp_path = dir.path();

    // 1. Create original true secret
    let secret_file = temp_path.join("secret_blueprint.dwg");
    let secret_payload = b"HARDWARE SPECIFICATIONS: CPU INSTRUCTIONS ARCHITECTURE V3.0".repeat(20);
    fs::write(&secret_file, &secret_payload).unwrap();

    // 2. Split secret into 3 shares
    let s1 = temp_path.join("share1.rfs");
    let s2 = temp_path.join("share2.rfs");
    let s3 = temp_path.join("share3.rfs");
    let split_res = Command::new(rfs_bin())
        .arg("split")
        .arg(&secret_file)
        .arg(&s1)
        .arg(&s2)
        .arg(&s3)
        .status()
        .expect("Split failed");
    assert!(split_res.success());

    // 3. Create benign decoy text
    let decoy_file = temp_path.join("shopping_list.txt");
    let decoy_payload = b"Apples, Oranges, Bread, Milk, Coffee beans".to_vec();
    fs::write(&decoy_file, &decoy_payload).unwrap();

    // 4. Adversary seizes s1 and s2; user forges fake s3 that reveals the shopping list
    let fake_s3 = temp_path.join("fake_s3.rfs");
    let forge_res = Command::new(rfs_bin())
        .arg("forge")
        .arg(&s1)
        .arg(&s2)
        .arg("--reveal-as")
        .arg(&decoy_file)
        .arg("-o")
        .arg(&fake_s3)
        .status()
        .expect("Forge failed");
    assert!(forge_res.success());

    // Delete decoy template to ensure clean restoration
    fs::remove_file(&decoy_file).unwrap();

    // 5. Restore with (s1, s2, fake_s3) -> reveals shopping_list.txt!
    let restore_res = Command::new(rfs_bin())
        .arg("restore")
        .arg(&s1)
        .arg(&s2)
        .arg(&fake_s3)
        .current_dir(temp_path)
        .output()
        .expect("Restore failed");
    assert!(restore_res.status.success());

    let restored_decoy = temp_path.join("shopping_list.txt");
    assert!(restored_decoy.exists());
    assert_eq!(fs::read(&restored_decoy).unwrap(), decoy_payload);

    // 6. Legitimate restore with true (s1, s2, s3) -> reveals original secret_blueprint.dwg!
    let true_restore = Command::new(rfs_bin())
        .arg("restore")
        .arg(&s1)
        .arg(&s2)
        .arg(&s3)
        .arg("-o")
        .arg(temp_path.join("true_blueprint.dwg"))
        .output()
        .expect("True restore failed");
    assert!(true_restore.status.success());
    assert_eq!(
        fs::read(temp_path.join("true_blueprint.dwg")).unwrap(),
        secret_payload
    );
}
