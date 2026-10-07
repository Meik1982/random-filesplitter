use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn rfs_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rfs"))
}

#[test]
fn test_edge_case_file_sizes_and_block_boundaries() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rfs_edge_sizes_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    // Relevante Grenzwerte:
    // 0 B (leer), 1 B (minimal), 44 B (RFS2 Footer), 59 B (RFS3 Footer - 1),
    // 65535 B (64K - 1), 65536 B (exakt 64K), 65537 B (64K + 1)
    let test_sizes = [0, 1, 44, 59, 65535, 65536, 65537];

    for (idx, &size) in test_sizes.iter().enumerate() {
        let in_file = temp_dir.join(format!("edge_{}.bin", idx));
        let p1 = temp_dir.join(format!("edge_{}.bin.rfs1", idx));
        let p2 = temp_dir.join(format!("edge_{}.bin.rfs2", idx));
        let restored = temp_dir.join(format!("edge_{}.restored", idx));

        let data: Vec<u8> = (0..size).map(|i| (i * 23 + 7) as u8).collect();
        fs::write(&in_file, &data).unwrap();

        // Split mit kleinster zulässiger Blockgröße (64K)
        let split = Command::new(rfs_bin())
            .arg("split")
            .arg(&in_file)
            .arg("-B")
            .arg("64K")
            .arg("-f")
            .status()
            .expect("rfs split fehlgeschlagen");
        assert!(split.success(), "Split fehlgeschlagen bei Größe {}", size);

        // Verify
        let verify = Command::new(rfs_bin())
            .arg("verify")
            .arg(&p1)
            .arg(&p2)
            .status()
            .expect("rfs verify fehlgeschlagen");
        assert!(verify.success(), "Verify fehlgeschlagen bei Größe {}", size);

        // Restore
        let restore = Command::new(rfs_bin())
            .arg("restore")
            .arg(&p1)
            .arg(&p2)
            .arg("-o")
            .arg(&restored)
            .arg("-f")
            .status()
            .expect("rfs restore fehlgeschlagen");
        assert!(
            restore.success(),
            "Restore fehlgeschlagen bei Größe {}",
            size
        );

        let restored_data = fs::read(&restored).unwrap();
        assert_eq!(
            restored_data, data,
            "Datenabweichung bei Dateigröße {}",
            size
        );
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_validation_invalid_part_counts() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rfs_val_parts_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let in_file = temp_dir.join("test.bin");
    fs::write(&in_file, b"test payload").unwrap();

    // -n 1 muss abgewiesen werden (< 2)
    let status_n1 = Command::new(rfs_bin())
        .arg("split")
        .arg("-n")
        .arg("1")
        .arg(&in_file)
        .status()
        .expect("Kommandoaufruf fehlgeschlagen");
    assert!(
        !status_n1.success(),
        "-n 1 hätte abgelehnt werden müssen (Exit-Code != 0 erwartet)"
    );

    // -n 65 muss abgewiesen werden (> 64)
    let status_n65 = Command::new(rfs_bin())
        .arg("split")
        .arg("-n")
        .arg("65")
        .arg(&in_file)
        .status()
        .expect("Kommandoaufruf fehlgeschlagen");
    assert!(
        !status_n65.success(),
        "-n 65 hätte abgelehnt werden müssen (Exit-Code != 0 erwartet)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_validation_invalid_block_sizes() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rfs_val_block_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let in_file = temp_dir.join("test.bin");
    fs::write(&in_file, b"test payload").unwrap();

    // -B 32K muss abgewiesen werden (< 64K)
    let status_b32k = Command::new(rfs_bin())
        .arg("split")
        .arg("-B")
        .arg("32K")
        .arg(&in_file)
        .status()
        .expect("Kommandoaufruf fehlgeschlagen");
    assert!(
        !status_b32k.success(),
        "-B 32K hätte abgelehnt werden müssen (< 64 KiB Limit)"
    );

    // -B 512M muss abgewiesen werden (> 256M)
    let status_b512m = Command::new(rfs_bin())
        .arg("split")
        .arg("-B")
        .arg("512M")
        .arg(&in_file)
        .status()
        .expect("Kommandoaufruf fehlgeschlagen");
    assert!(
        !status_b512m.success(),
        "-B 512M hätte abgelehnt werden müssen (> 256 MiB Limit)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_partial_and_duplicate_shares_rejected() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rfs_rej_shares_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let in_file = temp_dir.join("secret.bin");
    let p1 = temp_dir.join("secret.bin.rfs1");
    let p2 = temp_dir.join("secret.bin.rfs2");
    let _p3 = temp_dir.join("secret.bin.rfs3");

    fs::write(&in_file, b"Information-Theoretic Security").unwrap();

    // In 3 Teile splitten
    let split = Command::new(rfs_bin())
        .arg("split")
        .arg("-n")
        .arg("3")
        .arg(&in_file)
        .arg("-f")
        .status()
        .expect("rfs split fehlgeschlagen");
    assert!(split.success());

    // 1. Unvollständig: Restore mit nur 2 von 3 Teilen (p1 + p2) muss scheitern
    let partial_restore = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .status()
        .expect("rfs restore fehlgeschlagen");
    assert!(
        !partial_restore.success(),
        "Restore mit 2 von 3 Teilen hätte abbrechen müssen (Magic-Tag Mismatch erwartet)"
    );

    // 2. Doppelt übergeben: p1 + p1 (XOR eliminiert sich selbst) muss scheitern
    let dup_restore = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p1)
        .status()
        .expect("rfs restore fehlgeschlagen");
    assert!(
        !dup_restore.success(),
        "Restore mit doppelter Datei (p1 + p1) hätte abbrechen müssen"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_direct_io_and_quiet_mode() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rfs_direct_quiet_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let in_file = temp_dir.join("direct.bin");
    let p1 = temp_dir.join("direct.bin.rfs1");
    let p2 = temp_dir.join("direct.bin.rfs2");
    let restored = temp_dir.join("direct.restored");

    let payload = vec![0x42u8; 128 * 1024]; // 128 KiB
    fs::write(&in_file, &payload).unwrap();

    // Split mit --direct und -q
    let split_out = Command::new(rfs_bin())
        .arg("split")
        .arg(&in_file)
        .arg("--direct")
        .arg("-q")
        .arg("-f")
        .output()
        .expect("rfs split fehlgeschlagen");

    assert!(split_out.status.success());
    // -q darf keine Fortschrittsanzeige auf stderr/stdout erzeugen
    assert!(
        split_out.stderr.is_empty(),
        "Stderr war nicht leer im Quiet-Mode: {:?}",
        String::from_utf8_lossy(&split_out.stderr)
    );
    assert!(
        split_out.stdout.is_empty(),
        "Stdout war nicht leer im Quiet-Mode: {:?}",
        String::from_utf8_lossy(&split_out.stdout)
    );

    // Restore mit --direct und -q
    let restore_out = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg("-o")
        .arg(&restored)
        .arg("--direct")
        .arg("-q")
        .arg("-f")
        .output()
        .expect("rfs restore fehlgeschlagen");

    assert!(restore_out.status.success());
    assert!(restore_out.stderr.is_empty());
    assert!(restore_out.stdout.is_empty());

    let restored_data = fs::read(&restored).unwrap();
    assert_eq!(restored_data, payload);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_decoy_generation_standalone_and_during_split() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rfs_decoys_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let raw_file = temp_dir.join("document.pdf");
    let raw_payload = vec![0x37u8; 5000]; // 5000 Bytes
    fs::write(&raw_file, &raw_payload).unwrap();

    // 1. Split mit integrierter Köder-Erstellung (-d 3)
    let split_decoy = Command::new(rfs_bin())
        .arg("split")
        .arg("-n")
        .arg("2")
        .arg("-d")
        .arg("3")
        .arg(&raw_file)
        .arg("-f")
        .status()
        .expect("rfs split mit -d fehlgeschlagen");
    assert!(split_decoy.success());

    let s1 = temp_dir.join("document.pdf.rfs1");
    let s2 = temp_dir.join("document.pdf.rfs2");
    let d1 = temp_dir.join("document.pdf.decoy1.rfs");
    let d2 = temp_dir.join("document.pdf.decoy2.rfs");
    let d3 = temp_dir.join("document.pdf.decoy3.rfs");

    assert!(s1.exists() && s2.exists());
    assert!(d1.exists() && d2.exists() && d3.exists());

    // Alle 5 Dateien müssen exakt 5060 Bytes groß sein (5000 + 60)
    let expected_len = 5060u64;
    assert_eq!(fs::metadata(&s1).unwrap().len(), expected_len);
    assert_eq!(fs::metadata(&s2).unwrap().len(), expected_len);
    assert_eq!(fs::metadata(&d1).unwrap().len(), expected_len);
    assert_eq!(fs::metadata(&d2).unwrap().len(), expected_len);
    assert_eq!(fs::metadata(&d3).unwrap().len(), expected_len);

    // Echte Shares rekonstruieren einwandfrei
    let res_ok = temp_dir.join("doc.restored");
    let restore = Command::new(rfs_bin())
        .arg("restore")
        .arg(&s1)
        .arg(&s2)
        .arg("-o")
        .arg(&res_ok)
        .status()
        .expect("Restore fehlgeschlagen");
    assert!(restore.success());
    assert_eq!(fs::read(&res_ok).unwrap(), raw_payload);

    // Einmischung eines Decoys anstelle eines echten Shares scheitert sofort
    let fake_restore = Command::new(rfs_bin())
        .arg("restore")
        .arg(&s1)
        .arg(&d1)
        .status()
        .expect("Restore fehlgeschlagen");
    assert!(
        !fake_restore.success(),
        "Decoy durfte nicht decodiert werden"
    );

    // 2. Standalone Decoy mit Rohdatei-Muster: Muss automatisch +60 Bytes addieren
    let standalone_raw = Command::new(rfs_bin())
        .arg("decoy")
        .arg("-t")
        .arg(&raw_file)
        .arg("-c")
        .arg("2")
        .arg("-o")
        .arg(temp_dir.join("stand_raw").to_str().unwrap())
        .arg("-f")
        .status()
        .expect("rfs decoy fehlgeschlagen");
    assert!(standalone_raw.success());
    let sr1 = temp_dir.join("stand_raw.decoy1.rfs");
    let sr2 = temp_dir.join("stand_raw.decoy2.rfs");
    assert_eq!(fs::metadata(&sr1).unwrap().len(), expected_len);
    assert_eq!(fs::metadata(&sr2).unwrap().len(), expected_len);

    // 3. Standalone Decoy mit RFS-Muster: Muss exakt 1:1 Dateigröße übernehmen (5060 Bytes)
    let standalone_rfs = Command::new(rfs_bin())
        .arg("decoy")
        .arg("-t")
        .arg(&s1)
        .arg("-c")
        .arg("1")
        .arg("-o")
        .arg(temp_dir.join("stand_rfs.rfs").to_str().unwrap())
        .arg("-f")
        .status()
        .expect("rfs decoy fehlgeschlagen");
    assert!(standalone_rfs.success());
    let s_rfs = temp_dir.join("stand_rfs.rfs");
    assert_eq!(fs::metadata(&s_rfs).unwrap().len(), expected_len);

    // 4. Standalone Decoy mit expliziter Größe (-s 128K)
    let explicit_decoy = Command::new(rfs_bin())
        .arg("decoy")
        .arg("-s")
        .arg("128K")
        .arg("-c")
        .arg("1")
        .arg("-o")
        .arg(temp_dir.join("exact.decoy").to_str().unwrap())
        .arg("-f")
        .status()
        .expect("rfs decoy mit -s fehlgeschlagen");
    assert!(explicit_decoy.success());
    assert_eq!(
        fs::metadata(temp_dir.join("exact.decoy")).unwrap().len(),
        128 * 1024
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
