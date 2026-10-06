//! Integrationstests für N-Way Splitting (3, 4, 5 Teile) via One-Time-Pad Chain.

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

fn rfs_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rfs")
}

#[test]
fn test_3_way_split_and_restore_roundtrip() {
    let test_id = format!(
        "rfs_3way_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let in_file = temp_dir.join("secret_3way.bin");
    let p1 = temp_dir.join("part1.rfs");
    let p2 = temp_dir.join("part2.rfs");
    let p3 = temp_dir.join("part3.rfs");
    let restored_file = temp_dir.join("restored.bin");

    let payload = b"Das ist ein hochgeheimes Dokument aufgeteilt in exakt 3 One-Time-Pad Teile!";
    fs::write(&in_file, payload).unwrap();

    // 1. Split in 3 Teile
    let status = Command::new(rfs_bin())
        .arg("split")
        .arg("-n")
        .arg("3")
        .arg(&in_file)
        .arg(&p1)
        .arg(&p2)
        .arg(&p3)
        .status()
        .expect("rfs split fehlgeschlagen");
    assert!(status.success());
    assert!(p1.exists());
    assert!(p2.exists());
    assert!(p3.exists());

    // 2. Fast-Verify aller 3 Teile
    let verify_status = Command::new(rfs_bin())
        .arg("verify")
        .arg(&p1)
        .arg(&p2)
        .arg(&p3)
        .status()
        .expect("rfs verify fehlgeschlagen");
    assert!(verify_status.success());

    // 3. Rekonstruktion aus allen 3 Teilen
    let restore_status = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg(&p3)
        .arg(&restored_file)
        .status()
        .expect("rfs restore fehlgeschlagen");
    assert!(restore_status.success());

    let restored = fs::read(&restored_file).unwrap();
    assert_eq!(restored.as_slice(), payload);

    // 4. Test: Unvollständige Teile (nur Teil 1 und Teil 2) müssen fehlschlagen!
    let incomplete_status = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg(temp_dir.join("should_fail.bin"))
        .status()
        .expect("rfs restore Aufruf fehlgeschlagen");
    assert!(
        !incomplete_status.success(),
        "Wiederherstellung mit unvollständigen Teilen hätte fehlschlagen müssen!"
    );

    let _ = fs::remove_file(&in_file);
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_file(&p3);
    let _ = fs::remove_file(&restored_file);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_4_way_stdin_streaming_to_stdout() {
    let test_id = format!(
        "rfs_4way_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let p1 = temp_dir.join("quad.rfs1");
    let p2 = temp_dir.join("quad.rfs2");
    let p3 = temp_dir.join("quad.rfs3");
    let p4 = temp_dir.join("quad.rfs4");

    let payload = b"End-to-End Test: Stdin Streaming in 4 Teile und Rekonstruktion nach Stdout!";

    // Split via Stdin mit -n 4
    let mut child = Command::new(rfs_bin())
        .arg("split")
        .arg("-n")
        .arg("4")
        .arg("-")
        .arg(&p1)
        .arg(&p2)
        .arg(&p3)
        .arg(&p4)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());

    // Restore nach Stdout
    let output = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg(&p3)
        .arg(&p4)
        .arg("-o")
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout.as_slice(), payload);

    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_file(&p3);
    let _ = fs::remove_file(&p4);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_n_way_tamper_detection() {
    let test_id = format!(
        "rfs_tamper_n_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let in_file = temp_dir.join("orig.bin");
    let p1 = temp_dir.join("n3.rfs1");
    let p2 = temp_dir.join("n3.rfs2");
    let p3 = temp_dir.join("n3.rfs3");

    fs::write(&in_file, b"Unverfalschte Daten vor Manipulation an Teil 3").unwrap();

    let status = Command::new(rfs_bin())
        .arg("split")
        .arg("-n")
        .arg("3")
        .arg(&in_file)
        .arg(&p1)
        .arg(&p2)
        .arg(&p3)
        .status()
        .unwrap();
    assert!(status.success());

    // Bit-Flip in Teil 3
    let mut bytes = fs::read(&p3).unwrap();
    bytes[5] ^= 0xFF;
    fs::write(&p3, &bytes).unwrap();

    // Verify muss fehlschlagen
    let verify_status = Command::new(rfs_bin())
        .arg("verify")
        .arg(&p1)
        .arg(&p2)
        .arg(&p3)
        .status()
        .unwrap();
    assert!(
        !verify_status.success(),
        "Verify hätte bei manipuliertem Teil 3 fehlschlagen müssen!"
    );

    let _ = fs::remove_file(&in_file);
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_file(&p3);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_restore_source_collision_protection() {
    let test_id = format!(
        "rfs_protect_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let in_file = temp_dir.join("orig.iso");
    let p1 = temp_dir.join("orig.iso.rfs1");
    let p2 = temp_dir.join("orig.iso.rfs2");

    fs::write(&in_file, b"Sicherheits-Schutztest").unwrap();

    let split_res = Command::new(rfs_bin())
        .arg("split")
        .arg(&in_file)
        .arg("-f")
        .status()
        .unwrap();
    assert!(split_res.success());

    // Versuch: Quellteil 1 als Ziel angeben -> muss mit Fehler abbrechen!
    let restore_output = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg("-o")
        .arg(&p1)
        .arg("-f")
        .output()
        .unwrap();

    assert!(
        !restore_output.status.success(),
        "Überschreiben einer Quelldatei muss strikt blockiert werden"
    );
    let stderr = String::from_utf8_lossy(&restore_output.stderr);
    assert!(
        stderr.contains("darf nicht identisch mit Quellteil"),
        "Fehlermeldung erwartet: {}",
        stderr
    );

    let _ = fs::remove_file(&in_file);
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_restore_reversed_arguments_strips_suffix_properly() {
    let test_id = format!(
        "rfs_rev_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let in_file = temp_dir.join("payload.dat");
    let p1 = temp_dir.join("payload.dat.rfs1");
    let p2 = temp_dir.join("payload.dat.rfs2");
    let expected_restored = temp_dir.join("payload.dat");

    let original_data = b"Invertierte Argumentreihenfolge Testdaten";
    fs::write(&in_file, original_data).unwrap();

    let split_res = Command::new(rfs_bin())
        .arg("split")
        .arg(&in_file)
        .arg("-f")
        .status()
        .unwrap();
    assert!(split_res.success());
    let _ = fs::remove_file(&in_file); // Original löschen

    // Teil 2 vor Teil 1 übergeben (ohne -o): muss automatisch auf payload.dat deduzieren!
    let restore_res = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p2)
        .arg(&p1)
        .status()
        .unwrap();
    assert!(restore_res.success());
    assert!(expected_restored.exists());
    assert_eq!(fs::read(&expected_restored).unwrap(), original_data);

    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_file(&expected_restored);
    let _ = fs::remove_dir(&temp_dir);
}
