//! Integrationstests für maschinenlesbare NDJSON-Telemetrie (--json).

use std::fs;
use std::process::Command;

fn rfs_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rfs")
}

#[test]
fn test_json_telemetry_split_and_restore() {
    let test_id = format!(
        "rfs_json_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let in_file = temp_dir.join("input.bin");
    let p1 = temp_dir.join("input.rfs1");
    let p2 = temp_dir.join("input.rfs2");
    let restored_file = temp_dir.join("restored.bin");

    let payload = vec![0x42u8; 128 * 1024];
    fs::write(&in_file, &payload).unwrap();

    // 1. Split mit --json
    let split_output = Command::new(rfs_bin())
        .arg("split")
        .arg(&in_file)
        .arg(&p1)
        .arg(&p2)
        .arg("--json")
        .output()
        .expect("rfs split fehlgeschlagen");

    assert!(split_output.status.success());
    let stderr_str = String::from_utf8_lossy(&split_output.stderr);
    assert!(
        !stderr_str.is_empty(),
        "NDJSON Telemetrie auf stderr erwartet"
    );

    let mut found_finished = false;
    for line in stderr_str.lines() {
        if line.trim().is_empty() {
            continue;
        }
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "Jede Zeile muss valides JSON sein: {}",
            line
        );
        if line.contains("\"event\":\"finished\"") {
            found_finished = true;
            assert!(line.contains("\"action\":\"Split\""));
            assert!(line.contains("\"processed_bytes\":131072"));
            assert!(line.contains("\"checksum\":{\"algorithm\":\"blks-384\""));
        }
    }
    assert!(
        found_finished,
        "Finished-Event in JSON-Ausgabe nicht gefunden"
    );

    // 2. Restore mit --json
    let restore_output = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg(&restored_file)
        .arg("--json")
        .output()
        .expect("rfs restore fehlgeschlagen");

    assert!(restore_output.status.success());
    let restore_stderr = String::from_utf8_lossy(&restore_output.stderr);

    let mut found_restore_finished = false;
    for line in restore_stderr.lines() {
        if line.trim().is_empty() {
            continue;
        }
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "Jede Zeile muss valides JSON sein: {}",
            line
        );
        if line.contains("\"event\":\"finished\"") {
            found_restore_finished = true;
            assert!(line.contains("\"action\":\"Restore\""));
            assert!(line.contains("\"processed_bytes\":131072"));
            assert!(line.contains("\"checksum\":{\"algorithm\":\"blks-384\""));
        }
    }
    assert!(
        found_restore_finished,
        "Restore Finished-Event in JSON-Ausgabe nicht gefunden"
    );

    let restored_bytes = fs::read(&restored_file).unwrap();
    assert_eq!(restored_bytes, payload);

    let _ = fs::remove_file(&in_file);
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_file(&restored_file);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_json_telemetry_error_event() {
    let test_id = format!(
        "rfs_json_err_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let in_file = temp_dir.join("input.bin");
    let p1 = temp_dir.join("err.rfs1");
    let p2 = temp_dir.join("err.rfs2");

    fs::write(&in_file, b"Testdaten vor Fehler").unwrap();

    let split_res = Command::new(rfs_bin())
        .arg("split")
        .arg(&in_file)
        .arg(&p1)
        .arg(&p2)
        .arg("-f")
        .status()
        .unwrap();
    assert!(split_res.success());

    // Manipulieren von Teil 1
    let mut b = fs::read(&p1).unwrap();
    b[0] ^= 0xFF;
    fs::write(&p1, &b).unwrap();

    // Verify mit --json
    let verify_output = Command::new(rfs_bin())
        .arg("verify")
        .arg(&p1)
        .arg(&p2)
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        !verify_output.status.success(),
        "Manipulierte Datei muss fehlschlagen"
    );
    let stderr_str = String::from_utf8_lossy(&verify_output.stderr);
    let mut found_error_event = false;
    for line in stderr_str.lines() {
        if line.contains("\"event\":\"error\"") {
            found_error_event = true;
            assert!(
                line.contains("\"Integritätsfehler") || line.contains("Integrity"),
                "Unerwartete Fehlermeldung im Event: {}",
                line
            );
        }
    }
    assert!(
        found_error_event,
        "Erwartetes JSON-Fehler-Event nicht gefunden in:\n{}",
        stderr_str
    );

    let _ = fs::remove_file(&in_file);
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_dir(&temp_dir);
}
