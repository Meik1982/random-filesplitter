//! Umfassende Integrationstests für Stufe 2:
//! - Unix Stdin/Stdout Streaming-Pipes
//! - Entkoppeltes Triple-Buffering mit variablen Blockgrößen
//! - Subcommands (split, restore, verify)
//! - Bit-Flip / Manipulationserkennung

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

fn rfs_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rfs")
}

#[test]
fn test_pipe_split_and_restore_roundtrip() {
    let test_id = format!(
        "rfs_pipe_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let p1 = temp_dir.join("stream.rfs1");
    let p2 = temp_dir.join("stream.rfs2");

    let payload = b"Das ist ein geheimer Testdatenstrom uber Unix Stdin/Stdout Pipes mit RFS3-PQ!";

    // 1. Split via stdin
    let mut child = Command::new(rfs_bin())
        .arg("split")
        .arg("-")
        .arg(&p1)
        .arg(&p2)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Konnte rfs nicht starten");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload)
        .expect("Schreibfehler auf Stdin");

    let output = child
        .wait_with_output()
        .expect("Warten auf rfs fehlgeschlagen");
    assert!(
        output.status.success(),
        "rfs split via Stdin fehlgeschlagen: {:?}",
        output
    );

    assert!(p1.exists(), "Teil 1 wurde nicht erzeugt");
    assert!(p2.exists(), "Teil 2 wurde nicht erzeugt");

    // 2. Fast-Verify
    let verify_status = Command::new(rfs_bin())
        .arg("verify")
        .arg(&p1)
        .arg(&p2)
        .status()
        .expect("rfs verify fehlgeschlagen");
    assert!(verify_status.success(), "rfs verify meldet Fehler");

    // 3. Restore to stdout
    let restore_output = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg("-o")
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("rfs restore nach stdout fehlgeschlagen");

    assert!(
        restore_output.status.success(),
        "rfs restore Exit-Status nicht 0"
    );
    assert_eq!(
        restore_output.stdout.as_slice(),
        payload,
        "Wiederhergestellter Datenstrom stimmt nicht mit Original überein"
    );
}

#[test]
fn test_multichunk_streaming_with_custom_block_size() {
    let temp_dir = std::env::temp_dir().join(format!("rfs_multichunk_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let in_file = temp_dir.join("source.bin");
    let p1 = temp_dir.join("source.bin.rfs1");
    let p2 = temp_dir.join("source.bin.rfs2");
    let restored_file = temp_dir.join("restored.bin");

    // 256 KiB Nutzdaten mit deterministischem Muster
    let mut data = vec![0u8; 256 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 31 + 7) & 0xFF) as u8;
    }
    fs::write(&in_file, &data).unwrap();

    // Split mit 64 KiB Blockgröße
    let split_status = Command::new(rfs_bin())
        .arg("split")
        .arg(&in_file)
        .arg(&p1)
        .arg(&p2)
        .arg("-B")
        .arg("64K")
        .arg("-f")
        .status()
        .expect("rfs split fehlgeschlagen");
    assert!(split_status.success());

    // Restore mit 128 KiB Blockgröße
    let restore_status = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg(&restored_file)
        .arg("-B")
        .arg("128K")
        .arg("-f")
        .status()
        .expect("rfs restore fehlgeschlagen");
    assert!(restore_status.success());

    let restored_data = fs::read(&restored_file).unwrap();
    assert_eq!(restored_data, data, "Multi-Chunk Daten weichen ab");

    // Bereinigung
    let _ = fs::remove_file(&in_file);
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_file(&restored_file);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_tamper_detection_fails_restore() {
    let temp_dir = std::env::temp_dir().join(format!("rfs_tamper_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let in_file = temp_dir.join("secret.bin");
    let p1 = temp_dir.join("secret.rfs1");
    let p2 = temp_dir.join("secret.rfs2");
    let restored_file = temp_dir.join("corrupted.bin");

    fs::write(
        &in_file,
        b"Streng vertrauliche Information vor Manipulation",
    )
    .unwrap();

    let split_res = Command::new(rfs_bin())
        .arg("split")
        .arg(&in_file)
        .arg(&p1)
        .arg(&p2)
        .arg("-f")
        .status()
        .unwrap();
    assert!(split_res.success());

    // Bit-Flip in Teil 1 (erstes Byte der Nutzdaten manipulieren)
    let mut part1_bytes = fs::read(&p1).unwrap();
    part1_bytes[0] ^= 0x01;
    fs::write(&p1, &part1_bytes).unwrap();

    // Verify muss fehlschlagen
    let verify_status = Command::new(rfs_bin())
        .arg("verify")
        .arg(&p1)
        .arg(&p2)
        .status()
        .unwrap();
    assert!(
        !verify_status.success(),
        "Verify hätte bei manipulierter Datei fehlschlagen müssen!"
    );

    // Restore muss fehlschlagen
    let restore_status = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg(&restored_file)
        .status()
        .unwrap();
    assert!(
        !restore_status.success(),
        "Restore hätte bei manipulierter Datei fehlschlagen müssen!"
    );
    assert!(
        !restored_file.exists(),
        "Korrupte Datei darf nach Fehler nicht existieren"
    );

    let _ = fs::remove_file(&in_file);
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_classic_syntax_streaming_pipe() {
    let test_id = format!(
        "rfs_classic_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let p1 = temp_dir.join("classic.rfs1");
    let p2 = temp_dir.join("classic.rfs2");

    let payload = b"Klassische POSIX-Syntax ohne Subcommand: rfs - p1 p2 und rfs p1 p2 -";

    // Split: rfs - <p1> <p2>
    let mut child = Command::new(rfs_bin())
        .arg("-")
        .arg(&p1)
        .arg(&p2)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());

    // Restore: rfs <p1> <p2> -
    let output = Command::new(rfs_bin())
        .arg(&p1)
        .arg(&p2)
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout.as_slice(), payload);

    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_empty_stream_pipe() {
    let test_id = format!(
        "rfs_empty_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(test_id);
    fs::create_dir_all(&temp_dir).unwrap();

    let p1 = temp_dir.join("empty.rfs1");
    let p2 = temp_dir.join("empty.rfs2");

    // Split 0 Bytes aus Stdin
    let mut child = Command::new(rfs_bin())
        .arg("split")
        .arg("-")
        .arg(&p1)
        .arg(&p2)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    drop(child.stdin.take()); // Sofort EOF senden
    let status = child.wait().unwrap();
    assert!(status.success());

    // Restore nach stdout
    let output = Command::new(rfs_bin())
        .arg("restore")
        .arg(&p1)
        .arg(&p2)
        .arg("-o")
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "Restored stream von 0 Bytes muss leer sein"
    );

    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    let _ = fs::remove_dir(&temp_dir);
}
