//! Graphical User Interface (GUI) entry point for random-filesplitter.
//! Built with Slint for zero-overhead, native cross-platform rendering.

slint::include_modules!();

use std::path::PathBuf;

fn main() -> Result<(), slint::PlatformError> {
    let main_window = MainWindow::new()?;

    // Callback: Split File Dialog
    let window_handle = main_window.as_weak();
    main_window.on_request_select_file(move || {
        if let Some(file) = rfd::FileDialog::new()
            .set_title("Quelldatei für RFS-Split auswählen")
            .pick_file()
        {
            if let Some(window) = window_handle.upgrade() {
                let path_str = file.to_string_lossy().to_string();
                let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("Datei");
                let size_str = std::fs::metadata(&file)
                    .map(|m| rfs_core::telemetry::format_bytes(m.len()))
                    .unwrap_or_else(|_| "unbekannte Größe".to_string());

                window.set_split_file_path(path_str.into());
                window.set_split_file_info(
                    format!("Ausgewählt: {} ({})", file_name, size_str).into(),
                );
                window.set_split_status("Bereit zum Aufteilen".into());
            }
        }
    });

    let window_handle = main_window.as_weak();
    main_window.on_request_split(move || {
        if let Some(window) = window_handle.upgrade() {
            let path_str = window.get_split_file_path().to_string();
            let parts = window.get_split_num_parts() as usize;
            let decoys = if window.get_split_enable_decoys() {
                3
            } else {
                0
            };

            window.set_split_in_progress(true);
            window.set_split_status("Teile Datei via ChaCha20 & SIMD-XOR...".into());

            let window_bg = window.as_weak();
            std::thread::spawn(move || {
                let res = rfs_core::pipeline::split_stream_or_file(
                    &path_str,
                    None,
                    parts,
                    decoys,
                    None,
                    None,
                    rfs_core::types::DEFAULT_BLOCK_SIZE,
                    rfs_core::telemetry::TelemetryMode::Silent,
                    false,
                    false,
                    false,
                );

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = window_bg.upgrade() {
                        w.set_split_in_progress(false);
                        match res {
                            Ok(_) => {
                                w.set_split_progress(1.0);
                                w.set_split_status("Erfolgreich aufgeteilt!".into());
                            }
                            Err(e) => {
                                w.set_split_status(format!("Fehler: {}", e).into());
                            }
                        }
                    }
                });
            });
        }
    });

    // Callback: Restore Shares Dialog
    let window_handle = main_window.as_weak();
    main_window.on_request_select_shares(move || {
        if let Some(files) = rfd::FileDialog::new()
            .set_title("RFS Shares zur Rekonstruktion auswählen")
            .add_filter("RFS Shares", &["rfs", "rfs1", "rfs2", "rfs3", "rfs4"])
            .add_filter("Alle Dateien", &["*"])
            .pick_files()
        {
            if let Some(window) = window_handle.upgrade() {
                let joined = files
                    .iter()
                    .map(|f| f.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let count = files.len();
                window.set_restore_shares_input(joined.into());
                window.set_restore_detected_info(
                    format!("{} Share-Dateien ausgewählt.", count).into(),
                );
                window.set_restore_status("Bereit zur Wiederherstellung".into());
                window.set_restore_integrity_badge("Ausstehend".into());
            }
        }
    });

    let window_handle = main_window.as_weak();
    main_window.on_request_restore(move || {
        if let Some(window) = window_handle.upgrade() {
            let input_str = window.get_restore_shares_input().to_string();
            let part_paths: Vec<PathBuf> = input_str
                .split(',')
                .map(|s| PathBuf::from(s.trim()))
                .filter(|p| !p.as_os_str().is_empty())
                .collect();

            if part_paths.len() < 2 {
                window.set_restore_status("Mindestens 2 Shares erforderlich!".into());
                return;
            }

            window.set_restore_in_progress(true);
            window.set_restore_status("Rekonstruiere und prüfe BLKS-384 Integrität...".into());

            let window_bg = window.as_weak();
            std::thread::spawn(move || {
                let res = rfs_core::pipeline::restore_file(
                    &part_paths,
                    None,
                    false,
                    rfs_core::telemetry::TelemetryMode::Silent,
                    false,
                    rfs_core::types::DEFAULT_BLOCK_SIZE,
                    false,
                    false,
                );

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = window_bg.upgrade() {
                        w.set_restore_in_progress(false);
                        match res {
                            Ok(Some(path)) => {
                                w.set_restore_progress(1.0);
                                w.set_restore_integrity_badge("Gültig [OK]".into());
                                w.set_restore_status(
                                    format!("Erfolgreich wiederhergestellt: {}", path.display())
                                        .into(),
                                );
                            }
                            Ok(None) => {
                                w.set_restore_progress(1.0);
                                w.set_restore_integrity_badge("Gültig [OK]".into());
                                w.set_restore_status("Verifikation erfolgreich [OK]".into());
                            }
                            Err(e) => {
                                w.set_restore_integrity_badge("Fehler [Mismatch]".into());
                                w.set_restore_status(
                                    format!("Wiederherstellungsfehler: {}", e).into(),
                                );
                            }
                        }
                    }
                });
            });
        }
    });

    main_window.run()
}
