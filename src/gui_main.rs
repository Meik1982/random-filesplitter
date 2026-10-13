//! Graphical User Interface (GUI) entry point for random-filesplitter.
//! Built with Slint for zero-overhead, native cross-platform rendering.

slint::include_modules!();

use std::path::PathBuf;

fn main() -> Result<(), slint::PlatformError> {
    let main_window = MainWindow::new()?;

    // 1. Callback: Quelldatei-Auswahldialog
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

    // 2. Callback: Zielordner für Split auswählen
    let window_handle = main_window.as_weak();
    main_window.on_request_select_split_target_dir(move || {
        if let Some(dir) = rfd::FileDialog::new()
            .set_title("Zielverzeichnis für RFS-Shares auswählen (z. B. USB-Stick)")
            .pick_folder()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_split_target_dir(dir.to_string_lossy().to_string().into());
            }
        }
    });

    // 3. Callback: Split ausführen
    let window_handle = main_window.as_weak();
    main_window.on_request_split(move || {
        if let Some(window) = window_handle.upgrade() {
            let path_str = window.get_split_file_path().to_string();
            let target_dir_str = window.get_split_target_dir().to_string();
            let target_prefix = if target_dir_str.trim().is_empty() {
                None
            } else {
                Some(target_dir_str.trim().to_string())
            };

            let parts = window.get_split_num_parts() as usize;
            let decoys = if window.get_split_enable_decoys() {
                (window.get_split_num_decoys() as usize).max(1)
            } else {
                0
            };

            window.set_split_in_progress(true);
            window.set_split_status("Teile Datei via ChaCha20 & SIMD-XOR...".into());
            window.set_split_results_log("".into());

            let window_bg = window.as_weak();
            std::thread::spawn(move || {
                let res = rfs_core::pipeline::split_stream_or_file(
                    &path_str,
                    None,
                    parts,
                    decoys,
                    None,
                    target_prefix.as_deref(),
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
                            Ok(split_res) => {
                                w.set_split_progress(1.0);
                                w.set_split_status("✅ Erfolgreich aufgeteilt!".into());

                                let mut log = String::new();
                                log.push_str(&format!(
                                    "=== RFS4 AUFTEILUNG ERFOLGREICH (N={}, D={}) ===\n\n",
                                    split_res.real_shares.len(),
                                    split_res.decoy_shares.len()
                                ));
                                log.push_str("🔐 ECHTE SHARES (ZU 100% FÜR DIE WIEDERHERSTELLUNG NÖTIG):\n");
                                for (i, p) in split_res.real_shares.iter().enumerate() {
                                    log.push_str(&format!("  [Teil {}] {}\n", i + 1, p.display()));
                                }

                                if !split_res.decoy_shares.is_empty() {
                                    log.push_str("\n🎭 KÖDERDATEIEN (DECOYS - REINES CHA-CHA20 RAUSCHEN ZUR TÄUSCHUNG):\n");
                                    for (i, p) in split_res.decoy_shares.iter().enumerate() {
                                        log.push_str(&format!("  [Köder {}] {}\n", i + 1, p.display()));
                                    }
                                }

                                log.push_str("\nHINWEIS: Alle Dateien besitzen identische Cluster-Größen und neutrale Namen.");
                                w.set_split_results_log(log.into());
                            }
                            Err(e) => {
                                w.set_split_status(format!("Fehler: {}", e).into());
                                w.set_split_results_log(format!("FEHLER BEIM SPLITTEN:\n{}", e).into());
                            }
                        }
                    }
                });
            });
        }
    });

    // 4. Callback: Restore Shares Dialog (Mehrfachauswahl)
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

    // 4b. Callback: Ordner scannen und Kombinationen testen
    let window_handle = main_window.as_weak();
    main_window.on_request_scan_folder(move || {
        if let Some(folder) = rfd::FileDialog::new()
            .set_title("Ordner mit RFS-Dateien zum Kombinatorik-Scan auswählen")
            .pick_folder()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_restore_status("Scanne Ordner nach N-Way Kombinationen...".into());
                let window_bg = window.as_weak();
                std::thread::spawn(move || {
                    let mut candidate_files: Vec<PathBuf> = Vec::new();
                    if let Ok(entries) = std::fs::read_dir(&folder) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            if p.is_file() {
                                candidate_files.push(p);
                            }
                        }
                    }

                    let matches = rfs_core::scanner::scan_candidate_files(&candidate_files);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(w) = window_bg.upgrade() {
                            match matches {
                                Ok(found) if !found.is_empty() => {
                                    w.set_restore_status(
                                        format!("🎯 {} gültige(s) Set(s) entdeckt!", found.len())
                                            .into(),
                                    );
                                    let first = &found[0];
                                    let joined = first
                                        .shares
                                        .iter()
                                        .map(|p| p.to_string_lossy().to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    w.set_restore_shares_input(joined.into());
                                    let orig_name =
                                        first.metadata.filename().unwrap_or("unbenannt");
                                    w.set_restore_detected_info(
                                        format!(
                                            "Set #1 vorausgewählt: \"{}\" ({} Shares)",
                                            orig_name,
                                            first.shares.len()
                                        )
                                        .into(),
                                    );
                                    w.set_restore_integrity_badge("Gültig [OK]".into());

                                    let mut report = String::new();
                                    report.push_str(&format!(
                                        "=== SCAN-ERGEBNIS: {} DATEIEN GEPRÜFT, {} SETS GEFUNDEN ===\n\n",
                                        candidate_files.len(),
                                        found.len()
                                    ));
                                    for (i, m) in found.iter().enumerate() {
                                        let name = m.metadata.filename().unwrap_or("unbenannt");
                                        report.push_str(&format!(
                                            "🎯 Set #{}: \"{}\" ({})\n",
                                            i + 1,
                                            name,
                                            rfs_core::telemetry::format_bytes(
                                                m.metadata.original_size()
                                            )
                                        ));
                                        report.push_str(&format!(
                                            "   Shares ({} Teile):\n",
                                            m.shares.len()
                                        ));
                                        for s in &m.shares {
                                            report.push_str(&format!("     - {}\n", s.display()));
                                        }
                                        report.push('\n');
                                    }
                                    w.set_restore_results_log(report.into());
                                }
                                Ok(_) => {
                                    w.set_restore_status("Keine passenden Sets gefunden.".into());
                                    w.set_restore_detected_info(
                                        "Alle geprüften Dateien sind unkorreliertes Rauschen."
                                            .into(),
                                    );
                                    w.set_restore_results_log(
                                        "Keine gültigen RFS-Kombinationen im Ordner gefunden."
                                            .into(),
                                    );
                                }
                                Err(e) => {
                                    w.set_restore_status(format!("Scan-Fehler: {}", e).into());
                                }
                            }
                        }
                    });
                });
            }
        }
    });

    // 5. Callback: Zielordner für Wiederherstellung
    let window_handle = main_window.as_weak();
    main_window.on_request_select_restore_target_dir(move || {
        if let Some(dir) = rfd::FileDialog::new()
            .set_title("Zielverzeichnis für wiederhergestellte Datei auswählen")
            .pick_folder()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_restore_target_dir(dir.to_string_lossy().to_string().into());
            }
        }
    });

    // 6. Callback: Restore ausführen
    let window_handle = main_window.as_weak();
    main_window.on_request_restore(move || {
        if let Some(window) = window_handle.upgrade() {
            let input_str = window.get_restore_shares_input().to_string();
            let target_dir_str = window.get_restore_target_dir().to_string();
            let output_target = if target_dir_str.trim().is_empty() {
                None
            } else {
                Some(target_dir_str.trim().to_string())
            };

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
            window.set_restore_results_log("".into());

            let window_bg = window.as_weak();
            std::thread::spawn(move || {
                let res = rfs_core::pipeline::restore_file(
                    &part_paths,
                    output_target.as_deref(),
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
                                let mut log = String::new();
                                log.push_str("=== WIEDERHERSTELLUNG ERFOLGREICH ===\n\n");
                                log.push_str(&format!(
                                    "📁 Rekonstruierte Datei: {}\n",
                                    path.display()
                                ));
                                log.push_str("🛡️ BLKS-384 Integritätsprüfung: BESTANDEN [OK]\n");
                                log.push_str("Status: Bitgenaue Übereinstimmung mit dem Original.");
                                w.set_restore_results_log(log.into());
                            }
                            Ok(None) => {
                                w.set_restore_progress(1.0);
                                w.set_restore_integrity_badge("Gültig [OK]".into());
                                w.set_restore_status("Verifikation erfolgreich [OK]".into());
                                w.set_restore_results_log(
                                    "Verifikation ohne Fehler abgeschlossen.".into(),
                                );
                            }
                            Err(e) => {
                                w.set_restore_integrity_badge("Fehler [Mismatch]".into());
                                w.set_restore_status(
                                    format!("Wiederherstellungsfehler: {}", e).into(),
                                );
                                w.set_restore_results_log(
                                    format!("FEHLER BEI DER WIEDERHERSTELLUNG:\n{}", e).into(),
                                );
                            }
                        }
                    }
                });
            });
        }
    });

    // 7. Callback: Shares für Forge auswählen
    let window_handle = main_window.as_weak();
    main_window.on_request_select_forge_shares(move || {
        if let Some(files) = rfd::FileDialog::new()
            .set_title("Bestehende RFS Shares zur Köder-Synthese auswählen")
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
                window.set_forge_shares_input(joined.into());
            }
        }
    });

    // 8. Callback: Köder-Klartext auswählen
    let window_handle = main_window.as_weak();
    main_window.on_request_select_forge_decoy(move || {
        if let Some(file) = rfd::FileDialog::new()
            .set_title("Köder-Klartextdatei auswählen (z. B. PDF oder Urlaubsbild)")
            .pick_file()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_forge_decoy_input(file.to_string_lossy().to_string().into());
            }
        }
    });

    // 9. Callback: Zielort für Fake-Share auswählen
    let window_handle = main_window.as_weak();
    main_window.on_request_select_forge_output(move || {
        if let Some(file) = rfd::FileDialog::new()
            .set_title("Speicherort für gefälschte Gegen-Share festlegen")
            .set_file_name("counterpart_fake.rfs")
            .save_file()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_forge_output_path(file.to_string_lossy().to_string().into());
            }
        }
    });

    // 10. Callback: Forge ausführen
    let window_handle = main_window.as_weak();
    main_window.on_request_forge(move || {
        if let Some(window) = window_handle.upgrade() {
            let shares_str = window.get_forge_shares_input().to_string();
            let decoy_str = window.get_forge_decoy_input().to_string();
            let out_str = window.get_forge_output_path().to_string();

            let share_paths: Vec<PathBuf> = shares_str
                .split(',')
                .map(|s| PathBuf::from(s.trim()))
                .filter(|p| !p.as_os_str().is_empty())
                .collect();
            let decoy_path = PathBuf::from(decoy_str.trim());
            let out_path = PathBuf::from(out_str.trim());

            if share_paths.is_empty() {
                window.set_forge_status("Mindestens 1 bestehende Share erforderlich!".into());
                return;
            }

            window.set_forge_in_progress(true);
            window.set_forge_status("Synthetisiere Gegen-Share...".into());
            window.set_forge_results_log("".into());

            let window_bg = window.as_weak();
            std::thread::spawn(move || {
                let res = rfs_core::forge::forge_decoy_share(
                    &share_paths,
                    &decoy_path,
                    &out_path,
                    rfs_core::types::DEFAULT_BLOCK_SIZE,
                    false,
                    true,
                );

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = window_bg.upgrade() {
                        w.set_forge_in_progress(false);
                        match res {
                            Ok(()) => {
                                w.set_forge_status(
                                    "Gegen-Share erfolgreich synthetisiert [OK]".into(),
                                );
                                let mut log = String::new();
                                log.push_str("=== DENIABLE DECOY FORGE ERFOLGREICH ===\n\n");
                                log.push_str(&format!(
                                    "🎭 Synthetisierte Gegen-Share: {}\n",
                                    out_path.display()
                                ));
                                log.push_str(&format!(
                                    "📄 Eingebetteter Köder: {}\n",
                                    decoy_path.display()
                                ));
                                log.push_str(&format!(
                                    "🔗 Verknüpfte Basis-Shares: {} Datei(en)\n\n",
                                    share_paths.len()
                                ));
                                log.push_str("🛡️ Krypto-Garantie: Wenn diese Fake-Share mit den Basis-Shares rekonstruiert wird,\n");
                                log.push_str("   bestätigt RFS 100% BLKS-384 Integrität und liefert bitgenau den Köder-Klartext.\n");
                                log.push_str("   Ein Beweis für ein anderes Original ist mathematisch unmöglich.");
                                w.set_forge_results_log(log.into());
                            }
                            Err(e) => {
                                w.set_forge_status(format!("Fehler bei Synthese: {}", e).into());
                                w.set_forge_results_log(
                                    format!("FEHLER BEI DER KÖDER-SYNTHESE:\n{}", e).into(),
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
