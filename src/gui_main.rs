//! Graphical User Interface (GUI) entry point for random-filesplitter.
//! Built with Slint for zero-overhead, native cross-platform rendering and 7-language i18n.

slint::include_modules!();

use rfs_core::i18n::Lang;
use std::path::{Path, PathBuf};

/// Parses a comma-separated list of file paths from a GUI input field while preserving
/// filenames that legitimately contain commas (by checking filesystem existence greedily).
fn parse_gui_paths(raw: &str) -> Vec<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if Path::new(trimmed).exists() {
        return vec![PathBuf::from(trimmed)];
    }

    let raw_parts: Vec<&str> = trimmed.split(',').collect();
    let mut results = Vec::new();
    let mut i = 0;

    while i < raw_parts.len() {
        let mut candidate = raw_parts[i].trim().to_string();
        if candidate.is_empty() {
            i += 1;
            continue;
        }
        let mut matched_end = i;
        if !Path::new(&candidate).exists() {
            let mut acc = candidate.clone();
            for (j, part) in raw_parts.iter().enumerate().skip(i + 1) {
                acc.push(',');
                acc.push_str(part);
                if Path::new(acc.trim()).exists() {
                    candidate = acc.trim().to_string();
                    matched_end = j;
                    break;
                }
            }
        }
        results.push(PathBuf::from(candidate));
        i = matched_end + 1;
    }

    results
}

/// Returns the currently selected language from the MainWindow.
fn active_lang(window: &MainWindow) -> Lang {
    Lang::from_code(window.get_current_lang().as_str()).unwrap_or(Lang::En)
}

/// Applies all static and dynamic translation strings for `lang` to the MainWindow.
fn apply_language(window: &MainWindow, lang: Lang) {
    let tr = lang.tr();
    window.set_current_lang(lang.code().into());

    window.set_tr_subtitle(tr.subtitle.into());
    window.set_tr_tab_split(tr.tab_split.into());
    window.set_tr_tab_restore(tr.tab_restore.into());
    window.set_tr_tab_forge(tr.tab_forge.into());

    window.set_tr_split_step1_label(tr.split_step1_label.into());
    window.set_tr_split_file_placeholder(tr.split_file_placeholder.into());
    window.set_tr_split_select_files_btn(tr.split_select_files_btn.into());
    window.set_tr_split_step2_label(tr.split_step2_label.into());
    window.set_tr_split_target_placeholder(tr.split_target_placeholder.into());
    window.set_tr_split_select_dir_btn(tr.split_select_dir_btn.into());
    window.set_tr_split_total_shares_prefix(tr.split_total_shares_prefix.into());
    window.set_tr_split_threshold_prefix(tr.split_threshold_prefix.into());
    window.set_tr_split_threshold_of(tr.split_threshold_of.into());
    window.set_tr_split_enable_decoys_label(tr.split_enable_decoys_label.into());
    window.set_tr_split_decoy_count_prefix(tr.split_decoy_count_prefix.into());
    window.set_tr_split_action_btn(tr.split_action_btn.into());
    window.set_tr_split_action_running_btn(tr.split_action_running_btn.into());
    window.set_tr_split_log_label(tr.split_log_label.into());

    window.set_tr_restore_step1_label(tr.restore_step1_label.into());
    window.set_tr_restore_shares_placeholder(tr.restore_shares_placeholder.into());
    window.set_tr_restore_select_shares_btn(tr.restore_select_shares_btn.into());
    window.set_tr_restore_scan_folder_btn(tr.restore_scan_folder_btn.into());
    window.set_tr_restore_auto_restore_btn(tr.restore_auto_restore_btn.into());
    window.set_tr_restore_step2_label(tr.restore_step2_label.into());
    window.set_tr_restore_target_placeholder(tr.restore_target_placeholder.into());
    window.set_tr_restore_target_btn(tr.restore_target_btn.into());
    window.set_tr_restore_integrity_label(tr.restore_integrity_label.into());
    window.set_tr_restore_action_btn(tr.restore_action_btn.into());
    window.set_tr_restore_action_running_btn(tr.restore_action_running_btn.into());
    window.set_tr_restore_log_label(tr.restore_log_label.into());

    window.set_tr_forge_step1_label(tr.forge_step1_label.into());
    window.set_tr_forge_shares_placeholder(tr.forge_shares_placeholder.into());
    window.set_tr_forge_select_shares_btn(tr.forge_select_shares_btn.into());
    window.set_tr_forge_step2_label(tr.forge_step2_label.into());
    window.set_tr_forge_decoy_placeholder(tr.forge_decoy_placeholder.into());
    window.set_tr_forge_select_decoy_btn(tr.forge_select_decoy_btn.into());
    window.set_tr_forge_step3_label(tr.forge_step3_label.into());
    window.set_tr_forge_output_placeholder(tr.forge_output_placeholder.into());
    window.set_tr_forge_select_output_btn(tr.forge_select_output_btn.into());
    window.set_tr_forge_action_btn(tr.forge_action_btn.into());
    window.set_tr_forge_action_running_btn(tr.forge_action_running_btn.into());
    window.set_tr_forge_log_label(tr.forge_log_label.into());

    // Update dynamic status / hint fields according to current selection state
    let files = parse_gui_paths(&window.get_split_file_path());
    if files.is_empty() {
        window.set_split_file_info(tr.split_file_info_default.into());
        window.set_split_info_hint("".into());
    } else if files.len() == 1 {
        let f = &files[0];
        let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("file.bin");
        let size = std::fs::metadata(f)
            .map(|m| rfs_core::telemetry::format_bytes(m.len()))
            .unwrap_or_else(|_| "?".to_string());
        window.set_split_file_info(
            tr.format_selected_files(lang, 1, Some((name, &size)))
                .into(),
        );
        window.set_split_info_hint("".into());
    } else {
        let n_files = files.len();
        let m = window.get_split_num_parts() as usize;
        let (min_t, max_t) = rfs_core::matrix::policy::calculate_valid_threshold_range(n_files, m);
        window.set_split_file_info(tr.format_selected_files(lang, n_files, None).into());
        window.set_split_info_hint(
            tr.format_info_hint(lang, n_files, n_files + 1, m, min_t, max_t)
                .into(),
        );
    }

    if !window.get_split_in_progress() {
        window.set_split_status(tr.split_status_ready.into());
    }

    if window.get_restore_shares_input().is_empty() {
        window.set_restore_detected_info(tr.restore_detected_default.into());
    }
    if !window.get_restore_in_progress() {
        window.set_restore_status(tr.restore_status_ready.into());
    }

    match window.get_restore_integrity_state() {
        1 => window.set_restore_integrity_badge(tr.restore_badge_valid.into()),
        2 => window.set_restore_integrity_badge(tr.restore_badge_mismatch.into()),
        _ => window.set_restore_integrity_badge(tr.restore_badge_pending.into()),
    }

    if !window.get_forge_in_progress() {
        window.set_forge_status(tr.forge_status_ready.into());
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let main_window = MainWindow::new()?;

    // Determine initial language: CLI `--lang <code>` or `RFS_LANG`, defaulting to `Lang::En`
    let mut initial_lang = Lang::from_env();
    let args: Vec<String> = std::env::args().collect();
    for i in 1..args.len() {
        if (args[i] == "--lang" || args[i] == "-l") && i + 1 < args.len() {
            if let Some(l) = Lang::from_code(&args[i + 1]) {
                initial_lang = l;
            }
        } else if let Some(code) = args[i].strip_prefix("--lang=") {
            if let Some(l) = Lang::from_code(code) {
                initial_lang = l;
            }
        }
    }
    apply_language(&main_window, initial_lang);

    // 0. Callback: Switch UI language live
    let window_handle = main_window.as_weak();
    main_window.on_request_set_lang(move |code| {
        if let Some(window) = window_handle.upgrade() {
            if let Some(lang) = Lang::from_code(code.as_str()) {
                apply_language(&window, lang);
            }
        }
    });

    // 1. Callback: Select source file(s) for Split
    let window_handle = main_window.as_weak();
    main_window.on_request_select_file(move || {
        if let Some(files) = rfd::FileDialog::new()
            .set_title("Select source file(s) for One-Time-Pad")
            .pick_files()
        {
            if !files.is_empty() {
                if let Some(window) = window_handle.upgrade() {
                    let lang = active_lang(&window);
                    let tr = lang.tr();
                    let joined_paths = files
                        .iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(", ");

                    window.set_split_file_path(joined_paths.into());

                    let n_files = files.len();
                    if n_files == 1 {
                        let file = &files[0];
                        let file_name = file
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("file.bin");
                        let size_str = std::fs::metadata(file)
                            .map(|m| rfs_core::telemetry::format_bytes(m.len()))
                            .unwrap_or_else(|_| "?".to_string());
                        window.set_split_file_info(
                            tr.format_selected_files(lang, 1, Some((file_name, &size_str)))
                                .into(),
                        );
                        window.set_split_min_parts(2);
                        window.set_split_min_threshold(2);
                        let m = window.get_split_num_parts() as usize;
                        window.set_split_max_threshold(m as i32);
                        window.set_split_info_hint("".into());
                    } else {
                        let min_m = n_files + 1;
                        window.set_split_min_parts(min_m as i32);
                        if (window.get_split_num_parts() as usize) < min_m {
                            window.set_split_num_parts(min_m as i32);
                        }
                        let m = window.get_split_num_parts() as usize;
                        let (min_t, max_t) =
                            rfs_core::matrix::policy::calculate_valid_threshold_range(n_files, m);
                        window.set_split_min_threshold(min_t as i32);
                        window.set_split_max_threshold(max_t as i32);
                        let cur_t = window.get_split_threshold() as usize;
                        if cur_t < min_t {
                            window.set_split_threshold(min_t as i32);
                        } else if cur_t > max_t {
                            window.set_split_threshold(max_t as i32);
                        }
                        window.set_split_file_info(
                            tr.format_selected_files(lang, n_files, None).into(),
                        );
                        window.set_split_info_hint(
                            tr.format_info_hint(lang, n_files, min_m, m, min_t, max_t)
                                .into(),
                        );
                    }
                    window.set_split_status(tr.split_status_ready.into());
                }
            }
        }
    });

    // 1b. Callback: Total shares slider changed -> update threshold bounds live
    let window_handle = main_window.as_weak();
    main_window.on_request_shares_changed(move |m_parts| {
        if let Some(window) = window_handle.upgrade() {
            let lang = active_lang(&window);
            let tr = lang.tr();
            let path_str = window.get_split_file_path().to_string();
            let n_files = parse_gui_paths(&path_str).len();

            let m = m_parts as usize;
            if n_files > 1 {
                let (min_t, max_t) =
                    rfs_core::matrix::policy::calculate_valid_threshold_range(n_files, m);
                window.set_split_min_threshold(min_t as i32);
                window.set_split_max_threshold(max_t as i32);
                let cur_t = window.get_split_threshold() as usize;
                if cur_t < min_t {
                    window.set_split_threshold(min_t as i32);
                } else if cur_t > max_t {
                    window.set_split_threshold(max_t as i32);
                }
                window.set_split_info_hint(
                    tr.format_info_hint(lang, n_files, n_files + 1, m, min_t, max_t)
                        .into(),
                );
            } else {
                window.set_split_min_threshold(2);
                window.set_split_max_threshold(m as i32);
                if (window.get_split_threshold() as usize) > m {
                    window.set_split_threshold(m as i32);
                }
            }
        }
    });

    // 2. Callback: Select target directory for Split
    let window_handle = main_window.as_weak();
    main_window.on_request_select_split_target_dir(move || {
        if let Some(dir) = rfd::FileDialog::new()
            .set_title("Select output directory for RFS shares")
            .pick_folder()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_split_target_dir(dir.to_string_lossy().to_string().into());
            }
        }
    });

    // 3. Callback: Execute Split
    let window_handle = main_window.as_weak();
    main_window.on_request_split(move || {
        if let Some(window) = window_handle.upgrade() {
            let lang = active_lang(&window);
            let tr = lang.tr();
            let path_str = window.get_split_file_path().to_string();
            let target_dir_str = window.get_split_target_dir().to_string();
            let path_entries: Vec<PathBuf> = parse_gui_paths(&path_str);

            if path_entries.is_empty() {
                window.set_split_status(tr.split_status_select_at_least_one.into());
                return;
            }

            let target_prefix = if target_dir_str.trim().is_empty() {
                path_entries[0]
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(|p| p.to_string_lossy().to_string())
            } else {
                Some(target_dir_str.trim().to_string())
            };

            let parts = (window.get_split_num_parts() as usize).max(path_entries.len());
            let threshold = (window.get_split_threshold() as usize).max(2).min(parts);
            let is_multi = path_entries.len() > 1;

            let decoys = if window.get_split_enable_decoys() {
                (window.get_split_num_decoys() as usize).max(1)
            } else {
                0
            };

            window.set_split_in_progress(true);
            window.set_split_status(tr.split_status_running.into());
            window.set_split_results_log("".into());

            let window_bg = window.as_weak();
            std::thread::spawn(move || {
                if is_multi {
                    let res = rfs_core::pipeline::split_multi_payloads(
                        &path_entries,
                        parts,
                        Some(threshold),
                        decoys,
                        target_prefix.as_deref().map(std::path::Path::new),
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
                                Ok(multi_res) => {
                                    w.set_split_progress(1.0);
                                    w.set_split_status(
                                        format!(
                                            "✅ {} payloads split ({}-of-{})",
                                            multi_res.payload_subsets.len(),
                                            threshold,
                                            parts
                                        )
                                        .into(),
                                    );

                                    let mut log = String::new();
                                    log.push_str(&format!(
                                        "=== RFS MULTI-PAYLOAD SPLIT: {} FILES -> {} SHARES ({}-OF-{}) ===\n\n",
                                        multi_res.payload_subsets.len(),
                                        parts,
                                        threshold,
                                        parts
                                    ));
                                    log.push_str(&format!(
                                        "Uniform share size: {}\n\n",
                                        rfs_core::telemetry::format_bytes(multi_res.share_size)
                                    ));
                                    log.push_str("🔐 GENERATED ANONYMOUS SHARES:\n");
                                    for (i, p) in multi_res.share_paths.iter().enumerate() {
                                        log.push_str(&format!("  [Share {}] {}\n", i + 1, p.display()));
                                    }

                                    log.push_str("\n🎯 COMBINATORIAL ACCESS ALLOCATION:\n");
                                    for (name, shares) in &multi_res.payload_subsets {
                                        let names = shares
                                            .iter()
                                            .map(|p| p.file_name().and_then(|n| n.to_str()).unwrap_or(""))
                                            .collect::<Vec<_>>()
                                            .join(", ");
                                        log.push_str(&format!("  🎯 Payload: \"{}\"\n", name));
                                        log.push_str(&format!(
                                            "     Required {}-Way subset: [{}]\n\n",
                                            shares.len(),
                                            names
                                        ));
                                    }

                                    if !multi_res.decoy_paths.is_empty() {
                                        log.push_str(&format!(
                                            "🎭 GENERATED DECOY CHAFF FILES ({}):\n",
                                            multi_res.decoy_paths.len()
                                        ));
                                        for (i, p) in multi_res.decoy_paths.iter().enumerate() {
                                            log.push_str(&format!(
                                                "  [Decoy {}] {}\n",
                                                i + 1,
                                                p.display()
                                            ));
                                        }
                                        log.push('\n');
                                    }

                                    log.push_str("NOTE: All subsets can be auto-discovered via 'rfs scan' or the Restore Scanner.");
                                    w.set_split_results_log(log.into());
                                }
                                Err(e) => {
                                    w.set_split_status(format!("Error: {}", e).into());
                                    w.set_split_results_log(format!("MULTI-SPLIT ERROR:\n{}", e).into());
                                }
                            }
                        }
                    });
                } else {
                    let single_source = path_entries[0].to_string_lossy().to_string();
                    let res = rfs_core::pipeline::split_stream_or_file(
                        &single_source,
                        None,
                        parts,
                        decoys,
                        None,
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
                                    w.set_split_status("✅ Split completed [OK]".into());

                                    let mut log = String::new();
                                    log.push_str(&format!(
                                        "=== RFS4 SPLIT COMPLETED (N={}, D={}) ===\n\n",
                                        split_res.real_shares.len(),
                                        split_res.decoy_shares.len()
                                    ));
                                    log.push_str("🔐 GENUINE SHARES (ALL REQUIRED FOR RECONSTRUCTION):\n");
                                    for (i, p) in split_res.real_shares.iter().enumerate() {
                                        log.push_str(&format!("  [Share {}] {}\n", i + 1, p.display()));
                                    }

                                    if !split_res.decoy_shares.is_empty() {
                                        log.push_str("\n🎭 DECOY CHAFF FILES (100% CHACHA20 RANDOM NOISE):\n");
                                        for (i, p) in split_res.decoy_shares.iter().enumerate() {
                                            log.push_str(&format!("  [Decoy {}] {}\n", i + 1, p.display()));
                                        }
                                    }

                                    log.push_str("\nNOTE: All files share identical 4 KiB cluster-aligned sizes and anonymous tokens.");
                                    w.set_split_results_log(log.into());
                                }
                                Err(e) => {
                                    w.set_split_status(format!("Error: {}", e).into());
                                    w.set_split_results_log(format!("SPLIT ERROR:\n{}", e).into());
                                }
                            }
                        }
                    });
                }
            });
        }
    });

    // 4. Callback: Select shares for Restore
    let window_handle = main_window.as_weak();
    main_window.on_request_select_shares(move || {
        if let Some(files) = rfd::FileDialog::new()
            .set_title("Select RFS shares for reconstruction")
            .add_filter("RFS Shares", &["rfs", "rfs1", "rfs2", "rfs3", "rfs4"])
            .add_filter("All Files", &["*"])
            .pick_files()
        {
            if let Some(window) = window_handle.upgrade() {
                let lang = active_lang(&window);
                let tr = lang.tr();
                let joined = files
                    .iter()
                    .map(|f| f.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let count = files.len();
                window.set_restore_shares_input(joined.into());
                window.set_restore_detected_info(format!("{} shares selected.", count).into());
                window.set_restore_status(tr.restore_status_ready.into());
                window.set_restore_integrity_state(0);
                window.set_restore_integrity_badge(tr.restore_badge_pending.into());
            }
        }
    });

    // 4b. Callback: Scan folder for valid N-Way sets
    let window_handle = main_window.as_weak();
    main_window.on_request_scan_folder(move || {
        if let Some(folder) = rfd::FileDialog::new()
            .set_title("Select folder with RFS files for combinatorial scan")
            .pick_folder()
        {
            if let Some(window) = window_handle.upgrade() {
                let lang = active_lang(&window);
                let tr = lang.tr();
                window.set_restore_status(tr.restore_status_scanning.into());
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
                            let tr = active_lang(&w).tr();
                            match matches {
                                Ok(found) if !found.is_empty() => {
                                    w.set_restore_status(
                                        format!("🎯 {} valid set(s) discovered!", found.len())
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
                                        first.metadata.filename().unwrap_or("unnamed");
                                    w.set_restore_detected_info(
                                        format!(
                                            "Set #1 preselected: \"{}\" ({} shares)",
                                            orig_name,
                                            first.shares.len()
                                        )
                                        .into(),
                                    );
                                    w.set_restore_integrity_state(1);
                                    w.set_restore_integrity_badge(tr.restore_badge_valid.into());

                                    let mut report = String::new();
                                    report.push_str(&format!(
                                        "=== SCAN RESULT: {} FILES INSPECTED, {} VALID SETS FOUND ===\n\n",
                                        candidate_files.len(),
                                        found.len()
                                    ));
                                    for (i, m) in found.iter().enumerate() {
                                        let name = m.metadata.filename().unwrap_or("unnamed");
                                        report.push_str(&format!(
                                            "🎯 Set #{}: \"{}\" ({})\n",
                                            i + 1,
                                            name,
                                            rfs_core::telemetry::format_bytes(
                                                m.metadata.original_size()
                                            )
                                        ));
                                        report.push_str(&format!(
                                            "   Shares ({} parts):\n",
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
                                    w.set_restore_status(tr.restore_status_no_sets.into());
                                    w.set_restore_detected_info(
                                        tr.restore_detected_all_noise.into(),
                                    );
                                    w.set_restore_results_log(tr.restore_status_no_sets.into());
                                }
                                Err(e) => {
                                    w.set_restore_status(format!("Scan error: {}", e).into());
                                }
                            }
                        }
                    });
                });
            }
        }
    });

    // 4c. Callback: Scan folder AND auto-restore all sets
    let window_handle = main_window.as_weak();
    main_window.on_request_scan_and_restore(move || {
        if let Some(folder) = rfd::FileDialog::new()
            .set_title("Select folder with RFS shares for Auto-Restore")
            .pick_folder()
        {
            if let Some(window) = window_handle.upgrade() {
                let tr = active_lang(&window).tr();
                window.set_restore_in_progress(true);
                window.set_restore_status(tr.restore_status_scanning.into());
                window.set_restore_results_log("".into());

                let target_dir_str = window.get_restore_target_dir().to_string();
                let output_dir = if target_dir_str.trim().is_empty() {
                    Some(folder.clone())
                } else {
                    Some(PathBuf::from(target_dir_str.trim()))
                };

                let window_bg = window.as_weak();
                std::thread::spawn(move || {
                    let mut candidate_files = Vec::new();
                    if let Ok(entries) = std::fs::read_dir(&folder) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_file() {
                                candidate_files.push(path);
                            }
                        }
                    }

                    let outcome: Result<Vec<_>, String> = (|| {
                        let found = rfs_core::scanner::scan_candidate_files(&candidate_files)?;
                        let mut restored_list = Vec::new();
                        for m in &found {
                            let orig_name = m.metadata.filename().unwrap_or("unnamed");
                            let out_target = output_dir.as_ref().map(|d| d.join(orig_name));
                            let out_target_str =
                                out_target.as_ref().map(|p| p.to_string_lossy().to_string());
                            let restored = rfs_core::pipeline::restore_file(
                                &m.shares,
                                out_target_str.as_deref(),
                                true,
                                rfs_core::telemetry::TelemetryMode::Silent,
                                false,
                                rfs_core::types::DEFAULT_BLOCK_SIZE,
                                false,
                                false,
                            )?;
                            if let Some(p) = restored {
                                restored_list.push((orig_name.to_string(), p, m.shares.len()));
                            }
                        }
                        Ok(restored_list)
                    })();

                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(w) = window_bg.upgrade() {
                            let tr = active_lang(&w).tr();
                            w.set_restore_in_progress(false);
                            match outcome {
                                Ok(restored_list) if !restored_list.is_empty() => {
                                    w.set_restore_status(
                                        format!("✅ {} set(s) auto-restored!", restored_list.len())
                                            .into(),
                                    );
                                    w.set_restore_integrity_state(1);
                                    w.set_restore_integrity_badge(tr.restore_badge_valid.into());

                                    let mut report = String::new();
                                    report.push_str(&format!(
                                        "=== AUTO-RESTORE: {} SETS RECONSTRUCTED ===\n\n",
                                        restored_list.len()
                                    ));
                                    for (i, (orig_name, out_path, num_shares)) in
                                        restored_list.iter().enumerate()
                                    {
                                        report.push_str(&format!(
                                            "🎯 Set #{}: \"{}\"\n",
                                            i + 1,
                                            orig_name
                                        ));
                                        report.push_str(&format!(
                                            "   Output file: {}\n",
                                            out_path.display()
                                        ));
                                        report.push_str(
                                            "   Status:      ✅ Bit-exact BLKS-384 integrity verified\n",
                                        );
                                        report.push_str(&format!(
                                            "   Shares used: {} parts\n\n",
                                            num_shares
                                        ));
                                    }
                                    w.set_restore_results_log(report.into());
                                }
                                Ok(_) => {
                                    w.set_restore_status(tr.restore_status_no_sets.into());
                                }
                                Err(e) => {
                                    w.set_restore_status(format!("Restore error: {}", e).into());
                                }
                            }
                        }
                    });
                });
            }
        }
    });

    // 5. Callback: Select target directory for Restore
    let window_handle = main_window.as_weak();
    main_window.on_request_select_restore_target_dir(move || {
        if let Some(dir) = rfd::FileDialog::new()
            .set_title("Select output directory for restored file")
            .pick_folder()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_restore_target_dir(dir.to_string_lossy().to_string().into());
            }
        }
    });

    // 6. Callback: Execute Restore
    let window_handle = main_window.as_weak();
    main_window.on_request_restore(move || {
        if let Some(window) = window_handle.upgrade() {
            let tr = active_lang(&window).tr();
            let input_str = window.get_restore_shares_input().to_string();
            let target_dir_str = window.get_restore_target_dir().to_string();
            let output_target = if target_dir_str.trim().is_empty() {
                None
            } else {
                Some(target_dir_str.trim().to_string())
            };

            let part_paths: Vec<PathBuf> = parse_gui_paths(&input_str);

            if part_paths.len() < 2 {
                window.set_restore_status(tr.restore_status_need_2.into());
                return;
            }

            window.set_restore_in_progress(true);
            window.set_restore_status(tr.restore_status_running.into());
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
                        let tr = active_lang(&w).tr();
                        w.set_restore_in_progress(false);
                        match res {
                            Ok(Some(path)) => {
                                w.set_restore_progress(1.0);
                                w.set_restore_integrity_state(1);
                                w.set_restore_integrity_badge(tr.restore_badge_valid.into());
                                w.set_restore_status(
                                    format!("✅ Restored: {}", path.display()).into(),
                                );
                                let mut log = String::new();
                                log.push_str("=== RESTORATION COMPLETED ===\n\n");
                                log.push_str(&format!(
                                    "📁 Reconstructed file: {}\n",
                                    path.display()
                                ));
                                log.push_str("🛡️ BLKS-384 Integrity Check: PASSED [OK]\n");
                                log.push_str("Status: Bit-exact match with original plaintext.");
                                w.set_restore_results_log(log.into());
                            }
                            Ok(None) => {
                                w.set_restore_progress(1.0);
                                w.set_restore_integrity_state(1);
                                w.set_restore_integrity_badge(tr.restore_badge_valid.into());
                                w.set_restore_status("✅ Verification [OK]".into());
                                w.set_restore_results_log(
                                    "Verification completed without errors.".into(),
                                );
                            }
                            Err(e) => {
                                w.set_restore_integrity_state(2);
                                w.set_restore_integrity_badge(tr.restore_badge_mismatch.into());
                                w.set_restore_status(format!("Restore error: {}", e).into());
                                w.set_restore_results_log(
                                    format!("RESTORATION ERROR:\n{}", e).into(),
                                );
                            }
                        }
                    }
                });
            });
        }
    });

    // 7. Callback: Select existing shares for Forge
    let window_handle = main_window.as_weak();
    main_window.on_request_select_forge_shares(move || {
        if let Some(files) = rfd::FileDialog::new()
            .set_title("Select existing RFS shares for decoy synthesis")
            .add_filter("RFS Shares", &["rfs", "rfs1", "rfs2", "rfs3", "rfs4"])
            .add_filter("All Files", &["*"])
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

    // 8. Callback: Select decoy plaintext for Forge
    let window_handle = main_window.as_weak();
    main_window.on_request_select_forge_decoy(move || {
        if let Some(file) = rfd::FileDialog::new()
            .set_title("Select harmless decoy plaintext file")
            .pick_file()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_forge_decoy_input(file.to_string_lossy().to_string().into());
            }
        }
    });

    // 9. Callback: Select output path for forged share
    let window_handle = main_window.as_weak();
    main_window.on_request_select_forge_output(move || {
        if let Some(file) = rfd::FileDialog::new()
            .set_title("Specify output path for synthesized fake share")
            .set_file_name("counterpart_fake.rfs")
            .save_file()
        {
            if let Some(window) = window_handle.upgrade() {
                window.set_forge_output_path(file.to_string_lossy().to_string().into());
            }
        }
    });

    // 10. Callback: Execute Forge
    let window_handle = main_window.as_weak();
    main_window.on_request_forge(move || {
        if let Some(window) = window_handle.upgrade() {
            let tr = active_lang(&window).tr();
            let shares_str = window.get_forge_shares_input().to_string();
            let decoy_str = window.get_forge_decoy_input().to_string();
            let out_str = window.get_forge_output_path().to_string();

            let share_paths: Vec<PathBuf> = parse_gui_paths(&shares_str);
            let decoy_path = PathBuf::from(decoy_str.trim());
            let out_path = PathBuf::from(out_str.trim());

            if share_paths.is_empty() {
                window.set_forge_status(tr.forge_status_need_1.into());
                return;
            }

            window.set_forge_in_progress(true);
            window.set_forge_status(tr.forge_status_running.into());
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
                        let tr = active_lang(&w).tr();
                        w.set_forge_in_progress(false);
                        match res {
                            Ok(()) => {
                                w.set_forge_status(tr.forge_status_done.into());
                                let mut log = String::new();
                                log.push_str("=== DENIABLE DECOY FORGE COMPLETED ===\n\n");
                                log.push_str(&format!(
                                    "🎭 Synthesized Counterpart Share: {}\n",
                                    out_path.display()
                                ));
                                log.push_str(&format!(
                                    "📄 Embedded Decoy Plaintext:     {}\n",
                                    decoy_path.display()
                                ));
                                log.push_str(&format!(
                                    "🔗 Linked Existing Shares:       {} file(s)\n\n",
                                    share_paths.len()
                                ));
                                log.push_str("🛡️ Cryptographic Guarantee: Combining this fake share with the existing shares\n");
                                log.push_str("   validates 100% BLKS-384 integrity and reconstructs the decoy plaintext bit-exact.\n");
                                log.push_str("   Proving the existence of any other original file is mathematically impossible.");
                                w.set_forge_results_log(log.into());
                            }
                            Err(e) => {
                                w.set_forge_status(format!("Forge error: {}", e).into());
                                w.set_forge_results_log(format!("FORGE ERROR:\n{}", e).into());
                            }
                        }
                    }
                });
            });
        }
    });

    main_window.run()
}
