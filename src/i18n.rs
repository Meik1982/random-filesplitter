//! Lightweight, zero-allocation internationalization (i18n) engine for RFS CLI and Desktop GUI.
//! Default language is English (`en`), with built-in support for German (`de`), Spanish (`es`),
//! French (`fr`), Japanese (`ja`), Simplified Chinese (`zh`), Toki Pona (`tok`), and Sitelen Pona (`sp`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};

/// Global active language state for CLI and background threads (`0xFF` = uninitialized, read from env).
static ACTIVE_LANG: AtomicU8 = AtomicU8::new(0xFF);

/// Sets the globally active language for CLI output.
pub fn set_active_lang(lang: Lang) {
    ACTIVE_LANG.store(lang as u8, Ordering::Relaxed);
}

/// Returns the currently active language (from `-l/--lang`, `RFS_LANG`, or `Lang::En` default).
pub fn current_lang() -> Lang {
    match ACTIVE_LANG.load(Ordering::Relaxed) {
        0 => Lang::En,
        1 => Lang::De,
        2 => Lang::Es,
        3 => Lang::Fr,
        4 => Lang::Ja,
        5 => Lang::Zh,
        6 => Lang::Tok,
        7 => Lang::Sp,
        _ => Lang::from_env(),
    }
}

/// Returns the static translation table for the currently active language.
pub fn tr() -> &'static Translations {
    current_lang().tr()
}

/// Supported languages in RFS.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// English (Default)
    #[default]
    En = 0,
    /// German (Deutsch)
    De = 1,
    /// Spanish (Español)
    Es = 2,
    /// French (Français)
    Fr = 3,
    /// Japanese (日本語)
    Ja = 4,
    /// Simplified Chinese (简体中文)
    Zh = 5,
    /// Toki Pona in Latin script (sitelen Lasina)
    Tok = 6,
    /// Toki Pona in hieroglyphic script (sitelen pona / UCSUR)
    Sp = 7,
}

impl Lang {
    /// All supported languages in display order.
    pub const ALL: [Lang; 8] = [
        Lang::En,
        Lang::De,
        Lang::Es,
        Lang::Fr,
        Lang::Ja,
        Lang::Zh,
        Lang::Tok,
        Lang::Sp,
    ];

    /// Returns the canonical short ISO/BCP-47 code for this language.
    pub const fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::De => "de",
            Lang::Es => "es",
            Lang::Fr => "fr",
            Lang::Ja => "ja",
            Lang::Zh => "zh",
            Lang::Tok => "tok",
            Lang::Sp => "sp",
        }
    }

    /// Parses a language code (case-insensitive, supports locale prefixes like `de_DE.UTF-8`).
    pub fn from_code(raw: &str) -> Option<Self> {
        let cleaned = raw.trim().to_ascii_lowercase();
        if cleaned == "tok-sp"
            || cleaned == "tok_sp"
            || cleaned == "sitelen-pona"
            || cleaned == "sitelen_pona"
        {
            return Some(Lang::Sp);
        }
        let prefix = cleaned.split(['_', '-', '.']).next().unwrap_or("");
        match prefix {
            "en" | "eng" | "c" | "posix" => Some(Lang::En),
            "de" | "deu" | "ger" => Some(Lang::De),
            "es" | "esp" | "spa" => Some(Lang::Es),
            "fr" | "fra" | "fre" => Some(Lang::Fr),
            "ja" | "jp" | "jpn" => Some(Lang::Ja),
            "zh" | "zho" | "chi" | "cn" => Some(Lang::Zh),
            "tok" | "tp" | "tokipona" => Some(Lang::Tok),
            "sp" | "sitelen" | "ucsur" => Some(Lang::Sp),
            _ => None,
        }
    }

    /// Resolves active language from `RFS_LANG` environment variable, defaulting to `Lang::En`.
    pub fn from_env() -> Self {
        if let Ok(val) = std::env::var("RFS_LANG") {
            if let Some(lang) = Self::from_code(&val) {
                return lang;
            }
        }
        Lang::En
    }

    /// Returns the static translation table for this language.
    pub const fn tr(self) -> &'static Translations {
        match self {
            Lang::En => &TR_EN,
            Lang::De => &TR_DE,
            Lang::Es => &TR_ES,
            Lang::Fr => &TR_FR,
            Lang::Ja => &TR_JA,
            Lang::Zh => &TR_ZH,
            Lang::Tok => &TR_TOK,
            Lang::Sp => &TR_SP,
        }
    }
}

/// Complete compile-time verified translation table for GUI and localized messages.
pub struct Translations {
    pub subtitle: &'static str,
    pub tab_split: &'static str,
    pub tab_restore: &'static str,
    pub tab_forge: &'static str,

    // Split tab
    pub split_step1_label: &'static str,
    pub split_file_placeholder: &'static str,
    pub split_select_files_btn: &'static str,
    pub split_file_info_default: &'static str,
    pub split_step2_label: &'static str,
    pub split_target_placeholder: &'static str,
    pub split_select_dir_btn: &'static str,
    pub split_total_shares_prefix: &'static str,
    pub split_threshold_prefix: &'static str,
    pub split_threshold_of: &'static str,
    pub split_enable_decoys_label: &'static str,
    pub split_decoy_count_prefix: &'static str,
    pub split_status_ready: &'static str,
    pub split_status_running: &'static str,
    pub split_status_select_at_least_one: &'static str,
    pub split_action_btn: &'static str,
    pub split_action_running_btn: &'static str,
    pub split_log_label: &'static str,

    // Restore tab
    pub restore_step1_label: &'static str,
    pub restore_shares_placeholder: &'static str,
    pub restore_select_shares_btn: &'static str,
    pub restore_scan_folder_btn: &'static str,
    pub restore_auto_restore_btn: &'static str,
    pub restore_detected_default: &'static str,
    pub restore_step2_label: &'static str,
    pub restore_target_placeholder: &'static str,
    pub restore_target_btn: &'static str,
    pub restore_integrity_label: &'static str,
    pub restore_badge_pending: &'static str,
    pub restore_badge_valid: &'static str,
    pub restore_badge_mismatch: &'static str,
    pub restore_status_ready: &'static str,
    pub restore_status_need_2: &'static str,
    pub restore_status_running: &'static str,
    pub restore_status_scanning: &'static str,
    pub restore_status_no_sets: &'static str,
    pub restore_detected_all_noise: &'static str,
    pub restore_action_btn: &'static str,
    pub restore_action_running_btn: &'static str,
    pub restore_log_label: &'static str,

    // Forge tab
    pub forge_step1_label: &'static str,
    pub forge_shares_placeholder: &'static str,
    pub forge_select_shares_btn: &'static str,
    pub forge_step2_label: &'static str,
    pub forge_decoy_placeholder: &'static str,
    pub forge_select_decoy_btn: &'static str,
    pub forge_step3_label: &'static str,
    pub forge_output_placeholder: &'static str,
    pub forge_select_output_btn: &'static str,
    pub forge_status_ready: &'static str,
    pub forge_status_need_1: &'static str,
    pub forge_status_running: &'static str,
    pub forge_status_done: &'static str,
    pub forge_action_btn: &'static str,
    pub forge_action_running_btn: &'static str,
    pub forge_log_label: &'static str,
}

impl Translations {
    /// Formats the information-theoretic hint for multi-payload splitting over GF(2).
    pub fn format_info_hint(
        &self,
        lang: Lang,
        n_files: usize,
        min_m: usize,
        m: usize,
        min_t: usize,
        max_t: usize,
    ) -> String {
        match lang {
            Lang::En => format!(
                "ℹ️ Information Theory: {} files require at least {} shares (M ≥ N + 1).\nAt least 1 share acts as a ChaCha20 random basis for Shannon Perfect Secrecy.\nValid threshold range for {} files on {} shares: T in {}..={}",
                n_files, min_m, n_files, m, min_t, max_t
            ),
            Lang::De => format!(
                "ℹ️ Informationstheorie: Für {} Dateien werden mindestens {} Shares benötigt (M ≥ N + 1).\nMindestens 1 Share dient als ChaCha20-Zufallsentropiebasis für Shannon Perfect Secrecy.\nZulässiger Schwellenwert-Bereich für {} Dateien auf {} Shares: T in {}..={}",
                n_files, min_m, n_files, m, min_t, max_t
            ),
            Lang::Es => format!(
                "ℹ️ Teoría de la Información: {} archivos requieren al menos {} partes (M ≥ N + 1).\nAl menos 1 parte actúa como base aleatoria ChaCha20 para Secreto Perfecto de Shannon.\nRango de umbral válido para {} archivos en {} partes: T en {}..={}",
                n_files, min_m, n_files, m, min_t, max_t
            ),
            Lang::Fr => format!(
                "ℹ️ Théorie de l'information : {} fichiers nécessitent au moins {} parts (M ≥ N + 1).\nAu moins 1 part sert de base aléatoire ChaCha20 pour le secret parfait de Shannon.\nPlage de seuil valide pour {} fichiers sur {} parts : T dans {}..={}",
                n_files, min_m, n_files, m, min_t, max_t
            ),
            Lang::Ja => format!(
                "ℹ️ 情報理論: {} 個のファイルには最低 {} 個のシェアが必要です (M ≥ N + 1)。\n最低 1 シェアが ChaCha20 乱数基底として機能し、シャノンの完全秘匿性を保証します。\n{} ファイル / {} シェアの有効なしきい値範囲: T = {}..={}",
                n_files, min_m, n_files, m, min_t, max_t
            ),
            Lang::Zh => format!(
                "ℹ️ 信息论约束：{} 个文件至少需要 {} 个分片 (M ≥ N + 1)。\n至少 1 个分片作为 ChaCha20 随机熵基底以保证香农完美保密性。\n{} 个文件在 {} 个分片上的有效阈值范围：T 在 {}..={}",
                n_files, min_m, n_files, m, min_t, max_t
            ),
            Lang::Tok => format!(
                "ℹ️ sona nanpa: lipu {} li wile e kipisi {} anu mute (M ≥ N + 1).\nkipisi 1 li kalama nasa ChaCha20 tawa len pona.\nnanpa kipisi wile (T) lon kipisi {}: {}..={}",
                n_files, min_m, m, min_t, max_t
            ),
            Lang::Sp => format!(
                "ℹ️ 󱥡 󱤽: 󱤪 {} 󱤧 󱥷 󱤉 󱥻 {} 󱤇 󱤼 (M >= N + 1).\n󱥻 1 󱤧 󱤕 󱤾 ChaCha20 󱥩 󱤥 󱥔.\n󱤽 󱥻 󱥷 (T) 󱤬 󱥻 {}: {}..={}",
                n_files, min_m, m, min_t, max_t
            ),
        }
    }

    /// Formats the selected file info line in the Split tab.
    pub fn format_selected_files(
        &self,
        lang: Lang,
        n_files: usize,
        single_desc: Option<(&str, &str)>,
    ) -> String {
        if let Some((name, size)) = single_desc {
            match lang {
                Lang::En => format!("Selected: {} ({})", name, size),
                Lang::De => format!("Ausgewählt: {} ({})", name, size),
                Lang::Es => format!("Seleccionado: {} ({})", name, size),
                Lang::Fr => format!("Sélectionné : {} ({})", name, size),
                Lang::Ja => format!("選択済み: {} ({})", name, size),
                Lang::Zh => format!("已选择：{} ({})", name, size),
                Lang::Tok => format!("lipu wile: {} ({})", name, size),
                Lang::Sp => format!("󱤪 󱥷: {} ({})", name, size),
            }
        } else {
            match lang {
                Lang::En => format!(
                    "{} payloads selected (Symmetric Multi-Splitting over GF(2))",
                    n_files
                ),
                Lang::De => format!(
                    "{} Payloads ausgewählt (Symmetrisches Multi-Splitting über GF(2))",
                    n_files
                ),
                Lang::Es => format!(
                    "{} archivos seleccionados (División múltiple simétrica en GF(2))",
                    n_files
                ),
                Lang::Fr => format!(
                    "{} fichiers sélectionnés (Partage multiple symétrique sur GF(2))",
                    n_files
                ),
                Lang::Ja => format!("{} 個のペイロードを選択 (GF(2) 対称マルチ分割)", n_files),
                Lang::Zh => format!("已选择 {} 个载荷文件（GF(2) 对称多文件分割）", n_files),
                Lang::Tok => format!("lipu {} li lon (kipisi mute lon nasin GF(2))", n_files),
                Lang::Sp => format!("󱤪 {} 󱤧 󱤬 (󱥻 󱤼 󱤬 󱤿 GF(2))", n_files),
            }
        }
    }

    /// Prints localized CLI split completion report to stderr.
    #[allow(clippy::too_many_arguments)]
    pub fn print_cli_split_summary(
        &self,
        lang: Lang,
        n_parts: usize,
        original_filename: &str,
        total_processed: u64,
        share_size: u64,
        blks_b64: &str,
        out_paths: &[PathBuf],
        decoy_paths: &[PathBuf],
    ) {
        match lang {
            Lang::En => {
                eprintln!(
                    "Successfully split into {} shares (N-Way OTP, RFS4):",
                    n_parts
                );
                eprintln!("  Embedded name: {}", original_filename);
                eprintln!("  Original size: {} bytes", total_processed);
                eprintln!("  Share size (4 KiB cluster padding): {} bytes", share_size);
                eprintln!("  BLKS-384: {}", blks_b64);
                if !decoy_paths.is_empty() {
                    eprintln!("\nReal shares (N={}, randomized across set):", n_parts);
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                    eprintln!(
                        "\nDecoy chaff files (D={}, 100% ChaCha20 random noise):",
                        decoy_paths.len()
                    );
                    for (i, p) in decoy_paths.iter().enumerate() {
                        eprintln!("  Decoy {}: {} ({} bytes)", i + 1, p.display(), share_size);
                    }
                } else {
                    eprintln!("\nGenerated shares:");
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                }
            }
            Lang::De => {
                eprintln!(
                    "Erfolgreich in {} Shares aufgeteilt (N-Way OTP, RFS4):",
                    n_parts
                );
                eprintln!("  Eingebetteter Name: {}", original_filename);
                eprintln!("  Originalgröße:      {} Bytes", total_processed);
                eprintln!(
                    "  Share-Größe (4 KiB Cluster-Padding): {} Bytes",
                    share_size
                );
                eprintln!("  BLKS-384: {}", blks_b64);
                if !decoy_paths.is_empty() {
                    eprintln!("\nEchte Shares (N={}, zufällig gemischt):", n_parts);
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                    eprintln!(
                        "\nKöderdateien (D={}, 100% ChaCha20 Rauschen):",
                        decoy_paths.len()
                    );
                    for (i, p) in decoy_paths.iter().enumerate() {
                        eprintln!("  Decoy {}: {} ({} Bytes)", i + 1, p.display(), share_size);
                    }
                } else {
                    eprintln!("\nErzeugte Shares:");
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                }
            }
            Lang::Es => {
                eprintln!(
                    "Dividido con éxito en {} partes (N-Way OTP, RFS4):",
                    n_parts
                );
                eprintln!("  Nombre incrustado: {}", original_filename);
                eprintln!("  Tamaño original:   {} bytes", total_processed);
                eprintln!("  Tamaño de parte (relleno 4 KiB): {} bytes", share_size);
                eprintln!("  BLKS-384: {}", blks_b64);
                if !decoy_paths.is_empty() {
                    eprintln!("\nPartes reales (N={}, mezcladas aleatoriamente):", n_parts);
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                    eprintln!(
                        "\nArchivos señuelo (D={}, 100% ruido ChaCha20):",
                        decoy_paths.len()
                    );
                    for (i, p) in decoy_paths.iter().enumerate() {
                        eprintln!("  Decoy {}: {} ({} bytes)", i + 1, p.display(), share_size);
                    }
                } else {
                    eprintln!("\nPartes generadas:");
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                }
            }
            Lang::Fr => {
                eprintln!(
                    "Divisé avec succès en {} parts (N-Way OTP, RFS4) :",
                    n_parts
                );
                eprintln!("  Nom intégré :      {}", original_filename);
                eprintln!("  Taille originale : {} octets", total_processed);
                eprintln!(
                    "  Taille de part (alignement 4 Kio) : {} octets",
                    share_size
                );
                eprintln!("  BLKS-384 : {}", blks_b64);
                if !decoy_paths.is_empty() {
                    eprintln!("\nParts réelles (N={}, mélangées aléatoirement) :", n_parts);
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                    eprintln!(
                        "\nFichiers leurres (D={}, 100% bruit ChaCha20) :",
                        decoy_paths.len()
                    );
                    for (i, p) in decoy_paths.iter().enumerate() {
                        eprintln!("  Decoy {}: {} ({} octets)", i + 1, p.display(), share_size);
                    }
                } else {
                    eprintln!("\nParts générées :");
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                }
            }
            Lang::Ja => {
                eprintln!(
                    "{} 個のシェアに正常に分割されました (N-Way OTP, RFS4):",
                    n_parts
                );
                eprintln!("  埋め込みファイル名: {}", original_filename);
                eprintln!("  元サイズ:           {} バイト", total_processed);
                eprintln!("  シェアサイズ (4 KiB パディング): {} バイト", share_size);
                eprintln!("  BLKS-384: {}", blks_b64);
                if !decoy_paths.is_empty() {
                    eprintln!("\n本物のシェア (N={}, ランダム配置):", n_parts);
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                    eprintln!(
                        "\nおとりファイル (D={}, 100% ChaCha20 乱数ノイズ):",
                        decoy_paths.len()
                    );
                    for (i, p) in decoy_paths.iter().enumerate() {
                        eprintln!("  Decoy {}: {} ({} bytes)", i + 1, p.display(), share_size);
                    }
                } else {
                    eprintln!("\n生成されたシェア:");
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                }
            }
            Lang::Zh => {
                eprintln!("成功分割为 {} 个分片 (N-Way OTP, RFS4)：", n_parts);
                eprintln!("  嵌入文件名：{}", original_filename);
                eprintln!("  原始大小：  {} 字节", total_processed);
                eprintln!("  分片大小 (4 KiB 簇对齐)：{} 字节", share_size);
                eprintln!("  BLKS-384：{}", blks_b64);
                if !decoy_paths.is_empty() {
                    eprintln!("\n真实分片 (N={}，已随机混洗)：", n_parts);
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                    eprintln!(
                        "\n诱饵噪声文件 (D={}，100% ChaCha20 随机噪声)：",
                        decoy_paths.len()
                    );
                    for (i, p) in decoy_paths.iter().enumerate() {
                        eprintln!("  Decoy {}: {} ({} bytes)", i + 1, p.display(), share_size);
                    }
                } else {
                    eprintln!("\n已生成的分片：");
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                }
            }
            Lang::Tok => {
                eprintln!(
                    "lipu li kipisi pona tawa kipisi {} (N-Way OTP, RFS4):",
                    n_parts
                );
                eprintln!("  nimi insa:   {}", original_filename);
                eprintln!("  suli open:   {} bytes", total_processed);
                eprintln!("  suli kipisi: {} bytes (4 KiB)", share_size);
                eprintln!("  BLKS-384:    {}", blks_b64);
                if !decoy_paths.is_empty() {
                    eprintln!("\nkipisi lon (N={}):", n_parts);
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                    eprintln!(
                        "\nkipisi powe (D={}, kalama nasa ChaCha20):",
                        decoy_paths.len()
                    );
                    for (i, p) in decoy_paths.iter().enumerate() {
                        eprintln!("  Decoy {}: {} ({} bytes)", i + 1, p.display(), share_size);
                    }
                } else {
                    eprintln!("\nkipisi pali:");
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                }
            }
            Lang::Sp => {
                eprintln!("󱤪 󱤧 󱥻 󱥔 󱥩 󱥻 {} (N-Way OTP, RFS4):", n_parts);
                eprintln!("  󱥂 󱥇:   {}", original_filename);
                eprintln!("  󱥣 󱥇:   {} bytes", total_processed);
                eprintln!("  󱥣 󱥻:   {} bytes (4 KiB)", share_size);
                eprintln!("  BLKS-384: {}", blks_b64);
                if !decoy_paths.is_empty() {
                    eprintln!("\n󱥻 󱤬 (N={}):", n_parts);
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                    eprintln!("\n󱥻 󱦣 (D={}, 󱤕 󱤾 ChaCha20):", decoy_paths.len());
                    for (i, p) in decoy_paths.iter().enumerate() {
                        eprintln!("  Decoy {}: {} ({} bytes)", i + 1, p.display(), share_size);
                    }
                } else {
                    eprintln!("\n󱥻 󱥉:");
                    for (i, p) in out_paths.iter().enumerate() {
                        eprintln!("  Share {}: {}", i + 1, p.display());
                    }
                }
            }
        }
    }

    /// Prints the complete localized CLI help message for `lang`.
    pub fn print_cli_localized_help(&self, lang: Lang) {
        if lang != Lang::En {
            println!("\n------------------------------------------------------------");
            println!(" [{}] {}", lang.code().to_ascii_uppercase(), self.subtitle);
            println!("------------------------------------------------------------");
        }
        match lang {
            Lang::En => {
                println!("\nUsage:");
                println!("  rfs split [options] <source|-> [shares...]     (Split file or stdin into 2 or N shares)");
                println!("  rfs restore [options] <shares...> [target|-]   (Reconstruct N shares to disk or stdout)");
                println!("  rfs verify [options] <shares...>               (Verify integrity of N shares in RAM)");
                println!("  rfs scan [options] <candidate_files...>        (Auto-discover & assemble valid OTP sets)");
                println!("  rfs forge <shares...> --reveal-as <decoy> -o <out> (Synthesize plausible deniability decoy)");
                println!("  rfs decoy [options] [-t <template>] [-s <size>] (Generate ChaCha20 random decoy files)");

                println!("\nClassic Syntax:");
                println!("  rfs [options] <file|->                         (Split file or stdin into 2 shares)");
                println!("  rfs [options] <part1> <part2> [part3...]       (Reconstruct file from N shares)");
                println!("  rfs --verify <shares...>                       (Verify integrity of N shares)");

                println!("\nN-Way One-Time-Pad & Unix Streaming Pipes:");
                println!("  rfs split -n 3 secret.iso                      (Split into 3 noise shares: .rfs1, .rfs2, .rfs3)");
                println!("  rfs split -n 3 secret.iso --decoy-reveal doc.pdf (Embed authentic plaintext decoy into shares)");
                println!("  rfs split f1.db f2.pdf -n 4 -T 3 -o ./shares   (Symmetric multi-payload split over GF(2))");
                println!("  rfs restore secret.rfs1 secret.rfs2 secret.rfs3 (Bit-exact restore from all 3 shares)");
                println!("  rfs scan /backup/*.rfs -r -o ./restored        (Scan folder and auto-reconstruct all valid sets)");
                println!("  rfs forge share1.rfs --reveal-as harmless.pdf -o fake2.rfs (Rubber-hose defense counterpart)");
                println!("  tar -czf - /data | rfs split -n 4 - -o backup  (Stream stdin directly into 4 shares)");
                println!("  rfs restore backup.rfs* -o - | tar -xzf -      (Pipe restored stream directly to stdout)");

                println!("\nCommands & Tools:");
                println!("  -b, --benchmark                                Run hardware throughput benchmark");
                println!("  -e, --entropy-test                            Run two-phase entropy and jitter diagnostics");
                println!("  -a, --analyze <file>                          Cryptanalytic NIST SP 800-22 file analysis");
                println!(
                    "  -h, --help                                    Display this help message"
                );
                println!(
                    "  -V, --version                                 Display version information"
                );

                println!("\nOptions:");
                println!("  -n, --parts <COUNT>                           Number of shares for N-way splitting (2 to 64; default: 2)");
                println!("  -T, --threshold <COUNT>                       Subset threshold T for multi-payload splitting over GF(2)");
                println!("  -B, --block-size <SIZE>                       I/O buffer block size (e.g., 64K, 1M, 4M, 16M; default: 4M)");
                println!("  -d, --decoys <COUNT>                          Generate additional decoy chaff files during split");
                println!("  --decoy-reveal <FILE>                         Embed authentic plaintext decoy into shares during split");
                println!("  --pad-to <SIZE>                               Pad shares to an exact target byte size (e.g., 100M, 20G)");
                println!("  --token, --rnd                                Anti-forensics: Uncorrelated hex tokens (.<rnd>.rfs)");
                println!("  -r, --restore                                 Auto-reconstruct discovered sets ('rfs scan')");
                println!("  --reveal-as <FILE>                            Plaintext file to reveal during decoy forge ('rfs forge')");
                println!("  -c, --count <COUNT>                           Number of decoy files for 'rfs decoy' (default: 1)");
                println!("  -s, --size <SIZE>                             Explicit byte size for 'rfs decoy' (e.g., 64K, 10M, 1G)");
                println!("  -t, --template <FILE>                         Template file for 'rfs decoy' (raw file +64B or RFS 1:1)");
                println!("  -o, --output <PATH>                           Share prefix or restore target destination (or '-' for stdout)");
                println!("  --direct                                      Direct I/O: Bypass OS page cache for multi-gigabyte transfers");
                println!("  --mlock                                       Lock buffer memory in physical RAM (prevents swap paging)");
                println!("  --json                                        Machine-readable NDJSON telemetry on stderr");
                println!("  -f, --force                                   Overwrite existing destination files");
                println!("  -q, --quiet, --silent                         Suppress interactive progress (errors only)");
                println!("  -l, --lang <CODE>                             Language code (en [default], de, es, fr, ja, zh, tok, sp)");
                println!("\nTip: Run 'rfs <subcommand> --help' for detailed options on a specific command.\n");
            }
            Lang::De => {
                println!("\nVerwendung:");
                println!("  rfs split [Optionen] <Quelle|-> [Shares...]    (Datei oder Stdin in 2 oder N Shares aufteilen)");
                println!("  rfs restore [Optionen] <Shares...> [Ziel|-]    (N Shares auf Festplatte oder Stdout rekonstruieren)");
                println!("  rfs verify [Optionen] <Shares...>              (BLKS-384 Integrität von N Shares im RAM prüfen)");
                println!("  rfs scan [Optionen] <Kandidaten...>            (Gültige OTP-Sets automatisch finden & entpacken)");
                println!("  rfs forge <Shares...> --reveal-as <Köder> -o <Out> (Gegen-Share für glaubhafte Abstreitbarkeit)");
                println!("  rfs decoy [Optionen] [-t <Vorlage>] [-s <Größe>] (ChaCha20-Rauschdateien als Köder erzeugen)");

                println!("\nKlassische Syntax:");
                println!("  rfs [Optionen] <Datei|->                       (Datei oder Stdin in 2 Shares aufteilen)");
                println!("  rfs [Optionen] <Teil1> <Teil2> [Teil3...]      (Originaldatei aus N Shares wiederherstellen)");
                println!("  rfs --verify <Shares...>                       (Integrität von N Shares prüfen)");

                println!("\nN-Way One-Time-Pad & Unix-Streaming-Pipes:");
                println!("  rfs split -n 3 geheim.iso                      (In 3 Rausch-Shares aufteilen)");
                println!("  rfs split -n 3 geheim.iso --decoy-reveal dok.pdf (Echten Klartext-Köder simultan einweben)");
                println!("  rfs split d1.db d2.pdf -n 4 -T 3 -o ./shares   (Symmetrisches Multi-Payload-Splitting über GF(2))");
                println!("  rfs restore geheim.rfs1 geheim.rfs2 geheim.rfs3 (Bitgenaue Wiederherstellung aus allen 3 Shares)");
                println!("  rfs scan /backup/*.rfs -r -o ./wiederhergestellt (Ordner scannen & alle gültigen Sets entpacken)");
                println!("  rfs forge share1.rfs --reveal-as harmlos.pdf -o fake2.rfs (Gegen-Share zur Rubber-Hose-Abwehr)");
                println!("  tar -czf - /daten | rfs split -n 4 - -o backup (Stdin direkt in 4 Shares streamen)");
                println!("  rfs restore backup.rfs* -o - | tar -xzf -      (Rekonstruierten Stream direkt nach Stdout leiten)");

                println!("\nBefehle & Diagnose:");
                println!("  -b, --benchmark                                Hardware-Durchsatz-Benchmark (SIMD, ChaCha20, BLKS)");
                println!("  -e, --entropy-test                            Zweiphasige Entropie- und Hardware-Jitter-Diagnose");
                println!("  -a, --analyze <Datei>                         Kryptoanalytische NIST SP 800-22 Dateianalyse");
                println!("  -h, --help                                    Diese Hilfe anzeigen");
                println!("  -V, --version                                 Versionsinformationen anzeigen");

                println!("\nOptionen:");
                println!("  -n, --parts <ANZAHL>                          Anzahl der Shares beim N-Way-Splitting (2..64; Standard: 2)");
                println!("  -T, --threshold <ANZAHL>                      Schwellenwert T für Multi-Payload-Splitting über GF(2)");
                println!("  -B, --block-size <GRÖSSE>                     I/O-Puffergröße (z. B. 64K, 1M, 4M, 16M; Standard: 4M)");
                println!("  -d, --decoys <ANZAHL>                         Zusätzliche Köderdateien (Decoys) beim Split erzeugen");
                println!("  --decoy-reveal <DATEI>                        Harmlosen Klartext-Köder simultan in Shares einbetten");
                println!("  --pad-to <GRÖSSE>                             Shares auf exakte Zielgröße aufblähen (z. B. 100M, 20G)");
                println!("  --token, --rnd                                Anti-Forensik: Unkorrelierte Hex-Tokens (.<rnd>.rfs)");
                println!("  -r, --restore                                 Entdeckte Sets direkt wiederherstellen ('rfs scan')");
                println!("  --reveal-as <DATEI>                           Vorzulegende Köderdatei bei 'rfs forge'");
                println!("  -c, --count <ANZAHL>                          Anzahl der Köderdateien bei 'rfs decoy' (Standard: 1)");
                println!("  -s, --size <GRÖSSE>                           Explizite Bytegröße für 'rfs decoy' (z. B. 64K, 10M, 1G)");
                println!("  -t, --template <DATEI>                        Vorlagendatei für 'rfs decoy' (Rohdatei +64B oder RFS 1:1)");
                println!("  -o, --output <PFAD>                           Ausgabepräfix oder Zielpfad (oder '-' für Stdout)");
                println!("  --direct                                      Direct I/O: OS Page-Cache bei großen Dateien umgehen");
                println!("  --mlock                                       Puffer im physischen RAM sperren (verhindert Swap-Paging)");
                println!("  --json                                        Maschinenlesbare NDJSON-Telemetrie auf stderr");
                println!("  -f, --force                                   Bestehende Zieldateien überschreiben");
                println!("  -q, --quiet, --silent                         Fortschrittsanzeige unterdrücken (nur Fehler)");
                println!("  -l, --lang <CODE>                             Sprachcode (en [Standard], de, es, fr, ja, zh, tok, sp)");
                println!(
                    "\nTipp: 'rfs <Befehl> --help' zeigt detaillierte Optionen zu einem Befehl.\n"
                );
            }
            Lang::Es => {
                println!("\nUso:");
                println!("  rfs split [opciones] <fuente|-> [partes...]    (Dividir archivo o stdin en 2 o N partes)");
                println!("  rfs restore [opciones] <partes...> [destino|-] (Reconstruir N partes en disco o stdout)");
                println!("  rfs verify [opciones] <partes...>              (Verificar integridad BLKS-384 de N partes en RAM)");
                println!("  rfs scan [opciones] <archivos...>              (Auto-descubrir y ensamblar conjuntos OTP válidos)");
                println!("  rfs forge <partes...> --reveal-as <señuelo> -o <out> (Sintetizar parte falsa de negabilidad plausible)");
                println!("  rfs decoy [opciones] [-t <plantilla>] [-s <tam>] (Generar archivos señuelo de ruido ChaCha20)");

                println!("\nSintaxis Clásica:");
                println!("  rfs [opciones] <archivo|->                     (Dividir archivo o stdin en 2 partes)");
                println!("  rfs [opciones] <parte1> <parte2> [parte3...]   (Reconstruir archivo desde N partes)");
                println!("  rfs --verify <partes...>                       (Verificar integridad de N partes)");

                println!("\nOne-Time-Pad N-Way y Tuberías Unix (Streaming):");
                println!("  rfs split -n 3 secreto.iso                     (Dividir en 3 partes de ruido)");
                println!("  rfs split -n 3 secreto.iso --decoy-reveal doc.pdf (Incrustar señuelo auténtico simultáneamente)");
                println!("  rfs split f1.db f2.pdf -n 4 -T 3 -o ./partes   (División múltiple simétrica sobre GF(2))");
                println!("  rfs restore secreto.rfs1 secreto.rfs2 secreto.rfs3 (Restauración exacta bit a bit de las 3 partes)");
                println!("  rfs scan /backup/*.rfs -r -o ./restaurado      (Escanear carpeta y auto-reconstruir conjuntos)");
                println!("  rfs forge share1.rfs --reveal-as inofensivo.pdf -o fake2.rfs (Contraparte para defensa coercitiva)");
                println!("  tar -czf - /datos | rfs split -n 4 - -o backup (Transmitir stdin directamente en 4 partes)");
                println!("  rfs restore backup.rfs* -o - | tar -xzf -      (Enviar flujo restaurado directamente a stdout)");

                println!("\nComandos y Herramientas:");
                println!("  -b, --benchmark                                Ejecutar prueba de rendimiento de hardware");
                println!("  -e, --entropy-test                            Diagnóstico de entropía y jitter en dos fases");
                println!("  -a, --analyze <archivo>                       Análisis criptoanalítico NIST SP 800-22");
                println!(
                    "  -h, --help                                    Mostrar este mensaje de ayuda"
                );
                println!("  -V, --version                                 Mostrar información de versión");

                println!("\nOpciones:");
                println!("  -n, --parts <CANT>                            Número de partes para división N-way (2 a 64; defecto: 2)");
                println!("  -T, --threshold <CANT>                        Umbral T para división múltiple sobre GF(2)");
                println!("  -B, --block-size <TAM>                        Tamaño de bloque de E/S (ej. 64K, 1M, 4M, 16M; defecto: 4M)");
                println!("  -d, --decoys <CANT>                           Generar archivos señuelo adicionales durante la división");
                println!("  --decoy-reveal <ARCHIVO>                      Incrustar archivo señuelo inofensivo durante la división");
                println!("  --pad-to <TAM>                                Rellenar partes hasta un tamaño exacto (ej. 100M, 20G)");
                println!("  --token, --rnd                                Antiforense: Tokens hexadecimales no correlacionados");
                println!("  -r, --restore                                 Auto-reconstruir conjuntos descubiertos ('rfs scan')");
                println!("  --reveal-as <ARCHIVO>                         Archivo señuelo a revelar en 'rfs forge'");
                println!("  -c, --count <CANT>                            Cantidad de archivos señuelo en 'rfs decoy' (defecto: 1)");
                println!("  -s, --size <TAM>                              Tamaño explícito en bytes para 'rfs decoy' (ej. 64K, 10M)");
                println!("  -t, --template <ARCHIVO>                      Archivo plantilla para 'rfs decoy' (original +64B o RFS 1:1)");
                println!("  -o, --output <RUTA>                           Prefijo de salida o ruta destino (o '-' para stdout)");
                println!("  --direct                                      Direct I/O: Omitir caché de página del sistema operativo");
                println!("  --mlock                                       Bloquear memoria de búfer en RAM física (evita swap)");
                println!("  --json                                        Telemetría NDJSON legible por máquina en stderr");
                println!("  -f, --force                                   Sobrescribir archivos de destino existentes");
                println!("  -q, --quiet, --silent                         Suprimir barra de progreso interactiva (solo errores)");
                println!("  -l, --lang <CÓDIGO>                           Código de idioma (en [defecto], de, es, fr, ja, zh, tok, sp)");
                println!(
                    "\nConsejo: Ejecute 'rfs <subcomando> --help' para ver opciones detalladas.\n"
                );
            }
            Lang::Fr => {
                println!("\nUtilisation :");
                println!("  rfs split [options] <source|-> [parts...]      (Diviser un fichier ou stdin en 2 ou N parts)");
                println!("  rfs restore [options] <parts...> [cible|-]     (Reconstruire N parts sur disque ou stdout)");
                println!("  rfs verify [options] <parts...>                (Vérifier l'intégrité BLKS-384 de N parts en RAM)");
                println!("  rfs scan [options] <fichiers...>               (Découvrir et assembler les ensembles OTP valides)");
                println!("  rfs forge <parts...> --reveal-as <leurre> -o <out> (Synthétiser une contre-part de déni plausible)");
                println!("  rfs decoy [options] [-t <modèle>] [-s <taille>] (Générer des fichiers leurres ChaCha20)");

                println!("\nSyntaxe Classique :");
                println!("  rfs [options] <fichier|->                      (Diviser un fichier ou stdin en 2 parts)");
                println!("  rfs [options] <part1> <part2> [part3...]       (Reconstruire le fichier depuis N parts)");
                println!("  rfs --verify <parts...>                        (Vérifier l'intégrité de N parts)");

                println!("\nMasque Jetable N-Way & Tubes Unix (Streaming) :");
                println!("  rfs split -n 3 secret.iso                      (Diviser en 3 parts de bruit)");
                println!("  rfs split -n 3 secret.iso --decoy-reveal doc.pdf (Intégrer un fichier leurre authentique)");
                println!("  rfs split f1.db f2.pdf -n 4 -T 3 -o ./parts    (Partage multiple symétrique sur GF(2))");
                println!("  rfs restore secret.rfs1 secret.rfs2 secret.rfs3 (Restauration exacte bit-à-bit des 3 parts)");
                println!("  rfs scan /backup/*.rfs -r -o ./restaure        (Scanner un dossier et tout reconstruire)");
                println!("  rfs forge share1.rfs --reveal-as inoffensif.pdf -o fake2.rfs (Contre-part de défense sous contrainte)");
                println!("  tar -czf - /data | rfs split -n 4 - -o backup  (Flux stdin directement divisé en 4 parts)");
                println!("  rfs restore backup.rfs* -o - | tar -xzf -      (Envoyer le flux restauré vers stdout)");

                println!("\nCommandes & Outils :");
                println!("  -b, --benchmark                                Exécuter le benchmark matériel (SIMD, ChaCha20, BLKS)");
                println!("  -e, --entropy-test                            Diagnostic d'entropie et de gigue en deux phases");
                println!("  -a, --analyze <fichier>                       Analyse cryptanalytique NIST SP 800-22");
                println!(
                    "  -h, --help                                    Afficher ce message d'aide"
                );
                println!("  -V, --version                                 Afficher la version");

                println!("\nOptions :");
                println!("  -n, --parts <NB>                              Nombre de parts pour la division N-way (2 à 64 ; défaut : 2)");
                println!("  -T, --threshold <NB>                          Seuil T pour le multi-partage sur GF(2)");
                println!("  -B, --block-size <TAILLE>                     Taille de bloc d'E/S (ex. 64K, 1M, 4M, 16M ; défaut : 4M)");
                println!("  -d, --decoys <NB>                             Générer des fichiers leurres supplémentaires");
                println!("  --decoy-reveal <FICHIER>                      Intégrer un fichier leurre en texte clair");
                println!("  --pad-to <TAILLE>                             Remplir les parts jusqu'à une taille exacte (ex. 100M, 20G)");
                println!("  --token, --rnd                                Anti-forensique : Jetons hexadécimaux aléatoires");
                println!("  -r, --restore                                 Reconstruire automatiquement les ensembles ('rfs scan')");
                println!("  --reveal-as <FICHIER>                         Fichier leurre à révéler lors de 'rfs forge'");
                println!("  -c, --count <NB>                              Nombre de fichiers leurres pour 'rfs decoy' (défaut : 1)");
                println!("  -s, --size <TAILLE>                           Taille explicite pour 'rfs decoy' (ex. 64K, 10M, 1G)");
                println!("  -t, --template <FICHIER>                      Fichier modèle pour 'rfs decoy' (brut +64o ou RFS 1:1)");
                println!("  -o, --output <CHEMIN>                         Préfixe de sortie ou destination (ou '-' pour stdout)");
                println!("  --direct                                      Direct I/O : Contourner le cache système");
                println!("  --mlock                                       Verrouiller les tampons en RAM physique (sans swap)");
                println!(
                    "  --json                                        Télémétrie NDJSON sur stderr"
                );
                println!("  -f, --force                                   Écraser les fichiers existants");
                println!("  -q, --quiet, --silent                         Masquer la barre de progression (erreurs seules)");
                println!("  -l, --lang <CODE>                             Code de langue (en [défaut], de, es, fr, ja, zh, tok, sp)");
                println!(
                    "\nAstuce : 'rfs <sous-commande> --help' affiche les options détaillées.\n"
                );
            }
            Lang::Ja => {
                println!("\n使用法:");
                println!("  rfs split [options] <元ファイル|-> [シェア...] (ファイルまたは標準入力を 2〜N 個のシェアに分割)");
                println!("  rfs restore [options] <シェア...> [出力先|-]   (N 個のシェアから元ファイルまたは標準出力へ復元)");
                println!("  rfs verify [options] <シェア...>               (RAM 上で N 個のシェアの BLKS-384 完全性を検証)");
                println!("  rfs scan [options] <候補ファイル...>           (有効な OTP シェアの組み合わせを自動検出・復元)");
                println!("  rfs forge <シェア...> --reveal-as <おとり> -o <出力> (もっともらしい否認のためのおとり偽シェア合成)");
                println!("  rfs decoy [options] [-t <雛形>] [-s <サイズ>]  (ChaCha20 乱数ノイズのおとりファイルを生成)");

                println!("\nクラシック構文:");
                println!("  rfs [options] <ファイル|->                     (ファイルを 2 個のシェアに分割)");
                println!("  rfs [options] <part1> <part2> [part3...]       (N 個のシェアから元ファイルを復元)");
                println!(
                    "  rfs --verify <シェア...>                       (N 個のシェアの完全性を検証)"
                );

                println!("\nN-Way ワンタイムパッド & Unix ストリーミングパイプ:");
                println!("  rfs split -n 3 secret.iso                      (3 個の乱数ノイズシェアに分割)");
                println!("  rfs split -n 3 secret.iso --decoy-reveal doc.pdf (分割時に無害なおとり平文を同時埋め込み)");
                println!("  rfs split f1.db f2.pdf -n 4 -T 3 -o ./shares   (GF(2) 上の対称マルチペイロード分割)");
                println!("  rfs restore secret.rfs1 secret.rfs2 secret.rfs3 (全 3 シェアからビット単位で完全復元)");
                println!("  rfs scan /backup/*.rfs -r -o ./restored        (フォルダをスキャンし有効なセットを自動一括復元)");
                println!("  rfs forge share1.rfs --reveal-as harmless.pdf -o fake2.rfs (強制開示対策の偽カウンターパート合成)");
                println!("  tar -czf - /data | rfs split -n 4 - -o backup  (標準入力を直接 4 個のシェアへストリーム分割)");
                println!("  rfs restore backup.rfs* -o - | tar -xzf -      (復元ストリームを直接標準出力へパイプ)");

                println!("\nコマンド & 診断ツール:");
                println!("  -b, --benchmark                                ハードウェアスループット・ベンチマークを実行");
                println!("  -e, --entropy-test                            2段階のエントロピー & CPU ジッター診断を実行");
                println!("  -a, --analyze <file>                          NIST SP 800-22 暗号統計ファイル解析");
                println!(
                    "  -h, --help                                    このヘルプメッセージを表示"
                );
                println!("  -V, --version                                 バージョン情報を表示");

                println!("\nオプション:");
                println!("  -n, --parts <COUNT>                           分割するシェア数 (2〜64; デフォルト: 2)");
                println!("  -T, --threshold <COUNT>                       GF(2) マルチペイロード分割のしきい値 T");
                println!("  -B, --block-size <SIZE>                       I/O バッファブロックサイズ (64K, 1M, 4M, 16M; 標準: 4M)");
                println!("  -d, --decoys <COUNT>                          分割時に追加のおとりノイズファイルを生成");
                println!("  --decoy-reveal <FILE>                         分割時に本物のおとり平文ファイルを埋め込む");
                println!("  --pad-to <SIZE>                               シェアを指定バイトサイズまでパディング (例: 100M, 20G)");
                println!("  --token, --rnd                                アンチフォレンジック: ランダムな16進トークン名 (.<rnd>.rfs)");
                println!("  -r, --restore                                 検出したセットを自動復元 ('rfs scan')");
                println!("  --reveal-as <FILE>                            おとり合成時に開示する平文ファイル ('rfs forge')");
                println!("  -c, --count <COUNT>                           'rfs decoy' で生成するおとりファイル数 (標準: 1)");
                println!("  -s, --size <SIZE>                             'rfs decoy' の明示的なバイトサイズ (例: 64K, 10M, 1G)");
                println!("  -t, --template <FILE>                         'rfs decoy' のテンプレートファイル (元ファイル+64B または RFS 1:1)");
                println!("  -o, --output <PATH>                           出力プレフィックスまたは復元先パス ('-' で標準出力)");
                println!("  --direct                                      Direct I/O: OS ページキャッシュをバイパス");
                println!("  --mlock                                       バッファを物理 RAM にロック (スワップ流出防止)");
                println!("  --json                                        stderr に機械可読な NDJSON テレメトリを出力");
                println!(
                    "  -f, --force                                   既存の出力ファイルを上書き"
                );
                println!("  -q, --quiet, --silent                         進捗バーを非表示 (エラーのみ出力)");
                println!("  -l, --lang <CODE>                             言語コード (en [標準], de, es, fr, ja, zh, tok, sp)");
                println!("\nヒント: 'rfs <サブコマンド> --help' で各コマンドの詳細オプションを表示します。\n");
            }
            Lang::Zh => {
                println!("\n用法：");
                println!("  rfs split [选项] <源文件|-> [分片...]          (将文件或标准输入分割为 2 或 N 个分片)");
                println!("  rfs restore [选项] <分片...> [目标|-]          (将 N 个分片重构至磁盘或标准输出)");
                println!("  rfs verify [选项] <分片...>                    (在内存中快速验证 N 个分片的 BLKS-384 完整性)");
                println!("  rfs scan [选项] <候选文件...>                  (自动扫描发现并组装有效的 OTP 分片组合)");
                println!("  rfs forge <分片...> --reveal-as <诱饵> -o <输出> (合成可否认的诱饵对应伪造分片)");
                println!("  rfs decoy [选项] [-t <模板>] [-s <大小>]       (生成纯 ChaCha20 随机噪声诱饵文件)");

                println!("\n经典语法：");
                println!("  rfs [选项] <文件|->                            (将文件或标准输入分割为 2 个分片)");
                println!(
                    "  rfs [选项] <分片1> <分片2> [分片3...]          (从 N 个分片还原原始文件)"
                );
                println!(
                    "  rfs --verify <分片...>                         (验证 N 个分片的完整性)"
                );

                println!("\nN-Way 一次性密码本与 Unix 流式管道：");
                println!(
                    "  rfs split -n 3 secret.iso                      (分割为 3 个随机噪声分片)"
                );
                println!("  rfs split -n 3 secret.iso --decoy-reveal doc.pdf (分割时同时嵌入真实明文诱饵)");
                println!("  rfs split f1.db f2.pdf -n 4 -T 3 -o ./shares   (基于 GF(2) 的对称多载荷文件分割)");
                println!("  rfs restore secret.rfs1 secret.rfs2 secret.rfs3 (从全部 3 个分片比特级精确还原)");
                println!("  rfs scan /backup/*.rfs -r -o ./restored        (扫描文件夹并自动重构所有有效分片组合)");
                println!("  rfs forge share1.rfs --reveal-as harmless.pdf -o fake2.rfs (抗胁迫橡胶软管防御伪造分片)");
                println!("  tar -czf - /data | rfs split -n 4 - -o backup  (将标准输入直接流式分割为 4 个分片)");
                println!("  rfs restore backup.rfs* -o - | tar -xzf -      (将还原的数据流直接通过管道输出到 stdout)");

                println!("\n命令与工具：");
                println!("  -b, --benchmark                                运行硬件吞吐量基准测试 (SIMD, ChaCha20, BLKS)");
                println!(
                    "  -e, --entropy-test                            运行两阶段熵源与 CPU 抖动诊断"
                );
                println!("  -a, --analyze <文件>                          NIST SP 800-22 密码学文件熵统计分析");
                println!("  -h, --help                                    显示此帮助信息");
                println!("  -V, --version                                 显示版本信息");

                println!("\n选项：");
                println!("  -n, --parts <数量>                            N-Way 分割的分片数量 (2 到 64；默认：2)");
                println!("  -T, --threshold <数量>                        GF(2) 对称多文件分割的组合阈值 T");
                println!("  -B, --block-size <大小>                       I/O 缓冲区块大小 (如 64K, 1M, 4M, 16M；默认：4M)");
                println!("  -d, --decoys <数量>                           分割期间额外生成的诱饵噪声文件数量");
                println!(
                    "  --decoy-reveal <文件>                         分割期间嵌入无害明文诱饵文件"
                );
                println!("  --pad-to <大小>                               将分片填充至指定精确字节大小 (如 100M, 20G)");
                println!("  --token, --rnd                                反取证：生成无关联随机十六进制文件名 (.<rnd>.rfs)");
                println!("  -r, --restore                                 自动还原扫描发现的有效分片组合 ('rfs scan')");
                println!("  --reveal-as <文件>                            'rfs forge' 伪造时要展示的诱饵明文文件");
                println!("  -c, --count <数量>                            'rfs decoy' 生成的诱饵文件数量 (默认：1)");
                println!("  -s, --size <大小>                             'rfs decoy' 的显式字节大小 (如 64K, 10M, 1G)");
                println!("  -t, --template <文件>                         'rfs decoy' 的模板文件 (原始文件 +64B 或 RFS 1:1)");
                println!("  -o, --output <路径>                           分片前缀或还原目标路径 ('-' 表示标准输出)");
                println!("  --direct                                      Direct I/O：绕过操作系统页缓存");
                println!("  --mlock                                       将缓冲区锁定在物理内存 RAM 中（防止写入交换分区）");
                println!("  --json                                        在 stderr 上输出机器可读的 NDJSON 遥测事件");
                println!("  -f, --force                                   覆盖已存在的目标文件");
                println!("  -q, --quiet, --silent                         静默模式（仅输出错误）");
                println!("  -l, --lang <代码>                             语言代码 (en [默认], de, es, fr, ja, zh, tok, sp)");
                println!("\n提示：运行 'rfs <子命令> --help' 查看特定命令的详细选项。\n");
            }
            Lang::Tok => {
                println!("\nnasin kepeken:");
                println!("  rfs split [nasin] <lipu|-> [kipisi...]         (o kipisi e lipu tawa kipisi 2 anu N)");
                println!("  rfs restore [nasin] <kipisi...> [pini|-]       (o wan sin e lipu open tan kipisi N)");
                println!("  rfs verify [nasin] <kipisi...>                 (o lukin e pona BLKS-384 pi kipisi N)");
                println!("  rfs scan [nasin] <lipu...>                     (o alasa e kulupu kipisi pona)");
                println!("  rfs forge <kipisi...> --reveal-as <powe> -o <out> (o pali e kipisi powe sin)");
                println!("  rfs decoy [nasin] [-t <lipu>] [-s <suli>]      (o pali e lipu pi kalama nasa ChaCha20)");

                println!("\nnasin majuna:");
                println!("  rfs [nasin] <lipu|->                           (o kipisi e lipu tawa kipisi 2)");
                println!("  rfs [nasin] <kipisi1> <kipisi2> [kipisi3...]   (o wan sin e lipu tan kipisi N)");
                println!(
                    "  rfs --verify <kipisi...>                       (o lukin e pona pi kipisi N)"
                );

                println!("\nnasin kipisi N & nasin linja Unix:");
                println!("  rfs split -n 3 len.iso                         (o kipisi tawa kipisi 3 pi kalama nasa)");
                println!("  rfs split -n 3 len.iso --decoy-reveal musi.pdf (o pana e lipu powe lon insa kipisi)");
                println!("  rfs split f1.db f2.pdf -n 4 -T 3 -o ./kipisi   (o kipisi e lipu mute lon nasin GF(2))");
                println!("  rfs restore len.rfs1 len.rfs2 len.rfs3         (o wan sin e lipu tan kipisi 3 ale)");
                println!("  rfs scan /poki/*.rfs -r -o ./sin               (o alasa lon poki li wan sin e kulupu ale)");
                println!("  rfs forge share1.rfs --reveal-as musi.pdf -o fake2.rfs (o pali e kipisi powe tawa awen)");
                println!("  tar -czf - /data | rfs split -n 4 - -o backup  (o kipisi e linja tawa kipisi 4)");
                println!("  rfs restore backup.rfs* -o - | tar -xzf -      (o pana e lipu sin tawa linja pini)");

                println!("\nilo lukin & sona:");
                println!("  -b, --benchmark                                o lukin e wawa ilo (SIMD, ChaCha20, BLKS)");
                println!(
                    "  -e, --entropy-test                            o lukin e pona pi kalama nasa"
                );
                println!("  -a, --analyze <lipu>                          o lukin e nanpa NIST SP 800-22 lon lipu");
                println!("  -h, --help                                    o pana e lipu sona ni");
                println!(
                    "  -V, --version                                 o pana e nanpa pali pi ilo ni"
                );

                println!("\nnasin ante:");
                println!("  -n, --parts <MUTE>                            mute kipisi (2..64; nasin open: 2)");
                println!("  -T, --threshold <MUTE>                        mute kipisi wile T tawa lipu mute GF(2)");
                println!("  -B, --block-size <SULI>                       suli poki pali (64K, 1M, 4M, 16M; open: 4M)");
                println!("  -d, --decoys <MUTE>                           o pali e kipisi powe pi kalama nasa");
                println!("  --decoy-reveal <LIPU>                         o pana e lipu powe lon insa kipisi");
                println!("  --pad-to <SULI>                               o suli e kipisi ale tawa suli sama (100M, 20G)");
                println!("  --token, --rnd                                nimi len: nanpa nasa (.<rnd>.rfs)");
                println!("  -r, --restore                                 o wan sin e kulupu ale ('rfs scan')");
                println!(
                    "  --reveal-as <LIPU>                            lipu powe tawa 'rfs forge'"
                );
                println!("  -c, --count <MUTE>                            mute pi lipu powe lon 'rfs decoy' (open: 1)");
                println!("  -s, --size <SULI>                             suli pi lipu powe lon 'rfs decoy' (64K, 10M)");
                println!("  -t, --template <LIPU>                         lipu sama tawa 'rfs decoy' (+64B anu RFS 1:1)");
                println!("  -o, --output <NIMI>                           nimi anu poki pini ('-' tawa stdout)");
                println!("  --direct                                      Direct I/O: o kepeken ala e poki awen OS");
                println!("  --mlock                                       o awen e sona lon insa RAM taso");
                println!(
                    "  --json                                        o pana e toki JSON lon stderr"
                );
                println!("  -f, --force                                   o ante e lipu pini lon");
                println!(
                    "  -q, --quiet, --silent                         o kalama ala (pakala taso)"
                );
                println!("  -l, --lang <TOKI>                             toki ilo (en [open], de, es, fr, ja, zh, tok, sp)");
                println!("\nsona: o kepeken 'rfs <pali> --help' tawa sona mute.\n");
            }
            Lang::Sp => {
                println!("\n󱤿 󱤙:");
                println!("  rfs split [󱤿] <󱤪|-> [󱥻...]               (󱥄 󱥻 󱤉 󱤪 󱥩 󱥻 2 󱤇 N)");
                println!("  rfs restore [󱤿] <󱥻...> [󱥐|-]               (󱥄 󱥳 󱥝 󱤉 󱤪 󱥇 󱤬 󱥻 N)");
                println!("  rfs verify [󱤿] <󱥻...>                        (󱥄 󱤮 󱤉 󱥔 BLKS-384 󱥍 󱥻 N)");
                println!("  rfs scan [󱤿] <󱤪...>                         (󱥄 󱤃 󱤉 󱤟 󱥻 󱥔)");
                println!("  rfs forge <󱥻...> --reveal-as <󱦣> -o <out>    (󱥄 󱥉 󱤉 󱥻 󱦣 󱥝)");
                println!("  rfs decoy [󱤿] [-t <󱤪>] [-s <󱥣>]            (󱥄 󱥉 󱤉 󱤪 󱥍 󱤕 󱤾 ChaCha20)");

                println!("\n󱤿 󱥇:");
                println!("  rfs [󱤿] <󱤪|->                               (󱥄 󱥻 󱤉 󱤪 󱥩 󱥻 2)");
                println!("  rfs [󱤿] <󱥻1> <󱥻2> [󱥻3...]                 (󱥄 󱥳 󱥝 󱤉 󱤪 󱤬 󱥻 N)");
                println!("  rfs --verify <󱥻...>                           (󱥄 󱤮 󱤉 󱥔 󱥍 󱥻 N)");

                println!("\n󱤿 󱥻 N & Unix:");
                println!("  rfs split -n 3 len.iso                         (󱥄 󱥻 󱥩 󱥻 3 󱥍 󱤕 󱤾)");
                println!("  rfs split -n 3 len.iso --decoy-reveal musi.pdf (󱥄 󱥉 󱤉 󱤪 󱦣 󱤬 󱥻)");
                println!("  rfs split f1.db f2.pdf -n 4 -T 3 -o ./kipisi   (󱥄 󱥻 󱤉 󱤪 󱤼 󱤬 󱤿 GF(2))");
                println!("  rfs restore len.rfs1 len.rfs2 len.rfs3         (󱥄 󱥳 󱥝 󱤉 󱤪 󱤬 󱥻 3 󱤄)");
                println!("  rfs scan /poki/*.rfs -r -o ./sin               (󱥄 󱤃 󱤬 󱥓 󱤧 󱥳 󱥝 󱤉 󱤟 󱤄)");
                println!(
                    "  rfs forge share1.rfs --reveal-as musi.pdf -o fake2.rfs (󱥄 󱥉 󱤉 󱥻 󱦣 󱥩 󱤈)"
                );

                println!("\n󱤎 󱤮 & 󱥡:");
                println!("  -b, --benchmark                                󱥄 󱤮 󱤉 󱥵 󱤎 (SIMD, ChaCha20, BLKS)");
                println!("  -e, --entropy-test                            󱥄 󱤮 󱤉 󱥔 󱥍 󱤕 󱤾");
                println!(
                    "  -a, --analyze <lipu>                          󱥄 󱤮 󱤉 󱤽 NIST SP 800-22 󱤬 󱤪"
                );
                println!("  -h, --help                                    󱥄 󱤮 󱤉 󱤪 󱥡");
                println!("  -V, --version                                 󱥄 󱤮 󱤉 󱤽 󱤎");

                println!("\n󱤿 󱤆:");
                println!("  -n, --parts <MUTE>                            󱤼 󱥻 (2..64; 󱥇: 2)");
                println!("  -T, --threshold <MUTE>                        󱤼 󱥻 󱥷 T 󱥩 󱤪 󱤼 GF(2)");
                println!("  -B, --block-size <SULI>                       󱥣 󱥓 󱥉 (64K, 1M, 4M, 16M; 󱥇: 4M)");
                println!("  -d, --decoys <MUTE>                           󱥄 󱥉 󱤉 󱥻 󱦣 󱥍 󱤕 󱤾");
                println!("  --decoy-reveal <LIPU>                         󱥄 󱥉 󱤉 󱤪 󱦣 󱤬 󱥻");
                println!(
                    "  --pad-to <SULI>                               󱥄 󱥣 󱤉 󱥻 󱤄 󱥩 󱥣 󱥖 (100M, 20G)"
                );
                println!("  --token, --rnd                                󱥂 󱤥: 󱤽 󱤾 (.<rnd>.rfs)");
                println!(
                    "  -r, --restore                                 󱥄 󱥳 󱥝 󱤉 󱤟 󱤄 ('rfs scan')"
                );
                println!("  --reveal-as <LIPU>                            󱤪 󱦣 󱥩 'rfs forge'");
                println!(
                    "  -c, --count <MUTE>                            󱤼 󱥍 󱤪 󱦣 󱤬 'rfs decoy' (󱥇: 1)"
                );
                println!("  -s, --size <SULI>                             󱥣 󱥍 󱤪 󱦣 󱤬 'rfs decoy' (64K, 10M)");
                println!("  -t, --template <LIPU>                         󱤪 󱥖 󱥩 'rfs decoy' (+64B 󱤇 RFS 1:1)");
                println!("  -o, --output <NIMI>                           󱥂 󱤇 󱥓 󱥐 ('-' 󱥩 stdout)");
                println!(
                    "  --direct                                      Direct I/O: 󱥄 󱤙 󱤂 󱤉 󱥓 OS"
                );
                println!("  --mlock                                       󱥄 󱤈 󱤉 󱥡 󱤬 RAM 󱥨");
                println!("  --json                                        󱥄 󱥉 󱤉 JSON 󱤬 stderr");
                println!("  -f, --force                                   󱥄 󱤆 󱤉 󱤪 󱥐 󱤬");
                println!("  -q, --quiet, --silent                         󱥄 󱤕 󱤂 (󱥈 󱥨)");
                println!("  -l, --lang <TOKI>                             󱥬 󱤎 (en [󱥇], de, es, fr, ja, zh, tok, sp)");
                println!("\n󱥡: 󱥄 󱤙 'rfs <󱥉> --help' 󱥩 󱥡 󱤼.\n");
            }
        }
    }

    /// Formats localized restoration success message.
    pub fn format_cli_restored(&self, lang: Lang, path_display: &str) -> String {
        match lang {
            Lang::En => format!("Successfully restored: {}", path_display),
            Lang::De => format!("Erfolgreich wiederhergestellt: {}", path_display),
            Lang::Es => format!("Restaurado con éxito: {}", path_display),
            Lang::Fr => format!("Restauré avec succès : {}", path_display),
            Lang::Ja => format!("正常に復元されました: {}", path_display),
            Lang::Zh => format!("成功还原：{}", path_display),
            Lang::Tok => format!("lipu li wan sin pona: {}", path_display),
            Lang::Sp => format!("󱤪 󱤧 󱥳 󱥝 󱥔: {}", path_display),
        }
    }

    /// Formats localized BLKS-384 integrity check message for CLI stderr.
    pub fn format_cli_integrity_ok(&self, lang: Lang, dig_str: &str) -> String {
        match lang {
            Lang::En => format!("Integrity check [OK] (BLKS-384: {})", dig_str),
            Lang::De => format!("Integritätsprüfung [OK] (BLKS-384: {})", dig_str),
            Lang::Es => format!("Verificación de integridad [OK] (BLKS-384: {})", dig_str),
            Lang::Fr => format!("Vérification d'intégrité [OK] (BLKS-384 : {})", dig_str),
            Lang::Ja => format!("完全性検証 [OK] (BLKS-384: {})", dig_str),
            Lang::Zh => format!("完整性校验 [OK] (BLKS-384: {})", dig_str),
            Lang::Tok => format!("lukin pona [OK] (BLKS-384: {})", dig_str),
            Lang::Sp => format!("󱤮 󱥔 [OK] (BLKS-384: {})", dig_str),
        }
    }

    /// Prints localized CLI forge completion summary.
    pub fn print_cli_forge_summary(
        &self,
        lang: Lang,
        out_display: &str,
        num_existing: usize,
        decoy_display: &str,
    ) {
        match lang {
            Lang::En => {
                println!(
                    "Successfully forged decoy counterpart share: {}",
                    out_display
                );
                println!(
                    "When combined with {} existing share(s), restoration reveals: \"{}\"",
                    num_existing, decoy_display
                );
            }
            Lang::De => {
                println!(
                    "Gegen-Share für Köder erfolgreich synthetisiert: {}",
                    out_display
                );
                println!(
                    "Kombiniert mit {} vorhandenen Share(s) enthüllt die Wiederherstellung: \"{}\"",
                    num_existing, decoy_display
                );
            }
            Lang::Es => {
                println!("Parte señuelo sintetizada con éxito: {}", out_display);
                println!(
                    "Al combinarse con {} parte(s) existente(s), la restauración revela: \"{}\"",
                    num_existing, decoy_display
                );
            }
            Lang::Fr => {
                println!(
                    "Contre-part leurre synthétisée avec succès : {}",
                    out_display
                );
                println!(
                    "Combinée avec {} part(s) existante(s), la restauration révèle : \"{}\"",
                    num_existing, decoy_display
                );
            }
            Lang::Ja => {
                println!("おとり用の偽シェアを正常に合成しました: {}", out_display);
                println!(
                    "既存の {} 個のシェアと結合すると、次のファイルが復元されます: \"{}\"",
                    num_existing, decoy_display
                );
            }
            Lang::Zh => {
                println!("已成功合成诱饵对应分片：{}", out_display);
                println!(
                    "与现有的 {} 个分片组合时，还原将呈现：\"{}\"",
                    num_existing, decoy_display
                );
            }
            Lang::Tok => {
                println!("kipisi powe sin li pali pona: {}", out_display);
                println!(
                    "wan poka kipisi lon {} la lipu ni li kama: \"{}\"",
                    num_existing, decoy_display
                );
            }
            Lang::Sp => {
                println!("󱥻 󱦣 󱥝 󱤧 󱥉 󱥔: {}", out_display);
                println!("󱥳 󱤬 󱥻 󱤬 {} 󱤡 󱤪 󱦣 󱤧 󱤬: \"{}\"", num_existing, decoy_display);
            }
        }
    }

    /// Formats localized share count status for the Restore tab.
    pub fn format_gui_shares_selected(&self, lang: Lang, count: usize) -> String {
        match lang {
            Lang::En => format!("{} shares selected.", count),
            Lang::De => format!("{} Shares ausgewählt.", count),
            Lang::Es => format!("{} partes seleccionadas.", count),
            Lang::Fr => format!("{} parts sélectionnées.", count),
            Lang::Ja => format!("{} 個のシェアを選択しました。", count),
            Lang::Zh => format!("已选择 {} 个分片。", count),
            Lang::Tok => format!("kipisi {} li lon.", count),
            Lang::Sp => format!("󱥻 {} 󱤧 󱤬.", count),
        }
    }

    /// Formats localized status and log for a single-file split in the GUI.
    pub fn format_gui_single_split_report(
        &self,
        lang: Lang,
        real_shares: &[PathBuf],
        decoy_shares: &[PathBuf],
    ) -> (String, String) {
        let n = real_shares.len();
        let d = decoy_shares.len();
        let (status, header, real_hdr, decoy_hdr, note) = match lang {
            Lang::En => (
                "✅ Split completed [OK]".to_string(),
                format!("=== RFS4 SPLIT COMPLETED (N={}, D={}) ===\n\n", n, d),
                "🔐 GENUINE SHARES (ALL REQUIRED FOR RECONSTRUCTION):\n",
                "\n🎭 DECOY CHAFF FILES (100% CHACHA20 RANDOM NOISE):\n",
                "\nNOTE: All files share identical 4 KiB cluster-aligned sizes and anonymous tokens.",
            ),
            Lang::De => (
                "✅ Aufteilung abgeschlossen [OK]".to_string(),
                format!("=== RFS4 AUFTEILUNG ABGESCHLOSSEN (N={}, D={}) ===\n\n", n, d),
                "🔐 ECHTE SHARES (ALLE FÜR REKONSTRUKTION ERFORDERLICH):\n",
                "\n🎭 KÖDERDATEIEN (100% CHACHA20 ZUFALLSRAUSCHEN):\n",
                "\nHINWEIS: Alle Dateien besitzen identische 4-KiB-Clustergrößen und anonyme Hex-Tokens.",
            ),
            Lang::Es => (
                "✅ División completada [OK]".to_string(),
                format!("=== DIVISIÓN RFS4 COMPLETADA (N={}, D={}) ===\n\n", n, d),
                "🔐 PARTES REALES (TODAS NECESARIAS PARA RECONSTRUIR):\n",
                "\n🎭 ARCHIVOS SEÑUELO (100% RUIDO ALEATORIO CHACHA20):\n",
                "\nNOTA: Todos los archivos tienen el mismo tamaño alineado a 4 KiB y tokens anónimos.",
            ),
            Lang::Fr => (
                "✅ Division terminée [OK]".to_string(),
                format!("=== DIVISION RFS4 TERMINÉE (N={}, D={}) ===\n\n", n, d),
                "🔐 PARTS RÉELLES (TOUTES REQUISES POUR LA RECONSTRUCTION) :\n",
                "\n🎭 FICHIERS LEURRES (100% BRUIT ALÉATOIRE CHACHA20) :\n",
                "\nNOTE : Tous les fichiers ont une taille identique alignée sur 4 Kio et des jetons anonymes.",
            ),
            Lang::Ja => (
                "✅ 分割完了 [OK]".to_string(),
                format!("=== RFS4 分割完了 (N={}, D={}) ===\n\n", n, d),
                "🔐 本物のシェア (復元にはすべて必要):\n",
                "\n🎭 おとりノイズファイル (100% ChaCha20 乱数ノイズ):\n",
                "\n注記: すべてのファイルは同一の 4 KiB アライメントサイズと匿名トークンを持ちます。",
            ),
            Lang::Zh => (
                "✅ 分割完成 [OK]".to_string(),
                format!("=== RFS4 分割完成 (N={}, D={}) ===\n\n", n, d),
                "🔐 真实分片（还原时需全部提供）：\n",
                "\n🎭 诱饵噪声文件（100% ChaCha20 随机噪声）：\n",
                "\n注意：所有文件均具有相同的 4 KiB 对齐大小与匿名随机文件名。",
            ),
            Lang::Tok => (
                "✅ kipisi li pini pona [OK]".to_string(),
                format!("=== kipisi RFS4 li pini (N={}, D={}) ===\n\n", n, d),
                "🔐 kipisi lon (ale li wile tawa wan sin):\n",
                "\n🎭 kipisi powe (kalama nasa ChaCha20):\n",
                "\nsona: lipu ale li jo e suli sama (4 KiB) e nimi len.",
            ),
            Lang::Sp => (
                "✅ 󱥻 󱤧 󱥐 󱥔 [OK]".to_string(),
                format!("=== 󱥻 RFS4 󱤧 󱥐 (N={}, D={}) ===\n\n", n, d),
                "🔐 󱥻 󱤬 (󱤄 󱤧 󱥷 󱥩 󱥳 󱥝):\n",
                "\n🎭 󱥻 󱦣 (󱤕 󱤾 ChaCha20):\n",
                "\n󱥡: 󱤪 󱤄 󱤧 󱥖 󱤬 󱥣 (4 KiB) 󱤬 󱥂 󱤥.",
            ),
        };

        let mut log = String::new();
        log.push_str(&header);
        log.push_str(real_hdr);
        for (i, p) in real_shares.iter().enumerate() {
            log.push_str(&format!("  [Share {}] {}\n", i + 1, p.display()));
        }
        if !decoy_shares.is_empty() {
            log.push_str(decoy_hdr);
            for (i, p) in decoy_shares.iter().enumerate() {
                log.push_str(&format!("  [Decoy {}] {}\n", i + 1, p.display()));
            }
        }
        log.push_str(note);
        (status, log)
    }

    /// Formats localized status and log for a multi-payload split in the GUI.
    #[allow(clippy::too_many_arguments)]
    pub fn format_gui_multi_split_report(
        &self,
        lang: Lang,
        parts: usize,
        threshold: usize,
        share_size_fmt: &str,
        share_paths: &[PathBuf],
        payload_subsets: &[(String, Vec<PathBuf>)],
        decoy_paths: &[PathBuf],
    ) -> (String, String) {
        let k = payload_subsets.len();
        let (status, header, size_line, shares_hdr, alloc_hdr, req_prefix, decoy_hdr, note) = match lang {
            Lang::En => (
                format!("✅ {} payloads split ({}-of-{})", k, threshold, parts),
                format!("=== RFS MULTI-PAYLOAD SPLIT: {} FILES -> {} SHARES ({}-OF-{}) ===\n\n", k, parts, threshold, parts),
                format!("Uniform share size: {}\n\n", share_size_fmt),
                "🔐 GENERATED ANONYMOUS SHARES:\n",
                "\n🎯 COMBINATORIAL ACCESS ALLOCATION:\n",
                "Required subset",
                "\n🎭 GENERATED DECOY CHAFF FILES:\n",
                "NOTE: All subsets can be auto-discovered via 'rfs scan' or the Restore Scanner.",
            ),
            Lang::De => (
                format!("✅ {} Dateien aufgeteilt ({}-aus-{})", k, threshold, parts),
                format!("=== RFS MULTI-PAYLOAD-SPLIT: {} DATEIEN -> {} SHARES ({}-AUS-{}) ===\n\n", k, parts, threshold, parts),
                format!("Einheitliche Share-Größe: {}\n\n", share_size_fmt),
                "🔐 ERZEUGTE ANONYME SHARES:\n",
                "\n🎯 KOMBINATORISCHE ZUGRIFFS-ZUORDNUNG:\n",
                "Benötigte Kombination",
                "\n🎭 ERZEUGTE KÖDERDATEIEN (DECOYS):\n",
                "HINWEIS: Alle Sets können per 'rfs scan' oder Ordner-Scan automatisch erkannt werden.",
            ),
            Lang::Es => (
                format!("✅ {} archivos divididos ({}-de-{})", k, threshold, parts),
                format!("=== DIVISIÓN MÚLTIPLE RFS: {} ARCHIVOS -> {} PARTES ({}-DE-{}) ===\n\n", k, parts, threshold, parts),
                format!("Tamaño uniforme de parte: {}\n\n", share_size_fmt),
                "🔐 PARTES ANÓNIMAS GENERADAS:\n",
                "\n🎯 ASIGNACIÓN DE ACCESO COMBINATORIO:\n",
                "Subconjunto requerido",
                "\n🎭 ARCHIVOS SEÑUELO GENERADOS:\n",
                "NOTA: Todos los conjuntos pueden descubrirse automáticamente con 'rfs scan'.",
            ),
            Lang::Fr => (
                format!("✅ {} fichiers divisés ({}-sur-{})", k, threshold, parts),
                format!("=== MULTI-PARTAGE RFS : {} FICHIERS -> {} PARTS ({}-SUR-{}) ===\n\n", k, parts, threshold, parts),
                format!("Taille uniforme des parts : {}\n\n", share_size_fmt),
                "🔐 PARTS ANONYMES GÉNÉRÉES :\n",
                "\n🎯 ATTRIBUTION D'ACCÈS COMBINATOIRE :\n",
                "Sous-ensemble requis",
                "\n🎭 FICHIERS LEURRES GÉNÉRÉS :\n",
                "NOTE : Tous les sous-ensembles peuvent être découverts via 'rfs scan'.",
            ),
            Lang::Ja => (
                format!("✅ {} 個のファイルを分割完了 ({}/{})", k, threshold, parts),
                format!("=== RFS マルチペイロード分割: {} ファイル -> {} シェア ({}/{}) ===\n\n", k, parts, threshold, parts),
                format!("統一シェアサイズ: {}\n\n", share_size_fmt),
                "🔐 生成された匿名シェア:\n",
                "\n🎯 組み合わせアクセス割り当て:\n",
                "必要なシェア組み合わせ",
                "\n🎭 生成されたおとりファイル:\n",
                "注記: すべてのセットは 'rfs scan' またはフォルダスキャンで自動検出できます。",
            ),
            Lang::Zh => (
                format!("✅ 已分割 {} 个文件 ({}/{})", k, threshold, parts),
                format!("=== RFS 多载荷分割：{} 个文件 -> {} 个分片 ({}/{}) ===\n\n", k, parts, threshold, parts),
                format!("统一分片大小：{}\n\n", share_size_fmt),
                "🔐 已生成的匿名分片：\n",
                "\n🎯 组合访问分配表：\n",
                "所需分片组合",
                "\n🎭 已生成的诱饵噪声文件：\n",
                "注意：所有分片子集均可通过 'rfs scan' 或文件夹扫描自动识别。",
            ),
            Lang::Tok => (
                format!("✅ lipu {} li kipisi pona ({} lon {})", k, threshold, parts),
                format!("=== kipisi mute RFS: lipu {} -> kipisi {} ({} lon {}) ===\n\n", k, parts, threshold, parts),
                format!("suli sama pi kipisi ale: {}\n\n", share_size_fmt),
                "🔐 kipisi pi nimi len:\n",
                "\n🎯 kulupu kipisi tawa lipu:\n",
                "kipisi wile",
                "\n🎭 kipisi powe (kalama nasa):\n",
                "sona: ilo 'rfs scan' li ken alasa e kulupu ale.",
            ),
            Lang::Sp => (
                format!("✅ 󱤪 {} 󱤧 󱥻 󱥔 ({} 󱤬 {})", k, threshold, parts),
                format!("=== 󱥻 󱤼 RFS: 󱤪 {} -> 󱥻 {} ({} 󱤬 {}) ===\n\n", k, parts, threshold, parts),
                format!("󱥣 󱥖 󱥍 󱥻 󱤄: {}\n\n", share_size_fmt),
                "🔐 󱥻 󱥍 󱥂 󱤥:\n",
                "\n🎯 󱤟 󱥻 󱥩 󱤪:\n",
                "󱥻 󱥷",
                "\n🎭 󱥻 󱦣 (󱤕 󱤾):\n",
                "󱥡: 󱤎 'rfs scan' 󱤧 󱤘 󱤃 󱤉 󱤟 󱤄.",
            ),
        };

        let mut log = String::new();
        log.push_str(&header);
        log.push_str(&size_line);
        log.push_str(shares_hdr);
        for (i, p) in share_paths.iter().enumerate() {
            log.push_str(&format!("  [Share {}] {}\n", i + 1, p.display()));
        }
        log.push_str(alloc_hdr);
        for (name, shares) in payload_subsets {
            let names = shares
                .iter()
                .map(|p| p.file_name().and_then(|n| n.to_str()).unwrap_or(""))
                .collect::<Vec<_>>()
                .join(", ");
            log.push_str(&format!("  🎯 \"{}\"\n", name));
            log.push_str(&format!(
                "     {} ({}): [{}]\n\n",
                req_prefix,
                shares.len(),
                names
            ));
        }
        if !decoy_paths.is_empty() {
            log.push_str(decoy_hdr);
            for (i, p) in decoy_paths.iter().enumerate() {
                log.push_str(&format!("  [Decoy {}] {}\n", i + 1, p.display()));
            }
            log.push('\n');
        }
        log.push_str(note);
        (status, log)
    }

    /// Formats localized status, preselection info, and report for folder scanning in the GUI.
    pub fn format_gui_scan_report(
        &self,
        lang: Lang,
        total_inspected: usize,
        found_sets: &[(String, String, Vec<PathBuf>)],
    ) -> (String, String, String) {
        let count = found_sets.len();
        let (first_name, _, first_shares) = &found_sets[0];
        let f_len = first_shares.len();

        let (status, preselected, header, shares_lbl) = match lang {
            Lang::En => (
                format!("🎯 {} valid set(s) discovered!", count),
                format!("Set #1 preselected: \"{}\" ({} shares)", first_name, f_len),
                format!(
                    "=== SCAN RESULT: {} FILES INSPECTED, {} VALID SETS FOUND ===\n\n",
                    total_inspected, count
                ),
                "Shares",
            ),
            Lang::De => (
                format!("🎯 {} gültige(s) Set(s) gefunden!", count),
                format!(
                    "Set #1 vorausgewählt: \"{}\" ({} Shares)",
                    first_name, f_len
                ),
                format!(
                    "=== SCAN-ERGEBNIS: {} DATEIEN GEPRÜFT, {} GÜLTIGE SETS GEFUNDEN ===\n\n",
                    total_inspected, count
                ),
                "Shares",
            ),
            Lang::Es => (
                format!("🎯 ¡{} conjunto(s) válido(s) descubierto(s)!", count),
                format!(
                    "Conjunto #1 preseleccionado: \"{}\" ({} partes)",
                    first_name, f_len
                ),
                format!(
                    "=== RESULTADO DEL ESCANEO: {} ARCHIVOS, {} CONJUNTOS VÁLIDOS ===\n\n",
                    total_inspected, count
                ),
                "Partes",
            ),
            Lang::Fr => (
                format!("🎯 {} ensemble(s) valide(s) découvert(s) !", count),
                format!(
                    "Ensemble #1 présélectionné : \"{}\" ({} parts)",
                    first_name, f_len
                ),
                format!(
                    "=== RÉSULTAT DU SCAN : {} FICHIERS ANALYSÉS, {} ENSEMBLES VALIDES ===\n\n",
                    total_inspected, count
                ),
                "Parts",
            ),
            Lang::Ja => (
                format!("🎯 {} 個の有効なセットを検出しました！", count),
                format!(
                    "セット #1 を選択済み: \"{}\" ({} シェア)",
                    first_name, f_len
                ),
                format!(
                    "=== スキャン結果: {} ファイル検査、{} 個の有効セットを検出 ===\n\n",
                    total_inspected, count
                ),
                "シェア",
            ),
            Lang::Zh => (
                format!("🎯 发现 {} 个有效分片组合！", count),
                format!("已预选组合 #1：\"{}\"（{} 个分片）", first_name, f_len),
                format!(
                    "=== 扫描结果：已检查 {} 个文件，发现 {} 个有效组合 ===\n\n",
                    total_inspected, count
                ),
                "分片",
            ),
            Lang::Tok => (
                format!("🎯 kulupu pona {} li lon!", count),
                format!("kulupu #1 li lon: \"{}\" (kipisi {})", first_name, f_len),
                format!(
                    "=== lipu {} li lukin, kulupu pona {} li lon ===\n\n",
                    total_inspected, count
                ),
                "kipisi",
            ),
            Lang::Sp => (
                format!("🎯 󱤟 󱥔 {} 󱤧 󱤬!", count),
                format!("󱤟 #1 󱤧 󱤬: \"{}\" (󱥻 {})", first_name, f_len),
                format!("=== 󱤪 {} 󱤧 󱤮, 󱤟 󱥔 {} 󱤧 󱤬 ===\n\n", total_inspected, count),
                "󱥻",
            ),
        };

        let mut report = String::new();
        report.push_str(&header);
        for (i, (name, size_str, shares)) in found_sets.iter().enumerate() {
            report.push_str(&format!("🎯 #{}: \"{}\" ({})\n", i + 1, name, size_str));
            report.push_str(&format!("   {} ({}):\n", shares_lbl, shares.len()));
            for s in shares {
                report.push_str(&format!("     - {}\n", s.display()));
            }
            report.push('\n');
        }
        (status, preselected, report)
    }

    /// Formats localized status and report for auto-restore in the GUI.
    pub fn format_gui_auto_restore_report(
        &self,
        lang: Lang,
        restored_list: &[(String, PathBuf, usize)],
    ) -> (String, String) {
        let count = restored_list.len();
        let (status, header, out_lbl, status_ok, shares_lbl) = match lang {
            Lang::En => (
                format!("✅ {} set(s) auto-restored!", count),
                format!("=== AUTO-RESTORE: {} SETS RECONSTRUCTED ===\n\n", count),
                "Output file",
                "✅ Bit-exact BLKS-384 integrity verified",
                "Shares used",
            ),
            Lang::De => (
                format!("✅ {} Set(s) automatisch wiederhergestellt!", count),
                format!("=== AUTO-RESTORE: {} SETS REKONSTRUIERT ===\n\n", count),
                "Ausgabedatei",
                "✅ Bitgenaue BLKS-384 Integrität bestätigt",
                "Verwendete Shares",
            ),
            Lang::Es => (
                format!("✅ ¡{} conjunto(s) auto-restaurado(s)!", count),
                format!(
                    "=== AUTO-RESTAURACIÓN: {} CONJUNTOS RECONSTRUIDOS ===\n\n",
                    count
                ),
                "Archivo de salida",
                "✅ Integridad BLKS-384 exacta verificada",
                "Partes usadas",
            ),
            Lang::Fr => (
                format!("✅ {} ensemble(s) auto-restauré(s) !", count),
                format!(
                    "=== AUTO-RESTAURATION : {} ENSEMBLES RECONSTRUITS ===\n\n",
                    count
                ),
                "Fichier de sortie",
                "✅ Intégrité BLKS-384 bit-à-bit vérifiée",
                "Parts utilisées",
            ),
            Lang::Ja => (
                format!("✅ {} セットを自動復元しました！", count),
                format!("=== 自動一括復元: {} セットを復元完了 ===\n\n", count),
                "出力ファイル",
                "✅ BLKS-384 完全性検証済み (ビット完全一致)",
                "使用シェア数",
            ),
            Lang::Zh => (
                format!("✅ 已自动还原 {} 个组合！", count),
                format!("=== 自动还原：已重构 {} 个分片组合 ===\n\n", count),
                "输出文件",
                "✅ BLKS-384 完整性校验通过（比特级精确匹配）",
                "使用分片数",
            ),
            Lang::Tok => (
                format!("✅ kulupu {} li wan sin pona!", count),
                format!("=== wan sin ale: kulupu {} li pini pona ===\n\n", count),
                "lipu pini",
                "✅ pona BLKS-384 li lon",
                "mute kipisi",
            ),
            Lang::Sp => (
                format!("✅ 󱤟 {} 󱤧 󱥳 󱥝 󱥔!", count),
                format!("=== 󱥳 󱥝 󱤄: 󱤟 {} 󱤧 󱥐 󱥔 ===\n\n", count),
                "󱤪 󱥐",
                "✅ 󱥔 BLKS-384 󱤧 󱤬",
                "󱤼 󱥻",
            ),
        };

        let mut report = String::new();
        report.push_str(&header);
        for (i, (orig_name, out_path, num_shares)) in restored_list.iter().enumerate() {
            report.push_str(&format!("🎯 #{}: \"{}\"\n", i + 1, orig_name));
            report.push_str(&format!("   {}: {}\n", out_lbl, out_path.display()));
            report.push_str(&format!("   {}\n", status_ok));
            report.push_str(&format!("   {}: {}\n\n", shares_lbl, num_shares));
        }
        (status, report)
    }

    /// Formats localized status and report for single restoration in the GUI.
    pub fn format_gui_restore_report(&self, lang: Lang, path_display: &str) -> (String, String) {
        match lang {
            Lang::En => (
                format!("✅ Restored: {}", path_display),
                format!(
                    "=== RESTORATION COMPLETED ===\n\n📁 Reconstructed file: {}\n🛡️ BLKS-384 Integrity Check: PASSED [OK]\nStatus: Bit-exact match with original plaintext.",
                    path_display
                ),
            ),
            Lang::De => (
                format!("✅ Wiederhergestellt: {}", path_display),
                format!(
                    "=== WIEDERHERSTELLUNG ABGESCHLOSSEN ===\n\n📁 Rekonstruierte Datei: {}\n🛡️ BLKS-384 Integritätsprüfung: BESTANDEN [OK]\nStatus: Bitgenaue Übereinstimmung mit dem Original.",
                    path_display
                ),
            ),
            Lang::Es => (
                format!("✅ Restaurado: {}", path_display),
                format!(
                    "=== RESTAURACIÓN COMPLETADA ===\n\n📁 Archivo reconstruido: {}\n🛡️ Verificación BLKS-384: APROBADA [OK]\nEstado: Coincidencia exacta bit a bit con el original.",
                    path_display
                ),
            ),
            Lang::Fr => (
                format!("✅ Restauré : {}", path_display),
                format!(
                    "=== RESTAURATION TERMINÉE ===\n\n📁 Fichier reconstruit : {}\n🛡️ Vérification BLKS-384 : RÉUSSIE [OK]\nStatut : Correspondance exacte bit-à-bit avec l'original.",
                    path_display
                ),
            ),
            Lang::Ja => (
                format!("✅ 復元完了: {}", path_display),
                format!(
                    "=== 復元完了 ===\n\n📁 復元されたファイル: {}\n🛡️ BLKS-384 完全性検証: 合格 [OK]\nステータス: 元ファイルとビット単位で完全一致しています。",
                    path_display
                ),
            ),
            Lang::Zh => (
                format!("✅ 已还原：{}", path_display),
                format!(
                    "=== 还原完成 ===\n\n📁 重构文件：{}\n🛡️ BLKS-384 完整性校验：通过 [OK]\n状态：与原始明文比特级精确一致。",
                    path_display
                ),
            ),
            Lang::Tok => (
                format!("✅ lipu sin: {}", path_display),
                format!(
                    "=== wan sin li pini pona ===\n\n📁 lipu sin: {}\n🛡️ lukin pona BLKS-384: pona [OK]\nni li sama ale tawa lipu open.",
                    path_display
                ),
            ),
            Lang::Sp => (
                format!("✅ 󱤪 󱥝: {}", path_display),
                format!(
                    "=== 󱥳 󱥝 󱤧 󱥐 󱥔 ===\n\n📁 󱤪 󱥝: {}\n🛡️ 󱤮 󱥔 BLKS-384: 󱥔 [OK]\nlipu 󱤧 󱥖 󱤄 󱥩 󱤪 󱥇.",
                    path_display
                ),
            ),
        }
    }

    /// Formats localized report for Deniable Forge synthesis in the GUI.
    pub fn format_gui_forge_report(
        &self,
        lang: Lang,
        out_display: &str,
        decoy_display: &str,
        num_existing: usize,
    ) -> String {
        match lang {
            Lang::En => format!(
                "=== DENIABLE DECOY FORGE COMPLETED ===\n\n🎭 Synthesized Counterpart Share: {}\n📄 Embedded Decoy Plaintext:     {}\n🔗 Linked Existing Shares:       {} file(s)\n\n🛡️ Cryptographic Guarantee: Combining this fake share with the existing shares\n   validates 100% BLKS-384 integrity and reconstructs the decoy plaintext bit-exact.\n   Proving the existence of any other original file is mathematically impossible.",
                out_display, decoy_display, num_existing
            ),
            Lang::De => format!(
                "=== GLAUBHAFTE ABSTREITBARKEIT (FORGE) ABGESCHLOSSEN ===\n\n🎭 Synthetisierte Gegen-Share: {}\n📄 Eingebetteter Köder-Klartext: {}\n🔗 Verknüpfte bestehende Shares: {} Datei(en)\n\n🛡️ Kryptografische Garantie: In Kombination mit den bestehenden Shares besteht diese\n   Gegen-Share die BLKS-384-Prüfung zu 100% und rekonstruiert bitgenau den Köder.\n   Der Nachweis einer anderen Originaldatei ist mathematisch unmöglich.",
                out_display, decoy_display, num_existing
            ),
            Lang::Es => format!(
                "=== FORJA DE SEÑUELO NEGABLE COMPLETADA ===\n\n🎭 Parte falsa sintetizada:      {}\n📄 Archivo señuelo incrustado:   {}\n🔗 Partes existentes vinculadas: {} archivo(s)\n\n🛡️ Garantía criptográfica: Al combinar esta parte con las existentes se valida\n   el 100% de la integridad BLKS-384 y se reconstruye el señuelo bit a bit.\n   Demostrar la existencia de otro archivo original es matemáticamente imposible.",
                out_display, decoy_display, num_existing
            ),
            Lang::Fr => format!(
                "=== FORGE DE LEURRE DÉNIABLE TERMINÉE ===\n\n🎭 Contre-part synthétisée :     {}\n📄 Fichier leurre intégré :      {}\n🔗 Parts existantes liées :      {} fichier(s)\n\n🛡️ Garantie cryptographique : Combiner cette part avec les parts existantes\n   valide 100% de l'intégrité BLKS-384 et reconstruit le leurre bit-à-bit.\n   Prouver l'existence d'un autre fichier original est mathématiquement impossible.",
                out_display, decoy_display, num_existing
            ),
            Lang::Ja => format!(
                "=== おとり偽シェア合成完了 (Plausible Deniability) ===\n\n🎭 合成された偽シェア:     {}\n📄 埋め込まれたおとり平文: {}\n🔗 結合対象の既存シェア:   {} ファイル\n\n🛡️ 暗号論的保証: この偽シェアを既存のシェアと結合すると、BLKS-384 完全性検証に\n   100% 合格し、おとりファイルがビット単位で正確に復元されます。\n   他の元ファイルの存在を証明することは数学的に不可能です。",
                out_display, decoy_display, num_existing
            ),
            Lang::Zh => format!(
                "=== 可否认诱饵伪造合成完成 ===\n\n🎭 已合成伪造分片：{}\n📄 嵌入诱饵明文：  {}\n🔗 关联现有分片：  {} 个文件\n\n🛡️ 密码学保证：将该伪造分片与现有分片组合可通过 100% BLKS-384 完整性校验，\n   并比特级精确还原出诱饵文件。在数学上无法证明任何其他原始文件的存在。",
                out_display, decoy_display, num_existing
            ),
            Lang::Tok => format!(
                "=== pali pi kipisi powe li pini pona ===\n\n🎭 kipisi powe sin: {}\n📄 lipu powe insa:  {}\n🔗 kipisi lon poka: {}\n\n🛡️ sona nanpa: kipisi powe ni en kipisi lon li kama wan la,\n   lukin BLKS-384 li pona ale li pana e lipu powe taso.\n   jan ala li ken sona e lipu len ante.",
                out_display, decoy_display, num_existing
            ),
            Lang::Sp => format!(
                "=== 󱥉 󱥍 󱥻 󱦣 󱤧 󱥐 󱥔 ===\n\n🎭 󱥻 󱦣 󱥝: {}\n📄 󱤪 󱦣:    {}\n🔗 󱥻 󱤬:    {}\n\n🛡️ 󱥡 󱤽: 󱥻 󱦣 󱤬 󱥻 󱤬 󱤡 󱤮 BLKS-384 󱤧 󱥔 󱤄 󱤧 󱥳 󱥝 󱤉 󱤪 󱦣 󱥨.\n   󱤑 󱤂 󱤧 󱤘 󱥡 󱤉 󱤪 󱤥 󱤆.",
                out_display, decoy_display, num_existing
            ),
        }
    }
}

pub const TR_EN: Translations = Translations {
    subtitle: "Random File Splitter (Information-Theoretic Security & Anti-Forensics)",
    tab_split: " 📦 Split ",
    tab_restore: " 🔓 Restore ",
    tab_forge: " 🎭 Deniable Forge ",

    split_step1_label: "1. Source File(s) for One-Time-Pad (Symmetric Multi-Splitting supported):",
    split_file_placeholder: "Select one or multiple files...",
    split_select_files_btn: "Select Files...",
    split_file_info_default: "Select one or multiple files to split.",
    split_step2_label: "2. Output Directory (e.g., USB drive or target folder):",
    split_target_placeholder: "Default: Same directory as source file",
    split_select_dir_btn: "Choose Folder...",
    split_total_shares_prefix: "Total Shares (M = ",
    split_threshold_prefix: "Threshold (T = ",
    split_threshold_of: " of ",
    split_enable_decoys_label: "Generate Decoy Chaff Files",
    split_decoy_count_prefix: "Decoy Count (D = ",
    split_status_ready: "Ready to split",
    split_status_running: "Splitting via ChaCha20 & SIMD-XOR...",
    split_status_select_at_least_one: "Please select at least one file!",
    split_action_btn: "🚀 Split File Securely",
    split_action_running_btn: "Splitting...",
    split_log_label: "📋 Share Allocation & Output Log (Required for Reconstruction):",

    restore_step1_label: "1. Input RFS Shares (at least 2 parts):",
    restore_shares_placeholder: "Select share files or scan a directory...",
    restore_select_shares_btn: "Select Shares...",
    restore_scan_folder_btn: "🔍 Scan Folder...",
    restore_auto_restore_btn: "⚡ Auto-Restore...",
    restore_detected_default: "Select at least 2 .rfs share files.",
    restore_step2_label: "2. Output Target Directory (optional):",
    restore_target_placeholder: "Default: Original filename from RFS4 footer",
    restore_target_btn: "Target Folder...",
    restore_integrity_label: "Integrity Check:",
    restore_badge_pending: "Pending",
    restore_badge_valid: "Valid [OK]",
    restore_badge_mismatch: "Error [Mismatch]",
    restore_status_ready: "Ready to restore",
    restore_status_need_2: "At least 2 shares required!",
    restore_status_running: "Reconstructing & verifying BLKS-384 integrity...",
    restore_status_scanning: "Scanning folder for valid N-Way combinations...",
    restore_status_no_sets: "No matching RFS sets found.",
    restore_detected_all_noise: "All inspected files behave as uncorrelated noise.",
    restore_action_btn: "🔓 Reconstruct Original File",
    restore_action_running_btn: "Restoring...",
    restore_log_label: "📋 Restoration Report:",

    forge_step1_label: "1. Existing / Seized Shares:",
    forge_shares_placeholder: "Select existing .rfs share files...",
    forge_select_shares_btn: "Select Shares...",
    forge_step2_label: "2. Decoy Plaintext to Reveal (e.g., vacation photo, benign PDF):",
    forge_decoy_placeholder: "Select decoy plaintext file...",
    forge_select_decoy_btn: "Select Decoy...",
    forge_step3_label: "3. Output Path for Synthesized Counterpart Share (C_fake):",
    forge_output_placeholder: "Output path for fake share (e.g., counterpart_fake.rfs)...",
    forge_select_output_btn: "Save As...",
    forge_status_ready: "Ready for decoy synthesis",
    forge_status_need_1: "At least 1 existing share required!",
    forge_status_running: "Synthesizing counterpart share...",
    forge_status_done: "Counterpart share synthesized [OK]",
    forge_action_btn: "🎭 Synthesize Counterpart Share",
    forge_action_running_btn: "Synthesizing...",
    forge_log_label: "📋 Synthesis Log & Cryptographic Guarantee:",
};

pub const TR_DE: Translations = Translations {
    subtitle: "Random File Splitter (Informationstheoretische Sicherheit & Anti-Forensik)",
    tab_split: " 📦 Aufteilen (Split) ",
    tab_restore: " 🔓 Wiederherstellen ",
    tab_forge: " 🎭 Täuschung (Forge) ",

    split_step1_label:
        "1. Quelldatei(en) für One-Time-Pad (Symmetrisches Multi-Splitting möglich):",
    split_file_placeholder: "Eine oder mehrere Dateien auswählen...",
    split_select_files_btn: "Dateien wählen...",
    split_file_info_default: "Wählen Sie eine oder mehrere Dateien aus.",
    split_step2_label: "2. Ausgabe-Zielordner (z. B. USB-Stick oder Verzeichnis):",
    split_target_placeholder: "Standard: Gleiches Verzeichnis wie Quelldatei",
    split_select_dir_btn: "Ordner wählen...",
    split_total_shares_prefix: "Gesamt-Shares (M = ",
    split_threshold_prefix: "Kombination (T = ",
    split_threshold_of: " aus ",
    split_enable_decoys_label: "Köderdateien (Decoys) erzeugen",
    split_decoy_count_prefix: "Anzahl Köder (D = ",
    split_status_ready: "Bereit zum Aufteilen",
    split_status_running: "Teile Datei via ChaCha20 & SIMD-XOR...",
    split_status_select_at_least_one: "Bitte mindestens eine Datei auswählen!",
    split_action_btn: "🚀 Datei sicher aufteilen",
    split_action_running_btn: "Teilung läuft...",
    split_log_label: "📋 Share-Zuordnung & Ergebnis-Protokoll (Wichtig für Rekonstruktion):",

    restore_step1_label: "1. Eingabe der RFS-Shares (mindestens 2 Teile):",
    restore_shares_placeholder: "Dateien auswählen oder Ordner scannen...",
    restore_select_shares_btn: "Shares wählen...",
    restore_scan_folder_btn: "🔍 Ordner scannen...",
    restore_auto_restore_btn: "⚡ Auto-Restore...",
    restore_detected_default: "Wählen Sie mindestens 2 .rfs-Dateien aus.",
    restore_step2_label: "2. Ausgabe-Zielverzeichnis (optional):",
    restore_target_placeholder: "Standard: Originalpfad aus RFS4-Footer",
    restore_target_btn: "Zielordner...",
    restore_integrity_label: "Integritäts-Prüfung:",
    restore_badge_pending: "Ausstehend",
    restore_badge_valid: "Gültig [OK]",
    restore_badge_mismatch: "Fehler [Mismatch]",
    restore_status_ready: "Bereit zur Wiederherstellung",
    restore_status_need_2: "Mindestens 2 Shares erforderlich!",
    restore_status_running: "Rekonstruiere und prüfe BLKS-384 Integrität...",
    restore_status_scanning: "Scanne Ordner nach N-Way Kombinationen...",
    restore_status_no_sets: "Keine passenden Sets gefunden.",
    restore_detected_all_noise: "Alle geprüften Dateien sind unkorreliertes Rauschen.",
    restore_action_btn: "🔓 Originaldatei rekonstruieren",
    restore_action_running_btn: "Wiederherstellung läuft...",
    restore_log_label: "📋 Wiederherstellungs-Bericht:",

    forge_step1_label: "1. Vorhandene / beschlagnahmte Shares:",
    forge_shares_placeholder: "Bestehende .rfs-Dateien auswählen...",
    forge_select_shares_btn: "Shares wählen...",
    forge_step2_label: "2. Vorzulegender Köder-Klartext (z. B. Urlaubsbilder, Dummy-PDF):",
    forge_decoy_placeholder: "Köderdatei auswählen...",
    forge_select_decoy_btn: "Köder wählen...",
    forge_step3_label: "3. Zielpfad für synthetisierte Gegen-Share (C_fake):",
    forge_output_placeholder: "Pfad für die Fake-Share (z. B. counterpart_fake.rfs)...",
    forge_select_output_btn: "Speicherort wählen...",
    forge_status_ready: "Bereit zur Köder-Synthese",
    forge_status_need_1: "Mindestens 1 bestehende Share erforderlich!",
    forge_status_running: "Synthetisiere Gegen-Share...",
    forge_status_done: "Gegen-Share erfolgreich synthetisiert [OK]",
    forge_action_btn: "🎭 Gegen-Share synthetisieren",
    forge_action_running_btn: "Synthese läuft...",
    forge_log_label: "📋 Synthese-Protokoll & Krypto-Integrität:",
};

pub const TR_ES: Translations = Translations {
    subtitle:
        "Divisor de Archivos Criptográfico (Seguridad Teórica de la Información y Antiforense)",
    tab_split: " 📦 Dividir (Split) ",
    tab_restore: " 🔓 Restaurar ",
    tab_forge: " 🎭 Forja Negable ",

    split_step1_label: "1. Archivo(s) fuente para One-Time-Pad (soporta división múltiple):",
    split_file_placeholder: "Seleccione uno o varios archivos...",
    split_select_files_btn: "Elegir archivos...",
    split_file_info_default: "Seleccione uno o más archivos para dividir.",
    split_step2_label: "2. Carpeta de destino (ej. unidad USB o directorio):",
    split_target_placeholder: "Por defecto: Mismo directorio que el archivo fuente",
    split_select_dir_btn: "Elegir carpeta...",
    split_total_shares_prefix: "Partes totales (M = ",
    split_threshold_prefix: "Umbral (T = ",
    split_threshold_of: " de ",
    split_enable_decoys_label: "Generar archivos señuelo (Decoys)",
    split_decoy_count_prefix: "Cantidad de señuelos (D = ",
    split_status_ready: "Listo para dividir",
    split_status_running: "Dividiendo mediante ChaCha20 y SIMD-XOR...",
    split_status_select_at_least_one: "¡Seleccione al menos un archivo!",
    split_action_btn: "🚀 Dividir archivo de forma segura",
    split_action_running_btn: "Dividiendo...",
    split_log_label: "📋 Asignación de partes y registro (Importante para reconstruir):",

    restore_step1_label: "1. Partes RFS de entrada (mínimo 2 archivos):",
    restore_shares_placeholder: "Seleccione archivos .rfs o escanee una carpeta...",
    restore_select_shares_btn: "Elegir partes...",
    restore_scan_folder_btn: "🔍 Escanear carpeta...",
    restore_auto_restore_btn: "⚡ Auto-Restaurar...",
    restore_detected_default: "Seleccione al menos 2 archivos .rfs.",
    restore_step2_label: "2. Directorio de salida (opcional):",
    restore_target_placeholder: "Por defecto: Nombre original del pie RFS4",
    restore_target_btn: "Carpeta destino...",
    restore_integrity_label: "Verificación de integridad:",
    restore_badge_pending: "Pendiente",
    restore_badge_valid: "Válido [OK]",
    restore_badge_mismatch: "Error [Discrepancia]",
    restore_status_ready: "Listo para restaurar",
    restore_status_need_2: "¡Se requieren al menos 2 partes!",
    restore_status_running: "Reconstruyendo y verificando integridad BLKS-384...",
    restore_status_scanning: "Escaneando carpeta en busca de combinaciones válidas...",
    restore_status_no_sets: "No se encontraron conjuntos válidos.",
    restore_detected_all_noise: "Todos los archivos analizados parecen ruido aleatorio.",
    restore_action_btn: "🔓 Reconstruir archivo original",
    restore_action_running_btn: "Restaurando...",
    restore_log_label: "📋 Informe de restauración:",

    forge_step1_label: "1. Partes existentes / incautadas:",
    forge_shares_placeholder: "Seleccione archivos .rfs existentes...",
    forge_select_shares_btn: "Elegir partes...",
    forge_step2_label: "2. Archivo señuelo inofensivo a revelar (ej. foto, PDF):",
    forge_decoy_placeholder: "Seleccione archivo señuelo...",
    forge_select_decoy_btn: "Elegir señuelo...",
    forge_step3_label: "3. Ruta de salida para la parte falsa sintetizada (C_fake):",
    forge_output_placeholder: "Ruta de salida (ej. counterpart_fake.rfs)...",
    forge_select_output_btn: "Guardar como...",
    forge_status_ready: "Listo para sintetizar señuelo",
    forge_status_need_1: "¡Se requiere al menos 1 parte existente!",
    forge_status_running: "Sintetizando parte falsa...",
    forge_status_done: "Parte señuelo sintetizada [OK]",
    forge_action_btn: "🎭 Sintetizar parte señuelo",
    forge_action_running_btn: "Sintetizando...",
    forge_log_label: "📋 Registro de síntesis y garantía criptográfica:",
};

pub const TR_FR: Translations = Translations {
    subtitle: "Diviseur de Fichiers Cryptographique (Sécurité Inconditionnelle & Anti-Forensique)",
    tab_split: " 📦 Diviser (Split) ",
    tab_restore: " 🔓 Restaurer ",
    tab_forge: " 🎭 Forge Déniable ",

    split_step1_label: "1. Fichier(s) source pour masque jetable (Multi-partage supporté) :",
    split_file_placeholder: "Sélectionnez un ou plusieurs fichiers...",
    split_select_files_btn: "Choisir fichiers...",
    split_file_info_default: "Sélectionnez un ou plusieurs fichiers à diviser.",
    split_step2_label: "2. Dossier de destination (ex. clé USB ou répertoire) :",
    split_target_placeholder: "Par défaut : Même dossier que le fichier source",
    split_select_dir_btn: "Choisir dossier...",
    split_total_shares_prefix: "Total des parts (M = ",
    split_threshold_prefix: "Seuil (T = ",
    split_threshold_of: " sur ",
    split_enable_decoys_label: "Générer des fichiers leurres (Decoys)",
    split_decoy_count_prefix: "Nombre de leurres (D = ",
    split_status_ready: "Prêt à diviser",
    split_status_running: "Division via ChaCha20 et SIMD-XOR...",
    split_status_select_at_least_one: "Veuillez sélectionner au moins un fichier !",
    split_action_btn: "🚀 Diviser le fichier en sécurité",
    split_action_running_btn: "Division en cours...",
    split_log_label: "📋 Attribution des parts et journal (Important pour la reconstruction) :",

    restore_step1_label: "1. Parts RFS en entrée (au moins 2 fichiers) :",
    restore_shares_placeholder: "Sélectionnez des fichiers .rfs ou scannez un dossier...",
    restore_select_shares_btn: "Choisir parts...",
    restore_scan_folder_btn: "🔍 Scanner dossier...",
    restore_auto_restore_btn: "⚡ Auto-Restaurer...",
    restore_detected_default: "Sélectionnez au moins 2 fichiers .rfs.",
    restore_step2_label: "2. Répertoire de sortie (optionnel) :",
    restore_target_placeholder: "Par défaut : Nom original du pied RFS4",
    restore_target_btn: "Dossier cible...",
    restore_integrity_label: "Vérification d'intégrité :",
    restore_badge_pending: "En attente",
    restore_badge_valid: "Valide [OK]",
    restore_badge_mismatch: "Erreur [Invalide]",
    restore_status_ready: "Prêt à restaurer",
    restore_status_need_2: "Au moins 2 parts sont requises !",
    restore_status_running: "Reconstruction et vérification BLKS-384...",
    restore_status_scanning: "Analyse du dossier pour les combinaisons N-Way...",
    restore_status_no_sets: "Aucun ensemble RFS valide trouvé.",
    restore_detected_all_noise: "Tous les fichiers analysés ressemblent à du bruit aléatoire.",
    restore_action_btn: "🔓 Reconstruire le fichier original",
    restore_action_running_btn: "Restauration...",
    restore_log_label: "📋 Rapport de restauration :",

    forge_step1_label: "1. Parts existantes / saisies :",
    forge_shares_placeholder: "Sélectionnez les fichiers .rfs existants...",
    forge_select_shares_btn: "Choisir parts...",
    forge_step2_label: "2. Fichier leurre inoffensif à révéler (ex. photo, PDF) :",
    forge_decoy_placeholder: "Sélectionnez le fichier leurre...",
    forge_select_decoy_btn: "Choisir leurre...",
    forge_step3_label: "3. Chemin de sortie pour la fausse part synthétisée (C_fake) :",
    forge_output_placeholder: "Chemin de sortie (ex. counterpart_fake.rfs)...",
    forge_select_output_btn: "Enregistrer sous...",
    forge_status_ready: "Prêt pour la synthèse du leurre",
    forge_status_need_1: "Au moins 1 part existante requise !",
    forge_status_running: "Synthèse de la contre-part...",
    forge_status_done: "Contre-part synthétisée avec succès [OK]",
    forge_action_btn: "🎭 Synthétiser la contre-part",
    forge_action_running_btn: "Synthèse...",
    forge_log_label: "📋 Journal de synthèse et garantie cryptographique :",
};

pub const TR_JA: Translations = Translations {
    subtitle: "暗号論的ファイル分割ツール (情報理論的安全性 & アンチフォレンジック)",
    tab_split: " 📦 分割 (Split) ",
    tab_restore: " 🔓 復元 (Restore) ",
    tab_forge: " 🎭 おとり合成 (Forge) ",

    split_step1_label: "1. ワンタイムパッドの元ファイル (GF(2) 複数ファイル同時分割対応):",
    split_file_placeholder: "1つまたは複数のファイルを選択...",
    split_select_files_btn: "ファイル選択...",
    split_file_info_default: "分割するファイルを1つ以上選択してください。",
    split_step2_label: "2. 出力先フォルダ (USBメモリやディレクトリなど):",
    split_target_placeholder: "標準: 元ファイルと同じフォルダ",
    split_select_dir_btn: "フォルダ選択...",
    split_total_shares_prefix: "総シェア数 (M = ",
    split_threshold_prefix: "しきい値 (T = ",
    split_threshold_of: " / ",
    split_enable_decoys_label: "おとりノイズファイル (Decoy) を生成",
    split_decoy_count_prefix: "おとり数 (D = ",
    split_status_ready: "分割準備完了",
    split_status_running: "ChaCha20 & SIMD-XOR で分割中...",
    split_status_select_at_least_one: "少なくとも1つのファイルを選択してください！",
    split_action_btn: "🚀 ファイルを安全に分割",
    split_action_running_btn: "分割中...",
    split_log_label: "📋 シェア割り当て & 結果ログ (復元に必要):",

    restore_step1_label: "1. RFS シェアの入力 (最低 2 ファイル):",
    restore_shares_placeholder: ".rfs ファイルを選択するかフォルダをスキャン...",
    restore_select_shares_btn: "シェア選択...",
    restore_scan_folder_btn: "🔍 フォルダスキャン...",
    restore_auto_restore_btn: "⚡ 自動一括復元...",
    restore_detected_default: "2つ以上の .rfs ファイルを選択してください。",
    restore_step2_label: "2. 出力先ディレクトリ (任意):",
    restore_target_placeholder: "標準: RFS4 フッター内の元ファイル名",
    restore_target_btn: "出力先選択...",
    restore_integrity_label: "完全性検証 (BLKS-384):",
    restore_badge_pending: "待機中",
    restore_badge_valid: "正常 [OK]",
    restore_badge_mismatch: "エラー [不一致]",
    restore_status_ready: "復元準備完了",
    restore_status_need_2: "最低2つのシェアが必要です！",
    restore_status_running: "復元および BLKS-384 完全性を検証中...",
    restore_status_scanning: "フォルダ内の有効な組み合わせをスキャン中...",
    restore_status_no_sets: "有効なセットが見つかりませんでした。",
    restore_detected_all_noise: "すべてのファイルは無相関なランダムノイズです。",
    restore_action_btn: "🔓 元ファイルを復元",
    restore_action_running_btn: "復元中...",
    restore_log_label: "📋 復元レポート:",

    forge_step1_label: "1. 既存のシェアファイル:",
    forge_shares_placeholder: "既存の .rfs ファイルを選択...",
    forge_select_shares_btn: "シェア選択...",
    forge_step2_label: "2. 開示する無害なおとりファイル (旅行写真やダミーPDFなど):",
    forge_decoy_placeholder: "おとり平文ファイルを選択...",
    forge_select_decoy_btn: "おとり選択...",
    forge_step3_label: "3. 合成する偽シェア (C_fake) の保存先パス:",
    forge_output_placeholder: "保存先パス (例: counterpart_fake.rfs)...",
    forge_select_output_btn: "保存先選択...",
    forge_status_ready: "おとり合成準備完了",
    forge_status_need_1: "最低1つの既存シェアが必要です！",
    forge_status_running: "偽シェアを合成中...",
    forge_status_done: "偽シェアの合成完了 [OK]",
    forge_action_btn: "🎭 偽シェアを合成",
    forge_action_running_btn: "合成中...",
    forge_log_label: "📋 合成ログ & 暗号論的保証:",
};

pub const TR_ZH: Translations = Translations {
    subtitle: "加密文件分割器（信息论安全与反取证保护）",
    tab_split: " 📦 分割 (Split) ",
    tab_restore: " 🔓 还原 (Restore) ",
    tab_forge: " 🎭 否认伪造 (Forge) ",

    split_step1_label: "1. 一次性密码本源文件（支持 GF(2) 对称多文件分割）：",
    split_file_placeholder: "选择一个或多个文件...",
    split_select_files_btn: "选择文件...",
    split_file_info_default: "请选择一个或多个要分割的文件。",
    split_step2_label: "2. 输出目录（如 U 盘或目标文件夹）：",
    split_target_placeholder: "默认：与源文件相同的目录",
    split_select_dir_btn: "选择文件夹...",
    split_total_shares_prefix: "总分片数 (M = ",
    split_threshold_prefix: "组合阈值 (T = ",
    split_threshold_of: " / ",
    split_enable_decoys_label: "生成诱饵噪声文件 (Decoys)",
    split_decoy_count_prefix: "诱饵数量 (D = ",
    split_status_ready: "准备分割",
    split_status_running: "正在通过 ChaCha20 与 SIMD-XOR 分割...",
    split_status_select_at_least_one: "请至少选择一个文件！",
    split_action_btn: "🚀 安全分割文件",
    split_action_running_btn: "正在分割...",
    split_log_label: "📋 分片分配与结果日志（还原时必需）：",

    restore_step1_label: "1. 输入 RFS 分片（至少 2 个分片）：",
    restore_shares_placeholder: "选择 .rfs 分片文件或扫描文件夹...",
    restore_select_shares_btn: "选择分片...",
    restore_scan_folder_btn: "🔍 扫描文件夹...",
    restore_auto_restore_btn: "⚡ 自动全部还原...",
    restore_detected_default: "请选择至少 2 个 .rfs 分片文件。",
    restore_step2_label: "2. 输出目标目录（可选）：",
    restore_target_placeholder: "默认：使用 RFS4 尾部嵌入的原始文件名",
    restore_target_btn: "目标文件夹...",
    restore_integrity_label: "完整性校验 (BLKS-384)：",
    restore_badge_pending: "待校验",
    restore_badge_valid: "有效 [OK]",
    restore_badge_mismatch: "错误 [不匹配]",
    restore_status_ready: "准备还原",
    restore_status_need_2: "至少需要 2 个分片！",
    restore_status_running: "正在重构并验证 BLKS-384 完整性...",
    restore_status_scanning: "正在扫描文件夹中的有效组合...",
    restore_status_no_sets: "未找到匹配的 RFS 分片组合。",
    restore_detected_all_noise: "所有被检查的文件均表现为无关联随机噪声。",
    restore_action_btn: "🔓 还原原始文件",
    restore_action_running_btn: "正在还原...",
    restore_log_label: "📋 还原报告：",

    forge_step1_label: "1. 现有 / 已交出的分片：",
    forge_shares_placeholder: "选择现有的 .rfs 分片文件...",
    forge_select_shares_btn: "选择分片...",
    forge_step2_label: "2. 要展示的无害诱饵明文（如旅游照片、普通 PDF）：",
    forge_decoy_placeholder: "选择诱饵明文文件...",
    forge_select_decoy_btn: "选择诱饵...",
    forge_step3_label: "3. 合成伪造分片 (C_fake) 的输出路径：",
    forge_output_placeholder: "伪造分片保存路径（如 counterpart_fake.rfs）...",
    forge_select_output_btn: "另存为...",
    forge_status_ready: "准备合成诱饵分片",
    forge_status_need_1: "至少需要 1 个现有分片！",
    forge_status_running: "正在合成对应伪造分片...",
    forge_status_done: "伪造分片合成成功 [OK]",
    forge_action_btn: "🎭 合成伪造对应分片",
    forge_action_running_btn: "正在合成...",
    forge_log_label: "📋 合成日志与密码学保证：",
};

pub const TR_TOK: Translations = Translations {
    subtitle: "ilo RFS — kipisi lipu pi len pona (sona nanpa & kalama nasa)",
    tab_split: " 📦 kipisi (Split) ",
    tab_restore: " 🔓 wan sin (Restore) ",
    tab_forge: " 🎭 pali powe (Forge) ",

    split_step1_label: "1. lipu open tawa kipisi len (lipu wan anu lipu mute):",
    split_file_placeholder: "o anu e lipu wan anu lipu mute...",
    split_select_files_btn: "o anu e lipu...",
    split_file_info_default: "o anu e lipu tawa kipisi.",
    split_step2_label: "2. poki lipu pini (poki USB anu ma lipu):",
    split_target_placeholder: "nasin open: poki sama pi lipu open",
    split_select_dir_btn: "o anu e poki...",
    split_total_shares_prefix: "kipisi ale (M = ",
    split_threshold_prefix: "kipisi wile (T = ",
    split_threshold_of: " lon ",
    split_enable_decoys_label: "o pali e kipisi powe (kalama nasa)",
    split_decoy_count_prefix: "mute pi kipisi powe (D = ",
    split_status_ready: "ilo li ken kipisi",
    split_status_running: "ilo li kipisi kepeken ChaCha20 & SIMD-XOR...",
    split_status_select_at_least_one: "o anu e lipu wan anu mute!",
    split_action_btn: "🚀 o kipisi pona e lipu",
    split_action_running_btn: "ilo li kipisi...",
    split_log_label: "📋 lipu sona pi kipisi ale (suli tawa wan sin):",

    restore_step1_label: "1. kipisi RFS (kipisi 2 anu mute):",
    restore_shares_placeholder: "o anu e kipisi .rfs anu o alasa lon poki...",
    restore_select_shares_btn: "o anu e kipisi...",
    restore_scan_folder_btn: "🔍 o alasa lon poki...",
    restore_auto_restore_btn: "⚡ o wan sin ale...",
    restore_detected_default: "o anu e kipisi .rfs 2 anu mute.",
    restore_step2_label: "2. poki pini tawa lipu sin (ken):",
    restore_target_placeholder: "nasin open: nimi open lon pini RFS4",
    restore_target_btn: "poki pini...",
    restore_integrity_label: "lukin pona BLKS-384:",
    restore_badge_pending: "awen",
    restore_badge_valid: "pona [OK]",
    restore_badge_mismatch: "pakala [sama ala]",
    restore_status_ready: "ilo li ken wan sin",
    restore_status_need_2: "kipisi 2 anu mute li wile!",
    restore_status_running: "ilo li wan sin li lukin e pona BLKS-384...",
    restore_status_scanning: "ilo li alasa e kulupu kipisi pona lon poki...",
    restore_status_no_sets: "kulupu kipisi pona li lon ala.",
    restore_detected_all_noise: "lipu ale li kalama nasa taso.",
    restore_action_btn: "🔓 o wan sin e lipu open",
    restore_action_running_btn: "ilo li wan sin...",
    restore_log_label: "📋 lipu sona pi wan sin:",

    forge_step1_label: "1. kipisi lon (kipisi pi jan ante):",
    forge_shares_placeholder: "o anu e kipisi .rfs lon...",
    forge_select_shares_btn: "o anu e kipisi...",
    forge_step2_label: "2. lipu powe pona (sitelen musi anu lipu lili):",
    forge_decoy_placeholder: "o anu e lipu powe...",
    forge_select_decoy_btn: "o anu e lipu powe...",
    forge_step3_label: "3. nimi pi kipisi powe sin (C_fake):",
    forge_output_placeholder: "nimi pi kipisi powe (counterpart_fake.rfs)...",
    forge_select_output_btn: "o awen lon...",
    forge_status_ready: "ilo li ken pali powe",
    forge_status_need_1: "kipisi lon 1 anu mute li wile!",
    forge_status_running: "ilo li pali e kipisi powe...",
    forge_status_done: "kipisi powe li lon [OK]",
    forge_action_btn: "🎭 o pali e kipisi powe",
    forge_action_running_btn: "ilo li pali...",
    forge_log_label: "📋 lipu sona pi pali powe:",
};

/// Toki Pona in sitelen pona hieroglyphic script (UCSUR U+F1900..U+F19A3).
pub const TR_SP: Translations = Translations {
    subtitle: "󱤎 RFS - 󱥻 󱤪 󱥍 󱤥 󱥔 (󱥡 󱤽 & 󱤕 󱤾)",
    tab_split: " 📦 󱥻 (Split) ",
    tab_restore: " 🔓 󱥳 󱥝 (Restore) ",
    tab_forge: " 🎭 󱥉 󱦣 (Forge) ",

    split_step1_label: "1. 󱤪 󱥇 󱥩 󱥻 󱤥 (󱤪 󱥳 󱤇 󱤪 󱤼):",
    split_file_placeholder: "󱥄 󱤇 󱤉 󱤪 󱥳 󱤇 󱤪 󱤼...",
    split_select_files_btn: "󱥄 󱤇 󱤉 󱤪...",
    split_file_info_default: "󱥄 󱤇 󱤉 󱤪 󱥩 󱥻.",
    split_step2_label: "2. 󱥓 󱤪 󱥐 (󱥓 USB 󱤇 󱤰 󱤪):",
    split_target_placeholder: "󱤿 󱥇: 󱥓 󱥖 󱥍 󱤪 󱥇",
    split_select_dir_btn: "󱥄 󱤇 󱤉 󱥓...",
    split_total_shares_prefix: "󱥻 󱤄 (M = ",
    split_threshold_prefix: "󱥻 󱥷 (T = ",
    split_threshold_of: " 󱤬 ",
    split_enable_decoys_label: "󱥄 󱥉 󱤉 󱥻 󱦣 (󱤕 󱤾)",
    split_decoy_count_prefix: "󱤼 󱥍 󱥻 󱦣 (D = ",
    split_status_ready: "󱤎 󱤧 󱤘 󱥻",
    split_status_running: "󱤎 󱤧 󱥻 󱤙 ChaCha20 & SIMD-XOR...",
    split_status_select_at_least_one: "󱥄 󱤇 󱤉 󱤪 󱥳 󱤇 󱤼!",
    split_action_btn: "🚀 󱥄 󱥻 󱥔 󱤉 󱤪",
    split_action_running_btn: "󱤎 󱤧 󱥻...",
    split_log_label: "📋 󱤪 󱥡 󱥍 󱥻 󱤄 (󱥣 󱥩 󱥳 󱥝):",

    restore_step1_label: "1. 󱥻 RFS (󱥻 2 󱤇 󱤼):",
    restore_shares_placeholder: "󱥄 󱤇 󱤉 󱥻 .rfs 󱤇 󱥄 󱤃 󱤬 󱥓...",
    restore_select_shares_btn: "󱥄 󱤇 󱤉 󱥻...",
    restore_scan_folder_btn: "🔍 󱥄 󱤃 󱤬 󱥓...",
    restore_auto_restore_btn: "⚡ 󱥄 󱥳 󱥝 󱤄...",
    restore_detected_default: "󱥄 󱤇 󱤉 󱥻 .rfs 2 󱤇 󱤼.",
    restore_step2_label: "2. 󱥓 󱥐 󱥩 󱤪 󱥝 (󱤘):",
    restore_target_placeholder: "󱤿 󱥇: 󱥂 󱥇 󱤬 󱥐 RFS4",
    restore_target_btn: "󱥓 󱥐...",
    restore_integrity_label: "󱤮 󱥔 BLKS-384:",
    restore_badge_pending: "󱤈",
    restore_badge_valid: "󱥔 [OK]",
    restore_badge_mismatch: "󱥈 [󱥖 󱤂]",
    restore_status_ready: "󱤎 󱤧 󱤘 󱥳 󱥝",
    restore_status_need_2: "󱥻 2 󱤇 󱤼 󱤧 󱥷!",
    restore_status_running: "󱤎 󱤧 󱥳 󱥝 󱤧 󱤮 󱤉 󱥔 BLKS-384...",
    restore_status_scanning: "󱤎 󱤧 󱤃 󱤉 󱤟 󱥻 󱥔 󱤬 󱥓...",
    restore_status_no_sets: "󱤟 󱥻 󱥔 󱤧 󱤬 󱤂.",
    restore_detected_all_noise: "󱤪 󱤄 󱤧 󱤕 󱤾 󱥨.",
    restore_action_btn: "🔓 󱥄 󱥳 󱥝 󱤉 󱤪 󱥇",
    restore_action_running_btn: "󱤎 󱤧 󱥳 󱥝...",
    restore_log_label: "📋 󱤪 󱥡 󱥍 󱥳 󱥝:",

    forge_step1_label: "1. 󱥻 󱤬 (󱥻 󱥍 󱤑 󱤆):",
    forge_shares_placeholder: "󱥄 󱤇 󱤉 󱥻 .rfs 󱤬...",
    forge_select_shares_btn: "󱥄 󱤇 󱤉 󱥻...",
    forge_step2_label: "2. 󱤪 󱦣 󱥔 (󱥠 󱤻 󱤇 󱤪 󱤨):",
    forge_decoy_placeholder: "󱥄 󱤇 󱤉 󱤪 󱦣...",
    forge_select_decoy_btn: "󱥄 󱤇 󱤉 󱤪 󱦣...",
    forge_step3_label: "3. 󱥂 󱥍 󱥻 󱦣 󱥝 (C_fake):",
    forge_output_placeholder: "󱥂 󱥍 󱥻 󱦣 (counterpart_fake.rfs)...",
    forge_select_output_btn: "󱥄 󱤈 󱤬...",
    forge_status_ready: "󱤎 󱤧 󱤘 󱥉 󱦣",
    forge_status_need_1: "󱥻 󱤬 1 󱤇 󱤼 󱤧 󱥷!",
    forge_status_running: "󱤎 󱤧 󱥉 󱤉 󱥻 󱦣...",
    forge_status_done: "󱥻 󱦣 󱤧 󱤬 [OK]",
    forge_action_btn: "🎭 󱥄 󱥉 󱤉 󱥻 󱦣",
    forge_action_running_btn: "󱤎 󱤧 󱥉...",
    forge_log_label: "📋 󱤪 󱥡 󱥍 󱥉 󱦣:",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_parsing_and_defaults() {
        assert_eq!(Lang::default(), Lang::En);
        assert_eq!(Lang::from_code("en"), Some(Lang::En));
        assert_eq!(Lang::from_code("en_US.UTF-8"), Some(Lang::En));
        assert_eq!(Lang::from_code("de_DE.UTF-8"), Some(Lang::De));
        assert_eq!(Lang::from_code("es"), Some(Lang::Es));
        assert_eq!(Lang::from_code("fr_FR"), Some(Lang::Fr));
        assert_eq!(Lang::from_code("ja"), Some(Lang::Ja));
        assert_eq!(Lang::from_code("jp"), Some(Lang::Ja));
        assert_eq!(Lang::from_code("zh-CN"), Some(Lang::Zh));
        assert_eq!(Lang::from_code("tok"), Some(Lang::Tok));
        assert_eq!(Lang::from_code("sp"), Some(Lang::Sp));
        assert_eq!(Lang::from_code("tok-sp"), Some(Lang::Sp));
        assert_eq!(Lang::from_code("sitelen-pona"), Some(Lang::Sp));
        assert_eq!(Lang::from_code("unknown"), None);
    }

    #[test]
    fn test_all_eight_languages_have_non_empty_strings() {
        let dummy_paths = vec![PathBuf::from("a.rfs"), PathBuf::from("b.rfs")];
        let dummy_subsets = vec![("secret.bin".to_string(), dummy_paths.clone())];
        let dummy_scan = vec![(
            "secret.bin".to_string(),
            "4.0 KB".to_string(),
            dummy_paths.clone(),
        )];
        let dummy_auto = vec![("secret.bin".to_string(), PathBuf::from("secret.bin"), 2)];

        for lang in Lang::ALL {
            let tr = lang.tr();
            assert!(!tr.subtitle.is_empty());
            assert!(!tr.tab_split.is_empty());
            assert!(!tr.tab_restore.is_empty());
            assert!(!tr.tab_forge.is_empty());
            assert!(!tr.split_action_btn.is_empty());
            assert!(!tr.restore_action_btn.is_empty());
            assert!(!tr.forge_action_btn.is_empty());
            let hint = tr.format_info_hint(lang, 3, 4, 5, 2, 4);
            assert!(!hint.is_empty());

            let (s1, l1) = tr.format_gui_single_split_report(lang, &dummy_paths, &dummy_paths);
            assert!(!s1.is_empty() && !l1.is_empty());
            let (s2, l2) = tr.format_gui_multi_split_report(
                lang,
                3,
                2,
                "4.0 KB",
                &dummy_paths,
                &dummy_subsets,
                &dummy_paths,
            );
            assert!(!s2.is_empty() && !l2.is_empty());
            let (s3, p3, l3) = tr.format_gui_scan_report(lang, 4, &dummy_scan);
            assert!(!s3.is_empty() && !p3.is_empty() && !l3.is_empty());
            let (s4, l4) = tr.format_gui_auto_restore_report(lang, &dummy_auto);
            assert!(!s4.is_empty() && !l4.is_empty());
            let (s5, l5) = tr.format_gui_restore_report(lang, "restored.bin");
            assert!(!s5.is_empty() && !l5.is_empty());
            let l6 = tr.format_gui_forge_report(lang, "fake.rfs", "decoy.pdf", 2);
            assert!(!l6.is_empty());
            assert!(!tr.format_cli_integrity_ok(lang, "HASH").is_empty());
            assert!(!tr.format_cli_restored(lang, "out.bin").is_empty());
        }
    }

    #[test]
    fn test_cli_lang_flag_before_and_after_subcommand() {
        let cmd1 = crate::cli::parse_cli_args(["rfs", "-l", "es", "split", "test.bin"]).unwrap();
        assert_eq!(current_lang(), Lang::Es);
        assert!(matches!(cmd1, crate::cli::CliCommand::Split { .. }));

        let cmd2 = crate::cli::parse_cli_args(["rfs", "split", "test.bin", "-l", "de"]).unwrap();
        assert_eq!(current_lang(), Lang::De);
        assert!(matches!(cmd2, crate::cli::CliCommand::Split { .. }));

        let cmd3 = crate::cli::parse_cli_args(["rfs", "-l", "tok"]).unwrap();
        assert_eq!(current_lang(), Lang::Tok);
        assert_eq!(cmd3, crate::cli::CliCommand::Help(None));

        set_active_lang(Lang::En);
    }
}
