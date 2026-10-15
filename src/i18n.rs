//! Lightweight, zero-allocation internationalization (i18n) engine for RFS CLI and Desktop GUI.
//! Default language is English (`en`), with built-in support for German (`de`), Spanish (`es`),
//! French (`fr`), Japanese (`ja`), Simplified Chinese (`zh`), and Toki Pona (`tok`).

/// Supported languages in RFS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// English (Default)
    #[default]
    En,
    /// German (Deutsch)
    De,
    /// Spanish (Español)
    Es,
    /// French (Français)
    Fr,
    /// Japanese (日本語)
    Ja,
    /// Simplified Chinese (简体中文)
    Zh,
    /// Toki Pona (toki pona)
    Tok,
}

impl Lang {
    /// All supported languages in display order.
    pub const ALL: [Lang; 7] = [
        Lang::En,
        Lang::De,
        Lang::Es,
        Lang::Fr,
        Lang::Ja,
        Lang::Zh,
        Lang::Tok,
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
        }
    }

    /// Parses a language code (case-insensitive, supports locale prefixes like `de_DE.UTF-8`).
    pub fn from_code(raw: &str) -> Option<Self> {
        let cleaned = raw.trim().to_ascii_lowercase();
        let prefix = cleaned.split(['_', '-', '.']).next().unwrap_or("");
        match prefix {
            "en" | "eng" | "c" | "posix" => Some(Lang::En),
            "de" | "deu" | "ger" => Some(Lang::De),
            "es" | "esp" | "spa" => Some(Lang::Es),
            "fr" | "fra" | "fre" => Some(Lang::Fr),
            "ja" | "jp" | "jpn" => Some(Lang::Ja),
            "zh" | "zho" | "chi" | "cn" => Some(Lang::Zh),
            "tok" | "tp" | "tokipona" => Some(Lang::Tok),
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
            }
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
        assert_eq!(Lang::from_code("unknown"), None);
    }

    #[test]
    fn test_all_seven_languages_have_non_empty_strings() {
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
        }
    }
}
