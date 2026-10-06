//! rfs: Next-Gen High-Performance Cryptographic File Splitter & Reconstructor (v3.0.0 Rust)
//! Copyright (c) 2026 Meik Augenblick (LGPL v3)

mod benchmark;
mod crypto;
mod entropy;
mod format;
mod pipeline;
mod telemetry;
mod types;

use std::env;
use std::path::{Path, PathBuf};
use std::process;

const APP_NAME: &str = "rfs";
const APP_VERSION: &str = "3.0.0";
const FORMAT_TAG: &str = "RFS3-PQ";

fn display_version() {
    println!(
        "{} version {} (Format: {}, Rust Edition 2021)",
        APP_NAME, APP_VERSION, FORMAT_TAG
    );
    println!("Copyright (c) 2026 Meik Augenblick (LGPL v3)");
}

fn display_help() {
    display_version();
    println!("\nVerwendung:");
    println!(
        "  rfs split [Optionen] <Quelle|-> [Teile...]      (Datei oder Stdin in 2 oder N Teile splitten)"
    );
    println!(
        "  rfs restore [Optionen] <Teile...> [Ziel|-]      (N Teile auf Festplatte oder Stdout wiederherstellen)"
    );
    println!(
        "  rfs verify [Optionen] <Teile...>               (Integrität von N Teilen im RAM prüfen)"
    );
    println!("\nKlassische Syntax:");
    println!(
        "  rfs [Optionen] <Datei|->                       (Datei oder Stdin in 2 Teile splitten)"
    );
    println!(
        "  rfs [Optionen] <Teil1> <Teil2> [Teil3...]      (Datei aus N Teilen wiederherstellen)"
    );
    println!("  rfs --verify <Teile...>                        (Integrität von N Teilen prüfen)");
    println!("\nN-Way One-Time-Pad & Unix Streaming-Pipes:");
    println!("  rfs split -n 3 geheim.iso                      (In 3 Rausch-Dateien aufteilen: .rfs1, .rfs2, .rfs3)");
    println!("  rfs restore geheim.rfs1 geheim.rfs2 geheim.rfs3 (Bitgenaue Rekonstruktion aus allen 3 Teilen)");
    println!("  tar -czf - /data | rfs split -n 4 - -o backup  (Stdin direkt in 4 Teile streamen)");
    println!("  rfs restore backup.rfs* -o - | tar -xzf -      (Aus allen Teilen direkt nach Stdout pipen)");
    println!("\nBefehle & Werkzeuge:");
    println!("  -b, --benchmark                                Hardware- und Durchsatz-Benchmark");
    println!(
        "  -e, --entropy-test                            Zweiphasige Entropie- & Jitter-Diagnose"
    );
    println!(
        "  -a, --analyze <Datei>                         Kryptoanalytische Datei-Entropieanalyse"
    );
    println!("  -h, --help                                    Diese Hilfe anzeigen");
    println!("  -V, --version                                 Versionsnummer anzeigen");
    println!("\nOptionen:");
    println!("  -n, --parts <ANZAHL>                          Anzahl der Teile für N-Way Splitting (2 bis 64; Standard: 2)");
    println!("  -B, --block-size <GRÖSSE>                     I/O-Puffergröße (z. B. 64K, 1M, 4M, 16M; Standard: 4M)");
    println!("  -o, --output <PFAD>                           Präfix für Teile bzw. Pfad der Zieldatei (oder '-' für stdout)");
    println!("  --json                                        Maschinenlesbare NDJSON-Telemetrie auf stderr");
    println!(
        "  -f, --force                                   Zieldateien überschreiben falls vorhanden"
    );
    println!(
        "  -q, --quiet, --silent                         Ausgabe stummschalten (nur Fehler)\n"
    );
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Split,
    Restore,
    Verify,
}

fn parse_restore_targets(
    positionals: &[String],
    output_flag: Option<&str>,
) -> Result<(Vec<PathBuf>, Option<String>), String> {
    if positionals.is_empty() {
        return Err("Keine Split-Dateien zur Wiederherstellung angegeben.".to_string());
    }
    if let Some(target) = output_flag {
        let parts: Vec<PathBuf> = positionals.iter().map(PathBuf::from).collect();
        return Ok((parts, Some(target.to_string())));
    }

    let last = &positionals[positionals.len() - 1];
    if last == "-" {
        let parts: Vec<PathBuf> = positionals[..positionals.len() - 1]
            .iter()
            .map(PathBuf::from)
            .collect();
        return Ok((parts, Some("-".to_string())));
    }

    let all_exist = positionals.iter().all(|p| Path::new(p).exists());
    if all_exist {
        let parts: Vec<PathBuf> = positionals.iter().map(PathBuf::from).collect();
        return Ok((parts, None));
    }

    if positionals.len() >= 3 && !Path::new(last).exists() {
        let parts: Vec<PathBuf> = positionals[..positionals.len() - 1]
            .iter()
            .map(PathBuf::from)
            .collect();
        return Ok((parts, Some(last.clone())));
    }

    let parts: Vec<PathBuf> = positionals.iter().map(PathBuf::from).collect();
    Ok((parts, None))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        display_help();
        process::exit(1);
    }

    let first = &args[1];
    if first == "-h" || first == "--help" {
        display_help();
        return;
    }
    if first == "-V" || first == "--version" {
        display_version();
        return;
    }
    if first == "-b" || first == "--benchmark" {
        let code = benchmark::run_benchmark();
        process::exit(code);
    }
    if first == "-e" || first == "--entropy" || first == "--entropy-test" {
        let code = entropy::run_entropy_diagnostics();
        process::exit(code);
    }
    if first == "-a" || first == "--analyze" || first == "--file-entropy" {
        if args.len() < 3 {
            eprintln!("Fehler: Option {} erfordert einen Dateipfad.", first);
            eprintln!("Verwendung: rfs -a <Datei> [--json]");
            process::exit(1);
        }
        let json_mode = args.iter().any(|a| a == "--json");
        let file_arg = args
            .iter()
            .skip(2)
            .find(|a| *a != "--json")
            .unwrap_or(&args[2]);
        if let Err(e) = entropy::analyze_file_entropy(Path::new(file_arg), json_mode) {
            eprintln!("Fehler: {}", e);
            process::exit(1);
        }
        return;
    }

    // Subcommand-Erkennung
    let mut explicit_subcommand: Option<&str> = None;
    let mut start_idx = 1;
    if first == "split" || first == "restore" || first == "verify" {
        explicit_subcommand = Some(first.as_str());
        start_idx = 2;
    } else if first == "benchmark" {
        let code = benchmark::run_benchmark();
        process::exit(code);
    } else if first == "entropy" {
        let code = entropy::run_entropy_diagnostics();
        process::exit(code);
    } else if first == "analyze" {
        if args.len() < 3 {
            eprintln!("Fehler: Subcommand 'analyze' erfordert einen Dateipfad.");
            eprintln!("Verwendung: rfs analyze <Datei> [--json]");
            process::exit(1);
        }
        let json_mode = args.iter().any(|a| a == "--json");
        let file_arg = args
            .iter()
            .skip(2)
            .find(|a| *a != "--json")
            .unwrap_or(&args[2]);
        if let Err(e) = entropy::analyze_file_entropy(Path::new(file_arg), json_mode) {
            eprintln!("Fehler: {}", e);
            process::exit(1);
        }
        return;
    }

    // Flag-Parsing
    let mut verify_only = false;
    let mut force = false;
    let mut silent = false;
    let mut json_output = false;
    let mut num_parts: usize = 2;
    let mut block_size = types::DEFAULT_BLOCK_SIZE;
    let mut output_path: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();

    let mut i = start_idx;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-v" || arg == "--verify" || arg == "--check" {
            verify_only = true;
        } else if arg == "-f" || arg == "--force" {
            force = true;
        } else if arg == "-q" || arg == "--quiet" || arg == "--silent" {
            silent = true;
        } else if arg == "--json" {
            json_output = true;
        } else if arg == "-n" || arg == "--parts" {
            i += 1;
            if i >= args.len() {
                eprintln!("Fehler: Option {} erfordert eine Anzahl.", arg);
                process::exit(1);
            }
            match args[i].parse::<usize>() {
                Ok(n) if (2..=64).contains(&n) => num_parts = n,
                Ok(n) => {
                    eprintln!(
                        "Fehler: Anzahl der Teile ({}) muss zwischen 2 und 64 liegen.",
                        n
                    );
                    process::exit(1);
                }
                Err(_) => {
                    eprintln!("Fehler: Ungültige Zahl für Option {}: '{}'", arg, args[i]);
                    process::exit(1);
                }
            }
        } else if arg == "-B" || arg == "--block-size" {
            i += 1;
            if i >= args.len() {
                eprintln!("Fehler: Option {} erfordert eine Größenangabe.", arg);
                process::exit(1);
            }
            match types::parse_block_size(&args[i]) {
                Ok(bs) => block_size = bs,
                Err(e) => {
                    eprintln!("Fehler: {}", e);
                    process::exit(1);
                }
            }
        } else if arg == "-o" || arg == "--output" {
            i += 1;
            if i >= args.len() {
                eprintln!("Fehler: Option {} erfordert einen Pfad.", arg);
                process::exit(1);
            }
            output_path = Some(args[i].clone());
        } else if arg == "-" || !arg.starts_with('-') {
            positionals.push(arg.clone());
        } else {
            eprintln!("Fehler: Unbekannte Option '{}'", arg);
            eprintln!("Führen Sie 'rfs --help' für Hilfe aus.");
            process::exit(1);
        }
        i += 1;
    }

    let action = match explicit_subcommand {
        Some("split") => Action::Split,
        Some("restore") => Action::Restore,
        Some("verify") => Action::Verify,
        Some(cmd) => {
            eprintln!("Fehler: Unbekannter Befehl '{}'", cmd);
            display_help();
            process::exit(1);
        }
        None => {
            if verify_only {
                Action::Verify
            } else if positionals.is_empty() {
                eprintln!("Fehler: Keine Eingabedatei(en) angegeben.");
                eprintln!("Führen Sie 'rfs --help' für Hilfe aus.");
                process::exit(1);
            } else if positionals.len() == 1 || (positionals[0] == "-" && positionals.len() >= 3) {
                Action::Split
            } else {
                Action::Restore
            }
        }
    };

    let telemetry_mode = if json_output {
        telemetry::TelemetryMode::Json
    } else if silent {
        telemetry::TelemetryMode::Silent
    } else {
        telemetry::TelemetryMode::Interactive
    };

    match action {
        Action::Split => {
            if positionals.is_empty() {
                eprintln!("Fehler: Keine Eingabedatei für Split angegeben.");
                process::exit(1);
            }
            let input_source = &positionals[0];
            let output_parts: Option<Vec<PathBuf>> = if positionals.len() > 1 {
                Some(positionals[1..].iter().map(PathBuf::from).collect())
            } else {
                None
            };

            match pipeline::split_stream_or_file(
                input_source,
                output_parts.as_deref(),
                num_parts,
                output_path.as_deref(),
                block_size,
                telemetry_mode,
                force,
            ) {
                Ok(_) => process::exit(0),
                Err(e) => {
                    if telemetry_mode != telemetry::TelemetryMode::Json {
                        eprintln!("Fehler beim Splitten: {}", e);
                    }
                    process::exit(1);
                }
            }
        }
        Action::Restore => {
            let (parts, target) = match parse_restore_targets(&positionals, output_path.as_deref())
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("Fehler: {}", e);
                    process::exit(1);
                }
            };

            if parts.len() < 2 {
                eprintln!("Fehler: Restore erfordert mindestens 2 Split-Dateien.");
                process::exit(1);
            }

            match pipeline::restore_file(
                &parts,
                target.as_deref(),
                force,
                telemetry_mode,
                false,
                block_size,
            ) {
                Ok(restored_path_opt) => {
                    if telemetry_mode == telemetry::TelemetryMode::Interactive {
                        if let Some(restored) = restored_path_opt {
                            println!("Erfolgreich wiederhergestellt: {}", restored.display());
                        }
                    }
                    process::exit(0);
                }
                Err(e) => {
                    if telemetry_mode != telemetry::TelemetryMode::Json {
                        eprintln!("Fehler bei der Wiederherstellung: {}", e);
                    }
                    process::exit(1);
                }
            }
        }
        Action::Verify => {
            if positionals.len() < 2 {
                eprintln!("Fehler: Verify erfordert mindestens 2 Split-Dateien zur Prüfung.");
                process::exit(1);
            }
            let parts: Vec<PathBuf> = positionals.iter().map(PathBuf::from).collect();

            match pipeline::restore_file(&parts, None, force, telemetry_mode, true, block_size) {
                Ok(_) => process::exit(0),
                Err(e) => {
                    if telemetry_mode != telemetry::TelemetryMode::Json {
                        eprintln!("Fehler bei der Verifikation: {}", e);
                    }
                    process::exit(1);
                }
            }
        }
    }
}
