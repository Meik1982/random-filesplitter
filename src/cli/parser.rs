//! Typisiertes CLI-Parsing, Validierung und Hilfetexte für rfs.

use std::path::{Path, PathBuf};

use crate::telemetry::TelemetryMode;
use crate::types;

const APP_NAME: &str = "rfs";
const APP_VERSION: &str = "3.0.0";
const FORMAT_TAG: &str = "RFS3-PQ";

/// Zeigt die Versionsinformationen auf stdout an.
pub fn display_version() {
    println!(
        "{} version {} (Format: {}, Rust Edition 2021)",
        APP_NAME, APP_VERSION, FORMAT_TAG
    );
    println!("Copyright (c) 2026 Meik Augenblick (LGPL v3)");
}

/// Zeigt den vollständigen CLI-Hilfetext auf stdout an.
pub fn display_help() {
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
    println!(
        "  rfs decoy [Optionen] [-t <Muster>] [-s <Größe>] (Köderdateien mit ChaCha20-Zufallsrauschen erzeugen)"
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
    println!("  -d, --decoys <ANZAHL>                         Zusätzliche Köderdateien (Decoys) beim Splitten erzeugen");
    println!("  --pad-to <GRÖSSE>                             Share-Dateien auf eine exakte Bytegröße aufblähen (z. B. 100M, 20G)");
    println!("  --token, --rnd                                Anti-Forensik: Zufällige Hex-Tokens (.<rnd>.rfs) statt Nummern");
    println!("  -c, --count <ANZAHL>                          Anzahl der Köderdateien für 'rfs decoy' (Standard: 1)");
    println!("  -s, --size <GRÖSSE>                           Explizite Bytegröße für 'rfs decoy' (z. B. 64K, 10M, 1G)");
    println!("  -t, --template <DATEI>                        Musterdatei für 'rfs decoy' (Rohdatei +60B Footer oder RFS 1:1)");
    println!("  -o, --output <PFAD>                           Präfix für Teile bzw. Pfad der Zieldatei (oder '-' für stdout)");
    println!("  --direct                                      Direct I/O: Kernel Page-Cache für Multi-Gigabyte-Dateien umgehen");
    println!("  --json                                        Maschinenlesbare NDJSON-Telemetrie auf stderr");
    println!(
        "  -f, --force                                   Zieldateien überschreiben falls vorhanden"
    );
    println!(
        "  -q, --quiet, --silent                         Ausgabe stummschalten (nur Fehler)\n"
    );
}

/// Vollständig aufgelöste CLI-Aktion mit allen validierten Parametern.
#[derive(Debug, PartialEq, Eq)]
pub enum CliCommand {
    /// Hilfe anzeigen
    Help,
    /// Version anzeigen
    Version,
    /// Hardware-Benchmark ausführen
    Benchmark,
    /// Entropie-Diagnose ausführen
    Entropy,
    /// Kryptoanalytische Dateianalyse
    Analyze { file: PathBuf, json_mode: bool },
    /// Datei oder Stdin in N Teile splitten
    Split {
        input: String,
        parts: Option<Vec<PathBuf>>,
        num_parts: usize,
        num_decoys: usize,
        pad_to: Option<u64>,
        output_prefix: Option<String>,
        block_size: usize,
        telemetry_mode: TelemetryMode,
        force: bool,
        direct_io: bool,
    },
    /// Rekonstruktion aus N Teilen
    Restore {
        parts: Vec<PathBuf>,
        output_target: Option<String>,
        block_size: usize,
        telemetry_mode: TelemetryMode,
        force: bool,
        direct_io: bool,
    },
    /// RAM-Integritätsprüfung aus N Teilen
    Verify {
        parts: Vec<PathBuf>,
        block_size: usize,
        telemetry_mode: TelemetryMode,
        force: bool,
        direct_io: bool,
    },
    /// Köderdateien mit ChaCha20-Zufall erzeugen
    Decoy {
        template: Option<PathBuf>,
        size: Option<u64>,
        count: usize,
        token_mode: bool,
        output_path: Option<String>,
        block_size: usize,
        telemetry_mode: TelemetryMode,
        force: bool,
        direct_io: bool,
    },
}

/// Parst die CLI-Argumente in einen typsicheren `CliCommand`.
pub fn parse_cli_args(args: &[String]) -> Result<CliCommand, String> {
    if args.len() < 2 || args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(CliCommand::Help);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        return Ok(CliCommand::Version);
    }

    let first = &args[1];
    if first == "-b" || first == "--benchmark" {
        return Ok(CliCommand::Benchmark);
    }
    if first == "-e" || first == "--entropy" || first == "--entropy-test" {
        return Ok(CliCommand::Entropy);
    }
    if first == "-a" || first == "--analyze" || first == "--file-entropy" {
        if args.len() < 3 {
            return Err(format!(
                "Fehler: Option {} erfordert einen Dateipfad.\nVerwendung: rfs -a <Datei> [--json]",
                first
            ));
        }
        let json_mode = args.iter().any(|a| a == "--json");
        let file_arg = args
            .iter()
            .skip(2)
            .find(|a| *a != "--json")
            .unwrap_or(&args[2]);
        return Ok(CliCommand::Analyze {
            file: PathBuf::from(file_arg),
            json_mode,
        });
    }

    // Subcommand-Erkennung
    let mut explicit_subcommand: Option<&str> = None;
    let mut start_idx = 1;
    if first == "split" || first == "restore" || first == "verify" || first == "decoy" {
        explicit_subcommand = Some(first.as_str());
        start_idx = 2;
    } else if first == "benchmark" {
        return Ok(CliCommand::Benchmark);
    } else if first == "entropy" {
        return Ok(CliCommand::Entropy);
    } else if first == "analyze" {
        if args.len() < 3 {
            return Err(
                "Fehler: Subcommand 'analyze' erfordert einen Dateipfad.\nVerwendung: rfs analyze <Datei> [--json]".to_string(),
            );
        }
        let json_mode = args.iter().any(|a| a == "--json");
        let file_arg = args
            .iter()
            .skip(2)
            .find(|a| *a != "--json")
            .unwrap_or(&args[2]);
        return Ok(CliCommand::Analyze {
            file: PathBuf::from(file_arg),
            json_mode,
        });
    }

    // Flag-Parsing
    let mut verify_only = false;
    let mut force = false;
    let mut silent = false;
    let mut json_output = false;
    let mut direct_io = false;
    let mut token_mode = false;
    let mut pad_to: Option<u64> = None;
    let mut num_parts: usize = 2;
    let mut num_decoys: usize = 0;
    let mut decoy_count: usize = 1;
    let mut decoy_size: Option<u64> = None;
    let mut decoy_template: Option<String> = None;
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
        } else if arg == "--direct" || arg == "--direct-io" {
            direct_io = true;
        } else if arg == "--token" || arg == "--rnd" {
            token_mode = true;
        } else if arg == "--pad-to" {
            i += 1;
            if i >= args.len() {
                return Err(format!(
                    "Fehler: Option {} erfordert eine Größenangabe.",
                    arg
                ));
            }
            pad_to = Some(types::parse_file_size(&args[i])?);
        } else if arg == "-n" || arg == "--parts" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Fehler: Option {} erfordert eine Anzahl.", arg));
            }
            match args[i].parse::<usize>() {
                Ok(n) if (2..=64).contains(&n) => num_parts = n,
                Ok(n) => {
                    return Err(format!(
                        "Fehler: Anzahl der Teile ({}) muss zwischen 2 und 64 liegen.",
                        n
                    ));
                }
                Err(_) => {
                    return Err(format!(
                        "Fehler: Ungültige Zahl für Option {}: '{}'",
                        arg, args[i]
                    ));
                }
            }
        } else if arg == "-B" || arg == "--block-size" {
            i += 1;
            if i >= args.len() {
                return Err(format!(
                    "Fehler: Option {} erfordert eine Größenangabe.",
                    arg
                ));
            }
            block_size = types::parse_block_size(&args[i])?;
        } else if arg == "-d" || arg == "--decoys" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Fehler: Option {} erfordert eine Anzahl.", arg));
            }
            match args[i].parse::<usize>() {
                Ok(n) => num_decoys = n,
                Err(_) => {
                    return Err(format!(
                        "Fehler: Ungültige Zahl für Option {}: '{}'",
                        arg, args[i]
                    ));
                }
            }
        } else if arg == "-c" || arg == "--count" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Fehler: Option {} erfordert eine Anzahl.", arg));
            }
            match args[i].parse::<usize>() {
                Ok(n) if (1..=1000).contains(&n) => decoy_count = n,
                Ok(n) => {
                    return Err(format!(
                        "Fehler: Anzahl der Köderdateien ({}) muss zwischen 1 und 1000 liegen.",
                        n
                    ));
                }
                Err(_) => {
                    return Err(format!(
                        "Fehler: Ungültige Zahl für Option {}: '{}'",
                        arg, args[i]
                    ));
                }
            }
        } else if arg == "-s" || arg == "--size" {
            i += 1;
            if i >= args.len() {
                return Err(format!(
                    "Fehler: Option {} erfordert eine Größenangabe.",
                    arg
                ));
            }
            decoy_size = Some(types::parse_file_size(&args[i])?);
        } else if arg == "-t" || arg == "--template" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Fehler: Option {} erfordert einen Dateipfad.", arg));
            }
            decoy_template = Some(args[i].clone());
        } else if arg == "-o" || arg == "--output" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Fehler: Option {} erfordert einen Pfad.", arg));
            }
            output_path = Some(args[i].clone());
        } else if arg == "-" || !arg.starts_with('-') {
            positionals.push(arg.clone());
        } else {
            return Err(format!(
                "Fehler: Unbekannte Option '{}'\nFühren Sie 'rfs --help' für Hilfe aus.",
                arg
            ));
        }
        i += 1;
    }

    let action_str = match explicit_subcommand {
        Some(cmd) => cmd,
        None => {
            if verify_only {
                "verify"
            } else if positionals.is_empty() {
                return Err("Fehler: Keine Eingabedatei(en) angegeben.\nFühren Sie 'rfs --help' für Hilfe aus.".to_string());
            } else if positionals.len() == 1 || (positionals[0] == "-" && positionals.len() >= 3) {
                "split"
            } else {
                "restore"
            }
        }
    };

    let telemetry_mode = if json_output {
        TelemetryMode::Json
    } else if silent {
        TelemetryMode::Silent
    } else {
        TelemetryMode::Interactive
    };

    match action_str {
        "split" => {
            if positionals.is_empty() {
                return Err("Fehler: Keine Eingabedatei für Split angegeben.".to_string());
            }
            let input = positionals[0].clone();
            let parts: Option<Vec<PathBuf>> = if positionals.len() > 1 {
                Some(positionals[1..].iter().map(PathBuf::from).collect())
            } else {
                None
            };
            Ok(CliCommand::Split {
                input,
                parts,
                num_parts,
                num_decoys,
                pad_to,
                output_prefix: output_path,
                block_size,
                telemetry_mode,
                force,
                direct_io,
            })
        }
        "restore" => {
            let (parts, target) = parse_restore_targets(&positionals, output_path.as_deref())?;
            if parts.len() < 2 {
                return Err("Fehler: Restore erfordert mindestens 2 Split-Dateien.".to_string());
            }
            Ok(CliCommand::Restore {
                parts,
                output_target: target,
                block_size,
                telemetry_mode,
                force,
                direct_io,
            })
        }
        "verify" => {
            if positionals.len() < 2 {
                return Err(
                    "Fehler: Verify erfordert mindestens 2 Split-Dateien zur Prüfung.".to_string(),
                );
            }
            let parts: Vec<PathBuf> = positionals.iter().map(PathBuf::from).collect();
            Ok(CliCommand::Verify {
                parts,
                block_size,
                telemetry_mode,
                force,
                direct_io,
            })
        }
        "decoy" => {
            if decoy_template.is_none() && !positionals.is_empty() {
                decoy_template = Some(positionals[0].clone());
            }
            Ok(CliCommand::Decoy {
                template: decoy_template.map(PathBuf::from),
                size: decoy_size,
                count: decoy_count,
                token_mode,
                output_path,
                block_size,
                telemetry_mode,
                force,
                direct_io,
            })
        }
        unknown => Err(format!(
            "Fehler: Unbekannter Befehl '{}'\nFühren Sie 'rfs --help' für Hilfe aus.",
            unknown
        )),
    }
}

/// Trennt Positionsargumente in Quellteile und optionalen Zielpfad für `restore`.
pub fn parse_restore_targets(
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
