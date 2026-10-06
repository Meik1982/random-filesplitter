//! rfs: Next-Gen High-Performance Cryptographic File Splitter & Reconstructor (v3.0.0 Rust)
//! Copyright (c) 2026 Meik Augenblick (LGPL v3)

mod benchmark;
mod crypto;
mod entropy;
mod format;
mod pipeline;
mod types;

use std::env;
use std::path::Path;
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
        "  rfs split [Optionen] <Quelle|-> [Teil1 Teil2]   (Datei oder Stdin in 2 Teile splitten)"
    );
    println!("  rfs restore [Optionen] <Teil1> <Teil2> [Ziel|-] (Datei auf Platte oder Stdout wiederherstellen)");
    println!("  rfs verify [Optionen] <Teil1> <Teil2>          (Integrität im RAM prüfen ohne Schreiben)");
    println!("\nKlassische Syntax:");
    println!("  rfs [Optionen] <Datei|->                       (Datei oder Stdin splitten)");
    println!("  rfs [Optionen] <Teil1> <Teil2>                 (Datei wiederherstellen)");
    println!("  rfs --verify <Teil1> <Teil2>                   (Integrität prüfen)");
    println!("\nUnix Streaming-Pipes:");
    println!("  tar -czf - /data | rfs split - teil1.rfs teil2.rfs");
    println!("  rfs restore teil1.rfs teil2.rfs -o - | tar -xzf -");
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
    println!("  -B, --block-size <GRÖSSE>                     I/O-Puffergröße (z. B. 64K, 1M, 4M, 16M; Standard: 4M)");
    println!("  -o, --output <PFAD>                           Präfix für Teile bzw. Pfad der Zieldatei (oder '-' für stdout)");
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
            eprintln!("Verwendung: rfs -a <Datei>");
            process::exit(1);
        }
        if let Err(e) = entropy::analyze_file_entropy(Path::new(&args[2])) {
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
            eprintln!("Verwendung: rfs analyze <Datei>");
            process::exit(1);
        }
        if let Err(e) = entropy::analyze_file_entropy(Path::new(&args[2])) {
            eprintln!("Fehler: {}", e);
            process::exit(1);
        }
        return;
    }

    // Flag-Parsing
    let mut verify_only = false;
    let mut force = false;
    let mut silent = false;
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
            } else if positionals.len() == 1 {
                Action::Split
            } else if positionals.len() == 2 {
                Action::Restore
            } else if positionals.len() == 3 {
                if positionals[0] == "-" {
                    Action::Split
                } else if positionals[2] == "-"
                    || positionals[0].ends_with(".rfs1")
                    || positionals[1].ends_with(".rfs2")
                {
                    Action::Restore
                } else if Path::new(&positionals[0]).exists()
                    && !Path::new(&positionals[1]).exists()
                {
                    Action::Split
                } else {
                    Action::Restore
                }
            } else {
                eprintln!(
                    "Fehler: Zu viele Positionsargumente. Erwartet 1 (Split) oder 2-3 (Restore)."
                );
                process::exit(1);
            }
        }
    };

    match action {
        Action::Split => {
            if positionals.is_empty() {
                eprintln!("Fehler: Keine Eingabedatei für Split angegeben.");
                process::exit(1);
            }
            let input_source = &positionals[0];
            let output_parts = if positionals.len() >= 3 {
                Some((Path::new(&positionals[1]), Path::new(&positionals[2])))
            } else {
                None
            };

            match pipeline::split_stream_or_file(
                input_source,
                output_parts,
                output_path.as_deref(),
                block_size,
                silent,
                force,
            ) {
                Ok(_) => process::exit(0),
                Err(e) => {
                    eprintln!("Fehler beim Splitten: {}", e);
                    process::exit(1);
                }
            }
        }
        Action::Restore => {
            if positionals.len() < 2 {
                eprintln!("Fehler: Restore erfordert mindestens 2 Split-Dateien.");
                process::exit(1);
            }
            let p1 = Path::new(&positionals[0]);
            let p2 = Path::new(&positionals[1]);
            let target_arg = if positionals.len() >= 3 {
                Some(positionals[2].as_str())
            } else {
                output_path.as_deref()
            };

            match pipeline::restore_file(p1, p2, target_arg, force, silent, false, block_size) {
                Ok(restored_path_opt) => {
                    if !silent {
                        if let Some(restored) = restored_path_opt {
                            println!("Erfolgreich wiederhergestellt: {}", restored.display());
                        }
                    }
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Fehler bei der Wiederherstellung: {}", e);
                    process::exit(1);
                }
            }
        }
        Action::Verify => {
            if positionals.len() < 2 {
                eprintln!("Fehler: Verify erfordert 2 Split-Dateien zur Prüfung.");
                process::exit(1);
            }
            let p1 = Path::new(&positionals[0]);
            let p2 = Path::new(&positionals[1]);

            match pipeline::restore_file(p1, p2, None, force, silent, true, block_size) {
                Ok(_) => process::exit(0),
                Err(e) => {
                    eprintln!("Fehler bei der Verifikation: {}", e);
                    process::exit(1);
                }
            }
        }
    }
}
