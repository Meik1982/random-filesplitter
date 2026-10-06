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
    println!("  rfs [Optionen] <Datei>                 (Datei in 2 Teile splitten)");
    println!("  rfs [Optionen] <Teil1> <Teil2>         (Datei wiederherstellen)");
    println!("  rfs --verify <Teil1> <Teil2>           (Integrität im RAM prüfen ohne Schreiben)");
    println!("\nBefehle & Werkzeuge:");
    println!("  -b, --benchmark                        Hardware- und Durchsatz-Benchmark");
    println!("  -e, --entropy-test                     Zweiphasige Entropie- & Jitter-Diagnose");
    println!("  -a, --analyze <Datei>                  Kryptoanalytische Datei-Entropieanalyse");
    println!("  -h, --help                             Diese Hilfe anzeigen");
    println!("  -v, --version                          Versionsnummer anzeigen");
    println!("\nOptionen:");
    println!("  -B, --block-size <GRÖSSE>              I/O-Puffergröße (z. B. 64K, 1M, 4M, 16M; Standard: 4M)");
    println!("  -o, --output <PFAD>                    Präfix für Teile bzw. Pfad der Zieldatei");
    println!("  -f, --force                            Zieldateien überschreiben falls vorhanden");
    println!("  -q, --quiet, --silent                  Ausgabe stummschalten (nur Fehler)\n");
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
    if first == "-v" || first == "--version" {
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

    // Flag-Parsing
    let mut verify_only = false;
    let mut force = false;
    let mut silent = false;
    let mut block_size = types::DEFAULT_BLOCK_SIZE;
    let mut output_path: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();

    let mut i = 1;
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
        } else if !arg.starts_with('-') {
            positionals.push(arg.clone());
        } else {
            eprintln!("Fehler: Unbekannte Option '{}'", arg);
            eprintln!("Führen Sie 'rfs --help' für Hilfe aus.");
            process::exit(1);
        }
        i += 1;
    }

    if positionals.is_empty() {
        eprintln!("Fehler: Keine Eingabedatei(en) angegeben.");
        process::exit(1);
    }

    // Modus-Entscheidung: 1 Datei -> Split, 2 Dateien -> Restore / Verify
    if positionals.len() == 1 {
        let input = Path::new(&positionals[0]);
        if !input.exists() {
            eprintln!(
                "Fehler: Eingabedatei '{}' existiert nicht.",
                input.display()
            );
            process::exit(1);
        }
        match pipeline::split_file(input, output_path.as_deref(), block_size, silent) {
            Ok(_) => process::exit(0),
            Err(e) => {
                eprintln!("Fehler beim Splitten: {}", e);
                process::exit(1);
            }
        }
    } else if positionals.len() == 2 {
        let p1 = Path::new(&positionals[0]);
        let p2 = Path::new(&positionals[1]);
        if !p1.exists() || !p2.exists() {
            eprintln!("Fehler: Eine oder beide Split-Dateien existieren nicht.");
            process::exit(1);
        }
        match pipeline::restore_file(p1, p2, output_path.as_deref(), force, silent, verify_only) {
            Ok(restored) => {
                if !silent && !verify_only {
                    println!("Erfolgreich wiederhergestellt: {}", restored.display());
                }
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Fehler bei der Wiederherstellung: {}", e);
                process::exit(1);
            }
        }
    } else {
        eprintln!("Fehler: Zu viele Positionsargumente. Erwartet 1 (Split) oder 2 (Restore).");
        process::exit(1);
    }
}
