//! Typed CLI argument parsing, validation, and help formatting for rfs.

use std::path::{Path, PathBuf};

use crate::telemetry::TelemetryMode;
use crate::types;

const APP_NAME: &str = "rfs";
const APP_VERSION: &str = "3.0.0";
const FORMAT_TAG: &str = "RFS4";

/// Displays version information on stdout.
pub fn display_version() {
    println!(
        "{} version {} (Format: {}, Rust Edition 2021)",
        APP_NAME, APP_VERSION, FORMAT_TAG
    );
    println!("Copyright (c) 2026 Meik Augenblick (LGPL v3)");
}

/// Displays full CLI usage instructions on stdout.
pub fn display_help() {
    display_version();
    println!("\nUsage:");
    println!(
        "  rfs split [options] <source|-> [shares...]     (Split file or stdin into 2 or N shares)"
    );
    println!(
        "  rfs restore [options] <shares...> [target|-]   (Reconstruct N shares to disk or stdout)"
    );
    println!(
        "  rfs verify [options] <shares...>               (Verify integrity of N shares in RAM)"
    );
    println!(
        "  rfs decoy [options] [-t <template>] [-s <size>] (Generate ChaCha20 random decoy files)"
    );
    println!("\nClassic Syntax:");
    println!(
        "  rfs [options] <file|->                         (Split file or stdin into 2 shares)"
    );
    println!("  rfs [options] <part1> <part2> [part3...]       (Reconstruct file from N shares)");
    println!("  rfs --verify <shares...>                       (Verify integrity of N shares)");
    println!("\nN-Way One-Time-Pad & Unix Streaming Pipes:");
    println!("  rfs split -n 3 secret.iso                      (Split into 3 noise shares: .rfs1, .rfs2, .rfs3)");
    println!(
        "  rfs restore secret.rfs1 secret.rfs2 secret.rfs3 (Bit-exact restore from all 3 shares)"
    );
    println!(
        "  tar -czf - /data | rfs split -n 4 - -o backup  (Stream stdin directly into 4 shares)"
    );
    println!("  rfs restore backup.rfs* -o - | tar -xzf -      (Pipe restored stream directly to stdout)");
    println!("\nCommands & Tools:");
    println!("  -b, --benchmark                                Run hardware throughput benchmark");
    println!(
        "  -e, --entropy-test                            Run two-phase entropy and jitter diagnostics"
    );
    println!(
        "  -a, --analyze <file>                          Cryptanalytic NIST SP 800-22 file analysis"
    );
    println!("  -h, --help                                    Display this help message");
    println!("  -V, --version                                 Display version information");
    println!("\nOptions:");
    println!("  -n, --parts <COUNT>                           Number of shares for N-way splitting (2 to 64; default: 2)");
    println!("  -B, --block-size <SIZE>                       I/O buffer block size (e.g., 64K, 1M, 4M, 16M; default: 4M)");
    println!("  -d, --decoys <COUNT>                          Generate additional decoy chaff files during split");
    println!("  --pad-to <SIZE>                               Pad shares to an exact target byte size (e.g., 100M, 20G)");
    println!("  --token, --rnd                                Anti-forensics: Uncorrelated hex tokens (.<rnd>.rfs) instead of numbers");
    println!("  -c, --count <COUNT>                           Number of decoy files for 'rfs decoy' (default: 1)");
    println!("  -s, --size <SIZE>                             Explicit byte size for 'rfs decoy' (e.g., 64K, 10M, 1G)");
    println!("  -t, --template <FILE>                         Template file for 'rfs decoy' (raw file +64B footer or RFS 1:1)");
    println!("  -o, --output <PATH>                           Share prefix or restore target destination (or '-' for stdout)");
    println!("  --direct                                      Direct I/O: Bypass OS page cache for multi-gigabyte transfers");
    println!("  --mlock                                       Lock buffer memory in physical RAM (prevents swap paging)");
    println!("  --json                                        Machine-readable NDJSON telemetry on stderr");
    println!(
        "  -f, --force                                   Overwrite existing destination files"
    );
    println!(
        "  -q, --quiet, --silent                         Suppress interactive progress (errors only)\n"
    );
}

/// Fully parsed CLI action with all validated arguments.
#[derive(Debug, PartialEq, Eq)]
pub enum CliCommand {
    /// Display help text
    Help,
    /// Display version information
    Version,
    /// Run hardware benchmark
    Benchmark,
    /// Run entropy diagnostics
    Entropy,
    /// Cryptanalytic file entropy analysis
    Analyze { file: PathBuf, json_mode: bool },
    /// Split file or stream into N shares
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
        mlock: bool,
    },
    /// Reconstruct from N shares
    Restore {
        parts: Vec<PathBuf>,
        output_target: Option<String>,
        block_size: usize,
        telemetry_mode: TelemetryMode,
        force: bool,
        direct_io: bool,
        mlock: bool,
    },
    /// In-memory RAM integrity check across N shares
    Verify {
        parts: Vec<PathBuf>,
        block_size: usize,
        telemetry_mode: TelemetryMode,
        force: bool,
        direct_io: bool,
        mlock: bool,
    },
    /// Generate ChaCha20 random decoy files
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

/// Parses CLI arguments into a typed `CliCommand`.
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
                "Error: Option {} requires a file path.\nUsage: rfs -a <file> [--json]",
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

    // Subcommand detection
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
                "Error: Subcommand 'analyze' requires a file path.\nUsage: rfs analyze <file> [--json]".to_string(),
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

    // Flag parsing
    let mut verify_only = false;
    let mut force = false;
    let mut silent = false;
    let mut json_output = false;
    let mut direct_io = false;
    let mut mlock = false;
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
        } else if arg == "--mlock" {
            mlock = true;
        } else if arg == "--token" || arg == "--rnd" {
            token_mode = true;
        } else if arg == "--pad-to" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a size argument.", arg));
            }
            pad_to = Some(types::parse_file_size(&args[i])?);
        } else if arg == "-n" || arg == "--parts" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a count argument.", arg));
            }
            match args[i].parse::<usize>() {
                Ok(n) if (2..=64).contains(&n) => num_parts = n,
                Ok(n) => {
                    return Err(format!(
                        "Error: Part count ({}) must be between 2 and 64.",
                        n
                    ));
                }
                Err(_) => {
                    return Err(format!(
                        "Error: Invalid number for option {}: '{}'",
                        arg, args[i]
                    ));
                }
            }
        } else if arg == "-B" || arg == "--block-size" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a size argument.", arg));
            }
            block_size = types::parse_block_size(&args[i])?;
        } else if arg == "-d" || arg == "--decoys" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a count argument.", arg));
            }
            match args[i].parse::<usize>() {
                Ok(n) => num_decoys = n,
                Err(_) => {
                    return Err(format!(
                        "Error: Invalid number for option {}: '{}'",
                        arg, args[i]
                    ));
                }
            }
        } else if arg == "-c" || arg == "--count" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a count argument.", arg));
            }
            match args[i].parse::<usize>() {
                Ok(n) if (1..=1000).contains(&n) => decoy_count = n,
                Ok(n) => {
                    return Err(format!(
                        "Error: Decoy count ({}) must be between 1 and 1000.",
                        n
                    ));
                }
                Err(_) => {
                    return Err(format!(
                        "Error: Invalid number for option {}: '{}'",
                        arg, args[i]
                    ));
                }
            }
        } else if arg == "-s" || arg == "--size" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a size argument.", arg));
            }
            decoy_size = Some(types::parse_file_size(&args[i])?);
        } else if arg == "-t" || arg == "--template" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a file path.", arg));
            }
            decoy_template = Some(args[i].clone());
        } else if arg == "-o" || arg == "--output" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a path.", arg));
            }
            output_path = Some(args[i].clone());
        } else if arg == "-" || !arg.starts_with('-') {
            positionals.push(arg.clone());
        } else {
            return Err(format!(
                "Error: Unknown option '{}'\nRun 'rfs --help' for usage.",
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
                return Err(
                    "Error: No input file(s) specified.\nRun 'rfs --help' for usage.".to_string(),
                );
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
                return Err("Error: No input file specified for split.".to_string());
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
                mlock,
            })
        }
        "restore" => {
            let (parts, target) = parse_restore_targets(&positionals, output_path.as_deref())?;
            if parts.len() < 2 {
                return Err("Error: Restore requires at least 2 share files.".to_string());
            }
            Ok(CliCommand::Restore {
                parts,
                output_target: target,
                block_size,
                telemetry_mode,
                force,
                direct_io,
                mlock,
            })
        }
        "verify" => {
            if positionals.len() < 2 {
                return Err(
                    "Error: Verify requires at least 2 share files for verification.".to_string(),
                );
            }
            let parts: Vec<PathBuf> = positionals.iter().map(PathBuf::from).collect();
            Ok(CliCommand::Verify {
                parts,
                block_size,
                telemetry_mode,
                force,
                direct_io,
                mlock,
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
            "Error: Unknown command '{}'\nRun 'rfs --help' for usage.",
            unknown
        )),
    }
}

/// Separates positional arguments into source shares and optional target destination for `restore`.
pub fn parse_restore_targets(
    positionals: &[String],
    output_flag: Option<&str>,
) -> Result<(Vec<PathBuf>, Option<String>), String> {
    if positionals.is_empty() {
        return Err("No share files specified for restore.".to_string());
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
