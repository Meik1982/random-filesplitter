//! CLI argument parser and command configuration for random-filesplitter.
//!
//! Provides a unified, ergonomic command-line interface supporting:
//! - Subcommands: `split`, `restore`, `verify`, `decoy`, `scan`, `forge`, `benchmark`, `entropy`, `analyze`
//! - Context-sensitive help: `rfs <subcommand> --help`
//! - Classic 2-way and N-way syntax for Unix pipes and scripting
//! - Detailed, actionable error messages with usage examples

use std::path::PathBuf;

use crate::telemetry::TelemetryMode;
use crate::types;

/// Backward-compatible alias for `parse_args`.
pub fn parse_cli_args<I, T>(args_iter: I) -> Result<CliCommand, String>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    parse_args(args_iter)
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
    println!("  rfs scan [options] <candidate_files...>        (Auto-discover & assemble valid OTP sets)");
    println!("  rfs forge <shares...> --reveal-as <decoy> -o <out> (Synthesize plausible deniability decoy)");
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
    println!("  rfs split -n 3 secret.iso --decoy-reveal doc.pdf (Embed authentic plaintext decoy into shares)");
    println!(
        "  rfs restore secret.rfs1 secret.rfs2 secret.rfs3 (Bit-exact restore from all 3 shares)"
    );
    println!("  rfs scan /backup/*.rfs -r -o ./restored        (Scan folder and auto-reconstruct all valid sets)");
    println!("  rfs forge share1.rfs --reveal-as harmless.pdf -o fake2.rfs (Rubber-hose defense counterpart)");
    println!(
        "  tar -czf - /data | rfs split -n 4 - -o backup  (Stream stdin directly into 4 shares)"
    );
    println!("  rfs restore backup.rfs* -o - | tar -xzf -      (Pipe restored stream directly to stdout)");

    println!("\nCommands & Tools:");
    println!("  -b, --benchmark                                Run hardware throughput benchmark");
    println!("  -e, --entropy-test                            Run two-phase entropy and jitter diagnostics");
    println!("  -a, --analyze <file>                          Cryptanalytic NIST SP 800-22 file analysis");
    println!("  -h, --help                                    Display this help message");
    println!("  -V, --version                                 Display version information");

    println!("\nOptions:");
    println!("  -n, --parts <COUNT>                           Number of shares for N-way splitting (2 to 64; default: 2)");
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
    println!(
        "  -f, --force                                   Overwrite existing destination files"
    );
    println!("  -q, --quiet, --silent                         Suppress interactive progress (errors only)");
    println!("  -l, --lang <CODE>                             Language code (en [default], de, es, fr, ja, zh, tok)");
    println!("\nTip: Run 'rfs <subcommand> --help' for detailed options on a specific command.\n");
}

/// Displays context-sensitive help for a specific subcommand.
pub fn display_subcommand_help(subcommand: &str) {
    display_version();
    match subcommand {
        "split" => {
            println!("\nSubcommand: rfs split");
            println!("Splits one or multiple files into One-Time-Pad shares with ChaCha20 entropy and RFS4 cluster padding.\n");
            println!("Usage:");
            println!("  rfs split [options] <source|-> [shares...]");
            println!(
                "  rfs split <file1> <file2> [file3...] -n <SHARES> [-T <THRESHOLD>] -o <DIR>"
            );
            println!("\nOptions:");
            println!(
                "  -n, --parts <COUNT>       Number of shares to generate (2..64, default: 2)"
            );
            println!(
                "  -T, --threshold <COUNT>   Subset threshold for Multi-Payload LSSS over GF(2) (default: N-1)"
            );
            println!("  -d, --decoys <COUNT>      Generate additional decoy chaff files with random noise");
            println!("  --decoy-reveal <FILE>     Embed an authentic plaintext decoy (simultaneous multi-payload)");
            println!(
                "  --pad-to <SIZE>           Pad all shares to an exact byte size (e.g. 500M, 10G)"
            );
            println!(
                "  -o, --output <PATH>       Directory or filename prefix for generated shares"
            );
            println!("  -B, --block-size <SIZE>   I/O buffer block size (64K..256M, default: 4M)");
            println!(
                "  --direct                  Bypass OS page cache with O_DIRECT / posix_fadvise"
            );
            println!(
                "  --mlock                   Lock memory buffers in physical RAM (no swap paging)"
            );
            println!(
                "  --json                    Emit structured NDJSON progress events to stderr"
            );
            println!("  -f, --force               Overwrite existing output files");
            println!("  -q, --quiet               Suppress interactive progress bar");
            println!("\nExamples:");
            println!("  rfs split confidential.pdf");
            println!("  rfs split vault.kdbx vacation.pdf invoice.xlsx -n 5 -T 3 -o ./shares/");
            println!("  rfs split -n 3 database.kdbx -o /media/usb/");
            println!("  rfs split secret.iso -n 3 --decoy-reveal harmless.pdf -o shares/");
            println!("  tar -czf - /data | rfs split -n 4 - -o backup");
        }
        "restore" => {
            println!("\nSubcommand: rfs restore");
            println!("Reconstructs the original plaintext from N OTP shares using SIMD-XOR and verifies BLKS-384 PQ integrity.\n");
            println!("Usage:");
            println!("  rfs restore [options] <shares...> [target|-]");
            println!("\nOptions:");
            println!(
                "  -o, --output <PATH>       Destination file or directory (or '-' for stdout)"
            );
            println!("  -B, --block-size <SIZE>   I/O buffer block size (default: 4M)");
            println!("  --direct                  Bypass OS page cache");
            println!("  --mlock                   Lock buffer memory in RAM");
            println!("  --json                    Machine-readable NDJSON telemetry");
            println!("  -f, --force               Overwrite destination file if it exists");
            println!("  -q, --quiet               Errors only");
            println!("\nExamples:");
            println!("  rfs restore share1.rfs share2.rfs");
            println!("  rfs restore /media/shares/*.rfs -o restored.pdf");
            println!("  rfs restore backup.*.rfs -o - | tar -xzf -");
        }
        "scan" => {
            println!("\nSubcommand: rfs scan");
            println!("Combinatorial auto-discovery & assembly engine for arbitrary pools of .rfs files.\n");
            println!("Usage:");
            println!("  rfs scan [options] <candidate_files...>");
            println!("\nOptions:");
            println!(
                "  -r, --restore             Auto-reconstruct all discovered valid sets to disk"
            );
            println!("  -o, --output <DIR>        Destination directory for reconstructed files");
            println!("  -f, --force               Overwrite existing files during restore");
            println!("  -q, --quiet               Suppress banner output");
            println!("\nExamples:");
            println!("  rfs scan /mnt/usb/*.rfs");
            println!("  rfs scan /mnt/usb/*.rfs -r -o ./recovered");
        }
        "forge" => {
            println!("\nSubcommand: rfs forge");
            println!("Synthesizes a plausible deniability decoy counterpart share (Rubber-Hose Defense).\n");
            println!("Usage:");
            println!("  rfs forge [options] <existing_shares...> --reveal-as <decoy_file> -o <fake_share>");
            println!("\nOptions:");
            println!(
                "  --reveal-as <FILE>        Plaintext file to reveal upon combination (REQUIRED)"
            );
            println!(
                "  -o, --output <PATH>       Output path for the synthesized fake share (REQUIRED)"
            );
            println!("  -B, --block-size <SIZE>   I/O buffer block size (default: 4M)");
            println!("  --direct                  Bypass OS page cache");
            println!("  -f, --force               Overwrite output file if it exists");
            println!("\nExample:");
            println!("  rfs forge share1.rfs --reveal-as family_vacation.pdf -o share2_fake.rfs");
        }
        "verify" => {
            println!("\nSubcommand: rfs verify");
            println!("Verifies BLKS-384 PQ checksum and RFS4 trailer integrity in RAM without disk writes.\n");
            println!("Usage:");
            println!("  rfs verify [options] <shares...>");
            println!("\nExamples:");
            println!("  rfs verify share1.rfs share2.rfs share3.rfs");
        }
        "decoy" => {
            println!("\nSubcommand: rfs decoy");
            println!(
                "Generates standalone ChaCha20 random chaff files matching genuine share sizes.\n"
            );
            println!("Usage:");
            println!("  rfs decoy [options] [-t <template>] [-s <size>]");
            println!("\nOptions:");
            println!(
                "  -t, --template <FILE>     Template file to match size (+64B footer or RFS 1:1)"
            );
            println!("  -s, --size <SIZE>         Explicit byte size (e.g. 10M, 1G)");
            println!("  -c, --count <COUNT>       Number of decoy files to generate (default: 1)");
            println!("  -o, --output <PATH>       Directory or filename prefix for decoys");
            println!("\nExamples:");
            println!("  rfs decoy -t secret.pdf -c 3");
            println!("  rfs decoy -s 100M -c 5 -o chaff_pool");
        }
        _ => {
            display_help();
        }
    }
    println!();
}

/// Displays version and license information on stdout.
pub fn display_version() {
    println!(
        "rfs version {} (Format: RFS4, Rust Edition 2021)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Copyright (c) 2026 Meik Augenblick (LGPL v3)");
}

/// Fully parsed CLI action with all validated arguments.
#[derive(Debug, PartialEq, Eq)]
pub enum CliCommand {
    /// Display top-level help text
    Help(Option<String>),
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
        decoy_reveal: Option<PathBuf>,
        pad_to: Option<u64>,
        output_prefix: Option<String>,
        block_size: usize,
        telemetry_mode: TelemetryMode,
        force: bool,
        direct_io: bool,
        mlock: bool,
    },
    /// Split multiple plaintext files into M shares with threshold T over GF(2)
    MultiSplit {
        payloads: Vec<PathBuf>,
        num_shares: usize,
        threshold: Option<usize>,
        num_decoys: usize,
        output_dir: Option<PathBuf>,
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
    /// Verify integrity without writing output
    Verify {
        parts: Vec<PathBuf>,
        block_size: usize,
        telemetry_mode: TelemetryMode,
        force: bool,
        direct_io: bool,
        mlock: bool,
    },
    /// Generate standalone decoy files
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
    /// Combinatorial scan & auto-assembly
    Scan {
        paths: Vec<PathBuf>,
        restore: bool,
        output_dir: Option<PathBuf>,
    },
    /// Plausible deniability decoy forge (Rubber-Hose defense)
    Forge {
        existing_shares: Vec<PathBuf>,
        decoy_path: PathBuf,
        output_share: PathBuf,
        block_size: usize,
        direct_io: bool,
        force: bool,
    },
}

/// Parses raw CLI argument strings into a validated `CliCommand`.
pub fn parse_args<I, T>(args_iter: I) -> Result<CliCommand, String>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    let args: Vec<String> = args_iter.into_iter().map(Into::into).collect();
    if args.len() <= 1 {
        return Ok(CliCommand::Help(None));
    }

    if args.iter().skip(1).all(|a| a == "-h" || a == "--help") {
        return Ok(CliCommand::Help(None));
    }
    if args.iter().skip(1).all(|a| a == "-V" || a == "--version") {
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
    if first == "split"
        || first == "restore"
        || first == "verify"
        || first == "decoy"
        || first == "scan"
        || first == "forge"
    {
        explicit_subcommand = Some(first.as_str());
        start_idx = 2;

        // Context-sensitive help check: e.g. `rfs split --help` or `rfs scan -h`
        if args[start_idx..].iter().any(|a| a == "-h" || a == "--help") {
            return Ok(CliCommand::Help(Some(first.clone())));
        }
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

    let mut verify_only = false;
    let mut force = false;
    let mut silent = false;
    let mut json_output = false;
    let mut direct_io = false;
    let mut mlock = false;
    let mut token_mode = false;
    let mut num_parts: usize = 2;
    let mut num_parts_explicit = false;
    let mut num_decoys: usize = 0;
    let mut decoy_reveal: Option<PathBuf> = None;
    let mut decoy_count: usize = 1;
    let mut decoy_size: Option<u64> = None;
    let mut decoy_template: Option<String> = None;
    let mut block_size = types::DEFAULT_BLOCK_SIZE;
    let mut output_path: Option<String> = None;
    let mut pad_to: Option<u64> = None;
    let mut threshold: Option<usize> = None;
    let mut scan_restore = false;
    let mut forge_decoy_path: Option<PathBuf> = None;
    let mut positionals: Vec<String> = Vec::new();

    let mut i = start_idx;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-v" || arg == "--verify" || arg == "--check" {
            verify_only = true;
        } else if arg == "-f" || arg == "--force" {
            force = true;
        } else if arg == "-r" || arg == "--restore" {
            scan_restore = true;
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
                Ok(n) if (2..=64).contains(&n) => {
                    num_parts = n;
                    num_parts_explicit = true;
                }
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
        } else if arg == "-T" || arg == "--threshold" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a count argument.", arg));
            }
            match args[i].parse::<usize>() {
                Ok(n) if n >= 2 => threshold = Some(n),
                _ => {
                    return Err(format!(
                        "Error: Invalid threshold count for option {}: '{}' (must be >= 2)",
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
        } else if arg == "--decoy-reveal" || arg == "--reveal-decoy" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a file path.", arg));
            }
            decoy_reveal = Some(PathBuf::from(&args[i]));
        } else if arg == "--reveal-as" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a file path.", arg));
            }
            forge_decoy_path = Some(PathBuf::from(&args[i]));
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
                return Err(format!("Error: Option {} requires a template path.", arg));
            }
            decoy_template = Some(args[i].clone());
        } else if arg == "-o" || arg == "--output" {
            i += 1;
            if i >= args.len() {
                return Err(format!("Error: Option {} requires a path argument.", arg));
            }
            output_path = Some(args[i].clone());
        } else if arg == "-l" || arg == "--lang" {
            i += 1;
            if i >= args.len() {
                return Err(format!(
                    "Error: Option {} requires a language code (en, de, es, fr, ja, zh, tok).",
                    arg
                ));
            }
            if crate::i18n::Lang::from_code(&args[i]).is_none() {
                return Err(format!(
                    "Error: Unsupported language '{}'. Supported codes: en, de, es, fr, ja, zh, tok.",
                    args[i]
                ));
            }
        } else if let Some(code) = arg.strip_prefix("--lang=") {
            if crate::i18n::Lang::from_code(code).is_none() {
                return Err(format!(
                    "Error: Unsupported language '{}'. Supported codes: en, de, es, fr, ja, zh, tok.",
                    code
                ));
            }
        } else if arg.starts_with('-') && arg != "-" {
            return Err(format!("Error: Unrecognized option '{}'", arg));
        } else {
            positionals.push(arg.clone());
        }
        i += 1;
    }

    if token_mode && output_path.is_none() {
        output_path = Some(".".to_string());
    }

    let action_str = match explicit_subcommand {
        Some(s) => s,
        None => {
            if verify_only {
                "verify"
            } else if positionals.is_empty() {
                return Ok(CliCommand::Help(None));
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
                return Err(
                    "Error: No input file specified for split.\n\nUsage: rfs split [options] <source|-> [shares...]\n\nMulti-Payload Usage:\n  rfs split <file1> <file2> [file3...] -n <SHARES> [-T <THRESHOLD>] -o <DIR>\n\nExamples:\n  rfs split confidential.pdf\n  rfs split vault.kdbx vacation.pdf invoice.xlsx -n 5 -T 3 -o ./shares/\n  rfs split secret.iso -n 3 --decoy-reveal harmless.pdf\n  cat large.tar | rfs split -n 4 - -o backup"
                        .to_string(),
                );
            }

            // Detect Multi-Payload Split:
            // If >= 2 files are given that all exist on disk, or if -T/--threshold is specified
            let all_exist = positionals.len() > 1
                && positionals.iter().all(|p| std::path::Path::new(p).exists());
            let is_multi_split = (all_exist
                && !positionals[1].ends_with(".rfs")
                && !positionals[1].contains(".part"))
                || (threshold.is_some() && positionals.len() > 1);

            if is_multi_split {
                let n_files = positionals.len();
                let min_required_shares = n_files + 1;

                if num_parts_explicit && num_parts < min_required_shares {
                    return Err(format!(
                        "Error: Specified share count -n {} is too small for {} files.\n\n\
                         Information-Theoretic Rule (Shannon Secrecy over GF(2)):\n\
                         Embedding N files requires at least M >= N + 1 shares.\n\
                         At least 1 share dimension must serve as a ChaCha20 random noise basis.\n\
                         For {} files, specify at least: -n {}",
                        num_parts, n_files, n_files, min_required_shares
                    ));
                }

                let final_shares = num_parts.max(min_required_shares);

                if let Some(t) = threshold {
                    let (min_t, max_t) = crate::matrix::policy::calculate_valid_threshold_range(
                        n_files,
                        final_shares,
                    );
                    if t < min_t || t > max_t {
                        let count = crate::matrix::policy::binomial_coefficient(final_shares, t);
                        return Err(format!(
                            "Error: Threshold -T {} is impossible for {} files on {} shares.\n\n\
                             Combinatorial Rule:\n\
                             Subsets of size {} on {} shares yield only {} combination(s) (C({}, {}) = {}), but {} files must be assigned.\n\
                             Valid threshold range for {} files on {} shares is: -T {}..={}",
                            t, n_files, final_shares,
                            t, final_shares, count, final_shares, t, count, n_files,
                            n_files, final_shares, min_t, max_t
                        ));
                    }
                }

                return Ok(CliCommand::MultiSplit {
                    payloads: positionals.iter().map(PathBuf::from).collect(),
                    num_shares: final_shares,
                    threshold,
                    num_decoys,
                    output_dir: output_path.map(PathBuf::from),
                    block_size,
                    telemetry_mode,
                    force,
                    direct_io,
                    mlock,
                });
            }

            let input = positionals[0].clone();
            let parts: Option<Vec<PathBuf>> = if positionals.len() > 1 {
                Some(positionals[1..].iter().map(PathBuf::from).collect())
            } else {
                None
            };
            let mut final_num_decoys = num_decoys;
            if decoy_reveal.is_some() && final_num_decoys == 0 {
                final_num_decoys = 1;
            }

            Ok(CliCommand::Split {
                input,
                parts,
                num_parts,
                num_decoys: final_num_decoys,
                decoy_reveal,
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
            if positionals.len() < 2 {
                return Err(
                    "Error: At least 2 shares required for restore.\n\nUsage: rfs restore [options] <shares...> [target|-]\n\nExamples:\n  rfs restore part1.rfs part2.rfs\n  rfs restore backup.*.rfs -o restored.tar\n  rfs restore shares/*.rfs -o - | tar -xzf -"
                        .to_string(),
                );
            }
            let (parts, output_target) = match output_path {
                Some(p) => (positionals.iter().map(PathBuf::from).collect(), Some(p)),
                None => {
                    let last = &positionals[positionals.len() - 1];
                    let is_target = !last.ends_with(".rfs")
                        && !last.contains(".part")
                        && !last.contains(".rfs")
                        && positionals.len() > 2;

                    if is_target {
                        let p = positionals[..positionals.len() - 1]
                            .iter()
                            .map(PathBuf::from)
                            .collect();
                        (p, Some(last.clone()))
                    } else {
                        (positionals.iter().map(PathBuf::from).collect(), None)
                    }
                }
            };

            Ok(CliCommand::Restore {
                parts,
                output_target,
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
                    "Error: At least 2 shares required for verify.\n\nUsage: rfs verify [options] <shares...>\n\nExample:\n  rfs verify share1.rfs share2.rfs"
                        .to_string(),
                );
            }
            Ok(CliCommand::Verify {
                parts: positionals.iter().map(PathBuf::from).collect(),
                block_size,
                telemetry_mode,
                force,
                direct_io,
                mlock,
            })
        }
        "scan" => {
            if positionals.len() < 2 {
                return Err(
                    "Error: At least 2 candidate files required for 'scan'.\n\nUsage: rfs scan [options] <candidate_files...>\n\nExamples:\n  rfs scan *.rfs\n  rfs scan /media/backup/*.rfs -r -o ./recovered\n\nOptions:\n  -r, --restore          Auto-reconstruct all discovered sets\n  -o, --output <DIR>     Destination directory for restored files\n  -f, --force            Overwrite existing files"
                        .to_string(),
                );
            }
            Ok(CliCommand::Scan {
                paths: positionals.iter().map(PathBuf::from).collect(),
                restore: scan_restore,
                output_dir: output_path.map(PathBuf::from),
            })
        }
        "forge" => {
            if positionals.is_empty() {
                return Err(
                    "Error: Missing existing share files for 'forge'.\n\nUsage: rfs forge <existing_shares...> --reveal-as <decoy_file> -o <fake_share>\n\nExample:\n  rfs forge share1.rfs --reveal-as decoy.pdf -o share2_fake.rfs"
                        .to_string(),
                );
            }
            let decoy_path = forge_decoy_path.ok_or_else(|| {
                "Error: Option --reveal-as <FILE> is required for 'forge'.\n\nUsage: rfs forge <existing_shares...> --reveal-as <decoy_file> -o <fake_share>\n\nExample:\n  rfs forge share1.rfs --reveal-as decoy.pdf -o share2_fake.rfs".to_string()
            })?;
            let out_fake = output_path.ok_or_else(|| {
                "Error: Output option -o <PATH> is required for 'forge'.\n\nUsage: rfs forge <existing_shares...> --reveal-as <decoy_file> -o <fake_share>\n\nExample:\n  rfs forge share1.rfs --reveal-as decoy.pdf -o share2_fake.rfs".to_string()
            })?;

            Ok(CliCommand::Forge {
                existing_shares: positionals.iter().map(PathBuf::from).collect(),
                decoy_path,
                output_share: PathBuf::from(out_fake),
                block_size,
                direct_io,
                force,
            })
        }
        "decoy" => {
            if decoy_template.is_none() && decoy_size.is_none() {
                return Err(
                    "Error: Please provide either a template file (-t <FILE>) or an explicit size (-s <SIZE>).\n\nUsage: rfs decoy [-t <template>] [-s <size>] [-c <count>] [-o <prefix>]\n\nExamples:\n  rfs decoy -t original.pdf -c 3\n  rfs decoy -s 100M -c 5 -o decoy_pool"
                        .to_string(),
                );
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
        _ => Err(format!(
            "Error: Unrecognized subcommand '{}'. Run 'rfs --help' for available commands.",
            action_str
        )),
    }
}
