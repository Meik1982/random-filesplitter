//! rfs: Next-Gen High-Performance Cryptographic File Splitter & Reconstructor (v3.0.0 Rust)
//! Copyright (c) 2026 Meik Augenblick (LGPL v3)

#![warn(missing_docs)]

mod benchmark;
mod cli;
mod crypto;
mod decoy;
mod entropy;
mod fadvise;
mod format;
mod memlock;
mod naming;
mod pipeline;
mod telemetry;
mod types;

use std::env;
use std::process;

use cli::{display_help, display_version, parse_cli_args, CliCommand};

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = match parse_cli_args(&args) {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    match command {
        CliCommand::Help => {
            display_help();
            process::exit(0);
        }
        CliCommand::Version => {
            display_version();
            process::exit(0);
        }
        CliCommand::Benchmark => {
            let code = benchmark::run_benchmark();
            process::exit(code);
        }
        CliCommand::Entropy => {
            let code = entropy::run_entropy_diagnostics();
            process::exit(code);
        }
        CliCommand::Analyze { file, json_mode } => {
            if let Err(e) = entropy::analyze_file_entropy(&file, json_mode) {
                eprintln!("Fehler: {}", e);
                process::exit(1);
            }
            process::exit(0);
        }
        CliCommand::Split {
            input,
            parts,
            num_parts,
            num_decoys,
            pad_to,
            output_prefix,
            block_size,
            telemetry_mode,
            force,
            direct_io,
            mlock,
        } => {
            match pipeline::split_stream_or_file(
                &input,
                parts.as_deref(),
                num_parts,
                num_decoys,
                pad_to,
                output_prefix.as_deref(),
                block_size,
                telemetry_mode,
                force,
                direct_io,
                mlock,
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
        CliCommand::Restore {
            parts,
            output_target,
            block_size,
            telemetry_mode,
            force,
            direct_io,
            mlock,
        } => {
            match pipeline::restore_file(
                &parts,
                output_target.as_deref(),
                force,
                telemetry_mode,
                false,
                block_size,
                direct_io,
                mlock,
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
        CliCommand::Verify {
            parts,
            block_size,
            telemetry_mode,
            force,
            direct_io,
            mlock,
        } => {
            match pipeline::restore_file(
                &parts,
                None,
                force,
                telemetry_mode,
                true,
                block_size,
                direct_io,
                mlock,
            ) {
                Ok(_) => process::exit(0),
                Err(e) => {
                    if telemetry_mode != telemetry::TelemetryMode::Json {
                        eprintln!("Fehler bei der Verifikation: {}", e);
                    }
                    process::exit(1);
                }
            }
        }
        CliCommand::Decoy {
            template,
            size,
            count,
            token_mode,
            output_path,
            block_size,
            telemetry_mode,
            force,
            direct_io,
        } => {
            let interactive = telemetry_mode == telemetry::TelemetryMode::Interactive;
            let (target_size, base_name) =
                match decoy::determine_decoy_size(template.as_deref(), size, interactive) {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("Fehler: {}", e);
                        process::exit(1);
                    }
                };

            if let Err(e) = decoy::generate_decoy_files(
                target_size,
                count,
                token_mode,
                output_path.as_deref(),
                base_name.as_deref(),
                block_size,
                telemetry_mode,
                force,
                direct_io,
            ) {
                if telemetry_mode != telemetry::TelemetryMode::Json {
                    eprintln!("Fehler bei der Köder-Erzeugung: {}", e);
                }
                process::exit(1);
            }
            process::exit(0);
        }
    }
}
