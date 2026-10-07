//! CLI-Modul für Argument-Parsing, Validierung und Nutzerinteraktion.

pub mod parser;

pub use parser::{display_help, display_version, parse_cli_args, CliCommand};
