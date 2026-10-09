//! CLI module for argument parsing, validation, and user interaction.

pub mod parser;

pub use parser::{display_help, display_version, parse_cli_args, CliCommand};
