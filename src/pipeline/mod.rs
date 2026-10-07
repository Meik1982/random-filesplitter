//! Streaming Split & Restore Engine with Zero-Allocation Triple-Buffering,
//! In-Flight BLKS-384 / SHA-256 Hashing, Unix Pipe Support, N-Way OTP Splitting,
//! and Plausible Deniability Footers.

#![allow(clippy::type_complexity)]

pub mod restore;
pub mod split;

pub use restore::restore_file;
#[allow(unused_imports)]
pub use split::{split_file, split_stream_or_file};

#[allow(unused_imports)]
pub use crate::decoy::{determine_decoy_size, generate_decoy_files};
#[allow(unused_imports)]
pub use crate::naming::{generate_unique_hex_tokens, shuffle_paths};

/// Puffer-Poolgröße für Triple-Buffering (3 Puffer-Slots in-flight)
pub const BUFFER_POOL_SIZE: usize = 3;
