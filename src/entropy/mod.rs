//! Universal High-Resolution Entropy Harvesting, NIST SP 800-22 Test Suite,
//! and Deep Cryptographic Randomness Diagnostics.

pub mod harvester;
pub mod report;
pub mod stats;

pub use harvester::UniversalEntropyHarvester;
pub use report::{analyze_file_entropy, run_entropy_diagnostics};
#[allow(unused_imports)]
pub use stats::{chi_square_p_value, erfc};

#[cfg(test)]
#[allow(unused_imports)]
pub use stats::tests;
