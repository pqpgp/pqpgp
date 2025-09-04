//! PQPGP Command Line Interface
//!
//! A post-quantum secure implementation of PGP (Pretty Good Privacy) in Rust.

use pqpgp::cli;
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "pqpgp=info".into()))
        .init();

    if let Err(e) = cli::run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
