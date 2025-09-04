//! Command-line interface for PQPGP.
//!
//! This module provides a complete CLI for the PQPGP library, including commands
//! for key generation, encryption, decryption, signing, verification, and key management.

pub mod args;
pub mod commands;
pub mod utils;

use crate::Result;
use std::process;

pub use args::Command;
pub use commands::*;
pub use utils::*;

/// Main entry point for the CLI application
pub fn run() -> Result<()> {
    // Parse command line arguments
    let command = match args::parse_args() {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Error parsing arguments: {}", e);
            process::exit(1);
        }
    };

    // Execute command
    let result = match command {
        Command::GenerateKey {
            algorithm,
            user_id,
            password_protected,
        } => commands::generate_key(algorithm, &user_id, password_protected),
        Command::ListKeys => commands::list_keys(),
        Command::Import { file } => commands::import(&file),
        Command::Export { user_id, file } => commands::export(&user_id, file.as_deref()),
        Command::Encrypt {
            recipient,
            input_file,
            output_file,
        } => commands::encrypt(&recipient, &input_file, &output_file),
        Command::Decrypt {
            input_file,
            output_file,
        } => commands::decrypt(&input_file, &output_file),
        Command::Sign {
            key_id,
            input_file,
            output_file,
        } => commands::sign(&key_id, &input_file, &output_file),
        Command::Verify {
            input_file,
            signature_file,
        } => commands::verify(&input_file, &signature_file),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }

    Ok(())
}
