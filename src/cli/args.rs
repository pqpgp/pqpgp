//! Command-line argument parsing for PQPGP.

use crate::{crypto::Algorithm, Result};
use std::env;
use std::path::PathBuf;
use std::process;

/// Command-line interface commands
#[derive(Debug)]
pub enum Command {
    GenerateKey {
        algorithm: Algorithm,
        user_id: String,
        password_protected: bool,
    },
    ListKeys,
    Import {
        file: PathBuf,
    },
    Export {
        user_id: String,
        file: Option<PathBuf>,
    },
    Encrypt {
        recipient: String,
        input_file: PathBuf,
        output_file: PathBuf,
    },
    Decrypt {
        input_file: PathBuf,
        output_file: PathBuf,
    },
    Sign {
        key_id: String,
        input_file: PathBuf,
        output_file: PathBuf,
    },
    Verify {
        input_file: PathBuf,
        signature_file: PathBuf,
    },
}

/// Parse command line arguments into a Command
pub fn parse_args() -> Result<Command> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "generate-key" => {
            if args.len() < 4 {
                eprintln!("Error: generate-key requires algorithm and user ID");
                eprintln!("Usage: pqpgp generate-key <algorithm> <user_id> [--password]");
                process::exit(1);
            }

            let algorithm = match args[2].as_str() {
                "mlkem768" => Algorithm::Mlkem768,
                "mldsa65" => Algorithm::Mldsa65,
                _ => {
                    eprintln!("Error: Unsupported algorithm '{}'", args[2]);
                    eprintln!("Supported algorithms: mlkem768, mldsa65");
                    process::exit(1);
                }
            };

            // Check for --password flag
            let password_protected = args.len() > 4 && args[4] == "--password";

            Ok(Command::GenerateKey {
                algorithm,
                user_id: args[3].clone(),
                password_protected,
            })
        }

        "list-keys" => Ok(Command::ListKeys),

        "import" => {
            if args.len() < 3 {
                eprintln!("Error: import requires file path");
                process::exit(1);
            }
            Ok(Command::Import {
                file: PathBuf::from(&args[2]),
            })
        }

        "export" => {
            if args.len() < 3 {
                eprintln!("Error: export requires user ID");
                process::exit(1);
            }
            Ok(Command::Export {
                user_id: args[2].clone(),
                file: args.get(3).map(PathBuf::from),
            })
        }

        "encrypt" => {
            if args.len() < 5 {
                eprintln!("Error: encrypt requires recipient, input file, and output file");
                process::exit(1);
            }
            Ok(Command::Encrypt {
                recipient: args[2].clone(),
                input_file: PathBuf::from(&args[3]),
                output_file: PathBuf::from(&args[4]),
            })
        }

        "decrypt" => {
            if args.len() < 4 {
                eprintln!("Error: decrypt requires input file and output file");
                process::exit(1);
            }
            Ok(Command::Decrypt {
                input_file: PathBuf::from(&args[2]),
                output_file: PathBuf::from(&args[3]),
            })
        }

        "sign" => {
            if args.len() < 5 {
                eprintln!("Error: sign requires key ID, input file, and output file");
                process::exit(1);
            }
            Ok(Command::Sign {
                key_id: args[2].clone(),
                input_file: PathBuf::from(&args[3]),
                output_file: PathBuf::from(&args[4]),
            })
        }

        "verify" => {
            if args.len() < 4 {
                eprintln!("Error: verify requires input file and signature file");
                process::exit(1);
            }
            Ok(Command::Verify {
                input_file: PathBuf::from(&args[2]),
                signature_file: PathBuf::from(&args[3]),
            })
        }

        _ => {
            eprintln!("Error: Unknown command '{}'", args[1]);
            print_usage();
            process::exit(1);
        }
    }
}

/// Print usage information
pub fn print_usage() {
    println!("PQPGP - Post-Quantum Pretty Good Privacy");
    println!("=========================================");
    println!();
    println!("Usage: pqpgp <command> [args...]");
    println!();
    println!("Commands:");
    println!("  generate-key <algorithm> <user_id> [--password]  Generate a new key pair");
    println!("  list-keys                                        List all keys in keyring");
    println!("  import <file>                                    Import keys from file");
    println!(
        "  export <user_id> [file]                          Export public key to file or stdout"
    );
    println!("  encrypt <recipient> <input> <output>             Encrypt file for recipient");
    println!("  decrypt <input> <output>                         Decrypt file");
    println!("  sign <key_id> <input> <output>                   Sign file with key");
    println!("  verify <input> <signature>                       Verify signature");
    println!();
    println!("Algorithms:");
    println!("  mlkem768     - ML-KEM-768 for encryption");
    println!("  mldsa65      - ML-DSA-65 for signatures");
    println!();
    println!("Examples:");
    println!("  pqpgp generate-key mlkem768 'Alice <alice@example.com>'");
    println!("  pqpgp generate-key mldsa65 'Bob <bob@example.com>' --password");
    println!("  pqpgp encrypt alice@example.com message.txt encrypted.asc");
    println!("  pqpgp decrypt encrypted.asc decrypted.txt");
    println!("  pqpgp sign A1B2C3D4E5F60708 document.pdf signature.asc");
}
