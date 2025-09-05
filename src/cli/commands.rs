//! Command implementations for the PQPGP CLI.

use crate::{
    armor::{decode, encode, ArmorType},
    cli::utils::{
        create_keyring_manager, format_timestamp, get_keyring_dir, read_file, write_file,
    },
    crypto::{Algorithm, KeyPair},
    keyring::KeyringManager,
    Result,
};
use std::fs;
use std::path::Path;
use std::process;
use tracing::{error, info};

/// Execute generate-key command
pub fn generate_key(algorithm: Algorithm, user_id: &str, password_protected: bool) -> Result<()> {
    let mut keyring = create_keyring_manager()?;

    info!(algorithm = %algorithm, user_id = user_id, "Generating key pair");

    // Generate key pair based on algorithm
    let mut keypair = match algorithm {
        Algorithm::Mlkem1024 => KeyPair::generate_mlkem1024()?,
        Algorithm::Mldsa87 => KeyPair::generate_mldsa87()?,
        _ => {
            return Err(crate::error::PqpgpError::crypto(format!(
                "Unsupported algorithm for key generation: {}",
                algorithm
            )));
        }
    };

    // Handle password protection if requested
    if password_protected {
        let password =
            crate::cli::utils::prompt_for_password("Enter password to protect private key")?;
        keypair.private_key_mut().encrypt_with_password(&password)?;
        info!("Private key encrypted with password");
    }

    // Add to keyring
    keyring.add_keypair(&keypair, Some(user_id.to_string()))?;
    keyring.save()?;

    info!(
        algorithm = %algorithm,
        key_id = format!("{:016X}", keypair.key_id()),
        user_id = user_id,
        public_key_size = keypair.public_key().as_bytes().len(),
        private_key_algorithm = %keypair.private_key().algorithm(),
        "✅ Generated key pair successfully"
    );

    Ok(())
}

/// Execute list-keys command
pub fn list_keys() -> Result<()> {
    let keyring = create_keyring_manager()?;

    info!("Listing public keys in keyring");

    let entries = keyring.list_all_keys();

    if entries.is_empty() {
        info!("No keys found in keyring");
        return Ok(());
    }

    // Show all public keys (list_all_keys returns from public keyring)
    for (_key_id, entry, has_private_key) in &entries {
        info!(
            key_id = format!("{:016X}", entry.public_key.key_id()),
            algorithm = %entry.public_key.algorithm(),
            created = format_timestamp(entry.created),
            expires = entry.expires.map(format_timestamp),
            user_ids = ?entry.user_ids,
            trusted = entry.trusted,
            has_private_key = *has_private_key,
            "Key details"
        );
    }

    Ok(())
}

/// Execute import command
pub fn import(file: &Path) -> Result<()> {
    let keyring_dir = get_keyring_dir()?;
    let mut keyring = KeyringManager::with_directory(&keyring_dir);

    info!(file = %file.display(), "Importing keys from file");

    let data = read_file(file)?;

    // Try to decode as ASCII armor first
    let key_data = if let Ok(armored_data) = decode(&String::from_utf8_lossy(&data)) {
        armored_data.data
    } else {
        // Assume binary format
        data
    };

    match keyring.public_keyring.import_key(&key_data) {
        Ok(_) => {
            info!("✅ Keys imported successfully");
        }
        Err(e) => {
            let error_msg = format!("{:?}", e);
            if error_msg.contains("already exists") {
                info!("✅ Key already exists in keyring (duplicate import ignored)");
            } else {
                return Err(e);
            }
        }
    }

    keyring.save()?;

    Ok(())
}

/// Execute export command
pub fn export(user_id: &str, file: Option<&Path>) -> Result<()> {
    let keyring = create_keyring_manager()?;

    info!(user_id = user_id, "Exporting public key");

    // Find key by user ID first
    let all_entries = keyring.list_all_keys();
    let matching_key = all_entries
        .iter()
        .find(|(_, entry, _)| entry.user_ids.iter().any(|uid| uid.contains(user_id)))
        .ok_or_else(|| {
            crate::error::PqpgpError::key(format!("No key found for user ID: {}", user_id))
        })?;
    let key_id = matching_key.0;
    let exported = keyring.public_keyring.export_key(key_id)?;
    let armored = encode(&exported, ArmorType::PublicKey)?;

    if let Some(file_path) = file {
        write_file(file_path, armored.as_bytes())?;
        info!(file = %file_path.display(), "✅ Public key exported to file");
    } else {
        info!("Public key (armored format)");
        println!("{}", armored);
    }

    Ok(())
}

/// Execute encrypt command
pub fn encrypt(recipient: &str, input_file: &Path, output_file: &Path) -> Result<()> {
    let keyring = create_keyring_manager()?;

    info!(file = %input_file.display(), recipient = recipient, "Encrypting file");

    // Find recipient's public key
    let all_entries = keyring.list_all_keys();
    let matching_entries: Vec<_> = all_entries
        .iter()
        .filter(|(_, entry, _)| entry.user_ids.iter().any(|uid| uid.contains(recipient)))
        .collect();
    if matching_entries.is_empty() {
        return Err(crate::error::PqpgpError::key(format!(
            "No public key found for recipient '{}'",
            recipient
        )));
    }

    let recipient_key = &matching_entries[0].1.public_key;

    // Read message
    let message = read_file(input_file)?;

    // Encrypt message
    let encrypted = crate::crypto::encrypt_message(recipient_key, &message)?;

    // Serialize and armor
    let serialized = bincode::serialize(&encrypted).map_err(|e| {
        crate::error::PqpgpError::serialization(format!(
            "Failed to serialize encrypted message: {}",
            e
        ))
    })?;
    let armored = encode(&serialized, ArmorType::Message)?;

    // Write to output file
    write_file(output_file, armored.as_bytes())?;

    info!(output_file = %output_file.display(), "✅ File encrypted and saved");

    Ok(())
}

/// Execute decrypt command
pub fn decrypt(input_file: &Path, output_file: &Path) -> Result<()> {
    let keyring = create_keyring_manager()?;

    info!(file = %input_file.display(), "Decrypting file");

    // Read encrypted file
    let armored_data = fs::read_to_string(input_file)?;
    let armored = decode(&armored_data)?;
    let encrypted_message: crate::crypto::EncryptedMessage = bincode::deserialize(&armored.data)
        .map_err(|e| {
            crate::error::PqpgpError::serialization(format!(
                "Failed to deserialize encrypted message: {}",
                e
            ))
        })?;

    // Find matching private key
    let all_entries = keyring.list_all_keys();
    let entries_with_private: Vec<_> = all_entries
        .iter()
        .filter_map(|(key_id, _entry, has_private)| {
            if *has_private {
                // Get the actual private key from the private keyring
                keyring
                    .get_private_key(*key_id)
                    .map(|private_key| (*key_id, private_key))
            } else {
                None
            }
        })
        .collect();

    let mut decrypted = None;

    // Try to decrypt with available keys
    for (key_id, private_key) in entries_with_private.iter() {
        // Check if this key matches the target recipient
        if *key_id == encrypted_message.recipient_key_id() {
            // Try without password first
            if let Ok(message) =
                crate::crypto::decrypt_message(private_key, &encrypted_message, None)
            {
                decrypted = Some(message);
                break;
            }

            // If that fails and key is encrypted, prompt for password
            if private_key.is_encrypted() {
                match crate::cli::utils::prompt_for_password("Enter password for private key") {
                    Ok(password) => {
                        if let Ok(message) = crate::crypto::decrypt_message(
                            private_key,
                            &encrypted_message,
                            Some(&password),
                        ) {
                            decrypted = Some(message);
                            break;
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to read password");
                        continue;
                    }
                }
            }
        }
    }

    // If exact match failed, try all other keys
    if decrypted.is_none() {
        for (key_id, private_key) in entries_with_private {
            if key_id != encrypted_message.recipient_key_id() {
                // Try without password first
                if let Ok(message) =
                    crate::crypto::decrypt_message(private_key, &encrypted_message, None)
                {
                    decrypted = Some(message);
                    break;
                }

                // If that fails and key is encrypted, prompt for password
                if private_key.is_encrypted() {
                    match crate::cli::utils::prompt_for_password("Enter password for private key") {
                        Ok(password) => {
                            if let Ok(message) = crate::crypto::decrypt_message(
                                private_key,
                                &encrypted_message,
                                Some(&password),
                            ) {
                                decrypted = Some(message);
                                break;
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to read password");
                            continue;
                        }
                    }
                }
            }
        }
    }

    let message = decrypted.ok_or_else(|| {
        crate::error::PqpgpError::crypto("Failed to decrypt message with available private keys")
    })?;

    // Write decrypted message
    write_file(output_file, &message)?;

    info!(output_file = %output_file.display(), "✅ File decrypted and saved");

    Ok(())
}

/// Execute sign command
pub fn sign(key_id_str: &str, input_file: &Path, output_file: &Path) -> Result<()> {
    let keyring = create_keyring_manager()?;

    info!(
        file = %input_file.display(),
        key_id = key_id_str,
        "Signing file"
    );

    // Parse key ID
    let key_id = u64::from_str_radix(key_id_str, 16).map_err(|_| {
        crate::error::PqpgpError::key(format!("Invalid key ID format: {}", key_id_str))
    })?;

    // Find private key
    let all_entries = keyring.list_all_keys();
    let entries_with_private: Vec<_> = all_entries
        .iter()
        .filter_map(|(entry_key_id, _entry, has_private)| {
            if *has_private && *entry_key_id == key_id {
                keyring
                    .get_private_key(*entry_key_id)
                    .map(|private_key| (*entry_key_id, private_key))
            } else {
                None
            }
        })
        .collect();

    let signing_key = entries_with_private
        .iter()
        .map(|(_, private_key)| private_key)
        .next()
        .ok_or_else(|| {
            crate::error::PqpgpError::key(format!("No private key found for ID: {}", key_id_str))
        })?;

    // Read message
    let message = read_file(input_file)?;

    // Sign message - check if password is needed
    let signature = if signing_key.is_encrypted() {
        let password = crate::cli::utils::prompt_for_password("Enter password for signing key")?;
        crate::crypto::sign_message(signing_key, &message, Some(&password))?
    } else {
        crate::crypto::sign_message(signing_key, &message, None)?
    };

    // Serialize and armor
    let serialized = bincode::serialize(&signature).map_err(|e| {
        crate::error::PqpgpError::serialization(format!("Failed to serialize signature: {}", e))
    })?;
    let armored = encode(&serialized, ArmorType::Signature)?;

    // Write signature
    write_file(output_file, armored.as_bytes())?;

    info!(
        output_file = %output_file.display(),
        "✅ File signed and signature saved"
    );

    Ok(())
}

/// Execute verify command
pub fn verify(input_file: &Path, signature_file: &Path) -> Result<()> {
    let keyring = create_keyring_manager()?;

    info!(
        file = %input_file.display(),
        signature_file = %signature_file.display(),
        "Verifying signature"
    );

    // Read message and signature
    let message = read_file(input_file)?;
    let armored_sig = fs::read_to_string(signature_file)?;
    let sig_armored = decode(&armored_sig)?;
    let signature: crate::crypto::Signature =
        bincode::deserialize(&sig_armored.data).map_err(|e| {
            crate::error::PqpgpError::serialization(format!(
                "Failed to deserialize signature: {}",
                e
            ))
        })?;

    // Find public key for signature
    let all_entries = keyring.list_all_keys();
    let verifying_key = all_entries
        .iter()
        .find(|(key_id, _entry, _has_private)| *key_id == signature.key_id)
        .map(|(_, entry, _)| &entry.public_key)
        .ok_or_else(|| {
            crate::error::PqpgpError::key(format!(
                "No public key found for signature key ID: {:016X}",
                signature.key_id
            ))
        })?;

    // Verify signature
    match crate::crypto::verify_signature(verifying_key, &message, &signature) {
        Ok(()) => {
            info!("✅ Signature is valid");
        }
        Err(e) => {
            error!(error = %e, "❌ Signature is invalid");
            process::exit(1);
        }
    }

    Ok(())
}
