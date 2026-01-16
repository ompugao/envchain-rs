//! Age backend for envchain
//!
//! Stores secrets in an age-encrypted JSON file at ~/.config/envchain/secrets.age
//!
//! Supports:
//! - SSH keys (Ed25519, RSA) - specify with ENVCHAIN_AGE_IDENTITY or --age-identity
//! - Native age identities - auto-generated or specified
//!
//! Note: ssh-agent is NOT supported by the age crate. If your SSH key has a passphrase,
//! you'll be prompted each time. Use an unencrypted SSH key or native age identity
//! for passphrase-free operation.

use super::{Backend, EnvKey, EnvValue, Namespace};
use age::secrecy::ExposeSecret;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

type SecretsStore = HashMap<Namespace, HashMap<EnvKey, EnvValue>>;

pub struct AgeBackend {
    secrets_path: PathBuf,
    identity_path: PathBuf,
    recipient_path: PathBuf,
    secrets: SecretsStore,
}

impl AgeBackend {
    pub fn new(identity_path: Option<PathBuf>) -> Result<Self, String> {
        let config_dir = dirs::config_dir()
            .ok_or("Could not determine config directory")?
            .join("envchain");

        fs::create_dir_all(&config_dir)
            .map_err(|e| format!("Failed to create config dir: {e}"))?;

        let secrets_path = config_dir.join("secrets.age");
        let default_identity_path = config_dir.join("identity.txt");
        let recipient_path = config_dir.join("recipient.txt");

        let identity_path = identity_path
            .or_else(|| std::env::var("ENVCHAIN_AGE_IDENTITY").ok().map(PathBuf::from))
            .unwrap_or(default_identity_path);

        let mut backend = Self {
            secrets_path,
            identity_path,
            recipient_path,
            secrets: HashMap::new(),
        };

        backend.ensure_identity()?;
        backend.load_secrets()?;

        Ok(backend)
    }

    /// Ensure we have an identity (generate native age identity if needed)
    fn ensure_identity(&self) -> Result<(), String> {
        if self.identity_path.exists() {
            return Ok(());
        }

        // Check if it's an SSH key path that doesn't exist
        let path_str = self.identity_path.to_string_lossy();
        if path_str.contains(".ssh/") || path_str.ends_with(".pub") {
            return Err(format!(
                "SSH identity file not found: {}\nGenerate with: ssh-keygen -t ed25519 -f {}",
                self.identity_path.display(),
                self.identity_path.display()
            ));
        }

        // Generate a new native age identity
        eprintln!("Generating new age identity at {}", self.identity_path.display());
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();

        // Save identity
        fs::write(&self.identity_path, identity.to_string().expose_secret())
            .map_err(|e| format!("Failed to write identity: {e}"))?;

        // Restrict permissions on identity file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.identity_path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to set identity permissions: {e}"))?;
        }

        // Save recipient (public key) for convenience
        fs::write(&self.recipient_path, recipient.to_string())
            .map_err(|e| format!("Failed to write recipient: {e}"))?;

        eprintln!("Created age identity. Public key: {}", recipient);
        Ok(())
    }

    /// Load identities from file (supports SSH and native age identities)
    fn load_identities(&self) -> Result<Vec<Box<dyn age::Identity>>, String> {
        let identity_bytes = fs::read(&self.identity_path)
            .map_err(|e| format!("Failed to read identity file {}: {e}", self.identity_path.display()))?;
        let identity_str = String::from_utf8_lossy(&identity_bytes);

        // Try as SSH private key first (OpenSSH format starts with "-----BEGIN")
        if identity_str.contains("-----BEGIN") {
            let identity = age::ssh::Identity::from_buffer(identity_bytes.as_slice(), None)
                .map_err(|e| format!("Failed to parse SSH key: {e}"))?;
            return Ok(vec![Box::new(identity)]);
        }

        // Try parsing as age identity file
        let identities = age::IdentityFile::from_buffer(identity_bytes.as_slice())
            .map_err(|e| format!("Failed to parse identity file: {e}"))?;

        // Convert to boxed identities, prompting for passphrase if needed
        let identities: Vec<Box<dyn age::Identity>> = identities
            .into_identities()
            .map_err(|e| format!("Failed to process identities: {e}"))?;

        if identities.is_empty() {
            return Err("No identities found in identity file".to_string());
        }

        Ok(identities)
    }

    /// Get recipient for encryption
    fn get_recipient(&self) -> Result<Box<dyn age::Recipient + Send>, String> {
        let identity_str = fs::read_to_string(&self.identity_path)
            .map_err(|e| format!("Failed to read identity file: {e}"))?;

        // Try as native age identity first
        if let Ok(identity) = identity_str.trim().parse::<age::x25519::Identity>() {
            return Ok(Box::new(identity.to_public()));
        }

        // Try as SSH key
        for line in identity_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Check for SSH public key format in the identity file
            if line.starts_with("ssh-")
                && let Ok(recipient) = line.parse::<age::ssh::Recipient>()
            {
                return Ok(Box::new(recipient));
            }
        }

        // Try to read corresponding .pub file for SSH private keys
        let pub_path = PathBuf::from(format!("{}.pub", self.identity_path.display()));
        if pub_path.exists() {
            let pub_str = fs::read_to_string(&pub_path)
                .map_err(|e| format!("Failed to read public key file: {e}"))?;
            for line in pub_str.lines() {
                let line = line.trim();
                if line.starts_with("ssh-")
                    && let Ok(recipient) = line.parse::<age::ssh::Recipient>()
                {
                    return Ok(Box::new(recipient));
                }
            }
        }

        Err("Could not determine recipient from identity file".to_string())
    }

    /// Load and decrypt secrets from file
    fn load_secrets(&mut self) -> Result<(), String> {
        if !self.secrets_path.exists() {
            self.secrets = HashMap::new();
            return Ok(());
        }

        let encrypted = fs::read(&self.secrets_path)
            .map_err(|e| format!("Failed to read secrets file: {e}"))?;

        if encrypted.is_empty() {
            self.secrets = HashMap::new();
            return Ok(());
        }

        let identities = self.load_identities()?;

        let decryptor = age::Decryptor::new(&encrypted[..])
            .map_err(|e| format!("Failed to create decryptor: {e}"))?;

        let mut decrypted = vec![];
        let mut reader = decryptor
            .decrypt(identities.iter().map(|i| i.as_ref()))
            .map_err(|e| format!("Decryption failed: {e}"))?;
        reader
            .read_to_end(&mut decrypted)
            .map_err(|e| format!("Failed to read decrypted data: {e}"))?;

        self.secrets = serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Failed to parse secrets JSON: {e}"))?;

        Ok(())
    }

    /// Encrypt and save secrets to file
    fn save_secrets(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.secrets)
            .map_err(|e| format!("Failed to serialize secrets: {e}"))?;

        let recipient = self.get_recipient()?;
        let recipients: Vec<&dyn age::Recipient> = vec![recipient.as_ref()];

        let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
            .map_err(|e| format!("Failed to create encryptor: {e}"))?;

        let mut encrypted = vec![];
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| format!("Failed to create encryption writer: {e}"))?;
        writer
            .write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write encrypted data: {e}"))?;
        writer
            .finish()
            .map_err(|e| format!("Failed to finish encryption: {e}"))?;

        // Write atomically via temp file
        let temp_path = self.secrets_path.with_extension("tmp");
        fs::write(&temp_path, &encrypted)
            .map_err(|e| format!("Failed to write temp file: {e}"))?;
        fs::rename(&temp_path, &self.secrets_path)
            .map_err(|e| format!("Failed to rename secrets file: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.secrets_path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to set secrets file permissions: {e}"))?;
        }

        Ok(())
    }
}

impl Backend for AgeBackend {
    fn list_namespaces(&self) -> Result<Vec<Namespace>, String> {
        let mut namespaces: Vec<_> = self.secrets.keys().cloned().collect();
        namespaces.sort();
        Ok(namespaces)
    }

    fn list_secrets(&self, namespace: &str) -> Result<HashMap<EnvKey, EnvValue>, String> {
        Ok(self.secrets.get(namespace).cloned().unwrap_or_default())
    }

    fn set_secret(&mut self, namespace: &str, key: &str, value: &str) -> Result<(), String> {
        self.secrets
            .entry(namespace.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
        self.save_secrets()
    }

    fn delete_secret(&mut self, namespace: &str, key: &str) -> Result<(), String> {
        if let Some(ns) = self.secrets.get_mut(namespace) {
            ns.remove(key);
            if ns.is_empty() {
                self.secrets.remove(namespace);
            }
        }
        self.save_secrets()
    }
}
