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
use zeroize::{Zeroize, Zeroizing};

type SecretsStore = HashMap<Namespace, HashMap<EnvKey, EnvValue>>;

/// On Windows, restrict `path` to the current user only by removing inherited
/// ACEs and granting Full Control exclusively to the current user.
/// Uses the built-in `icacls` command — no extra dependencies required.
#[cfg(target_os = "windows")]
fn restrict_identity_file_to_owner(path: &PathBuf) -> Result<(), String> {
    let username = std::env::var("USERNAME")
        .map_err(|_| "USERNAME environment variable not set".to_string())?;
    let status = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{username}:F"))
        .status()
        .map_err(|e| format!("Failed to run icacls: {e}"))?;
    if !status.success() {
        return Err(format!("icacls exited with failure for {}", path.display()));
    }
    Ok(())
}

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

        fs::create_dir_all(&config_dir).map_err(|e| format!("Failed to create config dir: {e}"))?;

        // Restrict config directory to owner only so others cannot list its contents.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("Failed to set config dir permissions: {e}"))?;
        }

        let secrets_path = config_dir.join("secrets.age");
        let default_identity_path = config_dir.join("identity.txt");
        let recipient_path = config_dir.join("recipient.txt");

        // Distinguish explicitly-provided paths from the default so that
        // ensure_identity knows whether to auto-generate or error out.
        let explicit_identity = identity_path.or_else(|| {
            std::env::var("ENVCHAIN_AGE_IDENTITY")
                .ok()
                .map(PathBuf::from)
        });

        let is_default_identity = explicit_identity.is_none();
        let identity_path = explicit_identity.unwrap_or(default_identity_path);

        let mut backend = Self {
            secrets_path,
            identity_path,
            recipient_path,
            secrets: HashMap::new(),
        };

        backend.ensure_identity(is_default_identity)?;
        backend.load_secrets()?;

        Ok(backend)
    }

    /// Ensure we have an identity file.
    ///
    /// When `is_default_path` is true and the file is absent, a new native age
    /// identity is generated.  When false (user supplied a path explicitly) and
    /// the file is absent, a clear error is returned without any auto-generation.
    fn ensure_identity(&self, is_default_path: bool) -> Result<(), String> {
        if self.identity_path.exists() {
            return Ok(());
        }

        if !is_default_path {
            return Err(format!(
                "Identity file not found: {path}\n\
                 For SSH keys:       ssh-keygen -t ed25519 -f {path}\n\
                 For age identities: age-keygen -o {path}",
                path = self.identity_path.display()
            ));
        }

        // Generate a new native age identity at the default location.
        eprintln!(
            "Generating new age identity at {}",
            self.identity_path.display()
        );
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();

        // Open with O_CREAT | O_EXCL and mode 0o600 in a single syscall so
        // that (a) the file is never world-readable even briefly and (b) a
        // pre-existing symlink cannot redirect the write.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&self.identity_path)
                .map_err(|e| format!("Failed to create identity file: {e}"))?;
            file.write_all(identity.to_string().expose_secret().as_bytes())
                .map_err(|e| format!("Failed to write identity: {e}"))?;
        }
        #[cfg(not(unix))]
        {
            // Use create_new to prevent races (no O_EXCL mode bits on non-Unix,
            // but create_new still maps to CREATE_NEW on Windows).
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&self.identity_path)
                .map_err(|e| format!("Failed to create identity file: {e}"))?;
            file.write_all(identity.to_string().expose_secret().as_bytes())
                .map_err(|e| format!("Failed to write identity: {e}"))?;
            drop(file);

            // Restrict the identity file to the current user only.
            // Windows does not have Unix mode bits, so use icacls to remove
            // inherited ACEs and grant Full Control exclusively to the owner.
            #[cfg(target_os = "windows")]
            if let Err(e) = restrict_identity_file_to_owner(&self.identity_path) {
                eprintln!("Warning: could not restrict identity file permissions: {e}");
            }
        }

        // Save recipient (public key) for convenience — not sensitive.
        fs::write(&self.recipient_path, recipient.to_string())
            .map_err(|e| format!("Failed to write recipient: {e}"))?;

        eprintln!("Created age identity. Public key: {}", recipient);
        Ok(())
    }

    /// Load identities from file (supports SSH and native age identities).
    fn load_identities(&self) -> Result<Vec<Box<dyn age::Identity>>, String> {
        let identity_bytes = Zeroizing::new(fs::read(&self.identity_path).map_err(|e| {
            format!(
                "Failed to read identity file {}: {e}",
                self.identity_path.display()
            )
        })?);

        // Detect OpenSSH / PEM format by the "-----BEGIN" header.
        if identity_bytes.windows(10).any(|w| w == b"-----BEGIN") {
            let identity = age::ssh::Identity::from_buffer(identity_bytes.as_slice(), None)
                .map_err(|e| format!("Failed to parse SSH key: {e}"))?;
            return Ok(vec![Box::new(identity)]);
        }

        // Try parsing as age identity file.
        let identities = age::IdentityFile::from_buffer(identity_bytes.as_slice())
            .map_err(|e| format!("Failed to parse identity file: {e}"))?;

        // Convert to boxed identities, prompting for passphrase if needed.
        let identities: Vec<Box<dyn age::Identity>> = identities
            .into_identities()
            .map_err(|e| format!("Failed to process identities: {e}"))?;

        if identities.is_empty() {
            return Err("No identities found in identity file".to_string());
        }

        Ok(identities)
    }

    /// Get recipient for encryption.
    fn get_recipient(&self) -> Result<Box<dyn age::Recipient + Send>, String> {
        let identity_str = Zeroizing::new(
            fs::read_to_string(&self.identity_path)
                .map_err(|e| format!("Failed to read identity file: {e}"))?,
        );

        // Try as native age identity first.
        if let Ok(identity) = identity_str.trim().parse::<age::x25519::Identity>() {
            return Ok(Box::new(identity.to_public()));
        }

        // Try as SSH key — look for an SSH public key line inside the identity file.
        for line in identity_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("ssh-")
                && let Ok(recipient) = line.parse::<age::ssh::Recipient>()
            {
                return Ok(Box::new(recipient));
            }
        }

        // Try to read a corresponding .pub file for SSH private keys.
        let pub_path = PathBuf::from(format!("{}.pub", self.identity_path.display()));
        if pub_path.exists() {
            let pub_str = Zeroizing::new(
                fs::read_to_string(&pub_path)
                    .map_err(|e| format!("Failed to read public key file: {e}"))?,
            );
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

    /// Load and decrypt secrets from file.
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

        // Wrap in Zeroizing so the plaintext is wiped from memory on drop.
        let mut decrypted = Zeroizing::new(vec![]);
        let mut reader = decryptor
            .decrypt(identities.iter().map(|i| i.as_ref()))
            .map_err(|e| format!("Decryption failed: {e}"))?;
        reader
            .read_to_end(&mut *decrypted)
            .map_err(|e| format!("Failed to read decrypted data: {e}"))?;

        self.secrets = serde_json::from_slice(decrypted.as_slice())
            .map_err(|e| format!("Failed to parse secrets JSON: {e}"))?;

        Ok(())
    }

    /// Encrypt and save secrets to file.
    fn save_secrets(&self) -> Result<(), String> {
        // Wrap in Zeroizing so the plaintext JSON is wiped from memory on drop.
        let json = Zeroizing::new(
            serde_json::to_string_pretty(&self.secrets)
                .map_err(|e| format!("Failed to serialize secrets: {e}"))?,
        );

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

        // Write atomically via a unique temp file created in the same directory
        // as secrets.age (same filesystem → rename is atomic).
        // tempfile creates the file with O_CREAT | O_EXCL | mode 0o600 on Unix,
        // so the permissions are correct from the start and survive the rename
        // without a subsequent chmod call.
        let parent = self
            .secrets_path
            .parent()
            .ok_or("Could not determine secrets file parent directory")?;
        let mut temp_file = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| format!("Failed to create temp file: {e}"))?;
        temp_file
            .write_all(&encrypted)
            .map_err(|e| format!("Failed to write temp file: {e}"))?;
        temp_file
            .flush()
            .map_err(|e| format!("Failed to flush temp file: {e}"))?;
        temp_file
            .persist(&self.secrets_path)
            .map_err(|e| format!("Failed to rename secrets file: {e}"))?;

        Ok(())
    }
}

impl Drop for AgeBackend {
    fn drop(&mut self) {
        for inner in self.secrets.values_mut() {
            for val in inner.values_mut() {
                val.zeroize();
            }
        }
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
