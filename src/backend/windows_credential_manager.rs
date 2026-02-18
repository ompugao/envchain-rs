//! Windows Credential Manager backend for envchain
//!
//! Stores secrets in Windows Credential Manager, accessible from both
//! native Windows and WSL2 environments.
//!
//! Credentials are stored with target names: envchain:{namespace}:{key}

use super::{Backend, EnvKey, EnvValue, Namespace};
use keyring_core::api::CredentialStoreApi;
use keyring_core::Error as KeyringError;
use std::collections::HashMap;
use std::sync::Arc;
use windows_native_keyring_store::Store;

const TARGET_PREFIX: &str = "envchain:";

pub struct WindowsCredentialManagerBackend {
    store: Arc<Store>,
}

impl WindowsCredentialManagerBackend {
    pub fn new() -> Result<Self, String> {
        // Configure store with custom delimiters: prefix="envchain:", divider=":", suffix=""
        let mut config = HashMap::new();
        config.insert("prefix", "envchain:");
        config.insert("divider", ":");
        config.insert("suffix", "");

        let store = Store::new_with_configuration(&config)
            .map_err(|e| format!("Failed to create Windows Credential Manager store: {e}"))?;

        Ok(Self { store })
    }

    fn parse_target(target: &str) -> Option<(String, String)> {
        // Parse "envchain:{namespace}:{key}" format
        target.strip_prefix(TARGET_PREFIX).and_then(|rest| {
            let mut parts = rest.splitn(2, ':');
            let namespace = parts.next()?.to_string();
            let key = parts.next()?.to_string();
            Some((namespace, key))
        })
    }
}

impl Backend for WindowsCredentialManagerBackend {
    fn list_namespaces(&self) -> Result<Vec<Namespace>, String> {
        // Search for all credentials starting with "envchain:"
        let mut search_spec: HashMap<&str, &str> = HashMap::new();
        let pattern = format!("^{}", regex::escape(TARGET_PREFIX));
        search_spec.insert("pattern", pattern.as_str());

        let entries = self
            .store
            .search(&search_spec)
            .map_err(|e| format!("Failed to search credentials: {e}"))?;

        let mut namespaces = Vec::new();
        for entry in entries {
            // Get the attributes to read the target_name
            if let Ok(attrs) = entry.get_attributes() {
                if let Some(target_name) = attrs.get("target_name") {
                    if let Some((namespace, _)) = Self::parse_target(target_name) {
                        namespaces.push(namespace);
                    }
                }
            }
        }

        namespaces.sort();
        namespaces.dedup();

        Ok(namespaces)
    }

    fn list_secrets(&self, namespace: &str) -> Result<HashMap<EnvKey, EnvValue>, String> {
        // Search for all credentials with our prefix
        let mut search_spec: HashMap<&str, &str> = HashMap::new();
        let pattern = format!("^{}{}:", regex::escape(TARGET_PREFIX), regex::escape(namespace));
        search_spec.insert("pattern", pattern.as_str());

        let entries = self
            .store
            .search(&search_spec)
            .map_err(|e| format!("Failed to search credentials: {e}"))?;

        let mut secrets = HashMap::new();

        for entry in &entries {
            // Get target_name from attributes
            if let Ok(attrs) = entry.get_attributes() {
                if let Some(target_name) = attrs.get("target_name") {
                    if let Some((ns, key)) = Self::parse_target(target_name) {
                        if ns == namespace {
                            // Get the password
                            match entry.get_password() {
                                Ok(password) => {
                                    secrets.insert(key, password);
                                }
                                Err(_) => {
                                    // Skip credentials we can't read
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(secrets)
    }

    fn set_secret(&mut self, namespace: &str, key: &str, value: &str) -> Result<(), String> {
        // build(service, user, _) produces target_name "{prefix}{user}{divider}{service}{suffix}"
        // so build(key, namespace, _) => "envchain:{namespace}:{key}"
        let entry = self
            .store
            .build(key, namespace, None)
            .map_err(|e| format!("Failed to build credential entry: {e}"))?;

        entry
            .set_password(value)
            .map_err(|e| format!("Failed to set password: {e}"))?;

        Ok(())
    }

    fn delete_secret(&mut self, namespace: &str, key: &str) -> Result<(), String> {
        // build(key, namespace, _) => target_name "envchain:{namespace}:{key}"
        let entry = self
            .store
            .build(key, namespace, None)
            .map_err(|e| format!("Failed to build credential entry: {e}"))?;

        entry
            .delete_credential()
            .map_err(|e| match e {
                KeyringError::NoEntry => format!("Credential not found for {namespace}:{key}"),
                _ => format!("Failed to delete credential: {e}"),
            })?;

        Ok(())
    }
}
