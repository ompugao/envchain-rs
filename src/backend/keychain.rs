//! macOS Keychain backend for envchain
//!
//! Uses the Security framework to store secrets in the macOS Keychain.
//! Compatible with the original sorah/envchain implementation.

use super::{Backend, EnvKey, EnvValue, Namespace};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};
use std::collections::HashMap;

/// Service name prefix used by envchain (compatible with original implementation)
const SERVICE_PREFIX: &str = "envchain-";

pub struct KeychainBackend;

impl KeychainBackend {
    pub fn new() -> Result<Self, String> {
        Ok(Self)
    }

    fn service_name(namespace: &str) -> String {
        format!("{}{}", SERVICE_PREFIX, namespace)
    }
}

impl Backend for KeychainBackend {
    fn list_namespaces(&self) -> Result<Vec<Namespace>, String> {
        // Search for all generic passwords with our service prefix
        let results = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .limit(Limit::All)
            .load_attributes(true)
            .search()
            .map_err(|e| format!("Keychain search failed: {e}"))?;

        let mut namespaces: Vec<String> = results
            .into_iter()
            .filter_map(|item| {
                if let SearchResult::Dict(dict) = item {
                    // Get the service attribute
                    if let Some(service) = dict.get("svce").or(dict.get("service")) {
                        let service_str = service.to_string();
                        if service_str.starts_with(SERVICE_PREFIX) {
                            return Some(service_str[SERVICE_PREFIX.len()..].to_string());
                        }
                    }
                }
                None
            })
            .collect();

        namespaces.sort();
        namespaces.dedup();
        Ok(namespaces)
    }

    fn list_secrets(&self, namespace: &str) -> Result<HashMap<EnvKey, EnvValue>, String> {
        let service = Self::service_name(namespace);

        // Search for all items with this service
        let results = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(&service)
            .limit(Limit::All)
            .load_attributes(true)
            .load_data(true)
            .search()
            .map_err(|e| format!("Keychain search failed: {e}"))?;

        let mut secrets = HashMap::new();
        for item in results {
            if let SearchResult::Dict(dict) = item {
                // Get account name (key) and password (value)
                if let Some(account) = dict.get("acct").or(dict.get("account")) {
                    let key = account.to_string();
                    if let Some(data) = dict.get("v_Data").or(dict.get("data")) {
                        if let Some(bytes) = data.as_bytes() {
                            let value = String::from_utf8_lossy(bytes).to_string();
                            secrets.insert(key, value);
                        }
                    }
                }
            }
        }

        Ok(secrets)
    }

    fn set_secret(&mut self, namespace: &str, key: &str, value: &str) -> Result<(), String> {
        let service = Self::service_name(namespace);

        // Try to delete existing entry first (set_generic_password doesn't update)
        let _ = delete_generic_password(&service, key);

        set_generic_password(&service, key, value.as_bytes())
            .map_err(|e| format!("Failed to store secret in keychain: {e}"))?;

        Ok(())
    }

    fn delete_secret(&mut self, namespace: &str, key: &str) -> Result<(), String> {
        let service = Self::service_name(namespace);

        delete_generic_password(&service, key)
            .map_err(|e| format!("Failed to delete secret from keychain: {e}"))?;

        Ok(())
    }
}
