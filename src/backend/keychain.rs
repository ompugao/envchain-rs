//! macOS Keychain backend for envchain
//!
//! Uses the Security framework to store secrets in the macOS Keychain.
//! Compatible with the original sorah/envchain implementation.
//!
//! # Testing
//!
//! Tests in this module only run on macOS with the keychain-backend feature enabled.
//! They interact with the actual macOS Keychain and are gated with:
//! `#[cfg(all(target_os = "macos", feature = "keychain-backend"))]`

use super::{Backend, EnvKey, EnvValue, Namespace};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NAMESPACE: &str = "envchain-test-ns";
    const TEST_KEY: &str = "TEST_VAR";
    const TEST_VALUE: &str = "test-value-123";

    /// Clean up any leftover test data
    fn cleanup_test_data() {
        let mut backend = KeychainBackend::new().unwrap();
        let _ = backend.delete_secret(TEST_NAMESPACE, TEST_KEY);
        let _ = backend.delete_secret(TEST_NAMESPACE, "TEST_VAR2");
        let _ = backend.delete_secret(TEST_NAMESPACE, "TEST_VAR3");
    }

    #[test]
    fn test_keychain_backend_new() {
        let backend = KeychainBackend::new();
        assert!(backend.is_ok());
    }

    #[test]
    fn test_service_name_format() {
        let service = KeychainBackend::service_name("test");
        assert_eq!(service, "envchain-test");

        // Verify compatibility with original envchain
        let service = KeychainBackend::service_name("aws");
        assert_eq!(service, "envchain-aws");
    }

    #[test]
    fn test_set_and_get_secret() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();

        // Set a secret
        let result = backend.set_secret(TEST_NAMESPACE, TEST_KEY, TEST_VALUE);
        assert!(result.is_ok(), "Failed to set secret: {:?}", result.err());

        // Retrieve and verify
        let secrets = backend.list_secrets(TEST_NAMESPACE).unwrap();
        assert_eq!(secrets.get(TEST_KEY), Some(&TEST_VALUE.to_string()));

        cleanup_test_data();
    }

    #[test]
    fn test_update_existing_secret() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();

        // Set initial value
        backend
            .set_secret(TEST_NAMESPACE, TEST_KEY, "old-value")
            .unwrap();

        // Update with new value
        backend
            .set_secret(TEST_NAMESPACE, TEST_KEY, "new-value")
            .unwrap();

        // Verify updated value
        let secrets = backend.list_secrets(TEST_NAMESPACE).unwrap();
        assert_eq!(secrets.get(TEST_KEY), Some(&"new-value".to_string()));

        cleanup_test_data();
    }

    #[test]
    fn test_delete_secret() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();

        // Set a secret
        backend
            .set_secret(TEST_NAMESPACE, TEST_KEY, TEST_VALUE)
            .unwrap();

        // Verify it exists
        let secrets = backend.list_secrets(TEST_NAMESPACE).unwrap();
        assert!(secrets.contains_key(TEST_KEY));

        // Delete it
        let result = backend.delete_secret(TEST_NAMESPACE, TEST_KEY);
        assert!(
            result.is_ok(),
            "Failed to delete secret: {:?}",
            result.err()
        );

        // Verify it's gone
        let secrets = backend.list_secrets(TEST_NAMESPACE).unwrap();
        assert!(!secrets.contains_key(TEST_KEY));
    }

    #[test]
    fn test_delete_nonexistent_secret() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();

        // Try to delete a secret that doesn't exist
        let result = backend.delete_secret(TEST_NAMESPACE, "NONEXISTENT_KEY");
        assert!(
            result.is_err(),
            "Expected error when deleting nonexistent secret"
        );
    }

    #[test]
    fn test_multiple_secrets_in_namespace() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();

        // Set multiple secrets
        backend
            .set_secret(TEST_NAMESPACE, "TEST_VAR2", "value2")
            .unwrap();
        backend
            .set_secret(TEST_NAMESPACE, "TEST_VAR3", "value3")
            .unwrap();

        // Retrieve all secrets
        let secrets = backend.list_secrets(TEST_NAMESPACE).unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets.get("TEST_VAR2"), Some(&"value2".to_string()));
        assert_eq!(secrets.get("TEST_VAR3"), Some(&"value3".to_string()));

        cleanup_test_data();
    }

    #[test]
    fn test_list_namespaces() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();

        // Set a secret to create the namespace
        backend
            .set_secret(TEST_NAMESPACE, TEST_KEY, TEST_VALUE)
            .unwrap();

        // List namespaces
        let namespaces = backend.list_namespaces().unwrap();

        // Should contain our test namespace
        assert!(
            namespaces.contains(&TEST_NAMESPACE.to_string()),
            "Test namespace not found in: {:?}",
            namespaces
        );

        cleanup_test_data();
    }

    #[test]
    fn test_list_secrets_empty_namespace() {
        let backend = KeychainBackend::new().unwrap();

        // Query a namespace that shouldn't exist
        let secrets = backend.list_secrets("nonexistent-namespace-xyz").unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_special_characters_in_values() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();

        let special_value = "value with spaces, symbols: !@#$%^&*()_+{}[]|:;<>?,./";
        backend
            .set_secret(TEST_NAMESPACE, TEST_KEY, special_value)
            .unwrap();

        let secrets = backend.list_secrets(TEST_NAMESPACE).unwrap();
        assert_eq!(secrets.get(TEST_KEY), Some(&special_value.to_string()));

        cleanup_test_data();
    }

    #[test]
    fn test_empty_value() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();

        backend.set_secret(TEST_NAMESPACE, TEST_KEY, "").unwrap();

        let secrets = backend.list_secrets(TEST_NAMESPACE).unwrap();
        assert_eq!(secrets.get(TEST_KEY), Some(&"".to_string()));

        cleanup_test_data();
    }

    #[test]
    fn test_namespace_isolation() {
        cleanup_test_data();

        let mut backend = KeychainBackend::new().unwrap();
        let namespace2 = "envchain-test-ns2";

        // Set same key in two different namespaces
        backend
            .set_secret(TEST_NAMESPACE, TEST_KEY, "value1")
            .unwrap();
        backend.set_secret(namespace2, TEST_KEY, "value2").unwrap();

        // Verify isolation
        let secrets1 = backend.list_secrets(TEST_NAMESPACE).unwrap();
        let secrets2 = backend.list_secrets(namespace2).unwrap();

        assert_eq!(secrets1.get(TEST_KEY), Some(&"value1".to_string()));
        assert_eq!(secrets2.get(TEST_KEY), Some(&"value2".to_string()));

        // Cleanup both namespaces
        let _ = backend.delete_secret(namespace2, TEST_KEY);
        cleanup_test_data();
    }
}
