use std::collections::HashMap;

pub type Namespace = String;
pub type EnvKey = String;
pub type EnvValue = String;

/// Backend trait for secret storage
pub trait Backend {
    /// List all namespaces
    fn list_namespaces(&self) -> Result<Vec<Namespace>, String>;

    /// List all key-value pairs in a namespace
    fn list_secrets(&self, namespace: &str) -> Result<HashMap<EnvKey, EnvValue>, String>;

    /// Set a secret value
    fn set_secret(&mut self, namespace: &str, key: &str, value: &str) -> Result<(), String>;

    /// Delete a secret
    fn delete_secret(&mut self, namespace: &str, key: &str) -> Result<(), String>;
}

#[cfg(feature = "secret-service-backend")]
pub mod secret_service;

#[cfg(feature = "age-backend")]
pub mod age;

#[cfg(feature = "windows-credential-manager")]
pub mod windows_credential_manager;
