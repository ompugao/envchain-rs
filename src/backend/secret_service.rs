use super::{Backend, EnvKey, EnvValue, Namespace};
use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::EncryptionType;
use std::collections::HashMap;

pub struct SecretServiceBackend {
    ss: SecretService<'static>,
}

impl SecretServiceBackend {
    pub fn new() -> Result<Self, String> {
        let ss = SecretService::connect(EncryptionType::Dh)
            .map_err(|e| format!("SecretService connect failed: {e}"))?;
        Ok(Self { ss })
    }

    fn get_collection(&self) -> Result<Collection<'_>, String> {
        self.ss
            .get_default_collection()
            .map_err(|e| format!("SecretService default collection failed: {e}"))
    }
}

impl Backend for SecretServiceBackend {
    fn list_namespaces(&self) -> Result<Vec<Namespace>, String> {
        let collection = self.get_collection()?;
        let items: Vec<Item> = collection
            .search_items(HashMap::new())
            .map_err(|e| format!("search_items failed: {e}"))?;

        let mut namespaces: Vec<String> = items
            .into_iter()
            .filter_map(|item| {
                let attrs = item.get_attributes().ok()?;
                attrs.get("name").cloned()
            })
            .collect();
        namespaces.sort();
        namespaces.dedup();
        Ok(namespaces)
    }

    fn list_secrets(&self, namespace: &str) -> Result<HashMap<EnvKey, EnvValue>, String> {
        let collection = self.get_collection()?;
        let items: Vec<Item> = collection
            .search_items(HashMap::from([("name", namespace)]))
            .map_err(|e| format!("search_items failed: {e}"))?;

        let mut secrets = HashMap::new();
        for item in items {
            let attrs = match item.get_attributes() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let Some(key) = attrs.get("key") else {
                continue;
            };
            if let Ok(secret) = item.get_secret() {
                let val = String::from_utf8(secret)
                    .map_err(|e| format!("Secret for {key} is not valid UTF-8: {e}"))?;
                secrets.insert(key.clone(), val);
            }
        }
        Ok(secrets)
    }

    fn set_secret(&mut self, namespace: &str, key: &str, value: &str) -> Result<(), String> {
        let collection = self.get_collection()?;
        collection
            .create_item(
                key,
                HashMap::from([("name", namespace), ("key", key)]),
                value.as_bytes(),
                true,
                "text/plain",
            )
            .map_err(|e| format!("Failed to store secret: {e}"))?;
        Ok(())
    }

    fn delete_secret(&mut self, namespace: &str, key: &str) -> Result<(), String> {
        let collection = self.get_collection()?;
        let items: Vec<Item> = collection
            .search_items(HashMap::from([("name", namespace), ("key", key)]))
            .map_err(|e| format!("search_items failed: {e}"))?;
        for item in items {
            if let Err(e) = item.delete() {
                eprintln!("Failed to delete {namespace}.{key}: {e}");
            }
        }
        Ok(())
    }
}
