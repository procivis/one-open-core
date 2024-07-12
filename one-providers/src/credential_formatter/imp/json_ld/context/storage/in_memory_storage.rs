use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;

use crate::credential_formatter::imp::json_ld::context::storage::{
    JsonLdContext, JsonLdContextStorage, JsonLdContextStorageError,
};

pub struct InMemoryStorage {
    storage: Arc<Mutex<HashMap<String, JsonLdContext>>>,
}

impl InMemoryStorage {
    pub fn new(storage: HashMap<String, JsonLdContext>) -> Self {
        Self {
            storage: Arc::new(Mutex::new(storage)),
        }
    }
}

#[async_trait]
impl JsonLdContextStorage for InMemoryStorage {
    async fn delete_oldest_context(&self) -> Result<(), JsonLdContextStorageError> {
        let mut hash_map_handle = self
            .storage
            .lock()
            .map_err(|e| JsonLdContextStorageError::DeleteError(e.to_string()))?;

        if let Some(key) = hash_map_handle.iter().min().map(|(k, _)| k.to_owned()) {
            hash_map_handle.remove(&key);
        }

        Ok(())
    }

    async fn get_json_ld_context_by_url(
        &self,
        url: &str,
    ) -> Result<Option<JsonLdContext>, JsonLdContextStorageError> {
        let hash_map_handle = self
            .storage
            .lock()
            .map_err(|e| JsonLdContextStorageError::GetByUrlError(e.to_string()))?;

        Ok(hash_map_handle.get(url).map(|v| v.to_owned()))
    }

    async fn get_storage_size(&self) -> Result<usize, JsonLdContextStorageError> {
        let hash_map_handle = self
            .storage
            .lock()
            .map_err(|e| JsonLdContextStorageError::GetStorageSizeError(e.to_string()))?;

        Ok(hash_map_handle.len())
    }

    async fn insert_json_ld_context(
        &self,
        request: JsonLdContext,
    ) -> Result<(), JsonLdContextStorageError> {
        let mut hash_map_handle = self
            .storage
            .lock()
            .map_err(|e| JsonLdContextStorageError::InsertError(e.to_string()))?;

        hash_map_handle.insert(request.url.to_string(), request);

        Ok(())
    }
}
