use std::{collections::HashMap, sync::Arc};

use crate::{
    common_models::key::OpenKey,
    credential_formatter::model::SignatureProvider,
    crypto::SignerError,
    key_storage::{provider::KeyProvider, KeyStorage},
};

pub struct KeyProviderImpl {
    storages: HashMap<String, Arc<dyn KeyStorage>>,
}

impl KeyProviderImpl {
    pub fn new(storages: HashMap<String, Arc<dyn KeyStorage>>) -> Self {
        Self { storages }
    }
}

impl KeyProvider for KeyProviderImpl {
    fn get_key_storage(&self, format: &str) -> Option<Arc<dyn KeyStorage>> {
        self.storages.get(format).cloned()
    }
}

pub(crate) struct SignatureProviderImpl {
    pub storage: Arc<dyn KeyStorage>,
    pub key: OpenKey,
    pub jwk_key_id: Option<String>,
}

#[async_trait::async_trait]
impl SignatureProvider for SignatureProviderImpl {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.storage.sign(&self.key, message).await
    }

    fn get_key_id(&self) -> Option<String> {
        self.jwk_key_id.to_owned()
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.key.public_key.to_owned()
    }
}
