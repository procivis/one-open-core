use std::sync::Arc;

use super::{error::KeyStorageProviderError, imp::provider::SignatureProviderImpl, KeyStorage};
use crate::{common_models::key::Key, credential_formatter::model::AuthenticationFn};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyProvider: Send + Sync {
    fn get_key_storage(&self, key_provider_id: &str) -> Option<Arc<dyn KeyStorage>>;

    fn get_signature_provider(
        &self,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<AuthenticationFn, KeyStorageProviderError> {
        let storage = self.get_key_storage(&key.storage_type).ok_or(
            KeyStorageProviderError::InvalidKeyStorage(key.storage_type.clone()),
        )?;

        Ok(Box::new(SignatureProviderImpl {
            key: key.to_owned(),
            storage,
            jwk_key_id,
        }))
    }
}
