use async_trait;
use zeroize::Zeroizing;

use crate::{
    common_models::key::{Key, KeyId},
    crypto::SignerError,
};

pub mod error;
pub mod imp;
pub mod model;
pub mod provider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait KeyStorage: Send + Sync {
    async fn generate(
        &self,
        key_id: &KeyId,
        key_type: &str,
    ) -> Result<model::StorageGeneratedKey, error::KeyStorageError>;

    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError>;

    fn secret_key_as_jwk(&self, key: &Key) -> Result<Zeroizing<String>, error::KeyStorageError>;

    fn get_capabilities(&self) -> model::KeyStorageCapabilities;
}
