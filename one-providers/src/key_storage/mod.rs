//! Tools for safe generation and usage of keys.
//!
//! This module provides a middle layer for interacting with private keys via key
//! references. Generate key pairs and sign via key reference.

use async_trait;
use zeroize::Zeroizing;

use one_crypto::SignerError;

use crate::common_models::key::{KeyId, OpenKey};

pub mod error;
pub mod imp;
pub mod model;
pub mod provider;

/// Generate key pairs and sign via key references.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait KeyStorage: Send + Sync {
    /// Generates a key pair and returns the key reference. Does not expose the private key.
    async fn generate(
        &self,
        key_id: &KeyId,
        key_type: &str,
    ) -> Result<model::StorageGeneratedKey, error::KeyStorageError>;

    /// Sign with a private key via the key reference.
    async fn sign(&self, key: &OpenKey, message: &[u8]) -> Result<Vec<u8>, SignerError>;

    /// Converts a private key to JWK (thus exposing it).
    ///
    /// **Use carefully.**
    ///
    /// May not be implemented for some storage providers (e.g. Azure Key Vault).
    fn secret_key_as_jwk(&self, key: &OpenKey)
        -> Result<Zeroizing<String>, error::KeyStorageError>;

    #[doc = include_str!("../../../docs/capabilities.md")]
    ///
    /// See the [API docs][ksc] for a complete list of credential format capabilities.
    ///
    /// [ksc]: https://docs.procivis.ch/api/resources/keys#key-storage-capabilities
    fn get_capabilities(&self) -> model::KeyStorageCapabilities;
}
