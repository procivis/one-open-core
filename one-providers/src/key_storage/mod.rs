//! Tools for safe generation and usage of keys.
//!
//! This module provides a middle layer for interacting with private keys via key
//! references.

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
    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError>;

    /// Converts a private key to JWK (thus exposing it).
    ///
    /// Use carefully.
    ///
    /// May not be implemented for some storage providers (e.g. Azure Key Vault).
    fn secret_key_as_jwk(&self, key: &Key) -> Result<Zeroizing<String>, error::KeyStorageError>;

    #[doc = include_str!("../../../docs/capabilities.md")]
    ///
    /// Key storage capabilities include reports such as which key algorithms are supported
    /// by different key storage types and whether keys can be exported or backed up.
    fn get_capabilities(&self) -> model::KeyStorageCapabilities;
}
