use std::sync::Arc;

use crate::crypto::Signer;

use super::{
    error::KeyAlgorithmProviderError,
    model::{ParsedPublicKeyJwk, PublicKeyJwk},
    KeyAlgorithm,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithmProvider: Send + Sync {
    fn get_key_algorithm(&self, algorithm: &str) -> Option<Arc<dyn KeyAlgorithm>>;

    fn get_signer(&self, algorithm: &str) -> Result<Arc<dyn Signer>, KeyAlgorithmProviderError>;

    fn parse_jwk(
        &self,
        key: &PublicKeyJwk,
    ) -> Result<ParsedPublicKeyJwk, KeyAlgorithmProviderError>;
}
