//! Key algorithm provider.

use std::sync::Arc;

use super::{error::KeyAlgorithmProviderError, model::ParsedPublicKeyJwk, KeyAlgorithm};
use crate::{common_models::OpenPublicKeyJwk, crypto::Signer};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithmProvider: Send + Sync {
    fn get_key_algorithm(&self, algorithm: &str) -> Option<Arc<dyn KeyAlgorithm>>;

    fn get_signer(&self, algorithm: &str) -> Result<Arc<dyn Signer>, KeyAlgorithmProviderError>;

    fn parse_jwk(
        &self,
        key: &OpenPublicKeyJwk,
    ) -> Result<ParsedPublicKeyJwk, KeyAlgorithmProviderError>;
}
