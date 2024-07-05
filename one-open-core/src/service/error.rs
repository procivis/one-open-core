use one_providers::crypto::{CryptoProviderError, SignerError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureServiceError {
    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),
    #[error("Could not sign")]
    CouldNotSign,
    #[error("Could not verify")]
    CouldNotVerify,
    #[error("Crypto provider error: `{0}`")]
    CryptoProviderError(#[from] CryptoProviderError),
    #[error("Signer error: `{0}`")]
    SignerError(#[from] SignerError),
}
