//! Enumerates errors related to key storage provider.

use thiserror::Error;

use one_crypto::SignerError;

use crate::key_algorithm::error::KeyAlgorithmError;

#[derive(Debug, Error)]
pub enum KeyStorageProviderError {
    #[error("Invalid key storage `{0}`")]
    InvalidKeyStorage(String),
}

#[derive(Debug, Error)]
pub enum KeyStorageError {
    #[error("Key algorithm error: `{0}`")]
    Failed(String),
    #[error("Signer error: `{0}`")]
    SignerError(#[from] SignerError),
    #[error("Not supported for type: `{0}`")]
    NotSupported(String),
    #[error("Unsupported key type: {key_type}")]
    UnsupportedKeyType { key_type: String },
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("Key algorithm error: `{0}`")]
    KeyAlgorithmError(#[from] KeyAlgorithmError),
    #[error("Password decryption failure")]
    PasswordDecryptionFailure,
    #[error("Invalid key algorithm `{0}`")]
    InvalidKeyAlgorithm(String),
}
