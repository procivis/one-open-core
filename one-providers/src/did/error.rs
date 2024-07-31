//! Enumerates errors related to DID method provider.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DidMethodError {
    #[error("Key algorithm not found")]
    KeyAlgorithmNotFound,
    #[error("Could not resolve: `{0}`")]
    ResolutionError(String),
    #[error("Could not create: `{0}`")]
    CouldNotCreate(String),
    #[error("Not supported")]
    NotSupported,
}

#[derive(Debug, Error)]
pub enum DidMethodProviderError {
    #[error("Did method error: `{0}`")]
    DidMethod(#[from] DidMethodError),
    #[error("Missing did method name in did value")]
    MissingDidMethodNameInDidValue,
    #[error("Missing did provider: `{0}`")]
    MissingProvider(String),
    #[error("Other: `{0}`")]
    Other(String),
}
