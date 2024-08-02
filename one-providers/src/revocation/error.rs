//! Enumerates errors related to revocation method provider.

use thiserror::Error;

use crate::{
    caching_loader::CachingLoaderError,
    common_models::{
        credential::{CredentialId, CredentialStateEnum},
        did::{DidId, KeyRole},
    },
    credential_formatter::error::FormatterError,
    did::error::DidMethodProviderError,
    key_storage::error::KeyStorageProviderError,
    remote_entity_storage::RemoteEntityStorageError,
    util::bitstring::BitstringError,
};

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("Credential not found: `{0}`")]
    CredentialNotFound(CredentialId),
    #[error("Formatter not found: `{0}`")]
    FormatterNotFound(String),
    #[error("Invalid credential state: `{0}`")]
    InvalidCredentialState(CredentialStateEnum),
    #[error("Key with role `{0}` not found`")]
    KeyWithRoleNotFound(KeyRole),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Missing credential index `{0}` on revocation list for did id `{1}`")]
    MissingCredentialIndexOnRevocationList(CredentialId, DidId),
    #[error("Operation not supported: `{0}`")]
    OperationNotSupported(String),
    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("Bitstring error: `{0}`")]
    BitstringError(#[from] BitstringError),
    #[error("Caching loader error: `{0}`")]
    CachingLoader(#[from] CachingLoaderError),
    #[error("Did method provider error: `{0}`")]
    DidMethodProviderError(#[from] DidMethodProviderError),
    #[error("Formatter error: `{0}`")]
    FormatterError(#[from] FormatterError),
    #[error("Key storage provider error: `{0}`")]
    KeyStorageProviderError(#[from] KeyStorageProviderError),
    #[error("Remote entity storage error: `{0}`")]
    RemoteEntityStorageError(#[from] RemoteEntityStorageError),

    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("HTTP request error: `{0}`")]
    HttpRequestError(#[from] reqwest::Error),
    #[error("JSON error: `{0}`")]
    JsonError(#[from] serde_json::Error),
}
