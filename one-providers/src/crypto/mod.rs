use std::sync::Arc;

use thiserror::Error;

pub mod imp;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum CryptoProviderError {
    #[error("Missing hasher: `{0}`")]
    MissingHasher(String),
    #[error("Missing signer: `{0}`")]
    MissingSigner(String),
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum HasherError {
    #[error("Could not hash")]
    CouldNotHash,
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SignerError {
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
    #[error("Could not sign: `{0}`")]
    CouldNotSign(String),
    #[error("Could not extract keypair")]
    CouldNotExtractKeyPair,
    #[error("Could not extract public key: `{0}`")]
    CouldNotExtractPublicKey(String),
    #[error("Could not verify: `{0}`")]
    CouldNotVerify(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),
    #[error("Missing key")]
    MissingKey,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait Hasher: Send + Sync {
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError>;
    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, HasherError>;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait Signer: Send + Sync {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError>;
    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError>;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait CryptoProvider: Send + Sync {
    fn get_hasher(&self, hasher: &str) -> Result<Arc<dyn Hasher>, CryptoProviderError>;

    fn get_signer(&self, signer: &str) -> Result<Arc<dyn Signer>, CryptoProviderError>;
}
