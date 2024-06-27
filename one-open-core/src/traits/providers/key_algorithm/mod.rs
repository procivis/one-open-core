use error::KeyAlgorithmError;
use model::{GeneratedKey, PublicKeyJwk};
use zeroize::Zeroizing;

pub mod error;
pub mod model;
pub mod provider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithm: Send + Sync {
    /// related crypto signer ID
    fn get_signer_algorithm_id(&self) -> String;

    /// base58-btc representation of the public key (following did:key spec)
    fn get_multibase(&self, public_key: &[u8]) -> Result<String, KeyAlgorithmError>;

    /// generate a new in-memory key-pair
    fn generate_key_pair(&self) -> GeneratedKey;

    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwk, KeyAlgorithmError>;

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwk) -> Result<Vec<u8>, KeyAlgorithmError>;

    fn private_key_as_jwk(
        &self,
        _secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<String>, KeyAlgorithmError> {
        Err(KeyAlgorithmError::NotSupported(
            std::any::type_name::<Self>().to_string(),
        ))
    }

    fn public_key_from_der(&self, public_key_der: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError>;
}
