use std::sync::Arc;

use one_providers::{
    crypto::CryptoProvider,
    key_algorithm::{model::GeneratedKey, provider::KeyAlgorithmProvider},
};
use zeroize::Zeroizing;

use super::error::SignatureServiceError;
use crate::model::KeyAlgorithmType;

pub struct SignatureService {
    pub crypto: Arc<dyn CryptoProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl SignatureService {
    pub fn new(
        crypto: Arc<dyn CryptoProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            crypto,
            key_algorithm_provider,
        }
    }
    pub fn get_key_pair(
        &self,
        algorithm: &KeyAlgorithmType,
    ) -> Result<GeneratedKey, SignatureServiceError> {
        let selected_algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&algorithm.to_string())
            .ok_or(SignatureServiceError::MissingAlgorithm(
                algorithm.to_string(),
            ))?;

        Ok(selected_algorithm.generate_key_pair())
    }

    pub fn sign(
        &self,
        algorithm: &KeyAlgorithmType,
        public_key: &[u8],
        private_key: Zeroizing<Vec<u8>>,
        data: &[u8],
    ) -> Result<Vec<u8>, SignatureServiceError> {
        let algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&algorithm.to_string())
            .ok_or(SignatureServiceError::MissingAlgorithm(
                algorithm.to_string(),
            ))?;

        let signer_algorithm_id = algorithm.get_signer_algorithm_id();

        let signer = self.crypto.get_signer(&signer_algorithm_id)?;

        Ok(signer.sign(data, public_key, private_key.as_slice())?)
    }

    pub fn verify(
        &self,
        algorithm: &KeyAlgorithmType,
        public_key: &[u8],
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), SignatureServiceError> {
        let algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&algorithm.to_string())
            .ok_or(SignatureServiceError::MissingAlgorithm(
                algorithm.to_string(),
            ))?;

        let signer_algorithm_id = algorithm.get_signer_algorithm_id();

        let signer = self.crypto.get_signer(&signer_algorithm_id)?;

        Ok(signer.verify(data, signature, public_key)?)
    }
}
