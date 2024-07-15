use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    common_models::{
        did::{DidId, DidValue},
        key::Key,
    },
    did::{
        error::DidMethodError,
        imp::jwk_helpers::{encode_to_did, extract_jwk, generate_document},
        keys::Keys,
        model::{AmountOfKeys, DidCapabilities, DidDocument, Operation},
        DidMethod,
    },
    key_algorithm::provider::KeyAlgorithmProvider,
};

pub struct JWKDidMethod {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl JWKDidMethod {
    #[allow(clippy::new_without_default)]
    pub fn new(key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>) -> Self {
        Self {
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl DidMethod for JWKDidMethod {
    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        keys: &[Key],
    ) -> Result<DidValue, DidMethodError> {
        let key = match keys {
            [key] => key,
            [] => return Err(DidMethodError::CouldNotCreate("Missing key".to_string())),
            _ => return Err(DidMethodError::CouldNotCreate("Too many keys".to_string())),
        };
        let key_algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&key.key_type)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?;
        let jwk = key_algorithm
            .bytes_to_jwk(&key.public_key, None)
            .map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))?;

        encode_to_did(&jwk.into())
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError> {
        let jwk = extract_jwk(did)?;
        Ok(generate_document(did, jwk))
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE, Operation::CREATE],
            key_algorithms: vec![
                "ES256".to_string(),
                "EDDSA".to_string(),
                "BBS_PLUS".to_string(),
                "DILITHIUM".to_string(),
            ],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        Keys::default().validate_keys(keys)
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(Keys::default())
    }
}

#[cfg(test)]
mod test;
