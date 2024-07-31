//! A service for issuing credentials, creating and signing presentations as a holder,
//! and parsing and verifying credentials as a verifier.
//!
//! See the **/examples** directory in the [repository][repo] for an
//! example implementation.
//!
//! [repo]: https://github.com/procivis/one-open-core

use std::sync::Arc;

use one_providers::{
    common_models::{
        did::{DidValue, KeyRole},
        key::Key,
    },
    credential_formatter::{
        model::{CredentialData, CredentialPresentation, DetailCredential},
        provider::CredentialFormatterProvider,
    },
    did::provider::DidMethodProvider,
    key_algorithm::provider::KeyAlgorithmProvider,
    key_storage::provider::KeyProvider,
};

use one_providers::util::key_verification::KeyVerification;

use crate::{
    model::{CredentialFormat, KeyAlgorithmType},
    service::error::CredentialServiceError,
};

pub struct CredentialService {
    key_storage_provider: Arc<dyn KeyProvider>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
}

impl CredentialService {
    pub fn new(
        key_storage_provider: Arc<dyn KeyProvider>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
    ) -> Self {
        Self {
            key_storage_provider,
            credential_formatter_provider,
            key_algorithm_provider,
            did_method_provider,
        }
    }

    pub async fn format_credential(
        &self,
        credential_data: CredentialData,
        format: CredentialFormat,
        algorithm: KeyAlgorithmType,
        holder_did: DidValue,
        key: Key,
    ) -> Result<String, CredentialServiceError> {
        let auth_fn = self
            .key_storage_provider
            .get_signature_provider(&key.to_owned(), None)?;

        let token = self
            .credential_formatter_provider
            .get_formatter(&format.to_string())
            .ok_or(CredentialServiceError::MissingFormat(format.to_string()))?
            .format_credentials(
                credential_data,
                &holder_did,
                &algorithm.to_string(),
                vec![],
                vec![],
                auth_fn,
                None,
                None,
            )
            .await?;

        Ok(token)
    }

    pub async fn format_credential_presentation(
        &self,
        format: CredentialFormat,
        credential: CredentialPresentation,
    ) -> Result<String, CredentialServiceError> {
        let token = self
            .credential_formatter_provider
            .get_formatter(&format.to_string())
            .ok_or(CredentialServiceError::MissingFormat(format.to_string()))?
            .format_credential_presentation(credential)
            .await?;

        Ok(token)
    }

    pub async fn extract_credential(
        &self,
        format: CredentialFormat,
        credential: &str,
    ) -> Result<DetailCredential, CredentialServiceError> {
        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let details = self
            .credential_formatter_provider
            .get_formatter(&format.to_string())
            .ok_or(CredentialServiceError::MissingFormat(format.to_string()))?
            .extract_credentials(credential, key_verification)
            .await?;

        Ok(details)
    }
}
