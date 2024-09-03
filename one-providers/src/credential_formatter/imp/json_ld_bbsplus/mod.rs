//! Implementation of JSON-LD credential format with BBS+ signatures, allowing for selective disclosure.

use std::{sync::Arc, vec};

use async_trait::async_trait;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use time::Duration;

use super::json_ld::{
    context::caching_loader::ContextCache, jsonld_forbidden_claim_names, model::LdCredential,
};
use crate::{
    common_models::did::DidValue,
    credential_formatter::{
        error::FormatterError,
        imp::json_ld::context::caching_loader::JsonLdCachingLoader,
        model::{
            AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential,
            ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, Presentation,
            VerificationFn,
        },
        CredentialFormatter,
    },
    did::provider::DidMethodProvider,
    key_algorithm::provider::KeyAlgorithmProvider,
};

use crate::http_client::HttpClient;
use one_crypto::CryptoProvider;

mod base_proof;
mod derived_proof;
mod mapper;
pub mod model;
mod remove_undisclosed_keys;
mod verify_proof;

#[cfg(test)]
mod test;

#[allow(dead_code)]
pub struct JsonLdBbsplus {
    pub base_url: Option<String>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub caching_loader: ContextCache,
    params: Params,
}

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway: Duration,
    pub embed_layout_properties: Option<bool>,
}

#[async_trait]
impl CredentialFormatter for JsonLdBbsplus {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        json_ld_context_url: Option<String>,
        custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        self.format(
            credential,
            holder_did,
            algorithm,
            additional_context,
            additional_types,
            auth_fn,
            json_ld_context_url,
            custom_subject_name,
            self.params.embed_layout_properties.unwrap_or_default(),
        )
        .await
    }

    async fn extract_credentials(
        &self,
        credential: &str,
        verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        self.verify(credential, verification_fn).await
    }

    async fn extract_credentials_unverified(
        &self,
        credential: &str,
    ) -> Result<DetailCredential, FormatterError> {
        let ld_credential: LdCredential = serde_json::from_str(credential).map_err(|e| {
            FormatterError::CouldNotVerify(format!("Could not deserialize base proof: {e}"))
        })?;
        ld_credential.try_into()
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        self.derive_proof(credential).await
    }

    async fn format_presentation(
        &self,
        _tokens: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        unimplemented!()
    }

    async fn extract_presentation(
        &self,
        _json_ld: &str,
        _verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        unimplemented!()
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway.whole_seconds() as u64
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec!["BBS_PLUS".to_owned()],
            features: vec![
                "SUPPORTS_CREDENTIAL_DESIGN".to_string(),
                "SELECTIVE_DISCLOSURE".to_owned(),
            ],
            selective_disclosure: vec!["ANY_LEVEL".to_owned()],
            issuance_did_methods: vec![
                "KEY".to_string(),
                "WEB".to_string(),
                "JWK".to_string(),
                "X509".to_string(),
            ],
            allowed_schema_ids: vec![],
            datatypes: vec![
                "STRING".to_string(),
                "BOOLEAN".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
                "PICTURE".to_string(),
                "OBJECT".to_string(),
                "ARRAY".to_string(),
            ],
            issuance_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            proof_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            revocation_methods: vec![
                "NONE".to_string(),
                "BITSTRINGSTATUSLIST".to_string(),
                "LVVC".to_string(),
            ],
            verification_key_algorithms: vec![
                "EDDSA".to_string(),
                "ES256".to_string(),
                "DILITHIUM".to_string(),
            ],
            forbidden_claim_names: [jsonld_forbidden_claim_names(), vec!["0".to_string()]].concat(),
        }
    }

    async fn extract_presentation_unverified(
        &self,
        _token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        unimplemented!()
    }
}

impl JsonLdBbsplus {
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        base_url: Option<String>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        caching_loader: JsonLdCachingLoader,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            params,
            crypto,
            base_url,
            did_method_provider,
            key_algorithm_provider,
            caching_loader: ContextCache::new(caching_loader, client),
        }
    }
}
