use async_trait::async_trait;

use crate::common_models::did::DidValue;
use model::CredentialData;

use error::FormatterError;
use model::{
    AuthenticationFn, CredentialPresentation, DetailCredential, ExtractPresentationCtx,
    FormatPresentationCtx, Presentation, TokenVerifier,
};

pub mod error;
pub mod imp;
pub mod model;
pub mod provider;

#[allow(clippy::too_many_arguments)]
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait CredentialFormatter: Send + Sync {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: model::AuthenticationFn,
        json_ld_context_url: Option<String>,
        custom_subject_name: Option<String>,
    ) -> Result<String, error::FormatterError>;

    async fn extract_credentials(
        &self,
        credentials: &str,
        verification: Box<dyn model::TokenVerifier>,
    ) -> Result<DetailCredential, FormatterError>;

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError>;

    async fn extract_credentials_unverified(
        &self,
        credential: &str,
    ) -> Result<DetailCredential, FormatterError>;

    async fn format_presentation(
        &self,
        tokens: &[String],
        holder_did: &DidValue,
        algorithm: &str,
        auth_fn: AuthenticationFn,
        ctx: FormatPresentationCtx,
    ) -> Result<String, FormatterError>;

    async fn extract_presentation(
        &self,
        token: &str,
        verification: Box<dyn TokenVerifier>,
        ctx: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError>;

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        ctx: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError>;

    fn get_leeway(&self) -> u64;

    fn get_capabilities(&self) -> model::FormatterCapabilities;
}
