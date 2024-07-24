//! Credential formatting, parsing and signing.
//!
//! Credentials must be formatted for publication and sharing, and shared credentials
//! must be parsed.
//!
//! This module provides tools for formatting and parsing credentials.

use async_trait::async_trait;
use error::FormatterError;
use model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential,
    ExtractPresentationCtx, FormatPresentationCtx, Presentation, TokenVerifier,
};

use crate::common_models::did::DidValue;

pub mod error;
pub mod imp;
pub mod model;
pub mod provider;

/// Format credentials for sharing and parse credentials which have been shared.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait CredentialFormatter: Send + Sync {
    /// Formats and signs a credential.
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

    /// Parses a received credential and verifies the signature.
    async fn extract_credentials(
        &self,
        credentials: &str,
        verification: Box<dyn model::TokenVerifier>,
    ) -> Result<DetailCredential, FormatterError>;

    /// Formats presentation with selective disclosure.
    ///
    /// For those formats capable of selective disclosure, call this with the keys of the claims
    /// to be shared. The token is processed and returns the correctly formatted presentation
    /// containing only the selected attributes.
    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError>;

    /// Parses a received credential without verifying the signature.
    async fn extract_credentials_unverified(
        &self,
        credential: &str,
    ) -> Result<DetailCredential, FormatterError>;

    /// Formats a presentation of credentials and signs it.
    async fn format_presentation(
        &self,
        tokens: &[String],
        holder_did: &DidValue,
        algorithm: &str,
        auth_fn: AuthenticationFn,
        ctx: FormatPresentationCtx,
    ) -> Result<String, FormatterError>;

    /// Parses a presentation and verifies the signature.
    async fn extract_presentation(
        &self,
        token: &str,
        verification: Box<dyn TokenVerifier>,
        ctx: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError>;

    /// Parses a presentation without verifying the signature.
    ///
    /// This can be useful for checking the validity of a presentation (e.g.
    /// expiration and revocation status) before committing to verifying a
    /// signature.
    async fn extract_presentation_unverified(
        &self,
        token: &str,
        ctx: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError>;

    /// Returns the leeway time.
    ///
    /// Leeway is a buffer time (in seconds) added to account for clock skew
    /// between systems when validating issuance and expiration dates of presentations
    /// and the credentials included therein. This prevents minor discrepancies in system
    /// clocks from causing validation failures.
    fn get_leeway(&self) -> u64;

    #[doc = include_str!("../../../docs/capabilities.md")]
    ///
    /// Credential format capabilities include reports such as:
    /// - Whether the format supports selective disclosure
    /// - Which signing algorithms are supported
    /// - Which DID methods are supported
    /// - Which revocation methods are supported
    fn get_capabilities(&self) -> model::FormatterCapabilities;
}
