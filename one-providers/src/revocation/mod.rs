//! Tools for suspending and revoking credentials, and checking the status of credentials.
//!
//! Credentials issued with no revocation method cannot be revoked and remain valid
//! indefinitely. Suspended credentials can be made valid again. Revoked credentials
//! are rendered permanently invalid.
//!
//! This module provides tools for changing the suspension or revocation status of a
//! credential and for retrieving the validity status of a credential.

use crate::{
    common_models::{credential::Credential, did::DidValue},
    credential_formatter::model::CredentialStatus,
    revocation::{
        error::RevocationError,
        model::{
            CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
            CredentialRevocationState, JsonLdContext, RevocationMethodCapabilities,
            RevocationUpdate,
        },
    },
};

pub mod error;
pub mod imp;
pub mod model;
pub mod provider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait RevocationMethod: Send + Sync {
    fn get_status_type(&self) -> String;

    ///
    async fn add_issued_credential(
        &self,
        credential: &Credential,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError>;

    /// Updates a credential's status.
    ///
    /// Change a credential's status to valid, revoked, or suspended.
    ///
    /// For list-based revocation methods, use `additional_data` to specify the ID of the associated list.
    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError>;

    /// Checks the revocation status of a credential.
    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, RevocationError>;

    #[doc = include_str!("../../../docs/capabilities.md")]
    ///
    /// Revocation method capabilities include reports such as
    fn get_capabilities(&self) -> RevocationMethodCapabilities;

    /// Returns the @context of a JSON-LD credential.
    ///
    /// The [@context][con] of JSON-LD credentials allows for mapping terms to Internationalized
    /// Resource Identifiers (IRIs), enabling credentials to declare and share a context
    /// within which to understand the terms used.
    ///
    /// Contexts can be published and used within domains to create a shared language. This
    /// also allows for larger architectures to use multiple contexts across different domains
    /// according to needs.
    ///
    /// [con]: https://www.w3.org/TR/json-ld11/#the-context
    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError>;
}
