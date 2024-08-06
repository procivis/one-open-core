//! Tools for suspending and revoking credentials, and checking the status of credentials.
//!
//! Credentials issued with no revocation method cannot be revoked and remain valid
//! indefinitely. Suspended credentials can be made valid again. Revoked credentials
//! are rendered permanently invalid.
//!
//! This module provides tools for changing the suspension or revocation status of a
//! credential and for retrieving the validity status of a credential.

use crate::common_models::credential::OpenCredential;
use crate::common_models::did::DidValue;
use crate::credential_formatter::model::CredentialStatus;
use crate::revocation::error::RevocationError;
use crate::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
    CredentialRevocationState, JsonLdContext, RevocationMethodCapabilities, RevocationUpdate,
};

pub mod error;
pub mod imp;
pub mod model;
pub mod provider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait RevocationMethod: Send + Sync {
    /// Returns the revocation method as a string for the `credentialStatus` field of the VC.
    fn get_status_type(&self) -> String;

    /// Creates the `credentialStatus` field of the VC.
    ///
    /// For BitstringStatusList, this method creates the entry in revocation and suspension lists.
    ///
    /// For LVVC, the URL used by the holder to obtain a new LVVC is returned.
    async fn add_issued_credential(
        &self,
        credential: &OpenCredential,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError>;

    /// Change a credential's status to valid, revoked, or suspended.
    ///
    /// For list-based revocation methods, use `additional_data` to specify the ID of the associated list.
    async fn mark_credential_as(
        &self,
        credential: &OpenCredential,
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
    /// Revocation method capabilities include the operations possible for each revocation
    /// method.
    fn get_capabilities(&self) -> RevocationMethodCapabilities;

    /// For credentials with LVVC revocation method, this method creates the URL
    /// where the JSON-LD @context is hosted.
    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError>;
}
