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

    async fn add_issued_credential(
        &self,
        credential: &Credential,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError>;

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError>;

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, RevocationError>;

    fn get_capabilities(&self) -> RevocationMethodCapabilities;

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError>;
}
