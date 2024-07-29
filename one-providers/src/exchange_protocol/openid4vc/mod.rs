use std::collections::HashMap;
use std::sync::Arc;

use model::{
    DatatypeType, InvitationResponseDTO, OpenID4VCICredentialOfferCredentialDTO,
    OpenID4VCICredentialValueDetails, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VPPresentationDefinitionInputDescriptorFormat, PresentationDefinitionResponseDTO,
    PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use thiserror::Error;
use url::Url;

use crate::common_dto::PublicKeyJwkDTO;
use crate::common_models::claim::Claim;
use crate::common_models::credential::{Credential, CredentialId};
use crate::common_models::credential_schema::{CredentialSchema, CredentialSchemaId};
use crate::common_models::did::{Did, DidId, DidValue};
use crate::common_models::interaction::{Interaction, InteractionId};
use crate::common_models::key::Key;
use crate::common_models::key::KeyId;
use crate::common_models::organisation::Organisation;
use crate::common_models::proof::Proof;
use crate::credential_formatter::model::DetailCredential;

pub mod error;
pub mod imp;
pub mod mapper;
pub mod model;
pub mod proof_formatter;
pub mod service;
pub mod validator;

pub type FormatMapper = Arc<dyn Fn(&str) -> Result<String, ExchangeProtocolError> + Send + Sync>;
pub type TypeToDescriptorMapper = Arc<
    dyn Fn(
            &str,
        ) -> Result<
            HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat>,
            ExchangeProtocolError,
        > + Send
        + Sync,
>;

#[cfg(test)]
mod test;

#[derive(Debug, Error)]
pub enum ExchangeProtocolError {
    #[error("Exchange protocol failure: `{0}`")]
    Failed(String),
    #[error("Exchange protocol disabled: `{0}`")]
    Disabled(String),
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Base url is unknown")]
    MissingBaseUrl,
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Incorrect credential schema type")]
    IncorrectCredentialSchemaType,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    StorageAccessError(anyhow::Error),
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait StorageProxy: Send + Sync {
    async fn create_interaction(&self, interaction: Interaction) -> anyhow::Result<InteractionId>;
    async fn get_schema(&self, schema_id: &str) -> anyhow::Result<Option<CredentialSchema>>;
    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: &str,
    ) -> anyhow::Result<Vec<Credential>>;
    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> anyhow::Result<CredentialSchemaId>;
    async fn create_did(&self, did: Did) -> anyhow::Result<DidId>;
    async fn get_did_by_value(&self, value: &DidValue) -> anyhow::Result<Option<Did>>;
}
pub type StorageAccess = dyn StorageProxy;

pub struct BasicSchemaData {
    pub schema_id: String,
    pub schema_type: String,
}

pub struct BuildCredentialSchemaResponse {
    pub claims: Vec<Claim>,
    pub schema: CredentialSchema,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait HandleInvitationOperations: Send + Sync {
    /// Utilizes custom logic to find out credential schema
    /// name from credential offer
    async fn get_credential_schema_name(
        &self,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
    ) -> Result<String, ExchangeProtocolError>;

    /// Utilizes custom logic to find out credential schema
    /// type and id from credential offer
    async fn find_schema_data(
        &self,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
    ) -> BasicSchemaData;

    /// Allows use of custom logic to create new credential schema for
    /// incoming credential
    async fn create_new_schema(
        &self,
        schema_data: &BasicSchemaData,
        claim_keys: &HashMap<String, OpenID4VCICredentialValueDetails>,
        credential_id: &CredentialId,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential_schema_name: &str,
    ) -> Result<BuildCredentialSchemaResponse, ExchangeProtocolError>;
}
pub type HandleInvitationOperationsAccess = dyn HandleInvitationOperations;

#[cfg_attr(any(test, feature = "mock"), mockall::automock(type VCInteractionContext = (); type VPInteractionContext = ();))]
#[async_trait::async_trait]
pub trait ExchangeProtocolImpl: Send + Sync {
    type VCInteractionContext;
    type VPInteractionContext;

    // holder methods
    fn can_handle(&self, url: &Url) -> bool;

    async fn handle_invitation(
        &self,
        url: Url,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError>;

    async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError>;

    #[allow(clippy::too_many_arguments)]
    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError>;

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError>;

    async fn reject_credential(&self, credential: &Credential)
        -> Result<(), ExchangeProtocolError>;

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
        context: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
        types: HashMap<String, DatatypeType>,
        organisation: Organisation,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError>;

    // issuer methods
    /// Generates QR-code content to start the credential issuance flow
    async fn share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError>;

    // verifier methods
    /// Generates QR-code content to start the proof request flow
    async fn share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, model::OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError>;

    /// For now: Specially for ScanToVerify
    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError>;
}
