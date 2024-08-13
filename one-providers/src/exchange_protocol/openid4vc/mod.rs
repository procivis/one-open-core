//! Tools for exchanging credentials using OpenID4VC.
//!
//! Exchange protocols govern the direct exchange of credentials. They define
//! the types of messages sent and their content, whenever credentials are
//! exchanged between parties.
//!
//! This module contains traits for implementing a chosen storage layer as
//! well as credential schema handling. These must be implemented to enable
//! the use of an exchange protocol.
//!
//! Methods for issuing, holding, and verifying in OpenID4VC are found in
//! `ExchangeProtocolImpl` trait.

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
use crate::common_models::claim::OpenClaim;
use crate::common_models::credential::{CredentialId, OpenCredential};
use crate::common_models::credential_schema::{CredentialSchemaId, OpenCredentialSchema};
use crate::common_models::did::{DidId, DidValue, OpenDid};
use crate::common_models::interaction::{InteractionId, OpenInteraction};
use crate::common_models::key::KeyId;
use crate::common_models::key::OpenKey;
use crate::common_models::organisation::{OpenOrganisation, OrganisationId};
use crate::common_models::proof::OpenProof;
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

/// Interface to be implemented in order to use an exchange protocol.
///
/// The exchange protocol provider relies on storage of data for interactions,
/// credentials, credential schemas, and DIDs. A storage layer must be
/// chosen and implemented for the exchange protocol to be enabled.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait StorageProxy: Send + Sync {
    /// Store an interaction with a chosen storage layer.
    async fn create_interaction(
        &self,
        interaction: OpenInteraction,
    ) -> anyhow::Result<InteractionId>;
    /// Get a credential schema from a chosen storage layer.
    async fn get_schema(
        &self,
        schema_id: &str,
        schema_type: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<OpenCredentialSchema>>;
    /// Get credentials from a specified schema ID, from a chosen storage layer.
    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: &str,
    ) -> anyhow::Result<Vec<OpenCredential>>;
    /// Create a credential schema in a chosen storage layer.
    async fn create_credential_schema(
        &self,
        schema: OpenCredentialSchema,
    ) -> anyhow::Result<CredentialSchemaId>;
    /// Create a DID in a chosen storage layer.
    async fn create_did(&self, did: OpenDid) -> anyhow::Result<DidId>;
    /// Obtain a DID by its address, from a chosen storage layer.
    async fn get_did_by_value(&self, value: &DidValue) -> anyhow::Result<Option<OpenDid>>;
}
pub type StorageAccess = dyn StorageProxy;

pub struct BasicSchemaData {
    pub schema_id: String,
    pub schema_type: String,
}

pub struct BuildCredentialSchemaResponse {
    pub claims: Vec<OpenClaim>,
    pub schema: OpenCredentialSchema,
}

/// Interface to be implemented in order to use an exchange protocol.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[allow(clippy::too_many_arguments)]
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
        organisation: OpenOrganisation,
    ) -> Result<BuildCredentialSchemaResponse, ExchangeProtocolError>;
}
pub type HandleInvitationOperationsAccess = dyn HandleInvitationOperations;

/// This trait contains methods for exchanging credentials between issuers,
/// holders, and verifiers.
#[cfg_attr(any(test, feature = "mock"), mockall::automock(type VCInteractionContext = (); type VPInteractionContext = ();))]
#[async_trait::async_trait]
#[allow(clippy::too_many_arguments)]
pub trait ExchangeProtocolImpl: Send + Sync {
    type VCInteractionContext;
    type VPInteractionContext;

    // Holder methods:
    /// Check if the holder can handle the necessary URLs.
    fn can_handle(&self, url: &Url) -> bool;

    /// For handling credential issuance and verification, this method
    /// saves the offer information coming in.
    async fn handle_invitation(
        &self,
        url: Url,
        organisation: OpenOrganisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError>;

    /// Rejects a verifier's request for credential presentation.
    async fn reject_proof(&self, proof: &OpenProof) -> Result<(), ExchangeProtocolError>;

    /// Submits a presentation to a verifier.
    #[allow(clippy::too_many_arguments)]
    async fn submit_proof(
        &self,
        proof: &OpenProof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &OpenDid,
        key: &OpenKey,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError>;

    /// Accepts an offered credential.
    ///
    /// Storage access must be implemented.
    async fn accept_credential(
        &self,
        credential: &OpenCredential,
        holder_did: &OpenDid,
        key: &OpenKey,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        // This helps map to correct formatter key if crypto suite hast o be scanned.
        map_external_format_to_external: service::FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError>;

    /// Rejects an offered credential.
    async fn reject_credential(
        &self,
        credential: &OpenCredential,
    ) -> Result<(), ExchangeProtocolError>;

    /// Takes a proof request and filters held credentials,
    /// returning those which are acceptable for the request.
    ///
    /// Storage access is needed to check held credentials.
    async fn get_presentation_definition(
        &self,
        proof: &OpenProof,
        context: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
        types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError>;

    // Issuer methods:
    /// Generates QR-code content to start the credential issuance flow.
    async fn share_credential(
        &self,
        credential: &OpenCredential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError>;

    // Verifier methods:
    /// Generates QR-code content to start the proof request flow.
    async fn share_proof(
        &self,
        proof: &OpenProof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, model::OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError>;

    /// Checks if the submitted presentation complies with the given proof request.
    async fn verifier_handle_proof(
        &self,
        proof: &OpenProof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError>;
}
