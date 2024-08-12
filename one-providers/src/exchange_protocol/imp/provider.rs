//! Exchange protocol provider.

use std::collections::HashMap;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use url::Url;

use crate::common_dto::PublicKeyJwkDTO;
use crate::common_models::credential::OpenCredential;
use crate::common_models::did::OpenDid;
use crate::common_models::key::{KeyId, OpenKey};
use crate::common_models::organisation::OpenOrganisation;
use crate::common_models::proof::OpenProof;
use crate::credential_formatter::model::DetailCredential;
use crate::exchange_protocol::openid4vc::model::{
    DatatypeType, InvitationResponseDTO, OpenID4VPFormat, PresentationDefinitionResponseDTO,
    PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use crate::exchange_protocol::openid4vc::service::FnMapExternalFormatToExternalDetailed;
#[cfg(any(test, feature = "mock"))]
use crate::exchange_protocol::openid4vc::MockExchangeProtocolImpl;
use crate::exchange_protocol::openid4vc::{
    ExchangeProtocolError, ExchangeProtocolImpl, FormatMapper, HandleInvitationOperationsAccess,
    StorageAccess, TypeToDescriptorMapper,
};
use crate::exchange_protocol::provider::{ExchangeProtocol, ExchangeProtocolProvider};

#[cfg(any(test, feature = "mock"))]
pub type MockExchangeProtocol = ExchangeProtocolWrapper<MockExchangeProtocolImpl>;

#[derive(Default)]
pub struct ExchangeProtocolWrapper<T> {
    pub inner: T,
}

impl<T> ExchangeProtocolWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<T> ExchangeProtocolImpl for ExchangeProtocolWrapper<T>
where
    T: ExchangeProtocolImpl,
    T::VCInteractionContext: Serialize + DeserializeOwned,
    T::VPInteractionContext: Serialize + DeserializeOwned,
{
    type VCInteractionContext = serde_json::Value;
    type VPInteractionContext = serde_json::Value;

    fn can_handle(&self, url: &Url) -> bool {
        self.inner.can_handle(url)
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: OpenOrganisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        self.inner
            .handle_invitation(
                url,
                organisation,
                storage_access,
                handle_invitation_operations,
            )
            .await
    }

    async fn reject_proof(&self, proof: &OpenProof) -> Result<(), ExchangeProtocolError> {
        self.inner.reject_proof(proof).await
    }

    async fn submit_proof(
        &self,
        proof: &OpenProof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &OpenDid,
        key: &OpenKey,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        self.inner
            .submit_proof(
                proof,
                credential_presentations,
                holder_did,
                key,
                jwk_key_id,
                format_map,
                presentation_format_map,
            )
            .await
    }

    async fn accept_credential(
        &self,
        credential: &OpenCredential,
        holder_did: &OpenDid,
        key: &OpenKey,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        map_external_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        self.inner
            .accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
                format,
                storage_access,
                map_external_format_to_external,
            )
            .await
    }

    async fn reject_credential(
        &self,
        credential: &OpenCredential,
    ) -> Result<(), ExchangeProtocolError> {
        self.inner.reject_credential(credential).await
    }

    async fn get_presentation_definition(
        &self,
        proof: &OpenProof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
        types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let interaction_data =
            serde_json::from_value(interaction_data).map_err(ExchangeProtocolError::JsonError)?;
        self.inner
            .get_presentation_definition(proof, interaction_data, storage_access, format_map, types)
            .await
    }

    async fn share_credential(
        &self,
        credential: &OpenCredential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        self.inner
            .share_credential(credential, credential_format)
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                id: resp.id,
                context: serde_json::json!(resp.context),
            })
    }

    async fn share_proof(
        &self,
        proof: &OpenProof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        self.inner
            .share_proof(
                proof,
                format_to_type_mapper,
                key_id,
                encryption_key_jwk,
                vp_formats,
                type_to_descriptor,
            )
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                id: resp.id,
                context: serde_json::json!(resp.context),
            })
    }

    async fn verifier_handle_proof(
        &self,
        proof: &OpenProof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        self.inner.verifier_handle_proof(proof, submission).await
    }
}

impl<T> ExchangeProtocol for ExchangeProtocolWrapper<T>
where
    T: ExchangeProtocolImpl,
    T::VCInteractionContext: Serialize + DeserializeOwned,
    T::VPInteractionContext: Serialize + DeserializeOwned,
{
}

pub struct ExchangeProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn ExchangeProtocol>>,
}

impl ExchangeProtocolProviderImpl {
    pub fn new(protocols: HashMap<String, Arc<dyn ExchangeProtocol>>) -> Self {
        Self { protocols }
    }
}

#[async_trait::async_trait]
impl ExchangeProtocolProvider for ExchangeProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn ExchangeProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    fn detect_protocol(&self, url: &Url) -> Option<Arc<dyn ExchangeProtocol>> {
        self.protocols
            .values()
            .find(|protocol| protocol.can_handle(url))
            .cloned()
    }
}
