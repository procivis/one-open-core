//! Bitstring Status List implementation.

use std::{collections::HashMap, sync::Arc};

use resolver::StatusListResolver;

use crate::http_client::HttpClient;
use crate::{
    common_models::{
        credential::{CredentialId, OpenCredential, OpenCredentialStateEnum},
        did::{DidId, DidValue, KeyRole, OpenDid},
    },
    credential_formatter::model::CredentialStatus,
    did::provider::DidMethodProvider,
    key_algorithm::provider::KeyAlgorithmProvider,
    key_storage::provider::KeyProvider,
    revocation::{
        error::RevocationError,
        imp::bitstring_status_list::{
            jwt_formatter::BitstringStatusListJwtFormatter,
            model::{RevocationListPurpose, RevocationUpdateData, StatusPurpose},
            resolver::StatusListCachingLoader,
        },
        model::{
            CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
            CredentialRevocationState, JsonLdContext, RevocationListId,
            RevocationMethodCapabilities, RevocationUpdate,
        },
        RevocationMethod,
    },
    util::key_verification::KeyVerification,
};

mod jwt_formatter;
pub mod model;
pub mod resolver;
pub mod util;

const CREDENTIAL_STATUS_TYPE: &str = "BitstringStatusListEntry";

pub struct BitstringStatusList {
    pub core_base_url: Option<String>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_provider: Arc<dyn KeyProvider>,
    pub caching_loader: StatusListCachingLoader,
    resolver: Arc<StatusListResolver>,
}

impl BitstringStatusList {
    pub fn new(
        core_base_url: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        caching_loader: StatusListCachingLoader,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            core_base_url,
            key_algorithm_provider,
            did_method_provider,
            key_provider,
            caching_loader,
            resolver: Arc::new(StatusListResolver::new(client)),
        }
    }
}

#[async_trait::async_trait]
impl RevocationMethod for BitstringStatusList {
    fn get_status_type(&self) -> String {
        CREDENTIAL_STATUS_TYPE.to_string()
    }

    async fn add_issued_credential(
        &self,
        credential: &OpenCredential,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError> {
        let data = additional_data.ok_or(RevocationError::MappingError(
            "additional_data is None".to_string(),
        ))?;

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?;

        let index_on_status_list = self
            .get_credential_index_on_revocation_list(
                &data.credentials_by_issuer_did,
                &credential.id,
                &issuer_did.id,
            )
            .await?;

        Ok((
            None,
            vec![
                CredentialRevocationInfo {
                    credential_status: self.create_credential_status(
                        &data.revocation_list_id,
                        index_on_status_list,
                        "revocation",
                    )?,
                },
                CredentialRevocationInfo {
                    credential_status: self.create_credential_status(
                        &data.suspension_list_id,
                        index_on_status_list,
                        "suspension",
                    )?,
                },
            ],
        ))
    }

    async fn mark_credential_as(
        &self,
        credential: &OpenCredential,
        new_state: CredentialRevocationState,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError> {
        let additional_data = additional_data.ok_or(RevocationError::MappingError(
            "additional_data is None".to_string(),
        ))?;

        match new_state {
            CredentialRevocationState::Revoked => {
                self.mark_credential_as_impl(
                    RevocationListPurpose::Revocation,
                    credential,
                    true,
                    additional_data,
                )
                .await
            }
            CredentialRevocationState::Valid => {
                self.mark_credential_as_impl(
                    RevocationListPurpose::Suspension,
                    credential,
                    false,
                    additional_data,
                )
                .await
            }
            CredentialRevocationState::Suspended { .. } => {
                self.mark_credential_as_impl(
                    RevocationListPurpose::Suspension,
                    credential,
                    true,
                    additional_data,
                )
                .await
            }
        }
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        _additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, RevocationError> {
        if credential_status.r#type != CREDENTIAL_STATUS_TYPE {
            return Err(RevocationError::ValidationError(format!(
                "Invalid credential status type: {}",
                credential_status.r#type
            )));
        }

        let list_url = credential_status
            .additional_fields
            .get("statusListCredential")
            .and_then(|url| url.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list url".to_string(),
            ))?;

        let list_index = credential_status
            .additional_fields
            .get("statusListIndex")
            .and_then(|index| index.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list index".to_string(),
            ))?;
        let list_index: usize = list_index
            .parse()
            .map_err(|_| RevocationError::ValidationError("Invalid list index".to_string()))?;

        let response = String::from_utf8(
            self.caching_loader
                .get(list_url, self.resolver.clone())
                .await?,
        )?;

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let encoded_list = BitstringStatusListJwtFormatter::parse_status_list(
            &response,
            issuer_did,
            key_verification,
        )
        .await?;

        if util::extract_bitstring_index(encoded_list, list_index)? {
            Ok(match credential_status.status_purpose.as_ref() {
                Some(purpose) => match purpose.as_str() {
                    "revocation" => CredentialRevocationState::Revoked,
                    "suspension" => CredentialRevocationState::Suspended {
                        suspend_end_date: None,
                    },
                    _ => {
                        return Err(RevocationError::ValidationError(format!(
                            "Invalid status purpose: {purpose}",
                        )))
                    }
                },
                None => {
                    return Err(RevocationError::ValidationError(
                        "Missing status purpose ".to_string(),
                    ))
                }
            })
        } else {
            Ok(CredentialRevocationState::Valid)
        }
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string(), "SUSPEND".to_string()],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }
}

impl BitstringStatusList {
    async fn get_credential_index_on_revocation_list(
        &self,
        credentials_by_issuer_did: &[OpenCredential],
        credential_id: &CredentialId,
        issuer_did_id: &DidId,
    ) -> Result<usize, RevocationError> {
        let index = credentials_by_issuer_did
            .iter()
            .position(|credential| credential.id == *credential_id)
            .ok_or(RevocationError::MissingCredentialIndexOnRevocationList(
                *credential_id,
                *issuer_did_id,
            ))?;

        Ok(index)
    }

    fn create_credential_status(
        &self,
        revocation_list_id: &RevocationListId,
        index_on_status_list: usize,
        purpose: &str,
    ) -> Result<CredentialStatus, RevocationError> {
        let revocation_list_url = get_revocation_list_url(revocation_list_id, &self.core_base_url)?;
        Ok(CredentialStatus {
            id: Some(uuid::Uuid::new_v4().urn().to_string()),
            r#type: CREDENTIAL_STATUS_TYPE.to_string(),
            status_purpose: Some(purpose.to_string()),
            additional_fields: HashMap::from([
                (
                    "statusListCredential".to_string(),
                    revocation_list_url.into(),
                ),
                (
                    "statusListIndex".to_string(),
                    index_on_status_list.to_string().into(),
                ),
            ]),
        })
    }

    async fn mark_credential_as_impl(
        &self,
        purpose: RevocationListPurpose,
        credential: &OpenCredential,
        new_revocation_value: bool,
        data: CredentialAdditionalData,
    ) -> Result<RevocationUpdate, RevocationError> {
        let list_id = match purpose {
            RevocationListPurpose::Revocation => data.revocation_list_id,
            RevocationListPurpose::Suspension => data.suspension_list_id,
        };

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?
            .clone();

        let encoded_list = generate_bitstring_from_credentials(
            &data.credentials_by_issuer_did,
            purpose_to_credential_state_enum(purpose.to_owned()),
            Some(BitstringCredentialInfo {
                credential_id: credential.id,
                value: new_revocation_value,
            }),
        )
        .await?;

        let list_credential = format_status_list_credential(
            &list_id,
            &issuer_did,
            encoded_list,
            purpose,
            &self.key_provider,
            &self.core_base_url,
        )
        .await?;

        Ok(RevocationUpdate {
            status_type: self.get_status_type(),
            data: serde_json::to_vec(&RevocationUpdateData {
                id: list_id,
                value: list_credential.as_bytes().to_vec(),
            })?,
        })
    }
}

pub struct BitstringCredentialInfo {
    pub credential_id: CredentialId,
    pub value: bool,
}

pub fn purpose_to_credential_state_enum(purpose: RevocationListPurpose) -> OpenCredentialStateEnum {
    match purpose {
        RevocationListPurpose::Revocation => OpenCredentialStateEnum::Revoked,
        RevocationListPurpose::Suspension => OpenCredentialStateEnum::Suspended,
    }
}

pub fn purpose_to_bitstring_status_purpose(purpose: RevocationListPurpose) -> StatusPurpose {
    match purpose {
        RevocationListPurpose::Revocation => StatusPurpose::Revocation,
        RevocationListPurpose::Suspension => StatusPurpose::Suspension,
    }
}

pub async fn format_status_list_credential(
    revocation_list_id: &RevocationListId,
    issuer_did: &OpenDid,
    encoded_list: String,
    purpose: RevocationListPurpose,
    key_provider: &Arc<dyn KeyProvider>,
    core_base_url: &Option<String>,
) -> Result<String, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;

    let keys = issuer_did
        .keys
        .as_ref()
        .ok_or(RevocationError::MappingError(
            "Issuer has no keys".to_string(),
        ))?;

    let key = keys
        .iter()
        .find(|k| k.role == KeyRole::AssertionMethod)
        .ok_or(RevocationError::KeyWithRoleNotFound(
            KeyRole::AssertionMethod,
        ))?;

    let auth_fn = key_provider.get_signature_provider(&key.key.to_owned(), None)?;

    let status_list = BitstringStatusListJwtFormatter::format_status_list(
        revocation_list_url,
        issuer_did,
        encoded_list,
        key.key.key_type.to_owned(),
        auth_fn,
        purpose_to_bitstring_status_purpose(purpose),
    )
    .await?;

    Ok(status_list)
}

pub async fn generate_bitstring_from_credentials(
    credentials_by_issuer_did: &[OpenCredential],
    matching_state: OpenCredentialStateEnum,
    additionally_changed_credential: Option<BitstringCredentialInfo>,
) -> Result<String, RevocationError> {
    let states = credentials_by_issuer_did
        .iter()
        .map(|credential| {
            if let Some(changed_credential) = additionally_changed_credential.as_ref() {
                if changed_credential.credential_id == credential.id {
                    return Ok(changed_credential.value);
                }
            }
            let states = credential
                .state
                .as_ref()
                .ok_or(RevocationError::MappingError("state is None".to_string()))?;
            let latest_state = states
                .first()
                .ok_or(RevocationError::MappingError(
                    "latest state not found".to_string(),
                ))?
                .state
                .to_owned();

            Ok(latest_state == matching_state)
        })
        .collect::<Result<Vec<_>, RevocationError>>()?;

    util::generate_bitstring(states).map_err(RevocationError::from)
}

pub fn get_revocation_list_url(
    revocation_list_id: &RevocationListId,
    core_base_url: &Option<String>,
) -> Result<String, RevocationError> {
    Ok(format!(
        "{}/ssi/revocation/v1/list/{}",
        core_base_url.as_ref().ok_or(RevocationError::MappingError(
            "Host URL not specified".to_string()
        ))?,
        revocation_list_id
    ))
}
