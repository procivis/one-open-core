//! LVVC implementation.

use std::{collections::HashMap, ops::Sub, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_with::DurationSeconds;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    common_models::{
        credential::{OpenCredential, OpenCredentialRole},
        did::{DidValue, KeyRole},
    },
    credential_formatter::{
        imp::jwt::{model::JWTPayload, Jwt},
        model::{CredentialData, CredentialSchemaData, CredentialStatus},
        provider::CredentialFormatterProvider,
        CredentialFormatter,
    },
    did::provider::DidMethodProvider,
    key_storage::provider::KeyProvider,
    revocation::{
        error::RevocationError,
        imp::lvvc::dto::{IssuerResponseDTO, Lvvc},
        model::{
            CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
            CredentialRevocationState, JsonLdContext, RevocationMethodCapabilities,
            RevocationUpdate, VerifierCredentialData,
        },
        RevocationMethod,
    },
};

pub mod dto;
pub mod mapper;

#[cfg(test)]
mod test;

use self::{
    dto::LvvcStatus,
    mapper::{create_id_claim, create_status_claims, status_from_lvvc_claims},
};

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub credential_expiry: time::Duration,
    pub json_ld_context_url: Option<String>,
}

pub struct LvvcProvider {
    core_base_url: Option<String>,
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    client: reqwest::Client,
    params: Params,
}

#[allow(clippy::too_many_arguments)]
impl LvvcProvider {
    pub fn new(
        core_base_url: Option<String>,
        credential_formatter: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        client: reqwest::Client,
        params: Params,
    ) -> Self {
        Self {
            core_base_url,
            credential_formatter,
            did_method_provider,
            key_provider,
            client,
            params,
        }
    }

    fn get_base_url(&self) -> Result<&String, RevocationError> {
        self.core_base_url.as_ref().ok_or_else(|| {
            RevocationError::MappingError("LVVC issuance is missing core base_url".to_string())
        })
    }

    fn formatter(
        &self,
        credential: &OpenCredential,
    ) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let format = credential
            .schema
            .as_ref()
            .map(|schema| schema.format.as_str())
            .ok_or(RevocationError::MappingError(
                "credential_schema is None".to_string(),
            ))?;

        let formatter = self
            .credential_formatter
            .get_formatter(format)
            .ok_or_else(|| RevocationError::FormatterNotFound(format.to_owned()))?;

        Ok(formatter)
    }

    async fn create_lvvc_with_status(
        &self,
        credential: &OpenCredential,
        status: LvvcStatus,
    ) -> Result<RevocationUpdate, RevocationError> {
        Ok(RevocationUpdate {
            status_type: self.get_status_type(),
            data: serde_json::to_vec(
                &create_lvvc_with_status(
                    credential,
                    status,
                    &self.core_base_url,
                    self.params.credential_expiry,
                    self.formatter(credential)?,
                    self.key_provider.clone(),
                    self.did_method_provider.clone(),
                    self.get_json_ld_context()?,
                )
                .await?,
            )?,
        })
    }

    async fn check_revocation_status_as_holder_or_issuer(
        &self,
        credential: &OpenCredential,
        credential_status: &CredentialStatus,
    ) -> Result<CredentialRevocationState, RevocationError> {
        let bearer_token = prepare_bearer_token(credential, self.key_provider.clone()).await?;

        let lvvc_check_url =
            credential_status
                .id
                .as_ref()
                .ok_or(RevocationError::ValidationError(
                    "LVVC status id is missing".to_string(),
                ))?;

        let response: IssuerResponseDTO = self
            .client
            .get(lvvc_check_url)
            .bearer_auth(bearer_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let formatter = self
            .credential_formatter
            .get_formatter(&response.format)
            .ok_or(RevocationError::FormatterNotFound(response.format))?;

        let lvvc = formatter
            .extract_credentials_unverified(&response.credential)
            .await?;

        let status = status_from_lvvc_claims(&lvvc.claims.values)?;
        Ok(match status {
            LvvcStatus::Accepted => CredentialRevocationState::Valid,
            LvvcStatus::Revoked => CredentialRevocationState::Revoked,
            LvvcStatus::Suspended { suspend_end_date } => {
                CredentialRevocationState::Suspended { suspend_end_date }
            }
        })
    }

    fn check_revocation_status_as_verifier(
        &self,
        issuer_did: &DidValue,
        data: VerifierCredentialData,
    ) -> Result<CredentialRevocationState, RevocationError> {
        let credential_id = data
            .credential
            .id
            .as_ref()
            .ok_or(RevocationError::ValidationError(
                "credential id missing".to_string(),
            ))?;

        let lvvc = data
            .extracted_lvvcs
            .iter()
            .find(|lvvc| {
                if let Some((_, id)) = lvvc.claims.values.iter().find(|(key, _)| *key == "id") {
                    *id == *credential_id
                } else {
                    false
                }
            })
            .ok_or(RevocationError::ValidationError(
                "no matching LVVC found among credentials".to_string(),
            ))?;

        let lvvc_issuer_did = lvvc
            .issuer_did
            .as_ref()
            .ok_or(RevocationError::ValidationError(
                "LVVC issuer DID missing".to_string(),
            ))?;

        if *issuer_did != Into::<DidValue>::into(Into::<String>::into(lvvc_issuer_did.clone())) {
            return Err(RevocationError::ValidationError(
                "LVVC issuer DID is not equal to issuer DID".to_string(),
            ));
        }

        let lvvc_issued_at = lvvc.issued_at.ok_or(RevocationError::ValidationError(
            "LVVC issued_at missing".to_string(),
        ))?;

        if let Some(validity_constraint) = data.proof_input.validity_constraint {
            let now = OffsetDateTime::now_utc();

            if now.sub(Duration::seconds(validity_constraint)) > lvvc_issued_at {
                return Err(RevocationError::ValidationError(
                    "LVVC has expired".to_string(),
                ));
            }
        }

        let status = status_from_lvvc_claims(&lvvc.claims.values)?;
        Ok(match status {
            LvvcStatus::Accepted => CredentialRevocationState::Valid,
            LvvcStatus::Revoked => CredentialRevocationState::Revoked,
            LvvcStatus::Suspended { suspend_end_date } => {
                CredentialRevocationState::Suspended { suspend_end_date }
            }
        })
    }

    fn get_json_ld_context_url(&self) -> Result<Option<String>, RevocationError> {
        if let Some(json_ld_params_context_url) = &self.params.json_ld_context_url {
            return Ok(Some(json_ld_params_context_url.to_string()));
        }
        Ok(Some(format!(
            "{}/ssi/context/v1/lvvc.json",
            self.get_base_url()?
        )))
    }
}

#[async_trait::async_trait]
impl RevocationMethod for LvvcProvider {
    fn get_status_type(&self) -> String {
        "LVVC".to_string()
    }

    async fn add_issued_credential(
        &self,
        credential: &OpenCredential,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError> {
        let base_url = self.get_base_url()?;

        Ok((
            Some(
                self.create_lvvc_with_status(credential, LvvcStatus::Accepted)
                    .await?,
            ),
            vec![CredentialRevocationInfo {
                credential_status: CredentialStatus {
                    id: Some(format!(
                        "{base_url}/ssi/revocation/v1/lvvc/{}",
                        credential.id
                    )),
                    r#type: self.get_status_type(),
                    status_purpose: None,
                    additional_fields: HashMap::new(),
                },
            }],
        ))
    }

    async fn mark_credential_as(
        &self,
        credential: &OpenCredential,
        new_state: CredentialRevocationState,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError> {
        match new_state {
            CredentialRevocationState::Revoked => {
                self.create_lvvc_with_status(credential, LvvcStatus::Revoked)
                    .await
            }
            CredentialRevocationState::Valid => {
                self.create_lvvc_with_status(credential, LvvcStatus::Accepted)
                    .await
            }
            CredentialRevocationState::Suspended { suspend_end_date } => {
                self.create_lvvc_with_status(credential, LvvcStatus::Suspended { suspend_end_date })
                    .await
            }
        }
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, RevocationError> {
        let additional_credential_data = additional_credential_data.ok_or(
            RevocationError::ValidationError("additional_credential_data is None".to_string()),
        )?;

        match additional_credential_data {
            CredentialDataByRole::Holder(credential) | CredentialDataByRole::Issuer(credential) => {
                self.check_revocation_status_as_holder_or_issuer(&credential, credential_status)
                    .await
            }
            CredentialDataByRole::Verifier(data) => {
                self.check_revocation_status_as_verifier(issuer_did, *data)
            }
        }
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string(), "SUSPEND".to_string()],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext {
            revokable_credential_type: "LvvcCredential".to_string(),
            revokable_credential_subject: "Lvvc".to_string(),
            url: self.get_json_ld_context_url()?,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_lvvc_with_status(
    credential: &OpenCredential,
    status: LvvcStatus,
    core_base_url: &Option<String>,
    credential_expiry: time::Duration,
    formatter: Arc<dyn CredentialFormatter>,
    key_provider: Arc<dyn KeyProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    json_ld_context: JsonLdContext,
) -> Result<Lvvc, RevocationError> {
    let base_url = core_base_url.as_ref().ok_or_else(|| {
        RevocationError::MappingError("LVVC issuance is missing core base_url".to_string())
    })?;
    let issuer_did = credential.issuer_did.as_ref().ok_or_else(|| {
        RevocationError::MappingError("LVVC issuance is missing issuer DID".to_string())
    })?;
    let holder_did = credential.holder_did.as_ref().ok_or_else(|| {
        RevocationError::MappingError("LVVC issuance is missing holder DID".to_string())
    })?;
    let schema = credential.schema.as_ref().ok_or_else(|| {
        RevocationError::MappingError("LVVC issuance is missing credential schema".to_string())
    })?;

    let key = credential
        .key
        .as_ref()
        .ok_or_else(|| RevocationError::MappingError("LVVC issuance is missing key".to_string()))?
        .to_owned();

    let did_document = did_method_provider
        .resolve(&issuer_did.did.to_string().into())
        .await?;
    let assertion_methods = did_document
        .assertion_method
        .ok_or(RevocationError::MappingError(
            "Missing assertion_method keys".to_owned(),
        ))?;

    let issuer_jwk_key_id = match assertion_methods
        .iter()
        .find(|id| id.contains(&key.id.to_string()))
        .cloned()
    {
        Some(id) => id,
        None => assertion_methods
            .first()
            .ok_or(RevocationError::MappingError(
                "Missing first assertion_method key".to_owned(),
            ))?
            .to_owned(),
    };

    let auth_fn = key_provider.get_signature_provider(&key.to_owned(), Some(issuer_jwk_key_id))?;

    let lvvc_credential_id = Uuid::new_v4();
    let mut claims = vec![create_id_claim(base_url, credential.id)];
    claims.extend(create_status_claims(&status)?);

    let credential_data = CredentialData {
        id: format!("{base_url}/ssi/lvvc/v1/{lvvc_credential_id}"),
        issuance_date: OffsetDateTime::now_utc(),
        valid_for: credential_expiry,
        claims,
        issuer_did: issuer_did.did.to_owned(),
        status: vec![],
        schema: CredentialSchemaData {
            id: None,
            context: None,
            r#type: None,
            name: schema.name.to_owned(),
        },
    };

    let formatted_credential = formatter
        .format_credentials(
            credential_data,
            &holder_did.did.clone(),
            &key.key_type,
            vec![],
            vec![json_ld_context.revokable_credential_type],
            auth_fn,
            json_ld_context.url,
            Some(json_ld_context.revokable_credential_subject),
        )
        .await?;

    let lvvc_credential = Lvvc {
        id: lvvc_credential_id,
        created_date: OffsetDateTime::now_utc(),
        credential: formatted_credential.into_bytes(),
        linked_credential_id: credential.id.into(),
    };

    Ok(lvvc_credential)
}

pub async fn prepare_bearer_token(
    credential: &OpenCredential,
    key_provider: Arc<dyn KeyProvider>,
) -> Result<String, RevocationError> {
    let did = match credential.role {
        OpenCredentialRole::Holder => {
            credential
                .holder_did
                .as_ref()
                .ok_or(RevocationError::MappingError(
                    "holder_did is None".to_string(),
                ))
        }
        OpenCredentialRole::Issuer => {
            credential
                .issuer_did
                .as_ref()
                .ok_or(RevocationError::MappingError(
                    "issuer_did is None".to_string(),
                ))
        }
        OpenCredentialRole::Verifier => Err(RevocationError::MappingError(
            "cannot prepare bearer_token for verifier".to_string(),
        )),
    }?;
    let keys = did
        .keys
        .as_ref()
        .ok_or(RevocationError::MappingError("keys is None".to_string()))?;
    let authentication_key = keys
        .iter()
        .find(|key| key.role == KeyRole::Authentication)
        .ok_or(RevocationError::MappingError(
            "No authentication keys found for DID".to_string(),
        ))?;

    let payload = JWTPayload {
        custom: BearerTokenPayload {
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
        },
        ..Default::default()
    };

    let signer = key_provider.get_signature_provider(&authentication_key.key.to_owned(), None)?;
    let bearer_token = Jwt::new("JWT".to_string(), "HS256".to_string(), None, payload)
        .tokenize(signer)
        .await?;

    Ok(bearer_token)
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct BearerTokenPayload {
    pub timestamp: i64,
}
