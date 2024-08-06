use std::collections::{HashMap, HashSet};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::common_models::credential::{OpenCredential, OpenCredentialStateEnum};
use crate::common_models::interaction::OpenInteraction;
use crate::exchange_protocol::openid4vc::model::{CredentialGroup, OpenID4VPInteractionData};
use crate::exchange_protocol::openid4vc::{ExchangeProtocolError, StorageAccess};

pub fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    interaction: Option<&OpenInteraction>,
) -> Result<DataDTO, ExchangeProtocolError> {
    let data = interaction
        .ok_or(ExchangeProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .data
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "interaction data is missing".to_string(),
        ))?;
    serde_json::from_slice(data).map_err(ExchangeProtocolError::JsonError)
}

pub fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, ExchangeProtocolError> {
    serde_json::to_vec(&dto).map_err(ExchangeProtocolError::JsonError)
}

pub async fn interaction_data_from_query(
    query: &str,
    client: &reqwest::Client,
    allow_insecure_http_transport: bool,
) -> Result<OpenID4VPInteractionData, ExchangeProtocolError> {
    let mut interaction_data: OpenID4VPInteractionData = serde_qs::from_str(query)
        .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

    if interaction_data.client_metadata.is_some() && interaction_data.client_metadata_uri.is_some()
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata and client_metadata_uri cannot be set together".to_string(),
        ));
    }

    if interaction_data.presentation_definition.is_some()
        && interaction_data.presentation_definition_uri.is_some()
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "presentation_definition and presentation_definition_uri cannot be set together"
                .to_string(),
        ));
    }

    if let Some(client_metadata_uri) = &interaction_data.client_metadata_uri {
        if !allow_insecure_http_transport && client_metadata_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "client_metadata_uri must use HTTPS scheme".to_string(),
            ));
        }

        let client_metadata = client
            .get(client_metadata_uri.to_owned())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .await
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.client_metadata = Some(client_metadata);
    }

    if let Some(presentation_definition_uri) = &interaction_data.presentation_definition_uri {
        if !allow_insecure_http_transport && presentation_definition_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "presentation_definition_uri must use HTTPS scheme".to_string(),
            ));
        }

        let presentation_definition = client
            .get(presentation_definition_uri.to_owned())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .await
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.presentation_definition = Some(presentation_definition);
    }

    Ok(interaction_data)
}

pub fn validate_interaction_data(
    interaction_data: &OpenID4VPInteractionData,
) -> Result<(), ExchangeProtocolError> {
    if interaction_data.redirect_uri.is_some() {
        return Err(ExchangeProtocolError::InvalidRequest(
            "redirect_uri must be None".to_string(),
        ));
    }
    assert_query_param(&interaction_data.response_type, "vp_token", "response_type")?;
    assert_query_param(
        &interaction_data.client_id_scheme,
        "redirect_uri",
        "client_id_scheme",
    )?;
    assert_query_param(
        &interaction_data.response_mode,
        "direct_post",
        "response_mode",
    )?;

    let client_metadata =
        interaction_data
            .client_metadata
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "client_metadata is None".to_string(),
            ))?;

    if client_metadata.client_id_scheme != interaction_data.client_id_scheme {
        return Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata.client_id_scheme must match client_scheme".to_string(),
        ));
    }

    match client_metadata.vp_formats.get("jwt_vp_json") {
        None => Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata.vp_formats must contain 'jwt_vp_json'".to_string(),
        )),
        Some(jwt_vp_json) => {
            if jwt_vp_json.alg.contains(&"EdDSA".to_string()) {
                Ok(())
            } else {
                Err(ExchangeProtocolError::InvalidRequest(
                    "client_metadata.vp_formats[\"jwt_vp_json\"] must contain 'EdDSA' algorithm"
                        .to_string(),
                ))
            }
        }
    }?;

    Ok(())
}

fn assert_query_param(
    value: &str,
    expected_value: &str,
    key: &str,
) -> Result<(), ExchangeProtocolError> {
    if value != expected_value {
        return Err(ExchangeProtocolError::InvalidRequest(format!(
            "{key} must be '{expected_value}'"
        )));
    }
    Ok(())
}

pub fn get_claim_name_by_json_path(path: &[String]) -> Result<String, ExchangeProtocolError> {
    const VC_CREDENTIAL_PREFIX: &str = "$.vc.credentialSubject.";

    match path.first() {
        Some(vc) if vc.starts_with(VC_CREDENTIAL_PREFIX) => {
            Ok(vc[VC_CREDENTIAL_PREFIX.len()..].to_owned())
        }

        Some(subscript_path) if subscript_path.starts_with("$['") => {
            let path: Vec<&str> = subscript_path
                .split(['$', '[', ']', '\''])
                .filter(|s| !s.is_empty())
                .collect();

            let json_pointer_path = path.join("/");

            if json_pointer_path.is_empty() {
                return Err(ExchangeProtocolError::Failed(format!(
                    "Invalid json path: {subscript_path}"
                )));
            }

            Ok(json_pointer_path)
        }
        Some(other) => Err(ExchangeProtocolError::Failed(format!(
            "Invalid json path: {other}"
        ))),

        None => Err(ExchangeProtocolError::Failed("No path".to_string())),
    }
}

pub async fn get_relevant_credentials_to_credential_schemas(
    storage_access: &StorageAccess,
    mut credential_groups: Vec<CredentialGroup>,
    group_id_to_schema_id_mapping: HashMap<String, String>,
    allowed_schema_formats: &HashSet<&str>,
) -> Result<(Vec<OpenCredential>, Vec<CredentialGroup>), ExchangeProtocolError> {
    let mut relevant_credentials: Vec<OpenCredential> = Vec::new();
    for group in &mut credential_groups {
        let credential_schema_id =
            group_id_to_schema_id_mapping
                .get(&group.id)
                .ok_or(ExchangeProtocolError::Failed(
                    "Incorrect group id to credential schema id mapping".to_owned(),
                ))?;

        let relevant_credentials_inner = storage_access
            .get_credentials_by_credential_schema_id(credential_schema_id)
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        for credential in &relevant_credentials_inner {
            let schema = credential
                .schema
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed("schema missing".to_string()))?;

            if !allowed_schema_formats
                .iter()
                // In case of JSON_LD we could have different crypto suits as separate formats.
                // This will work as long as we have common part as allowed format. In this case
                // it translates ldp_vc to JSON_LD that could be a common part of JSON_LD_CS1 and JSON_LD_CS2
                .any(|allowed_schema_format| schema.format.starts_with(allowed_schema_format))
            {
                continue;
            }

            let credential_state = credential
                .state
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed("state missing".to_string()))?
                .first()
                .ok_or(ExchangeProtocolError::Failed("state missing".to_string()))?;

            // only consider credentials that have finished the issuance flow
            if ![
                OpenCredentialStateEnum::Accepted,
                OpenCredentialStateEnum::Revoked,
                OpenCredentialStateEnum::Suspended,
            ]
            .contains(&credential_state.state.clone())
            {
                continue;
            }

            let claim_schemas = credential
                .claims
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed("claims missing".to_string()))?
                .iter()
                .map(|claim| {
                    claim
                        .schema
                        .as_ref()
                        .ok_or(ExchangeProtocolError::Failed("schema missing".to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if group.claims.iter().all(|requested_claim| {
                claim_schemas
                    .iter()
                    .any(|claim_schema| claim_schema.key.starts_with(&requested_claim.key))
            }) {
                if group.claims.iter().all(|requested_claim| {
                    claim_schemas.iter().any(|claim_schema| {
                        claim_schema.key.starts_with(&requested_claim.key)
                            && claim_schemas
                                .iter()
                                .filter(|other_schema| {
                                    other_schema.key.starts_with(&claim_schema.key)
                                        && other_schema.key != claim_schema.key
                                })
                                .any(|other_schema| other_schema.array)
                    })
                }) {
                    return Err(ExchangeProtocolError::Failed(
                        "field in array requested".into(),
                    ));
                }

                group.applicable_credentials.push(credential.to_owned());
                relevant_credentials.push(credential.to_owned());
            }
        }
    }

    Ok((relevant_credentials, credential_groups))
}
