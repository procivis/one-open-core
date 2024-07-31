use time::OffsetDateTime;
use uuid::Uuid;

use super::error::OpenID4VCIError;
use super::model::{
    CredentialClaimSchemaDTO, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesRequestDTO, CredentialSchemaCodeTypeEnum,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    DetailCredentialSchemaResponseDTO, DidListItemResponseDTO,
};
use super::{ExchangeProtocolError, FormatMapper, TypeToDescriptorMapper};
use crate::common_models::claim::Claim;
use crate::common_models::claim_schema::ClaimSchema;
use crate::common_models::credential::{
    Credential, CredentialId, CredentialRole, CredentialState, CredentialStateEnum,
};
use crate::common_models::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema, CredentialSchemaClaim,
    LayoutProperties, LogoProperties,
};
use crate::common_models::did::{Did, DidValue};
use crate::common_models::interaction::InteractionId;
use crate::common_models::organisation::OrganisationId;
use crate::common_models::proof::Proof;
use crate::common_models::proof_schema::ProofInputClaimSchema;
use crate::common_models::NESTED_CLAIM_MARKER;
use crate::credential_formatter::imp::json_ld::get_crypto_suite;
use crate::credential_formatter::model::ExtractPresentationCtx;
use crate::exchange_protocol::openid4vc::error::OpenID4VCError;
use crate::exchange_protocol::openid4vc::model::{
    OpenID4VCIInteractionDataDTO, OpenID4VCITokenResponseDTO, OpenID4VPInteractionContent,
    OpenID4VPPresentationDefinition, OpenID4VPPresentationDefinitionConstraint,
    OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor, ProvedCredential, Timestamp,
};

impl TryFrom<OpenID4VCIInteractionDataDTO> for OpenID4VCITokenResponseDTO {
    type Error = OpenID4VCIError;
    fn try_from(value: OpenID4VCIInteractionDataDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            access_token: value.access_token.to_string(),
            token_type: "bearer".to_string(),
            expires_in: Timestamp(
                value
                    .access_token_expires_at
                    .ok_or(OpenID4VCIError::RuntimeError(
                        "access_token_expires_at missing".to_string(),
                    ))?
                    .unix_timestamp(),
            ),
            refresh_token: value.refresh_token,
            refresh_token_expires_in: value
                .refresh_token_expires_at
                .map(|dt| Timestamp(dt.unix_timestamp())),
        })
    }
}

pub(super) fn parse_interaction_content(
    data: &[u8],
) -> Result<OpenID4VPInteractionContent, OpenID4VCError> {
    serde_json::from_slice(data).map_err(|e| OpenID4VCError::MappingError(e.to_string()))
}

pub(crate) fn vec_last_position_from_token_path(path: &str) -> Result<usize, OpenID4VCError> {
    // Find the position of '[' and ']'
    if let Some(open_bracket) = path.rfind('[') {
        if let Some(close_bracket) = path.rfind(']') {
            // Extract the substring between '[' and ']'
            let value = &path[open_bracket + 1..close_bracket];

            let parsed_value = value.parse().map_err(|_| {
                OpenID4VCError::MappingError("Could not parse vec position".to_string())
            })?;

            Ok(parsed_value)
        } else {
            Err(OpenID4VCError::MappingError(
                "Credential path is incorrect".to_string(),
            ))
        }
    } else {
        Ok(0)
    }
}

pub fn extract_presentation_ctx_from_interaction_content(
    content: OpenID4VPInteractionContent,
) -> ExtractPresentationCtx {
    ExtractPresentationCtx {
        nonce: Some(content.nonce),
        format_nonce: None,
        issuance_date: None,
        expiration_date: None,
    }
}

pub fn map_from_oidc_format_to_core_real(
    format: &str,
    token: &str,
) -> Result<String, OpenID4VCError> {
    match format {
        "jwt_vc_json" => Ok("JWT".to_string()),
        "vc+sd-jwt" => Ok("SDJWT".to_string()),
        "ldp_vc" => match get_crypto_suite(token) {
            Some(suite) => match suite.as_str() {
                "bbs-2023" => Ok("JSON_LD_BBSPLUS".to_string()),
                _ => Ok("JSON_LD_CLASSIC".to_string()),
            },
            None => Err(OpenID4VCError::OpenID4VCI(
                OpenID4VCIError::UnsupportedCredentialFormat,
            )),
        },
        _ => Err(OpenID4VCError::OpenID4VCI(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}

pub fn map_from_oidc_vp_format_to_core(format: &str) -> Result<String, OpenID4VCError> {
    match format {
        "jwt_vp_json" => Ok("JWT".to_string()),
        "ldp_vp" => Ok("JSON_LD_CLASSIC".to_string()),
        _ => Err(OpenID4VCError::OpenID4VCI(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}

pub fn extracted_credential_to_model(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema: CredentialSchema,
    claims: Vec<(serde_json::Value, ClaimSchema)>,
    issuer_did: &DidValue,
    holder_did: &DidValue,
) -> Result<ProvedCredential, OpenID4VCError> {
    let now = OffsetDateTime::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for (value, claim_schema) in claims {
        model_claims.extend(value_to_model_claims(
            credential_id,
            claim_schemas,
            &value,
            now,
            &claim_schema,
            &claim_schema.key,
        )?);
    }

    Ok(ProvedCredential {
        credential: Credential {
            id: credential_id,
            created_date: now,
            issuance_date: now,
            last_modified: now,
            deleted_at: None,
            credential: vec![],
            exchange: "OPENID4VC".to_string(),
            state: Some(vec![CredentialState {
                created_date: now,
                state: CredentialStateEnum::Accepted,
                suspend_end_date: None,
            }]),
            claims: Some(model_claims.to_owned()),
            issuer_did: None,
            holder_did: None,
            schema: Some(credential_schema),
            redirect_uri: None,
            key: None,
            role: CredentialRole::Verifier,
            interaction: None,
        },
        issuer_did_value: issuer_did.to_owned(),
        holder_did_value: holder_did.to_owned(),
    })
}

fn value_to_model_claims(
    credential_id: CredentialId,
    claim_schemas: &[CredentialSchemaClaim],
    json_value: &serde_json::Value,
    now: OffsetDateTime,
    claim_schema: &ClaimSchema,
    path: &str,
) -> Result<Vec<Claim>, OpenID4VCError> {
    let mut model_claims = vec![];

    match json_value {
        serde_json::Value::String(value) => {
            model_claims.push(Claim {
                id: Uuid::new_v4().into(),
                credential_id,
                created_date: now,
                last_modified: now,
                value: value.to_owned(),
                path: path.to_owned(),
                schema: Some(claim_schema.to_owned()),
            });
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let this_name = &claim_schema.key;
                let child_schema_name = format!("{this_name}/{key}");
                let child_credential_schema_claim = claim_schemas
                    .iter()
                    .find(|claim_schema| claim_schema.schema.key == child_schema_name)
                    .ok_or(OpenID4VCError::MissingClaimSchemas)?;
                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value,
                    now,
                    &child_credential_schema_claim.schema,
                    &format!("{path}/{key}"),
                )?);
            }
        }
        serde_json::Value::Array(array) => {
            for (index, value) in array.iter().enumerate() {
                let child_schema_path = format!("{path}/{index}");

                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value,
                    now,
                    claim_schema,
                    &child_schema_path,
                )?);
            }
        }
        _ => {
            return Err(OpenID4VCError::MappingError(
                "value type is not supported".to_string(),
            ));
        }
    }

    Ok(model_claims)
}

impl From<CredentialSchemaBackgroundPropertiesRequestDTO> for BackgroundProperties {
    fn from(value: CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaLogoPropertiesRequestDTO> for LogoProperties {
    fn from(value: CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaCodePropertiesRequestDTO> for CodeProperties {
    fn from(value: CredentialSchemaCodePropertiesRequestDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<CredentialSchemaCodeTypeEnum> for CodeTypeEnum {
    fn from(value: CredentialSchemaCodeTypeEnum) -> Self {
        match value {
            CredentialSchemaCodeTypeEnum::Barcode => Self::Barcode,
            CredentialSchemaCodeTypeEnum::Mrz => Self::Mrz,
            CredentialSchemaCodeTypeEnum::QrCode => Self::QrCode,
        }
    }
}

impl From<CredentialSchemaLayoutPropertiesRequestDTO> for LayoutProperties {
    fn from(value: CredentialSchemaLayoutPropertiesRequestDTO) -> Self {
        Self {
            background: value.background.map(Into::into),
            logo: value.logo.map(Into::into),
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code: value.code.map(Into::into),
        }
    }
}

pub fn create_open_id_for_vp_presentation_definition(
    interaction_id: InteractionId,
    proof: &Proof,
    format_type_to_input_descriptor_format: TypeToDescriptorMapper,
    format_to_type_mapper: FormatMapper, // Credential schema format to format type mapper
) -> Result<OpenID4VPPresentationDefinition, ExchangeProtocolError> {
    let proof_schema = proof.schema.as_ref().ok_or(ExchangeProtocolError::Failed(
        "Proof schema not found".to_string(),
    ))?;
    // using vec to keep the original order of claims/credentials in the proof request
    let requested_credentials: Vec<(CredentialSchema, Option<Vec<ProofInputClaimSchema>>)> =
        match proof_schema.input_schemas.as_ref() {
            Some(proof_input) if !proof_input.is_empty() => proof_input
                .iter()
                .filter_map(|input| {
                    let credential_schema = input.credential_schema.as_ref()?;

                    let claims = input.claim_schemas.as_ref().map(|schemas| {
                        schemas
                            .iter()
                            .map(|claim_schema| ProofInputClaimSchema {
                                order: claim_schema.order,
                                required: claim_schema.required,
                                schema: claim_schema.schema.to_owned(),
                            })
                            .collect()
                    });

                    Some((credential_schema.to_owned(), claims))
                })
                .collect(),

            _ => {
                return Err(ExchangeProtocolError::Failed(
                    "Missing proof input schemas".to_owned(),
                ))
            }
        };

    Ok(OpenID4VPPresentationDefinition {
        id: interaction_id.into(),
        input_descriptors: requested_credentials
            .into_iter()
            .enumerate()
            .map(|(index, (credential_schema, claim_schemas))| {
                let format_type = format_to_type_mapper(&credential_schema.format)?;
                create_open_id_for_vp_presentation_definition_input_descriptor(
                    index,
                    credential_schema,
                    claim_schemas.unwrap_or_default(),
                    &format_type,
                    format_type_to_input_descriptor_format.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn create_open_id_for_vp_presentation_definition_input_descriptor(
    index: usize,
    credential_schema: CredentialSchema,
    claim_schemas: Vec<ProofInputClaimSchema>,
    presentation_format_type: &str,
    format_to_type_mapper: TypeToDescriptorMapper,
) -> Result<OpenID4VPPresentationDefinitionInputDescriptor, ExchangeProtocolError> {
    let schema_id_field = OpenID4VPPresentationDefinitionConstraintField {
        id: None,
        name: None,
        purpose: None,
        path: vec!["$.credentialSchema.id".to_string()],
        optional: None,
        filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
            r#type: "string".to_string(),
            r#const: credential_schema.schema_id,
        }),
        intent_to_retain: None,
    };

    let intent_to_retain = match presentation_format_type {
        "MDOC" => Some(true),
        _ => None,
    };

    let constraint_fields = claim_schemas
        .iter()
        .map(|claim| {
            Ok(OpenID4VPPresentationDefinitionConstraintField {
                id: Some(claim.schema.id),
                name: None,
                purpose: None,
                path: vec![format_path(&claim.schema.key, presentation_format_type)?],
                optional: Some(!claim.required),
                filter: None,
                intent_to_retain,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut fields = vec![schema_id_field];
    fields.extend(constraint_fields);

    Ok(OpenID4VPPresentationDefinitionInputDescriptor {
        id: format!("input_{index}"),
        name: Some(credential_schema.name),
        purpose: None,
        format: format_to_type_mapper(presentation_format_type)?,
        constraints: OpenID4VPPresentationDefinitionConstraint {
            fields,
            validity_credential_nbf: None,
        },
    })
}

fn format_path(claim_key: &str, format_type: &str) -> Result<String, ExchangeProtocolError> {
    match format_type {
        "MDOC" => match claim_key.split_once(NESTED_CLAIM_MARKER) {
            None => Ok(format!("$['{claim_key}']")),
            Some((namespace, key)) => Ok(format!("$['{namespace}']['{key}']")),
        },
        _ => Ok(format!("$.vc.credentialSubject.{}", claim_key)),
    }
}

pub mod unix_timestamp {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S>(datetime: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        datetime.unix_timestamp().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp = i64::deserialize(deserializer)?;

        OffsetDateTime::from_unix_timestamp(timestamp).map_err(serde::de::Error::custom)
    }
}

impl From<Did> for DidListItemResponseDTO {
    fn from(value: Did) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            did: value.did,
            did_type: value.did_type,
            did_method: value.did_method,
            deactivated: value.deactivated,
        }
    }
}

impl From<LayoutProperties> for CredentialSchemaLayoutPropertiesRequestDTO {
    fn from(value: LayoutProperties) -> Self {
        Self {
            background: value.background.map(|value| {
                CredentialSchemaBackgroundPropertiesRequestDTO {
                    color: value.color,
                    image: value.image,
                }
            }),
            logo: value
                .logo
                .map(|v| CredentialSchemaLogoPropertiesRequestDTO {
                    font_color: v.font_color,
                    background_color: v.background_color,
                    image: v.image,
                }),
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code: value
                .code
                .map(|v| CredentialSchemaCodePropertiesRequestDTO {
                    attribute: v.attribute,
                    r#type: match v.r#type {
                        CodeTypeEnum::Barcode => CredentialSchemaCodeTypeEnum::Barcode,
                        CodeTypeEnum::Mrz => CredentialSchemaCodeTypeEnum::Mrz,
                        CodeTypeEnum::QrCode => CredentialSchemaCodeTypeEnum::QrCode,
                    },
                }),
        }
    }
}

pub fn map_credential_schema_to_detailed(
    value: CredentialSchema,
    organisation_id: OrganisationId,
) -> DetailCredentialSchemaResponseDTO {
    DetailCredentialSchemaResponseDTO {
        id: value.id,
        created_date: value.created_date,
        deleted_at: value.deleted_at,
        last_modified: value.last_modified,
        name: value.name,
        format: value.format,
        revocation_method: value.revocation_method,
        wallet_storage_type: value.wallet_storage_type,
        organisation_id,
        schema_type: value.schema_type,
        schema_id: value.schema_id,
        layout_type: value.layout_type.into(),
        layout_properties: value.layout_properties.map(Into::into),
    }
}

impl From<CredentialSchemaClaim> for CredentialClaimSchemaDTO {
    fn from(value: CredentialSchemaClaim) -> Self {
        Self {
            id: value.schema.id,
            created_date: value.schema.created_date,
            last_modified: value.schema.last_modified,
            key: value.schema.key,
            datatype: value.schema.data_type,
            required: value.required,
            array: value.schema.array,
            claims: vec![],
        }
    }
}