use std::collections::HashMap;
use std::str::FromStr;

use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::common_models::claim_schema::ClaimSchema;
use crate::common_models::credential_schema::{CredentialSchema, LayoutType};
use crate::common_models::did::DidValue;
use crate::common_models::proof::{Proof, ProofState, ProofStateEnum};
use crate::common_models::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::credential_formatter::model::{CredentialSubject, DetailCredential};
use crate::exchange_protocol::openid4vc::error::{OpenID4VCError, OpenID4VCIError};
use crate::exchange_protocol::openid4vc::mapper::vec_last_position_from_token_path;
use crate::exchange_protocol::openid4vc::model::{
    OpenID4VPInteractionContent, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionInputDescriptor,
    OpenID4VPPresentationDefinitionInputDescriptorFormat,
};
use crate::exchange_protocol::openid4vc::service::oidc_verifier_presentation_definition;
use crate::exchange_protocol::openid4vc::validator::validate_claims;

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

#[test]
fn test_vec_last_position_from_token_path() {
    assert_eq!(
        vec_last_position_from_token_path("$[0].verifiableCredential[0]").unwrap(),
        0
    );
    assert_eq!(
        vec_last_position_from_token_path("$[0].verifiableCredential[1]").unwrap(),
        1
    );
    assert_eq!(
        vec_last_position_from_token_path("$[1].verifiableCredential[2]").unwrap(),
        2
    );
    assert_eq!(
        vec_last_position_from_token_path("$.verifiableCredential[3]").unwrap(),
        3
    );
    assert_eq!(vec_last_position_from_token_path("$[4]").unwrap(), 4);
    assert_eq!(
        vec_last_position_from_token_path("$[152046]").unwrap(),
        152046
    );
    assert_eq!(vec_last_position_from_token_path("$").unwrap(), 0);
    assert!(vec_last_position_from_token_path("$[ABC]").is_err());
}

fn generic_detail_credential() -> DetailCredential {
    let holder_did: DidValue = DidValue::from("did:holder".to_string());
    let issuer_did: DidValue = DidValue::from("did:issuer".to_string());

    DetailCredential {
        id: None,
        issued_at: Some(OffsetDateTime::now_utc()),
        expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
        update_at: None,
        invalid_before: Some(OffsetDateTime::now_utc()),
        issuer_did: Some(issuer_did),
        subject: Some(holder_did),
        claims: CredentialSubject {
            values: HashMap::new(),
        },
        status: vec![],
        credential_schema: None,
    }
}

fn generic_proof_input_schema() -> ProofInputSchema {
    let now = OffsetDateTime::now_utc();

    ProofInputSchema {
        validity_constraint: Some(100),
        claim_schemas: None,
        credential_schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "None".to_string(),
            wallet_storage_type: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "".to_string(),
            schema_type: "".to_string(),
            claim_schemas: None,
        }),
    }
}

#[test]
fn test_validate_claims_success_nested_claims() {
    let mut detail_credential = generic_detail_credential();
    detail_credential.claims.values = HashMap::from([(
        "location".to_string(),
        json!({
            "X": "123",
            "Y": "456"
        }),
    )]);

    let mut proof_input_schema = generic_proof_input_schema();
    proof_input_schema.claim_schemas = Some(vec![
        ProofInputClaimSchema {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/X".to_owned(),
                data_type: "STRING".to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            },
            required: true,
            order: 0,
        },
        ProofInputClaimSchema {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/Y".to_owned(),
                data_type: "STRING".to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            },
            required: true,
            order: 0,
        },
    ]);

    validate_claims(detail_credential, &proof_input_schema).unwrap();
}

#[test]
fn test_validate_claims_failed_malformed_claim() {
    let mut detail_credential = generic_detail_credential();
    detail_credential.claims.values = HashMap::from([(
        "location/".to_string(),
        json!({
            "X": "123",
            "Y": "456"
        }),
    )]);

    let mut proof_input_schema = generic_proof_input_schema();
    proof_input_schema.claim_schemas = Some(vec![
        ProofInputClaimSchema {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/X".to_owned(),
                data_type: "STRING".to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            },
            required: true,
            order: 0,
        },
        ProofInputClaimSchema {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "location/Y".to_owned(),
                data_type: "STRING".to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            },
            required: true,
            order: 0,
        },
    ]);

    matches!(
        validate_claims(detail_credential, &proof_input_schema,).unwrap_err(),
        OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest)
    );
}

fn jwt_format_map() -> HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat> {
    HashMap::from([(
        "jwt_vc_json".to_string(),
        OpenID4VPPresentationDefinitionInputDescriptorFormat {
            alg: vec!["EdDSA".to_string(), "ES256".to_string()],
            proof_type: vec![],
        },
    )])
}

fn interaction_content() -> OpenID4VPInteractionContent {
    OpenID4VPInteractionContent {
        nonce: "nonce".to_string(),
        presentation_definition: OpenID4VPPresentationDefinition {
            id: Uuid::new_v4(),
            input_descriptors: vec![OpenID4VPPresentationDefinitionInputDescriptor {
                id: "123".to_string(),
                name: None,
                purpose: None,
                format: jwt_format_map(),
                constraints: OpenID4VPPresentationDefinitionConstraint {
                    validity_credential_nbf: None,
                    fields: vec![OpenID4VPPresentationDefinitionConstraintField {
                        id: Some(Uuid::new_v4().into()),
                        name: None,
                        purpose: None,
                        path: vec!["123".to_string()],
                        optional: Some(false),
                        filter: None,
                        intent_to_retain: None,
                    }],
                },
            }],
        },
    }
}

#[test]
fn test_oidc_verifier_presentation_definition_success() {
    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        issuance_date: get_dummy_date(),
        exchange: "OPENID4VC".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            state: ProofStateEnum::Pending,
        }]),
        schema: Some(ProofSchema {
            id: Uuid::default().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            name: "test".to_string(),
            expire_duration: 0,
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: Some(100),
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: Uuid::from_str("2fa85f64-5717-4562-b3fc-2c963f66afa6")
                            .unwrap()
                            .into(),
                        key: "Key".to_owned(),
                        data_type: "STRING".to_owned(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                    },
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(CredentialSchema {
                    id: Uuid::from_str("3fa85f64-5717-4562-b3fc-2c963f66afa6")
                        .unwrap()
                        .into(),
                    deleted_at: None,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "Credential1".to_owned(),
                    format: "JWT".to_owned(),
                    revocation_method: "NONE".to_owned(),
                    wallet_storage_type: None,
                    claim_schemas: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_type: "".to_string(),
                    schema_id: "CredentialSchemaId".to_owned(),
                }),
            }]),
        }),
        claims: None,
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: None,
    };

    let result = oidc_verifier_presentation_definition(proof, interaction_content());
    assert!(result.is_ok());
}
