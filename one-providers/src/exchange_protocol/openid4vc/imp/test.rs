use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use maplit::hashmap;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{build_claims_keys_for_mdoc, OpenID4VCHTTP, OpenID4VCParams};
use crate::common_dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::common_models::claim::Claim;
use crate::common_models::claim_schema::ClaimSchema;
use crate::common_models::credential::{
    Credential, CredentialRole, CredentialState, CredentialStateEnum,
};
use crate::common_models::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, LayoutType, WalletStorageTypeEnum,
};
use crate::common_models::did::{Did, DidType, KeyRole, RelatedKey};
use crate::common_models::interaction::Interaction;
use crate::common_models::key::Key;
use crate::common_models::organisation::Organisation;
use crate::common_models::proof::{Proof, ProofState, ProofStateEnum};
use crate::common_models::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::common_models::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::exchange_protocol::openid4vc::imp::mappers::get_parent_claim_paths;
use crate::exchange_protocol::openid4vc::model::{
    InvitationResponseDTO, OpenID4VCICredentialOfferClaim, OpenID4VCICredentialOfferClaimValue,
    OpenID4VCICredentialValueDetails, OpenID4VPClientMetadata, OpenID4VPFormat,
    OpenID4VPInteractionData, OpenID4VPPresentationDefinition,
};
use crate::exchange_protocol::openid4vc::service::{create_credential_offer, credentials_format};
use crate::exchange_protocol::openid4vc::{
    ExchangeProtocolError, ExchangeProtocolImpl, MockHandleInvitationOperations, MockStorageProxy,
};
use crate::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::key_algorithm::MockKeyAlgorithm;
use crate::key_storage::provider::MockKeyProvider;
use crate::revocation::provider::MockRevocationMethodProvider;

#[derive(Default)]
struct TestInputs {
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_provider: MockRevocationMethodProvider,
    pub key_provider: MockKeyProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub params: Option<OpenID4VCParams>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VCHTTP {
    OpenID4VCHTTP::new(
        Some("http://base_url".to_string()),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.revocation_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.key_algorithm_provider),
        inputs.params.unwrap_or(OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: None,
            client_metadata_by_value: None,
            presentation_definition_by_value: None,
            allow_insecure_http_transport: Some(true),
            refresh_expires_in: 1000,
        }),
    )
}

fn construct_proof_with_state(transport: &str) -> Proof {
    let now = OffsetDateTime::now_utc();

    Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: transport.to_string(),
        exchange: "OPENID4VC".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Pending,
        }]),
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "schema".to_string(),
            expire_duration: 10,
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "first_name".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                    },
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                    name: "credential schema".to_string(),
                    format: "JWT".to_string(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_type: "ProcivisOneSchema2024".into(),
                    schema_id: "CredentialSchemaId".to_owned(),
                }),
            }]),
        }),
        claims: None,
        verifier_did: Some(Did {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb966")
                .unwrap()
                .into(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            did: "did1".to_owned().into(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: Some(vec![RelatedKey {
                role: KeyRole::KeyAgreement,
                key: Key {
                    id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                        .unwrap()
                        .into(),
                    created_date: now,
                    last_modified: now,
                    public_key: vec![],
                    name: "verifier_key1".to_string(),
                    key_reference: vec![],
                    storage_type: "INTERNAL".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: None,
                },
            }]),
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
    }
}

fn generic_credential() -> Credential {
    let now = OffsetDateTime::now_utc();

    let claim_schema = ClaimSchema {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
    };

    let credential_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();
    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
        }]),
        claims: Some(vec![Claim {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: "123".to_string(),
            path: claim_schema.key.to_owned(),
            schema: Some(claim_schema.clone()),
        }]),
        issuer_did: Some(Did {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            did: "did1".to_owned().into(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            deleted_at: None,
            created_date: now,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: claim_schema,
                required: true,
            }]),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: "ProcivisOneSchema2024".into(),
            schema_id: "CredentialSchemaId".to_owned(),
        }),
        interaction: Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: now,
            last_modified: now,
            host: Some("http://host.co".parse().unwrap()),
            data: Some(vec![1, 2, 3]),
        }),
        key: None,
    }
}

#[tokio::test]
async fn test_generate_offer() {
    let base_url = "BASE_URL".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential();

    let wallet_storage_type = credential
        .schema
        .as_ref()
        .unwrap()
        .wallet_storage_type
        .clone();

    let oidc_format = "jwt_vc_json";

    let claims = credential
        .claims
        .unwrap()
        .iter()
        .map(|claim| claim.to_owned())
        .collect::<Vec<_>>();

    let credentials = credentials_format(wallet_storage_type, oidc_format, &claims).unwrap();

    let offer = create_credential_offer(
        &base_url,
        &interaction_id.to_string(),
        &credential.schema.as_ref().unwrap().id,
        credentials,
    )
    .unwrap();

    assert_eq!(
        serde_json::json!(&offer),
        serde_json::json!({
            "credential_issuer": "BASE_URL/ssi/oidc-issuer/v1/c322aa7f-9803-410d-b891-939b279fb965",
            "credentials": [{
                "wallet_storage_type": "SOFTWARE",
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": ["VerifiableCredential"],
                    "credentialSubject": {
                        "NUMBER": { "value": "123", "value_type": "NUMBER" }
                    }
                }
            }],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
            }
        })
    )
}

#[tokio::test]
async fn test_generate_share_credentials() {
    let credential = generic_credential();
    let protocol = setup_protocol(Default::default());

    let result = protocol.share_credential(&credential, "").await.unwrap();
    assert_eq!(result.url, "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965");
}

#[tokio::test]
async fn test_generate_share_credentials_offer_by_value() {
    let credential = generic_credential();

    let protocol = setup_protocol(TestInputs {
        params: Some(OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: Some(true),
            client_metadata_by_value: None,
            presentation_definition_by_value: None,
            allow_insecure_http_transport: Some(true),
            refresh_expires_in: 1000,
        }),
        ..Default::default()
    });

    let result = protocol
        .share_credential(&credential, "jwt_vc_json")
        .await
        .unwrap();

    // Everything except for interaction id is here.
    // Generating token with predictable interaction id is tested somewhere else.
    assert!(
        result.url.starts_with(r#"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22credential_definition%22%3A%7B%22type%22%3A%5B%22VerifiableCredential%22%5D%2C%22credentialSubject%22%3A%7B%22NUMBER%22%3A%7B%22value%22%3A%22123%22%2C%22value_type%22%3A%22NUMBER%22%7D%7D%7D%2C%22wallet_storage_type%22%3A%22SOFTWARE%22%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%"#)
    )
}

#[tokio::test]
async fn test_generate_share_proof_open_id_flow_success() {
    let proof = construct_proof_with_state("HTTP");

    let mut key_algorithm = MockKeyAlgorithm::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();

    key_algorithm.expect_bytes_to_jwk().return_once(|_, _| {
        Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            r#use: None,
            crv: "123".to_string(),
            x: "456".to_string(),
            y: None,
        }))
    });
    key_algorithm_provider
        .expect_get_key_algorithm()
        .return_once(|_| Some(Arc::new(key_algorithm)));

    let protocol = setup_protocol(TestInputs {
        key_algorithm_provider,
        ..Default::default()
    });

    let result = protocol
        .share_proof(
            &proof,
            Arc::new(|data| Ok(data.to_owned())),
            Uuid::new_v4().into(),
            PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
                r#use: None,
                crv: "crv".into(),
                x: "x".into(),
                y: None,
            }),
            Default::default(),
            Arc::new(|data| Ok(Default::default())),
        )
        .await
        .unwrap();

    assert!(result
        .url
        .starts_with(r#"openid4vp://?response_type=vp_token"#))
}

fn generic_organisation() -> Organisation {
    let now = OffsetDateTime::now_utc();
    Organisation {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
    }
}

#[tokio::test]
async fn test_handle_invitation_proof_success() {
    let protocol = setup_protocol(Default::default());

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let url = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
        , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();

    let mut storage_proxy = MockStorageProxy::default();
    storage_proxy
        .expect_create_interaction()
        .times(2)
        .returning(move |request| Ok(request.id));

    let operations = MockHandleInvitationOperations::default();
    // storage_proxy
    //     .expect_create_interaction()
    //     .times(2)
    //     .returning(move |request| Ok(request.id));

    let result = protocol
        .handle_invitation(url, &storage_proxy, &operations)
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseDTO::ProofRequest { .. }));

    let mock_server = MockServer::start().await;

    let client_metadata_uri = format!("{}/client_metadata_uri", mock_server.uri());
    let presentation_definition_uri = format!("{}/presentation_definition_uri", mock_server.uri());

    Mock::given(method(Method::GET))
        .and(path("/client_metadata_uri"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(client_metadata.to_owned(), "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::GET))
        .and(path("/presentation_definition_uri"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(presentation_definition.to_owned(), "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let url_using_uri_instead_of_values = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata_uri={}&response_mode=direct_post&response_uri={}&presentation_definition_uri={}"
                                                              , nonce, callback_url, client_metadata_uri, callback_url, presentation_definition_uri)).unwrap();

    let result = protocol
        .handle_invitation(url_using_uri_instead_of_values, &storage_proxy, &operations)
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseDTO::ProofRequest { .. }));
}

#[tokio::test]
async fn test_handle_invitation_proof_failed() {
    let protocol = setup_protocol(Default::default());

    let client_metadata_uri = "https://127.0.0.1/client_metadata_uri";
    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
    })
    .unwrap();
    let presentation_definition_uri = "https://127.0.0.1/presentation_definition_uri";
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let storage_proxy = MockStorageProxy::default();
    let operations = MockHandleInvitationOperations::default();

    let incorrect_response_type = Url::parse(&format!("openid4vp://?response_type=some_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                      , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(incorrect_response_type, &storage_proxy, &operations)
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let missing_nonce = Url::parse(&format!("openid4vp://?response_type=vp_token&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                            , callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(missing_nonce, &storage_proxy, &operations)
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let incorrect_client_id_scheme = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=some_scheme&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                         , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(incorrect_client_id_scheme, &storage_proxy, &operations)
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let incorrect_response_mode = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=some_mode&response_uri={}&presentation_definition={}"
                                                      , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(incorrect_response_mode, &storage_proxy, &operations)
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let incorrect_client_id_scheme = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=some_scheme&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                         , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(incorrect_client_id_scheme, &storage_proxy, &operations)
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let metadata_missing_jwt_vp_json = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: Default::default(),
        client_id_scheme: "redirect_uri".to_string(),
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
    })
    .unwrap();
    let missing_metadata_field = Url::parse(&format!("openid4vp://?response_type=some_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}", nonce, callback_url, metadata_missing_jwt_vp_json, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(missing_metadata_field, &storage_proxy, &operations)
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let both_client_metadata_and_uri_specified = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&client_metadata_uri={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                                     , nonce, callback_url, client_metadata, client_metadata_uri, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .handle_invitation(
            both_client_metadata_and_uri_specified,
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let both_presentation_definition_and_uri_specified = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}&presentation_definition_uri={}"
                                                                             , nonce, callback_url, client_metadata, callback_url, presentation_definition, presentation_definition_uri)).unwrap();
    let result = protocol
        .handle_invitation(
            both_presentation_definition_and_uri_specified,
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let protocol_https_only = setup_protocol(TestInputs {
        params: Some(OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: None,
            client_metadata_by_value: None,
            presentation_definition_by_value: None,
            allow_insecure_http_transport: None,
            refresh_expires_in: 1000,
        }),
        ..Default::default()
    });

    let invalid_client_metadata_uri = "http://127.0.0.1/client_metadata_uri";
    let client_metadata_uri_is_not_https = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata_uri={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                               , nonce, callback_url, invalid_client_metadata_uri, callback_url, presentation_definition)).unwrap();
    let result = protocol_https_only
        .handle_invitation(
            client_metadata_uri_is_not_https,
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let invalid_presentation_definition_uri = "http://127.0.0.1/presentation_definition_uri";
    let presentation_definition_uri_is_not_https = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition_uri={}"
                                                                       , nonce, callback_url, client_metadata, callback_url, invalid_presentation_definition_uri)).unwrap();
    let result = protocol_https_only
        .handle_invitation(
            presentation_definition_uri_is_not_https,
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));
}

#[test]
fn test_serialize_and_deserialize_interaction_data() {
    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let query = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                    , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap().query().unwrap().to_string();
    let data: OpenID4VPInteractionData = serde_qs::from_str(&query).unwrap();
    let json = serde_json::to_string(&data).unwrap();
    let _data_from_json: OpenID4VPInteractionData = serde_json::from_str(&json).unwrap();

    let presentation_definition_uri = "https://127.0.0.1/presentation-definition";
    let query_with_presentation_definition_uri = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition_uri={}"
                                                                     , nonce, callback_url, client_metadata, callback_url, presentation_definition_uri)).unwrap().query().unwrap().to_string();
    let data: OpenID4VPInteractionData =
        serde_qs::from_str(&query_with_presentation_definition_uri).unwrap();
    let json = serde_json::to_string(&data).unwrap();
    let _data_from_json: OpenID4VPInteractionData = serde_json::from_str(&json).unwrap();
}

#[test]
fn test_get_parent_claim_paths() {
    assert!(get_parent_claim_paths("").is_empty());
    assert!(get_parent_claim_paths("this_is_not_yellow").is_empty());
    assert_eq!(
        vec!["this", "this/is", "this/is/yellow"],
        get_parent_claim_paths("this/is/yellow/man")
    );
}

#[test]
fn test_build_claims_keys_for_mdoc_converts_to_credential_subjects_compatible_claim_keys() {
    let claims = [
        (hashmap! {}, hashmap! {}),
        (
            hashmap! {
                "age".into() => OpenID4VCICredentialOfferClaim {
                    value_type: "INTEGER".into(),
                    value: OpenID4VCICredentialOfferClaimValue::String("55".into()),
                },
                "address".into() => OpenID4VCICredentialOfferClaim {
                    value_type: "OBJECT".into(),
                    value: OpenID4VCICredentialOfferClaimValue::Nested(hashmap! {
                        "streetName".into() => OpenID4VCICredentialOfferClaim {
                            value: OpenID4VCICredentialOfferClaimValue::String("Via Roma".into()),
                            value_type: "STRING".into(),
                        },
                    }),
                },
                "company".into() => OpenID4VCICredentialOfferClaim {
                    value_type: "OBJECT".into(),
                    value: OpenID4VCICredentialOfferClaimValue::Nested(hashmap! {
                        "name".into() => OpenID4VCICredentialOfferClaim {
                            value_type: "STRING".into(),
                            value: OpenID4VCICredentialOfferClaimValue::String("Procivis".into()),
                        },
                        "address".into() => OpenID4VCICredentialOfferClaim {
                            value_type: "OBJECT".into(),
                            value: OpenID4VCICredentialOfferClaimValue::Nested(hashmap! {
                                "streetName".into() => OpenID4VCICredentialOfferClaim {
                                    value: OpenID4VCICredentialOfferClaimValue::String("Deitzingerstrasse 22".into()),
                                    value_type: "STRING".into(),
                                },
                            }),
                        },
                    }),
                }
            },
            // expected
            hashmap! {
                "age".into() => OpenID4VCICredentialValueDetails { value: "55".into(), value_type: "INTEGER".into() },
                "address/streetName".into() => OpenID4VCICredentialValueDetails { value: "Via Roma".into(), value_type: "STRING".into() },
                "company/name".into() => OpenID4VCICredentialValueDetails { value: "Procivis".into(), value_type: "STRING".into() },
                "company/address/streetName".into() => OpenID4VCICredentialValueDetails { value: "Deitzingerstrasse 22".into(), value_type: "STRING".into() }
            },
        ),
    ];

    for (input, expected) in claims {
        let res = build_claims_keys_for_mdoc(&input);
        assert_eq!(expected, res);
    }
}