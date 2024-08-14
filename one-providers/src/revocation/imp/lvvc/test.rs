use crate::{
    credential_formatter::provider::MockCredentialFormatterProvider,
    did::provider::MockDidMethodProvider,
    key_storage::provider::MockKeyProvider,
    revocation::{
        imp::lvvc::{LvvcProvider, Params},
        RevocationMethod,
    },
};
use std::collections::HashMap;

use crate::common_models::credential::{OpenCredential, OpenCredentialRole};
use crate::common_models::did::{DidType, DidValue, KeyRole, OpenDid, RelatedKey};
use crate::common_models::key::OpenKey;
use crate::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, MockSignatureProvider,
};
use crate::credential_formatter::MockCredentialFormatter;
use crate::revocation::model::{CredentialDataByRole, CredentialRevocationState};
use serde_json::json;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::matchers::{header_regex, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn generic_did_credential(role: OpenCredentialRole) -> (OpenDid, OpenCredential) {
    let now = OffsetDateTime::now_utc();

    let did = OpenDid {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "did".to_string(),
        did: DidValue::from("did:key:123".to_string()),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        deactivated: false,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: OpenKey {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                public_key: vec![],
                name: "".to_string(),
                key_reference: vec![],
                storage_type: "".to_string(),
                key_type: "".to_string(),
                organisation: None,
            },
        }]),
        organisation: None,
    };

    let credential = OpenCredential {
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "OPENID4VC".to_string(),
        redirect_uri: None,
        role,
        state: None,
        claims: None,
        issuer_did: Some(did.to_owned()),
        holder_did: None,
        schema: None,
        key: None,
        interaction: None,
    };

    (did, credential)
}

fn extracted_credential(status: &str) -> DetailCredential {
    DetailCredential {
        id: None,
        issued_at: None,
        expires_at: None,
        update_at: None,
        invalid_before: None,
        issuer_did: None,
        subject: None,
        claims: CredentialSubject {
            values: HashMap::from([("status".to_string(), json!(status))]),
        },
        status: vec![],
        credential_schema: None,
    }
}

fn create_provider(
    formatter_provider: MockCredentialFormatterProvider,
    key_provider: MockKeyProvider,
) -> LvvcProvider {
    LvvcProvider::new(
        None,
        Arc::new(formatter_provider),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(key_provider),
        reqwest::Client::new(),
        Params {
            credential_expiry: Default::default(),
            json_ld_context_url: None,
        },
    )
}
#[tokio::test]
async fn test_check_revocation_status_as_issuer() {
    let mock_server = MockServer::start().await;

    Mock::given(path("/lvvcurl"))
        .and(header_regex("Authorization", "Bearer .*\\.c2lnbmVk")) // c2lnbmVk == base64("signed")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential": "this.is.jwt",
            "format": "MOCK"
        })))
        .mount(&mock_server)
        .await;

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .returning(|_, _| {
            let mut auth_fn = MockSignatureProvider::new();
            auth_fn
                .expect_sign()
                .returning(|_| Ok("signed".as_bytes().to_vec()));

            Ok(Box::new(auth_fn))
        });

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider.expect_get_formatter().returning(|_| {
        let mut formatter = MockCredentialFormatter::new();
        formatter
            .expect_extract_credentials_unverified()
            .returning(|_| Ok(extracted_credential("ACCEPTED")));

        Some(Arc::new(formatter))
    });

    let lvvc_url = format!("{}/lvvcurl", mock_server.uri());
    let status = CredentialStatus {
        id: Some(lvvc_url),
        r#type: "".to_string(),
        status_purpose: None,
        additional_fields: Default::default(),
    };

    let (did, credential) = generic_did_credential(OpenCredentialRole::Issuer);

    let provider = create_provider(formatter_provider, key_provider);

    let result = provider
        .check_credential_revocation_status(
            &status,
            &did.did,
            Some(CredentialDataByRole::Issuer(credential)),
        )
        .await
        .unwrap();
    assert_eq!(CredentialRevocationState::Valid, result);
}
