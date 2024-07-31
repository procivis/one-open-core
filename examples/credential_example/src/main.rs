use one_open_core::model::{CredentialFormat, KeyAlgorithmType, StorageType};
use one_open_core::service::error::CredentialServiceError;
use one_providers::common_models::key::Key;
use time::{Duration, OffsetDateTime};

use one_open_core::OneOpenCore;

use one_providers::credential_formatter::model::{
    CredentialData, CredentialPresentation, CredentialSchemaData, PublishedClaim,
};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), CredentialServiceError> {
    let core = OneOpenCore::new(None).unwrap();

    let did_service = core.did_service;
    let did_method = did_service
        .get_did_method("KEY")
        .expect("Key method provider");

    let key_pair = core
        .signature_service
        .get_key_pair(&KeyAlgorithmType::Es256)
        .expect("Key pair creation failed");

    let key = Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: key_pair.public,
        name: "My New Key".to_owned(),
        //Encryption is disabled so key_reference just holds private key
        key_reference: key_pair.private,
        storage_type: StorageType::Internal.to_string(),
        key_type: KeyAlgorithmType::Es256.to_string(),
        organisation: None,
    };

    // We will use the same did value for both issuer and holder
    let did = did_method
        .create(&Uuid::new_v4().into(), &None, &[key.clone()])
        .await
        .expect("Did creation failed");

    let credential_service = core.credential_service;

    let credential_data = CredentialData {
        id: "https://test-credential".to_string(),
        issuance_date: OffsetDateTime::now_utc(),
        valid_for: Duration::days(365),
        claims: vec![
            PublishedClaim {
                key: "root/array/0".into(),
                value: "array_item1".into(),
                datatype: Some("STRING".to_owned()),
                array_item: true,
            },
            PublishedClaim {
                key: "root/array/1".into(),
                value: "array_item2".into(),
                datatype: Some("STRING".to_owned()),
                array_item: true,
            },
            PublishedClaim {
                key: "root/nested".into(),
                value: "nested_item".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
            PublishedClaim {
                key: "root_item".into(),
                value: "root_item".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
        ],
        issuer_did: did.clone(),
        status: vec![],
        schema: CredentialSchemaData {
            id: None,
            r#type: None,
            context: None,
            name: "".to_string(),
        },
    };

    let token = credential_service
        .format_credential(
            credential_data,
            CredentialFormat::SdJwt,
            KeyAlgorithmType::Es256,
            did,
            key,
        )
        .await
        .expect("Credential formatting failed");

    println!("SDJWT token = {token}");

    let credential_presentation_config = CredentialPresentation {
        token,
        // We only disclose those two claims
        disclosed_keys: vec![
            "root/array".into(),
            "root/nested".into(),
            // "root_item".into(),
        ],
    };

    let credential_presentation = credential_service
        .format_credential_presentation(CredentialFormat::SdJwt, credential_presentation_config)
        .await
        .expect("Credential presentation creation failed");

    println!("SDJWT credential presentation = {credential_presentation}");

    let details = credential_service
        .extract_credential(CredentialFormat::SdJwt, &credential_presentation)
        .await
        .expect("Credential extraction failed");

    assert!(!details.claims.values.contains_key("root_item"));
    let root = details.claims.values.get("root").expect("root is missing");
    assert!(root["array"].is_array());
    assert!(root["nested"].is_string());
    assert_eq!(root["nested"].as_str().unwrap(), "nested_item");

    println!("Array items: {:?}", root["array"].as_array().unwrap());
    println!("Nested item: {:?}", root["nested"].as_str().unwrap());

    Ok(())
}
