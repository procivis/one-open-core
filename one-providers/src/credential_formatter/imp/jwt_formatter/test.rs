use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::JWTFormatter;
use crate::{
    common_models::{
        credential_schema::{OpenLayoutProperties, OpenLayoutType},
        did::DidValue,
    },
    credential_formatter::{
        imp::{
            common::MockAuth,
            jwt::model::JWTPayload,
            jwt_formatter::{
                model::{VC, VP},
                Params,
            },
        },
        model::{
            CredentialData, CredentialPresentation, CredentialSchemaData, CredentialSchemaMetadata,
            CredentialStatus, ExtractPresentationCtx, MockTokenVerifier, PublishedClaim,
        },
        CredentialFormatter,
    },
};

fn get_credential_data(status: Vec<CredentialStatus>, core_base_url: &str) -> CredentialData {
    let id = Some(Uuid::new_v4().to_string());
    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);
    let schema = CredentialSchemaData {
        id: Some("CredentialSchemaId".to_owned()),
        r#type: Some("TestType".to_owned()),
        context: Some(format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())),
        name: "".to_owned(),
        metadata: Some(CredentialSchemaMetadata {
            layout_properties: OpenLayoutProperties {
                background: None,
                logo: None,
                primary_attribute: Some("name".into()),
                secondary_attribute: None,
                picture_attribute: None,
                code: None,
            },
            layout_type: OpenLayoutType::Card,
        }),
    };

    CredentialData {
        id,
        issuance_date,
        valid_for,
        claims: vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
            PublishedClaim {
                key: "age".into(),
                value: "42".into(),
                datatype: Some("NUMBER".to_owned()),
                array_item: false,
            },
        ],
        issuer_did: DidValue::from("Issuer DID".to_string()),
        status,
        schema,
    }
}

fn get_credential_data_with_array(
    status: Vec<CredentialStatus>,
    core_base_url: &str,
) -> CredentialData {
    let id = Some(Uuid::new_v4().to_string());
    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);
    let schema = CredentialSchemaData {
        id: Some("CredentialSchemaId".to_owned()),
        r#type: Some("TestType".to_owned()),
        context: Some(format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())),
        name: "".to_owned(),
        metadata: None,
    };

    CredentialData {
        id,
        issuance_date,
        valid_for,
        claims: vec![
            PublishedClaim {
                key: "root_item".into(),
                value: "root_item".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
            PublishedClaim {
                key: "root/nested".into(),
                value: "nested_item".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
            PublishedClaim {
                key: "root/array/0".into(),
                value: "array_item".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
        ],
        issuer_did: DidValue::from("Issuer DID".to_string()),
        status,
        schema,
    }
}

#[tokio::test]
async fn test_format_credential() {
    let leeway = 45u64;

    let formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let credential_data = get_credential_data(
        vec![CredentialStatus {
            id: Some("STATUS_ID".to_string()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        }],
        "http://base_url",
    );

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = formatter
        .format_credentials(
            credential_data,
            &DidValue::from("holder_did".to_string()),
            "algorithm",
            vec!["Context1".to_string()],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
            None,
            None,
        )
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let jwt_parts: Vec<&str> = token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(
            r##"{"alg":"algorithm","kid":"#key0","typ":"JWT"}"##
        )
        .unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<VC> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::days(365 * 2)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    assert_eq!(payload.issuer, Some(String::from("Issuer DID")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vc = payload.custom.vc;

    assert!(vc.credential_schema.unwrap().metadata.is_none());

    assert!(vc
        .credential_subject
        .values
        .iter()
        .all(|claim| ["name", "age"].contains(&claim.0.as_str())));

    assert!(vc.context.contains(&String::from("Context1")));
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(1, vc.credential_status.len());
    let credential_status = vc.credential_status.first().unwrap();
    assert_eq!(&credential_status.id, &Some("STATUS_ID".to_string()));
    assert_eq!(&credential_status.r#type, "TYPE");
    assert_eq!(credential_status.status_purpose.as_deref(), Some("PURPOSE"));

    let field1 = credential_status.additional_fields.get("Field1").unwrap();
    assert_eq!(field1, "Val1");
}

#[tokio::test]
async fn test_format_credential_with_layout_properties() {
    let leeway = 45u64;

    let formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: true,
        },
    };

    let credential_data = get_credential_data(
        vec![CredentialStatus {
            id: Some("STATUS_ID".to_string()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        }],
        "http://base_url",
    );

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = formatter
        .format_credentials(
            credential_data,
            &DidValue::from("holder_did".to_string()),
            "algorithm",
            vec!["Context1".to_string()],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
            None,
            None,
        )
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let jwt_parts: Vec<&str> = token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(
            r##"{"alg":"algorithm","kid":"#key0","typ":"JWT"}"##
        )
        .unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<VC> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::days(365 * 2)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    assert_eq!(payload.issuer, Some(String::from("Issuer DID")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vc = payload.custom.vc;

    assert!(vc.credential_schema.unwrap().metadata.is_some());

    assert!(vc
        .credential_subject
        .values
        .iter()
        .all(|claim| ["name", "age"].contains(&claim.0.as_str())));

    assert!(vc.context.contains(&String::from("Context1")));
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(1, vc.credential_status.len());
    let credential_status = vc.credential_status.first().unwrap();
    assert_eq!(&credential_status.id, &Some("STATUS_ID".to_string()));
    assert_eq!(&credential_status.r#type, "TYPE");
    assert_eq!(credential_status.status_purpose.as_deref(), Some("PURPOSE"));

    let field1 = credential_status.additional_fields.get("Field1").unwrap();
    assert_eq!(field1, "Val1");
}

#[tokio::test]
async fn test_format_credential_nested_array() {
    let leeway = 45u64;

    let sd_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let credential_data = get_credential_data_with_array(
        vec![CredentialStatus {
            id: Some("STATUS_ID".to_string()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        }],
        "http://base_url",
    );

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credentials(
            credential_data,
            &DidValue::from("holder_did".to_string()),
            "algorithm",
            vec!["Context1".to_string()],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
            None,
            None,
        )
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let jwt_parts: Vec<&str> = token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(
            r##"{"alg":"algorithm","kid":"#key0","typ":"JWT"}"##
        )
        .unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<VC> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::days(365 * 2)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    let vc = payload.custom.vc;

    let root_item = vc.credential_subject.values.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = vc.credential_subject.values.get("root").unwrap();
    let nested = root.get("nested").unwrap();
    assert_eq!(nested.as_str(), Some("nested_item"));

    let array = root.get("array").unwrap().as_array().unwrap();
    assert_eq!(array[0].as_str(), Some("array_item"));
}

#[tokio::test]
async fn test_extract_credentials() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTkzNTQyMjgsI\
        mV4cCI6MTc2MjQyNjIyOCwibmJmIjoxNjk5MzU0MTgzLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVy\
        X2RpZCIsImp0aSI6IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBjb250ZXh\
        0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiQ29udGV4dDEiXSwidHlwZSI6Wy\
        JWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFnZSI6IjQyIiwib\
        mFtZSI6IkpvaG4ifSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6IlNUQVRVU19JRCIsInR5cGUiOiJUWVBFIiwi\
        c3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19fQ";

    let token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!("Issuer DID", issuer_did_value.as_ref().unwrap().as_str());
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let result = jwt_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer_did,
        Some(DidValue::from("Issuer DID".to_owned())),
    );
    assert_eq!(
        credentials.subject,
        Some(DidValue::from("holder_did".to_owned()))
    );

    assert_eq!(1, credentials.status.len());

    let first_credential_status = credentials.status.first().unwrap();
    assert_eq!(first_credential_status.id, Some("STATUS_ID".to_string()));
    assert_eq!(first_credential_status.r#type, "TYPE");
    assert_eq!(
        first_credential_status.status_purpose.as_deref(),
        Some("PURPOSE")
    );
    assert_eq!(
        first_credential_status.additional_fields.get("Field1"),
        Some(&"Val1".into())
    );

    assert_eq!(credentials.claims.values.get("name").unwrap(), "John");
    assert_eq!(credentials.claims.values.get("age").unwrap(), "42");
}

#[tokio::test]
async fn test_extract_credentials_nested_array() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJraWQiOiIja2V5MCIsInR5cCI6IkpXVCJ9.eyJpYXQ\
        iOjE3MTgyNTk4NTYsImV4cCI6MTc4MTMzMTg1NiwibmJmIjoxNzE4MjU5ODExLCJpc3MiOiJJc3N1ZXIgRElEIi\
        wic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6Imh0dHA6Ly9iYXNlX3VybC9zc2kvY3JlZGVudGlhbC92MS85YTQxN\
        GE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53\
        My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsIkNvbnRleHQxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnR\
        pYWwiLCJUeXBlMSJdLCJpZCI6Imh0dHA6Ly9iYXNlX3VybC9zc2kvY3JlZGVudGlhbC92MS85YTQxNGE2MC05ZT\
        ZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJyb290Ijp7ImFycmF5IjpbI\
        mFycmF5X2l0ZW0iXSwibmVzdGVkIjoibmVzdGVkX2l0ZW0ifSwicm9vdF9pdGVtIjoicm9vdF9pdGVtIn0sImNy\
        ZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJTVEFUVVNfSUQiLCJ0eXBlIjoiVFlQRSIsInN0YXR1c1B1cnBvc2UiOiJ\
        QVVJQT1NFIiwiRmllbGQxIjoiVmFsMSJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiQ3JlZGVudGlhbFNjaG\
        VtYUlkIiwidHlwZSI6IlByb2NpdmlzT25lU2NoZW1hMjAyNCJ9fX0";

    let token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!("Issuer DID", issuer_did_value.as_ref().unwrap().as_str());
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let result = jwt_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer_did,
        Some(DidValue::from("Issuer DID".to_owned())),
    );
    assert_eq!(
        credentials.subject,
        Some(DidValue::from("holder_did".to_owned()))
    );

    assert_eq!(1, credentials.status.len());

    let first_credential_status = credentials.status.first().unwrap();
    assert_eq!(first_credential_status.id, Some("STATUS_ID".to_string()));
    assert_eq!(first_credential_status.r#type, "TYPE");
    assert_eq!(
        first_credential_status.status_purpose.as_deref(),
        Some("PURPOSE")
    );
    assert_eq!(
        first_credential_status.additional_fields.get("Field1"),
        Some(&"Val1".into())
    );

    let root_item = credentials.claims.values.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = credentials.claims.values.get("root").unwrap();
    let nested = root.get("nested").unwrap();
    assert_eq!(nested.as_str(), Some("nested_item"));

    let array = root.get("array").unwrap().as_array().unwrap();
    assert_eq!(array[0].as_str(), Some("array_item"));
}

#[tokio::test]
async fn test_format_credential_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
        eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
        MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
        IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
        b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
        IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
        cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
        SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
        dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
        IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0.QUJD";

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway: 45,
            embed_layout_properties: false,
        },
    };

    // Both
    let credential_presentation = CredentialPresentation {
        token: jwt_token.to_owned(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = jwt_formatter
        .format_credential_presentation(credential_presentation)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), jwt_token);

    // Just name
    let credential_presentation = CredentialPresentation {
        token: jwt_token.to_owned(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = jwt_formatter
        .format_credential_presentation(credential_presentation)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), jwt_token);
}

#[tokio::test]
async fn test_format_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
        eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
        MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
        IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
        b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
        IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
        cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
        SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
        dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
        IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0.QUJD";

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = jwt_formatter
        .format_presentation(
            &[jwt_token.to_owned()],
            &DidValue::from("holder_did".to_string()),
            "algorithm",
            Box::new(auth_fn),
            Default::default(),
        )
        .await;

    assert!(result.is_ok());

    let presentation_token = result.unwrap();

    let jwt_parts: Vec<&str> = presentation_token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(
            r##"{"alg":"algorithm","kid":"#key0","typ":"JWT"}"##
        )
        .unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<VP> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::minutes(5)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    assert_eq!(payload.issuer, Some(String::from("holder_did")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vp = payload.custom.vp;

    assert_eq!(vp.verifiable_credential.len(), 1);
    assert_eq!(vp.verifiable_credential[0], jwt_token);
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTkzNTc1ODIsI\
        mV4cCI6MTY5OTM1Nzg4MiwibmJmIjoxNjk5MzU3NTM3LCJpc3MiOiJob2xkZXJfZGlkIiwic3ViIjoiaG9sZGVy\
        X2RpZCIsImp0aSI6IjY2YWFiNmE2LWQxNWMtNDNkYi1iMDk1LTM5MWE3NWFmYzc4ZSIsInZwIjp7IkBjb250ZXh\
        0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZV\
        ByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSmhiR2R2Y21sMGFHMGlMQ\
        0owZVhBaU9pSlRSRXBYVkNKOS5leUpwWVhRaU9qRTJPVGt5TnpBeU5qWXNJbVY0Y0NJNk1UYzJNak0wTWpJMk5p\
        d2libUptSWpveE5qazVNamN3TWpJeExDSnBjM01pT2lKSmMzTjFaWElnUkVsRUlpd2ljM1ZpSWpvaWFHOXNaR1Z\
        5WDJScFpDSXNJbXAwYVNJNklqbGhOREUwWVRZd0xUbGxObUl0TkRjMU55MDRNREV4TFRsaFlUZzNNR1ZtTkRjNE\
        9DSXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV\
        1JsYm5ScFlXeHpMM1l4SWl3aVEyOXVkR1Y0ZERFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdW\
        dWRHbGhiQ0lzSWxSNWNHVXhJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lsOXpaQ0k2V3lKWlYwcHF\
        UVlJKZWlJc0lsbFhTbXBOVkVsNklsMTlMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW1sa0lqb2lVMVJCVk\
        ZWVFgwbEVJaXdpZEhsd1pTSTZJbFJaVUVVaUxDSnpkR0YwZFhOUWRYSndiM05sSWpvaVVGVlNVRTlUUlNJc0lrW\
        nBaV3hrTVNJNklsWmhiREVpZlgwc0lsOXpaRjloYkdjaU9pSnphR0V0TWpVMkluMC5RVUpEIl19fQ";
    let presentation_token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!("holder_did", issuer_did_value.as_ref().unwrap().as_str());
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let result = jwt_formatter
        .extract_presentation(
            &presentation_token,
            Box::new(verify_mock),
            ExtractPresentationCtx::default(),
        )
        .await;

    assert!(result.is_ok());

    let presentation = result.unwrap();

    assert_eq!(
        presentation.expires_at,
        Some(presentation.issued_at.unwrap() + Duration::minutes(5)),
    );

    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(
        presentation.issuer_did,
        Some(DidValue::from("holder_did".to_owned()))
    );
}

#[test]
fn test_get_capabilities() {
    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway: 123u64,
            embed_layout_properties: false,
        },
    };

    assert_eq!(1, jwt_formatter.get_capabilities().features.len());
}
