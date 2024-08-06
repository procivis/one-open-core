use std::{collections::HashMap, sync::Arc};

use mockall::predicate;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::KeyDidMethod;
use crate::{
    common_models::{
        did::{DidId, DidValue},
        key::OpenKey,
        OpenPublicKeyJwk, OpenPublicKeyJwkEllipticData,
    },
    crypto::MockCryptoProvider,
    did::{
        model::{AmountOfKeys, DidDocument, DidVerificationMethod},
        DidMethod,
    },
    key_algorithm::{imp::provider::KeyAlgorithmProviderImpl, KeyAlgorithm, MockKeyAlgorithm},
};

fn setup_key_did_method(key_algorithm: MockKeyAlgorithm, algorithm_id: &str) -> KeyDidMethod {
    let mut key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm>> = HashMap::new();
    key_algorithms.insert(algorithm_id.to_string(), Arc::new(key_algorithm));

    let key_algorithm_provider =
        KeyAlgorithmProviderImpl::new(key_algorithms, Arc::new(MockCryptoProvider::new()));

    KeyDidMethod::new(Arc::new(key_algorithm_provider))
}

#[tokio::test]
async fn test_did_key_resolve_details_eddsa() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_bytes_to_jwk()
        .with(
            predicate::eq(vec![
                59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50,
                21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
            ]),
            predicate::eq(None),
        )
        .once()
        .returning(|_, _| {
            Ok(OpenPublicKeyJwk::Okp(OpenPublicKeyJwkEllipticData {
                r#use: None,
                crv: "Ed25519".to_owned(),
                x: "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS".to_owned(),
                y: None,
            }))
        });

    let did_method = setup_key_did_method(key_algorithm, "EDDSA");

    let result = did_method
        .resolve(&DidValue::from(
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_string(),
        ))
        .await
        .unwrap();

    assert_eq!(result,
    DidDocument {
        context: json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]),
        id: DidValue::from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_string()),
        verification_method: vec![
            DidVerificationMethod {
                id: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
                public_key_jwk: OpenPublicKeyJwk::Okp(
                    OpenPublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "Ed25519".to_owned(),
                        x: "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS".to_owned(),
                        y: None,
                    },
                ),
            },
        ],
        authentication: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        assertion_method: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        key_agreement: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        capability_invocation: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        capability_delegation: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        rest: Default::default()
    });
}

// https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/nist-curves.json
#[tokio::test]
async fn test_did_key_resolve_details_es256() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_bytes_to_jwk()
        .with(
            predicate::eq(vec![
                3, 138, 10, 197, 154, 45, 48, 134, 232, 161, 42, 120, 253, 71, 115, 166, 213, 42,
                12, 166, 30, 246, 193, 65, 158, 21, 160, 91, 204, 109, 175, 206, 123,
            ]),
            predicate::eq(None),
        )
        .once()
        .returning(|_, _| {
            Ok(OpenPublicKeyJwk::Ec(OpenPublicKeyJwkEllipticData {
                r#use: None,
                crv: "P-256".to_string(),
                x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
            }))
        });

    let did_method = setup_key_did_method(key_algorithm, "ES256");

    let result = did_method
        .resolve(&DidValue::from(
            "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_string(),
        ))
        .await
        .unwrap();

    assert_eq!(result,
    DidDocument {
        context: json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]),
        id: DidValue::from("did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_string()),
        verification_method: vec![
            DidVerificationMethod {
                id: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
                public_key_jwk: OpenPublicKeyJwk::Ec(
                    OpenPublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "P-256".to_owned(),
                        x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                        y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                    },
                ),
            },
        ],
        authentication: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        assertion_method: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        key_agreement: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        capability_invocation: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        capability_delegation: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        rest: Default::default()
    });
}

#[tokio::test]
async fn test_did_key_resolve_details_bbs() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_bytes_to_jwk()
        .with(predicate::eq(vec![
            130, 59, 60, 150, 203, 83, 130, 132, 224, 92, 193, 122, 65, 119, 114, 135, 121, 188,
            147, 104, 177, 197, 68, 70, 96, 179, 26, 99, 41, 85, 43, 252, 116, 23, 193, 225, 19,
            204, 228, 209, 133, 162, 25, 93, 194, 31, 10, 80, 17, 173, 172, 31, 131, 193, 100, 182,
            152, 10, 127, 44, 123, 237, 92, 150, 96, 142, 68, 59, 10, 197, 182, 240, 220, 155, 63,
            2, 91, 184, 58, 105, 21, 246, 9, 155, 38, 204, 181, 96, 93, 171, 183, 181, 113, 206,
            206, 146
        ]), predicate::eq(None))
        .once()
        .returning(|_, _| {
            Ok(OpenPublicKeyJwk::Okp(OpenPublicKeyJwkEllipticData {
                r#use: None,
                crv: "Bls12381G2".to_string(),
                x: "Ajs8lstTgoTgXMF6QXdyh3m8k2ixxURGYLMaYylVK_x0F8HhE8zk0YWiGV3CHwpQEa2sH4PBZLaYCn8se-1clmCORDsKxbbw3Js_Alu4OmkV9gmbJsy1YF2rt7Vxzs6S".to_owned(),
                y: Some("BVkkrVEib-P_FMPHNtqxJymP3pV-H8fCdvPkoWInpFfM9tViyqD8JAmwDf64zU2hBV_vvCQ632ScAooEExXuz1IeQH9D2o-uY_dAjZ37YHuRMEyzh8Tq-90JHQvicOqx".to_owned()),
            }))
        });

    let did_method = setup_key_did_method(key_algorithm, "BBS_PLUS");

    let result = did_method
        .resolve(
            &DidValue::from("did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_string()))
        .await
        .unwrap();

    assert_eq!(result,
    DidDocument {
        context: json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]),
        id: DidValue::from("did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_string()),
        verification_method: vec![
            DidVerificationMethod {
                id: "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
                public_key_jwk: OpenPublicKeyJwk::Okp(
                    OpenPublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "Bls12381G2".to_string(),
                        x: "Ajs8lstTgoTgXMF6QXdyh3m8k2ixxURGYLMaYylVK_x0F8HhE8zk0YWiGV3CHwpQEa2sH4PBZLaYCn8se-1clmCORDsKxbbw3Js_Alu4OmkV9gmbJsy1YF2rt7Vxzs6S".to_owned(),
                        y: Some("BVkkrVEib-P_FMPHNtqxJymP3pV-H8fCdvPkoWInpFfM9tViyqD8JAmwDf64zU2hBV_vvCQ632ScAooEExXuz1IeQH9D2o-uY_dAjZ37YHuRMEyzh8Tq-90JHQvicOqx".to_owned()),
                    },
                ),
            },
        ],
        authentication: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        assertion_method: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        key_agreement: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        capability_invocation: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        capability_delegation: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        rest: Default::default()
    });
}

#[tokio::test]
async fn test_create_did_success() {
    let key_id = Uuid::new_v4();

    let key = OpenKey {
        id: key_id.into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "".to_string(),
        key_reference: vec![],
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_get_multibase()
        .times(1)
        .returning(|_| Ok("MULTIBASE".to_string()));

    let did_method = setup_key_did_method(key_algorithm, "EDDSA");
    let result = did_method
        .create(&DidId::from(Uuid::new_v4()), &None, &vec![key])
        .await;
    result.unwrap();
}

#[test]
fn test_validate_keys() {
    let did_method = setup_key_did_method(MockKeyAlgorithm::default(), "EDDSA");

    let keys = AmountOfKeys {
        global: 1,
        authentication: 1,
        assertion_method: 1,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_no_keys() {
    let did_method = setup_key_did_method(MockKeyAlgorithm::default(), "EDDSA");

    let keys = AmountOfKeys {
        global: 0,
        authentication: 0,
        assertion_method: 0,
        key_agreement: 0,
        capability_invocation: 0,
        capability_delegation: 0,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_too_much_keys() {
    let did_method = setup_key_did_method(MockKeyAlgorithm::default(), "EDDSA");

    let keys = AmountOfKeys {
        global: 2,
        authentication: 1,
        assertion_method: 1,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_missing_key() {
    let did_method = setup_key_did_method(MockKeyAlgorithm::default(), "EDDSA");

    let keys = AmountOfKeys {
        global: 1,
        authentication: 1,
        assertion_method: 0,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(!did_method.validate_keys(keys));
}
