use std::{collections::HashMap, sync::Arc};

use one_crypto::MockCryptoProvider;
use time::{Duration, OffsetDateTime};

use super::{
    derived_proof::find_selective_indices,
    model::{GroupEntry, TransformedEntry},
};
use crate::{
    credential_formatter::imp::{
        json_ld::{
            model::{LdCredential, LdCredentialSubject},
            test_utilities::prepare_caching_loader,
        },
        json_ld_bbsplus::{
            remove_undisclosed_keys::remove_undisclosed_keys, JsonLdBbsplus, Params,
        },
    },
    did::provider::MockDidMethodProvider,
    key_algorithm::provider::MockKeyAlgorithmProvider,
};

#[tokio::test]
async fn test_canonize_any() {
    let crypto = MockCryptoProvider::default();
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let did_method_provider = MockDidMethodProvider::default();

    let ld_formatter = JsonLdBbsplus::new(
        Params {
            leeway: Duration::seconds(10),
        },
        Arc::new(crypto),
        Some("base".to_owned()),
        Arc::new(did_method_provider),
        Arc::new(key_algorithm_provider),
        prepare_caching_loader(),
    );

    let hmac_key = [
        0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 17, 34, 51, 68,
        85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255,
    ];
    let result = ld_formatter
        .create_blank_node_identifier_map(CANONICAL, &hmac_key)
        .unwrap();

    assert_eq!(result.get("_:c14n0"), Some(&"_:b2".to_string()));
    assert_eq!(result.get("_:c14n1"), Some(&"_:b1".to_string()));
    assert_eq!(result.get("_:c14n2"), Some(&"_:b4".to_string()));
    assert_eq!(result.get("_:c14n3"), Some(&"_:b7".to_string()));
    assert_eq!(result.get("_:c14n4"), Some(&"_:b5".to_string()));
    assert_eq!(result.get("_:c14n5"), Some(&"_:b3".to_string()));
    assert_eq!(result.get("_:c14n6"), Some(&"_:b6".to_string()));
    assert_eq!(result.get("_:c14n7"), Some(&"_:b0".to_string()));
}

#[tokio::test]
async fn test_transform_canonized() {
    let crypto = MockCryptoProvider::default();
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let did_method_provider = MockDidMethodProvider::default();

    let ld_formatter = JsonLdBbsplus::new(
        Params {
            leeway: Duration::seconds(10),
        },
        Arc::new(crypto),
        Some("base".to_owned()),
        Arc::new(did_method_provider),
        Arc::new(key_algorithm_provider),
        prepare_caching_loader(),
    );

    let bnode_ident_map = HashMap::from([
        ("_:c14n0".to_owned(), "_:b2".to_owned()),
        ("_:c14n1".to_owned(), "_:b1".to_owned()),
        ("_:c14n2".to_owned(), "_:b4".to_owned()),
        ("_:c14n3".to_owned(), "_:b7".to_owned()),
        ("_:c14n4".to_owned(), "_:b5".to_owned()),
        ("_:c14n5".to_owned(), "_:b3".to_owned()),
        ("_:c14n6".to_owned(), "_:b6".to_owned()),
        ("_:c14n7".to_owned(), "_:b0".to_owned()),
    ]);

    let result = ld_formatter
        .transform_canonical(&bnode_ident_map, CANONICAL)
        .unwrap();

    assert_eq!(
        result,
        TRANSFORMED
            .lines()
            .map(|l| l.to_owned())
            .collect::<Vec<String>>()
    );
}

#[tokio::test]
async fn test_transform_grouped() {
    let crypto = MockCryptoProvider::default();
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let did_method_provider = MockDidMethodProvider::default();

    let ld_formatter = JsonLdBbsplus::new(
        Params {
            leeway: Duration::seconds(10),
        },
        Arc::new(crypto),
        Some("base".to_owned()),
        Arc::new(did_method_provider),
        Arc::new(key_algorithm_provider),
        prepare_caching_loader(),
    );

    let transformed_lines = &TRANSFORMED_OWN
        .lines()
        .map(|l| l.to_owned())
        .collect::<Vec<String>>();

    let result = ld_formatter
        .create_grouped_transformation(transformed_lines)
        .unwrap();

    for (i, index) in (1..=10).enumerate() {
        assert_eq!(result.mandatory.value[i].index, index);
        assert_eq!(transformed_lines[index], result.mandatory.value[i].entry)
    }

    for (i, index) in [0, 11, 12, 13].into_iter().enumerate() {
        assert_eq!(result.non_mandatory.value[i].index, index);
        assert_eq!(
            transformed_lines[index],
            result.non_mandatory.value[i].entry
        )
    }
}

#[test]
fn test_find_disclosed_indicies() {
    let non_mandatory = TransformedEntry {
        data_type: "Map".to_owned(),
        value: vec![
        GroupEntry {
            index: 0,
            entry: "<did:key:123> <http://127.0.0.1:38083/ssi/context/v1/7201a00e-dc01-4dbf-bcae-f78f6baeeb8e#TestSubject> _:c14n5 .".to_owned()
        },
        GroupEntry {
            index: 1,
            entry: "_:c14n5 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .".to_owned()
        },
        GroupEntry {
            index: 2,
            entry: "_:c14n5 <https://windsurf.grotto-networking.com/selective#sailNumber123> \"Earth101\" .".to_owned()
        }]
    };

    let disclosed_keys = vec!["sailNumber".to_string()];

    let result = find_selective_indices(&non_mandatory, &disclosed_keys).unwrap();
    assert_eq!(result.len(), 2);
    let expected = [0, 1];
    assert!(result.iter().all(|index| expected.contains(index)));
}

static CANONICAL: &str = "_:c14n0 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .
_:c14n0 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .
_:c14n0 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:c14n1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:c14n1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n2 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .
_:c14n2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .
_:c14n2 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n3 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:c14n3 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n3 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n4 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .
_:c14n4 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:c14n4 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n5 <https://windsurf.grotto-networking.com/selective#boards> _:c14n0 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#boards> _:c14n2 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n1 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n3 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n4 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n6 .
_:c14n6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:c14n6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:c14n6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n7 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:c14n7 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 .
_:c14n7 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .
";

static TRANSFORMED: &str = "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:b0 <https://www.w3.org/2018/credentials#credentialSubject> _:b3 .
_:b0 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .
_:b1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:b1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:b1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b2 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .
_:b2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .
_:b2 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b2 .
_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b4 .
_:b3 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .
_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b1 .
_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b5 .
_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b6 .
_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b7 .
_:b4 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .
_:b4 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .
_:b4 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b5 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .
_:b5 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:b5 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:b6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:b6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b7 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:b7 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b7 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .";

static TRANSFORMED_OWN: &str = "<did:key:z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB> <http://127.0.0.1:36585/ssi/context/v1/bb9c433c-3d35-437c-bfb7-919ae6da07aa#TestSubject> _:b0 .
<http://127.0.0.1:36585/ssi/revocation/v1/list/2a66f052-142c-4215-b4bb-00e5eab92318#0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vc/status-list#StatusList2021Entry> .
<http://127.0.0.1:36585/ssi/revocation/v1/list/2a66f052-142c-4215-b4bb-00e5eab92318#0> <https://w3id.org/vc/status-list#statusListCredential> <http://127.0.0.1:36585/ssi/revocation/v1/list/2a66f052-142c-4215-b4bb-00e5eab92318> .
<http://127.0.0.1:36585/ssi/revocation/v1/list/2a66f052-142c-4215-b4bb-00e5eab92318#0> <https://w3id.org/vc/status-list#statusListIndex> \"0\" .
<http://127.0.0.1:36585/ssi/revocation/v1/list/2a66f052-142c-4215-b4bb-00e5eab92318#0> <https://w3id.org/vc/status-list#statusPurpose> \"revocation\" .
<urn:uuid:0f1ec186-ca23-457d-ba20-ccefb412bbe0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://127.0.0.1:36585/ssi/context/v1/bb9c433c-3d35-437c-bfb7-919ae6da07aa#TestSubject> .
<urn:uuid:0f1ec186-ca23-457d-ba20-ccefb412bbe0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<urn:uuid:0f1ec186-ca23-457d-ba20-ccefb412bbe0> <https://www.w3.org/2018/credentials#credentialStatus> <http://127.0.0.1:36585/ssi/revocation/v1/list/2a66f052-142c-4215-b4bb-00e5eab92318#0> .
<urn:uuid:0f1ec186-ca23-457d-ba20-ccefb412bbe0> <https://www.w3.org/2018/credentials#credentialSubject> <did:key:z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB> .
<urn:uuid:0f1ec186-ca23-457d-ba20-ccefb412bbe0> <https://www.w3.org/2018/credentials#issuanceDate> \"2024-02-12T13:23:34.013897142Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<urn:uuid:0f1ec186-ca23-457d-ba20-ccefb412bbe0> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC77bqRWgmZNzUQHeSSuQTiMc2Pqv3uTp1oWgbwrXushHz4Y5CbCG3WRZVo93qMwqKqizMbA6ntvgGBXq5ZoHZ6HseTN842bp43GkR3N1Sw7TkJ52uQPUEyWYVD5ggtnn1E85W> .
_:b0 <http://127.0.0.1:36585/ssi/context/v1/bb9c433c-3d35-437c-bfb7-919ae6da07aa#Address> \"test\" .
_:b0 <http://127.0.0.1:36585/ssi/context/v1/bb9c433c-3d35-437c-bfb7-919ae6da07aa#Key> \"test\" .
_:b0 <http://127.0.0.1:36585/ssi/context/v1/bb9c433c-3d35-437c-bfb7-919ae6da07aa#Name> \"test\" .";

fn generate_ld_credential(subject_claims: serde_json::Value) -> LdCredential {
    LdCredential {
        context: vec![],
        id: Some("".to_string()),
        r#type: vec![],
        issuer: "did:key:1234".to_string().into(),
        valid_from: Some(OffsetDateTime::now_utc()),
        credential_subject: LdCredentialSubject {
            id: Some("did:key:1234".to_string().into()),
            subject: HashMap::from([("credentialSubject".to_string(), subject_claims)]),
        },
        credential_status: vec![],
        proof: None,
        credential_schema: None,
        valid_until: None,
    }
}

#[test]
fn test_find_selective() {
    let input: TransformedEntry = TransformedEntry {
        data_type: "Map".to_string(),
        value: vec![
            GroupEntry {
                entry: "<did:key:z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB> <http://127.0.0.1:38083/ssi/context/v1/7201a00e-dc01-4dbf-bcae-f78f6baeeb8e#TestSubject> _:b0 .".to_string(),
                index: 0
            },
            GroupEntry {
                entry: "_:b0 <http://127.0.0.1:42643/ssi/context/v1/7f539283-3468-4d50-8540-7e9f831acc0c#Address%20root> _:b1 .".to_string(),
                index: 8
            },
            GroupEntry {
                entry: "_:b0 <http://127.0.0.1:38083/ssi/context/v1/7201a00e-dc01-4dbf-bcae-f78f6baeeb8e#Key%201> \"test\" .".to_string(),
                index: 9
            },
            GroupEntry {
                entry: "_:b1 <http://127.0.0.1:38083/ssi/context/v1/7201a00e-dc01-4dbf-bcae-f78f6baeeb8e#Address1> \"test\" .".to_string(),
                index: 10
            },
            GroupEntry {
                entry: "_:b1 <http://127.0.0.1:38083/ssi/context/v1/7201a00e-dc01-4dbf-bcae-f78f6baeeb8e#Address2> _:b2 .".to_string(),
                index: 11
            },
            GroupEntry {
                entry: "_:b2 <http://127.0.0.1:38083/ssi/context/v1/7201a00e-dc01-4dbf-bcae-f78f6baeeb8e#Address3> \"test\" .".to_string(),
                index: 12
            },
        ],
    };

    let res = find_selective_indices(
        &input,
        &[
            "Address root/Address2".to_string(),
            "Address root/Address1".to_string(),
        ],
    )
    .unwrap();

    let expected = [0, 8, 10, 11, 12];

    assert!(res.iter().all(|index| expected.contains(index)));
}

#[test]
fn test_remove_undisclosed_keys_group_allow_whole_object() {
    let mut test_cred = generate_ld_credential(serde_json::json!({
        "foo": {
            "bar": 10,
            "bar1": 11
        }
    }));

    remove_undisclosed_keys(&mut test_cred, &["foo".to_string()]).unwrap();

    let expected = serde_json::json!({
        "foo": {
            "bar": 10,
            "bar1": 11
        }
    });

    assert_eq!(
        expected,
        test_cred.credential_subject.subject["credentialSubject"]
    );
}

#[test]
fn test_remove_undisclosed_keys_group_allow_separate_claims() {
    let mut test_cred = generate_ld_credential(serde_json::json!({
        "foo": {
            "bar": 10,
            "bar1": 11
        }
    }));

    remove_undisclosed_keys(&mut test_cred, &["foo/bar".to_string()]).unwrap();

    let expected = serde_json::json!({
        "foo": {
            "bar": 10
        }
    });

    assert_eq!(
        expected,
        test_cred.credential_subject.subject["credentialSubject"]
    );
}

#[test]
fn test_remove_undisclosed_keys_group_allow_none() {
    let mut test_cred = generate_ld_credential(serde_json::json!({
        "foo": {
            "bar": 10,
            "bar1": 11
        }
    }));

    remove_undisclosed_keys(&mut test_cred, &["some_unrelated_claim".to_string()]).unwrap();

    let expected = serde_json::json!({});

    assert_eq!(
        expected,
        test_cred.credential_subject.subject["credentialSubject"]
    );
}

#[test]
fn test_remove_undisclosed_keys_group_allow_multiple_claims() {
    let mut test_cred = generate_ld_credential(serde_json::json!({
        "foo": {
            "bar": 10,
            "bar1": 11
        }
    }));

    remove_undisclosed_keys(
        &mut test_cred,
        &["foo/bar".to_string(), "foo/bar1".to_string()],
    )
    .unwrap();

    let expected = serde_json::json!({
        "foo": {
            "bar": 10,
            "bar1": 11
        }
    });

    assert_eq!(
        expected,
        test_cred.credential_subject.subject["credentialSubject"]
    );
}
