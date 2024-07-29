#![feature(async_closure)]

use one_open_core::OneOpenCore;
use one_providers::did::{
    imp::{
        universal::{
            UniversalDidMethod,
            Params as UniversalDidMethodParams,
        },
    },
    error::DidMethodError,
    DidMethod,
};
use one_providers::common_models::did::DidValue;
use futures::future::join_all;

#[tokio::main]
async fn main() -> Result<(), DidMethodError> {
    let core = OneOpenCore::new(None).unwrap();
    let did_service = core.did_service;

    let example_did_values_implemented = vec![
        // did:key
        DidValue::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()),
        // did:jwk
        DidValue::from("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9".to_string()),
        // did:web
        DidValue::from("did:web:core.trial.procivis-one.com:ssi:did-web:v1:bcbfef61-cfd4-4d31-ae46-82f0a121463e".to_string()),
    ];
    let example_did_value_unimplemented = DidValue::from("did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0".to_string());

    //
    // Resolving DIDs using the core DID service
    //

    join_all(example_did_values_implemented.into_iter().map(async |did| {
        // resolve DID using service without allowing fallback provider
        let result = did_service.resolve_did(&did, false).await;
        assert!(result.is_ok(), "expected to resolve DID {}", did);
        println!("Resolved {} into:\n{:#?}\n", did, result);
    })).await;

    // resolving an unimplemented DID method with fallback provider disabled will fail
    let result = did_service.resolve_did(&example_did_value_unimplemented, false).await;
    assert!(result.is_err(), "expected not to resolve DID");

    // when enabling the fallback to an universal resolver, DID resolution should succeed however
    let result = did_service.resolve_did(&example_did_value_unimplemented, true).await;
    assert!(result.is_ok(), "expected to resolve DID");

    //
    // Resolving DIDs using the DID method impolementation directly
    //

    let example_did_key = DidValue::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string());
    let did_key = did_service.get_did_method("KEY").unwrap();
    let result = did_key.resolve(&example_did_key).await;
    assert!(result.is_ok(), "expected to resolve DID");

    //
    // Resolving DIDs without initializing core - if desired, the DID methods
    // can also be instantiated and used directly
    //

    let universal_resolver = UniversalDidMethod::new(UniversalDidMethodParams {
        resolver_url: "https://dev.uniresolver.io".to_string(),
    });
    let result = universal_resolver.resolve(&example_did_key).await;
    assert!(result.is_ok(), "expected to resolve DID");

    Ok(())
}
