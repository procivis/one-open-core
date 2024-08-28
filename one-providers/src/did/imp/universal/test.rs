use std::sync::Arc;

use crate::did::{
    imp::universal::{Params, UniversalDidMethod},
    model::Operation,
    DidMethod,
};
use crate::http_client::MockHttpClient;

#[test]
fn test_get_capabilities() {
    let provider = UniversalDidMethod::new(
        Params {
            resolver_url: "".into(),
        },
        Arc::new(MockHttpClient::new()),
    );

    assert_eq!(
        vec![Operation::RESOLVE],
        provider.get_capabilities().operations
    );
}
