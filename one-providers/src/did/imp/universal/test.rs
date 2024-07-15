use crate::did::{
    imp::universal::{Params, UniversalDidMethod},
    model::Operation,
    DidMethod,
};

#[test]
fn test_get_capabilities() {
    let provider = UniversalDidMethod::new(Params {
        resolver_url: "".into(),
    });

    assert_eq!(
        vec![Operation::RESOLVE],
        provider.get_capabilities().operations
    );
}
