//! DID method provider.

use std::sync::Arc;

use crate::{
    common_models::did::DidValue,
    did::{error::DidMethodProviderError, model::DidDocument, DidMethod},
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidMethodProvider: Send + Sync {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>>;

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError>;
}
