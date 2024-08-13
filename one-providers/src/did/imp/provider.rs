use std::{collections::HashMap, sync::Arc};

use crate::{
    common_models::did::DidValue,
    did::{
        error::DidMethodProviderError,
        imp::{dto::DidDocumentDTO, resolver::DidCachingLoader},
        model::DidDocument,
        provider::DidMethodProvider,
        DidMethod,
    },
};

use super::resolver::DidResolver;

pub struct DidMethodProviderImpl {
    caching_loader: DidCachingLoader,
    did_methods: HashMap<String, Arc<dyn DidMethod>>,
    resolver: Arc<DidResolver>,
}

impl DidMethodProviderImpl {
    pub fn new(
        caching_loader: DidCachingLoader,
        did_methods: HashMap<String, Arc<dyn DidMethod>>,
    ) -> Self {
        let resolver = DidResolver {
            did_methods: did_methods.clone(),
        };

        Self {
            caching_loader,
            did_methods,
            resolver: Arc::new(resolver),
        }
    }
}

#[async_trait::async_trait]
impl DidMethodProvider for DidMethodProviderImpl {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>> {
        self.did_methods.get(did_method_id).cloned()
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError> {
        let result = self
            .caching_loader
            .get(did.as_str(), self.resolver.clone())
            .await?;
        let dto: DidDocumentDTO = serde_json::from_slice(&result)?;
        Ok(dto.into())
    }
}
