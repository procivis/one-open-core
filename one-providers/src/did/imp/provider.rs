use std::{collections::HashMap, sync::Arc};

use crate::{
    common_models::did::DidValue,
    did::{
        error::DidMethodProviderError, model::DidDocument, provider::DidMethodProvider, DidMethod,
    },
};

pub struct DidMethodProviderImpl {
    did_methods: HashMap<String, Arc<dyn DidMethod>>,
}

impl DidMethodProviderImpl {
    pub fn new(did_methods: HashMap<String, Arc<dyn DidMethod>>) -> Self {
        Self { did_methods }
    }
}

#[async_trait::async_trait]
impl DidMethodProvider for DidMethodProviderImpl {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>> {
        self.did_methods.get(did_method_id).cloned()
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError> {
        let did_method_id = did_method_id_from_value(did)?;

        let method = self
            .get_did_method(&did_method_id)
            .ok_or(DidMethodProviderError::MissingProvider(did_method_id))?;

        Ok(method.resolve(did).await?)
    }
}
pub(super) fn did_method_id_from_value(
    did_value: &DidValue,
) -> Result<String, DidMethodProviderError> {
    let mut parts = did_value.as_str().splitn(3, ':');

    let did_method = parts
        .nth(1)
        .ok_or(DidMethodProviderError::MissingDidMethodNameInDidValue)?;
    Ok(did_method.to_uppercase())
}
