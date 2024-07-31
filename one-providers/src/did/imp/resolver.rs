use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    caching_loader::Resolver,
    common_models::did::DidValue,
    did::{error::DidMethodProviderError, imp::dto::DidDocumentDTO, DidMethod},
};

pub struct DidResolver {
    pub did_methods: HashMap<String, Arc<dyn DidMethod>>,
}

#[async_trait]
impl Resolver for DidResolver {
    type Error = DidMethodProviderError;

    async fn do_resolve(&self, did_value: &str) -> Result<Vec<u8>, Self::Error> {
        let did_method_id = did_method_id_from_value(did_value)?;

        let method = self
            .did_methods
            .get(&did_method_id)
            .ok_or(DidMethodProviderError::MissingProvider(did_method_id))?;

        let did_value = DidValue::from(did_value.to_string());
        let document = method.resolve(&did_value).await?;
        let dto: DidDocumentDTO = document.into();

        Ok(serde_json::to_vec(&dto)?)
    }
}

fn did_method_id_from_value(did_value: &str) -> Result<String, DidMethodProviderError> {
    let mut parts = did_value.splitn(3, ':');

    let did_method = parts
        .nth(1)
        .ok_or(DidMethodProviderError::MissingDidMethodNameInDidValue)?;
    Ok(did_method.to_uppercase())
}
