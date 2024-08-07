//! Implementation of DID Universal Resolver.

use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    common_models::{
        did::{DidId, DidValue},
        key::OpenKey,
    },
    did::{
        error::DidMethodError,
        imp::dto::DidDocumentDTO,
        keys::Keys,
        model::{AmountOfKeys, DidCapabilities, DidDocument, Operation},
        DidMethod,
    },
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolutionResponse {
    did_document: DidDocumentDTO,
}

#[derive(Debug)]
pub struct Params {
    pub resolver_url: String,
}

pub struct UniversalDidMethod {
    pub params: Params,
    pub client: reqwest::Client,
}

impl UniversalDidMethod {
    pub fn new(params: Params) -> Self {
        Self {
            params,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl DidMethod for UniversalDidMethod {
    async fn create(
        &self,
        _id: Option<DidId>,
        _params: &Option<serde_json::Value>,
        _keys: Option<Vec<OpenKey>>,
    ) -> Result<DidValue, DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocument, DidMethodError> {
        let url = format!("{}/1.0/identifiers/{}", self.params.resolver_url, did_value,);

        let response = self
            .client
            .get(url)
            .send()
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| {
                DidMethodError::ResolutionError(format!("Could not fetch did document: {e}"))
            })?;

        Ok(response
            .json::<ResolutionResponse>()
            .await
            .map(|resp| resp.did_document)
            .map_err(|e| {
                DidMethodError::ResolutionError(format!("Could not deserialize response: {e}"))
            })?
            .into())
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE],
            key_algorithms: vec![],
        }
    }

    fn validate_keys(&self, _keys: AmountOfKeys) -> bool {
        unimplemented!()
    }

    fn get_keys(&self) -> Option<Keys> {
        None
    }
}

#[cfg(test)]
mod test;
