use async_trait::async_trait;

use crate::{
    common_models::{
        did::{DidId, DidValue},
        key::Key,
    },
    did::{
        error::DidMethodError,
        keys::Keys,
        model::{AmountOfKeys, DidCapabilities, DidDocument},
    },
};

pub mod error;
pub mod imp;
pub mod keys;
pub mod model;
pub mod provider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait DidMethod: Send + Sync {
    async fn create(
        &self,
        id: &DidId,
        params: &Option<serde_json::Value>,
        keys: &[Key],
    ) -> Result<DidValue, DidMethodError>;
    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError>;
    fn update(&self) -> Result<(), DidMethodError>;
    fn can_be_deactivated(&self) -> bool;
    fn get_capabilities(&self) -> DidCapabilities;
    fn validate_keys(&self, keys: AmountOfKeys) -> bool;
    fn get_keys(&self) -> Option<Keys>;
}
