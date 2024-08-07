//! Tools for DID method operations and metadata.
//!
//! Decentralized identifiers (DIDs) are a type of globally unique identifier
//! for a resource. The DID is similar to a URL and can be resolved to a DID
//! document which offers metadata about the identified resource.
//!
//! Use this module to perform all operations associated with the relevant
//! DID method.

use async_trait::async_trait;

use crate::{
    common_models::{
        did::{DidId, DidValue},
        key::OpenKey,
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

/// Performs operations on DIDs and provides DID utilities.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait DidMethod: Send + Sync {
    /// Creates a DID.
    async fn create(
        &self,
        id: Option<DidId>,
        params: &Option<serde_json::Value>,
        keys: Option<Vec<OpenKey>>,
    ) -> Result<DidValue, DidMethodError>;

    /// Resolve a DID to its DID document.
    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError>;

    /// Deactivates a DID. Note that DID deactivation is permanent.
    fn update(&self) -> Result<(), DidMethodError>;

    /// Informs whether a DID can be deactivated or not.
    ///
    /// DID deactivation is useful if, for instance, a private key is leaked.
    fn can_be_deactivated(&self) -> bool;

    #[doc = include_str!("../../../docs/capabilities.md")]
    ///
    /// See the [API docs][dmc] for a complete list of credential format capabilities.
    ///
    /// [dmc]: https://docs.procivis.ch/api/resources/dids#did-method-capabilities
    fn get_capabilities(&self) -> DidCapabilities;

    /// Validates whether the number of keys assigned is supported by the DID method.
    ///
    /// Different DID methods support different numbers of keys for verification relationships.
    /// This method validates whether the method of the DID supports the keys associated with it.
    fn validate_keys(&self, keys: AmountOfKeys) -> bool;
    /// Returns the keys associated with a DID.
    fn get_keys(&self) -> Option<Keys>;
}
