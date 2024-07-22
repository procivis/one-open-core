use serde::{Deserialize, Serialize};
use strum::Display;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common_models::{
    key::Key,
    macros::{impl_display, impl_from, impl_into},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct DidId(Uuid);
impl_display!(DidId);
impl_from!(DidId; uuid::Uuid);
impl_into!(DidId; uuid::Uuid);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct DidValue(String);
impl_display!(DidValue);
impl_from!(DidValue; String);
impl_into!(DidValue; String);

impl DidValue {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Did {
    pub id: DidId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub did: DidValue,
    pub did_type: DidType,
    pub did_method: String,
    pub deactivated: bool,

    // Relations:
    pub keys: Option<Vec<RelatedKey>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidType {
    Remote,
    Local,
}

#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum KeyRole {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedKey {
    pub role: KeyRole,
    pub key: Key,
}
