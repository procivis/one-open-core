use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::common_models::macros::{impl_display, impl_from, impl_into};

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
