use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    macros::{impl_display, impl_from, impl_into},
    organisation::Organisation,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct KeyId(Uuid);
impl_display!(KeyId);
impl_from!(KeyId; Uuid);
impl_into!(KeyId; Uuid);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Key {
    pub id: KeyId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub public_key: Vec<u8>,
    pub name: String,
    pub key_reference: Vec<u8>,
    pub storage_type: String,
    pub key_type: String,

    // Relations:
    pub organisation: Option<Organisation>,
}
