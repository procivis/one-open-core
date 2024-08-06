use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common_models::macros::{impl_display, impl_from, impl_into};

#[derive(Debug, Clone, Copy, Eq, Serialize, Deserialize, PartialEq, Hash)]
pub struct ClaimSchemaId(Uuid);
impl_display!(ClaimSchemaId);
impl_from!(ClaimSchemaId; Uuid);
impl_into!(ClaimSchemaId; Uuid);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenClaimSchema {
    pub id: ClaimSchemaId,
    pub key: String,
    pub data_type: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub array: bool,
}
