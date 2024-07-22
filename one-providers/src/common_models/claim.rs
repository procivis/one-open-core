use time::OffsetDateTime;
use uuid::Uuid;

use super::claim_schema::ClaimSchema;
use crate::common_models::{
    credential::CredentialId,
    macros::{impl_display, impl_from, impl_into},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ClaimId(Uuid);
impl_display!(ClaimId);
impl_from!(ClaimId; Uuid);
impl_into!(ClaimId; Uuid);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    pub id: ClaimId,
    pub credential_id: CredentialId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: String,
    pub path: String,

    // Relations
    pub schema: Option<ClaimSchema>,
}
