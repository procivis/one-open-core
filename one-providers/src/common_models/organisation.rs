use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::macros::{impl_display, impl_from, impl_into};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OrganisationId(Uuid);
impl_display!(OrganisationId);
impl_from!(OrganisationId; Uuid);
impl_into!(OrganisationId; Uuid);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenOrganisation {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}
