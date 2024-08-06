use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::macros::{impl_display, impl_from, impl_into};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct InteractionId(Uuid);
impl_display!(InteractionId);
impl_from!(InteractionId; Uuid);
impl_into!(InteractionId; Uuid);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenInteraction {
    pub id: InteractionId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub host: Option<Url>,
    pub data: Option<Vec<u8>>,
}
