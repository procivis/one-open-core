use serde::{Deserialize, Serialize};
use strum::Display;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    claim::OpenClaim,
    credential_schema::OpenCredentialSchema,
    did::DidId,
    interaction::{InteractionId, OpenInteraction},
    key::KeyId,
};
use crate::common_models::{
    did::OpenDid,
    key::OpenKey,
    macros::{impl_display, impl_from, impl_into},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CredentialId(Uuid);
impl_display!(CredentialId);
impl_from!(CredentialId; Uuid);
impl_into!(CredentialId; Uuid);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCredential {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub credential: Vec<u8>,
    pub exchange: String,
    pub redirect_uri: Option<String>,
    pub role: OpenCredentialRole,

    // Relations:
    pub state: Option<Vec<OpenCredentialState>>,
    pub claims: Option<Vec<OpenClaim>>,
    pub issuer_did: Option<OpenDid>,
    pub holder_did: Option<OpenDid>,
    pub schema: Option<OpenCredentialSchema>,
    pub key: Option<OpenKey>,
    pub interaction: Option<OpenInteraction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCredentialState {
    pub created_date: OffsetDateTime,
    pub state: OpenCredentialStateEnum,
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCredentialRole {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenUpdateCredentialRequest {
    pub id: CredentialId,

    pub credential: Option<Vec<u8>>,
    pub holder_did_id: Option<DidId>,
    pub issuer_did_id: Option<DidId>,
    pub state: Option<OpenCredentialState>,
    pub interaction: Option<InteractionId>,
    pub key: Option<KeyId>,
    pub redirect_uri: Option<Option<String>>,
}
