use strum::Display;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{claim::Claim, credential_schema::CredentialSchema};
use crate::common_models::{
    did::Did,
    key::Key,
    macros::{impl_display, impl_from, impl_into},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct CredentialId(Uuid);
impl_display!(CredentialId);
impl_from!(CredentialId; Uuid);
impl_into!(CredentialId; Uuid);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub credential: Vec<u8>,
    pub exchange: String,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,

    // Relations:
    pub state: Option<Vec<CredentialState>>,
    pub claims: Option<Vec<Claim>>,
    pub issuer_did: Option<Did>,
    pub holder_did: Option<Did>,
    pub schema: Option<CredentialSchema>,
    pub key: Option<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialState {
    pub created_date: OffsetDateTime,
    pub state: CredentialStateEnum,
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum CredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}
