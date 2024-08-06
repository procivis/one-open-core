use super::claim::OpenClaim;
use super::credential::OpenCredential;
use super::did::{DidId, OpenDid};
use super::interaction::{InteractionId, OpenInteraction};
use super::proof_schema::OpenProofSchema;
use crate::common_models::key::OpenKey;
use crate::common_models::macros::{impl_display, impl_from, impl_into};
use strum::Display;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ProofId(Uuid);
impl_display!(ProofId);
impl_from!(ProofId; Uuid);
impl_into!(ProofId; Uuid);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenProof {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub exchange: String,
    pub transport: String,
    pub redirect_uri: Option<String>,

    // Relations
    pub state: Option<Vec<OpenProofState>>,
    pub schema: Option<OpenProofSchema>,
    pub claims: Option<Vec<OpenProofClaim>>,
    pub verifier_did: Option<OpenDid>,
    pub holder_did: Option<OpenDid>,
    pub verifier_key: Option<OpenKey>,
    pub interaction: Option<OpenInteraction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum OpenProofStateEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenProofState {
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub state: OpenProofStateEnum,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenProofClaim {
    pub claim: OpenClaim,
    // Relations
    pub credential: Option<OpenCredential>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenUpdateProofRequest {
    pub id: ProofId,

    pub holder_did_id: Option<DidId>,
    pub verifier_did_id: Option<DidId>,
    pub state: Option<OpenProofState>,
    pub interaction: Option<Option<InteractionId>>,
    pub redirect_uri: Option<Option<String>>,
}
