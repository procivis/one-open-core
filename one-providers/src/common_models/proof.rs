use super::claim::Claim;
use super::credential::Credential;
use super::did::{Did, DidId};
use super::interaction::{Interaction, InteractionId};
use super::proof_schema::ProofSchema;
use crate::common_models::key::Key;
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
pub struct Proof {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub exchange: String,
    pub transport: String,
    pub redirect_uri: Option<String>,

    // Relations
    pub state: Option<Vec<ProofState>>,
    pub schema: Option<ProofSchema>,
    pub claims: Option<Vec<ProofClaim>>,
    pub verifier_did: Option<Did>,
    pub holder_did: Option<Did>,
    pub verifier_key: Option<Key>,
    pub interaction: Option<Interaction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum ProofStateEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofState {
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub state: ProofStateEnum,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofClaim {
    pub claim: Claim,
    // Relations
    pub credential: Option<Credential>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateProofRequest {
    pub id: ProofId,

    pub holder_did_id: Option<DidId>,
    pub verifier_did_id: Option<DidId>,
    pub state: Option<ProofState>,
    pub interaction: Option<Option<InteractionId>>,
    pub redirect_uri: Option<Option<String>>,
}
