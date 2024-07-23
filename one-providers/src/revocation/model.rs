use serde::Serialize;
use strum::Display;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    common_models::{credential::Credential, proof_schema::ProofInputSchema},
    credential_formatter::model::{CredentialStatus, DetailCredential},
};

pub type RevocationListId = Uuid;

pub struct CredentialAdditionalData {
    pub credentials_by_issuer_did: Vec<Credential>,
    pub revocation_list_id: RevocationListId,
    pub suspension_list_id: RevocationListId,
}

#[derive(Clone)]
pub enum CredentialDataByRole {
    Holder(Credential),
    Issuer(Credential),
    Verifier(Box<VerifierCredentialData>),
}

#[derive(Debug, Clone)]
pub struct VerifierCredentialData {
    pub credential: DetailCredential,
    pub extracted_lvvcs: Vec<DetailCredential>,
    pub proof_input: ProofInputSchema,
}

pub struct CredentialRevocationInfo {
    pub credential_status: CredentialStatus,
}

#[derive(Clone, Debug, Display, PartialEq)]
pub enum CredentialRevocationState {
    Valid,
    Revoked,
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
}

#[derive(Debug, Default)]
pub struct JsonLdContext {
    pub revokable_credential_type: String,
    pub revokable_credential_subject: String,
    pub url: Option<String>,
}

#[derive(Clone, Default, Serialize)]
pub struct RevocationMethodCapabilities {
    pub operations: Vec<String>,
}

#[derive(Debug)]
pub struct RevocationUpdate {
    pub status_type: String,
    pub data: Vec<u8>,
}