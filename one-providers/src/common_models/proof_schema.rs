use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    claim_schema::OpenClaimSchema, credential_schema::OpenCredentialSchema,
    organisation::OpenOrganisation,
};
use crate::common_models::macros::{impl_display, impl_from, impl_into};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ProofSchemaId(Uuid);
impl_display!(ProofSchemaId);
impl_from!(ProofSchemaId; Uuid);
impl_into!(ProofSchemaId; Uuid);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenProofSchema {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub expire_duration: u32,

    // Relations
    pub input_schemas: Option<Vec<OpenProofInputSchema>>,
    pub organisation: Option<OpenOrganisation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OpenProofInputSchema {
    pub validity_constraint: Option<i64>,

    // Relations
    pub claim_schemas: Option<Vec<OpenProofInputClaimSchema>>,
    pub credential_schema: Option<OpenCredentialSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenProofInputClaimSchema {
    pub schema: OpenClaimSchema,
    pub required: bool,
    pub order: u32,
}
