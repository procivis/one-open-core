use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, OneOrMany};
use time::OffsetDateTime;

use crate::{
    common_models::did::DidValue,
    credential_formatter::model::{CredentialSchema, CredentialStatus},
};

pub type VerifiableCredential = Vec<serde_json::Map<String, serde_json::Value>>;

// The main credential
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LdCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub r#type: Vec<String>,
    pub issuer: DidValue,
    // we keep this field for backwards compatibility with VCDM v1.1
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<OffsetDateTime>,
    pub credential_subject: LdCredentialSubject,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub credential_status: Vec<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<LdProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<CredentialSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LdCredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<DidValue>,
    #[serde(flatten)]
    pub subject: HashMap<String, serde_json::Value>,
}

pub type Claims = HashMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LdProof {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created: Option<OffsetDateTime>,
    pub cryptosuite: String,
    pub verification_method: String,
    pub proof_purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

// The main presentation
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LdPresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub issuance_date: OffsetDateTime,
    pub verifiable_credential: VerifiableCredential,
    pub holder: DidValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<LdProof>,
}
