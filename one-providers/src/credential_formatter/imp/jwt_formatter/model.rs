use serde::{Deserialize, Serialize};
use serde_with::{serde_as, OneOrMany};
use time::OffsetDateTime;

use crate::credential_formatter::model::{CredentialSchema, CredentialStatus, CredentialSubject};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub credential_subject: CredentialSubject,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub credential_status: Vec<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<CredentialSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Issuer>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VPContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VC {
    pub vc: VCContent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VP {
    pub vp: VPContent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Issuer {
    Object(IssuerObject),
    Url(String),
}

impl Issuer {
    pub fn issuer(&self) -> &str {
        match self {
            Issuer::Object(object) => &object.id,
            Issuer::Url(s) => s,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssuerObject {
    id: String,
    #[serde(flatten)]
    rest: Option<serde_json::Value>,
}
