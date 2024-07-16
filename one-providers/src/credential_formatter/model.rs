use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use strum::Display;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::{common_models::did::DidValue, crypto::SignerError};

use super::error::FormatterError;

pub type AuthenticationFn = Box<dyn SignatureProvider>;
pub type VerificationFn = Box<dyn TokenVerifier>;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    async fn verify<'a>(
        &self,
        issuer_did_value: Option<DidValue>,
        issuer_key_id: Option<&'a str>,
        algorithm: &'a str,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError>;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait SignatureProvider: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
    fn get_key_id(&self) -> Option<String>;
    fn get_public_key(&self) -> Vec<u8>;
}

#[derive(Debug, Clone)]
pub struct DetailCredential {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub update_at: Option<OffsetDateTime>,
    pub invalid_before: Option<OffsetDateTime>,
    pub issuer_did: Option<DidValue>,
    pub subject: Option<DidValue>,
    pub claims: CredentialSubject,
    pub status: Vec<CredentialStatus>,
    pub credential_schema: Option<CredentialSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(flatten)]
    pub values: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    pub id: String,
    pub r#type: String,
}

impl CredentialSchema {
    pub fn new(id: String, r#type: String) -> Self {
        Self { id, r#type }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublishedClaim {
    pub key: String,
    pub value: PublishedClaimValue,
    pub datatype: Option<String>,
    pub array_item: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PublishedClaimValue {
    Bool(bool),
    Float(f64),
    Integer(i64),
    String(String),
}

impl TryFrom<PublishedClaimValue> for serde_json::Value {
    type Error = FormatterError;

    fn try_from(value: PublishedClaimValue) -> Result<Self, Self::Error> {
        Ok(match value {
            PublishedClaimValue::Bool(value) => serde_json::Value::Bool(value),
            PublishedClaimValue::Float(value) => serde_json::Value::Number(
                serde_json::Number::from_f64(value).ok_or(FormatterError::FloatValueIsNaN)?,
            ),
            PublishedClaimValue::Integer(value) => {
                serde_json::Value::Number(serde_json::Number::from(value))
            }
            PublishedClaimValue::String(value) => serde_json::Value::String(value),
        })
    }
}

impl Display for PublishedClaimValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishedClaimValue::Bool(value) => write!(f, "{}", value),
            PublishedClaimValue::Float(value) => write!(f, "{}", value),
            PublishedClaimValue::Integer(value) => write!(f, "{}", value),
            PublishedClaimValue::String(value) => write!(f, "{}", value),
        }
    }
}

impl From<&str> for PublishedClaimValue {
    fn from(value: &str) -> Self {
        PublishedClaimValue::String(value.to_string())
    }
}

impl PartialEq<str> for PublishedClaimValue {
    fn eq(&self, other: &str) -> bool {
        if let PublishedClaimValue::String(value) = self {
            value == other
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct CredentialData {
    pub id: String,
    pub issuance_date: OffsetDateTime,
    pub valid_for: Duration,
    pub claims: Vec<PublishedClaim>,
    pub issuer_did: DidValue,
    pub status: Vec<CredentialStatus>,
    pub schema: CredentialSchemaData,
}

#[derive(Debug)]
pub struct CredentialSchemaData {
    pub id: Option<String>,
    pub r#type: Option<String>,
    pub context: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_purpose: Option<String>,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, String>,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct FormatPresentationCtx {
    pub nonce: Option<String>,
    pub format_nonce: Option<String>,
    pub client_id: Option<Url>,
    pub response_uri: Option<Url>,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct ExtractPresentationCtx {
    pub nonce: Option<String>,
    pub format_nonce: Option<String>,
    pub issuance_date: Option<OffsetDateTime>,
    pub expiration_date: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Presentation {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub issuer_did: Option<DidValue>,
    pub nonce: Option<String>,
    pub credentials: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPresentation {
    pub token: String,
    pub disclosed_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialClaimSchemaResponse {
    pub key: String,
    pub id: String,
    pub datatype: String,
    pub required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialSchemaResponse {
    pub name: String,
    pub id: String,
    pub claims: Vec<VCCredentialClaimSchemaResponse>,
}

#[derive(Clone, Default)]
pub struct FormatterCapabilities {
    pub features: Vec<String>,
    pub selective_disclosure: Vec<String>,
    pub issuance_did_methods: Vec<String>,
    pub issuance_exchange_protocols: Vec<String>,
    pub proof_exchange_protocols: Vec<String>,
    pub revocation_methods: Vec<String>,
    pub signing_key_algorithms: Vec<String>,
    pub verification_key_algorithms: Vec<String>,
    pub datatypes: Vec<String>,
    pub allowed_schema_ids: Vec<String>,
    pub forbidden_claim_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Display)]
pub enum Context {
    #[serde(rename = "https://www.w3.org/2018/credentials/v1")]
    #[strum(to_string = "https://www.w3.org/2018/credentials/v1")]
    CredentialsV1,

    #[serde(rename = "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld")]
    #[strum(to_string = "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld")]
    BitstringStatusList,

    #[serde(rename = "https://w3id.org/security/data-integrity/v2")]
    #[strum(to_string = "https://w3id.org/security/data-integrity/v2")]
    DataIntegrityV2,
}
