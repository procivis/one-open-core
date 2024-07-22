use serde::{Deserialize, Serialize};
use strum::Display;
use time::OffsetDateTime;

use crate::{
    common_models::did::DidValue,
    credential_formatter::model::Context,
    revocation::{
        imp::bitstring_status_list::jwt_formatter::{from_timestamp, into_timestamp},
        model::RevocationListId,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub enum ContentType {
    VerifiableCredential,
    BitstringStatusListCredential,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<Context>,
    pub id: String,
    pub r#type: Vec<ContentType>,
    pub issuer: DidValue,
    #[serde(serialize_with = "into_timestamp", deserialize_with = "from_timestamp")]
    pub issued: OffsetDateTime,
    pub credential_subject: CredentialSubject,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SubjectType {
    BitstringStatusList,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub id: String,
    pub r#type: SubjectType,
    pub status_purpose: StatusPurpose,
    pub encoded_list: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VC {
    pub vc: VCContent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    Revocation,
    Suspension,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationUpdateData {
    pub id: RevocationListId,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RevocationList {
    pub id: RevocationListId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credentials: Vec<u8>,
    pub purpose: RevocationListPurpose,
}

#[derive(Clone, Debug, Eq, PartialEq, Display, Serialize)]
pub enum RevocationListPurpose {
    Revocation,
    Suspension,
}
