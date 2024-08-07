use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{claim_schema::OpenClaimSchema, organisation::OpenOrganisation};
use crate::common_models::macros::{impl_display, impl_from, impl_into};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CredentialSchemaId(Uuid);
impl_display!(CredentialSchemaId);
impl_from!(CredentialSchemaId; Uuid);
impl_into!(CredentialSchemaId; Uuid);

pub type CredentialSchemaName = String;
pub type CredentialFormat = String;
pub type RevocationMethod = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCredentialSchema {
    pub id: CredentialSchemaId,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: CredentialSchemaName,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub wallet_storage_type: Option<OpenWalletStorageTypeEnum>,
    pub layout_type: OpenLayoutType,
    pub layout_properties: Option<OpenLayoutProperties>,
    pub schema_id: String,
    pub schema_type: String,

    // Relations
    pub claim_schemas: Option<Vec<OpenCredentialSchemaClaim>>,
    pub organisation: Option<OpenOrganisation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCredentialSchemaClaim {
    pub schema: OpenClaimSchema,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum OpenWalletStorageTypeEnum {
    Hardware,
    Software,
}

#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenLayoutType {
    Card,
    Document,
    SingleAttribute,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenLayoutProperties {
    pub background: Option<OpenBackgroundProperties>,
    pub logo: Option<OpenLogoProperties>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    pub code: Option<OpenCodeProperties>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenBackgroundProperties {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenLogoProperties {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenCodeProperties {
    pub attribute: String,
    pub r#type: OpenCodeTypeEnum,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCodeTypeEnum {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenUpdateCredentialSchemaRequest {
    pub id: CredentialSchemaId,
    pub revocation_method: Option<RevocationMethod>,
    pub format: Option<String>,
    pub claim_schemas: Option<Vec<OpenCredentialSchemaClaim>>,
}
