use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kty")]
pub enum PublicKeyJwkDTO {
    #[serde(rename = "EC")]
    Ec(PublicKeyJwkEllipticDataDTO),
    #[serde(rename = "RSA")]
    Rsa(PublicKeyJwkRsaDataDTO),
    #[serde(rename = "OKP")]
    Okp(PublicKeyJwkEllipticDataDTO),
    #[serde(rename = "oct")]
    Oct(PublicKeyJwkOctDataDTO),
    #[serde(rename = "MLWE")]
    Mlwe(PublicKeyJwkMlweDataDTO),
}

impl PublicKeyJwkDTO {
    pub fn get_use(&self) -> &Option<String> {
        match self {
            PublicKeyJwkDTO::Ec(val) => &val.r#use,
            PublicKeyJwkDTO::Rsa(val) => &val.r#use,
            PublicKeyJwkDTO::Okp(val) => &val.r#use,
            PublicKeyJwkDTO::Oct(val) => &val.r#use,
            PublicKeyJwkDTO::Mlwe(val) => &val.r#use,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkRsaDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkOctDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkMlweDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkEllipticDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}
