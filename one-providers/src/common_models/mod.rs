//! Models shared across providers. See the [API resources][api] for more on
//! entities found here.
//!
//! [api]: https://docs.procivis.ch/guides/api/overview

pub mod claim;
pub mod claim_schema;
pub mod credential;
pub mod credential_schema;
pub mod did;
pub mod interaction;
pub mod key;
pub mod macros;
pub mod organisation;
pub mod proof;
pub mod proof_schema;

pub const NESTED_CLAIM_MARKER: char = '/';

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenPublicKeyJwk {
    Ec(OpenPublicKeyJwkEllipticData),
    Rsa(OpenPublicKeyJwkRsaData),
    Okp(OpenPublicKeyJwkEllipticData),
    Oct(OpenPublicKeyJwkOctData),
    Mlwe(OpenPublicKeyJwkMlweData),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPublicKeyJwkRsaData {
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPublicKeyJwkOctData {
    pub r#use: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPublicKeyJwkMlweData {
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPublicKeyJwkEllipticData {
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}
