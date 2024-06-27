#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKeyJwk {
    Ec(PublicKeyJwkEllipticData),
    Rsa(PublicKeyJwkRsaData),
    Okp(PublicKeyJwkEllipticData),
    Oct(PublicKeyJwkOctData),
    Mlwe(PublicKeyJwkMlweData),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkRsaData {
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkOctData {
    pub r#use: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkMlweData {
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyJwkEllipticData {
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

pub struct ParsedPublicKeyJwk {
    pub public_key_bytes: Vec<u8>,
    pub signer_algorithm_id: String,
}

pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}
