//! `struct`s and `enum`s for key storage provider.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeySecurity {
    Hardware,
    Software,
}

#[derive(Clone, Debug, Default)]
pub struct KeyStorageCapabilities {
    pub features: Vec<String>,
    pub algorithms: Vec<String>,
    pub security: Vec<KeySecurity>,
}

pub struct StorageGeneratedKey {
    pub public_key: Vec<u8>,
    pub key_reference: Vec<u8>,
}
