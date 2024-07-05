use std::{collections::HashMap, sync::Arc};

use hmac::Hmac;
use sha2::Sha256;

use super::{CryptoProvider, CryptoProviderError, Hasher, Signer};

pub mod encryption;
pub mod hasher;
pub mod signer;
pub mod utilities;

mod password;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct CryptoProviderImpl {
    hashers: HashMap<String, Arc<dyn Hasher>>,
    signers: HashMap<String, Arc<dyn Signer>>,
}

impl CryptoProviderImpl {
    pub fn new(
        hashers: HashMap<String, Arc<dyn Hasher>>,
        signers: HashMap<String, Arc<dyn Signer>>,
    ) -> Self {
        Self { hashers, signers }
    }
}

impl CryptoProvider for CryptoProviderImpl {
    fn get_hasher(&self, hasher: &str) -> Result<Arc<dyn Hasher>, CryptoProviderError> {
        Ok(self
            .hashers
            .get(hasher)
            .ok_or(CryptoProviderError::MissingHasher(hasher.to_owned()))?
            .clone())
    }

    fn get_signer(&self, signer: &str) -> Result<Arc<dyn Signer>, CryptoProviderError> {
        Ok(self
            .signers
            .get(signer)
            .ok_or(CryptoProviderError::MissingHasher(signer.to_owned()))?
            .clone())
    }
}
