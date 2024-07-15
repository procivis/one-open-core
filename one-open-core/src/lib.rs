use std::{collections::HashMap, sync::Arc};

use model::KeyAlgorithmType;
use one_providers::{
    crypto::imp::{
        hasher::sha256::SHA256,
        signer::{bbs::BBSSigner, crydi3::CRYDI3Signer, eddsa::EDDSASigner, es256::ES256Signer},
        CryptoProviderImpl,
    },
    key_algorithm::{
        imp::{
            bbs::BBS,
            eddsa::{self, Eddsa, EddsaParams},
            es256::{self, Es256, Es256Params},
            provider::KeyAlgorithmProviderImpl,
        },
        KeyAlgorithm,
    },
};
use service::signature_service::SignatureService;

pub mod model;
pub mod service;

pub struct OneOpenCore {
    pub signature_service: SignatureService,
}

impl Default for OneOpenCore {
    fn default() -> Self {
        Self::new()
    }
}

impl OneOpenCore {
    pub fn new() -> Self {
        let crypto = Arc::new(CryptoProviderImpl::new(
            HashMap::from_iter(vec![("sha-256".to_string(), Arc::new(SHA256 {}) as _)]),
            HashMap::from_iter(vec![
                ("Ed25519".to_string(), Arc::new(EDDSASigner {}) as _),
                ("ES256".to_string(), Arc::new(ES256Signer {}) as _),
                ("CRYDI3".to_string(), Arc::new(CRYDI3Signer {}) as _),
                ("BBS".to_string(), Arc::new(BBSSigner {}) as _),
            ]),
        ));

        let key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm>> = HashMap::from_iter(vec![
            (
                KeyAlgorithmType::Eddsa.to_string(),
                Arc::new(Eddsa::new(EddsaParams {
                    algorithm: eddsa::Algorithm::Ed25519,
                })) as _,
            ),
            (
                KeyAlgorithmType::Es256.to_string(),
                Arc::new(Es256::new(Es256Params {
                    algorithm: es256::Algorithm::Es256,
                })) as _,
            ),
            (KeyAlgorithmType::BbsPlus.to_string(), Arc::new(BBS) as _),
        ]);

        let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(
            key_algorithms,
            crypto.clone(),
        ));

        let signature_service = SignatureService {
            crypto,
            key_algorithm_provider,
        };

        Self { signature_service }
    }
}
