//! The **Procivis One Open Core** is a library for issuing, holding, and verifying
//! verifiable credentials.
//!
//! Self-sovereign identity (SSI) is a model of digital identity that enables individuals
//! to receive and hold their identity and credentials, controlling when and with whom
//! they share them, without requesting permission from a centralized authority or
//! identity provider.
//!
//! The library provides all SSI functionality needed to issue, hold, and
//! verify credentials, including credential formats, exchange protocols, digital
//! signature schemes and associated key handling, DID management and revocation
//! methods.
//!
//! ## Key features:
//!
//! - Generate cryptographic key pairs using [ECDSA][ecd], [EdDSA][edd], [BBS+][bbs], and [Dilithium 3][dil] (FIPS 204, post-quantum) algorithms
//! - Create and resolve decentralized identifiers ([DIDs][di]) using [did:web][dw], [did:key][dk], and [did:jwk][djw]
//! - Store keys and safely interact via [Azure Key Vault][akv] or encrypted internal database
//! - Create and issue credentials in [JSON-LD][jld] and [JWT][jw] formats using [OpenID4VCI][vci]
//! - Revoke applicable credentials using [Status list][sl] or [Linked Validity Verifiable Credentials][lvvc] (LVVC)
//! - Hold credentials and create signed presentations to share with verifiers; selectively disclose attributes (with JSON-LD BBS+)
//! - Verify presentations of credentials using [OpenID4VP][vp] remotely or in-proximity over [Bluetooth Low Energy][ble] (BLE)
//!
//! ## Design
//!
//! The library consists of two crates: the **Core** and the **Providers**.
//!
//! ### Core
//!
//! Provides a [signature service][ss] for signing and verifying credentals. Additional
//! services are planned for the future.
//!
//! ### Providers
//!
//! Includes all traits and implementations needed for integrating SSI
//! functionality into projects. Traits are separated into modules for
//! standalone functionality.
//!
//! [akv]: https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts
//! [bbs]: https://w3c.github.io/vc-di-bbs/
//! [ble]: https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html
//! [di]: https://w3c-ccg.github.io/did-primer/
//! [dil]: https://csrc.nist.gov/pubs/fips/204/ipd
//! [djw]: https://github.com/quartzjer/did-jwk/blob/main/spec.md
//! [dk]: https://w3c-ccg.github.io/did-method-key/
//! [dw]: https://w3c-ccg.github.io/did-method-web/
//! [ecd]: https://www.rfc-editor.org/rfc/rfc7518#section-3.4
//! [edd]: https://www.w3.org/TR/vc-di-eddsa/
//! [jld]: https://www.w3.org/TR/json-ld11/
//! [jw]: https://www.w3.org/TR/2023/WD-vc-jwt-20230427/
//! [lvvc]: https://eprint.iacr.org/2022/1658.pdf
//! [sl]: https://w3c.github.io/vc-bitstring-status-list/
//! [ss]: ..//one_open_core/service/signature_service/struct.SignatureService.html
//! [vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html
//! [vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

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
