//! The **Procivis One Open Core** is a library for issuing, holding and verifying
//! verifiable credentials.
//!
//! Self-sovereign identity (SSI) is a model of digital identity that enables individuals
//! to receive and hold their identity and credentials, controlling when and with whom
//! they share them, without requesting permission from a centralized authority or
//! identity provider.
//!
//! The library provides all SSI functionality needed to issue, hold and
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
//! - Verify presentations of credentials using [OpenID4VP][vp] remotely
//!
//! ## Usage
//!
//! The library consists of two crates:
//!
//! - **Core**: A few developer APIs for orchestrating the providers.
//! - **Providers**: Implementations of the complete range of functionality. Most projects will
//! use the providers, even if they take advantage of the services of the Core.
//!
//! ### Core
//!
//! The **Core** provides developer APIs for simple and easy-to-use functionalities
//! of the library and its supported technologies, without extension. As an orchestration
//! layer, it provides the simplest access to related functions with
//! the least amount of effort. Use the provided [services][serv] to get started.
//! Additional services will be added.
//!
//! - [Signature service][ss] for signing and verifying credentals.
//! - [DID resolver service][dresolv] for resolving DIDs.
//!
//! To get started, initialize the core:
//!
//! ```rust
//! /// `None` initializes the Core with the default configuration
//! let core = OneOpenCore::new(None).unwrap();
//! ```
//!
//! Then start using the services, e.g.:
//! ```rust
//! let key_pair = core
//!     .signature_service
//!     .get_key_pair(&KeyAlgorithmType::Es256)
//!     .expect("Key pair creation failed");
//! ```
//!
//! #### Examples
//!
//! Some examples of using the **Core** are provided in the **/examples** directory of
//! the [repository][repo]. More examples will be added in the future. Examples include:
//!
//! - `examples/signature_example`: Signing and verifying via the signature service
//! - `examples/did_resolution_example`: Resolving DIDs via the DID service or using the
//! implementations directly
//!
//! ### Providers
//!
//! The **Providers** contain the actual implementations of technologies. This includes all
//! elements of issuing, holding and verifying credentials.
//!
//! - Credential format provider: implements credential formats, including seralizing and parsing of credentials
//! - DID method provider: implements DID operations such as creating, resolving, and (where applicable) updating
//! - Key algorithm provider: implements cryptographic key pair generation and key representations
//! - Key storage provider: implements storage of cryptographic keys and the creation of digital signatures
//! - Revocation provider: implements revocation methods, including revoking and suspending credentials for the issuer and
//! checking the revocation/suspension status for holders and verifiers
//!
//! This is where all the functions to issue, hold and verify come from. These providers
//! are described further in the relevant [doc][prov]. The library can be extended
//! by adding new implementations in the relevant provider.
//!
//! ## Documentation
//!
//! This site provides descriptions of crates, modules, and traits for the providers.
//!
//! Additionally, higher-level documentation can be found at the root
//! [Procivis One documentation][docs] site. This includes:
//!
//! - The complete list of **Procivis One** supported technologies
//! - Trial access to the full solution
//! - APIs and SDK documentation
//! - Conceptual topics
//!
//! [akv]: https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts
//! [bbs]: https://w3c.github.io/vc-di-bbs/
//! [di]: https://w3c-ccg.github.io/did-primer/
//! [dil]: https://csrc.nist.gov/pubs/fips/204/ipd
//! [djw]: https://github.com/quartzjer/did-jwk/blob/main/spec.md
//! [dk]: https://w3c-ccg.github.io/did-method-key/
//! [docs]: https://docs.procivis.ch/
//! [dresolv]: ..//one_open_core/service/did_service/struct.DidService.html
//! [dw]: https://w3c-ccg.github.io/did-method-web/
//! [ecd]: https://www.rfc-editor.org/rfc/rfc7518#section-3.4
//! [edd]: https://www.w3.org/TR/vc-di-eddsa/
//! [jld]: https://www.w3.org/TR/json-ld11/
//! [jw]: https://www.w3.org/TR/2023/WD-vc-jwt-20230427/
//! [lvvc]: https://eprint.iacr.org/2022/1658.pdf
//! [prov]: ../one_providers/index.html
//! [repo]: https://github.com/procivis/one-open-core
//! [serv]: ..//one_open_core/service/index.html
//! [sl]: https://w3c.github.io/vc-bitstring-status-list/
//! [ss]: ..//one_open_core/service/signature_service/struct.SignatureService.html
//! [vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html
//! [vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

#![doc(html_favicon_url = "https://docs.procivis.ch/img/favicon.svg")]

use std::error::Error;
use std::{collections::HashMap, default::Default, sync::Arc};

use config::OneCoreConfig;
use model::KeyAlgorithmType;
use one_providers::{
    crypto::imp::{
        hasher::sha256::SHA256,
        signer::{bbs::BBSSigner, crydi3::CRYDI3Signer, eddsa::EDDSASigner, es256::ES256Signer},
        CryptoProviderImpl,
    },
    did::{
        imp::{
            jwk::JWKDidMethod,
            key::KeyDidMethod,
            provider::DidMethodProviderImpl,
            universal::{Params as UniversalDidMethodParams, UniversalDidMethod},
            web::{Params as WebDidMethodParams, WebDidMethod},
        },
        keys::{Keys, MinMax},
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
use service::{did_service::DidService, signature_service::SignatureService};

pub mod config;
pub mod model;
pub mod service;

pub struct OneOpenCore {
    pub signature_service: SignatureService,
    pub did_service: DidService,
}

impl Default for OneOpenCore {
    fn default() -> Self {
        Self::new(None).unwrap()
    }
}

impl OneOpenCore {
    pub fn new(config: Option<OneCoreConfig>) -> Result<Self, Box<dyn Error>> {
        let config = config.unwrap_or(OneCoreConfig {
            ..Default::default()
        });

        // initialize crypto provider
        let crypto_provider = Arc::new(CryptoProviderImpl::new(
            HashMap::from_iter(vec![("sha-256".to_string(), Arc::new(SHA256 {}) as _)]),
            HashMap::from_iter(vec![
                ("Ed25519".to_string(), Arc::new(EDDSASigner {}) as _),
                ("ES256".to_string(), Arc::new(ES256Signer {}) as _),
                ("CRYDI3".to_string(), Arc::new(CRYDI3Signer {}) as _),
                ("BBS".to_string(), Arc::new(BBSSigner {}) as _),
            ]),
        ));

        // initialize key algorithm provider
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
            crypto_provider.clone(),
        ));

        // initialize did method provider
        let universal_resolver = Arc::new(UniversalDidMethod::new(UniversalDidMethodParams {
            resolver_url: config.did_method_config.universal_resolver_url,
        }));
        let did_method_provider = Arc::new(DidMethodProviderImpl::new(HashMap::from_iter(vec![
            (
                "JWK".to_string(),
                Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as _,
            ),
            (
                "KEY".to_string(),
                Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())) as _,
            ),
            (
                "WEB".to_string(),
                Arc::new(WebDidMethod::new(
                    &None,
                    WebDidMethodParams {
                        resolve_to_insecure_http: Some(false),
                        keys: Keys {
                            global: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            assertion_method: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            authentication: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            capability_delegation: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            capability_invocation: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            key_agreement: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                        },
                    },
                )?) as _,
            ),
        ])));

        let signature_service = SignatureService::new(crypto_provider, key_algorithm_provider);

        let did_service = DidService::new(did_method_provider, Some(universal_resolver));

        Ok(Self {
            signature_service,
            did_service,
        })
    }
}
