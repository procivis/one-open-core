![Procivis](docs/assets/logo_light_mode_Open_One_Core.svg#gh-light-mode-only)
![Procivis](docs/assets/logo_dark_mode_Open_One_Core.svg#gh-dark-mode-only)

The Procivis One Open Core library is a subset of our [Procivis One Core](https://docs.procivis.ch/)
including specific services and protocols.

## Table of contents

* [Background](#background)
* [Project affiliation](#project-affiliation)
* [Features](#description-of-the-providers)
* [Getting started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Install](#install)
* [Usage](#usage)
  * [Repository structure](#repository-structure)
  * [Providers](#providers-and-crypto)
  * [Core](#core)
    * [Examples](#examples)
* [Documentation](#documentation)
* [Acknowledgement](#acknowledgement)
* [License](#license)

## Background

Decentralized digital identities and credentials is an approach to identity that relocates
digital credentials from the possession and control of centralized authorities to the digital
wallet of the credentials holder. This architecture eliminates the need for the user to "phone
home" to use their credentials as well as the verifier to communicate to the issuer via
back-channels, keeping the wallet holder's interactions private between only
those parties directly involved in each interaction.

## Project affiliation

The Procivis One Open Core was developed with funding from the U.S. Department of
Homeland Security's (DHS) Silicon Valley Innovation Program (SVIP) and provides
cryptographic and metadata management tools for issuers, holders, and verifiers:

* OSL (A): Cryptographic Tools SDK for Issuers, Digital Wallets, and Verifiers
  * [Credential formatter provider](#credential-formatter-provider)
  * [Crypto provider](#crypto-provider)
  * [Key algorithm provider](#key-algorithm-provider)
* OSL (B): Sealed Storage SDK for Issuers, Digital Wallets, and Verifiers
  * [Key storage provider](#key-storage-provider)
* OSL (C): Metadata Management SDK for Issuers, Digital Wallets, and Verifiers
  * [Revocation provider](#revocation-provider)
  * [DID method provider](#did-method-provider)
* Additional modules
  * [Exchange protocol provider](#exchange-protocol-provider)

See the section on [repository structure](#repository-structure) for a description of
how these functions are divided and the different ways in which this library can be used.

## Description of the providers

### Credential formatter provider

Format and parse digital credentials according to [W3C Verifiable Credentials Data Model v2.0][vcdm],
for issuing, presenting, and verifying.

The following proofs are supported:

| Securing mechanism                           | Supported representations                           | Supported proof/signature types                                                          |
| -------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------ |
| [W3C Data Integrity Proofs][vcdi] (embedded) | [JSON-LD][jld] in Compacted Document Form | <ul><li>[W3C Data Integrity ECDSA Cryptosuites v1.0][ecd] / [ecdsa-rdfc-2019][ecd2019]</li><li>[W3C Data Integrity EdDSA Cryptosuites v1.0][edd] / [eddsa-rdfc-2022][edd2022]</li><li>[W3C Data Integrity BBS Cryptosuites v1.0][bbs] / [bbs-2023][bbs2023]</li></ul> |
| [W3C VC-JOSE-COSE][jose] (enveloping)        | <ul><li>[SD-JWT][sdjwt]</li><li>[JWT][jw]</li></ul> | <ul><li>JOSE / ECDSA [ES256][es2]</li><li>JOSE / EdDSA [Ed25519][ed255]</li><li>JOSE / CRYSTALS-DILITHIUM 3 [CRYDI3][crydi3]* |

\* CRYSTALS-DILITHIUM is a post-quantum resistant signature scheme, selected by NIST for [Post-Quantum Cryptography Standardization][pqc].
Support for the recently published [FIPS-204][fips] is planned for the near future.

When provided with the necessary ingredients (e.g. public keys, authentication function
for signing, cryptographic operations for calculating hash comparisons, etc.), this
module can sign and verify proofs. These ingredients can be delivered by the other
providers, or they can be provided independently.

Additionally, the provider can be used for other data models. For the technologies supported
by the complete **Procivis One** solution, see our [docs][supptech].

### Crypto provider

* Sign and verify raw bytes, including necessary hashing, using the curves listed above

### Key algorithm provider

* Generate cryptographic key pairs for use with the following algorithms
  * EdDSA
  * ECDSA
  * BBS+
  * ML-DSA
* Serialize keys, converting to and from different structures (multibase, jwk, bytes, DER)

### Key storage provider

Store and safely use keys via:

* [Azure Key Vault][akv] hardware security module (HSM)
* Internal encrypted database

### Revocation provider

Manage credential status with the following revocation methods:

* [W3C Bitstring Status List v1.0][sl]
* [Linked Validity Verifiable Credentials][lvvc]

For issuers: suspend, reactivate and revoke credentials.

For holders and verifiers: check the status of credentials.

### DID method provider

Uses [W3C Decentralized Identifiers (DIDs) v1.0][did]-based architecture and data model to manage identifiers

* Create DIDs and publish metadata
  * [did:web][dw]
  * [did:key][dk]
  * [did:jwk][djw]
* Resolve DIDs directly or with the supported [Universal DID resolver][univ]
  * Retrieve metadata, returning DID Documents and associated public keys
* Update DIDs (if supported by the method)

### Exchange protocol provider

Exchange credentials and presentations:

* Issue credentials using [OpenID4VCI (draft 12)][vci]
* Receive credentials and make verifiable presentations using OpenID4VC
* Verify credentials using [OpenID4VP (draft 20)][vp]

### Additional features

* **Selective disclosure**: holders control information using
  * JSON-LD credentials signed with BBS+
  * SD-JWT credentials
* **Caching for mobile devices**: In-memory caching for mobile devices with intermittent internet connectivity
  * DID documents for metadata retrieval (DID method provider)
  * Status lists for credentials issued with [W3C Bitstring Status List v1.0][sl] (Revocation method provider)
  * JSON-LD contexts for credential structures and calculation of proofs (Credential format provider)
* **Schemas**
  * Structure credentials for issuance with customizable credential schemas
  * Structure verification requests with customizable credential and proof schemas
* **Interoperability**
  * We actively support standards-based interoperability
  * We are participating in interop testing soon, and will update
  this section as results come in

[akv]: https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts
[bbs]: https://www.w3.org/TR/vc-di-bbs/
[bbs2023]: https://www.w3.org/TR/vc-di-bbs/#bbs-2023
[cmvp]: https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program
[crydi3]: https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-01
[did]: https://www.w3.org/TR/did-core/
[djw]: https://github.com/quartzjer/did-jwk/blob/main/spec.md
[dk]: https://w3c-ccg.github.io/did-method-key/
[dw]: https://w3c-ccg.github.io/did-method-web/
[ecd]: https://www.w3.org/TR/vc-di-ecdsa/
[ecd2019]: https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019
[edd]: https://www.w3.org/TR/vc-di-eddsa/
[edd2022]: https://www.w3.org/TR/vc-di-eddsa/#eddsa-rdfc-2022
[ed255]: https://datatracker.ietf.org/doc/html/rfc8037
[es2]: https://datatracker.ietf.org/doc/html/rfc7518
[fips]: https://csrc.nist.gov/pubs/fips/204/final
[jld]: https://www.w3.org/TR/json-ld11/
[jose]: https://w3c.github.io/vc-jose-cose/
[jw]: https://datatracker.ietf.org/doc/html/rfc7519
[lvvc]: https://eprint.iacr.org/2022/1658.pdf
[pqc]: https://csrc.nist.gov/pqc-standardization
[sdjwt]: https://www.ietf.org/archive/id/draft-terbu-oauth-sd-jwt-vc-00.html
[sl]: https://www.w3.org/TR/vc-bitstring-status-list/
[supptech]: https://docs.procivis.ch/product/supported_tech
[univ]: https://dev.uniresolver.io
[vcdi]: https://www.w3.org/TR/vc-data-integrity/
[vcdm]: https://www.w3.org/TR/vc-data-model-2.0/
[vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html
[vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

## Getting started

### Prerequisites

A stable version of Rust ≥ 1.75 is recommended.

### Install

```rust
cargo install --git https://github.com/procivis/one-open-core
```

## Usage

### Repository structure

The library consists of three crates:

* **Providers**
  * Credential formatter provider
  * Key algorithm provider
  * Key storage provider
  * Revocation provider
  * DID method provider
  * Exchange protocol provider
* **Crypto**: This provider is delimited in its own directory to enable future certification
of the cryptographic components of this library, e.g. in the [NIST Cryptographic Module Validation Program (CMVP)][cmvp].
  * Crypto provider
* **Core**
  * Services

The **Providers** (including Crypto provider) are modular implementations of the complete
range of functionality. Developers can use providers — or implementations of individual
technologies from within a provider — for modular functionality.

The **Core** is a service layer that offers developer APIs for orchestrating the whole
suite of providers for simplified workflows in issuing, holding, or verifying. Services
return provider implementations.

### Providers and Crypto

The **Providers** and **Crypto** crates contain the actual implementations of technologies,
in a modular format. Implementations or providers can be used modularly. The library can be
extended (e.g. with a new DID method or key signing algorithm) by adding additional
implementations in the relevant provider.

See the [docs](https://docs.procivis-one.com/) for details on each provider and
related implementations.

See the [examples](#examples) for a few iterations of using the providers.

#### Provider structure

Each provider is structured in a similar pattern, each containing some subset of:

* `imp`: Implements the functionality. Within this directory, each technology (e.g. each credential format,
each key algorithm, each DID method) is implemented within its own directory.
* `error`: Enumerates errors of the provider.
* `mod`: Provides the traits used in the implementation.
* `model`: `struct`s and `enum`s of the provider.
* `provider`: The provider implementation.

Some providers may include additional elements of implementation.

There are additional modules in the **Providers** crate containing, for example, shared
resources such as DTOs as well as utilities such as bitstring list handling and key verification
of DIDs.

### Core

The **Core** provides developer APIs for simple and easy-to-use functionalities
of the library and its supported technologies. As an orchestration layer, it
provides the simplest access to related functions with the least amount of
effort. Services currently available:

* [Credential service](https://docs.procivis-one.com//one_open_core/service/credential_service/struct.CredentialService.html)
* [Signature service](https://docs.procivis-one.com//one_open_core/service/signature_service/struct.SignatureService.html)
* [DID resolver service](https://docs.procivis-one.com///one_open_core/service/did_service/struct.DidService.html)

To get started, initialize the core:

```rust
/// `None` initializes the Core with the default configuration
let core = OneOpenCore::new(None).unwrap();
```

Then start using the services, e.g.:

```rust
let key_pair = core
    .signature_service
    .get_key_pair(&KeyAlgorithmType::Es256)
    .expect("Key pair creation failed");
```

#### Examples

Some examples of using the **Core** are provided in the **/examples** directory of the repository.
More examples will be added in the future. Examples include:

* [Signing for issuing, presenting and verifying](https://github.com/procivis/one-open-core/blob/main/examples/credential_example/src/main.rs): Signing
for issuance, signing for a presentation, and verifying a credential, via the credential service
* [Signing and verifying](https://github.com/procivis/one-open-core/blob/main/examples/signature_example/src/main.rs): Signing and verifying via the signature service
* [DID Resolution](https://github.com/procivis/one-open-core/blob/main/examples/did_resolution_example/src/main.rs): Resolving DIDs via the DID service or using the implementations directly

## Documentation

See the [library documentation](https://docs.procivis-one.com/) for details on
this repository. The library documentation provides further descriptions of crates,
modules, and traits.

See the [Procivis One documentation](https://docs.procivis.ch/) for:

* The complete list of **Procivis One** [supported technologies](https://docs.procivis.ch/product/supported_tech)
* [Trial access](https://docs.procivis.ch/trial/intro) to the full solution
* [APIs](https://docs.procivis.ch/guides/api/overview) and [SDK](https://docs.procivis.ch/sdk/overview) documentation
* Conceptual topics

## Acknowledgement

This work is funded in part by the U.S Department of Homeland Security Science and Technology
Directorate (DHS S&T) Silicon Valley Innovation Program (SVIP) under contract 70RSAT24T00000012.
Any opinions contained herein are those of the performer and do not necessarily reflect those of
DHS.

## License

Some rights reserved. This library is published under the [Apache License
Version 2.0](./LICENSE).

![Procivis AG](docs/assets/logo_light_mode_Procivis.svg#gh-light-mode-only)
![Procivis AG](docs/assets/logo_dark_mode_Procivis.svg#gh-dark-mode-only)

© Procivis AG, https://www.procivis.ch.
