![Procivis](docs/assets/Open_One_Core_light.png#gh-light-mode-only)
![Procivis](docs/assets/Open_One_Core_dark.png#gh-dark-mode-only)

# Procivis One Core

The [Procivis](https://www.procivis.ch) One Core is a high-performance Rust library for decentralized
digital identities and credentials. Use it to issue, hold and verify digital
identities and credentials on almost any device.

## Table of contents

* [Background](#background)
* [Project affiliation](#project-affiliation)
* [Features](#features)
* [Supported technologies](#supported-technologies)
* [Repository structure](#repository-structure)
* [Getting started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Install](#install)
* [Usage](#usage)
  * [Core](#core)
    * [Examples](#examples)
  * [Providers](#providers)
* [Documentation](#documentation)
* [License](#license)

## Background

Decentralized digital identities and credentials is an approach to identity that relocates
digital credentials from the possession and control of centralized authorities to the digital
wallet of the credentials holder. This eliminates the need for verifiers to "phone home" to
issuers to verify credentials, keeping the wallet holder's interactions private between only
those parties directly involved in each interaction.

## Project affiliation

The Procivis One Core was developed with funding from the U.S. Department of
Homeland Security's (DHS) Silicon Valley Innovation Program (SVIP). The Core consists
of two open-source libraries (OSL) for Issuers, Digital Wallets, and Verifiers:

- OSL (A): Cryptographic Tools SDK
  - Credential format provider
  - Signature provider
  - Key storage provider
  - Revocation provider
  - Exchange protocol provider
- OSL (C): Metadata Management SDK
  - DID method provider

These libraries are combined here for simplicity of use.

## Features

- Issue, hold and verify digital credentials in different formats
- Generate new key pairs with different algorithms, create and verify signatures
- Perform operations of multiple DID methods
- Store keys in Azure Key Vault or an encrypted internal database
- Issue credentials with different revocation methods; discover the status of credentials
- Seamless operation from end-to-end regardless of which technologies are employed
- Install and operate almost anywhere

## Supported technologies

Additional information and documentation about the supported technologies and methods can be found in our general [Procivis One documentation](https://docs.procivis.ch/).

| Credential formats | Revocation methods | DID methods                | Exchange protocols                       | Key signing algorithms                      | Key storage                 |
| ------------------ | ------------------ | -------------------------- | ---------------------------------------- | ------------------------------------------- | --------------------------- |
| [JSON-LD][jld]     | [LVVC][lvvc]       | [did:web][dw]              | [OpenID4VCI (draft 12)][vci]             | [ECDSA][ecd]                                | [Azure Key Vault][akv]      |
| [JWT][jw]          | [Status list][sl]  | [did:key][dk]              | [OpenID4VCP (draft 20)][vp]              | [EdDSA][edd]                                | Internal encrypted database |
|                    |                    | [did:jwk][djw]             |                                          | [BBS+][bbs]                                 |                             |
|                    |                    | [+ Universal DID resolver] |                                          | [Dilithium 3 (FIPS 204: post-quantum)][dil] |                             |

[akv]: https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts
[bbs]: https://w3c.github.io/vc-di-bbs/
[dil]: https://csrc.nist.gov/pubs/fips/204/ipd
[djw]: https://github.com/quartzjer/did-jwk/blob/main/spec.md
[dk]: https://w3c-ccg.github.io/did-method-key/
[dw]: https://w3c-ccg.github.io/did-method-web/
[ecd]: https://www.rfc-editor.org/rfc/rfc7518#section-3.4
[edd]: https://www.w3.org/TR/vc-di-eddsa/
[jld]: https://www.w3.org/TR/json-ld11/
[jw]: https://www.w3.org/TR/2023/WD-vc-jwt-20230427/
[lvvc]: https://eprint.iacr.org/2022/1658.pdf
[sl]: https://w3c.github.io/vc-bitstring-status-list/
[vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html
[vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

The **Procivis One Core** allows the mixing and matching of different technologies (where
technically possible) and handles the complexity so that issuance and verification
flows remain simple.

## Repository structure

The library consists of two crates:

- **Core**: Developer APIs for orchestrating the providers.
- **Providers**: Implementations of the complete range of functionality. Most projects
will use the providers, even if they take advantage of the services of the Core.

## Getting started

### Prerequisites

A stable version of Rust ≥ 1.75 is recommended.

### Install

```rust
cargo install --git https://github.com/procivis/one-open-core
```

## Usage

### Core

The **Core** provides developer APIs for simple and easy-to-use functionalities
of the library and its supported technologies, without extension. As an orchestration
layer, it provides the simplest access to related functions with the least amount of
effort. Services currently available:

- [Signature service](https://docs.procivis-one.com//one_open_core/service/signature_service/struct.SignatureService.html)
- [DID resolver service](https://docs.procivis-one.com///one_open_core/service/did_service/struct.DidService.html)

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

- `examples/signature_example`: Signing and verifying via the signature service
- `examples/did_resolution_example`: Resolving DIDs via the DID service or using the implementations directly

The services return provider implementations, covered next.

### Providers

The **Providers** contain the actual implementations of technologies.

- Credential format provider: implements credential formats, including seralizing and parsing of credentials
- DID method provider: implements DID operations such as creating, resolving, and (where applicable) updating
- Key algorithm provider: implements cryptographic key pair generation and key representations
- Key storage provider: implements storage of cryptographic keys and the creation of digital signatures
- Revocation provider: implements revocation methods, including revoking and suspending credentials for the issuer and
checking the revocation/suspension status for holders and verifiers

The library can be extended (e.g. with a new DID method or key signing algorithm) by adding
additional implementations in the relevant provider.

Each provider is structured in a similar pattern, each containing some subset of:

- `imp`: Implements the functionality. Within this directory, each technology (e.g. each credential format,
each key algorithm, each DID method) is implemented within its own directory.
- `error`: Enumerates errors of the provider.
- `mod`: Provides the traits used in the implementation.
- `model`: `struct`s and `enum`s of the provider.
- `provider`: The provider implementation.

Some providers may include additional elements of implementation.

There are additional modules in the **Providers** crate containing, for example, shared
resources such as DTOs as well as utilities such as bitstring list handling and key verification
of DIDs.

## Documentation

See the [library documentation](https://docs.procivis-one.com/) for details on
this repository. The library documentation provides further descriptions of crates,
modules, and traits.

See the [Procivis One documentation](https://docs.procivis.ch/) for:

- The complete list of **Procivis One** supported technologies
- Trial access to the full solution
- APIs and SDK documentation
- Conceptual topics

## License

Some rights reserved. This library is published under the  [Apache License
Version 2.0](./LICENSE).

![Procivis AG](docs/assets/logo_light_Procivis@2x.png#gh-light-mode-only)
![Procivis AG](docs/assets/logo_dark_Procivis@2x.png#gh-dark-mode-only)

© Procivis AG, https://www.procivis.ch.
