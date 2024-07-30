[![Procivis](docs/assets/Procivis_logo_on_white.svg#gh-light-mode-only)](https://www.procivis.ch)
[![Procivis](docs/assets/Procivis_logo_on_black.svg#gh-dark-mode-only)](https://www.procivis.ch)

The Procivis One Open Core is a high-performance Rust library for decentralized
digital identities and credentials.

Use it to issue, hold and verify digital identities and credentials on almost any device.

## Project affiliation

The Procivis One Open Core was developed with funding from the U.S. Department of
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
- Generate new key pairs, create and verify signatures
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

## Background

Decentralized digital identities and credentials is an approach to identity that relocates
digital credentials from the possession and control of centralized authorities to the digital
wallet of the credentials holder. This eliminates the need for verifiers to "phone home" to
issuers to verify credentials, keeping the wallet holder's interactions private between only
those parties directly involved in each interaction.

## Getting started

### Prerequisites

A stable version of Rust ≥ 1.75 is recommended.

### Install

```rust
cargo install --git https://github.com/procivis/one-open-core
```

## Usage

The library consists of two crates: the **Core** and the **Providers**.

### Core

The **Core** provides developer APIs for simple and easy-to-use functionalities
of the library and its supported technologies, without extension. Most developers
will use the Core as it provides the simplest access to all library functions with
the least amount of effort.

Use the provided services to get started. Additional services will be added.

### Providers

For extending the library, the **Providers** include traits and implementations
separated into logical modules. Additional functionalities (e.g. the addition of
a new key algorithm, or a new DID method) can be extended via the providers.

## Documentation

See the [library documentation](https://docs.procivis-one.com/) for details on the
**One Open Core**. The library documentation provides descriptions of crates, modules,
and traits.

See the [Procivis One documentation](https://docs.procivis.ch/) for:

- The complete list of **Procivis One** supported technologies
- Trial access to the full solution
- APIs and SDK documentation
- Conceptual topics

## Examples

Several examples of using the **Core** are provided in the **/examples** directory of
the repository. More examples will be added in the future. Examples include:

- `examples/signature_example`: Signing and verifying via the signature service
- `examples/did_resolution_example`: Resolving DIDs via the DID service or using the implementations directly

## License

Some rights reserved. This library is published under the  [Apache License
Version 2.0](./LICENSE).

© Procivis AG, https://www.procivis.ch.
