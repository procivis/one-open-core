![Procivis](.docs/assets/Procivis_logo_on_white.svg#gh-light-mode-only)

![Procivis](.docs/assets/Procivis_logo_on_black.svg#gh-dark-mode-only)

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

| Credential formats | Revocation methods | DID methods                | Exchange protocols                       | Key signing algorithms               | Key storage       |
| ------------------ | ------------------ | -------------------------- | ---------------------------------------- | ------------------------------------ | ----------------- |
| JSON-LD            | LVVC               | did:web                    | OpenID4VCI (draft 12)                    | ECDSA                                | Azure Key Vault   |
| JWT                | Status list        | did:key                    | OpenID4VCP (draft 20)                    | EdDSA                                | Internal database |
|                    |                    | did:jwk                    | OpenID4VP over BLE (in-person exchanges) | BBS+                                 |                   |
|                    |                    | [+ Universal DID resolver] |                                          | Dilithium 3 (FIPS 204: post-quantum) |                   |

The Procivis One Core allows the mixing and matching of different technologies (where 
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


## License

[Apache License Version 2.0](./LICENSE)