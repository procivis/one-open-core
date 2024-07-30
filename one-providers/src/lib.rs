//! Implementations of functionality and traits for interfaces.
//!
//! Where the [Core][cor] provides developer APIs for quick implementations
//! of supported functionalities through [services][serv], the providers
//! implement the actual functioning (i.e. generating key pairs, signing,
//! verifying, exchanging credentials, etc.).
//!
//! ## Provider structure
//!
//! Each provider is contained within a module below and structured in a
//! similar pattern, each containing some subset of:
//!
//! - `imp`: Implements the functionality. Within this directory, each
//! technology (e.g. each credential format, each key algorithm, each
//! DID method) is implemented within its own directory.
//! - `error`: Enumerates errors of the provider.
//! - `mod`: Provides the traits used in the implementation.
//! - `model`: `struct`s and `enum`s of the provider.
//! - `provider`: The provider implementation.
//!
//! Some providers may include additional elements of implementation.
//!
//! There are additional modules in the **Providers** crate containing,
//! for example, shared resources such as DTOs as well as utilities such
//! as bitstring list handling and key verification of DIDs.
//!
//! ## Extension
//!
//! The library can be extended by adding additional implementations in the
//! relevant provider.
//!
//! [cor]: ..//one_open_core/index.html
//! [serv]: ..//one_open_core/service/index.html

#![doc(html_favicon_url = "https://docs.procivis.ch/img/favicon.svg")]

pub mod common_dto;
pub mod common_models;
pub mod credential_formatter;
pub mod crypto;
pub mod did;
pub mod key_algorithm;
pub mod key_storage;
pub mod revocation;
pub mod util;

pub mod common_mappers;

pub mod exchange_protocol;
