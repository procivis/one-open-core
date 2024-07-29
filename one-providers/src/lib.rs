//! Traits and implementations for integrating SSI functionality into projects.
//!
//! Where the [Core][cor] provides developer APIs for quick implementations
//! of supported functionalities through [services][serv], the providers contain
//! logically divided modules of traits to allow for the possibility of extending
//! functionality.
//!
//! Each provider is contained within a module below.
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
