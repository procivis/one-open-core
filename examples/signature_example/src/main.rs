use std::sync::Arc;

use hex_literal::hex;
use one_open_core::{model::KeyAlgorithmType, OneOpenCore};
use one_providers::http_client::imp::reqwest_client::ReqwestClient;
use zeroize::Zeroizing;

fn main() {
    let core = OneOpenCore::new(None, Arc::new(ReqwestClient::default())).unwrap();

    let key_pair = core
        .signature_service
        .get_key_pair(&KeyAlgorithmType::Es256)
        .expect("Key pair creation failed");

    let bytes = hex!("d14ccebdae5153c916d82168c1e2a9e39ab056cfd197c64242151773ce1c61f8");

    let signature = core
        .signature_service
        .sign(
            &KeyAlgorithmType::Es256,
            &key_pair.public,
            Zeroizing::new(key_pair.private),
            &bytes,
        )
        .expect("Signing failed");

    let verification = core.signature_service.verify(
        &KeyAlgorithmType::Es256,
        &key_pair.public,
        &signature,
        &bytes,
    );

    match verification {
        Ok(_) => println!("Successfully verified"),
        Err(_) => println!("Signature is incorrect"),
    };
}
