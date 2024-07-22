use std::collections::HashMap;

use convert_case::{Case, Casing};
use serde::Serialize;
use sophia_api::{quad::Spog, source::QuadSource, term::SimpleTerm};
use sophia_c14n::rdfc10;
use sophia_jsonld::{
    loader::NoLoader, loader_factory::DefaultLoaderFactory, JsonLdOptions, JsonLdParser,
};
use time::OffsetDateTime;

use self::model::{LdCredential, LdCredentialSubject, LdProof};
use super::common::nest_claims;
use crate::{
    common_models::did::DidValue,
    credential_formatter::{
        error::FormatterError,
        imp::json_ld::context::caching_loader::CachingLoader,
        model::{Context, CredentialData, PublishedClaim},
    },
};

pub mod context;
pub mod model;

#[cfg(test)]
mod test;
#[cfg(test)]
pub mod test_utilities;

type LdDataset = std::collections::HashSet<Spog<SimpleTerm<'static>>>;

pub fn prepare_credential(
    credential: CredentialData,
    holder_did: &DidValue,
    additional_context: Vec<String>,
    additional_types: Vec<String>,
    json_ld_context_url: Option<String>,
    custom_subject_name: Option<String>,
) -> Result<LdCredential, FormatterError> {
    let credential_schema = &credential.schema;

    let issuance_date = OffsetDateTime::now_utc();

    let mut context = prepare_context(additional_context);
    if let Some(json_ld_context_url) = json_ld_context_url {
        context.push(json_ld_context_url);
    }

    if let Some(credential_schema_context) = &credential_schema.context {
        context.push(credential_schema_context.to_owned());
    }

    let ld_type = prepare_credential_type(&credential_schema.name, additional_types);

    let credential_subject = prepare_credential_subject(
        &credential_schema.name,
        credential.claims,
        holder_did,
        custom_subject_name,
    )?;

    Ok(LdCredential {
        context,
        id: credential.id,
        r#type: ld_type,
        issuer: credential.issuer_did,
        issuance_date,
        credential_subject,
        credential_status: credential.status,
        proof: None,
        credential_schema: credential.schema.into(),
    })
}

pub fn get_crypto_suite(json_ld_str: &str) -> Option<String> {
    match serde_json::from_str::<LdCredential>(json_ld_str) {
        Ok(json_ld) => json_ld.proof.map(|proof| proof.cryptosuite),
        Err(_) => None,
    }
}

pub async fn prepare_proof_config(
    proof_purpose: &str,
    cryptosuite: &str,
    context: Vec<String>,
    key_id: String,
) -> Result<LdProof, FormatterError> {
    let r#type = "DataIntegrityProof".to_owned();

    Ok(LdProof {
        context,
        r#type,
        created: OffsetDateTime::now_utc(),
        cryptosuite: cryptosuite.to_owned(),
        verification_method: key_id,
        proof_purpose: proof_purpose.to_owned(),
        proof_value: None,
        nonce: None,
        challenge: None,
        domain: None,
    })
}

pub fn prepare_context(additional_context: Vec<String>) -> Vec<String> {
    let mut context = vec![
        Context::CredentialsV1.to_string(),
        Context::DataIntegrityV2.to_string(),
    ];

    context.extend(additional_context);
    context
}

pub fn prepare_credential_type(
    credential_schema_name: &str,
    additional_types: Vec<String>,
) -> Vec<String> {
    let credential_schema_name = credential_schema_name.to_case(Case::Pascal);

    let mut types = vec![
        "VerifiableCredential".to_string(),
        format!("{}Subject", credential_schema_name),
    ];

    types.extend(additional_types);

    types
}

pub fn prepare_credential_subject(
    credential_schema_name: &str,
    claims: Vec<PublishedClaim>,
    holder_did: &DidValue,
    custom_subject_name: Option<String>,
) -> Result<LdCredentialSubject, FormatterError> {
    let credential_schema_name = credential_schema_name.to_case(Case::Pascal);

    let subject_name_base = custom_subject_name.unwrap_or(credential_schema_name);

    Ok(LdCredentialSubject {
        id: holder_did.clone(),
        subject: HashMap::from([(
            format!("{subject_name_base}Subject"),
            serde_json::to_value(nest_claims(claims)?)
                .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?,
        )]),
    })
}

pub async fn canonize_any<T>(
    json_ld: &T,
    caching_loader: CachingLoader,
) -> Result<String, FormatterError>
where
    T: Serialize,
{
    let content_str = serde_json::to_string(&json_ld)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

    let options = JsonLdOptions::<DefaultLoaderFactory<NoLoader>>::default()
        .with_document_loader(caching_loader);

    let parser = JsonLdParser::new_with_options(options);

    // This will actually fetch context
    let parsed = parser.async_parse_str(&content_str).await;

    let dataset: LdDataset = parsed
        .collect_quads()
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

    canonize_dataset(dataset).await
}

pub async fn canonize_dataset(dataset: LdDataset) -> Result<String, FormatterError> {
    let mut buf = Vec::<u8>::new();
    rdfc10::normalize(&dataset, &mut buf)
        .map_err(|e| FormatterError::CouldNotFormat(format!("Normalization error: `{}`", e)))?;

    let str = String::from_utf8_lossy(buf.as_slice());

    Ok(str.into_owned())
}

pub fn jsonld_forbidden_claim_names() -> Vec<String> {
    vec![
        "id".to_string(),
        "type".to_string(),
        "cred".to_string(),
        "sec".to_string(),
        "xsd".to_string(),
        "credentialSchema".to_string(),
        "credentialStatus".to_string(),
        "credentialSubject".to_string(),
        "evidence".to_string(),
        "expirationDate".to_string(),
        "holder".to_string(),
        "issued".to_string(),
        "issuer".to_string(),
        "issuanceDate".to_string(),
        "proof".to_string(),
        "refreshService".to_string(),
        "termsOfUse".to_string(),
        "validFrom".to_string(),
        "validUntil".to_string(),
    ]
}
