//! SD-JWT implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::sync::Arc;

use one_crypto::CryptoProvider;

use crate::common_models::did::DidValue;
use crate::credential_formatter::error::FormatterError;
use crate::credential_formatter::imp::jwt::model::DecomposedToken;
use crate::credential_formatter::imp::jwt::model::JWTPayload;
use crate::credential_formatter::imp::jwt::Jwt;
use crate::credential_formatter::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, CredentialSubject, DetailCredential,
    ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, Presentation,
    VerificationFn,
};
use crate::credential_formatter::CredentialFormatter;
use async_trait::async_trait;
use disclosures::extract_claims_from_disclosures;
use disclosures::extract_disclosures;
use disclosures::gather_disclosures;
use disclosures::get_disclosures_by_claim_name;
use disclosures::sort_published_claims_by_indices;
use disclosures::to_hashmap;
use itertools::Itertools;
use serde::Deserialize;
use time::Duration;

#[cfg(test)]
mod test;

mod mapper;
use self::mapper::*;

mod model;
use self::model::*;

mod disclosures;
mod verifier;

use self::verifier::*;

pub struct SDJWTFormatter {
    pub crypto: Arc<dyn CryptoProvider>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
}

#[async_trait]
impl CredentialFormatter for SDJWTFormatter {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        _json_ld_context_url: Option<String>,
        _custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        let issuer = credential.issuer_did.to_string();
        let id = credential.id.clone();
        let issued_at = credential.issuance_date;
        let expires_at = issued_at.checked_add(credential.valid_for);

        let (vc, disclosures) = self.format_hashed_credential(
            credential,
            "sha-256",
            additional_context,
            additional_types,
        )?;

        let payload = JWTPayload {
            issued_at: Some(issued_at),
            expires_at,
            invalid_before: issued_at.checked_sub(Duration::seconds(self.get_leeway() as i64)),
            subject: Some(holder_did.to_string()),
            issuer: Some(issuer),
            jwt_id: Some(id),
            custom: vc,
            nonce: None,
        };

        let key_id = auth_fn.get_key_id();
        let jwt = Jwt::new("SDJWT".to_owned(), algorithm.to_owned(), key_id, payload);

        let mut token = jwt.tokenize(auth_fn).await?;

        let disclosures_token = tokenize_claims(disclosures)?;

        token.push_str(&disclosures_token);

        Ok(token)
    }

    async fn extract_credentials(
        &self,
        token: &str,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(token, Some(verification))
            .await
    }

    async fn extract_credentials_unverified(
        &self,
        token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(token, None).await
    }

    async fn format_presentation(
        &self,
        _credentials: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        // for presentation the JWT formatter is used
        unreachable!()
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, Some(verification)).await?;

        Ok(jwt.into())
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        prepare_sd_presentation(credential, &*self.crypto)
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                "EDDSA".to_owned(),
                "ES256".to_owned(),
                "DILITHIUM".to_owned(),
            ],
            allowed_schema_ids: vec![],
            datatypes: vec![
                "STRING".to_string(),
                "BOOLEAN".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
                "PICTURE".to_string(),
                "OBJECT".to_string(),
                "ARRAY".to_string(),
            ],
            features: vec![
                "SELECTIVE_DISCLOSURE".to_string(),
                "SUPPORTS_CREDENTIAL_DESIGN".to_string(),
            ],
            selective_disclosure: vec!["ANY_LEVEL".to_string()],
            issuance_did_methods: vec![
                "KEY".to_string(),
                "WEB".to_string(),
                "JWK".to_string(),
                "X509".to_string(),
            ],
            issuance_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            proof_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            revocation_methods: vec![
                "NONE".to_string(),
                "BITSTRINGSTATUSLIST".to_string(),
                "LVVC".to_string(),
            ],
            verification_key_algorithms: vec![
                "EDDSA".to_string(),
                "ES256".to_string(),
                "DILITHIUM".to_string(),
            ],
            forbidden_claim_names: vec![],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, None).await?;

        Ok(jwt.into())
    }
}

impl SDJWTFormatter {
    pub fn new(params: Params, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self { params, crypto }
    }

    async fn extract_credentials_internal(
        &self,
        token: &str,
        verification: Option<VerificationFn>,
    ) -> Result<DetailCredential, FormatterError> {
        let model::DecomposedToken {
            deserialized_disclosures,
            jwt,
        } = extract_disclosures(token)?;

        let jwt: Jwt<Sdvc> = Jwt::build_from_token(jwt, verification).await?;

        let hasher = self
            .crypto
            .get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

        verify_claims(
            &jwt.payload.custom.vc.credential_subject.claims,
            &deserialized_disclosures,
            &*hasher,
        )?;

        let claims = extract_claims_from_disclosures(&deserialized_disclosures, &*hasher)?;

        Ok(DetailCredential {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            update_at: None,
            invalid_before: jwt.payload.invalid_before,
            issuer_did: jwt.payload.issuer.map(DidValue::from),
            subject: jwt.payload.subject.map(DidValue::from),
            claims: CredentialSubject {
                values: to_hashmap(unpack_arrays(&claims)?)?,
            },
            status: jwt.payload.custom.vc.credential_status,
            credential_schema: jwt.payload.custom.vc.credential_schema,
        })
    }

    fn format_hashed_credential(
        &self,
        credential: CredentialData,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
    ) -> Result<(Sdvc, Vec<String>), FormatterError> {
        let nested = nest_claims_to_json(&sort_published_claims_by_indices(&credential.claims))?;
        let (disclosures, sd_section) = gather_disclosures(&nested, algorithm, &*self.crypto)?;

        let vc = vc_from_credential(
            credential,
            &sd_section,
            additional_context,
            additional_types,
            algorithm,
        );

        Ok((vc, disclosures))
    }
}

fn prepare_sd_presentation(
    presentation: CredentialPresentation,
    crypto: &dyn CryptoProvider,
) -> Result<String, FormatterError> {
    let model::DecomposedToken {
        jwt,
        deserialized_disclosures,
    } = extract_disclosures(&presentation.token)?;

    let decomposed_jwt: DecomposedToken<Sdvc> = Jwt::decompose_token(jwt)?;
    let algorithm = decomposed_jwt
        .payload
        .custom
        .hash_alg
        .unwrap_or("sha-256".to_string());
    let hasher = crypto
        .get_hasher(&algorithm)
        .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;

    let disclosures = presentation
        .disclosed_keys
        .iter()
        .map(|key| get_disclosures_by_claim_name(key, &deserialized_disclosures, &*hasher))
        .collect::<Result<Vec<Vec<Disclosure>>, FormatterError>>()?
        .into_iter()
        .flatten()
        .map(|disclosure| disclosure.base64_encoded_disclosure)
        .unique()
        .collect::<Vec<String>>();

    let mut token = jwt.to_owned();
    for disclosure in disclosures {
        token.push('~');
        token.push_str(&disclosure);
    }

    Ok(token)
}
