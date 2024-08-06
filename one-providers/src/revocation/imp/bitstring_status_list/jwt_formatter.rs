use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    common_models::did::{DidValue, OpenDid},
    credential_formatter::{
        error::FormatterError,
        imp::jwt::{model::JWTPayload, Jwt},
        model::{AuthenticationFn, Context, VerificationFn},
    },
    revocation::imp::bitstring_status_list::model::{
        ContentType, CredentialSubject, StatusPurpose, SubjectType, VCContent, VC,
    },
};

pub struct BitstringStatusListJwtFormatter {}

impl BitstringStatusListJwtFormatter {
    pub async fn format_status_list(
        revocation_list_url: String,
        issuer_did: &OpenDid,
        encoded_list: String,
        algorithm: String,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
    ) -> Result<String, FormatterError> {
        let subject = format!("{}#list", revocation_list_url);
        let vc = VC {
            vc: VCContent {
                context: vec![Context::CredentialsV1, Context::BitstringStatusList],
                id: revocation_list_url.to_owned(),
                r#type: vec![
                    ContentType::VerifiableCredential,
                    ContentType::BitstringStatusListCredential,
                ],
                issuer: issuer_did.did.to_owned(),
                issued: OffsetDateTime::now_utc(),
                credential_subject: CredentialSubject {
                    id: subject.to_owned(),
                    r#type: SubjectType::BitstringStatusList,
                    status_purpose,
                    encoded_list,
                },
            },
        };

        let payload = JWTPayload {
            issuer: Some(issuer_did.did.to_string()),
            jwt_id: Some(revocation_list_url),
            subject: Some(subject),
            custom: vc,
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            nonce: None,
        };

        let jwt = Jwt::new("JWT".to_owned(), algorithm, None, payload);

        jwt.tokenize(auth_fn).await
    }

    pub async fn parse_status_list(
        status_list_token: &str,
        issuer_did: &DidValue,
        verification: VerificationFn,
    ) -> Result<String, FormatterError> {
        let jwt: Jwt<VC> = Jwt::build_from_token(status_list_token, Some(verification)).await?;

        let payload = jwt.payload;
        if !payload
            .issuer
            .is_some_and(|issuer| issuer == issuer_did.as_str())
        {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid issuer".to_string(),
            ));
        }

        if issuer_did != &payload.custom.vc.issuer {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid issuer".to_string(),
            ));
        }

        Ok(payload.custom.vc.credential_subject.encoded_list)
    }
}

pub(super) fn into_timestamp<S>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month() as i32,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    formatted.serialize(s)
}

pub(super) fn from_timestamp<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    String::deserialize(deserializer).and_then(|string| {
        OffsetDateTime::parse(&string, &Rfc3339).map_err(|err| Error::custom(err.to_string()))
    })
}
