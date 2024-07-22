use super::model::{VCContent, VC};
use crate::{
    common_models::did::DidValue,
    credential_formatter::{
        error::FormatterError,
        imp::{common::nest_claims, jwt::Jwt},
        model::{
            Context, CredentialData, CredentialSchema, CredentialSchemaData, CredentialSubject,
            DetailCredential,
        },
    },
};

impl From<CredentialSchemaData> for Option<CredentialSchema> {
    fn from(credential_schema: CredentialSchemaData) -> Self {
        match credential_schema {
            CredentialSchemaData {
                id: Some(id),
                r#type: Some(r#type),
                ..
            } => Some(CredentialSchema::new(id, r#type)),
            _ => None,
        }
    }
}

pub(super) fn format_vc(
    credential: CredentialData,
    additional_context: Vec<String>,
    additional_types: Vec<String>,
) -> Result<VC, FormatterError> {
    let context = vec![Context::CredentialsV1.to_string()]
        .into_iter()
        .chain(additional_context)
        .collect();

    let types = vec!["VerifiableCredential".to_owned()]
        .into_iter()
        .chain(additional_types)
        .collect();

    Ok(VC {
        vc: VCContent {
            context,
            r#type: types,
            id: Some(credential.id),
            credential_subject: CredentialSubject {
                values: nest_claims(credential.claims)?,
            },
            credential_status: credential.status,
            credential_schema: credential.schema.into(),
        },
    })
}

impl From<Jwt<VC>> for DetailCredential {
    fn from(jwt: Jwt<VC>) -> Self {
        DetailCredential {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            update_at: None,
            invalid_before: jwt.payload.invalid_before,
            issuer_did: jwt.payload.issuer.map(DidValue::from),
            subject: jwt.payload.subject.map(DidValue::from),
            claims: jwt.payload.custom.vc.credential_subject,
            status: jwt.payload.custom.vc.credential_status,
            credential_schema: jwt.payload.custom.vc.credential_schema,
        }
    }
}
