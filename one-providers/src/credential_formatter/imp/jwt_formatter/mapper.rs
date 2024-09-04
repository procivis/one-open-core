use super::model::{Issuer, VCContent, VC, VP};
use crate::{
    common_models::did::DidValue,
    credential_formatter::{
        error::FormatterError,
        imp::{common::nest_claims, jwt::Jwt},
        model::{
            Context, CredentialData, CredentialSchema, CredentialSchemaData, CredentialSubject,
            DetailCredential, Presentation,
        },
    },
};

impl From<CredentialSchemaData> for Option<CredentialSchema> {
    fn from(credential_schema: CredentialSchemaData) -> Self {
        match credential_schema {
            CredentialSchemaData {
                id: Some(id),
                r#type: Some(r#type),
                metadata,
                ..
            } => Some(CredentialSchema::new(id, r#type, metadata)),
            _ => None,
        }
    }
}

pub(super) fn format_vc(
    credential: CredentialData,
    issuer: String,
    additional_context: Vec<String>,
    additional_types: Vec<String>,
    embed_layout_properties: bool,
) -> Result<VC, FormatterError> {
    let context = vec![Context::CredentialsV2.to_string()]
        .into_iter()
        .chain(additional_context)
        .collect();

    let types = vec!["VerifiableCredential".to_owned()]
        .into_iter()
        .chain(additional_types)
        .collect();

    // Strip layout (whole metadata as it only contains layout)
    let mut credential_schema: Option<CredentialSchema> = credential.schema.into();
    if let Some(schema) = &mut credential_schema {
        if !embed_layout_properties {
            schema.metadata = None;
        }
    }

    Ok(VC {
        vc: VCContent {
            context,
            r#type: types,
            id: credential.id,
            issuer: Some(Issuer::Url(issuer)),
            credential_subject: CredentialSubject {
                values: nest_claims(credential.claims)?,
            },
            credential_status: credential.status,
            credential_schema,
            valid_from: None,
            valid_until: None,
        },
    })
}

impl From<Jwt<VC>> for DetailCredential {
    fn from(jwt: Jwt<VC>) -> Self {
        DetailCredential {
            id: jwt.payload.jwt_id,
            valid_from: jwt.payload.issued_at,
            valid_until: jwt.payload.expires_at,
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

impl From<Jwt<VP>> for Presentation {
    fn from(jwt: Jwt<VP>) -> Self {
        Presentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer_did: jwt.payload.issuer.map(DidValue::from),
            nonce: jwt.payload.nonce,
            credentials: jwt.payload.custom.vp.verifiable_credential,
        }
    }
}
