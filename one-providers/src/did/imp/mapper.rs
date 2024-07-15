use crate::{
    common_models::{
        PublicKeyJwk, PublicKeyJwkEllipticData, PublicKeyJwkMlweData, PublicKeyJwkOctData,
        PublicKeyJwkRsaData,
    },
    did::{
        imp::dto::{
            DidDocumentDTO, DidVerificationMethodDTO, PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO,
            PublicKeyJwkMlweDataDTO, PublicKeyJwkOctDataDTO, PublicKeyJwkRsaDataDTO,
        },
        model::{DidDocument, DidVerificationMethod},
    },
};

impl From<PublicKeyJwkDTO> for PublicKeyJwk {
    fn from(value: PublicKeyJwkDTO) -> Self {
        match value {
            PublicKeyJwkDTO::Ec(value) => PublicKeyJwk::Ec(value.into()),
            PublicKeyJwkDTO::Rsa(value) => PublicKeyJwk::Rsa(value.into()),
            PublicKeyJwkDTO::Okp(value) => PublicKeyJwk::Okp(value.into()),
            PublicKeyJwkDTO::Oct(value) => PublicKeyJwk::Oct(value.into()),
            PublicKeyJwkDTO::Mlwe(value) => PublicKeyJwk::Mlwe(value.into()),
        }
    }
}

impl From<PublicKeyJwkEllipticDataDTO> for PublicKeyJwkEllipticData {
    fn from(value: PublicKeyJwkEllipticDataDTO) -> Self {
        Self {
            r#use: value.r#use,
            crv: value.crv,
            x: value.x,
            y: value.y,
        }
    }
}

impl From<PublicKeyJwkRsaDataDTO> for PublicKeyJwkRsaData {
    fn from(value: PublicKeyJwkRsaDataDTO) -> Self {
        Self {
            r#use: value.r#use,
            e: value.e,
            n: value.n,
        }
    }
}

impl From<PublicKeyJwkOctDataDTO> for PublicKeyJwkOctData {
    fn from(value: PublicKeyJwkOctDataDTO) -> Self {
        Self {
            r#use: value.r#use,
            k: value.k,
        }
    }
}

impl From<PublicKeyJwkMlweDataDTO> for PublicKeyJwkMlweData {
    fn from(value: PublicKeyJwkMlweDataDTO) -> Self {
        Self {
            r#use: value.r#use,
            alg: value.alg,
            x: value.x,
        }
    }
}

impl From<PublicKeyJwk> for PublicKeyJwkDTO {
    fn from(value: PublicKeyJwk) -> Self {
        match value {
            PublicKeyJwk::Ec(value) => PublicKeyJwkDTO::Ec(value.into()),
            PublicKeyJwk::Rsa(value) => PublicKeyJwkDTO::Rsa(value.into()),
            PublicKeyJwk::Okp(value) => PublicKeyJwkDTO::Okp(value.into()),
            PublicKeyJwk::Oct(value) => PublicKeyJwkDTO::Oct(value.into()),
            PublicKeyJwk::Mlwe(value) => PublicKeyJwkDTO::Mlwe(value.into()),
        }
    }
}

impl From<PublicKeyJwkEllipticData> for PublicKeyJwkEllipticDataDTO {
    fn from(value: PublicKeyJwkEllipticData) -> Self {
        Self {
            r#use: value.r#use,
            crv: value.crv,
            x: value.x,
            y: value.y,
        }
    }
}

impl From<PublicKeyJwkRsaData> for PublicKeyJwkRsaDataDTO {
    fn from(value: PublicKeyJwkRsaData) -> Self {
        Self {
            r#use: value.r#use,
            e: value.e,
            n: value.n,
        }
    }
}

impl From<PublicKeyJwkOctData> for PublicKeyJwkOctDataDTO {
    fn from(value: PublicKeyJwkOctData) -> Self {
        Self {
            r#use: value.r#use,
            k: value.k,
        }
    }
}

impl From<PublicKeyJwkMlweData> for PublicKeyJwkMlweDataDTO {
    fn from(value: PublicKeyJwkMlweData) -> Self {
        Self {
            r#use: value.r#use,
            alg: value.alg,
            x: value.x,
        }
    }
}

impl From<DidDocumentDTO> for DidDocument {
    fn from(value: DidDocumentDTO) -> Self {
        Self {
            context: value.context,
            id: value.id,
            verification_method: value
                .verification_method
                .into_iter()
                .map(|v| v.into())
                .collect(),
            authentication: value.authentication,
            assertion_method: value.assertion_method,
            key_agreement: value.key_agreement,
            capability_invocation: value.capability_invocation,
            capability_delegation: value.capability_delegation,
            rest: value.rest,
        }
    }
}

impl From<DidVerificationMethodDTO> for DidVerificationMethod {
    fn from(value: DidVerificationMethodDTO) -> Self {
        Self {
            id: value.id,
            r#type: value.r#type,
            controller: value.controller,
            public_key_jwk: value.public_key_jwk.into(),
        }
    }
}
