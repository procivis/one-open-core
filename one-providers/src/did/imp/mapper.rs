use crate::{
    common_dto::{
        PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO, PublicKeyJwkMlweDataDTO,
        PublicKeyJwkOctDataDTO, PublicKeyJwkRsaDataDTO,
    },
    common_models::{
        OpenPublicKeyJwk, OpenPublicKeyJwkEllipticData, OpenPublicKeyJwkMlweData,
        OpenPublicKeyJwkOctData, OpenPublicKeyJwkRsaData,
    },
    did::{
        imp::dto::{DidDocumentDTO, DidVerificationMethodDTO},
        model::{DidDocument, DidVerificationMethod},
    },
};

impl From<PublicKeyJwkDTO> for OpenPublicKeyJwk {
    fn from(value: PublicKeyJwkDTO) -> Self {
        match value {
            PublicKeyJwkDTO::Ec(value) => OpenPublicKeyJwk::Ec(value.into()),
            PublicKeyJwkDTO::Rsa(value) => OpenPublicKeyJwk::Rsa(value.into()),
            PublicKeyJwkDTO::Okp(value) => OpenPublicKeyJwk::Okp(value.into()),
            PublicKeyJwkDTO::Oct(value) => OpenPublicKeyJwk::Oct(value.into()),
            PublicKeyJwkDTO::Mlwe(value) => OpenPublicKeyJwk::Mlwe(value.into()),
        }
    }
}

impl From<PublicKeyJwkEllipticDataDTO> for OpenPublicKeyJwkEllipticData {
    fn from(value: PublicKeyJwkEllipticDataDTO) -> Self {
        Self {
            r#use: value.r#use,
            crv: value.crv,
            x: value.x,
            y: value.y,
        }
    }
}

impl From<PublicKeyJwkRsaDataDTO> for OpenPublicKeyJwkRsaData {
    fn from(value: PublicKeyJwkRsaDataDTO) -> Self {
        Self {
            r#use: value.r#use,
            e: value.e,
            n: value.n,
        }
    }
}

impl From<PublicKeyJwkOctDataDTO> for OpenPublicKeyJwkOctData {
    fn from(value: PublicKeyJwkOctDataDTO) -> Self {
        Self {
            r#use: value.r#use,
            k: value.k,
        }
    }
}

impl From<PublicKeyJwkMlweDataDTO> for OpenPublicKeyJwkMlweData {
    fn from(value: PublicKeyJwkMlweDataDTO) -> Self {
        Self {
            r#use: value.r#use,
            alg: value.alg,
            x: value.x,
        }
    }
}

impl From<OpenPublicKeyJwk> for PublicKeyJwkDTO {
    fn from(value: OpenPublicKeyJwk) -> Self {
        match value {
            OpenPublicKeyJwk::Ec(value) => PublicKeyJwkDTO::Ec(value.into()),
            OpenPublicKeyJwk::Rsa(value) => PublicKeyJwkDTO::Rsa(value.into()),
            OpenPublicKeyJwk::Okp(value) => PublicKeyJwkDTO::Okp(value.into()),
            OpenPublicKeyJwk::Oct(value) => PublicKeyJwkDTO::Oct(value.into()),
            OpenPublicKeyJwk::Mlwe(value) => PublicKeyJwkDTO::Mlwe(value.into()),
        }
    }
}

impl From<OpenPublicKeyJwkEllipticData> for PublicKeyJwkEllipticDataDTO {
    fn from(value: OpenPublicKeyJwkEllipticData) -> Self {
        Self {
            r#use: value.r#use,
            crv: value.crv,
            x: value.x,
            y: value.y,
        }
    }
}

impl From<OpenPublicKeyJwkRsaData> for PublicKeyJwkRsaDataDTO {
    fn from(value: OpenPublicKeyJwkRsaData) -> Self {
        Self {
            r#use: value.r#use,
            e: value.e,
            n: value.n,
        }
    }
}

impl From<OpenPublicKeyJwkOctData> for PublicKeyJwkOctDataDTO {
    fn from(value: OpenPublicKeyJwkOctData) -> Self {
        Self {
            r#use: value.r#use,
            k: value.k,
        }
    }
}

impl From<OpenPublicKeyJwkMlweData> for PublicKeyJwkMlweDataDTO {
    fn from(value: OpenPublicKeyJwkMlweData) -> Self {
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

impl From<DidDocument> for DidDocumentDTO {
    fn from(value: DidDocument) -> Self {
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

impl From<DidVerificationMethod> for DidVerificationMethodDTO {
    fn from(value: DidVerificationMethod) -> Self {
        Self {
            id: value.id,
            r#type: value.r#type,
            controller: value.controller,
            public_key_jwk: value.public_key_jwk.into(),
        }
    }
}
