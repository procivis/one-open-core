use crate::credential_formatter::{error::FormatterError, model::PublishedClaim};
use std::collections::HashMap;

pub fn nest_claims(
    claims: impl IntoIterator<Item = PublishedClaim>,
) -> Result<HashMap<String, serde_json::Value>, FormatterError> {
    let mut data = serde_json::Value::Object(Default::default());

    let mut claims = claims.into_iter().collect::<Vec<PublishedClaim>>();
    claims.sort_unstable_by(|a, b| a.key.cmp(&b.key));

    for claim in claims {
        let pointer = jsonptr::Pointer::try_from(format!("/{}", claim.key))?;
        let value: serde_json::Value = claim.value.try_into()?;
        pointer.assign(&mut data, value)?;
    }

    Ok(data
        .as_object()
        .ok_or(FormatterError::JsonMapping(
            "data is not an Object".to_string(),
        ))?
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_format_nested_vc_jwt() {
        let claims = vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/x".into(),
                value: "1".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/y".into(),
                value: "2".into(),
                datatype: None,
                array_item: false,
            },
        ];
        let expected = HashMap::from([
            (
                "location".to_string(),
                json!({
                  "x": "1",
                  "y": "2"
                }),
            ),
            ("name".to_string(), json!("John")),
        ]);

        assert_eq!(expected, nest_claims(claims).unwrap());
    }

    #[test]
    fn test_format_nested_vc_jwt_array() {
        let claims = vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/0".into(),
                value: "1".into(),
                datatype: None,
                array_item: true,
            },
            PublishedClaim {
                key: "location/1".into(),
                value: "2".into(),
                datatype: None,
                array_item: true,
            },
        ];
        let expected = HashMap::from([
            ("location".to_string(), json!(["1", "2"])),
            ("name".to_string(), json!("John")),
        ]);

        assert_eq!(expected, nest_claims(claims).unwrap());
    }
}

#[cfg(any(test, feature = "mock"))]
#[derive(Clone)]
pub struct MockAuth<F: Fn(&[u8]) -> Vec<u8> + Send + Sync>(pub F);

#[cfg(any(test, feature = "mock"))]
pub use crate::credential_formatter::model::SignatureProvider;

#[cfg(any(test, feature = "mock"))]
pub use crate::crypto::SignerError;

#[cfg(any(test, feature = "mock"))]
#[async_trait::async_trait]
impl<F: Fn(&[u8]) -> Vec<u8> + Send + Sync> SignatureProvider for MockAuth<F> {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0(message))
    }
    fn get_key_id(&self) -> Option<String> {
        Some("#key0".to_owned())
    }
    fn get_public_key(&self) -> Vec<u8> {
        vec![]
    }
}
