use crate::http_client::{
    Error, Headers, HttpClient, Method, RequestBuilder, Response, StatusCode,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Clone)]
pub struct ReqwestClient {
    pub client: reqwest::Client,
}

impl ReqwestClient {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
    fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Get, url)
    }

    fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Post, url)
    }

    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<Headers>,
        method: Method,
    ) -> Result<Response, Error> {
        let mut builder = match method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url),
        };

        if let Some(headers) = headers {
            builder = builder.headers(to_header_map(headers)?);
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }

        do_send(builder).await
    }
}

fn to_header_map(headers: HashMap<String, String>) -> Result<HeaderMap, Error> {
    headers
        .into_iter()
        .map(|(k, v)| {
            let name = HeaderName::from_str(k.as_str()).map_err(|e| Error::Other(e.to_string()))?;
            let value =
                HeaderValue::from_str(v.as_str()).map_err(|e| Error::Other(e.to_string()))?;

            Ok((name, value))
        })
        .collect::<Result<HeaderMap, Error>>()
}

async fn do_send(builder: reqwest::RequestBuilder) -> Result<Response, Error> {
    let response = builder
        .send()
        .await
        .map_err(|e| Error::HttpError(e.to_string()))?;

    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            let value = v.to_str().map_err(|e| Error::Other(e.to_string()))?;

            Ok((k.to_string(), value.to_string()))
        })
        .collect::<Result<Headers, Error>>()?;
    let status_code = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .map_err(|e| Error::HttpError(e.to_string()))?;

    Ok(Response {
        body: body.to_vec(),
        headers,
        status: StatusCode(status_code),
    })
}
