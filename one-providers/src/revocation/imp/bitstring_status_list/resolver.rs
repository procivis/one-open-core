use async_trait::async_trait;

use crate::{caching_loader::Resolver, revocation::error::RevocationError};

pub struct StatusListResolver {
    pub client: reqwest::Client,
}

#[async_trait]
impl Resolver for StatusListResolver {
    type Error = RevocationError;

    async fn do_resolve(&self, url: &str) -> Result<Vec<u8>, Self::Error> {
        Ok(self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?
            .into_bytes())
    }
}
