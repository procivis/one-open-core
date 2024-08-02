use async_trait::async_trait;
use time::OffsetDateTime;

use crate::{
    caching_loader::{CachingLoader, ResolveResult, Resolver},
    revocation::error::RevocationError,
};

#[derive(Default)]
pub struct StatusListResolver {
    pub client: reqwest::Client,
}

pub type StatusListCachingLoader = CachingLoader<RevocationError>;

#[async_trait]
impl Resolver for StatusListResolver {
    type Error = RevocationError;

    async fn do_resolve(
        &self,
        url: &str,
        _previous: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        Ok(ResolveResult::NewValue(
            self.client
                .get(url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?
                .into_bytes(),
        ))
    }
}
