use std::{string::FromUtf8Error, sync::Arc};

use futures::future::BoxFuture;
use json_ld::{Loader, RemoteDocument};
use json_syntax::Parse;
use locspan::{Location, Meta};
use rdf_types::IriVocabulary;
use sophia_jsonld::loader::FutureExt;
use time::{format_description::well_known::Rfc2822, macros::offset, OffsetDateTime};
use tokio::sync::Mutex;

use crate::{
    remote_entity_storage::{
        RemoteEntity, RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
    },
    util::caching::{context_requires_update, ContextRequiresUpdate},
};

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct JsonLdCachingLoader {
    pub cache_size: usize,
    pub cache_refresh_timeout: time::Duration,
    pub refresh_after: time::Duration,

    pub client: reqwest::Client,
    pub remote_entity_storage: Arc<dyn RemoteEntityStorage>,
    clean_old_mutex: Arc<Mutex<()>>,
}

impl JsonLdCachingLoader {
    pub fn new(
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
        client: reqwest::Client,
        remote_entity_storage: Arc<dyn RemoteEntityStorage>,
    ) -> Self {
        Self {
            cache_size,
            cache_refresh_timeout,
            refresh_after,
            client,
            remote_entity_storage,
            clean_old_mutex: Arc::new(Mutex::new(())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CachingLoaderError {
    #[error("HTTP error: Cannot parse Last-Modified header")]
    CannotParseLastModifiedHeader,
    #[error("HTTP error: received 3xx status code when 2xx was expected")]
    ReceivedStatus3xxInsteadOf2xx,
    #[error("HTTP error: unexpected status code: `{0}`")]
    UnexpectedStatusCode(String),

    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("JSON parse error: `{0}`")]
    JsonParseError(#[from] JsonParseError),
    #[error("MIME from str error: `{0}`")]
    MimeFromStrError(#[from] mime::FromStrError),
    #[error("OffsetDateTime parse error: `{0}`")]
    OffsetDateTimeError(#[from] time::error::Parse),
    #[error("Remote entity storage error: `{0}`")]
    RemoteEntityStorageError(#[from] RemoteEntityStorageError),
    #[error("HTTP error: `{0}`")]
    Reqwest(#[from] reqwest::Error),
    #[error("Time error: `{0}`")]
    TimeError(#[from] time::error::Format),
    #[error("URL parse error: `{0}`")]
    UrlParseError(#[from] url::ParseError),
}

type ArcIri = sophia_api::prelude::Iri<Arc<str>>;
type JsonParseError = Meta<json_syntax::parse::Error<Location<ArcIri>>, Location<ArcIri>>;

impl Loader<ArcIri, Location<ArcIri>> for JsonLdCachingLoader {
    type Output = json_syntax::Value<Location<ArcIri>>;
    type Error = CachingLoaderError;

    #[inline(always)]
    fn load_with<'a>(
        &'a mut self,
        _namespace: &mut impl IriVocabulary<Iri = ArcIri>,
        url: ArcIri,
    ) -> BoxFuture<
        'a,
        Result<
            RemoteDocument<ArcIri, Location<ArcIri>, json_syntax::Value<Location<ArcIri>>>,
            Self::Error,
        >,
    >
    where
        ArcIri: 'a,
    {
        async move {
            let context = self.load_context(url.as_str()).await?;

            let doc = json_syntax::Value::parse_str(&context, |span| {
                Location::new(url.to_owned(), span)
            })?;

            Ok(RemoteDocument::new(
                Some(url.to_owned()),
                Some("application/ld+json".parse()?),
                doc,
            ))
        }
        .boxed()
    }
}

impl JsonLdCachingLoader {
    pub async fn load_context(&self, url: &str) -> Result<String, CachingLoaderError> {
        let result = self.remote_entity_storage.get_by_key(url).await?;

        let context = match result {
            None => {
                let context_str = match self.fetch_context(url, None).await? {
                    FetchContextResult::LastModifiedHeader(_) => {
                        Err(CachingLoaderError::ReceivedStatus3xxInsteadOf2xx)
                    }
                    FetchContextResult::Value(context_str) => Ok(context_str),
                }?;

                let now = OffsetDateTime::now_utc();
                let context = RemoteEntity {
                    last_modified: now,
                    entity_type: RemoteEntityType::JsonLdContext,
                    key: url.to_string(),
                    value: context_str.to_owned().into_bytes(),
                    hit_counter: 0,
                };

                self.remote_entity_storage.insert(context).await?;

                context_str
            }
            Some(mut context) => {
                let requires_update = context_requires_update(
                    context.last_modified,
                    self.cache_refresh_timeout,
                    self.refresh_after,
                );

                if requires_update != ContextRequiresUpdate::IsRecent {
                    let current_context_str = String::from_utf8(context.value.to_owned())?;

                    let result = self
                        .fetch_context(url, Some(context.last_modified))
                        .await
                        .map(|value| match value {
                            FetchContextResult::LastModifiedHeader(last_modified) => {
                                (current_context_str, last_modified)
                            }
                            FetchContextResult::Value(context_str) => {
                                (context_str, OffsetDateTime::now_utc())
                            }
                        });
                    match result {
                        Ok((context_str, last_modified)) => {
                            context.last_modified = last_modified;
                            context.value = context_str.into_bytes();
                        }
                        Err(error) => {
                            if requires_update == ContextRequiresUpdate::MustBeUpdated {
                                return Err(error);
                            }
                        }
                    }
                }
                context.hit_counter = context.hit_counter.to_owned() + 1;

                self.remote_entity_storage
                    .insert(context.to_owned())
                    .await?;

                String::from_utf8(context.value)?
            }
        };

        self.clean_old_context_if_needed().await?;

        Ok(context)
    }

    async fn clean_old_context_if_needed(&self) -> Result<(), RemoteEntityStorageError> {
        let _lock = self.clean_old_mutex.lock().await;

        if self
            .remote_entity_storage
            .get_storage_size(RemoteEntityType::JsonLdContext)
            .await?
            > self.cache_size
        {
            self.remote_entity_storage
                .delete_oldest(RemoteEntityType::JsonLdContext)
                .await?;
        }

        Ok(())
    }

    async fn fetch_context(
        &self,
        url: &str,
        last_modified: Option<OffsetDateTime>,
    ) -> Result<FetchContextResult, CachingLoaderError> {
        let mut request = self.client.get(url);
        if let Some(last_modified) = last_modified {
            request = request.header(
                "If-Modified-Since",
                last_modified
                    .to_offset(offset!(+0))
                    .format(&RFC_2822_BUT_WITH_GMT)?,
            );
        }

        let response = request.send().await?.error_for_status()?;
        let status = response.status();
        if status.is_success() {
            Ok(FetchContextResult::Value(response.text().await?))
        } else if status.is_redirection() {
            let result = response
                .headers()
                .get("Last-Modified")
                .map(|value| value.to_str())
                .transpose()
                .map_err(|_| CachingLoaderError::CannotParseLastModifiedHeader)?;

            let last_modified = match result {
                None => OffsetDateTime::now_utc(),
                Some(value) => OffsetDateTime::parse(value, &Rfc2822)?,
            };
            Ok(FetchContextResult::LastModifiedHeader(last_modified))
        } else {
            Err(CachingLoaderError::UnexpectedStatusCode(status.to_string()))
        }
    }
}

enum FetchContextResult {
    LastModifiedHeader(OffsetDateTime),
    Value(String),
}

const RFC_2822_BUT_WITH_GMT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);
