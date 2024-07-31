use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::{
    remote_entity_storage::{
        RemoteEntity, RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
    },
    util::caching::{context_requires_update, ContextRequiresUpdate},
};

#[async_trait]
pub trait Resolver: Send + Sync {
    type Error: From<RemoteEntityStorageError>;

    async fn do_resolve(&self, url: &str) -> Result<Vec<u8>, Self::Error>;
}

pub struct CachingLoader<E> {
    pub resolver: Arc<dyn Resolver<Error = E>>,
    pub remote_entity_type: RemoteEntityType,
    pub storage: Arc<dyn RemoteEntityStorage>,

    pub cache_size: usize,
    pub cache_refresh_timeout: time::Duration,
    pub refresh_after: time::Duration,

    clean_old_mutex: Arc<Mutex<()>>,
}

impl<E: From<RemoteEntityStorageError>> CachingLoader<E> {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = E>>,
        remote_entity_type: RemoteEntityType,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            resolver,
            remote_entity_type,
            storage,
            cache_size,
            cache_refresh_timeout,
            refresh_after,
            clean_old_mutex: Arc::new(Mutex::new(())),
        }
    }

    pub async fn resolve(&self, url: &str) -> Result<Vec<u8>, E> {
        let context = match self.storage.get_by_key(url).await? {
            None => {
                let document = self.resolver.do_resolve(url).await?;

                self.storage
                    .insert(RemoteEntity {
                        last_modified: OffsetDateTime::now_utc(),
                        entity_type: self.remote_entity_type,
                        key: url.to_string(),
                        value: document.to_owned(),
                        hit_counter: 0,
                    })
                    .await?;

                Ok(document)
            }
            Some(mut context) => {
                let requires_update = context_requires_update(
                    context.last_modified,
                    self.cache_refresh_timeout,
                    self.refresh_after,
                );

                if requires_update != ContextRequiresUpdate::IsRecent {
                    let result = self.resolver.do_resolve(url).await;

                    match result {
                        Ok(value) => {
                            context.last_modified = OffsetDateTime::now_utc();
                            context.value = value;
                        }
                        Err(error) => {
                            if requires_update == ContextRequiresUpdate::MustBeUpdated {
                                return Err(error);
                            }
                        }
                    }
                }
                context.hit_counter = context.hit_counter.to_owned() + 1;

                self.storage.insert(context.to_owned()).await?;

                Ok(context.value)
            }
        }?;

        self.clean_old_entries_if_needed().await?;

        Ok(context)
    }

    async fn clean_old_entries_if_needed(&self) -> Result<(), RemoteEntityStorageError> {
        let _lock = self.clean_old_mutex.lock().await;

        if self
            .storage
            .get_storage_size(self.remote_entity_type)
            .await?
            > self.cache_size
        {
            self.storage.delete_oldest(self.remote_entity_type).await?;
        }

        Ok(())
    }
}
