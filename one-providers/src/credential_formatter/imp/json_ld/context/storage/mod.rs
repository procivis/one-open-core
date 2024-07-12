use std::cmp::Ordering;

use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

pub mod in_memory_storage;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonLdContext {
    pub last_modified: OffsetDateTime,

    pub context: Vec<u8>,

    pub url: Url,
    pub hit_counter: u32,
}

#[derive(Debug, Error)]
pub enum JsonLdContextStorageError {
    #[error("Delete error: `{0}`")]
    DeleteError(String),
    #[error("Get by url error: `{0}`")]
    GetByUrlError(String),
    #[error("Get storage size error: `{0}`")]
    GetStorageSizeError(String),
    #[error("Insert error: `{0}`")]
    InsertError(String),
}

impl PartialOrd<Self> for JsonLdContext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JsonLdContext {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.hit_counter.cmp(&other.hit_counter) {
            Ordering::Equal => self.last_modified.cmp(&other.last_modified),
            value => value,
        }
    }
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait JsonLdContextStorage: Send + Sync {
    async fn delete_oldest_context(&self) -> Result<(), JsonLdContextStorageError>;

    async fn get_json_ld_context_by_url(
        &self,
        url: &str,
    ) -> Result<Option<JsonLdContext>, JsonLdContextStorageError>;

    async fn get_storage_size(&self) -> Result<usize, JsonLdContextStorageError>;

    async fn insert_json_ld_context(
        &self,
        request: JsonLdContext,
    ) -> Result<(), JsonLdContextStorageError>;
}
