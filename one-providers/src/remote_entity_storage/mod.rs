use std::cmp::Ordering;

use thiserror::Error;
use time::OffsetDateTime;

pub mod in_memory;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait RemoteEntityStorage: Send + Sync {
    async fn delete_oldest(
        &self,
        entity_type: RemoteEntityType,
    ) -> Result<(), RemoteEntityStorageError>;

    async fn get_by_key(&self, key: &str)
        -> Result<Option<RemoteEntity>, RemoteEntityStorageError>;

    async fn get_storage_size(
        &self,
        entity_type: RemoteEntityType,
    ) -> Result<usize, RemoteEntityStorageError>;

    async fn insert(&self, request: RemoteEntity) -> Result<(), RemoteEntityStorageError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteEntity {
    pub last_modified: OffsetDateTime,

    pub entity_type: RemoteEntityType,
    pub key: String,
    pub value: Vec<u8>,

    pub hit_counter: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteEntityType {
    DidDocument,
    JsonLdContext,
    StatusListCredential,
}

#[derive(Clone, Error, Debug)]
pub enum RemoteEntityStorageError {
    #[error("Delete error: `{0}`")]
    Delete(String),
    #[error("Get by key error: `{0}`")]
    GetByKey(String),
    #[error("Get storage size: `{0}`")]
    GetStorageSize(String),
    #[error("Insert: `{0}`")]
    Insert(String),
}

impl PartialOrd<Self> for RemoteEntity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RemoteEntity {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.hit_counter.cmp(&other.hit_counter) {
            Ordering::Equal => self.last_modified.cmp(&other.last_modified),
            value => value,
        }
    }
}
