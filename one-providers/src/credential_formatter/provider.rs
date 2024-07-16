use std::sync::Arc;

use super::CredentialFormatter;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait CredentialFormatterProvider: Send + Sync {
    fn get_formatter(&self, formatter_id: &str) -> Option<Arc<dyn CredentialFormatter>>;
}
