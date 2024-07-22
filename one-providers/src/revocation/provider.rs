use std::sync::Arc;

use crate::revocation::RevocationMethod;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait RevocationMethodProvider: Send + Sync {
    fn get_revocation_method(
        &self,
        revocation_method_id: &str,
    ) -> Option<Arc<dyn RevocationMethod>>;

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Option<(Arc<dyn RevocationMethod>, String)>;
}
