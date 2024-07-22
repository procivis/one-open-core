use std::{collections::HashMap, sync::Arc};

use crate::revocation::{provider::RevocationMethodProvider, RevocationMethod};

pub struct RevocationMethodProviderImpl {
    revocation_methods: HashMap<String, Arc<dyn RevocationMethod>>,
}

impl RevocationMethodProviderImpl {
    pub fn new(revocation_methods: HashMap<String, Arc<dyn RevocationMethod>>) -> Self {
        Self { revocation_methods }
    }
}

impl RevocationMethodProvider for RevocationMethodProviderImpl {
    fn get_revocation_method(
        &self,
        revocation_method_id: &str,
    ) -> Option<Arc<dyn RevocationMethod>> {
        self.revocation_methods.get(revocation_method_id).cloned()
    }

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Option<(Arc<dyn RevocationMethod>, String)> {
        let result = self
            .revocation_methods
            .iter()
            .find(|(_id, method)| method.get_status_type() == credential_status_type)?;

        Some((result.1.to_owned(), result.0.to_owned()))
    }
}
