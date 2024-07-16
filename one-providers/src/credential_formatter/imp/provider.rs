use std::{collections::HashMap, sync::Arc};

use crate::credential_formatter::{provider::CredentialFormatterProvider, CredentialFormatter};

pub struct CredentialFormatterProviderImpl {
    formatters: HashMap<String, Arc<dyn CredentialFormatter>>,
}

impl CredentialFormatterProviderImpl {
    pub fn new(formatters: HashMap<String, Arc<dyn CredentialFormatter>>) -> Self {
        Self { formatters }
    }
}

impl CredentialFormatterProvider for CredentialFormatterProviderImpl {
    fn get_formatter(&self, format: &str) -> Option<Arc<dyn CredentialFormatter>> {
        self.formatters.get(format).cloned()
    }
}
