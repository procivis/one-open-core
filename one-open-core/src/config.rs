pub struct OneCoreConfig {
    pub did_method_config: DidMethodConfig,
}

pub struct DidMethodConfig {
    pub universal_resolver_url: String,
    pub key_count_range: (usize, usize),
}

impl Default for OneCoreConfig {
    fn default() -> Self {
        Self {
            did_method_config: DidMethodConfig {
                universal_resolver_url: "https://dev.uniresolver.io".to_string(),
                key_count_range: (1, 1),
            },
        }
    }
}
