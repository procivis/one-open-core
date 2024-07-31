//! Exchange protocol provider.

use std::sync::Arc;

use url::Url;

use super::openid4vc::ExchangeProtocolImpl;

pub trait ExchangeProtocol:
    ExchangeProtocolImpl<
    VCInteractionContext = serde_json::Value,
    VPInteractionContext = serde_json::Value,
>
{
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ExchangeProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn ExchangeProtocol>>;
    fn detect_protocol(&self, url: &Url) -> Option<Arc<dyn ExchangeProtocol>>;
}
