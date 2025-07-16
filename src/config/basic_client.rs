use std::time::Duration;

use reqwest::Client;

use crate::config::KeyCheckerConfig;

pub fn client_builder(config: &KeyCheckerConfig) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder().timeout(Duration::from_secs(config.timeout_sec));

    if let Some(ref proxy_url) = config.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy_url.clone())?);
    }

    builder.build()
}
