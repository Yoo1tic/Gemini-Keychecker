use std::time::Duration;

use reqwest::Client;

use crate::config::KeyCheckerConfig;

pub fn client_builder(config: &KeyCheckerConfig) -> Result<Client, reqwest::Error> {
    // Adjust connection pool size based on concurrency, optimizing for 0.5 second response time
    let pool_size = config.concurrency / 2;

    let mut builder = Client::builder()
        .timeout(Duration::from_secs(config.timeout_sec))
        .pool_max_idle_per_host(pool_size);
//        .http2_prior_knowledge();

    if let Some(ref proxy_url) = config.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy_url.clone())?);
    }

    builder.build()
}
