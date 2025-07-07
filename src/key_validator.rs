use anyhow::Result;
use backon::{ExponentialBuilder, Retryable};
use reqwest::{Client, StatusCode};
use serde_json;
use tokio::time::Duration;
use url::Url;

use crate::types::{KeyStatus, ApiKey};

pub async fn validate_key_with_retry(client: &Client, api_host: &Url, key: ApiKey) -> Option<ApiKey> {
    let retry_policy = ExponentialBuilder::default()
        .with_max_times(3)
        .with_min_delay(Duration::from_secs(3))
        .with_max_delay(Duration::from_secs(5));

    let result = (|| async {
        match keytest(&client, &api_host, &key).await {
            Ok(KeyStatus::Valid) => {
                println!("Key: {}... -> SUCCESS", &key.as_str()[..10]);
                Ok(Some(key.clone()))
            }
            Ok(KeyStatus::Invalid) => {
                println!("Key: {}... -> INVALID (Forbidden)", &key.as_str()[..10]);
                Ok(None)
            }
            Ok(KeyStatus::Retryable(reason)) => {
                eprintln!("Key: {}... -> RETRYABLE (Reason: {})", &key.as_str()[..10], reason);
                Err(anyhow::anyhow!("Retryable error: {}", reason))
            }
            Err(e) => {
                eprintln!("Key: {}... -> NETWORK ERROR (Reason: {})", &key.as_str()[..10], e);
                Err(e)
            }
        }
    })
    .retry(retry_policy)
    .await;

    match result {
        Ok(key_result) => key_result,
        Err(_) => {
            eprintln!("Key: {}... -> FAILED after all retries.", &key.as_str()[..10]);
            None
        }
    }
}

async fn keytest(client: &Client, api_host: &Url, key: &ApiKey) -> Result<KeyStatus> {
    const API_PATH: &str = "v1beta/models/gemini-2.0-flash-exp:generateContent";
    let full_url = api_host.join(API_PATH)?;
    
    let request_body = serde_json::json!({
        "contents": [
            {
                "parts": [
                    {
                        "text": "Hi"
                    }
                ]
            }
        ]
    });

    let response = client
        .post(full_url)
        .header("Content-Type", "application/json")
        .header("X-goog-api-key", key.as_str())
        .json(&request_body)
        .send()
        .await?;

    let status = response.status();

    let key_status = match status {
        StatusCode::OK => KeyStatus::Valid,
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => KeyStatus::Invalid,
        other => KeyStatus::Retryable(format!("Received status {}, will retry.", other)),
    };
    Ok(key_status)
}