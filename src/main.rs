use anyhow::Result;
use async_stream::stream;
use clap::Parser;
use futures::{pin_mut, stream::StreamExt};
use reqwest::Client;
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    thread::spawn,
    time::Instant,
};
use tokio::time::Duration;
use url::Url;

use gemini_keychecker::key_validator::validate_key_with_retry;
use gemini_keychecker::types::ApiKey;
/// Configuration structure for the key checker tool
#[derive(Parser, Debug)]
#[command(version, about = "A tool to check and backup API keys", long_about = None)]
struct KeyCheckerConfig {
    /// Input file path containing API keys to check
    #[arg(long, short = 'i', default_value = "keys.txt")]
    input_path: PathBuf,

    /// Output file path for valid API keys
    #[arg(long, short = 'o', default_value = "output_keys.txt")]
    output_path: PathBuf,

    /// API host URL for key validation
    #[arg(
        long,
        short = 'u',
        default_value = "https://generativelanguage.googleapis.com/"
    )]
    api_host: Url,

    /// Request timeout in seconds
    #[arg(long, short = 't', default_value_t = 60)]
    timeout_sec: u64,

    /// Maximum number of concurrent requests
    #[arg(long, short = 'c', default_value_t = 30)]
    concurrency: usize,

    /// Optional proxy URL for HTTP requests (supports http://user:pass@host:port)
    #[arg(long, short = 'x')]
    proxy: Option<Url>,
}
/// Load and validate API keys from a file
/// Returns a vector of unique, valid API keys
fn load_keys(path: &Path) -> Result<Vec<ApiKey>> {
    let keys_txt = fs::read_to_string(path)?;
    // Use HashSet to automatically deduplicate keys
    let unique_keys_set: HashSet<&str> = keys_txt
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();

    let mut keys = Vec::new();
    for key_str in unique_keys_set {
        match ApiKey::from_str(key_str) {
            Ok(api_key) => keys.push(api_key),
            Err(e) => eprintln!("Skipping invalid key: {}", e),
        }
    }

    Ok(keys)
}

/// Build HTTP client with optional proxy configuration
/// Returns a configured reqwest Client
fn build_client(config: &KeyCheckerConfig) -> Result<Client> {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(config.timeout_sec));

    // Add proxy configuration if specified
    if let Some(proxy_url) = &config.proxy {
        let mut proxy = reqwest::Proxy::all(proxy_url.clone())?;

        // Extract username and password from URL if present
        if !proxy_url.username().is_empty() {
            let username = proxy_url.username();
            let password = proxy_url.password().unwrap_or("");
            proxy = proxy.basic_auth(username, password);
        }

        client_builder = client_builder.proxy(proxy);
    }

    client_builder.build().map_err(Into::into)
}

/// Main function - orchestrates the key validation process
#[tokio::main]
async fn main() -> Result<()> {
    let start_time = Instant::now();
    let config = KeyCheckerConfig::parse();
    let keys = load_keys(&config.input_path)?;
    let client = build_client(&config)?;

    // Create channel for streaming keys from producer to consumer
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ApiKey>();
    let stream = stream! {
        while let Some(item) = rx.recv().await {
            yield item;
        }
    };

    // Spawn producer thread to send keys through channel
    spawn(move || {
        for key in keys {
            if let Err(e) = tx.send(key) {
                eprintln!("Failed to send key: {}", e);
            }
        }
    });

    // Create stream to validate keys concurrently
    let valid_keys_stream = stream
        .map(|key| validate_key_with_retry(&client, &config.api_host, key))
        .buffer_unordered(config.concurrency)
        .filter_map(|r| async { r });
    pin_mut!(valid_keys_stream);

    // Open output file for writing valid keys
    let mut output_file = fs::File::create(&config.output_path)?;

    // Process validated keys and write to output file
    while let Some(valid_key) = valid_keys_stream.next().await {
        println!("Valid key found: {}", valid_key.as_str());
        if let Err(e) = writeln!(output_file, "{}", valid_key.as_str()) {
            eprintln!("Failed to write key to output file: {}", e);
        }
    }

    println!("Total Elapsed Time: {:?}", start_time.elapsed());
    Ok(())
}
