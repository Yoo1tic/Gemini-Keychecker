use anyhow::Result;
use async_stream::stream;
use futures::{pin_mut, stream::StreamExt};
use reqwest::Client;
use std::{fs, time::Instant};
use tokio::sync::mpsc;

use crate::config::KeyCheckerConfig;
use crate::adapters::write_keys_txt_file;
use crate::key_validator::validate_key_with_retry;
use crate::types::ApiKey;

pub struct ValidationService {
    config: KeyCheckerConfig,
    client: Client,
}

impl ValidationService {
    pub fn new(config: KeyCheckerConfig, client: Client) -> Self {
        Self { config, client }
    }

    pub async fn validate_keys(&self, keys: Vec<ApiKey>) -> Result<()> {
        let start_time = Instant::now();

        // Create channel for streaming keys from producer to consumer
        let (tx, mut rx) = mpsc::unbounded_channel::<ApiKey>();
        let stream = stream! {
            while let Some(item) = rx.recv().await {
                yield item;
            }
        };

        // Spawn producer task to send keys through channel
        tokio::spawn(async move {
            for key in keys {
                if let Err(e) = tx.send(key) {
                    eprintln!("Failed to send key: {}", e);
                }
            }
        });

        // Create stream to validate keys concurrently
        let valid_keys_stream = stream
            .map(|key| validate_key_with_retry(&self.client, &self.config.api_host, key))
            .buffer_unordered(self.config.concurrency)
            .filter_map(|r| async { r });
        pin_mut!(valid_keys_stream);

        // Open output file for writing valid keys
        let mut output_file = fs::File::create(&self.config.output_path)?;

        // Process validated keys and write to output file
        while let Some(valid_key) = valid_keys_stream.next().await {
            println!("Valid key found: {}", valid_key.as_str());
            if let Err(e) = write_keys_txt_file(&mut output_file, &valid_key) {
                eprintln!("Failed to write key to output file: {}", e);
            }
        }

        println!("Total Elapsed Time: {:?}", start_time.elapsed());
        Ok(())
    }
}
