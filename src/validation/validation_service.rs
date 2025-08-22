use super::key_validator::{test_cache_content_api, test_generate_content_api};
use crate::adapters::load_keys_from_txt;
use crate::config::KeyCheckerConfig;
use crate::error::ValidatorError;
use crate::types::{GeminiKey, KeyTier, ValidatedKey};
use crate::utils::{client_builder, write_key_into_file};
use async_stream::stream;
use futures::{pin_mut, stream::StreamExt};
use indicatif::ProgressStyle;
use reqwest::Client;
use tokio::{fs, io::AsyncWriteExt, sync::mpsc};
use tracing::{Span, error, info_span};
use tracing_indicatif::span_ext::IndicatifSpanExt;

pub struct ValidationService {
    config: KeyCheckerConfig,
    client: Client,
    full_url: url::Url,
}

impl ValidationService {
    pub fn new(config: KeyCheckerConfig, client: Client) -> Self {
        let full_url = config.gemini_api_url();
        Self {
            config,
            client,
            full_url,
        }
    }

    pub async fn validate_keys(&self, keys: Vec<GeminiKey>) -> Result<(), ValidatorError> {
        let total_keys = keys.len();
        // Create a progress bar to track validation progress
        let progress_span = info_span!("key_checker");
        progress_span.pb_set_style(
            &ProgressStyle::with_template(
                "[{bar:60.cyan/blue}] {pos}/{len} ({percent}%) [{elapsed_precise}] ETA:{eta} Speed:{per_sec}",
            )
            .unwrap(),
        );
        progress_span.pb_set_length(total_keys as u64);
        progress_span.pb_set_message("Validating keys...");
        progress_span.pb_set_finish_message("All items processed");
        let progress_span_enter = progress_span.enter();

        // Create channel for streaming keys from producer to consumer
        let (tx, mut rx) = mpsc::unbounded_channel::<GeminiKey>();
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

        let (invalid_tx, mut invalid_rx) = mpsc::unbounded_channel::<GeminiKey>();
        let invalid_stream = stream! {
            while let Some(item) = invalid_rx.recv().await {
                yield ValidatedKey::new(item);
            }
        };

        // Create invalid keys stream
        let cache_api_url = self.config.cache_api_url();
        let valid_keys_stream = stream
            .map(|key| async move {
                let result = test_generate_content_api(
                    self.client.clone(),
                    self.full_url.clone(),
                    key.clone(),
                    self.config.clone(),
                )
                .await;
                Span::current().pb_inc(1);
                (key, result)
            })
            .buffer_unordered(self.config.concurrency)
            .filter_map(|(key, result)| async {
                match result {
                    Ok(()) => Some(ValidatedKey::new(key)),
                    Err(_e) => {
                        let _ = invalid_tx.send(key);
                        None
                    }
                }
            })
            .map(|validated_key| {
                test_cache_content_api(self.client.clone(), cache_api_url.clone(), validated_key)
            })
            .buffer_unordered(self.config.concurrency);
        pin_mut!(valid_keys_stream);

        // Open output files for writing keys by tier (fixed filenames)
        let free_keys_path = "freekey.txt";
        let paid_keys_path = "paidkey.txt";
        let invalid_keys_path = "invalidkey.txt";

        let free_file = fs::File::create(&free_keys_path).await?;
        let paid_file = fs::File::create(&paid_keys_path).await?;
        let invalid_file = fs::File::create(&invalid_keys_path).await?;

        let mut free_buffer_writer = tokio::io::BufWriter::new(free_file);
        let mut paid_buffer_writer = tokio::io::BufWriter::new(paid_file);
        let mut invalid_buffer_writer = tokio::io::BufWriter::new(invalid_file);

        // Spawn task to process invalid keys stream
        tokio::spawn(async move {
            pin_mut!(invalid_stream);
            while let Some(invalid_key) = invalid_stream.next().await {
                if let Err(e) = write_key_into_file(&mut invalid_buffer_writer, &invalid_key).await
                {
                    error!("Failed to write invalid key to file: {e}");
                }
            }
            if let Err(e) = invalid_buffer_writer.flush().await {
                error!("Failed to flush invalid keys buffer: {e}");
            }
        });

        // Process all keys and write to appropriate tier files
        while let Some(validated_key) = valid_keys_stream.next().await {
            match validated_key.tier {
                KeyTier::Free => {
                    if let Err(e) =
                        write_key_into_file(&mut free_buffer_writer, &validated_key).await
                    {
                        error!("Failed to write free key to file: {e}");
                    }
                }
                KeyTier::Paid => {
                    if let Err(e) =
                        write_key_into_file(&mut paid_buffer_writer, &validated_key).await
                    {
                        error!("Failed to write paid key to file: {e}");
                    }
                }
            }
        }
        // Flush buffers for valid keys
        free_buffer_writer.flush().await?;
        paid_buffer_writer.flush().await?;

        std::mem::drop(progress_span_enter);
        std::mem::drop(progress_span);

        Ok(())
    }
}

pub async fn start_validation() -> Result<(), ValidatorError> {
    let config = KeyCheckerConfig::load_config()?;

    let keys = load_keys_from_txt(config.input_path.as_path())?;

    let client = client_builder(&config)?;

    let validation_service = ValidationService::new(config, client);
    validation_service.validate_keys(keys).await
}
