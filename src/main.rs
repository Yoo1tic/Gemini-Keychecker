use anyhow::Result;
use gemini_keychecker::config::{KeyCheckerConfig, client_builder};
use gemini_keychecker::adapters::load_keys;
use gemini_keychecker::validation::ValidationService;

/// Main function - orchestrates the key validation process
#[tokio::main]
async fn main() -> Result<()> {
    let config = KeyCheckerConfig::load_config().unwrap();
    let keys = load_keys(&config.input_path)?;
    let client = client_builder(&config)?;

    let validation_service = ValidationService::new(config, client);
    validation_service.validate_keys(keys).await?;

    Ok(())
}
