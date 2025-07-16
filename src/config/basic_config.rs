use anyhow::{Ok, Result};
use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;
use url::Url;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyCheckerConfig {
    // Input file path containing API keys to check.
    #[serde(default)]
    pub input_path: PathBuf,

    // Output file path for valid API keys.
    #[serde(default)]
    pub output_path: PathBuf,

    // Backup file path for all API keys.
    #[serde(default)]
    pub backup_path: PathBuf,

    // API host URL for key validation.
    #[serde(default = "default_api_host")]
    pub api_host: Url,

    // Request timeout in seconds.
    #[serde(default)]
    pub timeout_sec: u64,

    // Maximum number of concurrent requests.
    #[serde(default)]
    pub concurrency: usize,

    // Optional proxy URL for HTTP requests (e.g., --proxy http://user:pass@host:port).
    #[serde(default)]
    pub proxy: Option<Url>,
}

impl Default for KeyCheckerConfig {
    fn default() -> Self {
        Self {
            input_path: default_input_path(),
            output_path: default_output_path(),
            backup_path: default_backup_path(),
            api_host: default_api_host(),
            timeout_sec: default_timeout(),
            concurrency: default_concurrency(),
            proxy: None,
        }
    }
}
impl KeyCheckerConfig {
    pub fn load_config() -> Result<Self> {
        // Define the path to the configuration file
        static CONFIG_PATH: LazyLock<PathBuf> = LazyLock::new(|| "config.toml".into());

        // Check if config.toml exists, if not create it with default values
        if !CONFIG_PATH.exists() {
            let default_config = Self::default();
            let toml_content = toml::to_string_pretty(&default_config)?;
            fs::write(CONFIG_PATH.as_path(), toml_content)?;
        }

        // Load configuration from config.toml, environment variables, and defaults
        let config = Figment::new()
            .merge(Toml::file(CONFIG_PATH.as_path()))
            .merge(Env::prefixed("KEYCHECKER_"))
            .extract()?;
        Ok(config)
    }
}

fn default_input_path() -> PathBuf {
    "keys.txt".into()
}
fn default_output_path() -> PathBuf {
    "output_keys.txt".into()
}
fn default_backup_path() -> PathBuf {
    "backup_keys.txt".into()
}
fn default_api_host() -> Url {
    Url::parse("https://generativelanguage.googleapis.com/").unwrap()
}
fn default_timeout() -> u64 {
    20
}
fn default_concurrency() -> usize {
    30
}
