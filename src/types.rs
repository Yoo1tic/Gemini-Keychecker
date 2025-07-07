use regex::Regex;
use std::str::FromStr;
use std::sync::LazyLock;

#[derive(Debug)]
pub enum KeyStatus {
    Valid,
    Invalid,
    Retryable(String),
}

#[derive(Debug, Clone)]
pub struct ApiKey {
    inner: String,
}

impl ApiKey {
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

#[derive(Debug)]
pub enum KeyValidationError {
    InvalidFormat(String),
}

impl std::fmt::Display for KeyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyValidationError::InvalidFormat(msg) => write!(f, "Invalid key format: {}", msg),
        }
    }
}

impl std::error::Error for KeyValidationError {}

impl FromStr for ApiKey {
    type Err = KeyValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^AIzaSy.{33}$").unwrap());

        let cleaned = s.trim();

        if RE.is_match(cleaned) {
            Ok(Self {
                inner: cleaned.to_string(),
            })
        } else {
            Err(KeyValidationError::InvalidFormat(
                "Google API key must start with 'AIzaSy' followed by 33 characters".to_string(),
            ))
        }
    }
}
