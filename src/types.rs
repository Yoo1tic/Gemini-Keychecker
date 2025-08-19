use crate::error::ValidatorError;
use regex::Regex;
use std::str::FromStr;
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct GeminiKey {
    pub inner: String,
}

impl AsRef<str> for GeminiKey {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl FromStr for GeminiKey {
    type Err = ValidatorError;
    fn from_str(s: &str) -> Result<Self, ValidatorError> {
        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^AIzaSy[A-Za-z0-9_-]{33}$").unwrap());

        let cleaned = s.trim();

        if RE.is_match(cleaned) {
            Ok(Self {
                inner: cleaned.to_string(),
            })
        } else {
            Err(ValidatorError::KeyFormatInvalid(cleaned.to_string()))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyTier {
    Free,
    Paid,
    Invalid,
    RateLimited,
}

#[derive(Debug, Clone)]
pub struct ValidatedKey {
    pub key: GeminiKey,
    pub tier: KeyTier,
}

impl ValidatedKey {
    pub fn new(key: GeminiKey, tier: KeyTier) -> Self {
        Self { key, tier }
    }
}
