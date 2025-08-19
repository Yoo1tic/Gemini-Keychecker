use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidatorError {
    #[error("HTTP error: {0}")]
    ReqwestError(Box<reqwest::Error>),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    ConfigError(Box<figment::Error>),

    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("TOML deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Key is unavailable or invalid")]
    KeyInvalid,

    #[error("Key has exceeded its rate limit")]
    KeyRateLimited,

    #[error("Invalid Google API key format: {0}")]
    KeyFormatInvalid(String),

    #[error("HTTP 400 Bad Request: {body}")]
    HttpBadRequest { body: String },

    #[error("HTTP 401 Unauthorized: {body}")]
    HttpUnauthorized { body: String },

    #[error("HTTP 403 Forbidden: {body}")]
    HttpForbidden { body: String },

    #[error("HTTP 429 Too Many Requests: {body}")]
    HttpTooManyRequests { body: String },

    #[error("HTTP {status} Client Error: {body}")]
    HttpClientError { status: u16, body: String },

    #[error("HTTP {status} Server Error: {body}")]
    HttpServerError { status: u16, body: String },
}

impl From<reqwest::Error> for ValidatorError {
    fn from(err: reqwest::Error) -> Self {
        ValidatorError::ReqwestError(Box::new(err))
    }
}

impl From<figment::Error> for ValidatorError {
    fn from(err: figment::Error) -> Self {
        ValidatorError::ConfigError(Box::new(err))
    }
}

pub type Result<T> = std::result::Result<T, ValidatorError>;
