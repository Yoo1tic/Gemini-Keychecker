use reqwest::{Client, IntoUrl};
use tracing::{debug, error, info, warn};

use super::{CACHE_CONTENT_TEST_BODY, GENERATE_CONTENT_TEST_BODY};
use crate::config::KeyCheckerConfig;
use crate::error::ValidatorError;
use crate::types::{GeminiKey, KeyTier, ValidatedKey};
use crate::utils::send_request;

pub async fn test_generate_content_api(
    client: Client,
    api_endpoint: impl IntoUrl,
    api_key: GeminiKey,
    config: KeyCheckerConfig,
) -> Result<ValidatedKey, ValidatorError> {
    let api_endpoint = api_endpoint.into_url().unwrap();

    match send_request(
        client,
        &api_endpoint,
        api_key.clone(),
        &*GENERATE_CONTENT_TEST_BODY,
        config.max_retries,
    )
    .await
    {
        Ok(_) => {
            info!(
                "BASIC API VALID - {}... - Passed generate content API test",
                &api_key.as_ref()[..10]
            );
            Ok(ValidatedKey::new(api_key, KeyTier::Free))
        }
        Err(e) => match &e {
            ValidatorError::HttpBadRequest { .. }
            | ValidatorError::HttpUnauthorized { .. }
            | ValidatorError::HttpForbidden { .. } => {
                warn!(
                    "INVALID - {}... - {}",
                    &api_key.as_ref()[..10],
                    ValidatorError::KeyInvalid
                );
                Ok(ValidatedKey::new(api_key, KeyTier::Invalid))
            }
            ValidatorError::HttpTooManyRequests { .. } => {
                warn!(
                    "RATE LIMITED - {}... - {}",
                    &api_key.as_ref()[..10],
                    ValidatorError::KeyRateLimited
                );
                Ok(ValidatedKey::new(api_key, KeyTier::RateLimited))
            }
            _ => {
                error!("ERROR-  {}... - {}", &api_key.as_ref()[..10], e);
                Err(e)
            }
        },
    }
}

pub async fn test_cache_content_api(
    client: Client,
    api_endpoint: impl IntoUrl,
    validated_key: ValidatedKey,
) -> ValidatedKey {
    let api_endpoint = api_endpoint.into_url().unwrap();

    match send_request(
        client,
        &api_endpoint,
        validated_key.key.clone(),
        &*CACHE_CONTENT_TEST_BODY,
        1,
    )
    .await
    {
        Ok(_) => {
            info!(
                "PAID KEY DETECTED - {}... - Cache API accessible",
                &validated_key.key.as_ref()[..10]
            );
            ValidatedKey::new(validated_key.key, KeyTier::Paid)
        }
        Err(e) => match &e {
            ValidatorError::HttpTooManyRequests { .. } => {
                debug!(
                    "FREE KEY DETECTED - {}... - Rate limit exceeded for cache API",
                    &validated_key.key.as_ref()[..10]
                );
                validated_key
            }
            _ => {
                error!(
                    "CACHE API ERROR - {}... - {}",
                    &validated_key.key.as_ref()[..10],
                    e
                );
                validated_key
            }
        },
    }
}
