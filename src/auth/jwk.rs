//! JWK fetching and caching logic for Google's Firebase Auth public keys

use crate::errors::{AuthError, AuthResult};
use jsonwebtoken::DecodingKey;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Google's public key endpoint for Firebase Auth
const GOOGLE_CERTS_URL: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

/// Default cache TTL: 1 hour
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Minimum interval between fetches (prevent abuse)
const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(60);

/// Cached JWK entry with expiration tracking
struct CachedKey {
    key: DecodingKey,
    fetched_at: Instant,
}

/// Global JWK cache: HashMap<kid, CachedKey>
static JWK_CACHE: Lazy<RwLock<HashMap<String, CachedKey>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Last fetch timestamp for rate limiting
static LAST_FETCH: Lazy<RwLock<Option<Instant>>> = Lazy::new(|| RwLock::new(None));

/// Get a decoding key for the given Key ID (kid)
///
/// Checks cache first, only fetches from Google if key is not found or expired.
pub async fn get_decoding_key(kid: &str) -> AuthResult<DecodingKey> {
    // Check cache
    {
        let cache = JWK_CACHE
            .read()
            .map_err(|_| AuthError::ConfigError("JWK cache lock poisoned".into()))?;

        if let Some(entry) = cache.get(kid) {
            if entry.fetched_at.elapsed() < DEFAULT_CACHE_TTL {
                tracing::debug!("JWK cache hit for kid: {}", kid);
                return Ok(entry.key.clone());
            }
            tracing::debug!("JWK cache expired for kid: {}", kid);
        }
    }

    // Cache miss or expired - refresh keys
    tracing::info!("Refreshing JWKs from Google (kid: {})", kid);
    refresh_jwks().await?;

    // Retry lookup
    let cache = JWK_CACHE
        .read()
        .map_err(|_| AuthError::ConfigError("JWK cache lock poisoned".into()))?;

    cache
        .get(kid)
        .map(|entry| entry.key.clone())
        .ok_or_else(|| AuthError::KeyNotFound {
            kid: kid.to_string(),
        })
}

/// Fetch Google's public keys and update the cache
async fn refresh_jwks() -> AuthResult<()> {
    // Rate limit check
    {
        let last = LAST_FETCH
            .read()
            .map_err(|_| AuthError::ConfigError("Last fetch lock poisoned".into()))?;

        if let Some(instant) = *last {
            if instant.elapsed() < MIN_FETCH_INTERVAL {
                tracing::debug!("JWK refresh skipped (rate limited)");
                return Ok(());
            }
        }
    }

    // Fetch from Google
    let response = reqwest::get(GOOGLE_CERTS_URL)
        .await
        .map_err(|e| AuthError::JwkFetchError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(AuthError::JwkFetchError(format!(
            "HTTP {} from Google",
            response.status()
        )));
    }

    let certs: HashMap<String, String> = response
        .json()
        .await
        .map_err(|e| AuthError::JwkFetchError(format!("Failed to parse JWK response: {}", e)))?;

    // Convert to DecodingKeys
    let mut new_cache = HashMap::new();
    let now = Instant::now();

    for (kid, pem) in certs {
        match DecodingKey::from_rsa_pem(pem.as_bytes()) {
            Ok(key) => {
                new_cache.insert(
                    kid,
                    CachedKey {
                        key,
                        fetched_at: now,
                    },
                );
            }
            Err(e) => {
                tracing::warn!("Failed to parse RSA key for kid {}: {}", kid, e);
            }
        }
    }

    if new_cache.is_empty() {
        return Err(AuthError::JwkFetchError(
            "No valid keys found in Google response".into(),
        ));
    }

    // Update cache atomically
    let key_count = new_cache.len();
    {
        let mut cache = JWK_CACHE
            .write()
            .map_err(|_| AuthError::ConfigError("JWK cache lock poisoned".into()))?;
        *cache = new_cache;
    }

    {
        let mut last = LAST_FETCH
            .write()
            .map_err(|_| AuthError::ConfigError("Last fetch lock poisoned".into()))?;
        *last = Some(now);
    }

    tracing::info!("Refreshed {} JWKs from Google", key_count);
    Ok(())
}

/// Force refresh the JWK cache (for testing or manual refresh)
pub async fn force_refresh_jwks() -> AuthResult<()> {
    // Clear LAST_FETCH to bypass rate limiting
    {
        let mut last = LAST_FETCH
            .write()
            .map_err(|_| AuthError::ConfigError("Last fetch lock poisoned".into()))?;
        *last = None;
    }

    refresh_jwks().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_refresh_jwks() {
        let result = force_refresh_jwks().await;
        assert!(result.is_ok(), "Failed to refresh JWKs: {:?}", result);

        let cache = JWK_CACHE.read().unwrap();
        assert!(!cache.is_empty(), "Cache should not be empty after refresh");
    }
}
