//! Token verification logic for Firebase ID tokens

use crate::auth::claims::Claims;
use crate::auth::jwk::get_decoding_key;
use crate::errors::{AuthError, AuthResult};
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};

/// Firebase project ID (loaded from environment)
fn get_project_id() -> AuthResult<String> {
    std::env::var("FIREBASE_PROJECT_ID").map_err(|_| {
        AuthError::ConfigError("Missing FIREBASE_PROJECT_ID environment variable".into())
    })
}

/// Verify a Firebase ID token and return the decoded claims
///
/// # Arguments
/// * `token` - The Firebase ID token string (without "Bearer " prefix)
///
/// # Returns
/// * `Ok(Claims)` - The decoded and verified claims
/// * `Err(AuthError)` - If verification fails
pub async fn verify_token(token: &str) -> AuthResult<Claims> {
    // Decode header to get 'kid'
    let header = decode_header(token).map_err(|e| AuthError::DecodeError(e.to_string()))?;

    let kid = header.kid.ok_or(AuthError::MissingKeyId)?;

    // Get decoding key (with caching)
    let decoding_key = get_decoding_key(&kid).await?;

    // Build validation
    let project_id = get_project_id()?;
    let issuer = format!("https://securetoken.google.com/{}", project_id);

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&issuer]);
    validation.set_audience(&[&project_id]);
    validation.validate_exp = true;

    // Decode and verify
    let token_data =
        decode::<Claims>(token, &decoding_key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::InvalidSignature,
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => AuthError::IssuerMismatch {
                expected: issuer.clone(),
                actual: "unknown".into(),
            },
            jsonwebtoken::errors::ErrorKind::InvalidAudience => AuthError::AudienceMismatch {
                expected: project_id.clone(),
                actual: "unknown".into(),
            },
            _ => AuthError::DecodeError(e.to_string()),
        })?;

    let claims = token_data.claims;

    // Additional validations
    if claims.sub.is_empty() {
        return Err(AuthError::DecodeError("'sub' claim is empty".into()));
    }

    // auth_time should be in the past
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if claims.auth_time > now {
        return Err(AuthError::DecodeError(
            "'auth_time' is in the future".into(),
        ));
    }

    Ok(claims)
}

/// Extract bearer token from Authorization header value
///
/// # Arguments
/// * `auth_header` - The full Authorization header value (e.g., "Bearer eyJ...")
///
/// # Returns
/// * `Ok(&str)` - The token without the "Bearer " prefix
/// * `Err(AuthError)` - If the header format is invalid
pub fn extract_bearer_token(auth_header: &str) -> AuthResult<&str> {
    const BEARER_PREFIX: &str = "Bearer ";

    if auth_header.len() < BEARER_PREFIX.len() {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }

    let prefix = &auth_header[..BEARER_PREFIX.len()];
    if !prefix.eq_ignore_ascii_case(BEARER_PREFIX) {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }

    let token = auth_header[BEARER_PREFIX.len()..].trim();
    if token.is_empty() {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token_valid() {
        assert_eq!(extract_bearer_token("Bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("bearer xyz789").unwrap(), "xyz789");
    }

    #[test]
    fn test_extract_bearer_token_invalid() {
        assert!(extract_bearer_token("Basic abc123").is_err());
        assert!(extract_bearer_token("").is_err());
        assert!(extract_bearer_token("Bearer ").is_err());
        assert!(extract_bearer_token("Bearer").is_err());
    }
}
