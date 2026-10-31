use thiserror::Error;
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Missing Authorization header")]
    MissingAuthHeader,

    #[error("Invalid Authorization header format: expected 'Bearer <token>'")]
    InvalidAuthHeaderFormat,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid token signature")]
    InvalidSignature,

    #[error("Invalid X-Firebase-Signature")]
    InvalidSignatureHeader,

    #[error("Token issuer mismatch: expected '{expected}', got '{actual}'")]
    IssuerMismatch { expected: String, actual: String },

    #[error("Token audience mismatch: expected '{expected}', got '{actual}'")]
    AudienceMismatch { expected: String, actual: String },

    #[error("Missing 'kid' (Key ID) in token header")]
    MissingKeyId,

    #[error("Key ID '{kid}' not found in Google's public keys")]
    KeyNotFound { kid: String },

    #[error("Failed to fetch Google public keys: {0}")]
    JwkFetchError(String),

    #[error("Failed to decode token: {0}")]
    DecodeError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type AuthResult<T> = Result<T, AuthError>;
