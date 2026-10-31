//! Firebase Authentication module
//!
//! Provides JWT verification for Firebase ID tokens.
//!
//! # Example
//! ```rust,ignore
//! use cf_auth::auth::{verify_token, Claims, CurrentUser};
//!
//! async fn authenticate(token: &str) -> Result<CurrentUser, AuthError> {
//!     let claims = verify_token(token).await?;
//!     Ok(CurrentUser::from(claims))
//! }
//! ```

mod claims;
mod jwk;
mod verifier;

// Public exports
pub use claims::{Claims, CurrentUser, FirebaseClaims};
pub use jwk::force_refresh_jwks;
pub use verifier::{extract_bearer_token, verify_token};
