//! # cf-auth
//!
//! A shared Rust library for Firebase Authentication.
//!
//! ## Features
//!
//! - JWT verification against Google's public keys
//! - Automatic JWK caching with smart refresh
//! - Actix-web middleware (optional, via `actix` feature)
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use cf_auth::auth::{verify_token, CurrentUser};
//!
//! async fn authenticate(token: &str) -> Result<CurrentUser, AuthError> {
//!     let claims = verify_token(token).await?;
//!     Ok(CurrentUser::from(claims))
//! }
//! ```
//!
//! ## With Actix-web
//!
//! Enable the `actix` feature in Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! cf-auth = { git = "...", features = ["actix"] }
//! ```
//!
//! Then use the middleware:
//!
//! ```rust,ignore
//! use actix_web::{App, middleware::from_fn};
//! use cf_auth::middleware::firebase_auth_middleware;
//!
//! App::new()
//!     .wrap(from_fn(firebase_auth_middleware))
//! ```
//!
//! ## Environment Variables
//!
//! - `FIREBASE_PROJECT_ID`: Required. Your Firebase project ID.
//! - `FIREBASE_SIGNATURE`: Required by `firebase_signature_middleware`. Expected `X-Firebase-Signature` value.

// Modules
pub mod auth;
pub mod errors;
pub mod response;

#[cfg(feature = "actix")]
pub mod middleware;

// Re-exports for convenience
pub use auth::{Claims, CurrentUser, verify_token};
pub use errors::{AuthError, AuthResult};
pub use response::{ApiResponse, EmptyResponse};

#[cfg(feature = "actix")]
pub use middleware::{
    AuthenticatedUser, OptionalUser, firebase_auth_middleware, firebase_signature_middleware,
    optional_firebase_auth_middleware,
};
