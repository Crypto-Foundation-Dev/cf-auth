//! Middleware implementations for Firebase Authentication
//!
//! Currently supports:
//! - Actix-web (via `actix` feature flag)
//!
//! # Feature Flags
//!
//! - `actix`: Enables Actix-web middleware

#[cfg(feature = "actix")]
pub mod actix;

#[cfg(feature = "actix")]
pub use self::actix::{
    AuthenticatedUser, OptionalUser, firebase_auth_middleware, firebase_signature_middleware,
    optional_firebase_auth_middleware,
};
