//! Standardized API response wrapper
//!
//! Provides a consistent response format across all endpoints:
//! ```json
//! { "data": ..., "message": "...", "status": true/false }
//! ```

use serde::Serialize;

/// Standardized API response wrapper
///
/// # Example
/// ```rust
/// use cf_auth::response::ApiResponse;
///
/// // Success response with data
/// let success = ApiResponse::success("user_data", "User retrieved successfully");
///
/// // Error response
/// let error = ApiResponse::<()>::error("Authentication failed");
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: Option<T>,
    pub message: String,
    pub status: bool,
}

impl<T: Serialize> ApiResponse<T> {
    /// Create a success response with data
    pub fn success(data: T, message: impl Into<String>) -> Self {
        Self {
            data: Some(data),
            message: message.into(),
            status: true,
        }
    }

    /// Create an error response (no data)
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            data: None,
            message: message.into(),
            status: false,
        }
    }
}

/// Convenience type for responses without data payload
pub type EmptyResponse = ApiResponse<()>;
