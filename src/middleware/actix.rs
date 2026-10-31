//! Actix-web middleware for Firebase Authentication
//!
//! This module is only available when the `actix` feature is enabled.

use crate::auth::{CurrentUser, extract_bearer_token, verify_token};
use crate::errors::AuthError;
use crate::response::ApiResponse;

use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header::AUTHORIZATION,
};
use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload};

/// Firebase Auth middleware function for use with `actix_web::middleware::from_fn`
///
/// # Usage
/// ```rust,ignore
/// use actix_web::{web, App, HttpServer, middleware::from_fn};
/// use cf_auth::middleware::firebase_auth_middleware;
///
/// HttpServer::new(|| {
///     App::new()
///         .wrap(from_fn(firebase_auth_middleware))
///         .route("/protected", web::get().to(protected_handler))
/// })
/// ```
pub async fn firebase_auth_middleware(
    req: ServiceRequest,
    next: actix_web::middleware::Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // Extract Authorization header
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let auth_header = match auth_header {
        Some(h) => h,
        None => {
            let response = HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Missing Authorization header"));
            return Ok(req.into_response(response).map_into_boxed_body());
        }
    };

    // Parse Bearer token
    let token = match extract_bearer_token(auth_header) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Invalid auth header format: {}", e);
            let response =
                HttpResponse::Unauthorized().json(ApiResponse::<()>::error(e.to_string()));
            return Ok(req.into_response(response).map_into_boxed_body());
        }
    };

    // Verify token
    let claims = match verify_token(token).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Token verification failed: {}", e);
            let (status, message) = match &e {
                AuthError::TokenExpired => {
                    (actix_web::http::StatusCode::UNAUTHORIZED, "Token expired")
                }
                AuthError::InvalidSignature => {
                    (actix_web::http::StatusCode::UNAUTHORIZED, "Invalid token")
                }
                AuthError::KeyNotFound { .. } | AuthError::JwkFetchError(_) => (
                    actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Authentication service error",
                ),
                _ => (
                    actix_web::http::StatusCode::UNAUTHORIZED,
                    "Authentication failed",
                ),
            };
            let response = HttpResponse::build(status)
                .json(ApiResponse::<()>::error(format!("{} - {}", message, e)));
            return Ok(req.into_response(response).map_into_boxed_body());
        }
    };

    // Create CurrentUser and insert into extensions
    let current_user = CurrentUser::from(claims);
    tracing::debug!("Authenticated user: {}", current_user.uid);

    req.extensions_mut().insert(current_user);

    // Call next handler and map to boxed body for consistent return type
    next.call(req).await.map(|res| res.map_into_boxed_body())
}

/// Firebase middleware with X-Firebase-Signature header validation
///
/// Reusable accross multiple endpoint that needed the signature
///
/// # Usage
/// ```rust,ignore
/// use actix_web::web;
/// use cf_auth::middleware::firebase_signature_middleware;
///
/// let app = App::new()
///     .wrap(firebase_signature_middleware)
///     .service(web::scope("/api").service(web::get().to(handler)))
/// ```

pub async fn firebase_signature_middleware(
    req: ServiceRequest,
    next: actix_web::middleware::Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    use subtle::ConstantTimeEq;

    let expected_secret = match std::env::var("FIREBASE_SIGNATURE") {
        Ok(secret) if !secret.is_empty() => secret,
        Ok(_) => {
            tracing::error!("FIREBASE_SIGNATURE environment variable is empty");
            let response = HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                "Authentication service configuration error",
            ));
            return Ok(req.into_response(response).map_into_boxed_body());
        }
        Err(_) => {
            tracing::error!("FIREBASE_SIGNATURE environment variable not configured");
            let response = HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                "Authentication service configuration error",
            ));
            return Ok(req.into_response(response).map_into_boxed_body());
        }
    };

    // Extract X-Firebase-Signature header
    let signature = req
        .headers()
        .get("X-Firebase-Signature")
        .and_then(|h| h.to_str().ok());

    match signature {
        Some(sig) => {
            let sig_bytes = sig.as_bytes();
            let expected_bytes = expected_secret.as_bytes();

            if sig_bytes.len() == expected_bytes.len() && sig_bytes.ct_eq(expected_bytes).into() {
                tracing::debug!("Firebase signature validation successful");
                next.call(req).await.map(|res| res.map_into_boxed_body())
            } else {
                tracing::warn!("Invalid X-Firebase-Signature");
                let response = HttpResponse::Unauthorized()
                    .json(ApiResponse::<()>::error("Invalid X-Firebase-Signature"));
                Ok(req.into_response(response).map_into_boxed_body())
            }
        }
        None => {
            tracing::warn!("Missing X-Firebase-Signature header");
            let response = HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Missing X-Firebase-Signature"));
            Ok(req.into_response(response).map_into_boxed_body())
        }
    }
}

/// Optional auth middleware
///
/// Behavior:
/// - No Authorization header: Proceeds as anonymous (no CurrentUser extension)
/// - Valid Bearer token: Proceeds as authenticated (CurrentUser extension added)
/// - Invalid Bearer token: Returns 401 Unauthorized
///
/// Useful for public endpoints that have optional user-specific functionality.
pub async fn optional_firebase_auth_middleware(
    req: ServiceRequest,
    next: actix_web::middleware::Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // Try to get auth header
    if let Some(auth_header) = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        // If present, try to validate
        match extract_bearer_token(auth_header) {
            Ok(token) => match verify_token(token).await {
                Ok(claims) => {
                    let current_user = CurrentUser::from(claims);
                    tracing::debug!("Optional auth: authenticated user {}", current_user.uid);
                    req.extensions_mut().insert(current_user);
                }
                Err(e) => {
                    tracing::warn!("Optional auth: token validation failed: {}", e);
                    let (status, message) = match &e {
                        AuthError::TokenExpired => {
                            (actix_web::http::StatusCode::UNAUTHORIZED, "Token expired")
                        }
                        AuthError::InvalidSignature => {
                            (actix_web::http::StatusCode::UNAUTHORIZED, "Invalid token")
                        }
                        AuthError::KeyNotFound { .. } | AuthError::JwkFetchError(_) => (
                            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                            "Authentication service error",
                        ),
                        _ => (
                            actix_web::http::StatusCode::UNAUTHORIZED,
                            "Authentication failed",
                        ),
                    };
                    let response = HttpResponse::build(status)
                        .json(ApiResponse::<()>::error(format!("{} - {}", message, e)));
                    return Ok(req.into_response(response).map_into_boxed_body());
                }
            },
            Err(e) => {
                // If header is present but not a valid Bearer token, we might choose to ignore or reject.
                // Given "optional" usually implies "if you try to auth, do it right", rejecting bad formats is safer.
                // However, some might argue if it's not Bearer it's not for us.
                // But extract_bearer_token returns error if it looks like a bearer token but is empty or malformed.
                // If it doesn't start with Bearer, it returns InvalidAuthHeaderFormat.

                // Let's stick to the plan: "If it looks like a token, validate it".
                // If it's "Basic ...", extract_bearer_token errors.
                // If we want to support other auth schemes co-existing, we should check if it starts with Bearer first.

                // Re-reading extract_bearer_token: it checks prefix.
                // If I send "Basic xyz", extract_bearer_token returns Err.
                // If the user intends to warn about ANY bad auth header, we return 401.
                // If we want to allow other schemes to be ignored, we should check prefix.

                // For now, consistent with strict optional auth:
                // If Authorization header is present, it MUST be valid.
                tracing::warn!("Optional auth: invalid auth header format: {}", e);
                let response =
                    HttpResponse::Unauthorized().json(ApiResponse::<()>::error(e.to_string()));
                return Ok(req.into_response(response).map_into_boxed_body());
            }
        }
    }

    // Continue as anonymous (no token provided or token valid)
    next.call(req).await.map(|res| res.map_into_boxed_body())
}

/// Extractor for CurrentUser from request
///
/// # Usage
/// ```rust,ignore
/// use actix_web::web;
/// use cf_auth::middleware::AuthenticatedUser;
///
/// async fn protected_handler(user: AuthenticatedUser) -> impl Responder {
///     format!("Hello, {}", user.uid)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub CurrentUser);

impl std::ops::Deref for AuthenticatedUser {
    type Target = CurrentUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let user = req.extensions().get::<CurrentUser>().cloned();

        match user {
            Some(u) => ready(Ok(AuthenticatedUser(u))),
            None => {
                let body =
                    serde_json::to_string(&ApiResponse::<()>::error("Authentication required"))
                        .unwrap_or_else(|_| {
                            r#"{"data":null,"message":"Authentication required","status":false}"#
                                .to_string()
                        });
                ready(Err(actix_web::error::InternalError::from_response(
                    "Authentication required",
                    HttpResponse::Unauthorized()
                        .content_type("application/json")
                        .body(body),
                )
                .into()))
            }
        }
    }
}

/// Optional extractor - returns Option<CurrentUser>
///
/// Use this when authentication is optional for an endpoint.
#[derive(Debug, Clone)]
pub struct OptionalUser(pub Option<CurrentUser>);

impl std::ops::Deref for OptionalUser {
    type Target = Option<CurrentUser>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for OptionalUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let user = req.extensions().get::<CurrentUser>().cloned();
        ready(Ok(OptionalUser(user)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};

    #[actix_web::test]
    async fn test_optional_auth_invalid_token_rejects() {
        let app = test::init_service(
            App::new()
                .wrap(actix_web::middleware::from_fn(
                    optional_firebase_auth_middleware,
                ))
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                "Bearer invalid_token",
            ))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
