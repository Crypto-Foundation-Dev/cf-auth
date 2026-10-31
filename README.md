# cf-auth

A shared Rust library for Firebase Authentication, designed for use by multiple microservices.

## Features

- 🔐 **JWT Verification** - Verify Firebase ID tokens against Google's public keys
- 🗄️ **JWK Caching** - Automatic caching with 1-hour TTL and smart refresh
- 🌐 **Actix-web Middleware** - Optional feature flag for Actix integration
- ⚡ **Framework Agnostic** - Core auth logic works with any Rust framework

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
# Without Actix middleware
cf-auth = { git = "https://github.com/Crypto-Foundation-Dev/cf-auth.git" }

# With Actix middleware
cf-auth = { git = "https://github.com/Crypto-Foundation-Dev/cf-auth.git", features = ["actix"] }
```

## Environment Variables

| Variable              | Required | Description              |
| --------------------- | -------- | ------------------------ |
| `FIREBASE_PROJECT_ID` | Yes      | Your Firebase project ID |
| `FIREBASE_SIGNATURE`  | Only for `firebase_signature_middleware` | Expected `X-Firebase-Signature` value |

## Usage

### Basic Token Verification

```rust
use cf_auth::{verify_token, CurrentUser, AuthError};

async fn authenticate(token: &str) -> Result<CurrentUser, AuthError> {
    let claims = verify_token(token).await?;
    Ok(CurrentUser::from(claims))
}
```

### Actix-web Middleware

```rust
use actix_web::{web, App, HttpServer, middleware::from_fn};
use cf_auth::{firebase_auth_middleware, AuthenticatedUser};

async fn protected_handler(user: AuthenticatedUser) -> String {
    format!("Hello, {}!", user.uid)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(from_fn(firebase_auth_middleware))
            .route("/me", web::get().to(protected_handler))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

### Optional Authentication

For endpoints that work with or without auth:

```rust
use cf_auth::middleware::{optional_firebase_auth_middleware, OptionalUser};

async fn mixed_handler(user: OptionalUser) -> String {
    match user.0 {
        Some(u) => format!("Hello, {}!", u.uid),
        None => "Hello, anonymous!".to_string(),
    }
}
```

## API Reference

### Structs

| Struct              | Description                                   |
| ------------------- | --------------------------------------------- |
| `Claims`            | Full Firebase JWT payload                     |
| `CurrentUser`       | Lightweight user data extracted from claims   |
| `AuthenticatedUser` | Actix `FromRequest` extractor (requires auth) |
| `OptionalUser`      | Actix `FromRequest` extractor (optional auth) |

### Functions

| Function                       | Description                               |
| ------------------------------ | ----------------------------------------- |
| `verify_token(token)`          | Verify a Firebase ID token                |
| `extract_bearer_token(header)` | Extract token from `Authorization` header |
| `force_refresh_jwks()`         | Force refresh Google's public keys        |

### Middleware (Actix feature)

| Middleware                          | Description                        |
| ----------------------------------- | ---------------------------------- |
| `firebase_auth_middleware`          | Returns 401 if auth fails          |
| `optional_firebase_auth_middleware` | Continues without error if no auth |
| `firebase_signature_middleware`     | Returns 401 if signature fails     |

## Error Types

```rust
pub enum AuthError {
    MissingAuthHeader,
    InvalidAuthHeaderFormat,
    TokenExpired,
    InvalidSignature,
    IssuerMismatch { expected, actual },
    AudienceMismatch { expected, actual },
    MissingKeyId,
    KeyNotFound { kid },
    JwkFetchError(String),
    DecodeError(String),
    ConfigError(String),
}
```

## License

MIT
