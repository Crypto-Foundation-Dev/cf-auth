use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub auth_time: u64,

    // Firebase specific claims
    #[serde(default)]
    pub email: String,

    #[serde(default)]
    pub email_verified: bool,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub picture: Option<String>,

    #[serde(default)]
    pub user_id: Option<String>,

    #[serde(default)]
    pub firebase: Option<FirebaseClaims>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirebaseClaims {
    pub sign_in_provider: Option<String>,
    pub identities: Option<serde_json::Value>,
}

/// Lightweight user struct extracted from Claims
/// Used for request extensions in middleware
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub uid: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub sign_in_provider: Option<String>,
}

impl From<Claims> for CurrentUser {
    fn from(claims: Claims) -> Self {
        CurrentUser {
            uid: claims.sub,
            email: if claims.email.is_empty() {
                None
            } else {
                Some(claims.email)
            },
            email_verified: claims.email_verified,
            name: claims.name,
            picture: claims.picture,
            sign_in_provider: claims.firebase.and_then(|f| f.sign_in_provider),
        }
    }
}
