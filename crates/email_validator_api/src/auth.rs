//! JWT Authentication module for developer endpoints
//!
//! This module provides JWT-based authentication for protected developer routes
//! that expose performance metrics and additional debugging information.

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::LazyLock;
use tracing::{debug, warn};

/// JWT Keys for encoding and decoding tokens
static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (username)
    pub sub: String,
    /// Issuer (our service)
    pub iss: String,
    /// Expiry time as UTC timestamp
    pub exp: usize,
    /// Issued at time as UTC timestamp
    pub iat: usize,
}

/// Authentication payload for login
#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

/// Authentication response with token
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: usize,
}

/// Authentication errors
#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    ExpiredToken,
}

/// JWT encoding/decoding keys
struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

impl Claims {
    /// Create new claims for a user
    pub fn new(username: String) -> Self {
        let now = chrono::Utc::now().timestamp() as usize;
        let exp = now + 3600; // 1 hour expiry
        
        Self {
            sub: username,
            iss: "email-validator-api".to_string(),
            exp,
            iat: now,
        }
    }

    /// Create a JWT token from these claims
    pub fn to_token(&self) -> Result<String, AuthError> {
        encode(&Header::default(), self, &KEYS.encoding)
            .map_err(|e| {
                warn!("Failed to create JWT token: {}", e);
                AuthError::TokenCreation
            })
    }
}

impl AuthResponse {
    pub fn new(token: String) -> Self {
        Self {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: 3600, // 1 hour
        }
    }
}

/// Extract and validate JWT claims from request headers
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let token = parts
            .headers
            .get("authorization")
            .and_then(|header| header.to_str().ok())
            .and_then(|header| {
                if header.starts_with("Bearer ") {
                    Some(&header[7..])
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                debug!("Missing or invalid Authorization header");
                AuthError::InvalidToken
            })?;

        // Decode the token
        let token_data = decode::<Claims>(token, &KEYS.decoding, &Validation::default())
            .map_err(|e| {
                warn!("Failed to decode JWT token: {}", e);
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                    _ => AuthError::InvalidToken,
                }
            })?;

        // Check if token is expired (additional check)
        let now = chrono::Utc::now().timestamp() as usize;
        if token_data.claims.exp < now {
            warn!("Token expired: exp={}, now={}", token_data.claims.exp, now);
            return Err(AuthError::ExpiredToken);
        }

        debug!("Valid JWT token for user: {}", token_data.claims.sub);
        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Invalid username or password", "INVALID_CREDENTIALS"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Username and password are required", "MISSING_CREDENTIALS"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create authentication token", "TOKEN_CREATION_ERROR"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid or malformed authentication token", "INVALID_TOKEN"),
            AuthError::ExpiredToken => (StatusCode::UNAUTHORIZED, "Authentication token has expired", "EXPIRED_TOKEN"),
        };

        let body = Json(json!({
            "error": error_message,
            "error_code": error_code,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }));

        (status, body).into_response()
    }
}

/// Validate credentials against environment variables
pub fn validate_credentials(username: &str, password: &str) -> Result<(), AuthError> {
    let expected_username = std::env::var("JWT_DEV_USERNAME")
        .map_err(|_| {
            warn!("JWT_DEV_USERNAME environment variable not set");
            AuthError::MissingCredentials
        })?;

    let expected_password = std::env::var("JWT_DEV_PASSWORD")
        .map_err(|_| {
            warn!("JWT_DEV_PASSWORD environment variable not set");
            AuthError::MissingCredentials
        })?;

    if username != expected_username || password != expected_password {
        warn!("Invalid credentials provided for username: {}", username);
        return Err(AuthError::WrongCredentials);
    }

    debug!("Credentials validated for user: {}", username);
    Ok(())
}

/// Create an authentication token for valid credentials
pub async fn authenticate(Json(payload): Json<AuthPayload>) -> Result<Json<AuthResponse>, AuthError> {
    // Validate required fields
    if payload.username.is_empty() || payload.password.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    // Validate credentials against environment variables
    validate_credentials(&payload.username, &payload.password)?;

    // Create JWT claims
    let claims = Claims::new(payload.username.clone());

    // Generate token
    let token = claims.to_token()?;

    debug!("Generated authentication token for user: {}", payload.username);

    // Return response
    Ok(Json(AuthResponse::new(token)))
}

/// Authentication middleware for protecting routes
/// 
/// This middleware validates JWT tokens and extracts claims for protected routes.
/// It only applies to routes that require authentication (dev endpoints).
pub async fn auth_middleware<S>(
    State(_state): State<std::sync::Arc<crate::AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AuthError>
where
    S: Send + Sync,
{
    // Extract the token from the authorization header
    let token = req
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| {
            if header.starts_with("Bearer ") {
                Some(&header[7..])
            } else {
                None
            }
        })
        .ok_or_else(|| {
            debug!("Missing or invalid Authorization header");
            AuthError::InvalidToken
        })?;

    // Decode the token
    let token_data = decode::<Claims>(token, &KEYS.decoding, &Validation::default())
        .map_err(|e| {
            warn!("Failed to decode JWT token: {}", e);
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                _ => AuthError::InvalidToken,
            }
        })?;

    // Check if token is expired (additional check)
    let now = chrono::Utc::now().timestamp() as usize;
    if token_data.claims.exp < now {
        warn!("Token expired: exp={}, now={}", token_data.claims.exp, now);
        return Err(AuthError::ExpiredToken);
    }

    debug!("Valid JWT token for user: {}", token_data.claims.sub);

    // Insert claims into request extensions so handlers can access them
    req.extensions_mut().insert(token_data.claims);

    // Continue to the next handler
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_creation() {
        let claims = Claims::new("testuser".to_string());
        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.iss, "email-validator-api");
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_auth_response_creation() {
        let response = AuthResponse::new("test_token".to_string());
        assert_eq!(response.access_token, "test_token");
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 3600);
    }
}