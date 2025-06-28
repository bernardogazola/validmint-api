//! Authentication route handlers
//!
//! This module contains the JWT authentication endpoints for obtaining
//! access tokens for protected developer routes.

use crate::{api_handler::*, auth::Claims, AppState};
use axum::{
    extract::State,
    response::Json,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

/// Login request structure
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: String,
}

/// Login response structure
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// JWT access token
    pub access_token: String,
    /// Token type (always "Bearer")
    pub token_type: String,
    /// Token expiration time in seconds
    pub expires_in: u64,
}

/// POST /auth/login
///
/// Authenticate with username/password and receive a JWT access token.
/// The token can be used to access protected developer endpoints.
///
/// # Authentication
/// Uses environment variables:
/// - JWT_DEV_USERNAME: Expected username
/// - JWT_DEV_PASSWORD: Expected password
/// - JWT_SECRET: Secret key for signing tokens
///
/// # Token Validity
/// Tokens are valid for 24 hours (86400 seconds).
pub async fn login_handler(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<LoginResponse> {
    info!("Login attempt for username: {}", request.username);
    
    // Get credentials from environment
    let expected_username = std::env::var("JWT_DEV_USERNAME")
        .map_err(|_| ApiError::InternalError("JWT_DEV_USERNAME not configured".to_string()))?;
    let expected_password = std::env::var("JWT_DEV_PASSWORD")
        .map_err(|_| ApiError::InternalError("JWT_DEV_PASSWORD not configured".to_string()))?;
    let jwt_secret = std::env::var("JWT_SECRET")
        .map_err(|_| ApiError::InternalError("JWT_SECRET not configured".to_string()))?;
    
    // Verify credentials
    if request.username != expected_username || request.password != expected_password {
        warn!("Invalid login attempt for username: {}", request.username);
        return Err(ApiError::ValidationFailed("Invalid credentials".to_string()));
    }
    
    // Create JWT claims
    let now = chrono::Utc::now();
    let expires_in = 31556952; // 1 year in seconds
    let exp = now + chrono::Duration::seconds(expires_in as i64);
    
    let claims = Claims {
        sub: request.username.clone(),
        iss: "email-validator-api".to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    
    // Create JWT token
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|e| ApiError::InternalError(format!("Failed to create token: {}", e)))?;
    
    info!("Successful login for username: {}", request.username);
    
    Ok(Json(LoginResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: expires_in,
    }))
}