//! API Routes Module
//!
//! This module organizes all HTTP endpoints into logical groups:
//! - `validate`: Full domain validation endpoints
//! - `fast_validate`: Optimized validation endpoints
//! - `validate_dev`: JWT-protected full validation with performance metrics
//! - `fast_validate_dev`: JWT-protected fast validation with performance metrics
//! - `auth`: Authentication endpoints for obtaining JWT tokens
//! - `health`: Health checks and monitoring endpoints

pub mod auth;
pub mod fast_validate;
pub mod fast_validate_dev;
pub mod health;
pub mod validate;
pub mod validate_dev;

use crate::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

/// Build all API routes and return a configured Router
///
/// This function sets up all the application routes with their handlers
/// and applies the shared application state.
pub fn build_routes(state: Arc<AppState>) -> Router {
    Router::new()
        // Authentication endpoints
        .route("/auth/login", post(auth::login_handler))
        
        // Public validation endpoints
        .route("/v1/validate", get(validate::validate_domain_handler))
        .route("/v1/fast-validate", get(fast_validate::fast_validate_domain_handler))
        
        // JWT-protected developer endpoints with performance metrics
        .route("/v1/validate-dev", get(validate_dev::validate_dev_domain_handler))
        .route("/v1/fast-validate-dev", get(fast_validate_dev::fast_validate_dev_domain_handler))
        
        // Health and monitoring endpoints
        .route("/health", get(health::health_handler))
        .route("/ready", get(health::ready_handler))
        .route("/metrics", get(health::metrics_handler))
        
        // Administrative endpoints
        .route("/admin/stats", get(health::stats_handler))
        .route("/admin/cache/clear", post(health::clear_cache_handler))
        
        // Apply shared state to all routes
        .with_state(state)
}

/// API version information
#[allow(dead_code)]
pub const API_VERSION: &str = "v1";

/// Maximum allowed domain length
#[allow(dead_code)]
pub const MAX_DOMAIN_LENGTH: usize = 253;

/// Default request timeout in seconds
#[allow(dead_code)]
pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;