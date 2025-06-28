//! Fast domain validation dev route handler
//!
//! This module contains the JWT-protected fast validation endpoint that includes
//! performance metrics for developer debugging and monitoring.

use crate::{api_handler::{extract_domain_from_input, *}, auth::Claims, AppState};
use axum::{
    extract::{Query, State},
    response::Json,
};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

/// GET /v1/fast-validate-dev?domain=example.com
///
/// Protected fast domain validation endpoint with performance metrics.
/// Requires JWT authentication with valid Bearer token.
///
/// Performs essential domain validation for real-time use cases with detailed metrics:
/// - Domain format validation
/// - Disposable domain detection (Bloom filter - very fast)
/// - Basic DNS existence check (A records only)
/// - Performance timing and cache hit information
///
/// # Authentication
/// Requires JWT Bearer token in Authorization header.
/// Use /auth/login endpoint to obtain a valid token.
///
/// # Performance
/// Optimized for speed with ~10-50ms response times, same as regular fast validation
/// but includes detailed performance metrics for debugging.
#[instrument(skip(state, claims), fields(domain = %query.domain, request_id, username = %claims.sub))]
pub async fn fast_validate_dev_domain_handler(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    Query(query): Query<ValidateQuery>,
) -> ApiResult<FastValidateDevResponse> {
    let request_id = Uuid::new_v4().to_string();
    tracing::Span::current().record("request_id", &request_id);

    info!("Fast validating domain (DEV): {} by user: {}", query.domain, claims.sub);
    
    let start_time = std::time::Instant::now();
    
    // Validate input
    if query.domain.trim().is_empty() {
        warn!("Empty domain provided");
        return Err(ApiError::InvalidDomain("Domain cannot be empty".to_string()));
    }

    if query.domain.len() > 253 {
        warn!("Domain too long: {} characters", query.domain.len());
        return Err(ApiError::InvalidDomain("Domain name too long (max 253 characters)".to_string()));
    }

    // Extract domain from email address if @ symbol is present
    let domain = extract_domain_from_input(&query.domain);
    
    // Log if domain was extracted from email
    if domain != query.domain {
        debug!("Extracted domain '{}' from email address '{}'", domain, query.domain);
    }

    // Perform fast validation
    let result = state
        .validation_pipeline
        .fast_validate_domain(domain)
        .await
        .map_err(ApiError::from)?;

    let processing_time = start_time.elapsed();
    
    debug!("Fast validation (DEV) completed in {:?}", processing_time);
    
    // Convert to API response with performance metrics
    let response = convert_fast_validation_dev_result(result, request_id, processing_time);
    
    info!(
        "Fast domain validation (DEV) completed: {} -> is_valid={}, is_disposable={} ({}ms) by user: {}",
        domain, response.is_valid, response.is_disposable, processing_time.as_millis(), claims.sub
    );

    Ok(Json(response))
}