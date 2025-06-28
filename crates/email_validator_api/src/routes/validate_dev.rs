//! Full domain validation dev route handlers
//!
//! This module contains the JWT-protected comprehensive validation endpoint that includes
//! performance metrics for developer debugging and monitoring.

use crate::{api_handler::{extract_domain_from_input, *}, auth::Claims, AppState};
use axum::{
    extract::{Query, State},
    response::Json,
};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

/// GET /v1/validate-dev?domain=example.com
///
/// Protected comprehensive domain validation endpoint with performance metrics.
/// Requires JWT authentication with valid Bearer token.
///
/// Performs comprehensive domain validation including:
/// - Domain format validation
/// - Disposable domain detection
/// - DNS record validation (A, AAAA, MX)
/// - Email authentication analysis (SPF, DKIM, DMARC)
/// - Typo detection against major providers
/// - Risk scoring
/// - Detailed performance metrics and cache hit information
///
/// # Authentication
/// Requires JWT Bearer token in Authorization header.
/// Use /auth/login endpoint to obtain a valid token.
///
/// # Performance
/// Typically responds within 50-200ms depending on DNS cache hits
/// and enabled features. Includes detailed timing information.
#[instrument(skip(state, claims), fields(domain = %query.domain, request_id, username = %claims.sub))]
pub async fn validate_dev_domain_handler(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    Query(query): Query<ValidateQuery>,
) -> ApiResult<ValidateDevResponse> {
    let request_id = Uuid::new_v4().to_string();
    tracing::Span::current().record("request_id", &request_id);

    info!("Validating domain (DEV): {} by user: {}", query.domain, claims.sub);
    
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

    // Perform validation
    let result = state
        .validation_pipeline
        .validate_domain(domain)
        .await
        .map_err(ApiError::from)?;

    let processing_time = start_time.elapsed();
    
    debug!("Validation (DEV) completed in {:?}", processing_time);
    
    // Convert to API response with performance metrics
    let response = convert_validation_dev_result(result, request_id, processing_time);
    
    info!(
        "Domain validation (DEV) completed: {} -> risk_level={:?}, risk_score={} ({}ms) by user: {}",
        domain, response.risk_level, response.risk_score, processing_time.as_millis(), claims.sub
    );

    Ok(Json(response))
}