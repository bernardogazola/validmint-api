//! Fast domain validation route handler
//!
//! This module contains the optimized validation endpoint that performs
//! only essential checks for maximum speed.

use crate::{api_handler::{extract_domain_from_input, *}, AppState};
use axum::{
    extract::{Query, State},
    response::Json,
};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

/// GET /v1/fast-validate?domain=example.com
///
/// Performs essential domain validation for real-time use cases:
/// - Domain format validation
/// - Disposable domain detection (Bloom filter - very fast)
/// - Basic DNS existence check (A records only)
///
/// # Performance
/// Optimized for speed with ~10-50ms response times. Ideal for:
/// - Real-time form validation
/// - User registration flows
/// - High-volume validation scenarios
/// - Mobile applications with limited bandwidth
///
/// # Trade-offs
/// This endpoint skips several checks for speed:
/// - No MX record validation
/// - No email authentication analysis (SPF/DKIM/DMARC)
/// - No typo detection
/// - No risk scoring
/// - No SMTP probing
#[instrument(skip(state), fields(domain = %query.domain, request_id))]
pub async fn fast_validate_domain_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ValidateQuery>,
) -> ApiResult<FastValidateResponse> {
    let request_id = Uuid::new_v4().to_string();
    tracing::Span::current().record("request_id", &request_id);

    info!("Fast validating domain: {}", query.domain);
    
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

    // Perform fast validation on the extracted domain
    let result = state
        .validation_pipeline
        .fast_validate_domain(domain)
        .await
        .map_err(ApiError::from)?;

    let processing_time = start_time.elapsed();
    
    debug!("Fast validation completed in {:?}", processing_time);
    
    // Convert to API response
    let response = convert_fast_validation_result(result, request_id);
    
    info!(
        "Fast domain validation completed: {} -> is_valid={}, is_disposable={} ({}ms)",
        domain, response.is_valid, response.is_disposable, processing_time.as_millis()
    );

    Ok(Json(response))
}