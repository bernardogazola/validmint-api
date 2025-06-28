//! Full domain validation route handlers
//!
//! This module contains the complete validation endpoint that performs
//! comprehensive domain analysis including DNS checks, email authentication,
//! typo detection, and risk scoring.

use crate::{api_handler::{extract_domain_from_input, *}, AppState};
use axum::{
    extract::{Query, State},
    response::Json,
};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

/// GET /v1/validate?domain=example.com
///
/// Performs comprehensive domain validation including:
/// - Domain format validation
/// - Disposable domain detection
/// - DNS record validation (A, AAAA, MX)
/// - Email authentication analysis (SPF, DKIM, DMARC)
/// - Typo detection against major providers
/// - Risk scoring
///
/// # Performance
/// Typically responds within 50-200ms depending on DNS cache hits
/// and enabled features.
#[instrument(skip(state), fields(domain = %query.domain, request_id))]
pub async fn validate_domain_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ValidateQuery>,
) -> ApiResult<ValidateResponse> {
    let request_id = Uuid::new_v4().to_string();
    tracing::Span::current().record("request_id", &request_id);

    info!("Validating domain: {}", query.domain);
    
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

    // Perform validation on the extracted domain
    let result = state
        .validation_pipeline
        .validate_domain(domain)
        .await
        .map_err(ApiError::from)?;

    let processing_time = start_time.elapsed();
    
    debug!("Validation completed in {:?}", processing_time);
    
    // Convert to API response (without performance metrics)
    let response = convert_validation_result(result, request_id);
    
    info!(
        "Domain validation completed: {} -> risk_level={:?}, risk_score={}",
        domain, response.risk_level, response.risk_score
    );

    Ok(Json(response))
}