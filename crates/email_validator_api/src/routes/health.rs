//! Health check and monitoring routes
//!
//! This module contains endpoints for service health checks, readiness probes,
//! and monitoring metrics.

use crate::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::Serialize;
use std::sync::Arc;
use tracing::{info, warn};

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: std::time::SystemTime,
}

/// Health check endpoint - GET /health
///
/// Simple health check to verify the API is running.
/// Returns 200 OK with service information.
pub async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: std::time::SystemTime::now(),
    })
}

/// Readiness response
#[derive(Serialize)]
pub struct ReadinessResponse {
    pub ready: bool,
    pub timestamp: std::time::SystemTime,
}

/// Readiness check endpoint - GET /ready
///
/// Verifies the service is ready to handle requests by performing
/// a quick validation to ensure the pipeline is working.
pub async fn ready_handler(State(state): State<Arc<AppState>>) -> Json<ReadinessResponse> {
    // Perform a quick validation to ensure the pipeline is working
    let is_ready = match state.validation_pipeline.validate_domain("test.com").await {
        Ok(_) => true,
        Err(e) => {
            warn!("Readiness check failed: {}", e);
            false
        }
    };
    
    Json(ReadinessResponse {
        ready: is_ready,
        timestamp: std::time::SystemTime::now(),
    })
}

/// Metrics endpoint - GET /metrics
///
/// Returns Prometheus-compatible metrics for monitoring.
pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> (StatusCode, String) {
    let stats = state.validation_pipeline.get_stats();
    
    let metrics = format!(
        "# HELP email_validator_disposable_domains_total Total number of disposable domains in filter\n\
         # TYPE email_validator_disposable_domains_total gauge\n\
         email_validator_disposable_domains_total {}\n\
         \n\
         # HELP email_validator_filter_memory_bytes Memory usage of disposable domain filter\n\
         # TYPE email_validator_filter_memory_bytes gauge\n\
         email_validator_filter_memory_bytes {}\n\
         \n\
         # HELP email_validator_typo_providers_total Total number of typo detection providers\n\
         # TYPE email_validator_typo_providers_total gauge\n\
         email_validator_typo_providers_total {}\n\
         \n\
         # HELP email_validator_build_info Build information\n\
         # TYPE email_validator_build_info gauge\n\
         email_validator_build_info{{version=\"{}\"}} 1\n",
        stats.disposable_domains_count,
        stats.disposable_filter_memory_bytes,
        stats.typo_providers_count,
        env!("CARGO_PKG_VERSION")
    );
    
    (StatusCode::OK, metrics)
}

/// Statistics response
#[derive(Serialize)]
pub struct StatsResponse {
    pub version: String,
    pub pipeline_stats: email_core::validation_pipeline::PipelineStats,
    pub timestamp: std::time::SystemTime,
}

/// Statistics endpoint - GET /admin/stats
///
/// Returns detailed statistics about the validation pipeline.
pub async fn stats_handler(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let pipeline_stats = state.validation_pipeline.get_stats();
    
    Json(StatsResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pipeline_stats,
        timestamp: std::time::SystemTime::now(),
    })
}

/// Cache response
#[derive(Serialize)]
pub struct CacheResponse {
    pub message: String,
    pub timestamp: std::time::SystemTime,
}

/// Cache clearing endpoint - POST /admin/cache/clear
///
/// Clears the DNS cache for administrative purposes.
pub async fn clear_cache_handler(State(state): State<Arc<AppState>>) -> Json<CacheResponse> {
    state.validation_pipeline.clear_dns_cache();
    
    info!("DNS cache cleared by admin request");
    
    Json(CacheResponse {
        message: "DNS cache cleared successfully".to_string(),
        timestamp: std::time::SystemTime::now(),
    })
}