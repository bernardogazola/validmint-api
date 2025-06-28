//! Email Domain Validation API Server
//!
//! High-performance email domain validation API built with axum and tokio.
//! Designed for deployment on RapidAPI with sub-20ms p99 latency.

use axum::Router;
use email_core::{ValidationConfig, ValidationPipeline};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::{info, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api_handler;
mod auth;
mod config;
mod middleware;
mod routes;

use config::*;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub validation_pipeline: Arc<ValidationPipeline>,
    pub config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = load_config()?;
    
    // Initialize tracing/logging
    init_tracing(&config)?;
    
    info!("Starting Email Domain Validation API v{}", env!("CARGO_PKG_VERSION"));
    info!("Configuration loaded: {}", config.server.host);
    
    // Initialize validation pipeline
    let validation_config = ValidationConfig {
        dns_timeout_ms: config.validation.dns_timeout_ms,
        dns_attempts: config.validation.dns_attempts,
        dns_cache_size: config.validation.dns_cache_size,
        dns_min_ttl_secs: config.validation.dns_min_ttl_secs,
        bloom_filter_fp_rate: config.validation.bloom_filter_fp_rate,
        enable_smtp_probe: config.validation.enable_smtp_probe,
        enable_dmarc_analysis: config.validation.enable_dmarc_analysis,
    };
    
    let validation_pipeline = ValidationPipeline::new(validation_config)
        .await
        .map_err(|e| format!("Failed to initialize validation pipeline: {}", e))?;
    
    let pipeline_stats = validation_pipeline.get_stats();
    info!(
        "Pipeline initialized - {} disposable domains, {} MB memory, {} providers",
        pipeline_stats.disposable_domains_count,
        pipeline_stats.disposable_filter_memory_bytes / 1024 / 1024,
        pipeline_stats.typo_providers_count
    );
    
    // Create shared application state
    let app_state = AppState {
        validation_pipeline: Arc::new(validation_pipeline),
        config: Arc::new(config.clone()),
    };
    
    // Build the router
    let app = create_router(app_state);
    
    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    info!("Server listening on {}", addr);
    info!("Health check available at http://{}/health", addr);
    info!("Metrics available at http://{}/metrics", addr);
    info!("Full validation API: http://{}/v1/validate", addr);
    info!("Fast validation API: http://{}/v1/fast-validate", addr);
    
    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    
    info!("Server shut down gracefully");
    Ok(())
}

/// Create the main application router
fn create_router(state: AppState) -> Router {
    // Use the new routes module to build all routes
    let mut router = routes::build_routes(Arc::new(state));
    
    // Add middleware layers
    router = router
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
        )
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers(tower_http::cors::Any)
        )
        .layer(CompressionLayer::new());
    
    router
}

/// Load application configuration from environment and files
fn load_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    // Start with a base configuration using defaults
    let mut figment = Figment::from(Serialized::defaults(AppConfig::default()));
    
    // Try to load config file if it exists (optional)
    if std::path::Path::new("Config.toml").exists() {
        figment = figment.merge(Toml::file("Config.toml"));
    }
    
    // Override with environment variables
    figment = figment.merge(Env::prefixed("EMAIL_API_").split("_"));
    
    let config: AppConfig = figment.extract()?;
    
    Ok(config)
}

/// Initialize tracing and logging
fn init_tracing(config: &AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_PKG_NAME")).into());
    
    if config.observability.json_logs {
        // JSON format for production
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        // Human-readable format for development
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
    
    Ok(())
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, starting graceful shutdown");
        },
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown");
        },
    }
}

