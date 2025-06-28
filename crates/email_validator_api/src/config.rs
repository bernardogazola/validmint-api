//! Configuration management for the email validation API
//!
//! This module handles loading configuration from environment variables
//! and configuration files using the figment crate.

use serde::{Deserialize, Serialize};

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub validation: ValidationConfig,
    pub observability: ObservabilityConfig,
    pub security: SecurityConfig,
}


/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host address
    pub host: String,
    /// Server port
    pub port: u16,
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Enable graceful shutdown
    pub graceful_shutdown: bool,
    /// Graceful shutdown timeout in seconds
    pub shutdown_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            max_connections: 1000,
            request_timeout_secs: 30,
            graceful_shutdown: true,
            shutdown_timeout_secs: 30,
        }
    }
}

/// Validation pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// DNS resolver timeout in milliseconds
    pub dns_timeout_ms: u64,
    /// Maximum number of DNS lookup attempts
    pub dns_attempts: usize,
    /// DNS cache size (number of entries)
    pub dns_cache_size: usize,
    /// Minimum TTL for positive DNS cache entries in seconds
    pub dns_min_ttl_secs: u64,
    /// Bloom filter false positive rate
    pub bloom_filter_fp_rate: f64,
    /// Enable SMTP connection probing
    pub enable_smtp_probe: bool,
    /// Enable full DMARC/SPF/DKIM analysis
    pub enable_dmarc_analysis: bool,
    /// SMTP probe timeout in milliseconds
    pub smtp_timeout_ms: u64,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            dns_timeout_ms: 500,
            dns_attempts: 2,
            dns_cache_size: 10_000,
            dns_min_ttl_secs: 60,
            bloom_filter_fp_rate: 0.0001, // 0.01%
            enable_smtp_probe: cfg!(feature = "smtp_probe"),
            enable_dmarc_analysis: cfg!(feature = "dmarc"),
            smtp_timeout_ms: 2000,
        }
    }
}

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Enable JSON structured logging
    pub json_logs: bool,
    /// Log level filter
    pub log_level: String,
    /// Enable OpenTelemetry tracing
    pub enable_tracing: bool,
    /// OTLP endpoint for traces
    pub otlp_endpoint: Option<String>,
    /// Service name for tracing
    pub service_name: String,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Metrics namespace
    pub metrics_namespace: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            json_logs: false,
            log_level: "info".to_string(),
            enable_tracing: true,
            otlp_endpoint: None,
            service_name: "email-validator-api".to_string(),
            enable_metrics: true,
            metrics_namespace: "email_validator".to_string(),
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable rate limiting (local, in addition to RapidAPI)
    pub enable_rate_limiting: bool,
    /// Rate limit: requests per minute per IP
    pub rate_limit_rpm: u32,
    /// Rate limit: burst size
    pub rate_limit_burst: u32,
    /// Enable request body size limits
    pub enable_body_limits: bool,
    /// Maximum request body size in bytes
    pub max_body_size_bytes: usize,
    /// Enable CORS
    pub enable_cors: bool,
    /// Allowed CORS origins (empty = allow all)
    pub cors_origins: Vec<String>,
    /// Privacy salt for hashing (base64 encoded)
    pub privacy_salt: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_rate_limiting: false, // Disabled by default since RapidAPI handles this
            rate_limit_rpm: 60,
            rate_limit_burst: 10,
            enable_body_limits: true,
            max_body_size_bytes: 1024, // 1KB should be enough for domain names
            enable_cors: true,
            cors_origins: Vec::new(), // Allow all origins by default
            privacy_salt: None, // Should be set in production
        }
    }
}

/// Environment variable names for configuration
#[allow(dead_code)]
pub mod env_vars {
    pub const SERVER_HOST: &str = "EMAIL_API_SERVER_HOST";
    pub const SERVER_PORT: &str = "EMAIL_API_SERVER_PORT";
    pub const DNS_TIMEOUT_MS: &str = "EMAIL_API_DNS_TIMEOUT_MS";
    pub const DNS_CACHE_SIZE: &str = "EMAIL_API_DNS_CACHE_SIZE";
    pub const ENABLE_SMTP_PROBE: &str = "EMAIL_API_ENABLE_SMTP_PROBE";
    pub const ENABLE_DMARC_ANALYSIS: &str = "EMAIL_API_ENABLE_DMARC_ANALYSIS";
    pub const JSON_LOGS: &str = "EMAIL_API_JSON_LOGS";
    pub const LOG_LEVEL: &str = "EMAIL_API_LOG_LEVEL";
    pub const OTLP_ENDPOINT: &str = "EMAIL_API_OTLP_ENDPOINT";
    pub const PRIVACY_SALT: &str = "EMAIL_API_PRIVACY_SALT";
    pub const RATE_LIMIT_RPM: &str = "EMAIL_API_RATE_LIMIT_RPM";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.validation.dns_timeout_ms, 500);
        assert!(!config.observability.json_logs);
        assert!(!config.security.enable_rate_limiting);
    }

    #[test]
    fn test_validation_config_defaults() {
        let config = ValidationConfig::default();
        assert_eq!(config.dns_attempts, 2);
        assert_eq!(config.dns_cache_size, 10_000);
        assert_eq!(config.bloom_filter_fp_rate, 0.0001);
    }

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(!config.enable_rate_limiting);
        assert_eq!(config.rate_limit_rpm, 60);
        assert_eq!(config.max_body_size_bytes, 1024);
        assert!(config.enable_cors);
    }

    #[test]
    fn test_observability_config_defaults() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.service_name, "email-validator-api");
        assert_eq!(config.log_level, "info");
        assert!(config.enable_tracing);
        assert!(config.enable_metrics);
    }
}