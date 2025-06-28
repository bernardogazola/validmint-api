//! # email_core
//!
//! High-performance email domain validation library for detecting disposable domains,
//! validating DNS records, and analyzing email deliverability.
//!
//! ## Features
//!
//! - **Fast disposable domain detection** using Bloom filters
//! - **DNS validation** with aggressive caching via hickory-resolver
//! - **SPF/DKIM/DMARC policy analysis** for deliverability assessment
//! - **Typo detection** using Levenshtein distance against major providers
//! - **Privacy-first design** with salted hashing for sensitive data
//!
//! ## Example
//!
//! ```rust
//! use email_core::{ValidationPipeline, ValidationConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ValidationConfig::default();
//!     let pipeline = ValidationPipeline::new(config).await?;
//!     
//!     let result = pipeline.validate_domain("example.com").await?;
//!     println!("Domain valid: {}", result.is_valid);
//!     
//!     Ok(())
//! }
//! ```

pub mod disposable;
pub mod dns;
pub mod heuristics;
pub mod privacy;
pub mod validation_pipeline;

#[cfg(feature = "dmarc")]
pub mod deliverability;

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

/// Configuration for the email validation pipeline
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// DNS resolver timeout in milliseconds
    pub dns_timeout_ms: u64,
    /// Maximum number of DNS lookup attempts
    pub dns_attempts: usize,
    /// DNS cache size (number of entries)
    pub dns_cache_size: usize,
    /// Minimum TTL for positive DNS cache entries
    pub dns_min_ttl_secs: u64,
    /// Bloom filter false positive rate
    pub bloom_filter_fp_rate: f64,
    /// Enable SMTP connection probing
    pub enable_smtp_probe: bool,
    /// Enable full DMARC/SPF/DKIM analysis
    pub enable_dmarc_analysis: bool,
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
        }
    }
}

/// Complete validation result for a domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// The domain that was validated
    pub domain: String,
    /// Whether the domain is syntactically valid
    pub is_valid: bool,
    /// Whether the domain is from a disposable email provider
    pub is_disposable: bool,
    /// Whether the domain has MX records
    pub has_mx_records: bool,
    /// Whether the domain has A/AAAA records
    pub has_a_records: bool,
    /// Whether the domain appears to be a typo of a major provider
    pub is_potential_typo: bool,
    /// Suggested correction if is_potential_typo is true
    pub suggestion: Option<String>,
    /// SPF record analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub spf_record: Option<SpfRecord>,
    /// DMARC policy analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub dmarc_record: Option<DmarcRecord>,
    /// DKIM record analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub dkim_records: Vec<DkimRecord>,
    /// SMTP connection test result (if SMTP probe feature enabled)
    #[cfg(feature = "smtp_probe")]
    pub smtp_accessible: Option<bool>,
    /// Risk score (0-100, higher = more risky)
    pub risk_score: u8,
    /// Timestamp when validation was performed
    pub checked_at: SystemTime,
}

/// Fast validation result for a domain - only essential information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastValidationResult {
    /// The domain that was validated
    pub domain: String,
    /// Whether the domain is syntactically valid and exists
    pub is_valid: bool,
    /// Whether the domain is from a disposable email provider
    pub is_disposable: bool,
    /// Timestamp when validation was performed
    pub checked_at: SystemTime,
}

/// SPF record analysis result
#[cfg(feature = "dmarc")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfRecord {
    pub exists: bool,
    pub policy: Option<String>,
    pub is_strict: bool, // true if ends with "-all"
}

/// DMARC record analysis result
#[cfg(feature = "dmarc")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcRecord {
    pub exists: bool,
    pub policy: Option<String>, // "none", "quarantine", "reject"
    pub percentage: Option<u8>,
}

/// DKIM record analysis result
#[cfg(feature = "dmarc")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimRecord {
    pub selector: String,
    pub exists: bool,
    pub has_public_key: bool,
}

/// Errors that can occur during validation
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid domain format: {0}")]
    InvalidDomain(String),
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(#[from] hickory_resolver::error::ResolveError),
    #[error("SMTP probe failed: {0}")]
    SmtpProbeFailed(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Internal error: {0}")]
    InternalError(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, ValidationError>;

// Re-export main types
pub use validation_pipeline::ValidationPipeline;
pub use ValidationConfig as Config;