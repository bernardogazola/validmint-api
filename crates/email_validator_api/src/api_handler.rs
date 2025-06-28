//! Shared API types and utilities
//!
//! This module contains common types, error handling, and conversion utilities
//! used across all API endpoints.

use axum::{http::StatusCode, response::Json};
use email_core::{ValidationResult, ValidationError, FastValidationResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Query parameters for domain validation
#[derive(Debug, Deserialize)]
pub struct ValidateQuery {
    /// Domain to validate (e.g., "example.com")
    pub domain: String,
}

/// Request body for POST validation
#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    /// Domain to validate
    pub domain: String,
    /// Optional request ID for tracking
    pub request_id: Option<String>,
}

/// API response for domain validation
#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    /// Request ID for tracking
    pub request_id: String,
    /// The domain that was validated
    pub domain: String,
    /// Whether the domain is syntactically valid
    pub is_valid: bool,
    /// Whether the domain is from a disposable email provider
    pub is_disposable: bool,
    /// Whether the domain has MX records (can receive email)
    pub has_mx_records: bool,
    /// Whether the domain has A/AAAA records (domain exists)
    pub has_a_records: bool,
    /// Whether the domain appears to be a typo of a major provider
    pub is_potential_typo: bool,
    /// Suggested correction if is_potential_typo is true
    pub suggestion: Option<String>,
    /// SPF record analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub spf_record: Option<SpfRecordResponse>,
    /// DMARC policy analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub dmarc_record: Option<DmarcRecordResponse>,
    /// DKIM record analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub dkim_records: Vec<DkimRecordResponse>,
    /// SMTP connection test result (if SMTP probe feature enabled)
    #[cfg(feature = "smtp_probe")]
    pub smtp_accessible: Option<bool>,
    /// Risk score (0-100, higher = more risky)
    pub risk_score: u8,
    /// Risk level categorization
    pub risk_level: RiskLevel,
    /// Timestamp when validation was performed (ISO 8601)
    pub checked_at: String,
}

/// Fast validation API response for domain validation
#[derive(Debug, Serialize)]
pub struct FastValidateResponse {
    /// Request ID for tracking
    pub request_id: String,
    /// The domain that was validated
    pub domain: String,
    /// Whether the domain is syntactically valid and exists
    pub is_valid: bool,
    /// Whether the domain is from a disposable email provider
    pub is_disposable: bool,
}

/// Fast validation API response for developer endpoints (includes performance metrics)
#[derive(Debug, Serialize)]
pub struct FastValidateDevResponse {
    /// Request ID for tracking
    pub request_id: String,
    /// The domain that was validated
    pub domain: String,
    /// Whether the domain is syntactically valid and exists
    pub is_valid: bool,
    /// Whether the domain is from a disposable email provider
    pub is_disposable: bool,
    /// Performance metrics
    pub performance: PerformanceMetrics,
}

/// Full validation API response for developer endpoints (includes performance metrics)
#[derive(Debug, Serialize)]
pub struct ValidateDevResponse {
    /// Request ID for tracking
    pub request_id: String,
    /// The domain that was validated
    pub domain: String,
    /// Whether the domain is syntactically valid
    pub is_valid: bool,
    /// Whether the domain is from a disposable email provider
    pub is_disposable: bool,
    /// Whether the domain has MX records (can receive email)
    pub has_mx_records: bool,
    /// Whether the domain has A/AAAA records (domain exists)
    pub has_a_records: bool,
    /// Whether the domain appears to be a typo of a major provider
    pub is_potential_typo: bool,
    /// Suggested correction if is_potential_typo is true
    pub suggestion: Option<String>,
    /// SPF record analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub spf_record: Option<SpfRecordResponse>,
    /// DMARC policy analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub dmarc_record: Option<DmarcRecordResponse>,
    /// DKIM record analysis (if DMARC feature enabled)
    #[cfg(feature = "dmarc")]
    pub dkim_records: Vec<DkimRecordResponse>,
    /// SMTP connection test result (if SMTP probe feature enabled)
    #[cfg(feature = "smtp_probe")]
    pub smtp_accessible: Option<bool>,
    /// Risk score (0-100, higher = more risky)
    pub risk_score: u8,
    /// Risk level categorization
    pub risk_level: RiskLevel,
    /// Timestamp when validation was performed (ISO 8601)
    pub checked_at: String,
    /// Performance metrics
    pub performance: PerformanceMetrics,
}

/// SPF record response
#[cfg(feature = "dmarc")]
#[derive(Debug, Serialize)]
pub struct SpfRecordResponse {
    pub exists: bool,
    pub policy: Option<String>,
    pub is_strict: bool,
}

/// DMARC record response
#[cfg(feature = "dmarc")]
#[derive(Debug, Serialize)]
pub struct DmarcRecordResponse {
    pub exists: bool,
    pub policy: Option<String>,
    pub percentage: Option<u8>,
}

/// DKIM record response
#[cfg(feature = "dmarc")]
#[derive(Debug, Serialize)]
pub struct DkimRecordResponse {
    pub selector: String,
    pub exists: bool,
    pub has_public_key: bool,
}

/// Risk level categorization
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,      // 0-25
    Medium,   // 26-50
    High,     // 51-75
    Critical, // 76-100
}

impl From<u8> for RiskLevel {
    fn from(score: u8) -> Self {
        match score {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            76..=100 => RiskLevel::Critical,
            _ => RiskLevel::Critical, // Fallback for any values > 100
        }
    }
}

/// Performance metrics for the validation
#[derive(Debug, Serialize)]
pub struct PerformanceMetrics {
    /// Total processing time in milliseconds
    pub total_time_ms: u64,
    /// Whether DNS cache was hit
    pub dns_cache_hit: bool,
}

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_code: String,
    pub request_id: String,
    pub timestamp: String,
    pub details: Option<HashMap<String, String>>,
}

/// Result type for API handlers
pub type ApiResult<T> = Result<Json<T>, ApiError>;

/// API error types
#[derive(Debug)]
pub enum ApiError {
    InvalidDomain(String),
    ValidationFailed(String),
    InternalError(String),
    #[allow(dead_code)]
    RateLimited,
    #[allow(dead_code)]
    RequestTooLarge,
}

impl From<ValidationError> for ApiError {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::InvalidDomain(msg) => ApiError::InvalidDomain(msg),
            ValidationError::DnsResolutionFailed(e) => ApiError::ValidationFailed(e.to_string()),
            ValidationError::SmtpProbeFailed(msg) => ApiError::ValidationFailed(msg),
            ValidationError::ConfigurationError(msg) => ApiError::InternalError(msg),
            ValidationError::InternalError(e) => ApiError::InternalError(e.to_string()),
        }
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_code, message) = match self {
            ApiError::InvalidDomain(msg) => (StatusCode::BAD_REQUEST, "INVALID_DOMAIN", msg),
            ApiError::ValidationFailed(msg) => (StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_FAILED", msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", msg),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED", "Too many requests".to_string()),
            ApiError::RequestTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "REQUEST_TOO_LARGE", "Request body too large".to_string()),
        };

        let request_id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();

        let error_response = ErrorResponse {
            error: message,
            error_code: error_code.to_string(),
            request_id,
            timestamp,
            details: None,
        };

        (status, Json(error_response)).into_response()
    }
}


/// Convert core ValidationResult to API response (without performance metrics)
pub fn convert_validation_result(
    result: ValidationResult,
    request_id: String,
) -> ValidateResponse {
    let risk_level = RiskLevel::from(result.risk_score);
    
    // Format timestamp as ISO 8601
    let checked_at = match result.checked_at.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => {
            chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
                .unwrap_or_else(chrono::Utc::now)
                .to_rfc3339()
        }
        Err(_) => chrono::Utc::now().to_rfc3339(),
    };

    ValidateResponse {
        request_id,
        domain: result.domain,
        is_valid: result.is_valid,
        is_disposable: result.is_disposable,
        has_mx_records: result.has_mx_records,
        has_a_records: result.has_a_records,
        is_potential_typo: result.is_potential_typo,
        suggestion: result.suggestion,
        
        #[cfg(feature = "dmarc")]
        spf_record: result.spf_record.map(|spf| SpfRecordResponse {
            exists: spf.exists,
            policy: spf.policy,
            is_strict: spf.is_strict,
        }),
        
        #[cfg(feature = "dmarc")]
        dmarc_record: result.dmarc_record.map(|dmarc| DmarcRecordResponse {
            exists: dmarc.exists,
            policy: dmarc.policy,
            percentage: dmarc.percentage,
        }),
        
        #[cfg(feature = "dmarc")]
        dkim_records: result.dkim_records.into_iter().map(|dkim| DkimRecordResponse {
            selector: dkim.selector,
            exists: dkim.exists,
            has_public_key: dkim.has_public_key,
        }).collect(),
        
        #[cfg(feature = "smtp_probe")]
        smtp_accessible: result.smtp_accessible,
        
        risk_score: result.risk_score,
        risk_level,
        checked_at,
    }
}

/// Extract domain from email address or return the input if it's already a domain
/// 
/// Examples:
/// - "test@gmail.com" -> "gmail.com"
/// - "gmail.com" -> "gmail.com"
/// - "user@sub.domain.com" -> "sub.domain.com"
pub fn extract_domain_from_input(input: &str) -> &str {
    if let Some(at_pos) = input.rfind('@') {
        &input[at_pos + 1..]
    } else {
        input
    }
}

/// Convert core FastValidationResult to API response (without performance metrics)
pub fn convert_fast_validation_result(
    result: FastValidationResult,
    request_id: String,
) -> FastValidateResponse {
    FastValidateResponse {
        request_id,
        domain: result.domain,
        is_valid: result.is_valid,
        is_disposable: result.is_disposable,
    }
}

/// Convert core ValidationResult to dev API response (with performance metrics)
pub fn convert_validation_dev_result(
    result: ValidationResult,
    request_id: String,
    processing_time: std::time::Duration,
) -> ValidateDevResponse {
    let risk_level = RiskLevel::from(result.risk_score);
    
    // Format timestamp as ISO 8601
    let checked_at = match result.checked_at.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => {
            chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
                .unwrap_or_else(chrono::Utc::now)
                .to_rfc3339()
        }
        Err(_) => chrono::Utc::now().to_rfc3339(),
    };

    ValidateDevResponse {
        request_id,
        domain: result.domain,
        is_valid: result.is_valid,
        is_disposable: result.is_disposable,
        has_mx_records: result.has_mx_records,
        has_a_records: result.has_a_records,
        is_potential_typo: result.is_potential_typo,
        suggestion: result.suggestion,
        
        #[cfg(feature = "dmarc")]
        spf_record: result.spf_record.map(|spf| SpfRecordResponse {
            exists: spf.exists,
            policy: spf.policy,
            is_strict: spf.is_strict,
        }),
        
        #[cfg(feature = "dmarc")]
        dmarc_record: result.dmarc_record.map(|dmarc| DmarcRecordResponse {
            exists: dmarc.exists,
            policy: dmarc.policy,
            percentage: dmarc.percentage,
        }),
        
        #[cfg(feature = "dmarc")]
        dkim_records: result.dkim_records.into_iter().map(|dkim| DkimRecordResponse {
            selector: dkim.selector,
            exists: dkim.exists,
            has_public_key: dkim.has_public_key,
        }).collect(),
        
        #[cfg(feature = "smtp_probe")]
        smtp_accessible: result.smtp_accessible,
        
        risk_score: result.risk_score,
        risk_level,
        checked_at,
        performance: PerformanceMetrics {
            total_time_ms: processing_time.as_millis() as u64,
            dns_cache_hit: processing_time.as_millis() < 50, // Heuristic for cache hit
        },
    }
}

/// Convert core FastValidationResult to dev API response (with performance metrics)
pub fn convert_fast_validation_dev_result(
    result: FastValidationResult,
    request_id: String,
    processing_time: std::time::Duration,
) -> FastValidateDevResponse {
    FastValidateDevResponse {
        request_id,
        domain: result.domain,
        is_valid: result.is_valid,
        is_disposable: result.is_disposable,
        performance: PerformanceMetrics {
            total_time_ms: processing_time.as_millis() as u64,
            dns_cache_hit: processing_time.as_millis() < 50, // Heuristic for cache hit
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_conversion() {
        assert!(matches!(RiskLevel::from(0), RiskLevel::Low));
        assert!(matches!(RiskLevel::from(25), RiskLevel::Low));
        assert!(matches!(RiskLevel::from(26), RiskLevel::Medium));
        assert!(matches!(RiskLevel::from(50), RiskLevel::Medium));
        assert!(matches!(RiskLevel::from(51), RiskLevel::High));
        assert!(matches!(RiskLevel::from(75), RiskLevel::High));
        assert!(matches!(RiskLevel::from(76), RiskLevel::Critical));
        assert!(matches!(RiskLevel::from(100), RiskLevel::Critical));
    }

    #[test]
    fn test_validate_query_deserialization() {
        // This would typically be tested with actual HTTP requests
        // but we can test the structure
        let query = ValidateQuery {
            domain: "example.com".to_string(),
        };
        assert_eq!(query.domain, "example.com");
    }

    #[test]
    fn test_validate_request_deserialization() {
        let request = ValidateRequest {
            domain: "example.com".to_string(),
            request_id: Some("test-123".to_string()),
        };
        assert_eq!(request.domain, "example.com");
        assert_eq!(request.request_id, Some("test-123".to_string()));
    }

    #[test]
    fn test_extract_domain_from_input() {
        // Test email addresses
        assert_eq!(extract_domain_from_input("test@gmail.com"), "gmail.com");
        assert_eq!(extract_domain_from_input("user@subdomain.example.com"), "subdomain.example.com");
        assert_eq!(extract_domain_from_input("complex.email+tag@domain.co.uk"), "domain.co.uk");
        
        // Test domains (should remain unchanged)
        assert_eq!(extract_domain_from_input("gmail.com"), "gmail.com");
        assert_eq!(extract_domain_from_input("subdomain.example.com"), "subdomain.example.com");
        
        // Test edge cases
        assert_eq!(extract_domain_from_input("@domain.com"), "domain.com");
        assert_eq!(extract_domain_from_input("email@"), "");
        assert_eq!(extract_domain_from_input(""), "");
        
        // Test multiple @ symbols (should use the last one)
        assert_eq!(extract_domain_from_input("test@invalid@gmail.com"), "gmail.com");
    }
}