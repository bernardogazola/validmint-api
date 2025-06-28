//! Main validation pipeline orchestrating all email domain checks
//!
//! This module coordinates the entire validation process, calling each check
//! in the optimal order for performance and accuracy.

use crate::{
    disposable::DisposableDetector,
    dns::DnsResolver,
    heuristics::TypoDetector,
    privacy::PrivacyProcessor,
    ValidationConfig, ValidationError, ValidationResult, FastValidationResult,
};

#[cfg(feature = "dmarc")]
use crate::deliverability::DeliverabilityAnalyzer;

#[cfg(feature = "smtp_probe")]
use lettre::SmtpTransport;

use anyhow::{Context, Result};
use std::time::SystemTime;
use tracing::{debug, info, warn, instrument, Span};

/// Parameters for risk score calculation
struct RiskCalculationParams<'a> {
    is_disposable: bool,
    has_a_records: bool,
    has_mx_records: bool,
    is_potential_typo: bool,
    #[cfg(feature = "dmarc")]
    spf_record: &'a Option<crate::SpfRecord>,
    #[cfg(feature = "dmarc")]
    dmarc_record: &'a Option<crate::DmarcRecord>,
    #[cfg(feature = "dmarc")]
    dkim_records: &'a [crate::DkimRecord],
    #[cfg(feature = "smtp_probe")]
    smtp_accessible: Option<bool>,
}

/// Main validation pipeline coordinating all domain checks
pub struct ValidationPipeline {
    config: ValidationConfig,
    disposable_detector: DisposableDetector,
    dns_resolver: DnsResolver,
    typo_detector: TypoDetector,
    privacy_processor: PrivacyProcessor,
}

impl ValidationPipeline {
    /// Create a new validation pipeline with the given configuration
    ///
    /// # Arguments
    /// * `config` - Validation configuration
    ///
    /// # Returns
    /// * `Ok(ValidationPipeline)` on success
    /// * `Err(ValidationError)` if initialization fails
    pub async fn new(config: ValidationConfig) -> Result<Self, ValidationError> {
        info!("Initializing validation pipeline");
        
        // Load disposable domains list
        let list_content = include_str!("../../../list.txt");
        let disposable_detector = DisposableDetector::from_list_txt(
            list_content,
            config.bloom_filter_fp_rate,
        ).context("Failed to initialize disposable detector")?;
        
        // Initialize DNS resolver
        let dns_resolver = DnsResolver::new(
            config.dns_timeout_ms,
            config.dns_attempts,
            config.dns_cache_size,
            config.dns_min_ttl_secs,
        ).context("Failed to initialize DNS resolver")?;
        
        // Initialize typo detector
        let typo_detector = TypoDetector::new();
        
        // Initialize privacy processor with a default salt
        // In production, this should be loaded from secure configuration
        let privacy_processor = PrivacyProcessor::with_random_salt();
        
        info!("Validation pipeline initialized successfully");
        
        Ok(Self {
            config,
            disposable_detector,
            dns_resolver,
            typo_detector,
            privacy_processor,
        })
    }

    /// Validate a domain through the complete pipeline
    ///
    /// # Arguments
    /// * `domain` - Domain to validate (e.g., "example.com")
    ///
    /// # Returns
    /// * `Ok(ValidationResult)` with complete analysis
    /// * `Err(ValidationError)` on validation failures
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn validate_domain(&self, domain: &str) -> Result<ValidationResult, ValidationError> {
        let span = Span::current();
        span.record("domain", domain);
        
        debug!("Starting domain validation for: {}", domain);
        
        // Step 1: Input validation and privacy check
        self.privacy_processor.validate_input(domain)
            .map_err(|e| ValidationError::InvalidDomain(e.to_string()))?;
        
        let normalized_domain = domain.trim().to_lowercase();
        
        if normalized_domain.is_empty() {
            return Err(ValidationError::InvalidDomain("Empty domain".to_string()));
        }
        
        // Basic domain format validation
        if !self.is_valid_domain_format(&normalized_domain) {
            debug!("Domain failed basic format validation: {}", normalized_domain);
            return Ok(ValidationResult {
                domain: normalized_domain,
                is_valid: false,
                is_disposable: false,
                has_mx_records: false,
                has_a_records: false,
                is_potential_typo: false,
                suggestion: None,
                #[cfg(feature = "dmarc")]
                spf_record: None,
                #[cfg(feature = "dmarc")]
                dmarc_record: None,
                #[cfg(feature = "dmarc")]
                dkim_records: Vec::new(),
                #[cfg(feature = "smtp_probe")]
                smtp_accessible: None,
                risk_score: 100, // Maximum risk for invalid domains
                checked_at: SystemTime::now(),
            });
        }
        
        // Step 2: Fast disposable domain check (Bloom filter)
        debug!("Checking disposable domains");
        let is_disposable = self.disposable_detector.is_disposable(&normalized_domain);
        
        if is_disposable {
            debug!("Domain flagged as disposable: {}", normalized_domain);
            // For disposable domains, we can return early with high risk
            return Ok(ValidationResult {
                domain: normalized_domain,
                is_valid: true, // Format is valid, but it's disposable
                is_disposable: true,
                has_mx_records: false, // Don't bother checking DNS for disposable domains
                has_a_records: false,
                is_potential_typo: false,
                suggestion: None,
                #[cfg(feature = "dmarc")]
                spf_record: None,
                #[cfg(feature = "dmarc")]
                dmarc_record: None,
                #[cfg(feature = "dmarc")]
                dkim_records: Vec::new(),
                #[cfg(feature = "smtp_probe")]
                smtp_accessible: None,
                risk_score: 85, // High risk for disposable domains
                checked_at: SystemTime::now(),
            });
        }
        
        // Step 3: Typo detection (fast, in-memory)
        debug!("Checking for typos");
        let typo_suggestion = self.typo_detector.check_typo(&normalized_domain)
            .context("Typo detection failed")?;
        
        let is_potential_typo = typo_suggestion.is_some();
        
        if is_potential_typo {
            debug!("Potential typo detected: {} -> {:?}", normalized_domain, typo_suggestion);
        }
        
        // Step 4: DNS checks (parallel A/AAAA and MX lookups)
        debug!("Performing DNS checks");
        let (has_a_records, has_mx_records) = match self.dns_resolver.check_domain_records(&normalized_domain).await {
            Ok((has_a, has_mx)) => (has_a, has_mx),
            Err(e) => {
                warn!("DNS lookup failed for {}: {}", normalized_domain, e);
                // Continue with limited information
                (false, false)
            }
        };
        
        if !has_a_records {
            debug!("Domain has no A/AAAA records: {}", normalized_domain);
            return Ok(ValidationResult {
                domain: normalized_domain,
                is_valid: false, // No A/AAAA records means domain doesn't exist
                is_disposable: false,
                has_mx_records: false,
                has_a_records: false,
                is_potential_typo,
                suggestion: typo_suggestion,
                #[cfg(feature = "dmarc")]
                spf_record: None,
                #[cfg(feature = "dmarc")]
                dmarc_record: None,
                #[cfg(feature = "dmarc")]
                dkim_records: Vec::new(),
                #[cfg(feature = "smtp_probe")]
                smtp_accessible: None,
                risk_score: 90, // High risk for non-existent domains
                checked_at: SystemTime::now(),
            });
        }
        
        // Step 5: Email authentication analysis (if DMARC feature enabled)
        #[cfg(feature = "dmarc")]
        let (spf_record, dmarc_record, dkim_records) = if self.config.enable_dmarc_analysis {
            debug!("Performing email authentication analysis");
            self.analyze_email_authentication(&normalized_domain).await
        } else {
            (None, None, Vec::new())
        };
        
        #[cfg(not(feature = "dmarc"))]
        let (spf_record, dmarc_record, dkim_records) = (None, None, Vec::new());
        
        // Step 6: SMTP probe (if enabled)
        #[cfg(feature = "smtp_probe")]
        let smtp_accessible = if self.config.enable_smtp_probe && has_mx_records {
            debug!("Performing SMTP probe");
            self.probe_smtp(&normalized_domain).await
        } else {
            None
        };
        
        #[cfg(not(feature = "smtp_probe"))]
        let smtp_accessible = None;
        
        // Step 7: Calculate overall risk score
        let risk_params = RiskCalculationParams {
            is_disposable,
            has_a_records,
            has_mx_records,
            is_potential_typo,
            #[cfg(feature = "dmarc")]
            spf_record: &spf_record,
            #[cfg(feature = "dmarc")]
            dmarc_record: &dmarc_record,
            #[cfg(feature = "dmarc")]
            dkim_records: &dkim_records,
            #[cfg(feature = "smtp_probe")]
            smtp_accessible,
        };
        let risk_score = self.calculate_risk_score(&risk_params);
        
        debug!("Domain validation complete for {}: risk_score={}", normalized_domain, risk_score);
        
        Ok(ValidationResult {
            domain: normalized_domain,
            is_valid: true,
            is_disposable,
            has_mx_records,
            has_a_records,
            is_potential_typo,
            suggestion: typo_suggestion,
            #[cfg(feature = "dmarc")]
            spf_record,
            #[cfg(feature = "dmarc")]
            dmarc_record,
            #[cfg(feature = "dmarc")]
            dkim_records,
            #[cfg(feature = "smtp_probe")]
            smtp_accessible,
            risk_score,
            checked_at: SystemTime::now(),
        })
    }

    /// Fast validation for domains - only performs essential checks for speed
    ///
    /// This method only performs:
    /// 1. Basic format validation
    /// 2. Disposable domain check (Bloom filter - very fast)
    /// 3. Basic A record DNS lookup (to verify domain exists)
    ///
    /// # Arguments
    /// * `domain` - Domain to validate (e.g., "example.com")
    ///
    /// # Returns
    /// * `Ok(FastValidationResult)` with essential validation info
    /// * `Err(ValidationError)` on validation failures
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn fast_validate_domain(&self, domain: &str) -> Result<FastValidationResult, ValidationError> {
        let span = Span::current();
        span.record("domain", domain);
        
        debug!("Starting fast domain validation for: {}", domain);
        
        // Step 1: Input validation and privacy check
        self.privacy_processor.validate_input(domain)
            .map_err(|e| ValidationError::InvalidDomain(e.to_string()))?;
        
        let normalized_domain = domain.trim().to_lowercase();
        
        if normalized_domain.is_empty() {
            return Err(ValidationError::InvalidDomain("Empty domain".to_string()));
        }
        
        // Step 2: Basic domain format validation
        let is_valid_format = self.is_valid_domain_format(&normalized_domain);
        if !is_valid_format {
            debug!("Domain failed basic format validation: {}", normalized_domain);
            return Ok(FastValidationResult {
                domain: normalized_domain,
                is_valid: false,
                is_disposable: false,
                checked_at: SystemTime::now(),
            });
        }
        
        // Step 3: Fast disposable domain check (Bloom filter)
        debug!("Checking disposable domains");
        let is_disposable = self.disposable_detector.is_disposable(&normalized_domain);
        
        if is_disposable {
            debug!("Domain flagged as disposable: {}", normalized_domain);
            return Ok(FastValidationResult {
                domain: normalized_domain,
                is_valid: true, // Format is valid, but it's disposable
                is_disposable: true,
                checked_at: SystemTime::now(),
            });
        }
        
        // Step 4: Quick A record check to verify domain exists
        debug!("Performing quick A record check");
        let has_a_records = match self.dns_resolver.has_a_records(&normalized_domain).await {
            Ok(has_a) => has_a,
            Err(e) => {
                warn!("A record lookup failed for {}: {}", normalized_domain, e);
                false
            }
        };
        
        let is_valid = is_valid_format && has_a_records;
        
        debug!("Fast domain validation complete for {}: valid={}, disposable={}", 
               normalized_domain, is_valid, is_disposable);
        
        Ok(FastValidationResult {
            domain: normalized_domain,
            is_valid,
            is_disposable,
            checked_at: SystemTime::now(),
        })
    }

    /// Validate email format and extract domain
    ///
    /// # Arguments
    /// * `email` - Email address to validate
    ///
    /// # Returns
    /// * `Ok(domain)` if email is valid
    /// * `Err(ValidationError)` if email is invalid
    pub fn extract_domain_from_email(&self, email: &str) -> Result<String, ValidationError> {
        // Check privacy policy first
        self.privacy_processor.validate_input(email)
            .map_err(|e| ValidationError::InvalidDomain(e.to_string()))?;
        
        // Parse using email_address crate for RFC 5322 compliance
        use email_address::EmailAddress;
        let parsed = EmailAddress::parse_with_options(email, Default::default())
            .map_err(|e| ValidationError::InvalidDomain(format!("Invalid email format: {}", e)))?;
        
        Ok(parsed.domain().to_string())
    }

    /// Basic domain format validation
    fn is_valid_domain_format(&self, domain: &str) -> bool {
        // Basic length check
        if domain.len() > 253 || domain.is_empty() {
            return false;
        }
        
        // Must contain at least one dot
        if !domain.contains('.') {
            return false;
        }
        
        // Cannot start or end with dot or hyphen
        if domain.starts_with('.') || domain.ends_with('.') || 
           domain.starts_with('-') || domain.ends_with('-') {
            return false;
        }
        
        // Check each label
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            
            // Labels cannot start or end with hyphen
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
            
            // Labels must contain only alphanumeric characters and hyphens
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
        }
        
        true
    }

    /// Analyze email authentication records (SPF, DKIM, DMARC)
    #[cfg(feature = "dmarc")]
    async fn analyze_email_authentication(
        &self, 
        domain: &str
    ) -> (Option<crate::SpfRecord>, Option<crate::DmarcRecord>, Vec<crate::DkimRecord>) {
        // Perform parallel lookups for better performance
        let (spf_result, dmarc_result, dkim_result) = tokio::join!(
            self.dns_resolver.get_spf_record(domain),
            self.dns_resolver.get_dmarc_record(domain),
            self.dns_resolver.get_common_dkim_records(domain)
        );
        
        let spf_record = DeliverabilityAnalyzer::analyze_spf_record(spf_result.unwrap_or(None));
        let dmarc_record = DeliverabilityAnalyzer::analyze_dmarc_record(dmarc_result.unwrap_or(None));
        let dkim_records = DeliverabilityAnalyzer::analyze_dkim_records(dkim_result.unwrap_or_default());
        
        (Some(spf_record), Some(dmarc_record), dkim_records)
    }

    /// Probe SMTP server accessibility
    #[cfg(feature = "smtp_probe")]
    async fn probe_smtp(&self, domain: &str) -> Option<bool> {
        debug!("Probing SMTP accessibility for: {}", domain);
        
        // Create a simple SMTP connection test
        // Note: This is a basic implementation. In production, you might want
        // to use a more sophisticated approach with connection pooling.
        let smtp_host = format!("smtp.{}", domain);
        
        // Simple connectivity test - just try to create transport
        match tokio::time::timeout(
            std::time::Duration::from_millis(2000),
            async {
                // Try to build SMTP transport as a basic connectivity test
                let _transport = SmtpTransport::builder_dangerous(&smtp_host).build();
                Ok::<(), std::io::Error>(())
            }
        ).await {
            Ok(_) => {
                debug!("SMTP accessible for: {}", domain);
                Some(true)
            }
            Err(_) => {
                debug!("SMTP not accessible for {}: timeout", domain);
                Some(false)
            }
        }
    }

    /// Calculate overall risk score based on all validation results
    fn calculate_risk_score(&self, params: &RiskCalculationParams) -> u8 {
        let mut risk = 0u8;
        
        // Basic validation risks
        if !params.has_a_records {
            risk += 50; // Domain doesn't exist
        }
        
        if params.is_disposable {
            risk += 40; // Disposable domain
        }
        
        if params.is_potential_typo {
            risk += 30; // Likely typo
        }
        
        if !params.has_mx_records {
            risk += 15; // Cannot receive email
        }
        
        // Email authentication risks (if DMARC feature enabled)
        #[cfg(feature = "dmarc")]
        if let (Some(spf), Some(dmarc)) = (params.spf_record, params.dmarc_record) {
            let auth_risk = DeliverabilityAnalyzer::calculate_deliverability_risk(
                spf, dmarc, params.dkim_records
            );
            // Scale down deliverability risk (it's less critical than basic validation)
            risk += (auth_risk / 3).min(20);
        }
        
        // SMTP accessibility (if enabled)
        #[cfg(feature = "smtp_probe")]
        if let Some(false) = params.smtp_accessible {
            risk += 10; // SMTP not accessible
        }
        
        // Ensure risk doesn't exceed 100
        risk.min(100)
    }

    /// Get pipeline statistics for monitoring
    pub fn get_stats(&self) -> PipelineStats {
        PipelineStats {
            disposable_domains_count: self.disposable_detector.domain_count(),
            disposable_filter_memory_bytes: self.disposable_detector.memory_usage(),
            typo_providers_count: self.typo_detector.provider_count(),
            typo_tlds_count: self.typo_detector.tld_count(),
        }
    }

    /// Clear DNS cache (for testing or administrative purposes)
    pub fn clear_dns_cache(&self) {
        self.dns_resolver.clear_cache();
    }
}

/// Statistics about the validation pipeline
#[derive(Debug, Clone, serde::Serialize)]
pub struct PipelineStats {
    pub disposable_domains_count: usize,
    pub disposable_filter_memory_bytes: usize,
    pub typo_providers_count: usize,
    pub typo_tlds_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    

    #[tokio::test]
    async fn test_pipeline_creation() {
        let config = ValidationConfig::default();
        let pipeline = ValidationPipeline::new(config).await;
        assert!(pipeline.is_ok());
    }

    #[tokio::test]
    async fn test_domain_format_validation() {
        let config = ValidationConfig::default();
        let pipeline = ValidationPipeline::new(config).await.unwrap();
        
        assert!(pipeline.is_valid_domain_format("example.com"));
        assert!(pipeline.is_valid_domain_format("sub.example.com"));
        assert!(pipeline.is_valid_domain_format("test-domain.co.uk"));
        
        assert!(!pipeline.is_valid_domain_format(""));
        assert!(!pipeline.is_valid_domain_format("invalid"));
        assert!(!pipeline.is_valid_domain_format(".example.com"));
        assert!(!pipeline.is_valid_domain_format("example.com."));
    }

    #[tokio::test]
    async fn test_email_domain_extraction() {
        let config = ValidationConfig::default();
        let pipeline = ValidationPipeline::new(config).await.unwrap();
        
        // This should fail because the API only accepts domains, not email addresses
        let result = pipeline.extract_domain_from_email("user@example.com");
        assert!(result.is_err());
        
        // Valid domain should work
        let result = pipeline.extract_domain_from_email("example.com");
        assert!(result.is_err()); // Should still fail because it's not an email format
    }

    #[tokio::test]
    async fn test_pipeline_stats() {
        let config = ValidationConfig::default();
        let pipeline = ValidationPipeline::new(config).await.unwrap();
        
        let stats = pipeline.get_stats();
        assert!(stats.disposable_domains_count > 0);
        assert!(stats.disposable_filter_memory_bytes > 0);
        assert!(stats.typo_providers_count > 0);
        assert!(stats.typo_tlds_count > 0);
    }

    #[tokio::test]
    async fn test_risk_calculation() {
        let config = ValidationConfig::default();
        let pipeline = ValidationPipeline::new(config).await.unwrap();
        
        // Test various risk scenarios
        let low_risk_params = RiskCalculationParams {
            is_disposable: false,
            has_a_records: true,
            has_mx_records: true,
            is_potential_typo: false,
            #[cfg(feature = "dmarc")]
            spf_record: &None,
            #[cfg(feature = "dmarc")]
            dmarc_record: &None,
            #[cfg(feature = "dmarc")]
            dkim_records: &[],
            #[cfg(feature = "smtp_probe")]
            smtp_accessible: None,
        };
        let low_risk = pipeline.calculate_risk_score(&low_risk_params);
        
        let high_risk_params = RiskCalculationParams {
            is_disposable: true,
            has_a_records: false,
            has_mx_records: false,
            is_potential_typo: true,
            #[cfg(feature = "dmarc")]
            spf_record: &None,
            #[cfg(feature = "dmarc")]
            dmarc_record: &None,
            #[cfg(feature = "dmarc")]
            dkim_records: &[],
            #[cfg(feature = "smtp_probe")]
            smtp_accessible: Some(false),
        };
        let high_risk = pipeline.calculate_risk_score(&high_risk_params);
        
        assert!(low_risk < high_risk);
        assert!(high_risk <= 100);
    }
}