//! Disposable domain detection using Bloom filters
//!
//! This module provides fast, memory-efficient detection of disposable email domains
//! using a Bloom filter data structure loaded from the mailchecker dataset.

use anyhow::Result;
use fastbloom::BloomFilter;
use std::collections::HashSet;
use tracing::{debug, info, warn};

/// Manages disposable domain detection using a high-performance Bloom filter
/// Provides memory-efficient O(1) lookup with configurable false positive rate
pub struct DisposableDetector {
    bloom_filter: BloomFilter,
    domain_count: usize,
    estimated_memory_usage: usize,
}

impl DisposableDetector {
    /// Create a new disposable detector from a list of domains
    ///
    /// # Arguments
    /// * `domains` - Iterator of domain strings to add to the filter
    /// * `false_positive_rate` - Desired false positive rate (e.g., 0.0001 for 0.01%)
    ///
    /// # Example
    /// ```rust
    /// use email_core::disposable::DisposableDetector;
    /// 
    /// let domains = vec!["10minutemail.com", "guerrillamail.com"];
    /// let detector = DisposableDetector::new(domains.into_iter(), 0.0001)?;
    /// assert!(detector.is_disposable("10minutemail.com"));
    /// assert!(!detector.is_disposable("gmail.com"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new<I>(domains: I, false_positive_rate: f64) -> Result<Self>
    where
        I: Iterator<Item = String>,
    {
        let domains: Vec<String> = domains.collect();
        let domain_count = domains.len();
        
        if domain_count == 0 {
            return Err(anyhow::anyhow!("No domains provided for disposable detection"));
        }

        debug!("Creating Bloom filter for {} disposable domains with {:.4}% false positive rate", 
               domain_count, false_positive_rate * 100.0);
        
        // Create Bloom filter with target false positive rate
        // FastBloom will automatically calculate optimal parameters
        let domain_items: Vec<String> = domains.iter().map(|d| d.to_lowercase()).collect();
        let bloom_filter = BloomFilter::with_false_pos(false_positive_rate)
            .items(domain_items);
        
        // Estimate memory usage (approximation based on item count and FP rate)
        let estimated_bits = Self::calculate_optimal_bits(domain_count, false_positive_rate);
        let estimated_memory = estimated_bits.div_ceil(8); // Convert bits to bytes
        
        debug!("Bloom filter created with {:.4}% false positive rate, ~{} KB memory", 
               false_positive_rate * 100.0, estimated_memory / 1024);

        info!(
            "Disposable detector initialized with {} domains, ~{} KB memory, {:.4}% false positive rate",
            domain_count,
            estimated_memory / 1024,
            false_positive_rate * 100.0
        );

        Ok(Self {
            bloom_filter,
            domain_count,
            estimated_memory_usage: estimated_memory,
        })
    }

    /// Load disposable domains from the provided list.txt file
    ///
    /// # Arguments
    /// * `list_content` - Content of the list.txt file
    /// * `false_positive_rate` - Desired false positive rate
    pub fn from_list_txt(list_content: &str, false_positive_rate: f64) -> Result<Self> {
        let domains = parse_disposable_list(list_content)?;
        Self::new(domains.into_iter(), false_positive_rate)
    }

    /// Check if a domain is likely disposable
    ///
    /// # Arguments
    /// * `domain` - Domain to check (e.g., "example.com")
    ///
    /// # Returns
    /// * `true` if the domain might be disposable (may have false positives)
    /// * `false` if the domain is definitely not in the disposable list
    pub fn is_disposable(&self, domain: &str) -> bool {
        let normalized_domain = domain.to_lowercase();
        let result = self.bloom_filter.contains(&normalized_domain);
        
        if result {
            debug!("Domain '{}' flagged as potentially disposable (Bloom filter match)", domain);
        }
        
        result
    }

    /// Get the number of domains in the filter
    pub fn domain_count(&self) -> usize {
        self.domain_count
    }

    /// Get the estimated memory usage of the Bloom filter in bytes
    pub fn memory_usage(&self) -> usize {
        self.estimated_memory_usage
    }

    /// Calculate optimal number of bits for Bloom filter
    /// Formula: m = -(n * ln(p)) / (ln(2)^2)
    /// where n = number of items, p = desired false positive rate
    fn calculate_optimal_bits(item_count: usize, false_positive_rate: f64) -> usize {
        let n = item_count as f64;
        let p = false_positive_rate;
        let ln2_squared = (2.0_f64).ln().powi(2);
        
        let optimal_bits = (-n * p.ln()) / ln2_squared;
        optimal_bits.ceil() as usize
    }

}

/// Parse the disposable domain list from list.txt content
fn parse_disposable_list(content: &str) -> Result<HashSet<String>> {
    let mut domains = HashSet::new();
    let mut line_count = 0;
    let mut invalid_count = 0;

    for line in content.lines() {
        line_count += 1;
        let domain = line.trim();
        
        // Skip empty lines and comments
        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }

        // Basic domain validation
        if is_valid_domain_format(domain) {
            domains.insert(domain.to_lowercase());
        } else {
            invalid_count += 1;
            if invalid_count <= 10 {
                warn!("Invalid domain format at line {}: '{}'", line_count, domain);
            }
        }
    }

    if invalid_count > 10 {
        warn!("... and {} more invalid domain entries", invalid_count - 10);
    }

    info!(
        "Parsed {} valid domains from {} lines ({} invalid entries)",
        domains.len(),
        line_count,
        invalid_count
    );

    if domains.is_empty() {
        return Err(anyhow::anyhow!("No valid domains found in list"));
    }

    Ok(domains)
}

/// Basic domain format validation
fn is_valid_domain_format(domain: &str) -> bool {
    // Basic checks for domain format
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_disposable_detector_creation() {
        let domains = vec![
            "10minutemail.com".to_string(),
            "guerrillamail.com".to_string(),
            "tempmail.org".to_string(),
        ];
        
        let detector = DisposableDetector::new(domains.into_iter(), 0.01).unwrap();
        assert_eq!(detector.domain_count(), 3);
        assert!(detector.memory_usage() > 0);
    }

    #[test]
    fn test_disposable_detection() {
        let domains = vec![
            "10minutemail.com".to_string(),
            "guerrillamail.com".to_string(),
        ];
        
        let detector = DisposableDetector::new(domains.into_iter(), 0.01).unwrap();
        
        // These should be detected as disposable
        assert!(detector.is_disposable("10minutemail.com"));
        assert!(detector.is_disposable("guerrillamail.com"));
        
        // These should not be detected (assuming no false positives)
        assert!(!detector.is_disposable("gmail.com"));
        assert!(!detector.is_disposable("example.com"));
    }

    #[test]
    fn test_case_insensitive_detection() {
        let domains = vec!["TempMail.Org".to_string()];
        let detector = DisposableDetector::new(domains.into_iter(), 0.01).unwrap();
        
        assert!(detector.is_disposable("tempmail.org"));
        assert!(detector.is_disposable("TEMPMAIL.ORG"));
        assert!(detector.is_disposable("TempMail.Org"));
    }

    #[test]
    fn test_parse_disposable_list() {
        let content = r#"
# This is a comment
10minutemail.com
guerrillamail.com

tempmail.org
invalid_domain_without_dot
"#;
        
        let domains = parse_disposable_list(content).unwrap();
        assert_eq!(domains.len(), 3);
        assert!(domains.contains("10minutemail.com"));
        assert!(domains.contains("guerrillamail.com"));
        assert!(domains.contains("tempmail.org"));
        assert!(!domains.contains("invalid_domain_without_dot"));
    }

    #[test]
    fn test_domain_format_validation() {
        assert!(is_valid_domain_format("example.com"));
        assert!(is_valid_domain_format("sub.example.com"));
        assert!(is_valid_domain_format("test-domain.co.uk"));
        
        assert!(!is_valid_domain_format(""));
        assert!(!is_valid_domain_format("no-dot"));
        assert!(!is_valid_domain_format(".example.com"));
        assert!(!is_valid_domain_format("example.com."));
        assert!(!is_valid_domain_format("-example.com"));
        assert!(!is_valid_domain_format("example.com-"));
        assert!(!is_valid_domain_format("ex ample.com"));
    }

    #[test]
    fn test_from_list_txt() {
        let content = "10minutemail.com\nguerrillamail.com\ntempmail.org";
        let detector = DisposableDetector::from_list_txt(content, 0.01).unwrap();
        
        assert_eq!(detector.domain_count(), 3);
        assert!(detector.is_disposable("10minutemail.com"));
        assert!(detector.is_disposable("guerrillamail.com"));
        assert!(detector.is_disposable("tempmail.org"));
    }
}