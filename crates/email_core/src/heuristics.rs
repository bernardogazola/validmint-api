//! Typo detection heuristics using string distance algorithms
//!
//! This module implements typo detection by comparing domains against a curated
//! list of major email providers using Levenshtein distance.

use anyhow::Result;
use std::collections::HashSet;
use textdistance::str::levenshtein;
use tracing::debug;

/// Typo detector for identifying potential typos of major email providers
pub struct TypoDetector {
    major_providers: HashSet<String>,
    valid_tlds: HashSet<String>,
}

impl TypoDetector {
    /// Create a new typo detector with default major providers and TLDs
    pub fn new() -> Self {
        let major_providers = Self::default_major_providers();
        let valid_tlds = Self::default_valid_tlds();
        
        debug!("Typo detector initialized with {} providers and {} TLDs", 
               major_providers.len(), valid_tlds.len());
        
        Self {
            major_providers,
            valid_tlds,
        }
    }

    /// Create a typo detector with custom provider and TLD lists
    pub fn with_lists(providers: HashSet<String>, tlds: HashSet<String>) -> Self {
        Self {
            major_providers: providers,
            valid_tlds: tlds,
        }
    }

    /// Check if a domain might be a typo of a major provider
    ///
    /// # Arguments
    /// * `domain` - Domain to check (e.g., "gogle.com")
    ///
    /// # Returns
    /// * `Ok(Some(suggestion))` if likely typo with suggested correction
    /// * `Ok(None)` if not a typo or invalid domain
    /// * `Err(_)` on processing errors
    pub fn check_typo(&self, domain: &str) -> Result<Option<String>> {
        debug!("Checking domain for typos: {}", domain);
        
        let domain_lower = domain.to_lowercase();
        let parts: Vec<&str> = domain_lower.splitn(2, '.').collect();
        
        if parts.len() != 2 {
            debug!("Invalid domain format: {}", domain);
            return Ok(None);
        }
        
        let (sld, tld) = (parts[0], parts[1]);
        
        // First, check if TLD is valid
        if !self.valid_tlds.contains(tld) {
            debug!("Invalid TLD: {}", tld);
            return Ok(None);
        }
        
        // Check if SLD is close to any major provider
        for provider in &self.major_providers {
            let distance = levenshtein(sld, provider);
            
            // Consider it a typo if distance is 1 for short domains (up to 6 chars)
            // or distance is 2 for longer domains
            let is_typo = if provider.len() <= 6 {
                distance == 1
            } else {
                distance <= 2 && distance > 0
            };
            
            if is_typo {
                let suggestion = format!("{}.{}", provider, tld);
                debug!("Potential typo detected: {} -> {} (distance: {})", 
                       domain, suggestion, distance);
                return Ok(Some(suggestion));
            }
        }
        
        debug!("No typo detected for: {}", domain);
        Ok(None)
    }

    /// Get the default list of major email providers (SLD only)
    fn default_major_providers() -> HashSet<String> {
        [
            // Google
            "gmail", "googlemail",
            
            // Microsoft
            "outlook", "hotmail", "live", "msn",
            
            // Yahoo
            "yahoo", "ymail", "rocketmail",
            
            // Apple
            "icloud", "me", "mac",
            
            // AOL
            "aol",
            
            // Other major providers
            "protonmail", "proton",
            "tutanota", "tuta",
            "fastmail",
            "zoho",
            "yandex",
            "mail", "email",
            
            // Corporate/Enterprise
            "company", "corp", "enterprise",
            
            // Country-specific major providers
            "gmx", // Germany
            "web", // Germany (web.de)
            "t-online", // Germany
            "orange", // France
            "free", // France
            "laposte", // France
            "libero", // Italy
            "tin", // Italy
            "virgilio", // Italy
            "naver", // South Korea
            "daum", // South Korea
            "qq", // China
            "163", // China (163.com)
            "126", // China (126.com)
            "sina", // China
            "sohu", // China
            "rediffmail", // India
            "sify", // India
        ]
        .iter()
        .map(|&s| s.to_string())
        .collect()
    }

    /// Get the default list of valid TLDs
    fn default_valid_tlds() -> HashSet<String> {
        [
            // Generic TLDs
            "com", "org", "net", "edu", "gov", "mil", "int",
            "info", "biz", "name", "pro", "museum", "coop", "aero",
            "jobs", "mobi", "travel", "tel", "cat",
            
            // New generic TLDs (common ones)
            "email", "mail", "post", "tech", "online", "site", "website",
            "app", "web", "digital", "cloud", "dev", "io", "ai",
            
            // Country code TLDs (major ones)
            "us", "uk", "ca", "au", "de", "fr", "it", "es", "nl", "be",
            "ch", "at", "se", "no", "dk", "fi", "pl", "cz", "hu", "ru",
            "ua", "by", "lt", "lv", "ee", "jp", "kr", "cn", "hk", "tw",
            "sg", "my", "th", "ph", "id", "in", "pk", "bd", "lk", "np",
            "ae", "sa", "il", "tr", "gr", "ro", "bg", "hr", "si", "sk",
            "rs", "ba", "mk", "al", "me", "mx", "br", "ar", "cl", "pe",
            "co", "ve", "ec", "bo", "py", "uy", "gf", "sr", "gy", "fk",
            "za", "ng", "ke", "gh", "tz", "ug", "mw", "zm", "zw", "bw",
            "na", "sz", "ls", "mg", "mu", "re", "yt", "km", "sc", "dj",
            "so", "et", "er", "sd", "eg", "ly", "tn", "dz", "ma", "mr",
            "sn", "gm", "gw", "gn", "sl", "lr", "ci", "bf", "ml", "ne",
            "td", "cf", "cm", "gq", "ga", "cg", "cd", "ao", "st", "cv",
            
            // Special use
            "local", "localhost", "test", "invalid", "example",
        ]
        .iter()
        .map(|&s| s.to_string())
        .collect()
    }

    /// Add a custom major provider to the list
    pub fn add_major_provider(&mut self, provider: String) {
        self.major_providers.insert(provider.to_lowercase());
    }

    /// Add a custom valid TLD to the list
    pub fn add_valid_tld(&mut self, tld: String) {
        self.valid_tlds.insert(tld.to_lowercase());
    }

    /// Get the number of major providers being tracked
    pub fn provider_count(&self) -> usize {
        self.major_providers.len()
    }

    /// Get the number of valid TLDs being tracked
    pub fn tld_count(&self) -> usize {
        self.valid_tlds.len()
    }
}

impl Default for TypoDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_typo_detector_creation() {
        let detector = TypoDetector::new();
        assert!(detector.provider_count() > 0);
        assert!(detector.tld_count() > 0);
    }

    #[test]
    fn test_obvious_typos() {
        let detector = TypoDetector::new();
        
        // Gmail typos
        let result = detector.check_typo("gogle.com").unwrap();
        assert_eq!(result, Some("gmail.com".to_string()));
        
        let result = detector.check_typo("gmai.com").unwrap();
        assert_eq!(result, Some("gmail.com".to_string()));
        
        let result = detector.check_typo("gmial.com").unwrap();
        assert_eq!(result, Some("gmail.com".to_string()));
        
        // Outlook typos
        let result = detector.check_typo("outloo.com").unwrap();
        assert_eq!(result, Some("outlook.com".to_string()));
        
        let result = detector.check_typo("outlok.com").unwrap();
        assert_eq!(result, Some("outlook.com".to_string()));
    }

    #[test]
    fn test_no_false_positives() {
        let detector = TypoDetector::new();
        
        // Valid domains that shouldn't be flagged
        assert_eq!(detector.check_typo("google.com").unwrap(), None);
        assert_eq!(detector.check_typo("example.com").unwrap(), None);
        assert_eq!(detector.check_typo("stackoverflow.com").unwrap(), None);
        assert_eq!(detector.check_typo("github.com").unwrap(), None);
    }

    #[test]
    fn test_invalid_domains() {
        let detector = TypoDetector::new();
        
        // Invalid TLD
        assert_eq!(detector.check_typo("gmail.invalidtld").unwrap(), None);
        
        // No TLD
        assert_eq!(detector.check_typo("gmail").unwrap(), None);
        
        // Multiple dots (should only split on first)
        assert_eq!(detector.check_typo("gogle.co.uk").unwrap(), None);
    }

    #[test]
    fn test_case_insensitive() {
        let detector = TypoDetector::new();
        
        let result = detector.check_typo("GOGLE.COM").unwrap();
        assert_eq!(result, Some("gmail.com".to_string()));
        
        let result = detector.check_typo("GoGle.CoM").unwrap();
        assert_eq!(result, Some("gmail.com".to_string()));
    }

    #[test]
    fn test_distance_thresholds() {
        let detector = TypoDetector::new();
        
        // Distance 1 should be flagged for short domains
        let result = detector.check_typo("yaho.com").unwrap();
        assert_eq!(result, Some("yahoo.com".to_string()));
        
        // Distance 2 should be flagged for longer domains
        let result = detector.check_typo("outlok.com").unwrap();
        assert_eq!(result, Some("outlook.com".to_string()));
        
        // Distance too high should not be flagged
        let result = detector.check_typo("completely-different.com").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_custom_providers() {
        let mut providers = HashSet::new();
        providers.insert("mycompany".to_string());
        
        let tlds = TypoDetector::default_valid_tlds();
        let detector = TypoDetector::with_lists(providers, tlds);
        
        let result = detector.check_typo("mycompany.com").unwrap();
        assert_eq!(result, None); // Exact match, no typo
        
        let result = detector.check_typo("mycompan.com").unwrap();
        assert_eq!(result, Some("mycompany.com".to_string()));
    }

    #[test]
    fn test_add_custom_provider() {
        let mut detector = TypoDetector::new();
        detector.add_major_provider("testprovider".to_string());
        
        let result = detector.check_typo("testprovider.com").unwrap();
        assert_eq!(result, None); // Exact match
        
        let result = detector.check_typo("testprovder.com").unwrap();
        assert_eq!(result, Some("testprovider.com".to_string()));
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein("gmail", "gmail"), 0);
        assert_eq!(levenshtein("gmail", "gmai"), 1);
        assert_eq!(levenshtein("gmail", "gogle"), 2);
        assert_eq!(levenshtein("outlook", "outlok"), 1);
        assert_eq!(levenshtein("yahoo", "yaho"), 1);
    }
}