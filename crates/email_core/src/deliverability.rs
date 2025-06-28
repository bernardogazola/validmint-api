//! Email deliverability analysis through SPF, DKIM, and DMARC records
//!
//! This module analyzes DNS TXT records to assess email authentication and
//! deliverability policies for domains.

use crate::{DkimRecord, DmarcRecord, SpfRecord};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Deliverability analyzer for SPF, DKIM, and DMARC records
pub struct DeliverabilityAnalyzer;

impl DeliverabilityAnalyzer {
    /// Analyze SPF record for strictness and validity
    ///
    /// # Arguments
    /// * `spf_record` - Raw SPF record string (e.g., "v=spf1 include:_spf.google.com ~all")
    ///
    /// # Returns
    /// * `SpfRecord` with analysis results
    pub fn analyze_spf_record(spf_record: Option<String>) -> SpfRecord {
        match spf_record {
            Some(record) => {
                debug!("Analyzing SPF record: {}", record);
                
                let record_lower = record.to_lowercase();
                
                // Check if it's a valid SPF record
                if !record_lower.starts_with("v=spf1") {
                    warn!("Invalid SPF record format: {}", record);
                    return SpfRecord {
                        exists: false,
                        policy: None,
                        is_strict: false,
                    };
                }
                
                // Determine strictness based on 'all' mechanism
                let is_strict = if record_lower.contains("-all") {
                    debug!("SPF record has strict policy (-all)");
                    true
                } else if record_lower.contains("~all") {
                    debug!("SPF record has soft fail policy (~all)");
                    false
                } else if record_lower.contains("+all") || record_lower.contains("?all") {
                    debug!("SPF record has permissive policy (+all or ?all)");
                    false
                } else {
                    debug!("SPF record has no explicit 'all' mechanism");
                    false
                };
                
                SpfRecord {
                    exists: true,
                    policy: Some(record),
                    is_strict,
                }
            }
            None => {
                debug!("No SPF record found");
                SpfRecord {
                    exists: false,
                    policy: None,
                    is_strict: false,
                }
            }
        }
    }

    /// Analyze DMARC record for policy and settings
    ///
    /// # Arguments
    /// * `dmarc_record` - Raw DMARC record string (e.g., "v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
    ///
    /// # Returns
    /// * `DmarcRecord` with analysis results
    pub fn analyze_dmarc_record(dmarc_record: Option<String>) -> DmarcRecord {
        match dmarc_record {
            Some(record) => {
                debug!("Analyzing DMARC record: {}", record);
                
                let record_lower = record.to_lowercase();
                
                // Check if it's a valid DMARC record
                if !record_lower.starts_with("v=dmarc1") {
                    warn!("Invalid DMARC record format: {}", record);
                    return DmarcRecord {
                        exists: false,
                        policy: None,
                        percentage: None,
                    };
                }
                
                // Parse DMARC tags
                let tags = Self::parse_dmarc_tags(&record);
                
                let policy = tags.get("p").cloned();
                let percentage = tags.get("pct")
                    .and_then(|pct| pct.parse::<u8>().ok())
                    .filter(|&pct| pct <= 100);
                
                debug!("DMARC policy: {:?}, percentage: {:?}", policy, percentage);
                
                DmarcRecord {
                    exists: true,
                    policy,
                    percentage,
                }
            }
            None => {
                debug!("No DMARC record found");
                DmarcRecord {
                    exists: false,
                    policy: None,
                    percentage: None,
                }
            }
        }
    }

    /// Analyze DKIM records for validity and key presence
    ///
    /// # Arguments
    /// * `dkim_records` - Vector of (selector, record) tuples
    ///
    /// # Returns
    /// * `Vec<DkimRecord>` with analysis results
    pub fn analyze_dkim_records(dkim_records: Vec<(String, String)>) -> Vec<DkimRecord> {
        if dkim_records.is_empty() {
            debug!("No DKIM records found");
            return Vec::new();
        }
        
        debug!("Analyzing {} DKIM record(s)", dkim_records.len());
        
        dkim_records
            .into_iter()
            .map(|(selector, record)| {
                debug!("Analyzing DKIM record for selector '{}': {}", selector, record);
                
                let record_lower = record.to_lowercase();
                
                // Check if it's a valid DKIM record
                let is_valid = record_lower.contains("v=dkim1");
                let has_public_key = record_lower.contains("p=") && 
                    !record_lower.contains("p=;") && 
                    !record_lower.contains("p= ;");
                
                if !is_valid {
                    warn!("Invalid DKIM record format for selector '{}': {}", selector, record);
                }
                
                if !has_public_key {
                    debug!("DKIM record for selector '{}' has no public key", selector);
                }
                
                DkimRecord {
                    selector,
                    exists: is_valid,
                    has_public_key,
                }
            })
            .collect()
    }

    /// Calculate overall deliverability risk score based on email authentication
    ///
    /// # Arguments
    /// * `spf` - SPF record analysis
    /// * `dmarc` - DMARC record analysis  
    /// * `dkim` - DKIM records analysis
    ///
    /// # Returns
    /// * Risk score from 0-100 (higher = more risky)
    pub fn calculate_deliverability_risk(
        spf: &SpfRecord,
        dmarc: &DmarcRecord,
        dkim: &[DkimRecord],
    ) -> u8 {
        let mut risk_score = 0u8;
        
        // SPF analysis (0-30 points of risk)
        if !spf.exists {
            risk_score += 15; // No SPF record
            debug!("Risk +15: No SPF record");
        } else if !spf.is_strict {
            risk_score += 10; // Weak SPF policy
            debug!("Risk +10: Weak SPF policy");
        } else {
            debug!("Risk +0: Strong SPF policy");
        }
        
        // DMARC analysis (0-40 points of risk)
        if !dmarc.exists {
            risk_score += 25; // No DMARC record
            debug!("Risk +25: No DMARC record");
        } else {
            match dmarc.policy.as_deref() {
                Some("reject") => {
                    debug!("Risk +0: DMARC policy 'reject'");
                    // Best policy, no additional risk
                }
                Some("quarantine") => {
                    risk_score += 5; // Good but not perfect
                    debug!("Risk +5: DMARC policy 'quarantine'");
                }
                Some("none") => {
                    risk_score += 15; // Monitoring only
                    debug!("Risk +15: DMARC policy 'none'");
                }
                _ => {
                    risk_score += 20; // Unknown or invalid policy
                    debug!("Risk +20: Unknown/invalid DMARC policy");
                }
            }
            
            // Check percentage (if less than 100%, add risk)
            if let Some(pct) = dmarc.percentage {
                if pct < 100 {
                    let pct_risk = ((100 - pct) as f32 * 0.15) as u8; // Max 15 points
                    risk_score += pct_risk;
                    debug!("Risk +{}: DMARC percentage {}%", pct_risk, pct);
                }
            }
        }
        
        // DKIM analysis (0-30 points of risk)
        let valid_dkim_count = dkim.iter().filter(|d| d.exists && d.has_public_key).count();
        
        if valid_dkim_count == 0 {
            risk_score += 20; // No valid DKIM
            debug!("Risk +20: No valid DKIM records");
        } else if valid_dkim_count == 1 {
            risk_score += 5; // Single DKIM (good but could be better)
            debug!("Risk +5: Single DKIM record");
        } else {
            debug!("Risk +0: Multiple DKIM records");
            // Multiple DKIM records, no additional risk
        }
        
        // Ensure risk score doesn't exceed 100
        let final_risk = risk_score.min(100);
        debug!("Final deliverability risk score: {}", final_risk);
        
        final_risk
    }

    /// Parse DMARC record tags into a key-value map
    fn parse_dmarc_tags(record: &str) -> HashMap<String, String> {
        let mut tags = HashMap::new();
        
        for part in record.split(';') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                tags.insert(key, value);
            }
        }
        
        tags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_spf_analysis() {
        // Strict SPF record
        let spf = DeliverabilityAnalyzer::analyze_spf_record(
            Some("v=spf1 include:_spf.google.com -all".to_string())
        );
        assert!(spf.exists);
        assert!(spf.is_strict);
        assert!(spf.policy.is_some());
        
        // Soft fail SPF record
        let spf = DeliverabilityAnalyzer::analyze_spf_record(
            Some("v=spf1 include:_spf.google.com ~all".to_string())
        );
        assert!(spf.exists);
        assert!(!spf.is_strict);
        
        // No SPF record
        let spf = DeliverabilityAnalyzer::analyze_spf_record(None);
        assert!(!spf.exists);
        assert!(!spf.is_strict);
        assert!(spf.policy.is_none());
        
        // Invalid SPF record
        let spf = DeliverabilityAnalyzer::analyze_spf_record(
            Some("invalid record".to_string())
        );
        assert!(!spf.exists);
    }

    #[test]
    fn test_dmarc_analysis() {
        // Reject policy
        let dmarc = DeliverabilityAnalyzer::analyze_dmarc_record(
            Some("v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string())
        );
        assert!(dmarc.exists);
        assert_eq!(dmarc.policy, Some("reject".to_string()));
        assert_eq!(dmarc.percentage, None);
        
        // Quarantine policy with percentage
        let dmarc = DeliverabilityAnalyzer::analyze_dmarc_record(
            Some("v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com".to_string())
        );
        assert!(dmarc.exists);
        assert_eq!(dmarc.policy, Some("quarantine".to_string()));
        assert_eq!(dmarc.percentage, Some(50));
        
        // No DMARC record
        let dmarc = DeliverabilityAnalyzer::analyze_dmarc_record(None);
        assert!(!dmarc.exists);
        
        // Invalid DMARC record
        let dmarc = DeliverabilityAnalyzer::analyze_dmarc_record(
            Some("invalid record".to_string())
        );
        assert!(!dmarc.exists);
    }

    #[test]
    fn test_dkim_analysis() {
        // Valid DKIM records
        let dkim_records = vec![
            ("selector1".to_string(), "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...".to_string()),
            ("selector2".to_string(), "v=DKIM1; k=rsa; p=".to_string()), // No key
        ];
        
        let dkim = DeliverabilityAnalyzer::analyze_dkim_records(dkim_records);
        assert_eq!(dkim.len(), 2);
        assert!(dkim[0].exists);
        assert!(dkim[0].has_public_key);
        assert!(dkim[1].exists);
        assert!(!dkim[1].has_public_key);
        
        // No DKIM records
        let dkim = DeliverabilityAnalyzer::analyze_dkim_records(vec![]);
        assert!(dkim.is_empty());
    }

    #[test]
    fn test_risk_calculation() {
        // Perfect setup: strict SPF, reject DMARC, multiple DKIM
        let spf = SpfRecord {
            exists: true,
            policy: Some("v=spf1 -all".to_string()),
            is_strict: true,
        };
        let dmarc = DmarcRecord {
            exists: true,
            policy: Some("reject".to_string()),
            percentage: None,
        };
        let dkim = vec![
            DkimRecord {
                selector: "s1".to_string(),
                exists: true,
                has_public_key: true,
            },
            DkimRecord {
                selector: "s2".to_string(),
                exists: true,
                has_public_key: true,
            },
        ];
        
        let risk = DeliverabilityAnalyzer::calculate_deliverability_risk(&spf, &dmarc, &dkim);
        assert_eq!(risk, 0); // Perfect setup
        
        // Worst case: no records
        let spf = SpfRecord {
            exists: false,
            policy: None,
            is_strict: false,
        };
        let dmarc = DmarcRecord {
            exists: false,
            policy: None,
            percentage: None,
        };
        let dkim = vec![];
        
        let risk = DeliverabilityAnalyzer::calculate_deliverability_risk(&spf, &dmarc, &dkim);
        assert_eq!(risk, 60); // 15 (SPF) + 25 (DMARC) + 20 (DKIM) = 60
    }

    #[test]
    fn test_dmarc_tag_parsing() {
        let tags = DeliverabilityAnalyzer::parse_dmarc_tags(
            "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com"
        );
        
        assert_eq!(tags.get("v"), Some(&"DMARC1".to_string()));
        assert_eq!(tags.get("p"), Some(&"reject".to_string()));
        assert_eq!(tags.get("pct"), Some(&"100".to_string()));
        assert_eq!(tags.get("rua"), Some(&"mailto:dmarc@example.com".to_string()));
        assert_eq!(tags.get("ruf"), Some(&"mailto:forensic@example.com".to_string()));
    }
}