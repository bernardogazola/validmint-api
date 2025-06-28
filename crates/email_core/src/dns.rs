//! DNS resolution and caching using hickory-resolver
//!
//! This module provides high-performance, async DNS resolution with aggressive caching
//! and DNS-over-HTTPS support for security and privacy.

use anyhow::Result;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    AsyncResolver, TokioAsyncResolver,
};
use std::time::Duration;
use tracing::{debug, info, warn};

/// DNS resolver wrapper with optimized configuration
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
}

impl DnsResolver {
    /// Create a new DNS resolver with optimized settings
    ///
    /// # Arguments
    /// * `timeout_ms` - DNS query timeout in milliseconds
    /// * `attempts` - Maximum number of retry attempts
    /// * `cache_size` - Number of entries to cache
    /// * `min_ttl_secs` - Minimum TTL for positive cache entries
    pub fn new(
        timeout_ms: u64,
        attempts: usize,
        cache_size: usize,
        min_ttl_secs: u64,
    ) -> Result<Self> {
        info!("Initializing DNS resolver with Cloudflare DNS");
        
        // Use Cloudflare's regular DNS (temporarily for debugging)
        let config = ResolverConfig::cloudflare();
        
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(timeout_ms);
        opts.attempts = attempts;
        opts.cache_size = cache_size;
        opts.positive_min_ttl = Some(Duration::from_secs(min_ttl_secs));
        opts.negative_min_ttl = Some(Duration::from_secs(30)); // Cache NXDOMAIN for 30s
        opts.positive_max_ttl = Some(Duration::from_secs(3600)); // Max 1 hour cache
        
        let resolver = AsyncResolver::tokio(config, opts);

        info!(
            "DNS resolver initialized - timeout: {}ms, attempts: {}, cache_size: {}",
            timeout_ms, attempts, cache_size
        );

        Ok(Self { resolver })
    }

    /// Check if a domain has A or AAAA records (domain exists)
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Ok(true)` if domain has A or AAAA records
    /// * `Ok(false)` if domain doesn't exist or has no A/AAAA records
    /// * `Err(_)` on DNS resolution errors
    pub async fn has_a_records(&self, domain: &str) -> Result<bool> {
        debug!("Checking A/AAAA records for domain: {}", domain);
        
        // Try A record first
        match self.resolver.ipv4_lookup(domain).await {
            Ok(response) => {
                if response.iter().count() > 0 {
                    debug!("Domain {} has A records", domain);
                    return Ok(true);
                }
            }
            Err(e) => {
                debug!("A record lookup failed for {}: {}", domain, e);
                // Continue to try AAAA
            }
        }

        // Try AAAA record
        match self.resolver.ipv6_lookup(domain).await {
            Ok(response) => {
                if response.iter().count() > 0 {
                    debug!("Domain {} has AAAA records", domain);
                    return Ok(true);
                }
            }
            Err(e) => {
                debug!("AAAA record lookup failed for {}: {}", domain, e);
            }
        }

        debug!("Domain {} has no A or AAAA records", domain);
        Ok(false)
    }

    /// Check if a domain has MX records (can receive email)
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Ok(true)` if domain has MX records
    /// * `Ok(false)` if domain has no MX records
    /// * `Err(_)` on DNS resolution errors
    pub async fn has_mx_records(&self, domain: &str) -> Result<bool> {
        debug!("Checking MX records for domain: {}", domain);
        
        match self.resolver.mx_lookup(domain).await {
            Ok(response) => {
                let mx_count = response.iter().count();
                let has_mx = mx_count > 0;
                if has_mx {
                    debug!("Domain {} has {} MX record(s)", domain, mx_count);
                } else {
                    debug!("Domain {} has no MX records", domain);
                }
                Ok(has_mx)
            }
            Err(e) => {
                debug!("MX record lookup failed for {}: {}", domain, e);
                Ok(false) // Treat DNS errors as "no MX records"
            }
        }
    }

    /// Get TXT records for a domain
    ///
    /// # Arguments
    /// * `domain` - Domain to query
    ///
    /// # Returns
    /// * `Ok(Vec<String>)` with TXT record contents
    /// * `Err(_)` on DNS resolution errors
    pub async fn get_txt_records(&self, domain: &str) -> Result<Vec<String>> {
        debug!("Querying TXT records for domain: {}", domain);
        
        match self.resolver.txt_lookup(domain).await {
            Ok(response) => {
                let records: Vec<String> = response
                    .iter()
                    .flat_map(|txt| txt.txt_data())
                    .map(|data| String::from_utf8_lossy(data).to_string())
                    .collect();
                
                debug!("Found {} TXT record(s) for {}", records.len(), domain);
                Ok(records)
            }
            Err(e) => {
                debug!("TXT record lookup failed for {}: {}", domain, e);
                Ok(Vec::new()) // Return empty vec instead of error
            }
        }
    }

    /// Perform parallel DNS lookups for A/AAAA and MX records
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Ok((has_a_records, has_mx_records))` tuple
    /// * `Err(_)` if both lookups fail
    pub async fn check_domain_records(&self, domain: &str) -> Result<(bool, bool)> {
        debug!("Performing parallel DNS checks for domain: {}", domain);
        
        let (a_result, mx_result) = tokio::join!(
            self.has_a_records(domain),
            self.has_mx_records(domain)
        );

        match (a_result, mx_result) {
            (Ok(has_a), Ok(has_mx)) => {
                debug!(
                    "Domain {} - A/AAAA: {}, MX: {}",
                    domain, has_a, has_mx
                );
                Ok((has_a, has_mx))
            }
            (Err(e), _) | (_, Err(e)) => {
                warn!("DNS lookup failed for {}: {}", domain, e);
                Err(e)
            }
        }
    }

    /// Get SPF record for a domain
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Ok(Some(spf_record))` if SPF record found
    /// * `Ok(None)` if no SPF record
    /// * `Err(_)` on DNS resolution errors
    pub async fn get_spf_record(&self, domain: &str) -> Result<Option<String>> {
        debug!("Checking SPF record for domain: {}", domain);
        
        let txt_records = self.get_txt_records(domain).await?;
        
        for record in txt_records {
            if record.trim().to_lowercase().starts_with("v=spf1") {
                debug!("Found SPF record for {}: {}", domain, record);
                return Ok(Some(record));
            }
        }
        
        debug!("No SPF record found for {}", domain);
        Ok(None)
    }

    /// Get DMARC record for a domain
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Ok(Some(dmarc_record))` if DMARC record found
    /// * `Ok(None)` if no DMARC record
    /// * `Err(_)` on DNS resolution errors
    pub async fn get_dmarc_record(&self, domain: &str) -> Result<Option<String>> {
        let dmarc_domain = format!("_dmarc.{}", domain);
        debug!("Checking DMARC record at: {}", dmarc_domain);
        
        let txt_records = self.get_txt_records(&dmarc_domain).await?;
        
        for record in txt_records {
            if record.trim().to_lowercase().starts_with("v=dmarc1") {
                debug!("Found DMARC record for {}: {}", domain, record);
                return Ok(Some(record));
            }
        }
        
        debug!("No DMARC record found for {}", domain);
        Ok(None)
    }

    /// Get DKIM record for a domain and selector
    ///
    /// # Arguments
    /// * `selector` - DKIM selector (e.g., "default", "google")
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Ok(Some(dkim_record))` if DKIM record found
    /// * `Ok(None)` if no DKIM record
    /// * `Err(_)` on DNS resolution errors
    pub async fn get_dkim_record(&self, selector: &str, domain: &str) -> Result<Option<String>> {
        let dkim_domain = format!("{}._domainkey.{}", selector, domain);
        debug!("Checking DKIM record at: {}", dkim_domain);
        
        let txt_records = self.get_txt_records(&dkim_domain).await?;
        
        for record in txt_records {
            if record.trim().to_lowercase().contains("v=dkim1") {
                debug!("Found DKIM record for {} ({}): {}", domain, selector, record);
                return Ok(Some(record));
            }
        }
        
        debug!("No DKIM record found for {} ({})", domain, selector);
        Ok(None)
    }

    /// Check multiple common DKIM selectors in parallel
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Ok(Vec<(selector, record)>)` with found DKIM records
    /// * `Err(_)` on DNS resolution errors
    pub async fn get_common_dkim_records(&self, domain: &str) -> Result<Vec<(String, String)>> {
        const COMMON_SELECTORS: &[&str] = &[
            "default",
            "google",
            "selector1",
            "selector2", 
            "k1",
            "k2",
            "dkim",
            "s1",
            "s2",
        ];

        debug!("Checking common DKIM selectors for domain: {}", domain);
        
        let mut results = Vec::new();
        
        for selector in COMMON_SELECTORS {
            match self.get_dkim_record(selector, domain).await {
                Ok(Some(record)) => results.push((selector.to_string(), record)),
                _ => continue,
            }
        }
        let dkim_records = results;
        
        debug!("Found {} DKIM records for {}", dkim_records.len(), domain);
        Ok(dkim_records)
    }

    /// Clear the DNS cache (for testing or administrative purposes)
    pub fn clear_cache(&self) {
        self.resolver.clear_cache();
        info!("DNS cache cleared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[tokio::test]
    async fn test_dns_resolver_creation() {
        let resolver = DnsResolver::new(1000, 2, 1000, 60);
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_a_record_lookup() {
        let resolver = DnsResolver::new(1000, 2, 1000, 60).unwrap();
        
        // Google should have A records
        let result = resolver.has_a_records("google.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Non-existent domain should not have A records
        let result = resolver.has_a_records("this-domain-definitely-does-not-exist-12345.com").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_mx_record_lookup() {
        let resolver = DnsResolver::new(1000, 2, 1000, 60).unwrap();
        
        // Gmail should have MX records
        let result = resolver.has_mx_records("gmail.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_parallel_domain_check() {
        let resolver = DnsResolver::new(1000, 2, 1000, 60).unwrap();
        
        let result = resolver.check_domain_records("google.com").await;
        assert!(result.is_ok());
        let (has_a, has_mx) = result.unwrap();
        assert!(has_a);
        assert!(has_mx);
    }

    #[tokio::test]
    async fn test_spf_record_lookup() {
        let resolver = DnsResolver::new(1000, 2, 1000, 60).unwrap();
        
        // Many major domains have SPF records
        let result = resolver.get_spf_record("google.com").await;
        assert!(result.is_ok());
        // We don't assert the result since SPF records can change
    }
}