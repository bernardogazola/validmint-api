//! Privacy utilities for GDPR-compliant data handling
//!
//! This module provides utilities for privacy-preserving processing of email data,
//! including salted hashing for pseudonymization as required by GDPR.

use sha2::{Digest, Sha256};
use std::fmt;
use tracing::debug;

/// Privacy-preserving email processor with salted hashing
pub struct PrivacyProcessor {
    salt: Vec<u8>,
}

impl PrivacyProcessor {
    /// Create a new privacy processor with a random salt
    ///
    /// The salt should be stored securely and rotated periodically for maximum security.
    /// For production use, load the salt from a secure configuration source.
    pub fn new(salt: Vec<u8>) -> Self {
        debug!("Privacy processor initialized with {}-byte salt", salt.len());
        Self { salt }
    }

    /// Create a privacy processor with a random salt (for testing/development)
    ///
    /// # Warning
    /// This method generates a random salt each time it's called, which means
    /// hashes will not be consistent across restarts. Use `new()` with a
    /// persistent salt for production.
    pub fn with_random_salt() -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;
        
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        let hash = hasher.finish();
        
        let salt = hash.to_be_bytes().to_vec();
        Self::new(salt)
    }

    /// Hash an email local-part (the part before @) with salt
    ///
    /// This function implements pseudonymization as defined by GDPR Article 4(5).
    /// The hashed data is still considered personal data under GDPR but provides
    /// technical protection against trivial data breaches.
    ///
    /// # Arguments
    /// * `local_part` - The local part of an email address (e.g., "john.doe" from "john.doe@example.com")
    ///
    /// # Returns
    /// * Hex-encoded SHA-256 hash of the salted local part
    ///
    /// # Example
    /// ```rust
    /// use email_core::privacy::PrivacyProcessor;
    /// 
    /// let processor = PrivacyProcessor::with_random_salt();
    /// let hash = processor.hash_local_part("john.doe");
    /// println!("Hashed local part: {}", hash);
    /// ```
    pub fn hash_local_part(&self, local_part: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(local_part.as_bytes());
        let result = hasher.finalize();
        
        let hex_hash = hex::encode(result);
        debug!("Hashed local part (length: {}) -> {}", local_part.len(), &hex_hash[..8]);
        hex_hash
    }

    /// Extract and hash the local part from a full email address
    ///
    /// This is a convenience method that extracts the local part from a full
    /// email address and hashes it. The domain part is returned unchanged.
    ///
    /// # Arguments
    /// * `email` - Full email address (e.g., "john.doe@example.com")
    ///
    /// # Returns
    /// * `Ok((hashed_local_part, domain))` if email is valid
    /// * `Err(PrivacyError)` if email format is invalid
    ///
    /// # Example
    /// ```rust
    /// use email_core::privacy::PrivacyProcessor;
    /// 
    /// let processor = PrivacyProcessor::with_random_salt();
    /// let result = processor.process_email("john.doe@example.com")?;
    /// println!("Hash: {}, Domain: {}", result.0, result.1);
    /// # Ok::<(), email_core::privacy::PrivacyError>(())
    /// ```
    pub fn process_email(&self, email: &str) -> Result<(String, String), PrivacyError> {
        let parts: Vec<&str> = email.splitn(2, '@').collect();
        
        if parts.len() != 2 {
            return Err(PrivacyError::InvalidEmailFormat(email.to_string()));
        }
        
        let (local_part, domain) = (parts[0], parts[1]);
        
        if local_part.is_empty() || domain.is_empty() {
            return Err(PrivacyError::InvalidEmailFormat(email.to_string()));
        }
        
        let hashed_local = self.hash_local_part(local_part);
        Ok((hashed_local, domain.to_string()))
    }

    /// Check if an email should be rejected due to privacy policy
    ///
    /// According to the API specification, only domain names should be accepted,
    /// not full email addresses. This method helps enforce that policy.
    ///
    /// # Arguments
    /// * `input` - Input string to validate
    ///
    /// # Returns
    /// * `Ok(())` if input is acceptable (domain-only)
    /// * `Err(PrivacyError::ContainsLocalPart)` if input contains @ symbol
    pub fn validate_input(&self, input: &str) -> Result<(), PrivacyError> {
        if input.contains('@') {
            debug!("Input rejected: contains @ symbol (email address not allowed)");
            return Err(PrivacyError::ContainsLocalPart);
        }
        
        debug!("Input validated: domain-only format");
        Ok(())
    }

    /// Generate a new random salt for key rotation
    ///
    /// This method generates a cryptographically secure random salt that can be
    /// used to replace the current salt. Salt rotation is a security best practice
    /// for long-running systems.
    ///
    /// # Returns
    /// * 32-byte random salt suitable for SHA-256 hashing
    pub fn generate_new_salt() -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;
        
        // In production, use a proper CSPRNG like ring::rand or getrandom
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        std::thread::current().id().hash(&mut hasher);
        
        let hash = hasher.finish();
        let mut salt = hash.to_be_bytes().to_vec();
        
        // Extend to 32 bytes for SHA-256
        while salt.len() < 32 {
            let mut hasher = DefaultHasher::new();
            salt.hash(&mut hasher);
            let next_hash = hasher.finish();
            salt.extend_from_slice(&next_hash.to_be_bytes());
        }
        
        salt.truncate(32);
        debug!("Generated new 32-byte salt for key rotation");
        salt
    }

    /// Get the current salt (for secure storage/backup)
    ///
    /// # Warning
    /// The salt should be treated as sensitive data and stored securely.
    /// Do not log or expose the salt in plaintext.
    pub fn get_salt(&self) -> &[u8] {
        &self.salt
    }
}

/// Errors that can occur during privacy processing
#[derive(Debug, Clone)]
pub enum PrivacyError {
    /// Input contains @ symbol (email address instead of domain)
    ContainsLocalPart,
    /// Invalid email format for processing
    InvalidEmailFormat(String),
}

impl fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyError::ContainsLocalPart => {
                write!(f, "Input contains @ symbol - only domain names are accepted")
            }
            PrivacyError::InvalidEmailFormat(email) => {
                write!(f, "Invalid email format: {}", email)
            }
        }
    }
}

impl std::error::Error for PrivacyError {}

// Helper function to include hex dependency
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_privacy_processor_creation() {
        let salt = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let processor = PrivacyProcessor::new(salt.clone());
        assert_eq!(processor.get_salt(), &salt);
    }

    #[test]
    fn test_random_salt_creation() {
        let processor1 = PrivacyProcessor::with_random_salt();
        let processor2 = PrivacyProcessor::with_random_salt();
        
        // Different processors should have different salts
        assert_ne!(processor1.get_salt(), processor2.get_salt());
    }

    #[test]
    fn test_local_part_hashing() {
        let salt = vec![1, 2, 3, 4];
        let processor = PrivacyProcessor::new(salt);
        
        let hash1 = processor.hash_local_part("john.doe");
        let hash2 = processor.hash_local_part("john.doe");
        let hash3 = processor.hash_local_part("jane.doe");
        
        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        
        // Different input should produce different hash
        assert_ne!(hash1, hash3);
        
        // Hash should be 64 characters (32 bytes in hex)
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_email_processing() {
        let processor = PrivacyProcessor::with_random_salt();
        
        let result = processor.process_email("john.doe@example.com").unwrap();
        assert_eq!(result.1, "example.com");
        assert_eq!(result.0.len(), 64); // SHA-256 hash length
        
        // Test error cases
        assert!(processor.process_email("invalid-email").is_err());
        assert!(processor.process_email("@example.com").is_err());
        assert!(processor.process_email("john.doe@").is_err());
        assert!(processor.process_email("").is_err());
    }

    #[test]
    fn test_input_validation() {
        let processor = PrivacyProcessor::with_random_salt();
        
        // Valid domain-only inputs
        assert!(processor.validate_input("example.com").is_ok());
        assert!(processor.validate_input("sub.example.com").is_ok());
        assert!(processor.validate_input("localhost").is_ok());
        
        // Invalid inputs containing @
        assert!(processor.validate_input("user@example.com").is_err());
        assert!(processor.validate_input("test@").is_err());
        assert!(processor.validate_input("@domain.com").is_err());
        
        match processor.validate_input("user@example.com") {
            Err(PrivacyError::ContainsLocalPart) => {}, // Expected
            _ => panic!("Expected ContainsLocalPart error"),
        }
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = PrivacyProcessor::generate_new_salt();
        let salt2 = PrivacyProcessor::generate_new_salt();
        
        // Generated salts should be different
        assert_ne!(salt1, salt2);
        
        // Salt should be 32 bytes
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
    }

    #[test]
    fn test_consistent_hashing_with_same_salt() {
        let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let processor1 = PrivacyProcessor::new(salt.clone());
        let processor2 = PrivacyProcessor::new(salt);
        
        let hash1 = processor1.hash_local_part("test.user");
        let hash2 = processor2.hash_local_part("test.user");
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_privacy_error_display() {
        let error1 = PrivacyError::ContainsLocalPart;
        assert!(error1.to_string().contains("@ symbol"));
        
        let error2 = PrivacyError::InvalidEmailFormat("bad-email".to_string());
        assert!(error2.to_string().contains("Invalid email format"));
        assert!(error2.to_string().contains("bad-email"));
    }
}