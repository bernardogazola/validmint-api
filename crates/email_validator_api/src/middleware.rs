//! Middleware for error handling, request processing, and observability
//!
//! This module contains middleware functions for common request processing
//! tasks like error handling, request logging, and security.

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Global error handler middleware
///
/// This middleware catches any unhandled errors and converts them into
/// standardized JSON error responses to prevent information leakage.
#[allow(dead_code)]
pub async fn error_handler(request: Request, next: Next) -> Response {
    let request_id = extract_or_generate_request_id(request.headers());
    
    debug!("Processing request: {}", request_id);
    
    let response = next.run(request).await;
    
    // Check if the response indicates an error
    if response.status().is_server_error() {
        error!("Server error occurred for request: {}", request_id);
        
        // Create a generic error response to avoid information leakage
        let error_body = json!({
            "error": "Internal server error occurred",
            "error_code": "INTERNAL_ERROR",
            "request_id": request_id,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });
        
        return (StatusCode::INTERNAL_SERVER_ERROR, error_body.to_string()).into_response();
    }
    
    if response.status().is_client_error() {
        warn!("Client error for request {}: {}", request_id, response.status());
    }
    
    response
}

/// Request ID extraction and generation
///
/// Extracts request ID from headers or generates a new one.
/// Useful for distributed tracing and request correlation.
#[allow(dead_code)]
fn extract_or_generate_request_id(headers: &HeaderMap) -> String {
    // Try to extract from common request ID headers
    if let Some(trace_id) = headers.get("x-trace-id") {
        if let Ok(id) = trace_id.to_str() {
            return id.to_string();
        }
    }
    
    if let Some(request_id) = headers.get("x-request-id") {
        if let Ok(id) = request_id.to_str() {
            return id.to_string();
        }
    }
    
    if let Some(rapidapi_proxy_secret) = headers.get("x-rapidapi-proxy-secret") {
        if let Ok(secret) = rapidapi_proxy_secret.to_str() {
            // Use the RapidAPI proxy secret as a request identifier
            // (this is safe to log as it's meant for identification)
            debug!("Request from RapidAPI proxy: {}", &secret[..8.min(secret.len())]);
        }
    }
    
    // Generate a new UUID if no existing request ID found
    Uuid::new_v4().to_string()
}

/// Request validation middleware
///
/// Performs basic request validation before processing.
#[allow(dead_code)]
pub async fn request_validator(request: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = request.headers();
    
    // Check for required headers in production environments
    if cfg!(not(debug_assertions)) {
        // In production, we might want to validate RapidAPI headers
        if let Some(_rapidapi_key) = headers.get("x-rapidapi-key") {
            debug!("Request authenticated with RapidAPI key");
            // RapidAPI gateway should handle authentication, but we can log it
        }
    }
    
    // Validate content-type for POST requests
    if request.method() == axum::http::Method::POST {
        if let Some(content_type) = headers.get("content-type") {
            if let Ok(ct) = content_type.to_str() {
                if !ct.starts_with("application/json") {
                    warn!("Invalid content-type for POST request: {}", ct);
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }
            }
        } else {
            warn!("Missing content-type header for POST request");
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    
    Ok(next.run(request).await)
}

/// Security headers middleware
///
/// Adds security-related headers to all responses.
#[allow(dead_code)]
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    
    // Add security headers
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert("referrer-policy", "strict-origin-when-cross-origin".parse().unwrap());
    
    // Add API-specific headers
    headers.insert("x-api-version", env!("CARGO_PKG_VERSION").parse().unwrap());
    headers.insert("x-powered-by", "email-validator-api".parse().unwrap());
    
    response
}

/// Rate limiting middleware (local, backup to RapidAPI)
///
/// Provides local rate limiting as a backup to RapidAPI's rate limiting.
/// This is primarily for protection against abuse and should be configured
/// with higher limits than RapidAPI's plans.
#[cfg(feature = "local_rate_limit")]
pub async fn rate_limiter(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    
    // This is a simple in-memory rate limiter
    // In production, you might want to use Redis or a more sophisticated solution
    static RATE_LIMIT_STORE: std::sync::OnceLock<Arc<Mutex<HashMap<String, (Instant, u32)>>>> = 
        std::sync::OnceLock::new();
    
    let store = RATE_LIMIT_STORE.get_or_init(|| {
        Arc::new(Mutex::new(HashMap::new()))
    });
    
    // Extract client identifier (IP address)
    let client_ip = extract_client_ip(request.headers())
        .unwrap_or_else(|| "unknown".to_string());
    
    const RATE_LIMIT: u32 = 100; // requests per minute
    const WINDOW: Duration = Duration::from_secs(60);
    
    let now = Instant::now();
    let mut store = store.lock().unwrap();
    
    match store.get_mut(&client_ip) {
        Some((last_reset, count)) => {
            if now.duration_since(*last_reset) > WINDOW {
                // Reset the window
                *last_reset = now;
                *count = 1;
            } else {
                *count += 1;
                if *count > RATE_LIMIT {
                    warn!("Rate limit exceeded for IP: {}", client_ip);
                    return Err(StatusCode::TOO_MANY_REQUESTS);
                }
            }
        }
        None => {
            store.insert(client_ip.clone(), (now, 1));
        }
    }
    
    // Clean up old entries (simple cleanup)
    store.retain(|_, (last_reset, _)| now.duration_since(*last_reset) <= WINDOW);
    
    Ok(next.run(request).await)
}

/// Extract client IP address from request headers
#[allow(dead_code)]
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Try various headers in order of preference
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP in the chain
            if let Some(ip) = forwarded_str.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
    }
    
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }
    
    if let Some(cf_connecting_ip) = headers.get("cf-connecting-ip") {
        if let Ok(ip_str) = cf_connecting_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }
    
    None
}

/// Request size limiter middleware
///
/// Prevents excessively large requests that could cause memory issues.
#[allow(dead_code)]
pub async fn request_size_limiter(request: Request, next: Next) -> Result<Response, StatusCode> {
    const MAX_BODY_SIZE: usize = 1024; // 1KB should be plenty for domain names
    
    if let Some(content_length) = request.headers().get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > MAX_BODY_SIZE {
                    warn!("Request body too large: {} bytes", length);
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
        }
    }
    
    Ok(next.run(request).await)
}

/// Helper function to convert StatusCode to proper error response
#[allow(dead_code)]
pub fn status_code_to_response(status_code: StatusCode) -> Response {
    let error_message = match status_code {
        StatusCode::BAD_REQUEST => "Bad Request",
        StatusCode::UNAUTHORIZED => "Unauthorized", 
        StatusCode::FORBIDDEN => "Forbidden",
        StatusCode::NOT_FOUND => "Not Found",
        StatusCode::METHOD_NOT_ALLOWED => "Method Not Allowed",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "Unsupported Media Type",
        StatusCode::TOO_MANY_REQUESTS => "Too Many Requests",
        StatusCode::PAYLOAD_TOO_LARGE => "Payload Too Large",
        StatusCode::INTERNAL_SERVER_ERROR => "Internal Server Error",
        _ => "Unknown Error",
    };
    
    let error_body = json!({
        "error": error_message,
        "error_code": format!("{}", status_code.as_u16()),
        "request_id": Uuid::new_v4().to_string(),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    (status_code, error_body.to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_client_ip() {
        let mut headers = HeaderMap::new();
        
        // Test X-Forwarded-For
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1, 10.0.0.1"));
        assert_eq!(extract_client_ip(&headers), Some("192.168.1.1".to_string()));
        
        // Test X-Real-IP
        headers.clear();
        headers.insert("x-real-ip", HeaderValue::from_static("192.168.1.2"));
        assert_eq!(extract_client_ip(&headers), Some("192.168.1.2".to_string()));
        
        // Test CF-Connecting-IP
        headers.clear();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("192.168.1.3"));
        assert_eq!(extract_client_ip(&headers), Some("192.168.1.3".to_string()));
        
        // Test no headers
        headers.clear();
        assert_eq!(extract_client_ip(&headers), None);
    }

    #[test]
    fn test_extract_or_generate_request_id() {
        let mut headers = HeaderMap::new();
        
        // Test X-Trace-ID
        headers.insert("x-trace-id", HeaderValue::from_static("trace-123"));
        assert_eq!(extract_or_generate_request_id(&headers), "trace-123");
        
        // Test X-Request-ID
        headers.clear();
        headers.insert("x-request-id", HeaderValue::from_static("req-456"));
        assert_eq!(extract_or_generate_request_id(&headers), "req-456");
        
        // Test generation when no headers present
        headers.clear();
        let generated_id = extract_or_generate_request_id(&headers);
        assert!(!generated_id.is_empty());
        assert!(Uuid::parse_str(&generated_id).is_ok());
    }
}