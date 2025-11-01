use pingora_proxy::Session;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, Ordering};

// Global configuration flag for using Cloudflare
static USE_CLOUDFLARE: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

// Function to initialize the configuration
pub fn set_use_cloudflare(use_cf: bool) {
    USE_CLOUDFLARE.store(use_cf, Ordering::SeqCst);
}

pub fn get_client_ip(session: &mut Session) -> Option<String> {
    // Check if we should use Cloudflare headers first
    if USE_CLOUDFLARE.load(Ordering::SeqCst) {
        // Cloudflare proxy logic - prioritize CF-specific headers
        let cf_ip = session.req_header().headers.get("CF-Connecting-IP")
            .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
            
        if cf_ip.is_some() {
            return cf_ip;
        }
        
        // Try X-Forwarded-For (Cloudflare sets this too)
        let forwarded_ip = session.req_header().headers.get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next().map(|s| s.trim().to_string()));
            
        if forwarded_ip.is_some() {
            return forwarded_ip;
        }
        
        // Try True-Client-IP (another Cloudflare header)
        let true_client_ip = session.req_header().headers.get("True-Client-IP")
            .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
            
        if true_client_ip.is_some() {
            return true_client_ip;
        }
    }
    
    // If not using Cloudflare or CF headers weren't found, try direct client address
    if let Some(addr) = session.client_addr() {
        let ip = addr.to_string().split(':').next().unwrap_or("127.0.0.1").to_string();
        return Some(ip);
    }

    // Standard fallback headers for any proxy
    let real_ip = session.req_header().headers.get("X-Real-IP")
        .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
        
    if real_ip.is_some() {
        return real_ip;
    }
    
    let forwarded_ip = session.req_header().headers.get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next().map(|s| s.trim().to_string()));
        
    if forwarded_ip.is_some() {
        return forwarded_ip;
    }

    Some("127.0.0.1".to_string())
}