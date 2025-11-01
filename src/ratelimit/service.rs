// src/ratelimit/service.rs
use crate::notification::block_service::{BlockNotifier, BlockNotificationParams};
use crate::ratelimit::limiter;
use crate::utils::ip::get_client_ip;
use log::{info, warn};
use pingora::http::ResponseHeader;
use pingora_core::Result;
use pingora_proxy::Session;

#[derive(Clone)]
pub struct RateLimitService {
    pub block_notifier: BlockNotifier,
}

impl RateLimitService {
    pub fn new(block_notifier: BlockNotifier) -> Self {
        Self { block_notifier }
    }

    pub async fn check_rate_limit(&self, session: &mut Session, ip: &str, path: &str) -> Result<bool> {
        // Extract the host header if present for domain-specific rate limiting
        let host = session.req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok());
            
        // Create a combined domain+path key for rate limiting
        let domain_path_key = if let Some(host_value) = host {
            format!("{}{}", host_value, path)
        } else {
            path.to_string()
        };
        
        // Get rate limit settings using the combined key
        let max_requests = limiter::get_route_max_requests(&domain_path_key);
        let block_duration = limiter::get_route_block_duration(&domain_path_key);
        
        // Check if IP is already blocked
        if limiter::is_blocked(ip) {
            let blocked_path = limiter::get_blocked_path(ip).unwrap_or_else(|| "unknown".to_string());
            info!("Blocked request from IP: {} (previously blocked on path: {})", ip, blocked_path);
            self.send_blocked_response(session).await?;
            return Ok(true);
        }

        // Log request details for debugging
        let request_url = format!("{}", session.req_header().uri);
        if let Some(host_value) = host {
            info!("Request from IP: {} to domain: {}, path: {} (URL: {}) - Rate limit: {}", 
                ip, host_value, path, request_url, max_requests);
        } else {
            info!("Request from IP: {} to path: {} (URL: {}) - Rate limit: {}", 
                ip, path, request_url, max_requests);
        }

        // Check if rate limit is exceeded and increment the counter
        if limiter::check_and_increment(ip, path, host) {
            // Get current count after increment
            let current_count = limiter::get_current_count(ip, path, host);
            
            if let Some(host_value) = host {
                info!("⚠️ Rate limit exceeded for IP: {} on domain: {}, path: {} (count: {}/{} requests)", 
                     ip, host_value, path, current_count, max_requests);
            } else {
                info!("⚠️ Rate limit exceeded for IP: {} on path: {} (count: {}/{} requests)", 
                     ip, path, current_count, max_requests);
            }
            
            limiter::block_ip(ip, path, host);
            
            // Get the User-Agent if available
            let user_agent = session.req_header()
                .headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            
            // Send notification with enhanced information and better error handling
            info!("Attempting to send rate limit exceeded notification for IP: {} on path: {}", ip, path);
            
            let notification_params = BlockNotificationParams {
                ip,
                block_duration,
                path,
                domain: host,          // Domain information
                request_url: Some(request_url.clone()),
                user_agent: user_agent.clone(),
                current_count,  // Current count that triggered the block
                max_requests    // Maximum allowed requests
            };

            match self.block_notifier.notify_block(notification_params).await {
                Ok(_) => info!("Successfully sent rate limit exceeded notification for IP: {} on path: {}", ip, path),
                Err(e) => warn!("Failed to send rate limit exceeded notification: {}", e)
            }
            
            self.send_rate_limited_response(session, path).await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn send_blocked_response(&self, session: &mut Session) -> Result<()> {
        // Extract IP and path information for notification
        let ip = match get_client_ip(session) {
            Some(ip) => ip,
            None => "unknown".to_string(),
        };
        
        // Extract the host header if present for domain information
        let host = session.req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok());
            
        // Get the path from the request URI
        let path = session.req_header().uri.path();
        
        // Get the blocked path from the limiter (if available)
        let blocked_path = limiter::get_blocked_path(&ip).unwrap_or_else(|| path.to_string());
        
        // Get rate limit settings for the blocked path
        let max_requests = limiter::get_route_max_requests(&blocked_path);
        let block_duration = limiter::get_route_block_duration(&blocked_path);
        
        // Get the User-Agent if available
        let user_agent = session.req_header()
            .headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
            
        // Get the request URL
        let request_url = format!("{}", session.req_header().uri);
        
        // Send notification for repeated blocked request with better error handling
        info!("Attempting to send block notification for IP: {} on path: {}", ip, blocked_path);
        
        let notification_params = BlockNotificationParams {
            ip: &ip,
            block_duration,
            path: &blocked_path,
            domain: host,
            request_url: Some(request_url.clone()),
            user_agent: user_agent.clone(),
            current_count: max_requests + 1,  // Current count (over the limit)
            max_requests       // Maximum allowed requests
        };

        match self.block_notifier.notify_block(notification_params).await {
            Ok(_) => info!("Successfully sent block notification for IP: {} on path: {}", ip, blocked_path),
            Err(e) => warn!("Failed to send block notification: {}", e)
        }
        
        // Send 429 response
        let mut header = ResponseHeader::build(429, None)?;
        header.insert_header("X-Rate-Limit-Status", "Blocked")?;

        session.set_keepalive(None);
        session.write_response_header(Box::new(header), true).await?;
        Ok(())
    }

    async fn send_rate_limited_response(&self, session: &mut Session, path: &str) -> Result<()> {
        let mut header = ResponseHeader::build(429, None)?;
        header.insert_header("X-Rate-Limit-Limit", limiter::get_route_max_requests(path).to_string())?;
        header.insert_header("X-Rate-Limit-Remaining", "0")?;
        header.insert_header("X-Rate-Limit-Reset", limiter::get_route_block_duration(path).to_string())?;
        header.insert_header("X-Rate-Limit-Path", path)?;

        session.set_keepalive(None);
        session.write_response_header(Box::new(header), true).await?;
        Ok(())
    }
}