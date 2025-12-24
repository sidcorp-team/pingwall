// src/ratelimit/service.rs
use crate::notification::block_service::{BlockNotifier, BlockNotificationParams};
use crate::ratelimit::limiter::{self, RequestContext};
use crate::utils::ip::get_client_ip;
use crate::utils::cloudflare::CloudflareContext;
use crate::utils::useragent::UserAgentInfo;
use crate::config::{AdvancedRateLimitConfig, RateLimitCondition};
use log::{info, warn, debug};
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

    /// Build request context from session
    fn build_request_context(session: &Session, ip: &str, path: &str, host: Option<&str>) -> RequestContext {
        // Extract Cloudflare context
        let cloudflare = CloudflareContext::from_session(session);

        // Extract User-Agent
        let user_agent = UserAgentInfo::from_session(session);

        info!(
            "Request context: ip={}, path={}, domain={:?}, country={:?}, asn={:?}, ua_category={}",
            ip, path, host, cloudflare.country, cloudflare.asn, user_agent.category.as_str()
        );

        RequestContext {
            ip: ip.to_string(),
            path: path.to_string(),
            domain: host.map(|s| s.to_string()),
            cloudflare,
            user_agent,
        }
    }

    /// Evaluate advanced rate limits and return (is_limited, should_block, reason, max_limit, block_duration, window_secs)
    /// - is_limited: true if any limit exceeded
    /// - should_block: true if IP should be blocked (false for soft limit)
    /// - reason: description of which limit was hit
    /// - max_limit: the max requests value
    /// - block_duration: how long to block (if should_block = true)
    /// - window_secs: the window duration for this limit (for Retry-After header)
    fn evaluate_advanced_limits(
        context: &RequestContext,
        advanced_config: &AdvancedRateLimitConfig,
        global_window_secs: u64,
        default_block_duration: u64,
    ) -> Option<(bool, bool, String, isize, u64, u64)> {
        // 1. Check threat score threshold (highest priority - instant block)
        if let Some(threat_score) = context.cloudflare.threat_score {
            if advanced_config.should_block_threat(threat_score) {
                info!(
                    "Blocking IP {} due to high threat score: {}",
                    context.ip, threat_score
                );
                return Some((
                    true,
                    true,
                    format!("Threat score {} exceeds threshold", threat_score),
                    0,
                    default_block_duration,
                    global_window_secs,  // Use global window for instant blocks
                ));
            }
        }

        // 2. Check country blocklist
        if let Some(ref country) = context.cloudflare.country {
            if advanced_config.is_country_blocked(country) {
                info!("Blocking IP {} from blocked country: {}", context.ip, country);
                return Some((
                    true,
                    true,
                    format!("Country {} is blocked", country),
                    0,
                    default_block_duration,
                    global_window_secs,  // Use global window for country blocks
                ));
            }
        }

        // 3. Check custom rules (if any match, return that rule's limit)
        if let Some(ref rules) = advanced_config.rules {
            for rule in rules {
                if Self::rule_matches(context, rule) {
                    info!(
                        "IP {} matched rule '{}' with limit {}",
                        context.ip, rule.name, rule.max_req
                    );
                    // Rules use global window for now (can be extended later)
                    return Some((
                        false,
                        false,
                        format!("Matched rule: {}", rule.name),
                        rule.max_req,
                        rule.block_duration,
                        global_window_secs,  // Rules use global window
                    ));
                }
            }
        }

        // 4. Check User-Agent pattern limits (check raw User-Agent string for patterns)

        // Country limit
        if let Some(ref country) = context.cloudflare.country {
            if let Some(limit_config) = advanced_config.get_country_limit(country) {
                let max_req = limit_config.max_req();
                let window_secs = limit_config.window_secs().unwrap_or(global_window_secs);
                let block_duration = limit_config.block_duration_secs();

                info!(
                    "Applying country limit for {}: {} req/{} sec (block: {:?})",
                    country, max_req, window_secs, block_duration
                );

                let (is_limited, should_block, _count) = limiter::check_dimension_limit_with_window(
                    context,
                    "country",
                    max_req,
                    window_secs,
                    block_duration,
                );

                if is_limited {
                    let block_dur = block_duration.unwrap_or(default_block_duration);
                    return Some((
                        true,
                        should_block,
                        format!("Country {} limit exceeded", country),
                        max_req,
                        block_dur,
                        window_secs,  // ⭐ Return actual window for this limit
                    ));
                }
            }
        }

        // User-Agent pattern matching
        // Check each configured pattern against the raw User-Agent string
        let ua_lower = context.user_agent.raw.to_lowercase();

        info!(
            "Checking User-Agent limits - raw: '{}', category: {:?}, has_ua_limits: {}",
            context.user_agent.raw,
            context.user_agent.category,
            advanced_config.user_agent_limits.is_some()
        );

        // First check category-based limits (chrome, firefox, bot, etc.)
        let ua_category = context.user_agent.category.as_str();
        if let Some(limit_config) = advanced_config.get_user_agent_limit(ua_category) {
            let max_req = limit_config.max_req();
            let window_secs = limit_config.window_secs().unwrap_or(global_window_secs);
            let block_duration = limit_config.block_duration_secs();

            info!(
                "Applying User-Agent category limit for {}: {} req/{} sec (block: {:?})",
                ua_category, max_req, window_secs, block_duration
            );

            let (is_limited, should_block, _count) = limiter::check_dimension_limit_with_window(
                context,
                "user_agent",
                max_req,
                window_secs,
                block_duration,
            );

            if is_limited {
                let block_dur = block_duration.unwrap_or(default_block_duration);
                return Some((
                    true,
                    should_block,
                    format!("User-Agent {} limit exceeded", ua_category),
                    max_req,
                    block_dur,
                    window_secs,
                ));
            }
        }

        // Then check pattern-based limits (e.g., "fb", "facebook", "google")
        // This allows more granular control than category matching
        if let Some(ref ua_limits) = advanced_config.user_agent_limits {
            info!("Checking {} User-Agent pattern(s)", ua_limits.len());

            for (pattern, limit_config) in ua_limits {
                // Skip category names (already checked above)
                if ["chrome", "firefox", "safari", "edge", "mobile", "bot", "crawler", "curl", "unknown"].contains(&pattern.as_str()) {
                    info!("Skipping category pattern: {}", pattern);
                    continue;
                }

                info!("Checking pattern '{}' against UA '{}'", pattern, ua_lower);

                // Check if User-Agent contains the pattern
                if ua_lower.contains(&pattern.to_lowercase()) {
                    let max_req = limit_config.max_req();
                    let window_secs = limit_config.window_secs().unwrap_or(global_window_secs);
                    let block_duration = limit_config.block_duration_secs();

                    info!(
                        "Applying User-Agent pattern limit for '{}': {} req/{} sec (block: {:?})",
                        pattern, max_req, window_secs, block_duration
                    );

                    let (is_limited, should_block, _count) = limiter::check_dimension_limit_with_window(
                        context,
                        &format!("user_agent_pattern_{}", pattern),
                        max_req,
                        window_secs,
                        block_duration,
                    );

                    if is_limited {
                        let block_dur = block_duration.unwrap_or(default_block_duration);
                        return Some((
                            true,
                            should_block,
                            format!("User-Agent pattern '{}' limit exceeded", pattern),
                            max_req,
                            block_dur,
                            window_secs,
                        ));
                    }
                }
            }
        }

        None
    }

    /// Check if a rule matches the context (ALL conditions must match)
    fn rule_matches(context: &RequestContext, rule: &crate::config::RateLimitRule) -> bool {
        rule.conditions.iter().all(|cond| Self::condition_matches(context, cond))
    }

    /// Check if a single condition matches
    fn condition_matches(context: &RequestContext, condition: &RateLimitCondition) -> bool {
        match condition {
            RateLimitCondition::UserAgentContains { value } => {
                context.user_agent.raw.to_lowercase().contains(&value.to_lowercase())
            }
            RateLimitCondition::CountryIn { values } => {
                context.cloudflare.country_in(values)
            }
            RateLimitCondition::CountryNotIn { values } => {
                !context.cloudflare.country_in(values)
            }
            RateLimitCondition::AsnIn { values } => {
                values.iter().any(|asn| context.cloudflare.asn_matches(asn))
            }
            RateLimitCondition::ThreatScoreAbove { value } => {
                context.cloudflare.is_threat_above(*value)
            }
        }
    }

    pub async fn check_rate_limit(
        &self,
        session: &mut Session,
        ip: &str,
        path: &str,
        advanced_limits: Option<&AdvancedRateLimitConfig>,
    ) -> Result<bool> {
        info!(
            "check_rate_limit called - ip: {}, path: {}, has_advanced_limits: {}",
            ip, path, advanced_limits.is_some()
        );

        // Extract the host header if present for domain-specific rate limiting
        // Try multiple sources in order:
        // 1. Host header (HTTP/1.1)
        // 2. :authority pseudo-header (HTTP/2)
        // 3. Request URI authority (fallback)
        let host = session.req_header()
            .headers
            .get("host")
            .or_else(|| session.req_header().headers.get(":authority"))
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                // Fallback: Extract from request URI
                session.req_header().uri.authority().map(|a| a.as_str())
            });

        // ========== ADVANCED RATE LIMITING ==========
        // If advanced_limits is configured, use multi-dimensional rate limiting
        if let Some(advanced_config) = advanced_limits {
            let context = Self::build_request_context(session, ip, path, host);

            // Get global window and default block duration
            let global_window_secs = limiter::get_rate_limit_window();
            let default_block_duration = limiter::get_block_duration();

            // Evaluate advanced limits (threat score, country block, rules, dimension limits)
            if let Some((is_limited, should_block, reason, limit, block_dur, window_secs)) =
                Self::evaluate_advanced_limits(&context, advanced_config, global_window_secs, default_block_duration)
            {
                if should_block {
                    // Hard block: Block IP for specified duration
                    info!("⛔ Advanced rate limit HARD BLOCK: {} - {} (limit: {}, blocking for {} secs)",
                        reason, ip, limit, block_dur);

                    // Block the IP
                    limiter::block_ip(ip, path, host);

                    self.send_blocked_response(session).await?;
                    return Ok(true);
                } else if is_limited {
                    // Soft limit: Just reject this request, don't block IP
                    info!("⚠️ Advanced rate limit SOFT LIMIT: {} - {} (limit: {}, window: {}s, rejecting request only)",
                        reason, ip, limit, window_secs);
                    // ⭐ Pass actual advanced limit values (not route defaults)
                    self.send_rate_limited_response(session, path, limit, block_dur, window_secs).await?;
                    return Ok(true);
                }
            }

            // If no advanced limit matched, fall through to default IP-based limiting
            info!("No advanced limit matched for IP {}, falling back to IP-based limiting", ip);
        }

        // ========== DEFAULT IP-BASED RATE LIMITING ==========
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

            // Use route values for fallback IP-based limiting
            let window_secs = limiter::get_rate_limit_window();
            // ⭐ Pass route limit values (not advanced limit)
            self.send_rate_limited_response(session, path, max_requests, block_duration, window_secs).await?;
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

    async fn send_rate_limited_response(
        &self,
        session: &mut Session,
        path: &str,
        max_limit: isize,
        block_duration: u64,
        window_secs: u64,
    ) -> Result<()> {
        let mut header = ResponseHeader::build(429, None)?;

        // Standard rate limit headers
        // ⭐ Use actual values from the limit that was triggered, not route defaults
        header.insert_header("X-Rate-Limit-Limit", max_limit.to_string())?;
        header.insert_header("X-Rate-Limit-Remaining", "0")?;
        header.insert_header("X-Rate-Limit-Reset", block_duration.to_string())?;
        header.insert_header("X-Rate-Limit-Path", path)?;

        // Retry-After: Standard HTTP header (RFC 6585)
        // Tells client to wait N seconds before retrying
        // For sliding window: client should wait for window duration
        // ⭐ Uses actual window from the limit that was triggered
        header.insert_header("Retry-After", window_secs.to_string())?;

        // X-RateLimit-Window: Custom header to inform client of window duration
        header.insert_header("X-RateLimit-Window", window_secs.to_string())?;

        session.set_keepalive(None);
        session.write_response_header(Box::new(header), true).await?;
        Ok(())
    }
}