use pingora_limits::rate::Rate;
use once_cell::sync::Lazy;
use std::{collections::HashMap, sync::{Arc, RwLock}, time::{SystemTime, UNIX_EPOCH, Duration}};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::metrics;
use crate::utils::cloudflare::CloudflareContext;
use crate::utils::useragent::UserAgentInfo;

// ==================== Request Context for Multi-Dimensional Rate Limiting ====================

/// Full request context with all dimensions for rate limiting
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub ip: String,
    pub path: String,
    pub domain: Option<String>,
    pub cloudflare: CloudflareContext,
    pub user_agent: UserAgentInfo,
}

impl RequestContext {
    /// Create a rate limit key based on the context and dimension
    pub fn create_key(&self, dimension: &str) -> String {
        let domain_prefix = self.domain.as_deref().unwrap_or("_");

        // Check for user_agent_pattern_* dimensions first
        if dimension.starts_with("user_agent_pattern_") {
            // Extract pattern name (e.g., "facebook" from "user_agent_pattern_facebook")
            let pattern = dimension.strip_prefix("user_agent_pattern_").unwrap_or("");
            // Key does NOT include IP - shared across all IPs with this pattern
            return format!("{}:{}:ua_pattern:{}", domain_prefix, self.path, pattern);
        }

        match dimension {
            "ip" => format!("{}:{}:{}", domain_prefix, self.path, self.ip),
            "user_agent" => {
                let ua_cat = self.user_agent.category.as_str();
                format!("{}:{}:ua:{}", domain_prefix, self.path, ua_cat)
            }
            "asn" => {
                let asn = self.cloudflare.asn.as_deref().unwrap_or("unknown");
                format!("{}:{}:asn:{}", domain_prefix, self.path, asn)
            }
            "country" => {
                let country = self.cloudflare.country.as_deref().unwrap_or("unknown");
                format!("{}:{}:country:{}", domain_prefix, self.path, country)
            }
            _ => format!("{}:{}:{}", domain_prefix, self.path, self.ip), // fallback to IP
        }
    }
}

// Route identifier for rate limiting (LEGACY - kept for backward compatibility)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RouteIdentifier {
    pub path: String,
    pub domain: Option<String>,
    pub ip: String,
}

impl fmt::Display for RouteIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(domain) = &self.domain {
            write!(f, "{}:{}:{}", domain, self.path, self.ip)
        } else {
            write!(f, "{}:{}", self.path, self.ip)
        }
    }
}

// Rate limiter window duration (configurable via init_globals_with_window)
static mut RATE_LIMIT_WINDOW_SECS: u64 = 1;  // Default: 1 second

// Default rate limiter (backward compatible)
static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| {
    unsafe {
        Rate::new(Duration::from_secs(RATE_LIMIT_WINDOW_SECS))
    }
});

// Multiple rate limiters with different windows
// Key: window duration in seconds
// Value: Arc<Rate> for that window
static RATE_LIMITERS: Lazy<RwLock<HashMap<u64, Arc<Rate>>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

static mut MAX_REQ_PER_WINDOW: isize = 60;
static mut BLOCK_DURATION_SECS: u64 = 300;

// Store blocked IPs with their expiration time and the path that triggered the block
// Using RwLock instead of Mutex for better read performance
static BLOCKED_IPS: Lazy<RwLock<HashMap<String, (u64, String)>>> = Lazy::new(|| RwLock::new(HashMap::new()));

// Store per-route rate limit configurations
static ROUTE_LIMITS: Lazy<RwLock<HashMap<String, (isize, u64)>>> = Lazy::new(|| RwLock::new(HashMap::new()));

// Track last cleanup time to avoid cleaning up too frequently
static LAST_CLEANUP: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));
const CLEANUP_INTERVAL_SECS: u64 = 60; // Cleanup every 60 seconds

pub fn init_globals(max_req: isize, block_secs: u64) {
    unsafe {
        MAX_REQ_PER_WINDOW = max_req;
        BLOCK_DURATION_SECS = block_secs;
    }
}

/// Initialize globals with custom rate limit window duration
/// MUST be called BEFORE first rate limit check (before RATE_LIMITER is initialized)
pub fn init_globals_with_window(max_req: isize, block_secs: u64, window_secs: u64) {
    unsafe {
        RATE_LIMIT_WINDOW_SECS = window_secs;
        MAX_REQ_PER_WINDOW = max_req;
        BLOCK_DURATION_SECS = block_secs;
    }
}

pub fn set_route_limits(path: &str, max_req: isize, block_secs: u64) {
    ROUTE_LIMITS.write().unwrap().insert(path.to_string(), (max_req, block_secs));
}

pub fn get_max_requests() -> isize {
    unsafe { MAX_REQ_PER_WINDOW }
}

pub fn get_block_duration() -> u64 {
    unsafe { BLOCK_DURATION_SECS }
}

pub fn get_rate_limit_window() -> u64 {
    unsafe { RATE_LIMIT_WINDOW_SECS }
}

pub fn get_route_max_requests(path: &str) -> isize {
    let route_limits = ROUTE_LIMITS.read().unwrap();
    match route_limits.get(path) {
        Some((max_req, _)) => *max_req,
        None => get_max_requests(),
    }
}

pub fn get_route_block_duration(path: &str) -> u64 {
    let route_limits = ROUTE_LIMITS.read().unwrap();
    match route_limits.get(path) {
        Some((_, block_duration)) => *block_duration,
        None => get_block_duration(),
    }
}

// Cleanup expired IPs periodically (called every CLEANUP_INTERVAL_SECS)
fn cleanup_expired_ips() {
    let now = current_time();
    let last_cleanup = LAST_CLEANUP.load(Ordering::Relaxed);

    // Only cleanup if enough time has passed
    if now - last_cleanup >= CLEANUP_INTERVAL_SECS {
        if LAST_CLEANUP.compare_exchange(
            last_cleanup,
            now,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ).is_ok() {
            // We won the race to do cleanup
            let mut blocked = BLOCKED_IPS.write().unwrap();
            let before_count = blocked.len();
            blocked.retain(|_, &mut (expires, _)| expires > now);
            let after_count = blocked.len();
            if before_count != after_count {
                log::debug!("Cleaned up {} expired blocked IPs", before_count - after_count);
            }
        }
    }
}

pub fn is_blocked(ip: &str) -> bool {
    // Try cleanup in background if needed (non-blocking)
    cleanup_expired_ips();

    // Use read lock for checking (much faster than write lock)
    let blocked = BLOCKED_IPS.read().unwrap();

    // Check if IP is in the blocked list
    if let Some((expires, _)) = blocked.get(ip) {
        // Check if still valid
        *expires > current_time()
    } else {
        false
    }
}

pub fn get_blocked_path(ip: &str) -> Option<String> {
    let blocked = BLOCKED_IPS.read().unwrap();
    blocked.get(ip).map(|(_, path)| path.clone())
}

pub fn block_ip(ip: &str, path: &str, domain: Option<&str>) {
    let now = current_time();

    // Create a combined domain+path key for rate limiting
    let domain_path_key = if let Some(domain_str) = domain {
        format!("{}{}", domain_str, path)
    } else {
        path.to_string()
    };

    let block_duration = get_route_block_duration(&domain_path_key);
    let expires = now + block_duration;

    // Store the domain information along with the path
    let block_info = if let Some(domain_str) = domain {
        format!("{}:{}", domain_str, path)
    } else {
        path.to_string()
    };

    BLOCKED_IPS.write().unwrap().insert(ip.to_string(), (expires, block_info));

    // Record metrics
    let domain_str = domain.unwrap_or("unknown");
    metrics::record_rate_limit_block(domain_str, path, ip);

    // Update blocked IPs gauge
    let blocked_count = BLOCKED_IPS.read().unwrap()
        .values()
        .filter(|(exp, info)| *exp > now && info.starts_with(&format!("{}:{}", domain_str, path)))
        .count();
    metrics::update_blocked_ips(domain_str, path, blocked_count as i64);
}

pub fn get_current_count(ip: &str, path: &str, domain: Option<&str>) -> isize {
    let route_id = RouteIdentifier {
        path: path.to_string(),
        domain: domain.map(|d| d.to_string()),
        ip: ip.to_string(),
    };
    
    // Get current count without incrementing
    RATE_LIMITER.observe(&route_id.to_string(), 0)
}

pub fn check_and_increment(ip: &str, path: &str, domain: Option<&str>) -> bool {
    let route_id = RouteIdentifier {
        path: path.to_string(),
        domain: domain.map(|d| d.to_string()),
        ip: ip.to_string(),
    };
    
    // Create a combined domain+path key for rate limiting
    let domain_path_key = if let Some(domain_str) = domain {
        format!("{}{}", domain_str, path)
    } else {
        path.to_string()
    };
    
    let max_requests = get_route_max_requests(&domain_path_key);
    
    // If max_requests is negative or zero, rate limiting is disabled for this route
    if max_requests <= 0 {
        return false;
    }
    
    let current_count = RATE_LIMITER.observe(&route_id.to_string(), 1);

    current_count > max_requests
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Get or create a rate limiter for a specific window duration
/// Returns Arc<Rate> for the specified window
fn get_rate_limiter_for_window(window_secs: u64) -> Arc<Rate> {
    // Fast path: check if limiter already exists
    {
        let limiters = RATE_LIMITERS.read().unwrap();
        if let Some(limiter) = limiters.get(&window_secs) {
            return Arc::clone(limiter);
        }
    }

    // Slow path: create new limiter
    let mut limiters = RATE_LIMITERS.write().unwrap();

    // Double-check in case another thread created it
    if let Some(limiter) = limiters.get(&window_secs) {
        return Arc::clone(limiter);
    }

    // Create new Rate limiter for this window
    let new_limiter = Arc::new(Rate::new(Duration::from_secs(window_secs)));
    limiters.insert(window_secs, Arc::clone(&new_limiter));

    log::debug!("Created new rate limiter for window: {} seconds", window_secs);

    new_limiter
}

// ==================== Advanced Multi-Dimensional Rate Limiting ====================

/// Check and increment rate limit with full request context
pub fn check_and_increment_advanced(
    context: &RequestContext,
    max_requests: isize,
) -> bool {
    // If max_requests is negative or zero, rate limiting is disabled
    if max_requests <= 0 {
        return false;
    }

    // Create key based on IP (primary dimension)
    let key = context.create_key("ip");
    let current_count = RATE_LIMITER.observe(&key, 1);

    current_count > max_requests
}

/// Get current count for request context
pub fn get_current_count_advanced(context: &RequestContext) -> isize {
    let key = context.create_key("ip");
    RATE_LIMITER.observe(&key, 0)
}

/// Check rate limit for specific dimension (IP, ASN, Country, User-Agent)
pub fn check_dimension_limit(
    context: &RequestContext,
    dimension: &str,
    max_requests: isize,
) -> bool {
    if max_requests <= 0 {
        return false;
    }

    let key = context.create_key(dimension);
    let current_count = RATE_LIMITER.observe(&key, 1);

    current_count > max_requests
}

/// Check rate limit for specific dimension with custom window and block behavior
/// Returns: (is_limited, should_block, current_count)
/// - is_limited: true if request count exceeds max_requests
/// - should_block: true if IP should be blocked (based on block_duration_secs)
/// - current_count: current request count in window
pub fn check_dimension_limit_with_window(
    context: &RequestContext,
    dimension: &str,
    max_requests: isize,
    window_secs: u64,
    block_duration_secs: Option<u64>,
) -> (bool, bool, isize) {
    // Disabled if max_requests <= 0
    if max_requests <= 0 {
        return (false, false, 0);
    }

    // Get the appropriate rate limiter for this window
    let limiter = get_rate_limiter_for_window(window_secs);

    // Create unique key for this dimension
    let key = context.create_key(dimension);

    // Observe and increment
    let current_count = limiter.observe(&key, 1);

    // Check if limit exceeded
    let is_limited = current_count > max_requests;

    // Determine if should block IP
    let should_block = if let Some(duration) = block_duration_secs {
        // If block_duration_secs = 0: soft limit (reject only, don't block)
        // If block_duration_secs > 0: hard block
        is_limited && duration > 0
    } else {
        // None means use default behavior (block if limited)
        is_limited
    };

    (is_limited, should_block, current_count)
}
