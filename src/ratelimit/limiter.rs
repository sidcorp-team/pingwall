use pingora_limits::rate::Rate;
use once_cell::sync::Lazy;
use std::{collections::HashMap, sync::Mutex, time::{SystemTime, UNIX_EPOCH, Duration}};
use std::fmt;
use crate::metrics;

// Route identifier for rate limiting
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

static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(1)));
static mut MAX_REQ_PER_WINDOW: isize = 60;
static mut BLOCK_DURATION_SECS: u64 = 300;

// Store blocked IPs with their expiration time and the path that triggered the block
static BLOCKED_IPS: Lazy<Mutex<HashMap<String, (u64, String)>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// Store per-route rate limit configurations
static ROUTE_LIMITS: Lazy<Mutex<HashMap<String, (isize, u64)>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn init_globals(max_req: isize, block_secs: u64) {
    unsafe {
        MAX_REQ_PER_WINDOW = max_req;
        BLOCK_DURATION_SECS = block_secs;
    }
}

pub fn set_route_limits(path: &str, max_req: isize, block_secs: u64) {
    ROUTE_LIMITS.lock().unwrap().insert(path.to_string(), (max_req, block_secs));
}

pub fn get_max_requests() -> isize {
    unsafe { MAX_REQ_PER_WINDOW }
}

pub fn get_block_duration() -> u64 {
    unsafe { BLOCK_DURATION_SECS }
}

pub fn get_route_max_requests(path: &str) -> isize {
    let route_limits = ROUTE_LIMITS.lock().unwrap();
    match route_limits.get(path) {
        Some((max_req, _)) => *max_req,
        None => get_max_requests(),
    }
}

pub fn get_route_block_duration(path: &str) -> u64 {
    let route_limits = ROUTE_LIMITS.lock().unwrap();
    match route_limits.get(path) {
        Some((_, block_duration)) => *block_duration,
        None => get_block_duration(),
    }
}

pub fn is_blocked(ip: &str) -> bool {
    let now = current_time();
    let mut blocked = BLOCKED_IPS.lock().unwrap();
    blocked.retain(|_, &mut (expires, _)| expires > now);
    blocked.contains_key(ip)
}

pub fn get_blocked_path(ip: &str) -> Option<String> {
    let blocked = BLOCKED_IPS.lock().unwrap();
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

    BLOCKED_IPS.lock().unwrap().insert(ip.to_string(), (expires, block_info));

    // Record metrics
    let domain_str = domain.unwrap_or("unknown");
    metrics::record_rate_limit_block(domain_str, path, ip);

    // Update blocked IPs gauge
    let blocked_count = BLOCKED_IPS.lock().unwrap()
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
