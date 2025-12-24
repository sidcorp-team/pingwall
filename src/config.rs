use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    FileReadError(#[from] std::io::Error),
    
    #[error("Failed to parse YAML: {0}")]
    YamlParseError(#[from] serde_yaml::Error),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SslConfig {
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub ca_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Router {
    pub path: String,
    pub upstream: String,
    #[serde(default = "default_route_max_req_per_window")]
    pub max_req_per_window: isize,
    #[serde(default = "default_route_block_duration_secs")]
    pub block_duration_secs: u64,
    #[serde(default)]
    pub follow_domain: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub advanced_limits: Option<AdvancedRateLimitConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainConfig {
    pub domain: String,
    #[serde(default)]
    pub ssl: Option<SslConfig>,
    #[serde(default)]
    pub routers: Vec<Router>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

// Legacy route structure for backward compatibility
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpstreamRoute {
    pub path: String,
    pub upstream: String,
    #[serde(default = "default_route_max_req_per_window")]
    pub max_req_per_window: isize,
    #[serde(default = "default_route_block_duration_secs")]
    pub block_duration_secs: u64,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub follow_domain: bool,
    #[serde(default)]
    pub ssl: Option<SslConfig>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub advanced_limits: Option<AdvancedRateLimitConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_max_req_per_window")]
    pub max_req_per_window: isize,

    #[serde(default = "default_block_duration_secs")]
    pub block_duration_secs: u64,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default)]
    pub upstream_addr: Option<String>,

    #[serde(default = "default_routes")]
    pub routes: Vec<UpstreamRoute>,

    #[serde(default)]
    pub domains: Vec<DomainConfig>,

    #[serde(default = "default_block_url")]
    pub block_url: String,

    #[serde(default = "default_api_key")]
    pub api_key: String,

    #[serde(default = "default_use_cloudflare")]
    pub use_cloudflare: bool,

    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    #[serde(default)]
    pub metrics_port: Option<u16>,

    /// Rate limit window duration in seconds
    /// Default: 1 second (most granular)
    /// Examples: 1 (per second), 60 (per minute), 3600 (per hour)
    #[serde(default = "default_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,
}

fn default_max_req_per_window() -> isize { 60 }
fn default_block_duration_secs() -> u64 { 300 }
fn default_route_max_req_per_window() -> isize { 60 }
fn default_route_block_duration_secs() -> u64 { 300 }
fn default_upstream_addr() -> String { "127.0.0.1:9992".to_string() }
fn default_block_url() -> String { "https://example.com/api/v1/block".to_string() }
fn default_api_key() -> String { "your-api-key".to_string() }
fn default_use_cloudflare() -> bool { false }
fn default_timeout_secs() -> u64 { 30 }
fn default_rate_limit_window_secs() -> u64 { 1 }  // Default: 1 second (most granular)

fn default_routes() -> Vec<UpstreamRoute> {
    vec![
        UpstreamRoute {
            path: "/".to_string(),
            upstream: default_upstream_addr(),
            max_req_per_window: default_route_max_req_per_window(),
            block_duration_secs: default_route_block_duration_secs(),
            domain: None,
            follow_domain: false,
            ssl: None,
            timeout_secs: None,
            advanced_limits: None,
        }
    ]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_req_per_window: default_max_req_per_window(),
            block_duration_secs: default_block_duration_secs(),
            port: None,
            upstream_addr: None,
            routes: default_routes(),
            domains: Vec::new(),
            block_url: default_block_url(),
            api_key: default_api_key(),
            use_cloudflare: default_use_cloudflare(),
            timeout_secs: default_timeout_secs(),
            metrics_port: None,
            rate_limit_window_secs: default_rate_limit_window_secs(),
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Get effective timeout for a route with priority: path > domain > global
    pub fn get_effective_timeout(&self, route: &Router, domain: &DomainConfig) -> u64 {
        route.timeout_secs
            .or(domain.timeout_secs)
            .unwrap_or(self.timeout_secs)
    }

    /// Get effective timeout for legacy routes with priority: path > global
    pub fn get_effective_timeout_legacy(&self, route: &UpstreamRoute) -> u64 {
        route.timeout_secs.unwrap_or(self.timeout_secs)
    }
}

// ==================== Advanced Rate Limiting Configuration ====================

/// Rate limit configuration - supports both simple and extended formats
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum LimitConfig {
    /// Simple format: just a number (e.g., "15169": 200)
    /// Uses global window and route block_duration
    Simple(isize),

    /// Extended format with custom window and block behavior
    /// Example: { max_req: 60, window_secs: 60, block_duration_secs: 0 }
    Extended(ExtendedLimitConfig),
}

impl LimitConfig {
    /// Get max requests from this config
    pub fn max_req(&self) -> isize {
        match self {
            LimitConfig::Simple(max) => *max,
            LimitConfig::Extended(config) => config.max_req,
        }
    }

    /// Get window in seconds (None = use global)
    pub fn window_secs(&self) -> Option<u64> {
        match self {
            LimitConfig::Simple(_) => None,
            LimitConfig::Extended(config) => config.window_secs,
        }
    }

    /// Get block duration (None = use route default, Some(0) = soft limit)
    pub fn block_duration_secs(&self) -> Option<u64> {
        match self {
            LimitConfig::Simple(_) => None,
            LimitConfig::Extended(config) => config.block_duration_secs,
        }
    }
}

/// Extended limit configuration with window and block behavior
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExtendedLimitConfig {
    /// Maximum requests allowed
    pub max_req: isize,

    /// Rate limit window in seconds
    /// - None: Use global rate_limit_window_secs
    /// - Some(1): Per second
    /// - Some(60): Per minute
    /// - Some(3600): Per hour
    /// - Some(86400): Per day
    #[serde(default)]
    pub window_secs: Option<u64>,

    /// Block duration when limit exceeded
    /// - None: Use route's block_duration_secs
    /// - Some(0): Soft limit (reject requests only, don't block IP)
    /// - Some(N): Hard block IP for N seconds
    #[serde(default)]
    pub block_duration_secs: Option<u64>,
}

/// Advanced rate limiting configuration with multi-dimensional limits
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AdvancedRateLimitConfig {
    /// User-Agent based limits
    /// Simple: "bot": 10
    /// Extended: "bot": { max_req: 10, window_secs: 1, block_duration_secs: 300 }
    #[serde(default)]
    pub user_agent_limits: Option<HashMap<String, LimitConfig>>,

    /// ASN-based limits
    /// Simple: "15169": 200
    /// Extended: "32934": { max_req: 60, window_secs: 60, block_duration_secs: 0 }
    #[serde(default)]
    pub asn_limits: Option<HashMap<String, LimitConfig>>,

    /// Country-based limits
    /// Simple: "CN": 50
    /// Extended: "CN": { max_req: 50, window_secs: 3600, block_duration_secs: 3600 }
    #[serde(default)]
    pub country_limits: Option<HashMap<String, LimitConfig>>,

    /// List of countries to completely block (2-letter ISO codes)
    #[serde(default)]
    pub block_countries: Option<Vec<String>>,

    /// Cloudflare threat score threshold (0-100). Block if above this value.
    #[serde(default)]
    pub threat_score_threshold: Option<u8>,

    /// Custom rules with complex conditions
    #[serde(default)]
    pub rules: Option<Vec<RateLimitRule>>,
}

/// A rate limit rule with conditions
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimitRule {
    /// Rule name (for logging/debugging)
    pub name: String,

    /// Conditions that must ALL be true (AND logic)
    pub conditions: Vec<RateLimitCondition>,

    /// Max requests if this rule matches
    pub max_req: isize,

    /// Block duration in seconds if this rule matches
    pub block_duration: u64,
}

/// A condition for rate limit rules
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RateLimitCondition {
    /// User-Agent contains string (case-insensitive)
    UserAgentContains { value: String },

    /// Country is in the list
    CountryIn { values: Vec<String> },

    /// Country is NOT in the list
    CountryNotIn { values: Vec<String> },

    /// ASN is in the list
    AsnIn { values: Vec<String> },

    /// Threat score is above threshold
    ThreatScoreAbove { value: u8 },
}

impl AdvancedRateLimitConfig {
    /// Get User-Agent limit config for a specific category
    pub fn get_user_agent_limit(&self, category: &str) -> Option<&LimitConfig> {
        self.user_agent_limits
            .as_ref()
            .and_then(|limits| limits.get(category))
    }

    /// Get ASN limit config
    pub fn get_asn_limit(&self, asn: &str) -> Option<&LimitConfig> {
        self.asn_limits
            .as_ref()
            .and_then(|limits| limits.get(asn))
    }

    /// Get country limit config
    pub fn get_country_limit(&self, country: &str) -> Option<&LimitConfig> {
        self.country_limits
            .as_ref()
            .and_then(|limits| limits.get(country))
    }

    /// Check if country is in block list
    pub fn is_country_blocked(&self, country: &str) -> bool {
        self.block_countries
            .as_ref()
            .map_or(false, |blocked| {
                blocked.iter().any(|c| c.eq_ignore_ascii_case(country))
            })
    }

    /// Check if threat score should be blocked
    pub fn should_block_threat(&self, threat_score: u8) -> bool {
        self.threat_score_threshold
            .map_or(false, |threshold| threat_score > threshold)
    }
}
