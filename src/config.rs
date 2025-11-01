use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
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
