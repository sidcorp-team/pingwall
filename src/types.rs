use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct RateLimitExceeded {
    pub message: String,
    pub ip: String,
    pub lock_duration: u64,
    pub domain: Option<String>,
    pub path: String,
    pub request_url: Option<String>,
    pub user_agent: Option<String>,
    pub current_count: isize,
    pub max_requests: isize,
    pub timestamp: String,
}
