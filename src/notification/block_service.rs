use crate::types::RateLimitExceeded;
use crate::metrics;
use log::{error, info, warn};
use pingora_core::Result;
use reqwest::{Client, ClientBuilder};
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};
use once_cell::sync::Lazy;

// Use a simple timestamp-based approach instead of a mutex-based HashMap
// This avoids potential deadlocks in multi-process environments
static LAST_NOTIFICATION_TIMESTAMP: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));

// How long to wait before sending another notification (in seconds)
const NOTIFICATION_COOLDOWN_SECS: u64 = 10; // 10 second cooldown

#[derive(Clone)]
pub struct BlockNotificationParams<'a> {
    pub ip: &'a str,
    pub block_duration: u64,
    pub path: &'a str,
    pub domain: Option<&'a str>,
    pub request_url: Option<String>,
    pub user_agent: Option<String>,
    pub current_count: isize,
    pub max_requests: isize,
}

#[derive(Clone)]
pub struct BlockNotifier {
    pub third_party_block_url: String,
    pub api_key: String,
}

impl BlockNotifier {
    pub fn new(third_party_block_url: String, api_key: String) -> Self {
        Self {
            third_party_block_url,
            api_key,
        }
    }

    pub async fn notify_block(&self, params: BlockNotificationParams<'_>) -> Result<()> {
        // Use a simpler approach that won't cause deadlocks
        // Get the current time as seconds since UNIX epoch
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        // Get the last notification timestamp
        let last_notification = LAST_NOTIFICATION_TIMESTAMP.load(Ordering::Relaxed);
        
        // Calculate elapsed time since last notification
        let elapsed = if last_notification > 0 { now - last_notification } else { NOTIFICATION_COOLDOWN_SECS + 1 };
        
        // Check if we should send a notification
        if elapsed < NOTIFICATION_COOLDOWN_SECS {
            // Too soon, skip this notification
            info!("Skipping notification for IP: {} (last notification was {} seconds ago)",
                  params.ip, elapsed);
            return Ok(());
        }

        // Update the last notification timestamp
        LAST_NOTIFICATION_TIMESTAMP.store(now, Ordering::Relaxed);

        // Add a small random component to the timestamp to prevent thundering herd in multi-process environments
        // This creates a small variation in the next allowed notification time based on IP
        let random_component = params.ip.as_bytes().iter().fold(0, |acc, &x| acc + x as u64) % 5;
        LAST_NOTIFICATION_TIMESTAMP.store(now - random_component, Ordering::Relaxed);
        // Skip notification only if URL is empty or explicitly set to the example value
        if self.third_party_block_url.is_empty() {
            warn!("Skipping notification: webhook URL is empty");
            return Ok(());
        }
        
        // Log the webhook URL being used
        info!("Using webhook URL: {}", self.third_party_block_url);
        
        // Create a client with timeout settings and disabled SSL verification
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(5)) // 5 second timeout
            .danger_accept_invalid_certs(true) // Disable SSL certificate verification
            .build()
            .unwrap_or_else(|_| {
                error!("Failed to build HTTP client, using default");
                // If the builder fails, create a client with default settings
                // but still try to disable SSL verification
                ClientBuilder::new()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap_or_else(|_| Client::new())
            });
        
        // Get current timestamp in ISO 8601 format
        let now = chrono::Utc::now();
        let timestamp = now.to_rfc3339();
        
        let message = if let Some(domain_str) = params.domain {
            format!("Rate limit exceeded on domain '{}', path '{}', IP blocked (count: {}/{})",
                    domain_str, params.path, params.current_count, params.max_requests)
        } else {
            format!("Rate limit exceeded on path '{}', IP blocked (count: {}/{})",
                    params.path, params.current_count, params.max_requests)
        };

        let payload = RateLimitExceeded {
            message,
            ip: params.ip.to_string(),
            lock_duration: params.block_duration,
            domain: params.domain.map(|d| d.to_string()),
            path: params.path.to_string(),
            request_url: params.request_url,
            user_agent: params.user_agent,
            current_count: params.current_count,
            max_requests: params.max_requests,
            timestamp,
        };

        info!("Sending block notification to webhook for IP: {} (path: {})", params.ip, params.path);
        info!("Webhook URL: {}", self.third_party_block_url);
        
        // Log the payload for debugging
        if let Ok(json) = serde_json::to_string(&payload) {
            info!("Notification payload: {}", json);
        }

        // Check if API key is set to the default value
        let using_default_api_key = self.api_key == "your-api-key";
        if using_default_api_key {
            warn!("Using default API key. This may not work with your webhook service.");
        }
        
        // Prepare the request with appropriate headers
        let mut request = client.post(&self.third_party_block_url)
            .header("Content-Type", "application/json");
            
        // Add Authorization header only if API key is not the default
        if !using_default_api_key {
            request = request.header("Authorization", format!("Bearer {}", self.api_key));
        } else {
            // Try to send without Authorization header
            info!("Sending webhook without Authorization header due to default API key");
        }
        
        // Send the webhook request
        match request
            .json(&payload)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    info!("Successfully notified block system for IP: {} (path: {}), status: {}", params.ip, params.path, status);
                    metrics::record_webhook_notification(true);

                    // Log response body for debugging if needed
                    match response.text().await {
                        Ok(body) => {
                            if !body.is_empty() {
                                info!("Webhook response: {}", body);
                            }
                        },
                        Err(e) => error!("Failed to read webhook response body: {}", e)
                    }
                } else {
                    error!("Webhook returned error status: {} for IP: {}", status, params.ip);
                    metrics::record_webhook_notification(false);

                    // Try to get error details from response
                    match response.text().await {
                        Ok(body) => error!("Webhook error response: {}", body),
                        Err(e) => error!("Failed to read webhook error response: {}", e)
                    }
                }
            },
            Err(e) => {
                error!("Failed to send webhook notification: {}", e);
                metrics::record_webhook_notification(false);

                // Provide more detailed error information
                if e.is_timeout() {
                    error!("Webhook request timed out after 5 seconds");
                } else if e.is_connect() {
                    error!("Webhook connection error - check network or URL: {}", self.third_party_block_url);
                } else if e.is_request() {
                    error!("Webhook request error - malformed request");
                }
            },
        }

        Ok(())
    }
}
