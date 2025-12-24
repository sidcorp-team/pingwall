// src/utils/useragent.rs
use pingora_proxy::Session;
use woothee::parser::{Parser, WootheeResult};
use log::debug;

/// User-Agent classification category
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UserAgentCategory {
    Bot,
    Crawler,
    Chrome,
    Firefox,
    Safari,
    Edge,
    Mobile,
    Curl,
    Unknown,
}

impl UserAgentCategory {
    /// Get string representation for config matching
    pub fn as_str(&self) -> &'static str {
        match self {
            UserAgentCategory::Bot => "bot",
            UserAgentCategory::Crawler => "crawler",
            UserAgentCategory::Chrome => "chrome",
            UserAgentCategory::Firefox => "firefox",
            UserAgentCategory::Safari => "safari",
            UserAgentCategory::Edge => "edge",
            UserAgentCategory::Mobile => "mobile",
            UserAgentCategory::Curl => "curl",
            UserAgentCategory::Unknown => "unknown",
        }
    }

    /// Parse from string (for config)
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "bot" => UserAgentCategory::Bot,
            "crawler" => UserAgentCategory::Crawler,
            "chrome" => UserAgentCategory::Chrome,
            "firefox" => UserAgentCategory::Firefox,
            "safari" => UserAgentCategory::Safari,
            "edge" => UserAgentCategory::Edge,
            "mobile" => UserAgentCategory::Mobile,
            "curl" => UserAgentCategory::Curl,
            _ => UserAgentCategory::Unknown,
        }
    }
}

/// Parsed User-Agent information
#[derive(Debug, Clone)]
pub struct UserAgentInfo {
    /// Raw User-Agent string
    pub raw: String,

    /// Classified category
    pub category: UserAgentCategory,

    /// Browser/client name (e.g., "Chrome", "Firefox", "curl")
    pub name: Option<String>,

    /// Version string (e.g., "96.0.4664.110")
    pub version: Option<String>,

    /// Operating system (e.g., "Windows", "Linux", "iOS")
    pub os: Option<String>,
}

impl UserAgentInfo {
    /// Parse User-Agent from HTTP session
    pub fn from_session(session: &Session) -> Self {
        let raw = session
            .req_header()
            .headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        Self::from_string(&raw)
    }

    /// Parse User-Agent from string
    pub fn from_string(user_agent: &str) -> Self {
        if user_agent.is_empty() {
            return Self {
                raw: String::new(),
                category: UserAgentCategory::Unknown,
                name: None,
                version: None,
                os: None,
            };
        }

        // Parse with woothee
        let parser = Parser::new();
        let result: Option<WootheeResult> = parser.parse(user_agent);

        let (category, name, version, os) = if let Some(r) = result {
            let category = classify_from_woothee(&r, user_agent);
            let name = if r.name.is_empty() {
                None
            } else {
                Some(r.name.to_string())
            };
            let version = if r.version.is_empty() {
                None
            } else {
                Some(r.version.to_string())
            };
            let os = if r.os.is_empty() {
                None
            } else {
                Some(r.os.to_string())
            };

            (category, name, version, os)
        } else {
            // Fallback classification
            let category = classify_fallback(user_agent);
            (category, None, None, None)
        };

        debug!(
            "Parsed User-Agent: category={:?}, name={:?}, version={:?}, os={:?}, raw={}",
            category, name, version, os, user_agent
        );

        Self {
            raw: user_agent.to_string(),
            category,
            name,
            version,
            os,
        }
    }

    /// Check if this is a bot/crawler
    pub fn is_bot(&self) -> bool {
        matches!(
            self.category,
            UserAgentCategory::Bot | UserAgentCategory::Crawler
        )
    }

    /// Check if this is a mobile device
    pub fn is_mobile(&self) -> bool {
        self.category == UserAgentCategory::Mobile
    }
}

/// Classify User-Agent using woothee result
fn classify_from_woothee(result: &WootheeResult, user_agent: &str) -> UserAgentCategory {
    // Check for bots/crawlers first
    if result.category == "crawler" {
        return UserAgentCategory::Crawler;
    }

    // Check raw string for common bot patterns (case-insensitive)
    let ua_lower = user_agent.to_lowercase();
    if ua_lower.contains("bot")
        || ua_lower.contains("crawler")
        || ua_lower.contains("spider")
        || ua_lower.contains("scraper")
    {
        return UserAgentCategory::Bot;
    }

    // Check for curl
    if result.name.to_lowercase().contains("curl") || ua_lower.starts_with("curl/") {
        return UserAgentCategory::Curl;
    }

    // Classify based on browser name
    match result.name.to_lowercase().as_str() {
        name if name.contains("chrome") => UserAgentCategory::Chrome,
        name if name.contains("firefox") => UserAgentCategory::Firefox,
        name if name.contains("safari") && !name.contains("chrome") => UserAgentCategory::Safari,
        name if name.contains("edge") => UserAgentCategory::Edge,
        _ => {
            // Check if mobile
            if result.category == "smartphone" || result.category == "mobilephone" {
                UserAgentCategory::Mobile
            } else {
                UserAgentCategory::Unknown
            }
        }
    }
}

/// Fallback classification when woothee fails
fn classify_fallback(user_agent: &str) -> UserAgentCategory {
    let ua_lower = user_agent.to_lowercase();

    // Bot/Crawler detection
    if ua_lower.contains("bot")
        || ua_lower.contains("crawler")
        || ua_lower.contains("spider")
        || ua_lower.contains("scraper")
    {
        return UserAgentCategory::Bot;
    }

    // Curl detection
    if ua_lower.starts_with("curl/") {
        return UserAgentCategory::Curl;
    }

    // Browser detection
    if ua_lower.contains("chrome") {
        UserAgentCategory::Chrome
    } else if ua_lower.contains("firefox") {
        UserAgentCategory::Firefox
    } else if ua_lower.contains("safari") {
        UserAgentCategory::Safari
    } else if ua_lower.contains("edge") {
        UserAgentCategory::Edge
    } else if ua_lower.contains("mobile") {
        UserAgentCategory::Mobile
    } else {
        UserAgentCategory::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chrome() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36";
        let info = UserAgentInfo::from_string(ua);
        assert_eq!(info.category, UserAgentCategory::Chrome);
        assert!(!info.is_bot());
    }

    #[test]
    fn test_parse_bot() {
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        let info = UserAgentInfo::from_string(ua);
        assert!(info.is_bot());
    }

    #[test]
    fn test_parse_curl() {
        let ua = "curl/7.68.0";
        let info = UserAgentInfo::from_string(ua);
        assert_eq!(info.category, UserAgentCategory::Curl);
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(UserAgentCategory::Bot.as_str(), "bot");
        assert_eq!(UserAgentCategory::Chrome.as_str(), "chrome");
        assert_eq!(UserAgentCategory::Curl.as_str(), "curl");
    }
}
