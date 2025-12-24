// src/utils/cloudflare.rs
use pingora_proxy::Session;
use log::debug;

/// Context information extracted from Cloudflare headers
#[derive(Debug, Clone, Default)]
pub struct CloudflareContext {
    /// Country code (2-letter ISO code, e.g., "US", "VN", "CN")
    pub country: Option<String>,

    /// Autonomous System Number (e.g., "15169" for Google)
    pub asn: Option<String>,

    /// Cloudflare threat score (0-100, higher = more suspicious)
    pub threat_score: Option<u8>,

    /// Cloudflare Ray ID (for debugging/tracking)
    pub ray_id: Option<String>,
}

impl CloudflareContext {
    /// Extract Cloudflare context from HTTP session headers
    pub fn from_session(session: &Session) -> Self {
        let headers = &session.req_header().headers;

        // Extract CF-IPCountry
        let country = headers
            .get("cf-ipcountry")
            .and_then(|h| h.to_str().ok())
            .filter(|s| !s.is_empty() && *s != "XX")  // XX = unknown country
            .map(|s| s.to_uppercase());

        // Extract CF-ASN (format: "AS15169" or just "15169")
        let asn = headers
            .get("cf-connecting-asn")
            .or_else(|| headers.get("cf-asn"))
            .and_then(|h| h.to_str().ok())
            .map(|s| {
                // Remove "AS" prefix if present
                if s.starts_with("AS") || s.starts_with("as") {
                    s[2..].to_string()
                } else {
                    s.to_string()
                }
            });

        // Extract CF-Threat-Score (0-100)
        let threat_score = headers
            .get("cf-threat-score")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u8>().ok())
            .filter(|score| *score <= 100);

        // Extract CF-Ray (for tracking)
        let ray_id = headers
            .get("cf-ray")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let context = Self {
            country,
            asn,
            threat_score,
            ray_id,
        };

        debug!(
            "Cloudflare context: country={:?}, asn={:?}, threat_score={:?}, ray_id={:?}",
            context.country, context.asn, context.threat_score, context.ray_id
        );

        context
    }

    /// Check if this request has any Cloudflare headers
    pub fn has_cloudflare_headers(&self) -> bool {
        self.country.is_some() || self.asn.is_some() || self.threat_score.is_some()
    }

    /// Check if threat score is above threshold
    pub fn is_threat_above(&self, threshold: u8) -> bool {
        self.threat_score.map_or(false, |score| score > threshold)
    }

    /// Check if country is in the given list
    pub fn country_in(&self, countries: &[String]) -> bool {
        if let Some(ref country) = self.country {
            countries.iter().any(|c| c.eq_ignore_ascii_case(country))
        } else {
            false
        }
    }

    /// Check if ASN matches
    pub fn asn_matches(&self, asn: &str) -> bool {
        if let Some(ref self_asn) = self.asn {
            self_asn == asn
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_context_threat_above() {
        let ctx = CloudflareContext {
            threat_score: Some(80),
            ..Default::default()
        };

        assert!(ctx.is_threat_above(75));
        assert!(!ctx.is_threat_above(80));
        assert!(!ctx.is_threat_above(85));
    }

    #[test]
    fn test_cloudflare_context_country_in() {
        let ctx = CloudflareContext {
            country: Some("US".to_string()),
            ..Default::default()
        };

        let allowed = vec!["US".to_string(), "VN".to_string()];
        assert!(ctx.country_in(&allowed));

        let blocked = vec!["CN".to_string(), "RU".to_string()];
        assert!(!ctx.country_in(&blocked));
    }
}
