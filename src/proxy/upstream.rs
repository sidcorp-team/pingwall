use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::Session;
use pingora_core::{Result, Error};
use pingora_error::{ErrorType};
use log::error;
use crate::config::UpstreamRoute;

/// A wrapper around HttpPeer that includes base path information
#[derive(Debug)]
pub struct PeerWithPath {
    pub peer: HttpPeer,
    pub base_path: Option<String>,
}

impl PeerWithPath {
    /// Create a new PeerWithPath
    pub fn new(peer: HttpPeer, base_path: Option<String>) -> Self {
        Self { peer, base_path }
    }

    /// Convert to a boxed HttpPeer
    pub fn into_boxed_http_peer(self) -> Box<HttpPeer> {
        Box::new(self.peer)
    }
}

/// Resolves a URL or host:port string to an HttpPeer
/// Returns a PeerWithPath containing the HttpPeer and optionally the base path if present
pub async fn resolve_upstream(upstream: &str) -> Result<PeerWithPath> {
    resolve_upstream_with_host(upstream, None).await
}

/// Resolves a URL or host:port string to an HttpPeer with an optional custom host header
/// Returns a PeerWithPath containing the HttpPeer and optionally the base path if present
pub async fn resolve_upstream_with_host(upstream: &str, custom_host: Option<&str>) -> Result<PeerWithPath> {
    if upstream.starts_with("http://") || upstream.starts_with("https://") {
        let url = url::Url::parse(upstream).map_err(|e| {
            error!("URL parse error: {}", e);
            Error::explain(ErrorType::InvalidHTTPHeader, "Invalid upstream URL")
        })?;

        let host = url.host_str().unwrap_or("localhost").to_string();
        let port = url.port().unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });
        let use_ssl = url.scheme() == "https";

        // Extract the path from the URL if present (will be empty or start with /)
        let path = url.path();
        let path_str = if path.is_empty() || path == "/" { String::new() } else { path.to_string() };

        // Create a peer with the extracted host, port, and SSL setting
        // If custom_host is provided, use it for the host header
        let host_header = if let Some(h) = custom_host {
            // Extract only the domain part without port
            let domain_only = match h.split_once(':') {
                Some((domain, _)) => domain,  // Strip port if present
                None => h                     // No port, use as is
            };
            
            // Remove leading dot if present (common in cookie domains)
            let clean_domain = if domain_only.starts_with('.') {
                &domain_only[1..]
            } else {
                domain_only
            };

            clean_domain.to_string()
        } else {
            host.clone()
        };

        let peer = HttpPeer::new(format!("{}:{}", host, port), use_ssl, host_header);
        
        let base_path = if !path_str.is_empty() {
            Some(path_str)
        } else {
            None
        };

        Ok(PeerWithPath::new(peer, base_path))
    } else {
        // Handle host:port format with potential path
        let parts: Vec<&str> = upstream.split('/').collect();
        let host_port = parts[0].to_string();
        
        // Create the peer with the host:port part
        // If custom_host is provided, use it for the host header
        let host_header = if let Some(h) = custom_host {
            // Extract only the domain part without port
            let domain_only = match h.split_once(':') {
                Some((domain, _)) => domain,  // Strip port if present
                None => h                     // No port, use as is
            };
            
            // Remove leading dot if present (common in cookie domains)
            let clean_domain = if domain_only.starts_with('.') {
                &domain_only[1..]
            } else {
                domain_only
            };
            
            clean_domain.to_string()
        } else {
            String::new()
        };

        let peer = HttpPeer::new(host_port, false, host_header);

        let base_path = if parts.len() > 1 {
            let path = format!("/{}", parts[1..].join("/"));
            Some(path)
        } else {
            None
        };
        
        Ok(PeerWithPath::new(peer, base_path))
    }
}

/// Finds the best matching route for a given path and optional domain
pub fn find_matching_route<'a>(routes: &'a [UpstreamRoute], path: &str, host: Option<&str>) -> Option<&'a UpstreamRoute> {
    // First try to match both domain and path if host is provided
    if let Some(host_value) = host {
        // Extract domain and port from host header
        let (domain_part, _) = match host_value.split_once(':') {
            Some((domain, _)) => (domain, true),  // Host contains port
            None => (host_value, false)           // Host without port
        };
        
        // First, try to find the most specific domain+path match (longest path wins)
        let domain_path_matches: Vec<&UpstreamRoute> = routes.iter()
            .filter(|route| {
                // Check if this route has a domain requirement
                if let Some(route_domain) = &route.domain {
                    // Extract domain part from route domain (without port)
                    let route_domain_part = match route_domain.split_once(':') {
                        Some((d, _)) => d,
                        None => route_domain.as_str()
                    };
                    
                    route_domain_part == domain_part && path.starts_with(&route.path)
                } else {
                    false
                }
            })
            .collect();
        
        // Sort matches by path length (descending) to find most specific match
        if !domain_path_matches.is_empty() {
            // Find the match with the longest path (most specific)
            let best_match = domain_path_matches.iter()
                .max_by_key(|route| route.path.len());
            
            if let Some(route) = best_match {
                return Some(route);
            }
        }
    }
    
    // If no domain-specific match or no host provided, fall back to path-only matching
    // Only consider routes without domain requirements
    let path_matches: Vec<&UpstreamRoute> = routes.iter()
        .filter(|route| {
            // Only consider routes with no domain requirement
            route.domain.is_none() && path.starts_with(&route.path)
        })
        .collect();
    
    if !path_matches.is_empty() {
        // Find the match with the longest path (most specific)
        let best_match = path_matches.iter()
            .max_by_key(|route| route.path.len());
        
        if let Some(route) = best_match {
            return Some(route);
        }
    }
    
    // If no specific match found, try to find a default route for the domain
    if let Some(host_value) = host {
        let (domain_part, _) = match host_value.split_once(':') {
            Some((domain, _)) => (domain, true),
            None => (host_value, false)
        };
        
        // Look for a root path (/) route for this domain
        let domain_default = routes.iter()
            .find(|route| {
                if let Some(route_domain) = &route.domain {
                    // Extract domain part from route domain (without port)
                    let route_domain_part = match route_domain.split_once(':') {
                        Some((d, _)) => d,
                        None => route_domain.as_str()
                    };
                    
                    // Check if domains match and this is a root path
                    route_domain_part == domain_part && route.path == "/"
                } else {
                    false
                }
            });
        
        if let Some(route) = domain_default {
            return Some(route);
        }
    }
    
    // Last resort: find a global default route (path="/" with no domain)
    let global_default = routes.iter()
        .find(|route| route.domain.is_none() && route.path == "/");
    
    global_default
}

/// Get the upstream peer based on the request path and host
pub async fn upstream_peer_by_path(routes: &[UpstreamRoute], default_upstream: &str, session: &mut Session) -> Result<Box<HttpPeer>> {
    // Store all the information we need from the immutable session first
    let path = session.req_header().uri.path().to_string();
    
    // Extract the host header if present for domain-based routing
    // In HTTP/2, the host information is in :authority pseudo-header
    // but Pingora should provide it through various means
    let host = session.req_header()
        .headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            // Try to get from authority pseudo-header
            session.req_header()
                .headers
                .get(":authority")
                .and_then(|h| h.to_str().ok())
        })
        .or_else(|| {
            // Try to get from URI if it contains host information
            let uri = &session.req_header().uri;
            uri.authority().map(|auth| auth.as_str())
        })
        .map(|s| s.to_string());
    
    // Find the best matching route considering both domain and path
    if let Some(route) = find_matching_route(routes, &path, host.as_deref()) {
        // Check if we need to follow domain for this route
        let custom_host = if route.follow_domain && route.domain.is_some() {
            route.domain.as_deref()
        } else {
            None
        };
        
        // Resolve the upstream with the custom host if needed
        let peer_with_path = resolve_upstream_with_host(&route.upstream, custom_host).await?;
        
        // If there's a base path, modify the request URI
        if let Some(ref base_path) = peer_with_path.base_path {
            // Get the path after the matched route path
            let remaining_path = &path[route.path.len()..];
            let new_path = if remaining_path.is_empty() || remaining_path == "/" {
                base_path.clone()
            } else {
                format!("{}{}", base_path, remaining_path)
            };

            // Modify the URI directly by setting a new URI string
            let uri_str = session.req_header().uri.to_string();
            let uri_parts: Vec<&str> = uri_str.split('?').collect();
            
            let new_uri_str = if uri_parts.len() > 1 {
                // URI has a query string
                format!("{}?{}", new_path, uri_parts[1])
            } else {
                new_path
            };
            
            // Modify the request URI
            let uri_result = new_uri_str.parse();
            match uri_result {
                Ok(new_uri) => {
                    session.req_header_mut().set_uri(new_uri);
                },
                Err(e) => {
                    error!("Failed to parse URI '{}': {}", new_uri_str, e);
                }
            }
        }

        Ok(peer_with_path.into_boxed_http_peer())
    } else {
        let peer_with_path = resolve_upstream(default_upstream).await?;
        
        // If there's a base path, modify the request URI
        if let Some(ref base_path) = peer_with_path.base_path {
            let new_path = format!("{}{}", base_path, path);
            // Modify the URI directly by setting a new URI string
            let uri_str = session.req_header().uri.to_string();
            let uri_parts: Vec<&str> = uri_str.split('?').collect();
            
            let new_uri_str = if uri_parts.len() > 1 {
                // URI has a query string
                format!("{}?{}", new_path, uri_parts[1])
            } else {
                new_path
            };
            
            // Modify the request URI
            let uri_result = new_uri_str.parse();
            match uri_result {
                Ok(new_uri) => {
                    session.req_header_mut().set_uri(new_uri);
                },
                Err(e) => {
                    error!("Failed to parse URI '{}': {}", new_uri_str, e);
                }
            }
        }

        Ok(peer_with_path.into_boxed_http_peer())
    }
}

/// Legacy function for backward compatibility
pub async fn upstream_peer(upstream: &str, session: &mut Session) -> Result<Box<HttpPeer>> {
    let peer_with_path = resolve_upstream(upstream).await?;

    if let Some(ref base_path) = peer_with_path.base_path {
        let path = session.req_header().uri.path();
        let new_path = format!("{}{}", base_path, path);
        // Modify the URI directly by setting a new URI string
        let uri_str = session.req_header().uri.to_string();
        let uri_parts: Vec<&str> = uri_str.split('?').collect();
        
        let new_uri_str = if uri_parts.len() > 1 {
            // URI has a query string
            format!("{}?{}", new_path, uri_parts[1])
        } else {
            new_path
        };
        
        // Modify the request URI
        let uri_result = new_uri_str.parse();
        match uri_result {
            Ok(new_uri) => {
                session.req_header_mut().set_uri(new_uri);
            },
            Err(e) => {
                error!("Failed to parse URI '{}': {}", new_uri_str, e);
            }
        }
    }
    
    Ok(peer_with_path.into_boxed_http_peer())
}