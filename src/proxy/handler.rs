use crate::utils::ip::get_client_ip;
use crate::proxy::upstream::{upstream_peer, upstream_peer_by_path};
use crate::proxy::sni_handler::SniHandler;
use crate::notification::block_service::BlockNotifier;
use crate::ratelimit::service::RateLimitService;
use crate::config::{UpstreamRoute, Config};
use crate::metrics;

use async_trait::async_trait;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service, HttpProxy};
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::services::listening::Service;
use pingora_core::listeners::tls::TlsSettings;
use pingora_http::ResponseHeader;
use pingora_core::protocols::http::v2::server::H2Options;

use std::sync::Arc;
use pingora_core::server::configuration::ServerConf;

#[derive(Clone)]
pub struct ReverseProxy {
    pub rate_limiter: RateLimitService,
    pub upstream_addr: String,
    pub routes: Vec<UpstreamRoute>,
    pub config: Config,
}

impl ReverseProxy {
    pub fn new(third_party_block_url: String, api_key: String, upstream_addr: String, config: Config) -> Self {
        let block_notifier = BlockNotifier::new(third_party_block_url, api_key);
        Self {
            rate_limiter: RateLimitService::new(block_notifier),
            upstream_addr,
            routes: Vec::new(),
            config,
        }
    }
    
    pub fn with_routes(mut self, routes: Vec<UpstreamRoute>) -> Self {
        self.routes = routes;
        self
    }

    /// Get the effective timeout for a request based on the route configuration
    /// Priority: path-specific timeout > domain timeout > global timeout
    fn get_timeout_for_request(&self, session: &Session) -> u64 {
        let path = session.req_header().uri.path();

        // In HTTP/2, the host information is in :authority pseudo-header
        let host = session.req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                session.req_header()
                    .headers
                    .get(":authority")
                    .and_then(|h| h.to_str().ok())
            })
            .or_else(|| {
                let uri = &session.req_header().uri;
                uri.authority().map(|auth| auth.as_str())
            });


        if let Some(host_str) = host {
            for domain_config in &self.config.domains {
                let domain_matches = if domain_config.domain.contains(':') {
                    domain_config.domain == host_str
                } else {
                    host_str.starts_with(&domain_config.domain)
                };

                if domain_matches {
                    for router in &domain_config.routers {
                        if path.starts_with(&router.path) {
                            let timeout = self.config.get_effective_timeout(router, domain_config);
                            return timeout;
                        }
                    }
                    return domain_config.timeout_secs.unwrap_or(self.config.timeout_secs);
                }
            }
        }

        if let Some(matching_route) = crate::proxy::upstream::find_matching_route(&self.routes, path, host) {
            self.config.get_effective_timeout_legacy(matching_route)
        } else {
            self.config.timeout_secs
        }
    }
}

#[async_trait]
impl ProxyHttp for ReverseProxy {
    type CTX = std::time::Instant;

    fn new_ctx(&self) -> Self::CTX {
        std::time::Instant::now()
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let host = session.req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");

        metrics::update_active_connections(host, 1);

        let mut peer = if !self.routes.is_empty() {
            upstream_peer_by_path(&self.routes, &self.upstream_addr, session).await?
        } else {
            upstream_peer(&self.upstream_addr, session).await?
        };

        let timeout_secs = self.get_timeout_for_request(session);
        let timeout_duration = std::time::Duration::from_secs(timeout_secs);

        // ⚡ Performance optimizations

        // 1. Connection reuse: Set idle timeout to keep connections alive
        // This avoids TCP handshake overhead (150-400ms per request!)
        peer.options.idle_timeout = Some(std::time::Duration::from_secs(90));

        // 2. Timeout configuration
        peer.options.connection_timeout = Some(timeout_duration);
        peer.options.read_timeout = Some(timeout_duration);
        peer.options.write_timeout = Some(timeout_duration);
        peer.options.total_connection_timeout = Some(timeout_duration);

        // 3. Enable HTTP/2 ONLY for HTTPS upstreams (not HTTP)
        // HTTP/2 requires TLS, enabling it for HTTP causes negotiation failures
        use pingora_core::protocols::ALPN;
        if peer.is_tls() {
            peer.options.alpn = ALPN::H2H1;
            // Increase max HTTP/2 streams for better performance
            peer.options.max_h2_streams = 128;
        } else {
            // For HTTP upstreams, stick with HTTP/1.1
            peer.options.alpn = ALPN::H1;
        }

        // 4. TCP buffer size optimization for large uploads
        // 1MB receive buffer for better throughput
        peer.options.tcp_recv_buf = Some(1024 * 1024);

        // 5. Enable TCP fast open for faster connection establishment
        peer.options.tcp_fast_open = true;

        Ok(peer)
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let ip = match get_client_ip(session) {
            Some(ip) => ip,
            None => {
                log::warn!("Could not determine client IP");
                return Ok(false);
            }
        };

        let path = session.req_header().uri.path();

        // In HTTP/2, the host information is in :authority pseudo-header
        let host = session.req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                session.req_header()
                    .headers
                    .get(":authority")
                    .and_then(|h| h.to_str().ok())
            })
            .or_else(|| {
                let uri = &session.req_header().uri;
                uri.authority().map(|auth| auth.as_str())
            });


        let matching_route = crate::proxy::upstream::find_matching_route(&self.routes, path, host);

        if let Some(route) = matching_route {
            if route.max_req_per_window < 0 {
                return Ok(false);
            }

            // Pass advanced_limits if configured
            self.rate_limiter.check_rate_limit(
                session,
                &ip,
                &route.path,
                route.advanced_limits.as_ref(),
            ).await
        } else {
            self.rate_limiter.check_rate_limit(session, &ip, "/", None).await
        }
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // ⚡ Performance: Enable HTTP/2 server push hints
        // Remove hop-by-hop headers that shouldn't be forwarded
        upstream_request.remove_header("connection");
        upstream_request.remove_header("keep-alive");
        upstream_request.remove_header("proxy-authenticate");
        upstream_request.remove_header("proxy-authorization");
        upstream_request.remove_header("te");
        upstream_request.remove_header("trailer");
        upstream_request.remove_header("transfer-encoding");
        upstream_request.remove_header("upgrade");

        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        resp: &mut ResponseHeader,
        ctx: &mut Self::CTX
    ) -> Result<()> {
        resp.insert_header("X-Proxied-By", "Pingwall")?;

        let duration = ctx.elapsed().as_secs_f64();
        let status = resp.status.as_u16();
        let method = session.req_header().method.as_str();
        let path = session.req_header().uri.path();

        let host = session.req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");

        metrics::record_request(host, path, method, status, duration);

        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_error::Error>,
        ctx: &mut Self::CTX,
    ) {
        let duration = ctx.elapsed().as_secs_f64();
        let status = session.response_written().map(|r| r.status.as_u16()).unwrap_or(0);
        let method = session.req_header().method.as_str();
        let path = session.req_header().uri.path();

        let host = session.req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");

        metrics::update_active_connections(host, -1);

        if let Some(e) = _e {
            metrics::record_upstream_error(host, path, &format!("{:?}", e.etype()));
        }

        if status >= 400 || _e.is_some() {
            metrics::record_request(host, path, method, status, duration);
        }
    }

}

pub fn build_service(
    conf: &Arc<ServerConf>,
    proxy: ReverseProxy,
    port: u16,
) -> Service<HttpProxy<ReverseProxy>> {
    let mut service = http_proxy_service(conf, proxy.clone());

    // ⚡ HTTP/2 Performance: Increase window size to 8 MiB for large uploads
    // Default H2 window is only 64KB, which causes flow-control blocking for large files
    // This prevents the upload performance issue (30MB uploads taking 60s instead of 2s)
    const H2_WINDOW_SIZE: u32 = 8 * 1024 * 1024; // 8 MiB

    let mut h2_options = H2Options::new();
    h2_options.initial_connection_window_size(H2_WINDOW_SIZE);
    h2_options.initial_window_size(H2_WINDOW_SIZE);

    service.app_logic_mut().unwrap().h2_options = Some(h2_options);

    let (http_ports, https_ports) = extract_domain_ports(&proxy.routes, port);

    for http_port in http_ports {
        log::info!("Opening HTTP port: {}", http_port);
        service.add_tcp(&format!("0.0.0.0:{}", http_port));
    }

    for https_port in &https_ports {
        log::info!("Detected HTTPS port: {}", https_port);
    }

    use std::collections::HashMap;
    let mut configured_ssl_ports = HashMap::new();

    // Collect all SSL configurations by port
    let mut port_to_ssl_configs: HashMap<u16, Vec<(String, String, String)>> = HashMap::new();
    
    for route in &proxy.routes {
        if let Some(domain) = &route.domain {
            if let Some(ssl_config) = &route.ssl {
                let (domain_part, port_part) = match domain.split_once(':') {
                    Some((domain, port_str)) => (domain, port_str.parse::<u16>().unwrap_or(443)),
                    None => (domain.as_str(), 443)
                };

                let cert_path = std::path::Path::new(&ssl_config.cert_path);
                let key_path = std::path::Path::new(&ssl_config.key_path);

                if !cert_path.exists() || !key_path.exists() {
                    log::warn!("SSL certificate or key file not found for domain {}", domain_part);
                    log::warn!("  Certificate path: {}", ssl_config.cert_path);
                    log::warn!("  Key path: {}", ssl_config.key_path);
                    continue;
                }

                log::info!("Verifying certificate and key files for domain: {}", domain_part);

                match std::fs::read_to_string(&ssl_config.cert_path) {
                    Ok(cert_content) => {
                        if !cert_content.contains("-----BEGIN CERTIFICATE-----") {
                            log::error!("Certificate file does not appear to be in PEM format: {}", ssl_config.cert_path);
                            log::error!("Certificate must begin with '-----BEGIN CERTIFICATE-----'");
                            continue;
                        }
                    },
                    Err(e) => {
                        log::error!("Failed to read certificate file: {}: {}", ssl_config.cert_path, e);
                        continue;
                    }
                }

                match std::fs::read_to_string(&ssl_config.key_path) {
                    Ok(key_content) => {
                        if !key_content.contains("-----BEGIN PRIVATE KEY-----") &&
                           !key_content.contains("-----BEGIN RSA PRIVATE KEY-----") {
                            log::error!("Key file does not appear to be in PEM format: {}", ssl_config.key_path);
                            log::error!("Key file must begin with '-----BEGIN PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----'");
                            continue;
                        }
                    },
                    Err(e) => {
                        log::error!("Failed to read key file: {}: {}", ssl_config.key_path, e);
                        continue;
                    }
                }

                port_to_ssl_configs
                    .entry(port_part)
                    .or_default()
                    .push((
                        domain_part.to_string(),
                        ssl_config.cert_path.clone(),
                        ssl_config.key_path.clone()
                    ));
            }
        }
    }
    
    // Configure TLS listeners with SNI support for each port
    for (port, configs) in port_to_ssl_configs {
        if !configs.is_empty() {
            log::info!("Configuring TLS listener with SNI for port {}", port);

            let mut sni_handler = SniHandler::new();
            let mut domains_configured = Vec::new();

            for (domain, cert_path, key_path) in &configs {
                if !std::path::Path::new(cert_path).exists() || !std::path::Path::new(key_path).exists() {
                    log::error!("Certificate or key file not found for domain {}", domain);
                    log::error!("  Certificate path: {}", cert_path);
                    log::error!("  Key path: {}", key_path);
                    continue;
                }

                sni_handler.add_certificate(domain, cert_path.clone(), key_path.clone());
                domains_configured.push(domain.clone());
                log::info!("Added certificate for domain {} on port {}", domain, port);
            }

            if domains_configured.is_empty() {
                log::error!("No valid certificates found for port {}", port);
                continue;
            }

            match TlsSettings::with_callbacks(sni_handler.into_callbacks()) {
                Ok(mut tls_settings) => {
                    tls_settings.enable_h2();

                    service.add_tls_with_settings(
                        &format!("0.0.0.0:{}", port),
                        None,
                        tls_settings
                    );

                    log::info!("SSL with SNI configuration successful for port: {}", port);
                    configured_ssl_ports.insert(port, domains_configured.join(", "));

                    log::info!("SNI enabled for {} domains on port {}: {}",
                        domains_configured.len(), port, domains_configured.join(", "));
                },
                Err(e) => {
                    log::error!("Failed to create TLS settings for port {}: {}", port, e);
                    log::error!("This port will not be configured for SSL/TLS");
                }
            }
        }
    }

    if configured_ssl_ports.is_empty() {
        log::info!("No SSL ports configured");
    } else {
        log::info!("Configured SSL for {} ports", configured_ssl_ports.len());
        for (port, domain) in configured_ssl_ports {
            log::info!("Port {} using certificate from domain: {}", port, domain);
        }
    }

    service
}

fn extract_domain_ports(routes: &[UpstreamRoute], default_port: u16) -> (Vec<u16>, Vec<u16>) {
    let mut http_ports = vec![default_port];
    let mut https_ports = vec![];

    for route in routes {
        if let Some(domain) = &route.domain {
            let has_ssl = route.ssl.is_some();

            if let Some((_, port_str)) = domain.split_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    if has_ssl {
                        if !https_ports.contains(&port) {
                            https_ports.push(port);
                        }
                    } else if !http_ports.contains(&port) {
                        http_ports.push(port);
                    }
                } else {
                    log::warn!("Invalid port in domain configuration: {}", domain);
                }
            } else if has_ssl {
                if !https_ports.contains(&443) {
                    https_ports.push(443);
                }
            }
        }
    }

    (http_ports, https_ports)
}