mod args;
mod proxy;
mod utils;
mod types;
mod notification;
mod ratelimit;
mod logging;
mod config;
mod metrics;

use args::Args;
use proxy::handler::{build_service, ReverseProxy};
use pingora_core::server::Server;
use pingora_core::services::background::GenBackgroundService;
use clap::Parser;
use crate::utils::ip::set_use_cloudflare;
use crate::config::{Config, UpstreamRoute};
use std::path::Path;
use std::sync::Arc;
use log::{info, warn};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_logger()?;

    let config_path = "config.yaml";
    let config = load_config(config_path);

    set_use_cloudflare(config.use_cloudflare);
    ratelimit::limiter::init_globals(config.max_req_per_window, config.block_duration_secs);

    let mut all_routes = Vec::new();

    for domain_config in &config.domains {
        info!("Processing domain configuration for: {}", domain_config.domain);

        for router in &domain_config.routers {
            let route = UpstreamRoute {
                path: router.path.clone(),
                upstream: router.upstream.clone(),
                max_req_per_window: router.max_req_per_window,
                block_duration_secs: router.block_duration_secs,
                domain: Some(domain_config.domain.clone()),
                follow_domain: router.follow_domain,
                ssl: domain_config.ssl.clone(),
                timeout_secs: router.timeout_secs,
            };

            all_routes.push(route);
        }
    }

    for route in &all_routes {
        let domain_path_key = if let Some(domain) = &route.domain {
            format!("{}{}", domain, route.path)
        } else {
            route.path.clone()
        };
        
        info!("Setting rate limits for {}: {} req/window, {} sec block", 
              domain_path_key, route.max_req_per_window, route.block_duration_secs);
              
        ratelimit::limiter::set_route_limits(
            &domain_path_key, 
            route.max_req_per_window, 
            route.block_duration_secs
        );
    }

    let default_upstream = "127.0.0.1:9992".to_string();
    let proxy = ReverseProxy::new(config.block_url.clone(), config.api_key.clone(), config.upstream_addr.clone().unwrap_or(default_upstream), config.clone())
        .with_routes(all_routes.clone());

    info!("Configured routing with {} routes:", all_routes.len());
    for route in &all_routes {
        if let Some(domain) = &route.domain {
            let ssl_info = if route.ssl.is_some() { " (SSL enabled)" } else { "" };
            info!("  Domain '{}'{}, Path '{}' → upstream '{}' (rate limit: {} reqs, block duration: {}s)", 
                domain,
                ssl_info,
                route.path, 
                route.upstream,
                route.max_req_per_window,
                route.block_duration_secs
            );
        } else {
            info!("  Path '{}' → upstream '{}' (rate limit: {} reqs, block duration: {}s)", 
                route.path, 
                route.upstream,
                route.max_req_per_window,
                route.block_duration_secs
            );
        }
    }


    let mut server = Server::new(None).unwrap();
    server.bootstrap();
    let default_port = 8081;
    let proxy_service = build_service(&server.configuration, proxy.clone(), config.port.unwrap_or(default_port));
    server.add_service(proxy_service);

    let metrics_port = config.metrics_port.unwrap_or(9090);
    let metrics_service = Arc::new(metrics::MetricsService::new(metrics_port));
    server.add_service(GenBackgroundService::new("metrics".to_string(), metrics_service));

    let domain_ports = extract_domain_ports(&config.routes);
    
    let port = config.port.unwrap_or(default_port);
    if !domain_ports.is_empty() {
        info!("Server listening on multiple ports: {}, {}", 
            port,
            domain_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        );
    } else {
        info!(
            "Server running on port {}. Rate limit: {} reqs, block duration: {}s",
            port, config.max_req_per_window, config.block_duration_secs
        );
    }
    server.run_forever();
}

fn extract_domain_ports(routes: &[config::UpstreamRoute]) -> Vec<u16> {
    let mut ports = Vec::new();
    
    for route in routes {
        if let Some(domain) = &route.domain {
            if let Some((_, port_str)) = domain.split_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    if !ports.contains(&port) {
                        ports.push(port);
                    }
                }
            }
        }
    }
    
    ports
}

fn load_config(config_path: &str) -> Config {
    if Path::new(config_path).exists() {
        match Config::from_file(config_path) {
            Ok(config) => {
                info!("Loaded configuration from {}", config_path);
                return config;
            }
            Err(e) => {
                warn!("Failed to load config from {}: {}", config_path, e);
                warn!("Falling back to command line arguments");
            }
        }
    } else {
        info!("Config file {} not found, using command line arguments", config_path);
    }

    let args = Args::parse();
    Config {
        max_req_per_window: args.max_req_per_window,
        block_duration_secs: args.block_duration_secs,
        port: Some(args.port),
        upstream_addr: Some(args.upstream_addr),
        routes: Vec::new(),
        domains: Vec::new(),
        block_url: args.block_url,
        api_key: args.api_key,
        use_cloudflare: args.use_cloudflare,
        timeout_secs: 30,
        metrics_port: None,
    }
}