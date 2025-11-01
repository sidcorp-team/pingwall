# Pingwall

> Pingora-powered firewall with intelligent rate limiting and SSL/TLS support

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org/)
[![Pingora](https://img.shields.io/badge/Powered%20by-Pingora%200.6-blue.svg)](https://github.com/cloudflare/pingora)

## Overview

Pingwall is a production-ready reverse proxy and web application firewall built on [Cloudflare Pingora](https://github.com/cloudflare/pingora), the same technology that powers Cloudflare's global network. It provides advanced traffic management, rate limiting, and SSL/TLS termination for protecting your upstream services.

### Key Benefits

- **🚀 High Performance**: Built on Pingora, designed to handle millions of requests with minimal latency
- **🔒 Memory Safe**: Leverages Rust's memory safety guarantees for secure, crash-resistant operation
- **⚡ Async Architecture**: Modern async design for efficient resource utilization
- **🛡️ Smart Protection**: Domain and path-based rate limiting with intelligent IP blocking
- **🔐 SSL/TLS Ready**: SNI-based multi-domain SSL/TLS termination with automatic certificate management
- **📊 Observable**: Prometheus metrics, Grafana dashboards, and webhook notifications for comprehensive monitoring

## Features

### Traffic Management
- **Domain-Based Routing**: Multi-tenant support with domain-specific configurations
- **Path-Based Routing**: Route different paths to different upstream services
- **Base Path Rewriting**: Automatically handle base paths for upstream services
- **Configurable Timeouts**: Per-route timeout settings for fine-grained control

### Security & Rate Limiting
- **Granular Rate Limiting**: Configure limits per domain, path, or combination
- **Intelligent IP Blocking**: Automatic blocking with configurable durations
- **Webhook Notifications**: Real-time alerts for rate limit violations
- **Cloudflare Integration**: Proper client IP detection behind Cloudflare proxy

### SSL/TLS
- **SNI Support**: Multiple SSL certificates per port with Server Name Indication
- **Per-Domain Certificates**: Configure different certificates for different domains
- **HTTP/2 Ready**: Full HTTP/2 support with TLS ALPN

## Quick Start

### Prerequisites

- Rust 1.81 or higher
- OpenSSL development libraries (for building)

### Installation

```bash
# Clone the repository
git clone https://github.com/sidcorp-team/pingwall.git
cd pingwall

# Build the project
cargo build --release

# Run with default configuration
./target/release/pingwall
```

### Basic Configuration

Copy the example configuration and customize it:

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
```

Minimal `config.yaml` example:

```yaml
# Global settings
max_req_per_window: 100
block_duration_secs: 300
timeout_secs: 30
use_cloudflare: false

# Webhook notifications
block_url: "https://your-webhook-url.com/notifications"
api_key: "your-api-key"

# Domain configurations
domains:
  - domain: "127.0.0.1:8081"
    routers:
      - path: "/"
        upstream: "127.0.0.1:9992"
        max_req_per_window: 60
        block_duration_secs: 300
```

See [config.example.yaml](config.example.yaml) for comprehensive configuration examples including SSL/TLS setup, multi-domain routing, and advanced scenarios.

## Configuration Guide

### Configuration Structure

The configuration file uses a hierarchical YAML structure:

```yaml
# Global defaults
max_req_per_window: <number>      # Default rate limit
block_duration_secs: <number>     # Default block duration
timeout_secs: <number>             # Global timeout
use_cloudflare: <boolean>          # Enable Cloudflare IP detection

# Notification settings
block_url: "<webhook-url>"         # Webhook for notifications
api_key: "<api-key>"               # Authentication for webhook

# Domain-specific configurations
domains:
  - domain: "<hostname:port>"      # Domain identifier
    timeout_secs: <number>         # Domain-level timeout (optional)
    ssl:                           # SSL configuration (optional)
      cert_path: "<path>"          # SSL certificate
      key_path: "<path>"           # Private key
      ca_path: "<path>"            # CA certificate (optional)
    routers:                       # Path-based routes
      - path: "<path-prefix>"      # Path to match
        upstream: "<upstream-url>" # Upstream service
        max_req_per_window: <num>  # Route-specific rate limit
        block_duration_secs: <num> # Route-specific block duration
        timeout_secs: <number>     # Route-specific timeout (optional)
        follow_domain: <boolean>   # Set Host header to domain
```

### Configuration Options

#### Global Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_req_per_window` | integer | 60 | Default maximum requests per time window |
| `block_duration_secs` | integer | 300 | Default block duration in seconds |
| `timeout_secs` | integer | 30 | Default timeout for upstream requests |
| `use_cloudflare` | boolean | false | Enable Cloudflare IP header detection |
| `block_url` | string | - | Webhook URL for block notifications |
| `api_key` | string | - | API key for webhook authentication |

#### Domain Settings

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `domain` | string | Yes | Domain name with port (e.g., "api.example.com:8080") |
| `timeout_secs` | integer | No | Override global timeout for this domain |
| `ssl.cert_path` | string | No | Path to SSL certificate file |
| `ssl.key_path` | string | No | Path to SSL private key file |
| `ssl.ca_path` | string | No | Path to CA certificate for client verification |

#### Router Settings

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `path` | string | Yes | Path prefix to match (e.g., "/api") |
| `upstream` | string | Yes | Upstream service URL or host:port |
| `max_req_per_window` | integer | No | Override rate limit for this route |
| `block_duration_secs` | integer | No | Override block duration for this route |
| `timeout_secs` | integer | No | Override timeout for this route |
| `follow_domain` | boolean | No | Set Host header to match domain name |

### Timeout Configuration

Timeouts are applied with the following priority (highest to lowest):

1. **Route-level**: `domains[].routers[].timeout_secs`
2. **Domain-level**: `domains[].timeout_secs`
3. **Global**: `timeout_secs`

Example:

```yaml
timeout_secs: 30  # Global default

domains:
  - domain: "api.example.com:8080"
    timeout_secs: 60  # Override for all routes in this domain
    routers:
      - path: "/fast"
        upstream: "http://service1:8000"
        timeout_secs: 5  # Override for this specific route
      - path: "/slow"
        upstream: "http://service2:8000"
        # Will use domain-level timeout (60s)
```

### Advanced Examples

#### Multi-Domain with SSL

```yaml
domains:
  # API domain with SSL
  - domain: "api.example.com:443"
    ssl:
      cert_path: "/etc/ssl/certs/api.example.com.pem"
      key_path: "/etc/ssl/private/api.example.com-key.pem"
    routers:
      - path: "/v1"
        upstream: "http://api-v1:8000"
        max_req_per_window: 200
        timeout_secs: 30
      - path: "/v2"
        upstream: "http://api-v2:8000"
        max_req_per_window: 500
        timeout_secs: 15

  # Admin domain with SSL
  - domain: "admin.example.com:443"
    ssl:
      cert_path: "/etc/ssl/certs/admin.example.com.pem"
      key_path: "/etc/ssl/private/admin.example.com-key.pem"
    routers:
      - path: "/"
        upstream: "http://admin-panel:8000"
        max_req_per_window: 20
        block_duration_secs: 3600
        timeout_secs: 60
```

#### Path-Based Routing with Base Paths

```yaml
domains:
  - domain: "gateway.example.com:8080"
    routers:
      # Route /api/* to http://service:8000/v1/*
      - path: "/api"
        upstream: "http://service:8000/v1"
        follow_domain: true

      # Route /images/* to http://cdn:3000/convert/*
      - path: "/images"
        upstream: "http://cdn:3000/convert"
        max_req_per_window: 10
        timeout_secs: 120
```

#### Cloudflare Integration

```yaml
use_cloudflare: true  # Enable Cloudflare IP detection

domains:
  - domain: "www.example.com:443"
    ssl:
      cert_path: "/etc/ssl/certs/example.com.pem"
      key_path: "/etc/ssl/private/example.com-key.pem"
    routers:
      - path: "/"
        upstream: "http://web-server:8000"
        max_req_per_window: 1000
```

### Routing Priority

Routes are matched with the following priority:

1. **Domain + Path match** (most specific)
2. **Path-only match** (routes without domain)
3. **Domain default** (path="/")
4. **Global default**

Within each category, the **longest matching path** wins.

Example:

```yaml
domains:
  - domain: "api.example.com:8080"
    routers:
      - path: "/api/v1/users"    # Highest priority for api.example.com/api/v1/users/*
      - path: "/api"             # Medium priority for api.example.com/api/*
      - path: "/"                # Lowest priority for api.example.com/*
```

## Deployment

### Docker

Build the Docker image:

```bash
docker build -t pingwall:latest .
```

Run with custom configuration:

```bash
docker run -d \
  --name pingwall \
  -p 8080:8080 \
  -p 8443:8443 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/certs:/etc/ssl/certs \
  pingwall:latest
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  pingwall:
    image: pingwall:latest
    build: .
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./config.yaml:/app/config.yaml
      - ./certs:/etc/ssl/certs
      - ./logs:/app/logs
    restart: unless-stopped
    environment:
      - RUST_LOG=info
```

Run:

```bash
docker-compose up -d
```

### Production Deployment

For production deployments, consider:

1. **Multiple instances**: Run behind a load balancer for high availability
2. **Health checks**: Implement health check endpoints
3. **Monitoring**: Set up webhook notifications and log aggregation
4. **SSL certificates**: Use Let's Encrypt or your certificate authority
5. **Rate limits**: Tune based on your traffic patterns

## Monitoring

### Logs

Logs are written to the `logs/` directory:

- `application.log`: All non-error logs (INFO, WARN, DEBUG)
- `error.log`: Error logs only

Log format:

```
2025-03-01T10:30:45.123456Z - INFO - Server running on port 8080
2025-03-01T10:30:46.234567Z - WARN - Rate limit exceeded for IP: 1.2.3.4
2025-03-01T10:30:47.345678Z - ERROR - Failed to connect to upstream: connection refused
```

### Webhook Notifications

When an IP is blocked, a webhook notification is sent with the following payload:

```json
{
  "message": "Rate limit exceeded on domain 'api.example.com', path '/api/v1', IP blocked (count: 105/100)",
  "ip": "1.2.3.4",
  "lock_duration": 300,
  "domain": "api.example.com",
  "path": "/api/v1",
  "request_url": "https://api.example.com/api/v1/users",
  "user_agent": "Mozilla/5.0...",
  "current_count": 105,
  "max_requests": 100,
  "timestamp": "2025-03-01T10:30:45Z"
}
```

Configure the webhook in `config.yaml`:

```yaml
block_url: "https://your-webhook.com/notify"
api_key: "your-secret-key"
```

The webhook request includes:
- Header: `Authorization: Bearer your-secret-key`
- Header: `Content-Type: application/json`

### Prometheus Metrics

Pingwall exposes Prometheus metrics on port 9090 (configurable) at the `/metrics` endpoint for comprehensive monitoring and observability.

#### Available Metrics

**Request Metrics:**
- `pingwall_http_requests_total` - Total number of HTTP requests (labels: domain, path, method, status)
- `pingwall_http_request_duration_seconds` - HTTP request duration histogram (labels: domain, path, method)

**Rate Limiting Metrics:**
- `pingwall_rate_limit_blocks_total` - Total number of requests blocked by rate limiting (labels: domain, path, ip)
- `pingwall_blocked_ips` - Number of currently blocked IPs (labels: domain, path)

**Upstream Metrics:**
- `pingwall_upstream_errors_total` - Total number of upstream errors (labels: domain, path, error_type)

**SSL/TLS Metrics:**
- `pingwall_ssl_handshakes_total` - Total number of SSL/TLS handshakes (labels: domain, success)

**Webhook Metrics:**
- `pingwall_webhook_notifications_total` - Total number of webhook notifications sent (labels: success)

#### Configuration

Enable metrics in `config.yaml`:

```yaml
# Optional: Custom metrics port (default: 9090)
metrics_port: 9090
```

Access metrics:

```bash
curl http://localhost:9090/metrics
```

Example output:

```prometheus
# HELP pingwall_http_requests_total Total number of HTTP requests processed
# TYPE pingwall_http_requests_total counter
pingwall_http_requests_total{domain="api.example.com",path="/v1",method="GET",status="200"} 1542

# HELP pingwall_http_request_duration_seconds HTTP request duration in seconds
# TYPE pingwall_http_request_duration_seconds histogram
pingwall_http_request_duration_seconds_bucket{domain="api.example.com",path="/v1",method="GET",le="0.005"} 1234
pingwall_http_request_duration_seconds_bucket{domain="api.example.com",path="/v1",method="GET",le="0.01"} 1456

# HELP pingwall_rate_limit_blocks_total Total number of requests blocked by rate limiting
# TYPE pingwall_rate_limit_blocks_total counter
pingwall_rate_limit_blocks_total{domain="api.example.com",path="/v1",ip="1.2.3.4"} 5

# HELP pingwall_blocked_ips Number of currently blocked IPs
# TYPE pingwall_blocked_ips gauge
pingwall_blocked_ips{domain="api.example.com",path="/v1"} 3
```

### Grafana Dashboard

Pingwall includes a pre-built Grafana dashboard for visualizing metrics. The monitoring stack can be deployed using Docker Compose (see below).

#### Key Dashboard Panels

1. **Request Rate**: Requests per second by domain and path
2. **Response Times**: P50, P95, P99 latency metrics
3. **Status Codes**: HTTP status code distribution
4. **Rate Limit Blocks**: Blocked IPs and rate limit violations
5. **Upstream Health**: Upstream errors and availability
6. **SSL/TLS**: Handshake success rate and certificate info

#### Setup with Docker Compose

Use the provided [docker-compose.monitoring.yml](docker-compose.monitoring.yml) to deploy the complete monitoring stack:

```bash
# Start Pingwall with Prometheus and Grafana
docker-compose -f docker-compose.monitoring.yml up -d
```

Access the services:
- **Pingwall**: http://localhost:8080
- **Prometheus**: http://localhost:9091
- **Grafana**: http://localhost:3000 (default credentials: admin/admin)

The Grafana dashboard is automatically provisioned and available at: **Home → Dashboards → Pingwall Metrics**

#### Manual Grafana Setup

If setting up Grafana manually:

1. Add Prometheus data source:
   - URL: `http://prometheus:9090` (Docker) or `http://localhost:9090` (local)
   - Access: `Server`

2. Import dashboard:
   - Use the JSON from [grafana/dashboards/pingwall.json](grafana/dashboards/pingwall.json)
   - Or create custom panels using the metrics above

3. Create alerts for:
   - High error rates (4xx, 5xx)
   - Increased rate limit blocks
   - Upstream errors
   - High response times

## Troubleshooting

### Common Issues

#### SSL Certificate Errors

**Problem**: "Failed to read certificate file" or "Certificate does not appear to be in PEM format"

**Solution**:
- Verify certificate files exist and are readable
- Ensure certificates are in PEM format (begin with `-----BEGIN CERTIFICATE-----`)
- Check file permissions

#### Rate Limiting Not Working

**Problem**: Rate limiting doesn't block requests as expected

**Solution**:
- Verify `max_req_per_window` is set correctly (positive value)
- Check if Cloudflare integration is properly configured
- Ensure the correct IP is being detected (check logs)

#### Connection Refused to Upstream

**Problem**: "Failed to connect to upstream"

**Solution**:
- Verify upstream service is running and accessible
- Check network connectivity and firewall rules
- Verify upstream URL format in configuration

#### Wrong Client IP Detected

**Problem**: Always seeing proxy IP instead of client IP

**Solution**:
- Enable Cloudflare integration: `use_cloudflare: true`
- Verify proxy headers are being set correctly
- Check network setup and proxy configuration

### Debug Mode

Enable debug logging:

```bash
RUST_LOG=debug ./target/release/pingwall
```

Or in Docker:

```bash
docker run -e RUST_LOG=debug pingwall:latest
```

## Performance Tuning

### Rate Limiting

Adjust rate limits based on your traffic patterns:

```yaml
# High-traffic public API
- path: "/api/public"
  max_req_per_window: 1000
  block_duration_secs: 60

# Sensitive admin endpoints
- path: "/admin"
  max_req_per_window: 10
  block_duration_secs: 3600
```

### Timeouts

Configure timeouts based on upstream service characteristics:

```yaml
# Fast microservice
- path: "/fast"
  timeout_secs: 5

# Image processing
- path: "/images"
  timeout_secs: 120

# Long-running operations
- path: "/batch"
  timeout_secs: 300
```

### Resource Limits

For Docker deployments, set appropriate resource limits:

```yaml
services:
  pingwall:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '1'
          memory: 512M
```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/sidcorp-team/pingwall.git
cd pingwall

# Build debug version
cargo build

# Build release version
cargo build --release

# Run tests
cargo test

# Run with custom config
cargo run -- --config config.yaml
```

### Project Structure

```
pingwall/
├── src/
│   ├── main.rs              # Entry point
│   ├── args.rs              # CLI argument parsing
│   ├── config.rs            # Configuration management
│   ├── logging.rs           # Logging setup
│   ├── types.rs             # Type definitions
│   ├── metrics/
│   │   └── mod.rs           # Prometheus metrics
│   ├── proxy/
│   │   ├── mod.rs           # Proxy module
│   │   ├── handler.rs       # Request/response handling
│   │   ├── upstream.rs      # Upstream resolution
│   │   └── sni_handler.rs   # SNI certificate handling
│   ├── ratelimit/
│   │   ├── mod.rs           # Rate limiting module
│   │   ├── limiter.rs       # Rate limit logic
│   │   └── service.rs       # Rate limit service
│   ├── notification/
│   │   ├── mod.rs           # Notification module
│   │   └── block_service.rs # Webhook notifications
│   └── utils/
│       ├── mod.rs           # Utilities module
│       └── ip.rs            # IP detection
├── grafana/
│   ├── dashboards/          # Pre-built Grafana dashboards
│   └── provisioning/        # Grafana provisioning config
├── Cargo.toml               # Rust dependencies
├── Dockerfile               # Docker build
├── docker-compose.monitoring.yml  # Monitoring stack
├── config.example.yaml      # Example configuration
├── config.yaml              # Configuration file (ignored)
└── README.md                # This file
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Format code (`cargo fmt`)
6. Run clippy (`cargo clippy`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Code Style

- Follow Rust naming conventions
- Use `cargo fmt` for formatting
- Address all `cargo clippy` warnings
- Add tests for new functionality
- Update documentation as needed

## Security

### Reporting Security Issues

If you discover a security vulnerability, please email songhieu2516@gmail.com instead of using the issue tracker.

### Security Best Practices

When deploying Pingwall:

1. **Use HTTPS**: Always configure SSL/TLS for production
2. **Secure Webhooks**: Use strong API keys for webhook authentication
3. **Update Regularly**: Keep dependencies up to date
4. **Monitor Logs**: Set up log monitoring and alerting
5. **Rate Limits**: Configure appropriate rate limits for your use case
6. **Network Security**: Use firewalls and network segmentation

## License

MIT License

Copyright (c) 2025 Pingwall Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acknowledgments

- Built with [Cloudflare Pingora](https://github.com/cloudflare/pingora)
- Inspired by modern reverse proxy solutions
- Thanks to all contributors

## Support

- **Documentation**: This README and inline code documentation
- **Issues**: [GitHub Issues](https://github.com/sidcorp-team/pingwall/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sidcorp-team/pingwall/discussions)

---

**Pingwall** - Pingora-powered firewall | Made with ❤️ using Rust
