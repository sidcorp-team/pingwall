# Pingwall

> High-performance reverse proxy & WAF built on Cloudflare Pingora with advanced rate limiting

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org/)
[![Pingora](https://img.shields.io/badge/Powered%20by-Pingora%200.6-blue.svg)](https://github.com/cloudflare/pingora)

## Overview

Pingwall is a production-ready reverse proxy and web application firewall built on [Cloudflare Pingora](https://github.com/cloudflare/pingora) - the same technology powering Cloudflare's global network handling millions of requests per second.

### Why Pingwall?

- **🚀 Blazing Fast**: Rust + async architecture for minimal latency
- **🔒 Memory Safe**: Rust's safety guarantees prevent crashes and vulnerabilities
- **🎯 Smart Rate Limiting**: Multi-dimensional limits with sliding windows
- **🛡️ Advanced Protection**: ASN, country, user-agent, and threat-based filtering
- **🔐 SSL/TLS**: SNI-based multi-domain HTTPS with HTTP/2 support
- **📊 Observable**: Prometheus metrics + webhook notifications

## Key Features

### Advanced Rate Limiting

**Sliding Window Algorithm** - Industry standard used by GitHub, Stripe, Cloudflare
- Prevents burst loopholes of fixed windows
- Accurate per-second/minute/hour/day limiting
- Configurable window duration per limit

**Multi-Dimensional Limits**
- 🌐 **ASN-based**: Different limits for cloud providers (Google, AWS, Facebook, etc.)
- 🌍 **Country-based**: Geo-restrictions with automatic blocking
- 🤖 **User-Agent**: Distinguish browsers, bots, crawlers, mobile
- ⚠️ **Threat Score**: Auto-block high-risk IPs (Cloudflare integration)

**Soft Limit vs Hard Block**
- **Soft Limit** (`block_duration_secs: 0`): Reject requests, don't block IP
- **Hard Block** (`block_duration_secs > 0`): Block IP for N seconds
- Perfect for treating trusted users differently from abusers

**Accurate HTTP Headers**
```http
HTTP/1.1 429 Too Many Requests
X-Rate-Limit-Limit: 60              # Max requests allowed
X-Rate-Limit-Remaining: 0            # Requests remaining
X-Rate-Limit-Reset: 300              # Block duration (if hard block)
X-Rate-Limit-Path: /api              # Path that was limited
Retry-After: 60                      # Wait N seconds (RFC 6585)
X-RateLimit-Window: 60               # Window duration
```

### Traffic Management

- ✅ Domain-based routing with SSL/TLS (SNI)
- ✅ Path-based routing to different upstreams
- ✅ Configurable timeouts per route
- ✅ HTTP/2 support
- ✅ Host header forwarding control

### Monitoring & Alerts

- ✅ Prometheus metrics endpoint (`:9090/metrics`)
- ✅ Webhook notifications on rate limit violations
- ✅ Detailed request/block logging

## Quick Start

### Installation

```bash
# Prerequisites: Rust 1.81+
git clone https://github.com/sidcorp-team/pingwall.git
cd pingwall

# Build
cargo build --release

# Run
./target/release/pingwall
```

### Basic Configuration

Create `config.yaml`:

```yaml
# Global settings
rate_limit_window_secs: 60  # Default: 60 seconds (per minute)
max_req_per_window: 100      # Default: 100 requests/minute
block_duration_secs: 300     # Block for 5 minutes
use_cloudflare: true         # Enable Cloudflare headers

# Notifications
block_url: "https://your-webhook.com/alert"
api_key: "your-api-key"

# Routing
domains:
  - domain: "api.example.com:443"
    ssl:
      cert_path: "/path/to/cert.pem"
      key_path: "/path/to/key.pem"
    routers:
      - path: "/api"
        upstream: "http://127.0.0.1:8000"
        max_req_per_window: 100  # 100 req/min for normal users

        advanced_limits:
          # ASN limits
          asn_limits:
            "32934":  # Facebook/Meta
              max_req: 60
              window_secs: 60
              block_duration_secs: 0  # Soft limit

            "15169":  # Google Cloud
              max_req: 200
              window_secs: 60
              block_duration_secs: 0

          # Country limits
          country_limits:
            "US": 200
            "VN": 150
            "CN": 50  # Restricted

          # User-Agent limits
          user_agent_limits:
            "chrome": 150
            "bot": 20

          # Block high-risk IPs
          threat_score_threshold: 70
```

See [QUICK_START.md](QUICK_START.md) for detailed production configuration examples.

## Configuration Examples

### Per-Second API Rate Limiting

```yaml
- path: "/api"
  upstream: "http://backend:8000"
  max_req_per_window: 10  # Fallback: 10 req/sec
  advanced_limits:
    asn_limits:
      "15169":  # Google Cloud
        max_req: 50
        window_secs: 1      # Per SECOND
        block_duration_secs: 0
```

### File Upload with Per-Hour Limits

```yaml
- path: "/upload"
  upstream: "http://storage:9000"
  max_req_per_window: 100  # 100 uploads/hour
  advanced_limits:
    asn_limits:
      "32934":  # Facebook
        max_req: 200
        window_secs: 3600   # Per HOUR
        block_duration_secs: 0  # Soft limit

      "4134":  # China Telecom
        max_req: 10
        window_secs: 86400  # Per DAY
        block_duration_secs: 86400  # Hard block 1 day
```

### Admin Panel with Country Whitelist

```yaml
- path: "/admin"
  upstream: "http://admin:3000"
  advanced_limits:
    country_limits:
      "US": 1000  # Allow US
      "VN": 500   # Allow Vietnam

    # Block all other countries
    block_countries: ["CN", "RU", "KP"]

    # Only allow browsers
    user_agent_limits:
      "chrome": 1000
      "firefox": 1000
      "bot":
        max_req: 0
        window_secs: 1
        block_duration_secs: 86400  # Block bots for 1 day
```

## Testing

### Test Rate Limiting

```bash
# Send 70 requests (limit: 60/min)
for i in {1..70}; do
  curl -i -H "CF-Connecting-ASN: AS32934" \
       http://localhost:8081/api
  echo "Request $i"
done

# Expected:
# Request 1-60: 200 OK
# Request 61-70: 429 Too Many Requests
#   Headers: Retry-After: 60, X-RateLimit-Window: 60
```

### Test Sliding Window

```bash
# T=0s: Send 60 requests instantly
for i in {1..60}; do curl http://localhost:8081/api & done
wait

# T=0s: Try 61st → 429 Too Many Requests
curl -i http://localhost:8081/api

# T=30s: Still blocked (60 requests from T=0 still in window)
sleep 30 && curl -i http://localhost:8081/api

# T=60s: OK (window slid, old requests expired)
sleep 30 && curl -i http://localhost:8081/api
```

## Production Deployment

### Docker

```bash
# Build image
docker build -t pingwall:latest .

# Run container
docker run -d \
  -p 8081:8081 \
  -p 9090:9090 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v /path/to/certs:/certs \
  pingwall:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  pingwall:
    build: .
    ports:
      - "8081:8081"
      - "9090:9090"
    volumes:
      - ./config.production-ready.yaml:/app/config.yaml
      - ./certs:/certs
    restart: unless-stopped
```

### Systemd Service

```ini
[Unit]
Description=Pingwall Reverse Proxy
After=network.target

[Service]
Type=simple
User=pingwall
WorkingDirectory=/opt/pingwall
ExecStart=/opt/pingwall/target/release/pingwall
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Monitoring

### Prometheus Metrics

Metrics available at `:9090/metrics`:

```
# Request counters
pingwall_requests_total{path="/api",status="200"}
pingwall_requests_total{path="/api",status="429"}

# Rate limit metrics
pingwall_rate_limited_total{path="/api",reason="advanced_asn"}
pingwall_blocked_ips_total{path="/api"}

# Response times
pingwall_request_duration_seconds{path="/api"}
```

### Grafana Dashboard

Import the included dashboard from `grafana/pingwall-dashboard.json`.

## Performance

**Benchmarks** (MacBook Pro M1, 8GB RAM):

```
Concurrent connections: 1000
Requests/sec: ~50,000
Latency (p99): <5ms
Memory usage: ~50MB
```

Pingora's async architecture enables handling millions of requests with minimal resource usage.

## FAQ

**Q: Why are my rate limits not working?**
A: Enable Cloudflare integration (`use_cloudflare: true`) and ensure traffic goes through Cloudflare proxy. Advanced limits require CF headers (ASN, Country, etc.).

**Q: What's the difference between soft limit and hard block?**
A:
- **Soft limit** (`block_duration_secs: 0`): Only rejects exceeded requests, doesn't block IP
- **Hard block** (`block_duration_secs > 0`): Blocks IP for N seconds

**Q: How does sliding window work?**
A: Unlike fixed windows (00:00-00:59, 01:00-01:59), sliding windows calculate limits based on the last N seconds from NOW. This prevents burst loopholes where users could send 120 requests in 2 seconds across window boundaries.

**Q: Can I use different windows for different limits?**
A: Yes! Each advanced limit can have its own `window_secs`:
```yaml
asn_limits:
  "15169":
    max_req: 50
    window_secs: 1      # Per SECOND
  "32934":
    max_req: 60
    window_secs: 60     # Per MINUTE
```

## Documentation

- [QUICK_START.md](QUICK_START.md) - Production-ready configuration guide
- [config.production-ready.yaml](config.production-ready.yaml) - Complete config example

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built on [Cloudflare Pingora](https://github.com/cloudflare/pingora)
- Inspired by industry-standard rate limiting (GitHub, Stripe, Cloudflare)

---

**Production Ready | Memory Safe | Lightning Fast** ⚡
