use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec,
    CounterVec, GaugeVec, HistogramVec, Encoder, TextEncoder
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use async_trait::async_trait;

lazy_static! {
    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "pingwall_http_requests_total",
        "Total number of HTTP requests processed",
        &["domain", "path", "method", "status"]
    ).unwrap();

    pub static ref HTTP_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "pingwall_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["domain", "path", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).unwrap();

    pub static ref RATE_LIMIT_BLOCKS: CounterVec = register_counter_vec!(
        "pingwall_rate_limit_blocks_total",
        "Total number of requests blocked by rate limiting",
        &["domain", "path", "ip"]
    ).unwrap();

    pub static ref ACTIVE_CONNECTIONS: GaugeVec = register_gauge_vec!(
        "pingwall_active_connections",
        "Number of active connections",
        &["domain"]
    ).unwrap();

    pub static ref UPSTREAM_ERRORS: CounterVec = register_counter_vec!(
        "pingwall_upstream_errors_total",
        "Total number of upstream errors",
        &["domain", "path", "error_type"]
    ).unwrap();

    pub static ref SSL_HANDSHAKES: CounterVec = register_counter_vec!(
        "pingwall_ssl_handshakes_total",
        "Total number of SSL/TLS handshakes",
        &["domain", "success"]
    ).unwrap();

    pub static ref BLOCKED_IPS: GaugeVec = register_gauge_vec!(
        "pingwall_blocked_ips",
        "Number of currently blocked IPs",
        &["domain", "path"]
    ).unwrap();

    pub static ref WEBHOOK_NOTIFICATIONS: CounterVec = register_counter_vec!(
        "pingwall_webhook_notifications_total",
        "Total number of webhook notifications sent",
        &["success"]
    ).unwrap();
}

pub struct MetricsService {
    port: u16,
}

impl MetricsService {
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}

#[async_trait]
impl BackgroundService for MetricsService {
    async fn start(&self, _shutdown: ShutdownWatch) {
        let addr = ([0, 0, 0, 0], self.port);

        log::info!("Starting Prometheus metrics server on port {}", self.port);

        let make_service = hyper::service::make_service_fn(|_| async {
            Ok::<_, hyper::Error>(hyper::service::service_fn(metrics_handler))
        });

        let server = hyper::Server::bind(&addr.into())
            .serve(make_service);

        if let Err(e) = server.await {
            log::error!("Metrics server error: {}", e);
        }
    }
}

async fn metrics_handler(
    _req: hyper::Request<hyper::Body>,
) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        log::error!("Failed to encode metrics: {}", e);
        return Ok(hyper::Response::builder()
            .status(500)
            .body(hyper::Body::from("Failed to encode metrics"))
            .unwrap());
    }

    Ok(hyper::Response::builder()
        .status(200)
        .header("Content-Type", encoder.format_type())
        .body(hyper::Body::from(buffer))
        .unwrap())
}

pub fn record_request(domain: &str, path: &str, method: &str, status: u16, duration_secs: f64) {
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[domain, path, method, &status.to_string()])
        .inc();

    HTTP_REQUEST_DURATION
        .with_label_values(&[domain, path, method])
        .observe(duration_secs);
}

pub fn record_rate_limit_block(domain: &str, path: &str, ip: &str) {
    RATE_LIMIT_BLOCKS
        .with_label_values(&[domain, path, ip])
        .inc();
}

pub fn record_upstream_error(domain: &str, path: &str, error_type: &str) {
    UPSTREAM_ERRORS
        .with_label_values(&[domain, path, error_type])
        .inc();
}

pub fn record_ssl_handshake(domain: &str, success: bool) {
    SSL_HANDSHAKES
        .with_label_values(&[domain, if success { "true" } else { "false" }])
        .inc();
}

pub fn update_active_connections(domain: &str, delta: i64) {
    if delta > 0 {
        ACTIVE_CONNECTIONS.with_label_values(&[domain]).add(delta as f64);
    } else {
        ACTIVE_CONNECTIONS.with_label_values(&[domain]).sub((-delta) as f64);
    }
}

pub fn update_blocked_ips(domain: &str, path: &str, count: i64) {
    BLOCKED_IPS
        .with_label_values(&[domain, path])
        .set(count as f64);
}

pub fn record_webhook_notification(success: bool) {
    WEBHOOK_NOTIFICATIONS
        .with_label_values(&[if success { "true" } else { "false" }])
        .inc();
}
