# ============================================================================
# Pingwall - Pingora-powered Firewall
# ============================================================================
# Multi-stage Dockerfile for building a minimal production image

# Build stage
FROM rust:1.90 AS builder

WORKDIR /usr/src/pingwall

# Install build dependencies required for Pingora and its dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set build optimization flags to reduce memory usage
ENV CARGO_BUILD_JOBS=2
ENV CARGO_NET_RETRY=10
ENV RUSTFLAGS="-C codegen-units=1"

# Copy all source code
COPY . .

# Build the application with limited parallelism
RUN cargo build --release -j 2

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies for SSL/TLS support
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the built executable
COPY --from=builder /usr/src/pingwall/target/release/pingwall /app/

# Copy the example config file
COPY config.example.yaml /app/

# Create directories for logs and SSL certificates
RUN mkdir -p /app/logs /app/certs

# Expose ports for HTTP and HTTPS
EXPOSE 8080 8443

# Create volumes for SSL certificates and configuration
VOLUME ["/app/certs", "/app/config", "/app/logs"]

# Set environment variable for config file location
ENV CONFIG_FILE=/app/config.yaml

# Command to run the application
CMD ["/app/pingwall"]