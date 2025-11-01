# ============================================================================
# Pingwall - Pingora-powered Firewall
# ============================================================================
# Multi-stage Dockerfile for building a minimal production image

# Build stage
FROM rust:1.81 as builder

WORKDIR /usr/src/pingwall

# Copy the Cargo.toml and Cargo.lock files first to leverage Docker caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release

# Now copy the real source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim

WORKDIR /app

# Install SSL certificates for HTTPS support
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

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