# ============================================================================
# Pingwall - Pingora-powered Firewall
# ============================================================================
# Multi-stage Dockerfile for building a minimal production image

# Build stage
FROM rust:1.90 as builder

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

# Now copy the real source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM ubuntu:latest

WORKDIR /app

# Install SSL certificates for HTTPS support
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the built executable
COPY --from=builder /usr/src/pingwall/target/release/pingwall /app/



# Expose ports for HTTP and HTTPS
EXPOSE 80 443


# Set environment variable for config file location
ENV CONFIG_FILE=/app/config.yaml
RUN chmod +x /app/pingwall
# Command to run the application
CMD ["/app/pingwall"]