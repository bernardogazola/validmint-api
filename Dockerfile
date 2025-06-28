# Multi-stage Dockerfile for email validator API
# Optimized for production deployment with minimal image size

# Build stage
FROM rust:1.87-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

# Set up build environment
WORKDIR /app
ENV RUSTFLAGS="-C target-cpu=native -C link-arg=-s"
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
COPY crates/email_core/Cargo.toml ./crates/email_core/
COPY crates/email_validator_api/Cargo.toml ./crates/email_validator_api/

# Create dummy source files for dependency caching
RUN mkdir -p crates/email_core/src crates/email_validator_api/src && \
    echo "fn main() {}" > crates/email_validator_api/src/main.rs && \
    echo "// dummy" > crates/email_core/src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --bin email_validator_api

# Copy the actual source code
COPY crates/ ./crates/
COPY list.txt ./

# Touch source files to ensure rebuild
RUN find crates/ -name "*.rs" -exec touch {} \;

# Build the application
RUN cargo build --release --bin email_validator_api

# Verify binary was built
RUN ls -la target/release/

# Runtime stage - distroless for minimal attack surface
FROM gcr.io/distroless/cc-debian12:latest

# Copy the binary from builder stage
COPY --from=builder /app/target/release/email_validator_api /usr/local/bin/email_validator_api

# Copy the disposable domains list
COPY --from=builder /app/list.txt /app/list.txt

# Set working directory
WORKDIR /app

# Create non-root user
USER 1000:1000

# Expose port
EXPOSE 3000

# Health check using wget (need to add it to the distroless image)
# For distroless, we'll rely on Fly.io's built-in health checks instead

# Default command
ENTRYPOINT ["/usr/local/bin/email_validator_api"]

# Metadata
LABEL maintainer="Code-Agent <noreply@anthropic.com>"
LABEL description="High-performance email domain validation API"
LABEL version="0.1.0"
LABEL org.opencontainers.image.title="Email Validator API"
LABEL org.opencontainers.image.description="Email domain validation API for RapidAPI"
LABEL org.opencontainers.image.vendor="Code-Agent"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/your-org/email-validator-api"