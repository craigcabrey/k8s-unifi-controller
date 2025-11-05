# Stage 1: Builder
FROM rust:latest AS builder

WORKDIR /app

# Copy Cargo.toml and Cargo.lock to leverage Docker cache
COPY Cargo.toml Cargo.lock ./

# Copy the actual source code
COPY src ./src

# Build the application
RUN cargo build --release

# Stage 2: Runtime
FROM debian:stable-slim

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/k8s-unifi-controller ./k8s-unifi-controller

# Run the application with debug flag
CMD ["./k8s-unifi-controller", "--debug"]
