# Stage 1: Build
FROM rust:1.77-bookworm AS builder

RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build -p zcash-test-miner --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zcash-test-miner /usr/local/bin/

ENTRYPOINT ["zcash-test-miner"]
