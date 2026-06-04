# Zebra built with internal-miner feature for Sovright testnet
FROM rust:1.85-slim as builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch v4.3.0 https://github.com/ZcashFoundation/zebra.git /zebra
WORKDIR /zebra

RUN cargo build --release --features "internal-miner" --bin zebrad

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /zebra/target/release/zebrad /usr/local/bin/zebrad

EXPOSE 18232 18233
ENTRYPOINT ["zebrad"]
