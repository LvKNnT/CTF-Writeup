FROM rust:1-bookworm AS builder

WORKDIR /build
COPY Cargo.toml .
COPY Cargo.lock .
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/chall /app/chall
COPY run.sh /app/run.sh

RUN chmod +x /app/chall /app/run.sh

EXPOSE 1337
ENTRYPOINT ["/app/run.sh"]
