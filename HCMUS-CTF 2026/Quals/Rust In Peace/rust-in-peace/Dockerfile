FROM rust:1.82-alpine AS builder

WORKDIR /build
COPY chall.rs .
RUN rustc -C opt-level=3 -C strip=symbols chall.rs -o chall

FROM alpine:3.20

RUN apk add --no-cache socat \
    && adduser -D -H -s /sbin/nologin ctf

WORKDIR /app
COPY --from=builder /build/chall /app/chall
COPY run.sh /app/run.sh
RUN chmod +x /app/chall /app/run.sh

USER ctf
EXPOSE 1337
ENTRYPOINT ["/app/run.sh"]
