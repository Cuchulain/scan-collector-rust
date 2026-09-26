FROM rust:1-alpine AS build
RUN apk add --no-cache build-base musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY templates ./templates
RUN cargo build --release

FROM alpine:3.22
RUN apk add --no-cache su-exec \
    && addgroup -S app \
    && adduser -S -G app app \
    && mkdir -p /data
COPY --from=build /src/target/release/scan-collector-rust /usr/local/bin/scan-collector-rust
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENV PORT=8765 DATA_DIR=/data
EXPOSE 8765
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["scan-collector-rust"]
