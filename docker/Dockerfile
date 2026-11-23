# ghcr.io/amet13/unpatched: the `unpatched` binary and nothing else.
#
#   docker build -f docker/Dockerfile -t unpatched .
#   docker run --rm -v "$PWD:/work" ghcr.io/amet13/unpatched            # check --notify
#   docker run --rm -v "$PWD:/work" ghcr.io/amet13/unpatched explain CVE-2024-21762
#
# The binary is built on Alpine (musl), so it is static and the final image needs
# no libc. Build on the architecture you want to run (the release workflow uses a
# native runner for each); there is no cross-compiling here.

FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
# rust-toolchain.toml asks for rustfmt and clippy; the image only needs to build.
ENV RUSTUP_TOOLCHAIN=stable
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p unpatched \
    && install -D -m 0755 target/release/unpatched /out/unpatched

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/unpatched /usr/local/bin/unpatched
COPY LICENSE NOTICE /usr/share/doc/unpatched/
WORKDIR /work
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/unpatched"]
CMD ["check", "--notify"]
LABEL org.opencontainers.image.title="unpatched" \
      org.opencontainers.image.description="Tells you when software you run has a vulnerability you need to act on" \
      org.opencontainers.image.source="https://github.com/Amet13/unpatched" \
      org.opencontainers.image.licenses="MIT"
