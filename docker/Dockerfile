# ghcr.io/amet13/unpatched: the `unpatched` binary and nothing else.
#
#   docker build -f docker/Dockerfile -t unpatched .
#   docker run --rm -v "$PWD:/work" ghcr.io/amet13/unpatched            # check --notify
#   docker run --rm -v "$PWD:/work" ghcr.io/amet13/unpatched explain CVE-2024-21762
#
# The binary is built on Alpine (musl), so it is static and the final image needs
# no libc. Build on the architecture you want to run (the release workflow uses a
# native runner for each); there is no cross-compiling here.

# Base images are pinned by digest (Dependabot proposes new ones). The Rust version is the
# one in rust-toolchain.toml; keep the tag equal to it (MAINTAINING.md, "Bumping Rust").
FROM rust:1.100.0-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY . .
# The image's own Rust (the tag above) builds; rust-toolchain.toml would ask rustup for a
# download and for rustfmt and clippy, which the image does not need.
RUN rm -f rust-toolchain.toml
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p unpatched \
    && install -D -m 0755 target/release/unpatched /out/unpatched

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/unpatched /usr/local/bin/unpatched
COPY LICENSE NOTICE /usr/share/doc/unpatched/
WORKDIR /work
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/unpatched"]
CMD ["check", "--notify"]
LABEL org.opencontainers.image.title="unpatched" \
      org.opencontainers.image.description="Tells you when software you run has a vulnerability you need to act on" \
      org.opencontainers.image.source="https://github.com/Amet13/unpatched" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.Amet13/unpatched"
