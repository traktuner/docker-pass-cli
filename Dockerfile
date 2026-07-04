# syntax=docker/dockerfile:1.25

ARG RUST_VERSION=1.96
ARG PROTON_PASS_VERSION=2.2.2
ARG PROTON_PASS_COMMIT=1168b64fea6fd1210f6f976e8b33da0d46995a57

FROM rust:${RUST_VERSION}-bookworm AS broker-builder
ARG TARGETPLATFORM
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY broker/Cargo.toml broker/Cargo.toml
RUN mkdir -p broker/src && \
    printf 'fn main() {}\n' > broker/src/main.rs
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=broker-target-${TARGETPLATFORM},target=/src/target,sharing=locked \
    cargo build --locked --release --package proton-pass-broker
COPY broker/src broker/src
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=broker-target-${TARGETPLATFORM},target=/src/target,sharing=locked \
    touch broker/src/main.rs && \
    cargo build --locked --release --package proton-pass-broker && \
    install -D -m 0755 target/release/proton-pass-broker \
      /out/proton-pass-broker

FROM rust:${RUST_VERSION}-bookworm AS pass-cli-builder
ARG PROTON_PASS_COMMIT
ARG TARGETPLATFORM
RUN apt-get update && \
    apt-get install --yes --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git init . && \
    git remote add origin https://github.com/protonpass/pass-cli.git && \
    git fetch --depth 1 origin "${PROTON_PASS_COMMIT}" && \
    git checkout --detach "${PROTON_PASS_COMMIT}" && \
    test "$(git rev-parse HEAD)" = "${PROTON_PASS_COMMIT}"
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=pass-cli-target-${TARGETPLATFORM},target=/src/target,sharing=locked \
    cargo build --locked --release --package pass-cli && \
    install -D -m 0755 target/release/pass-cli /out/pass-cli

FROM cgr.dev/chainguard/glibc-dynamic:latest
ARG PROTON_PASS_VERSION
ARG PROTON_PASS_COMMIT

LABEL org.opencontainers.image.title="Proton Pass Broker" \
      org.opencontainers.image.description="Scoped Unix-socket broker for Proton Pass CLI" \
      org.opencontainers.image.source="https://github.com/traktuner/docker-pass-cli" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="${PROTON_PASS_VERSION}" \
      org.opencontainers.image.revision="${PROTON_PASS_COMMIT}" \
      io.traktuner.proton-pass.version="${PROTON_PASS_VERSION}" \
      io.traktuner.proton-pass.commit="${PROTON_PASS_COMMIT}"

COPY --from=broker-builder /out/proton-pass-broker /usr/local/bin/proton-pass-broker
COPY --from=pass-cli-builder /out/pass-cli /usr/local/bin/pass-cli
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/

USER 1001:0
ENTRYPOINT ["/usr/local/bin/proton-pass-broker"]
CMD ["serve"]
