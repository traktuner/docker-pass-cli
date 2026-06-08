# syntax=docker/dockerfile:1.24

ARG RUST_VERSION=1.88
ARG PROTON_PASS_VERSION=2.1.2
ARG PROTON_PASS_COMMIT=b0a15d41dabc4e71d2cc3cf6710595a4271355b9

FROM rust:${RUST_VERSION}-bookworm AS broker-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY broker ./broker
RUN cargo build --locked --release --package proton-pass-broker

FROM rust:${RUST_VERSION}-bookworm AS pass-cli-builder
ARG PROTON_PASS_COMMIT
RUN apt-get update && \
    apt-get install --yes --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/protonpass/pass-cli.git . && \
    git checkout --detach "${PROTON_PASS_COMMIT}" && \
    test "$(git rev-parse HEAD)" = "${PROTON_PASS_COMMIT}"
RUN cargo build --locked --release --package pass-cli

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

COPY --from=broker-builder /src/target/release/proton-pass-broker /usr/local/bin/proton-pass-broker
COPY --from=pass-cli-builder /src/target/release/pass-cli /usr/local/bin/pass-cli
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/

USER 1001:0
ENTRYPOINT ["/usr/local/bin/proton-pass-broker"]
CMD ["serve"]
