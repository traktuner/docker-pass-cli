#!/usr/bin/env bash
# Diagnose a pinned source build. Never use the generated lockfile in an image.
set -euo pipefail

rust_version="$(sed -n 's/^ARG RUST_VERSION=//p' Dockerfile)"
pass_commit="$(sed -n 's/^ARG PROTON_PASS_COMMIT=//p' Dockerfile)"
[[ "$rust_version" =~ ^[0-9]+\.[0-9]+$ ]]
[[ "$pass_commit" =~ ^[0-9a-f]{40}$ ]]

docker run --rm "rust:${rust_version}-bookworm" /bin/sh -eu -c '
  mkdir /diagnostic
  cd /diagnostic
  git init -q
  git remote add origin https://github.com/protonpass/pass-cli.git
  git fetch --depth 1 origin "$1"
  git checkout --detach "$1"
  test "$(git rev-parse HEAD)" = "$1"
  cargo metadata --format-version 1 > /tmp/pass-metadata.json
  git diff --stat -- Cargo.lock
  git diff -- Cargo.lock
' diagnostic "$pass_commit"
