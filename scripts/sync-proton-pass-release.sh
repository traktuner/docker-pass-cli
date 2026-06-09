#!/usr/bin/env bash
set -euo pipefail

repo="protonpass/pass-cli"

release_json="$(gh api "repos/${repo}/releases/latest")"
version="$(jq -r '.tag_name' <<<"${release_json}")"
prerelease="$(jq -r '.prerelease' <<<"${release_json}")"
draft="$(jq -r '.draft' <<<"${release_json}")"

if [[ "${draft}" != "false" || "${prerelease}" != "false" ]]; then
  echo "Latest Proton Pass CLI release is not stable" >&2
  exit 1
fi
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Unexpected Proton Pass CLI version: ${version}" >&2
  exit 1
fi

ref_json="$(gh api "repos/${repo}/git/ref/tags/${version}")"
object_type="$(jq -r '.object.type' <<<"${ref_json}")"
commit="$(jq -r '.object.sha' <<<"${ref_json}")"

while [[ "${object_type}" == "tag" ]]; do
  tag_json="$(gh api "repos/${repo}/git/tags/${commit}")"
  object_type="$(jq -r '.object.type' <<<"${tag_json}")"
  commit="$(jq -r '.object.sha' <<<"${tag_json}")"
done

if [[ "${object_type}" != "commit" || ! "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Unable to resolve Proton Pass CLI ${version} to a commit" >&2
  exit 1
fi

current_version="$(sed -n 's/^ARG PROTON_PASS_VERSION=//p' Dockerfile)"
current_commit="$(sed -n 's/^ARG PROTON_PASS_COMMIT=//p' Dockerfile)"
current_broker_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"

if [[ "${current_version}" == "${version}" && "${current_commit}" == "${commit}" ]]; then
  echo "changed=false"
  echo "version=${version}"
  echo "commit=${commit}"
  echo "broker_version=${current_broker_version}"
  exit 0
fi

broker_version="${version}-1"
python3 - "${version}" "${commit}" "${broker_version}" <<'PY'
from pathlib import Path
import re
import sys

version, commit, broker_version = sys.argv[1:]

dockerfile = Path("Dockerfile")
docker_text = dockerfile.read_text(encoding="utf-8")
docker_text, version_count = re.subn(
    r"(?m)^ARG PROTON_PASS_VERSION=.*$",
    f"ARG PROTON_PASS_VERSION={version}",
    docker_text,
)
docker_text, commit_count = re.subn(
    r"(?m)^ARG PROTON_PASS_COMMIT=.*$",
    f"ARG PROTON_PASS_COMMIT={commit}",
    docker_text,
)
if version_count != 1 or commit_count != 1:
    raise SystemExit("Dockerfile Proton Pass build arguments are invalid")
dockerfile.write_text(docker_text, encoding="utf-8")

cargo_toml = Path("Cargo.toml")
toml_text = cargo_toml.read_text(encoding="utf-8")
toml_text, count = re.subn(
    r'(?m)^(version = ")[^"]+(")$',
    rf"\g<1>{broker_version}\2",
    toml_text,
    count=1,
)
if count != 1:
    raise SystemExit("Cargo.toml workspace version is invalid")
cargo_toml.write_text(toml_text, encoding="utf-8")

cargo_lock = Path("Cargo.lock")
lock_text = cargo_lock.read_text(encoding="utf-8")
lock_text, count = re.subn(
    r'(?m)(name = "proton-pass-broker"\nversion = ")[^"]+(")',
    rf"\g<1>{broker_version}\2",
    lock_text,
    count=1,
)
if count != 1:
    raise SystemExit("Cargo.lock broker package is invalid")
cargo_lock.write_text(lock_text, encoding="utf-8")
PY

echo "changed=true"
echo "version=${version}"
echo "commit=${commit}"
echo "broker_version=${broker_version}"
