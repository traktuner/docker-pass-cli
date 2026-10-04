#!/bin/sh
# Only apply an explicitly reviewed normalization for this immutable source.
set -eu

patch_dir="/upstream-lock-patches/$1"
if [ ! -d "$patch_dir" ]; then
  exit 0
fi
sha256sum --check "$patch_dir/before.sha256"
git apply --check --whitespace=error-all "$patch_dir/Cargo.lock.patch"
git apply --whitespace=error-all "$patch_dir/Cargo.lock.patch"
test "$(git diff --name-only)" = Cargo.lock
sha256sum --check "$patch_dir/after.sha256"
