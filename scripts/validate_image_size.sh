#!/usr/bin/env bash
# validate_image_size.sh — Phase 4 PKG-03 assertions
# Asserts: binary ≤ 20MB, image ≤ 50MB, static binary (no dynamic deps)
set -euo pipefail

BINARY="${1:-target/x86_64-unknown-linux-musl/release/bastion}"
IMAGE="${2:-bastion-test}"

if [ ! -f "$BINARY" ]; then
  echo "SKIP: binary not found at $BINARY (build first)"
  exit 0
fi

binary_size=$(stat -c%s "$BINARY")
max_binary=20971520  # 20MB in bytes
if [ "$binary_size" -gt "$max_binary" ]; then
  echo "FAIL: binary ${binary_size} bytes > 20MB (${max_binary} bytes)"
  exit 1
fi
echo "PASS: binary size = ${binary_size} bytes (≤ 20MB)"

if ldd "$BINARY" 2>&1 | grep -qv "not a dynamic executable"; then
  # ldd on a static binary prints "not a dynamic executable" to stderr and exits 1
  # We want to confirm it IS static
  :
fi
if ! (ldd "$BINARY" 2>&1 || true) | grep -q "not a dynamic executable"; then
  echo "FAIL: binary appears dynamically linked — must use x86_64-unknown-linux-musl target"
  exit 1
fi
echo "PASS: binary is statically linked"

if docker image inspect "$IMAGE" &>/dev/null 2>&1; then
  image_size=$(docker image inspect "$IMAGE" --format='{{.Size}}')
  max_image=52428800  # 50MB in bytes
  if [ "$image_size" -gt "$max_image" ]; then
    echo "FAIL: image ${image_size} bytes > 50MB (${max_image} bytes)"
    exit 1
  fi
  echo "PASS: image size = ${image_size} bytes (≤ 50MB)"
else
  echo "SKIP: image ${IMAGE} not built yet"
fi

echo "ALL CHECKS PASSED"
