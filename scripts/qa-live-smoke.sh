#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${UGRANT_BIN:-$ROOT/zig-out/bin/ugrant}"
TMPROOT="$(mktemp -d)"
trap 'rm -rf "$TMPROOT"' EXIT

export HOME="$TMPROOT/home"
mkdir -p "$HOME"

unset UGRANT_TEST_PLATFORM_STORE_AVAILABLE
unset UGRANT_TEST_PLATFORM_STORE_SECRET

log() {
  printf '\n==> %s\n' "$1"
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "$needle" <<<"$haystack"; then
    printf 'Expected output to contain: %s\n' "$needle" >&2
    printf 'Actual output:\n%s\n' "$haystack" >&2
    exit 1
  fi
}

log "init insecure-keyfile in isolated HOME"
"$BIN" init --backend insecure-keyfile --allow-insecure-keyfile >/tmp/ugrant-init.out
status_out="$($BIN status)"
assert_contains "$status_out" "initialized: yes"
assert_contains "$status_out" "backend: insecure-keyfile"
assert_contains "$status_out" "security_mode: degraded"

doctor_out="$($BIN doctor)"
assert_contains "$doctor_out" "config:"
assert_contains "$doctor_out" "state_dir:"

log "add a real profile record without live oauth"
"$BIN" profile add \
  --name qa-smoke \
  --service google-imap \
  --client-id qa-client-id \
  --client-secret qa-client-secret >/tmp/ugrant-profile-add.out
profile_list="$($BIN profile list)"
assert_contains "$profile_list" "qa-smoke"

log "rekey into platform-secure-store test backend"
export UGRANT_TEST_PLATFORM_STORE_AVAILABLE=1
export UGRANT_TEST_PLATFORM_STORE_SECRET=ci-platform-secret
"$BIN" rekey --backend platform-secure-store >/tmp/ugrant-rekey-platform.out
status_out="$($BIN status)"
assert_contains "$status_out" "backend: platform-secure-store"
assert_contains "$status_out" "security_mode: normal"

doctor_out="$($BIN doctor)"
assert_contains "$doctor_out" "config:"
assert_contains "$doctor_out" "state_dir:"

log "rekey back to insecure-keyfile"
"$BIN" rekey --allow-insecure-keyfile >/tmp/ugrant-rekey-insecure.out
status_out="$($BIN status)"
assert_contains "$status_out" "backend: insecure-keyfile"
assert_contains "$status_out" "security_mode: degraded"

log "live smoke passed"
