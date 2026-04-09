#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER_ENTITLEMENTS="$ROOT/helpers/macos-se-helper/entitlements.plist"
IDENTITY="${APPLE_CODESIGN_IDENTITY:-}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary> [<binary> ...]" >&2
  exit 2
fi

if [[ -z "$IDENTITY" ]]; then
  echo "sign-macos-binaries: APPLE_CODESIGN_IDENTITY is required" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "sign-macos-binaries: macOS only" >&2
  exit 1
fi

for binary in "$@"; do
  if [[ ! -f "$binary" ]]; then
    echo "sign-macos-binaries: missing binary $binary" >&2
    exit 1
  fi

  args=(
    --force
    --sign "$IDENTITY"
    --timestamp
    --options runtime
  )

  if [[ "$(basename "$binary")" == "ugrant-se-helper" ]]; then
    args+=(--entitlements "$HELPER_ENTITLEMENTS" -i dev.ugrant.secure-enclave-helper)
  else
    args+=(-i dev.ugrant)
  fi

  codesign "${args[@]}" "$binary"
done
