#!/usr/bin/env bash
set -euo pipefail

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

  args+=(-i dev.ugrant)

  codesign "${args[@]}" "$binary"
done
