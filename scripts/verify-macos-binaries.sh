#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary> [<binary> ...]" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "verify-macos-binaries: macOS only" >&2
  exit 1
fi

for binary in "$@"; do
  codesign --verify --verbose=2 "$binary"
  codesign -dv --verbose=4 "$binary" >/dev/null
done
