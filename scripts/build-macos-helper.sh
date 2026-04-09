#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="$ROOT/helpers/macos-se-helper"
CONFIG=release
OUT_DIR="$ROOT/dist/macos-helper"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)
      CONFIG=debug
      shift
      ;;
    --release)
      CONFIG=release
      shift
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [--debug|--release] [--out-dir <dir>]" >&2
      exit 2
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build-macos-helper: macOS only" >&2
  exit 1
fi

command -v swift >/dev/null || {
  echo "build-macos-helper: swift not found" >&2
  exit 1
}

swift build --package-path "$PKG_DIR" -c "$CONFIG"
mkdir -p "$OUT_DIR"
cp "$PKG_DIR/.build/$CONFIG/ugrant-se-helper" "$OUT_DIR/ugrant-se-helper"
chmod +x "$OUT_DIR/ugrant-se-helper"
echo "$OUT_DIR/ugrant-se-helper"
