#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <zip-archive>" >&2
  exit 2
fi

ARCHIVE="$1"
APPLE_ID="${APPLE_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
APPLE_APP_PASSWORD="${APPLE_APP_PASSWORD:-}"

if [[ -z "$APPLE_ID" || -z "$APPLE_TEAM_ID" || -z "$APPLE_APP_PASSWORD" ]]; then
  echo "notarize-macos-archive: APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_PASSWORD are required" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "notarize-macos-archive: macOS only" >&2
  exit 1
fi

xcrun notarytool submit "$ARCHIVE" \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD" \
  --wait
