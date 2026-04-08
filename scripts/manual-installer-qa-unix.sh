#!/usr/bin/env bash
set -euo pipefail

TMPROOT="$(mktemp -d)"
trap 'rm -rf "$TMPROOT"' EXIT

export HOME="$TMPROOT/home"
mkdir -p "$HOME"
BIN="$HOME/.local/bin/ugrant"

step() {
  printf '\n### %s\n' "$1"
}

step "Fresh install into isolated HOME"
curl -fsSLo "$TMPROOT/install.sh" https://www.ugrant.sh/install.sh
sh "$TMPROOT/install.sh"
"$BIN" status || true

step "Initialize and inspect live state"
"$BIN" init --backend insecure-keyfile --allow-insecure-keyfile
"$BIN" status
"$BIN" doctor

step "Add a profile record and verify it exists"
"$BIN" profile add \
  --name qa-smoke \
  --service google-imap \
  --client-id qa-client-id \
  --client-secret qa-client-secret
"$BIN" profile list

step "Reinstall over the existing binary"
sh "$TMPROOT/install.sh"
"$BIN" status

step "Repair a clobbered install"
printf '#!/bin/sh\necho broken\n' > "$BIN"
chmod +x "$BIN"
sh "$TMPROOT/install.sh"
"$BIN" status

cat <<EOF

Manual checks to record:
- Did install succeed without touching your real HOME?
- Did reinstall overwrite the existing binary cleanly?
- Did the repair step replace a broken binary with a working one?
- Did status/doctor show sensible config and state paths?
EOF
