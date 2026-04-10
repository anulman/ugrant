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

if [ "$(uname -s)" = "Darwin" ]; then
  step "macOS only: rekey into login Keychain-backed platform-secure-store"
  "$BIN" rekey --backend platform-secure-store
  "$BIN" status
  "$BIN" doctor
fi

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

if [ "$(uname -s)" = "Darwin" ]; then
  cat <<EOF
- On macOS, after `ugrant rekey --backend platform-secure-store`, did `status` / `doctor` report `backend: platform-secure-store` and `backend_provider: macOS Keychain`?
- On macOS, did Keychain Access or `security find-generic-password -s dev.ugrant.platform-secure-store ~/Library/Keychains/login.keychain-db` show a login-keychain generic-password item with account `dek:<key_version>`?
- On macOS, was the move into Keychain explicit, meaning nothing migrated before you ran `ugrant rekey --backend platform-secure-store`?
- On macOS, manually run `ugrant rekey --secure-enclave`. Did `status` / `doctor` report `backend: macos-secure-enclave` and `backend_provider: macOS Secure Enclave`?
- If you also test `ugrant rekey --secure-enclave --require-user-presence`, did `status` / `doctor` report `user_presence_required: yes`, and did you record both an approved prompt and a cancelled prompt? A cancelled prompt should now appear as its own explicit Secure Enclave doctor failure.
- After Secure Enclave testing, did `ugrant rekey --backend platform-secure-store` return the install to plain `backend_provider: macOS Keychain`?
- Before any broader rollout, record at least one Apple Silicon pass for the Keychain -> Secure Enclave -> Keychain round-trip. Additional macOS hardware/version coverage is still recommended before calling it broadly ready.
EOF
fi
