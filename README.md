# ugrant

`ugrant` is a portable OAuth 2.0 token broker and exec wrapper for local tools, scripts, and shell workflows.

It keeps grant material local, encrypts secret fields at rest, refreshes access tokens on use, and injects only the child-safe environment a tool actually needs.

Recent hardening includes Argon2id passphrase wrapping, 0700/0600 secret-state permissions on Unix, state-validated manual login fallback, and checksum-verified release installs.

## What it does

- Local OAuth login with stored refresh-token custody
- Encrypted-at-rest token storage with rekey support
- Strong local backend selection (`platform-secure-store`, `tpm2`, `passphrase`, explicit insecure fallback)
- Child-safe env injection via `ugrant env` and `ugrant exec`
- Concurrent refresh leasing so one process refreshes while others wait

## Build

Requirements:

- Zig 0.15.2+
- SQLite development headers / library (`libsqlite3-dev` on Debian/Ubuntu)
- Python 3 (used for OAuth helper flows)

Build:

```bash
zig build -Doptimize=ReleaseSafe
```

Test:

```bash
zig test src/main.zig -lc -lsqlite3
```

## Quick start

```bash
ugrant init

ugrant profile add \
  --name gmail \
  --service google-imap \
  --client-id <id> \
  --client-secret <secret>

ugrant login --profile gmail

ugrant exec --profile gmail -- python sync_mail.py
```

Manual login fallback accepts a full redirect URL by default. Bare auth-code entry is still available, but only with `--unsafe-bare-code` because it skips OAuth state validation.

## Install

```bash
curl -fsSLo /tmp/ugrant-install.sh https://www.ugrant.sh/install.sh && sh /tmp/ugrant-install.sh
```

The install script fetches the matching release checksum and verifies the archive before copying the binary into `~/.local/bin`.

## Project files

- `src/main.zig` — CLI implementation
- `SPEC.md` — user-visible behavior/spec
- `site/` — single-page homepage draft for `ugrant.sh`

## Website draft

A simple single-page homepage draft lives in `site/`.

## License

MIT
