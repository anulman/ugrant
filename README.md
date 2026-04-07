# ugrant

`ugrant` is a portable OAuth 2.0 token broker and exec wrapper for local tools, scripts, and shell workflows.

## Agent quickstart

- Use-agent entrypoint: `https://www.ugrant.sh/llms.txt`
- Full site agent guide: `https://www.ugrant.sh/llms-full.txt`
- Coding-agent entrypoint: read [`AGENTS.md`](./AGENTS.md) first

It keeps grant material local, encrypts secret fields at rest, refreshes access tokens on use, and injects only the child-safe environment a tool actually needs.

Recent hardening includes Argon2id passphrase wrapping, 0700/0600 secret-state permissions on Unix, state-validated manual login fallback, concurrent refresh leasing, and minisign-signed release archives with checksum fallback installs.

## What it does

- Local OAuth login with stored refresh-token custody
- Encrypted-at-rest token storage with rekey support
- Strong local backend selection (`platform-secure-store`, `tpm2`, `passphrase`, explicit insecure fallback)
- Child-safe env injection via `ugrant env` and `ugrant exec`
- Concurrent refresh leasing so one process refreshes while others wait
- Minisign-signed release archives, with `.sha256` files kept for compatibility

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

## Agent flow

If you're driving `ugrant` from an AI agent, the happy path is:

1. install `ugrant`
2. run `ugrant init`
3. run `ugrant profile add ...`
4. pause for human OAuth consent during `ugrant login`
5. resume with `ugrant exec --profile ... -- <command>`

That split matters. Agents can handle setup, but OAuth approval is still a human boundary.

## Install

```bash
curl -fsSLo /tmp/ugrant-install.sh https://www.ugrant.sh/install.sh && sh /tmp/ugrant-install.sh
```

The install script prefers minisign verification when `minisign` is available. If not, it falls back to the matching `.sha256` file with a blunt warning so older environments still work.

## Verify a release manually

Minisign is the preferred authenticity check for published archives.

```bash
TAG=v0.1.0
TARGET=linux-x86_64
ARCHIVE="ugrant-${TAG}-${TARGET}.tar.gz"

curl -fsSL "https://www.ugrant.sh/install?target=${TARGET}" -o "$ARCHIVE"
curl -fsSL "https://www.ugrant.sh/install?target=${TARGET}&kind=minisig" -o "${ARCHIVE}.minisig"
curl -fsSLo minisign.pub https://www.ugrant.sh/minisign.pub

minisign -Vm "$ARCHIVE" -p minisign.pub -x "${ARCHIVE}.minisig"
```

For environments without `minisign`, the matching checksum remains available:

```bash
curl -fsSL "https://www.ugrant.sh/install?target=${TARGET}&kind=sha256" -o "${ARCHIVE}.sha256"
sha256sum -c "${ARCHIVE}.sha256"
```

## Maintainer notes for release signing

The release workflow expects:

- a checked-in `minisign.pub` file containing the public key for release verification
- a GitHub Actions secret named `MINISIGN_SECRET_KEY` containing the matching secret key

A pragmatic way to generate that pair for CI is:

```bash
minisign -G -W -p minisign.pub -s ugrant.minisign.key
```

That creates an unencrypted secret key, which is simpler for GitHub Actions automation. Store the contents of `ugrant.minisign.key` in the `MINISIGN_SECRET_KEY` repository secret, and commit `minisign.pub`.

## Project files

- `src/main.zig` — CLI implementation
- `SPEC.md` — user-visible behavior/spec
- `site/` — single-page homepage draft for `ugrant.sh`
- `minisign.pub` — checked-in release verification key

## Website draft

A simple single-page homepage draft lives in `site/`.

## License

MIT
