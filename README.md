# ugrant

`ugrant` is a portable OAuth 2.0 token broker and exec wrapper for local tools, scripts, and shell workflows.

## Agent quickstart

- Use-agent entrypoint: `https://www.ugrant.sh/llms.txt`
- Full site agent guide: `https://www.ugrant.sh/llms-full.txt`
- Coding-agent entrypoint: read [`AGENTS.md`](./AGENTS.md) first

It keeps grant material local, encrypts secret fields at rest, refreshes access tokens on use, and adds negotiated runtime env vars for the child process.

Recent hardening includes Argon2id passphrase wrapping, 0700/0600 secret-state permissions on Unix, state-validated manual login fallback, concurrent refresh leasing, minisign-signed release archives with checksum fallback installs, and bundled SQLite builds across Linux, macOS, and Windows.

On macOS, `platform-secure-store` uses the default login Keychain. On Linux, `platform-secure-store` uses Secret Service when available and still prefers TPM2 when present. On Windows, `platform-secure-store` now uses user-scoped DPAPI for local wrap-secret custody.

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
- Python 3 (used for OAuth helper flows)

`ugrant` vendors the SQLite amalgamation, so you do not need separate SQLite headers or libraries on Linux, macOS, or Windows.

Build:

```bash
zig build -Doptimize=ReleaseSafe
```

To stamp a specific artifact version into the binary, pass `-Dversion=...` at build time:

```bash
zig build -Doptimize=ReleaseSafe -Dversion=v0.2.0-alpha.2
```

Test:

```bash
zig build test
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

macOS and Linux:

```bash
curl -fsSLo /tmp/ugrant-install.sh https://www.ugrant.sh/install.sh && sh /tmp/ugrant-install.sh
```

Windows PowerShell (x64 and ARM64):

```powershell
irm https://www.ugrant.sh/install.ps1 | iex
```

Both installers prefer minisign verification when `minisign` is available. If not, they fall back to the matching `.sha256` file with a blunt warning so older environments still work.

## macOS notes

- Config lives at `~/.config/ugrant/config.toml`. State lives at `~/.local/state/ugrant/` with `state.db` and wrapped key metadata.
- `ugrant init` on macOS prefers `platform-secure-store`, which now means the default login Keychain. The public backend name stays `platform-secure-store`.
- When that backend is active, `ugrant status` and `ugrant doctor` print `backend_provider: macOS Keychain`.
- The wrapped DEK is stored as a login-keychain generic-password item with service `dev.ugrant.platform-secure-store` and account `dek:<key_version>`.
- Existing passphrase or insecure installs are not silently migrated into Keychain. Move them explicitly with `ugrant rekey --backend platform-secure-store`.
- Secure Enclave mode is a separate macOS opt-in. Use `ugrant init --secure-enclave` or `ugrant rekey --secure-enclave`, and add `--require-user-presence` only when you want local approval on unwrap.
- In Secure Enclave mode, the public backend still stays `platform-secure-store`, while `ugrant status` and `ugrant doctor` should report `backend_provider: macOS Secure Enclave`. Plain login Keychain remains the default path when `--secure-enclave` is not set.
- Release builds now ship a single `ugrant` binary. The old `ugrant-se-helper` sidecar is no longer packaged or installed.
- The current macOS bridge path is inline from `ugrant` itself, with `sc_auth` handling CTK identity lifecycle. Secure Enclave mode is still explicit opt-in and still needs more real-device validation before broader rollout.
- `ugrant doctor` now distinguishes a cancelled user-presence prompt from other Secure Enclave failures, while still reporting missing keys, unsupported hardware, and access problems as separate cases.
- Live Keychain validation still needs a real Mac. After rekey, confirm `status` and `doctor` look right, then inspect the login keychain with Keychain Access or `security find-generic-password -s dev.ugrant.platform-secure-store ~/Library/Keychains/login.keychain-db`.

## Windows notes

- `install.ps1` installs the matching Windows build, including native ARM64 releases, to `%LOCALAPPDATA%\Programs\ugrant\bin` and updates your user PATH.
- PATH updates only affect new shells, so open a fresh PowerShell window before running `ugrant`. If you want to keep the current window, run `& "$env:LOCALAPPDATA\Programs\ugrant\bin\ugrant.exe" ...` directly.
- Config lives at `%APPDATA%\ugrant\config.toml`. State lives at `%LOCALAPPDATA%\ugrant\state\` with `state.db` and wrapped key material.
- Existing Windows installs under `%USERPROFILE%\.config\ugrant\` and `%USERPROFILE%\.local\state\ugrant\` are migrated forward automatically the first time a current build resolves its paths.
- `ugrant init` on Windows prefers the `platform-secure-store` backend, which uses the native Windows secure store.
- Command usage is otherwise the same: run `ugrant init`, `ugrant profile add ...`, `ugrant login --profile <name>`, then `ugrant exec --profile <name> -- <command>`.
- The OAuth consent step is still a human checkpoint. `ugrant login` may open a browser flow or print a URL, and some providers may ask you to paste a final redirect URL back into the terminal.
- Secret prompts are hidden in a normal Windows console, but OAuth consent is not bypassed or automated for you.

### PowerShell examples

Run a downstream command from PowerShell the same way you would elsewhere:

```powershell
ugrant exec --profile gmail -- python .\sync_mail.py
```

If you just ran the installer and have not opened a new shell yet:

```powershell
& "$env:LOCALAPPDATA\Programs\ugrant\bin\ugrant.exe" status
```

If you want to consume runtime env in PowerShell itself, prefer JSON output over POSIX-style exports:

```powershell
$envMap = ugrant env --profile gmail --format json | ConvertFrom-Json
$envMap.PSObject.Properties | ForEach-Object {
  Set-Item -Path "Env:$($_.Name)" -Value $_.Value
}
```

That keeps the command surface the same, while making PowerShell automation less annoying.

## Verify a release manually

### Preferred: minisign

Minisign is the preferred authenticity check for published archives.

Windows releases use `.zip` archives, for example `TARGET=windows-x86_64` or `TARGET=windows-arm64` with `ARCHIVE="ugrant-${TAG}-${TARGET}.zip"`.

```bash
TAG=v0.1.0
TARGET=linux-x86_64
ARCHIVE="ugrant-${TAG}-${TARGET}.tar.gz"

curl -fsSL "https://www.ugrant.sh/install?target=${TARGET}" -o "$ARCHIVE"
curl -fsSL "https://www.ugrant.sh/install?target=${TARGET}&kind=minisig" -o "${ARCHIVE}.minisig"
curl -fsSLo minisign.pub https://www.ugrant.sh/minisign.pub

minisign -Vm "$ARCHIVE" -p minisign.pub -x "${ARCHIVE}.minisig"
```

### Compatibility fallback: sha256

```bash
curl -fsSL "https://www.ugrant.sh/install?target=${TARGET}&kind=sha256" -o "${ARCHIVE}.sha256"
sha256sum -c "${ARCHIVE}.sha256"
```

## Maintainer notes for release signing

The release workflow expects:

- a checked-in `minisign.pub` file containing the public key for release verification
- a GitHub Actions secret named `MINISIGN_SECRET_KEY` containing the matching secret key
- for optional macOS signing and notarization, these GitHub Actions secrets:
  - `APPLE_CODESIGN_P12_BASE64`
  - `APPLE_CODESIGN_P12_PASSWORD`
  - `APPLE_CODESIGN_IDENTITY`
  - `APPLE_TEAM_ID`
  - `APPLE_ID`
  - `APPLE_APP_PASSWORD`

A pragmatic way to generate that pair for CI is:

```bash
minisign -G -W -p minisign.pub -s ugrant.minisign.key
```

That creates an unencrypted secret key, which is simpler for GitHub Actions automation. Store the contents of `ugrant.minisign.key` in the `MINISIGN_SECRET_KEY` repository secret, and commit `minisign.pub`.

For macOS signing/notarization, export a `Developer ID Application` certificate as a `.p12`, base64-encode it into `APPLE_CODESIGN_P12_BASE64`, and keep the other Apple secrets scoped to the release environment only.

## QA scripts

For live lifecycle checks against the built binary, use:

- `bash scripts/qa-live-smoke.sh`
- `pwsh -File .\scripts\qa-live-smoke.ps1`

Those smoke scripts cover isolated-home init, status, doctor, profile add, and rekey transitions without needing a real OAuth login. On macOS, they still use the test platform-store path rather than a live Keychain item.

For manual installer QA against the public install endpoints, use:

- `bash scripts/manual-installer-qa-unix.sh`
- `pwsh -File .\scripts\manual-installer-qa-windows.ps1`

Those installer scripts exercise fresh install, reinstall, repair-after-clobber, and basic post-install command checks in an isolated temp home/profile. On a real Mac, the Unix installer QA script also walks the explicit `rekey --backend platform-secure-store` path so you can verify `backend_provider: macOS Keychain` and the expected login-keychain item.

For Secure Enclave mode, keep the manual gate on a real Mac separate from the Linux-host smoke scripts:

1. Run `bash scripts/manual-installer-qa-unix.sh` on a real Mac, preferably Apple Silicon first.
2. From that fresh install, run `ugrant rekey --secure-enclave`, then confirm `ugrant status` / `ugrant doctor` report `backend: platform-secure-store` and `backend_provider: macOS Secure Enclave`.
3. If you intend to support local approval prompts, also run `ugrant rekey --secure-enclave --require-user-presence`, confirm `user_presence_required: yes`, and record both an approved access and a cancelled prompt. A cancelled prompt should now surface as its own explicit `doctor` failure.
4. Rekey back with `ugrant rekey --backend platform-secure-store` and confirm the install returns to plain `backend_provider: macOS Keychain`.

Release-readiness for any broader rollout should mean at least one recorded Apple Silicon pass for that Keychain -> Secure Enclave -> Keychain round-trip, plus docs that still describe Secure Enclave as explicit opt-in rather than the default macOS path.

For signed release validation on macOS, also confirm:

1. the packaged archive contains `bin/ugrant`
2. `codesign --verify --verbose=2` passes for `bin/ugrant`
3. `spctl --assess --type execute` passes for `bin/ugrant`
4. notarization succeeds for the published macOS `.zip`

## Project files

- `src/main.zig` — CLI implementation
- `SPEC.md` — user-visible behavior/spec
- `site/` — single-page homepage draft for `ugrant.sh`
- `minisign.pub` — checked-in release verification key

## Website draft

A simple single-page homepage draft lives in `site/`.

## License

MIT
