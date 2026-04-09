# macOS Secure Enclave helper

`ugrant-se-helper` is a standalone Swift executable used for macOS Secure Enclave operations that need a stable, signable binary identity.

## Why this exists

The fallback `xcrun swift -` path is useful for local development, but it runs as an ephemeral unsigned helper. That is not a reliable foundation for persistent Secure Enclave + Keychain storage. The compiled helper is the release path.

## Build

```bash
bash scripts/build-macos-helper.sh
```

## Sign locally

```bash
export APPLE_CODESIGN_IDENTITY='Apple Development: Your Name (TEAMID)'
bash scripts/sign-macos-binaries.sh dist/macos-helper/ugrant-se-helper
```

## CI secrets

Release signing/notarization expects these secrets when enabled:

- `APPLE_CODESIGN_P12_BASE64`
- `APPLE_CODESIGN_P12_PASSWORD`
- `APPLE_CODESIGN_IDENTITY`
- `APPLE_TEAM_ID`
- `APPLE_ID`
- `APPLE_APP_PASSWORD`

If those are absent, CI still builds the helper but skips signing/notarization.
