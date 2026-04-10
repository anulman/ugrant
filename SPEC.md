# ugrant — Spec (Cucumber)

`ugrant` is a portable OAuth 2.0 token broker and exec wrapper.

Recommended alias:

```bash
alias ug=ugrant
```

This spec defines user-visible expectations for the CLI.
Implementation details may evolve, but behavior should remain stable.

## Scope

`ugrant` must support:

- Authorization Code + PKCE login
- durable refresh-token custody
- singleton refresh across many concurrent invocations
- encrypted secret fields with plaintext queryable metadata
- normalized env injection into wrapped programs
- portable local operation without requiring a daemon in the MVP

## Current implemented slice

Today the real implemented surface is:

- `ugrant init`
- `ugrant profile add`
- `ugrant profile list`
- `ugrant login`
- `ugrant env`
- `ugrant exec`
- `ugrant revoke`
- `ugrant rekey`
- `ugrant status`
- `ugrant doctor`
- built-in service presets via `ugrant profile add --service <preset>`
- OIDC discovery bootstrap via `ugrant profile add --discover <issuer-or-url>`
- top-level and subcommand help output
- version output

Recent addition:

- concurrent refresh leasing via SQLite-backed shared state
- localhost callback login for loopback redirect URIs, with manual paste fallback
- additional DEK wrapping backends: TPM2 local wrap and platform secure store

## Storage expectations

### Scenario: init creates the expected storage layout
Given `ugrant` is not yet initialized
When I run `ugrant init`
Then on Linux and macOS it creates `~/.config/ugrant/config.toml` if missing
And on Linux and macOS it creates `~/.local/state/ugrant/state.db`
And on Linux and macOS it creates `~/.local/state/ugrant/keys.json`
And on Windows it creates `%APPDATA%\ugrant\config.toml` if missing
And on Windows it creates `%LOCALAPPDATA%\ugrant\state\state.db`
And on Windows it creates `%LOCALAPPDATA%\ugrant\state\keys.json`
And it prints which DEK wrapping backend was selected
And it verifies that the DEK can be unwrapped

### Scenario: Windows storage migrates forward from the old XDG-style layout
Given a Windows machine has existing state under `%USERPROFILE%\.config\ugrant\` or `%USERPROFILE%\.local\state\ugrant\`
When a current `ugrant` build resolves its paths
Then it moves that config and state into `%APPDATA%\ugrant\` and `%LOCALAPPDATA%\ugrant\state\` when the new locations are still empty
And it does not overwrite an existing AppData-based install

### Scenario: runtime metadata stays queryable
Given `ugrant` has stored credentials for a profile
When I inspect the runtime state
Then `expires_at` is available without decrypting the whole row
And `profile_name`, `subject_key`, `provider`, and `base_url` remain queryable metadata
And secret-bearing fields are stored in encrypted-field columns

### Scenario: secret fields are encrypted
Given `ugrant` stores tokens locally
Then `refresh_token` is encrypted at rest
And `access_token` is encrypted at rest
And `id_token` is encrypted at rest when present
And `client_secret` is encrypted at rest when stored locally

## DEK management expectations

### Scenario: strongest available DEK wrapping backend is selected
Given `ugrant init` is running on a supported machine
When multiple wrapping backends are available
Then it chooses the strongest reasonable backend in this order:
  | order | backend |
  | 1 | TPM2 local wrap |
  | 2 | platform secure store |
  | 3 | passphrase wrap |
  | 4 | explicit insecure keyfile fallback |
And the public backend choices remain portable:
  | public choice |
  | platform-secure-store |
  | tpm2 |
  | passphrase |
  | insecure-keyfile |

### Scenario: platform-secure-store resolves to the strongest local platform backend
Given I select `platform-secure-store`
When `ugrant` resolves the requested backend
Then on Linux it prefers TPM2 when TPM2 is available
And otherwise on Linux it falls back to Secret Service via `secret-tool`
And on macOS it uses the user's Keychain via a generic-password item in the default login keychain by default
And macOS Secure Enclave is the preferred default for `ugrant init` when it is available
And plain `--backend platform-secure-store` still means login Keychain rather than Secure Enclave on macOS
And on other operating systems it uses that platform's secure store implementation
And the persisted backend may be the concrete backend that was actually used
And macOS Secure Enclave still persists the public backend `platform-secure-store` plus enclave-specific metadata

### Scenario: Secure Enclave is the default macOS init backend
Given I am on macOS
When I run `ugrant init`
Then `ugrant` prefers Secure Enclave when it is available
And it uses a Secure Enclave-backed non-exportable key instead of a plain Keychain generic-password wrap secret
And `backend` reports `macos-secure-enclave`
And `backend_provider` reports `macOS Secure Enclave`
And `user_presence_required` reports `yes`
And no silent fallback occurs if Secure Enclave setup fails

### Scenario: Secure Enclave can still be requested explicitly on macOS
Given I am on macOS
When I run `ugrant init --secure-enclave`
Then `ugrant` uses a Secure Enclave-backed non-exportable key instead of a plain Keychain generic-password wrap secret
And `backend` reports `macos-secure-enclave`
And `backend_provider` reports `macOS Secure Enclave`
And no silent fallback occurs if Secure Enclave setup fails

### Scenario: user presence is only valid with Secure Enclave
Given I am on macOS
When I run `ugrant init --secure-enclave --require-user-presence`
Or I run `ugrant rekey --secure-enclave --require-user-presence`
Then the Secure Enclave key requires local user presence for unwrap
And `status` and `doctor` report `user_presence_required: yes`
And `--require-user-presence` is rejected unless `--secure-enclave` is also present

### Scenario: explicit Secure Enclave requests fail on unsupported platforms
Given I am not on macOS
When I run `ugrant init --secure-enclave`
Or I run `ugrant rekey --secure-enclave`
Then `ugrant` exits with a clear unsupported-platform error
And it does not silently fall back to plain `platform-secure-store`, passphrase, or insecure-keyfile mode

### Scenario: passphrase wrapping remains the portable fallback backend
Given TPM2 and platform secure store are unavailable
When I run `ugrant init`
Then it falls back to passphrase wrapping
And it uses Argon2id-derived wrapping material
And it wraps the DEK with AES-256-GCM
And it marks insecure keyfile mode as degraded when explicitly selected

### Scenario: insecure fallback requires explicit consent
Given no strong wrapping backend is available
When I run `ugrant init`
Then it does not silently choose an insecure keyfile
And it presents explicit choices
And insecure keyfile mode requires an opt-in flag or explicit selection

### Scenario: rekey rotates encrypted state safely
Given `ugrant` already has stored credentials
When I run `ugrant rekey`
Then it generates a new DEK
And it re-encrypts all secret-bearing fields
And it re-wraps the new DEK using the currently configured wrapping backend
And it writes the updated wrapped DEK file atomically
And it increments the active key version
And it does not leave partially re-encrypted rows behind

### Scenario: rekey can switch wrapping backend modes
Given `ugrant` already has stored credentials
When I run `ugrant rekey --allow-insecure-keyfile`
Then it may switch from passphrase wrapping to explicit insecure keyfile mode
And it still generates a new DEK
And it still re-encrypts all secret-bearing fields
And it preserves plaintext metadata

### Scenario: rekey can switch from insecure keyfile to passphrase wrapping
Given `ugrant` already has stored credentials in insecure keyfile mode
When I run `ugrant rekey --passphrase-env UGRANT_NEW_PASSPHRASE`
Then it switches the wrapped DEK to passphrase mode
And it still generates a new DEK
And it still re-encrypts all secret-bearing fields
And insecure fallback still requires explicit opt-in

### Scenario: rekey can move into and out of stronger local backends
Given `ugrant` already has stored credentials
When I run `ugrant rekey --backend platform-secure-store`
Then it resolves that public choice the same way `ugrant init` does
And it may persist `tpm2` on Linux when TPM2 is the concrete backend used
And on macOS it selects plain Keychain mode unless `--secure-enclave` is also present
And `ugrant rekey --secure-enclave` moves macOS state into Secure Enclave mode
And `ugrant rekey --backend platform-secure-store` from Secure Enclave mode moves macOS state back to plain Keychain mode
And I can later rekey back to `platform-secure-store`, `tpm2`, `passphrase`, or explicit insecure keyfile mode
And each rekey still rotates the DEK and re-encrypts secret-bearing fields

## Login flow expectations

### Scenario: profile add can use a built-in Google IMAP preset
Given `ugrant` knows the `google-imap` service preset
When I run `ugrant profile add --name gmail --service google-imap --client-id <id> --client-secret <secret>`
Then `ugrant` fills in the provider auth URL
And it fills in the token URL
And it fills in the default IMAP scope
And it sets `env_kind` to `google-imap`
And it stores the resulting profile

### Scenario: profile add can use a built-in OpenAI preset
Given `ugrant` knows the `openai` service preset
When I run `ugrant profile add --name openai --service openai --client-id <id>`
Then `ugrant` fills in the provider auth URL
And it fills in the token URL
And it sets `env_kind` to `openai`
And it sets `OPENAI_BASE_URL` metadata to `https://api.openai.com/v1`

### Scenario: profile add can discover OIDC metadata from an issuer URL
Given a provider exposes `/.well-known/openid-configuration`
When I run `ugrant profile add --name acme --discover https://auth.example.com --client-id <id> --scope openid --env-kind generic`
Then `ugrant` fetches the provider discovery document
And it fills in the authorization endpoint
And it fills in the token endpoint
And explicit CLI flags still override discovered defaults

### Scenario: profile list prints saved profiles without secrets
Given `ugrant` has saved profiles
When I run `ugrant profile list`
Then it prints each profile name
And it includes safe metadata like provider and env kind
And it may include base URL and model when present
And it never prints `client_secret`

### Scenario: login supports manual auth code exchange
Given I have a profile configured for Authorization Code + PKCE
When I run `ugrant login --profile watcher`
Then `ugrant` prints an authorization URL
And it can accept a pasted redirect URL
And it validates the pasted OAuth `state` before exchanging the code
And on success it stores refreshable credentials for the subject

### Scenario: bare auth-code fallback is explicit and degraded
Given I have a profile configured for Authorization Code + PKCE
When I run `ugrant login --profile watcher --unsafe-bare-code`
Then `ugrant` may accept a pasted final code without the full redirect URL
And it treats that path as explicitly unsafe because it cannot validate OAuth `state`

### Scenario: login can use a localhost callback when available
Given the provider permits localhost redirect callbacks
When I run `ugrant login --profile watcher`
Then `ugrant` may open a temporary localhost callback listener
And if the callback succeeds it completes the login without manual paste
And if the callback does not arrive it still falls back to manual paste

### Scenario: login stores granted scope metadata
Given a provider returns a successful token response
When `ugrant` stores the grant
Then it records the granted scopes
And it records token type and subject metadata
And it records refresh token expiry metadata when available

## Exec and env expectations

### Scenario: exec injects provider-shaped env into a child
Given a profile resolves to a valid OpenAI-compatible token
When I run `ugrant exec --profile watcher -- bun daemon.ts`
Then the child receives `OPENAI_API_KEY`
And the child receives `OPENAI_BASE_URL` when configured
And the child receives `UGRANT_PROVIDER` and `LLM_MODEL` when configured
And the env vars added by `ugrant` do not include the refresh token
And the env vars added by `ugrant` do not include the DEK

### Scenario: env prints normalized shell exports
Given a profile resolves to a valid Anthropic token
When I run `ugrant env --profile watcher`
Then it prints shell-safe exports
And those exports include `ANTHROPIC_API_KEY`
And those exports exclude refresh-token material

### Scenario: subcommand help is explicit and consistent
When I run `ugrant profile --help`
Or I run `ugrant env --help`
Or I run `ugrant exec --help`
Or I run `ugrant revoke --help`
Or I run `ugrant rekey --help`
Or I run `ugrant status --help`
Or I run `ugrant doctor --help`
Then `ugrant` prints a usage line for that command
And it exits successfully without falling through to unknown-option errors
And `ugrant rekey --help` documents `--backend` for `platform-secure-store`, `tpm2`, and `passphrase`
And `ugrant init --help` and `ugrant rekey --help` document `--secure-enclave`
And `ugrant init --help` and `ugrant rekey --help` document `--require-user-presence`

### Scenario: json output supports automation
Given a profile resolves successfully
When I run `ugrant env --profile watcher --format json`
Then it prints valid JSON to stdout
And the JSON contains only the runtime env values emitted by `ugrant`

### Scenario: env and exec refresh a stale access token on use
Given a profile has a stored refresh token
And the cached access token is stale
When I run `ugrant env --profile watcher`
Or I run `ugrant exec --profile watcher -- <cmd>`
Then `ugrant` refreshes the access token before returning runtime env values
And it persists any rotated refresh token atomically
And the env vars added by `ugrant` still never include refresh-token material

## Singleton refresh expectations

### Scenario: one process refreshes while others wait
Given multiple concurrent processes run `ugrant exec --profile watcher`
And the cached access token is stale or missing
When refresh is required
Then exactly one process performs the refresh
And the other processes wait or poll shared SQLite state
And they reuse the refreshed token once committed
And `lease_timeout_seconds`, `poll_interval_ms`, and `max_wait_seconds` bound the wait behavior

### Scenario: valid token is reused idempotently
Given a cached access token is still valid
When multiple processes call `ugrant exec --profile watcher`
Then none of them triggers a refresh
And all of them reuse the same cached token family state

### Scenario: crash during refresh does not corrupt state
Given one process is refreshing a token
When that process crashes before completion
Then the refresh lease eventually expires
And a later process may reacquire refresh responsibility
And partially written token state is not observed as valid
And `ugrant status` may report `refresh_in_progress` while the lease is active

### Scenario: refresh-token rotation is atomic
Given a provider returns both a new access token and a new refresh token
When `ugrant` persists the refresh result
Then it writes both atomically in one transaction
And waiting callers never observe the new access token without the new refresh token being saved

### Scenario: failed refresh is persisted for waiters
Given one process holds the refresh lease
When the refresh exchange fails
Then `ugrant` persists `refresh_failed`
And it clears the active refresh lease
And waiting callers observe the failure and exit cleanly instead of spinning forever

## Doctor and status expectations

### Scenario: doctor validates installation without printing secrets
Given `ugrant` is initialized
When I run `ugrant doctor`
Then it verifies config paths
And it verifies secret-state permissions
And it verifies the active DEK can be unwrapped
And platform secure store backends fail clearly when the referenced local secret is missing or inaccessible
And it verifies schema and indexes
And it never prints secret values

### Scenario: doctor detects missing passphrase for passphrase-wrapped DEK
Given `ugrant` uses passphrase wrapping
When I run `ugrant doctor` without `UGRANT_PASSPHRASE`
Then the unwrap health check fails clearly
And no secret material is printed

### Scenario: status shows security metadata before login exists
Given `ugrant` is initialized but no profile has logged in yet
When I run `ugrant status`
Then it shows initialization state
And it shows the selected DEK wrapping backend
And it may name the concrete local provider, such as macOS Keychain or Secret Service
And it shows whether security mode is normal or degraded
And it shows that no grants currently exist
And it does not print the DEK or token material

### Scenario: status and doctor report Secure Enclave mode clearly
Given `ugrant` is initialized on macOS with `--secure-enclave --require-user-presence`
When I run `ugrant status`
Then it shows `backend: platform-secure-store`
And it shows `backend_provider: macOS Secure Enclave`
And it shows `secure_enclave: yes`
And it shows `user_presence_required: yes`
And it does not print the DEK or key material
When I run `ugrant doctor`
Then it verifies the referenced Secure Enclave key is reachable
And it verifies the active DEK can be unwrapped
And it reports a Secure Enclave-specific failure reason if the key is missing, inaccessible, or user presence is cancelled
And it reports when Secure Enclave is unavailable or unsupported instead of collapsing those failures into one generic bucket
And it never prints secret values

### Scenario: status shows expiry metadata
Given a profile has a cached access token
When I run `ugrant status --profile watcher`
Then it shows the provider
And it shows the subject
And it shows `expires_at`
And it shows whether the token is valid, stale, refreshing, failed, or revoked
And it does not print the token itself

### Scenario: status reports stale when cached expiry is in the past
Given a profile record says `access_token_valid`
And its cached `expires_at` is already in the past
When I run `ugrant status --profile watcher`
Then it reports `access_token_stale`
And it still does not print the token itself

### Scenario: revoke clears local grant state
Given a profile has stored credentials
When I run `ugrant revoke --profile watcher`
Then `ugrant` removes or tombstones the local credential state
And it clears the locally stored access token, refresh token, and ID token ciphertext
And `ugrant status --profile watcher` reports `revoked`
And future `ugrant exec` calls require re-login
And it reports that remote revocation was skipped for now

## State model

`ugrant` uses shared on-disk coordination, not shared in-memory runtime.
Every invocation is a separate process.
The canonical token family key is:

- `profile_name`
- `subject_key`

### Core runtime states

- `uninitialized`
- `authorized_no_access_token`
- `access_token_valid`
- `access_token_stale`
- `refresh_in_progress`
- `refresh_failed`
- `revoked`

### Scenario: stale tokens enter refresh state
Given credentials exist but the access token is stale
When a caller needs a child-safe access token
Then the token family enters `refresh_in_progress`
And one refresh lease owner is elected

### Scenario: valid tokens are directly usable
Given the token family is in `access_token_valid`
When a caller runs `ugrant exec`
Then it receives a usable child-safe access token immediately

### Scenario: revoked tokens require a fresh login
Given the token family is in `revoked`
When a caller runs `ugrant exec`
Then `ugrant` exits with a clear error
And it instructs the user to run `ugrant login`

### Scenario: rekey preserves plaintext metadata
Given `ugrant` stores credentials for a profile
When I run `ugrant rekey`
Then `provider`, `subject_key`, `scope`, and expiry metadata remain queryable
And the rotated ciphertext still decrypts to the same secret values

## Portability expectations

### Scenario: MVP does not require a local daemon
Given I am using `ugrant` on Linux, macOS, or Windows
When I use the MVP commands
Then `ugrant` works without requiring a long-running broker process
And singleton refresh is coordinated through shared runtime state

### Scenario: future transport does not replace the state machine
Given a future version adds HTTP, named pipes, or Unix sockets
Then those are optional transports only
And the SQLite-backed token family state remains the source of truth

## Exit behavior

### Scenario: missing credentials fail clearly
Given I run `ugrant exec --profile watcher`
And no valid credentials exist
Then `ugrant` exits non-zero
And it explains whether the problem is initialization, login, refresh, or revocation

### Scenario: forced degraded mode is explicit
Given `ugrant` is operating with an insecure keyfile backend
When it prints status or doctor output
Then it clearly marks the security mode as degraded
And it suggests re-initializing to a stronger backend
