# AGENTS.md

If you're a coding agent working in this repo, start here.

## What this repo is

`ugrant` is a portable OAuth 2.0 token broker and exec wrapper for local tools, scripts, shell workflows, and local daemons that need OAuth without becoming their own credential manager.

There are two parallel surfaces here:

- the CLI itself, built from Zig in `src/`
- the website + installer redirector, served by the Cloudflare Worker in `worker.js` with static assets in `site/`

Release, website, and install UX are coupled. Do not change one blindly.

## First things to understand

- `src/main.zig` is the CLI implementation.
- `SPEC.md` is the user-visible behavior contract.
- `README.md` is the human technical entrypoint.
- `worker.js` serves `install.sh`, `minisign.pub`, and release-asset redirects.
- `site/` is the human-facing marketing/docs surface for `ugrant.sh`.
- `.github/workflows/release.yml` packages and publishes release assets.
- `minisign.pub` is the checked-in public key used for release verification.

## Build and test

Build:

```bash
zig build -Doptimize=ReleaseSafe
```

Primary tests:

```bash
zig build test
```

SQLite is vendored via `third_party/sqlite-amalgamation`, so builds and tests should not depend on a system `libsqlite3` package.

If you touch release, installer, worker, or docs, also sanity-check the affected files directly.

## Deploy surface

This repo deploys the public website and install endpoints via Cloudflare Workers.

Key files:

- `wrangler.toml`
- `worker.js`
- `site/index.html`
- `site/llms.txt`
- `site/llms-full.txt`

Important routes:

- `/install.sh`
- `/install?target=...`
- `/minisign.pub`
- `/llms.txt`
- `/llms-full.txt`

## Agent-facing product intent

When someone says “point your agent at ugrant”, the intended flow is:

1. understand what `ugrant` is quickly
2. install it safely
3. initialize local state
4. add the right profile
5. stop at the human OAuth consent boundary
6. resume and run the downstream command via `ugrant exec`

Do not document or imply fully autonomous OAuth consent. That should stay a human checkpoint.

## Editing guidance

- Keep the homepage human-readable. Do not turn the hero section into machine sludge.
- Put machine-oriented guidance into `site/llms.txt`, `site/llms-full.txt`, and this file.
- Keep README useful for humans first, but allow a short agent quickstart near the top.
- If you change install verification, keep the docs, worker, and release workflow aligned.
- If you change release artifact naming, update both the release workflow and the Worker redirect logic.

## Safe expectations

Good changes:

- tightening install authenticity
- improving agent handoff docs
- adding machine-readable diagnostics
- clarifying the consent boundary
- keeping site and repo docs aligned

Bad changes:

- documenting commands that do not exist
- weakening verification for convenience
- burying the human install path under agent-only instructions
- changing release asset names without updating `worker.js`

## Before you finish

Check:

- build/test commands still make sense
- README and site copy still read well to humans
- agent entrypoints still exist and are linked correctly
- release/install docs match actual shipped behavior
