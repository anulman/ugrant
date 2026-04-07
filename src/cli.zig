const std = @import("std");

pub const version = "0.2.0";

pub const usage_text =
    \\ugrant — portable OAuth 2.0 token broker and exec wrapper
    \\
    \\Usage:
    \\  ugrant <command> [options]
    \\
    \\Commands:
    \\  init              Initialize config, encrypted key state, and database schema
    \\  profile add       Add or update a provider profile
    \\  profile list      List saved profiles (safe metadata only)
    \\  login             Run manual OAuth Authorization Code + PKCE login for a profile
    \\  env               Print child-safe runtime env for a profile
    \\  exec              Execute a command with injected child-safe env
    \\  revoke            Tombstone local grant state for a profile
    \\  rekey             Rotate the local DEK and re-encrypt stored secrets
    \\  status            Report initialization and profile/grant metadata
    \\  doctor            Validate config, schema, and key unwrap health
    \\  version           Print version
    \\
    \\Profile add helpers:
    \\  --service <preset>    Apply a built-in preset (google-imap, openai)
    \\  --discover <url>      Fetch OIDC discovery metadata from issuer or well-known URL
    \\
    \\Rekey backend switches:
    \\  --backend <name>            Rewrap to platform-secure-store, tpm2, or passphrase
    \\  --passphrase-env <NAME>    Rewrap to passphrase backend using env var contents
    \\  --passphrase-file <PATH>   Rewrap to passphrase backend using file contents
    \\  --allow-insecure-keyfile   Rewrap to insecure-keyfile backend (explicit opt-in)
    \\                            platform-secure-store resolves to the strongest local platform store
    \\                            on Linux: TPM2 first, otherwise Secret Service (secret-tool)
    \\
    \\Options:
    \\  --help, -h      Show this help
    \\  --version       Show version
    \\
    \\Recommended alias:
    \\  alias ug=ugrant
    \\
;

pub const profile_usage_text =
    "usage: ugrant profile <subcommand> [options]\n" ++
    "\n" ++
    "subcommands:\n" ++
    "  add     Add or update a provider profile\n" ++
    "  list    List saved profiles (safe metadata only)\n" ++
    "\n" ++
    "usage: ugrant profile add --name <name> [--service <preset> | --discover <issuer-or-url>] [--provider <provider>] [--auth-url <url>] [--token-url <url>] --client-id <id> [--scope <scope>] [--env-kind <kind>] [--redirect-uri <uri>] [--base-url <url>] [--model <model>] [--audience <aud>] [--client-secret <secret>]\n" ++
    "usage: ugrant profile list\n";

pub const login_usage_text =
    "usage: ugrant login --profile <name> [--redirect-url <url>] [--unsafe-bare-code [--code <code>]] [--no-open]\n";
pub const env_usage_text = "usage: ugrant env --profile <name> [--format shell|json]\n";
pub const exec_usage_text = "usage: ugrant exec --profile <name> -- <cmd> [args...]\n";
pub const revoke_usage_text = "usage: ugrant revoke --profile <name>\n";
pub const rekey_usage_text =
    "usage: ugrant rekey [--backend <platform-secure-store|tpm2|passphrase> | --passphrase-env <NAME> | --passphrase-file <PATH> | --allow-insecure-keyfile]\n";
pub const status_usage_text = "usage: ugrant status [--profile <name>]\n";
pub const doctor_usage_text = "usage: ugrant doctor\n";

test "usage strings include new profile list and subcommand help" {
    try std.testing.expect(std.mem.indexOf(u8, usage_text, "profile list") != null);
    try std.testing.expect(std.mem.indexOf(u8, profile_usage_text, "usage: ugrant profile list") != null);
    try std.testing.expect(std.mem.eql(u8, login_usage_text, "usage: ugrant login --profile <name> [--redirect-url <url>] [--unsafe-bare-code [--code <code>]] [--no-open]\n"));
    try std.testing.expect(std.mem.eql(u8, env_usage_text, "usage: ugrant env --profile <name> [--format shell|json]\n"));
    try std.testing.expect(std.mem.eql(u8, exec_usage_text, "usage: ugrant exec --profile <name> -- <cmd> [args...]\n"));
    try std.testing.expect(std.mem.eql(u8, revoke_usage_text, "usage: ugrant revoke --profile <name>\n"));
    try std.testing.expect(std.mem.eql(u8, rekey_usage_text, "usage: ugrant rekey [--backend <platform-secure-store|tpm2|passphrase> | --passphrase-env <NAME> | --passphrase-file <PATH> | --allow-insecure-keyfile]\n"));
    try std.testing.expect(std.mem.eql(u8, status_usage_text, "usage: ugrant status [--profile <name>]\n"));
    try std.testing.expect(std.mem.eql(u8, doctor_usage_text, "usage: ugrant doctor\n"));
}
