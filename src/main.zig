const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const argx = @import("args.zig");
const cli = @import("cli.zig");
const command_params = @import("command_params.zig");
const env_output = @import("env_output.zig");
const env_runtime = @import("env_runtime.zig");
const pathing = @import("paths.zig");
const reporting = @import("reporting.zig");
const service = @import("service.zig");
const wrapped_backend = @import("wrapped_backend.zig");
const c = @cImport({
    @cInclude("sqlite3.h");
    if (builtin.os.tag != .windows) {
        @cInclude("poll.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    } else {
        @cDefine("WIN32_LEAN_AND_MEAN", "1");
        @cInclude("windows.h");
        @cInclude("wincrypt.h");
    }
});

const version = cli.version;
const usage_text = cli.usage_text;
const profile_usage_text = cli.profile_usage_text;
const login_usage_text = cli.login_usage_text;
const env_usage_text = cli.env_usage_text;
const exec_usage_text = cli.exec_usage_text;
const revoke_usage_text = cli.revoke_usage_text;
const rekey_usage_text = cli.rekey_usage_text;
const status_usage_text = cli.status_usage_text;
const doctor_usage_text = cli.doctor_usage_text;
const db_filename = pathing.db_filename;
const keys_filename = pathing.keys_filename;
const default_redirect_uri = service.default_redirect_uri;

const kdf_salt_len = 16;
const dek_len = 32;
const gcm_nonce_len = 12;
const gcm_tag_len = 16;
const argon2_params = crypto.pwhash.argon2.Params.owasp_2id;
const argon2_kdf_name = "argon2id-v19";
const hkdf_sha256_kdf_name = "hkdf-sha256";
const dpapi_entropy = "ugrant-dpapi-wrap-v1";
const secure_enclave_local_wrap_aad = "ugrant-secure-enclave-wrap-material";
const secure_enclave_local_wrap_blob_version = 1;
const macos_keychain_service = "dev.ugrant.platform-secure-store";
const macos_keychain_account_prefix = "dek:";
const macos_keychain_secret_ref_prefix = "macos-keychain:service=";
const macos_keychain_account_marker = ";account=";
const macos_secure_enclave_application_tag_prefix = "dev.ugrant.secure-enclave.dek:";
// Direct persistent SecKey storage from this CLI/helper context fails on macOS with errSecMissingEntitlement (-34018),
// while Apple-managed CTK identities created via `sc_auth` persist correctly. The shipping path is therefore single-binary
// `sc_auth` integration with CTK-backed refs, not a required sidecar helper.
const macos_secure_enclave_secret_ref_prefix = "macos-ctk-secure-enclave:label=";
const macos_security_tool = "/usr/bin/security";
const macos_sc_auth_tool = "/usr/sbin/sc_auth";
const macos_xcrun_tool = "/usr/bin/xcrun";
const schema_version = 3;

const WrappedDekRecord = struct {
    version: u32,
    backend: []const u8,
    key_version: u32,
    salt_b64: []const u8,
    nonce_b64: []const u8,
    ciphertext_b64: []const u8,
    created_at: []const u8,
    kdf: ?[]const u8 = null,
    kdf_t: ?u32 = null,
    kdf_m: ?u32 = null,
    kdf_p: ?u32 = null,
    secret_ref: ?[]const u8 = null,
    tpm2_pub_b64: ?[]const u8 = null,
    tpm2_priv_b64: ?[]const u8 = null,
    secure_enclave_ephemeral_pub_b64: ?[]const u8 = null,
    require_user_presence: ?bool = null,
};

const StatusSummary = reporting.StatusSummary;
const GrantStatusRecord = reporting.GrantStatusRecord;
const BackendMetadata = wrapped_backend.BackendMetadata;

const ProfileRecord = struct {
    name: []const u8,
    provider: []const u8,
    auth_url: []const u8,
    token_url: []const u8,
    client_id: []const u8,
    scope: []const u8,
    redirect_uri: []const u8,
    env_kind: []const u8,
    base_url: ?[]const u8,
    model: ?[]const u8,
    audience: ?[]const u8,
    client_secret: ?[]const u8,
};

const ProfileListRecord = struct {
    name: []const u8,
    provider: []const u8,
    env_kind: []const u8,
    base_url: ?[]const u8,
    model: ?[]const u8,
};

const GrantRecord = struct {
    profile_name: []const u8,
    provider: []const u8,
    subject_key: []const u8,
    token_type: ?[]const u8,
    scope: ?[]const u8,
    state: []const u8,
    expires_at: ?i64,
    refresh_token_expires_at: ?i64,
    access_token: ?[]const u8,
    refresh_token: ?[]const u8,
    id_token: ?[]const u8,
    granted_at: i64,
    updated_at: i64,
};

const StorageConfig = pathing.StorageConfig;

const RefreshLeaseStatus = struct {
    state: []const u8,
    expires_at: ?i64,
    has_refresh_token: bool,
    refresh_started_at: ?i64,
};

const EnvVar = env_runtime.EnvVar;

const ServiceDefinition = service.ServiceDefinition;
const Paths = pathing.Paths;

const MacOsKeychainRef = struct {
    service: []const u8,
    account: []const u8,
    key_version: u32,
};

const MacOsSecureEnclaveRef = struct {
    label: []const u8,
    public_key_hash: []const u8,
    key_version: u32,
};

const MacOsSecureEnclaveFailureReason = enum {
    user_cancelled,
    unavailable,
    key_missing,
    access_denied,
};

const MacOsSecureEnclaveFailure = struct {
    reason: MacOsSecureEnclaveFailureReason,
    message: ?[]u8 = null,
};

const MacOsSecureEnclaveHelperResult = union(enum) {
    success: WrapSecret,
    failure: MacOsSecureEnclaveFailure,
};

const WrapBackendOptions = wrapped_backend.WrapBackendOptions;

const backendProviderLabel = wrapped_backend.backendProviderLabel;
const backendMetadata = wrapped_backend.backendMetadata;
const writeBackendMetadataLines = wrapped_backend.writeBackendMetadataLines;
const runtimeGrantState = reporting.runtimeGrantState;
const freeGrantStatus = reporting.freeGrantStatus;
const freeStatusSummary = reporting.freeStatusSummary;
const freeEnvVars = env_runtime.freeEnvVars;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var out_buf: [32768]u8 = undefined;
    var err_buf: [16384]u8 = undefined;
    var out = std.fs.File.stdout().writer(&out_buf);
    var err = std.fs.File.stderr().writer(&err_buf);

    if (args.len <= 1) {
        try out.interface.writeAll(usage_text);
        try out.interface.flush();
        return;
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "help")) {
        try out.interface.writeAll(usage_text);
        try out.interface.flush();
        return;
    }
    if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version")) {
        try out.interface.print("ugrant {s}\n", .{version});
        try out.interface.flush();
        return;
    }

    if (std.mem.eql(u8, cmd, "init")) {
        try cmdInit(allocator, args[2..], &out.interface, &err.interface);
    } else if (std.mem.eql(u8, cmd, "profile")) {
        try cmdProfile(allocator, args[2..], &out.interface, &err.interface);
    } else if (std.mem.eql(u8, cmd, "login")) {
        try cmdLogin(allocator, args[2..], &out.interface, &err.interface);
    } else if (std.mem.eql(u8, cmd, "env")) {
        try cmdEnv(allocator, args[2..], &out.interface, &err.interface);
    } else if (std.mem.eql(u8, cmd, "exec")) {
        try cmdExec(allocator, args[2..], &out.interface, &err.interface);
    } else if (std.mem.eql(u8, cmd, "revoke")) {
        try cmdRevoke(allocator, args[2..], &out.interface, &err.interface);
    } else if (std.mem.eql(u8, cmd, "rekey")) {
        try cmdRekey(allocator, args[2..], &out.interface, &err.interface);
    } else if (std.mem.eql(u8, cmd, "status")) {
        try cmdStatus(allocator, args[2..], &out.interface, &err.interface);
    } else if (std.mem.eql(u8, cmd, "doctor")) {
        try cmdDoctor(allocator, args[2..], &out.interface, &err.interface);
    } else {
        try err.interface.print("ugrant: command '{s}' is not implemented yet.\n", .{cmd});
        try err.interface.flush();
        std.process.exit(2);
    }

    try out.interface.flush();
    try err.interface.flush();
}

fn cmdInit(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    const init_usage = "usage: ugrant init [--backend <name>] [--allow-insecure-keyfile] [--secure-enclave [--require-user-presence]]\n";
    var requested_backend: ?[]const u8 = null;
    var allow_insecure = false;
    var wrap_options = WrapBackendOptions{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--allow-insecure-keyfile") or std.mem.eql(u8, arg, "--insecure-keyfile")) allow_insecure = true else if (std.mem.eql(u8, arg, "--backend")) {
            requested_backend = try argx.nextValueOrUsage(args, &i, init_usage, err);
        } else if (std.mem.eql(u8, arg, "--secure-enclave")) {
            wrap_options.secure_enclave = true;
        } else if (std.mem.eql(u8, arg, "--require-user-presence")) {
            wrap_options.require_user_presence = true;
        } else if (argx.isHelpArg(arg)) {
            try out.writeAll(init_usage);
            return;
        } else {
            try err.writeAll(init_usage);
            std.process.exit(2);
        }
    }

    if (requested_backend) |backend| {
        if (std.mem.eql(u8, backend, "macos-secure-enclave")) {
            wrap_options.secure_enclave = true;
        }
    } else if (builtin.os.tag == .macos and !allow_insecure and secureEnclaveAvailable(allocator)) {
        wrap_options.secure_enclave = true;
    }
    if (wrap_options.require_user_presence and !wrap_options.secure_enclave) {
        try err.writeAll("ugrant init: --require-user-presence only works with --secure-enclave\n");
        std.process.exit(2);
    }
    if (wrap_options.secure_enclave) {
        wrap_options.require_user_presence = true;
        if (requested_backend) |backend| {
            if (!std.mem.eql(u8, backend, "macos-secure-enclave")) {
                try err.writeAll("ugrant init: --secure-enclave only works with --backend macos-secure-enclave\n");
                std.process.exit(2);
            }
        }
        if (!secureEnclaveAvailable(allocator)) {
            try err.writeAll("ugrant init: macOS Secure Enclave requested but unavailable on this system\n");
            std.process.exit(1);
        }
        requested_backend = "macos-secure-enclave";
    }

    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);

    try ensureParentDirs(paths);
    try ensureConfig(paths.config_path);

    var init_state = try initOrLoadKeys(allocator, paths.keys_path, requested_backend, allow_insecure, wrap_options);
    defer init_state.deinit(allocator);

    const should_normalize_secure_enclave = builtin.os.tag == .macos and wrap_options.secure_enclave and (init_state.dek == null) and (!std.mem.eql(u8, init_state.wrapped.backend, "macos-secure-enclave") or !(init_state.wrapped.require_user_presence orelse false));
    if (should_normalize_secure_enclave) {
        const current_wrapped = init_state.wrapped;
        const current_wrap_secret = wrapSecretForBackend(allocator, current_wrapped.backend, "Current ugrant passphrase: ", paths.keys_path, current_wrapped.key_version, current_wrapped) catch |wrap_err| switch (wrap_err) {
            error.MacOsSecureEnclaveUserCancelled => {
                try writeMacOsSecureEnclaveFailure(err, "init", .{ .reason = .user_cancelled });
                std.process.exit(1);
            },
            error.MacOsSecureEnclaveKeyMissing => {
                try writeMacOsSecureEnclaveFailure(err, "init", .{ .reason = .key_missing });
                std.process.exit(1);
            },
            error.MacOsSecureEnclaveAccessDenied => {
                try writeMacOsSecureEnclaveFailure(err, "init", .{ .reason = .access_denied });
                std.process.exit(1);
            },
            else => return wrap_err,
        };
        defer freeWrapSecret(allocator, current_wrap_secret);

        const detailed = try createMacOsSecureEnclaveSecretDetailed(allocator, current_wrapped.key_version + 1, true);
        const target_wrap = try unwrapOrWriteMacOsSecureEnclaveFailure(allocator, "init", err, detailed);
        defer freeWrapSecret(allocator, target_wrap);

        const db = try openDb(paths.db_path);
        defer _ = c.sqlite3_close(db);
        try ensureSchema(db);
        _ = try performRekey(allocator, db, paths.keys_path, current_wrapped, current_wrap_secret.secret, "macos-secure-enclave", target_wrap.secret, target_wrap.secret_ref, target_wrap.tpm2_pub_b64, target_wrap.tpm2_priv_b64, target_wrap.secure_enclave_ephemeral_pub_b64, true);
        freeWrappedDekRecord(allocator, init_state.wrapped);
        init_state.wrapped = try loadWrappedDek(allocator, paths.keys_path);
    }

    const wrapped = init_state.wrapped;

    const dek = if (init_state.dek) |created_dek|
        try allocator.dupe(u8, created_dek)
    else
        try unwrapDek(allocator, wrapped);
    defer allocator.free(dek);

    const db = try openDb(paths.db_path);
    defer _ = c.sqlite3_close(db);
    try ensureSchema(db);
    try tightenSecretStatePermissions(paths);

    const metadata = backendMetadata(wrapped.backend, wrapped.secret_ref, wrapped.require_user_presence);
    try out.print("initialized: yes\nbackend: {s}\n", .{wrapped.backend});
    try writeBackendMetadataLines(out, metadata, "");
    try out.print("keys: {s}\ndb: {s}\n", .{ paths.keys_path, paths.db_path });
}

fn cmdProfile(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    if (args.len == 0 or std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")) {
        try out.writeAll(profile_usage_text);
        return;
    }
    if (std.mem.eql(u8, args[0], "list")) {
        if (args.len > 1 and (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h"))) {
            try out.writeAll("usage: ugrant profile list\n");
            return;
        }
        if (args.len > 1) {
            try err.writeAll("usage: ugrant profile list\n");
            std.process.exit(2);
        }
        return cmdProfileList(allocator, out);
    }
    if (!std.mem.eql(u8, args[0], "add")) {
        try err.writeAll(profile_usage_text);
        std.process.exit(2);
    }

    var temp_arena = std.heap.ArenaAllocator.init(allocator);
    defer temp_arena.deinit();
    const ta = temp_arena.allocator();

    const opts = command_params.parseProfileAdd(args, out, err) catch |e| switch (e) {
        error.HelpDisplayed => return,
        else => return e,
    };

    var definition = ServiceDefinition{};
    if (opts.service_name) |svc| {
        definition = service.mergeServiceDefinition(definition, try service.resolveServicePreset(svc));
    }
    if (opts.discover_url) |url| {
        definition = service.mergeServiceDefinition(definition, try service.discoverService(ta, url));
    }

    const final_provider = opts.provider orelse definition.provider;
    const final_auth_url = opts.auth_url orelse definition.auth_url;
    const final_token_url = opts.token_url orelse definition.token_url;
    const final_scope = opts.scope orelse definition.scope;
    const final_redirect_uri = opts.redirect_uri orelse definition.redirect_uri orelse "urn:ietf:wg:oauth:2.0:oob";
    const final_env_kind = opts.env_kind orelse definition.env_kind;
    const final_base_url = opts.base_url orelse definition.base_url;
    const final_model = opts.model orelse definition.model;
    const final_audience = opts.audience orelse definition.audience;

    if (opts.name == null or final_provider == null or final_auth_url == null or final_token_url == null or opts.client_id == null or final_scope == null or final_env_kind == null) {
        try err.writeAll("ugrant profile add: missing required flags\n");
        std.process.exit(2);
    }

    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    try requireInitialized(paths);

    const wrapped = try loadWrappedDek(allocator, paths.keys_path);
    defer freeWrappedDekRecord(allocator, wrapped);
    const dek = try unwrapDek(allocator, wrapped);
    defer allocator.free(dek);

    const db = try openDb(paths.db_path);
    defer _ = c.sqlite3_close(db);
    try ensureSchema(db);

    const enc_secret = if (opts.client_secret) |secret| try encryptField(allocator, dek, "profiles", "client_secret", opts.name.?, "_", secret) else null;
    defer if (enc_secret) |v| allocator.free(v);

    const sql =
        "INSERT INTO profiles(name, provider, auth_url, token_url, client_id, scope, redirect_uri, env_kind, base_url, model, audience, client_secret_enc, created_at, updated_at) " ++
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12, unixepoch(), unixepoch()) " ++
        "ON CONFLICT(name) DO UPDATE SET provider=excluded.provider, auth_url=excluded.auth_url, token_url=excluded.token_url, client_id=excluded.client_id, scope=excluded.scope, redirect_uri=excluded.redirect_uri, env_kind=excluded.env_kind, base_url=excluded.base_url, model=excluded.model, audience=excluded.audience, client_secret_enc=excluded.client_secret_enc, updated_at=unixepoch()";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, opts.name.?);
    try bindText(stmt.?, 2, final_provider.?);
    try bindText(stmt.?, 3, final_auth_url.?);
    try bindText(stmt.?, 4, final_token_url.?);
    try bindText(stmt.?, 5, opts.client_id.?);
    try bindText(stmt.?, 6, final_scope.?);
    try bindText(stmt.?, 7, final_redirect_uri);
    try bindText(stmt.?, 8, final_env_kind.?);
    try bindNullableText(stmt.?, 9, final_base_url);
    try bindNullableText(stmt.?, 10, final_model);
    try bindNullableText(stmt.?, 11, final_audience);
    try bindNullableText(stmt.?, 12, enc_secret);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(db);

    try out.print("profile saved: {s}\n", .{opts.name.?});
}

fn cmdProfileList(allocator: std.mem.Allocator, out: *std.Io.Writer) !void {
    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    try requireInitialized(paths);

    const db = try openDb(paths.db_path);
    defer _ = c.sqlite3_close(db);
    try ensureSchema(db);

    const profiles = try loadProfileList(allocator, db);
    defer freeProfileList(allocator, profiles);

    if (profiles.len == 0) {
        try out.writeAll("no profiles saved\n");
        return;
    }

    for (profiles) |profile| {
        try out.print("- {s} | provider={s} | env_kind={s}", .{ profile.name, profile.provider, profile.env_kind });
        if (profile.base_url) |base_url| try out.print(" | base_url={s}", .{base_url});
        if (profile.model) |model| try out.print(" | model={s}", .{model});
        try out.writeAll("\n");
    }
}

fn cmdLogin(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    const opts = command_params.parseLogin(args, out, err) catch |e| switch (e) {
        error.HelpDisplayed => return,
        else => return e,
    };
    if (opts.profile_name == null) {
        try err.writeAll(login_usage_text);
        std.process.exit(2);
    }
    if (opts.code_override != null and !opts.allow_unsafe_bare_code) {
        try err.writeAll("ugrant login: bare auth codes skip OAuth state validation, rerun with --unsafe-bare-code if you must use --code\n");
        std.process.exit(2);
    }

    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    try requireInitialized(paths);
    const wrapped = try loadWrappedDek(allocator, paths.keys_path);
    defer freeWrappedDekRecord(allocator, wrapped);
    const dek = try unwrapDek(allocator, wrapped);
    defer allocator.free(dek);

    const db = try openDb(paths.db_path);
    defer _ = c.sqlite3_close(db);
    const profile = try loadProfile(allocator, db, opts.profile_name.?);
    defer freeProfile(allocator, profile);

    const verifier = try generateCodeVerifier(allocator);
    defer allocator.free(verifier);
    const challenge = try pkceChallenge(allocator, verifier);
    defer allocator.free(challenge);
    const oauth_state = try randomUrlSafe(allocator, 24);
    defer allocator.free(oauth_state);
    const auth_url = try buildAuthUrl(allocator, profile, challenge, oauth_state);
    defer allocator.free(auth_url);

    try out.print("Open this URL and authorize:\n{s}\n\n", .{auth_url});
    const open_result: OpenUrlResult = if (opts.no_open) .disabled else maybeOpenUrl(auth_url);
    switch (open_result) {
        .launched => try out.writeAll("Attempted to open the authorization URL in your browser.\n\n"),
        .unavailable => try out.writeAll("No browser opener was available, continuing with manual login.\n\n"),
        .disabled => {},
    }

    var final_code: ?[]u8 = if (opts.code_override) |v| try allocator.dupe(u8, v) else null;
    if (final_code == null) {
        if (opts.redirect_override) |redirect_url| {
            final_code = extractCodeFromRedirect(allocator, redirect_url, oauth_state) catch |e| switch (e) {
                error.InvalidOAuthState => {
                    try err.writeAll("ugrant login: pasted redirect URL had the wrong OAuth state, restart login and try again\n");
                    std.process.exit(1);
                },
                else => return e,
            };
        }
    }
    if (final_code == null and open_result == .launched and isLoopbackRedirect(profile.redirect_uri) and builtin.os.tag != .windows) {
        final_code = waitForLoopbackOrManualCode(allocator, profile.redirect_uri, oauth_state, opts.allow_unsafe_bare_code, out) catch |e| switch (e) {
            error.InvalidOAuthState => {
                try err.writeAll("ugrant login: pasted redirect URL had the wrong OAuth state, restart login and try again\n");
                std.process.exit(1);
            },
            error.UnsafeBareCodeRequiresFlag => {
                try err.writeAll("ugrant login: bare auth codes skip OAuth state validation, rerun with --unsafe-bare-code if you must use one\n");
                std.process.exit(2);
            },
            else => return e,
        };
        if (final_code != null) try out.writeAll("login input received\n");
    }
    if (final_code == null) {
        if (opts.allow_unsafe_bare_code) {
            try out.writeAll("Paste redirect URL or final code: ");
        } else {
            try out.writeAll("Paste full redirect URL (or rerun with --unsafe-bare-code to allow a bare auth code): ");
        }
        try out.flush();
        const pasted = try promptLine(allocator, "");
        defer freeSecret(allocator, pasted);
        final_code = resolveManualCodeInput(allocator, pasted, oauth_state, opts.allow_unsafe_bare_code) catch |e| switch (e) {
            error.InvalidOAuthState => {
                try err.writeAll("ugrant login: pasted redirect URL had the wrong OAuth state, restart login and try again\n");
                std.process.exit(1);
            },
            error.UnsafeBareCodeRequiresFlag => {
                try err.writeAll("ugrant login: bare auth codes skip OAuth state validation, rerun with --unsafe-bare-code if you must use one\n");
                std.process.exit(2);
            },
            else => return e,
        };
    } else if (opts.redirect_override != null) {
        // already allocated by extractCodeFromRedirect
    }
    defer if (final_code) |v| freeSecret(allocator, v);

    const token_resp = try exchangeToken(allocator, profile, final_code.?, verifier);
    defer freeTokenResponse(allocator, token_resp);

    const subject_key = if (token_resp.subject_key) |v| v else "default";
    const enc_access = try encryptField(allocator, dek, "grants", "access_token", profile.name, subject_key, token_resp.access_token);
    defer allocator.free(enc_access);
    const enc_refresh = if (token_resp.refresh_token) |v| try encryptField(allocator, dek, "grants", "refresh_token", profile.name, subject_key, v) else null;
    defer if (enc_refresh) |v| allocator.free(v);
    const enc_id = if (token_resp.id_token) |v| try encryptField(allocator, dek, "grants", "id_token", profile.name, subject_key, v) else null;
    defer if (enc_id) |v| allocator.free(v);

    const sql =
        "INSERT INTO grants(profile_name, provider, subject_key, token_type, scope, state, expires_at, refresh_token_expires_at, access_token_enc, refresh_token_enc, id_token_enc, granted_at, updated_at) " ++
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11, unixepoch(), unixepoch()) " ++
        "ON CONFLICT(profile_name) DO UPDATE SET provider=excluded.provider, subject_key=excluded.subject_key, token_type=excluded.token_type, scope=excluded.scope, state=excluded.state, expires_at=excluded.expires_at, refresh_token_expires_at=excluded.refresh_token_expires_at, access_token_enc=excluded.access_token_enc, refresh_token_enc=excluded.refresh_token_enc, id_token_enc=excluded.id_token_enc, granted_at=unixepoch(), updated_at=unixepoch()";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile.name);
    try bindText(stmt.?, 2, profile.provider);
    try bindText(stmt.?, 3, subject_key);
    try bindNullableText(stmt.?, 4, token_resp.token_type);
    try bindNullableText(stmt.?, 5, token_resp.scope);
    try bindText(stmt.?, 6, if (token_resp.expires_at != null) "access_token_valid" else "authorized_no_access_token");
    try bindNullableInt(stmt.?, 7, token_resp.expires_at);
    try bindNullableInt(stmt.?, 8, token_resp.refresh_token_expires_at);
    try bindText(stmt.?, 9, enc_access);
    try bindNullableText(stmt.?, 10, enc_refresh);
    try bindNullableText(stmt.?, 11, enc_id);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(db);

    try out.print("login complete for profile {s}\nsubject: {s}\n", .{ profile.name, subject_key });
}

fn cmdEnv(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    var profile_name: ?[]const u8 = null;
    var format: env_output.Format = .shell;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--profile")) {
            profile_name = try argx.nextValueOrUsage(args, &i, env_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--format")) {
            const raw = try argx.nextValueOrUsage(args, &i, env_usage_text, err);
            format = env_output.parseFormat(raw) catch {
                std.debug.print("ugrant env: unsupported format {s}\n{s}", .{ raw, env_usage_text });
                std.process.exit(2);
            };
        } else if (argx.isHelpArg(arg)) {
            try out.writeAll(env_usage_text);
            return;
        } else {
            try argx.writeUnknownOptionAndExit(err, arg);
        }
    }
    if (profile_name == null) {
        try err.writeAll(env_usage_text);
        std.process.exit(2);
    }

    const envs = try resolveEnvOrExit(allocator, profile_name.?, "env", err);
    defer freeEnvVars(allocator, envs);

    try env_output.write(out, allocator, envs, format);
}

fn cmdExec(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    var profile_name: ?[]const u8 = null;
    var cmd_index: ?usize = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--profile")) {
            profile_name = try argx.nextValueOrUsage(args, &i, exec_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--")) {
            cmd_index = i + 1;
            break;
        } else if (argx.isHelpArg(arg)) {
            try out.writeAll(exec_usage_text);
            return;
        } else {
            try argx.writeUnknownOptionAndExit(err, arg);
        }
    }
    if (profile_name == null or cmd_index == null or cmd_index.? >= args.len) {
        try err.writeAll(exec_usage_text);
        std.process.exit(2);
    }

    const envs = try resolveEnvOrExit(allocator, profile_name.?, "exec", err);
    defer freeEnvVars(allocator, envs);

    const cmd_args = args[cmd_index.?..];
    var proc = std.process.Child.init(cmd_args, allocator);
    proc.stdin_behavior = .Inherit;
    proc.stdout_behavior = .Inherit;
    proc.stderr_behavior = .Inherit;
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    for (envs) |ev| try env_map.put(ev.key, ev.value);
    proc.env_map = &env_map;
    try proc.spawn();
    const term = try proc.wait();
    switch (term) {
        .Exited => |code| std.process.exit(code),
        else => std.process.exit(1),
    }
}

fn cmdRevoke(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    var profile_name: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--profile")) {
            profile_name = try argx.nextValueOrUsage(args, &i, revoke_usage_text, err);
        } else if (argx.isHelpArg(arg)) {
            try out.writeAll(revoke_usage_text);
            return;
        } else {
            try argx.writeUnknownOptionAndExit(err, arg);
        }
    }
    if (profile_name == null) {
        try err.writeAll(revoke_usage_text);
        std.process.exit(2);
    }

    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    try requireInitialized(paths);

    const db = try openDb(paths.db_path);
    defer _ = c.sqlite3_close(db);
    if (!try revokeGrantState(db, profile_name.?)) {
        try err.print("ugrant revoke: no grant found for profile {s}\n", .{profile_name.?});
        std.process.exit(1);
    }

    try out.print(
        "profile: {s}\nlocal_state: revoked\nremote_revocation: skipped\nnext_step: run `ugrant login --profile {s}` to re-authorize\n",
        .{ profile_name.?, profile_name.? },
    );
}

fn cmdRekey(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    var passphrase_env: ?[]const u8 = null;
    var passphrase_file: ?[]const u8 = null;
    var backend_override: ?[]const u8 = null;
    var allow_insecure = false;
    var wrap_options = WrapBackendOptions{};

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--passphrase-env")) {
            passphrase_env = try argx.nextValueOrUsage(args, &i, rekey_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--passphrase-file")) {
            passphrase_file = try argx.nextValueOrUsage(args, &i, rekey_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--allow-insecure-keyfile")) {
            allow_insecure = true;
        } else if (std.mem.eql(u8, arg, "--backend")) {
            backend_override = try argx.nextValueOrUsage(args, &i, rekey_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--secure-enclave")) {
            wrap_options.secure_enclave = true;
        } else if (std.mem.eql(u8, arg, "--require-user-presence")) {
            wrap_options.require_user_presence = true;
        } else if (argx.isHelpArg(arg)) {
            try out.writeAll(rekey_usage_text);
            return;
        } else {
            try err.writeAll(rekey_usage_text);
            std.process.exit(2);
        }
    }

    if (allow_insecure and (passphrase_env != null or passphrase_file != null or backend_override != null)) {
        try err.writeAll("ugrant rekey: choose either passphrase wrap or --allow-insecure-keyfile, not both\n");
        std.process.exit(2);
    }
    if (backend_override) |backend| {
        if (std.mem.eql(u8, backend, "macos-secure-enclave")) {
            wrap_options.secure_enclave = true;
        }
    }
    if (wrap_options.require_user_presence and !wrap_options.secure_enclave) {
        try err.writeAll("ugrant rekey: --require-user-presence only works with --secure-enclave\n");
        std.process.exit(2);
    }
    if (wrap_options.secure_enclave) {
        if (allow_insecure or passphrase_env != null or passphrase_file != null) {
            try err.writeAll("ugrant rekey: --secure-enclave cannot be combined with passphrase or insecure rewrap options\n");
            std.process.exit(2);
        }
        if (backend_override) |backend| {
            if (!std.mem.eql(u8, backend, "macos-secure-enclave")) {
                try err.writeAll("ugrant rekey: --secure-enclave only works with --backend macos-secure-enclave\n");
                try out.flush();
                try err.flush();
                std.process.exit(2);
            }
        }
        if (!secureEnclaveAvailable(allocator)) {
            try err.writeAll("ugrant rekey: macOS Secure Enclave requested but unavailable on this system\n");
            try out.flush();
            try err.flush();
            std.process.exit(1);
        }
    }

    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    try requireInitialized(paths);

    const wrapped = try loadWrappedDek(allocator, paths.keys_path);
    defer freeWrappedDekRecord(allocator, wrapped);

    const current_wrap_secret = wrapSecretForBackend(allocator, wrapped.backend, "Current ugrant passphrase: ", paths.keys_path, wrapped.key_version, wrapped) catch |wrap_err| switch (wrap_err) {
        error.MacOsSecureEnclaveUserCancelled => {
            try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .user_cancelled });
            std.process.exit(1);
        },
        error.MacOsSecureEnclaveKeyMissing => {
            try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .key_missing });
            std.process.exit(1);
        },
        error.MacOsSecureEnclaveAccessDenied => {
            try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .access_denied });
            std.process.exit(1);
        },
        else => return wrap_err,
    };
    defer freeWrapSecret(allocator, current_wrap_secret);

    var target_backend: []const u8 = wrapped.backend;
    var target_wrap: WrapSecret = undefined;
    var target_wrap_options = if (isMacOsSecureEnclaveRecord(wrapped)) secureEnclaveOptionsFromRecord(wrapped) else WrapBackendOptions{};

    if (allow_insecure) {
        target_backend = "insecure-keyfile";
        target_wrap = .{ .secret = try allocator.dupe(u8, "insecure-local-keyfile") };
        target_wrap_options = .{};
    } else if (backend_override) |backend| {
        if (wrap_options.secure_enclave) {
            target_backend = "macos-secure-enclave";
            target_wrap_options = wrap_options;
        } else {
            target_backend = try resolveBackendChoice(backend, false, backendAvailable(allocator, "tpm2"), backendAvailable(allocator, "platform-secure-store"), backendAvailable(allocator, "macos-secure-enclave"));
            target_wrap_options = .{};
        }
        if (std.mem.eql(u8, target_backend, "passphrase")) {
            target_wrap = .{ .secret = try promptSecret(allocator, "New ugrant passphrase: ") };
        } else {
            target_wrap = wrapSecretForBackendWithOptions(allocator, target_backend, "", paths.keys_path, wrapped.key_version + 1, null, target_wrap_options) catch |wrap_err| switch (wrap_err) {
                error.MacOsSecureEnclaveUserCancelled => {
                    try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .user_cancelled });
                    std.process.exit(1);
                },
                error.MacOsSecureEnclaveKeyMissing => {
                    try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .key_missing });
                    std.process.exit(1);
                },
                error.MacOsSecureEnclaveAccessDenied => {
                    try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .access_denied });
                    std.process.exit(1);
                },
                else => return wrap_err,
            };
        }
    } else if (wrap_options.secure_enclave) {
        target_backend = "macos-secure-enclave";
        target_wrap_options = wrap_options;
        const detailed = try createMacOsSecureEnclaveSecretDetailed(allocator, wrapped.key_version + 1, wrap_options.require_user_presence);
        target_wrap = try unwrapOrWriteMacOsSecureEnclaveFailure(allocator, "rekey", err, detailed);
    } else if (passphrase_env) |env_name| {
        target_backend = "passphrase";
        target_wrap_options = .{};
        target_wrap = .{ .secret = try std.process.getEnvVarOwned(allocator, env_name) };
    } else if (passphrase_file) |file_path| {
        target_backend = "passphrase";
        target_wrap_options = .{};
        const raw = try std.fs.cwd().readFileAlloc(allocator, file_path, 4096);
        defer allocator.free(raw);
        target_wrap = .{ .secret = try allocator.dupe(u8, std.mem.trim(u8, raw, "\r\n\t ")) };
    } else if (std.mem.eql(u8, wrapped.backend, "passphrase")) {
        target_wrap_options = .{};
        target_wrap = .{ .secret = try promptSecret(allocator, "New ugrant passphrase: ") };
    } else {
        target_wrap = wrapSecretForBackendWithOptions(allocator, wrapped.backend, "", paths.keys_path, wrapped.key_version + 1, null, target_wrap_options) catch |wrap_err| switch (wrap_err) {
            error.MacOsSecureEnclaveUserCancelled => {
                try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .user_cancelled });
                std.process.exit(1);
            },
            error.MacOsSecureEnclaveKeyMissing => {
                try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .key_missing });
                std.process.exit(1);
            },
            error.MacOsSecureEnclaveAccessDenied => {
                try writeMacOsSecureEnclaveFailure(err, "rekey", .{ .reason = .access_denied });
                std.process.exit(1);
            },
            else => return wrap_err,
        };
    }
    defer freeWrapSecret(allocator, target_wrap);

    const db = try openDb(paths.db_path);
    defer _ = c.sqlite3_close(db);
    const stats = try performRekey(allocator, db, paths.keys_path, wrapped, current_wrap_secret.secret, target_backend, target_wrap.secret, target_wrap.secret_ref, target_wrap.tpm2_pub_b64, target_wrap.tpm2_priv_b64, target_wrap.secure_enclave_ephemeral_pub_b64, target_wrap.require_user_presence);
    try tightenSecretStatePermissions(paths);
    const target_metadata = backendMetadata(target_backend, target_wrap.secret_ref, target_wrap.require_user_presence);
    const previous_metadata = backendMetadata(wrapped.backend, wrapped.secret_ref, wrapped.require_user_presence);
    try out.print("rekey: ok\nbackend: {s}\n", .{target_backend});
    try writeBackendMetadataLines(out, target_metadata, "");
    try out.print("previous_backend: {s}\n", .{wrapped.backend});
    try writeBackendMetadataLines(out, previous_metadata, "previous_");
    try out.print(
        "key_version: {}\nprofiles_rewritten: {}\ngrants_rewritten: {}\n",
        .{ stats.key_version, stats.profiles_rewritten, stats.grants_rewritten },
    );
}

fn resolveEnvOrExit(allocator: std.mem.Allocator, profile_name: []const u8, command_name: []const u8, err: *std.Io.Writer) ![]EnvVar {
    return resolveEnv(allocator, profile_name) catch |e| switch (e) {
        error.NotInitialized => {
            try err.print("ugrant {s}: not initialized, run `ugrant init` first\n", .{command_name});
            std.process.exit(1);
        },
        error.ProfileNotFound, error.GrantNotFound, error.NoAccessToken => {
            try err.print("ugrant {s}: no usable credentials for profile {s}, run `ugrant login --profile {s}`\n", .{ command_name, profile_name, profile_name });
            std.process.exit(1);
        },
        error.GrantRevoked => {
            try err.print("ugrant {s}: profile {s} is revoked, run `ugrant login --profile {s}`\n", .{ command_name, profile_name, profile_name });
            std.process.exit(1);
        },
        error.AccessTokenStale => {
            try err.print("ugrant {s}: cached access token for profile {s} is stale and no refresh path is available, run `ugrant login --profile {s}`\n", .{ command_name, profile_name, profile_name });
            std.process.exit(1);
        },
        error.TokenExchangeFailed => {
            try err.print("ugrant {s}: refresh failed for profile {s}, run `ugrant login --profile {s}`\n", .{ command_name, profile_name, profile_name });
            std.process.exit(1);
        },
        error.RefreshWaitTimeout => {
            try err.print("ugrant {s}: timed out waiting for refresh lease for profile {s}\n", .{ command_name, profile_name });
            std.process.exit(1);
        },
        else => return e,
    };
}

fn cmdStatus(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    var profile_name: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--profile")) {
            profile_name = try argx.nextValueOrUsage(args, &i, status_usage_text, err);
        } else if (argx.isHelpArg(args[i])) {
            try out.writeAll(status_usage_text);
            return;
        } else {
            try argx.writeUnknownOptionAndExit(err, args[i]);
        }
    }

    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    const summary = try collectStatusSummary(allocator, paths);
    defer freeStatusSummary(allocator, summary);

    try out.print("initialized: {s}\nconfig: {s}\nstate_dir: {s}\ndb: {s}\nkeys: {s}\nbackend: {s}\n", .{ if (summary.initialized) "yes" else "no", summary.config_path, summary.state_dir, summary.db_path, summary.keys_path, summary.backend orelse "none" });
    if (summary.backend != null) {
        try writeBackendMetadataLines(out, .{
            .provider = summary.backend_provider,
            .secure_enclave = summary.secure_enclave,
            .user_presence_required = summary.user_presence_required,
        }, "");
    }
    try out.print("security_mode: {s}\nprofiles: {}\ngrants: {}\nstate: {s}\n", .{ summary.security_mode, summary.profile_count, summary.grant_count, summary.grant_state });

    if (summary.initialized and profile_name != null) {
        const db = try openDb(paths.db_path);
        defer _ = c.sqlite3_close(db);
        const maybe = try loadGrantStatus(allocator, db, profile_name.?);
        if (maybe) |rec| {
            defer freeGrantStatus(allocator, rec);
            const runtime_state = runtimeGrantState(rec.state, rec.expires_at);
            try out.print("\nprofile: {s}\nprovider: {s}\nsubject: {s}\nstatus: {s}\n", .{ profile_name.?, rec.provider, rec.subject_key, runtime_state });
            if (rec.expires_at) |ts| try out.print("expires_at: {}\n", .{ts});
            if (rec.scope) |scope| try out.print("scope: {s}\n", .{scope});
        } else {
            try out.print("\nprofile: {s}\nstatus: no grant\n", .{profile_name.?});
        }
    }
}

fn cmdDoctor(allocator: std.mem.Allocator, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !void {
    if (args.len > 0) {
        if (argx.isHelpArg(args[0])) {
            try out.writeAll(doctor_usage_text);
            return;
        }
        try err.writeAll(doctor_usage_text);
        std.process.exit(2);
    }
    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    try out.print("config: {s}\nstate_dir: {s}\ndb: {s}\nkeys: {s}\n", .{ paths.config_path, paths.state_dir, paths.db_path, paths.keys_path });
    if (!(try fileExists(paths.keys_path))) {
        try err.writeAll("doctor: keys.json missing\n");
        std.process.exit(1);
    }
    const wrapped = try loadWrappedDek(allocator, paths.keys_path);
    defer freeWrappedDekRecord(allocator, wrapped);
    const metadata = backendMetadata(wrapped.backend, wrapped.secret_ref, wrapped.require_user_presence);
    try out.print("backend: {s}\n", .{wrapped.backend});
    try writeBackendMetadataLines(out, metadata, "");
    if (std.mem.eql(u8, wrapped.backend, "macos-secure-enclave")) {
        const dek = try unwrapMacOsSecureEnclaveDekForDoctor(allocator, wrapped, out, err);
        defer allocator.free(dek);

        const db = try openDb(paths.db_path);
        defer _ = c.sqlite3_close(db);
        try ensureSchema(db);
        try tightenSecretStatePermissions(paths);
        try out.writeAll("dek_unwrap: ok\nschema: ok\npermissions: ok\n");
        return;
    }
    const dek = unwrapDek(allocator, wrapped) catch |e| switch (e) {
        error.InvalidWrappedDek => {
            if (std.mem.eql(u8, wrapped.backend, "platform-secure-store")) {
                if (builtin.os.tag == .macos) {
                    try err.writeAll("doctor: macOS Keychain secret reference is invalid\n");
                    std.process.exit(1);
                }
            }
            if (std.mem.eql(u8, wrapped.backend, "macos-secure-enclave")) {
                try err.writeAll("doctor: macOS Secure Enclave key reference is invalid\n");
                std.process.exit(1);
            }
            return e;
        },
        error.WrapBackendUnavailable => {
            if (std.mem.eql(u8, wrapped.backend, "platform-secure-store")) {
                if (builtin.os.tag == .macos) {
                    try err.writeAll("doctor: macOS Keychain item missing or inaccessible\n");
                    std.process.exit(1);
                }
            }
            if (std.mem.eql(u8, wrapped.backend, "macos-secure-enclave")) {
                try err.writeAll("doctor: macOS Secure Enclave key is missing\n");
                std.process.exit(1);
            }
            return e;
        },
        else => return e,
    };
    defer allocator.free(dek);
    const db = try openDb(paths.db_path);
    defer _ = c.sqlite3_close(db);
    try ensureSchema(db);
    try tightenSecretStatePermissions(paths);
    try out.writeAll("dek_unwrap: ok\nschema: ok\npermissions: ok\n");
}

const TokenResponse = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8,
    id_token: ?[]const u8,
    token_type: ?[]const u8,
    scope: ?[]const u8,
    expires_at: ?i64,
    refresh_token_expires_at: ?i64,
    subject_key: ?[]const u8,
};

fn resolvePaths(allocator: std.mem.Allocator) !Paths {
    return pathing.resolvePaths(allocator);
}

fn ensureParentDirs(paths: Paths) !void {
    return pathing.ensureParentDirs(paths);
}

fn ensureConfig(config_path: []const u8) !void {
    return pathing.ensureConfig(config_path);
}

fn tightenSecretStatePermissions(paths: Paths) !void {
    return pathing.tightenSecretStatePermissions(paths);
}

fn requireInitialized(paths: Paths) !void {
    return pathing.requireInitialized(paths);
}

fn fileExists(path: []const u8) !bool {
    return pathing.fileExists(path);
}

fn nowTs() i64 {
    return pathing.nowTs();
}

fn loadStorageConfig(allocator: std.mem.Allocator, config_path: []const u8) !StorageConfig {
    return pathing.loadStorageConfig(allocator, config_path);
}

fn envTruthy(name: []const u8) bool {
    return pathing.envTruthy(name);
}

fn commandExists(allocator: std.mem.Allocator, name: []const u8) bool {
    return pathing.commandExists(allocator, name);
}

fn getEnvOrDefaultOwned(allocator: std.mem.Allocator, name: []const u8, fallback: []const u8) ![]u8 {
    return std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => allocator.dupe(u8, fallback),
        else => err,
    };
}

fn getEnvVarOwnedOrNull(allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
    return std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => err,
    };
}

fn backendAvailable(allocator: std.mem.Allocator, backend: []const u8) bool {
    return pathing.backendAvailable(allocator, backend);
}

fn resolveBackendChoice(requested_backend: ?[]const u8, allow_insecure: bool, tpm2_available: bool, platform_store_available: bool, macos_secure_enclave_available: bool) ![]const u8 {
    return pathing.resolveBackendChoice(requested_backend, allow_insecure, tpm2_available, platform_store_available, macos_secure_enclave_available);
}

fn chooseInitBackend(allocator: std.mem.Allocator, requested_backend: ?[]const u8, allow_insecure: bool) ![]const u8 {
    return pathing.chooseInitBackend(allocator, requested_backend, allow_insecure);
}

const InitKeyState = struct {
    wrapped: WrappedDekRecord,
    dek: ?[]u8 = null,

    fn deinit(self: InitKeyState, allocator: std.mem.Allocator) void {
        freeWrappedDekRecord(allocator, self.wrapped);
        if (self.dek) |dek| freeSecret(allocator, dek);
    }
};

fn initOrLoadKeys(allocator: std.mem.Allocator, keys_path: []const u8, requested_backend: ?[]const u8, allow_insecure: bool, options: WrapBackendOptions) !InitKeyState {
    if (try fileExists(keys_path)) return .{ .wrapped = try loadWrappedDek(allocator, keys_path) };

    // First-time init on macOS Secure Enclave is expected to create the CTK identity
    // and wrap material if they do not already exist.
    const backend = if (options.secure_enclave) blk: {
        if (!secureEnclaveAvailable(allocator)) return error.WrapBackendUnavailable;
        break :blk "macos-secure-enclave";
    } else try chooseInitBackend(allocator, requested_backend, allow_insecure);
    const wrap_secret = try wrapSecretForBackendWithOptions(allocator, backend, "Create passphrase for ugrant: ", keys_path, 1, null, options);
    defer freeWrapSecret(allocator, wrap_secret);
    errdefer cleanupPersistedWrapSecret(allocator, backend, wrap_secret) catch {};

    var dek: [dek_len]u8 = undefined;
    crypto.random.bytes(&dek);
    const record = try wrapDekForBackend(allocator, backend, 1, wrap_secret.secret, &dek, wrap_secret);
    errdefer freeWrappedDekRecord(allocator, record);
    try saveWrappedDek(keys_path, record);
    return .{
        .wrapped = record,
        .dek = try allocator.dupe(u8, &dek),
    };
}

const WrapSecret = struct {
    secret: []u8,
    secret_ref: ?[]const u8 = null,
    tpm2_pub_b64: ?[]const u8 = null,
    tpm2_priv_b64: ?[]const u8 = null,
    secure_enclave_ephemeral_pub_b64: ?[]const u8 = null,
    require_user_presence: bool = false,
};

fn wrapDekForBackend(allocator: std.mem.Allocator, backend: []const u8, key_version: u32, passphrase: []const u8, dek: *const [dek_len]u8, wrap: WrapSecret) !WrappedDekRecord {
    var salt: [kdf_salt_len]u8 = undefined;
    var nonce: [gcm_nonce_len]u8 = undefined;
    crypto.random.bytes(&salt);
    crypto.random.bytes(&nonce);
    var key: [dek_len]u8 = undefined;
    const secure_enclave_mode = isMacOsSecureEnclaveSecretRefOpt(wrap.secret_ref);
    if (secure_enclave_mode) {
        if (wrap.secure_enclave_ephemeral_pub_b64 == null) return error.InvalidArgs;
        deriveWrapKeyHkdfSha256(&key, passphrase, &salt);
    } else {
        try deriveWrapKeyArgon2id(allocator, &key, passphrase, &salt, argon2_params);
    }
    var ct: [dek_len]u8 = undefined;
    var tag: [gcm_tag_len]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(&ct, &tag, dek, "ugrant-dek-wrap", nonce, key);
    var combined = try allocator.alloc(u8, dek_len + gcm_tag_len);
    @memcpy(combined[0..dek_len], &ct);
    @memcpy(combined[dek_len..], &tag);
    defer allocator.free(combined);
    return .{
        .version = schema_version,
        .backend = try allocator.dupe(u8, backend),
        .key_version = key_version,
        .salt_b64 = try b64EncodeAlloc(allocator, &salt),
        .nonce_b64 = try b64EncodeAlloc(allocator, &nonce),
        .ciphertext_b64 = try b64EncodeAlloc(allocator, combined),
        .created_at = try std.fmt.allocPrint(allocator, "{}", .{nowTs()}),
        .kdf = try allocator.dupe(u8, if (secure_enclave_mode) hkdf_sha256_kdf_name else argon2_kdf_name),
        .kdf_t = if (secure_enclave_mode) null else argon2_params.t,
        .kdf_m = if (secure_enclave_mode) null else argon2_params.m,
        .kdf_p = if (secure_enclave_mode) null else argon2_params.p,
        .secret_ref = if (wrap.secret_ref) |v| try allocator.dupe(u8, v) else null,
        .tpm2_pub_b64 = if (wrap.tpm2_pub_b64) |v| try allocator.dupe(u8, v) else null,
        .tpm2_priv_b64 = if (wrap.tpm2_priv_b64) |v| try allocator.dupe(u8, v) else null,
        .secure_enclave_ephemeral_pub_b64 = if (wrap.secure_enclave_ephemeral_pub_b64) |v| try allocator.dupe(u8, v) else null,
        .require_user_presence = if (secure_enclave_mode) wrap.require_user_presence else null,
    };
}

fn unwrapDek(allocator: std.mem.Allocator, record: WrappedDekRecord) ![]u8 {
    const passphrase = try wrapSecretForBackend(allocator, record.backend, "Unlock ugrant passphrase: ", null, record.key_version, record);
    defer freeWrapSecret(allocator, passphrase);

    return unwrapDekWithSecret(allocator, record, passphrase.secret);
}

const WrapSecretForBackendError = error{
    MacOsSecureEnclaveUserCancelled,
    MacOsSecureEnclaveKeyMissing,
    MacOsSecureEnclaveAccessDenied,
} || anyerror;

fn wrapSecretForBackend(allocator: std.mem.Allocator, backend: []const u8, prompt: []const u8, keys_path: ?[]const u8, key_version: ?u32, record: ?WrappedDekRecord) WrapSecretForBackendError!WrapSecret {
    return wrapSecretForBackendWithOptions(allocator, backend, prompt, keys_path, key_version, record, .{});
}

fn wrapSecretForBackendWithOptions(allocator: std.mem.Allocator, backend: []const u8, prompt: []const u8, keys_path: ?[]const u8, key_version: ?u32, record: ?WrappedDekRecord, options: WrapBackendOptions) WrapSecretForBackendError!WrapSecret {
    if (std.mem.eql(u8, backend, "insecure-keyfile")) return .{ .secret = try allocator.dupe(u8, "insecure-local-keyfile") };
    if (std.mem.eql(u8, backend, "passphrase")) return .{ .secret = try promptSecret(allocator, prompt) };
    if (std.mem.eql(u8, backend, "platform-secure-store")) return platformStoreWrapSecret(allocator, keys_path, key_version, record);
    if (std.mem.eql(u8, backend, "macos-secure-enclave")) return macOsSecureEnclaveWrapSecret(allocator, key_version, record, options);
    if (std.mem.eql(u8, backend, "tpm2")) return tpm2WrapSecret(allocator, record);
    return error.UnsupportedWrapBackend;
}

fn unwrapDekWithSecret(allocator: std.mem.Allocator, record: WrappedDekRecord, passphrase: []const u8) ![]u8 {
    const salt = try b64DecodeAlloc(allocator, record.salt_b64);
    defer freeSecret(allocator, salt);
    const nonce = try b64DecodeAlloc(allocator, record.nonce_b64);
    defer freeSecret(allocator, nonce);
    const ciphertext = try b64DecodeAlloc(allocator, record.ciphertext_b64);
    defer freeSecret(allocator, ciphertext);
    if (ciphertext.len != dek_len + gcm_tag_len) return error.InvalidWrappedDek;
    var key: [dek_len]u8 = undefined;
    try deriveWrapKeyForRecord(allocator, &key, passphrase, salt, record);
    var out: [dek_len]u8 = undefined;
    const tag: [gcm_tag_len]u8 = ciphertext[dek_len..][0..gcm_tag_len].*;
    crypto.aead.aes_gcm.Aes256Gcm.decrypt(&out, ciphertext[0..dek_len], tag, "ugrant-dek-wrap", nonce[0..gcm_nonce_len].*, key) catch return error.InvalidPassphrase;
    return allocator.dupe(u8, &out);
}

fn deriveLegacyWrapKey(out: *[dek_len]u8, passphrase: []const u8, salt: []const u8) void {
    var h = crypto.hash.sha2.Sha256.init(.{});
    h.update(passphrase);
    h.update(salt);
    h.final(out);
}

fn deriveWrapKeyArgon2id(allocator: std.mem.Allocator, out: *[dek_len]u8, passphrase: []const u8, salt: []const u8, params: crypto.pwhash.argon2.Params) !void {
    try crypto.pwhash.argon2.kdf(allocator, out, passphrase, salt, params, .argon2id);
}

fn deriveWrapKeyHkdfSha256(out: *[dek_len]u8, ikm: []const u8, salt: []const u8) void {
    const hkdf = crypto.kdf.hkdf.HkdfSha256;
    const prk = hkdf.extract(salt, ikm);
    hkdf.expand(out, "ugrant-dek-wrap", prk);
}

fn deriveWrapKeyForRecord(allocator: std.mem.Allocator, out: *[dek_len]u8, passphrase: []const u8, salt: []const u8, record: WrappedDekRecord) !void {
    if (record.kdf) |kdf_name| {
        if (std.mem.eql(u8, kdf_name, argon2_kdf_name)) {
            return deriveWrapKeyArgon2id(allocator, out, passphrase, salt, .{
                .t = record.kdf_t orelse argon2_params.t,
                .m = record.kdf_m orelse argon2_params.m,
                .p = @as(u24, @intCast(record.kdf_p orelse argon2_params.p)),
            });
        }
        if (std.mem.eql(u8, kdf_name, hkdf_sha256_kdf_name)) {
            if (!isMacOsSecureEnclaveRecord(record) or record.secure_enclave_ephemeral_pub_b64 == null) return error.InvalidWrappedDek;
            deriveWrapKeyHkdfSha256(out, passphrase, salt);
            return;
        }
        return error.UnsupportedWrapKdf;
    }
    deriveLegacyWrapKey(out, passphrase, salt);
}

fn saveWrappedDek(keys_path: []const u8, record: WrappedDekRecord) !void {
    var list = std.ArrayList(u8){};
    defer list.deinit(std.heap.page_allocator);
    try list.writer(std.heap.page_allocator).print("{{\"version\":{},\"backend\":\"{s}\",\"key_version\":{},\"salt_b64\":\"{s}\",\"nonce_b64\":\"{s}\",\"ciphertext_b64\":\"{s}\",\"created_at\":\"{s}\"", .{ record.version, record.backend, record.key_version, record.salt_b64, record.nonce_b64, record.ciphertext_b64, record.created_at });
    if (record.kdf) |v| {
        try list.writer(std.heap.page_allocator).print(",\"kdf\":\"{s}\"", .{v});
        if (record.kdf_t != null and record.kdf_m != null and record.kdf_p != null) {
            try list.writer(std.heap.page_allocator).print(",\"kdf_t\":{},\"kdf_m\":{},\"kdf_p\":{}", .{ record.kdf_t.?, record.kdf_m.?, record.kdf_p.? });
        }
    }
    if (record.secret_ref) |v| try list.writer(std.heap.page_allocator).print(",\"secret_ref\":\"{s}\"", .{v});
    if (record.tpm2_pub_b64) |v| try list.writer(std.heap.page_allocator).print(",\"tpm2_pub_b64\":\"{s}\"", .{v});
    if (record.tpm2_priv_b64) |v| try list.writer(std.heap.page_allocator).print(",\"tpm2_priv_b64\":\"{s}\"", .{v});
    if (record.secure_enclave_ephemeral_pub_b64) |v| try list.writer(std.heap.page_allocator).print(",\"secure_enclave_ephemeral_pub_b64\":\"{s}\"", .{v});
    if (record.require_user_presence) |v| try list.writer(std.heap.page_allocator).print(",\"require_user_presence\":{}", .{v});
    try list.append(std.heap.page_allocator, '}');
    const rendered = try list.toOwnedSlice(std.heap.page_allocator);
    defer std.heap.page_allocator.free(rendered);
    const tmp_path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.tmp", .{keys_path});
    defer std.heap.page_allocator.free(tmp_path);
    {
        var file = try std.fs.createFileAbsolute(tmp_path, .{ .truncate = true, .mode = pathing.secret_file_mode });
        defer file.close();
        try file.writeAll(rendered);
    }
    try std.fs.renameAbsolute(tmp_path, keys_path);
    if (builtin.os.tag != .windows) {
        var file = try std.fs.openFileAbsolute(keys_path, .{});
        defer file.close();
        try file.chmod(pathing.secret_file_mode);
    }
}

fn loadWrappedDek(allocator: std.mem.Allocator, keys_path: []const u8) !WrappedDekRecord {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, keys_path, 1024 * 1024);
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    return .{
        .version = @as(u32, @intCast(obj.get("version").?.integer)),
        .backend = try allocator.dupe(u8, obj.get("backend").?.string),
        .key_version = @as(u32, @intCast(obj.get("key_version").?.integer)),
        .salt_b64 = try allocator.dupe(u8, obj.get("salt_b64").?.string),
        .nonce_b64 = try allocator.dupe(u8, obj.get("nonce_b64").?.string),
        .ciphertext_b64 = try allocator.dupe(u8, obj.get("ciphertext_b64").?.string),
        .created_at = try allocator.dupe(u8, obj.get("created_at").?.string),
        .kdf = if (obj.get("kdf")) |v| try allocator.dupe(u8, v.string) else null,
        .kdf_t = if (obj.get("kdf_t")) |v| @as(u32, @intCast(v.integer)) else null,
        .kdf_m = if (obj.get("kdf_m")) |v| @as(u32, @intCast(v.integer)) else null,
        .kdf_p = if (obj.get("kdf_p")) |v| @as(u32, @intCast(v.integer)) else null,
        .secret_ref = if (obj.get("secret_ref")) |v| try allocator.dupe(u8, v.string) else null,
        .tpm2_pub_b64 = if (obj.get("tpm2_pub_b64")) |v| try allocator.dupe(u8, v.string) else null,
        .tpm2_priv_b64 = if (obj.get("tpm2_priv_b64")) |v| try allocator.dupe(u8, v.string) else null,
        .secure_enclave_ephemeral_pub_b64 = if (obj.get("secure_enclave_ephemeral_pub_b64")) |v| try allocator.dupe(u8, v.string) else null,
        .require_user_presence = if (obj.get("require_user_presence")) |v| v.bool else null,
    };
}

fn freeWrappedDekRecord(allocator: std.mem.Allocator, record: WrappedDekRecord) void {
    allocator.free(record.backend);
    allocator.free(record.salt_b64);
    allocator.free(record.nonce_b64);
    allocator.free(record.ciphertext_b64);
    allocator.free(record.created_at);
    if (record.kdf) |v| allocator.free(v);
    if (record.secret_ref) |v| allocator.free(v);
    if (record.tpm2_pub_b64) |v| allocator.free(v);
    if (record.tpm2_priv_b64) |v| allocator.free(v);
    if (record.secure_enclave_ephemeral_pub_b64) |v| allocator.free(v);
}

fn freeWrapSecret(allocator: std.mem.Allocator, wrap: WrapSecret) void {
    freeSecret(allocator, wrap.secret);
    if (wrap.secret_ref) |v| allocator.free(v);
    if (wrap.tpm2_pub_b64) |v| allocator.free(v);
    if (wrap.tpm2_priv_b64) |v| allocator.free(v);
    if (wrap.secure_enclave_ephemeral_pub_b64) |v| allocator.free(v);
}

fn dpapiDataBlob(bytes: []const u8) c.DATA_BLOB {
    return .{
        .cbData = @as(c.DWORD, @intCast(bytes.len)),
        .pbData = if (bytes.len == 0) null else @as([*c]u8, @ptrCast(@constCast(bytes.ptr))),
    };
}

fn protectDpapiBytes(allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
    if (builtin.os.tag != .windows) return error.WrapBackendUnavailable;

    var input = dpapiDataBlob(plaintext);
    var entropy = dpapiDataBlob(dpapi_entropy);
    var output: c.DATA_BLOB = std.mem.zeroes(c.DATA_BLOB);
    if (c.CryptProtectData(&input, null, &entropy, null, null, c.CRYPTPROTECT_UI_FORBIDDEN, &output) == 0) {
        return error.WrapBackendUnavailable;
    }
    defer _ = c.LocalFree(output.pbData);

    const protected_slice = @as([*]u8, @ptrCast(output.pbData))[0..output.cbData];
    return allocator.dupe(u8, protected_slice);
}

fn unprotectDpapiBytes(allocator: std.mem.Allocator, protected: []const u8) ![]u8 {
    if (builtin.os.tag != .windows) return error.WrapBackendUnavailable;

    var input = dpapiDataBlob(protected);
    var entropy = dpapiDataBlob(dpapi_entropy);
    var output: c.DATA_BLOB = std.mem.zeroes(c.DATA_BLOB);
    if (c.CryptUnprotectData(&input, null, &entropy, null, null, c.CRYPTPROTECT_UI_FORBIDDEN, &output) == 0) {
        return error.WrapBackendUnavailable;
    }
    defer _ = c.LocalFree(output.pbData);

    const plaintext_slice = @as([*]u8, @ptrCast(output.pbData))[0..output.cbData];
    return allocator.dupe(u8, plaintext_slice);
}

const macos_secure_enclave_helper_script =
    "import CryptoKit\n" ++
    "import Foundation\n" ++
    "import LocalAuthentication\n" ++
    "import Security\n" ++
    "let wrapMaterialService = \"dev.ugrant.secure-enclave.wrap-material\"\n" ++
    "let wrapMaterialVersion = 1\n" ++
    "let wrapMaterialInfo = Data(\"ugrant-secure-enclave-wrap-material\".utf8)\n" ++
    "func emitError(reason: String, message: String) {\n" ++
    "    let payload = [\"reason\": reason, \"message\": message]\n" ++
    "    if let data = try? JSONSerialization.data(withJSONObject: payload, options: []) {\n" ++
    "        FileHandle.standardError.write(data)\n" ++
    "        FileHandle.standardError.write(Data(\"\\n\".utf8))\n" ++
    "        return\n" ++
    "    }\n" ++
    "    FileHandle.standardError.write(Data((reason + \": \" + message + \"\\n\").utf8))\n" ++
    "}\n" ++
    "func reasonForStatus(_ status: OSStatus) -> String {\n" ++
    "    switch status {\n" ++
    "    case errSecUserCanceled:\n" ++
    "        return \"user_cancelled\"\n" ++
    "    case errSecItemNotFound:\n" ++
    "        return \"key_missing\"\n" ++
    "    case errSecAuthFailed, errSecInteractionNotAllowed, errSecInteractionRequired:\n" ++
    "        return \"access_denied\"\n" ++
    "    case errSecUnimplemented, errSecNotAvailable:\n" ++
    "        return \"unavailable\"\n" ++
    "    default:\n" ++
    "        return \"unavailable\"\n" ++
    "    }\n" ++
    "}\n" ++
    "func reasonForNSError(_ error: NSError) -> String {\n" ++
    "    if error.domain == LAError.errorDomain {\n" ++
    "        switch error.code {\n" ++
    "        case LAError.userCancel.rawValue:\n" ++
    "            return \"user_cancelled\"\n" ++
    "        case LAError.authenticationFailed.rawValue,\n" ++
    "             LAError.notInteractive.rawValue,\n" ++
    "             LAError.appCancel.rawValue,\n" ++
    "             LAError.systemCancel.rawValue:\n" ++
    "            return \"access_denied\"\n" ++
    "        case LAError.passcodeNotSet.rawValue,\n" ++
    "             LAError.biometryNotAvailable.rawValue,\n" ++
    "             LAError.biometryNotEnrolled.rawValue,\n" ++
    "             LAError.biometryLockout.rawValue:\n" ++
    "            return \"unavailable\"\n" ++
    "        default:\n" ++
    "            break\n" ++
    "        }\n" ++
    "    }\n" ++
    "    return reasonForStatus(OSStatus(error.code))\n" ++
    "}\n" ++
    "func fail(_ message: String, reason: String = \"unavailable\") -> Never {\n" ++
    "    emitError(reason: reason, message: message)\n" ++
    "    exit(1)\n" ++
    "}\n" ++
    "func secError(_ error: Unmanaged<CFError>?) -> (reason: String, message: String) {\n" ++
    "    guard let error else { return (\"unavailable\", \"unknown Security error\") }\n" ++
    "    let value = error.takeRetainedValue()\n" ++
    "    let nsError = value as Error as NSError\n" ++
    "    return (reasonForNSError(nsError), String(describing: value))\n" ++
    "}\n" ++
    "func appTag(_ keyVersion: Int) -> String {\n" ++
    "    \"dev.ugrant.secure-enclave.dek:\\(keyVersion)\"\n" ++
    "}\n" ++
    "func randomData(_ count: Int) -> Data {\n" ++
    "    var bytes = [UInt8](repeating: 0, count: count)\n" ++
    "    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)\n" ++
    "    guard status == errSecSuccess else { fail(\"SecRandomCopyBytes failed: \\(status)\", reason: reasonForStatus(status)) }\n" ++
    "    return Data(bytes)\n" ++
    "}\n" ++
    "func deleteKey(tag: String) {\n" ++
    "    let query: [String: Any] = [\n" ++
    "        kSecClass as String: kSecClassKey,\n" ++
    "        kSecAttrApplicationTag as String: Data(tag.utf8),\n" ++
    "        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "    ]\n" ++
    "    let status = SecItemDelete(query as CFDictionary)\n" ++
    "    if status != errSecSuccess && status != errSecItemNotFound {\n" ++
    "        fail(\"SecItemDelete failed: \\(status)\", reason: reasonForStatus(status))\n" ++
    "    }\n" ++
    "}\n" ++
    "func deleteWrapMaterial(tag: String) {\n" ++
    "    let query: [String: Any] = [\n" ++
    "        kSecClass as String: kSecClassGenericPassword,\n" ++
    "        kSecAttrService as String: wrapMaterialService,\n" ++
    "        kSecAttrAccount as String: tag,\n" ++
    "    ]\n" ++
    "    let status = SecItemDelete(query as CFDictionary)\n" ++
    "    if status != errSecSuccess && status != errSecItemNotFound {\n" ++
    "        fail(\"SecItemDelete wrap material failed: \\(status)\", reason: reasonForStatus(status))\n" ++
    "    }\n" ++
    "}\n" ++
    "func createEphemeralPrivateKey() -> SecKey {\n" ++
    "    var error: Unmanaged<CFError>?\n" ++
    "    let attrs: [String: Any] = [\n" ++
    "        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "        kSecAttrKeySizeInBits as String: 256,\n" ++
    "        kSecAttrIsPermanent as String: false,\n" ++
    "    ]\n" ++
    "    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {\n" ++
    "        let failure = secError(error)\n" ++
    "        fail(\"ephemeral key generation failed: \\(failure.message)\", reason: failure.reason)\n" ++
    "    }\n" ++
    "    return key\n" ++
    "}\n" ++
    "func createSecureEnclavePrivateKey(tag: String, requireUserPresence: Bool, permanent: Bool = true) -> SecKey {\n" ++
    "    var accessError: Unmanaged<CFError>?\n" ++
    "    let flags: SecAccessControlCreateFlags = requireUserPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]\n" ++
    "    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &accessError) else {\n" ++
    "        let failure = secError(accessError)\n" ++
    "        fail(\"SecAccessControlCreateWithFlags failed: \\(failure.message)\", reason: failure.reason)\n" ++
    "    }\n" ++
    "\n" ++
    "    var privateKeyAttrs: [String: Any] = [\n" ++
    "        kSecAttrIsPermanent as String: permanent,\n" ++
    "        kSecAttrAccessControl as String: access,\n" ++
    "    ]\n" ++
    "    if permanent {\n" ++
    "        privateKeyAttrs[kSecAttrLabel as String] = tag\n" ++
    "        privateKeyAttrs[kSecAttrApplicationTag as String] = Data(tag.utf8)\n" ++
    "    }\n" ++
    "    let attrs: [String: Any] = [\n" ++
    "        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "        kSecAttrKeySizeInBits as String: 256,\n" ++
    "        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,\n" ++
    "        kSecPrivateKeyAttrs as String: privateKeyAttrs,\n" ++
    "    ]\n" ++
    "\n" ++
    "    var error: Unmanaged<CFError>?\n" ++
    "    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {\n" ++
    "        let failure = secError(error)\n" ++
    "        let permanence = permanent ? \"persistent\" : \"temporary\"\n" ++
    "        fail(\"\\(permanence) secure enclave key generation failed: \\(failure.message)\", reason: failure.reason)\n" ++
    "    }\n" ++
    "    return key\n" ++
    "}\n" ++
    "func loadSecureEnclavePrivateKey(tag: String) -> SecKey {\n" ++
    "    let query: [String: Any] = [\n" ++
    "        kSecClass as String: kSecClassKey,\n" ++
    "        kSecAttrApplicationTag as String: Data(tag.utf8),\n" ++
    "        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "        kSecReturnRef as String: true,\n" ++
    "    ]\n" ++
    "    var item: CFTypeRef?\n" ++
    "    let status = SecItemCopyMatching(query as CFDictionary, &item)\n" ++
    "    guard status == errSecSuccess, let key = item as! SecKey? else {\n" ++
    "        fail(\"SecItemCopyMatching failed: \\(status)\", reason: reasonForStatus(status))\n" ++
    "    }\n" ++
    "    return key\n" ++
    "}\n" ++
    "\n" ++
    "func persistSecureEnclavePrivateKey(_ key: SecKey, tag: String) {\n" ++
    "    let query: [String: Any] = [\n" ++
    "        kSecClass as String: kSecClassKey,\n" ++
    "        kSecValueRef as String: key,\n" ++
    "        kSecAttrApplicationTag as String: Data(tag.utf8),\n" ++
    "        kSecAttrLabel as String: tag,\n" ++
    "        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,\n" ++
    "    ]\n" ++
    "    let status = SecItemAdd(query as CFDictionary, nil)\n" ++
    "    guard status == errSecSuccess else {\n" ++
    "        fail(\"SecItemAdd persisted secure enclave key failed: \\(status)\", reason: reasonForStatus(status))\n" ++
    "    }\n" ++
    "}\n" ++
    "func publicKeyData(_ key: SecKey) -> Data {\n" ++
    "    guard let pub = SecKeyCopyPublicKey(key) else { fail(\"missing public key\") }\n" ++
    "    var error: Unmanaged<CFError>?\n" ++
    "    guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {\n" ++
    "        let failure = secError(error)\n" ++
    "        fail(\"public key export failed: \\(failure.message)\", reason: failure.reason)\n" ++
    "    }\n" ++
    "    return data\n" ++
    "}\n" ++
    "func publicKeyHashHex(_ key: SecKey) -> String {\n" ++
    "    let digest = SHA256.hash(data: publicKeyData(key))\n" ++
    "    return digest.map { String(format: \"%02x\", $0) }.joined()\n" ++
    "}\n" ++
    "func findCtkPrivateKey(label: String, expectedPublicKeyHash: String? = nil) -> SecKey? {\n" ++
    "    let labelData = label.data(using: .utf8)!\n" ++
    "    let candidateQueries: [[String: Any]] = [\n" ++
    "        [\n" ++
    "            kSecClass as String: kSecClassIdentity,\n" ++
    "            kSecAttrLabel as String: label,\n" ++
    "            kSecReturnRef as String: true,\n" ++
    "            kSecMatchLimit as String: kSecMatchLimitAll,\n" ++
    "        ],\n" ++
    "        [\n" ++
    "            kSecClass as String: kSecClassKey,\n" ++
    "            kSecAttrApplicationTag as String: labelData,\n" ++
    "            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,\n" ++
    "            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "            kSecReturnRef as String: true,\n" ++
    "            kSecMatchLimit as String: kSecMatchLimitAll,\n" ++
    "        ],\n" ++
    "        [\n" ++
    "            kSecClass as String: kSecClassKey,\n" ++
    "            kSecAttrApplicationLabel as String: labelData,\n" ++
    "            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,\n" ++
    "            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "            kSecReturnRef as String: true,\n" ++
    "            kSecMatchLimit as String: kSecMatchLimitAll,\n" ++
    "        ],\n" ++
    "        [\n" ++
    "            kSecClass as String: kSecClassKey,\n" ++
    "            kSecAttrLabel as String: label,\n" ++
    "            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,\n" ++
    "            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "            kSecReturnRef as String: true,\n" ++
    "            kSecMatchLimit as String: kSecMatchLimitAll,\n" ++
    "        ],\n" ++
    "        [\n" ++
    "            kSecClass as String: kSecClassKey,\n" ++
    "            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,\n" ++
    "            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "            kSecReturnRef as String: true,\n" ++
    "            kSecMatchLimit as String: kSecMatchLimitAll,\n" ++
    "        ],\n" ++
    "    ]\n" ++
    "\n" ++
    "    for (queryIndex, query) in candidateQueries.enumerated() {\n" ++
    "        var item: CFTypeRef?\n" ++
    "        let status = SecItemCopyMatching(query as CFDictionary, &item)\n" ++
    "        debugLog(\"findCtkPrivateKey query#\\(queryIndex + 1) status=\\(status) label=\\(label) expectedHash=\\(expectedPublicKeyHash ?? \"<none>\")\")\n" ++
    "        if status == errSecItemNotFound { continue }\n" ++
    "        guard status == errSecSuccess else {\n" ++
    "            fail(\"SecItemCopyMatching CTK key failed: \\(status)\", reason: reasonForStatus(status))\n" ++
    "        }\n" ++
    "\n" ++
    "        var keys: [SecKey] = []\n" ++
    "        if let many = item as? [SecKey] {\n" ++
    "            keys = many\n" ++
    "        } else if let manyIdentities = item as? [SecIdentity] {\n" ++
    "            keys = manyIdentities.compactMap { identity in\n" ++
    "                var key: SecKey?\n" ++
    "                let copyStatus = SecIdentityCopyPrivateKey(identity, &key)\n" ++
    "                debugLog(\"findCtkPrivateKey SecIdentityCopyPrivateKey status=\\(copyStatus)\")\n" ++
    "                return copyStatus == errSecSuccess ? key : nil\n" ++
    "            }\n" ++
    "        } else if let rawItem = item {\n" ++
    "            let typeId = CFGetTypeID(rawItem)\n" ++
    "            if typeId == SecKeyGetTypeID() {\n" ++
    "                keys = [unsafeBitCast(rawItem, to: SecKey.self)]\n" ++
    "            } else if typeId == SecIdentityGetTypeID() {\n" ++
    "                let identity = unsafeBitCast(rawItem, to: SecIdentity.self)\n" ++
    "                var key: SecKey?\n" ++
    "                let copyStatus = SecIdentityCopyPrivateKey(identity, &key)\n" ++
    "                debugLog(\"findCtkPrivateKey SecIdentityCopyPrivateKey status=\\(copyStatus)\")\n" ++
    "                if copyStatus == errSecSuccess, let key { keys = [key] }\n" ++
    "            } else {\n" ++
    "                fail(\"CTK key lookup returned unexpected result typeId=\\(typeId)\", reason: \"unavailable\")\n" ++
    "            }\n" ++
    "        } else {\n" ++
    "            fail(\"CTK key lookup returned no result object despite success\", reason: \"unavailable\")\n" ++
    "        }\n" ++
    "\n" ++
    "        debugLog(\"findCtkPrivateKey query#\\(queryIndex + 1) candidateCount=\\(keys.count)\")\n" ++
    "        for key in keys {\n" ++
    "            guard let publicKey = SecKeyCopyPublicKey(key) else { continue }\n" ++
    "            let hash = publicKeyHashHex(publicKey)\n" ++
    "            debugLog(\"findCtkPrivateKey candidate hash=\\(hash)\")\n" ++
    "            if let expectedPublicKeyHash, hash.caseInsensitiveCompare(expectedPublicKeyHash) != ComparisonResult.orderedSame {\n" ++
    "                continue\n" ++
    "            }\n" ++
    "            debugLog(\"findCtkPrivateKey matched candidate hash=\\(hash) via query#\\(queryIndex + 1)\")\n" ++
    "            return key\n" ++
    "        }\n" ++
    "    }\n" ++
    "    return nil\n" ++
    "}\n" ++
    "func loadCtkPrivateKey(label: String, expectedPublicKeyHash: String? = nil, retries: Int = 20, retryDelaySeconds: Double = 0.1) -> SecKey {\n" ++
    "    for attempt in 0...max(0, retries) {\n" ++
    "        if let key = findCtkPrivateKey(label: label, expectedPublicKeyHash: expectedPublicKeyHash) {\n" ++
    "            debugLog(\"loadCtkPrivateKey success attempt=\\(attempt + 1) label=\\(label) expectedHash=\\(expectedPublicKeyHash ?? \"<none>\")\")\n" ++
    "            return key\n" ++
    "        }\n" ++
    "        if attempt < retries {\n" ++
    "            Thread.sleep(forTimeInterval: retryDelaySeconds)\n" ++
    "        }\n" ++
    "    }\n" ++
    "    let identities = parseCtkIdentities(runScAuth([\"list-ctk-identities\"]))\n" ++
    "    let matching = identities.filter { $0[\"label\"] == label }\n" ++
    "    let hashes = matching.compactMap { $0[\"public_key_hash\"] }.joined(separator: \",\")\n" ++
    "    fail(\"CTK key not found for label \\(label); expectedHash=\\(expectedPublicKeyHash ?? \"<none>\"); listedCount=\\(matching.count); listedHashes=[\\(hashes)]\", reason: \"key_missing\")\n" ++
    "}\n" ++
    "func loadWrapMaterial(tag: String) -> Data? {\n" ++
    "    let query: [String: Any] = [\n" ++
    "        kSecClass as String: kSecClassGenericPassword,\n" ++
    "        kSecAttrService as String: wrapMaterialService,\n" ++
    "        kSecAttrAccount as String: tag,\n" ++
    "        kSecReturnData as String: true,\n" ++
    "    ]\n" ++
    "    var item: CFTypeRef?\n" ++
    "    let status = SecItemCopyMatching(query as CFDictionary, &item)\n" ++
    "    if status == errSecItemNotFound { return nil }\n" ++
    "    guard status == errSecSuccess, let data = item as? Data else {\n" ++
    "        fail(\"SecItemCopyMatching wrap material failed: \\(status)\", reason: reasonForStatus(status))\n" ++
    "    }\n" ++
    "    return data\n" ++
    "}\n" ++
    "func storeWrapMaterial(tag: String, payload: [String: Any]) {\n" ++
    "    let data: Data\n" ++
    "    do {\n" ++
    "        data = try JSONSerialization.data(withJSONObject: payload, options: [])\n" ++
    "    } catch {\n" ++
    "        fail(\"wrap material serialization failed: \\(error)\")\n" ++
    "    }\n" ++
    "    deleteWrapMaterial(tag: tag)\n" ++
    "    let query: [String: Any] = [\n" ++
    "        kSecClass as String: kSecClassGenericPassword,\n" ++
    "        kSecAttrService as String: wrapMaterialService,\n" ++
    "        kSecAttrAccount as String: tag,\n" ++
    "        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,\n" ++
    "        kSecValueData as String: data,\n" ++
    "    ]\n" ++
    "    let status = SecItemAdd(query as CFDictionary, nil)\n" ++
    "    guard status == errSecSuccess else {\n" ++
    "        fail(\"SecItemAdd wrap material failed: \\(status)\", reason: reasonForStatus(status))\n" ++
    "    }\n" ++
    "}\n" ++
    "func publicKeyFromData(_ data: Data) -> SecKey {\n" ++
    "    var error: Unmanaged<CFError>?\n" ++
    "    let attrs: [String: Any] = [\n" ++
    "        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,\n" ++
    "        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,\n" ++
    "        kSecAttrKeySizeInBits as String: 256,\n" ++
    "    ]\n" ++
    "    guard let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error) else {\n" ++
    "        let failure = secError(error)\n" ++
    "        fail(\"public key import failed: \\(failure.message)\", reason: failure.reason)\n" ++
    "    }\n" ++
    "    return key\n" ++
    "}\n" ++
    "func keyExchangeContext() -> LAContext {\n" ++
    "    let context = LAContext()\n" ++
    "    context.interactionNotAllowed = false\n" ++
    "    return context\n" ++
    "}\n" ++
    "func sharedSecret(privateKey: SecKey, publicKey: SecKey) -> Data {\n" ++
    "    let algorithm = SecKeyAlgorithm.ecdhKeyExchangeStandard\n" ++
    "    guard SecKeyIsAlgorithmSupported(privateKey, .keyExchange, algorithm) else {\n" ++
    "        fail(\"ECDH key exchange is not supported for this key\", reason: \"unavailable\")\n" ++
    "    }\n" ++
    "    var error: Unmanaged<CFError>?\n" ++
    "    let context = keyExchangeContext()\n" ++
    "    let params = NSMutableDictionary()\n" ++
    "    params[kSecUseAuthenticationContext] = context\n" ++
    "    guard let data = SecKeyCopyKeyExchangeResult(privateKey, algorithm, publicKey, params, &error) as Data? else {\n" ++
    "        let failure = secError(error)\n" ++
    "        fail(\"key exchange failed: \\(failure.message)\", reason: failure.reason)\n" ++
    "    }\n" ++
    "    return data\n" ++
    "}\n" ++
    "func wrapKey(privateKey: SecKey, publicKey: SecKey) -> SymmetricKey {\n" ++
    "    let secret = sharedSecret(privateKey: privateKey, publicKey: publicKey)\n" ++
    "    var material = Data()\n" ++
    "    material.append(secret)\n" ++
    "    material.append(wrapMaterialInfo)\n" ++
    "    let digest = SHA256.hash(data: material)\n" ++
    "    return SymmetricKey(data: Data(digest))\n" ++
    "}\n" ++
    "func sealWrapMaterial(secret: Data, key: SymmetricKey) -> [String: Any] {\n" ++
    "    do {\n" ++
    "        let sealed = try AES.GCM.seal(secret, using: key)\n" ++
    "        let nonce = sealed.nonce.withUnsafeBytes { Data($0) }\n" ++
    "        let ciphertext = sealed.ciphertext + sealed.tag\n" ++
    "        return [\n" ++
    "            \"version\": wrapMaterialVersion,\n" ++
    "            \"nonce_b64\": nonce.base64EncodedString(),\n" ++
    "            \"ciphertext_b64\": ciphertext.base64EncodedString(),\n" ++
    "        ]\n" ++
    "    } catch {\n" ++
    "        fail(\"AES-GCM seal failed: \\(error)\")\n" ++
    "    }\n" ++
    "}\n" ++
    "func openWrapMaterial(payload: [String: Any], key: SymmetricKey) -> Data {\n" ++
    "    guard let version = payload[\"version\"] as? Int, version == wrapMaterialVersion else {\n" ++
    "        fail(\"unsupported wrap material version\")\n" ++
    "    }\n" ++
    "    guard let nonceB64 = payload[\"nonce_b64\"] as? String,\n" ++
    "          let ciphertextB64 = payload[\"ciphertext_b64\"] as? String,\n" ++
    "          let nonceData = Data(base64Encoded: nonceB64),\n" ++
    "          let combined = Data(base64Encoded: ciphertextB64),\n" ++
    "          combined.count >= 16 else {\n" ++
    "        fail(\"wrap material payload is invalid\")\n" ++
    "    }\n" ++
    "    do {\n" ++
    "        let box = try AES.GCM.SealedBox(\n" ++
    "            nonce: AES.GCM.Nonce(data: nonceData),\n" ++
    "            ciphertext: Data(combined.dropLast(16)),\n" ++
    "            tag: Data(combined.suffix(16))\n" ++
    "        )\n" ++
    "        return try AES.GCM.open(box, using: key)\n" ++
    "    } catch {\n" ++
    "        fail(\"AES-GCM open failed: \\(error)\")\n" ++
    "    }\n" ++
    "}\n" ++
    "let debugLoggingEnabled = ProcessInfo.processInfo.environment[\"DEBUG\"] == \"1\"\n" ++
    "func debugLog(_ message: String) {\n" ++
    "    guard debugLoggingEnabled else { return }\n" ++
    "    FileHandle.standardError.write(Data((\"[ugrant-se-helper] \" + message + \"\\n\").utf8))\n" ++
    "}\n" ++
    "func emit(_ payload: [String: Any]) {\n" ++
    "    do {\n" ++
    "        let data = try JSONSerialization.data(withJSONObject: payload, options: [])\n" ++
    "        FileHandle.standardOutput.write(data)\n" ++
    "    } catch {\n" ++
    "        fail(\"JSON serialization failed: \\(error)\")\n" ++
    "    }\n" ++
    "}\n" ++
    "func runScAuth(_ args: [String]) -> String {\n" ++
    "    let proc = Process()\n" ++
    "    proc.executableURL = URL(fileURLWithPath: \"/usr/sbin/sc_auth\")\n" ++
    "    proc.arguments = args\n" ++
    "    let out = Pipe()\n" ++
    "    let err = Pipe()\n" ++
    "    proc.standardOutput = out\n" ++
    "    proc.standardError = err\n" ++
    "    do {\n" ++
    "        try proc.run()\n" ++
    "    } catch {\n" ++
    "        fail(\"failed to launch sc_auth: \\(error)\")\n" ++
    "    }\n" ++
    "    proc.waitUntilExit()\n" ++
    "    let stdout = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? \"\"\n" ++
    "    let stderr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? \"\"\n" ++
    "    guard proc.terminationStatus == 0 else {\n" ++
    "        fail(\"sc_auth failed: \\(stderr.isEmpty ? stdout : stderr)\")\n" ++
    "    }\n" ++
    "    return stdout\n" ++
    "}\n" ++
    "func parseCtkIdentities(_ text: String) -> [[String: String]] {\n" ++
    "    let lines = text.split(whereSeparator: \\ .isNewline).map(String.init).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }\n" ++
    "    guard lines.count >= 2 else { return [] }\n" ++
    "    return lines.dropFirst().compactMap { line in\n" ++
    "        let parts = line.split(whereSeparator: \\ .isWhitespace).map(String.init)\n" ++
    "        guard parts.count >= 6 else { return nil }\n" ++
    "        return [\n" ++
    "            \"key_type\": parts[0],\n" ++
    "            \"public_key_hash\": parts[1],\n" ++
    "            \"protection\": parts[2],\n" ++
    "            \"label\": parts[3],\n" ++
    "            \"common_name\": parts[4],\n" ++
    "            \"valid\": parts.last ?? \"\",\n" ++
    "        ]\n" ++
    "    }\n" ++
    "}\n" ++
    "let args = CommandLine.arguments\n" ++
    "if args.count < 2 { fail(\"missing mode\") }\n" ++
    "switch args[1] {\n" ++
    "case \"create-ctk\":\n" ++
    "    if args.count != 4 { fail(\"usage: create-ctk <label> <require-user-presence>\") }\n" ++
    "    let label = args[2]\n" ++
    "    let requireUserPresence = args[3] == \"1\" || args[3].lowercased() == \"true\"\n" ++
    "    let protection = requireUserPresence ? \"bio\" : \"none\"\n" ++
    "    _ = runScAuth([\"create-ctk-identity\", \"-l\", label, \"-k\", \"p-256\", \"-t\", protection])\n" ++
    "    let identities = parseCtkIdentities(runScAuth([\"list-ctk-identities\"]))\n" ++
    "    guard let match = identities.first(where: { $0[\"label\"] == label }) else {\n" ++
    "        fail(\"created CTK identity not found after sc_auth create\")\n" ++
    "    }\n" ++
    "    emit([\n" ++
    "        \"secret_ref\": \"macos-ctk-secure-enclave:label=\\(label);hash=\\(match[\"public_key_hash\"] ?? \"\")\",\n" ++
    "        \"label\": label,\n" ++
    "        \"public_key_hash\": match[\"public_key_hash\"] ?? \"\",\n" ++
    "        \"require_user_presence\": requireUserPresence,\n" ++
    "    ])\n" ++
    "case \"create-ctk-wrap\":\n" ++
    "    if args.count != 4 { fail(\"usage: create-ctk-wrap <label> <require-user-presence>\") }\n" ++
    "    let label = args[2]\n" ++
    "    let requireUserPresence = args[3] == \"1\" || args[3].lowercased() == \"true\"\n" ++
    "    let protection = requireUserPresence ? \"bio\" : \"none\"\n" ++
    "    debugLog(\"create-ctk-wrap start label=\\(label) requireUserPresence=\\(requireUserPresence) protection=\\(protection)\")\n" ++
    "    _ = runScAuth([\"create-ctk-identity\", \"-l\", label, \"-k\", \"p-256\", \"-t\", protection, \"-N\", \"ugrant\", \"-O\", \"ugrant\", \"-U\", \"Secure Enclave\", \"-L\", \"Local\", \"-S\", \"Local\", \"-C\", \"US\"])\n" ++
    "    debugLog(\"create-ctk-wrap identity created, listing identities\")\n" ++
    "    let identities = parseCtkIdentities(runScAuth([\"list-ctk-identities\"]))\n" ++
    "    debugLog(\"create-ctk-wrap identities count=\\(identities.count)\")\n" ++
    "    guard let match = identities.first(where: { $0[\"label\"] == label }), let publicKeyHash = match[\"public_key_hash\"], !publicKeyHash.isEmpty else {\n" ++
    "        fail(\"created CTK identity not found after sc_auth create\")\n" ++
    "    }\n" ++
    "    debugLog(\"create-ctk-wrap matched label=\\(label) publicKeyHash=\\(publicKeyHash)\")\n" ++
    "    let enclaveKey = loadCtkPrivateKey(label: label)\n" ++
    "    debugLog(\"create-ctk-wrap CTK private key loaded (label-only bootstrap path)\")\n" ++
    "    let ephemeralPrivate = createEphemeralPrivateKey()\n" ++
    "    let ephemeralPubB64 = publicKeyData(ephemeralPrivate).base64EncodedString()\n" ++
    "    debugLog(\"create-ctk-wrap ephemeral key generated pubB64Length=\\(ephemeralPubB64.count)\")\n" ++
    "    let wrapSecret = randomData(32)\n" ++
    "    debugLog(\"create-ctk-wrap wrap secret generated length=\\(wrapSecret.count)\")\n" ++
    "    let key = wrapKey(privateKey: ephemeralPrivate, publicKey: SecKeyCopyPublicKey(enclaveKey)!)\n" ++
    "    debugLog(\"create-ctk-wrap derived wrap key\")\n" ++
    "    var payload = sealWrapMaterial(secret: wrapSecret, key: key)\n" ++
    "    payload[\"ephemeral_pub_b64\"] = ephemeralPubB64\n" ++
    "    debugLog(\"create-ctk-wrap storing wrap material\")\n" ++
    "    storeWrapMaterial(tag: label, payload: payload)\n" ++
    "    debugLog(\"create-ctk-wrap success\")\n" ++
    "    emit([\n" ++
    "        \"secret_b64\": wrapSecret.base64EncodedString(),\n" ++
    "        \"secret_ref\": \"macos-ctk-secure-enclave:label=\\(label);hash=\\(publicKeyHash)\",\n" ++
    "        \"ephemeral_pub_b64\": ephemeralPubB64,\n" ++
    "        \"require_user_presence\": requireUserPresence,\n" ++
    "    ])\n" ++
    "case \"list-ctk\":\n" ++
    "    emit([\"identities\": parseCtkIdentities(runScAuth([\"list-ctk-identities\"]))])\n" ++
    "case \"load-ctk\":\n" ++
    "    if args.count != 5 { fail(\"usage: load-ctk <label> <public-key-hash> <ephemeral-pub-b64>\") }\n" ++
    "    debugLog(\"load-ctk start label=\\(args[2]) publicKeyHash=\\(args[3]) ephemeralPubB64Length=\\(args[4].count)\")\n" ++
    "    let identities = parseCtkIdentities(runScAuth([\"list-ctk-identities\"]))\n" ++
    "    let matching = identities.filter { $0[\"label\"] == args[2] }\n" ++
    "    debugLog(\"load-ctk identitiesForLabel=\\(matching.count) hashes=\\(matching.compactMap { $0[\"public_key_hash\"] }.joined(separator: \",\"))\")\n" ++
    "    guard let ephemeralPub = Data(base64Encoded: args[4]) else { fail(\"invalid ephemeral public key base64\") }\n" ++
    "    debugLog(\"load-ctk decoded ephemeral public key bytes=\\(ephemeralPub.count)\")\n" ++
    "    let enclaveKey = loadCtkPrivateKey(label: args[2], expectedPublicKeyHash: args[3])\n" ++
    "    debugLog(\"load-ctk CTK private key loaded\")\n" ++
    "    guard let derivedPublicKey = SecKeyCopyPublicKey(enclaveKey) else { fail(\"load-ctk loaded key missing public key\") }\n" ++
    "    let derivedHash = publicKeyHashHex(derivedPublicKey)\n" ++
    "    debugLog(\"load-ctk loaded key public hash=\\(derivedHash)\")\n" ++
    "    let secret: Data\n" ++
    "    if let stored = loadWrapMaterial(tag: args[2]) {\n" ++
    "        debugLog(\"load-ctk found stored wrap material bytes=\\(stored.count)\")\n" ++
    "        let raw: Any\n" ++
    "        do {\n" ++
    "            raw = try JSONSerialization.jsonObject(with: stored, options: [])\n" ++
    "        } catch {\n" ++
    "            fail(\"wrap material JSON is invalid: \\(error)\")\n" ++
    "        }\n" ++
    "        guard let payload = raw as? [String: Any] else {\n" ++
    "            fail(\"wrap material JSON is invalid\")\n" ++
    "        }\n" ++
    "        if let storedEphemeral = payload[\"ephemeral_pub_b64\"] as? String, storedEphemeral != args[4] {\n" ++
    "            fail(\"stored wrap material does not match wrapped-key metadata\")\n" ++
    "        }\n" ++
    "        debugLog(\"load-ctk deriving wrap key from stored material\")\n" ++
    "        secret = openWrapMaterial(payload: payload, key: wrapKey(privateKey: enclaveKey, publicKey: publicKeyFromData(ephemeralPub)))\n" ++
    "        debugLog(\"load-ctk unwrapped stored material successfully\")\n" ++
    "    } else {\n" ++
    "        debugLog(\"load-ctk no stored wrap material, using raw shared secret path\")\n" ++
    "        secret = sharedSecret(privateKey: enclaveKey, publicKey: publicKeyFromData(ephemeralPub))\n" ++
    "        debugLog(\"load-ctk derived shared secret successfully\")\n" ++
    "    }\n" ++
    "    emit([\n" ++
    "        \"secret_b64\": secret.base64EncodedString(),\n" ++
    "        \"secret_ref\": \"macos-ctk-secure-enclave:label=\\(args[2]);hash=\\(args[3])\",\n" ++
    "    ])\n" ++
    "case \"delete-ctk-wrap\":\n" ++
    "    if args.count != 3 { fail(\"usage: delete-ctk-wrap <label>\") }\n" ++
    "    deleteWrapMaterial(tag: args[2])\n" ++
    "default:\n" ++
    "    fail(\"unknown mode: \\(args[1])\")\n" ++
    "}";

fn secureEnclaveAvailable(allocator: std.mem.Allocator) bool {
    if (envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE")) return true;
    if (builtin.os.tag != .macos) return false;
    return (fileExists(macos_sc_auth_tool) catch false) and commandExists(allocator, "xcrun");
}

fn formatMacOsSecureEnclaveApplicationTag(allocator: std.mem.Allocator, key_version: u32) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{}", .{ macos_secure_enclave_application_tag_prefix, key_version });
}

fn formatMacOsSecureEnclaveSecretRefForParts(allocator: std.mem.Allocator, label: []const u8, public_key_hash: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{s};hash={s}", .{ macos_secure_enclave_secret_ref_prefix, label, public_key_hash });
}

fn parseMacOsSecureEnclaveSecretRef(secret_ref: []const u8) !MacOsSecureEnclaveRef {
    if (!std.mem.startsWith(u8, secret_ref, macos_secure_enclave_secret_ref_prefix)) return error.InvalidWrappedDek;
    const rest = secret_ref[macos_secure_enclave_secret_ref_prefix.len..];
    const hash_marker = ";hash=";
    const hash_index = std.mem.indexOf(u8, rest, hash_marker) orelse return error.InvalidWrappedDek;
    const label = rest[0..hash_index];
    const public_key_hash = rest[hash_index + hash_marker.len ..];
    if (label.len == 0 or public_key_hash.len == 0) return error.InvalidWrappedDek;
    if (!std.mem.startsWith(u8, label, macos_secure_enclave_application_tag_prefix)) return error.InvalidWrappedDek;
    const key_version_text = label[macos_secure_enclave_application_tag_prefix.len..];
    if (key_version_text.len == 0) return error.InvalidWrappedDek;
    const key_version = std.fmt.parseUnsigned(u32, key_version_text, 10) catch return error.InvalidWrappedDek;
    return .{ .label = label, .public_key_hash = public_key_hash, .key_version = key_version };
}

fn isMacOsSecureEnclaveSecretRef(secret_ref: []const u8) bool {
    _ = parseMacOsSecureEnclaveSecretRef(secret_ref) catch return false;
    return true;
}

fn isMacOsSecureEnclaveSecretRefOpt(secret_ref: ?[]const u8) bool {
    if (secret_ref) |ref| return isMacOsSecureEnclaveSecretRef(ref);
    return false;
}

fn isMacOsSecureEnclaveRecord(record: WrappedDekRecord) bool {
    return isMacOsSecureEnclaveSecretRefOpt(record.secret_ref);
}

fn secureEnclaveOptionsFromRecord(record: WrappedDekRecord) WrapBackendOptions {
    return .{
        .secure_enclave = isMacOsSecureEnclaveRecord(record),
        .require_user_presence = record.require_user_presence orelse false,
    };
}

const SecureEnclaveLocalWrapBlob = struct {
    version: u32,
    ephemeral_pub_b64: []const u8,
    nonce_b64: []const u8,
    ciphertext_b64: []const u8,
};

fn freeSecureEnclaveLocalWrapBlob(allocator: std.mem.Allocator, blob: SecureEnclaveLocalWrapBlob) void {
    allocator.free(blob.ephemeral_pub_b64);
    allocator.free(blob.nonce_b64);
    allocator.free(blob.ciphertext_b64);
}

fn secureEnclaveTestStoreDir(allocator: std.mem.Allocator) ![]const u8 {
    return getEnvOrDefaultOwned(allocator, "UGRANT_TEST_SECURE_ENCLAVE_STORE_DIR", "/tmp/ugrant-secure-enclave-store");
}

fn secureEnclaveTestBlobPathForTag(allocator: std.mem.Allocator, tag: []const u8) ![]const u8 {
    const dir = try secureEnclaveTestStoreDir(allocator);
    defer allocator.free(dir);

    var digest: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(tag, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ dir, hex });
}

fn ensureSecureEnclaveTestStoreDir(allocator: std.mem.Allocator) !void {
    const dir = try secureEnclaveTestStoreDir(allocator);
    defer allocator.free(dir);
    if (!std.fs.path.isAbsolute(dir)) return error.InvalidArgs;
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

fn deriveSyntheticSecureEnclaveWrapKey(allocator: std.mem.Allocator, out: *[dek_len]u8, tag: []const u8, ephemeral_pub_b64: []const u8) !void {
    const root = try getEnvOrDefaultOwned(allocator, "UGRANT_TEST_SECURE_ENCLAVE_KEY_MATERIAL", "ugrant-test-secure-enclave-root");
    defer allocator.free(root);

    var h = crypto.hash.sha2.Sha256.init(.{});
    h.update(root);
    h.update("\n");
    h.update(tag);
    h.update("\n");
    h.update(ephemeral_pub_b64);
    h.final(out);
}

fn saveSecureEnclaveTestBlob(allocator: std.mem.Allocator, tag: []const u8, blob: SecureEnclaveLocalWrapBlob) !void {
    try ensureSecureEnclaveTestStoreDir(allocator);

    var list = std.ArrayList(u8){};
    defer list.deinit(std.heap.page_allocator);
    try list.writer(std.heap.page_allocator).print(
        "{{\"version\":{},\"ephemeral_pub_b64\":\"{s}\",\"nonce_b64\":\"{s}\",\"ciphertext_b64\":\"{s}\"}}",
        .{ blob.version, blob.ephemeral_pub_b64, blob.nonce_b64, blob.ciphertext_b64 },
    );
    const rendered = try list.toOwnedSlice(std.heap.page_allocator);
    defer std.heap.page_allocator.free(rendered);

    const path = try secureEnclaveTestBlobPathForTag(allocator, tag);
    defer allocator.free(path);
    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true, .mode = pathing.secret_file_mode });
    defer file.close();
    try file.writeAll(rendered);
}

fn loadSecureEnclaveTestBlob(allocator: std.mem.Allocator, tag: []const u8) !SecureEnclaveLocalWrapBlob {
    const path = try secureEnclaveTestBlobPathForTag(allocator, tag);
    defer allocator.free(path);

    const bytes = std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024) catch |err| switch (err) {
        error.FileNotFound => return error.WrapBackendUnavailable,
        else => return err,
    };
    defer allocator.free(bytes);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    return .{
        .version = @as(u32, @intCast(obj.get("version").?.integer)),
        .ephemeral_pub_b64 = try allocator.dupe(u8, obj.get("ephemeral_pub_b64").?.string),
        .nonce_b64 = try allocator.dupe(u8, obj.get("nonce_b64").?.string),
        .ciphertext_b64 = try allocator.dupe(u8, obj.get("ciphertext_b64").?.string),
    };
}

fn deleteSecureEnclaveTestBlob(allocator: std.mem.Allocator, tag: []const u8) !void {
    const path = try secureEnclaveTestBlobPathForTag(allocator, tag);
    defer allocator.free(path);
    std.fs.deleteFileAbsolute(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

fn saveSyntheticSecureEnclaveWrapSecret(allocator: std.mem.Allocator, tag: []const u8, ephemeral_pub_b64: []const u8, secret: []const u8) !void {
    var key: [dek_len]u8 = undefined;
    try deriveSyntheticSecureEnclaveWrapKey(allocator, &key, tag, ephemeral_pub_b64);

    var nonce: [gcm_nonce_len]u8 = undefined;
    crypto.random.bytes(&nonce);

    const ciphertext = try allocator.alloc(u8, secret.len);
    defer allocator.free(ciphertext);

    var auth_tag: [gcm_tag_len]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, &auth_tag, secret, secure_enclave_local_wrap_aad, nonce, key);

    const combined = try allocator.alloc(u8, ciphertext.len + auth_tag.len);
    defer allocator.free(combined);
    @memcpy(combined[0..ciphertext.len], ciphertext);
    @memcpy(combined[ciphertext.len..], &auth_tag);

    const blob = SecureEnclaveLocalWrapBlob{
        .version = secure_enclave_local_wrap_blob_version,
        .ephemeral_pub_b64 = try allocator.dupe(u8, ephemeral_pub_b64),
        .nonce_b64 = try b64EncodeAlloc(allocator, &nonce),
        .ciphertext_b64 = try b64EncodeAlloc(allocator, combined),
    };
    defer freeSecureEnclaveLocalWrapBlob(allocator, blob);
    try saveSecureEnclaveTestBlob(allocator, tag, blob);
}

fn loadSyntheticSecureEnclaveWrapSecret(allocator: std.mem.Allocator, tag: []const u8, ephemeral_pub_b64: []const u8) ![]u8 {
    const blob = try loadSecureEnclaveTestBlob(allocator, tag);
    defer freeSecureEnclaveLocalWrapBlob(allocator, blob);

    if (blob.version != secure_enclave_local_wrap_blob_version) return error.InvalidWrappedDek;
    if (!std.mem.eql(u8, blob.ephemeral_pub_b64, ephemeral_pub_b64)) return error.InvalidWrappedDek;

    const nonce = try b64DecodeAlloc(allocator, blob.nonce_b64);
    defer allocator.free(nonce);
    if (nonce.len != gcm_nonce_len) return error.InvalidWrappedDek;

    const combined = try b64DecodeAlloc(allocator, blob.ciphertext_b64);
    defer allocator.free(combined);
    if (combined.len < gcm_tag_len) return error.InvalidWrappedDek;

    var key: [dek_len]u8 = undefined;
    try deriveSyntheticSecureEnclaveWrapKey(allocator, &key, tag, ephemeral_pub_b64);

    const ciphertext = combined[0 .. combined.len - gcm_tag_len];
    const auth_tag: [gcm_tag_len]u8 = combined[combined.len - gcm_tag_len ..][0..gcm_tag_len].*;
    const secret = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(secret);
    crypto.aead.aes_gcm.Aes256Gcm.decrypt(secret, ciphertext, auth_tag, secure_enclave_local_wrap_aad, nonce[0..gcm_nonce_len].*, key) catch return error.InvalidWrappedDek;
    return secret;
}

fn parseSecureEnclaveWrapSecretFromJson(allocator: std.mem.Allocator, stdout: []const u8) !WrapSecret {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, stdout, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    const secret_b64 = obj.get("secret_b64") orelse return error.WrapBackendUnavailable;
    const secret_ref = obj.get("secret_ref") orelse return error.WrapBackendUnavailable;
    return .{
        .secret = try b64DecodeAlloc(allocator, secret_b64.string),
        .secret_ref = try allocator.dupe(u8, secret_ref.string),
        .secure_enclave_ephemeral_pub_b64 = if (obj.get("ephemeral_pub_b64")) |v| try allocator.dupe(u8, v.string) else null,
        .require_user_presence = if (obj.get("require_user_presence")) |v| v.bool else false,
    };
}

fn parseMacOsSecureEnclaveFailureReason(reason_text: []const u8) ?MacOsSecureEnclaveFailureReason {
    if (std.mem.eql(u8, reason_text, "user_cancelled")) return .user_cancelled;
    if (std.mem.eql(u8, reason_text, "unavailable")) return .unavailable;
    if (std.mem.eql(u8, reason_text, "key_missing")) return .key_missing;
    if (std.mem.eql(u8, reason_text, "access_denied")) return .access_denied;
    return null;
}

fn parseMacOsSecureEnclaveFailureFromJson(allocator: std.mem.Allocator, stderr: []const u8) ?MacOsSecureEnclaveFailure {
    var candidate = std.mem.trim(u8, stderr, "\r\n\t ");
    if (candidate.len == 0) return null;
    if (std.mem.lastIndexOfScalar(u8, candidate, '\n')) |idx| {
        const tail = std.mem.trim(u8, candidate[idx + 1 ..], "\r\n\t ");
        if (tail.len > 0) candidate = tail;
    }
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, candidate, .{}) catch return null;
    defer parsed.deinit();
    const obj = parsed.value.object;
    const reason = obj.get("reason") orelse return null;
    if (reason != .string) return null;
    const parsed_reason = parseMacOsSecureEnclaveFailureReason(reason.string) orelse return null;
    const message = if (obj.get("message")) |value|
        if (value == .string) allocator.dupe(u8, value.string) catch null else null
    else
        null;
    return .{ .reason = parsed_reason, .message = message };
}

fn macOsSecureEnclaveDoctorFailureMessage(reason: MacOsSecureEnclaveFailureReason) []const u8 {
    return switch (reason) {
        .user_cancelled => "doctor: macOS Secure Enclave user-presence prompt was cancelled\n",
        .unavailable => "doctor: macOS Secure Enclave is unavailable or unsupported on this system\n",
        .key_missing => "doctor: macOS Secure Enclave key is missing\n",
        .access_denied => "doctor: macOS Secure Enclave key is inaccessible (access denied)\n",
    };
}

fn macOsSecureEnclaveFailureError(reason: MacOsSecureEnclaveFailureReason) anyerror {
    return switch (reason) {
        .user_cancelled => error.MacOsSecureEnclaveUserCancelled,
        .unavailable => error.WrapBackendUnavailable,
        .key_missing => error.MacOsSecureEnclaveKeyMissing,
        .access_denied => error.MacOsSecureEnclaveAccessDenied,
    };
}

fn freeMacOsSecureEnclaveFailure(allocator: std.mem.Allocator, failure: MacOsSecureEnclaveFailure) void {
    if (failure.message) |message| allocator.free(message);
}

fn writeMacOsSecureEnclaveFailure(err: *std.Io.Writer, command_name: []const u8, failure: MacOsSecureEnclaveFailure) !void {
    switch (failure.reason) {
        .user_cancelled => try err.print("ugrant {s}: macOS Secure Enclave prompt was cancelled\n", .{command_name}),
        .unavailable => try err.print("ugrant {s}: macOS Secure Enclave is unavailable or CTK/sc_auth failed\n", .{command_name}),
        .key_missing => try err.print("ugrant {s}: macOS Secure Enclave key is missing\n", .{command_name}),
        .access_denied => try err.print("ugrant {s}: macOS Secure Enclave key is inaccessible (access denied)\n", .{command_name}),
    }
    if (failure.message) |message| {
        try err.print("ugrant {s}: helper detail: {s}\n", .{ command_name, message });
    }
    try err.print("ugrant {s}: set DEBUG=1 for detailed helper logs\n", .{command_name});
}

fn debugEnabled() bool {
    return envTruthy("DEBUG");
}

fn logMacOsSecureEnclaveFailure(result: MacOsSecureEnclaveHelperResult, phase: []const u8, debug_enabled: bool) void {
    switch (result) {
        .success => |wrap| {
            if (debug_enabled) std.log.info("secure-enclave {s} success key_version=? secret_ref={s} eph_pub_len={} require_user_presence={}", .{ phase, wrap.secret_ref orelse "", if (wrap.secure_enclave_ephemeral_pub_b64) |v| v.len else 0, wrap.require_user_presence });
        },
        .failure => |failure| {
            std.log.err("secure-enclave {s} failure reason={s}", .{ phase, @tagName(failure.reason) });
            if (failure.message) |message| std.log.err("secure-enclave {s} failure detail={s}", .{ phase, message });
        },
    }
}

fn unwrapOrWriteMacOsSecureEnclaveFailure(allocator: std.mem.Allocator, command_name: []const u8, err: *std.Io.Writer, result: MacOsSecureEnclaveHelperResult) !WrapSecret {
    return switch (result) {
        .success => |wrap| wrap,
        .failure => |failure| {
            defer freeMacOsSecureEnclaveFailure(allocator, failure);
            try writeMacOsSecureEnclaveFailure(err, command_name, failure);
            try err.flush();
            std.process.exit(1);
        },
    };
}

fn runMacOsSecureEnclaveHelper(allocator: std.mem.Allocator, argv: []const []const u8) !std.process.Child.RunResult {
    var full_argv = std.ArrayList([]const u8){};
    defer full_argv.deinit(allocator);
    try full_argv.appendSlice(allocator, &.{ "xcrun", "swift", "-" });
    try full_argv.appendSlice(allocator, argv);

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    if (envTruthy("DEBUG")) try env_map.put("DEBUG", "1");

    return runChildWithEnvAndInput(allocator, full_argv.items, &env_map, macos_secure_enclave_helper_script, 64 * 1024);
}

fn finishMacOsSecureEnclaveHelperResult(allocator: std.mem.Allocator, result: std.process.Child.RunResult) !MacOsSecureEnclaveHelperResult {
    switch (result.term) {
        .Exited => |code| {
            if (code == 0) return .{ .success = try parseSecureEnclaveWrapSecretFromJson(allocator, result.stdout) };

            if (parseMacOsSecureEnclaveFailureFromJson(allocator, result.stderr)) |failure| {
                return .{ .failure = failure };
            }
            const stdout_trimmed = std.mem.trim(u8, result.stdout, "\r\n\t ");
            const stderr_trimmed = std.mem.trim(u8, result.stderr, "\r\n\t ");
            const stdout_tail = if (stdout_trimmed.len > 400) stdout_trimmed[stdout_trimmed.len - 400 ..] else stdout_trimmed;
            const stderr_tail = if (stderr_trimmed.len > 400) stderr_trimmed[stderr_trimmed.len - 400 ..] else stderr_trimmed;
            const message = try std.fmt.allocPrint(allocator, "helper exited code={} stdout={s} stderr={s}", .{ code, stdout_tail, stderr_tail });
            return .{ .failure = .{ .reason = .unavailable, .message = message } };
        },
        else => {
            const stdout_tail = if (result.stdout.len > 400) result.stdout[result.stdout.len - 400 ..] else result.stdout;
            const stderr_tail = if (result.stderr.len > 400) result.stderr[result.stderr.len - 400 ..] else result.stderr;
            return .{ .failure = .{ .reason = .unavailable, .message = try std.fmt.allocPrint(allocator, "macOS Secure Enclave helper terminated unexpectedly term={any} stdout={s} stderr={s}", .{ result.term, stdout_tail, stderr_tail }) } };
        },
    }
}

fn runScAuth(allocator: std.mem.Allocator, argv: []const []const u8) !std.process.Child.RunResult {
    var full_argv = std.ArrayList([]const u8){};
    defer full_argv.deinit(allocator);
    try full_argv.append(allocator, macos_sc_auth_tool);
    try full_argv.appendSlice(allocator, argv);
    return runChildWithInput(allocator, full_argv.items, "", 16 * 1024);
}

fn parseScAuthIdentities(allocator: std.mem.Allocator, stdout: []const u8) ![]MacOsSecureEnclaveRef {
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    _ = lines.next();
    var items = std.ArrayList(MacOsSecureEnclaveRef){};
    errdefer {
        for (items.items) |item| {
            allocator.free(item.label);
            allocator.free(item.public_key_hash);
        }
        items.deinit(allocator);
    }
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, "\r\t ");
        if (line.len == 0) continue;
        var parts = std.ArrayList([]const u8){};
        defer parts.deinit(allocator);
        var it = std.mem.tokenizeAny(u8, line, " \t");
        while (it.next()) |part| try parts.append(allocator, part);
        if (parts.items.len < 6) continue;
        const label = parts.items[3];
        if (!std.mem.startsWith(u8, label, macos_secure_enclave_application_tag_prefix)) continue;
        const key_version_text = label[macos_secure_enclave_application_tag_prefix.len..];
        const key_version = std.fmt.parseUnsigned(u32, key_version_text, 10) catch continue;
        try items.append(allocator, .{
            .label = try allocator.dupe(u8, label),
            .public_key_hash = try allocator.dupe(u8, parts.items[1]),
            .key_version = key_version,
        });
    }
    return items.toOwnedSlice(allocator);
}

fn freeMacOsSecureEnclaveRefs(allocator: std.mem.Allocator, refs: []MacOsSecureEnclaveRef) void {
    for (refs) |ref| {
        allocator.free(ref.label);
        allocator.free(ref.public_key_hash);
    }
    allocator.free(refs);
}

fn createMacOsSecureEnclaveSecretDetailed(allocator: std.mem.Allocator, key_version: u32, require_user_presence: bool) !MacOsSecureEnclaveHelperResult {
    const debug_enabled = debugEnabled();
    if (debug_enabled) std.log.info("secure-enclave create start key_version={} require_user_presence={}", .{ key_version, require_user_presence });
    if (debug_enabled) std.log.info("secure-enclave create context test_mode={} os={s}", .{ envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE"), @tagName(builtin.os.tag) });
    if (envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE")) {
        const tag = try formatMacOsSecureEnclaveApplicationTag(allocator, key_version);
        defer allocator.free(tag);

        const secret_ref = try formatMacOsSecureEnclaveSecretRefForParts(allocator, tag, "test-hash");
        errdefer allocator.free(secret_ref);

        const secret = if (try getEnvVarOwnedOrNull(allocator, "UGRANT_TEST_SECURE_ENCLAVE_SECRET")) |v|
            v
        else
            try randomUrlSafe(allocator, 32);
        errdefer freeSecret(allocator, secret);

        const ephemeral_pub_b64 = if (try getEnvVarOwnedOrNull(allocator, "UGRANT_TEST_SECURE_ENCLAVE_EPHEMERAL_PUB_B64")) |v|
            v
        else blk: {
            var ephemeral_pub: [33]u8 = undefined;
            crypto.random.bytes(&ephemeral_pub);
            break :blk try b64EncodeAlloc(allocator, &ephemeral_pub);
        };
        errdefer allocator.free(ephemeral_pub_b64);

        try saveSyntheticSecureEnclaveWrapSecret(allocator, tag, ephemeral_pub_b64, secret);
        return .{ .success = .{
            .secret = secret,
            .secret_ref = secret_ref,
            .secure_enclave_ephemeral_pub_b64 = ephemeral_pub_b64,
            .require_user_presence = require_user_presence,
        } };
    }
    if (builtin.os.tag != .macos) return .{ .failure = .{ .reason = .unavailable } };

    const label = try formatMacOsSecureEnclaveApplicationTag(allocator, key_version);
    defer allocator.free(label);
    if (debug_enabled) std.log.info("secure-enclave create invoking helper label={s}", .{label});
    const helper_result = runMacOsSecureEnclaveHelper(allocator, &.{ "create-ctk-wrap", label, if (require_user_presence) "1" else "0" }) catch |helper_err| {
        return .{ .failure = .{ .reason = .unavailable, .message = try std.fmt.allocPrint(allocator, "failed to launch macOS Secure Enclave helper: {any}", .{helper_err}) } };
    };
    defer allocator.free(helper_result.stdout);
    defer allocator.free(helper_result.stderr);
    if (debug_enabled) std.log.info("secure-enclave create helper exited term={any} stdout_len={} stderr_len={}", .{ helper_result.term, helper_result.stdout.len, helper_result.stderr.len });
    if (helper_result.stderr.len > 0) std.log.err("secure-enclave create helper stderr:\n{s}", .{helper_result.stderr});
    const result = try finishMacOsSecureEnclaveHelperResult(allocator, helper_result);
    switch (result) {
        .success => |wrap| {
            if (debug_enabled) std.log.info("secure-enclave create success key_version={} secret_ref={s} eph_pub_len={} require_user_presence={}", .{ key_version, wrap.secret_ref orelse "", if (wrap.secure_enclave_ephemeral_pub_b64) |v| v.len else 0, wrap.require_user_presence });
        },
        .failure => |failure| {
            std.log.err("secure-enclave create failure reason={s}", .{@tagName(failure.reason)});
            if (failure.message) |message| std.log.err("secure-enclave create failure detail={s}", .{message});
        },
    }
    return result;
}

fn createMacOsSecureEnclaveSecret(allocator: std.mem.Allocator, key_version: u32, require_user_presence: bool) !WrapSecret {
    const result = try createMacOsSecureEnclaveSecretDetailed(allocator, key_version, require_user_presence);
    return switch (result) {
        .success => |wrap| wrap,
        .failure => |failure| {
            defer freeMacOsSecureEnclaveFailure(allocator, failure);
            return macOsSecureEnclaveFailureError(failure.reason);
        },
    };
}

fn loadMacOsSecureEnclaveSecret(allocator: std.mem.Allocator, secret_ref: []const u8, expected_key_version: u32, ephemeral_pub_b64: []const u8, require_user_presence: bool) !WrapSecret {
    const parsed = try parseMacOsSecureEnclaveSecretRef(secret_ref);
    if (parsed.key_version != expected_key_version) return error.InvalidWrappedDek;

    if (envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE")) {
        const secret = loadSyntheticSecureEnclaveWrapSecret(allocator, parsed.label, ephemeral_pub_b64) catch |err| switch (err) {
            error.WrapBackendUnavailable => try getEnvOrDefaultOwned(allocator, "UGRANT_TEST_SECURE_ENCLAVE_SECRET", "secure-enclave-test-secret"),
            else => return err,
        };
        return .{
            .secret = secret,
            .secret_ref = try allocator.dupe(u8, secret_ref),
            .secure_enclave_ephemeral_pub_b64 = try allocator.dupe(u8, ephemeral_pub_b64),
            .require_user_presence = require_user_presence,
        };
    }
    if (builtin.os.tag != .macos) return error.WrapBackendUnavailable;

    const result = try loadMacOsSecureEnclaveSecretDetailed(allocator, secret_ref, expected_key_version, ephemeral_pub_b64, require_user_presence);
    return switch (result) {
        .success => |wrap| wrap,
        .failure => |failure| {
            defer freeMacOsSecureEnclaveFailure(allocator, failure);
            return macOsSecureEnclaveFailureError(failure.reason);
        },
    };
}

fn loadMacOsSecureEnclaveSecretDetailed(allocator: std.mem.Allocator, secret_ref: []const u8, expected_key_version: u32, ephemeral_pub_b64: []const u8, require_user_presence: bool) !MacOsSecureEnclaveHelperResult {
    const debug_enabled = debugEnabled();
    if (debug_enabled) std.log.info("secure-enclave load start key_version={} require_user_presence={} secret_ref={s}", .{ expected_key_version, require_user_presence, secret_ref });
    const parsed = try parseMacOsSecureEnclaveSecretRef(secret_ref);
    if (parsed.key_version != expected_key_version) return .{ .failure = .{ .reason = .key_missing, .message = try std.fmt.allocPrint(allocator, "Secure Enclave key version mismatch: expected {}, got {}", .{ expected_key_version, parsed.key_version }) } };

    if (envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE")) {
        const secret = loadSyntheticSecureEnclaveWrapSecret(allocator, parsed.label, ephemeral_pub_b64) catch |err| switch (err) {
            error.WrapBackendUnavailable => try getEnvOrDefaultOwned(allocator, "UGRANT_TEST_SECURE_ENCLAVE_SECRET", "secure-enclave-test-secret"),
            else => return err,
        };
        return .{ .success = .{
            .secret = secret,
            .secret_ref = try allocator.dupe(u8, secret_ref),
            .secure_enclave_ephemeral_pub_b64 = try allocator.dupe(u8, ephemeral_pub_b64),
            .require_user_presence = require_user_presence,
        } };
    }
    if (builtin.os.tag != .macos) return .{ .failure = .{ .reason = .unavailable } };

    const helper_result = runMacOsSecureEnclaveHelper(allocator, &.{ "load-ctk", parsed.label, parsed.public_key_hash, ephemeral_pub_b64 }) catch |helper_err| {
        return .{ .failure = .{ .reason = .unavailable, .message = try std.fmt.allocPrint(allocator, "failed to launch macOS Secure Enclave helper: {any}", .{helper_err}) } };
    };
    defer allocator.free(helper_result.stdout);
    defer allocator.free(helper_result.stderr);
    if (debug_enabled) std.log.info("secure-enclave load helper exited term={any} stdout_len={} stderr_len={}", .{ helper_result.term, helper_result.stdout.len, helper_result.stderr.len });
    if (helper_result.stderr.len > 0) std.log.err("secure-enclave load helper stderr:\n{s}", .{helper_result.stderr});
    const result = try finishMacOsSecureEnclaveHelperResult(allocator, helper_result);
    switch (result) {
        .success => if (debug_enabled) std.log.info("secure-enclave load success key_version={}", .{expected_key_version}),
        .failure => |failure| std.log.err("secure-enclave load failure reason={s}", .{@tagName(failure.reason)}),
    }
    return result;
}

fn unwrapMacOsSecureEnclaveDekForDoctor(allocator: std.mem.Allocator, record: WrappedDekRecord, out: *std.Io.Writer, err: *std.Io.Writer) ![]u8 {
    const secret_ref = record.secret_ref orelse {
        try err.writeAll("doctor: macOS Secure Enclave key reference is invalid\n");
        std.process.exit(1);
    };
    _ = parseMacOsSecureEnclaveSecretRef(secret_ref) catch {
        try err.writeAll("doctor: macOS Secure Enclave key reference is invalid\n");
        std.process.exit(1);
    };
    const ephemeral_pub_b64 = record.secure_enclave_ephemeral_pub_b64 orelse {
        try err.writeAll("doctor: macOS Secure Enclave wrapped-key metadata is invalid\n");
        std.process.exit(1);
    };

    const result = try loadMacOsSecureEnclaveSecretDetailed(allocator, secret_ref, record.key_version, ephemeral_pub_b64, record.require_user_presence orelse false);
    const wrap = switch (result) {
        .success => |wrap| wrap,
        .failure => |failure| {
            try err.writeAll(macOsSecureEnclaveDoctorFailureMessage(failure.reason));
            try out.flush();
            try err.flush();
            std.process.exit(1);
        },
    };
    defer freeWrapSecret(allocator, wrap);

    return unwrapDekWithSecret(allocator, record, wrap.secret) catch |unwrap_err| switch (unwrap_err) {
        error.InvalidWrappedDek => {
            try err.writeAll("doctor: macOS Secure Enclave wrapped DEK is invalid\n");
            std.process.exit(1);
        },
        else => return unwrap_err,
    };
}

fn deleteMacOsSecureEnclaveSecret(allocator: std.mem.Allocator, secret_ref: []const u8) !void {
    const parsed = try parseMacOsSecureEnclaveSecretRef(secret_ref);
    if (envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE")) return deleteSecureEnclaveTestBlob(allocator, parsed.label);
    if (builtin.os.tag != .macos) return;

    const helper_result = runMacOsSecureEnclaveHelper(allocator, &.{ "delete-ctk-wrap", parsed.label }) catch return;
    defer allocator.free(helper_result.stdout);
    defer allocator.free(helper_result.stderr);
}

fn cleanupPersistedWrapSecret(allocator: std.mem.Allocator, backend: []const u8, wrap: WrapSecret) !void {
    if (!std.mem.eql(u8, backend, "platform-secure-store") and !std.mem.eql(u8, backend, "macos-secure-enclave")) return;
    const secret_ref = wrap.secret_ref orelse return;
    if (isMacOsSecureEnclaveSecretRef(secret_ref)) try deleteMacOsSecureEnclaveSecret(allocator, secret_ref);
}

fn formatMacOsKeychainAccount(allocator: std.mem.Allocator, key_version: u32) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{}", .{ macos_keychain_account_prefix, key_version });
}

fn formatMacOsKeychainLabel(allocator: std.mem.Allocator, key_version: u32) ![]u8 {
    return std.fmt.allocPrint(allocator, "ugrant DEK wrap secret ({})", .{key_version});
}

fn formatMacOsKeychainSecretRef(allocator: std.mem.Allocator, key_version: u32) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{s}{s}{s}{}", .{ macos_keychain_secret_ref_prefix, macos_keychain_service, macos_keychain_account_marker, macos_keychain_account_prefix, key_version });
}

fn parseMacOsKeychainSecretRef(secret_ref: []const u8) !MacOsKeychainRef {
    if (!std.mem.startsWith(u8, secret_ref, macos_keychain_secret_ref_prefix)) return error.InvalidWrappedDek;

    const rest = secret_ref[macos_keychain_secret_ref_prefix.len..];
    const marker_index = std.mem.indexOf(u8, rest, macos_keychain_account_marker) orelse return error.InvalidWrappedDek;
    const service_name = rest[0..marker_index];
    if (!std.mem.eql(u8, service_name, macos_keychain_service)) return error.InvalidWrappedDek;

    const account = rest[marker_index + macos_keychain_account_marker.len ..];
    if (!std.mem.startsWith(u8, account, macos_keychain_account_prefix)) return error.InvalidWrappedDek;
    if (std.mem.indexOfScalar(u8, account, ';') != null) return error.InvalidWrappedDek;

    const key_version_text = account[macos_keychain_account_prefix.len..];
    if (key_version_text.len == 0) return error.InvalidWrappedDek;
    const key_version = std.fmt.parseUnsigned(u32, key_version_text, 10) catch return error.InvalidWrappedDek;
    return .{ .service = service_name, .account = account, .key_version = key_version };
}

fn validateMacOsKeychainRecord(record: WrappedDekRecord) !MacOsKeychainRef {
    const secret_ref = record.secret_ref orelse return error.InvalidWrappedDek;
    const parsed = try parseMacOsKeychainSecretRef(secret_ref);
    if (parsed.key_version != record.key_version) return error.InvalidWrappedDek;
    return parsed;
}

fn loadMacOsKeychainSecret(allocator: std.mem.Allocator, secret_ref: []const u8, expected_key_version: u32) !WrapSecret {
    const parsed = try validateMacOsKeychainRecord(.{
        .version = 0,
        .backend = "platform-secure-store",
        .key_version = expected_key_version,
        .salt_b64 = "",
        .nonce_b64 = "",
        .ciphertext_b64 = "",
        .created_at = "",
        .secret_ref = secret_ref,
    });

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ macos_security_tool, "find-generic-password", "-a", parsed.account, "-s", parsed.service, "-w" },
        .max_output_bytes = 4096,
    });
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.WrapBackendUnavailable,
        else => return error.WrapBackendUnavailable,
    }
    const trimmed = std.mem.trim(u8, result.stdout, "\r\n\t ");
    if (trimmed.len == 0) {
        allocator.free(result.stdout);
        return error.WrapBackendUnavailable;
    }
    const secret = try allocator.dupe(u8, trimmed);
    allocator.free(result.stdout);
    return .{ .secret = secret, .secret_ref = try allocator.dupe(u8, secret_ref) };
}

fn storeMacOsKeychainSecret(allocator: std.mem.Allocator, key_version: u32) !WrapSecret {
    const secret = try randomUrlSafe(allocator, 32);
    errdefer freeSecret(allocator, secret);

    const account = try formatMacOsKeychainAccount(allocator, key_version);
    defer allocator.free(account);
    const label = try formatMacOsKeychainLabel(allocator, key_version);
    defer allocator.free(label);
    const secret_ref = try formatMacOsKeychainSecretRef(allocator, key_version);
    errdefer allocator.free(secret_ref);

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ macos_security_tool, "add-generic-password", "-a", account, "-s", macos_keychain_service, "-l", label, "-U", "-w", secret },
        .max_output_bytes = 4096,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.WrapBackendUnavailable,
        else => return error.WrapBackendUnavailable,
    }
    return .{ .secret = secret, .secret_ref = secret_ref };
}

fn platformStoreWrapSecret(allocator: std.mem.Allocator, keys_path: ?[]const u8, key_version: ?u32, record: ?WrappedDekRecord) !WrapSecret {
    if (record) |existing| {
        const secret_ref = existing.secret_ref orelse return error.InvalidWrappedDek;
        if (isMacOsSecureEnclaveSecretRef(secret_ref)) {
            const ephemeral_pub_b64 = existing.secure_enclave_ephemeral_pub_b64 orelse return error.InvalidWrappedDek;
            return loadMacOsSecureEnclaveSecret(allocator, secret_ref, existing.key_version, ephemeral_pub_b64, existing.require_user_presence orelse false);
        }
        if (envTruthy("UGRANT_TEST_PLATFORM_STORE_AVAILABLE")) return .{ .secret = try getEnvOrDefaultOwned(allocator, "UGRANT_TEST_PLATFORM_STORE_SECRET", "platform-store-test-secret"), .secret_ref = try allocator.dupe(u8, secret_ref) };
        if (builtin.os.tag == .windows) {
            const protected = try b64DecodeAlloc(allocator, secret_ref);
            defer allocator.free(protected);
            return .{ .secret = try unprotectDpapiBytes(allocator, protected), .secret_ref = try allocator.dupe(u8, secret_ref) };
        }
        if (builtin.os.tag == .macos) return loadMacOsKeychainSecret(allocator, secret_ref, existing.key_version);
        const result = try std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "secret-tool", "lookup", "service", "ugrant", "secret_ref", secret_ref }, .max_output_bytes = 4096 });
        defer allocator.free(result.stderr);
        switch (result.term) {
            .Exited => |code| if (code != 0) return error.WrapBackendUnavailable,
            else => return error.WrapBackendUnavailable,
        }
        const secret = try allocator.dupe(u8, std.mem.trim(u8, result.stdout, "\r\n\t "));
        allocator.free(result.stdout);
        return .{ .secret = secret, .secret_ref = try allocator.dupe(u8, secret_ref) };
    }
    if (envTruthy("UGRANT_TEST_PLATFORM_STORE_AVAILABLE")) {
        const secret_ref = if (builtin.os.tag == .macos)
            try formatMacOsKeychainSecretRef(allocator, key_version orelse return error.InvalidArgs)
        else
            try randomUrlSafe(allocator, 18);
        return .{ .secret = try getEnvOrDefaultOwned(allocator, "UGRANT_TEST_PLATFORM_STORE_SECRET", "platform-store-test-secret"), .secret_ref = secret_ref };
    }
    if (builtin.os.tag == .windows) {
        const secret = try randomUrlSafe(allocator, 32);
        errdefer freeSecret(allocator, secret);
        const protected = try protectDpapiBytes(allocator, secret);
        defer allocator.free(protected);
        return .{ .secret = secret, .secret_ref = try b64EncodeAlloc(allocator, protected) };
    }
    if (builtin.os.tag == .macos) return storeMacOsKeychainSecret(allocator, key_version orelse return error.InvalidArgs);

    const ref = try randomUrlSafe(allocator, 18);
    const secret = try randomUrlSafe(allocator, 32);
    errdefer freeSecret(allocator, secret);
    const key_path = keys_path orelse return error.InvalidArgs;
    const result = try runChildWithInput(allocator, &.{ "secret-tool", "store", "--label", "ugrant DEK wrap secret", "service", "ugrant", "secret_ref", ref, "key_path", key_path }, secret, 4096);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.WrapBackendUnavailable,
        else => return error.WrapBackendUnavailable,
    }
    return .{ .secret = secret, .secret_ref = ref };
}

fn macOsSecureEnclaveWrapSecret(allocator: std.mem.Allocator, key_version: ?u32, record: ?WrappedDekRecord, options: WrapBackendOptions) !WrapSecret {
    if (record) |existing| {
        const secret_ref = existing.secret_ref orelse return error.InvalidWrappedDek;
        const ephemeral_pub_b64 = existing.secure_enclave_ephemeral_pub_b64 orelse return error.InvalidWrappedDek;
        return loadMacOsSecureEnclaveSecret(allocator, secret_ref, existing.key_version, ephemeral_pub_b64, existing.require_user_presence orelse false);
    }
    return createMacOsSecureEnclaveSecret(allocator, key_version orelse return error.InvalidArgs, options.require_user_presence);
}

fn tpm2WrapSecret(allocator: std.mem.Allocator, record: ?WrappedDekRecord) !WrapSecret {
    if (record) |existing| {
        if (envTruthy("UGRANT_TEST_TPM2_AVAILABLE")) return .{ .secret = try getEnvOrDefaultOwned(allocator, "UGRANT_TEST_TPM2_SECRET", "tpm2-test-secret"), .tpm2_pub_b64 = try allocator.dupe(u8, existing.tpm2_pub_b64.?), .tpm2_priv_b64 = try allocator.dupe(u8, existing.tpm2_priv_b64.?) };
        const pub_blob = existing.tpm2_pub_b64 orelse return error.InvalidWrappedDek;
        const priv_blob = existing.tpm2_priv_b64 orelse return error.InvalidWrappedDek;
        return unsealTpm2Secret(allocator, pub_blob, priv_blob);
    }
    const secret = if (envTruthy("UGRANT_TEST_TPM2_AVAILABLE")) try getEnvOrDefaultOwned(allocator, "UGRANT_TEST_TPM2_SECRET", "tpm2-test-secret") else try randomUrlSafe(allocator, 32);
    errdefer freeSecret(allocator, secret);
    if (envTruthy("UGRANT_TEST_TPM2_AVAILABLE")) return .{ .secret = secret, .tpm2_pub_b64 = try allocator.dupe(u8, "dHBtMi1wdWI="), .tpm2_priv_b64 = try allocator.dupe(u8, "dHBtMi1wcml2") };
    return sealTpm2Secret(allocator, secret);
}

fn sealTpm2Secret(allocator: std.mem.Allocator, secret: []const u8) !WrapSecret {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const secret_path = try std.fs.path.join(allocator, &.{ base, "secret.bin" });
    defer allocator.free(secret_path);
    {
        var file = try std.fs.createFileAbsolute(secret_path, .{ .truncate = true, .mode = pathing.secret_file_mode });
        defer file.close();
        try file.writeAll(secret);
    }
    const script =
        "set -eu\n" ++
        "BASE=\"$1\"\n" ++
        "tpm2_createprimary -Q -C o -c \"$BASE/primary.ctx\" >/dev/null\n" ++
        "tpm2_create -Q -C \"$BASE/primary.ctx\" -u \"$BASE/wrap.pub\" -r \"$BASE/wrap.priv\" -i \"$BASE/secret.bin\" >/dev/null\n";
    const result = try std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "sh", "-c", script, "sh", base }, .max_output_bytes = 64 * 1024 });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.WrapBackendUnavailable,
        else => return error.WrapBackendUnavailable,
    }
    const pub_blob = try std.fs.cwd().readFileAlloc(allocator, try std.fs.path.join(allocator, &.{ base, "wrap.pub" }), 64 * 1024);
    const priv_blob = try std.fs.cwd().readFileAlloc(allocator, try std.fs.path.join(allocator, &.{ base, "wrap.priv" }), 64 * 1024);
    defer allocator.free(pub_blob);
    defer allocator.free(priv_blob);
    return .{ .secret = try allocator.dupe(u8, secret), .tpm2_pub_b64 = try b64EncodeAlloc(allocator, pub_blob), .tpm2_priv_b64 = try b64EncodeAlloc(allocator, priv_blob) };
}

fn unsealTpm2Secret(allocator: std.mem.Allocator, pub_b64: []const u8, priv_b64: []const u8) !WrapSecret {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const pub_blob = try b64DecodeAlloc(allocator, pub_b64);
    const priv_blob = try b64DecodeAlloc(allocator, priv_b64);
    defer allocator.free(pub_blob);
    defer allocator.free(priv_blob);
    const pub_path = try std.fs.path.join(allocator, &.{ base, "wrap.pub" });
    const priv_path = try std.fs.path.join(allocator, &.{ base, "wrap.priv" });
    const primary_path = try std.fs.path.join(allocator, &.{ base, "primary.ctx" });
    const key_path = try std.fs.path.join(allocator, &.{ base, "wrap.ctx" });
    defer allocator.free(pub_path);
    defer allocator.free(priv_path);
    defer allocator.free(primary_path);
    defer allocator.free(key_path);
    {
        var file = try std.fs.createFileAbsolute(pub_path, .{ .truncate = true, .mode = pathing.secret_file_mode });
        defer file.close();
        try file.writeAll(pub_blob);
    }
    {
        var file = try std.fs.createFileAbsolute(priv_path, .{ .truncate = true, .mode = pathing.secret_file_mode });
        defer file.close();
        try file.writeAll(priv_blob);
    }
    const script =
        "set -eu\nBASE=\"$1\"\n" ++
        "tpm2_createprimary -Q -C o -c \"$BASE/primary.ctx\" >/dev/null\n" ++
        "tpm2_load -Q -C \"$BASE/primary.ctx\" -u \"$BASE/wrap.pub\" -r \"$BASE/wrap.priv\" -c \"$BASE/wrap.ctx\" >/dev/null\n" ++
        "tpm2_unseal -Q -c \"$BASE/wrap.ctx\"\n";
    const result = try std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "sh", "-c", script, "sh", base }, .max_output_bytes = 4096 });
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.WrapBackendUnavailable,
        else => return error.WrapBackendUnavailable,
    }
    const secret = try allocator.dupe(u8, std.mem.trim(u8, result.stdout, "\r\n\t "));
    allocator.free(result.stdout);
    return .{ .secret = secret, .tpm2_pub_b64 = try allocator.dupe(u8, pub_b64), .tpm2_priv_b64 = try allocator.dupe(u8, priv_b64) };
}

const RekeyStats = struct {
    key_version: u32,
    profiles_rewritten: usize,
    grants_rewritten: usize,
};

const ProfileSecretRewrite = struct {
    name: []const u8,
    client_secret_enc: []const u8,
};

const GrantSecretRewrite = struct {
    profile_name: []const u8,
    subject_key: []const u8,
    access_token_enc: ?[]const u8,
    refresh_token_enc: ?[]const u8,
    id_token_enc: ?[]const u8,
};

fn freeProfileSecretRewrites(allocator: std.mem.Allocator, rewrites: []ProfileSecretRewrite) void {
    for (rewrites) |rewrite| {
        allocator.free(rewrite.name);
        allocator.free(rewrite.client_secret_enc);
    }
    allocator.free(rewrites);
}

fn freeGrantSecretRewrites(allocator: std.mem.Allocator, rewrites: []GrantSecretRewrite) void {
    for (rewrites) |rewrite| {
        allocator.free(rewrite.profile_name);
        allocator.free(rewrite.subject_key);
        if (rewrite.access_token_enc) |v| allocator.free(v);
        if (rewrite.refresh_token_enc) |v| allocator.free(v);
        if (rewrite.id_token_enc) |v| allocator.free(v);
    }
    allocator.free(rewrites);
}

fn openDb(path: []const u8) !*c.sqlite3 {
    var db: ?*c.sqlite3 = null;
    const sqlite_path = if (builtin.os.tag == .windows) try sqlitePathForWindows(std.heap.page_allocator, path) else path;
    defer if (builtin.os.tag == .windows) std.heap.page_allocator.free(sqlite_path);
    if (c.sqlite3_open(sqlite_path.ptr, &db) != c.SQLITE_OK) return error.SqliteOpen;
    if (builtin.os.tag != .windows) {
        var file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();
        try file.chmod(pathing.secret_file_mode);
    }
    return db.?;
}

fn sqlitePathForWindows(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const out = try allocator.dupe(u8, path);
    for (out) |*ch| {
        if (ch.* == '\\') ch.* = '/';
    }
    return out;
}

fn ensureSchema(db: *c.sqlite3) !void {
    const schema =
        "PRAGMA journal_mode=WAL;" ++
        "CREATE TABLE IF NOT EXISTS profiles (" ++
        "name TEXT PRIMARY KEY, provider TEXT NOT NULL, auth_url TEXT NOT NULL, token_url TEXT NOT NULL, client_id TEXT NOT NULL, scope TEXT NOT NULL, redirect_uri TEXT NOT NULL, env_kind TEXT NOT NULL, base_url TEXT, model TEXT, audience TEXT, client_secret_enc TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);" ++
        "CREATE TABLE IF NOT EXISTS grants (" ++
        "profile_name TEXT PRIMARY KEY, provider TEXT NOT NULL, subject_key TEXT NOT NULL, token_type TEXT, scope TEXT, state TEXT NOT NULL, expires_at INTEGER, refresh_token_expires_at INTEGER, access_token_enc TEXT, refresh_token_enc TEXT, id_token_enc TEXT, refresh_started_at INTEGER, refresh_owner TEXT, refresh_error TEXT, granted_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, FOREIGN KEY(profile_name) REFERENCES profiles(name));" ++
        "CREATE INDEX IF NOT EXISTS idx_grants_expires_at ON grants(expires_at);";
    var errmsg: [*c]u8 = null;
    if (c.sqlite3_exec(db, schema.ptr, null, null, &errmsg) != c.SQLITE_OK) {
        if (errmsg != null) c.sqlite3_free(errmsg);
        return error.SqliteExec;
    }
    try ensureColumn(db, "grants", "refresh_started_at", "INTEGER");
    try ensureColumn(db, "grants", "refresh_owner", "TEXT");
    try ensureColumn(db, "grants", "refresh_error", "TEXT");
}

fn ensureColumn(db: *c.sqlite3, table: []const u8, column: []const u8, definition: []const u8) !void {
    const pragma = try std.fmt.allocPrint(std.heap.page_allocator, "PRAGMA table_info({s})", .{table});
    defer std.heap.page_allocator.free(pragma);
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, pragma.ptr, @as(c_int, @intCast(pragma.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    while (true) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return sqliteErr(db);
        const name = try dupeColumnText(std.heap.page_allocator, stmt.?, 1);
        defer std.heap.page_allocator.free(name);
        if (std.mem.eql(u8, name, column)) return;
    }
    const sql = try std.fmt.allocPrint(std.heap.page_allocator, "ALTER TABLE {s} ADD COLUMN {s} {s}", .{ table, column, definition });
    defer std.heap.page_allocator.free(sql);
    try execSql(db, sql);
}

fn execSql(db: *c.sqlite3, sql: []const u8) !void {
    var errmsg: [*c]u8 = null;
    if (c.sqlite3_exec(db, sql.ptr, null, null, &errmsg) != c.SQLITE_OK) {
        if (errmsg != null) c.sqlite3_free(errmsg);
        return error.SqliteExec;
    }
}

fn revokeGrantState(db: *c.sqlite3, profile_name: []const u8) !bool {
    const sql =
        "UPDATE grants SET state='revoked', expires_at=NULL, refresh_token_expires_at=NULL, access_token_enc=NULL, refresh_token_enc=NULL, id_token_enc=NULL, updated_at=unixepoch() WHERE profile_name=?1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile_name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(db);
    return c.sqlite3_changes(db) > 0;
}

fn performRekey(allocator: std.mem.Allocator, db: *c.sqlite3, keys_path: []const u8, current_record: WrappedDekRecord, current_wrap_secret: []const u8, target_backend: []const u8, target_wrap_secret: []const u8, secret_ref: ?[]const u8, tpm2_pub_b64: ?[]const u8, tpm2_priv_b64: ?[]const u8, secure_enclave_ephemeral_pub_b64: ?[]const u8, require_user_presence: bool) !RekeyStats {
    const old_dek = try unwrapDekWithSecret(allocator, current_record, current_wrap_secret);
    defer allocator.free(old_dek);

    var new_dek: [dek_len]u8 = undefined;
    crypto.random.bytes(&new_dek);
    defer std.crypto.secureZero(u8, &new_dek);

    const stats = try rekeyEncryptedState(allocator, db, old_dek, &new_dek);

    const target_wrap = WrapSecret{
        .secret = @constCast(target_wrap_secret),
        .secret_ref = secret_ref,
        .tpm2_pub_b64 = tpm2_pub_b64,
        .tpm2_priv_b64 = tpm2_priv_b64,
        .secure_enclave_ephemeral_pub_b64 = secure_enclave_ephemeral_pub_b64,
        .require_user_presence = require_user_presence,
    };

    const new_record = try wrapDekForBackend(allocator, target_backend, current_record.key_version + 1, target_wrap_secret, &new_dek, target_wrap);
    defer freeWrappedDekRecord(allocator, new_record);

    saveWrappedDek(keys_path, new_record) catch |save_err| {
        _ = try rekeyEncryptedState(allocator, db, &new_dek, old_dek);
        cleanupPersistedWrapSecret(allocator, target_backend, target_wrap) catch {};
        return save_err;
    };

    if (current_record.secret_ref) |current_secret_ref| {
        if (!std.mem.eql(u8, current_secret_ref, secret_ref orelse "")) {
            if (isMacOsSecureEnclaveSecretRef(current_secret_ref)) {
                deleteMacOsSecureEnclaveSecret(allocator, current_secret_ref) catch {};
            }
        }
    }

    return .{
        .key_version = current_record.key_version + 1,
        .profiles_rewritten = stats.profiles_rewritten,
        .grants_rewritten = stats.grants_rewritten,
    };
}

fn rekeyEncryptedState(allocator: std.mem.Allocator, db: *c.sqlite3, old_dek: []const u8, new_dek: []const u8) !RekeyStats {
    const profile_rewrites = try prepareProfileSecretRewrites(allocator, db, old_dek, new_dek);
    defer freeProfileSecretRewrites(allocator, profile_rewrites);
    const grant_rewrites = try prepareGrantSecretRewrites(allocator, db, old_dek, new_dek);
    defer freeGrantSecretRewrites(allocator, grant_rewrites);

    try execSql(db, "BEGIN IMMEDIATE;");
    errdefer execSql(db, "ROLLBACK;") catch {};
    try applyProfileSecretRewrites(db, profile_rewrites);
    try applyGrantSecretRewrites(db, grant_rewrites);
    try execSql(db, "COMMIT;");

    return .{
        .key_version = 0,
        .profiles_rewritten = profile_rewrites.len,
        .grants_rewritten = grant_rewrites.len,
    };
}

fn prepareProfileSecretRewrites(allocator: std.mem.Allocator, db: *c.sqlite3, old_dek: []const u8, new_dek: []const u8) ![]ProfileSecretRewrite {
    const sql = "SELECT name, client_secret_enc FROM profiles WHERE client_secret_enc IS NOT NULL";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);

    var rewrites = std.ArrayList(ProfileSecretRewrite){};
    errdefer {
        for (rewrites.items) |rewrite| {
            allocator.free(rewrite.name);
            allocator.free(rewrite.client_secret_enc);
        }
        rewrites.deinit(allocator);
    }

    while (true) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return sqliteErr(db);

        const name = try dupeColumnText(allocator, stmt.?, 0);
        errdefer allocator.free(name);
        const current_enc = try dupeColumnText(allocator, stmt.?, 1);
        defer allocator.free(current_enc);
        const plaintext = try decryptField(allocator, old_dek, "profiles", "client_secret", name, "_", current_enc);
        defer allocator.free(plaintext);
        const rewritten = try encryptField(allocator, new_dek, "profiles", "client_secret", name, "_", plaintext);
        try rewrites.append(allocator, .{ .name = name, .client_secret_enc = rewritten });
    }

    return rewrites.toOwnedSlice(allocator);
}

fn prepareGrantSecretRewrites(allocator: std.mem.Allocator, db: *c.sqlite3, old_dek: []const u8, new_dek: []const u8) ![]GrantSecretRewrite {
    const sql =
        "SELECT profile_name, subject_key, access_token_enc, refresh_token_enc, id_token_enc FROM grants " ++
        "WHERE access_token_enc IS NOT NULL OR refresh_token_enc IS NOT NULL OR id_token_enc IS NOT NULL";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);

    var rewrites = std.ArrayList(GrantSecretRewrite){};
    errdefer {
        for (rewrites.items) |rewrite| {
            allocator.free(rewrite.profile_name);
            allocator.free(rewrite.subject_key);
            if (rewrite.access_token_enc) |v| allocator.free(v);
            if (rewrite.refresh_token_enc) |v| allocator.free(v);
            if (rewrite.id_token_enc) |v| allocator.free(v);
        }
        rewrites.deinit(allocator);
    }

    while (true) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return sqliteErr(db);

        const profile_name = try dupeColumnText(allocator, stmt.?, 0);
        errdefer allocator.free(profile_name);
        const subject_key = try dupeColumnText(allocator, stmt.?, 1);
        errdefer allocator.free(subject_key);
        const access_enc = try dupeNullableColumnText(allocator, stmt.?, 2);
        const refresh_enc = try dupeNullableColumnText(allocator, stmt.?, 3);
        const id_enc = try dupeNullableColumnText(allocator, stmt.?, 4);
        defer if (access_enc) |v| allocator.free(v);
        defer if (refresh_enc) |v| allocator.free(v);
        defer if (id_enc) |v| allocator.free(v);

        const access_token_enc = if (access_enc) |v| blk: {
            const plaintext = try decryptField(allocator, old_dek, "grants", "access_token", profile_name, subject_key, v);
            defer allocator.free(plaintext);
            break :blk try encryptField(allocator, new_dek, "grants", "access_token", profile_name, subject_key, plaintext);
        } else null;
        errdefer if (access_token_enc) |v| allocator.free(v);
        const refresh_token_enc = if (refresh_enc) |v| blk: {
            const plaintext = try decryptField(allocator, old_dek, "grants", "refresh_token", profile_name, subject_key, v);
            defer allocator.free(plaintext);
            break :blk try encryptField(allocator, new_dek, "grants", "refresh_token", profile_name, subject_key, plaintext);
        } else null;
        errdefer if (refresh_token_enc) |v| allocator.free(v);
        const id_token_enc = if (id_enc) |v| blk: {
            const plaintext = try decryptField(allocator, old_dek, "grants", "id_token", profile_name, subject_key, v);
            defer allocator.free(plaintext);
            break :blk try encryptField(allocator, new_dek, "grants", "id_token", profile_name, subject_key, plaintext);
        } else null;

        try rewrites.append(allocator, .{
            .profile_name = profile_name,
            .subject_key = subject_key,
            .access_token_enc = access_token_enc,
            .refresh_token_enc = refresh_token_enc,
            .id_token_enc = id_token_enc,
        });
    }

    return rewrites.toOwnedSlice(allocator);
}

fn applyProfileSecretRewrites(db: *c.sqlite3, rewrites: []const ProfileSecretRewrite) !void {
    const sql = "UPDATE profiles SET client_secret_enc=?1, updated_at=unixepoch() WHERE name=?2";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);

    for (rewrites) |rewrite| {
        _ = c.sqlite3_reset(stmt.?);
        _ = c.sqlite3_clear_bindings(stmt.?);
        try bindText(stmt.?, 1, rewrite.client_secret_enc);
        try bindText(stmt.?, 2, rewrite.name);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(db);
    }
}

fn applyGrantSecretRewrites(db: *c.sqlite3, rewrites: []const GrantSecretRewrite) !void {
    const sql =
        "UPDATE grants SET access_token_enc=?1, refresh_token_enc=?2, id_token_enc=?3, updated_at=unixepoch() " ++
        "WHERE profile_name=?4 AND subject_key=?5";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);

    for (rewrites) |rewrite| {
        _ = c.sqlite3_reset(stmt.?);
        _ = c.sqlite3_clear_bindings(stmt.?);
        try bindNullableText(stmt.?, 1, rewrite.access_token_enc);
        try bindNullableText(stmt.?, 2, rewrite.refresh_token_enc);
        try bindNullableText(stmt.?, 3, rewrite.id_token_enc);
        try bindText(stmt.?, 4, rewrite.profile_name);
        try bindText(stmt.?, 5, rewrite.subject_key);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(db);
    }
}

fn sqliteErr(db: *c.sqlite3) error{SqliteFailure} {
    _ = db;
    return error.SqliteFailure;
}

fn bindText(stmt: *c.sqlite3_stmt, idx: c_int, text: []const u8) !void {
    // Current call sites keep the bound buffer alive until sqlite3_step/finalize,
    // so SQLITE_STATIC semantics are sufficient here and avoid macOS Zig cimport
    // issues around SQLITE_TRANSIENT.
    if (c.sqlite3_bind_text(stmt, idx, text.ptr, @as(c_int, @intCast(text.len)), null) != c.SQLITE_OK) return error.SqliteBind;
}
fn bindNullableText(stmt: *c.sqlite3_stmt, idx: c_int, text: ?[]const u8) !void {
    if (text) |v| return bindText(stmt, idx, v);
    if (c.sqlite3_bind_null(stmt, idx) != c.SQLITE_OK) return error.SqliteBind;
}
fn bindInt(stmt: *c.sqlite3_stmt, idx: c_int, value: i64) !void {
    if (c.sqlite3_bind_int64(stmt, idx, value) != c.SQLITE_OK) return error.SqliteBind;
}
fn bindNullableInt(stmt: *c.sqlite3_stmt, idx: c_int, value: ?i64) !void {
    if (value) |v| {
        if (c.sqlite3_bind_int64(stmt, idx, v) != c.SQLITE_OK) return error.SqliteBind;
    } else if (c.sqlite3_bind_null(stmt, idx) != c.SQLITE_OK) return error.SqliteBind;
}

fn encryptField(allocator: std.mem.Allocator, dek: []const u8, table: []const u8, column: []const u8, profile: []const u8, subject: []const u8, plaintext: []const u8) ![]u8 {
    var nonce: [gcm_nonce_len]u8 = undefined;
    crypto.random.bytes(&nonce);
    const aad = try std.fmt.allocPrint(allocator, "v{}:{s}:{s}:{s}:{s}", .{ schema_version, table, column, profile, subject });
    defer allocator.free(aad);
    var key: [32]u8 = undefined;
    @memcpy(&key, dek[0..32]);
    const ct = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ct);
    var tag: [gcm_tag_len]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(ct, &tag, plaintext, aad, nonce, key);
    var combined = try allocator.alloc(u8, gcm_nonce_len + plaintext.len + gcm_tag_len);
    @memcpy(combined[0..gcm_nonce_len], &nonce);
    @memcpy(combined[gcm_nonce_len .. gcm_nonce_len + plaintext.len], ct);
    @memcpy(combined[gcm_nonce_len + plaintext.len ..], &tag);
    allocator.free(ct);
    defer allocator.free(combined);
    return b64EncodeAlloc(allocator, combined);
}

fn decryptField(allocator: std.mem.Allocator, dek: []const u8, table: []const u8, column: []const u8, profile: []const u8, subject: []const u8, encoded: []const u8) ![]u8 {
    const blob = try b64DecodeAlloc(allocator, encoded);
    defer allocator.free(blob);
    if (blob.len < gcm_nonce_len + gcm_tag_len) return error.InvalidCiphertext;
    const nonce = blob[0..gcm_nonce_len];
    const tag: [gcm_tag_len]u8 = blob[blob.len - gcm_tag_len ..][0..gcm_tag_len].*;
    const ciphertext = blob[gcm_nonce_len .. blob.len - gcm_tag_len];
    const aad = try std.fmt.allocPrint(allocator, "v{}:{s}:{s}:{s}:{s}", .{ schema_version, table, column, profile, subject });
    defer allocator.free(aad);
    var key: [32]u8 = undefined;
    @memcpy(&key, dek[0..32]);
    const pt = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(pt);
    crypto.aead.aes_gcm.Aes256Gcm.decrypt(pt, ciphertext, tag, aad, nonce[0..gcm_nonce_len].*, key) catch return error.DecryptFailed;
    return pt;
}

fn b64EncodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const size = std.base64.standard.Encoder.calcSize(bytes.len);
    const out = try allocator.alloc(u8, size);
    _ = std.base64.standard.Encoder.encode(out, bytes);
    return out;
}

fn b64DecodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(text);
    const out = try allocator.alloc(u8, size);
    try std.base64.standard.Decoder.decode(out, text);
    return out;
}

fn freeSecret(allocator: std.mem.Allocator, secret: []u8) void {
    std.crypto.secureZero(u8, secret);
    allocator.free(secret);
}

fn promptLine(allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    var stdout_file = std.fs.File.stdout();
    try stdout_file.writeAll(prompt);

    var stdin_file = std.fs.File.stdin();
    var buf: [4096]u8 = undefined;
    const n = try stdin_file.read(&buf);
    return allocator.dupe(u8, std.mem.trimRight(u8, buf[0..n], "\r\n"));
}

const WindowsHiddenConsoleInput = struct {
    handle: c.HANDLE,
    original_mode: c.DWORD,
};

fn trimPromptInput(input: []const u8) []const u8 {
    return std.mem.trimRight(u8, input, "\r\n");
}

fn promptSecret(allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    var stdout_file = std.fs.File.stdout();
    try stdout_file.writeAll(prompt);

    if (builtin.os.tag == .windows) {
        const hidden_console = enableWindowsHiddenConsoleInput();
        defer {
            if (hidden_console) |state| {
                _ = c.SetConsoleMode(state.handle, state.original_mode);
                stdout_file.writeAll("\n") catch {};
            }
        }
    } else {
        var restored = false;
        var original_termios: c.termios = undefined;
        if (c.isatty(c.STDIN_FILENO) == 1) {
            if (c.tcgetattr(c.STDIN_FILENO, &original_termios) == 0) {
                var hidden = original_termios;
                hidden.c_lflag &= ~@as(@TypeOf(hidden.c_lflag), c.ECHO);
                _ = c.tcsetattr(c.STDIN_FILENO, c.TCSANOW, &hidden);
                restored = true;
            }
        }
        defer {
            if (restored) {
                _ = c.tcsetattr(c.STDIN_FILENO, c.TCSANOW, &original_termios);
                stdout_file.writeAll("\n") catch {};
            }
        }
    }

    var stdin_file = std.fs.File.stdin();
    var buf: [4096]u8 = undefined;
    const n = try stdin_file.read(&buf);
    return allocator.dupe(u8, trimPromptInput(buf[0..n]));
}

fn enableWindowsHiddenConsoleInput() ?WindowsHiddenConsoleInput {
    if (builtin.os.tag != .windows) return null;

    const stdin_handle = c.GetStdHandle(c.STD_INPUT_HANDLE);
    var original_mode: c.DWORD = 0;
    if (c.GetConsoleMode(stdin_handle, &original_mode) == 0) return null;

    const hidden_mode = original_mode & ~@as(c.DWORD, c.ENABLE_ECHO_INPUT);
    if (c.SetConsoleMode(stdin_handle, hidden_mode) == 0) return null;

    return .{
        .handle = stdin_handle,
        .original_mode = original_mode,
    };
}

fn generateCodeVerifier(allocator: std.mem.Allocator) ![]u8 {
    return randomUrlSafe(allocator, 48);
}

fn randomUrlSafe(allocator: std.mem.Allocator, len: usize) ![]u8 {
    const raw = try allocator.alloc(u8, len);
    defer allocator.free(raw);
    crypto.random.bytes(raw);
    const b64 = try b64EncodeAlloc(allocator, raw);
    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);
    for (b64) |ch| {
        switch (ch) {
            '+' => try out.append(allocator, '-'),
            '/' => try out.append(allocator, '_'),
            '=' => {},
            else => try out.append(allocator, ch),
        }
    }
    allocator.free(b64);
    return out.toOwnedSlice(allocator);
}

fn pkceChallenge(allocator: std.mem.Allocator, verifier: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    const b64 = try b64EncodeAlloc(allocator, &digest);
    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);
    for (b64) |ch| {
        switch (ch) {
            '+' => try out.append(allocator, '-'),
            '/' => try out.append(allocator, '_'),
            '=' => {},
            else => try out.append(allocator, ch),
        }
    }
    allocator.free(b64);
    return out.toOwnedSlice(allocator);
}

fn loadProfile(allocator: std.mem.Allocator, db: *c.sqlite3, name: []const u8) !ProfileRecord {
    const sql = "SELECT name, provider, auth_url, token_url, client_id, scope, redirect_uri, env_kind, base_url, model, audience, client_secret_enc FROM profiles WHERE name=?1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return error.ProfileNotFound;

    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    const wrapped = try loadWrappedDek(allocator, paths.keys_path);
    defer freeWrappedDekRecord(allocator, wrapped);
    const dek = try unwrapDek(allocator, wrapped);
    defer allocator.free(dek);

    const name_v = try dupeColumnText(allocator, stmt.?, 0);
    const provider_v = try dupeColumnText(allocator, stmt.?, 1);
    const auth_url_v = try dupeColumnText(allocator, stmt.?, 2);
    const token_url_v = try dupeColumnText(allocator, stmt.?, 3);
    const client_id_v = try dupeColumnText(allocator, stmt.?, 4);
    const scope_v = try dupeColumnText(allocator, stmt.?, 5);
    const redirect_uri_v = try dupeColumnText(allocator, stmt.?, 6);
    const env_kind_v = try dupeColumnText(allocator, stmt.?, 7);
    const base_url_v = try dupeNullableColumnText(allocator, stmt.?, 8);
    const model_v = try dupeNullableColumnText(allocator, stmt.?, 9);
    const audience_v = try dupeNullableColumnText(allocator, stmt.?, 10);
    const secret_enc = try dupeNullableColumnText(allocator, stmt.?, 11);
    const secret = if (secret_enc) |enc| try decryptField(allocator, dek, "profiles", "client_secret", name, "_", enc) else null;
    defer if (secret_enc) |enc| allocator.free(enc);
    return .{ .name = name_v, .provider = provider_v, .auth_url = auth_url_v, .token_url = token_url_v, .client_id = client_id_v, .scope = scope_v, .redirect_uri = redirect_uri_v, .env_kind = env_kind_v, .base_url = base_url_v, .model = model_v, .audience = audience_v, .client_secret = secret };
}

fn freeProfile(allocator: std.mem.Allocator, profile: ProfileRecord) void {
    allocator.free(profile.name);
    allocator.free(profile.provider);
    allocator.free(profile.auth_url);
    allocator.free(profile.token_url);
    allocator.free(profile.client_id);
    allocator.free(profile.scope);
    allocator.free(profile.redirect_uri);
    allocator.free(profile.env_kind);
    if (profile.base_url) |v| allocator.free(v);
    if (profile.model) |v| allocator.free(v);
    if (profile.audience) |v| allocator.free(v);
    if (profile.client_secret) |v| allocator.free(v);
}

fn buildAuthUrl(allocator: std.mem.Allocator, profile: ProfileRecord, challenge: []const u8, state: []const u8) ![]u8 {
    var list = std.ArrayList(u8){};
    defer list.deinit(allocator);
    try list.writer(allocator).print("{s}?response_type=code&client_id=", .{profile.auth_url});
    try appendUrlEscaped(allocator, &list, profile.client_id);
    try list.appendSlice(allocator, "&redirect_uri=");
    try appendUrlEscaped(allocator, &list, profile.redirect_uri);
    try list.appendSlice(allocator, "&scope=");
    try appendUrlEscaped(allocator, &list, profile.scope);
    try list.appendSlice(allocator, "&code_challenge=");
    try appendUrlEscaped(allocator, &list, challenge);
    try list.appendSlice(allocator, "&code_challenge_method=S256&state=");
    try appendUrlEscaped(allocator, &list, state);
    if (profile.audience) |aud| {
        try list.appendSlice(allocator, "&audience=");
        try appendUrlEscaped(allocator, &list, aud);
    }
    return list.toOwnedSlice(allocator);
}

fn appendUrlEscaped(allocator: std.mem.Allocator, list: *std.ArrayList(u8), value: []const u8) !void {
    for (value) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try list.append(allocator, ch);
        } else {
            try list.writer(allocator).print("%{X:0>2}", .{ch});
        }
    }
}

fn resolveManualCodeInput(allocator: std.mem.Allocator, raw_input: []const u8, expected_state: []const u8, allow_unsafe_bare_code: bool) ![]u8 {
    const trimmed = std.mem.trim(u8, raw_input, " \r\n\t");
    if (trimmed.len == 0) return error.CodeNotFound;
    if (std.mem.indexOf(u8, trimmed, "://") != null or std.mem.indexOf(u8, trimmed, "code=") != null) {
        return extractCodeFromRedirect(allocator, trimmed, expected_state);
    }
    if (!allow_unsafe_bare_code) return error.UnsafeBareCodeRequiresFlag;
    return allocator.dupe(u8, trimmed);
}

fn extractCodeFromRedirect(allocator: std.mem.Allocator, redirect: []const u8, expected_state: []const u8) ![]u8 {
    const start = std.mem.indexOfAny(u8, redirect, "?#") orelse return error.CodeNotFound;
    var code: ?[]u8 = null;
    var state: ?[]u8 = null;
    defer if (state) |value| allocator.free(value);

    var it = std.mem.tokenizeAny(u8, redirect[start..], "?#&");
    while (it.next()) |part| {
        if (std.mem.startsWith(u8, part, "code=")) {
            if (code == null) code = try urlDecodeAlloc(allocator, part[5..]);
        } else if (std.mem.startsWith(u8, part, "state=")) {
            if (state) |prev| allocator.free(prev);
            state = try urlDecodeAlloc(allocator, part[6..]);
        }
    }

    if (code == null) return error.CodeNotFound;
    if (state == null or !std.mem.eql(u8, expected_state, state.?)) {
        freeSecret(allocator, code.?);
        return error.InvalidOAuthState;
    }
    return code.?;
}

fn urlDecodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const ch = input[i];
        if (ch == '%' and i + 2 < input.len) {
            const hi = try std.fmt.parseInt(u8, input[i + 1 .. i + 2], 16);
            const lo = try std.fmt.parseInt(u8, input[i + 2 .. i + 3], 16);
            try out.append(allocator, (hi << 4) | lo);
            i += 2;
        } else if (ch == '+') try out.append(allocator, ' ') else try out.append(allocator, ch);
    }
    return out.toOwnedSlice(allocator);
}

const OpenUrlResult = enum {
    launched,
    unavailable,
    disabled,
};

fn spawnDetached(argv: []const []const u8) bool {
    var proc = std.process.Child.init(argv, std.heap.page_allocator);
    proc.stdin_behavior = .Ignore;
    proc.stdout_behavior = .Ignore;
    proc.stderr_behavior = .Ignore;
    proc.spawn() catch return false;
    return true;
}

fn maybeOpenUrl(url: []const u8) OpenUrlResult {
    switch (builtin.os.tag) {
        .macos => {
            if (spawnDetached(&.{ "/usr/bin/open", url })) return .launched;
            if (spawnDetached(&.{ "open", url })) return .launched;
        },
        .linux => {
            if (spawnDetached(&.{ "xdg-open", url })) return .launched;
            if (spawnDetached(&.{ "gio", "open", url })) return .launched;
            if (spawnDetached(&.{ "sensible-browser", url })) return .launched;
            if (spawnDetached(&.{ "gnome-open", url })) return .launched;
            if (spawnDetached(&.{ "kde-open", url })) return .launched;
            if (spawnDetached(&.{ "kde-open5", url })) return .launched;
            if (spawnDetached(&.{ "firefox", url })) return .launched;
            if (spawnDetached(&.{ "google-chrome", url })) return .launched;
            if (spawnDetached(&.{ "chromium", url })) return .launched;
            if (spawnDetached(&.{ "brave-browser", url })) return .launched;
        },
        .windows => {
            if (spawnDetached(&.{ "rundll32.exe", "url.dll,FileProtocolHandler", url })) return .launched;
            if (spawnDetached(&.{ "cmd.exe", "/c", "start", "", url })) return .launched;
        },
        else => {},
    }
    return .unavailable;
}

fn isLoopbackRedirect(redirect_uri: []const u8) bool {
    return std.mem.startsWith(u8, redirect_uri, "http://127.0.0.1:") or std.mem.startsWith(u8, redirect_uri, "http://localhost:");
}

fn waitForLoopbackCode(allocator: std.mem.Allocator, redirect_uri: []const u8, expected_state: []const u8) ![]u8 {
    const result = try std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "python3", "-c", loopbackCallbackScript(), redirect_uri, expected_state }, .max_output_bytes = 4096 });
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0 or std.mem.trim(u8, result.stdout, "\r\n\t ").len == 0) {
            allocator.free(result.stdout);
            return error.LoopbackCallbackFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.LoopbackCallbackFailed;
        },
    }
    const code = try allocator.dupe(u8, std.mem.trim(u8, result.stdout, "\r\n\t "));
    allocator.free(result.stdout);
    return code;
}

fn loopbackCallbackScript() []const u8 {
    return "import sys, urllib.parse, http.server\n" ++
        "u = urllib.parse.urlparse(sys.argv[1])\nstate = sys.argv[2]\n" ++
        "class H(http.server.BaseHTTPRequestHandler):\n" ++
        "  def do_GET(self):\n" ++
        "    q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)\n" ++
        "    code = q.get('code', [None])[0]\n" ++
        "    got = q.get('state', [None])[0]\n" ++
        "    ok = code and (got == state)\n" ++
        "    self.send_response(200 if ok else 400)\n    self.end_headers()\n" ++
        "    self.wfile.write((b'Login complete, return to ugrant.' if ok else b'Invalid OAuth callback.'))\n" ++
        "    if ok: print(code)\n" ++
        "  def log_message(self, *args):\n    pass\n" ++
        "srv = http.server.ThreadingHTTPServer((u.hostname, u.port), H)\n" ++
        "srv.timeout = 90\nend = __import__('time').time() + 90\n" ++
        "while __import__('time').time() < end:\n  srv.handle_request()\n  break\n";
}

fn waitForLoopbackOrManualCode(allocator: std.mem.Allocator, redirect_uri: []const u8, expected_state: []const u8, allow_unsafe_bare_code: bool, out: *std.Io.Writer) ![]u8 {
    var child = std.process.Child.init(&.{ "python3", "-c", loopbackCallbackScript(), redirect_uri, expected_state }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    errdefer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    if (allow_unsafe_bare_code) {
        try out.print("Waiting up to 90s for localhost callback on {s}.\nYou can also paste the redirect URL or final code now, whichever is faster: ", .{redirect_uri});
    } else {
        try out.print("Waiting up to 90s for localhost callback on {s}.\nYou can also paste the full redirect URL now if you want to skip the wait: ", .{redirect_uri});
    }
    try out.flush();

    var stdin_buf: [4096]u8 = undefined;
    var stdin_len: usize = 0;
    var callback_buf: [4096]u8 = undefined;
    var callback_len: usize = 0;
    const stdin_fd: c_int = @intCast(std.fs.File.stdin().handle);
    const callback_fd: c_int = @intCast(child.stdout.?.handle);
    var child_done = false;

    while (true) {
        var fds = [_]c.pollfd{
            .{ .fd = stdin_fd, .events = c.POLLIN, .revents = 0 },
            .{ .fd = if (child_done) -1 else callback_fd, .events = c.POLLIN, .revents = 0 },
        };
        const ready = c.poll(&fds, @intCast(fds.len), -1);
        if (ready < 0) return error.LoopbackCallbackFailed;

        if (!child_done and (fds[1].revents & c.POLLIN) != 0) {
            const n = try child.stdout.?.read(callback_buf[callback_len..]);
            if (n == 0) {
                child_done = true;
            } else {
                callback_len += n;
                const trimmed = std.mem.trim(u8, callback_buf[0..callback_len], "\r\n\t ");
                if (trimmed.len != 0 and std.mem.indexOfScalar(u8, callback_buf[0..callback_len], '\n') != null) {
                    _ = child.wait() catch {};
                    try out.writeAll("\nlocalhost callback received\n");
                    return allocator.dupe(u8, trimmed);
                }
            }
        }
        if (!child_done and (fds[1].revents & (c.POLLHUP | c.POLLERR | c.POLLNVAL)) != 0) {
            child_done = true;
            _ = child.wait() catch {};
            if (std.mem.trim(u8, callback_buf[0..callback_len], "\r\n\t ").len != 0) {
                try out.writeAll("\nlocalhost callback received\n");
                return allocator.dupe(u8, std.mem.trim(u8, callback_buf[0..callback_len], "\r\n\t "));
            }
        }

        if ((fds[0].revents & c.POLLIN) != 0) {
            const n = try std.fs.File.stdin().read(stdin_buf[stdin_len..]);
            if (n == 0) continue;
            stdin_len += n;
            if (std.mem.indexOfScalar(u8, stdin_buf[0..stdin_len], '\n') != null or std.mem.indexOfScalar(u8, stdin_buf[0..stdin_len], '\r') != null) {
                const pasted = try allocator.dupe(u8, std.mem.trimRight(u8, stdin_buf[0..stdin_len], "\r\n"));
                defer freeSecret(allocator, pasted);
                if (!child_done) {
                    _ = child.kill() catch {};
                    _ = child.wait() catch {};
                }
                try out.writeAll("\nmanual input received\n");
                return resolveManualCodeInput(allocator, pasted, expected_state, allow_unsafe_bare_code);
            }
        }
    }
}

fn runChildWithInput(allocator: std.mem.Allocator, argv: []const []const u8, input: []const u8, max_output_bytes: usize) !std.process.Child.RunResult {
    return runChildWithEnvAndInput(allocator, argv, null, input, max_output_bytes);
}

fn runChildWithEnvAndInput(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    env_map: ?*std.process.EnvMap,
    input: []const u8,
    max_output_bytes: usize,
) !std.process.Child.RunResult {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = env_map;

    var stdout = std.ArrayList(u8).empty;
    defer stdout.deinit(allocator);
    var stderr = std.ArrayList(u8).empty;
    defer stderr.deinit(allocator);

    try child.spawn();
    errdefer {
        _ = child.kill() catch {};
    }

    if (child.stdin) |*stdin_pipe| {
        try stdin_pipe.writeAll(input);
        stdin_pipe.close();
        child.stdin = null;
    }

    try child.collectOutput(allocator, &stdout, &stderr, max_output_bytes);
    return .{
        .stdout = try stdout.toOwnedSlice(allocator),
        .stderr = try stderr.toOwnedSlice(allocator),
        .term = try child.wait(),
    };
}

fn requestTokenResponse(allocator: std.mem.Allocator, token_url: []const u8, body_params: []const u8) ![]u8 {
    const script =
        "import sys, urllib.request, urllib.error\n" ++
        "url = sys.argv[1]\n" ++
        "body = sys.stdin.buffer.read()\n" ++
        "req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/x-www-form-urlencoded'})\n" ++
        "try:\n" ++
        "    with urllib.request.urlopen(req) as r:\n" ++
        "        sys.stdout.buffer.write(r.read())\n" ++
        "except urllib.error.HTTPError as e:\n" ++
        "    sys.stderr.buffer.write(e.read())\n" ++
        "    raise\n";
    const result = try runChildWithInput(allocator, &.{ "python3", "-c", script, token_url }, body_params, 1024 * 1024);
    allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code_int| if (code_int != 0) {
            allocator.free(result.stdout);
            return error.TokenExchangeFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.TokenExchangeFailed;
        },
    }
    return result.stdout;
}

fn parseTokenResponse(allocator: std.mem.Allocator, profile: ProfileRecord, response_body: []const u8) !TokenResponse {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response_body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    const access_token = try allocator.dupe(u8, obj.get("access_token").?.string);
    const refresh_token = if (obj.get("refresh_token")) |v| try allocator.dupe(u8, v.string) else null;
    const id_token = if (obj.get("id_token")) |v| try allocator.dupe(u8, v.string) else null;
    const token_type = if (obj.get("token_type")) |v| try allocator.dupe(u8, v.string) else null;
    const scope = if (obj.get("scope")) |v| try allocator.dupe(u8, v.string) else try allocator.dupe(u8, profile.scope);
    const expires_at = if (obj.get("expires_in")) |v| nowTs() + v.integer else null;
    const refresh_expires = if (obj.get("refresh_token_expires_in")) |v| nowTs() + v.integer else null;
    const subject_key = try inferSubjectKey(allocator, id_token, access_token);
    return .{ .access_token = access_token, .refresh_token = refresh_token, .id_token = id_token, .token_type = token_type, .scope = scope, .expires_at = expires_at, .refresh_token_expires_at = refresh_expires, .subject_key = subject_key };
}

fn exchangeToken(allocator: std.mem.Allocator, profile: ProfileRecord, code: []const u8, verifier: []const u8) !TokenResponse {
    var body = std.ArrayList(u8){};
    defer body.deinit(allocator);
    try body.appendSlice(allocator, "grant_type=authorization_code&code=");
    try appendUrlEscaped(allocator, &body, code);
    try body.appendSlice(allocator, "&client_id=");
    try appendUrlEscaped(allocator, &body, profile.client_id);
    try body.appendSlice(allocator, "&redirect_uri=");
    try appendUrlEscaped(allocator, &body, profile.redirect_uri);
    try body.appendSlice(allocator, "&code_verifier=");
    try appendUrlEscaped(allocator, &body, verifier);
    if (profile.client_secret) |secret| {
        try body.appendSlice(allocator, "&client_secret=");
        try appendUrlEscaped(allocator, &body, secret);
    }

    const response_body = try requestTokenResponse(allocator, profile.token_url, body.items);
    defer allocator.free(response_body);
    return parseTokenResponse(allocator, profile, response_body);
}

fn exchangeRefreshToken(allocator: std.mem.Allocator, profile: ProfileRecord, refresh_token: []const u8) !TokenResponse {
    var body = std.ArrayList(u8){};
    defer body.deinit(allocator);
    try body.appendSlice(allocator, "grant_type=refresh_token&refresh_token=");
    try appendUrlEscaped(allocator, &body, refresh_token);
    try body.appendSlice(allocator, "&client_id=");
    try appendUrlEscaped(allocator, &body, profile.client_id);
    if (profile.client_secret) |secret| {
        try body.appendSlice(allocator, "&client_secret=");
        try appendUrlEscaped(allocator, &body, secret);
    }

    const response_body = try requestTokenResponse(allocator, profile.token_url, body.items);
    defer allocator.free(response_body);
    return parseTokenResponse(allocator, profile, response_body);
}

fn inferSubjectKey(allocator: std.mem.Allocator, id_token: ?[]const u8, access_token: []const u8) !?[]u8 {
    if (id_token) |jwt| {
        const maybe = try jwtClaim(allocator, jwt, "sub");
        if (maybe != null) return maybe;
        return jwtClaim(allocator, jwt, "email");
    }
    if (std.mem.indexOfScalar(u8, access_token, '.')) |_| {}
    return null;
}

fn jwtClaim(allocator: std.mem.Allocator, jwt: []const u8, field: []const u8) !?[]u8 {
    var it = std.mem.splitScalar(u8, jwt, '.');
    _ = it.next();
    const payload = it.next() orelse return null;
    const decoded = try base64UrlDecodeAlloc(allocator, payload);
    defer allocator.free(decoded);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, decoded, .{});
    defer parsed.deinit();
    if (parsed.value.object.get(field)) |v| return try allocator.dupe(u8, v.string);
    return null;
}

fn base64UrlDecodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var norm = std.ArrayList(u8){};
    defer norm.deinit(allocator);
    for (text) |ch| switch (ch) {
        '-' => try norm.append(allocator, '+'),
        '_' => try norm.append(allocator, '/'),
        else => try norm.append(allocator, ch),
    };
    while (norm.items.len % 4 != 0) try norm.append(allocator, '=');
    return b64DecodeAlloc(allocator, norm.items);
}

fn freeTokenResponse(allocator: std.mem.Allocator, token: TokenResponse) void {
    allocator.free(token.access_token);
    if (token.refresh_token) |v| allocator.free(v);
    if (token.id_token) |v| allocator.free(v);
    if (token.token_type) |v| allocator.free(v);
    if (token.scope) |v| allocator.free(v);
    if (token.subject_key) |v| allocator.free(v);
}

fn persistGrantTokenResponse(allocator: std.mem.Allocator, db: *c.sqlite3, dek: []const u8, profile: ProfileRecord, prior_grant: GrantRecord, token: TokenResponse) !void {
    const subject_key = token.subject_key orelse prior_grant.subject_key;
    const refresh_plain = token.refresh_token orelse prior_grant.refresh_token;
    const id_plain = token.id_token orelse prior_grant.id_token;
    const scope_value = token.scope orelse prior_grant.scope;
    const token_type_value = token.token_type orelse prior_grant.token_type;
    const refresh_expires = token.refresh_token_expires_at orelse prior_grant.refresh_token_expires_at;

    const enc_access = try encryptField(allocator, dek, "grants", "access_token", profile.name, subject_key, token.access_token);
    defer allocator.free(enc_access);
    const enc_refresh = if (refresh_plain) |value| try encryptField(allocator, dek, "grants", "refresh_token", profile.name, subject_key, value) else null;
    defer if (enc_refresh) |value| allocator.free(value);
    const enc_id = if (id_plain) |value| try encryptField(allocator, dek, "grants", "id_token", profile.name, subject_key, value) else null;
    defer if (enc_id) |value| allocator.free(value);

    try execSql(db, "BEGIN IMMEDIATE;");
    errdefer execSql(db, "ROLLBACK;") catch {};

    const sql =
        "UPDATE grants SET provider=?1, subject_key=?2, token_type=?3, scope=?4, state=?5, expires_at=?6, refresh_token_expires_at=?7, access_token_enc=?8, refresh_token_enc=?9, id_token_enc=?10, refresh_started_at=NULL, refresh_owner=NULL, refresh_error=NULL, updated_at=unixepoch() WHERE profile_name=?11";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile.provider);
    try bindText(stmt.?, 2, subject_key);
    try bindNullableText(stmt.?, 3, token_type_value);
    try bindNullableText(stmt.?, 4, scope_value);
    try bindText(stmt.?, 5, "access_token_valid");
    try bindNullableInt(stmt.?, 6, token.expires_at);
    try bindNullableInt(stmt.?, 7, refresh_expires);
    try bindText(stmt.?, 8, enc_access);
    try bindNullableText(stmt.?, 9, enc_refresh);
    try bindNullableText(stmt.?, 10, enc_id);
    try bindText(stmt.?, 11, profile.name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(db);
    try execSql(db, "COMMIT;");
}

fn persistRefreshFailure(db: *c.sqlite3, profile_name: []const u8) !void {
    const sql =
        "UPDATE grants SET state='refresh_failed', refresh_started_at=NULL, refresh_owner=NULL, updated_at=unixepoch() WHERE profile_name=?1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile_name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(db);
}

fn loadRefreshLeaseStatus(allocator: std.mem.Allocator, db: *c.sqlite3, profile_name: []const u8) !RefreshLeaseStatus {
    const sql = "SELECT state, expires_at, refresh_token_enc IS NOT NULL, refresh_started_at FROM grants WHERE profile_name=?1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile_name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return error.GrantNotFound;
    return .{
        .state = try dupeColumnText(allocator, stmt.?, 0),
        .expires_at = nullableIntColumn(stmt.?, 1),
        .has_refresh_token = c.sqlite3_column_int(stmt.?, 2) != 0,
        .refresh_started_at = nullableIntColumn(stmt.?, 3),
    };
}

fn freeRefreshLeaseStatus(allocator: std.mem.Allocator, status: RefreshLeaseStatus) void {
    allocator.free(status.state);
}

fn tryAcquireRefreshLease(db: *c.sqlite3, profile_name: []const u8, lease_timeout_seconds: i64) !bool {
    try execSql(db, "BEGIN IMMEDIATE;");
    errdefer execSql(db, "ROLLBACK;") catch {};
    const sql =
        "UPDATE grants SET state='refresh_in_progress', refresh_started_at=unixepoch(), refresh_owner='local', refresh_error=NULL, updated_at=unixepoch() " ++
        "WHERE profile_name=?1 AND state!='revoked' AND refresh_token_enc IS NOT NULL AND (state!='refresh_in_progress' OR refresh_started_at IS NULL OR refresh_started_at <= unixepoch() - ?2)";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile_name);
    try bindInt(stmt.?, 2, lease_timeout_seconds);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(db);
    const acquired = c.sqlite3_changes(db) > 0;
    try execSql(db, if (acquired) "COMMIT;" else "ROLLBACK;");
    return acquired;
}

fn loadUsableGrant(allocator: std.mem.Allocator, db: *c.sqlite3, dek: []const u8, profile: ProfileRecord, storage: StorageConfig) !GrantRecord {
    const deadline = nowTs() + storage.max_wait_seconds;
    while (true) {
        const grant = try loadGrant(allocator, db, profile.name, dek);
        ensureGrantUsable(grant) catch |err| switch (err) {
            error.AccessTokenStale => {
                if (grant.refresh_token == null) {
                    freeGrant(allocator, grant);
                    return err;
                }
                if (try tryAcquireRefreshLease(db, profile.name, storage.lease_timeout_seconds)) {
                    const refresh_token = try allocator.dupe(u8, grant.refresh_token.?);
                    defer allocator.free(refresh_token);
                    errdefer persistRefreshFailure(db, profile.name) catch {};
                    const refreshed = try exchangeRefreshToken(allocator, profile, refresh_token);
                    defer freeTokenResponse(allocator, refreshed);
                    try persistGrantTokenResponse(allocator, db, dek, profile, grant, refreshed);
                    freeGrant(allocator, grant);
                    continue;
                }

                freeGrant(allocator, grant);
                while (true) {
                    if (nowTs() >= deadline) return error.RefreshWaitTimeout;
                    const status = try loadRefreshLeaseStatus(allocator, db, profile.name);
                    defer freeRefreshLeaseStatus(allocator, status);
                    const runtime_state = runtimeGrantState(status.state, status.expires_at);
                    if (std.mem.eql(u8, runtime_state, "access_token_valid")) break;
                    if (std.mem.eql(u8, runtime_state, "refresh_failed")) return error.TokenExchangeFailed;
                    if (!status.has_refresh_token) return error.AccessTokenStale;
                    if (std.mem.eql(u8, runtime_state, "refresh_in_progress")) {
                        if (status.refresh_started_at) |started_at| {
                            if (started_at + storage.lease_timeout_seconds < nowTs()) break;
                        } else break;
                    }
                    std.Thread.sleep(storage.poll_interval_ms * std.time.ns_per_ms);
                }
                continue;
            },
            else => {
                freeGrant(allocator, grant);
                return err;
            },
        };
        return grant;
    }
}

fn ensureGrantUsable(grant: GrantRecord) !void {
    if (std.mem.eql(u8, grant.state, "revoked")) return error.GrantRevoked;
    if (grant.access_token == null) return error.NoAccessToken;
    if (grant.expires_at) |ts| if (ts <= nowTs()) return error.AccessTokenStale;
}

fn resolveEnv(allocator: std.mem.Allocator, profile_name: []const u8) ![]EnvVar {
    const paths = try resolvePaths(allocator);
    defer paths.deinit(allocator);
    try requireInitialized(paths);
    const storage = try loadStorageConfig(allocator, paths.config_path);
    const wrapped = try loadWrappedDek(allocator, paths.keys_path);
    defer freeWrappedDekRecord(allocator, wrapped);
    const dek = try unwrapDek(allocator, wrapped);
    defer allocator.free(dek);
    const db = try openDb(paths.db_path);
    defer _ = c.sqlite3_close(db);
    const profile = try loadProfile(allocator, db, profile_name);
    defer freeProfile(allocator, profile);
    const grant = try loadUsableGrant(allocator, db, dek, profile, storage);
    defer freeGrant(allocator, grant);

    return env_runtime.buildEnv(allocator, profile, grant);
}

fn loadGrant(allocator: std.mem.Allocator, db: *c.sqlite3, profile_name: []const u8, dek: []const u8) !GrantRecord {
    const sql = "SELECT profile_name, provider, subject_key, token_type, scope, state, expires_at, refresh_token_expires_at, access_token_enc, refresh_token_enc, id_token_enc, granted_at, updated_at FROM grants WHERE profile_name=?1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile_name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return error.GrantNotFound;
    const subject = try dupeColumnText(allocator, stmt.?, 2);
    const access_enc = try dupeNullableColumnText(allocator, stmt.?, 8);
    const refresh_enc = try dupeNullableColumnText(allocator, stmt.?, 9);
    const id_enc = try dupeNullableColumnText(allocator, stmt.?, 10);
    const access = if (access_enc) |enc| try decryptField(allocator, dek, "grants", "access_token", profile_name, subject, enc) else null;
    const refresh = if (refresh_enc) |enc| try decryptField(allocator, dek, "grants", "refresh_token", profile_name, subject, enc) else null;
    const idt = if (id_enc) |enc| try decryptField(allocator, dek, "grants", "id_token", profile_name, subject, enc) else null;
    defer if (access_enc) |v| allocator.free(v);
    defer if (refresh_enc) |v| allocator.free(v);
    defer if (id_enc) |v| allocator.free(v);
    return .{
        .profile_name = try dupeColumnText(allocator, stmt.?, 0),
        .provider = try dupeColumnText(allocator, stmt.?, 1),
        .subject_key = subject,
        .token_type = try dupeNullableColumnText(allocator, stmt.?, 3),
        .scope = try dupeNullableColumnText(allocator, stmt.?, 4),
        .state = try dupeColumnText(allocator, stmt.?, 5),
        .expires_at = nullableIntColumn(stmt.?, 6),
        .refresh_token_expires_at = nullableIntColumn(stmt.?, 7),
        .access_token = access,
        .refresh_token = refresh,
        .id_token = idt,
        .granted_at = c.sqlite3_column_int64(stmt.?, 11),
        .updated_at = c.sqlite3_column_int64(stmt.?, 12),
    };
}

fn freeGrant(allocator: std.mem.Allocator, grant: GrantRecord) void {
    allocator.free(grant.profile_name);
    allocator.free(grant.provider);
    allocator.free(grant.subject_key);
    if (grant.token_type) |v| allocator.free(v);
    if (grant.scope) |v| allocator.free(v);
    allocator.free(grant.state);
    if (grant.access_token) |v| allocator.free(v);
    if (grant.refresh_token) |v| allocator.free(v);
    if (grant.id_token) |v| allocator.free(v);
}

fn loadGrantStatus(allocator: std.mem.Allocator, db: *c.sqlite3, profile_name: []const u8) !?GrantStatusRecord {
    const sql = "SELECT provider, subject_key, scope, state, expires_at FROM grants WHERE profile_name=?1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile_name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return null;
    return .{
        .provider = try dupeColumnText(allocator, stmt.?, 0),
        .subject_key = try dupeColumnText(allocator, stmt.?, 1),
        .scope = try dupeNullableColumnText(allocator, stmt.?, 2),
        .state = try dupeColumnText(allocator, stmt.?, 3),
        .expires_at = nullableIntColumn(stmt.?, 4),
    };
}

fn loadProfileList(allocator: std.mem.Allocator, db: *c.sqlite3) ![]ProfileListRecord {
    const sql = "SELECT name, provider, env_kind, base_url, model FROM profiles ORDER BY name";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);

    var profiles = std.ArrayList(ProfileListRecord){};
    errdefer {
        for (profiles.items) |profile| {
            allocator.free(profile.name);
            allocator.free(profile.provider);
            allocator.free(profile.env_kind);
            if (profile.base_url) |base_url| allocator.free(base_url);
            if (profile.model) |model| allocator.free(model);
        }
        profiles.deinit(allocator);
    }

    while (true) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return sqliteErr(db);
        try profiles.append(allocator, .{
            .name = try dupeColumnText(allocator, stmt.?, 0),
            .provider = try dupeColumnText(allocator, stmt.?, 1),
            .env_kind = try dupeColumnText(allocator, stmt.?, 2),
            .base_url = try dupeNullableColumnText(allocator, stmt.?, 3),
            .model = try dupeNullableColumnText(allocator, stmt.?, 4),
        });
    }

    return profiles.toOwnedSlice(allocator);
}

fn freeProfileList(allocator: std.mem.Allocator, profiles: []ProfileListRecord) void {
    for (profiles) |profile| {
        allocator.free(profile.name);
        allocator.free(profile.provider);
        allocator.free(profile.env_kind);
        if (profile.base_url) |base_url| allocator.free(base_url);
        if (profile.model) |model| allocator.free(model);
    }
    allocator.free(profiles);
}

fn dupeColumnText(allocator: std.mem.Allocator, stmt: *c.sqlite3_stmt, idx: c_int) ![]const u8 {
    const ptr = c.sqlite3_column_text(stmt, idx);
    const len = c.sqlite3_column_bytes(stmt, idx);
    return allocator.dupe(u8, @as([*]const u8, @ptrCast(ptr))[0..@intCast(len)]);
}
fn dupeNullableColumnText(allocator: std.mem.Allocator, stmt: *c.sqlite3_stmt, idx: c_int) !?[]const u8 {
    if (c.sqlite3_column_type(stmt, idx) == c.SQLITE_NULL) return null;
    return try dupeColumnText(allocator, stmt, idx);
}
fn nullableIntColumn(stmt: *c.sqlite3_stmt, idx: c_int) ?i64 {
    if (c.sqlite3_column_type(stmt, idx) == c.SQLITE_NULL) return null;
    return c.sqlite3_column_int64(stmt, idx);
}

fn collectStatusSummary(allocator: std.mem.Allocator, paths: Paths) !StatusSummary {
    const initialized = (try fileExists(paths.db_path)) and (try fileExists(paths.keys_path));
    var backend: ?[]const u8 = null;
    var backend_provider: ?[]const u8 = null;
    var secure_enclave = false;
    var user_presence_required: ?bool = null;
    var security_mode: []const u8 = "uninitialized";
    var profile_count: usize = 0;
    var grant_count: usize = 0;
    var grant_state: []const u8 = "uninitialized";
    if (initialized) {
        const wrapped = try loadWrappedDek(allocator, paths.keys_path);
        defer freeWrappedDekRecord(allocator, wrapped);
        const metadata = backendMetadata(wrapped.backend, wrapped.secret_ref, wrapped.require_user_presence);
        backend = try allocator.dupe(u8, wrapped.backend);
        if (metadata.provider) |provider| {
            backend_provider = try allocator.dupe(u8, provider);
        }
        secure_enclave = metadata.secure_enclave;
        user_presence_required = metadata.user_presence_required;
        security_mode = if (std.mem.eql(u8, wrapped.backend, "insecure-keyfile") or wrapped.kdf == null) "degraded" else "normal";
        const db = try openDb(paths.db_path);
        defer _ = c.sqlite3_close(db);
        profile_count = try countRows(db, "profiles");
        grant_count = try countRows(db, "grants");
        grant_state = try overallGrantState(db);
    }
    return .{
        .initialized = initialized,
        .config_path = try allocator.dupe(u8, paths.config_path),
        .state_dir = try allocator.dupe(u8, paths.state_dir),
        .db_path = try allocator.dupe(u8, paths.db_path),
        .keys_path = try allocator.dupe(u8, paths.keys_path),
        .backend = backend,
        .backend_provider = backend_provider,
        .secure_enclave = secure_enclave,
        .user_presence_required = user_presence_required,
        .security_mode = try allocator.dupe(u8, security_mode),
        .profile_count = profile_count,
        .grant_count = grant_count,
        .grant_state = try allocator.dupe(u8, grant_state),
    };
}

fn overallGrantState(db: *c.sqlite3) ![]const u8 {
    const sql =
        "SELECT CASE " ++
        "WHEN COUNT(*) = 0 THEN 'authorized_no_access_token' " ++
        "WHEN SUM(CASE WHEN state='revoked' THEN 1 ELSE 0 END) = COUNT(*) THEN 'revoked' " ++
        "WHEN SUM(CASE WHEN state='refresh_failed' THEN 1 ELSE 0 END) > 0 THEN 'refresh_failed' " ++
        "WHEN SUM(CASE WHEN state='refresh_in_progress' THEN 1 ELSE 0 END) > 0 THEN 'refresh_in_progress' " ++
        "WHEN SUM(CASE WHEN state='access_token_valid' AND expires_at IS NOT NULL AND expires_at <= unixepoch() THEN 1 ELSE 0 END) = COUNT(*) THEN 'access_token_stale' " ++
        "WHEN SUM(CASE WHEN state='access_token_valid' AND (expires_at IS NULL OR expires_at > unixepoch()) THEN 1 ELSE 0 END) = COUNT(*) THEN 'access_token_valid' " ++
        "ELSE 'mixed' END FROM grants";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return error.SqliteFailure;
    const state = try dupeColumnText(std.heap.page_allocator, stmt.?, 0);
    defer std.heap.page_allocator.free(state);
    if (std.mem.eql(u8, state, "revoked")) return "revoked";
    if (std.mem.eql(u8, state, "refresh_failed")) return "refresh_failed";
    if (std.mem.eql(u8, state, "refresh_in_progress")) return "refresh_in_progress";
    if (std.mem.eql(u8, state, "access_token_stale")) return "access_token_stale";
    if (std.mem.eql(u8, state, "access_token_valid")) return "access_token_valid";
    if (std.mem.eql(u8, state, "mixed")) return "mixed";
    return "authorized_no_access_token";
}

fn countRows(db: *c.sqlite3, table: []const u8) !usize {
    const sql = try std.fmt.allocPrint(std.heap.page_allocator, "SELECT COUNT(*) FROM {s}", .{table});
    defer std.heap.page_allocator.free(sql);
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return error.SqliteFailure;
    return @as(usize, @intCast(c.sqlite3_column_int64(stmt.?, 0)));
}

test "loopback redirect detection is limited to localhost" {
    try std.testing.expect(isLoopbackRedirect("http://127.0.0.1:8788/callback"));
    try std.testing.expect(isLoopbackRedirect("http://localhost:8788/callback"));
    try std.testing.expect(!isLoopbackRedirect("urn:ietf:wg:oauth:2.0:oob"));
    try std.testing.expect(!isLoopbackRedirect("https://example.com/callback"));
}

test "redirect extraction enforces oauth state" {
    const allocator = std.testing.allocator;
    const code = try extractCodeFromRedirect(allocator, "http://127.0.0.1:8788/callback?code=abc123&state=match-me", "match-me");
    defer freeSecret(allocator, code);
    try std.testing.expectEqualStrings("abc123", code);

    try std.testing.expectError(error.InvalidOAuthState, extractCodeFromRedirect(allocator, "http://127.0.0.1:8788/callback?code=abc123&state=wrong", "match-me"));
}

test "wrapped dek metadata round trips optional backend fields" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const keys_path = try std.fs.path.join(allocator, &.{ base, "keys.json" });
    defer allocator.free(keys_path);
    const record = WrappedDekRecord{ .version = 3, .backend = try allocator.dupe(u8, "platform-secure-store"), .key_version = 4, .salt_b64 = try allocator.dupe(u8, "salt"), .nonce_b64 = try allocator.dupe(u8, "nonce"), .ciphertext_b64 = try allocator.dupe(u8, "cipher"), .created_at = try allocator.dupe(u8, "123"), .kdf = try allocator.dupe(u8, argon2_kdf_name), .kdf_t = argon2_params.t, .kdf_m = argon2_params.m, .kdf_p = argon2_params.p, .secret_ref = try allocator.dupe(u8, "ref-1"), .tpm2_pub_b64 = try allocator.dupe(u8, "pub"), .tpm2_priv_b64 = try allocator.dupe(u8, "priv"), .secure_enclave_ephemeral_pub_b64 = try allocator.dupe(u8, "ephemeral-pub"), .require_user_presence = false };
    defer freeWrappedDekRecord(allocator, record);
    try saveWrappedDek(keys_path, record);
    const loaded = try loadWrappedDek(allocator, keys_path);
    defer freeWrappedDekRecord(allocator, loaded);
    try std.testing.expectEqualStrings("platform-secure-store", loaded.backend);
    try std.testing.expectEqualStrings(argon2_kdf_name, loaded.kdf.?);
    try std.testing.expectEqualStrings("ref-1", loaded.secret_ref.?);
    try std.testing.expectEqualStrings("pub", loaded.tpm2_pub_b64.?);
    try std.testing.expectEqualStrings("priv", loaded.tpm2_priv_b64.?);
    try std.testing.expectEqualStrings("ephemeral-pub", loaded.secure_enclave_ephemeral_pub_b64.?);
    try std.testing.expectEqual(false, loaded.require_user_presence.?);
}

test "windows platform secure store round trips via DPAPI" {
    if (builtin.os.tag != .windows or envTruthy("UGRANT_TEST_PLATFORM_STORE_AVAILABLE")) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const keys_path = try std.fs.path.join(allocator, &.{ base, "keys.json" });
    defer allocator.free(keys_path);

    const created = try platformStoreWrapSecret(allocator, keys_path, 1, null);
    defer freeWrapSecret(allocator, created);
    try std.testing.expect(created.secret_ref != null);

    const record = WrappedDekRecord{
        .version = 3,
        .backend = try allocator.dupe(u8, "platform-secure-store"),
        .key_version = 1,
        .salt_b64 = try allocator.dupe(u8, "salt"),
        .nonce_b64 = try allocator.dupe(u8, "nonce"),
        .ciphertext_b64 = try allocator.dupe(u8, "cipher"),
        .created_at = try allocator.dupe(u8, "123"),
        .secret_ref = try allocator.dupe(u8, created.secret_ref.?),
    };
    defer freeWrappedDekRecord(allocator, record);

    const loaded = try platformStoreWrapSecret(allocator, null, record.key_version, record);
    defer freeWrapSecret(allocator, loaded);
    try std.testing.expectEqualStrings(created.secret, loaded.secret);
    try std.testing.expectEqualStrings(created.secret_ref.?, loaded.secret_ref.?);
}

test "windows prompt fallback trims CRLF from redirected input" {
    if (builtin.os.tag != .windows) return;

    try std.testing.expectEqualStrings("hunter2", trimPromptInput("hunter2\r\n"));
    try std.testing.expectEqualStrings("hunter2", trimPromptInput("hunter2\n"));
    try std.testing.expectEqualStrings("", trimPromptInput("\r\n"));
}

test "macos keychain secret refs are strict and versioned" {
    const allocator = std.testing.allocator;

    const secret_ref = try formatMacOsKeychainSecretRef(allocator, 7);
    defer allocator.free(secret_ref);
    const account = try formatMacOsKeychainAccount(allocator, 7);
    defer allocator.free(account);
    const label = try formatMacOsKeychainLabel(allocator, 7);
    defer allocator.free(label);

    const parsed = try parseMacOsKeychainSecretRef(secret_ref);
    try std.testing.expectEqualStrings(macos_keychain_service, parsed.service);
    try std.testing.expectEqualStrings(account, parsed.account);
    try std.testing.expectEqual(@as(u32, 7), parsed.key_version);
    try std.testing.expectEqualStrings("ugrant DEK wrap secret (7)", label);

    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsKeychainSecretRef("macos-keychain:service=wrong;account=dek:7"));
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsKeychainSecretRef("macos-keychain:service=dev.ugrant.platform-secure-store;account=wrong:7"));
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsKeychainSecretRef("macos-keychain:service=dev.ugrant.platform-secure-store;account=dek:"));
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsKeychainSecretRef("macos-keychain:service=dev.ugrant.platform-secure-store;account=dek:7;extra=x"));
}

test "macos keychain records reject malformed refs and version mismatches" {
    const allocator = std.testing.allocator;

    var record = WrappedDekRecord{
        .version = 3,
        .backend = try allocator.dupe(u8, "platform-secure-store"),
        .key_version = 4,
        .salt_b64 = try allocator.dupe(u8, "salt"),
        .nonce_b64 = try allocator.dupe(u8, "nonce"),
        .ciphertext_b64 = try allocator.dupe(u8, "cipher"),
        .created_at = try allocator.dupe(u8, "123"),
        .secret_ref = try formatMacOsKeychainSecretRef(allocator, 4),
    };
    defer freeWrappedDekRecord(allocator, record);

    const parsed = try validateMacOsKeychainRecord(record);
    try std.testing.expectEqualStrings("dek:4", parsed.account);
    try std.testing.expectEqual(@as(u32, 4), parsed.key_version);

    record.key_version = 5;
    try std.testing.expectError(error.InvalidWrappedDek, validateMacOsKeychainRecord(record));
    record.key_version = 4;

    allocator.free(record.secret_ref.?);
    record.secret_ref = try allocator.dupe(u8, "macos-keychain:service=dev.ugrant.platform-secure-store;account=dek:");
    try std.testing.expectError(error.InvalidWrappedDek, validateMacOsKeychainRecord(record));
}

test "macos keychain secret refs reject malformed prefixes and numeric versions" {
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsKeychainSecretRef("secret-service:service=dev.ugrant.platform-secure-store;account=dek:7"));
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsKeychainSecretRef("macos-keychain:service=dev.ugrant.platform-secure-storeaccount=dek:7"));
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsKeychainSecretRef("macos-keychain:service=dev.ugrant.platform-secure-store;account=dek:seven"));
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsKeychainSecretRef("macos-keychain:service=dev.ugrant.platform-secure-store;account=dek:4294967296"));
}

test "macos secure enclave secret refs are strict and versioned" {
    const parsed = try parseMacOsSecureEnclaveSecretRef("macos-ctk-secure-enclave:label=dev.ugrant.secure-enclave.dek:9;hash=test-hash");
    try std.testing.expectEqualStrings("dev.ugrant.secure-enclave.dek:9", parsed.label);
    try std.testing.expectEqual(@as(u32, 9), parsed.key_version);

    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsSecureEnclaveSecretRef("macos-ctk-secure-enclave:label=wrong:9;hash=test-hash"));
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsSecureEnclaveSecretRef("macos-ctk-secure-enclave:label=dev.ugrant.secure-enclave.dek:;hash=test-hash"));
    try std.testing.expectError(error.InvalidWrappedDek, parseMacOsSecureEnclaveSecretRef("macos-ctk-secure-enclave:label=dev.ugrant.secure-enclave.dek:9"));
}

test "macos secure enclave helper failure reasons parse from structured JSON" {
    const allocator = std.testing.allocator;

    const cancelled = parseMacOsSecureEnclaveFailureFromJson(allocator, "{\"reason\":\"user_cancelled\",\"message\":\"cancelled\"}").?;
    defer freeMacOsSecureEnclaveFailure(allocator, cancelled);
    try std.testing.expectEqual(MacOsSecureEnclaveFailureReason.user_cancelled, cancelled.reason);

    const key_missing = parseMacOsSecureEnclaveFailureFromJson(allocator, "{\"reason\":\"key_missing\"}").?;
    defer freeMacOsSecureEnclaveFailure(allocator, key_missing);
    try std.testing.expectEqual(MacOsSecureEnclaveFailureReason.key_missing, key_missing.reason);

    const access_denied = parseMacOsSecureEnclaveFailureFromJson(allocator, "{\"reason\":\"access_denied\"}").?;
    defer freeMacOsSecureEnclaveFailure(allocator, access_denied);
    try std.testing.expectEqual(MacOsSecureEnclaveFailureReason.access_denied, access_denied.reason);

    const unavailable = parseMacOsSecureEnclaveFailureFromJson(allocator, "{\"reason\":\"unavailable\"}").?;
    defer freeMacOsSecureEnclaveFailure(allocator, unavailable);
    try std.testing.expectEqual(MacOsSecureEnclaveFailureReason.unavailable, unavailable.reason);

    try std.testing.expect(parseMacOsSecureEnclaveFailureFromJson(allocator, "{\"reason\":\"mystery\"}") == null);
    try std.testing.expect(parseMacOsSecureEnclaveFailureFromJson(allocator, "not json") == null);
}

test "doctor secure enclave failure messages stay specific" {
    try std.testing.expectEqualStrings(
        "doctor: macOS Secure Enclave user-presence prompt was cancelled\n",
        macOsSecureEnclaveDoctorFailureMessage(.user_cancelled),
    );
    try std.testing.expectEqualStrings(
        "doctor: macOS Secure Enclave key is missing\n",
        macOsSecureEnclaveDoctorFailureMessage(.key_missing),
    );
    try std.testing.expectEqualStrings(
        "doctor: macOS Secure Enclave key is inaccessible (access denied)\n",
        macOsSecureEnclaveDoctorFailureMessage(.access_denied),
    );
    try std.testing.expectEqualStrings(
        "doctor: macOS Secure Enclave is unavailable or unsupported on this system\n",
        macOsSecureEnclaveDoctorFailureMessage(.unavailable),
    );
}

test "platform secure store provider label matches the local OS" {
    const provider = backendProviderLabel("platform-secure-store", null).?;

    switch (builtin.os.tag) {
        .macos => try std.testing.expectEqualStrings("macOS Keychain", provider),
        .windows => try std.testing.expectEqualStrings("Windows DPAPI", provider),
        else => try std.testing.expectEqualStrings("Secret Service", provider),
    }

    try std.testing.expect(backendProviderLabel("tpm2", null) == null);
    try std.testing.expect(backendProviderLabel("passphrase", null) == null);
    try std.testing.expect(backendProviderLabel("insecure-keyfile", null) == null);
}

test "secure enclave records report secure enclave backend provider" {
    try std.testing.expectEqualStrings("macOS Secure Enclave", backendProviderLabel("macos-secure-enclave", "macos-ctk-secure-enclave:label=dev.ugrant.secure-enclave.dek:3;hash=test-hash").?);
}

test "backend metadata lines include secure enclave state and user presence" {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);

    var writer = out.writer(allocator);
    try writeBackendMetadataLines(&writer, backendMetadata("macos-secure-enclave", "macos-ctk-secure-enclave:label=dev.ugrant.secure-enclave.dek:3;hash=test-hash", true), "previous_");

    const rendered = try out.toOwnedSlice(allocator);
    defer allocator.free(rendered);
    try std.testing.expectEqualStrings(
        "previous_backend_provider: macOS Secure Enclave\n" ++
            "previous_secure_enclave: yes\n" ++
            "previous_user_presence_required: yes\n",
        rendered,
    );
}

test "status summary reports secure enclave metadata" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    var dek: [dek_len]u8 = [_]u8{0x42} ** dek_len;
    const wrapped = try wrapDekForBackend(allocator, "macos-secure-enclave", 2, "secure-enclave-wrap-secret", &dek, .{
        .secret = @constCast("secure-enclave-wrap-secret"),
        .secret_ref = "macos-ctk-secure-enclave:label=dev.ugrant.secure-enclave.dek:2;hash=test-hash",
        .secure_enclave_ephemeral_pub_b64 = "ZXBoZW1lcmFsLXB1Yg==",
        .require_user_presence = true,
    });
    defer freeWrappedDekRecord(allocator, wrapped);
    try saveWrappedDek(vault.keys_path, wrapped);

    const config_path = try std.fs.path.join(allocator, &.{ vault.base_path, "config.toml" });
    const state_dir = try allocator.dupe(u8, vault.base_path);
    const db_path = try allocator.dupe(u8, vault.db_path);
    const keys_path = try allocator.dupe(u8, vault.keys_path);
    const paths = Paths{
        .config_path = config_path,
        .state_dir = state_dir,
        .db_path = db_path,
        .keys_path = keys_path,
    };
    defer paths.deinit(allocator);

    const summary = try collectStatusSummary(allocator, paths);
    defer freeStatusSummary(allocator, summary);

    try std.testing.expect(summary.initialized);
    try std.testing.expectEqualStrings("macos-secure-enclave", summary.backend.?);
    try std.testing.expectEqualStrings("macOS Secure Enclave", summary.backend_provider.?);
    try std.testing.expect(summary.secure_enclave);
    try std.testing.expectEqual(true, summary.user_presence_required.?);
    try std.testing.expectEqual(@as(usize, 1), summary.profile_count);
    try std.testing.expectEqual(@as(usize, 1), summary.grant_count);
}

test "explicit secure enclave wrap never falls back to plain platform store" {
    if (builtin.os.tag == .macos or envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE")) return;

    try std.testing.expectError(error.WrapBackendUnavailable, createMacOsSecureEnclaveSecret(std.testing.allocator, 7, true));
}

test "init keeps freshly created secure enclave secret in process" {
    if (!envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE")) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const keys_path = try std.fs.path.join(allocator, &.{ base, "keys.json" });
    defer allocator.free(keys_path);

    const state = try initOrLoadKeys(allocator, keys_path, "macos-secure-enclave", false, .{ .secure_enclave = true });
    defer state.deinit(allocator);

    try std.testing.expectEqualStrings("macos-secure-enclave", state.wrapped.backend);
    try std.testing.expect(state.dek != null);
    try std.testing.expect(state.wrapped.secret_ref != null);
    try std.testing.expect(state.wrapped.secure_enclave_ephemeral_pub_b64 != null);
}

test "secure enclave wraps and unwraps via synthetic provider" {
    if (!envTruthy("UGRANT_TEST_SECURE_ENCLAVE_AVAILABLE")) return;

    const allocator = std.testing.allocator;
    const created = try createMacOsSecureEnclaveSecret(allocator, 5, true);
    defer freeWrapSecret(allocator, created);
    defer deleteMacOsSecureEnclaveSecret(allocator, created.secret_ref.?) catch {};
    try std.testing.expect(isMacOsSecureEnclaveSecretRef(created.secret_ref.?));
    try std.testing.expect(created.require_user_presence);
    try std.testing.expect(created.secure_enclave_ephemeral_pub_b64 != null);

    const parsed = try parseMacOsSecureEnclaveSecretRef(created.secret_ref.?);
    const blob_path = try secureEnclaveTestBlobPathForTag(allocator, parsed.label);
    defer allocator.free(blob_path);
    try std.testing.expect(try fileExists(blob_path));

    const blob = try loadSecureEnclaveTestBlob(allocator, parsed.label);
    defer freeSecureEnclaveLocalWrapBlob(allocator, blob);
    try std.testing.expectEqual(@as(u32, secure_enclave_local_wrap_blob_version), blob.version);
    try std.testing.expectEqualStrings(created.secure_enclave_ephemeral_pub_b64.?, blob.ephemeral_pub_b64);
    try std.testing.expect(blob.ciphertext_b64.len > 0);

    var dek: [dek_len]u8 = [_]u8{0x5a} ** dek_len;
    const record = try wrapDekForBackend(allocator, "macos-secure-enclave", 5, created.secret, &dek, created);
    defer freeWrappedDekRecord(allocator, record);
    try std.testing.expectEqualStrings(hkdf_sha256_kdf_name, record.kdf.?);
    try std.testing.expectEqual(true, record.require_user_presence.?);
    try std.testing.expect(record.secure_enclave_ephemeral_pub_b64 != null);

    const loaded = try loadMacOsSecureEnclaveSecret(allocator, record.secret_ref.?, record.key_version, record.secure_enclave_ephemeral_pub_b64.?, record.require_user_presence orelse false);
    defer freeWrapSecret(allocator, loaded);
    try std.testing.expectEqualStrings(created.secret, loaded.secret);

    const unwrapped = try unwrapDekWithSecret(allocator, record, loaded.secret);
    defer freeSecret(allocator, unwrapped);
    try std.testing.expectEqualSlices(u8, &dek, unwrapped);
}

test "legacy wrapped dek records remain readable" {
    const allocator = std.testing.allocator;
    var salt: [kdf_salt_len]u8 = [_]u8{0x11} ** kdf_salt_len;
    var nonce: [gcm_nonce_len]u8 = [_]u8{0x22} ** gcm_nonce_len;
    var dek: [dek_len]u8 = [_]u8{0x33} ** dek_len;
    var key: [dek_len]u8 = undefined;
    deriveLegacyWrapKey(&key, "legacy-passphrase", &salt);
    var ct: [dek_len]u8 = undefined;
    var tag: [gcm_tag_len]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(&ct, &tag, &dek, "ugrant-dek-wrap", nonce, key);
    var combined: [dek_len + gcm_tag_len]u8 = undefined;
    @memcpy(combined[0..dek_len], &ct);
    @memcpy(combined[dek_len..], &tag);

    const record = WrappedDekRecord{
        .version = 2,
        .backend = try allocator.dupe(u8, "passphrase"),
        .key_version = 1,
        .salt_b64 = try b64EncodeAlloc(allocator, &salt),
        .nonce_b64 = try b64EncodeAlloc(allocator, &nonce),
        .ciphertext_b64 = try b64EncodeAlloc(allocator, &combined),
        .created_at = try allocator.dupe(u8, "123"),
    };
    defer freeWrappedDekRecord(allocator, record);

    const unwrapped = try unwrapDekWithSecret(allocator, record, "legacy-passphrase");
    defer freeSecret(allocator, unwrapped);
    try std.testing.expectEqualSlices(u8, &dek, unwrapped);
    try std.testing.expect(record.kdf == null);
}

const TestVault = struct {
    tmp: std.testing.TmpDir,
    base_path: []const u8,
    db_path: []const u8,
    keys_path: []const u8,
    db: *c.sqlite3,
    wrapped: WrappedDekRecord,
    dek: []u8,

    fn deinit(self: *TestVault, allocator: std.mem.Allocator) void {
        _ = c.sqlite3_close(self.db);
        freeWrappedDekRecord(allocator, self.wrapped);
        allocator.free(self.dek);
        allocator.free(self.base_path);
        allocator.free(self.db_path);
        allocator.free(self.keys_path);
        self.tmp.cleanup();
    }
};

const RawGrantCipher = struct {
    access_token_enc: ?[]const u8,
    refresh_token_enc: ?[]const u8,
    id_token_enc: ?[]const u8,
};

fn setupTestVault() !TestVault {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    const base_path = try tmp.dir.realpathAlloc(allocator, ".");
    errdefer allocator.free(base_path);
    const db_path = try std.fs.path.join(allocator, &.{ base_path, db_filename });
    errdefer allocator.free(db_path);
    const keys_path = try std.fs.path.join(allocator, &.{ base_path, keys_filename });
    errdefer allocator.free(keys_path);

    const db = try openDb(db_path);
    errdefer _ = c.sqlite3_close(db);
    try ensureSchema(db);

    var dek_buf: [dek_len]u8 = undefined;
    for (&dek_buf, 0..) |*byte, idx| byte.* = @as(u8, @intCast(idx + 1));
    const wrap_secret = "insecure-local-keyfile";
    const wrapped = try wrapDekForBackend(allocator, "insecure-keyfile", 1, wrap_secret, &dek_buf, .{ .secret = @constCast(wrap_secret) });
    errdefer freeWrappedDekRecord(allocator, wrapped);
    try saveWrappedDek(keys_path, wrapped);
    const dek = try unwrapDekWithSecret(allocator, wrapped, wrap_secret);
    errdefer allocator.free(dek);

    try seedTestProfileAndGrant(allocator, db, dek);
    return .{
        .tmp = tmp,
        .base_path = base_path,
        .db_path = db_path,
        .keys_path = keys_path,
        .db = db,
        .wrapped = wrapped,
        .dek = dek,
    };
}

fn seedTestProfileAndGrant(allocator: std.mem.Allocator, db: *c.sqlite3, dek: []const u8) !void {
    const profile_secret = try encryptField(allocator, dek, "profiles", "client_secret", "watcher", "_", "client-secret-xyz");
    defer allocator.free(profile_secret);
    const access_token = try encryptField(allocator, dek, "grants", "access_token", "watcher", "subject-123", "access-token-abc");
    defer allocator.free(access_token);
    const refresh_token = try encryptField(allocator, dek, "grants", "refresh_token", "watcher", "subject-123", "refresh-token-def");
    defer allocator.free(refresh_token);
    const id_token = try encryptField(allocator, dek, "grants", "id_token", "watcher", "subject-123", "id-token-ghi");
    defer allocator.free(id_token);

    const profile_sql =
        "INSERT INTO profiles(name, provider, auth_url, token_url, client_id, scope, redirect_uri, env_kind, base_url, model, audience, client_secret_enc, created_at, updated_at) " ++
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, unixepoch(), unixepoch())";
    var profile_stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, profile_sql.ptr, @as(c_int, @intCast(profile_sql.len)), &profile_stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(profile_stmt);
    try bindText(profile_stmt.?, 1, "watcher");
    try bindText(profile_stmt.?, 2, "openai");
    try bindText(profile_stmt.?, 3, "https://auth.example.com/authorize");
    try bindText(profile_stmt.?, 4, "https://auth.example.com/token");
    try bindText(profile_stmt.?, 5, "client-id-123");
    try bindText(profile_stmt.?, 6, "openid profile offline_access");
    try bindText(profile_stmt.?, 7, default_redirect_uri);
    try bindText(profile_stmt.?, 8, "openai");
    try bindText(profile_stmt.?, 9, "https://api.example.com/v1");
    try bindText(profile_stmt.?, 10, "gpt-test");
    try bindNullableText(profile_stmt.?, 11, null);
    try bindText(profile_stmt.?, 12, profile_secret);
    if (c.sqlite3_step(profile_stmt.?) != c.SQLITE_DONE) return sqliteErr(db);

    const grant_sql =
        "INSERT INTO grants(profile_name, provider, subject_key, token_type, scope, state, expires_at, refresh_token_expires_at, access_token_enc, refresh_token_enc, id_token_enc, granted_at, updated_at) " ++
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, unixepoch(), unixepoch())";
    var grant_stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, grant_sql.ptr, @as(c_int, @intCast(grant_sql.len)), &grant_stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(grant_stmt);
    try bindText(grant_stmt.?, 1, "watcher");
    try bindText(grant_stmt.?, 2, "openai");
    try bindText(grant_stmt.?, 3, "subject-123");
    try bindText(grant_stmt.?, 4, "Bearer");
    try bindText(grant_stmt.?, 5, "openid profile offline_access");
    try bindText(grant_stmt.?, 6, "access_token_valid");
    try bindNullableInt(grant_stmt.?, 7, nowTs() + 3600);
    try bindNullableInt(grant_stmt.?, 8, nowTs() + 7200);
    try bindText(grant_stmt.?, 9, access_token);
    try bindText(grant_stmt.?, 10, refresh_token);
    try bindText(grant_stmt.?, 11, id_token);
    if (c.sqlite3_step(grant_stmt.?) != c.SQLITE_DONE) return sqliteErr(db);
}

fn loadRawProfileSecret(allocator: std.mem.Allocator, db: *c.sqlite3, name: []const u8) ![]const u8 {
    const sql = "SELECT client_secret_enc FROM profiles WHERE name=?1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return error.ProfileNotFound;
    return dupeColumnText(allocator, stmt.?, 0);
}

fn loadRawGrantCipher(allocator: std.mem.Allocator, db: *c.sqlite3, profile_name: []const u8) !RawGrantCipher {
    const sql = "SELECT access_token_enc, refresh_token_enc, id_token_enc FROM grants WHERE profile_name=?1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, @as(c_int, @intCast(sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, profile_name);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return error.GrantNotFound;
    return .{
        .access_token_enc = try dupeNullableColumnText(allocator, stmt.?, 0),
        .refresh_token_enc = try dupeNullableColumnText(allocator, stmt.?, 1),
        .id_token_enc = try dupeNullableColumnText(allocator, stmt.?, 2),
    };
}

fn freeRawGrantCipher(allocator: std.mem.Allocator, row: RawGrantCipher) void {
    if (row.access_token_enc) |v| allocator.free(v);
    if (row.refresh_token_enc) |v| allocator.free(v);
    if (row.id_token_enc) |v| allocator.free(v);
}

test "revoke clears local grant secrets and marks status revoked" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    try std.testing.expect(try revokeGrantState(vault.db, "watcher"));

    const grant = try loadGrant(allocator, vault.db, "watcher", vault.dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("revoked", grant.state);
    try std.testing.expect(grant.access_token == null);
    try std.testing.expect(grant.refresh_token == null);
    try std.testing.expect(grant.id_token == null);
    try std.testing.expect(grant.expires_at == null);
    try std.testing.expect(grant.refresh_token_expires_at == null);
    try std.testing.expectError(error.GrantRevoked, ensureGrantUsable(grant));

    const status = (try loadGrantStatus(allocator, vault.db, "watcher")).?;
    defer freeGrantStatus(allocator, status);
    try std.testing.expectEqualStrings("revoked", status.state);
    try std.testing.expectEqualStrings("revoked", try overallGrantState(vault.db));
}

test "rekey rotates DEK and re-encrypts stored secret fields" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    const profile_before = try loadRawProfileSecret(allocator, vault.db, "watcher");
    defer allocator.free(profile_before);
    const grant_before = try loadRawGrantCipher(allocator, vault.db, "watcher");
    defer freeRawGrantCipher(allocator, grant_before);

    const stats = try performRekey(allocator, vault.db, vault.keys_path, vault.wrapped, "insecure-local-keyfile", "insecure-keyfile", "insecure-local-keyfile", null, null, null, null, false);
    try std.testing.expectEqual(@as(u32, 2), stats.key_version);
    try std.testing.expectEqual(@as(usize, 1), stats.profiles_rewritten);
    try std.testing.expectEqual(@as(usize, 1), stats.grants_rewritten);

    const updated_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, updated_record);
    const new_dek = try unwrapDekWithSecret(allocator, updated_record, "insecure-local-keyfile");
    defer allocator.free(new_dek);
    try std.testing.expect(!std.mem.eql(u8, vault.dek, new_dek));

    const profile_after = try loadRawProfileSecret(allocator, vault.db, "watcher");
    defer allocator.free(profile_after);
    const grant_after = try loadRawGrantCipher(allocator, vault.db, "watcher");
    defer freeRawGrantCipher(allocator, grant_after);
    try std.testing.expect(!std.mem.eql(u8, profile_before, profile_after));
    try std.testing.expect(!std.mem.eql(u8, grant_before.access_token_enc.?, grant_after.access_token_enc.?));
    try std.testing.expect(!std.mem.eql(u8, grant_before.refresh_token_enc.?, grant_after.refresh_token_enc.?));
    try std.testing.expect(!std.mem.eql(u8, grant_before.id_token_enc.?, grant_after.id_token_enc.?));

    const client_secret = try decryptField(allocator, new_dek, "profiles", "client_secret", "watcher", "_", profile_after);
    defer allocator.free(client_secret);
    try std.testing.expectEqualStrings("client-secret-xyz", client_secret);
    try std.testing.expectError(error.DecryptFailed, decryptField(allocator, vault.dek, "profiles", "client_secret", "watcher", "_", profile_after));

    const grant = try loadGrant(allocator, vault.db, "watcher", new_dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("access-token-abc", grant.access_token.?);
    try std.testing.expectEqualStrings("refresh-token-def", grant.refresh_token.?);
    try std.testing.expectEqualStrings("id-token-ghi", grant.id_token.?);
    try std.testing.expectEqualStrings("access_token_valid", grant.state);

    const status = (try loadGrantStatus(allocator, vault.db, "watcher")).?;
    defer freeGrantStatus(allocator, status);
    try std.testing.expectEqualStrings("openai", status.provider);
    try std.testing.expectEqualStrings("subject-123", status.subject_key);
    try std.testing.expectEqualStrings("openid profile offline_access", status.scope.?);
}

test "rekey can switch from insecure-keyfile to passphrase backend" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    const profile_before = try loadRawProfileSecret(allocator, vault.db, "watcher");
    defer allocator.free(profile_before);
    const grant_before = try loadRawGrantCipher(allocator, vault.db, "watcher");
    defer freeRawGrantCipher(allocator, grant_before);

    const stats = try performRekey(allocator, vault.db, vault.keys_path, vault.wrapped, "insecure-local-keyfile", "passphrase", "switch-passphrase", null, null, null, null, false);
    try std.testing.expectEqual(@as(u32, 2), stats.key_version);

    const updated_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, updated_record);
    try std.testing.expectEqualStrings("passphrase", updated_record.backend);

    const new_dek = try unwrapDekWithSecret(allocator, updated_record, "switch-passphrase");
    defer allocator.free(new_dek);
    try std.testing.expect(!std.mem.eql(u8, vault.dek, new_dek));

    const profile_after = try loadRawProfileSecret(allocator, vault.db, "watcher");
    defer allocator.free(profile_after);
    const grant_after = try loadRawGrantCipher(allocator, vault.db, "watcher");
    defer freeRawGrantCipher(allocator, grant_after);
    try std.testing.expect(!std.mem.eql(u8, profile_before, profile_after));
    try std.testing.expect(!std.mem.eql(u8, grant_before.access_token_enc.?, grant_after.access_token_enc.?));

    const client_secret = try decryptField(allocator, new_dek, "profiles", "client_secret", "watcher", "_", profile_after);
    defer allocator.free(client_secret);
    try std.testing.expectEqualStrings("client-secret-xyz", client_secret);
    try std.testing.expectError(error.DecryptFailed, decryptField(allocator, vault.dek, "profiles", "client_secret", "watcher", "_", profile_after));

    const grant = try loadGrant(allocator, vault.db, "watcher", new_dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("access-token-abc", grant.access_token.?);
    try std.testing.expectEqualStrings("refresh-token-def", grant.refresh_token.?);
    try std.testing.expectEqualStrings("id-token-ghi", grant.id_token.?);

    const status = (try loadGrantStatus(allocator, vault.db, "watcher")).?;
    defer freeGrantStatus(allocator, status);
    try std.testing.expectEqualStrings("openai", status.provider);
    try std.testing.expectEqualStrings("subject-123", status.subject_key);
    try std.testing.expectEqualStrings("openid profile offline_access", status.scope.?);
}

test "rekey can switch from passphrase to insecure-keyfile backend" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    _ = try performRekey(allocator, vault.db, vault.keys_path, vault.wrapped, "insecure-local-keyfile", "passphrase", "switch-passphrase", null, null, null, null, false);
    const passphrase_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, passphrase_record);
    const passphrase_dek = try unwrapDekWithSecret(allocator, passphrase_record, "switch-passphrase");
    defer allocator.free(passphrase_dek);

    const profile_before = try loadRawProfileSecret(allocator, vault.db, "watcher");
    defer allocator.free(profile_before);
    const grant_before = try loadRawGrantCipher(allocator, vault.db, "watcher");
    defer freeRawGrantCipher(allocator, grant_before);

    const stats = try performRekey(allocator, vault.db, vault.keys_path, passphrase_record, "switch-passphrase", "insecure-keyfile", "insecure-local-keyfile", null, null, null, null, false);
    try std.testing.expectEqual(@as(u32, 3), stats.key_version);

    const updated_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, updated_record);
    try std.testing.expectEqualStrings("insecure-keyfile", updated_record.backend);

    const new_dek = try unwrapDekWithSecret(allocator, updated_record, "insecure-local-keyfile");
    defer allocator.free(new_dek);
    try std.testing.expect(!std.mem.eql(u8, passphrase_dek, new_dek));

    const profile_after = try loadRawProfileSecret(allocator, vault.db, "watcher");
    defer allocator.free(profile_after);
    const grant_after = try loadRawGrantCipher(allocator, vault.db, "watcher");
    defer freeRawGrantCipher(allocator, grant_after);
    try std.testing.expect(!std.mem.eql(u8, profile_before, profile_after));
    try std.testing.expect(!std.mem.eql(u8, grant_before.access_token_enc.?, grant_after.access_token_enc.?));

    const client_secret = try decryptField(allocator, new_dek, "profiles", "client_secret", "watcher", "_", profile_after);
    defer allocator.free(client_secret);
    try std.testing.expectEqualStrings("client-secret-xyz", client_secret);
    try std.testing.expectError(error.DecryptFailed, decryptField(allocator, passphrase_dek, "profiles", "client_secret", "watcher", "_", profile_after));

    const grant = try loadGrant(allocator, vault.db, "watcher", new_dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("access-token-abc", grant.access_token.?);
    try std.testing.expectEqualStrings("refresh-token-def", grant.refresh_token.?);
    try std.testing.expectEqualStrings("id-token-ghi", grant.id_token.?);

    const status = (try loadGrantStatus(allocator, vault.db, "watcher")).?;
    defer freeGrantStatus(allocator, status);
    try std.testing.expectEqualStrings("openai", status.provider);
    try std.testing.expectEqualStrings("subject-123", status.subject_key);
    try std.testing.expectEqualStrings("openid profile offline_access", status.scope.?);
}

test "rekey can switch from insecure-keyfile to resolved platform-secure-store backend" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    const target_backend = try resolveBackendChoice("platform-secure-store", false, true, true, false);
    const target_secret_ref: ?[]const u8 = if (std.mem.eql(u8, target_backend, "platform-secure-store")) "platform-ref-1" else null;
    const target_tpm2_pub: ?[]const u8 = if (std.mem.eql(u8, target_backend, "tpm2")) "dHBtMi1wdWI=" else null;
    const target_tpm2_priv: ?[]const u8 = if (std.mem.eql(u8, target_backend, "tpm2")) "dHBtMi1wcml2" else null;
    const stats = try performRekey(allocator, vault.db, vault.keys_path, vault.wrapped, "insecure-local-keyfile", target_backend, "tpm2-test-secret", target_secret_ref, target_tpm2_pub, target_tpm2_priv, null, false);
    try std.testing.expectEqual(@as(u32, 2), stats.key_version);

    const updated_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, updated_record);
    try std.testing.expectEqualStrings(target_backend, updated_record.backend);
    if (std.mem.eql(u8, target_backend, "tpm2")) {
        try std.testing.expectEqualStrings("dHBtMi1wdWI=", updated_record.tpm2_pub_b64.?);
        try std.testing.expectEqualStrings("dHBtMi1wcml2", updated_record.tpm2_priv_b64.?);
    } else {
        try std.testing.expectEqualStrings("platform-ref-1", updated_record.secret_ref.?);
        try std.testing.expect(updated_record.tpm2_pub_b64 == null);
        try std.testing.expect(updated_record.tpm2_priv_b64 == null);
    }

    const new_dek = try unwrapDekWithSecret(allocator, updated_record, "tpm2-test-secret");
    defer allocator.free(new_dek);
    const grant = try loadGrant(allocator, vault.db, "watcher", new_dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("access-token-abc", grant.access_token.?);
}

test "rekey can switch from tpm2 to platform secure store" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    _ = try performRekey(allocator, vault.db, vault.keys_path, vault.wrapped, "insecure-local-keyfile", "tpm2", "tpm2-test-secret", null, "dHBtMi1wdWI=", "dHBtMi1wcml2", null, false);
    const tpm2_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, tpm2_record);
    const tpm2_dek = try unwrapDekWithSecret(allocator, tpm2_record, "tpm2-test-secret");
    defer allocator.free(tpm2_dek);

    const stats = try performRekey(allocator, vault.db, vault.keys_path, tpm2_record, "tpm2-test-secret", "platform-secure-store", "platform-store-test-secret", "platform-ref-1", null, null, null, false);
    try std.testing.expectEqual(@as(u32, 3), stats.key_version);

    const updated_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, updated_record);
    try std.testing.expectEqualStrings("platform-secure-store", updated_record.backend);
    try std.testing.expectEqualStrings("platform-ref-1", updated_record.secret_ref.?);

    const new_dek = try unwrapDekWithSecret(allocator, updated_record, "platform-store-test-secret");
    defer allocator.free(new_dek);
    try std.testing.expect(!std.mem.eql(u8, tpm2_dek, new_dek));

    const grant = try loadGrant(allocator, vault.db, "watcher", new_dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("refresh-token-def", grant.refresh_token.?);
}

test "rekey can switch between secure enclave and plain platform store metadata" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    const secure_stats = try performRekey(
        allocator,
        vault.db,
        vault.keys_path,
        vault.wrapped,
        "insecure-local-keyfile",
        "macos-secure-enclave",
        "secure-enclave-wrap-secret",
        "macos-ctk-secure-enclave:label=dev.ugrant.secure-enclave.dek:2;hash=test-hash",
        null,
        null,
        "ZXBoZW1lcmFsLXB1Yg==",
        true,
    );
    try std.testing.expectEqual(@as(u32, 2), secure_stats.key_version);

    const secure_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, secure_record);
    try std.testing.expect(isMacOsSecureEnclaveRecord(secure_record));
    try std.testing.expectEqualStrings("macos-secure-enclave", secure_record.backend);
    try std.testing.expectEqualStrings(hkdf_sha256_kdf_name, secure_record.kdf.?);
    try std.testing.expectEqual(true, secure_record.require_user_presence.?);
    try std.testing.expectEqualStrings("ZXBoZW1lcmFsLXB1Yg==", secure_record.secure_enclave_ephemeral_pub_b64.?);

    const plain_stats = try performRekey(
        allocator,
        vault.db,
        vault.keys_path,
        secure_record,
        "secure-enclave-wrap-secret",
        "platform-secure-store",
        "platform-store-test-secret",
        "macos-keychain:service=dev.ugrant.platform-secure-store;account=dek:3",
        null,
        null,
        null,
        false,
    );
    try std.testing.expectEqual(@as(u32, 3), plain_stats.key_version);

    const updated_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, updated_record);
    try std.testing.expectEqualStrings("platform-secure-store", updated_record.backend);
    try std.testing.expect(!isMacOsSecureEnclaveRecord(updated_record));
    try std.testing.expectEqualStrings(argon2_kdf_name, updated_record.kdf.?);
    try std.testing.expectEqualStrings("macos-keychain:service=dev.ugrant.platform-secure-store;account=dek:3", updated_record.secret_ref.?);
    try std.testing.expect(updated_record.secure_enclave_ephemeral_pub_b64 == null);
    try std.testing.expect(updated_record.require_user_presence == null);

    const new_dek = try unwrapDekWithSecret(allocator, updated_record, "platform-store-test-secret");
    defer allocator.free(new_dek);
    const grant = try loadGrant(allocator, vault.db, "watcher", new_dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("access-token-abc", grant.access_token.?);
    try std.testing.expectEqualStrings("refresh-token-def", grant.refresh_token.?);
}

test "rekey can migrate passphrase-backed state to macos keychain metadata" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    _ = try performRekey(allocator, vault.db, vault.keys_path, vault.wrapped, "insecure-local-keyfile", "passphrase", "switch-passphrase", null, null, null, null, false);
    const passphrase_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, passphrase_record);
    const passphrase_dek = try unwrapDekWithSecret(allocator, passphrase_record, "switch-passphrase");
    defer allocator.free(passphrase_dek);

    const secret_ref = try formatMacOsKeychainSecretRef(allocator, passphrase_record.key_version + 1);
    defer allocator.free(secret_ref);

    const stats = try performRekey(allocator, vault.db, vault.keys_path, passphrase_record, "switch-passphrase", "platform-secure-store", "platform-store-test-secret", secret_ref, null, null, null, false);
    try std.testing.expectEqual(@as(u32, 3), stats.key_version);

    const updated_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, updated_record);
    try std.testing.expectEqualStrings("platform-secure-store", updated_record.backend);
    try std.testing.expectEqualStrings(secret_ref, updated_record.secret_ref.?);

    const parsed = try validateMacOsKeychainRecord(updated_record);
    try std.testing.expectEqualStrings(macos_keychain_service, parsed.service);
    try std.testing.expectEqualStrings("dek:3", parsed.account);
    try std.testing.expectEqual(@as(u32, 3), parsed.key_version);

    const new_dek = try unwrapDekWithSecret(allocator, updated_record, "platform-store-test-secret");
    defer allocator.free(new_dek);
    try std.testing.expect(!std.mem.eql(u8, passphrase_dek, new_dek));

    const grant = try loadGrant(allocator, vault.db, "watcher", new_dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("access-token-abc", grant.access_token.?);
    try std.testing.expectEqualStrings("refresh-token-def", grant.refresh_token.?);
    try std.testing.expectEqualStrings("id-token-ghi", grant.id_token.?);
}

test "macos platform secure store hook supports rekey migration" {
    if (builtin.os.tag != .macos or !envTruthy("UGRANT_TEST_PLATFORM_STORE_AVAILABLE")) return;

    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    const created = try platformStoreWrapSecret(allocator, vault.keys_path, 2, null);
    defer freeWrapSecret(allocator, created);
    try std.testing.expectEqualStrings("macos-keychain:service=dev.ugrant.platform-secure-store;account=dek:2", created.secret_ref.?);

    const stats = try performRekey(allocator, vault.db, vault.keys_path, vault.wrapped, "insecure-local-keyfile", "platform-secure-store", created.secret, created.secret_ref, null, null, null, false);
    try std.testing.expectEqual(@as(u32, 2), stats.key_version);

    const updated_record = try loadWrappedDek(allocator, vault.keys_path);
    defer freeWrappedDekRecord(allocator, updated_record);
    try std.testing.expectEqualStrings("platform-secure-store", updated_record.backend);
    try std.testing.expectEqual(@as(u32, 2), updated_record.key_version);
    try std.testing.expectEqualStrings(created.secret_ref.?, updated_record.secret_ref.?);

    const loaded = try platformStoreWrapSecret(allocator, null, updated_record.key_version, updated_record);
    defer freeWrapSecret(allocator, loaded);
    try std.testing.expectEqualStrings(created.secret, loaded.secret);
    try std.testing.expectEqualStrings(created.secret_ref.?, loaded.secret_ref.?);

    const new_dek = try unwrapDek(allocator, updated_record);
    defer allocator.free(new_dek);
    try std.testing.expect(!std.mem.eql(u8, vault.dek, new_dek));

    const grant = try loadGrant(allocator, vault.db, "watcher", new_dek);
    defer freeGrant(allocator, grant);
    try std.testing.expectEqualStrings("access-token-abc", grant.access_token.?);
    try std.testing.expectEqualStrings("refresh-token-def", grant.refresh_token.?);
}

test "profile list returns safe metadata ordered by name" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    const second_profile_sql =
        "INSERT INTO profiles(name, provider, auth_url, token_url, client_id, scope, redirect_uri, env_kind, base_url, model, audience, client_secret_enc, created_at, updated_at) " ++
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL, ?9, unixepoch(), unixepoch())";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(vault.db, second_profile_sql.ptr, @as(c_int, @intCast(second_profile_sql.len)), &stmt, null) != c.SQLITE_OK) return sqliteErr(vault.db);
    defer _ = c.sqlite3_finalize(stmt);
    try bindText(stmt.?, 1, "alpha");
    try bindText(stmt.?, 2, "google");
    try bindText(stmt.?, 3, "https://accounts.google.com/o/oauth2/v2/auth");
    try bindText(stmt.?, 4, "https://oauth2.googleapis.com/token");
    try bindText(stmt.?, 5, "client-id-456");
    try bindText(stmt.?, 6, "openid email profile");
    try bindText(stmt.?, 7, default_redirect_uri);
    try bindText(stmt.?, 8, "google-imap");
    try bindNullableText(stmt.?, 9, null);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return sqliteErr(vault.db);

    const profiles = try loadProfileList(allocator, vault.db);
    defer freeProfileList(allocator, profiles);

    try std.testing.expectEqual(@as(usize, 2), profiles.len);
    try std.testing.expectEqualStrings("alpha", profiles[0].name);
    try std.testing.expectEqualStrings("google", profiles[0].provider);
    try std.testing.expectEqualStrings("google-imap", profiles[0].env_kind);
    try std.testing.expect(profiles[0].base_url == null);
    try std.testing.expect(profiles[0].model == null);

    try std.testing.expectEqualStrings("watcher", profiles[1].name);
    try std.testing.expectEqualStrings("openai", profiles[1].provider);
    try std.testing.expectEqualStrings("openai", profiles[1].env_kind);
    try std.testing.expectEqualStrings("https://api.example.com/v1", profiles[1].base_url.?);
    try std.testing.expectEqualStrings("gpt-test", profiles[1].model.?);
}

test "runtime grant state marks expired valid grants stale" {
    try std.testing.expectEqualStrings("access_token_stale", runtimeGrantState("access_token_valid", nowTs() - 1));
    try std.testing.expectEqualStrings("access_token_valid", runtimeGrantState("access_token_valid", nowTs() + 3600));
    try std.testing.expectEqualStrings("revoked", runtimeGrantState("revoked", null));
}

test "refresh lease acquisition is singleton and expires" {
    var vault = try setupTestVault();
    defer vault.deinit(std.testing.allocator);

    try execSql(vault.db, "UPDATE grants SET expires_at=unixepoch()-10, state='access_token_valid'");

    try std.testing.expect(try tryAcquireRefreshLease(vault.db, "watcher", 30));
    try std.testing.expect(!(try tryAcquireRefreshLease(vault.db, "watcher", 30)));

    const status = try loadRefreshLeaseStatus(std.testing.allocator, vault.db, "watcher");
    defer freeRefreshLeaseStatus(std.testing.allocator, status);
    try std.testing.expectEqualStrings("refresh_in_progress", status.state);

    try execSql(vault.db, "UPDATE grants SET refresh_started_at=unixepoch()-31");
    try std.testing.expect(try tryAcquireRefreshLease(vault.db, "watcher", 30));
}

test "refresh failure is visible in status aggregation" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    try persistRefreshFailure(vault.db, "watcher");

    const status = (try loadGrantStatus(allocator, vault.db, "watcher")).?;
    defer freeGrantStatus(allocator, status);
    try std.testing.expectEqualStrings("refresh_failed", runtimeGrantState(status.state, status.expires_at));
    try std.testing.expectEqualStrings("refresh_failed", try overallGrantState(vault.db));
}

test "refresh persistence preserves prior refresh token when provider omits one" {
    const allocator = std.testing.allocator;
    var vault = try setupTestVault();
    defer vault.deinit(allocator);

    const profile = ProfileRecord{
        .name = "watcher",
        .provider = "openai",
        .auth_url = "",
        .token_url = "",
        .client_id = "",
        .scope = "openid profile offline_access",
        .redirect_uri = "",
        .env_kind = "openai",
        .base_url = null,
        .model = null,
        .audience = null,
        .client_secret = null,
    };
    const grant_before = try loadGrant(allocator, vault.db, "watcher", vault.dek);
    defer freeGrant(allocator, grant_before);

    const refreshed = TokenResponse{
        .access_token = try allocator.dupe(u8, "access-token-new"),
        .refresh_token = null,
        .id_token = null,
        .token_type = null,
        .scope = try allocator.dupe(u8, "openid profile offline_access"),
        .expires_at = nowTs() + 3600,
        .refresh_token_expires_at = null,
        .subject_key = null,
    };
    defer freeTokenResponse(allocator, refreshed);

    try persistGrantTokenResponse(allocator, vault.db, vault.dek, profile, grant_before, refreshed);

    const grant_after = try loadGrant(allocator, vault.db, "watcher", vault.dek);
    defer freeGrant(allocator, grant_after);
    try std.testing.expectEqualStrings("access-token-new", grant_after.access_token.?);
    try std.testing.expectEqualStrings("refresh-token-def", grant_after.refresh_token.?);
    try std.testing.expectEqualStrings("id-token-ghi", grant_after.id_token.?);
}
