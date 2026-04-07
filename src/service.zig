const std = @import("std");

pub const default_redirect_uri = "http://127.0.0.1:8788/callback";

pub const ServicePreset = struct {
    key: []const u8,
    aliases: []const []const u8,
    provider: []const u8,
    auth_url: []const u8,
    token_url: []const u8,
    scope: []const u8,
    redirect_uri: []const u8,
    env_kind: []const u8,
    base_url: ?[]const u8 = null,
    model: ?[]const u8 = null,
    audience: ?[]const u8 = null,
};

pub const ServiceDefinition = struct {
    provider: ?[]const u8 = null,
    auth_url: ?[]const u8 = null,
    token_url: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    redirect_uri: ?[]const u8 = null,
    env_kind: ?[]const u8 = null,
    base_url: ?[]const u8 = null,
    model: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    issuer: ?[]const u8 = null,
    discovery_url: ?[]const u8 = null,
};

const service_presets = [_]ServicePreset{
    .{
        .key = "google-imap",
        .aliases = &.{ "google", "gmail-imap", "imap-google" },
        .provider = "google",
        .auth_url = "https://accounts.google.com/o/oauth2/v2/auth",
        .token_url = "https://oauth2.googleapis.com/token",
        .scope = "https://mail.google.com/ openid email profile",
        .redirect_uri = default_redirect_uri,
        .env_kind = "google-imap",
    },
    .{
        .key = "openai",
        .aliases = &.{"openai-oidc"},
        .provider = "openai",
        .auth_url = "https://auth.openai.com/authorize",
        .token_url = "https://auth0.openai.com/oauth/token",
        .scope = "openid profile email offline_access",
        .redirect_uri = default_redirect_uri,
        .env_kind = "openai",
        .base_url = "https://api.openai.com/v1",
    },
};

pub fn mergeServiceDefinition(base: ServiceDefinition, overlay: ServiceDefinition) ServiceDefinition {
    var out = base;
    if (overlay.provider != null) out.provider = overlay.provider;
    if (overlay.auth_url != null) out.auth_url = overlay.auth_url;
    if (overlay.token_url != null) out.token_url = overlay.token_url;
    if (overlay.scope != null) out.scope = overlay.scope;
    if (overlay.redirect_uri != null) out.redirect_uri = overlay.redirect_uri;
    if (overlay.env_kind != null) out.env_kind = overlay.env_kind;
    if (overlay.base_url != null) out.base_url = overlay.base_url;
    if (overlay.model != null) out.model = overlay.model;
    if (overlay.audience != null) out.audience = overlay.audience;
    if (overlay.issuer != null) out.issuer = overlay.issuer;
    if (overlay.discovery_url != null) out.discovery_url = overlay.discovery_url;
    return out;
}

pub fn resolveServicePreset(name: []const u8) !ServiceDefinition {
    for (service_presets) |preset| {
        if (std.ascii.eqlIgnoreCase(name, preset.key)) return fromPreset(preset);
        for (preset.aliases) |alias| {
            if (std.ascii.eqlIgnoreCase(name, alias)) return fromPreset(preset);
        }
    }
    return error.UnknownServicePreset;
}

fn fromPreset(preset: ServicePreset) ServiceDefinition {
    return .{
        .provider = preset.provider,
        .auth_url = preset.auth_url,
        .token_url = preset.token_url,
        .scope = preset.scope,
        .redirect_uri = preset.redirect_uri,
        .env_kind = preset.env_kind,
        .base_url = preset.base_url,
        .model = preset.model,
        .audience = preset.audience,
    };
}

pub fn buildDiscoveryUrl(allocator: std.mem.Allocator, issuer_or_url: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, issuer_or_url, " \r\n\t/");
    if (std.mem.endsWith(u8, trimmed, ".well-known/openid-configuration")) {
        return allocator.dupe(u8, trimmed);
    }
    return std.fmt.allocPrint(allocator, "{s}/.well-known/openid-configuration", .{trimmed});
}

pub fn inferProviderFromUrl(url: []const u8) []const u8 {
    if (std.mem.indexOf(u8, url, "google")) |_| return "google";
    if (std.mem.indexOf(u8, url, "openai")) |_| return "openai";
    return "oidc";
}

pub fn inferEnvKind(provider: []const u8, issuer: ?[]const u8) []const u8 {
    if (std.mem.eql(u8, provider, "openai")) return "openai";
    if (issuer) |iss| {
        if (std.mem.indexOf(u8, iss, "openai")) |_| return "openai";
    }
    return "generic";
}

pub fn parseDiscoveredService(allocator: std.mem.Allocator, discovery_url: []const u8, document: []const u8) !ServiceDefinition {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, document, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    const issuer = if (obj.get("issuer")) |v| try allocator.dupe(u8, v.string) else null;
    const auth_url = if (obj.get("authorization_endpoint")) |v| try allocator.dupe(u8, v.string) else null;
    const token_url = if (obj.get("token_endpoint")) |v| try allocator.dupe(u8, v.string) else null;
    if (auth_url == null or token_url == null) return error.InvalidDiscoveryDocument;

    const provider = try allocator.dupe(u8, inferProviderFromUrl(issuer orelse discovery_url));
    const env_kind = try allocator.dupe(u8, inferEnvKind(provider, issuer));
    const base_url = if (std.mem.eql(u8, env_kind, "openai"))
        try allocator.dupe(u8, "https://api.openai.com/v1")
    else
        null;
    const scope = if (std.mem.eql(u8, provider, "openai"))
        try allocator.dupe(u8, "openid profile email offline_access")
    else
        null;

    return .{
        .provider = provider,
        .auth_url = auth_url,
        .token_url = token_url,
        .scope = scope,
        .redirect_uri = default_redirect_uri,
        .env_kind = env_kind,
        .base_url = base_url,
        .issuer = issuer,
        .discovery_url = try allocator.dupe(u8, discovery_url),
    };
}

pub fn discoverService(allocator: std.mem.Allocator, issuer_or_url: []const u8) !ServiceDefinition {
    const discovery_url = try buildDiscoveryUrl(allocator, issuer_or_url);
    const script =
        "import sys, urllib.request\n" ++
        "with urllib.request.urlopen(sys.argv[1]) as resp:\n" ++
        "    sys.stdout.buffer.write(resp.read())\n";
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "python3", "-c", script, discovery_url },
        .max_output_bytes = 256 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code_int| if (code_int != 0) return error.DiscoveryFetchFailed,
        else => return error.DiscoveryFetchFailed,
    }
    return try parseDiscoveredService(allocator, discovery_url, result.stdout);
}

test "service preset google-imap resolves expected fields" {
    const def = try resolveServicePreset("google-imap");
    try std.testing.expectEqualStrings("google", def.provider.?);
    try std.testing.expectEqualStrings("https://accounts.google.com/o/oauth2/v2/auth", def.auth_url.?);
    try std.testing.expectEqualStrings("https://oauth2.googleapis.com/token", def.token_url.?);
    try std.testing.expectEqualStrings("https://mail.google.com/ openid email profile", def.scope.?);
    try std.testing.expectEqualStrings("google-imap", def.env_kind.?);
}

test "service preset openai alias resolves expected fields" {
    const def = try resolveServicePreset("openai-oidc");
    try std.testing.expectEqualStrings("openai", def.provider.?);
    try std.testing.expectEqualStrings("https://auth.openai.com/authorize", def.auth_url.?);
    try std.testing.expectEqualStrings("https://auth0.openai.com/oauth/token", def.token_url.?);
    try std.testing.expectEqualStrings("openai", def.env_kind.?);
    try std.testing.expectEqualStrings("https://api.openai.com/v1", def.base_url.?);
}

test "build discovery url normalizes issuer" {
    const allocator = std.testing.allocator;
    const a = try buildDiscoveryUrl(allocator, "https://accounts.google.com");
    defer allocator.free(a);
    try std.testing.expectEqualStrings("https://accounts.google.com/.well-known/openid-configuration", a);

    const b = try buildDiscoveryUrl(allocator, "https://auth.openai.com/.well-known/openid-configuration");
    defer allocator.free(b);
    try std.testing.expectEqualStrings("https://auth.openai.com/.well-known/openid-configuration", b);
}

test "parse discovered service infers openai env shaping" {
    var arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_impl.deinit();
    const allocator = arena_impl.allocator();
    const document =
        \\{
        \\  "issuer": "https://auth.openai.com",
        \\  "authorization_endpoint": "https://auth.openai.com/authorize",
        \\  "token_endpoint": "https://auth0.openai.com/oauth/token"
        \\}
    ;
    const def = try parseDiscoveredService(allocator, "https://auth.openai.com/.well-known/openid-configuration", document);
    try std.testing.expectEqualStrings("openai", def.provider.?);
    try std.testing.expectEqualStrings("openai", def.env_kind.?);
    try std.testing.expectEqualStrings("https://api.openai.com/v1", def.base_url.?);
    try std.testing.expectEqualStrings("https://auth.openai.com/authorize", def.auth_url.?);
    try std.testing.expectEqualStrings("https://auth0.openai.com/oauth/token", def.token_url.?);
}
