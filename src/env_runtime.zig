const std = @import("std");

pub const EnvVar = struct {
    key: []const u8,
    value: []const u8,
};

pub fn buildEnv(allocator: std.mem.Allocator, profile: anytype, grant: anytype) ![]EnvVar {
    var list = std.ArrayList(EnvVar){};
    try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_PROVIDER"), .value = try allocator.dupe(u8, profile.provider) });
    if (profile.model) |model| try list.append(allocator, .{ .key = try allocator.dupe(u8, "LLM_MODEL"), .value = try allocator.dupe(u8, model) });

    if (std.mem.eql(u8, profile.env_kind, "openai")) {
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "OPENAI_API_KEY"), .value = try allocator.dupe(u8, grant.access_token.?) });
        if (profile.base_url) |base| try list.append(allocator, .{ .key = try allocator.dupe(u8, "OPENAI_BASE_URL"), .value = try allocator.dupe(u8, base) });
    } else if (std.mem.eql(u8, profile.env_kind, "anthropic")) {
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "ANTHROPIC_API_KEY"), .value = try allocator.dupe(u8, grant.access_token.?) });
    } else if (std.mem.eql(u8, profile.env_kind, "google-imap")) {
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_ACCESS_TOKEN"), .value = try allocator.dupe(u8, grant.access_token.?) });
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_SUBJECT"), .value = try allocator.dupe(u8, grant.subject_key) });
        if (grant.scope) |scope| try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_SCOPE"), .value = try allocator.dupe(u8, scope) });
    } else {
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_ACCESS_TOKEN"), .value = try allocator.dupe(u8, grant.access_token.?) });
        if (profile.base_url) |base| try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_BASE_URL"), .value = try allocator.dupe(u8, base) });
        if (grant.scope) |scope| try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_SCOPE"), .value = try allocator.dupe(u8, scope) });
    }
    return list.toOwnedSlice(allocator);
}

fn envValue(envs: []const EnvVar, key: []const u8) ?[]const u8 {
    for (envs) |env_var| {
        if (std.mem.eql(u8, env_var.key, key)) return env_var.value;
    }
    return null;
}

pub fn freeEnvVars(allocator: std.mem.Allocator, envs: []EnvVar) void {
    for (envs) |ev| {
        allocator.free(ev.key);
        allocator.free(ev.value);
    }
    allocator.free(envs);
}

test "buildEnv uses UGRANT_PROVIDER for openai-shaped profiles" {
    const profile = .{
        .provider = "openai",
        .model = @as(?[]const u8, "gpt-test"),
        .env_kind = "openai",
        .base_url = @as(?[]const u8, "https://api.openai.com/v1"),
    };
    const grant = .{
        .access_token = @as(?[]const u8, "token-123"),
        .subject_key = "subject-123",
        .scope = @as(?[]const u8, null),
    };

    const envs = try buildEnv(std.testing.allocator, profile, grant);
    defer freeEnvVars(std.testing.allocator, envs);

    try std.testing.expectEqualStrings("openai", envValue(envs, "UGRANT_PROVIDER").?);
    try std.testing.expectEqualStrings("gpt-test", envValue(envs, "LLM_MODEL").?);
    try std.testing.expectEqualStrings("token-123", envValue(envs, "OPENAI_API_KEY").?);
}

test "buildEnv uses UGRANT_PROVIDER for google-imap profiles" {
    const profile = .{
        .provider = "google",
        .model = @as(?[]const u8, null),
        .env_kind = "google-imap",
        .base_url = @as(?[]const u8, null),
    };
    const grant = .{
        .access_token = @as(?[]const u8, "token-123"),
        .subject_key = "subject-123",
        .scope = @as(?[]const u8, "mail profile"),
    };

    const envs = try buildEnv(std.testing.allocator, profile, grant);
    defer freeEnvVars(std.testing.allocator, envs);

    try std.testing.expectEqualStrings("google", envValue(envs, "UGRANT_PROVIDER").?);
    try std.testing.expectEqualStrings("token-123", envValue(envs, "UGRANT_ACCESS_TOKEN").?);
}
