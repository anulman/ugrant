const std = @import("std");

pub const EnvVar = struct {
    key: []const u8,
    value: []const u8,
};

pub fn buildEnv(allocator: std.mem.Allocator, profile: anytype, grant: anytype) ![]EnvVar {
    var list = std.ArrayList(EnvVar){};
    try list.append(allocator, .{ .key = try allocator.dupe(u8, "LLM_PROVIDER"), .value = try allocator.dupe(u8, profile.provider) });
    if (profile.model) |model| try list.append(allocator, .{ .key = try allocator.dupe(u8, "LLM_MODEL"), .value = try allocator.dupe(u8, model) });

    if (std.mem.eql(u8, profile.env_kind, "openai")) {
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "OPENAI_API_KEY"), .value = try allocator.dupe(u8, grant.access_token.?) });
        if (profile.base_url) |base| try list.append(allocator, .{ .key = try allocator.dupe(u8, "OPENAI_BASE_URL"), .value = try allocator.dupe(u8, base) });
    } else if (std.mem.eql(u8, profile.env_kind, "anthropic")) {
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "ANTHROPIC_API_KEY"), .value = try allocator.dupe(u8, grant.access_token.?) });
    } else if (std.mem.eql(u8, profile.env_kind, "google-imap")) {
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_PROVIDER"), .value = try allocator.dupe(u8, profile.provider) });
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_ACCESS_TOKEN"), .value = try allocator.dupe(u8, grant.access_token.?) });
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_SUBJECT"), .value = try allocator.dupe(u8, grant.subject_key) });
        if (grant.scope) |scope| try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_SCOPE"), .value = try allocator.dupe(u8, scope) });
    } else {
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_PROVIDER"), .value = try allocator.dupe(u8, profile.provider) });
        try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_ACCESS_TOKEN"), .value = try allocator.dupe(u8, grant.access_token.?) });
        if (profile.base_url) |base| try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_BASE_URL"), .value = try allocator.dupe(u8, base) });
        if (grant.scope) |scope| try list.append(allocator, .{ .key = try allocator.dupe(u8, "UGRANT_SCOPE"), .value = try allocator.dupe(u8, scope) });
    }
    return list.toOwnedSlice(allocator);
}

pub fn freeEnvVars(allocator: std.mem.Allocator, envs: []EnvVar) void {
    for (envs) |ev| {
        allocator.free(ev.key);
        allocator.free(ev.value);
    }
    allocator.free(envs);
}
