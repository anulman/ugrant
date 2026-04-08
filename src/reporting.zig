const std = @import("std");

pub const StatusSummary = struct {
    initialized: bool,
    config_path: []const u8,
    state_dir: []const u8,
    db_path: []const u8,
    keys_path: []const u8,
    backend: ?[]const u8,
    backend_provider: ?[]const u8,
    secure_enclave: bool,
    user_presence_required: ?bool,
    security_mode: []const u8,
    profile_count: usize,
    grant_count: usize,
    grant_state: []const u8,
};

pub const GrantStatusRecord = struct {
    provider: []const u8,
    subject_key: []const u8,
    scope: ?[]const u8,
    state: []const u8,
    expires_at: ?i64,
};

pub fn runtimeGrantState(state: []const u8, expires_at: ?i64) []const u8 {
    if (std.mem.eql(u8, state, "access_token_valid")) {
        if (expires_at) |ts| {
            if (ts <= std.time.timestamp()) return "access_token_stale";
        }
    }
    return state;
}

pub fn freeGrantStatus(allocator: std.mem.Allocator, rec: GrantStatusRecord) void {
    allocator.free(rec.provider);
    allocator.free(rec.subject_key);
    if (rec.scope) |v| allocator.free(v);
    allocator.free(rec.state);
}

pub fn freeStatusSummary(allocator: std.mem.Allocator, summary: StatusSummary) void {
    allocator.free(summary.config_path);
    allocator.free(summary.state_dir);
    allocator.free(summary.db_path);
    allocator.free(summary.keys_path);
    if (summary.backend) |v| allocator.free(v);
    if (summary.backend_provider) |v| allocator.free(v);
    allocator.free(summary.security_mode);
    allocator.free(summary.grant_state);
}
