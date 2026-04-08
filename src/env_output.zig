const std = @import("std");

pub const Format = enum {
    shell,
    json,
};

pub fn parseFormat(raw: []const u8) !Format {
    if (std.mem.eql(u8, raw, "shell")) return .shell;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return error.InvalidEnvFormat;
}

pub fn write(out: anytype, allocator: std.mem.Allocator, envs: anytype, format: Format) !void {
    switch (format) {
        .shell => try writeShell(out, allocator, envs),
        .json => try writeJson(out, envs),
    }
}

pub fn writeShell(out: anytype, allocator: std.mem.Allocator, envs: anytype) !void {
    for (envs) |ev| {
        const escaped = try shellEscape(allocator, ev.value);
        defer allocator.free(escaped);
        try out.print("export {s}={s}\n", .{ ev.key, escaped });
    }
}

pub fn writeJson(out: anytype, envs: anytype) !void {
    try out.writeAll("{");
    for (envs, 0..) |ev, idx| {
        if (idx != 0) try out.writeAll(",");
        try std.json.Stringify.value(ev.key, .{}, out);
        try out.writeAll(":");
        try std.json.Stringify.value(ev.value, .{}, out);
    }
    try out.writeAll("}\n");
}

pub fn shellEscape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);
    try out.append(allocator, '\'');
    for (value) |ch| {
        if (ch == '\'') try out.appendSlice(allocator, "'\\''") else try out.append(allocator, ch);
    }
    try out.append(allocator, '\'');
    return out.toOwnedSlice(allocator);
}

test "parseFormat rejects unknown env output formats" {
    try std.testing.expectEqual(Format.shell, try parseFormat("shell"));
    try std.testing.expectEqual(Format.json, try parseFormat("json"));
    try std.testing.expectError(error.InvalidEnvFormat, parseFormat("yaml"));
}
