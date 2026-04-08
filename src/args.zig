const std = @import("std");

pub fn isHelpArg(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h");
}

pub fn nextValueOrUsage(args: []const []const u8, i: *usize, usage: []const u8, err: anytype) ![]const u8 {
    _ = err;
    i.* += 1;
    if (i.* >= args.len) {
        std.debug.print("{s}", .{usage});
        std.process.exit(2);
    }
    return args[i.*];
}

pub fn writeUnknownOptionAndExit(err: anytype, arg: []const u8) !noreturn {
    _ = err;
    std.debug.print("unknown option: {s}\n", .{arg});
    std.process.exit(2);
}

test "help args are recognized" {
    try std.testing.expect(isHelpArg("--help"));
    try std.testing.expect(isHelpArg("-h"));
    try std.testing.expect(!isHelpArg("--profile"));
}
