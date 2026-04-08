const std = @import("std");
const argx = @import("args.zig");
const cli = @import("cli.zig");

pub const ProfileAddOptions = struct {
    name: ?[]const u8 = null,
    service_name: ?[]const u8 = null,
    discover_url: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    auth_url: ?[]const u8 = null,
    token_url: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    redirect_uri: ?[]const u8 = null,
    env_kind: ?[]const u8 = null,
    base_url: ?[]const u8 = null,
    model: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
};

pub const LoginOptions = struct {
    profile_name: ?[]const u8 = null,
    code_override: ?[]const u8 = null,
    redirect_override: ?[]const u8 = null,
    no_open: bool = false,
    allow_unsafe_bare_code: bool = false,
};

pub fn parseProfileAdd(args: []const []const u8, out: anytype, err: anytype) !ProfileAddOptions {
    var opts = ProfileAddOptions{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--name")) {
            opts.name = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--service")) {
            opts.service_name = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--discover")) {
            opts.discover_url = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--provider")) {
            opts.provider = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--auth-url")) {
            opts.auth_url = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--token-url")) {
            opts.token_url = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--client-id")) {
            opts.client_id = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--scope")) {
            opts.scope = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--redirect-uri")) {
            opts.redirect_uri = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--env-kind")) {
            opts.env_kind = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--base-url")) {
            opts.base_url = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--model")) {
            opts.model = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--audience")) {
            opts.audience = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--client-secret")) {
            opts.client_secret = try argx.nextValueOrUsage(args, &i, cli.profile_usage_text, err);
        } else if (argx.isHelpArg(arg)) {
            try out.writeAll("usage: ugrant profile add --name <name> [--service <preset> | --discover <issuer-or-url>] [--provider <provider>] [--auth-url <url>] [--token-url <url>] --client-id <id> [--scope <scope>] [--env-kind <kind>] [--redirect-uri <uri>] [--base-url <url>] [--model <model>] [--audience <aud>] [--client-secret <secret>]\n");
            return error.HelpDisplayed;
        } else {
            try argx.writeUnknownOptionAndExit(err, arg);
        }
    }
    return opts;
}

pub fn parseLogin(args: []const []const u8, out: anytype, err: anytype) !LoginOptions {
    var opts = LoginOptions{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--profile")) {
            opts.profile_name = try argx.nextValueOrUsage(args, &i, cli.login_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--code")) {
            opts.code_override = try argx.nextValueOrUsage(args, &i, cli.login_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--redirect-url")) {
            opts.redirect_override = try argx.nextValueOrUsage(args, &i, cli.login_usage_text, err);
        } else if (std.mem.eql(u8, arg, "--unsafe-bare-code")) {
            opts.allow_unsafe_bare_code = true;
        } else if (argx.isHelpArg(arg)) {
            try out.writeAll(cli.login_usage_text);
            return error.HelpDisplayed;
        } else if (std.mem.eql(u8, arg, "--no-open")) {
            opts.no_open = true;
        } else {
            try argx.writeUnknownOptionAndExit(err, arg);
        }
    }
    return opts;
}

test "parseLogin captures options" {
    var sink = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer sink.deinit();
    const opts = try parseLogin(&.{ "--profile", "demo", "--unsafe-bare-code", "--no-open" }, &sink.writer, &sink.writer);
    try std.testing.expectEqualStrings("demo", opts.profile_name.?);
    try std.testing.expect(opts.allow_unsafe_bare_code);
    try std.testing.expect(opts.no_open);
}
