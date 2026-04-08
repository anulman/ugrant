const std = @import("std");
const builtin = @import("builtin");

const secure_enclave_secret_ref_prefix = "macos-secure-enclave:tag=";

pub const WrapBackendOptions = struct {
    secure_enclave: bool = false,
    require_user_presence: bool = false,
};

pub const BackendMetadata = struct {
    provider: ?[]const u8,
    secure_enclave: bool,
    user_presence_required: ?bool,
};

pub fn backendProviderLabel(backend: []const u8, secret_ref: ?[]const u8) ?[]const u8 {
    if (!std.mem.eql(u8, backend, "platform-secure-store")) return null;

    if (secret_ref) |ref| {
        if (std.mem.startsWith(u8, ref, secure_enclave_secret_ref_prefix)) return "macOS Secure Enclave";
    }

    return switch (builtin.os.tag) {
        .macos => "macOS Keychain",
        .windows => "Windows DPAPI",
        else => "Secret Service",
    };
}

pub fn backendMetadata(backend: []const u8, secret_ref: ?[]const u8, require_user_presence: ?bool) BackendMetadata {
    const secure_enclave = if (secret_ref) |ref| std.mem.startsWith(u8, ref, secure_enclave_secret_ref_prefix) else false;
    return .{
        .provider = backendProviderLabel(backend, secret_ref),
        .secure_enclave = secure_enclave,
        .user_presence_required = if (secure_enclave) (require_user_presence orelse false) else null,
    };
}

pub fn writeBackendMetadataLines(writer: anytype, metadata: BackendMetadata, prefix: []const u8) !void {
    if (metadata.provider) |provider| {
        try writer.print("{s}backend_provider: {s}\n", .{ prefix, provider });
    }
    if (metadata.secure_enclave) {
        try writer.print("{s}secure_enclave: yes\n", .{prefix});
    }
    if (metadata.user_presence_required) |required| {
        try writer.print("{s}user_presence_required: {s}\n", .{ prefix, if (required) "yes" else "no" });
    }
}
