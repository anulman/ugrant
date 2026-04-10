const std = @import("std");

fn addSqlite(step: *std.Build.Step.Compile, b: *std.Build) void {
    step.root_module.addIncludePath(b.path("third_party/sqlite-amalgamation"));
    step.root_module.addCSourceFile(.{
        .file = b.path("third_party/sqlite-amalgamation/sqlite3.c"),
        .flags = &.{
            "-DSQLITE_THREADSAFE=1",
            "-DSQLITE_ENABLE_FTS5",
            "-DSQLITE_ENABLE_RTREE",
            "-DSQLITE_ENABLE_DBSTAT_VTAB",
        },
    });
}

fn addPlatformLibs(step: *std.Build.Step.Compile, target: std.Build.ResolvedTarget) void {
    if (target.result.os.tag == .windows) {
        step.linkSystemLibrary("crypt32");
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version = b.option([]const u8, "version", "Override the reported ugrant version string") orelse "0.2.0";

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.addImport("build_options", build_options.createModule());

    const exe = b.addExecutable(.{
        .name = "ugrant",
        .root_module = exe_mod,
    });
    addSqlite(exe, b);
    addPlatformLibs(exe, target);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run ugrant");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport("build_options", build_options.createModule());

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    addSqlite(unit_tests, b);
    addPlatformLibs(unit_tests, target);

    const test_run = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);

    const test_compile_step = b.step("test-compile", "Compile unit tests without running them");
    test_compile_step.dependOn(&unit_tests.step);
}
