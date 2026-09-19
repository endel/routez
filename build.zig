const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const quic_dep = b.dependency("quic", .{ .target = target, .optimize = optimize });
    const quic_mod = quic_dep.module("quic");

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", @import("build.zig.zon").version);
    build_options.addOption(bool, "fault_injection", b.option(bool, "fault-injection", "Test hooks: stall reads of files named *slow-read*") orelse false);

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        // quic-zig links libc for recvmsg; we use it for the remaining syscalls
        .link_libc = true,
        .imports = &.{
            .{ .name = "quic", .module = quic_mod },
            .{ .name = "build_options", .module = build_options.createModule() },
        },
    });

    const exe = b.addExecutable(.{ .name = "routez", .root_module = root_mod });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run the server").dependOn(&run_cmd.step);

    // WebTransport client used by tests/e2e/run.sh.
    const wt_client = b.addExecutable(.{ .name = "wt-test-client", .root_module = b.createModule(.{
        .root_source_file = b.path("tests/e2e/wt_client.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "quic", .module = quic_mod }},
    }) });
    b.step("wt-test-client", "Build the WebTransport e2e client").dependOn(&b.addInstallArtifact(wt_client, .{}).step);
    const wt_slow = b.addExecutable(.{ .name = "wt-slow-server", .root_module = b.createModule(.{
        .root_source_file = b.path("tests/e2e/wt_slow_server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "quic", .module = quic_mod }},
    }) });
    b.step("wt-slow-server", "Build the slow WebTransport upstream").dependOn(&b.addInstallArtifact(wt_slow, .{}).step);

    // Certificates and CSRs for tests/acme/run.sh.
    const test_cert = b.addExecutable(.{ .name = "acme-test-tool", .root_module = b.createModule(.{
        .root_source_file = b.path("tests/acme/tool.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "x509", .module = b.createModule(.{
            .root_source_file = b.path("src/acme/x509.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "quic", .module = quic_mod }},
        }) }},
    }) });
    b.step("acme-test-tool", "Build the ACME test helper").dependOn(&b.addInstallArtifact(test_cert, .{}).step);

    const fuzz_options = b.addOptions();
    fuzz_options.addOption(u64, "iterations", b.option(u64, "fuzz-iterations", "Mutations per fuzz target (default 20000)") orelse 20_000);
    const fuzz = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "fuzz_options", .module = fuzz_options.createModule() }},
    }) });
    b.step("fuzz", "Run fuzz targets under a mutation loop").dependOn(&b.addRunArtifact(fuzz).step);

    // HTTP/3 client used by the connection-migration check in tests/e2e/run.sh.
    const h3_client = b.addExecutable(.{ .name = "h3-test-client", .root_module = b.createModule(.{
        .root_source_file = b.path("tests/e2e/h3_client.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "quic", .module = quic_mod }},
    }) });
    b.step("h3-test-client", "Build the HTTP/3 e2e client").dependOn(&b.addInstallArtifact(h3_client, .{}).step);

    // Driver for tests/regex/differential.py, which checks src/regex.zig against Python's re.
    const regex_diff = b.addExecutable(.{ .name = "regex-diff", .root_module = b.createModule(.{
        .root_source_file = b.path("tests/regex/diff.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "regex", .module = b.createModule(.{
            .root_source_file = b.path("src/regex.zig"),
            .target = target,
            .optimize = optimize,
        }) }},
    }) });
    b.step("regex-diff", "Build the regex differential-test driver").dependOn(&b.addInstallArtifact(regex_diff, .{}).step);

    const tests = b.addTest(.{ .root_module = root_mod });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
