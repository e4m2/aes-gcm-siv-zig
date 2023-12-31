const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const main_source_file = std.Build.LazyPath.relative("src/aes_gcm_siv.zig");

    _ = b.addModule("aes_gcm_siv", .{ .source_file = main_source_file });

    const tests = b.addTest(.{
        .root_source_file = main_source_file,
        .target = target,
        .optimize = optimize,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);
}
