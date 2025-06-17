const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod_ttlv = b.addModule("ttlv", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib_temp = b.dependency("temp", .{
        .target = target,
        .optimize = optimize,
    });
    const mod_temp = lib_temp.module("temp");
    mod_ttlv.addImport("temp", mod_temp);

    const conduit_lib = b.dependency("conduit", .{
        .target = target,
        .optimize = optimize,
    });
    const conduit_mod = conduit_lib.module("conduit");
    mod_ttlv.addImport("conduit", conduit_mod);

    const lib = b.addStaticLibrary(.{
        .name = "ttlv",
        .root_module = mod_ttlv,
    });

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{ .root_module = mod_ttlv });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
