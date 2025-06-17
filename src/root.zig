const std = @import("std");
const enums = @import("enums.zig");
const ttlv = @import("ttlv.zig");

pub usingnamespace enums;
pub const Ttlv = ttlv.Ttlv;
pub const CustomTtlv = ttlv.CustomTtlv;

test {
    _ = @import("ttlv_tests.zig");

    std.testing.refAllDecls(@This());
}
