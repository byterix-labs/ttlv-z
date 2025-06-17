const std = @import("std");
const testing = std.testing;
const enums = @import("enums.zig");

const logger = std.log.scoped(.ttlv);

const TTLV_HEADER_LENGTH = 8;

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const TagType = Ttlv.TagType;
const ValueType = enums.ValueType;
const ConduitObject = @import("conduit").Object;
const AnyReader = std.io.AnyReader;
const countingReader = std.io.countingReader;

pub const DecodeError = error{
    MissingStartByte,
    UnsupportedType,
    UnknownTag,
};

pub const TtlvOptions = struct {
    allocator: ?std.mem.Allocator = null,
};

fn calculatePadding(len: usize) usize {
    const alignment = 8;
    const offset = len % alignment;

    if (offset == 0) {
        return 0;
    }

    return alignment - offset;
}

fn paddedLen(len: usize) usize {
    return len + calculatePadding(len);
}

pub fn CustomTtlv(T: type) type {
    return struct {
        const Self = @This();

        pub const TagType = T;

        pub const Value = union(ValueType) {
            structure: *std.ArrayListUnmanaged(*Self),
            integer: i32,
            longInteger: i64,
            bigInteger: i128,
            enumeration: u32,
            boolean: bool,
            textString: []const u8,
            byteString: ConduitObject,
            dateTime: u64,
            interval: u32,
            dateTimeExtended: u64,
            identifier: []const u8,
            reference: []const u8,
            nameReference: []const u8,
            none,

            /// Length of the value in bytes
            pub fn length(self: Value) usize {
                return switch (self) {
                    .structure => blk: {
                        var total_len: usize = 0;

                        for (self.structure.items) |c| {
                            total_len += c.length();
                        }

                        break :blk total_len;
                    },
                    .integer => 4,
                    .longInteger => 8,
                    .bigInteger => 16,
                    .enumeration => 4,
                    .boolean => 8,
                    .textString => self.textString.len,
                    .byteString => self.byteString.len,
                    .dateTime => 8,
                    .interval => 4,
                    .identifier => self.identifier.len,
                    .reference => self.reference.len,
                    .nameReference => self.nameReference.len,
                    else => 0,
                };
            }

            pub fn initEnum(enum_value: anytype) Value {
                return Value{ .enumeration = @intFromEnum(enum_value) };
            }
        };

        tag: T,
        value: Value,
        arena: ?*ArenaAllocator = null,

        fn initBare(tag: T, options: TtlvOptions) Self {
            const arena: ?*ArenaAllocator = if (options.allocator) |a| blk: {
                const arena = a.create(ArenaAllocator) catch @panic("OOM");
                arena.* = ArenaAllocator.init(a);
                break :blk arena;
            } else null;

            return Self{
                .tag = tag,
                .value = .none,
                .arena = arena,
            };
        }

        /// You should only need to deinit the root Ttlv, as it will recursively deinit all children.
        pub fn init(tag: T, value: Value, options: TtlvOptions) Self {
            var ttlv = initBare(tag, options);

            ttlv.value = value;

            return ttlv;
        }

        pub fn structure(allocator: std.mem.Allocator, comptime tag: T) !Self {
            var ttlv = initBare(tag, .{
                .allocator = allocator,
            });

            const structure_list = try allocator.create(std.ArrayListUnmanaged(*Self));
            structure_list.* = std.ArrayListUnmanaged(*Self){};

            ttlv.value = Value{ .structure = structure_list };

            return ttlv;
        }

        pub fn textString(comptime tag: T, value: []const u8) Self {
            return init(tag, .{ .textString = value }, .{});
        }

        fn getAllocator(self: Self) ?std.mem.Allocator {
            if (self.arena) |arena| {
                return arena.child_allocator;
            }

            return null;
        }

        /// Child Ttlv should be allocated with the same allocator as the parent.
        pub fn append(self: *Self, child: Self) !void {
            // make sure allocators are the same
            if (self.getAllocator()) |self_allocator| {
                if (child.getAllocator()) |child_allocator| {
                    if (self_allocator.ptr != child_allocator.ptr) {
                        @panic("Child Ttlv must be allocated with the same allocator as the parent");
                    }
                }
            }

            const allocator = self.arena.?.allocator();

            const ttlv = try allocator.create(Self);
            ttlv.* = child;

            switch (self.value) {
                .structure => {
                    try self.value.structure.append(allocator, ttlv);
                },
                else => @panic("append called on non-structure Ttlv"),
            }
        }

        pub fn appendSlice(self: *Self, children: []const Self) !void {
            for (children) |c| {
                try self.append(c);
            }
        }

        pub fn appendToPath(self: *Self, tag_path: anytype, child: Self) !void {
            var target = try self.path(tag_path);
            try target.append(child);
        }

        pub fn castValue(self: Self, comptime As: type) !As {
            const type_info = @typeInfo(As);

            switch (type_info) {
                .@"enum" => return @as(As, @enumFromInt(self.value.enumeration)),
                else => {},
            }

            switch (self.value) {
                .integer => |i| @as(As, @intCast(i)),
                .longInteger => |i| @as(As, @intCast(i)),
                .bigInteger => |i| @as(As, @intCast(i)),
                .dateTime => |i| @as(As, @intCast(i)),
                .dateTimeExtended => |i| @as(As, @intCast(i)),
                .interval => |i| @as(As, @intCast(i)),
                .enumeration => |e| @as(As, @enumFromInt(e)),
                else => error.UnsupportedCast,
            }
        }

        pub fn deinit(self: *@This()) void {
            switch (self.value) {
                .structure => {
                    const allocator = self.arena.?.child_allocator;

                    for (self.value.structure.items) |c| {
                        c.deinit();
                    }

                    self.value.structure.clearAndFree(self.arena.?.allocator());
                    allocator.destroy(self.value.structure);
                },
                .byteString => |*v| {
                    v.deinit();
                },
                else => {},
            }

            if (self.arena) |arena| {
                const allocator = arena.child_allocator;
                arena.deinit();
                allocator.destroy(arena);
            }
        }

        fn decodeTextString(allocator: std.mem.Allocator, reader: anytype, len: usize) !Value {
            const buffer: []u8 = try allocator.alloc(u8, len);
            _ = try reader.read(buffer);

            return Value{ .textString = buffer };
        }

        fn decodeByteString(allocator: std.mem.Allocator, reader: AnyReader, len: usize) !Value {
            var byte_string_buffer = try ConduitObject.init(allocator, .{
                .initial_capacity = len,
            });

            logger.debug("Decoding byte string with length {d}", .{len});

            var writer = try byte_string_buffer.writer();

            var bytes_written: usize = 0;
            var buffer: [4096]u8 = undefined;

            while (bytes_written < len) {
                const read_len = @min(len - bytes_written, buffer.len);

                const n = try reader.read(buffer[0..read_len]);
                if (n == 0) {
                    break;
                }

                bytes_written += try writer.write(buffer[0..n]);
            }

            return Value{ .byteString = byte_string_buffer };
        }

        fn createStructureValue(arena: *ArenaAllocator, reader: anytype, len: usize) !Value {
            const child_allocator = arena.child_allocator;
            const arena_allocator = arena.allocator();

            const children = try child_allocator.create(std.ArrayListUnmanaged(*Self));
            children.* = std.ArrayListUnmanaged(*Self){};

            var counting_reader = countingReader(reader);
            while (counting_reader.bytes_read < len) {
                const child = try arena_allocator.create(Self);
                child.* = try decodeInternal(child_allocator, counting_reader.reader().any());

                try children.append(arena_allocator, child);
            }

            return Value{ .structure = children };
        }

        pub fn decode(allocator: std.mem.Allocator, reader: AnyReader) anyerror!Self {
            return try decodeInternal(allocator, reader);
        }

        pub fn decodeFromBuffer(allocator: std.mem.Allocator, buffer: []const u8) !Self {
            var stream = std.io.fixedBufferStream(buffer);
            return try decodeInternal(allocator, stream.reader().any());
        }

        fn decodeInternal(allocator: std.mem.Allocator, reader: AnyReader) anyerror!Self {
            const tag_int = try reader.readInt(u24, .big);
            const tag: T = std.meta.intToEnum(T, tag_int) catch {
                std.log.debug("Invalid tag: {x}", .{tag_int});
                return DecodeError.UnknownTag;
            };

            var ttlv = initBare(tag, .{
                .allocator = allocator,
            });

            const arena_allocator = ttlv.arena.?.allocator();

            const value_type_int = try reader.readInt(u8, .big);
            const value_type = std.meta.intToEnum(ValueType, value_type_int) catch {
                logger.warn("Unsupported value type: 0x{x}", .{value_type_int});
                return DecodeError.UnsupportedType;
            };

            const len: usize = @intCast(try reader.readInt(u32, .big));
            const padded_len = paddedLen(len);

            const value = switch (value_type) {
                .structure => try createStructureValue(ttlv.arena.?, reader, len),
                .integer => blk: {
                    const i = try reader.readInt(i32, .big);

                    // Skip padding bytes
                    _ = try reader.skipBytes(4, .{});

                    break :blk Value{ .integer = i };
                },
                .longInteger => Value{ .longInteger = try reader.readInt(i64, .big) },
                .bigInteger => Value{ .bigInteger = try reader.readInt(i128, .big) },
                .enumeration => blk: {
                    const e = try reader.readInt(u32, .big);

                    // Skip padding bytes
                    _ = try reader.skipBytes(4, .{});

                    break :blk Value{ .enumeration = e };
                },
                .boolean => Value{ .boolean = try reader.readInt(u64, .big) != 0 },
                .textString => blk: {
                    const text_string = try decodeTextString(arena_allocator, reader, len);

                    // Skip padding bytes
                    _ = try reader.skipBytes(@intCast(padded_len - len), .{});

                    break :blk text_string;
                },
                .byteString => blk: {
                    const byte_string = try decodeByteString(arena_allocator, reader, len);

                    // Skip padding bytes
                    _ = try reader.skipBytes(@intCast(padded_len - len), .{});

                    break :blk byte_string;
                },
                .dateTime => Value{ .dateTime = try reader.readInt(u64, .big) },
                .interval => blk: {
                    const interval = Value{ .interval = try reader.readInt(u32, .big) };

                    // Skip padding bytes
                    _ = try reader.skipBytes(4, .{});

                    break :blk interval;
                },
                else => return DecodeError.UnsupportedType,
            };

            ttlv.value = value;

            return ttlv;
        }

        fn writeValueType(writer: anytype, comptime value_type: ValueType) !void {
            try writer.writeInt(u8, @intFromEnum(value_type), .big);
        }

        pub fn encode(self: *@This(), writer: anytype) !usize {
            try writer.writeInt(u24, @intFromEnum(self.tag), .big);

            const len: usize = switch (self.value) {
                .structure => |children| blk: {
                    try writeValueType(writer, .structure);

                    // Calculate and write the total length of the structure
                    var total_len: usize = 0;
                    for (children.items) |c| {
                        total_len += c.length();
                    }
                    try writer.writeInt(u32, @intCast(total_len), .big);

                    // Encode the children, discarding the result
                    for (children.items) |c| {
                        _ = try c.encode(writer);
                    }

                    break :blk total_len;
                },
                .integer => |v| blk: {
                    try writeValueType(writer, .integer);
                    try writer.writeInt(u32, @sizeOf(i32), .big);
                    try writer.writeInt(i32, v, .big);
                    try writer.writeInt(u32, 0, .big); // Padding

                    break :blk @sizeOf(i32);
                },
                .longInteger => |v| blk: {
                    try writeValueType(writer, .longInteger);
                    try writer.writeInt(u32, @sizeOf(i64), .big);
                    try writer.writeInt(i64, v, .big);

                    break :blk @sizeOf(i64);
                },
                .bigInteger => |v| blk: {
                    try writeValueType(writer, .bigInteger);
                    // TODO: size of big integer varies (multiples of 8 bytes)
                    try writer.writeInt(u32, @sizeOf(i128), .big);
                    try writer.writeInt(i128, v, .big);

                    break :blk @sizeOf(i128);
                },
                .enumeration => |v| blk: {
                    try writeValueType(writer, .enumeration);
                    try writer.writeInt(u32, @sizeOf(u32), .big);
                    try writer.writeInt(u32, v, .big);
                    try writer.writeInt(u32, 0, .big); // Padding

                    break :blk @sizeOf(u32);
                },
                .boolean => |v| blk: {
                    try writeValueType(writer, .boolean);
                    try writer.writeInt(u32, @sizeOf(u64), .big);
                    try writer.writeInt(u64, @intFromBool(v), .big);

                    break :blk @sizeOf(u64);
                },
                .textString => |v| blk: {
                    try writeValueType(writer, .textString);
                    try writer.writeInt(u32, @intCast(v.len), .big);
                    _ = try writer.write(v);

                    // Apply padding
                    const padding = calculatePadding(v.len);
                    for (0..padding) |_| {
                        try writer.writeInt(u8, 0, .big);
                    }

                    break :blk v.len;
                },
                .byteString => |*v| blk: {
                    try writeValueType(writer, .byteString);
                    try writer.writeInt(u32, @intCast(v.len), .big);

                    logger.debug("Encoding byte string with length {d}", .{v.len});

                    var reader = try v.reader();
                    var buffer: [4096]u8 = undefined;
                    var bytes_written: usize = 0;

                    while (bytes_written < v.len) {
                        const read_len = @min(v.len - bytes_written, buffer.len);
                        const n = try reader.read(buffer[0..read_len]);
                        if (n == 0) {
                            break;
                        }
                        bytes_written += try writer.write(buffer[0..n]);
                    }

                    // Apply padding
                    const padding = calculatePadding(v.len);
                    for (0..padding) |_| {
                        try writer.writeInt(u8, 0, .big);
                    }

                    break :blk v.len;
                },
                .dateTime => |v| blk: {
                    try writeValueType(writer, .dateTime);
                    try writer.writeInt(u32, @sizeOf(u64), .big);
                    try writer.writeInt(u64, v, .big);

                    break :blk @sizeOf(u64);
                },
                .interval => |v| blk: {
                    try writeValueType(writer, .interval);
                    try writer.writeInt(u32, @sizeOf(u32), .big);
                    try writer.writeInt(u32, v, .big);
                    try writer.writeInt(u32, 0, .big); // Padding

                    break :blk @sizeOf(u32);
                },
                else => return error.UnsupportedType,
            };

            return TTLV_HEADER_LENGTH + paddedLen(len);
        }

        pub fn length(self: Self) usize {
            return TTLV_HEADER_LENGTH + paddedLen(self.value.length());
        }

        pub fn path(self: Self, comptime tags: anytype) !*Self {
            if (self.value != .structure) {
                return error.TypeMismatch;
            }

            const is_single_tag = switch (@TypeOf(tags)) {
                T, @TypeOf(.enum_literal) => true,
                else => false,
            };

            if (is_single_tag) {
                return self.path([_]T{tags});
            }

            const tag = tags[0];

            var iter = self.iterate();
            while (iter.next()) |c| {
                if (c.tag == tag) {
                    if (tags.len == 1) {
                        return c;
                    } else {
                        return try c.path(tags[1..]);
                    }
                }
            }

            return error.ChildNotFound;
        }

        pub fn list(self: Self, allocator: Allocator, comptime tags: anytype) !std.ArrayList(*Self) {
            const is_single_tag = switch (@TypeOf(tags)) {
                T => true,
                @TypeOf(.enum_literal) => true,
                else => false,
            };

            const tags_array = if (is_single_tag) [_]T{tags} else tags;

            // get path to all but the last tag
            const parent_path = tags_array[0 .. tags_array.len - 1];
            const parent = if (parent_path.len > 0) try self.path(parent_path) else &self;
            const target_tag = tags_array[tags_array.len - 1];

            switch (parent.value) {
                .structure => |s| {
                    var result = try std.ArrayList(*Self).initCapacity(allocator, s.items.len);

                    for (s.items) |c| {
                        if (c.tag == target_tag) {
                            try result.append(c);
                        }
                    }

                    return result;
                },
                else => return error.TypeMismatch,
            }
        }

        pub fn dump(self: Self) !void {
            return try self.dumpRecursive(0);
        }

        fn printWithDepth(depth: usize, comptime fmt: []const u8, args: anytype) void {
            for (0..depth) |_| {
                std.debug.print("  ", .{});
            }

            std.debug.print(fmt, args);
        }

        fn dumpRecursive(self: Self, depth: usize) !void {
            const tag_name = @tagName(self.tag);

            switch (self.value) {
                .structure => |s| {
                    printWithDepth(depth, "{s}: structure\n", .{tag_name});

                    for (s.items) |c| {
                        try c.dumpRecursive(depth + 1);
                    }
                },
                .enumeration => |v| printWithDepth(depth, "{s}: enum = 0x{x}\n", .{ tag_name, v }),
                .textString => |s| printWithDepth(depth, "{s}: string = {s}\n", .{ tag_name, s }),
                .byteString => |byte_string| {
                    var bs = byte_string;

                    const buffer_len = 16;

                    // read a few bytes to print
                    const len = @min(buffer_len, bs.len);
                    var buffer: [buffer_len]u8 = undefined;
                    const reader = try bs.reader();
                    const n = try reader.read(buffer[0..len]);

                    printWithDepth(depth, "{s}: [{d}]byte = {x} ...\n", .{ tag_name, bs.len, buffer[0..n] });
                },
                .integer => |v| printWithDepth(depth, "{s}: int = {d}\n", .{ tag_name, v }),
                .dateTime => |v| printWithDepth(depth, "{s}: datetime = {d}\n", .{ tag_name, v }),
                else => |v| printWithDepth(depth, "{s}: unknown = {any}\n", .{ tag_name, v }),
            }
        }

        pub fn iterate(self: *const Self) Iterator {
            return Iterator.init(self);
        }

        pub fn walk(self: *const Self, allocator: Allocator) !Walker {
            return try Walker.init(allocator, self);
        }

        pub const Iterator = struct {
            index: usize,
            ttlv: *const Self,

            pub fn init(ttlv: *const Self) Iterator {
                return Iterator{
                    .index = 0,
                    .ttlv = ttlv,
                };
            }

            pub fn next(self: *Iterator) ?*Self {
                const item = self.peek();

                self.index += 1;

                return item;
            }

            pub fn peek(self: *Iterator) ?*Self {
                const s = self.ttlv.value.structure;
                if (self.index >= s.items.len) return null;

                const item = s.items[self.index];

                return item;
            }

            pub fn reset(self: *Iterator) void {
                self.index = 0;
            }
        };

        pub const Walker = struct {
            const StackItem = struct {
                root: ?*Self = null,
                iterator: Iterator,
                len: usize,
            };

            ttlv: *const Self,
            allocator: Allocator,
            stack: std.ArrayListUnmanaged(StackItem),

            pub fn init(allocator: Allocator, ttlv: *const Self) !Walker {
                var self = Walker{
                    .ttlv = ttlv,
                    .allocator = allocator,
                    .stack = try std.ArrayListUnmanaged(StackItem).initCapacity(allocator, ttlv.value.structure.items.len),
                };

                try self.stack.append(allocator, .{
                    .iterator = Iterator.init(ttlv),
                    .len = ttlv.value.structure.items.len,
                });

                return self;
            }

            pub fn next(self: *Walker) !?*Self {
                while (self.stack.items.len > 0) {
                    var top = &self.stack.items[self.stack.items.len - 1];

                    if (top.iterator.next()) |ttlv| {
                        switch (ttlv.value) {
                            .structure => {
                                try self.stack.append(self.allocator, .{
                                    .root = ttlv,
                                    .iterator = ttlv.iterate(),
                                    .len = ttlv.value.structure.items.len,
                                });
                            },
                            else => return ttlv,
                        }
                    } else if (self.stack.pop()) |item| {
                        return item.root;
                    }
                }

                return null;
            }

            pub fn deinit(self: *Walker) void {
                self.stack.deinit(self.allocator);
            }
        };
    };
}

pub const ExtendOptions = struct {
    is_exhaustive: bool = false,
};

pub fn extendDefault(comptime Extensions: type, options: ExtendOptions) type {
    const default_type_info = @typeInfo(enums.TagType).@"enum";
    const default_fields = default_type_info.fields;
    const extension_fields = @typeInfo(Extensions).@"enum".fields;
    const fields = default_fields ++ extension_fields;

    const ExtendedTagType = @Type(.{
        .@"enum" = std.builtin.Type.Enum{
            .decls = &.{},
            .tag_type = default_type_info.tag_type,
            .fields = fields,
            .is_exhaustive = options.is_exhaustive,
        },
    });

    return CustomTtlv(ExtendedTagType);
}

pub const Ttlv = CustomTtlv(enums.TagType);

test "path" {
    var requestMessage = blk: {
        var protocolVersion = try Ttlv.structure(testing.allocator, .protocolVersion);

        const protocolVersionMajor = Ttlv.init(.protocolVersionMajor, .{ .integer = 3 }, .{});
        const protocolVersionMinor = Ttlv.init(.protocolVersionMinor, .{ .integer = 0 }, .{});

        try protocolVersion.append(protocolVersionMajor);
        try protocolVersion.append(protocolVersionMinor);

        var requestHeader = try Ttlv.structure(testing.allocator, .requestHeader);
        try requestHeader.append(protocolVersion);

        const requestPayload = try Ttlv.structure(testing.allocator, .requestPayload);

        var batchItem = try Ttlv.structure(testing.allocator, .batchItem);
        try batchItem.append(requestPayload);

        var requestMessage = try Ttlv.structure(testing.allocator, .requestMessage);
        try requestMessage.append(requestHeader);
        try requestMessage.append(batchItem);

        break :blk requestMessage;
    };
    defer requestMessage.deinit();

    const protocolVersionMajor = try requestMessage.path([_]TagType{ .requestHeader, .protocolVersion, .protocolVersionMajor });
    try testing.expectEqual(3, protocolVersionMajor.value.integer);

    const protocolVersionMinor = try requestMessage.path([_]TagType{ .requestHeader, .protocolVersion, .protocolVersionMinor });
    try testing.expectEqual(0, protocolVersionMinor.value.integer);

    const requestPayload = try requestMessage.path([_]TagType{ .batchItem, .requestPayload });
    try testing.expectEqual(.requestPayload, requestPayload.tag);

    const batchItem = try requestMessage.path(.batchItem);
    try testing.expectEqual(.batchItem, batchItem.tag);
}

test "list" {
    var requestMessage = blk: {
        var protocolVersion = try Ttlv.structure(testing.allocator, .protocolVersion);

        const protocolVersionMajor = Ttlv.init(.protocolVersionMajor, .{ .integer = 3 }, .{});
        const protocolVersionMinor = Ttlv.init(.protocolVersionMinor, .{ .integer = 0 }, .{});

        try protocolVersion.append(protocolVersionMajor);
        try protocolVersion.append(protocolVersionMinor);

        var requestHeader = try Ttlv.structure(testing.allocator, .requestHeader);
        try requestHeader.append(protocolVersion);

        var requestPayload = try Ttlv.structure(testing.allocator, .requestPayload);

        for (0..10) |i| {
            try requestPayload.append(Ttlv.init(.operation, .{ .enumeration = @intCast(i) }, .{}));
        }

        try requestPayload.append(Ttlv.init(TagType.x, .{ .integer = 0 }, .{}));
        try requestPayload.append(Ttlv.init(TagType.y, .{ .integer = 0 }, .{}));

        var batchItem = try Ttlv.structure(testing.allocator, .batchItem);
        try batchItem.append(requestPayload);

        var requestMessage = try Ttlv.structure(testing.allocator, .requestMessage);
        try requestMessage.append(requestHeader);
        try requestMessage.append(batchItem);

        break :blk requestMessage;
    };
    defer requestMessage.deinit();

    const requestPayload = try requestMessage.path([_]TagType{ .batchItem, .requestPayload });
    try testing.expectEqual(.requestPayload, requestPayload.tag);

    const operations = try requestPayload.list(testing.allocator, .operation);
    defer operations.deinit();

    try testing.expectEqual(10, operations.items.len);

    for (operations.items, 0..) |ttlv, i| {
        try testing.expectEqual(TagType.operation, ttlv.tag);
        try testing.expectEqual(@as(u32, @intCast(i)), ttlv.value.enumeration);
    }
}

test "iterator" {
    var requestMessage = blk: {
        var protocolVersion = try Ttlv.structure(testing.allocator, .protocolVersion);

        const protocolVersionMajor = Ttlv.init(.protocolVersionMajor, .{ .integer = 3 }, .{});
        const protocolVersionMinor = Ttlv.init(.protocolVersionMinor, .{ .integer = 0 }, .{});

        try protocolVersion.append(protocolVersionMajor);
        try protocolVersion.append(protocolVersionMinor);

        var requestHeader = try Ttlv.structure(testing.allocator, .requestHeader);
        try requestHeader.append(protocolVersion);

        const requestPayload = try Ttlv.structure(testing.allocator, .requestPayload);

        var batchItem = try Ttlv.structure(testing.allocator, .batchItem);
        try batchItem.append(requestPayload);

        var requestMessage = try Ttlv.structure(testing.allocator, .requestMessage);
        try requestMessage.append(requestHeader);
        try requestMessage.append(batchItem);

        break :blk requestMessage;
    };
    defer requestMessage.deinit();

    var count: usize = 0;
    var iterator = requestMessage.iterate();

    while (iterator.next()) |ttlv| {
        if (iterator.index == 0) {
            try testing.expectEqual(.requestMessage, ttlv.tag);
        }

        if (iterator.index == 1) {
            try testing.expectEqual(.requestHeader, ttlv.tag);
        }

        count += 1;
    }

    try testing.expectEqual(2, count);
}

test "walker" {
    var requestMessage = blk: {
        var protocolVersion = try Ttlv.structure(testing.allocator, .protocolVersion);

        const protocolVersionMajor = Ttlv.init(.protocolVersionMajor, .{ .integer = 3 }, .{});
        const protocolVersionMinor = Ttlv.init(.protocolVersionMinor, .{ .integer = 0 }, .{});

        try protocolVersion.append(protocolVersionMajor);
        try protocolVersion.append(protocolVersionMinor);

        var requestHeader = try Ttlv.structure(testing.allocator, .requestHeader);
        try requestHeader.append(protocolVersion);

        const requestPayload = try Ttlv.structure(testing.allocator, .requestPayload);

        var batchItem = try Ttlv.structure(testing.allocator, .batchItem);
        try batchItem.append(requestPayload);

        var requestMessage = try Ttlv.structure(testing.allocator, .requestMessage);
        try requestMessage.append(requestHeader);
        try requestMessage.append(batchItem);

        break :blk requestMessage;
    };
    defer requestMessage.deinit();

    var count: usize = 0;

    var walker = try requestMessage.walk(testing.allocator);
    defer walker.deinit();

    while (try walker.next()) |_| {
        count += 1;
    }

    try testing.expectEqual(6, count);
}
