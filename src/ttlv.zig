//! TTLV (Tag-Type-Length-Value) encoding and decoding library for Zig.
//!
//! This module provides a flexible implementation of the TTLV protocol used in KMIP
//! (Key Management Interoperability Protocol) and other binary serialization formats.
//! TTLV is a binary encoding format where each value is preceded by a tag (identifier),
//! type (data type), and length (size in bytes).
//!
//! Key features:
//! - Support for all KMIP TTLV value types (structure, integer, string, etc.)
//! - Generic tag system allowing custom tag enumerations
//! - Efficient encoding/decoding with streaming support via conduit integration
//! - Memory-safe with arena allocation for automatic cleanup
//! - Path-based navigation for nested structures
//! - Iterator and walker patterns for traversing complex data

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

/// Errors that can occur during TTLV decoding operations.
pub const DecodeError = error{
    /// The expected start byte was not found in the input stream
    MissingStartByte,
    /// The TTLV type is not supported by this implementation
    UnsupportedType,
    /// The tag value is not recognized or valid
    UnknownTag,
};

/// Configuration options for creating TTLV instances.
pub const TtlvOptions = struct {
    /// Optional allocator for memory management. If provided, enables arena allocation
    /// for automatic cleanup of nested structures.
    allocator: ?std.mem.Allocator = null,
};

/// Calculates the number of padding bytes needed to align to 8-byte boundary.
/// TTLV values must be padded to 8-byte alignment as per the specification.
fn calculatePadding(len: usize) usize {
    const alignment = 8;
    const offset = len % alignment;

    if (offset == 0) {
        return 0;
    }

    return alignment - offset;
}

/// Returns the total length including padding bytes needed for 8-byte alignment.
fn paddedLen(len: usize) usize {
    return len + calculatePadding(len);
}

/// Creates a TTLV type with custom tag enumeration.
///
/// This generic function allows you to create TTLV instances with your own
/// tag enumeration type. The tag type must be an enum with underlying integer values.
///
/// Args:
///   - T: The tag enumeration type to use for this TTLV instance
///
/// Returns:
///   A TTLV type configured with the specified tag enumeration
pub fn CustomTtlv(T: type) type {
    return struct {
        const Self = @This();

        pub const TagType = T;

        /// TTLV value types corresponding to the KMIP specification.
        /// Each variant holds the appropriate data type for that TTLV value type.
        pub const Value = union(ValueType) {
            /// Nested structure containing other TTLV values
            structure: *std.ArrayListUnmanaged(*Self),
            /// 32-bit signed integer
            integer: i32,
            /// 64-bit signed integer
            longInteger: i64,
            /// 128-bit signed integer
            bigInteger: i128,
            /// 32-bit enumeration value
            enumeration: u32,
            /// Boolean value (stored as 8 bytes in TTLV format)
            boolean: bool,
            /// UTF-8 text string
            textString: []const u8,
            /// Binary data stored in a conduit object for efficient streaming
            byteString: ConduitObject,
            /// Date/time as 64-bit timestamp
            dateTime: u64,
            /// Time interval as 32-bit value
            interval: u32,
            /// Extended date/time as 64-bit timestamp
            dateTimeExtended: u64,
            /// Object identifier string
            identifier: []const u8,
            /// Reference to another object
            reference: []const u8,
            /// Named reference to another object
            nameReference: []const u8,
            /// Empty/null value
            none,

            /// Returns the length of the value in bytes according to TTLV encoding rules.
            /// For structures, this includes the total length of all nested elements.
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

            /// Creates a Value from an enumeration, converting it to the underlying integer.
            ///
            /// Args:
            ///   - enum_value: Any enum value to convert to a TTLV enumeration
            ///
            /// Returns:
            ///   A Value with the enumeration variant containing the enum's integer value
            pub fn initEnum(enum_value: anytype) Value {
                return Value{ .enumeration = @intFromEnum(enum_value) };
            }
        };

        /// The TTLV tag identifying this value
        tag: T,
        /// The actual value data of this TTLV element
        value: Value,
        /// Optional arena allocator for automatic memory management of nested structures
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

        /// Creates a new TTLV instance with the specified tag and value.
        ///
        /// You should only need to deinit the root Ttlv, as it will recursively deinit all children.
        ///
        /// Args:
        ///   - tag: The tag identifier for this TTLV element
        ///   - value: The value to store in this TTLV element
        ///   - options: Configuration options including optional allocator
        ///
        /// Returns:
        ///   A new TTLV instance
        pub fn init(tag: T, value: Value, options: TtlvOptions) Self {
            var ttlv = initBare(tag, options);

            ttlv.value = value;

            return ttlv;
        }

        /// Creates a new TTLV structure that can contain child elements.
        ///
        /// Args:
        ///   - allocator: The allocator to use for the structure's child list
        ///   - tag: The tag identifier for this structure
        ///
        /// Returns:
        ///   A new TTLV structure ready to accept child elements
        ///
        /// Errors:
        ///   Returns an error if memory allocation fails
        pub fn structure(allocator: std.mem.Allocator, comptime tag: T) !Self {
            var ttlv = initBare(tag, .{
                .allocator = allocator,
            });

            const structure_list = try allocator.create(std.ArrayListUnmanaged(*Self));
            structure_list.* = std.ArrayListUnmanaged(*Self){};

            ttlv.value = Value{ .structure = structure_list };

            return ttlv;
        }

        /// Creates a new TTLV text string value.
        ///
        /// Args:
        ///   - tag: The tag identifier for this text string
        ///   - value: The string content
        ///
        /// Returns:
        ///   A new TTLV text string instance
        pub fn textString(comptime tag: T, value: []const u8) Self {
            return init(tag, .{ .textString = value }, .{});
        }

        fn getAllocator(self: Self) ?std.mem.Allocator {
            if (self.arena) |arena| {
                return arena.child_allocator;
            }

            return null;
        }

        /// Appends a child TTLV element to this structure.
        ///
        /// Child Ttlv should be allocated with the same allocator as the parent.
        /// This method can only be called on TTLV elements with structure values.
        ///
        /// Args:
        ///   - child: The TTLV element to append as a child
        ///
        /// Errors:
        ///   Returns an error if memory allocation fails or allocators don't match
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

        /// Appends multiple child TTLV elements to this structure.
        ///
        /// Args:
        ///   - children: Slice of TTLV elements to append as children
        ///
        /// Errors:
        ///   Returns an error if any append operation fails
        pub fn appendSlice(self: *Self, children: []const Self) !void {
            for (children) |c| {
                try self.append(c);
            }
        }

        /// Appends a child to a structure found at the specified tag path.
        ///
        /// Args:
        ///   - tag_path: Path specification to locate the target structure
        ///   - child: The TTLV element to append
        ///
        /// Errors:
        ///   Returns an error if the path is not found or append fails
        pub fn appendToPath(self: *Self, tag_path: anytype, child: Self) !void {
            var target = try self.path(tag_path);
            try target.append(child);
        }

        /// Casts the TTLV value to the specified type.
        ///
        /// Supports casting integer types, enumerations, and other compatible types.
        /// The casting follows Zig's type conversion rules with additional support
        /// for TTLV-specific types like enumerations.
        ///
        /// Args:
        ///   - As: The target type to cast to
        ///
        /// Returns:
        ///   The value cast to the specified type
        ///
        /// Errors:
        ///   Returns an error if the cast is not valid or supported
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

        /// Cleans up all resources used by this TTLV element and its children.
        ///
        /// This method recursively deinitializes all child elements in structures
        /// and frees any allocated memory. Only call this on the root TTLV element
        /// as it will handle cleanup of the entire tree.
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

        /// Decodes a TTLV element from a reader stream.
        ///
        /// Args:
        ///   - allocator: The allocator to use for memory management
        ///   - reader: The input stream to read TTLV data from
        ///
        /// Returns:
        ///   A decoded TTLV instance
        ///
        /// Errors:
        ///   Returns an error if decoding fails due to invalid data or memory allocation
        pub fn decode(allocator: std.mem.Allocator, reader: AnyReader) anyerror!Self {
            return try decodeInternal(allocator, reader);
        }

        /// Decodes a TTLV element from a byte buffer.
        ///
        /// Args:
        ///   - allocator: The allocator to use for memory management
        ///   - buffer: The byte buffer containing TTLV data
        ///
        /// Returns:
        ///   A decoded TTLV instance
        ///
        /// Errors:
        ///   Returns an error if decoding fails due to invalid data or memory allocation
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

        /// Encodes this TTLV element to a writer stream.
        ///
        /// Writes the complete TTLV binary representation including tag, type, length,
        /// and value with proper padding according to the TTLV specification.
        ///
        /// Args:
        ///   - writer: The output stream to write TTLV data to
        ///
        /// Returns:
        ///   The total number of bytes written including headers and padding
        ///
        /// Errors:
        ///   Returns an error if writing fails or the value type is unsupported
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

        /// Returns the total encoded length of this TTLV element in bytes.
        ///
        /// Includes the 8-byte header (tag + type + length) plus the padded value length.
        /// For structures, this includes the total length of all nested elements.
        ///
        /// Returns:
        ///   The total encoded size in bytes
        pub fn length(self: Self) usize {
            return TTLV_HEADER_LENGTH + paddedLen(self.value.length());
        }

        /// Navigates to a nested TTLV element using a path of tags.
        ///
        /// Traverses the TTLV structure following the specified tag path.
        /// Supports both single tags and arrays of tags for deep navigation.
        ///
        /// Args:
        ///   - tags: Single tag or array of tags defining the path to navigate
        ///
        /// Returns:
        ///   A pointer to the TTLV element at the specified path
        ///
        /// Errors:
        ///   Returns an error if the path is not found or type mismatch occurs
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

        /// Returns a list of all TTLV elements matching the specified tag path.
        ///
        /// Collects all child elements that match the final tag in the path.
        /// Useful for finding multiple elements with the same tag within a structure.
        ///
        /// Args:
        ///   - allocator: The allocator to use for the returned list
        ///   - tags: Single tag or array of tags defining the path to search
        ///
        /// Returns:
        ///   An ArrayList containing pointers to all matching TTLV elements
        ///
        /// Errors:
        ///   Returns an error if memory allocation fails or type mismatch occurs
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

        /// Prints a human-readable representation of this TTLV structure to stdout.
        ///
        /// Recursively displays the entire TTLV tree with proper indentation
        /// showing tags, types, and values for debugging purposes.
        ///
        /// Errors:
        ///   Returns an error if printing fails
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

        /// Returns an iterator for traversing direct children of this TTLV structure.
        ///
        /// Only iterates through immediate children, does not recurse into nested structures.
        /// The TTLV element must be a structure type.
        ///
        /// Returns:
        ///   An Iterator instance for this TTLV's children
        pub fn iterate(self: *const Self) Iterator {
            return Iterator.init(self);
        }

        /// Returns a walker for recursively traversing the entire TTLV tree.
        ///
        /// Performs a depth-first traversal of all nested structures and their children.
        /// The walker manages its own memory for the traversal stack.
        ///
        /// Args:
        ///   - allocator: The allocator to use for the walker's internal stack
        ///
        /// Returns:
        ///   A Walker instance for recursive traversal
        ///
        /// Errors:
        ///   Returns an error if memory allocation for the stack fails
        pub fn walk(self: *const Self, allocator: Allocator) !Walker {
            return try Walker.init(allocator, self);
        }

        /// Iterator for traversing direct children of a TTLV structure.
        ///
        /// Provides sequential access to child elements without recursing into
        /// nested structures. Use Walker for recursive traversal.
        pub const Iterator = struct {
            index: usize,
            ttlv: *const Self,

            /// Creates a new iterator for the given TTLV structure.
            ///
            /// Args:
            ///   - ttlv: The TTLV structure to iterate over
            ///
            /// Returns:
            ///   A new Iterator instance positioned at the beginning
            pub fn init(ttlv: *const Self) Iterator {
                return Iterator{
                    .index = 0,
                    .ttlv = ttlv,
                };
            }

            /// Returns the next child element and advances the iterator.
            ///
            /// Returns:
            ///   The next TTLV child element, or null if at the end
            pub fn next(self: *Iterator) ?*Self {
                const item = self.peek();

                self.index += 1;

                return item;
            }

            /// Returns the current child element without advancing the iterator.
            ///
            /// Returns:
            ///   The current TTLV child element, or null if at the end
            pub fn peek(self: *Iterator) ?*Self {
                const s = self.ttlv.value.structure;
                if (self.index >= s.items.len) return null;

                const item = s.items[self.index];

                return item;
            }

            /// Resets the iterator to the beginning.
            pub fn reset(self: *Iterator) void {
                self.index = 0;
            }
        };

        /// Walker for recursive depth-first traversal of TTLV structures.
        ///
        /// Traverses the entire TTLV tree, visiting all nested structures and their
        /// children in depth-first order. Manages its own stack for traversal state.
        pub const Walker = struct {
            const StackItem = struct {
                root: ?*Self = null,
                iterator: Iterator,
                len: usize,
            };

            ttlv: *const Self,
            allocator: Allocator,
            stack: std.ArrayListUnmanaged(StackItem),

            /// Creates a new walker for the given TTLV structure.
            ///
            /// Args:
            ///   - allocator: The allocator to use for the traversal stack
            ///   - ttlv: The root TTLV structure to walk
            ///
            /// Returns:
            ///   A new Walker instance ready for traversal
            ///
            /// Errors:
            ///   Returns an error if memory allocation for the stack fails
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

            /// Returns the next TTLV element in depth-first order.
            ///
            /// Visits all leaf nodes (non-structure elements) and structure nodes
            /// in depth-first traversal order. Structure nodes are returned after
            /// all their children have been visited.
            ///
            /// Returns:
            ///   The next TTLV element, or null when traversal is complete
            ///
            /// Errors:
            ///   Returns an error if stack allocation fails during traversal
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

            /// Cleans up the walker's internal resources.
            ///
            /// Must be called when the walker is no longer needed to free
            /// the memory used by the traversal stack.
            pub fn deinit(self: *Walker) void {
                self.stack.deinit(self.allocator);
            }
        };
    };
}

/// Options for extending the default KMIP tag enumeration with custom tags.
pub const ExtendOptions = struct {
    /// Whether the extended enumeration should be exhaustive (no catch-all variant)
    is_exhaustive: bool = false,
};

/// Extends the default KMIP TagType enumeration with custom tags.
///
/// Creates a new TTLV type that includes all standard KMIP tags plus
/// additional custom tags defined in the Extensions enum. This allows
/// for protocol extensions while maintaining compatibility with standard KMIP.
///
/// Args:
///   - Extensions: An enum type containing additional tag definitions
///   - options: Configuration options for the extended enumeration
///
/// Returns:
///   A TTLV type with the extended tag enumeration
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

/// Standard TTLV type using the KMIP TagType enumeration.
///
/// This is the main TTLV type for working with standard KMIP protocol
/// messages. It includes all official KMIP tags and value types.
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
