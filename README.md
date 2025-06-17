# ttlv-z

A Zig library for TTLV (Tag-Type-Length-Value) encoding and decoding, implementing the [KMIP](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip) specification.

## Overview

ttlv-z provides a complete implementation of the TTLV binary format used in [KMIP](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip) and other systems. TTLV is a structured binary encoding where each value is preceded by a tag (identifier), type (data type), and length (size in bytes).

## Features

- **Complete KMIP Support**: All TTLV value types from KMIP 1.0-3.0 specifications
- **Generic Tag System**: Support for custom tag enumerations beyond standard KMIP
- **Memory Safe**: Automatic cleanup with arena allocation for nested structures
- **Streaming Operations**: Efficient encode/decode with reader/writer interfaces
- **Path Navigation**: Navigate nested structures using tag paths
- **Tree Traversal**: Iterator and walker patterns for exploring complex data
- **Type Safety**: Compile-time type checking for tags and values

## Installation

Add ttlv-z to your project:

```bash
zig fetch --save git+https://github.com/byterix-labs/ttlv-z.git
```

Then in your `build.zig`:

```zig
const ttlv = b.dependency("ttlv", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("ttlv", ttlv.module("ttlv"));
```

## Usage

### Basic TTLV Creation

```zig
const std = @import("std");
const ttlv = @import("ttlv");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a TTLV structure
    var request = try ttlv.Ttlv.structure(allocator, .requestMessage);
    defer request.deinit();

    // Add child elements
    try request.append(ttlv.Ttlv.textString(.username, "alice"));
    try request.append(ttlv.Ttlv.init(.operation, .{ .enumeration = 0x1 }, .{}));

    // Encode to buffer
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    _ = try request.encode(buffer.writer());

    std.debug.print("Encoded {} bytes\n", .{buffer.items.len});
}
```

### Decoding TTLV Data

```zig
// Decode from a byte buffer
const data = [_]u8{ /* TTLV binary data */ };
var decoded = try ttlv.Ttlv.decodeFromBuffer(allocator, &data);
defer decoded.deinit();

// Decode from a reader
var stream = std.io.fixedBufferStream(&data);
var decoded2 = try ttlv.Ttlv.decode(allocator, stream.reader().any());
defer decoded2.deinit();
```

### Navigation and Access

```zig
// Navigate using tag paths
var username_ttlv = try decoded.path(.username);
const username = username_ttlv.value.textString;

// Navigate nested paths
var nested = try decoded.path(.{ .requestMessage, .batchItem, .operation });

// Get multiple elements with the same tag
var attributes = try decoded.list(allocator, .attribute);
defer attributes.deinit();
```

### Tree Traversal

```zig
// Iterate direct children
var iter = decoded.iterate();
while (iter.next()) |child| {
    std.debug.print("Tag: {}\n", .{child.tag});
}

// Walk entire tree
var walker = try decoded.walk(allocator);
defer walker.deinit();

while (try walker.next()) |element| {
    std.debug.print("Found: {}\n", .{element.tag});
}
```

### Custom Tag Types

```zig
// Define your own tag enumeration
const CustomTags = enum(u24) {
    myCustomTag = 0x999001,
    anotherTag = 0x999002,
};

// Create TTLV with custom tags
const CustomTtlv = ttlv.CustomTtlv(CustomTags);

var custom = try CustomTtlv.structure(allocator, .myCustomTag);
defer custom.deinit();
```

### Working with Different Value Types

```zig
// Integer values
var int_ttlv = ttlv.Ttlv.init(.cryptographicLength, .{ .integer = 256 }, .{});

// Boolean values
var bool_ttlv = ttlv.Ttlv.init(.extractable, .{ .boolean = true }, .{});

// Enumeration values (from any enum type)
const MyEnum = enum { option1, option2 };
var enum_ttlv = ttlv.Ttlv.init(.operation, ttlv.Ttlv.Value.initEnum(MyEnum.option1), .{});

// Byte strings (using conduit for efficient streaming)
var conduit_obj = try @import("conduit").Object.init(allocator, .{});
defer conduit_obj.deinit();
var writer = try conduit_obj.writer();
try writer.writeAll("binary data");

var bytes_ttlv = ttlv.Ttlv.init(.certificateValue, .{ .byteString = conduit_obj }, .{ .allocator = allocator });
defer bytes_ttlv.deinit();
```

## API Reference

### Main Types

- `Ttlv` - Standard TTLV using KMIP tags
- `CustomTtlv(TagType)` - Generic TTLV with custom tag enumeration
- `ValueType` - Enumeration of all TTLV value types
- `TagType` - Complete KMIP tag enumeration

### Core Methods

#### Creation
- `init(tag, value, options)` - Create TTLV with tag and value
- `structure(allocator, tag)` - Create empty structure
- `textString(tag, text)` - Create text string value

#### Encoding/Decoding
- `encode(writer)` - Encode to writer stream
- `decode(allocator, reader)` - Decode from reader stream
- `decodeFromBuffer(allocator, buffer)` - Decode from byte buffer

#### Navigation
- `path(tags)` - Navigate to element by tag path
- `list(allocator, tags)` - Get all elements matching tag path
- `append(child)` - Add child to structure
- `appendToPath(path, child)` - Add child to nested structure

#### Traversal
- `iterate()` - Iterator for direct children
- `walk(allocator)` - Walker for recursive traversal
- `dump()` - Debug print of entire structure

#### Utilities
- `length()` - Total encoded size in bytes
- `castValue(Type)` - Cast value to specific type
- `deinit()` - Clean up resources

## Value Types

The library supports all KMIP value types:

| Type | Zig Type | Description |
|------|----------|-------------|
| `structure` | `*ArrayListUnmanaged(*Ttlv)` | Nested TTLV elements |
| `integer` | `i32` | 32-bit signed integer |
| `longInteger` | `i64` | 64-bit signed integer |
| `bigInteger` | `i128` | 128-bit signed integer |
| `enumeration` | `u32` | 32-bit enumeration value |
| `boolean` | `bool` | Boolean (8 bytes encoded) |
| `textString` | `[]const u8` | UTF-8 text string |
| `byteString` | `ConduitObject` | Binary data with streaming |
| `dateTime` | `u64` | Date/time timestamp |
| `interval` | `u32` | Time interval |
| `dateTimeExtended` | `u64` | Extended timestamp |
| `identifier` | `[]const u8` | Object identifier |
| `reference` | `[]const u8` | Object reference |
| `nameReference` | `[]const u8` | Named object reference |

## KMIP Tag Support

The library includes all official KMIP tags from versions 1.0 through 3.0.

## Requirements

- Zig 0.14.1 or later
- [conduit-z](https://github.com/byterix-labs/conduit-z) dependency (automatically managed)
- [temp.zig](https://github.com/abhinav/temp.zig) dependency (automatically managed)

## Development

### Building

```bash
zig build
```

### Testing

```bash
zig build test
```

### Documentation

```bash
zig build docs
```

### Tools

This project uses:
- `zig` 0.14.1
- `zls` 0.14.0 (Zig Language Server)
- `pre-commit` for code quality
- `zlint` for additional linting

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## References

- [KMIP Specification](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip)