//! ttlv-z: A Zig library for TTLV (Tag-Type-Length-Value) encoding and decoding.
//!
//! This library provides a complete implementation of the TTLV binary format used
//! in KMIP (Key Management Interoperability Protocol) and other systems. TTLV is
//! a structured binary encoding where each value is preceded by a tag (identifier),
//! type (data type), and length (size in bytes).
//!
//! Key features:
//! - Complete KMIP TTLV value type support (structures, integers, strings, etc.)
//! - Generic tag system allowing custom tag enumerations
//! - Memory-safe with automatic cleanup via arena allocation
//! - Efficient streaming encode/decode operations
//! - Path-based navigation for nested structures
//! - Iterator and walker patterns for tree traversal
//!
//! Example usage:
//! ```zig
//! // Create a TTLV structure
//! var root = try ttlv.Ttlv.structure(allocator, .requestMessage);
//! defer root.deinit();
//!
//! // Add a text string child
//! try root.append(ttlv.Ttlv.textString(.username, "alice"));
//!
//! // Encode to bytes
//! var buffer = std.ArrayList(u8).init(allocator);
//! defer buffer.deinit();
//! _ = try root.encode(buffer.writer());
//! ```

const std = @import("std");
const enums = @import("enums.zig");
const ttlv = @import("ttlv.zig");

/// Re-export all TTLV value types and tag types for convenience.
pub usingnamespace enums;

/// The main TTLV type using standard KMIP tags.
/// This is the primary type for working with KMIP protocol messages.
pub const Ttlv = ttlv.Ttlv;

/// Generic TTLV constructor for custom tag enumerations.
/// Use this to create TTLV types with your own tag definitions.
pub const CustomTtlv = ttlv.CustomTtlv;

test {
    _ = @import("ttlv_tests.zig");

    std.testing.refAllDecls(@This());
}
