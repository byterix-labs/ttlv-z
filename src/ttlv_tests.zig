const std = @import("std");
const testing = std.testing;
const Ttlv = @import("ttlv.zig").Ttlv;
const ConduitObject = @import("conduit").Object;

test "encode decode integer" {
    var expected = Ttlv.init(.buildDate, .{ .integer = 42 }, .{});

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 16);
    try testing.expectEqual(expected.length(), 16);

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    try testing.expect(actual.tag == expected.tag);
    try testing.expect(actual.value.integer == expected.value.integer);
}

test "encode decode long integer" {
    var expected = Ttlv.init(.buildDate, .{ .longInteger = 42 }, .{});

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 16);
    try testing.expectEqual(16, expected.length());

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    try testing.expect(actual.tag == expected.tag);
    try testing.expect(actual.value.longInteger == expected.value.longInteger);
}

test "encode decode big integer" {
    var expected = Ttlv.init(.buildDate, .{ .bigInteger = 42 }, .{});

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 24);
    try testing.expectEqual(24, expected.length());

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    try testing.expect(actual.tag == expected.tag);
    try testing.expect(actual.value.bigInteger == expected.value.bigInteger);
}

test "encode decode enumeration" {
    var expected = Ttlv.init(.buildDate, .{ .enumeration = 42 }, .{});

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 16);
    try testing.expectEqual(16, expected.length());

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    try testing.expect(actual.tag == expected.tag);
    try testing.expect(actual.value.enumeration == expected.value.enumeration);
}

test "encode decode boolean" {
    var expected = Ttlv.init(.buildDate, .{ .boolean = true }, .{});

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 16);
    try testing.expectEqual(16, expected.length());

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    try testing.expect(actual.tag == expected.tag);
    try testing.expect(actual.value.boolean == expected.value.boolean);
}

test "encode decode date time" {
    var expected = Ttlv.init(.buildDate, .{ .dateTime = 42 }, .{});

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 16);
    try testing.expectEqual(16, expected.length());

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    try testing.expect(actual.tag == expected.tag);
    try testing.expect(actual.value.dateTime == expected.value.dateTime);
}

test "encode decode interval" {
    var expected = Ttlv.init(.buildDate, .{ .interval = 42 }, .{});
    defer expected.deinit();

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 16);
    try testing.expectEqual(16, expected.length());

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    try testing.expect(actual.tag == expected.tag);
    try testing.expect(actual.value.interval == expected.value.interval);
}

test "encode decode text string" {
    var expected = Ttlv.textString(.buildDate, "hello world 👍");
    defer expected.deinit();

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 24);
    try testing.expectEqual(24, expected.length());

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    try testing.expectEqual(expected.tag, actual.tag);
    try testing.expect(std.mem.eql(u8, actual.value.textString, expected.value.textString));
}

test "encode decode byte string" {
    const byte_string = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var expected = Ttlv.init(.buildDate, .{ .byteString = try ConduitObject.initBuffer(testing.allocator, &byte_string) }, .{});
    defer expected.deinit();

    var bs = expected.value.byteString;
    var reader = try bs.reader();

    var test_buf: [byte_string.len]u8 = undefined;
    _ = try reader.readAll(&test_buf);

    var buffer: [100]u8 = undefined;
    @memset(&buffer, 0);

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const len = try expected.encode(writer);
    try testing.expect(len == 16);
    try testing.expectEqual(16, expected.length());

    stream.reset();
    var actual = try Ttlv.decode(testing.allocator, stream.reader().any());
    defer actual.deinit();

    const actual_byte_string = try actual.value.byteString.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(actual_byte_string);

    const expected_byte_string = try expected.value.byteString.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(expected_byte_string);

    try testing.expect(actual.tag == expected.tag);
    try testing.expect(std.mem.eql(u8, expected_byte_string, actual_byte_string));
}

test "encode decode structure" {
    const protocolVersion = Ttlv.init(.protocolVersion, .{ .integer = 6 }, .{});

    var requestHeader = try Ttlv.structure(testing.allocator, .requestHeader);
    try requestHeader.append(protocolVersion);

    const requestPayload = Ttlv.textString(.requestPayload, "Hello, world!");

    var expected = try Ttlv.structure(testing.allocator, .requestMessage);
    defer expected.deinit();

    try expected.append(requestHeader);
    try expected.append(requestPayload);

    var buffer: [1024]u8 = undefined;

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();
    const expected_len = try expected.encode(writer);

    stream.reset();
    stream.buffer = buffer[0..expected_len];

    var counting_reader = std.io.countingReader(stream.reader());

    var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
    defer actual.deinit();

    try testing.expectEqual(expected_len, counting_reader.bytes_read);

    @memset(&buffer, 0);
    stream.reset();
    const actual_len = try actual.encode(writer);

    try testing.expectEqual(expected_len, actual_len);
    try testing.expectEqual(.requestMessage, actual.tag);

    const actual_request_header = actual.value.structure.items[0];
    try testing.expectEqual(.requestHeader, actual_request_header.tag);
    try testing.expectEqual(1, actual_request_header.value.structure.items.len);

    const actual_protocol_version = actual_request_header.value.structure.items[0];
    try testing.expectEqual(.protocolVersion, actual_protocol_version.tag);
    try testing.expectEqual(6, actual_protocol_version.value.integer);

    const actual_request_payload = actual.value.structure.items[1];
    try testing.expectEqual(.requestPayload, actual_request_payload.tag);
    try testing.expectEqualStrings("Hello, world!", actual_request_payload.value.textString);
}

test "kmip spec examples" {
    if (true) {
        return;
    }

    {
        // An Integer containing the decimal value 8:
        // 42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00
        const ttlv: [16]u8 = [16]u8{
            0x42, 0x00, 0x20, // Tag
            0x02, // Type (Integer)
            0x00, 0x00, 0x00, 0x04, // Length (4 bytes)
            0x00, 0x00, 0x00, 0x08, // Value (integer 8)
            0x00, 0x00, 0x00, 0x00, // Padding (4 bytes)
        };

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 16);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqual(actual.value.integer, 0x8);
    }

    {
        // A Long Integer containing the decimal value 123456789000000000:
        // 42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00
        const ttlv: [16]u8 = [16]u8{
            0x42, 0x00, 0x20, // Tag
            0x03, // Type (Long Integer)
            0x00, 0x00, 0x00, 0x08, // Length (8 bytes)
            0x01, 0xB6, 0x9B, 0x4B, 0xA5, 0x74, 0x92, 0x00, // Value (long integer 123456789000000000)
        };

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 16);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqual(actual.value.longInteger, 123456789000000000);
    }

    {
        // A Big Integer containing the decimal value 1234567890000000000000000000:
        // 42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08 00 00
        const ttlv: [24]u8 = [24]u8{
            0x42, 0x00, 0x20, // Tag
            0x04, // Type (Big Integer)
            0x00, 0x00, 0x00, 0x10, // Length (16 bytes)
            0x00, 0x00, 0x00, 0x00, 0x03, 0xFD, 0x35, 0xEB, 0x6B, 0xC2, 0xDF, 0x46, 0x18, 0x08, 0x00, 0x00, // Value (big integer 1234567890000000000000000000)
        };

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 24);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqual(actual.value.bigInteger, 1234567890000000000000000000);
    }

    {
        // An Enumeration with value 255:
        // 42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
        const ttlv: [16]u8 = [16]u8{
            0x42, 0x00, 0x20, // Tag
            0x05, // Type (Enumeration)
            0x00, 0x00, 0x00, 0x04, // Length (4 bytes)
            0x00, 0x00, 0x00, 0xFF, // Value (enumeration 255)
            0x00, 0x00, 0x00, 0x00, // Padding (4 bytes)
        };

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 16);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqual(actual.value.enumeration, 0xFF);
    }

    {
        // A Boolean with the value True:
        // 42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01
        const ttlv: [16]u8 = [16]u8{
            0x42, 0x00, 0x20, // Tag
            0x06, // Type (Boolean)
            0x00, 0x00, 0x00, 0x08, // Length (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Value (boolean true)
        };

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 16);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqual(actual.value.boolean, true);
    }

    {
        // A Text String with the value "Hello World":
        // 42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00
        const ttlv: [24]u8 = [24]u8{
            0x42, 0x00, 0x20, // Tag
            0x07, // Type (Text String)
            0x00, 0x00, 0x00, 0x0B, // Length (11 bytes)
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, // Value (text string "Hello World")
            0x00, 0x00, 0x00, 0x00, 0x00, // Padding (5 bytes)
        };

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 24);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqualStrings(actual.value.textString, "Hello World");
    }

    {
        // A Byte String with the value { 0x01, 0x02, 0x03 }:
        // 42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00
        const ttlv: [16]u8 = [16]u8{
            0x42, 0x00, 0x20, // Tag
            0x08, // Type (Byte String)
            0x00, 0x00, 0x00, 0x03, // Length (3 bytes)
            0x01, 0x02, 0x03, // Value (byte string { 0x01, 0x02, 0x03 })
            0x00, 0x00, 0x00, 0x00, 0x00, // Padding (5 bytes)
        };

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        const byte_string = try actual.value.byteString.toOwnedSlice(testing.allocator);
        defer testing.allocator.free(byte_string);

        try testing.expectEqual(counting_reader.bytes_read, 16);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqual(actual.value.byteString.len, 3);
        try testing.expectEqual(byte_string[0], 0x01);
        try testing.expectEqual(byte_string[1], 0x02);
        try testing.expectEqual(byte_string[2], 0x03);
    }

    {
        // A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT:
        // 42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8
        const ttlv: [16]u8 = [16]u8{
            0x42, 0x00, 0x20, // Tag
            0x09, // Type (Date-Time)
            0x00, 0x00, 0x00, 0x08, // Length (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x47, 0xDA, 0x67, 0xF8, // Value (date-time for Friday, March 14, 2008, 11:56:40 GMT)
        };

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 16);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqual(actual.value.dateTime, 0x47DA67F8);
    }

    {
        // An Interval, containing the value for 10 days:
        // 42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00
        const ttlv: [16]u8 = [16]u8{
            0x42, 0x00, 0x20, // Tag
            0x0A, // Type (Interval)
            0x00, 0x00, 0x00, 0x04, // Length (4 bytes)
            0x00, 0x0D, 0x2F, 0x00, // Value (interval for 10 days)
            0x00, 0x00, 0x00, 0x00, // Padding (4 bytes)
        };

        const ten_days_in_seconds: u32 = 10 * 24 * 60 * 60;

        var stream = std.io.fixedBufferStream(&ttlv);
        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 16);
        try testing.expectEqual(actual.tag, .compromiseDate);
        try testing.expectEqual(ten_days_in_seconds, actual.value.interval);
    }

    {
        // A Structure containing an Enumeration, value 254, followed by an Integer, value 255, having tags 420004 and 420005 respectively:
        // 42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE 00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
        const ttlv: [40]u8 = [40]u8{
            0x42, 0x00, 0x20, // Tag
            0x01, // Type (Structure)
            0x00, 0x00, 0x00, 0x20, // Length (32 bytes)
            0x42, 0x00, 0x04, // Tag
            0x05, // Type (Enumeration)
            0x00, 0x00, 0x00, 0x04, // Length (4 bytes)
            0x00, 0x00, 0x00, 0xFE, // Value (enumeration 254)
            0x00, 0x00, 0x00, 0x00, // Padding (4 bytes)
            0x42, 0x00, 0x05, // Tag
            0x02, // Type (Integer)
            0x00, 0x00, 0x00, 0x04, // Length (4 bytes)
            0x00, 0x00, 0x00, 0xFF, // Value (integer 255)
            0x00, 0x00, 0x00, 0x00, // Padding (4 bytes)
        };

        var stream = std.io.fixedBufferStream(&ttlv);

        var counting_reader = std.io.countingReader(stream.reader());

        var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
        defer actual.deinit();

        try testing.expectEqual(counting_reader.bytes_read, 40);
        try testing.expectEqual(.compromiseDate, actual.tag);
        try testing.expectEqual(2, actual.value.structure.items.len);

        const child_0 = actual.value.structure.items[0];
        try testing.expectEqual(.applicationSpecificInformation, child_0.tag);
        try testing.expectEqual(0xFE, child_0.value.enumeration);

        const child_1 = actual.value.structure.items[1];
        try testing.expectEqual(.archiveDate, child_1.tag);
        try testing.expectEqual(0xFF, child_1.value.integer);
    }
}

test "structure length" {
    const protocol_version = Ttlv.init(.protocolVersion, .{ .integer = 6 }, .{});

    const protocol_version_length = protocol_version.length();

    var request_header = try Ttlv.structure(testing.allocator, .requestHeader);
    try request_header.append(protocol_version);

    try testing.expectEqual(8 + protocol_version_length, request_header.length());

    var request_payload = Ttlv.textString(.requestPayload, "Hello, world!");

    var expected = try Ttlv.structure(testing.allocator, .requestMessage);
    defer expected.deinit();

    try testing.expectEqual(8, expected.length());

    try expected.append(request_header);

    try testing.expectEqual(8 + request_header.length(), expected.length());

    try expected.append(request_payload);

    try testing.expectEqual(8 + request_header.length() + request_payload.length(), expected.length());

    var buffer: [1024]u8 = undefined;

    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();
    const expected_len = try expected.encode(writer);

    try testing.expectEqual(expected.length(), expected_len);

    stream.reset();
    stream.buffer = buffer[0..expected_len];

    var counting_reader = std.io.countingReader(stream.reader());

    var actual = try Ttlv.decode(testing.allocator, counting_reader.reader().any());
    defer actual.deinit();

    try testing.expectEqual(expected_len, counting_reader.bytes_read);

    @memset(&buffer, 0);
    stream.reset();

    const actual_len = try actual.encode(writer);

    try testing.expectEqual(expected_len, actual_len);
    try testing.expectEqual(.requestMessage, actual.tag);

    const actual_request_header = actual.value.structure.items[0];
    try testing.expectEqual(.requestHeader, actual_request_header.tag);
    try testing.expectEqual(1, actual_request_header.value.structure.items.len);

    const actual_protocol_version = actual_request_header.value.structure.items[0];
    try testing.expectEqual(.protocolVersion, actual_protocol_version.tag);
    try testing.expectEqual(6, actual_protocol_version.value.integer);

    const actual_request_payload = actual.value.structure.items[1];
    try testing.expectEqual(.requestPayload, actual_request_payload.tag);
    try testing.expectEqualStrings("Hello, world!", actual_request_payload.value.textString);
}
