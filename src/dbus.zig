const std = @import("std");

const Io     = std.Io;
const Stream = Io.net.Stream;

const String = [:0]const u8;
const Signature = struct {
    bytes: []const u8,
};
pub const ObjectPath = struct {
    bytes: []const u8,

    pub fn init(path: []const u8) error{InvalidObjectPath}!ObjectPath {
        if (path.len == 0 or path[0] != '/') return error.InvalidObjectPath;

        var it = std.mem.splitScalar(u8, path[1..], '/');
        while (it.next()) |slice| {
            for (slice) |c| {
                if ((c < 'A' or c > 'Z') and (c < 'a' or c > 'z') and (c < '0' or c > '9') and c != '_')
                    return error.InvalidObjectPath;
            }
            if (slice.len == 0) return error.InvalidObjectPath;
        }

        if (path.len > 1 and path[path.len - 1] == '/') return error.InvalidObjectPath;
        return .{.bytes = path};
    }

    pub fn initComptime(comptime path: []const u8) ObjectPath {
        return comptime init(path) catch unreachable;
    }
};

pub const Client = struct {
    stream_reader: Stream.Reader,
    stream_writer: Stream.Writer,

    written: usize = 0,

    pub const Transport = enum {
        unix,
    };

    pub const ConnectError = error {
        NoSessionBusAddres,
        NoValidAddress,
    } || Io.net.UnixAddress.InitError;

    pub fn init(io: Io, buf: []u8, stream: Stream) Client {
        return .{
            .stream_reader = stream.reader(io, buf[0..buf.len/2]),
            .stream_writer = stream.writer(io, buf[buf.len/2..]),
        };
    }

    pub fn connect(io: Io, envmap: *const std.process.Environ.Map, buf: []u8) ConnectError!Client {
        const bus_addresss = envmap.get("DBUS_SESSION_BUS_ADDRESS") orelse return error.NoSessionBusAddres;

        var reader = Io.Reader.fixed(bus_addresss);
        while (reader.takeDelimiter(';') catch unreachable) |address| {
            var inner = Io.Reader.fixed(address);
            const transport_string = inner.takeDelimiter(':') catch unreachable orelse break;

            const transport: Transport = blk: {
                inline for (std.meta.tags(Transport)) |tag| {
                    if (std.mem.eql(u8, transport_string, @tagName(tag))) {
                        break :blk tag;
                    }
                }
                std.debug.print("skipping unsupported transport protocol `{s}'", .{transport_string});
                continue;
            };

            while (inner.takeDelimiter(',') catch unreachable) |prop| {
                var it = std.mem.splitScalar(u8, prop, '=');
                const key = it.next() orelse continue;
                const val = it.next() orelse continue;

                switch (transport) {
                    .unix => {
                        if (std.mem.eql(u8, key, "path")) {
                            std.debug.print("Connecting to UNIX socket: {s}\n", .{val});
                            const addr = try Io.net.UnixAddress.init(val);
                            return .init(io, buf, addr.connect(io) catch |err| {
                                std.debug.print("Could not connect to UNIX socket: {t}. skipping", .{err});
                                continue;
                            });
                        } else {
                            std.debug.print("skipping invalid option `{s}: {s}'\n", .{key, val});
                        }
                    },
                }
            }
        }

        return error.NoValidAddress;
    }

    const AuthenticationError = error {
        UnexpectedResponse,
    } || Io.Writer.Error || Io.Reader.Error || Io.Reader.DelimiterError;

    fn getASCIIUid(arr: *[20]u8) []u8 {
        const uid = std.posix.system.getuid();
        var uid_writer = Io.Writer.fixed(arr);
        uid_writer.print("{d}", .{uid}) catch unreachable;
        return uid_writer.buffered();
    }

    fn sendAuthCommand(client: *Client, comptime format: []const u8, args: anytype) !void {
        try client.stream_writer.interface.print(format, args);
        try client.stream_writer.interface.writeAll("\r\n");
        try client.stream_writer.interface.flush();
    }
    fn expectAuthResponsePrefix(client: *Client, prefix: []const u8) AuthenticationError!void {
        var line = try client.stream_reader.interface.takeDelimiterInclusive('\n');
        if (!std.mem.endsWith(u8, line, "\r\n")) return error.UnexpectedResponse;
        line = line[0..line.len - 2];

        if (!std.mem.startsWith(u8, line, prefix)
                or (line.len > prefix.len and line[prefix.len] != ' ')) {
            std.debug.print("Client sent `{s}' while we were looking for a `{s}' response\n", .{line, prefix});
            return error.UnexpectedResponse;
        }
    }

    pub fn authenticate(client: *Client) AuthenticationError!void {
        try client.stream_writer.interface.writeByte(0);

        var uid_arr: [20]u8 = undefined;

        try client.sendAuthCommand("AUTH EXTERNAL {x}", .{getASCIIUid(&uid_arr)});
        try client.expectAuthResponsePrefix("OK");
        try client.sendAuthCommand("NEGOTIATE_UNIX_FD", .{});
        try client.expectAuthResponsePrefix("AGREE_UNIX_FD");
        try client.sendAuthCommand("BEGIN", .{});

        std.debug.print("Successfully authenticated with DBus\n", .{});
    }

    fn alignTo(self: *Client, writer: *Io.Writer, comptime bytes: usize) !void {
        if (bytes == 0) @compileError("cannot align to 0 bytes");

        const new = std.mem.alignForward(usize, self.written, bytes);
        try writer.splatByteAll(0, new - self.written);
        self.written = new;
    }

    const Operation = enum {
        write,
        signature,
    };
    fn OperationArgs(operation: Operation, T: type) type {
        return switch (operation) {
            .write => struct {value: T, endian: std.builtin.Endian, client: *Client, writer: *Io.Writer},
            .signature => *[]const u8,
        };
    }

    inline fn combineStructs(Target: type, orig: anytype, updates: anytype) Target {
        const Orig = @TypeOf(orig);
        const Updates = @TypeOf(updates);
        if (std.meta.fields(Updates).len == 0) return orig;

        var new: Target = undefined;
        inline for (std.meta.fields(Orig)) |f| {
            if (!@hasField(Updates, f.name))
                @field(new, f.name) = @field(orig, f.name);
        }
        inline for (std.meta.fields(Updates)) |f| {
            @field(new, f.name) = @field(updates, f.name);
        }
        return new;
    }
    fn runValueOperationRecursive(comptime T: type, comptime Op: Operation, args_prev: anytype, new_args: anytype) !void {
        return runValueOperation(T, Op, false, combineStructs(OperationArgs(Op, T), args_prev, new_args));
    }

    fn runValueOperation(comptime T: type, comptime Op: Operation, toplevel: bool, args: OperationArgs(Op, T)) !void {
        if (T == ObjectPath or T == String or T == Signature) {
            switch (Op) {
                .write => {
                    const bytes: []const u8 = if (T == String) args.value else args.value.bytes;

                    const Type = if (T == Signature) u8 else u32;
                    try args.client.alignTo(args.writer, @sizeOf(Type));

                    try args.writer.writeInt(Type, @intCast(bytes.len), args.endian);
                    var iovec: [2][]const u8 = .{bytes, "\x00"};
                    try args.writer.writeVecAll(&iovec);

                    args.client.written += @sizeOf(Type) + bytes.len + 1;
                },
                .signature => args.* = args.* ++ if (T == String) "s" else if (T == Signature) "g" else "o",
            }
            return;
        }

        switch (@typeInfo(T)) {
            .bool => return switch (Op) {
                .write => runValueOperationRecursive(u32, Op, args, .{.value = @intFromBool(args.value)}),
                .signature => "b",
            },
            .int => |i| {
                if (i.bits != 8 and i.bits != 16 and i.bits != 32 and i.bits != 64)
                    @compileError(std.fmt.comptimePrint("invalid integer {}", .{T}));
                if (i.bits == 8 and i.signedness == .signed)
                    @compileError("signed bytes (i8) not supported");

                const bytes = @divExact(i.bits, 8);
                switch (Op) {
                    .write => {
                        try args.client.alignTo(args.writer, bytes);
                        try args.writer.writeInt(T, args.value, args.endian);
                        args.client.written += bytes;
                    },
                    .signature => {
                        const unsigned = "yqut";
                        const signed = "?nix";
                        args.* = args.* ++
                            (if (i.signedness == .signed) signed else unsigned)[std.math.log2(bytes)..][0..1];
                    },
                }
            },
            .@"enum" => |e| {
                if (!e.is_exhaustive) @compileError("non-exhaustive enums not allowed");
                return runValueOperationRecursive(e.tag_type, Op, args, switch (Op) {
                    .write => .{.value = @intFromEnum(args.value) },
                    .signature => .{},
                });
            },
            .@"struct" => |s| {
                if (s.layout == .@"packed") {
                    if (s.backing_integer) |Int| {
                        return runValueOperationRecursive(Int, Op, args, switch (Op) {
                            .write => .{.value = @as(Int, @bitCast(args.value))},
                            .signature => .{},
                        });
                    }
                    @compileError("packed structs without backing integer not supported");
                }

                switch (Op) {
                    .write => try args.client.alignTo(args.writer, 8),
                    .signature => if (!toplevel) {
                        args.* = args.* ++ "(";
                    }
                }

                inline for (s.fields) |field| {
                    if (field.alignment != null)
                        @compileError("alignment on struct members not supported");
                    if (field.is_comptime) continue;

                    try runValueOperationRecursive(field.type, Op, args, switch (Op) {
                        .write => .{.value = @field(args.value, field.name)},
                        .signature => .{},
                    });
                }

                switch (Op) {
                    .write => {},
                    .signature => if (!toplevel) {
                        args.* = args.* ++ "(";
                    }
                }
            },
            .pointer => |p| {
                if (p.size != .slice) @compileError("pointers are not supported");
                if (p.address_space != .generic) @compileError("address spaces not supported");
                if (p.alignment != null) @compileError("aligned slices/pointers not supported");
                if (!p.is_const) @compileError("non-const slices not supported");

                switch (Op) {
                    .write => {
                        const written = args.client.written;

                        var buf: [64]u8 = undefined;
                        var discarding: Io.Writer.Discarding = .init(&buf);
                        {
                            defer args.client.written = written;
                            args.client.written = 0;

                            for (args.value) |v| {
                                try runValueOperationRecursive(p.child, Op, args, .{ .value = v, .writer = &discarding.writer });
                            }
                            try discarding.writer.flush();
                            std.debug.assert(discarding.count == args.client.written);
                        }

                        try runValueOperationRecursive(u32, Op, args, .{ .value = @as(u32, @intCast(discarding.count)) });
                        for (args.value) |v| {
                            try runValueOperationRecursive(p.child, Op, args, .{ .value = v });
                        }
                    },
                    .signature => {
                        args.* = args.* ++ "a";
                        return runValueOperationRecursive(p.child, Op, args, .{});
                    },
                }
            },
            .@"union" => |u| {
                if (u.tag_type) |Inner| {
                    switch (@typeInfo(Inner)) {
                        .@"enum" => |e| {
                            switch (Op) {
                                .write => {
                                    // we enumate a struct here, so we also have to do struct alignment (8 bytes)
                                    try args.client.alignTo(args.writer, 8);

                                    try runValueOperationRecursive(e.tag_type, Op, args, .{ .value = @intFromEnum(std.meta.activeTag(args.value)) });
                                    switch (args.value) {
                                        inline else => |v| {
                                            comptime var sig: []const u8 = "";
                                            comptime runValueOperation(@TypeOf(v), .signature, true, &sig) catch unreachable;

                                            try runValueOperationRecursive(Signature, Op, args, .{ .value = Signature{.bytes = sig} });
                                            try runValueOperationRecursive(@TypeOf(v), Op, args, .{ .value = v });
                                        }
                                    }
                                },
                                .signature => {
                                    args.* = args.* ++ "(";
                                    try runValueOperationRecursive(e.tag_type, Op, args, .{});
                                    args.* = args.* ++ "v)";
                                },
                            }
                        },
                        inline else => |_, b| @compileError(std.fmt.comptimePrint("unsupported union tag type `{t}'", .{b})),
                    }
                } else {
                    @compileError("TODO: anonymous variants");
                }
            },
            inline else => |_, b| @compileError(std.fmt.comptimePrint("cannot serialize type `{t}'", .{b})),
        }
    }

    /// Writes a value `value` of any type supported by DBus to the socket references by `self`.
    /// This function is NOT thread safe and expected to be executed atomically.
    /// Doing otherwise may result in interleaved messages, missing data or duplicate writes.
    pub fn writeValueRaw(self: *Client, value: anytype, endian: std.builtin.Endian) !void {
        try runValueOperation(@TypeOf(value), .write, true, .{.value = value, .endian = endian, .client = self, .writer = &self.stream_writer.interface});
        try self.stream_writer.interface.flush();
    }

    pub fn getSignature(T: type) ![]const u8 {
        comptime var signature: []const u8 = "";
        try comptime runValueOperation(T, .signature, true, &signature);
        return signature;
    }
};

pub fn Reserved(comptime bits: u16) type {
    return enum (@Int(.unsigned, bits)) {
        zero = 0,
    };
}

pub const Header = struct {
    endianess : enum(u8) {
        little = 'l',
        big   = 'b',
    } = .little,
    type : enum(u8) {
        method_call   = 1,
        method_reply  = 2,
        error_reply   = 3,
        signal        = 4,
    },
    flags: packed struct(u8) {
        no_reply_expected: bool = false,
        no_auto_start: bool = false,
        allow_interactive_authorization: bool = false,
        _pad : Reserved(5) = .zero,
    } = .{},
    major: u8 = 1,
    length: u32,
    serial: u32,

    fields: []const union(HeaderTag) {
        path:         ObjectPath,
        interface:    String,
        member:       String,
        error_name:   String,
        reply_serial: u32,
        destination:  String,
        sender:       String,
        signature:    Signature,
        unix_fds:     u32,
    },

    _align_to_8: struct {} = .{},

    const HeaderTag = enum(u8) {
        path = 1,
        interface = 2,
        member = 3,
        error_name = 4,
        reply_serial = 5,
        destination = 6,
        sender = 7,
        signature = 8,
        unix_fds = 9,
    };
};
