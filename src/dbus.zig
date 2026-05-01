const std = @import("std");

const Io     = std.Io;
const Stream = Io.net.Stream;

const Signature = struct {
    signature: []const u8,
};
const ObjectPath = struct {
    path: []const u8,
};

pub const Client = struct {
    reader: Stream.Reader,
    writer: Stream.Writer,

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
            .reader = stream.reader(io, buf[0..buf.len/2]),
            .writer = stream.writer(io, buf[buf.len/2..]),
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
        try client.writer.interface.print(format, args);
        try client.writer.interface.writeAll("\r\n");
        try client.writer.interface.flush();
    }
    fn expectAuthResponsePrefix(client: *Client, prefix: []const u8) AuthenticationError!void {
        var line = try client.reader.interface.takeDelimiterInclusive('\n');
        if (!std.mem.endsWith(u8, line, "\r\n")) return error.UnexpectedResponse;
        line = line[0..line.len - 2];

        if (!std.mem.startsWith(u8, line, prefix)
                or (line.len > prefix.len and line[prefix.len] != ' ')) {
            std.debug.print("Client sent `{s}' while we were looking for a `{s}' response\n", .{line, prefix});
            return error.UnexpectedResponse;
        }
    }

    pub fn authenticate(client: *Client) AuthenticationError!void {
        try client.writer.interface.writeByte(0);

        var uid_arr: [20]u8 = undefined;

        try client.sendAuthCommand("AUTH EXTERNAL {x}", .{getASCIIUid(&uid_arr)});
        try client.expectAuthResponsePrefix("OK");
        try client.sendAuthCommand("NEGOTIATE_UNIX_FD", .{});
        try client.expectAuthResponsePrefix("AGREE_UNIX_FD");
        try client.sendAuthCommand("BEGIN", .{});

        std.debug.print("Successfully authenticated with DBus\n", .{});
    }

    fn alignTo(self: *Client, comptime bytes: usize) !void {
        if (bytes == 0) @compileError("cannot align to 0 bytes");

        const new = std.mem.alignForward(usize, self.written, bytes);
        try self.writer.interface.splatByteAll(0, new - self.written);
        self.written = new;
    }

    const Operation = enum {
        write,
        signature,
    };
    fn OperationArgs(operation: Operation, T: type) type {
        return switch (operation) {
            .write => struct {value: T, endian: std.builtin.Endian, client: *Client},
            .signature => *[]const u8,
        };
    }

    fn runValueOperation(comptime T: type, comptime Op: Operation, toplevel: bool, args: OperationArgs(Op, T)) !void {
        switch (@typeInfo(T)) {
            .bool => return switch (Op) {
                .write => runValueOperation(u32, Op, false, .{.value = @intFromBool(args.value), .endian = args.endian, .client = args.client}),
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
                        try args.client.alignTo(bytes);
                        try args.client.writer.interface.writeInt(T, args.value, args.endian);
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
                return runValueOperation(e.tag_type, Op, false, switch (Op) {
                    .write => .{.value = @intFromEnum(args.value), .endian = args.endian, .client = args.client},
                    .signature => args,
                });
            },
            .@"struct" => |s| {
                if (s.layout == .@"packed") {
                    if (s.backing_integer) |i| {
                        return runValueOperation(i, Op, false, switch (Op) {
                            .write => .{.value = @bitCast(args.value), .endian = args.endian, .client = args.client},
                            .signature => args,
                        });
                    }
                    @compileError("packed structs without backing integer not supported");
                }

                switch (Op) {
                    .write => try args.client.alignTo(8),
                    .signature => if (!toplevel) {
                        args.* = args.* ++ "(";
                    }
                }

                inline for (s.fields) |field| {
                    if (field.alignment != null)
                        @compileError("alignment on struct members not supported");
                    if (field.is_comptime) continue;

                    try runValueOperation(field.type, Op, false, switch (Op) {
                        .write => .{.value = @field(args.value, field.name), .endian = args.endian, .client = args.client},
                        .signature => args,
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
                if (p.size != .slice) @compileError("pointer are not supported");
                if (p.address_space != .generic) @compileError("address spaces not supported");
                if (p.alignment != null) @compileError("aligned slices/pointers not supported");
                if (!p.is_const) @compileError("non-const slices not supported");

                switch (Op) {
                    .write => @compileError("TODO: write slices"),
                    .signature => {
                        args.* = args.* ++ "a";
                        return runValueOperation(p.child, Op, false, args);
                    },
                }
            },
            .@"union" => |u| {
                if (u.tag_type) |Inner| {
                    switch (@typeInfo(Inner)) {
                        .@"enum" => |e| {
                            switch (Op) {
                                .write => @compileError("TODO: write tagged variants"),
                                .signature => {
                                    args.* = args.* ++ "(";
                                    try runValueOperation(e.tag_type, Op, false, args);
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

    pub fn writeValueRaw(self: *Client, value: anytype, endian: std.builtin.Endian) !void {
        try runValueOperation(@TypeOf(value), .write, true, .{.value = value, .endian = endian, .client = self});
        try self.writer.interface.flush();
    }

    pub fn getSignature(T: type) ![]const u8 {
        var signature: []const u8 = "";
        try runValueOperation(T, .signature, true, &signature);
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
        interface:    []const u8,
        member:       []const u8,
        error_name:   []const u8,
        reply_serial: u32,
        destination:  []const u8,
        sender:       []const u8,
        signature:    Signature,
        unix_fds:     u32,
    },

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
