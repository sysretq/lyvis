const std = @import("std");

const Io     = std.Io;
const Stream = Io.net.Stream;

const dbus = struct {
    pub const Client = struct {
        reader: Stream.Reader,
        writer: Stream.Writer,

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
    };
};

pub fn main(init: std.process.Init) !void {
    const envmap = init.environ_map;
    const io = init.io;

    var buf: [8192]u8 = undefined;
    var client: dbus.Client = try .connect(io, envmap, &buf);
    try client.authenticate();

    // try client.writer.interface.writeAll("l1\x00\x01\x00\x01");
    try client.writer.interface.writeAll("l\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00n\x00\x00\x00\x01\x01o\x00\x15\x00\x00\x00/org/freedesktop/DBus\x00\x00\x00\x02\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x06\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x03\x01s\x00\x05\x00\x00\x00Hello\x00\x00\x00");
    try client.writer.interface.flush();

    var stdout_buf: [1]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    _ = try client.reader.interface.streamRemaining(&stdout_writer.interface);
}
