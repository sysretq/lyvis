const std = @import("std");
const dbus = @import("dbus.zig");

pub fn main(init: std.process.Init) !void {
    const envmap = init.environ_map;
    const io = init.io;

    var buf: [8192]u8 = undefined;
    var client: dbus.Client = try .connect(io, envmap, &buf);
    try client.authenticate();

    const header: dbus.Header = .{
        .type = .method_call,
        .length = 0,
        .serial = 1,
        .fields = &.{
            .{ .path = .initComptime("/org/freedesktop/DBus") },
            .{ .interface = "org.freedesktop.DBus" },
            .{ .destination = "org.freedesktop.DBus" },
            .{ .member = "Hello" },
        },
    };

    try client.writeValueRaw(header, .native);

    // std.debug.print("Header signature: {s}\n", .{try dbus.Client.getSignature(dbus.Header)});

    var stdout_buf: [1]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    _ = try client.stream_reader.interface.streamRemaining(&stdout_writer.interface);
}
