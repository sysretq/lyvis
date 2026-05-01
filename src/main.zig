const std = @import("std");
const dbus = @import("dbus.zig");

pub fn main(init: std.process.Init) !void {
    const envmap = init.environ_map;
    const io = init.io;

    var buf: [8192]u8 = undefined;
    var client: dbus.Client = try .connect(io, envmap, &buf);
    try client.authenticate();

    // try client.writer.interface.writeAll("l1\x00\x01\x00\x01");
    const header: dbus.Header = .{
        .type = .method_call,
        .length = 0,
        .serial = 1,
        .fields = &.{},
    };

    std.debug.print("Header signature: {s}\n", .{try dbus.Client.getSignature(dbus.Header)});

    try client.writeValueRaw(header, .native);
    try client.writeValueRaw(@as(u8, 110), .native);

    try client.writer.interface.writeAll("\x00\x00\x00\x01\x01o\x00\x15\x00\x00\x00/org/freedesktop/DBus\x00\x00\x00\x02\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x06\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x03\x01s\x00\x05\x00\x00\x00Hello\x00\x00\x00");
    try client.writer.interface.flush();

    var stdout_buf: [1]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    _ = try client.reader.interface.streamRemaining(&stdout_writer.interface);
}
