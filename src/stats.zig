//! Process-wide counters, shared by all workers.
const std = @import("std");

pub var accepted: std.atomic.Value(u64) = .init(0);
pub var active_tcp: std.atomic.Value(u64) = .init(0);
pub var requests: std.atomic.Value(u64) = .init(0);
pub var requests_h3: std.atomic.Value(u64) = .init(0);
pub var refused_per_ip: std.atomic.Value(u64) = .init(0);
/// QUIC datagrams handed to the worker owning their connection.
pub var quic_steered: std.atomic.Value(u64) = .init(0);

pub fn inc(v: *std.atomic.Value(u64)) void {
    _ = v.fetchAdd(1, .monotonic);
}

pub fn dec(v: *std.atomic.Value(u64)) void {
    _ = v.fetchSub(1, .monotonic);
}

/// nginx `stub_status`-style text.
pub fn format(buf: []u8, quic_connections: usize) []const u8 {
    return std.fmt.bufPrint(buf,
        \\Active connections: {d}
        \\  tcp: {d}
        \\  quic (this worker): {d}
        \\accepted: {d}
        \\requests: {d}
        \\  http/3: {d}
        \\refused per-ip: {d}
        \\quic steered: {d}
        \\
    , .{
        active_tcp.load(.monotonic) + quic_connections,
        active_tcp.load(.monotonic),
        quic_connections,
        accepted.load(.monotonic),
        requests.load(.monotonic),
        requests_h3.load(.monotonic),
        refused_per_ip.load(.monotonic),
        quic_steered.load(.monotonic),
    }) catch "stats unavailable\n";
}
