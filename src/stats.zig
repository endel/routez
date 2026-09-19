//! Process-wide counters, shared by all workers and generations, and their
//! stub_status and Prometheus renderings.
const std = @import("std");
const builtin = @import("builtin");

pub var accepted: std.atomic.Value(u64) = .init(0);
pub var active_tcp: std.atomic.Value(u64) = .init(0);
/// Published by each worker on its tick, from its QUIC servers' own counts.
pub var accepted_quic: std.atomic.Value(u64) = .init(0);
pub var active_quic: std.atomic.Value(u64) = .init(0);
pub var requests: std.atomic.Value(u64) = .init(0);
pub var requests_h3: std.atomic.Value(u64) = .init(0);
pub var refused_per_ip: std.atomic.Value(u64) = .init(0);
/// QUIC datagrams handed to the worker owning their connection.
pub var quic_steered: std.atomic.Value(u64) = .init(0);
/// Finished responses by protocol (HTTP/1.x, HTTP/3) and status class.
pub var responses: [2][5]std.atomic.Value(u64) = @splat(@splat(.init(0)));
/// Request and response body bytes, the latter as sent (compressed).
pub var request_bytes: std.atomic.Value(u64) = .init(0);
pub var response_bytes: std.atomic.Value(u64) = .init(0);
pub var reloads: std.atomic.Value(u64) = .init(0);
pub var reload_failures: std.atomic.Value(u64) = .init(0);
pub var workers: std.atomic.Value(u64) = .init(0);

/// Set by main.
pub var version: []const u8 = "unknown";
pub var start_time_s: i64 = 0;

pub fn inc(v: *std.atomic.Value(u64)) void {
    _ = v.fetchAdd(1, .monotonic);
}

pub fn dec(v: *std.atomic.Value(u64)) void {
    _ = v.fetchSub(1, .monotonic);
}

pub fn add(v: *std.atomic.Value(u64), n: u64) void {
    if (n != 0) _ = v.fetchAdd(n, .monotonic);
}

/// Count a finished response; `status` 0 (none sent) counts as 5xx.
pub fn response(http3: bool, status: u16) void {
    const class: usize = if (status < 100) 4 else @min(status / 100, 5) - 1;
    inc(&responses[@intFromBool(http3)][class]);
}

/// One upstream server's counters, by upstream and server name. Kept for
/// the life of the process, so reloads don't reset them.
pub const Peer = struct {
    upstream: []const u8,
    server: []const u8,
    /// HTTP requests sent to the server (retries included), WebTransport
    /// sessions and UDP flows.
    requests: std.atomic.Value(u64) = .init(0),
    /// Failed connections and responses (the passive health check's count).
    failures: std.atomic.Value(u64) = .init(0),
    /// The active health check's latest verdict, from whichever worker
    /// probed last: 1 healthy, 0 not.
    healthy: std.atomic.Value(u8) = .init(1),
};

var peers_mutex: std.Io.Mutex = .init;
var peers: std.ArrayListUnmanaged(*Peer) = .empty;

pub fn peer(io: std.Io, upstream_name: []const u8, server: []const u8) !*Peer {
    peers_mutex.lockUncancelable(io);
    defer peers_mutex.unlock(io);
    for (peers.items) |p| {
        if (std.mem.eql(u8, p.upstream, upstream_name) and std.mem.eql(u8, p.server, server)) return p;
    }
    const gpa = std.heap.smp_allocator;
    const p = try gpa.create(Peer);
    errdefer gpa.destroy(p);
    p.* = .{ .upstream = try gpa.dupe(u8, upstream_name), .server = try gpa.dupe(u8, server) };
    try peers.append(gpa, p);
    return p;
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

/// An upstream server as the scraping worker's configuration has it.
pub const UpstreamView = struct {
    stats: *Peer,
    health_checked: bool,
};

/// The Prometheus text exposition format, version 0.0.4.
pub fn prometheus(w: *std.Io.Writer, upstreams: []const UpstreamView) std.Io.Writer.Error!void {
    const load = struct {
        fn f(v: *const std.atomic.Value(u64)) u64 {
            return v.load(.monotonic);
        }
    }.f;
    try header(w, "routez_build_info", "gauge", "Version of routez and of the Zig it was built with.");
    try w.print("routez_build_info{{version=\"{f}\",zig=\"{s}\"}} 1\n", .{ label(version), builtin.zig_version_string });
    try header(w, "routez_start_time_seconds", "gauge", "Unix time the process started.");
    try w.print("routez_start_time_seconds {d}\n", .{start_time_s});
    try header(w, "routez_workers", "gauge", "Worker threads of the running configuration.");
    try w.print("routez_workers {d}\n", .{load(&workers)});
    try header(w, "routez_reloads_total", "counter", "Configuration reloads applied.");
    try w.print("routez_reloads_total {d}\n", .{load(&reloads)});
    try header(w, "routez_reload_failures_total", "counter", "Reloads rejected, the running configuration kept.");
    try w.print("routez_reload_failures_total {d}\n", .{load(&reload_failures)});

    try header(w, "routez_connections_accepted_total", "counter", "Client connections accepted.");
    try w.print("routez_connections_accepted_total{{protocol=\"tcp\"}} {d}\n", .{load(&accepted)});
    try w.print("routez_connections_accepted_total{{protocol=\"quic\"}} {d}\n", .{load(&accepted_quic)});
    try header(w, "routez_connections_active", "gauge", "Client connections open (QUIC as of the last 100 ms tick).");
    try w.print("routez_connections_active{{protocol=\"tcp\"}} {d}\n", .{load(&active_tcp)});
    try w.print("routez_connections_active{{protocol=\"quic\"}} {d}\n", .{load(&active_quic)});
    try header(w, "routez_connections_refused_per_ip_total", "counter", "TCP connections refused by limits.max_connections_per_ip.");
    try w.print("routez_connections_refused_per_ip_total {d}\n", .{load(&refused_per_ip)});

    const h3 = load(&requests_h3);
    try header(w, "routez_http_requests_total", "counter", "HTTP requests received.");
    try w.print("routez_http_requests_total{{protocol=\"http1\"}} {d}\n", .{load(&requests) -| h3});
    try w.print("routez_http_requests_total{{protocol=\"http3\"}} {d}\n", .{h3});
    try header(w, "routez_http_responses_total", "counter", "HTTP responses finished, by status class.");
    for (&responses, [_][]const u8{ "http1", "http3" }) |*row, proto| {
        for (row, 1..) |*v, class| try w.print("routez_http_responses_total{{protocol=\"{s}\",code=\"{d}xx\"}} {d}\n", .{ proto, class, load(v) });
    }
    try header(w, "routez_http_request_body_bytes_total", "counter", "Request body bytes received.");
    try w.print("routez_http_request_body_bytes_total {d}\n", .{load(&request_bytes)});
    try header(w, "routez_http_response_body_bytes_total", "counter", "Response body bytes sent.");
    try w.print("routez_http_response_body_bytes_total {d}\n", .{load(&response_bytes)});
    try header(w, "routez_quic_steered_datagrams_total", "counter", "QUIC datagrams passed to the worker owning their connection.");
    try w.print("routez_quic_steered_datagrams_total {d}\n", .{load(&quic_steered)});

    try header(w, "routez_upstream_requests_total", "counter", "Requests (retries included), WebTransport sessions and UDP flows sent to an upstream server.");
    for (upstreams) |u| try w.print("routez_upstream_requests_total{{upstream=\"{f}\",server=\"{f}\"}} {d}\n", .{ label(u.stats.upstream), label(u.stats.server), load(&u.stats.requests) });
    try header(w, "routez_upstream_failures_total", "counter", "Failed connections and responses from an upstream server.");
    for (upstreams) |u| try w.print("routez_upstream_failures_total{{upstream=\"{f}\",server=\"{f}\"}} {d}\n", .{ label(u.stats.upstream), label(u.stats.server), load(&u.stats.failures) });
    try header(w, "routez_upstream_healthy", "gauge", "Active health check verdict: 1 healthy, 0 not.");
    for (upstreams) |u| {
        if (!u.health_checked) continue;
        try w.print("routez_upstream_healthy{{upstream=\"{f}\",server=\"{f}\"}} {d}\n", .{ label(u.stats.upstream), label(u.stats.server), u.stats.healthy.load(.monotonic) });
    }
}

fn header(w: *std.Io.Writer, name: []const u8, kind: []const u8, help: []const u8) !void {
    try w.print("# HELP {s} {s}\n# TYPE {s} {s}\n", .{ name, help, name, kind });
}

/// A label value with `\`, `"` and newlines escaped.
fn label(s: []const u8) Label {
    return .{ .s = s };
}

const Label = struct {
    s: []const u8,
    pub fn format(self: Label, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.s) |c| switch (c) {
            '\\' => try w.writeAll("\\\\"),
            '"' => try w.writeAll("\\\""),
            '\n' => try w.writeAll("\\n"),
            else => try w.writeByte(c),
        };
    }
};

test "prometheus exposition" {
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var p: Peer = .{ .upstream = "b\"e", .server = "127.0.0.1:1" };
    p.healthy.store(0, .monotonic);
    response(true, 204);
    try prometheus(&w, &.{ .{ .stats = &p, .health_checked = true }, .{ .stats = &p, .health_checked = false } });
    const text = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, text, "routez_upstream_healthy{upstream=\"b\\\"e\",server=\"127.0.0.1:1\"} 0\n") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "routez_upstream_healthy{"));
    try std.testing.expect(std.mem.indexOf(u8, text, "routez_http_responses_total{protocol=\"http3\",code=\"2xx\"} 1\n") != null);
    // Every sample line: a name, optional labels, a value.
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        const sp = std.mem.lastIndexOfScalar(u8, line, ' ').?;
        _ = try std.fmt.parseInt(u64, line[sp + 1 ..], 10);
        try std.testing.expect(std.mem.startsWith(u8, line, "routez_"));
    }
}
