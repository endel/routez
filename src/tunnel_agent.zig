//! `routez-tunnel-agent` (`zig build tunnel-agent`): the tunnel agent of
//! `routez tunnel` on its own, for machines that share a server and never
//! run one. It leaves the server's code out, at about 40% of the size.
const std = @import("std");
const logs = @import("logs.zig");
const agent = @import("tunnel/agent.zig");

pub const std_options = logs.std_options;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    return agent.main(arena, "routez-tunnel-agent", args[1..], init.environ_map);
}
