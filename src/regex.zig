//! Regular expressions for regex locations and rewrites, matched in time
//! linear in the input: a Pike VM (an NFA simulation that carries capture
//! positions along each thread) with no backtracking, so no pattern can take
//! exponential time on any input (ReDoS).
//!
//! The syntax is the part of PCRE nginx configs use: literals, `.`, classes
//! (`[a-z_]`, `[^/]`, with `\d \w \s` and their negations), anchors `^ $`,
//! word boundaries `\b \B`, groups `( )` and `(?: )`, alternation `|`,
//! greedy and lazy quantifiers `* + ? {n} {n,} {n,m}`, the escapes
//! `\t \n \r \f \v \a \xHH` and escaped punctuation. Matching is on bytes,
//! leftmost-first like PCRE, and case folding is ASCII. `.` doesn't match a
//! newline and `$` also matches before a final one, as in PCRE.
//! Backreferences, lookaround, named groups, inline flags, atomic groups
//! and possessive quantifiers are refused.
//!
//! Work per match is bounded by the program size times the input length
//! (times the capture slots copied); patterns are capped at
//! `max_pattern_len` bytes and `max_insts` instructions.
const std = @import("std");

pub const max_pattern_len = 1024;
/// Compiled program size limit; `{n,m}` copies its operand, so this is what
/// bounds counted repetition.
pub const max_insts = 1000;
pub const max_repeat = 1000;
const max_depth = 64;
/// Nesting limit for loops whose body can match empty; each level
/// multiplies the states a match tracks.
pub const max_loop_levels = 4;
/// Groups whose positions are recorded, `$1`..`$9`; later groups still
/// group, uncaptured.
pub const max_groups = 9;
const slot_count = 2 * (max_groups + 1);
const unset = std.math.maxInt(u32);

pub const Options = struct { case_insensitive: bool = false };

pub const Diagnostic = struct {
    message: []const u8 = "",
    /// Byte offset in the pattern.
    offset: usize = 0,
};

pub const Error = error{ InvalidPattern, OutOfMemory };

const Set = std.StaticBitSet(256);

const Assert = enum { begin, end, word, not_word };

const Inst = union(enum) {
    byte: u8,
    set: u16,
    /// Any byte but `\n`.
    any,
    /// Both targets, `x` first (preferred).
    split: struct { x: u16, y: u16 },
    jmp: u16,
    /// Enters a loop whose body can match empty; `level` is its depth
    /// among such loops.
    star: struct { body: u16, exit: u16, greedy: bool, level: u8 },
    /// Ends that loop's body: back to `star`, or out when this iteration
    /// matched nothing (PCRE's rule, which also keeps it from spinning).
    back: struct { star: u16, exit: u16, level: u8 },
    save: u8,
    assert: Assert,
    match,
};

/// Positions of the whole match (group 0) and groups 1..9 in `input`.
pub const Captures = struct {
    input: []const u8 = "",
    slots: [slot_count]u32 = @splat(unset),

    pub fn get(self: *const Captures, group: usize) ?[]const u8 {
        if (group > max_groups) return null;
        const a = self.slots[2 * group];
        const b = self.slots[2 * group + 1];
        if (a == unset or b == unset) return null;
        return self.input[a..b];
    }
};

pub const Regex = struct {
    insts: []const Inst,
    sets: []const Set,
    /// Capture slots tracked: 2 per recorded group, group 0 included.
    slots: u8,
    /// Capturing groups in the pattern, recorded or not.
    groups: u16,
    /// Starts with `^`: only tried at offset 0.
    anchored: bool,
    /// Nesting depth of loops over bodies that can match empty.
    levels: u8,

    pub fn compile(alloc: std.mem.Allocator, pattern: []const u8, opts: Options, diag: ?*Diagnostic) Error!Regex {
        var d: Diagnostic = .{};
        const dg = diag orelse &d;
        if (pattern.len > max_pattern_len) {
            dg.* = .{ .message = "pattern is longer than 1024 bytes" };
            return error.InvalidPattern;
        }
        var arena_state = std.heap.ArenaAllocator.init(alloc);
        defer arena_state.deinit();
        var p: Parser = .{ .a = arena_state.allocator(), .src = pattern, .ci = opts.case_insensitive, .diag = dg };
        const root = try p.parseAlt(0);
        if (p.pos < pattern.len) return p.fail("unmatched )");

        var c: Compiler = .{ .a = arena_state.allocator(), .nodes = p.nodes.items, .diag = dg };
        _ = try c.emit(.{ .save = 0 });
        try c.node(root);
        _ = try c.emit(.{ .save = 1 });
        _ = try c.emit(.match);

        const insts = try alloc.dupe(Inst, c.insts.items);
        errdefer alloc.free(insts);
        return .{
            .insts = insts,
            .sets = try alloc.dupe(Set, p.sets.items),
            .slots = @intCast(2 * (@as(usize, @min(p.groups, max_groups)) + 1)),
            .groups = p.groups,
            .anchored = startsAnchored(p.nodes.items, root),
            .levels = c.max_level,
        };
    }

    /// The `Scratch` capacity this program needs.
    pub fn states(re: *const Regex) usize {
        return re.insts.len * (@as(usize, re.levels) + 1);
    }

    pub fn deinit(self: *const Regex, alloc: std.mem.Allocator) void {
        alloc.free(self.insts);
        alloc.free(self.sets);
    }

    /// Search `input` for the leftmost match (PCRE's choice among matches
    /// starting there). `scratch` must have room for this program.
    pub fn match(re: *const Regex, input: []const u8, s: *Scratch, caps: ?*Captures) bool {
        std.debug.assert(s.cap >= re.states());
        if (input.len >= unset) return false;
        const n = re.slots;
        var clist = &s.lists[0];
        var nlist = &s.lists[1];
        clist.clear();
        nlist.clear();
        var matched = false;
        var best: [slot_count]u32 = undefined;
        var i: usize = 0;
        while (true) : (i += 1) {
            // A new thread per offset, below every thread already running.
            if (!matched and (!re.anchored or i == 0)) {
                @memset(s.tmp[0..n], unset);
                re.addThread(s, clist, 0, i, input);
            }
            if (clist.len == 0 and (matched or re.anchored)) break;
            step: for (0..clist.len) |k| {
                const pc = clist.pcs[k];
                const tcaps = clist.caps[k * slot_count ..][0..n];
                const ok = switch (re.insts[pc]) {
                    .byte => |b| i < input.len and input[i] == b,
                    .set => |si| i < input.len and re.sets[si].isSet(input[i]),
                    .any => i < input.len and input[i] != '\n',
                    .match => {
                        @memcpy(best[0..n], tcaps);
                        matched = true;
                        // Lower-priority threads can't win any more.
                        break :step;
                    },
                    else => unreachable,
                };
                if (ok) {
                    @memcpy(s.tmp[0..n], tcaps);
                    re.addThread(s, nlist, pc + 1, i + 1, input);
                }
            }
            if (i >= input.len) break;
            std.mem.swap(*Scratch.List, &clist, &nlist);
            nlist.clear();
        }
        if (matched) if (caps) |c| {
            c.* = .{ .input = input };
            @memcpy(c.slots[0..n], best[0..n]);
        };
        return matched;
    }

    /// Follow empty transitions from `pc0` at `pos`, adding the threads that
    /// reach a byte test or the match, in priority order. `s.tmp` holds the
    /// captures on entry.
    fn addThread(re: *const Regex, s: *Scratch, list: *Scratch.List, pc0: u16, pos: usize, input: []const u8) void {
        const n = re.slots;
        var sp: usize = 0;
        s.stack[sp] = .{ .pc = pc0 };
        sp += 1;
        while (sp > 0) {
            sp -= 1;
            const f = s.stack[sp];
            if (f.restore) {
                s.tmp[f.slot] = f.val;
                continue;
            }
            const pc = f.pc;
            const inst = re.insts[pc];
            // `fresh`: the outermost empty-body loop whose current iteration
            // began at `pos` (0: none). It changes what `back` does, so it is
            // part of the state; a byte test resets it.
            const fresh: u8 = switch (inst) {
                .byte, .set, .any, .match => 0,
                else => f.fresh,
            };
            const key = @as(usize, pc) * (@as(usize, re.levels) + 1) + fresh;
            if (list.has(key)) continue;
            list.mark(key);
            switch (inst) {
                .jmp => |t| {
                    s.stack[sp] = .{ .pc = t, .fresh = fresh };
                    sp += 1;
                },
                .split => |b| {
                    s.stack[sp] = .{ .pc = b.y, .fresh = fresh };
                    s.stack[sp + 1] = .{ .pc = b.x, .fresh = fresh };
                    sp += 2;
                },
                .star => |l| {
                    const body: Scratch.Frame = .{ .pc = l.body, .fresh = if (fresh == 0) l.level else fresh };
                    const exit: Scratch.Frame = .{ .pc = l.exit, .fresh = fresh };
                    s.stack[sp], s.stack[sp + 1] = if (l.greedy) .{ exit, body } else .{ body, exit };
                    sp += 2;
                },
                .back => |b| {
                    s.stack[sp] = if (fresh != 0)
                        .{ .pc = b.exit, .fresh = if (fresh < b.level) fresh else 0 }
                    else
                        .{ .pc = b.star };
                    sp += 1;
                },
                .save => |slot| {
                    // Put the old value back once this branch is explored.
                    s.stack[sp] = .{ .restore = true, .slot = slot, .val = s.tmp[slot] };
                    s.stack[sp + 1] = .{ .pc = pc + 1, .fresh = fresh };
                    sp += 2;
                    s.tmp[slot] = @intCast(pos);
                },
                .assert => |a| if (holds(a, input, pos)) {
                    s.stack[sp] = .{ .pc = pc + 1, .fresh = fresh };
                    sp += 1;
                },
                .byte, .set, .any, .match => {
                    list.pcs[list.len] = pc;
                    @memcpy(list.caps[list.len * slot_count ..][0..n], s.tmp[0..n]);
                    list.len += 1;
                },
            }
        }
    }
};

fn holds(a: Assert, input: []const u8, pos: usize) bool {
    return switch (a) {
        .begin => pos == 0,
        .end => pos == input.len or (pos + 1 == input.len and input[pos] == '\n'),
        .word, .not_word => {
            const before = pos > 0 and isWord(input[pos - 1]);
            const after = pos < input.len and isWord(input[pos]);
            return (before != after) == (a == .word);
        },
    };
}

fn isWord(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// Match state for programs of up to `cap` states (`Regex.states`). One
/// per worker, reused by every match; not safe to share between threads.
pub const Scratch = struct {
    cap: usize = 0,
    lists: [2]List = .{ .{}, .{} },
    stack: []Frame = &.{},
    tmp: [slot_count]u32 = undefined,

    const Frame = struct {
        restore: bool = false,
        slot: u8 = 0,
        fresh: u8 = 0,
        pc: u16 = 0,
        val: u32 = 0,
    };

    const List = struct {
        /// Sparse set of the instructions visited at this offset.
        sparse: []u16 = &.{},
        dense: []u16 = &.{},
        visited: usize = 0,
        /// Threads, in priority order, and their capture slots.
        pcs: []u16 = &.{},
        caps: []u32 = &.{},
        len: usize = 0,

        fn clear(l: *List) void {
            l.visited = 0;
            l.len = 0;
        }

        fn has(l: *const List, key: usize) bool {
            const i = l.sparse[key];
            return i < l.visited and l.dense[i] == key;
        }

        fn mark(l: *List, key: usize) void {
            l.sparse[key] = @intCast(l.visited);
            l.dense[l.visited] = @intCast(key);
            l.visited += 1;
        }
    };

    pub fn init(alloc: std.mem.Allocator, cap: usize) !Scratch {
        std.debug.assert(cap <= std.math.maxInt(u16));
        var s: Scratch = .{ .cap = cap };
        errdefer s.deinit(alloc);
        for (&s.lists) |*l| {
            l.sparse = try alloc.alloc(u16, cap);
            @memset(l.sparse, 0);
            l.dense = try alloc.alloc(u16, cap);
            l.pcs = try alloc.alloc(u16, cap);
            l.caps = try alloc.alloc(u32, cap * slot_count);
        }
        // Each state is expanded once per offset and pushes two frames at most.
        s.stack = try alloc.alloc(Frame, 2 * cap + 1);
        return s;
    }

    pub fn deinit(self: *Scratch, alloc: std.mem.Allocator) void {
        for (&self.lists) |*l| {
            alloc.free(l.sparse);
            alloc.free(l.dense);
            alloc.free(l.pcs);
            alloc.free(l.caps);
        }
        alloc.free(self.stack);
        self.* = .{};
    }
};

const Node = union(enum) {
    empty,
    byte: u8,
    set: u16,
    any,
    assert: Assert,
    /// `index` 0: non-capturing.
    group: struct { sub: u32, index: u16 },
    concat: []const u32,
    alt: []const u32,
    /// `max` null: unbounded.
    repeat: struct { sub: u32, min: u16, max: ?u16, greedy: bool },
};

const Parser = struct {
    a: std.mem.Allocator,
    src: []const u8,
    pos: usize = 0,
    ci: bool,
    diag: *Diagnostic,
    nodes: std.ArrayList(Node) = .empty,
    sets: std.ArrayList(Set) = .empty,
    groups: u16 = 0,

    fn fail(p: *Parser, msg: []const u8) Error {
        p.diag.* = .{ .message = msg, .offset = p.pos };
        return error.InvalidPattern;
    }

    fn add(p: *Parser, n: Node) Error!u32 {
        try p.nodes.append(p.a, n);
        return @intCast(p.nodes.items.len - 1);
    }

    fn peek(p: *const Parser) ?u8 {
        return if (p.pos < p.src.len) p.src[p.pos] else null;
    }

    fn rest(p: *const Parser) []const u8 {
        return p.src[p.pos..];
    }

    fn parseAlt(p: *Parser, depth: usize) Error!u32 {
        if (depth > max_depth) return p.fail("groups nested too deep");
        var branches: std.ArrayList(u32) = .empty;
        try branches.append(p.a, try p.parseConcat(depth));
        while (p.peek() == '|') {
            p.pos += 1;
            try branches.append(p.a, try p.parseConcat(depth));
        }
        if (branches.items.len == 1) return branches.items[0];
        return p.add(.{ .alt = branches.items });
    }

    fn parseConcat(p: *Parser, depth: usize) Error!u32 {
        var items: std.ArrayList(u32) = .empty;
        while (p.peek()) |c| {
            if (c == '|' or c == ')') break;
            const atom = try p.parseAtom(depth);
            try items.append(p.a, try p.parseQuantifier(atom));
        }
        return switch (items.items.len) {
            0 => p.add(.empty),
            1 => items.items[0],
            else => p.add(.{ .concat = items.items }),
        };
    }

    const Bounds = struct { min: u16, max: ?u16, len: usize };

    /// `{n}`, `{n,}`, `{n,m}` or `{,m}` at the cursor; null when it isn't
    /// one, and `{` is then a literal (as in PCRE and Python).
    fn braces(p: *Parser) Error!?Bounds {
        const s = p.rest();
        if (s.len < 2 or s[0] != '{') return null;
        var i: usize = 1;
        const lo_start = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        const lo = s[lo_start..i];
        var hi = lo;
        var comma = false;
        if (i < s.len and s[i] == ',') {
            comma = true;
            i += 1;
            const hi_start = i;
            while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
            hi = s[hi_start..i];
        }
        if (i >= s.len or s[i] != '}' or (lo.len == 0 and !comma)) return null;
        const min = if (lo.len == 0) 0 else std.fmt.parseInt(u16, lo, 10) catch max_repeat + 1;
        const max: ?u16 = if (hi.len == 0) null else std.fmt.parseInt(u16, hi, 10) catch max_repeat + 1;
        if (min > max_repeat or (max orelse 0) > max_repeat) return p.fail("repeat count above 1000");
        if (max != null and max.? < min) return p.fail("repeat range out of order");
        return .{ .min = min, .max = max, .len = i + 1 };
    }

    fn parseQuantifier(p: *Parser, atom: u32) Error!u32 {
        const b: Bounds = switch (p.peek() orelse return atom) {
            '*' => .{ .min = 0, .max = null, .len = 1 },
            '+' => .{ .min = 1, .max = null, .len = 1 },
            '?' => .{ .min = 0, .max = 1, .len = 1 },
            '{' => try p.braces() orelse return atom,
            else => return atom,
        };
        switch (p.nodes.items[atom]) {
            .assert, .empty => return p.fail("nothing to repeat"),
            else => {},
        }
        p.pos += b.len;
        var greedy = true;
        if (p.peek() == '?') {
            greedy = false;
            p.pos += 1;
        } else if (p.peek() == '+') {
            return p.fail("possessive quantifiers aren't supported");
        }
        if (p.peek()) |c| if (c == '*' or c == '+' or c == '?' or (c == '{' and try p.braces() != null))
            return p.fail("multiple repeat");
        return p.add(.{ .repeat = .{ .sub = atom, .min = b.min, .max = b.max, .greedy = greedy } });
    }

    fn parseAtom(p: *Parser, depth: usize) Error!u32 {
        const c = p.src[p.pos];
        switch (c) {
            '(' => return p.parseGroup(depth),
            '[' => return p.parseClass(),
            '.' => {
                p.pos += 1;
                return p.add(.any);
            },
            '^' => {
                p.pos += 1;
                return p.add(.{ .assert = .begin });
            },
            '$' => {
                p.pos += 1;
                return p.add(.{ .assert = .end });
            },
            '\\' => return p.parseEscape(),
            '*', '+', '?' => return p.fail("nothing to repeat"),
            '{' => if (try p.braces() != null) return p.fail("nothing to repeat"),
            else => {},
        }
        p.pos += 1;
        return p.literal(c);
    }

    fn literal(p: *Parser, c: u8) Error!u32 {
        if (p.ci and std.ascii.isAlphabetic(c)) {
            var s = Set.initEmpty();
            s.set(std.ascii.toLower(c));
            s.set(std.ascii.toUpper(c));
            return p.addSet(s);
        }
        return p.add(.{ .byte = c });
    }

    fn addSet(p: *Parser, s: Set) Error!u32 {
        try p.sets.append(p.a, s);
        return p.add(.{ .set = @intCast(p.sets.items.len - 1) });
    }

    fn parseGroup(p: *Parser, depth: usize) Error!u32 {
        p.pos += 1;
        var index: u16 = 0;
        const s = p.rest();
        if (std.mem.startsWith(u8, s, "?")) {
            if (std.mem.startsWith(u8, s, "?:")) {
                p.pos += 2;
            } else if (std.mem.startsWith(u8, s, "?=") or std.mem.startsWith(u8, s, "?!") or
                std.mem.startsWith(u8, s, "?<=") or std.mem.startsWith(u8, s, "?<!"))
            {
                return p.fail("lookaround isn't supported");
            } else if (std.mem.startsWith(u8, s, "?P=")) {
                return p.fail("backreferences aren't supported");
            } else if (std.mem.startsWith(u8, s, "?P<") or std.mem.startsWith(u8, s, "?<") or std.mem.startsWith(u8, s, "?'")) {
                return p.fail("named groups aren't supported; use $1..$9");
            } else if (std.mem.startsWith(u8, s, "?>")) {
                return p.fail("atomic groups aren't supported");
            } else {
                return p.fail("inline flags and other (? groups aren't supported; use case_insensitive");
            }
        } else {
            p.groups += 1;
            index = p.groups;
        }
        const sub = try p.parseAlt(depth + 1);
        if (p.peek() != ')') return p.fail("missing )");
        p.pos += 1;
        return p.add(.{ .group = .{ .sub = sub, .index = index } });
    }

    const ClassAtom = union(enum) { byte: u8, set: Set };

    fn parseEscape(p: *Parser) Error!u32 {
        switch (try p.escape(false)) {
            .byte => |b| return p.literal(b),
            .set => |s| return p.addSet(s),
            .assert => |a| return p.add(.{ .assert = a }),
        }
    }

    const Escaped = union(enum) { byte: u8, set: Set, assert: Assert };

    fn escape(p: *Parser, in_class: bool) Error!Escaped {
        p.pos += 1;
        const e = p.peek() orelse return p.fail("trailing backslash");
        p.pos += 1;
        switch (e) {
            'd', 'D', 'w', 'W', 's', 'S' => {
                var s = Set.initEmpty();
                for (0..256) |i| {
                    const c: u8 = @intCast(i);
                    const in = switch (std.ascii.toLower(e)) {
                        'd' => std.ascii.isDigit(c),
                        'w' => isWord(c),
                        else => c == ' ' or (c >= '\t' and c <= '\r'),
                    };
                    if (in) s.set(i);
                }
                if (std.ascii.isUpper(e)) s.toggleAll();
                return .{ .set = s };
            },
            'b', 'B' => {
                if (in_class) return p.fail("\\b isn't supported in a class");
                return .{ .assert = if (e == 'b') .word else .not_word };
            },
            '1'...'9', 'k', 'g' => return p.fail("backreferences aren't supported"),
            '0' => return p.fail("octal escapes aren't supported; use \\xHH"),
            'n' => return .{ .byte = '\n' },
            't' => return .{ .byte = '\t' },
            'r' => return .{ .byte = '\r' },
            'f' => return .{ .byte = 0x0c },
            'v' => return .{ .byte = 0x0b },
            'a' => return .{ .byte = 0x07 },
            'x' => {
                const s = p.rest();
                if (s.len < 2) return p.fail("\\x needs two hex digits");
                const v = std.fmt.parseInt(u8, s[0..2], 16) catch return p.fail("\\x needs two hex digits");
                p.pos += 2;
                return .{ .byte = v };
            },
            else => {
                if (std.ascii.isAlphanumeric(e)) return p.fail("unsupported escape");
                return .{ .byte = e };
            },
        }
    }

    fn classAtom(p: *Parser) Error!ClassAtom {
        const c = p.src[p.pos];
        if (c != '\\') {
            p.pos += 1;
            return .{ .byte = c };
        }
        return switch (try p.escape(true)) {
            .byte => |b| .{ .byte = b },
            .set => |s| .{ .set = s },
            .assert => unreachable,
        };
    }

    fn parseClass(p: *Parser) Error!u32 {
        p.pos += 1;
        var negate = false;
        if (p.peek() == '^') {
            negate = true;
            p.pos += 1;
        }
        var set = Set.initEmpty();
        var first = true;
        while (true) {
            const c = p.peek() orelse return p.fail("missing ]");
            if (c == ']' and !first) {
                p.pos += 1;
                break;
            }
            first = false;
            if (c == '[' and p.pos + 1 < p.src.len and std.mem.indexOfScalar(u8, ":.=", p.src[p.pos + 1]) != null)
                return p.fail("POSIX classes like [:alpha:] aren't supported; use \\d, \\w, \\s or ranges");
            const lo = try p.classAtom();
            const is_range = p.peek() == '-' and p.pos + 1 < p.src.len and p.src[p.pos + 1] != ']';
            switch (lo) {
                .set => |s| {
                    if (is_range) return p.fail("bad class range");
                    set.setUnion(s);
                },
                .byte => |b| {
                    if (!is_range) {
                        set.set(b);
                        continue;
                    }
                    p.pos += 1;
                    const hi = switch (try p.classAtom()) {
                        .byte => |h| h,
                        .set => return p.fail("bad class range"),
                    };
                    if (hi < b) return p.fail("bad class range");
                    set.setRangeValue(.{ .start = b, .end = @as(usize, hi) + 1 }, true);
                },
            }
        }
        if (p.ci) {
            for ('a'..'z' + 1) |l| {
                const u = l - 32;
                if (set.isSet(l) or set.isSet(u)) {
                    set.set(l);
                    set.set(u);
                }
            }
        }
        if (negate) set.toggleAll();
        return p.addSet(set);
    }
};

const Compiler = struct {
    a: std.mem.Allocator,
    nodes: []const Node,
    diag: *Diagnostic,
    insts: std.ArrayList(Inst) = .empty,
    /// Empty-body loops around the node being compiled.
    level: u8 = 0,
    max_level: u8 = 0,

    fn emit(c: *Compiler, inst: Inst) Error!u16 {
        if (c.insts.items.len >= max_insts) {
            c.diag.* = .{ .message = "pattern compiles to over 1000 instructions; lower its repeat counts" };
            return error.InvalidPattern;
        }
        try c.insts.append(c.a, inst);
        return @intCast(c.insts.items.len - 1);
    }

    fn here(c: *const Compiler) u16 {
        return @intCast(c.insts.items.len);
    }

    fn node(c: *Compiler, idx: u32) Error!void {
        switch (c.nodes[idx]) {
            .empty => {},
            .byte => |b| _ = try c.emit(.{ .byte = b }),
            .set => |s| _ = try c.emit(.{ .set = s }),
            .any => _ = try c.emit(.any),
            .assert => |a| _ = try c.emit(.{ .assert = a }),
            .group => |g| {
                const recorded = g.index >= 1 and g.index <= max_groups;
                if (recorded) _ = try c.emit(.{ .save = @intCast(2 * g.index) });
                try c.node(g.sub);
                if (recorded) _ = try c.emit(.{ .save = @intCast(2 * g.index + 1) });
            },
            .concat => |items| for (items) |i| try c.node(i),
            .alt => |branches| {
                var jumps: std.ArrayList(u16) = .empty;
                for (branches[0 .. branches.len - 1]) |b| {
                    const split = try c.emit(.{ .split = .{ .x = 0, .y = 0 } });
                    try c.node(b);
                    try jumps.append(c.a, try c.emit(.{ .jmp = 0 }));
                    c.insts.items[split] = .{ .split = .{ .x = split + 1, .y = c.here() } };
                }
                try c.node(branches[branches.len - 1]);
                for (jumps.items) |j| c.insts.items[j] = .{ .jmp = c.here() };
            },
            .repeat => |r| try c.repeat(r.sub, r.min, r.max, r.greedy),
        }
    }

    fn repeat(c: *Compiler, sub: u32, min: u16, max: ?u16, greedy: bool) Error!void {
        if (max == null and nullable(c.nodes, sub)) {
            for (0..min) |_| try c.node(sub);
            if (c.level == max_loop_levels) {
                c.diag.* = .{ .message = "repeats of groups that can match empty nest over 4 deep" };
                return error.InvalidPattern;
            }
            c.level += 1;
            c.max_level = @max(c.max_level, c.level);
            const star = try c.emit(.{ .star = .{ .body = 0, .exit = 0, .greedy = greedy, .level = c.level } });
            try c.node(sub);
            const back = try c.emit(.{ .back = .{ .star = star, .exit = 0, .level = c.level } });
            c.level -= 1;
            c.insts.items[star].star.body = star + 1;
            c.insts.items[star].star.exit = c.here();
            c.insts.items[back].back.exit = c.here();
            return;
        }
        if (max == null) {
            var skip: ?u16 = null;
            if (min == 0) {
                skip = try c.emit(.{ .split = .{ .x = 0, .y = 0 } });
            } else {
                for (0..min - 1) |_| try c.node(sub);
            }
            const body = c.here();
            try c.node(sub);
            const loop = try c.emit(.{ .split = .{ .x = 0, .y = 0 } });
            c.insts.items[loop] = c.branch(body, loop + 1, greedy);
            if (skip) |s| c.insts.items[s] = c.branch(s + 1, c.here(), greedy);
            return;
        }
        for (0..min) |_| try c.node(sub);
        // x{0,k} nested: (x(x(x)?)?)?, never skipping one then taking the next.
        var holes: std.ArrayList(u16) = .empty;
        for (0..max.? - min) |_| {
            try holes.append(c.a, try c.emit(.{ .split = .{ .x = 0, .y = 0 } }));
            try c.node(sub);
        }
        for (holes.items) |h| c.insts.items[h] = c.branch(h + 1, c.here(), greedy);
    }

    fn branch(_: *const Compiler, take: u16, skip: u16, greedy: bool) Inst {
        return .{ .split = if (greedy) .{ .x = take, .y = skip } else .{ .x = skip, .y = take } };
    }
};

fn nullable(nodes: []const Node, idx: u32) bool {
    return switch (nodes[idx]) {
        .empty, .assert => true,
        .byte, .set, .any => false,
        .group => |g| nullable(nodes, g.sub),
        .concat => |items| for (items) |i| {
            if (!nullable(nodes, i)) break false;
        } else true,
        .alt => |branches| for (branches) |b| {
            if (nullable(nodes, b)) break true;
        } else false,
        .repeat => |r| r.min == 0 or nullable(nodes, r.sub),
    };
}

fn startsAnchored(nodes: []const Node, idx: u32) bool {
    return switch (nodes[idx]) {
        .assert => |a| a == .begin,
        .concat => |items| startsAnchored(nodes, items[0]),
        .group => |g| startsAnchored(nodes, g.sub),
        else => false,
    };
}

const testing = std.testing;

/// Compile and match once, for tests: the groups as strings, `null` for an
/// unset group; `null` overall for no match.
fn run(alloc: std.mem.Allocator, pattern: []const u8, ci: bool, input: []const u8) !?[max_groups + 1]?[]const u8 {
    const re = try Regex.compile(alloc, pattern, .{ .case_insensitive = ci }, null);
    defer re.deinit(alloc);
    var s = try Scratch.init(alloc, re.states());
    defer s.deinit(alloc);
    var caps: Captures = .{};
    if (!re.match(input, &s, &caps)) return null;
    var out: [max_groups + 1]?[]const u8 = undefined;
    for (&out, 0..) |*o, g| o.* = caps.get(g);
    return out;
}

const Case = struct {
    pattern: []const u8,
    input: []const u8,
    /// Group 0 first; "-" for an unset group. Empty: no match.
    want: []const []const u8,
    ci: bool = false,
};

const cases = [_]Case{
    .{ .pattern = "abc", .input = "xxabcxx", .want = &.{"abc"} },
    .{ .pattern = "abc", .input = "ab", .want = &.{} },
    .{ .pattern = "^/api/(.*)$", .input = "/api/v1/users", .want = &.{ "/api/v1/users", "v1/users" } },
    .{ .pattern = "^/api/(.*)$", .input = "/x/api/", .want = &.{} },
    .{ .pattern = "\\.(png|jpe?g|gif)$", .input = "/img/a.jpeg", .want = &.{ ".jpeg", "jpeg" } },
    .{ .pattern = "\\.(png|jpe?g|gif)$", .input = "/img/a.JPG", .want = &.{ ".JPG", "JPG" }, .ci = true },
    .{ .pattern = "\\.(png|jpe?g|gif)$", .input = "/img/a.JPG", .want = &.{} },
    .{ .pattern = "^/users/(\\d+)/posts/(\\d+)", .input = "/users/42/posts/7/x", .want = &.{ "/users/42/posts/7", "42", "7" } },
    .{ .pattern = "(a|ab)(c|bcd)(d*)", .input = "abcd", .want = &.{ "abcd", "a", "bcd", "" } },
    .{ .pattern = "(a+)(b)?", .input = "aaa", .want = &.{ "aaa", "aaa", "-" } },
    .{ .pattern = "(a*?)(a*)", .input = "aaa", .want = &.{ "aaa", "", "aaa" } },
    .{ .pattern = "a{2,3}", .input = "aaaa", .want = &.{"aaa"} },
    .{ .pattern = "a{2,3}?", .input = "aaaa", .want = &.{"aa"} },
    .{ .pattern = "a{3}", .input = "aa", .want = &.{} },
    .{ .pattern = "a{2,}b", .input = "aaaab", .want = &.{"aaaab"} },
    .{ .pattern = "x{,2}y", .input = "xxxy", .want = &.{"xxy"} },
    .{ .pattern = "a{", .input = "a{", .want = &.{"a{"} },
    .{ .pattern = "a{1,x}", .input = "a{1,x}", .want = &.{"a{1,x}"} },
    .{ .pattern = "[^/]+$", .input = "/a/bc", .want = &.{"bc"} },
    .{ .pattern = "[]a]+", .input = "x]a]", .want = &.{"]a]"} },
    .{ .pattern = "[a-]+", .input = "x-a-", .want = &.{"-a-"} },
    .{ .pattern = "[\\d_]+", .input = "ab1_2c", .want = &.{"1_2"} },
    .{ .pattern = "[^\\W]+", .input = "--ab--", .want = &.{"ab"} },
    .{ .pattern = "\\bfoo\\b", .input = "a foo b", .want = &.{"foo"} },
    .{ .pattern = "\\bfoo\\b", .input = "afoob", .want = &.{} },
    .{ .pattern = "\\Boo\\B", .input = "afoob", .want = &.{"oo"} },
    .{ .pattern = "(?:ab)+", .input = "ababa", .want = &.{"abab"} },
    .{ .pattern = "((a)|b)+", .input = "ab", .want = &.{ "ab", "b", "a" } },
    .{ .pattern = "(a*)*", .input = "b", .want = &.{ "", "" } },
    .{ .pattern = "(|a)*", .input = "aa", .want = &.{ "", "" } },
    // A last iteration that matches empty ends the loop, as in PCRE.
    .{ .pattern = "(a|)+", .input = "aa", .want = &.{ "aa", "" } },
    .{ .pattern = "(a|)*", .input = "aa", .want = &.{ "aa", "" } },
    .{ .pattern = "((a)|())*", .input = "aab", .want = &.{ "aa", "", "a", "" } },
    .{ .pattern = "(?:(a*)b?)*c", .input = "abac", .want = &.{ "abac", "" } },
    .{ .pattern = "(a|)+?b", .input = "aab", .want = &.{ "aab", "a" } },
    .{ .pattern = "a.c", .input = "a\nc abc", .want = &.{"abc"} },
    .{ .pattern = "a$", .input = "a\n", .want = &.{"a"} },
    .{ .pattern = "^$", .input = "", .want = &.{""} },
    .{ .pattern = "", .input = "abc", .want = &.{""} },
    .{ .pattern = "a|", .input = "b", .want = &.{""} },
    .{ .pattern = "\\x41\\t\\.", .input = "A\t.", .want = &.{"A\t."} },
    .{ .pattern = "[\\x00-\\x1f]", .input = "ab\x01", .want = &.{"\x01"} },
    .{ .pattern = "HeLLo", .input = "say hello", .want = &.{"hello"}, .ci = true },
    .{ .pattern = "[^a-z]+", .input = "abcXYZ12", .want = &.{"12"}, .ci = true },
    .{ .pattern = "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)", .input = "abcdefghij", .want = &.{ "abcdefghij", "a", "b", "c", "d", "e", "f", "g", "h", "i" } },
    .{ .pattern = "\\/\\-\\\\", .input = "/-\\", .want = &.{"/-\\"} },
    .{ .pattern = "(a+)+$", .input = "aaaa!", .want = &.{} },
};

test "patterns and captures" {
    for (cases) |c| {
        const got = run(testing.allocator, c.pattern, c.ci, c.input) catch |err| {
            std.debug.print("pattern {s}: {s}\n", .{ c.pattern, @errorName(err) });
            return err;
        };
        errdefer std.debug.print("pattern '{s}' on '{s}'\n", .{ c.pattern, c.input });
        if (c.want.len == 0) {
            try testing.expect(got == null);
            continue;
        }
        const g = got orelse return error.NoMatch;
        for (c.want, 0..) |w, i| {
            if (std.mem.eql(u8, w, "-")) {
                try testing.expect(g[i] == null);
            } else {
                try testing.expectEqualStrings(w, g[i] orelse return error.GroupUnset);
            }
        }
    }
}

test "refused syntax" {
    const bad = [_]struct { []const u8, []const u8 }{
        .{ "(a)\\1", "backreferences aren't supported" },
        .{ "(?P<n>a)(?P=n)", "named groups aren't supported; use $1..$9" },
        .{ "\\k<n>", "backreferences aren't supported" },
        .{ "a(?=b)", "lookaround isn't supported" },
        .{ "a(?!b)", "lookaround isn't supported" },
        .{ "(?<=a)b", "lookaround isn't supported" },
        .{ "(?<!a)b", "lookaround isn't supported" },
        .{ "(?<n>a)", "named groups aren't supported; use $1..$9" },
        .{ "(?i)a", "inline flags and other (? groups aren't supported; use case_insensitive" },
        .{ "(?>a)", "atomic groups aren't supported" },
        .{ "a*+", "possessive quantifiers aren't supported" },
        .{ "a**", "multiple repeat" },
        .{ "*a", "nothing to repeat" },
        .{ "^*", "nothing to repeat" },
        .{ "(a", "missing )" },
        .{ "a)", "unmatched )" },
        .{ "[a", "missing ]" },
        .{ "[z-a]", "bad class range" },
        .{ "[a-\\d]", "bad class range" },
        .{ "[[:alpha:]]", "POSIX classes like [:alpha:] aren't supported; use \\d, \\w, \\s or ranges" },
        .{ "\\p{L}", "unsupported escape" },
        .{ "\\A", "unsupported escape" },
        .{ "a\\", "trailing backslash" },
        .{ "\\xZ1", "\\x needs two hex digits" },
        .{ "a{1001}", "repeat count above 1000" },
        .{ "a{3,2}", "repeat range out of order" },
        .{ "(((a{100}){100}){100})", "pattern compiles to over 1000 instructions; lower its repeat counts" },
        .{ "[a\\b]", "\\b isn't supported in a class" },
        .{ "(((((a|)*)*)*)*)*", "repeats of groups that can match empty nest over 4 deep" },
    };
    for (bad) |b| {
        var d: Diagnostic = .{};
        const r = Regex.compile(testing.allocator, b[0], .{}, &d);
        if (r) |re| {
            re.deinit(testing.allocator);
            std.debug.print("accepted: {s}\n", .{b[0]});
            return error.Accepted;
        } else |err| {
            try testing.expectEqual(error.InvalidPattern, err);
            try testing.expectEqualStrings(b[1], d.message);
        }
    }
    var long: [max_pattern_len + 1]u8 = @splat('a');
    try testing.expectError(error.InvalidPattern, Regex.compile(testing.allocator, &long, .{}, null));
    var deep: [2 * (max_depth + 2)]u8 = undefined;
    @memset(deep[0 .. max_depth + 2], '(');
    @memset(deep[max_depth + 2 ..], ')');
    try testing.expectError(error.InvalidPattern, Regex.compile(testing.allocator, &deep, .{}, null));
}

fn monoNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "no catastrophic backtracking" {
    // (a+)+$ on 30 a's and a '!': about 2^30 paths for a backtracking engine.
    const re = try Regex.compile(testing.allocator, "(a+)+$", .{}, null);
    defer re.deinit(testing.allocator);
    var s = try Scratch.init(testing.allocator, re.states());
    defer s.deinit(testing.allocator);
    const input = "a" ** 30 ++ "!";
    const t0 = monoNs();
    try testing.expect(!re.match(input, &s, null));
    const took = monoNs() - t0;
    // Microseconds in a release build; generous for Debug and slow machines.
    try testing.expect(took < 5 * std.time.ns_per_ms);

    // And at size: the worst pattern allowed on a 16 KiB path stays linear.
    const big = try Regex.compile(testing.allocator, "(?:(a|aa)+)+(x|y)*b" ++ ".?" ** 200, .{}, null);
    defer big.deinit(testing.allocator);
    var s2 = try Scratch.init(testing.allocator, big.states());
    defer s2.deinit(testing.allocator);
    const path = try testing.allocator.alloc(u8, 16 * 1024);
    defer testing.allocator.free(path);
    @memset(path, 'a');
    try testing.expect(!big.match(path, &s2, null));
}
