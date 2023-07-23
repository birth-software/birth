const lib = @import("lib");
const x86 = @import("x86/common.zig");
pub usingnamespace x86;

pub const paging = struct {
    pub const page_table_entry_size = @sizeOf(u64);
    pub const page_table_size = lib.arch.valid_page_sizes[0];
    pub const page_table_entry_count = @divExact(page_table_size, page_table_entry_size);
    pub const page_table_alignment = page_table_size;
    pub const page_table_mask = page_table_entry_count - 1;
    pub const user_address_space_start = 0x200_000;
    pub const user_address_space_end = 0x8000_0000_0000;
    pub const root_page_table_level: Level = switch (Level) {
        Level4 => Level.PML4,
        Level5 => @compileError("TODO"),
        else => @compileError("Unknown level"),
    };

    pub const Level = Level4;

    pub const Level4 = enum(u2) {
        PML4 = 0,
        PDP = 1,
        PD = 2,
        PT = 3,

        pub const count = lib.enumCount(@This());
    };

    pub const Level5 = enum(u3) {};

    comptime {
        lib.assert(page_table_alignment == page_table_size);
        lib.assert(page_table_size == lib.arch.valid_page_sizes[0]);
    }
};

pub const valid_page_sizes = [3]comptime_int{ 0x1000, 0x1000 * 0x200, 0x1000 * 0x200 * 0x200 };
pub const reverse_valid_page_sizes = blk: {
    var reverse = valid_page_sizes;
    lib.reverse(@TypeOf(valid_page_sizes[0]), &reverse);
    // var reverse_u64: [valid_page_sizes.len]u64 = undefined;
    // for (reverse, &reverse_u64) |r_el, *ru64_el| {
    //     ru64_el.* = r_el;
    // }

    break :blk reverse;
};
pub const default_page_size = valid_page_sizes[0];
pub const reasonable_page_size = valid_page_sizes[1];

pub const registers = @import("x86/64/registers.zig");

pub inline fn readTimestamp() u64 {
    var edx: u32 = undefined;
    var eax: u32 = undefined;

    asm volatile (
        \\rdtsc
        : [eax] "={eax}" (eax),
          [edx] "={edx}" (edx),
    );

    return @as(u64, edx) << 32 | eax;
}

pub const stack_alignment = 0x10;
