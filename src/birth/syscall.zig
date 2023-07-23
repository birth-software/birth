const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.Syscall);

const birth = @import("birth");
const capabilities = birth.capabilities;

pub const Arguments = [6]usize;

pub const Convention = enum(u1) {
    linux = 0,
    birth = 1,
};

pub const Options = extern union {
    general: General,
    birth: Birth,
    linux: Linux,

    pub const General = packed struct(u64) {
        number: Number,
        convention: Convention,

        pub const Number = lib.IntType(.unsigned, union_space_bits);

        comptime {
            assertSize(@This());
        }

        pub inline fn getNumberInteger(general: General, comptime convention: Convention) NumberIntegerType(convention) {
            const options_integer = @as(u64, @bitCast(general));
            return @as(NumberIntegerType(convention), @truncate(options_integer));
        }

        pub fn NumberIntegerType(comptime convention: Convention) type {
            return switch (convention) {
                .birth => birth.IDInteger,
                .linux => u64,
            };
        }
    };

    pub const Birth = packed struct(u64) {
        type: capabilities.Type,
        command: capabilities.Subtype,
        reserved: ReservedInt = 0,
        convention: Convention = .birth,

        const ReservedInt = lib.IntType(.unsigned, @bitSizeOf(u64) - @bitSizeOf(capabilities.Type) - @bitSizeOf(capabilities.Subtype) - @bitSizeOf(Convention));

        comptime {
            Options.assertSize(@This());
        }

        // const IDInteger = u16;
        // pub const ID = enum(IDInteger) {
        //     qemu_exit = 0,
        //     print = 1,
        // };
    };

    pub const Linux = enum(u64) {
        _,
        comptime {
            Options.assertSize(@This());
        }
    };

    pub const union_space_bits = @bitSizeOf(u64) - @bitSizeOf(Convention);

    fn assertSize(comptime T: type) void {
        assert(@sizeOf(T) == @sizeOf(u64));
        assert(@bitSizeOf(T) == @bitSizeOf(u64));
    }

    comptime {
        assertSize(@This());
    }
};

pub const Result = extern union {
    general: General,
    birth: Birth,
    linux: Linux,

    pub const General = extern struct {
        first: packed struct(u64) {
            argument: u63,
            convention: Convention,
        },
        second: u64,
    };

    pub const Birth = extern struct {
        first: First,
        second: Second,

        pub const First = packed struct(u64) {
            padding1: u32 = 0,
            @"error": u16 = 0,
            padding2: u8 = 0,
            padding3: u7 = 0,
            convention: Convention = .birth,
        };

        pub const Second = u64;
    };

    pub const Linux = extern struct {
        result: u64,
        reserved: u64 = 0,
    };

    fn assertSize(comptime T: type) void {
        assert(@sizeOf(T) == @sizeOf(u64));
        assert(@bitSizeOf(T) == @bitSizeOf(u64));
    }
};
