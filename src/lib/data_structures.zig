const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const maxInt = lib.maxInt;

pub fn BitsetU64(comptime bits: comptime_int) type {
    assert(bits <= @bitSizeOf(u64));
    const max_value = maxInt(@Type(.{
        .Int = .{
            .signedness = .unsigned,
            .bits = bits,
        },
    }));

    return packed struct(u64) {
        value: u64 = 0,

        const Error = error{
            block_full,
        };

        pub inline fn allocate(bitset: *@This()) !u6 {
            if (bitset.value & max_value != max_value) {
                // log.debug("Bitset: 0b{b}", .{bitset.value});
                const result: u6 = @intCast(@ctz(~bitset.value));
                // log.debug("Result: {}", .{result});
                assert(!bitset.isSet(result));
                bitset.set(result);
                return result;
            } else {
                return error.block_full;
            }
        }

        pub inline fn set(bitset: *@This(), index: u6) void {
            assert(index < bits);
            bitset.value |= (@as(u64, 1) << index);
        }

        pub inline fn clear(bitset: *@This(), index: u6) void {
            assert(index < bits);
            bitset.value &= ~(@as(u64, 1) << index);
        }

        pub inline fn isSet(bitset: @This(), index: u6) bool {
            assert(index < bits);
            return bitset.value & (@as(u64, 1) << index) != 0;
        }

        pub inline fn isFull(bitset: @This()) bool {
            return bitset.value == max_value;
        }
    };
}

pub fn SparseArray(comptime T: type) type {
    return extern struct {
        ptr: [*]T,
        len: usize,
        capacity: usize,

        const Array = @This();

        pub const Error = error{
            index_out_of_bounds,
        };

        pub fn allocate(array: *Array, allocator: *Allocator) !*T {
            try array.ensureCapacity(allocator, array.len + 1);
            const index = array.len;
            array.len += 1;
            const slice = array.ptr[0..array.len];
            return &slice[index];
        }

        pub fn append(array: *Array, allocator: *Allocator, element: T) !usize {
            try array.ensureCapacity(allocator, array.len + 1);
            const index = array.len;
            array.len += 1;
            const slice = array.ptr[0..array.len];
            slice[index] = element;

            return index;
        }

        fn ensureCapacity(array: *Array, allocator: *Allocator, desired_capacity: usize) !void {
            if (array.capacity < desired_capacity) {
                // Allocate a new array
                const new_slice = try allocator.allocate(T, desired_capacity);
                if (array.capacity == 0) {
                    array.ptr = new_slice.ptr;
                    array.capacity = new_slice.len;
                } else {
                    // Reallocate
                    if (array.len > 0) {
                        @memcpy(new_slice[0..array.len], array.ptr[0..array.len]);
                    }

                    // TODO: free

                    array.ptr = new_slice.ptr;
                    array.capacity = new_slice.len;
                }
            }
        }

        pub fn indexOf(array: *Array, ptr: *T) usize {
            const base_int = @intFromPtr(array.ptr);
            const ptr_int = @intFromPtr(ptr);
            return @divExact(ptr_int - base_int, @sizeOf(T));
        }

        pub inline fn get(array: *Array, index: usize) T {
            assert(array.len > index);
            const slice = array.ptr[0..array.len];
            return slice[index];
        }

        pub inline fn getChecked(array: *Array, index: usize) !T {
            if (array.len > index) {
                return array.get(index);
            } else {
                return error.index_out_of_bounds;
            }
        }
    };
}
