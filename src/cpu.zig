const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const log = lib.log;

const bootloader = @import("bootloader");

const privileged = @import("privileged");
const CPUPageTables = privileged.arch.CPUPageTables;
const Mapping = privileged.Mapping;
const PageAllocatorInterface = privileged.PageAllocator;
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalAddressSpace = lib.PhysicalAddressSpace;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const stopCPU = privileged.arch.stopCPU;
const VirtualAddress = lib.VirtualAddress;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const birth = @import("birth");

pub const test_runner = @import("cpu/test_runner.zig");
pub const arch = @import("cpu/arch.zig");
pub const capabilities = @import("cpu/capabilities.zig");
pub const syscall = @import("cpu/syscall.zig");

pub export var stack: [0x8000]u8 align(0x1000) = undefined;

pub var bundle: []const u8 = &.{};
pub var bundle_files: []const u8 = &.{};

pub export var user_scheduler: *UserScheduler = undefined;
pub export var driver: *align(lib.arch.valid_page_sizes[0]) Driver = undefined;
pub export var heap = Heap{};
pub var debug_info: lib.ModuleDebugInfo = undefined;
pub export var page_tables: CPUPageTables = undefined;
pub var file: []align(lib.default_sector_size) const u8 = undefined;
pub export var core_id: u32 = 0;
pub export var bsp = false;
var panic_lock = lib.Spinlock.released;

/// This data structure holds the information needed to run a core
pub const Driver = extern struct {
    init_root_capability: capabilities.RootDescriptor,
    valid: bool,
    padding: [padding_byte_count]u8 = .{0} ** padding_byte_count,
    const padding_byte_count = lib.arch.valid_page_sizes[0] - @sizeOf(bool) - @sizeOf(capabilities.RootDescriptor);

    pub inline fn getRootCapability(drv: *Driver) *capabilities.Root {
        return drv.init_root_capability.value;
    }

    comptime {
        // @compileLog(@sizeOf(Driver));
        assert(lib.isAligned(@sizeOf(Driver), lib.arch.valid_page_sizes[0]));
    }
};

/// This data structure holds the information needed to run a program in a core (cpu side)
pub const UserScheduler = extern struct {
    s: S,
    padding: [padding_byte_count]u8 = .{0} ** padding_byte_count,

    const S = extern struct {
        capability_root_node: capabilities.Root,
        common: *birth.UserScheduler,
    };

    const total_size = @sizeOf(S);
    const aligned_size = lib.alignForward(usize, total_size, lib.arch.valid_page_sizes[0]);
    const padding_byte_count = aligned_size - total_size;

    comptime {
        if (padding_byte_count == 0 and @hasField(UserScheduler, "padding")) {
            @compileError("remove padding because it is not necessary");
        }
    }
};

const print_stack_trace = false;
var panic_count: usize = 0;

inline fn panicPrologue(comptime format: []const u8, arguments: anytype) !void {
    panic_count += 1;
    privileged.arch.disableInterrupts();
    if (panic_count == 1) panic_lock.acquire();

    try writer.writeAll(lib.Color.get(.bold));
    try writer.writeAll(lib.Color.get(.red));
    try writer.writeAll("[CPU DRIVER] [PANIC] ");
    try writer.print(format, arguments);
    try writer.writeByte('\n');
    try writer.writeAll(lib.Color.get(.reset));
}

inline fn panicEpilogue() noreturn {
    if (panic_count == 1) panic_lock.release();

    shutdown(.failure);
}

// inline fn printStackTrace(maybe_stack_trace: ?*lib.StackTrace) !void {
//     if (maybe_stack_trace) |stack_trace| {
//         var debug_info = try getDebugInformation();
//         try writer.writeAll("Stack trace:\n");
//         var frame_index: usize = 0;
//         var frames_left: usize = @min(stack_trace.index, stack_trace.instruction_addresses.len);
//
//         while (frames_left != 0) : ({
//             frames_left -= 1;
//             frame_index = (frame_index + 1) % stack_trace.instruction_addresses.len;
//         }) {
//             const return_address = stack_trace.instruction_addresses[frame_index];
//             try writer.print("[{}] ", .{frame_index});
//             try printSourceAtAddress(&debug_info, return_address);
//         }
//     } else {
//         try writer.writeAll("Stack trace not available\n");
//     }
// }

// inline fn printStackTraceFromStackIterator(return_address: usize, frame_address: usize) !void {
//     var debug_info = try getDebugInformation();
//     var stack_iterator = lib.StackIterator.init(return_address, frame_address);
//     var frame_index: usize = 0;
//     try writer.writeAll("Stack trace:\n");
//
//     try printSourceAtAddress(&debug_info, return_address);
//     while (stack_iterator.next()) |address| : (frame_index += 1) {
//         try writer.print("[{}] ", .{frame_index});
//         try printSourceAtAddress(&debug_info, address);
//     }
// }

// fn printSourceAtAddress(debug_info: *lib.ModuleDebugInfo, address: usize) !void {
//     if (debug_info.findCompileUnit(address)) |compile_unit| {
//         const symbol = .{
//             .symbol_name = debug_info.getSymbolName(address) orelse "???",
//             .compile_unit_name = compile_unit.die.getAttrString(debug_info, lib.dwarf.AT.name, debug_info.debug_str, compile_unit.*) catch "???",
//             .line_info = debug_info.getLineNumberInfo(heap_allocator.toZig(), compile_unit.*, address) catch null,
//         };
//         try writer.print("0x{x}: {s}!{s} {s}:{}:{}\n", .{ address, symbol.symbol_name, symbol.compile_unit_name, symbol.line_info.?.file_name, symbol.line_info.?.line, symbol.line_info.?.column });
//     } else |err| {
//         return err;
//     }
// }

pub fn panicWithStackTrace(stack_trace: ?*lib.StackTrace, comptime format: []const u8, arguments: anytype) noreturn {
    _ = stack_trace;
    panicPrologue(format, arguments) catch {};
    // if (print_stack_trace) printStackTrace(stack_trace) catch {};
    panicEpilogue();
}

pub fn panicFromInstructionPointerAndFramePointer(return_address: usize, frame_address: usize, comptime format: []const u8, arguments: anytype) noreturn {
    _ = frame_address;
    _ = return_address;
    panicPrologue(format, arguments) catch {};
    //if (print_stack_trace) printStackTraceFromStackIterator(return_address, frame_address) catch {};
    panicEpilogue();
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    @call(.always_inline, panicFromInstructionPointerAndFramePointer, .{ @returnAddress(), @frameAddress(), format, arguments });
}

pub var command_count: usize = 0;
pub var syscall_count: usize = 0;

pub inline fn shutdown(exit_code: lib.QEMU.ExitCode) noreturn {
    log.debug("Printing stats...", .{});
    log.debug("Syscall count: {}", .{syscall_count});

    privileged.shutdown(exit_code);
}

/// This is only meant to be used by the CPU driver
const Heap = extern struct {
    allocator: lib.Allocator = .{
        .callbacks = .{
            .allocate = callbackAllocate,
        },
    },
    regions: ?*Region = null,
    region_heap: ?*Region = null,
    liberated_regions: ?*Region = null,

    const Region = extern struct {
        region: VirtualMemoryRegion,
        previous: ?*Region = null,
        next: ?*Region = null,
    };

    pub fn create(heap_allocator: *Heap, comptime T: type) lib.Allocator.Allocate.Error!*T {
        const result = try heap_allocator.allocate(@sizeOf(T), @alignOf(T));
        return @ptrFromInt(result.address);
    }

    // TODO: turn the other way around: make the callback call this function
    pub fn allocate(heap_allocator: *Heap, size: u64, alignment: u64) lib.Allocator.Allocate.Error!lib.Allocator.Allocate.Result {
        return heap_allocator.allocator.callbacks.allocate(&heap_allocator.allocator, size, alignment);
    }

    fn callbackAllocate(allocator: *Allocator, size: u64, alignment: u64) lib.Allocator.Allocate.Error!lib.Allocator.Allocate.Result {
        // This assert is triggered by the Zig std library
        //assert(lib.isAligned(size, alignment));
        const heap_allocator = @fieldParentPtr(Heap, "allocator", allocator);
        var iterator = heap_allocator.regions;

        while (iterator) |region| : (iterator = region.next) {
            if (lib.isAligned(region.region.address.value(), alignment)) {
                if (region.region.size > size) {
                    const virtual_region = region.region.takeSlice(size) catch return error.OutOfMemory;
                    return .{
                        .address = virtual_region.address.value(),
                        .size = virtual_region.size,
                    };
                } else if (region.region.size == size) {
                    const result = .{
                        .address = region.region.address.value(),
                        .size = region.region.size,
                    };
                    region.previous.?.next = region.next;

                    region.* = lib.zeroes(Region);

                    if (heap_allocator.liberated_regions) |_| {
                        var inner_iterator = heap_allocator.liberated_regions;
                        while (inner_iterator) |inner_region| : (inner_iterator = inner_region.next) {
                            if (inner_region.next == null) {
                                inner_region.next = region;
                                region.previous = inner_region;
                                break;
                            }
                        }
                    } else {
                        heap_allocator.liberated_regions = region;
                    }

                    return result;
                } else {
                    continue;
                }
            }
            // TODO: else
            // Contemplate options to split the region to satisfy alignment
        } else {
            const total_size = lib.alignForward(u64, size, @max(alignment, lib.arch.valid_page_sizes[0]));
            const physical_region = try driver.getRootCapability().allocateRAMPrivileged(total_size);
            const virtual_region = physical_region.toHigherHalfVirtualAddress();

            if (virtual_region.size > size) {
                const new_region = nr: {
                    var region_heap_iterator: ?*Region = heap_allocator.region_heap;
                    while (region_heap_iterator) |region| : (region_heap_iterator = region.next) {
                        if (region.region.size > @sizeOf(Region)) {
                            @panic("TODO: fits");
                        } else if (region.region.size == @sizeOf(Region)) {
                            @panic("TODO: fits exactly");
                        } else {
                            continue;
                        }

                        break :nr undefined;
                    } else {
                        const physical_heap_region = try driver.getRootCapability().allocateRAMPrivileged(lib.arch.valid_page_sizes[0]);
                        var virtual_heap_region = physical_heap_region.toHigherHalfVirtualAddress();
                        const virtual_region_for_this_region = virtual_heap_region.takeSlice(@sizeOf(Region)) catch return error.OutOfMemory;
                        const this_region = virtual_region_for_this_region.address.access(*Region);
                        const virtual_region_for_new_region = virtual_heap_region.takeSlice(@sizeOf(Region)) catch return error.OutOfMemory;
                        const new_region = virtual_region_for_new_region.address.access(*Region);
                        new_region.* = .{
                            .region = undefined,
                            .previous = this_region,
                        };
                        this_region.* = .{
                            .region = virtual_heap_region,
                            .next = new_region,
                        };

                        var region_iterator = heap.regions;
                        if (region_iterator) |_| {
                            while (region_iterator) |region| : (region_iterator = region.next) {
                                if (region.next == null) {
                                    region.next = this_region;
                                    this_region.previous = region;
                                    break;
                                }
                            }
                        } else {
                            heap.regions = this_region;
                        }

                        break :nr new_region;
                    }
                };

                var region_slicer = virtual_region;
                const real_virtual_region = region_slicer.takeSlice(size) catch return error.OutOfMemory;
                const result = .{
                    .address = real_virtual_region.address.value(),
                    .size = real_virtual_region.size,
                };
                new_region.region = region_slicer;

                return result;
            } else {
                // TODO: register this allocation somehow
                return .{
                    .address = virtual_region.address.value(),
                    .size = virtual_region.size,
                };
            }
        }

        @panic("TODO: callbackAllocate");
    }
};

// fn getDebugInformation() !lib.ModuleDebugInfo {
//     const debug_info = lib.getDebugInformation(heap_allocator.toZig(), file) catch |err| {
//         try writer.print("Failed to get debug information: {}", .{err});
//         return err;
//     };
//
//     return debug_info;
// }

pub const writer = privileged.E9Writer{ .context = {} };
