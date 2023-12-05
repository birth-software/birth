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
const paging = privileged.arch.paging;

const birth = @import("birth");

pub const arch = @import("cpu/arch.zig");
pub const interface = @import("cpu/interface.zig");
pub const init = @import("cpu/init.zig");

const PageTableRegions = arch.init.PageTableRegions;

pub export var stack: [0x8000]u8 align(0x1000) = undefined;

pub var bundle: []const u8 = &.{};
pub var bundle_files: []const u8 = &.{};

pub export var page_allocator = PageAllocator{};
pub export var user_scheduler: *UserScheduler = undefined;
pub export var heap = HeapImplementation(false){};
pub var debug_info: lib.ModuleDebugInfo = undefined;
pub export var page_tables: CPUPageTables = undefined;
pub var file: []align(lib.default_sector_size) const u8 = undefined;
pub export var core_id: u32 = 0;
pub export var bsp = false;
var panic_lock = lib.Spinlock.released;

/// This data structure holds the information needed to run a program in a core (cpu side)
pub const UserScheduler = extern struct {
    s: S,
    padding: [padding_byte_count]u8 = .{0} ** padding_byte_count,

    const S = extern struct {
        capability_root_node: interface.Root,
        common: *birth.Scheduler.Common,
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

const print_stack_trace = true;
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

inline fn printStackTrace(maybe_stack_trace: ?*lib.StackTrace) !void {
    if (maybe_stack_trace) |stack_trace| {
        try writer.writeAll("Stack trace:\n");
        var frame_index: usize = 0;
        var frames_left: usize = @min(stack_trace.index, stack_trace.instruction_addresses.len);

        while (frames_left != 0) : ({
            frames_left -= 1;
            frame_index = (frame_index + 1) % stack_trace.instruction_addresses.len;
        }) {
            const return_address = stack_trace.instruction_addresses[frame_index];
            try writer.print("[{}] ", .{frame_index});
            try printSourceAtAddress(return_address);
            try writer.writeByte('\n');
        }
    } else {
        try writer.writeAll("Stack trace not available\n");
    }
}

inline fn printStackTraceFromStackIterator(return_address: usize, frame_address: usize) !void {
    var stack_iterator = lib.StackIterator.init(return_address, frame_address);
    var frame_index: usize = 0;
    try writer.writeAll("Stack trace:\n");

    while (stack_iterator.next()) |address| : (frame_index += 1) {
        if (address == 0) break;
        try writer.print("[{}] ", .{frame_index});
        try printSourceAtAddress(address);
        try writer.writeByte('\n');
    }
}

fn printSourceAtAddress(address: usize) !void {
    const compile_unit = debug_info.findCompileUnit(address) catch {
        try writer.print("0x{x}: ???", .{address});
        return;
    };
    const symbol_name = debug_info.getSymbolName(address) orelse "???";
    const compile_unit_name = compile_unit.die.getAttrString(&debug_info, lib.dwarf.AT.name, debug_info.section(.debug_str), compile_unit.*) catch "???";
    const line_info = debug_info.getLineNumberInfo(heap.allocator.zigUnwrap(), compile_unit.*, address) catch null;
    const symbol = .{
        .symbol_name = symbol_name,
        .compile_unit_name = compile_unit_name,
        .line_info = line_info,
    };

    const file_name = if (symbol.line_info) |li| li.file_name else "???";
    const line = if (symbol.line_info) |li| li.line else 0;
    const column = if (symbol.line_info) |li| li.column else 0;
    try writer.print("0x{x}: {s}!{s} {s}:{}:{}", .{ address, symbol.symbol_name, symbol.compile_unit_name, file_name, line, column });
}

pub fn panicWithStackTrace(stack_trace: ?*lib.StackTrace, comptime format: []const u8, arguments: anytype) noreturn {
    panicPrologue(format, arguments) catch {};
    if (print_stack_trace) printStackTrace(stack_trace) catch {};
    panicEpilogue();
}

pub fn panicFromInstructionPointerAndFramePointer(return_address: usize, frame_address: usize, comptime format: []const u8, arguments: anytype) noreturn {
    panicPrologue(format, arguments) catch {};
    if (print_stack_trace) printStackTraceFromStackIterator(return_address, frame_address) catch {};
    panicEpilogue();
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    @call(.always_inline, panicFromInstructionPointerAndFramePointer, .{ @returnAddress(), @frameAddress(), format, arguments });
}

pub var command_count: usize = 0;

pub inline fn shutdown(exit_code: lib.QEMU.ExitCode) noreturn {
    log.debug("Printing stats...", .{});
    log.debug("System call count: {}", .{interface.system_call_count});

    privileged.shutdown(exit_code);
}

pub const RegionList = extern struct {
    regions: [list_region_count]PhysicalMemoryRegion = .{PhysicalMemoryRegion.invalid()} ** list_region_count,
    metadata: Metadata = .{},

    pub const Metadata = extern struct {
        reserved: usize = 0,
        bitset: Bitset = .{},
        previous: ?*RegionList = null,
        next: ?*RegionList = null,

        const Bitset = lib.data_structures.BitsetU64(list_region_count);

        comptime {
            assert(@sizeOf(Metadata) == expected_size);
            assert(@bitSizeOf(usize) - list_region_count < 8);
        }

        const expected_size = 4 * @sizeOf(usize);
    };

    const Error = error{
        OutOfMemory,
        no_space,
        misalignment_page_size,
    };

    pub fn allocateAligned(list: *RegionList, size: usize, alignment: usize) Error!PhysicalMemoryRegion {
        assert(alignment % lib.arch.valid_page_sizes[0] == 0);

        for (&list.regions, 0..) |*region, _index| {
            const index: u6 = @intCast(_index);
            assert(lib.isAligned(region.size, lib.arch.valid_page_sizes[0]));
            assert(lib.isAligned(region.address.value(), lib.arch.valid_page_sizes[0]));

            if (list.metadata.bitset.isSet(index)) {
                if (lib.isAligned(region.address.value(), alignment)) {
                    if (region.size >= size) {
                        const result = region.takeSlice(size) catch unreachable;
                        if (region.size == 0) {
                            list.remove(@intCast(index));
                        }

                        return result;
                    }
                }
            }
        }

        return Error.OutOfMemory;
    }

    pub fn remove(list: *RegionList, index: u6) void {
        list.metadata.bitset.clear(index);
    }

    pub const UnalignedAllocationResult = extern struct {
        wasted: PhysicalMemoryRegion,
        allocated: PhysicalMemoryRegion,
    };

    /// Slow path
    pub fn allocateAlignedSplitting(list: *RegionList, size: usize, alignment: usize) !UnalignedAllocationResult {
        for (&list.regions, 0..) |*region, _index| {
            const index: u6 = @intCast(_index);
            const aligned_region_address = lib.alignForward(usize, region.address.value(), alignment);
            const wasted_space = aligned_region_address - region.address.value();

            if (list.metadata.bitset.isSet(index)) {
                const target_size = wasted_space + size;
                if (region.size >= target_size) {
                    const wasted_region = try region.takeSlice(wasted_space);
                    const allocated_region = try region.takeSlice(size);

                    if (region.size == 0) {
                        list.remove(index);
                    }

                    return UnalignedAllocationResult{
                        .wasted = wasted_region,
                        .allocated = allocated_region,
                    };
                }
            }
        }

        log.err("allocateAlignedSplitting", .{});
        return error.OutOfMemory;
    }

    pub fn allocate(list: *RegionList, size: usize) Error!PhysicalMemoryRegion {
        return list.allocateAligned(size, lib.arch.valid_page_sizes[0]);
    }

    pub fn append(list: *RegionList, region: PhysicalMemoryRegion) Error!birth.interface.Memory {
        var block_count: usize = 0;
        while (true) : (block_count += 1) {
            if (!list.metadata.bitset.isFull()) {
                const region_index = list.metadata.bitset.allocate() catch continue;
                const block_index = block_count;

                list.regions[region_index] = region;

                return .{
                    .block = @intCast(block_index),
                    .region = region_index,
                };
            } else {
                return Error.no_space;
            }
        }
    }

    const cache_line_count = 16;
    const list_region_count = @divExact((cache_line_count * lib.cache_line_size) - Metadata.expected_size, @sizeOf(PhysicalMemoryRegion));

    comptime {
        assert(@sizeOf(RegionList) % lib.cache_line_size == 0);
    }
};

const UseCase = extern struct {
    reason: Reason,
    const Reason = enum(u8) {
        heap,
        privileged,
        wasted,
        user_protected,
        user,
        bootloader,
    };
};

// TODO: make this more cache friendly
const UsedRegionList = extern struct {
    region: PhysicalMemoryRegion,
    use_case: UseCase,
    next: ?*UsedRegionList = null,
};

pub const PageAllocator = extern struct {
    free_regions: ?*RegionList = null,
    used_regions: ?*UsedRegionList = null,
    used_region_buffer: ?*UsedRegionList = null,
    free_byte_count: u64 = 0,
    used_byte_count: u64 = 0,

    pub fn allocate(allocator: *PageAllocator, size: usize, use_case: UseCase) lib.Allocator.Allocate.Error!PhysicalMemoryRegion {
        const allocation = try allocator.allocateRaw(size);
        try allocator.appendUsedRegion(allocation, use_case);
        return allocation;
    }

    fn allocateRaw(allocator: *PageAllocator, size: usize) !PhysicalMemoryRegion {
        var iterator = allocator.free_regions;
        while (iterator) |region_list| : (iterator = region_list.metadata.next) {
            const allocation = region_list.allocate(size) catch continue;
            allocator.free_byte_count -= size;
            allocator.used_byte_count += size;

            return allocation;
        }

        log.err("allocateRaw: out of memory. Used: 0x{x}. Free: 0x{x}", .{ allocator.used_byte_count, allocator.free_byte_count });
        return error.OutOfMemory;
    }

    /// The only purpose this serves is to do the trick when switching cr3
    pub fn allocateAligned(allocator: *PageAllocator, size: usize, alignment: usize, use_case: UseCase) lib.Allocator.Allocate.Error!PhysicalMemoryRegion {
        var iterator = allocator.free_regions;
        while (iterator) |region_list| : (iterator = region_list.metadata.next) {
            const unaligned_allocation = region_list.allocateAlignedSplitting(size, alignment) catch continue;
            // TODO: do something with the wasted space
            const total_allocation_size = unaligned_allocation.wasted.size + unaligned_allocation.allocated.size;
            log.err("ALLOCATED: 0x{x}. WASTED: 0x{x}. TOTAL: 0x{x}", .{ unaligned_allocation.allocated.size, unaligned_allocation.wasted.size, total_allocation_size });

            try allocator.appendUsedRegion(unaligned_allocation.allocated, use_case);
            try allocator.appendUsedRegion(unaligned_allocation.wasted, .{ .reason = .wasted });

            allocator.free_byte_count -= total_allocation_size;
            allocator.used_byte_count += total_allocation_size;

            return unaligned_allocation.allocated;
        }

        @panic("TODO: PageAllocator.allocateAligned");
    }

    pub fn appendUsedRegion(allocator: *PageAllocator, physical_region: PhysicalMemoryRegion, use_case: UseCase) lib.Allocator.Allocate.Error!void {
        const need_allocation = blk: {
            var result: bool = true;
            var iterator = allocator.used_region_buffer;
            while (iterator) |it| : (iterator = it.next) {
                result = it.region.size < @sizeOf(UsedRegionList);
                if (!result) {
                    break;
                }
            }

            break :blk result;
        };

        if (need_allocation) {
            const allocation = try allocator.allocateRaw(lib.arch.valid_page_sizes[0]);
            const new_buffer = allocation.address.toHigherHalfVirtualAddress().access(*UsedRegionList);
            new_buffer.* = .{
                .region = allocation,
                .use_case = undefined,
            };
            _ = new_buffer.region.takeSlice(@sizeOf(UsedRegionList)) catch unreachable;
            const used_region_allocation = new_buffer.region.takeSlice(@sizeOf(UsedRegionList)) catch unreachable;
            const new_used_region = used_region_allocation.address.toHigherHalfVirtualAddress().access(*UsedRegionList);
            new_used_region.* = .{
                .region = allocation,
                .use_case = .{ .reason = .privileged },
            };

            if (allocator.used_regions) |_| {
                var iterator = allocator.used_regions;
                _ = iterator;
                @panic("TODO: iterate");
            } else {
                allocator.used_regions = new_used_region;
            }

            if (allocator.used_region_buffer) |_| {
                var iterator = allocator.used_region_buffer;
                _ = iterator;
                @panic("TODO: iterate 2");
            } else {
                allocator.used_region_buffer = new_buffer;
            }

            assert(new_buffer.region.size < allocation.size);
        }

        var iterator = allocator.used_region_buffer;
        while (iterator) |it| : (iterator = it.next) {
            if (it.region.size >= @sizeOf(UsedRegionList)) {
                const new_used_region_allocation = it.region.takeSlice(@sizeOf(UsedRegionList)) catch unreachable;
                const new_used_region = new_used_region_allocation.address.toHigherHalfVirtualAddress().access(*UsedRegionList);
                new_used_region.* = .{
                    .region = physical_region,
                    .use_case = use_case,
                };

                iterator = allocator.used_regions;

                while (iterator) |i| : (iterator = i.next) {
                    if (i.next == null) {
                        i.next = new_used_region;
                        return;
                    }
                }
            }
        }

        if (true) @panic("TODO: PageAllocator.appendUsedRegion");
        return error.OutOfMemory;
    }

    pub fn getPageTableAllocatorInterface(allocator: *PageAllocator) privileged.PageAllocator {
        return .{
            .allocate = pageTableAllocateCallback,
            .context = allocator,
            .context_type = .cpu,
        };
    }

    fn pageTableAllocateCallback(context: ?*anyopaque, size: u64, alignment: u64, options: privileged.PageAllocator.AllocateOptions) error{OutOfMemory}!lib.PhysicalMemoryRegion {
        const allocator: *PageAllocator = @alignCast(@ptrCast(context orelse return error.OutOfMemory));
        assert(alignment == lib.arch.valid_page_sizes[0]);
        assert(size == lib.arch.valid_page_sizes[0]);
        assert(options.count == 1);
        assert(options.level_valid);

        const page_table_allocation = try allocator.allocate(size, .{ .reason = .user_protected });
        // log.debug("Page table allocation: 0x{x}", .{page_table_allocation.address.value()});

        // TODO: is this right?
        if (options.user) {
            const user_page_tables = &user_scheduler.s.capability_root_node.dynamic.page_table;
            const user_allocator = &user_scheduler.s.capability_root_node.heap.allocator;
            const new_page_table_ref = try user_page_tables.appendPageTable(user_allocator, .{
                .region = page_table_allocation,
                .mapping = page_table_allocation.address.toHigherHalfVirtualAddress(),
                .flags = .{ .level = options.level },
            });

            const indexed = options.virtual_address;
            const indices = indexed.toIndices();

            var page_table_ref = user_page_tables.user;
            log.debug("Level: {s}", .{@tagName(options.level)});

            for (0..@intFromEnum(options.level) - 1) |level_index| {
                log.debug("Fetching {s} page table", .{@tagName(@as(paging.Level, @enumFromInt(level_index)))});
                const page_table = user_page_tables.getPageTable(page_table_ref) catch @panic("WTF");
                page_table_ref = page_table.children[indices[level_index]];
            }

            const parent_page_table = user_page_tables.getPageTable(page_table_ref) catch @panic("WTF");
            parent_page_table.children[indices[@intFromEnum(options.level) - 1]] = new_page_table_ref;
        }

        return page_table_allocation;
    }
};

pub const HeapRegion = extern struct {
    region: VirtualMemoryRegion,
    previous: ?*HeapRegion = null,
    next: ?*HeapRegion = null,
};

pub fn HeapImplementation(comptime user: bool) type {
    const use_case = .{ .reason = if (user) .user_protected else .heap };
    _ = use_case;
    return extern struct {
        allocator: lib.Allocator = .{
            .callbacks = .{
                .allocate = callbackAllocate,
            },
        },
        regions: ?*Region = null,

        const Heap = @This();
        const Region = HeapRegion;

        pub fn create(heap_allocator: *Heap, comptime T: type) lib.Allocator.Allocate.Error!*T {
            const result = try heap_allocator.allocate(@sizeOf(T), @alignOf(T));
            return @ptrFromInt(result.address);
        }

        pub fn addBootstrapingRegion(heap_allocator: *Heap, region: VirtualMemoryRegion) !void {
            assert(heap_allocator.regions == null);

            var region_splitter = region;
            const new_region_vmr = try region_splitter.takeSlice(@sizeOf(Region));
            const new_region = new_region_vmr.address.access(*Region);
            new_region.* = Region{
                .region = region_splitter,
            };

            heap_allocator.regions = new_region;
        }

        // TODO: turn the other way around: make the callback call this function
        pub fn allocate(heap_allocator: *Heap, size: u64, alignment: u64) lib.Allocator.Allocate.Error!lib.Allocator.Allocate.Result {
            var iterator = heap_allocator.regions;
            while (iterator) |region| : (iterator = region.next) {
                if (region.region.address.isAligned(alignment)) {
                    if (region.region.size >= size) {
                        const virtual_region = region.region.takeSlice(size) catch unreachable;
                        const should_remove = region.region.size == 0;
                        if (should_remove) {
                            // TODO: actually remove and reuse
                            if (region.previous) |prev| prev.next = region.next;
                        }

                        return @bitCast(virtual_region);
                    }
                }
            }

            const new_size = lib.alignForward(usize, size + @sizeOf(HeapRegion), lib.arch.valid_page_sizes[0]);
            assert(alignment <= lib.arch.valid_page_sizes[0]);
            var new_physical_region = try page_allocator.allocate(new_size, .{ .reason = .heap });
            const new_alloc = new_physical_region.takeSlice(@sizeOf(HeapRegion)) catch unreachable;
            const new_heap_region = new_alloc.toHigherHalfVirtualAddress().address.access(*HeapRegion);
            new_heap_region.* = .{
                .region = new_physical_region.toHigherHalfVirtualAddress(),
            };

            iterator = heap.regions;
            if (iterator) |_| {
                while (iterator) |heap_region| : (iterator = heap_region.next) {
                    if (heap_region.next == null) {
                        heap_region.next = new_heap_region;
                        break;
                    }
                }
            } else {
                @panic("NO");
            }

            return heap.allocate(size, alignment);
        }

        fn callbackAllocate(allocator: *Allocator, size: u64, alignment: u64) lib.Allocator.Allocate.Error!lib.Allocator.Allocate.Result {
            // This assert is triggered by the Zig std library
            //assert(lib.isAligned(size, alignment));
            const heap_allocator = @fieldParentPtr(Heap, "allocator", allocator);
            return heap_allocator.allocate(size, alignment);
        }
    };
}

pub const writer = privileged.E9Writer{ .context = {} };
