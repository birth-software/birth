const lib = @import("lib");
const assert = lib.assert;
const Allocator = lib.Allocator;
const enumCount = lib.enumCount;
const log = lib.log.scoped(.capabilities);

const privileged = @import("privileged");
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const birth = @import("birth");
const cpu = @import("cpu");

pub fn processCommand(comptime Syscall: type, raw_arguments: birth.syscall.Arguments) Syscall.Error!Syscall.Result {
    defer cpu.command_count += 1;
    comptime assert(Syscall == birth.capabilities.Syscall(Syscall.capability, Syscall.command));
    const capability: birth.capabilities.Type = Syscall.capability;
    const command: birth.capabilities.Command(capability) = Syscall.command;
    const arguments = try Syscall.toArguments(raw_arguments);

    return if (cpu.user_scheduler.s.capability_root_node.hasPermissions(capability, command)) switch (capability) {
        .io => switch (command) {
            .copy, .mint, .retype, .delete, .revoke, .create => unreachable,
            .log => blk: {
                const message = arguments;
                cpu.writer.writeAll(message) catch unreachable;
                comptime assert(Syscall.Result == usize);
                break :blk message.len;
            },
        },
        .cpu => switch (command) {
            .copy, .mint, .retype, .delete, .revoke, .create => unreachable,
            .get_core_id => cpu.core_id,
            .shutdown => cpu.shutdown(.success),
            .get_command_buffer => {
                const command_buffer = arguments;
                _ = command_buffer;
                @panic("TODO: get_command_buffer");
            },
        },
        .cpu_memory => switch (command) {
            // .allocate => blk: {
            //     comptime assert(@TypeOf(arguments) == usize);
            //     const size = arguments;
            //     const physical_region = try cpu.user_scheduler.s.capability_root_node.allocatePages(size);
            //     try cpu.user_scheduler.s.capability_root_node.allocateCPUMemory(physical_region, .{ .privileged = false });
            //     break :blk physical_region.address;
            // },
            else => @panic(@tagName(command)),
        },
        .ram => switch (command) {
            .allocate => blk: {
                comptime assert(@TypeOf(arguments) == usize);
                const size = arguments;
                const ref = try cpu.driver.getRootCapability().allocateRAM(size);
                break :blk @bitCast(ref);
            },
            else => @panic(@tagName(command)),
        },
        .boot => switch (command) {
            .get_bundle_size => cpu.bundle.len,
            .get_bundle_file_list_size => cpu.bundle_files.len,
            else => @panic(@tagName(command)),
        },
        .process => switch (command) {
            .exit => cpu.shutdown(switch (arguments) {
                true => .success,
                false => .failure,
            }),
            .panic => cpu.panic("User process panicked with exit code 0x{x}: {s}", .{ arguments.exit_code, arguments.message }),
            else => @panic(@tagName(command)),
        },
        .page_table => @panic("TODO: page_table"),
    } else error.forbidden;
}

pub const RootDescriptor = extern struct {
    value: *Root,
};

pub const Static = enum {
    cpu,
    boot,
    process,

    pub const count = lib.enumCount(@This());

    pub const Bitmap = @Type(.{
        .Struct = blk: {
            const full_bit_size = @max(@as(comptime_int, 1 << 3), @as(u8, @sizeOf(Static)) << 3);
            break :blk .{
                .layout = .Packed,
                .backing_integer = lib.IntType(.unsigned, full_bit_size),
                .fields = fields: {
                    var fields: []const lib.Type.StructField = &.{};
                    inline for (lib.enumFields(Static)) |static_field| {
                        fields = fields ++ [1]lib.Type.StructField{.{
                            .name = static_field.name,
                            .type = bool,
                            .default_value = null,
                            .is_comptime = false,
                            .alignment = 0,
                        }};
                    }

                    assert(Static.count > 0);
                    assert(@sizeOf(Static) > 0 or Static.count == 1);

                    const padding_type = lib.IntType(.unsigned, full_bit_size - Static.count);

                    fields = fields ++ [1]lib.Type.StructField{.{
                        .name = "reserved",
                        .type = padding_type,
                        .default_value = &@as(padding_type, 0),
                        .is_comptime = false,
                        .alignment = 0,
                    }};
                    break :fields fields;
                },
                .decls = &.{},
                .is_tuple = false,
            };
        },
    });
};

pub const Dynamic = enum {
    io,
    ram, // Barrelfish equivalent: RAM (no PhysAddr)
    cpu_memory, // Barrelfish equivalent: Frame
    page_table, // Barrelfish equivalent: VNode
    // irq_table,
    // device_memory,
    // scheduler,

    pub const Map = extern struct {
        io: IO,
        ram: RAM,
        cpu_memory: CPUMemory,
        page_table: PageTables,

        comptime {
            inline for (lib.fields(Dynamic.Map), lib.fields(Dynamic)) |struct_field, enum_field| {
                assert(lib.equal(u8, enum_field.name, struct_field.name));
            }
        }
    };
};

pub const RegionList = extern struct {
    regions: [list_region_count]PhysicalMemoryRegion = [1]PhysicalMemoryRegion{PhysicalMemoryRegion.invalid()} ** list_region_count,
    metadata: Metadata = .{},

    pub const Metadata = extern struct {
        count: usize = 0,
        reserved: usize = 0,
        previous: ?*RegionList = null,
        next: ?*RegionList = null,
    };

    const Error = error{
        OutOfMemory,
        no_space,
        misalignment_page_size,
    };

    pub fn getRegions(list: *const RegionList) []const PhysicalMemoryRegion {
        return list.regions[0..list.metadata.count];
    }

    pub fn allocateAligned(list: *RegionList, size: usize, alignment: usize) Error!PhysicalMemoryRegion {
        assert(alignment % lib.arch.valid_page_sizes[0] == 0);
        const regions = list.regions[0..list.metadata.count];

        for (regions, 0..) |*region, index| {
            assert(region.size % lib.arch.valid_page_sizes[0] == 0);
            assert(region.address.value() % lib.arch.valid_page_sizes[0] == 0);

            if (lib.isAligned(region.address.value(), alignment)) {
                if (region.size >= size) {
                    const result = region.takeSlice(size) catch unreachable;
                    if (region.size == 0) {
                        if (index != regions.len - 1) {
                            regions[index] = regions[regions.len - 1];
                        }

                        list.metadata.count -= 1;
                    }

                    return result;
                }
            }
        }

        return Error.OutOfMemory;
    }

    pub const UnalignedAllocationResult = extern struct {
        wasted: PhysicalMemoryRegion,
        allocated: PhysicalMemoryRegion,
    };

    /// Slow path
    pub fn allocateAlignedSplitting(list: *RegionList, size: usize, alignment: usize) !UnalignedAllocationResult {
        const regions = list.regions[0..list.metadata.count];

        for (regions) |*region| {
            const aligned_region_address = lib.alignForward(usize, region.address.value(), alignment);
            const wasted_space = aligned_region_address - region.address.value();

            if (region.size >= wasted_space + size) {
                const wasted_region = try region.takeSlice(wasted_space);
                const allocated_region = try region.takeSlice(size);

                return UnalignedAllocationResult{
                    .wasted = wasted_region,
                    .allocated = allocated_region,
                };
            }
        }

        log.err("allocateAlignedSplitting", .{});
        return error.OutOfMemory;
    }

    pub fn allocate(list: *RegionList, size: usize) Error!PhysicalMemoryRegion {
        return list.allocateAligned(size, lib.arch.valid_page_sizes[0]);
    }

    pub fn append(list: *RegionList, region: PhysicalMemoryRegion) Error!birth.capabilities.RAM {
        var block_count: usize = 0;
        while (true) : (block_count += 1) {
            if (list.metadata.count < list.regions.len) {
                const block_id = block_count;
                const region_id = list.metadata.count;
                list.regions[list.metadata.count] = region;
                list.metadata.count += 1;

                return .{
                    .block = @intCast(block_id),
                    .region = @intCast(region_id),
                };
            } else {
                return Error.no_space;
            }
        }
    }

    const cache_line_count = 5;
    const list_region_count = @divExact((cache_line_count * lib.cache_line_size) - @sizeOf(Metadata), @sizeOf(PhysicalMemoryRegion));

    comptime {
        assert(@sizeOf(RegionList) % lib.cache_line_size == 0);
    }
};

pub const RAM = extern struct {
    lists: [lib.arch.reverse_valid_page_sizes.len]RegionList = .{.{}} ** lib.arch.valid_page_sizes.len,
    allocated: RegionList = .{},
    privileged: RegionList = .{},
    allocate: bool = true,

    const AllocateError = error{
        OutOfMemory,
    };

    inline fn getListIndex(size: usize) usize {
        inline for (lib.arch.reverse_valid_page_sizes, 0..) |reverse_page_size, reverse_index| {
            if (size >= reverse_page_size) return reverse_index;
        }

        unreachable;
    }

    pub fn appendRegion(ram: *RAM, region: PhysicalMemoryRegion) !void {
        _ = region;
        _ = ram;
        @panic("TODO: appendRegion");
    }
};

pub const CPUMemory = extern struct {
    privileged: RAM = .{},
    user: RAM = .{},
    flags: Flags = .{},

    const Flags = packed struct(u64) {
        allocate: bool = true,
        reserved: u63 = 0,
    };
};

pub const PageTables = extern struct {
    foo: u32 = 0,
};

pub const IO = extern struct {
    debug: bool,
};

pub const Scheduler = extern struct {
    handle: ?*cpu.UserScheduler = null,
    memory: PhysicalMemoryRegion,
};

comptime {
    assert(enumCount(Dynamic) + enumCount(Static) == enumCount(birth.capabilities.Type));
}

pub const Root = extern struct {
    static: Static.Bitmap,
    dynamic: Dynamic.Map,
    scheduler: Scheduler,
    heap: Heap = .{},
    padding: [padding_byte_count]u8 = .{0} ** padding_byte_count,

    const max_alignment = @max(@alignOf(Static.Bitmap), @alignOf(Dynamic.Map), @alignOf(Scheduler), @alignOf(Heap));
    const total_size = lib.alignForward(usize, @sizeOf(Static.Bitmap) + @sizeOf(Dynamic.Map) + @sizeOf(Scheduler) + @sizeOf(Heap), max_alignment);
    const page_aligned_size = lib.alignForward(usize, total_size, lib.arch.valid_page_sizes[0]);
    const padding_byte_count = page_aligned_size - total_size;

    comptime {
        assert(@sizeOf(Root) % lib.arch.valid_page_sizes[0] == 0);
    }

    // pub fn copy(root: *Root, other: *Root) void {
    //     other.static = root.static;
    //     // TODO:
    //     other.dynamic = root.dynamic;
    // }

    pub inline fn hasPermissions(root: *const Root, comptime capability_type: birth.capabilities.Type, command: birth.capabilities.Command(capability_type)) bool {
        return switch (capability_type) {
            // static capabilities
            inline .cpu,
            .boot,
            .process,
            => |static_capability| @field(root.static, @tagName(static_capability)),
            // dynamic capabilities
            .io => switch (command) {
                .copy, .mint, .retype, .delete, .revoke, .create => unreachable,
                .log => root.dynamic.io.debug,
            },
            .cpu_memory => root.dynamic.cpu_memory.flags.allocate,
            .ram => switch (command) {
                .allocate => root.dynamic.ram.allocate,
                else => @panic("TODO: else => ram"),
            },
            .page_table => unreachable,
        };
    }

    pub const AllocateError = error{
        OutOfMemory,
    };

    // Fast path
    fn allocateRAMRaw(root: *Root, size: usize) AllocateError!PhysicalMemoryRegion {
        lib.log.err("New allocation demanded: 0x{x} bytes", .{size});
        assert(size != 0);
        assert(lib.isAligned(size, lib.arch.valid_page_sizes[0]));
        var index = RAM.getListIndex(size);

        const result = blk: {
            while (true) : (index -= 1) {
                const list = &root.dynamic.ram.lists[index];
                var iterator: ?*cpu.capabilities.RegionList = list;

                const page_size = @as(u64, switch (index) {
                    0 => lib.arch.reverse_valid_page_sizes[0],
                    1 => lib.arch.reverse_valid_page_sizes[1],
                    2 => lib.arch.reverse_valid_page_sizes[2],
                    else => unreachable,
                });

                var list_count: usize = 0;
                while (iterator) |free_ram_list| : ({
                    iterator = free_ram_list.metadata.next;
                    list_count += 1;
                }) {
                    const allocation = free_ram_list.allocate(size) catch continue;
                    list_count += 1;
                    log.err("Found 0x{x}-page-size region for 0x{x} bytes after ({}/{}) lists", .{ page_size, size, list_count, list.metadata.count });
                    log.err("======", .{});
                    break :blk allocation;
                }

                log.err("Could not find any 0x{x}-page-size region for 0x{x} bytes after {} lists", .{ page_size, size, list.metadata.count });

                if (index == 0) break;
            }

            log.err("allocateRAMRaw", .{});
            return error.OutOfMemory;
        };

        @memset(result.toHigherHalfVirtualAddress().access(u8), 0);

        return result;
    }

    pub fn allocateRAM(root: *Root, size: usize) AllocateError!birth.capabilities.RAM {
        const result = try allocateRAMRaw(root, size);
        const reference = root.dynamic.ram.allocated.append(result) catch |err| {
            log.err("err(user): {}", .{err});
            return AllocateError.OutOfMemory;
        };
        return reference;
    }

    pub fn allocateRAMPrivileged(root: *Root, size: usize) AllocateError!PhysicalMemoryRegion {
        const result = try allocateRAMRaw(root, size);
        const reference = root.dynamic.ram.privileged.append(result) catch blk: {
            const region_list = try cpu.heap.create(RegionList);
            region_list.* = .{};
            const ref = region_list.append(result) catch |err| {
                log.err("Err(priv): {}", .{err});
                return AllocateError.OutOfMemory;
            };

            var iterator: ?*RegionList = &root.dynamic.ram.privileged;
            while (iterator) |rl| : (iterator = rl.metadata.next) {
                if (rl.metadata.next == null) {
                    rl.metadata.next = region_list;
                    region_list.metadata.previous = rl;
                    break;
                }
            }

            break :blk ref;
        };
        _ = reference;
        return result;
    }

    // Slow uncommon path. Use cases:
    // 1. CR3 switch. This is assumed to be privileged, so this function assumes privileged use of the memory
    pub fn allocatePageCustomAlignment(root: *Root, size: usize, alignment: usize) AllocateError!PhysicalMemoryRegion {
        assert(alignment > lib.arch.valid_page_sizes[0] and alignment < lib.arch.valid_page_sizes[1]);

        comptime assert(lib.arch.valid_page_sizes.len == 3);
        var index = RAM.getListIndex(size);

        while (true) : (index -= 1) {
            const smallest_region_list = &root.dynamic.ram.lists[index];
            var iterator: ?*cpu.capabilities.RegionList = smallest_region_list;
            while (iterator) |free_region_list| : (iterator = free_region_list.metadata.next) {
                if (free_region_list.metadata.count > 0) {
                    const physical_allocation = free_region_list.allocateAligned(size, alignment) catch blk: {
                        const splitted_allocation = free_region_list.allocateAlignedSplitting(size, alignment) catch continue;
                        _ = try root.appendRegion(&root.dynamic.ram, splitted_allocation.wasted);
                        break :blk splitted_allocation.allocated;
                    };

                    return physical_allocation;
                }
            }

            if (index == 0) break;
        }

        log.err("allocatePageCustomAlignment", .{});
        return AllocateError.OutOfMemory;
    }

    fn allocateSingle(root: *Root, comptime T: type) AllocateError!*T {
        const size = @sizeOf(T);
        const alignment = @alignOf(T);
        var iterator = root.heap.first;
        while (iterator) |heap_region| : (iterator = heap_region.next) {
            if (heap_region.alignmentFits(alignment)) {
                if (heap_region.sizeFits(size)) {
                    const allocated_region = heap_region.takeRegion(size);
                    const result = &allocated_region.toHigherHalfVirtualAddress().access(T)[0];
                    return result;
                }
            } else {
                @panic("ELSE");
            }
        }

        const physical_region = try root.allocateRAM(lib.arch.valid_page_sizes[0]);
        const heap_region = physical_region.toHigherHalfVirtualAddress().address.access(*Heap.Region);
        const first = root.heap.first;
        heap_region.* = .{
            .descriptor = physical_region.offset(@sizeOf(Heap.Region)),
            .allocated_size = @sizeOf(Heap.Region),
            .next = first,
        };

        root.heap.first = heap_region;

        return try root.allocateSingle(T);
    }

    fn allocateMany(root: *Root, comptime T: type, count: usize) AllocateError![]T {
        _ = count;
        _ = root;

        @panic("TODO many");
    }

    fn appendRegion(root: *Root, ram: *RAM, region: PhysicalMemoryRegion) !birth.capabilities.RAM {
        _ = root;
        const index = RAM.getListIndex(region.size);
        const ref = ram.lists[index].append(region) catch @panic("TODO: allocate in appendRegion");
        return ref;
    }

    pub const AllocateCPUMemoryOptions = packed struct {
        privileged: bool,
    };

    pub fn allocateCPUMemory(root: *Root, physical_region: PhysicalMemoryRegion, options: AllocateCPUMemoryOptions) !void {
        const ram_region = switch (options.privileged) {
            true => &root.dynamic.cpu_memory.privileged,
            false => &root.dynamic.cpu_memory.user,
        };

        try root.appendRegion(ram_region, physical_region);
    }

    pub const Heap = extern struct {
        first: ?*Region = null,

        const AllocateError = error{
            OutOfMemory,
        };

        pub fn new(physical_region: PhysicalMemoryRegion, previous_allocated_size: usize) Heap {
            const allocated_size = previous_allocated_size + @sizeOf(Region);
            assert(physical_region.size > allocated_size);
            const region = physical_region.offset(previous_allocated_size).address.toHigherHalfVirtualAddress().access(*Region);
            region.* = .{
                .descriptor = physical_region,
                .allocated_size = allocated_size,
            };
            return Heap{
                .first = region,
            };
        }

        fn create(heap: *Heap, comptime T: type) Heap.AllocateError!*T {
            const result = try heap.allocate(T, 1);
            return &result[0];
        }

        fn allocate(heap: *Heap, comptime T: type, count: usize) Heap.AllocateError![]T {
            var iterator = heap.first;
            while (iterator) |heap_region| {
                const allocation = heap_region.allocate(T, count) catch continue;
                return allocation;
            }
            @panic("TODO: heap allocate");
        }

        const Region = extern struct {
            descriptor: PhysicalMemoryRegion,
            allocated_size: usize,
            next: ?*Region = null,

            inline fn getFreeRegion(region: Region) PhysicalMemoryRegion {
                const free_region = region.descriptor.offset(region.allocated_size);
                assert(free_region.size > 0);
                return free_region;
            }

            const AllocateError = error{
                OutOfMemory,
            };

            fn takeRegion(region: *Region, size: usize) PhysicalMemoryRegion {
                var free_region = region.getFreeRegion();
                assert(free_region.size >= size);
                const allocated_region = free_region.takeSlice(size);
                region.allocated_size += size;
                return allocated_region;
            }

            fn allocate(region: *Region, comptime T: type, count: usize) Region.AllocateError![]T {
                const free_region = region.getFreeRegion();
                _ = free_region;
                _ = count;
                @panic("TODO: region allocate");
            }

            fn create(region: *Region, comptime T: type) Region.AllocateError!*T {
                const result = try region.allocate(T, 1);
                return &result[0];
            }

            // inline fn canAllocateDirectly(region: Region, size: usize, alignment: usize) bool {
            //     const alignment_fits = region.alignmentFits(alignment);
            //     const size_fits = region.sizeFits(size);
            //     return alignment_fits and size_fits;
            // }

            // inline fn canAllocateSplitting(region: Region, size: usize, alignment: usize) bool {
            //     const free_region = region.getFreeRegion();
            //     const aligned_region_address = lib.alignForward(usize, free_region.address.value(), alignment);
            //     const wasted_space = aligned_region_address - free_region.address.value();
            //     log.warn("Wasted space: {} bytes", .{wasted_space});
            //     _ = size;
            //     @panic("TODO: canAllocateSplitting");
            // }

            inline fn sizeFits(region: Region, size: usize) bool {
                return region.descriptor.size - region.allocated_size >= size;
            }

            inline fn alignmentFits(region: Region, alignment: usize) bool {
                const result = lib.isAligned(region.getFreeRegion().address.value(), alignment);
                return result;
            }
        };
    };
};

pub const RootPageTableEntry = extern struct {
    address: PhysicalAddress,
};
