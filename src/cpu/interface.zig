const lib = @import("lib");
const assert = lib.assert;
const Allocator = lib.Allocator;
const enumCount = lib.enumCount;
const log = lib.log.scoped(.capabilities);
const SparseArray = lib.data_structures.SparseArray;
const VirtualAddress = lib.VirtualAddress;

const privileged = @import("privileged");
const paging = privileged.arch.paging;
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;
const birth = @import("birth");
const cpu = @import("cpu");
const RegionList = cpu.RegionList;

pub var system_call_count: usize = 0;

pub fn processFromRaw(options: birth.interface.Raw.Options, arguments: birth.interface.Raw.Arguments) birth.interface.Raw.Result {
    defer system_call_count += 1;
    return switch (options.general.convention) {
        .birth => switch (options.birth.type) {
            inline else => |capability| switch (@as(birth.interface.Command.fromCapability(capability), @enumFromInt(options.birth.command))) {
                inline else => |command| blk: {
                    const Interface = birth.interface.Descriptor(capability, command);
                    const result = processCommand(Interface, arguments) catch |err| {
                        lib.log.err("Syscall ({s}, {s}) ended up in error: {}", .{ @tagName(capability), @tagName(command), err });
                        break :blk Interface.fromError(err);
                    };
                    break :blk Interface.fromResult(result);
                },
            },
        },
        .emulated => @panic("TODO: emulated"),
    };
}

pub fn processCommand(comptime Descriptor: type, raw_arguments: birth.interface.Raw.Arguments) Descriptor.Error!Descriptor.Result {
    defer cpu.command_count += 1;
    const capability = Descriptor.Capability;
    const command = Descriptor.Command;
    const arguments = try Descriptor.toArguments(raw_arguments);

    const root = &cpu.user_scheduler.s.capability_root_node;
    // log.err("\n========\nSyscall received: {s}, {s}\n========\n", .{ @tagName(capability), @tagName(command) });

    assert(root.static.process);
    const has_permissions = root.hasPermissions(Descriptor, arguments);

    return if (has_permissions) switch (capability) {
        .io => switch (command) {
            .copy, .mint, .retype, .delete, .revoke, .create => unreachable,
            .log => blk: {
                const message = arguments;
                cpu.writer.writeAll(message) catch unreachable;
                comptime assert(Descriptor.Result == usize);
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
            else => @panic(@tagName(command)),
        },
        .command_buffer_completion, .command_buffer_submission => switch (command) {
            .map => {
                const region = @field(root.dynamic, @tagName(capability)).region;
                assert(region.address.value() != 0);
                assert(region.size != 0);
                @panic("TODO: map");
            }, // TODO
            else => @panic(@tagName(command)),
        },
        .memory => switch (command) {
            .allocate => blk: {
                comptime assert(@TypeOf(arguments) == usize);
                const size = arguments;
                // TODO: we want more fine-grained control of the reason if we want more than a simple statistic
                const result = try root.allocateMemory(size);
                break :blk result.reference;
            },
            .retype => blk: {
                const source = arguments.source;
                const destination = arguments.destination;
                const region_ptr = root.dynamic.memory.find(source) orelse unreachable;
                const region_copy = region_ptr.*;
                root.dynamic.memory.remove(source);
                switch (destination) {
                    .cpu_memory => {
                        // TODO: delete properly
                        const new_ref = root.dynamic.cpu_memory.allocated.append(region_copy) catch |err| {
                            log.err("Error: {}", .{err});
                            return error.OutOfMemory;
                        };
                        // TODO: delete properly

                        break :blk @bitCast(new_ref);
                    },
                    .command_buffer_submission, .command_buffer_completion => {
                        switch (destination) {
                            inline .command_buffer_completion, .command_buffer_submission => |dst| @field(root.dynamic, @tagName(dst)).region = region_copy,
                            else => @panic("WTF"),
                        }
                        // TODO: better value
                        break :blk .{ .integer = 0 };
                    },
                    else => @panic("WTF"),
                }
                if (true) @panic("TODO: retype");
                break :blk undefined;
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
            .panic => cpu.panic("User process panicked with exit code 0x{x}:\n==========\n{s}\n==========", .{ arguments.exit_code, arguments.message }),
            else => @panic(@tagName(command)),
        },
        .page_table => switch (command) {
            .get => {
                const descriptor = arguments.descriptor;
                assert(descriptor.entry_type == .page_table);

                const block = try root.dynamic.page_table.page_tables.getChecked(descriptor.block);
                const page_table = &block.array[descriptor.index];
                log.debug("Page table: {}", .{page_table.flags.level});
                @memcpy(arguments.buffer, &page_table.children);
            },
            .get_leaf => {
                const descriptor = arguments.descriptor;
                assert(descriptor.entry_type == .leaf);

                const block = try root.dynamic.page_table.leaves.getChecked(descriptor.block);
                const leaf = &block.array[descriptor.index];

                const user_leaf = arguments.buffer;
                user_leaf.* = leaf.common;
            },
            else => @panic("TODO: page_table other"),
        },
        .memory_mapping => {
            @panic("TODO: memory_mapping");
        },
        .page_table_mapping => {
            @panic("TODO: page_table_mapping");
        },
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
                .backing_integer = @Type(.{
                    .Int = .{
                        .signedness = .unsigned,
                        .bits = full_bit_size,
                    },
                }),
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

                    const padding_type = @Type(.{
                        .Int = .{
                            .signedness = .unsigned,
                            .bits = full_bit_size - Static.count,
                        },
                    });

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

pub const CommandBufferMemory = extern struct {
    region: PhysicalMemoryRegion,
};

pub const Dynamic = enum {
    io,
    memory, // Barrelfish equivalent: Memory (no PhysAddr)
    cpu_memory, // Barrelfish equivalent: Frame
    page_table, // Barrelfish equivalent: VNode
    command_buffer_submission,
    command_buffer_completion,
    memory_mapping, // Barrelfish equivalent: Frame mapping, Device Frame Mapping
    page_table_mapping, // Barrelfish equivalent: VNode mapping
    // irq_table,
    // device_memory,
    // scheduler,

    pub const Map = extern struct {
        io: IO,
        memory: Memory,
        cpu_memory: CPUMemory,
        page_table: PageTables,
        command_buffer_submission: CommandBufferMemory,
        command_buffer_completion: CommandBufferMemory,
        memory_mapping: Memory.Mapping,
        page_table_mapping: PageTables.Mapping,

        comptime {
            inline for (lib.fields(Dynamic.Map), lib.fields(Dynamic)) |struct_field, enum_field| {
                assert(lib.equal(u8, enum_field.name, struct_field.name));
            }
        }
    };
};

pub const Memory = extern struct {
    allocated: RegionList = .{},
    allocate: bool = true,

    pub const Mapping = extern struct {
        foo: u32 = 0,
    };

    const AllocateError = error{
        OutOfMemory,
    };

    fn find(memory: *Memory, memory_descriptor: birth.interface.Memory) ?*PhysicalMemoryRegion {
        var iterator: ?*RegionList = &memory.allocated;
        var block_index: usize = 0;

        return blk: while (iterator) |list| : ({
            iterator = list.metadata.next;
            block_index += 1;
        }) {
            if (block_index == memory_descriptor.block) {
                @panic("TODO: find");
                // if (memory_descriptor.region < list.metadata.count) {
                //     const region = &list.regions[memory_descriptor.region];
                //     if (region.size != 0 and region.address.value() != 0) {
                //         assert(lib.isAligned(region.size, lib.arch.valid_page_sizes[0]));
                //         assert(lib.isAligned(region.address.value(), lib.arch.valid_page_sizes[0]));
                //         break :blk region;
                //     }
                // }
                //
                // break :blk null;
            } else if (block_index > memory_descriptor.block) {
                break :blk null;
            } else {
                continue;
            }
        } else break :blk null;
    }

    inline fn getListIndex(size: usize) usize {
        inline for (lib.arch.reverse_valid_page_sizes, 0..) |reverse_page_size, reverse_index| {
            if (size >= reverse_page_size) return reverse_index;
        }

        @panic("WTF");
    }

    pub fn appendRegion(memory: *Memory, region: PhysicalMemoryRegion) !birth.interface.Memory {
        var iterator: ?*RegionList = &memory.allocated;
        while (iterator) |region_list| : (iterator = region_list.metadata.next) {
            const result = region_list.append(region) catch continue;
            return result;
        }

        return error.OutOfMemory;
    }

    pub fn remove(memory: *Memory, ref: birth.interface.Memory) void {
        const region_index: u6 = @intCast(ref.region);
        var block_index: u32 = 0;
        var iterator: ?*RegionList = &memory.allocated;
        while (iterator) |region_list| : ({
            iterator = region_list.metadata.next;
            block_index += 1;
        }) {
            if (block_index == ref.block) {
                region_list.remove(region_index);
                break;
            } else if (block_index > ref.block) {
                @panic("WTF");
            } else continue;
        } else {
            @panic("WTF");
        }
    }
};

pub const CPUMemory = extern struct {
    allocated: RegionList = .{},
    flags: Flags = .{},

    const Flags = packed struct(u64) {
        allocate: bool = true,
        reserved: u63 = 0,
    };
};

pub const PageTable = extern struct {
    region: PhysicalMemoryRegion,
    mapping: VirtualAddress,
    flags: Flags,
    children: Children = .{.{}} ** children_count,

    pub const Children = [children_count]birth.interface.PageTable;
    pub const children_count = paging.page_table_entry_count;

    pub const Flags = packed struct(u64) {
        level: paging.Level,
        reserved: u62 = 0,
    };

    pub const Array = extern struct {
        array: [count]PageTable,
        bitset: Bitset,
        next: ?*Array = null,

        pub const Bitset = lib.data_structures.BitsetU64(count);

        pub const count = 32;

        pub fn get(array: *Array, index: u6) !*PageTable {
            if (array.bitset.isSet(index)) {
                return &array.array[index];
            } else {
                return error.index_out_of_bounds;
            }
        }
    };
};

pub const Leaf = extern struct {
    common: birth.interface.Leaf,
    physical: PhysicalAddress,
    flags: Flags,

    pub const Flags = packed struct(u64) {
        size: Size,
        reserved: u62 = 0,
    };

    pub const Size = enum(u2) {
        @"4KB",
        @"2MB",
        @"1GB",
    };

    pub const Array = extern struct {
        array: [count]Leaf,
        bitset: Bitset,
        next: ?*Array = null,
        pub const Bitset = lib.data_structures.BitsetU64(count);
        pub const count = 32;
        pub fn get(array: *Array, index: u6) !*PageTable {
            if (array.bitset.isSet(index)) {
                return &array.array[index];
            } else {
                return error.index_out_of_bounds;
            }
        }
    };
};

pub const PageTables = extern struct {
    // This one has the kernel mapped
    privileged: PageTable, // This one is separate as cannot be mapped
    user: birth.interface.PageTable,
    page_tables: SparseArray(*PageTable.Array),
    leaves: SparseArray(*Leaf.Array),
    // vmm: VMM,
    can_map_page_tables: bool,

    pub const Mapping = extern struct {
        foo: u32 = 0,
    };

    const end = privileged.arch.paging.user_address_space_end;

    fn getUser(page_tables: *const PageTables) ?PhysicalMemoryRegion {
        if (page_tables.user.address.value() == 0) {
            return null;
        }

        if (page_tables.user.size == 0) {
            return null;
        }

        return page_tables.user;
    }

    pub fn switchPrivileged(page_tables: *const PageTables) void {
        paging.Specific.fromPhysicalRegion(page_tables.privileged.region).makeCurrentPrivileged();
    }

    pub fn appendPageTable(page_tables: *PageTables, allocator: *Allocator, page_table: PageTable) !birth.interface.PageTable {
        if (page_tables.page_tables.len > 0) {
            const slice = page_tables.page_tables.ptr[0..page_tables.page_tables.len];
            for (slice, 0..) |block, block_index| {
                const index = block.bitset.allocate() catch continue;
                block.array[index] = page_table;
                return .{
                    .index = index,
                    .block = @intCast(block_index),
                    .entry_type = .page_table,
                    .present = true,
                };
            }
        }

        const page_table_array = try allocator.create(PageTable.Array);
        _ = try page_tables.page_tables.append(allocator, page_table_array);
        return appendPageTable(page_tables, allocator, page_table);
    }

    pub fn appendLeaf(page_tables: *PageTables, allocator: *Allocator, leaf: Leaf) !birth.interface.PageTable {
        if (page_tables.leaves.len > 0) {
            const slice = page_tables.leaves.ptr[0..page_tables.leaves.len];
            for (slice, 0..) |block, block_index| {
                const index = block.bitset.allocate() catch continue;
                block.array[index] = leaf;

                return .{
                    .index = index,
                    .block = @intCast(block_index),
                    .entry_type = .leaf,
                    .present = true,
                };
            }
        }

        const leaf_array = try allocator.create(Leaf.Array);
        _ = try page_tables.leaves.append(allocator, leaf_array);
        return appendLeaf(page_tables, allocator, leaf);
    }

    pub fn getPageTable(page_tables: *PageTables, page_table: birth.interface.PageTable) !*PageTable {
        assert(page_table.entry_type == .page_table);
        if (page_table.present) {
            const page_table_block = try page_tables.page_tables.getChecked(page_table.block);
            const result = try page_table_block.get(@intCast(page_table.index));
            return result;
        } else {
            return error.not_present;
        }
    }
};

pub const IO = extern struct {
    debug: bool,
};

pub const Scheduler = extern struct {
    memory: PhysicalMemoryRegion,
};

comptime {
    const dynamic_count = enumCount(Dynamic);
    const static_count = enumCount(Static);
    const total_count = enumCount(birth.interface.Capability);
    assert(dynamic_count + static_count == total_count);
}

pub const Root = extern struct {
    static: Static.Bitmap,
    dynamic: Dynamic.Map,
    scheduler: Scheduler,
    heap: Heap = .{},
    padding: [padding_byte_count]u8 = .{0} ** padding_byte_count,

    const Heap = cpu.HeapImplementation(true);

    const max_alignment = @max(@alignOf(Static.Bitmap), @alignOf(Dynamic.Map), @alignOf(Scheduler), @alignOf(Heap));
    const total_size = lib.alignForward(usize, @sizeOf(Static.Bitmap) + @sizeOf(Dynamic.Map) + @sizeOf(Scheduler) + @sizeOf(Heap), max_alignment);
    const page_aligned_size = lib.alignForward(usize, total_size, lib.arch.valid_page_sizes[0]);
    const padding_byte_count = page_aligned_size - total_size;

    comptime {
        assert(@sizeOf(Root) % lib.arch.valid_page_sizes[0] == 0);
    }

    pub const AllocateError = error{
        OutOfMemory,
    };

    fn hasPermissions(root: *Root, comptime Descriptor: type, arguments: Descriptor.Arguments) bool {
        const capability = Descriptor.Capability;
        const command = Descriptor.Command;

        if (command == .retype) {
            const can_retype: bool = switch (@TypeOf(arguments)) {
                void => @panic("Retype on void"),
                else => switch (arguments.destination) {
                    inline else => |destination| blk: {
                        const child_types = comptime capability.getChildTypes();
                        inline for (child_types) |child_type| {
                            if (child_type == destination) {
                                break :blk true;
                            }
                        } else {
                            break :blk false;
                        }
                    },
                },
            };

            if (!can_retype) {
                return false;
            }
        }

        const has_permissions = switch (capability) {
            // static capabilities
            inline .cpu,
            .boot,
            => |static_capability| @field(root.static, @tagName(static_capability)),
            .process => root.static.process or command == .panic,
            // dynamic capabilities
            .io => switch (command) {
                .copy, .mint, .retype, .delete, .revoke, .create => unreachable,
                .log => root.dynamic.io.debug,
            },
            .cpu_memory => root.dynamic.cpu_memory.flags.allocate,
            .command_buffer_completion, .command_buffer_submission => true, //TODO
            .memory => switch (command) {
                .allocate => root.dynamic.memory.allocate,
                .retype => root.dynamic.memory.find(arguments.source) != null,
                else => @panic("TODO: else => memory"),
            },
            .page_table => root.dynamic.page_table.can_map_page_tables, // TODO
            .memory_mapping => true, // TODO
            .page_table_mapping => true, // TODO
        };

        return has_permissions;
    }

    pub const AllocateMemoryResult = extern struct {
        region: PhysicalMemoryRegion,
        reference: birth.interface.Memory,
    };

    pub fn allocateMemory(root: *Root, size: usize) !AllocateMemoryResult {
        const physical_region = try cpu.page_allocator.allocate(size, .{ .reason = .user });
        const reference = try root.dynamic.memory.appendRegion(physical_region);

        return .{
            .region = physical_region,
            .reference = reference,
        };
    }
};
