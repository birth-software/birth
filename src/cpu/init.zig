const birth = @import("birth");
const bootloader = @import("bootloader");
const cpu = @import("cpu");
const lib = @import("lib");
const privileged = @import("privileged");

const assert = lib.assert;
const log = lib.log;
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualAddress = lib.VirtualAddress;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const RegionList = cpu.RegionList;
const PageTableRegions = cpu.arch.init.PageTableRegions;

const paging = privileged.arch.paging;
pub const Error = error{
    feature_requested_and_not_available,
    no_files,
    cpu_file_not_found,
    init_file_not_found,
    no_space_for_bootstrap_region,
};

pub fn initialize(bootloader_information: *bootloader.Information) !noreturn {
    // bootloader_information.draw_context.clearScreen(0xffff7f50);
    // Do an integrity check so that the bootloader information is in perfect state and there is no weird memory behavior.
    // This is mainly due to the transition from a 32-bit bootloader to a 64-bit CPU driver in the x86-64 architecture.
    try bootloader_information.checkIntegrity();
    // Informing the bootloader information struct that we have reached the CPU driver and any bootloader
    // functionality is not available anymore
    bootloader_information.stage = .cpu;
    // Check that the bootloader has loaded some files as the CPU driver needs them to go forward
    cpu.bundle = bootloader_information.getSlice(.bundle);
    if (cpu.bundle.len == 0) {
        return Error.no_files;
    }
    cpu.bundle_files = bootloader_information.getSlice(.file_list);
    if (cpu.bundle_files.len == 0) {
        return Error.no_files;
    }

    try cpu.arch.init.initialize();

    const memory_map_entries = bootloader_information.getMemoryMapEntries();
    const page_counters = bootloader_information.getPageCounters();

    const first_heap_allocation_size = 2 * lib.arch.valid_page_sizes[0];

    var heap_region_metadata: struct {
        region: PhysicalMemoryRegion,
        free_size: u64,
        index: usize,
    } = for (memory_map_entries, page_counters, 0..) |mmap_entry, page_counter, index| {
        if (mmap_entry.type == .usable) {
            const free_region = mmap_entry.getFreeRegion(page_counter);
            if (free_region.size >= first_heap_allocation_size) {
                break .{
                    .region = PhysicalMemoryRegion.new(.{
                        .address = free_region.address,
                        .size = free_region.size,
                    }),
                    .free_size = free_region.size - first_heap_allocation_size,
                    .index = index,
                };
            }
        }
    } else return error.no_space_for_bootstrap_region;

    const heap_region = try heap_region_metadata.region.takeSlice(first_heap_allocation_size);
    try cpu.heap.addBootstrapingRegion(heap_region.toHigherHalfVirtualAddress());

    const host_free_region_list = try cpu.heap.create(RegionList);

    var free_size: u64 = 0;
    _ = try host_free_region_list.append(heap_region_metadata.region);
    free_size += heap_region_metadata.region.size;

    var region_list_iterator = host_free_region_list;

    for (memory_map_entries, page_counters, 0..) |memory_map_entry, page_counter, index| {
        if (index == heap_region_metadata.index) continue;

        if (memory_map_entry.type == .usable) {
            const free_region = memory_map_entry.getFreeRegion(page_counter);

            if (free_region.size > 0) {
                assert(lib.isAligned(free_region.size, lib.arch.valid_page_sizes[0]));
                _ = region_list_iterator.append(free_region) catch {
                    const new_region_list = try cpu.heap.create(RegionList);
                    region_list_iterator.metadata.next = new_region_list;
                    new_region_list.metadata.previous = region_list_iterator;
                    region_list_iterator = new_region_list;
                    _ = try region_list_iterator.append(free_region);
                };

                free_size += free_region.size;
            }
        }
    }

    cpu.page_allocator.free_regions = host_free_region_list;
    cpu.page_allocator.free_byte_count = free_size;

    // Add used regions by the bootloader to the physical memory manager
    for (memory_map_entries, page_counters) |memory_map_entry, page_counter| {
        if (memory_map_entry.type == .usable) {
            const used_region = memory_map_entry.getUsedRegion(page_counter);
            if (used_region.size > 0) {
                assert(lib.isAligned(used_region.size, lib.arch.valid_page_sizes[0]));
                try cpu.page_allocator.appendUsedRegion(used_region, .{ .reason = .bootloader });
            }
        }
    }

    var used_regions = cpu.page_allocator.used_regions;
    var used_memory_by_bootloader: usize = 0;
    while (used_regions) |used_region| : (used_regions = used_region.next) {
        if (used_region.use_case.reason == .bootloader) {
            used_memory_by_bootloader += used_region.region.size;
        }
    }

    log.debug("Used memory by the bootloader: 0x{x} bytes", .{used_memory_by_bootloader});

    try cpu.page_allocator.appendUsedRegion(heap_region, .{ .reason = .heap });

    switch (cpu.bsp) {
        true => {
            // Setup kernel debug information
            cpu.debug_info = blk: {
                const cpu_driver_executable_descriptor = try bootloader_information.getFileDescriptor("cpu_driver");
                const elf_file = file: {
                    const aligned_file_len = lib.alignForward(usize, cpu_driver_executable_descriptor.content.len, lib.arch.valid_page_sizes[0]);
                    const elf_file_physical_allocation = try cpu.page_allocator.allocate(aligned_file_len, .{ .reason = .privileged });
                    break :file elf_file_physical_allocation.toHigherHalfVirtualAddress().address.access([*]align(lib.arch.valid_page_sizes[0]) u8)[0..elf_file_physical_allocation.size];
                };
                lib.memcpy(elf_file[0..cpu_driver_executable_descriptor.content.len], cpu_driver_executable_descriptor.content);
                const result = try lib.getDebugInformation(cpu.heap.allocator.zigUnwrap(), elf_file);
                break :blk result;
            };

            const init_module_descriptor = try bootloader_information.getFileDescriptor("init");

            try spawnInitBSP(init_module_descriptor.content, bootloader_information.cpu_page_tables);
        },
        false => @panic("TODO: implement APP"),
    }
}

const ELF = lib.ELF(64);

const SpawnInitCommonResult = extern struct {
    scheduler: *cpu.UserScheduler,
    entry_point: u64,
};

pub const MappingArgument = extern struct {
    virtual: VirtualAddress,
    physical: PhysicalAddress,
    size: u64,
};

pub const InitFile = struct {
    content: []const u8,
    segments: []const Segment,
};

pub const Segment = extern struct {
    virtual: VirtualAddress,
    physical: PhysicalAddress,
    memory_size: usize,
    flags: privileged.Mapping.Flags,
    file_offset: usize,
    file_size: usize,
};

var once: bool = false;

fn spawnInitCommon(init_file: []const u8, cpu_page_tables: paging.CPUPageTables) !SpawnInitCommonResult {
    assert(!once);
    once = true;
    // TODO: delete in the future
    assert(cpu.bsp);

    const init_elf = try ELF.Parser.init(init_file);
    const entry_point = init_elf.getEntryPoint();
    const program_headers = init_elf.getProgramHeaders();

    var segment_buffer: [20]Segment = undefined;
    var segment_count: usize = 0;
    var segment_total_size: usize = 0;
    var first_address: ?u64 = null;

    for (program_headers) |program_header| {
        if (program_header.type == .load) {
            if (first_address == null) {
                first_address = program_header.virtual_address;
            }

            const segment_size = lib.alignForward(usize, program_header.size_in_memory, lib.arch.valid_page_sizes[0]);
            segment_total_size += segment_size;

            const segment_virtual = VirtualAddress.new(program_header.virtual_address);
            const segment_physical_region = try cpu.page_allocator.allocate(segment_size, .{ .reason = .user });

            const segment = &segment_buffer[segment_count];
            segment.* = .{
                .physical = segment_physical_region.address,
                .virtual = segment_virtual,
                .memory_size = segment_size,
                .flags = .{
                    .execute = program_header.flags.executable,
                    .write = program_header.flags.writable,
                    .user = true,
                },
                .file_offset = program_header.offset,
                .file_size = program_header.size_in_file,
            };

            const src = init_file[segment.file_offset..][0..segment.file_size];
            // It's necessary to use the higher half address here since the user mapping is not applied yet
            const dst = segment_physical_region.toHigherHalfVirtualAddress().access(u8)[0..src.len];
            lib.memcpy(dst, src);

            segment_count += 1;
        }
    }

    const init_start_address = first_address orelse @panic("WTF");
    const init_top_address = init_start_address + segment_total_size;
    const user_scheduler_virtual_address = VirtualAddress.new(init_top_address);
    const user_scheduler_virtual_region = VirtualMemoryRegion.new(.{
        .address = user_scheduler_virtual_address,
        .size = lib.alignForward(usize, @sizeOf(birth.Scheduler), lib.arch.valid_page_sizes[0]),
    });
    // Align to 2MB
    const user_initial_heap_top = lib.alignForward(usize, user_scheduler_virtual_region.top().value(), lib.arch.valid_page_sizes[1]);

    const segments = segment_buffer[0..segment_count];

    const user_virtual_region = VirtualMemoryRegion.new(.{
        .address = VirtualAddress.new(init_start_address),
        .size = user_initial_heap_top - init_start_address,
    });
    // const page_table_regions = try PageTableRegions.create(user_virtual_region, cpu_page_tables);
    log.debug("Scheduler region", .{});
    const scheduler_physical_region = try cpu.page_allocator.allocate(user_scheduler_virtual_region.size, .{ .reason = .user });

    log.debug("Heap scheduler", .{});
    const init_cpu_scheduler = try cpu.heap.create(cpu.UserScheduler);
    init_cpu_scheduler.* = cpu.UserScheduler{
        .s = .{
            .common = user_scheduler_virtual_address.access(*birth.Scheduler.Common),
            .capability_root_node = cpu.interface.Root{
                .static = .{
                    .cpu = true,
                    .boot = true,
                    .process = true,
                },
                .dynamic = .{
                    .io = .{
                        .debug = true,
                    },
                    .memory = .{},
                    .cpu_memory = .{
                        .flags = .{
                            .allocate = true,
                        },
                    },
                    .page_table = cpu.interface.PageTables{
                        .privileged = undefined,
                        .user = birth.interface.PageTable{
                            .index = 0,
                            .entry_type = .page_table,
                        },
                        // .vmm = try cpu.interface.VMM.new(),
                        .can_map_page_tables = true,
                        .page_tables = .{
                            .ptr = undefined,
                            .len = 0,
                            .capacity = 0,
                        },
                        .leaves = .{
                            .ptr = undefined,
                            .len = 0,
                            .capacity = 0,
                        },
                    },
                    .command_buffer_submission = .{ .region = PhysicalMemoryRegion.invalid() },
                    .command_buffer_completion = .{ .region = PhysicalMemoryRegion.invalid() },
                    .memory_mapping = .{},
                    .page_table_mapping = .{},
                },
                .scheduler = .{
                    .memory = scheduler_physical_region,
                },
            },
        },
    };

    const scheduler_virtual_region = VirtualMemoryRegion.new(.{
        .address = user_scheduler_virtual_address,
        .size = scheduler_physical_region.size,
    });

    scheduler_physical_region.address.toHigherHalfVirtualAddress().access(*birth.Scheduler.Common).self = user_scheduler_virtual_address.access(*birth.Scheduler.Common);

    const heap_virtual_region = VirtualMemoryRegion.new(.{
        .address = scheduler_virtual_region.top(),
        .size = lib.alignForward(usize, scheduler_virtual_region.top().value(), lib.arch.valid_page_sizes[1]) - scheduler_virtual_region.top().value(),
    });

    log.debug("Heap region", .{});
    const heap_physical_region = try cpu.page_allocator.allocate(heap_virtual_region.size, .{ .reason = .user });
    @memset(heap_physical_region.toHigherHalfVirtualAddress().access(u8), 0);

    assert(scheduler_physical_region.size == scheduler_virtual_region.size);
    assert(heap_physical_region.size == heap_virtual_region.size);
    // Setup common variables
    const higher_half_scheduler_common = scheduler_physical_region.address.toHigherHalfVirtualAddress().access(*birth.Scheduler.Common);
    higher_half_scheduler_common.disabled = true;
    higher_half_scheduler_common.core_id = cpu.core_id;
    higher_half_scheduler_common.heap = VirtualMemoryRegion.new(.{
        .address = heap_virtual_region.address,
        .size = heap_virtual_region.size,
    });

    try cpu.arch.init.setupMapping(init_cpu_scheduler, user_virtual_region, cpu_page_tables, .{
        .content = init_file,
        .segments = segments,
    }, .{
        .scheduler = .{
            .physical = scheduler_physical_region.address,
            .virtual = scheduler_virtual_region.address,
            .size = scheduler_virtual_region.size,
        },
        .heap = .{
            .physical = heap_physical_region.address,
            .virtual = heap_virtual_region.address,
            .size = heap_virtual_region.size,
        },
    });

    return SpawnInitCommonResult{
        // .page_table_regions = page_table_regions,
        .scheduler = init_cpu_scheduler,
        .entry_point = entry_point,
    };
}

fn spawnInitBSP(init_file: []const u8, cpu_page_tables: paging.CPUPageTables) !noreturn {
    const spawn_init = try spawnInitCommon(init_file, cpu_page_tables);
    const init_scheduler = spawn_init.scheduler;
    // const page_table_regions = spawn_init.page_table_regions;
    const entry_point = spawn_init.entry_point;
    const scheduler_common = init_scheduler.s.common;

    cpu.user_scheduler = init_scheduler;

    cpu.arch.init.setupSchedulerCommon(scheduler_common, entry_point);
    scheduler_common.disabled_save_area.contextSwitch();
}
