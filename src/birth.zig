const lib = @import("lib");
const assert = lib.assert;

pub const arch = @import("birth/arch.zig");
pub const interface = @import("birth/interface.zig");

/// This struct is the shared part that the user and the cpu see
pub const Scheduler = extern struct {
    common: Common,
    current_thread: *Thread,
    thread_queue: ?*Thread = null,
    time_slice: u32,
    core_id: u32,
    core_state: CoreState,
    bootstrap_thread: Thread,

    pub const Common = extern struct {
        self: *Common,
        disabled: bool,
        has_work: bool,
        core_id: u32,
        heap: lib.VirtualMemoryRegion,
        setup_stack: [lib.arch.valid_page_sizes[0] * 4]u8 align(lib.arch.stack_alignment),
        setup_stack_lock: lib.Atomic(bool),
        disabled_save_area: arch.RegisterArena,

        pub fn heapAllocateFast(common: *Common, comptime T: type) !*T {
            const size = @sizeOf(T);
            const alignment = @alignOf(T);
            lib.log.debug("Heap: {}. Size: {}. Alignment: {}", .{ common.heap, size, alignment });
            const result = try common.heap.takeSlice(size);
            const ptr = &result.access(T)[0];
            assert(lib.isAligned(@intFromPtr(ptr), alignment));

            return ptr;
        }
    };

    pub fn enqueueThread(scheduler: *Scheduler, thread_to_queue: *Thread) void {
        // TODO: check queue
        // TODO: defer check queue
        if (scheduler.thread_queue) |thread_queue| {
            _ = thread_queue;
            @panic("TODO: enqueueThread");
        } else {
            scheduler.thread_queue = thread_to_queue;
            thread_to_queue.previous = thread_to_queue;
            thread_to_queue.next = thread_to_queue;
        }
    }

    pub noinline fn restore(scheduler: *Scheduler, register_arena: *const arch.RegisterArena) noreturn {
        assert(scheduler.common.generic.disabled);
        assert(scheduler.common.generic.has_work);

        assert(register_arena.registers.rip > lib.arch.valid_page_sizes[0]);
        assert(register_arena.registers.rflags.IF and register_arena.registers.rflags.reserved0);

        register_arena.contextSwitch();
    }
};

pub const Thread = extern struct {
    self: *Thread,
    previous: ?*Thread = null,
    next: ?*Thread = null,
    stack: [*]u8,
    stack_top: [*]align(lib.arch.stack_alignment) u8,
    register_arena: arch.RegisterArena align(arch.RegisterArena.alignment),
    core_id: u32,

    pub fn init(thread: *Thread, scheduler: *Scheduler) void {
        thread.* = Thread{
            .self = thread,
            .core_id = scheduler.generic.core_id,
            .stack = thread.stack,
            .stack_top = thread.stack_top,
            .register_arena = thread.register_arena,
        };
    }
};

pub const CoreState = extern struct {
    virtual_address_space: *VirtualAddressSpace,
};
pub const VirtualAddressSpace = extern struct {
    // TODO: physical map
    // TODO: layout
    regions: ?*VirtualMemoryRegion = null,
};

pub const VirtualMemoryRegion = extern struct {
    next: ?*VirtualMemoryRegion = null,
};
