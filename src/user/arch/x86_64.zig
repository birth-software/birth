const lib = @import("lib");
const log = lib.log;
const assert = lib.assert;
const birth = @import("birth");
const user = @import("user");

const FPU = birth.arch.FPU;
const Registers = birth.arch.Registers;
const RegisterArena = birth.arch.RegisterArena;

const VirtualAddress = lib.VirtualAddress;

const PhysicalMemoryRegion = user.PhysicalMemoryRegion;
const PhysicalMap = user.PhysicalMap;
const SlotAllocator = user.SlotAllocator;
const Thread = user.Thread;
const VirtualAddressSpace = user.VirtualAddressSpace;

// CRT0
pub fn _start() callconv(.Naked) noreturn {
    asm volatile (
        \\push %rbp
        \\jmp *%[startFunction]
        :
        : [startFunction] "r" (user.start),
    );
}

pub inline fn setInitialState(register_arena: *RegisterArena, entry: VirtualAddress, stack_virtual_address: VirtualAddress, arguments: birth.syscall.Arguments) void {
    assert(stack_virtual_address.value() > lib.arch.valid_page_sizes[0]);
    assert(lib.isAligned(stack_virtual_address.value(), lib.arch.stack_alignment));
    var stack_address = stack_virtual_address;
    // x86_64 ABI
    stack_address.subOffset(@sizeOf(usize));

    register_arena.registers.rip = entry.value();
    register_arena.registers.rsp = stack_address.value();
    register_arena.registers.rflags = .{ .IF = true };
    register_arena.registers.rdi = arguments[0];
    register_arena.registers.rsi = arguments[1];
    register_arena.registers.rdx = arguments[2];
    register_arena.registers.rcx = arguments[3];
    register_arena.registers.r8 = arguments[4];
    register_arena.registers.r9 = arguments[5];

    register_arena.fpu = lib.zeroes(FPU);
    // register_arena.fpu.fcw = 0x037f;
    register_arena.fpu.fcw = 0x1f80;
}

pub inline fn maybeCurrentScheduler() ?*user.Scheduler {
    return asm volatile (
        \\mov %fs:0, %[user_scheduler]
        : [user_scheduler] "=r" (-> ?*user.Scheduler),
        :
        : "memory"
    );
}
