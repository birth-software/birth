const bootloader = @import("bootloader");
const cpu = @import("cpu");
const lib = @import("lib");
const privileged = @import("privileged");
const birth = @import("birth");

const Allocator = lib.Allocator;
const assert = lib.assert;
const ELF = lib.ELF(64);
const log = lib.log.scoped(.INIT);
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualAddress = lib.VirtualAddress;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const Leaf = cpu.interface.Leaf;
const PageTable = cpu.interface.PageTable;
const panic = cpu.panic;
const RegionList = cpu.RegionList;
const x86_64 = cpu.arch.current;

const paging = privileged.arch.paging;

const APIC = privileged.arch.x86_64.APIC;
const cr0 = privileged.arch.x86_64.registers.cr0;
const cr3 = privileged.arch.x86_64.registers.cr3;
const cr4 = privileged.arch.x86_64.registers.cr4;
const XCR0 = privileged.arch.x86_64.registers.XCR0;
const IA32_APIC_BASE = privileged.arch.x86_64.registers.IA32_APIC_BASE;
const IA32_EFER = privileged.arch.x86_64.registers.IA32_EFER;
const IA32_FS_BASE = privileged.arch.x86_64.registers.IA32_FS_BASE;
const IA32_FSTAR = privileged.arch.x86_64.registers.IA32_FSTAR;
const IA32_FMASK = privileged.arch.x86_64.registers.IA32_FMASK;
const IA32_LSTAR = privileged.arch.x86_64.registers.IA32_LSTAR;
const IA32_STAR = privileged.arch.x86_64.registers.IA32_STAR;

pub fn entryPoint() callconv(.Naked) noreturn {
    asm volatile (
        \\lea stack(%rip), %rsp
        \\add %[stack_len], %rsp
        \\pushq $0
        \\mov %rsp, %rbp
        \\jmp *%[main]
        :
        : [stack_len] "i" (cpu.stack.len),
          [main] "{rax}" (&main),
        : "rsp", "rbp"
    );
}

noinline fn main(bootloader_information: *bootloader.Information) callconv(.C) noreturn {
    log.info("Initializing...\n\n\t[BUILD MODE] {s}\n\t[BOOTLOADER] {s}\n\t[BOOT PROTOCOL] {s}\n", .{ @tagName(lib.build_mode), @tagName(bootloader_information.bootloader), @tagName(bootloader_information.protocol) });
    cpu.init.initialize(bootloader_information) catch |err| {
        cpu.panicWithStackTrace(@errorReturnTrace(), "Failed to initialize CPU: {}", .{err});
    };
}

pub inline fn initialize() !void {
    const cpuid = lib.arch.x86_64.cpuid;
    if (x86_64.pcid) {
        if (cpuid(1).ecx & (1 << 17) == 0) return error.feature_requested_and_not_available;
    }

    if (x86_64.invariant_tsc) {
        if (cpuid(0x80000007).edx & (1 << 8) == 0) return error.feature_requested_and_not_available;
    }

    // Initialize GDT
    const gdt_descriptor = x86_64.GDT.Descriptor{
        .limit = @sizeOf(x86_64.GDT) - 1,
        .address = @intFromPtr(&gdt),
    };

    asm volatile (
        \\lgdt %[gdt]
        \\mov %[ds], %rax
        \\movq %rax, %ds
        \\movq %rax, %es
        \\movq %rax, %fs
        \\movq %rax, %gs
        \\movq %rax, %ss
        \\pushq %[cs]
        \\lea 1f(%rip), %rax
        \\pushq %rax
        \\lretq
        \\1:
        :
        : [gdt] "*p" (&gdt_descriptor),
          [ds] "i" (x86_64.data_64),
          [cs] "i" (x86_64.code_64),
        : "memory"
    );

    const tss_address = @intFromPtr(&tss);
    gdt.tss_descriptor = .{
        .limit_low = @as(u16, @truncate(@sizeOf(x86_64.TSS))),
        .base_low = @as(u16, @truncate(tss_address)),
        .base_mid_low = @as(u8, @truncate(tss_address >> 16)),
        .access = .{
            .type = .tss_available,
            .dpl = 0,
            .present = true,
        },
        .attributes = .{
            .limit = @as(u4, @truncate(@sizeOf(x86_64.TSS) >> 16)),
            .available_for_system_software = false,
            .granularity = false,
        },
        .base_mid_high = @as(u8, @truncate(tss_address >> 24)),
        .base_high = @as(u32, @truncate(tss_address >> 32)),
    };

    tss.rsp[0] = @intFromPtr(&interrupt_stack) + interrupt_stack.len;
    asm volatile (
        \\ltr %[tss_selector]
        :
        : [tss_selector] "r" (@as(u16, x86_64.tss_selector)),
        : "memory"
    );

    // Initialize IDT

    for (&idt.descriptors, interrupt_handlers, 0..) |*descriptor, interrupt_handler, i| {
        const interrupt_address = @intFromPtr(interrupt_handler);
        descriptor.* = .{
            .offset_low = @as(u16, @truncate(interrupt_address)),
            .segment_selector = x86_64.code_64,
            .flags = .{
                .ist = 0,
                .type = if (i < 32) .trap_gate else .interrupt_gate, // TODO: I think this is not correct
                .dpl = 0,
                .present = true,
            },
            .offset_mid = @as(u16, @truncate(interrupt_address >> 16)),
            .offset_high = @as(u32, @truncate(interrupt_address >> 32)),
        };
    }

    const idt_descriptor = x86_64.IDT.Descriptor{
        .limit = @sizeOf(x86_64.IDT) - 1,
        .address = @intFromPtr(&idt),
    };

    asm volatile (
        \\lidt %[idt_descriptor]
        :
        : [idt_descriptor] "*p" (&idt_descriptor),
        : "memory"
    );

    // Mask PIC
    privileged.arch.io.write(u8, 0xa1, 0xff);
    privileged.arch.io.write(u8, 0x21, 0xff);

    asm volatile ("sti" ::: "memory");

    const star = IA32_STAR{
        .kernel_cs = x86_64.code_64,
        .user_cs_anchor = x86_64.data_64,
    };

    comptime {
        assert(x86_64.data_64 == star.kernel_cs + 8);
        assert(star.user_cs_anchor == x86_64.user_data_64 - 8);
        assert(star.user_cs_anchor == x86_64.user_code_64 - 16);
    }

    star.write();

    IA32_LSTAR.write(@intFromPtr(&cpu.arch.x86_64.syscall.entryPoint));
    const syscall_mask = privileged.arch.x86_64.registers.syscall_mask;
    IA32_FMASK.write(syscall_mask);

    // Enable syscall extensions
    var efer = IA32_EFER.read();
    efer.SCE = true;
    efer.write();

    const avx_xsave_cpuid = cpuid(1, 0);
    const xsave_support = avx_xsave_cpuid.ecx & (1 << 26) != 0;

    // TODO: AVX
    var my_cr4 = cr4.read();
    my_cr4.OSFXSR = true;
    my_cr4.OSXMMEXCPT = true;
    if (xsave_support) {
        // my_cr4.OSXSAVE = true;
    }
    my_cr4.page_global_enable = true;
    my_cr4.performance_monitoring_counter_enable = true;
    my_cr4.write();

    var my_cr0 = cr0.read();
    my_cr0.monitor_coprocessor = true;
    my_cr0.emulation = false;
    my_cr0.numeric_error = true;
    my_cr0.task_switched = false;
    my_cr0.write();

    const avx_support = avx_xsave_cpuid.ecx & (1 << 28) != 0;
    // const avx2_support = cpuid(7).ebx & (1 << 5) != 0;
    log.debug("AVX: {}. AVX2: {}. XSAVE: {}. Can't enable them yet", .{ avx_support, false, xsave_support });

    comptime {
        assert(lib.arch.valid_page_sizes[0] == 0x1000);
    }

    // The bootloader already mapped APIC, so it's not necessary to map it here
    var ia32_apic_base = IA32_APIC_BASE.read();
    cpu.bsp = ia32_apic_base.bsp;
    ia32_apic_base.global_enable = true;

    const spurious_vector: u8 = 0xFF;
    APIC.write(.spurious, @as(u32, 0x100) | spurious_vector);

    const tpr = APIC.TaskPriorityRegister{};
    tpr.write();

    const lvt_timer = APIC.LVTTimer{};
    lvt_timer.write();

    ia32_apic_base.write();

    x86_64.ticks_per_ms = APIC.calibrateTimer();

    cpu.core_id = APIC.read(.id);

    asm volatile (
        \\fninit
        // TODO: figure out why this crashes with KVM
        //\\ldmxcsr %[mxcsr]
        :: //[mxcsr] "m" (@as(u32, 0x1f80)),
        : "memory");

    // TODO: configure PAT
}
// TODO:
// Write user TLS base address

export var interrupt_stack: [0x1000]u8 align(lib.arch.stack_alignment) = undefined;
export var gdt = x86_64.GDT{};
export var tss = x86_64.TSS{};
export var idt = x86_64.IDT{};
export var user_stack: u64 = 0;

comptime {
    assert(birth.arch.user_code_selector == x86_64.user_code_selector);
    assert(birth.arch.user_data_selector == x86_64.user_data_selector);
}

pub fn InterruptHandler(comptime interrupt_number: u64, comptime has_error_code: bool) fn () callconv(.Naked) noreturn {
    return struct {
        fn handler() callconv(.Naked) noreturn {
            asm volatile (
                \\endbr64
                ::: "memory");

            if (x86_64.smap) {
                // TODO: Investigate why this is Exception #6
                asm volatile (
                    \\clac
                    ::: "memory");
            }

            asm volatile (
                \\cld
                ::: "memory");
            if (!has_error_code) {
                asm volatile ("pushq $0" ::: "memory");
            }

            asm volatile (
                \\push %rdi
                \\push %rsi
                \\push %rdx
                \\push %rcx
                \\push %rax
                \\push %r8
                \\push %r9
                \\push %r10
                \\push %r11
                \\push %rbx
                \\push %rbp
                \\push %r12
                \\push %r13
                \\push %r14
                \\push %r15
                \\mov %rsp, %rdi
                \\mov %[interrupt_number], %rsi
                \\call interruptHandler
                \\pop %r15
                \\pop %r14
                \\pop %r13
                \\pop %r12
                \\pop %rbp
                \\pop %rbx
                \\pop %r11
                \\pop %r10
                \\pop %r9
                \\pop %r8
                \\pop %rax
                \\pop %rcx
                \\pop %rdx
                \\pop %rsi
                \\pop %rdi
                :
                : [interrupt_number] "i" (interrupt_number),
                : "memory"
            );

            if (!has_error_code) {
                asm volatile (
                    \\add $0x8, %rsp
                    ::: "memory");
            }

            asm volatile (
                \\iretq
                \\int3
                ::: "memory");
        }
    }.handler;
}

const Interrupt = enum(u5) {
    DE = 0x00,
    DB = 0x01,
    NMI = 0x02,
    BP = 0x03,
    OF = 0x04,
    BR = 0x05,
    UD = 0x06,
    NM = 0x07,
    DF = 0x08,
    CSO = 0x09, // Not used anymore
    TS = 0x0A,
    NP = 0x0B,
    SS = 0x0C,
    GP = 0x0D,
    PF = 0x0E,
    MF = 0x10,
    AC = 0x11,
    MC = 0x12,
    XM = 0x13,
    VE = 0x14,
    CP = 0x15,
    _,
};

const interrupt_handlers = [256]*const fn () callconv(.Naked) noreturn{
    InterruptHandler(@intFromEnum(Interrupt.DE), false),
    InterruptHandler(@intFromEnum(Interrupt.DB), false),
    InterruptHandler(@intFromEnum(Interrupt.NMI), false),
    InterruptHandler(@intFromEnum(Interrupt.BP), false),
    InterruptHandler(@intFromEnum(Interrupt.OF), false),
    InterruptHandler(@intFromEnum(Interrupt.BR), false),
    InterruptHandler(@intFromEnum(Interrupt.UD), false),
    InterruptHandler(@intFromEnum(Interrupt.NM), false),
    InterruptHandler(@intFromEnum(Interrupt.DF), true),
    InterruptHandler(@intFromEnum(Interrupt.CSO), false),
    InterruptHandler(@intFromEnum(Interrupt.TS), true),
    InterruptHandler(@intFromEnum(Interrupt.NP), true),
    InterruptHandler(@intFromEnum(Interrupt.SS), true),
    InterruptHandler(@intFromEnum(Interrupt.GP), true),
    InterruptHandler(@intFromEnum(Interrupt.PF), true),
    InterruptHandler(0x0f, false),
    InterruptHandler(@intFromEnum(Interrupt.MF), false),
    InterruptHandler(@intFromEnum(Interrupt.AC), true),
    InterruptHandler(@intFromEnum(Interrupt.MC), false),
    InterruptHandler(@intFromEnum(Interrupt.XM), false),
    InterruptHandler(@intFromEnum(Interrupt.VE), false),
    InterruptHandler(@intFromEnum(Interrupt.CP), true),
    InterruptHandler(0x16, false),
    InterruptHandler(0x17, false),
    InterruptHandler(0x18, false),
    InterruptHandler(0x19, false),
    InterruptHandler(0x1a, false),
    InterruptHandler(0x1b, false),
    InterruptHandler(0x1c, false),
    InterruptHandler(0x1d, false),
    InterruptHandler(0x1e, false),
    InterruptHandler(0x1f, false),
    InterruptHandler(0x20, false),
    InterruptHandler(0x21, false),
    InterruptHandler(0x22, false),
    InterruptHandler(0x23, false),
    InterruptHandler(0x24, false),
    InterruptHandler(0x25, false),
    InterruptHandler(0x26, false),
    InterruptHandler(0x27, false),
    InterruptHandler(0x28, false),
    InterruptHandler(0x29, false),
    InterruptHandler(0x2a, false),
    InterruptHandler(0x2b, false),
    InterruptHandler(0x2c, false),
    InterruptHandler(0x2d, false),
    InterruptHandler(0x2e, false),
    InterruptHandler(0x2f, false),
    InterruptHandler(0x30, false),
    InterruptHandler(0x31, false),
    InterruptHandler(0x32, false),
    InterruptHandler(0x33, false),
    InterruptHandler(0x34, false),
    InterruptHandler(0x35, false),
    InterruptHandler(0x36, false),
    InterruptHandler(0x37, false),
    InterruptHandler(0x38, false),
    InterruptHandler(0x39, false),
    InterruptHandler(0x3a, false),
    InterruptHandler(0x3b, false),
    InterruptHandler(0x3c, false),
    InterruptHandler(0x3d, false),
    InterruptHandler(0x3e, false),
    InterruptHandler(0x3f, false),
    InterruptHandler(0x40, false),
    InterruptHandler(0x41, false),
    InterruptHandler(0x42, false),
    InterruptHandler(0x43, false),
    InterruptHandler(0x44, false),
    InterruptHandler(0x45, false),
    InterruptHandler(0x46, false),
    InterruptHandler(0x47, false),
    InterruptHandler(0x48, false),
    InterruptHandler(0x49, false),
    InterruptHandler(0x4a, false),
    InterruptHandler(0x4b, false),
    InterruptHandler(0x4c, false),
    InterruptHandler(0x4d, false),
    InterruptHandler(0x4e, false),
    InterruptHandler(0x4f, false),
    InterruptHandler(0x50, false),
    InterruptHandler(0x51, false),
    InterruptHandler(0x52, false),
    InterruptHandler(0x53, false),
    InterruptHandler(0x54, false),
    InterruptHandler(0x55, false),
    InterruptHandler(0x56, false),
    InterruptHandler(0x57, false),
    InterruptHandler(0x58, false),
    InterruptHandler(0x59, false),
    InterruptHandler(0x5a, false),
    InterruptHandler(0x5b, false),
    InterruptHandler(0x5c, false),
    InterruptHandler(0x5d, false),
    InterruptHandler(0x5e, false),
    InterruptHandler(0x5f, false),
    InterruptHandler(0x60, false),
    InterruptHandler(0x61, false),
    InterruptHandler(0x62, false),
    InterruptHandler(0x63, false),
    InterruptHandler(0x64, false),
    InterruptHandler(0x65, false),
    InterruptHandler(0x66, false),
    InterruptHandler(0x67, false),
    InterruptHandler(0x68, false),
    InterruptHandler(0x69, false),
    InterruptHandler(0x6a, false),
    InterruptHandler(0x6b, false),
    InterruptHandler(0x6c, false),
    InterruptHandler(0x6d, false),
    InterruptHandler(0x6e, false),
    InterruptHandler(0x6f, false),
    InterruptHandler(0x70, false),
    InterruptHandler(0x71, false),
    InterruptHandler(0x72, false),
    InterruptHandler(0x73, false),
    InterruptHandler(0x74, false),
    InterruptHandler(0x75, false),
    InterruptHandler(0x76, false),
    InterruptHandler(0x77, false),
    InterruptHandler(0x78, false),
    InterruptHandler(0x79, false),
    InterruptHandler(0x7a, false),
    InterruptHandler(0x7b, false),
    InterruptHandler(0x7c, false),
    InterruptHandler(0x7d, false),
    InterruptHandler(0x7e, false),
    InterruptHandler(0x7f, false),
    InterruptHandler(0x80, false),
    InterruptHandler(0x81, false),
    InterruptHandler(0x82, false),
    InterruptHandler(0x83, false),
    InterruptHandler(0x84, false),
    InterruptHandler(0x85, false),
    InterruptHandler(0x86, false),
    InterruptHandler(0x87, false),
    InterruptHandler(0x88, false),
    InterruptHandler(0x89, false),
    InterruptHandler(0x8a, false),
    InterruptHandler(0x8b, false),
    InterruptHandler(0x8c, false),
    InterruptHandler(0x8d, false),
    InterruptHandler(0x8e, false),
    InterruptHandler(0x8f, false),
    InterruptHandler(0x90, false),
    InterruptHandler(0x91, false),
    InterruptHandler(0x92, false),
    InterruptHandler(0x93, false),
    InterruptHandler(0x94, false),
    InterruptHandler(0x95, false),
    InterruptHandler(0x96, false),
    InterruptHandler(0x97, false),
    InterruptHandler(0x98, false),
    InterruptHandler(0x99, false),
    InterruptHandler(0x9a, false),
    InterruptHandler(0x9b, false),
    InterruptHandler(0x9c, false),
    InterruptHandler(0x9d, false),
    InterruptHandler(0x9e, false),
    InterruptHandler(0x9f, false),
    InterruptHandler(0xa0, false),
    InterruptHandler(0xa1, false),
    InterruptHandler(0xa2, false),
    InterruptHandler(0xa3, false),
    InterruptHandler(0xa4, false),
    InterruptHandler(0xa5, false),
    InterruptHandler(0xa6, false),
    InterruptHandler(0xa7, false),
    InterruptHandler(0xa8, false),
    InterruptHandler(0xa9, false),
    InterruptHandler(0xaa, false),
    InterruptHandler(0xab, false),
    InterruptHandler(0xac, false),
    InterruptHandler(0xad, false),
    InterruptHandler(0xae, false),
    InterruptHandler(0xaf, false),
    InterruptHandler(0xb0, false),
    InterruptHandler(0xb1, false),
    InterruptHandler(0xb2, false),
    InterruptHandler(0xb3, false),
    InterruptHandler(0xb4, false),
    InterruptHandler(0xb5, false),
    InterruptHandler(0xb6, false),
    InterruptHandler(0xb7, false),
    InterruptHandler(0xb8, false),
    InterruptHandler(0xb9, false),
    InterruptHandler(0xba, false),
    InterruptHandler(0xbb, false),
    InterruptHandler(0xbc, false),
    InterruptHandler(0xbd, false),
    InterruptHandler(0xbe, false),
    InterruptHandler(0xbf, false),
    InterruptHandler(0xc0, false),
    InterruptHandler(0xc1, false),
    InterruptHandler(0xc2, false),
    InterruptHandler(0xc3, false),
    InterruptHandler(0xc4, false),
    InterruptHandler(0xc5, false),
    InterruptHandler(0xc6, false),
    InterruptHandler(0xc7, false),
    InterruptHandler(0xc8, false),
    InterruptHandler(0xc9, false),
    InterruptHandler(0xca, false),
    InterruptHandler(0xcb, false),
    InterruptHandler(0xcc, false),
    InterruptHandler(0xcd, false),
    InterruptHandler(0xce, false),
    InterruptHandler(0xcf, false),
    InterruptHandler(0xd0, false),
    InterruptHandler(0xd1, false),
    InterruptHandler(0xd2, false),
    InterruptHandler(0xd3, false),
    InterruptHandler(0xd4, false),
    InterruptHandler(0xd5, false),
    InterruptHandler(0xd6, false),
    InterruptHandler(0xd7, false),
    InterruptHandler(0xd8, false),
    InterruptHandler(0xd9, false),
    InterruptHandler(0xda, false),
    InterruptHandler(0xdb, false),
    InterruptHandler(0xdc, false),
    InterruptHandler(0xdd, false),
    InterruptHandler(0xde, false),
    InterruptHandler(0xdf, false),
    InterruptHandler(0xe0, false),
    InterruptHandler(0xe1, false),
    InterruptHandler(0xe2, false),
    InterruptHandler(0xe3, false),
    InterruptHandler(0xe4, false),
    InterruptHandler(0xe5, false),
    InterruptHandler(0xe6, false),
    InterruptHandler(0xe7, false),
    InterruptHandler(0xe8, false),
    InterruptHandler(0xe9, false),
    InterruptHandler(0xea, false),
    InterruptHandler(0xeb, false),
    InterruptHandler(0xec, false),
    InterruptHandler(0xed, false),
    InterruptHandler(0xee, false),
    InterruptHandler(0xef, false),
    InterruptHandler(0xf0, false),
    InterruptHandler(0xf1, false),
    InterruptHandler(0xf2, false),
    InterruptHandler(0xf3, false),
    InterruptHandler(0xf4, false),
    InterruptHandler(0xf5, false),
    InterruptHandler(0xf6, false),
    InterruptHandler(0xf7, false),
    InterruptHandler(0xf8, false),
    InterruptHandler(0xf9, false),
    InterruptHandler(0xfa, false),
    InterruptHandler(0xfb, false),
    InterruptHandler(0xfc, false),
    InterruptHandler(0xfd, false),
    InterruptHandler(0xfe, false),
    InterruptHandler(0xff, false),
};

const half_page_table_entry_count = @divExact(paging.page_table_entry_count, 2);

var once: bool = false;

fn map(address_space: paging.Specific, virtual: VirtualAddress, physical: PhysicalAddress, size: usize, flags: privileged.Mapping.Flags) !void {
    try address_space.map(physical, virtual, size, flags, cpu.page_allocator.getPageTableAllocatorInterface());
    if (flags.user) {
        const indexed: paging.IndexedVirtualAddress = @bitCast(virtual.value());
        const indices = indexed.toIndices();
        const top_indexed: paging.IndexedVirtualAddress = @bitCast(virtual.offset(size).value() - lib.arch.valid_page_sizes[0]);
        const top_indices = top_indexed.toIndices();
        _ = top_indices;
        // TODO: make this fast or not care, depending on how many times this is going to be executed
        //
        const user_page_tables = &cpu.user_scheduler.s.capability_root_node.dynamic.page_table;

        var page_table_ref = user_page_tables.user;

        assert(indexed.PML4 == top_indexed.PML4);
        assert(indexed.PDP == top_indexed.PDP);
        log.debug("PD base: {}. PD top: {}", .{ indexed.PD, top_indexed.PD });
        log.debug("PT base: {}. PT top: {}", .{ indexed.PT, top_indexed.PT });
        var pd_index: u10 = indexed.PD;
        var offset: usize = 0;

        while (pd_index <= top_indexed.PD) : (pd_index += 1) {
            const pt_base = if (pd_index == indexed.PD) indexed.PT else 0;
            const pt_top = if (pd_index == top_indexed.PD) top_indexed.PT else 511;
            log.debug("PD index: {}. Base: {}. Top: {}", .{ pd_index, pt_base, pt_top });

            var pt_index = pt_base;
            while (pt_index <= pt_top) : ({
                pt_index += 1;
                offset += lib.arch.valid_page_sizes[0];
            }) {
                const leaf = Leaf{
                    .physical = physical.offset(offset),
                    .flags = .{
                        .size = .@"4KB",
                    },
                    .common = undefined, // TODO:
                };
                const leaf_ref = try user_page_tables.appendLeaf(&cpu.user_scheduler.s.capability_root_node.heap.allocator, leaf);
                const level_fields = @typeInfo(paging.Level).Enum.fields;
                inline for (level_fields[0 .. level_fields.len - 1]) |level_field| {
                    const level = @field(paging.Level, level_field.name);
                    const page_table = user_page_tables.getPageTable(page_table_ref) catch |err| {
                        log.err("Error {s} at level {} when trying to map 0x{x} to 0x{x}", .{ @errorName(err), level, virtual.value(), physical.value() });
                        const virtual_address = virtual.offset(offset);
                        const physical_address = address_space.translateAddress(virtual_address, .{
                            .execute_disable = !flags.execute,
                            .write = flags.write,
                            .user = flags.user,
                        }) catch @panic("Could not translate address");
                        if (physical_address.value() != physical.offset(offset).value()) {
                            @panic("Address mismatch");
                        } else {
                            cpu.panic("PD index: {}. PT index: {}. Virtual: 0x{x}. Physical: 0x{x}", .{ pd_index, pt_index, virtual_address.value(), physical_address.value() });
                        }
                    };

                    page_table_ref = page_table.children[indices[@intFromEnum(level)]];
                }

                const page_table = try user_page_tables.getPageTable(page_table_ref);
                page_table.children[pt_index] = leaf_ref;
            }
        }
        // assert(indexed.PD == top_indexed.PD);
        // assert(indexed.PT <= top_indexed.PT);

        // var index: u10 = indexed.PT;
        // while (index <= top_indexed.PT) : (index += 1) {
        //     const leaf = Leaf{
        //         .physical = physical.offset(index - indexed.PT),
        //         .flags = .{
        //             .size = .@"4KB",
        //         },
        //         .common = undefined, // TODO:
        //     };
        //     const leaf_ref = try user_page_tables.appendLeaf(&cpu.user_scheduler.s.capability_root_node.heap.allocator, leaf);
        //     page_table.children[index] = leaf_ref;
        // }
    }
}

const CPUPageTables = privileged.arch.CPUPageTables;
// TODO: construct scheduler virtual memory tree
pub fn setupMapping(scheduler: *cpu.UserScheduler, user_virtual_region: VirtualMemoryRegion, cpu_page_tables: CPUPageTables, init_file: cpu.init.InitFile, regions: extern struct {
    scheduler: cpu.init.MappingArgument,
    heap: cpu.init.MappingArgument,
}) !void {
    // INFO: Need this hack for page table allocation callback to work
    cpu.user_scheduler = scheduler;
    _ = user_virtual_region;
    const page_tables = &scheduler.s.capability_root_node.dynamic.page_table;
    const heap_allocator = &scheduler.s.capability_root_node.heap.allocator;
    const page_table_size = paging.page_table_entry_count * paging.page_table_entry_size;
    log.debug("Root page table allocation", .{});
    const root_page_table_allocation = try cpu.page_allocator.allocateAligned(2 * page_table_size, cpu.arch.user_root_page_table_alignment, .{ .reason = .user_protected });
    const root_page_tables = root_page_table_allocation.split(2);
    log.debug("R priv: 0x{x}. R user: 0x{x}", .{ root_page_tables[0].address.value(), root_page_tables[1].address.value() });
    page_tables.privileged = .{
        .region = root_page_tables[0],
        .mapping = root_page_tables[0].address.toHigherHalfVirtualAddress(),
        .flags = .{
            .level = .PML4,
        },
    };
    const root_user_page_table = cpu.interface.PageTable{
        .region = root_page_tables[1],
        .mapping = root_page_tables[1].address.toHigherHalfVirtualAddress(),
        .flags = .{
            .level = .PML4,
        },
    };
    log.debug("Appending user root page table", .{});
    page_tables.user = try page_tables.appendPageTable(heap_allocator, root_user_page_table);

    log.debug("Copying higher half", .{});
    {
        // Copy the higher half into the user protected address space
        const current_address_space = paging.Specific{ .cr3 = cr3.read() };
        const src_half = (try current_address_space.getPML4TableUnchecked())[half_page_table_entry_count..][0..half_page_table_entry_count];
        const dst_half = page_tables.privileged.region.toHigherHalfVirtualAddress().access(paging.PML4TE)[half_page_table_entry_count..][0..half_page_table_entry_count];
        @memcpy(dst_half, src_half);

        // Map CPU driver into the CPU page table
        const cpu_pte_count = paging.page_table_entry_count - paging.CPUPageTables.left_ptables;
        const cpu_support_page_table_size = (paging.Level.count - 1) * paging.page_table_size;
        const cpu_support_page_table_allocation = try cpu.page_allocator.allocate(cpu_support_page_table_size, .{ .reason = .user_protected });
        var cpu_support_page_table_allocator = cpu_support_page_table_allocation;
        const pdp = try cpu_support_page_table_allocator.takeSlice(paging.page_table_size);
        const pd = try cpu_support_page_table_allocator.takeSlice(paging.page_table_size);
        const pt = try cpu_support_page_table_allocator.takeSlice(paging.page_table_size);
        assert(cpu_support_page_table_allocator.size == 0);

        // Copy CPU driver PTEs to user protected address space
        const cpu_ptes = cpu_page_tables.p_table.toHigherHalfVirtualAddress().access(*paging.PTable)[0..cpu_pte_count];
        const user_mapped_cpu_ptes = pt.toHigherHalfVirtualAddress().access(paging.PTE)[0..cpu_pte_count];
        @memcpy(user_mapped_cpu_ptes, cpu_ptes);

        // Fill the PML4 entry
        root_user_page_table.region.toHigherHalfVirtualAddress().access(paging.PML4TE)[paging.CPUPageTables.pml4_index] = paging.PML4TE{
            .present = true,
            .write = true,
            .execute_disable = false,
            .address = paging.packAddress(paging.PML4TE, pdp.address.value()),
        };

        // Fill the PDP entry
        pdp.toHigherHalfVirtualAddress().access(paging.PDPTE)[paging.CPUPageTables.pdp_index] = paging.PDPTE{
            .present = true,
            .write = true,
            .execute_disable = false,
            .address = paging.packAddress(paging.PDPTE, pd.address.value()),
        };

        // Fill the PD entry
        pd.toHigherHalfVirtualAddress().access(paging.PDTE)[paging.CPUPageTables.pd_index] = paging.PDTE{
            .present = true,
            .write = true,
            .execute_disable = false,
            .address = paging.packAddress(paging.PDTE, pt.address.value()),
        };
    }

    const privileged_address_space = paging.Specific.fromPhysicalRegion(root_page_tables[0]);
    const user_address_space = paging.Specific.fromPhysicalRegion(root_page_tables[1]);

    const scheduler_memory_map_flags = .{
        .write = true,
        .user = true,
        .huge_pages = false,
    };

    for (init_file.segments) |segment| {
        try map(user_address_space, segment.virtual, segment.physical, segment.memory_size, segment.flags);
    }
    try map(user_address_space, regions.scheduler.virtual, regions.scheduler.physical, regions.scheduler.size, scheduler_memory_map_flags);
    try map(user_address_space, regions.heap.virtual, regions.heap.physical, regions.heap.size, scheduler_memory_map_flags);

    // Map protected stack
    const privileged_stack_physical_region = try cpu.page_allocator.allocate(x86_64.capability_address_space_stack_size, .{ .reason = .user_protected });
    try map(privileged_address_space, x86_64.capability_address_space_stack_address, privileged_stack_physical_region.address, x86_64.capability_address_space_stack_size, .{
        .write = true,
        .execute = false,
        .user = false,
        .huge_pages = false,
    });

    const cpu_pml4 = try privileged_address_space.getPML4TableUnchecked();
    const user_pml4 = try user_address_space.getPML4TableUnchecked();
    @memcpy(cpu_pml4[0..cpu.arch.init.half_page_table_entry_count], user_pml4[0..cpu.arch.init.half_page_table_entry_count]);

    scheduler.s.capability_root_node.dynamic.page_table.switchPrivileged();
}

pub fn setupSchedulerCommon(scheduler_common: *birth.Scheduler.Common, entry_point: usize) void {
    const user_scheduler_virtual_address = @intFromPtr(scheduler_common);
    IA32_FS_BASE.write(user_scheduler_virtual_address);
    // Set arguments
    // First argument
    scheduler_common.disabled_save_area.registers.rdi = user_scheduler_virtual_address;
    // Second argument
    const is_init = true;
    scheduler_common.disabled_save_area.registers.rsi = @intFromBool(is_init);

    scheduler_common.disabled_save_area.registers.rip = entry_point;
    scheduler_common.disabled_save_area.registers.rsp = user_scheduler_virtual_address + @offsetOf(birth.Scheduler.Common, "setup_stack") + scheduler_common.setup_stack.len;
    scheduler_common.setup_stack_lock.value = true;
    scheduler_common.disabled_save_area.registers.rflags = .{ .IF = true }; // Set RFLAGS

    scheduler_common.disabled_save_area.fpu.fcw = 0x037f; // Set FPU
    scheduler_common.disabled_save_area.fpu.mxcsr = 0x1f80;
}
