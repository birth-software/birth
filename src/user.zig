const lib = @import("lib");
const log = lib.log;
const assert = lib.assert;
const ExecutionMode = lib.Syscall.ExecutionMode;

const birth = @import("birth");
pub const Command = birth.interface.Command;
pub const Interface = birth.interface.Descriptor;
pub const Scheduler = birth.Scheduler;

pub const arch = @import("user/arch.zig");
pub const capabilities = @import("user/capabilities.zig");
const core_state = @import("user/core_state.zig");
pub const CoreState = core_state.CoreState;
pub const libc = @import("user/libc.zig");
pub const thread = @import("user/thread.zig");
pub const Thread = thread.Thread;
pub const process = @import("user/process.zig");
pub const Virtual = @import("user/virtual.zig");
const VirtualAddress = lib.VirtualAddress;

comptime {
    @export(arch._start, .{ .linkage = .Strong, .name = "_start" });
}

pub const writer = lib.Writer(void, Writer.Error, Writer.write){ .context = {} };
const Writer = extern struct {
    const syscall = Interface(.io, .log);
    const Error = Writer.syscall.Error;

    fn write(_: void, bytes: []const u8) Error!usize {
        const result = try Writer.syscall.blocking(bytes);
        return result;
    }
};

pub const std_options = struct {
    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        lib.format(writer, format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
        _ = scope;
        _ = level;
    }
};

pub fn zigPanic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    @call(.always_inline, panic, .{ "{s}", .{message} });
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    var buffer: [0x100]u8 = undefined;
    const message: []const u8 = lib.bufPrint(&buffer, format, arguments) catch "Failed to get panic message!";
    while (true) {
        Interface(.process, .panic).blocking(.{
            .message = message,
            .exit_code = 1,
        }) catch |err| log.err("Exit failed: {}", .{err});
    }
}

fn schedulerInitDisabled(scheduler: *arch.Scheduler) void {
    // Architecture-specific initialization
    scheduler.generic.time_slice = 1;
    // TODO: capabilities
}

pub var is_init = false;
pub var command_buffer: Command.Buffer = undefined;
const entry_count = 50;

const CommandBufferCreateError = error{
    invalid_entry_count,
};

fn createCommandBuffer(options: Command.Buffer.CreateOptions) !Command.Buffer {
    // TODO: allow kernel to chop slices of memories
    try capabilities.setupCommandFrame(Command.Submission, options.submission_entry_count);
    try capabilities.setupCommandFrame(Command.Completion, options.completion_entry_count);
    @panic("TODO: createCommandBuffer");
}

pub export fn start(scheduler: *Scheduler, arg_init: bool) callconv(.C) noreturn {
    assert(arg_init);
    is_init = arg_init;
    if (is_init) {
        assert(scheduler.common.setup_stack_lock.load(.Monotonic));
    }

    initialize() catch |err| panic("Failed to initialize: {}", .{err});
    @import("root").main() catch |err| panic("Failed to execute main: {}", .{err});

    while (true) {
        @panic("TODO: after main");
    }
}

fn initialize() !void {
    _ = try Virtual.AddressSpace.create();
}

// export fn birthInitializeDisabled(scheduler: *arch.Scheduler, arg_init: bool) callconv(.C) noreturn {
//     // TODO: delete when this code is unnecessary. In the meanwhile it counts as a sanity check
//     assert(arg_init);
//     is_init = arg_init;
//     schedulerInitDisabled(scheduler);
//     thread.initDisabled(scheduler);
// }

// Barrelfish: vregion
pub inline fn currentScheduler() *birth.Scheduler {
    const result = arch.maybeCurrentScheduler().?;
    return result;
}
