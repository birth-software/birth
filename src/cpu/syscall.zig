const lib = @import("lib");
const cpu = @import("cpu");
const birth = @import("birth");

pub fn process(options: birth.syscall.Options, arguments: birth.syscall.Arguments) birth.syscall.Result {
    return switch (options.general.convention) {
        .birth => switch (options.birth.type) {
            inline else => |capability| switch (@as(birth.capabilities.Command(capability), @enumFromInt(options.birth.command))) {
                inline else => |command| blk: {
                    const Syscall = birth.capabilities.Syscall(capability, command);
                    const result = cpu.capabilities.processCommand(Syscall, arguments) catch |err| {
                        lib.log.err("Syscall ended up in error: {}", .{err});
                        break :blk Syscall.fromError(err);
                    };
                    break :blk Syscall.fromResult(result);
                },
            },
        },
        .linux => @panic("linux syscall"),
    };
}
