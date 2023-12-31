const lib = @import("lib");

comptime {
    if (lib.os == .freestanding) @compileError("Host file included in non-host target");
}

const std = @import("std");
pub const ChildProcess = std.ChildProcess;

pub const posix = std.os;
pub const sync = std.os.sync;

pub const fs = std.fs;
pub const cwd = fs.cwd;
pub const Dir = fs.Dir;
pub const basename = fs.path.basename;
pub const dirname = fs.path.dirname;
pub const realpathAlloc = fs.realpathAlloc;

pub const os = std.os;

const io = std.io;
pub const getStdOut = std.io.getStdOut;

const heap = std.heap;
pub const ArenaAllocator = heap.ArenaAllocator;
pub const page_allocator = heap.page_allocator;

pub const ArrayList = std.ArrayList;
pub const ArrayListAligned = std.ArrayListAligned;

pub const time = std.time;

pub const http = std.http;
pub const Uri = std.Uri;

// Build imports
pub const build = std.build;

pub fn allocateZeroMemory(bytes: u64) ![]align(0x1000) u8 {
    switch (lib.os) {
        .windows => {
            const windows = std.os.windows;
            return @as([*]align(0x1000) u8, @ptrCast(@alignCast(try windows.VirtualAlloc(null, bytes, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE))))[0..bytes];
        },
        // Assume all systems are POSIX
        else => {
            const mmap = std.os.mmap;
            const PROT = std.os.PROT;
            const MAP = std.os.MAP;
            return try mmap(null, bytes, PROT.READ | PROT.WRITE, MAP.PRIVATE | MAP.ANONYMOUS, -1, 0);
        },
        .freestanding => @compileError("Not implemented yet"),
    }
}

pub const ExecutionError = error{failed};
pub fn spawnProcess(arguments: []const []const u8, allocator: lib.ZigAllocator) !void {
    var process = ChildProcess.init(arguments, allocator);
    // std.log.err("Spawning process:", .{});
    // for (arguments) |arg| {
    //     std.log.err("Arg: {s}", .{arg});
    // }

    process.stdout_behavior = .Ignore;
    const execution_result = try process.spawnAndWait();

    switch (execution_result) {
        .Exited => |exit_code| {
            switch (exit_code) {
                0 => {},
                else => return ExecutionError.failed,
            }
        },
        .Signal => |signal_code| {
            _ = signal_code;
            unreachable;
        },
        .Stopped, .Unknown => unreachable,
    }
}

pub const panic = std.debug.panic;

pub const allocateArguments = std.process.argsAlloc;
