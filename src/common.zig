// This file is meant to be shared between all parts of the project, including build.zig
const std = @import("std");
const maxInt = std.math.maxInt;
const containsAtLeast = std.mem.containsAtLeast;
const Target = std.Target;
const Cpu = Target.Cpu;
const OptimizeMode = std.builtin.OptimizeMode;

const Allocator = std.mem.Allocator;

const builtin = @import("builtin");
const cpu = builtin.cpu;
const os = builtin.os.tag;

pub const Configuration = struct {
    architecture: Cpu.Arch,
    bootloader: Bootloader,
    boot_protocol: Bootloader.Protocol,
    execution_environment: ExecutionEnvironment,
    optimize_mode: OptimizeMode,
    execution_type: ExecutionType,
    executable_kind: std.Build.CompileStep.Kind,
};

pub const Bootloader = enum(u32) {
    birth,
    limine,

    pub const Protocol = enum(u32) {
        bios,
        uefi,
    };
};

pub const ExecutionEnvironment = enum {
    qemu,
};

pub const ExecutionType = enum {
    emulated,
    accelerated,
};

pub const TraditionalExecutionMode = enum(u1) {
    privileged = 0,
    user = 1,
};

pub fn canVirtualizeWithQEMU(architecture: Cpu.Arch, ci: bool) bool {
    if (architecture != cpu.arch) return false;
    if (ci) return false;

    return switch (os) {
        .linux => blk: {
            const uname = std.os.uname();
            const release = &uname.release;
            break :blk !containsAtLeast(u8, release, 1, "WSL") and !containsAtLeast(u8, release, 1, "microsoft");
        },
        else => false,
    };
}

pub const ArgumentParser = struct {
    pub const null_specifier = "-";

    pub const DiskImageBuilder = struct {
        argument_index: usize = 0,

        pub const ArgumentType = enum {
            disk_image_path,
            configuration,
            image_configuration_path,
            bootloader,
            cpu,
            user_programs,
        };

        pub const Result = struct {
            bootloader: []const u8,
            disk_image_path: []const u8,
            image_configuration_path: []const u8,
            cpu: []const u8,
            user_programs: []const []const u8,
            configuration: Configuration,
        };

        pub fn next(argument_parser: *ArgumentParser.DiskImageBuilder) ?ArgumentType {
            if (argument_parser.argument_index < enumCount(ArgumentType)) {
                const result: ArgumentType = @enumFromInt(argument_parser.argument_index);
                argument_parser.argument_index += 1;
                return result;
            }

            return null;
        }
    };

    pub const Runner = struct {
        argument_index: usize = 0,

        pub fn next(argument_parser: *ArgumentParser.Runner) ?ArgumentType {
            if (argument_parser.argument_index < enumCount(ArgumentType)) {
                const result: ArgumentType = @enumFromInt(argument_parser.argument_index);
                argument_parser.argument_index += 1;
                return result;
            }

            return null;
        }

        pub const ArgumentType = enum {
            configuration,
            disk_image_path,
            image_configuration_path,
            cpu_driver,
            loader_path,
            qemu_options,
            ci,
            debug_user,
            debug_loader,
            init,
            ovmf_path,
            is_default,
        };

        pub const Result = struct {
            configuration: Configuration,
            disk_image_path: []const u8,
            image_configuration_path: []const u8,
            cpu_driver: []const u8,
            loader_path: []const u8,
            qemu_options: QEMUOptions,
            ci: bool,
            debug_user: bool,
            debug_loader: bool,
            init: []const u8,
            ovmf_path: []const u8,
            is_default: bool,
        };
    };
};

fn enumCount(comptime E: type) comptime_int {
    return @typeInfo(E).Enum.fields.len;
}

pub const QEMUOptions = packed struct {
    is_test: bool,
    is_debug: bool,
};

pub const PartitionTableType = enum {
    mbr,
    gpt,
};

pub const ImageConfig = struct {
    sector_count: u64,
    sector_size: u16,
    partition_table: PartitionTableType,
    partition: PartitionConfig,

    pub const default_path = "config/image_config.json";

    pub fn get(allocator: Allocator, path: []const u8) !ImageConfig {
        const image_config_file = try std.fs.cwd().readFileAlloc(allocator, path, maxInt(usize));
        const parsed_image_configuration = try std.json.parseFromSlice(ImageConfig, allocator, image_config_file, .{});
        return parsed_image_configuration.value;
    }
};

pub const PartitionConfig = struct {
    name: []const u8,
    filesystem: FilesystemType,
    first_lba: u64,
};

pub const FilesystemType = enum(u32) {
    birth = 0,
    ext2 = 1,
    fat32 = 2,

    pub const count = enumCount(@This());
};
