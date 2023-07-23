const std = @import("std");
const ArrayList = std.ArrayList;
const assert = std.debug.assert;
const concat = std.mem.concat;
const cwd = std.fs.cwd;
const Cpu = Target.Cpu;
const CrossTarget = std.zig.CrossTarget;
const EnumArray = std.EnumArray;
const enumValues = std.enums.values;
const fields = std.meta.fields;
const json = std.json;
const maxInt = std.math.maxInt;
const OptimizeMode = std.builtin.OptimizeMode;
const Target = std.Target;

// Build types
const Build = std.Build;
const CompileStep = Build.CompileStep;
const LazyPath = Build.LazyPath;
const Module = Build.Module;
const ModuleDependency = Build.ModuleDependency;
const OptionsStep = Build.OptionsStep;
const RunStep = Build.RunStep;
const Step = Build.Step;

const builtin = @import("builtin");
const os = builtin.os.tag;
const cpu = builtin.cpu;

const common = @import("src/common.zig");
const ArgumentParser = common.ArgumentParser;
const Bootloader = common.Bootloader;
const canVirtualizeWithQEMU = common.canVirtualizeWithQEMU;
const Configuration = common.Configuration;
const DiskType = common.DiskType;
const ExecutionType = common.ExecutionType;
const ExecutionEnvironment = common.ExecutionEnvironment;
const FilesystemType = common.FilesystemType;
const ImageConfig = common.ImageConfig;
const QEMUOptions = common.QEMUOptions;
const Suffix = common.Suffix;
const TraditionalExecutionMode = common.TraditionalExecutionMode;

const Error = error{
    not_implemented,
    architecture_not_supported,
    failed_to_run,
};

const source_root_dir = "src";
const user_program_dir_path = "src/user/programs";

var ci = false;
var ci_native = false;
var debug_user = false;
var debug_loader = false;
var modules = Modules{};
var b: *Build = undefined;
var build_steps: *BuildSteps = undefined;
var default_configuration: Configuration = undefined;
var user_modules: []const UserModule = undefined;
var options = Options{};

const supported_architectures = [_]Cpu.Arch{
    .x86_64,
    //.aarch64,
    //.riscv64,
};

fn architectureIndex(comptime arch: Cpu.Arch) comptime_int {
    inline for (supported_architectures, 0..) |architecture, index| {
        if (arch == architecture) return index;
    }

    @compileError("Architecture not found");
}

const ArchitectureBootloader = struct {
    id: Bootloader,
    protocols: []const Bootloader.Protocol,
};

const architecture_bootloader_map = blk: {
    var array: [supported_architectures.len][]const ArchitectureBootloader = undefined;

    array[architectureIndex(.x86_64)] = &.{
        .{
            .id = .birth,
            .protocols = &.{ .bios, .uefi },
        },
        .{
            .id = .limine,
            .protocols = &.{ .bios, .uefi },
        },
    };

    // array[architectureIndex(.aarch64)] = &.{
    //     .{
    //         .id = .birth,
    //         .protocols = &.{.uefi},
    //     },
    //     .{
    //         .id = .limine,
    //         .protocols = &.{.uefi},
    //     },
    // };

    // array[architectureIndex(.riscv64)] = &.{
    //     .{
    //         .id = .birth,
    //         .protocols = &.{.uefi},
    //     },
    // };

    break :blk array;
};

pub const UserModule = struct {
    package: UserPackage,
    name: []const u8,
};
pub const UserPackage = struct {
    kind: Kind,
    dependencies: []const Dependency,

    pub const Kind = enum {
        zig_exe,
    };

    pub const Dependency = struct {
        foo: u64 = 0,
    };
};

pub const BirthProgram = enum {
    bootloader,
    cpu,
    user,
    host,
};

pub fn build(b_arg: *Build) !void {
    b = b_arg;
    ci = b.option(bool, "ci", "CI mode") orelse false;
    ci_native = b.option(bool, "ci_native", "CI mode in self-hosted runner") orelse false;
    debug_user = b.option(bool, "debug_user", "Debug user program") orelse false;
    debug_loader = b.option(bool, "debug_loader", "Debug loader program") orelse false;
    const default_cfg_override = b.option([]const u8, "default", "Default configuration JSON file") orelse "config/default.json";
    modules = blk: {
        var mods = Modules{};
        inline for (comptime enumValues(ModuleID)) |module_id| {
            mods.modules.set(module_id, b.createModule(.{
                .source_file = LazyPath.relative(switch (module_id) {
                    .limine_installer => "src/bootloader/limine/installer.zig",
                    else => switch (module_id) {
                        .bios, .uefi, .limine => "src/bootloader",
                        else => "src",
                    } ++ "/" ++ @tagName(module_id) ++ ".zig",
                }),
            }));
        }

        try mods.setDependencies(.lib, &.{});
        try mods.setDependencies(.host, &.{.lib});
        try mods.setDependencies(.bootloader, &.{ .lib, .privileged });
        try mods.setDependencies(.bios, &.{ .lib, .privileged });
        try mods.setDependencies(.limine, &.{ .lib, .privileged });
        try mods.setDependencies(.uefi, &.{ .lib, .privileged });
        try mods.setDependencies(.limine_installer, &.{ .lib, .privileged });
        try mods.setDependencies(.privileged, &.{ .lib, .bootloader });
        try mods.setDependencies(.cpu, &.{ .privileged, .lib, .bootloader, .birth });
        try mods.setDependencies(.birth, &.{.lib});
        try mods.setDependencies(.user, &.{ .lib, .birth });

        break :blk mods;
    };

    options = blk: {
        var opts = Options{};
        opts.createOption(.bootloader);
        opts.createOption(.cpu);
        opts.createOption(.user);
        opts.createOption(.host);
        break :blk opts;
    };

    default_configuration = blk: {
        const default_json_file = try cwd().readFileAlloc(b.allocator, default_cfg_override, maxInt(usize));
        const parsed_cfg = try json.parseFromSlice(Configuration, b.allocator, default_json_file, .{});
        const cfg = parsed_cfg.value;

        const optimize_mode = b.option(
            OptimizeMode,
            "optimize",
            "Prioritize performance, safety, or binary size (-O flag)",
        ) orelse cfg.optimize_mode;

        break :blk Configuration{
            .architecture = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = cfg.architecture } }).getCpuArch(),
            .bootloader = cfg.bootloader,
            .boot_protocol = cfg.boot_protocol,
            .execution_environment = cfg.execution_environment,
            .optimize_mode = optimize_mode,
            .execution_type = cfg.execution_type,
            .executable_kind = .exe,
        };
    };

    build_steps = try b.allocator.create(BuildSteps);
    build_steps.* = .{
        .build_all = b.step("all", "Build all the artifacts"),
        .build_all_tests = b.step("all_tests", "Build all the artifacts related to tests"),
        .run = b.step("run", "Run the operating system through an emulator"),
        .debug = b.step("debug", "Debug the operating system through an emulator"),
        .test_run = b.step("test", "Run unit tests"),
        .test_debug = b.step("test_debug", "Debug unit tests"),
        .test_all = b.step("test_all", "Run all unit tests"),
        .test_host = b.step("test_host", "Run host unit tests"),
    };

    const disk_image_builder_modules = &.{ .lib, .host, .bootloader, .limine_installer, .bios };
    const disk_image_root_path = "src/host/disk_image_builder";
    const disk_image_builder = blk: {
        const exe = try addCompileStep(.{
            .kind = .exe,
            .name = "disk_image_builder",
            .root_project_path = disk_image_root_path,
            .modules = disk_image_builder_modules,
        });

        b.default_step.dependOn(&exe.step);

        break :blk exe;
    };

    const runner = blk: {
        const exe = try addCompileStep(.{
            .kind = .exe,
            .name = "runner",
            .root_project_path = "src/host/runner",
            .modules = &.{ .lib, .host },
        });

        b.default_step.dependOn(&exe.step);

        break :blk exe;
    };

    const native_tests = [_]struct {
        name: []const u8,
        root_project_path: []const u8,
        modules: []const ModuleID,
        c: ?C = null,
        run_native: bool = true,

        const C = struct {
            include_paths: []const LazyPath,
            source_files: []const SourceFile,
            link_libc: bool,
            link_libcpp: bool,

            const SourceFile = struct {
                path: LazyPath,
                flags: []const []const u8,
            };
        };
    }{
        .{
            .name = "host_native_test",
            .root_project_path = "src/host",
            .modules = &.{ .lib, .host },
        },
        .{
            .name = "disk_image_builder_native_test",
            .root_project_path = disk_image_root_path,
            .modules = disk_image_builder_modules,
            .c = .{
                .include_paths = &.{LazyPath.relative("src/bootloader/limine/installables")},
                .source_files = &.{
                    .{
                        .path = LazyPath.relative("src/bootloader/limine/installables/limine-deploy.c"),
                        .flags = &.{},
                    },
                },
                .link_libc = true,
                .link_libcpp = false,
            },
            // Skip it because it requires sudo privileges
            .run_native = false,
        },
    };

    const native_test_optimize_mode = .ReleaseFast;
    for (native_tests) |native_test| {
        const test_name = try concat(b.allocator, u8, &.{ native_test.name, "_", @tagName(native_test_optimize_mode) });
        const test_exe = try addCompileStep(.{
            .name = test_name,
            .root_project_path = native_test.root_project_path,
            .optimize_mode = native_test_optimize_mode,
            .modules = native_test.modules,
            .kind = .@"test",
        });

        if (native_test.c) |c| {
            for (c.include_paths) |include_path| {
                test_exe.addIncludePath(include_path);
            }

            for (c.source_files) |source_file| {
                test_exe.addCSourceFile(.{ .file = source_file.path, .flags = source_file.flags });
            }

            if (c.link_libc) {
                test_exe.linkLibC();
            }

            if (c.link_libcpp) {
                test_exe.linkLibCpp();
            }
        }

        //run_test_step.condition = .always;
        const should_run = !ci_native or (ci_native and native_test.run_native);
        if (should_run) {
            const run_test_step = b.addRunArtifact(test_exe);
            build_steps.test_all.dependOn(&run_test_step.step);
            build_steps.test_host.dependOn(&run_test_step.step);
        }
    }

    const ovmf_downloader = try addCompileStep(.{
        .name = "ovmf_downloader",
        .root_project_path = "src/host/ovmf_downloader",
        .optimize_mode = .Debug,
        .modules = &.{ .lib, .host },
        .kind = .exe,
    });
    const ovmf_downloader_run_step = b.addRunArtifact(ovmf_downloader);
    const ovmf_path = ovmf_downloader_run_step.addOutputFileArg("OVMF.fd");

    {
        var user_module_list = ArrayList(UserModule).init(b.allocator);
        var user_program_dir = try cwd().openIterableDir(user_program_dir_path, .{ .access_sub_paths = true });
        defer user_program_dir.close();

        var user_program_iterator = user_program_dir.iterate();

        while (try user_program_iterator.next()) |entry| {
            const dir_name = entry.name;
            const file_path = try concat(b.allocator, u8, &.{ dir_name, "/module.json" });
            const file = try user_program_dir.dir.readFileAlloc(b.allocator, file_path, maxInt(usize));
            const parsed_user_package = try json.parseFromSlice(UserPackage, b.allocator, file, .{});
            const user_package = parsed_user_package.value;
            try user_module_list.append(.{
                .package = user_package,
                .name = b.dupe(dir_name), // we have to dupe here otherwise Windows CI fails
            });
        }

        user_modules = user_module_list.items;
    }

    const executable_kinds = [2]CompileStep.Kind{ .exe, .@"test" };

    for (enumValues(OptimizeMode)) |optimize_mode| {
        for (supported_architectures, 0..) |architecture, architecture_index| {
            const user_target = try getTarget(architecture, .user);

            for (executable_kinds) |executable_kind| {
                const is_test = executable_kind == .@"test";
                const cpu_driver_path = "src/cpu";
                const target = try getTarget(architecture, .privileged);
                const cpu_driver = try addCompileStep(.{
                    .kind = executable_kind,
                    .name = "cpu_driver",
                    .root_project_path = cpu_driver_path,
                    .target = target,
                    .optimize_mode = optimize_mode,
                    .modules = &.{ .lib, .bootloader, .privileged, .cpu, .birth },
                });

                cpu_driver.force_pic = true;
                cpu_driver.disable_stack_probing = true;
                cpu_driver.stack_protector = false;
                cpu_driver.strip = false;
                cpu_driver.red_zone = false;
                cpu_driver.omit_frame_pointer = false;

                cpu_driver.code_model = switch (architecture) {
                    .x86_64 => .kernel,
                    .riscv64 => .medium,
                    .aarch64 => .small,
                    else => return Error.architecture_not_supported,
                };

                const cpu_driver_linker_script_path = LazyPath.relative(try concat(b.allocator, u8, &.{ cpu_driver_path, "/arch/", switch (architecture) {
                    .x86_64 => "x86/64",
                    .x86 => "x86/32",
                    else => @tagName(architecture),
                }, "/linker_script.ld" }));

                cpu_driver.setLinkerScriptPath(cpu_driver_linker_script_path);

                var user_module_list = try ArrayList(*CompileStep).initCapacity(b.allocator, user_modules.len);
                const user_architecture_source_path = try concat(b.allocator, u8, &.{ "src/user/arch/", @tagName(architecture), "/" });
                const user_linker_script_path = LazyPath.relative(try concat(b.allocator, u8, &.{ user_architecture_source_path, "linker_script.ld" }));
                for (user_modules) |module| {
                    const user_module = try addCompileStep(.{
                        .kind = executable_kind,
                        .name = module.name,
                        .root_project_path = try concat(b.allocator, u8, &.{ user_program_dir_path, "/", module.name }),
                        .target = user_target,
                        .optimize_mode = optimize_mode,
                        .modules = &.{ .lib, .user, .birth },
                    });
                    user_module.strip = false;

                    user_module.setLinkerScriptPath(user_linker_script_path);

                    user_module_list.appendAssumeCapacity(user_module);
                }

                const bootloaders = architecture_bootloader_map[architecture_index];
                for (bootloaders) |bootloader_struct| {
                    const bootloader = bootloader_struct.id;
                    for (bootloader_struct.protocols) |boot_protocol| {
                        const birth_loader_path = "src/bootloader/birth/";
                        const limine_loader_path = "src/bootloader/limine/";
                        const bootloader_name = "loader";
                        const bootloader_modules = [_]ModuleID{ .lib, .bootloader, .privileged };

                        const bootloader_compile_step = switch (bootloader) {
                            .birth => switch (boot_protocol) {
                                .bios => switch (architecture) {
                                    .x86_64 => blk: {
                                        const bootloader_path = birth_loader_path ++ "bios";
                                        const executable = try addCompileStep(.{
                                            .kind = executable_kind,
                                            .name = bootloader_name,
                                            .root_project_path = bootloader_path,
                                            .target = try getTarget(.x86, .privileged),
                                            .optimize_mode = .ReleaseSmall,
                                            .modules = &(bootloader_modules ++ .{.bios}),
                                        });

                                        executable.strip = true;

                                        executable.addAssemblyFile(LazyPath.relative("src/bootloader/arch/x86/64/smp_trampoline.S"));
                                        executable.addAssemblyFile(LazyPath.relative(bootloader_path ++ "/unreal_mode.S"));
                                        executable.setLinkerScriptPath(LazyPath.relative(bootloader_path ++ "/linker_script.ld"));
                                        executable.code_model = .small;

                                        break :blk executable;
                                    },
                                    else => return Error.architecture_not_supported,
                                },
                                .uefi => blk: {
                                    const bootloader_path = birth_loader_path ++ "uefi";
                                    const executable = try addCompileStep(.{
                                        .kind = executable_kind,
                                        .name = bootloader_name,
                                        .root_project_path = bootloader_path,
                                        .target = .{
                                            .cpu_arch = architecture,
                                            .os_tag = .uefi,
                                            .abi = .msvc,
                                        },
                                        .optimize_mode = .ReleaseSafe,
                                        .modules = &(bootloader_modules ++ .{.uefi}),
                                    });

                                    executable.strip = true;

                                    switch (architecture) {
                                        .x86_64 => executable.addAssemblyFile(LazyPath.relative("src/bootloader/arch/x86/64/smp_trampoline.S")),
                                        else => {},
                                    }

                                    break :blk executable;
                                },
                            },
                            .limine => blk: {
                                const bootloader_path = limine_loader_path;
                                const executable = try addCompileStep(.{
                                    .kind = executable_kind,
                                    .name = bootloader_name,
                                    .root_project_path = bootloader_path,
                                    .target = target,
                                    .optimize_mode = .ReleaseSafe,
                                    .modules = &(bootloader_modules ++ .{.limine}),
                                });

                                executable.force_pic = true;
                                executable.omit_frame_pointer = false;
                                executable.want_lto = false;
                                executable.strip = false;

                                executable.code_model = cpu_driver.code_model;

                                executable.setLinkerScriptPath(LazyPath.relative(try concat(b.allocator, u8, &.{ limine_loader_path ++ "arch/", @tagName(architecture), "/linker_script.ld" })));

                                break :blk executable;
                            },
                        };

                        bootloader_compile_step.disable_stack_probing = true;
                        bootloader_compile_step.stack_protector = false;
                        bootloader_compile_step.red_zone = false;

                        if (architecture == default_configuration.architecture and bootloader == default_configuration.bootloader and boot_protocol == default_configuration.boot_protocol and optimize_mode == default_configuration.optimize_mode and !is_test) {
                            addObjdump(bootloader_compile_step, bootloader_name);
                            addFileSize(bootloader_compile_step, bootloader_name);
                        }

                        const execution_environments: []const ExecutionEnvironment = switch (bootloader) {
                            .birth, .limine => switch (boot_protocol) {
                                .bios => switch (architecture) {
                                    .x86_64 => &.{.qemu},
                                    else => return Error.architecture_not_supported,
                                },
                                .uefi => &.{.qemu},
                            },
                        };

                        const execution_types: []const ExecutionType =
                            switch (canVirtualizeWithQEMU(architecture, ci)) {
                            true => &.{ .emulated, .accelerated },
                            false => &.{.emulated},
                        };

                        for (execution_types) |execution_type| {
                            for (execution_environments) |execution_environment| {
                                const configuration = Configuration{
                                    .architecture = architecture,
                                    .bootloader = bootloader,
                                    .boot_protocol = boot_protocol,
                                    .optimize_mode = optimize_mode,
                                    .execution_environment = execution_environment,
                                    .execution_type = execution_type,
                                    .executable_kind = executable_kind,
                                };

                                var disk_argument_parser = ArgumentParser.DiskImageBuilder{};
                                const disk_image_builder_run = b.addRunArtifact(disk_image_builder);
                                const disk_image_path = disk_image_builder_run.addOutputFileArg("disk.hdd");

                                while (disk_argument_parser.next()) |argument_type| switch (argument_type) {
                                    .configuration => inline for (fields(Configuration)) |field| disk_image_builder_run.addArg(@tagName(@field(configuration, field.name))),
                                    .image_configuration_path => disk_image_builder_run.addArg(ImageConfig.default_path),
                                    .disk_image_path => {
                                        // Must be first
                                        assert(@intFromEnum(argument_type) == 0);
                                    },
                                    .bootloader => {
                                        disk_image_builder_run.addArtifactArg(bootloader_compile_step);
                                    },
                                    .cpu => disk_image_builder_run.addArtifactArg(cpu_driver),
                                    .user_programs => for (user_module_list.items) |user_module| disk_image_builder_run.addArtifactArg(user_module),
                                };

                                const user_init = user_module_list.items[0];

                                const is_default = architecture == default_configuration.architecture and bootloader == default_configuration.bootloader and boot_protocol == default_configuration.boot_protocol and optimize_mode == default_configuration.optimize_mode and execution_environment == default_configuration.execution_environment and execution_type == default_configuration.execution_type;

                                const runner_run = try newRunnerRunArtifact(.{
                                    .configuration = configuration,
                                    .disk_image_path = disk_image_path,
                                    .cpu_driver = cpu_driver,
                                    .loader = bootloader_compile_step,
                                    .user_init = user_init,
                                    .runner = runner,
                                    .qemu_options = .{
                                        .is_debug = false,
                                        .is_test = is_test,
                                    },
                                    .ovmf_path = ovmf_path,
                                    .is_default = is_default,
                                });

                                const runner_debug = try newRunnerRunArtifact(.{
                                    .configuration = configuration,
                                    .disk_image_path = disk_image_path,
                                    .cpu_driver = cpu_driver,
                                    .loader = bootloader_compile_step,
                                    .user_init = user_init,
                                    .runner = runner,
                                    .qemu_options = .{
                                        .is_debug = true,
                                        .is_test = is_test,
                                    },
                                    .ovmf_path = ovmf_path,
                                    .is_default = is_default,
                                });

                                if (is_test) {
                                    build_steps.test_all.dependOn(&runner_run.step);
                                }

                                if (is_default) {
                                    if (is_test) {
                                        build_steps.test_run.dependOn(&runner_run.step);
                                        build_steps.test_debug.dependOn(&runner_debug.step);
                                    } else {
                                        build_steps.run.dependOn(&runner_run.step);
                                        build_steps.debug.dependOn(&runner_debug.step);

                                        b.default_step.dependOn(&bootloader_compile_step.step);

                                        b.default_step.dependOn(&cpu_driver.step);

                                        for (user_module_list.items) |user_module| {
                                            b.default_step.dependOn(&user_module.step);
                                        }

                                        const artifacts: []const *CompileStep = &.{ cpu_driver, user_init };
                                        const artifact_names: []const []const u8 = &.{ "cpu", "init" };

                                        inline for (artifact_names, 0..) |artifact_name, index| {
                                            const artifact = artifacts[index];
                                            addObjdump(artifact, artifact_name);
                                            addFileSize(artifact, artifact_name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

const Options = struct {
    arr: EnumArray(BirthProgram, *OptionsStep) = EnumArray(BirthProgram, *OptionsStep).initUndefined(),

    pub fn createOption(options_struct: *Options, birth_program: BirthProgram) void {
        const new_options = b.addOptions();
        new_options.addOption(BirthProgram, "program_type", birth_program);
        options_struct.arr.set(birth_program, new_options);
    }
};

const BuildSteps = struct {
    build_all: *Step,
    build_all_tests: *Step,
    debug: *Step,
    run: *Step,
    test_run: *Step,
    test_debug: *Step,
    test_all: *Step,
    test_host: *Step,
};

fn addObjdump(artifact: *CompileStep, comptime name: []const u8) void {
    switch (os) {
        .linux, .macos => {
            const objdump = b.addSystemCommand(&.{ "objdump", "-dxS", "-Mintel" });
            objdump.addArtifactArg(artifact);
            const objdump_step = b.step("objdump_" ++ name, "Objdump " ++ name);
            objdump_step.dependOn(&objdump.step);
        },
        else => {},
    }
}

fn addFileSize(artifact: *CompileStep, comptime name: []const u8) void {
    switch (os) {
        .linux, .macos => {
            const file_size = b.addSystemCommand(switch (os) {
                .linux => &.{ "stat", "-c", "%s" },
                .macos => &.{ "wc", "-c" },
                else => unreachable,
            });
            file_size.addArtifactArg(artifact);

            const file_size_step = b.step("file_size_" ++ name, "Get the file size of " ++ name);
            file_size_step.dependOn(&file_size.step);
        },
        else => {},
    }
}

fn newRunnerRunArtifact(arguments: struct {
    configuration: Configuration,
    disk_image_path: LazyPath,
    loader: *CompileStep,
    runner: *CompileStep,
    cpu_driver: *CompileStep,
    user_init: *CompileStep,
    qemu_options: QEMUOptions,
    ovmf_path: LazyPath,
    is_default: bool,
}) !*RunStep {
    const runner = b.addRunArtifact(arguments.runner);

    var argument_parser = ArgumentParser.Runner{};

    while (argument_parser.next()) |argument_type| switch (argument_type) {
        .configuration => inline for (fields(Configuration)) |field| runner.addArg(@tagName(@field(arguments.configuration, field.name))),
        .image_configuration_path => runner.addArg(ImageConfig.default_path),
        .cpu_driver => runner.addArtifactArg(arguments.cpu_driver),
        .loader_path => runner.addArtifactArg(arguments.loader),
        .init => runner.addArtifactArg(arguments.user_init),
        .disk_image_path => runner.addFileArg(arguments.disk_image_path),
        .qemu_options => inline for (fields(QEMUOptions)) |field| runner.addArg(if (@field(arguments.qemu_options, field.name)) "true" else "false"),
        .ci => runner.addArg(if (ci) "true" else "false"),
        .debug_user => runner.addArg(if (debug_user) "true" else "false"),
        .debug_loader => runner.addArg(if (debug_loader) "true" else "false"),
        .ovmf_path => runner.addFileArg(arguments.ovmf_path),
        .is_default => runner.addArg(if (arguments.is_default) "true" else "false"),
    };

    return runner;
}

const ExecutableDescriptor = struct {
    kind: CompileStep.Kind,
    name: []const u8,
    root_project_path: []const u8,
    target: CrossTarget = .{},
    optimize_mode: OptimizeMode = .Debug,
    modules: []const ModuleID,
};

const main_package_path = LazyPath.relative(source_root_dir);
fn addCompileStep(executable_descriptor: ExecutableDescriptor) !*CompileStep {
    const main_file = try concat(b.allocator, u8, &.{ executable_descriptor.root_project_path, "/main.zig" });
    const compile_step = switch (executable_descriptor.kind) {
        .exe => blk: {
            const executable = b.addExecutable(.{
                .name = executable_descriptor.name,
                .root_source_file = LazyPath.relative(main_file),
                .target = executable_descriptor.target,
                .optimize = executable_descriptor.optimize_mode,
                .main_pkg_path = main_package_path,
            });

            build_steps.build_all.dependOn(&executable.step);

            break :blk executable;
        },
        .@"test" => blk: {
            const test_file = LazyPath.relative(try concat(b.allocator, u8, &.{ executable_descriptor.root_project_path, "/test.zig" }));
            const test_exe = b.addTest(.{
                .name = executable_descriptor.name,
                .root_source_file = test_file,
                .target = executable_descriptor.target,
                .optimize = executable_descriptor.optimize_mode,
                .test_runner = if (executable_descriptor.target.os_tag) |_| main_file else null,
                .main_pkg_path = main_package_path,
            });

            build_steps.build_all_tests.dependOn(&test_exe.step);

            break :blk test_exe;
        },
        else => return Error.not_implemented,
    };

    compile_step.link_gc_sections = true;

    if (executable_descriptor.target.getOs().tag == .freestanding) {
        compile_step.entry_symbol_name = "_start";
    }

    for (executable_descriptor.modules) |module| {
        modules.addModule(compile_step, module);
    }

    return compile_step;
}

const ModuleID = enum {
    /// This module has typical common stuff used everywhere
    lib,
    /// This module contains code that is used by host programs when building and trying to run the OS
    host,
    /// This module contains code related to the bootloaders
    bootloader,
    bios,
    uefi,
    limine,
    limine_installer,
    /// This module contains code that is used by birth privileged programs
    privileged,
    /// This module contains code that is unique to birth CPU drivers
    cpu,
    /// This module contains code that is used by userspace programs
    user,
    /// This module contains code that is interacting between userspace and cpu in birth
    birth,
};

pub const Modules = struct {
    modules: EnumArray(ModuleID, *Module) = EnumArray(ModuleID, *Module).initUndefined(),
    dependencies: EnumArray(ModuleID, []const ModuleDependency) = EnumArray(ModuleID, []const ModuleDependency).initUndefined(),

    fn addModule(mods: Modules, compile_step: *CompileStep, module_id: ModuleID) void {
        compile_step.addModule(@tagName(module_id), mods.modules.get(module_id));
    }

    fn setDependencies(mods: Modules, module_id: ModuleID, dependencies: []const ModuleID) !void {
        const module = mods.modules.get(module_id);
        try module.dependencies.put(@tagName(module_id), module);

        for (dependencies) |dependency_id| {
            const dependency_module = mods.modules.get(dependency_id);
            try module.dependencies.put(@tagName(dependency_id), dependency_module);
        }
    }
};

fn getTarget(asked_arch: Cpu.Arch, execution_mode: TraditionalExecutionMode) Error!CrossTarget {
    var enabled_features = Cpu.Feature.Set.empty;
    var disabled_features = Cpu.Feature.Set.empty;

    if (execution_mode == .privileged) {
        switch (asked_arch) {
            .x86, .x86_64 => {
                // disable FPU
                const Feature = Target.x86.Feature;
                disabled_features.addFeature(@intFromEnum(Feature.x87));
                disabled_features.addFeature(@intFromEnum(Feature.mmx));
                disabled_features.addFeature(@intFromEnum(Feature.sse));
                disabled_features.addFeature(@intFromEnum(Feature.sse2));
                disabled_features.addFeature(@intFromEnum(Feature.avx));
                disabled_features.addFeature(@intFromEnum(Feature.avx2));
                disabled_features.addFeature(@intFromEnum(Feature.avx512f));

                enabled_features.addFeature(@intFromEnum(Feature.soft_float));
            },
            else => return Error.architecture_not_supported,
        }
    }

    return CrossTarget{
        .cpu_arch = asked_arch,
        .cpu_model = switch (cpu.arch) {
            .x86 => .determined_by_cpu_arch,
            .x86_64 => if (execution_mode == .privileged) .determined_by_cpu_arch else
            // zig fmt off
            .determined_by_cpu_arch,
            // .determined_by_cpu_arch,
            // TODO: this causes some problems: https://github.com/ziglang/zig/issues/15524
            //.{ .explicit = &Target.x86.cpu.x86_64_v3 },
            else => .determined_by_cpu_arch,
        },
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_add = enabled_features,
        .cpu_features_sub = disabled_features,
    };
}
