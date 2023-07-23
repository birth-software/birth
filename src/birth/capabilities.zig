const lib = @import("lib");
const assert = lib.assert;
const PhysicalAddress = lib.PhysicalAddress;

const birth = @import("birth");
const syscall = birth.syscall;

const Capabilities = @This();

pub const Reference = packed struct(usize) {
    integer: usize,
};

pub const RAM = packed struct(u64) {
    block: u32,
    region: u32,
};

pub const Type = enum(u8) {
    io, // primitive
    cpu, // primitive
    ram, // primitive
    cpu_memory, // non-primitive Barrelfish: frame
    boot,
    process, // Temporarily available
    page_table, // Barrelfish: vnode
    // TODO: device_memory, // primitive
    // scheduler,
    // irq_table,

    // _,

    pub const BackingType = @typeInfo(Type).Enum.tag_type;

    pub const Mappable = enum {
        cpu_memory,
        page_table,

        pub inline fn toCapability(mappable: Mappable) Capabilities.Type {
            return switch (mappable) {
                inline else => |mappable_cap| @field(Capabilities.Type, @tagName(mappable_cap)),
            };
        }
    };
};

pub const Subtype = u16;
pub const AllTypes = Type;

pub fn CommandBuilder(comptime list: []const []const u8) type {
    const capability_base_command_list = .{
        "copy",
        "mint",
        "retype",
        "delete",
        "revoke",
        "create",
    } ++ list;

    const enum_fields = lib.enumAddNames(&.{}, capability_base_command_list);

    // TODO: make this non-exhaustive enums
    // PROBLEM: https://github.com/ziglang/zig/issues/12250
    // Currently waiting on this since this will enable some comptime magic
    const result = @Type(.{
        .Enum = .{
            .tag_type = Subtype,
            .fields = enum_fields,
            .decls = &.{},
            .is_exhaustive = true,
        },
    });
    return result;
}

/// Takes some names and integers. Then values are added to the Command enum for an specific capability
/// The number is an offset of the fields with respect to the base command enum fields
pub fn Command(comptime capability: Type) type {
    const extra_command_list = switch (capability) {
        .io => .{
            "log",
        },
        .cpu => .{
            "get_core_id",
            "shutdown",
            "get_command_buffer",
        },
        .ram => .{
            "allocate",
        },
        .cpu_memory => [_][]const u8{},
        .boot => .{
            "get_bundle_size",
            "get_bundle_file_list_size",
        },
        .process => .{
            "exit",
            "panic",
        },
        .page_table => [_][]const u8{},
    };

    return CommandBuilder(&extra_command_list);
}

const success = 0;
const first_valid_error = success + 1;
pub fn ErrorSet(comptime error_names: []const []const u8) type {
    const predefined_error_names = &.{ "forbidden", "corrupted_input", "invalid_input" };
    comptime var current_error = first_valid_error;
    comptime var predefined_errors: []const lib.Type.EnumField = &.{};

    inline for (predefined_error_names) |predefined_error_name| {
        defer current_error += 1;

        predefined_errors = predefined_errors ++ .{
            .{
                .name = predefined_error_name,
                .value = current_error,
            },
        };
    }

    return lib.ErrorSet(error_names, predefined_errors);
}

const raw_argument_count = @typeInfo(syscall.Arguments).Array.len;

const DefaultErrorSet = Capabilities.ErrorSet(&.{});
const Types = struct {
    Result: type = void,
    Arguments: type = void,
    ErrorSet: type = DefaultErrorSet,
};

fn Functions(comptime T: Types) type {
    const ToArguments = fn (syscall.Arguments) callconv(.Inline) T.ErrorSet.Error!T.Arguments;
    const FromArguments = fn (T.Arguments) callconv(.Inline) syscall.Arguments;

    return switch (T.Result) {
        else => blk: {
            const ToResult = fn (syscall.Result.Birth) callconv(.Inline) T.Result;
            const FromResult = fn (T.Result) callconv(.Inline) syscall.Result;

            // return if (T.Result == void and T.Arguments == void and T.ErrorSet == DefaultErrorSet) struct {
            break :blk if (T.ErrorSet == DefaultErrorSet and T.Result == void and T.Arguments == void) struct {
                toResult: ToResult = voidToResult,
                fromResult: FromResult = voidFromResult,
                toArguments: ToArguments = voidToArguments,
                fromArguments: FromArguments = voidFromArguments,
            } else if (T.ErrorSet == DefaultErrorSet and T.Result == void) struct {
                toResult: ToResult = voidToResult,
                fromResult: FromResult = voidFromResult,
                toArguments: ToArguments,
                fromArguments: FromArguments,
            } else if (T.ErrorSet == DefaultErrorSet and T.Arguments == void) struct {
                toResult: ToResult,
                fromResult: FromResult,
                toArguments: ToArguments = voidToArguments,
                fromArguments: FromArguments = voidFromArguments,
            } else struct {
                toResult: ToResult,
                fromResult: FromResult,
                toArguments: ToArguments,
                fromArguments: FromArguments,
            };
        },
        noreturn => if (T.ErrorSet == DefaultErrorSet and T.Arguments == void) struct {
            toArguments: ToArguments = voidToArguments,
            fromArguments: FromArguments = voidFromArguments,
        } else struct {
            toArguments: ToArguments,
            fromArguments: FromArguments,
        },
    };
}

fn Descriptor(comptime T: Types) type {
    return struct {
        types: Types = T,
        functions: Functions(T),
    };
}

fn CommandDescriptor(comptime capability: Type, comptime command: Command(capability)) type {
    return Descriptor(switch (capability) {
        .io => switch (command) {
            .log => .{
                .Result = usize,
                .Arguments = []const u8,
            },
            else => .{},
        },
        .ram => switch (command) {
            .allocate => .{
                .Result = Reference,
                .Arguments = usize,
                .ErrorSet = ErrorSet(&.{"OutOfMemory"}),
            },
            else => .{},
        },
        .process => switch (command) {
            .exit => .{
                .Result = noreturn,
                .Arguments = bool,
            },
            .panic => .{
                .Result = noreturn,
                .Arguments = struct {
                    message: []const u8,
                    exit_code: u64,
                },
            },
            else => .{},
        },
        .cpu => switch (command) {
            .get_core_id => .{
                .Result = u32,
            },
            .shutdown => .{
                .Result = noreturn,
            },
            // .get_command_buffer = .{
            // },
            else => .{},
        },
        .boot => switch (command) {
            .get_bundle_file_list_size, .get_bundle_size => .{
                .Result = usize,
            },
            else => .{},
        },
        else => .{},
    });
}

pub fn Syscall(comptime cap: Type, comptime com: Command(cap)) type {
    const D = CommandDescriptor(cap, com);
    const T = @as(?*const Types, @ptrCast(@typeInfo(D).Struct.fields[0].default_value)).?.*;
    const d = D{
        .functions = switch (cap) {
            .ram => switch (com) {
                .allocate => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: syscall.Result.Birth) Reference {
                            return @bitCast(raw_result.second);
                        }

                        inline fn fromResult(result: Reference) syscall.Result {
                            return .{
                                .birth = .{
                                    .first = .{},
                                    .second = @bitCast(result),
                                },
                            };
                        }

                        inline fn toArguments(raw_arguments: syscall.Arguments) T.ErrorSet.Error!usize {
                            const size = raw_arguments[0];
                            return size;
                        }

                        inline fn fromArguments(arguments: usize) syscall.Arguments {
                            const result = [1]usize{arguments};
                            return result ++ .{0} ** (raw_argument_count - result.len);
                        }
                    };
                    break :blk .{
                        .toResult = F.toResult,
                        .fromResult = F.fromResult,
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                    };
                },
                else => .{},
            },
            .process => switch (com) {
                .exit => blk: {
                    const F = struct {
                        inline fn toArguments(raw_arguments: syscall.Arguments) T.ErrorSet.Error!T.Arguments {
                            const result = raw_arguments[0] != 0;
                            return result;
                        }

                        inline fn fromArguments(arguments: T.Arguments) syscall.Arguments {
                            const result = [1]usize{@intFromBool(arguments)};
                            return result ++ .{0} ** (raw_argument_count - result.len);
                        }
                    };
                    break :blk .{
                        // .toResult = F.toResult,
                        // .fromResult = F.fromResult,
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                    };
                },
                .panic => blk: {
                    const F = struct {
                        inline fn toArguments(raw_arguments: syscall.Arguments) T.ErrorSet.Error!T.Arguments {
                            if (@as(?[*]const u8, @ptrFromInt(raw_arguments[0]))) |message_ptr| {
                                const message_len = raw_arguments[1];

                                if (message_len != 0) {
                                    const message = message_ptr[0..message_len];
                                    const exit_code = raw_arguments[2];

                                    return .{
                                        .message = message,
                                        .exit_code = exit_code,
                                    };
                                }
                            }

                            return error.invalid_input;
                        }

                        inline fn fromArguments(arguments: T.Arguments) syscall.Arguments {
                            const result: [3]usize = .{ @intFromPtr(arguments.message.ptr), arguments.message.len, arguments.exit_code };
                            return result ++ .{0} ** (raw_argument_count - result.len);
                        }
                    };
                    break :blk .{
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                    };
                },
                else => .{},
            },
            .io => switch (com) {
                .log => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: syscall.Result.Birth) T.Result {
                            return raw_result.second;
                        }

                        inline fn fromResult(result: T.Result) syscall.Result {
                            return syscall.Result{
                                .birth = .{
                                    .first = .{},
                                    .second = result,
                                },
                            };
                        }

                        inline fn toArguments(raw_arguments: syscall.Arguments) T.ErrorSet.Error!T.Arguments {
                            const message_ptr = @as(?[*]const u8, @ptrFromInt(raw_arguments[0])) orelse return error.invalid_input;
                            const message_len = raw_arguments[1];
                            if (message_len == 0) return error.invalid_input;
                            const message = message_ptr[0..message_len];
                            return message;
                        }

                        inline fn fromArguments(arguments: T.Arguments) syscall.Arguments {
                            const result = [2]usize{ @intFromPtr(arguments.ptr), arguments.len };
                            return result ++ .{0} ** (raw_argument_count - result.len);
                        }
                    };
                    break :blk .{
                        .toResult = F.toResult,
                        .fromResult = F.fromResult,
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                    };
                },
                else => .{},
            },
            .cpu => switch (com) {
                .get_core_id => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: syscall.Result.Birth) T.Result {
                            return @as(T.Result, @intCast(raw_result.second));
                        }

                        inline fn fromResult(result: T.Result) syscall.Result {
                            return syscall.Result{
                                .birth = .{
                                    .first = .{},
                                    .second = result,
                                },
                            };
                        }
                    };
                    break :blk .{
                        .toResult = F.toResult,
                        .fromResult = F.fromResult,
                    };
                },
                .shutdown => .{
                    .toArguments = voidToArguments,
                    .fromArguments = voidFromArguments,
                },
                .get_command_buffer => .{
                    //             .get_command_buffer => struct {
                    //                 pub const ErrorSet = Capabilities.ErrorSet(&.{});
                    //                 pub const Result = noreturn;
                    //                 pub const Arguments = *birth.CommandBuffer;
                    //
                    //                 pub const toResult = @compileError("noreturn unexpectedly returned");
                    //
                    //                 inline fn toArguments(raw_arguments: syscall.Arguments) !Arguments {
                    //                     const ptr = @as(?*birth.CommandBuffer, @ptrFromInt(raw_arguments[0])) orelse return error.invalid_input;
                    //                     return ptr;
                    //                 }
                    //
                    //                 inline fn argumentsToRaw(arguments: Arguments) syscall.Arguments {
                    //                     const result = [1]usize{@intFromPtr(arguments)};
                    //                     return result ++ .{0} ** (raw_argument_count - result.len);
                    //                 }
                    //             },
                },
                else => .{},
            },
            .boot => switch (com) {
                .get_bundle_file_list_size, .get_bundle_size => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: syscall.Result.Birth) T.Result {
                            return raw_result.second;
                        }
                        inline fn fromResult(result: T.Result) syscall.Result {
                            return syscall.Result{
                                .birth = .{
                                    .first = .{},
                                    .second = result,
                                },
                            };
                        }
                    };

                    break :blk .{
                        .toResult = F.toResult,
                        .fromResult = F.fromResult,
                    };
                },
                else => .{},
            },
            else => .{},
        },
    };

    return struct {
        pub const capability = cap;
        pub const command = com;
        pub const Error = T.ErrorSet.Error;
        pub const Result = T.Result;

        pub const toResult = d.functions.toResult;
        pub const fromResult = d.functions.fromResult;
        pub const toArguments = d.functions.toArguments;
        pub const fromArguments = d.functions.fromArguments;

        pub inline fn fromError(err: Error) syscall.Result {
            const error_enum = switch (err) {
                inline else => |comptime_error| @field(T.ErrorSet.Enum, @errorName(comptime_error)),
            };
            return syscall.Result{
                .birth = .{
                    .first = .{
                        .@"error" = @intFromEnum(error_enum),
                    },
                    .second = 0,
                },
            };
        }

        pub fn blocking(arguments: T.Arguments) Error!Result {
            const raw_arguments = d.functions.fromArguments(arguments);
            // TODO: make this more reliable and robust?
            const options = birth.syscall.Options{
                .birth = .{
                    .type = capability,
                    .command = @intFromEnum(command),
                },
            };

            const raw_result = birth.arch.syscall(options, raw_arguments);

            const raw_error_value = raw_result.birth.first.@"error";
            comptime {
                assert(lib.enumFields(T.ErrorSet.Enum)[0].value == first_valid_error);
            }

            return switch (raw_error_value) {
                success => switch (T.Result) {
                    noreturn => unreachable,
                    else => d.functions.toResult(raw_result.birth),
                },
                else => switch (@as(T.ErrorSet.Enum, @enumFromInt(raw_error_value))) {
                    inline else => |comptime_error_enum| @field(Error, @tagName(comptime_error_enum)),
                },
            };
        }

        pub fn buffer(command_buffer: *birth.CommandBuffer, arguments: T.Arguments) void {
            _ = arguments;
            _ = command_buffer;

            @panic("TODO: buffer");
        }
    };
}

inline fn voidToResult(raw_result: syscall.Result.Birth) void {
    _ = raw_result;

    @panic("TODO: voidToResult");
}

inline fn voidFromResult(result: void) syscall.Result {
    _ = result;

    @panic("TODO: voidFromResult");
}

inline fn voidToArguments(raw_arguments: syscall.Arguments) DefaultErrorSet.Error!void {
    _ = raw_arguments;
}

inline fn voidFromArguments(arguments: void) syscall.Arguments {
    _ = arguments;
    return [6]usize{0};
}
