const lib = @import("lib");
const assert = lib.assert;
const PhysicalAddress = lib.PhysicalAddress;

const birth = @import("birth");

pub const Capability = enum(u8) {
    io, // primitive
    cpu, // primitive
    memory, // primitive
    cpu_memory, // non-primitive Barrelfish: frame
    command_buffer_submission, // inherit from ram
    command_buffer_completion, // inherit from ram
    boot,
    process, // Temporarily available
    page_table, // Barrelfish: vnode
    memory_mapping, // Barrelfish: Frame Mapping, Device Frame Mapping,
    page_table_mapping, // Barrelfish: VNode mapping
    // TODO: device_memory, // primitive
    // scheduler,
    // irq_table,

    // _,

    pub const BackingType = @typeInfo(Capability).Enum.tag_type;

    pub const Mappable = enum {
        cpu_memory,
        page_table,
        command_buffer_completion,
        command_buffer_submission,

        pub inline fn toCapability(mappable: Mappable) Capability {
            return switch (mappable) {
                inline else => |mappable_cap| @field(Capability, @tagName(mappable_cap)),
            };
        }
    };

    pub fn getChildTypes(comptime capability: Capability) []const Capability {
        comptime {
            return switch (capability) {
                .memory => &.{
                    .cpu_memory,
                    .command_buffer_completion,
                    .command_buffer_submission,
                },
                else => &.{},
            };
        }
    }
};

pub const Reference = packed struct(usize) {
    integer: usize,
};

pub const Memory = packed struct(u64) {
    block: u32,
    region: u32,
};

pub const PageTable = packed struct(u16) {
    block: u7 = 0,
    index: u7 = 0,
    entry_type: EntryType = .page_table,
    present: bool = false,

    pub const EntryType = enum(u1) {
        page_table = 0,
        leaf = 1,
    };
};

pub const Mapping = packed struct(u32) {
    foo: u32 = 0,
};

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
            .tag_type = Command.Type,
            .fields = enum_fields,
            .decls = &.{},
            .is_exhaustive = true,
        },
    });
    return result;
}

pub const Command = extern struct {
    foo: u32 = 0,

    pub const Buffer = extern struct {
        submission_queue: Submission.Queue,
        completion_queue: Completion.Queue,

        pub const CreateOptions = packed struct {
            submission_entry_count: u16,
            completion_entry_count: u16,
        };
    };

    pub const Submission = extern struct {
        pub const Queue = extern struct {
            head: *u16,
            tail: *u16,
        };

        pub const Header = extern struct {
            head: u16,
            tail: u16,
        };
    };

    pub const Completion = extern struct {
        foo: u32 = 0,

        pub const Queue = extern struct {
            head: *u16,
            tail: *u16,
        };

        pub const Header = extern struct {
            head: u16,
            tail: u16,
        };
    };
    pub const Type = u16;
    pub fn fromCapability(comptime capability: Capability) type {
        const extra_command_list = switch (capability) {
            .io => .{
                "log",
            },
            .cpu => .{
                "get_core_id",
                "shutdown",
                "get_command_buffer",
            },
            .memory => .{
                "allocate",
            },
            .cpu_memory => .{},
            .command_buffer_submission, .command_buffer_completion => .{
                "map",
            },
            .boot => .{
                "get_bundle_size",
                "get_bundle_file_list_size",
            },
            .process => .{
                "exit",
                "panic",
            },
            .page_table => .{
                "get",
                "get_leaf",
            },
            .memory_mapping => .{},
            .page_table_mapping => .{},
        };

        return CommandBuilder(&extra_command_list);
    }
};

/// Takes some names and integers. Then values are added to the Command enum for an specific capability
/// The number is an offset of the fields with respect to the base command enum fields
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

const DefaultErrorSet = ErrorSet(&.{});
const Types = struct {
    Result: type = void,
    Arguments: type = void,
    ErrorSet: type = DefaultErrorSet,
};

fn CommandDescriptor(comptime capability: Capability, comptime command: Command.fromCapability(capability)) type {
    const type_descriptor: Types = switch (capability) {
        .io => switch (command) {
            .log => .{
                .Result = usize,
                .Arguments = []const u8,
            },
            else => .{},
        },
        .memory => switch (command) {
            .allocate => .{
                .Result = Memory,
                .Arguments = usize,
                .ErrorSet = ErrorSet(&.{"OutOfMemory"}),
            },
            .retype => .{
                .Result = Reference,
                .Arguments = extern struct {
                    source: Memory,
                    destination: Capability,
                },
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
            .get_command_buffer => .{
                .Result = void,
                .Arguments = extern struct {
                    submission_frame: Reference,
                    completion_frame: Reference,
                    options: Command.Buffer.CreateOptions,
                },
            },
            else => .{},
        },
        .boot => switch (command) {
            .get_bundle_file_list_size, .get_bundle_size => .{
                .Result = usize,
            },
            else => .{},
        },
        .command_buffer_completion, .command_buffer_submission => switch (command) {
            .map => .{
                .Result = usize,
                .Arguments = extern struct {
                    frame: Reference,
                    flags: packed struct(u64) {
                        write: bool,
                        execute: bool,
                        reserved: u62 = 0,
                    },
                },
            },
            else => .{},
        },
        .page_table => switch (command) {
            .get => .{
                .Arguments = extern struct {
                    descriptor: PageTable,
                    buffer: *[512]PageTable,
                },
                .ErrorSet = ErrorSet(&.{
                    "index_out_of_bounds",
                    "not_present",
                }),
            },
            .get_leaf => .{
                .Arguments = extern struct {
                    /// This descriptor works for leaves as well
                    descriptor: PageTable,
                    buffer: *Leaf,
                },
                .ErrorSet = ErrorSet(&.{
                    "index_out_of_bounds",
                    "not_present",
                }),
            },
            else => .{},
        },
        else => .{},
    };

    const ToArguments = fn (Raw.Arguments) callconv(.Inline) type_descriptor.ErrorSet.Error!type_descriptor.Arguments;
    const FromArguments = fn (type_descriptor.Arguments) callconv(.Inline) Raw.Arguments;

    const functions = switch (type_descriptor.Result) {
        else => blk: {
            const ToResult = fn (Raw.Result.Birth) callconv(.Inline) type_descriptor.Result;
            const FromResult = fn (type_descriptor.Result) callconv(.Inline) Raw.Result;

            // return if (type_descriptor.Result == void and type_descriptor.Arguments == void and type_descriptor.ErrorSet == DefaultErrorSet) struct {
            break :blk if (type_descriptor.ErrorSet == DefaultErrorSet and type_descriptor.Result == void and type_descriptor.Arguments == void) struct {
                toResult: ToResult = voidToResult,
                fromResult: FromResult = voidFromResult,
                toArguments: ToArguments = voidToArguments,
                fromArguments: FromArguments = voidFromArguments,
            } else if (type_descriptor.ErrorSet == DefaultErrorSet and type_descriptor.Result == void) struct {
                toResult: ToResult = voidToResult,
                fromResult: FromResult = voidFromResult,
                toArguments: ToArguments,
                fromArguments: FromArguments,
            } else if (type_descriptor.ErrorSet == DefaultErrorSet and type_descriptor.Arguments == void) struct {
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
        noreturn => if (type_descriptor.ErrorSet == DefaultErrorSet and type_descriptor.Arguments == void) struct {
            toArguments: ToArguments = voidToArguments,
            fromArguments: FromArguments = voidFromArguments,
        } else struct {
            toArguments: ToArguments,
            fromArguments: FromArguments,
        },
    };

    return struct {
        types: Types = type_descriptor,
        functions: functions,
    };
}

pub fn Descriptor(comptime capability: Capability, comptime command: Command.fromCapability(capability)) type {
    const D = CommandDescriptor(capability, command);
    const T = @as(?*const Types, @ptrCast(@typeInfo(D).Struct.fields[0].default_value)).?.*;
    const d = D{
        .functions = switch (capability) {
            .memory => switch (command) {
                .allocate => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) Memory {
                            return @bitCast(raw_result.second);
                        }

                        inline fn fromResult(result: Memory) Raw.Result {
                            return .{
                                .birth = .{
                                    .first = .{},
                                    .second = @bitCast(result),
                                },
                            };
                        }

                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!usize {
                            const size = raw_arguments[0];
                            return size;
                        }

                        inline fn fromArguments(arguments: usize) Raw.Arguments {
                            const result = [1]usize{arguments};
                            return result ++ .{0} ** (Raw.argument_count - result.len);
                        }
                    };
                    break :blk .{
                        .toResult = F.toResult,
                        .fromResult = F.fromResult,
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                    };
                },
                .retype => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) Reference {
                            return @bitCast(raw_result.second);
                        }

                        inline fn fromResult(result: Reference) Raw.Result {
                            return .{
                                .birth = .{
                                    .first = .{},
                                    .second = @bitCast(result),
                                },
                            };
                        }
                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
                            return T.Arguments{
                                .source = @bitCast(raw_arguments[0]),
                                .destination = @enumFromInt(@as(@typeInfo(Capability).Enum.tag_type, @intCast(raw_arguments[1]))),
                            };
                        }

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            const result = [2]usize{
                                @bitCast(arguments.source),
                                @intFromEnum(arguments.destination),
                            };
                            return result ++ .{0} ** (Raw.argument_count - result.len);
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
            .command_buffer_submission => switch (command) {
                .map => blk: {
                    const struct_helper = StructHelperArguments(T.Arguments);
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) T.Result {
                            _ = raw_result;
                            @panic("TODO: toResult");
                        }

                        inline fn fromResult(result: T.Result) Raw.Result {
                            _ = result;
                            @panic("TODO: fromResult");
                        }

                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
                            const arguments = try struct_helper.toArguments(raw_arguments);
                            if (arguments.flags.execute) {
                                return error.invalid_input;
                            }

                            return arguments;
                        }

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            return struct_helper.fromArguments(arguments);
                        }
                    };
                    break :blk .{
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                        .toResult = F.toResult,
                        .fromResult = F.fromResult,
                    };
                },
                else => .{},
            },
            .command_buffer_completion => switch (command) {
                .map => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) T.Result {
                            _ = raw_result;
                            @panic("TODO: toResult");
                        }

                        inline fn fromResult(result: T.Result) Raw.Result {
                            _ = result;
                            @panic("TODO: fromResult");
                        }

                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
                            _ = raw_arguments;
                            @panic("TODO: toArguments");
                        }

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            _ = arguments;
                            @panic("TODO: fromArguments");
                        }
                    };
                    break :blk .{
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                        .toResult = F.toResult,
                        .fromResult = F.fromResult,
                    };
                },
                else => .{},
            },
            .process => switch (command) {
                .exit => blk: {
                    const F = struct {
                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
                            const result = raw_arguments[0] != 0;
                            return result;
                        }

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            const result = [1]usize{@intFromBool(arguments)};
                            return result ++ .{0} ** (Raw.argument_count - result.len);
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
                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
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

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            const result: [3]usize = .{ @intFromPtr(arguments.message.ptr), arguments.message.len, arguments.exit_code };
                            return result ++ .{0} ** (Raw.argument_count - result.len);
                        }
                    };
                    break :blk .{
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                    };
                },
                else => .{},
            },
            .io => switch (command) {
                .log => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) T.Result {
                            return raw_result.second;
                        }

                        inline fn fromResult(result: T.Result) Raw.Result {
                            return Raw.Result{
                                .birth = .{
                                    .first = .{},
                                    .second = result,
                                },
                            };
                        }

                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
                            const message_ptr = @as(?[*]const u8, @ptrFromInt(raw_arguments[0])) orelse return error.invalid_input;
                            const message_len = raw_arguments[1];
                            if (message_len == 0) return error.invalid_input;
                            const message = message_ptr[0..message_len];
                            return message;
                        }

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            const result = [2]usize{ @intFromPtr(arguments.ptr), arguments.len };
                            return result ++ .{0} ** (Raw.argument_count - result.len);
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
            .cpu => switch (command) {
                .get_core_id => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) T.Result {
                            return @as(T.Result, @intCast(raw_result.second));
                        }

                        inline fn fromResult(result: T.Result) Raw.Result {
                            return Raw.Result{
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
                .get_command_buffer => blk: {
                    const struct_helper = StructHelperArguments(T.Arguments);
                    const F = struct {
                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
                            const args = try struct_helper.toArguments(raw_arguments);

                            if (args.options.submission_entry_count == 0) {
                                return error.invalid_input;
                            }

                            if (args.options.completion_entry_count == 0) {
                                return error.invalid_input;
                            }

                            return args;
                        }

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            return struct_helper.fromArguments(arguments);
                        }
                    };

                    break :blk .{
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                    };
                },
                else => .{},
            },
            .boot => switch (command) {
                .get_bundle_file_list_size, .get_bundle_size => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) T.Result {
                            return raw_result.second;
                        }

                        inline fn fromResult(result: T.Result) Raw.Result {
                            return Raw.Result{
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
            .page_table => switch (command) {
                .get => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) void {
                            _ = raw_result;
                        }

                        inline fn fromResult(result: T.Result) Raw.Result {
                            _ = result;
                            return Raw.Result{
                                .birth = .{
                                    .first = .{},
                                    .second = 0,
                                },
                            };
                        }

                        const struct_helper = StructHelperArguments(T.Arguments);
                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
                            const args = try struct_helper.toArguments(raw_arguments);

                            return args;
                        }

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            return struct_helper.fromArguments(arguments);
                        }
                    };

                    break :blk .{
                        .toResult = F.toResult,
                        .fromResult = F.fromResult,
                        .toArguments = F.toArguments,
                        .fromArguments = F.fromArguments,
                    };
                },
                .get_leaf => blk: {
                    const F = struct {
                        inline fn toResult(raw_result: Raw.Result.Birth) void {
                            _ = raw_result;
                        }

                        inline fn fromResult(result: T.Result) Raw.Result {
                            _ = result;
                            return Raw.Result{
                                .birth = .{
                                    .first = .{},
                                    .second = 0,
                                },
                            };
                        }

                        const struct_helper = StructHelperArguments(T.Arguments);
                        inline fn toArguments(raw_arguments: Raw.Arguments) T.ErrorSet.Error!T.Arguments {
                            const args = try struct_helper.toArguments(raw_arguments);

                            return args;
                        }

                        inline fn fromArguments(arguments: T.Arguments) Raw.Arguments {
                            return struct_helper.fromArguments(arguments);
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
            else => .{},
        },
    };

    return struct {
        pub const Capability = capability;
        pub const Command = command;
        pub const Error = T.ErrorSet.Error;
        pub const Result = T.Result;
        pub const Arguments = T.Arguments;

        pub const toResult = d.functions.toResult;
        pub const fromResult = d.functions.fromResult;
        pub const toArguments = d.functions.toArguments;
        pub const fromArguments = d.functions.fromArguments;

        pub fn fromError(err: Error) Raw.Result {
            const error_enum = switch (err) {
                inline else => |comptime_error| @field(T.ErrorSet.Enum, @errorName(comptime_error)),
            };
            return Raw.Result{
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
            const options = birth.interface.Raw.Options{
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

inline fn voidToResult(raw_result: Raw.Result.Birth) void {
    _ = raw_result;
}

inline fn voidFromResult(result: void) Raw.Result {
    _ = result;

    return .{
        .birth = .{
            .first = .{},
            .second = 0,
        },
    };
}

inline fn voidToArguments(raw_arguments: Raw.Arguments) DefaultErrorSet.Error!void {
    _ = raw_arguments;
}

inline fn voidFromArguments(arguments: void) Raw.Arguments {
    _ = arguments;
    return .{0} ** Raw.argument_count;
}

fn getPacked(comptime T: type) lib.Type.Struct {
    comptime {
        const type_info = @typeInfo(T);
        assert(type_info == .Struct);
        assert(type_info.Struct.layout == .Packed);

        return type_info.Struct;
    }
}

fn encodePackedStruct(comptime T: type, raw: usize) T {
    const Packed = getPacked(T);
    const BackingInteger = Packed.backing_integer.?;
    return switch (BackingInteger) {
        u8, u16, u32, u64 => @bitCast(@as(BackingInteger, raw)),
        else => @compileError("Not supported backing integer"),
    };
}

fn decodePackedStruct(value: anytype) usize {
    _ = getPacked(@TypeOf(value));

    return @bitCast(value);
}

fn ensureUnionCorrectness(comptime union_type_info: lib.Type.Union) void {
    comptime {
        assert(union_type_info.layout == .Extern);
        assert(union_type_info.tag_type == null);
        var first_field = union_type_info.fields[0];
        inline for (union_type_info.fields) |field| {
            if (@sizeOf(field.type) != @sizeOf(first_field.type)) {
                @compileError("All fields must match in size");
            }
        }
    }
}

fn StructHelperArguments(comptime Arguments: type) type {
    return struct {
        fn toArguments(raw_arguments: Raw.Arguments) !Arguments {
            var args = lib.zeroes(Arguments);

            switch (@typeInfo(Arguments)) {
                .Struct => |struct_type_info| switch (struct_type_info.layout) {
                    .Extern => inline for (struct_type_info.fields, 0..) |argument_field, index| {
                        const raw_argument = raw_arguments[index];
                        @field(args, argument_field.name) = switch (@sizeOf(argument_field.type) == @sizeOf(@TypeOf(raw_arguments[0]))) {
                            true => switch (@typeInfo(argument_field.type)) {
                                .Pointer => @as(?argument_field.type, @ptrFromInt(raw_argument)) orelse return error.invalid_input,
                                else => @bitCast(raw_argument),
                            },
                            false => @bitCast(lib.cast(@Type(.{
                                .Int = .{
                                    .signedness = .unsigned,
                                    .bits = @bitSizeOf(argument_field.type),
                                },
                            }), raw_argument) orelse return error.corrupted_input),
                        };
                    },
                    .Auto => @compileError("Auto structs are forbidden for Birth ABI"),
                    .Packed => {
                        args = encodePackedStruct(Arguments, raw_arguments[0]);
                    },
                },
                .Union => |union_type_info| {
                    ensureUnionCorrectness(union_type_info);

                    const FirstFieldType = union_type_info.fields[0].type;
                    switch (@typeInfo(FirstFieldType)) {
                        .Struct => |struct_type_info| switch (struct_type_info.layout) {
                            .Extern => @compileError("TODO: extern structs"),
                            .Auto => @compileError("Auto structs are forbidden for Birth ABI"),
                            .Packed => {
                                args = @bitCast(encodePackedStruct(FirstFieldType, raw_arguments[0]));
                            },
                        },
                        else => @compileError("TODO: " ++ @typeName(FirstFieldType)),
                    }
                },
                else => |unknown_type_info| @compileError("TODO: " ++ @tagName(unknown_type_info)),
            }

            return args;
        }

        fn fromArguments(arguments: Arguments) Raw.Arguments {
            var raw_arguments: Raw.Arguments = .{0} ** Raw.argument_count;
            switch (@typeInfo(Arguments)) {
                .Struct => |struct_type_info| switch (struct_type_info.layout) {
                    .Extern => {
                        inline for (lib.fields(@TypeOf(arguments)), 0..) |argument_field, index| {
                            const arg_value = @field(arguments, argument_field.name);
                            raw_arguments[index] = switch (@sizeOf(argument_field.type) == @sizeOf(@TypeOf(raw_arguments[0]))) {
                                true => switch (@typeInfo(argument_field.type)) {
                                    .Pointer => @intFromPtr(arg_value),
                                    else => @bitCast(arg_value),
                                },
                                false => @as(@Type(.{
                                    .Int = .{
                                        .signedness = .unsigned,
                                        .bits = @bitSizeOf(argument_field.type),
                                    },
                                }), @bitCast(arg_value)),
                            };
                        }
                    },
                    .Packed => {
                        raw_arguments[0] = @as(@TypeOf(raw_arguments[0]), @bitCast(arguments));
                    },
                    .Auto => @compileError("Auto structs are forbidden for Birth ABI"),
                },
                .Union => |union_type_info| {
                    comptime {
                        assert(union_type_info.layout == .Extern);
                    }
                },
                else => |unknown_type_info| @compileError("TODO: " ++ @tagName(unknown_type_info)),
            }

            return raw_arguments;
        }
    };
}

pub const Raw = extern struct {
    pub const Arguments = [argument_count]usize;
    pub const argument_count = 6;

    pub const Convention = enum(u1) {
        emulated = 0,
        birth = 1,
    };

    pub const Options = extern union {
        general: General,
        birth: Birth,
        emulated: EmulatedOperatingSystem,

        pub const General = packed struct(u64) {
            number: Number,
            convention: Convention,

            pub const Number = @Type(.{
                .Int = .{
                    .signedness = .unsigned,
                    .bits = union_space_bits,
                },
            });

            comptime {
                assertSize(@This());
            }

            pub inline fn getNumberInteger(general: General, comptime convention: Convention) NumberIntegerType(convention) {
                const options_integer = @as(u64, @bitCast(general));
                return @as(NumberIntegerType(convention), @truncate(options_integer));
            }

            pub fn NumberIntegerType(comptime convention: Convention) type {
                return switch (convention) {
                    .birth => birth.IDInteger,
                    .emulated => u64,
                };
            }
        };

        pub const Birth = packed struct(u64) {
            type: Capability,
            command: Command.Type,
            reserved: ReservedInt = 0,
            convention: Convention = .birth,

            const ReservedInt = @Type(.{
                .Int = .{
                    .signedness = .unsigned,
                    .bits = @bitSizeOf(u64) - @bitSizeOf(Capability) - @bitSizeOf(Command.Type) - @bitSizeOf(Convention),
                },
            });

            comptime {
                Options.assertSize(@This());
            }

            // const IDInteger = u16;
            // pub const ID = enum(IDInteger) {
            //     qemu_exit = 0,
            //     print = 1,
            // };
        };

        pub const EmulatedOperatingSystem = enum(u64) {
            _,
            comptime {
                Options.assertSize(@This());
            }
        };

        pub const union_space_bits = @bitSizeOf(u64) - @bitSizeOf(Convention);

        fn assertSize(comptime T: type) void {
            assert(@sizeOf(T) == @sizeOf(u64));
            assert(@bitSizeOf(T) == @bitSizeOf(u64));
        }

        comptime {
            assertSize(@This());
        }
    };

    pub const Result = extern union {
        general: General,
        birth: Birth,
        emulated: EmulatedOperatingSystem,

        pub const General = extern struct {
            first: packed struct(u64) {
                argument: u63,
                convention: Convention,
            },
            second: u64,
        };

        pub const Birth = extern struct {
            first: First,
            second: Second,

            pub const First = packed struct(u64) {
                padding: u48 = 0,
                @"error": u15 = 0,
                convention: Convention = .birth,
            };

            pub const Second = u64;
        };

        pub const EmulatedOperatingSystem = extern struct {
            result: u64,
            reserved: u64 = 0,
        };

        fn assertSize(comptime T: type) void {
            assert(@sizeOf(T) == @sizeOf(u64));
            assert(@bitSizeOf(T) == @bitSizeOf(u64));
        }
    };
};

pub const Leaf = extern struct {
    mapped_physical: birth.interface.Memory,
    own_physical: birth.interface.Memory,
    flags: Flags,

    pub const Flags = packed struct(u64) {
        foo: u64 = 0,
    };
};
