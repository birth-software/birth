const lib = @import("lib");
const log = lib.log;
const assert = lib.assert;
const birth = @import("birth");
const user = @import("user");
const Interface = user.Interface;

const Command = birth.interface.Command;

// TODO: ref
pub fn frameCreate(bytes: usize) !birth.capabilities.RAM {
    return mappableCapabilityCreate(.cpu_memory, bytes);
}

const CommandBufferFrameType = enum {
    command_buffer_completion,
    command_buffer_submission,
};

pub fn setupCommandFrame(comptime QueueType: type, entry_count: usize) !void {
    assert(entry_count > 0);
    comptime assert(@alignOf(QueueType) <= @sizeOf(QueueType.Header));
    const total_size = lib.alignForward(usize, @sizeOf(QueueType.Header) + entry_count * @sizeOf(QueueType), lib.arch.valid_page_sizes[0]);
    const capability = switch (QueueType) {
        Command.Submission => .command_buffer_submission,
        Command.Completion => .command_buffer_completion,
        else => @compileError("Unexpected type"),
    };

    const allocation = try Interface(.ram, .allocate).blocking(total_size);
    const dst_cap_frame = try retype(@bitCast(allocation), capability);
    const flags = .{
        .write = QueueType == Command.Submission,
        .execute = false,
    };
    _ = try Interface(capability, .map).blocking(.{
        .frame = dst_cap_frame,
        .flags = flags,
    });

    @panic("TODO: setup frame");
}

fn mappableCapabilityCreate(capability: birth.capabilities.Type.Mappable, bytes: usize) !birth.capabilities.RAM {
    assert(bytes > 0);

    return RamDescendant.create(capability, bytes);
}

const Ram = extern struct {
    pub fn allocate(size: usize) !usize {
        _ = size;
        log.err("TODO: allocate", .{});
        return error.not_implemented;
    }
};

const RamDescendant = extern struct {
    capability: usize,
    size: usize,

    pub fn create(capability: birth.capabilities.Type.Mappable, size: usize) !birth.capabilities.RAM {
        const allocation = try Interface(.ram, .allocate).blocking(size);
        const generic_capability = switch (capability) {
            inline else => |mappable_cap| @field(birth.interface.Capability, @tagName(mappable_cap)),
        };
        const result = try retype(@bitCast(allocation), generic_capability);

        // TODO: check if the previous capability needs to be deleted (because maybe it should be deleted at the retype operation
        // try destroy(@bitCast(allocation));
        return @bitCast(result);
    }
};

// TODO: make this more complex and generic to handle all cases
pub fn retype(source: birth.interface.Reference, capability: birth.interface.Capability) !birth.interface.Reference {
    const new_reference = try Interface(.ram, .retype).blocking(.{ .source = @bitCast(source), .destination = capability });
    return new_reference;
}

pub fn destroy(capability: birth.capabilities.Reference) !void {
    _ = capability;
    log.err("TODO: destroy", .{});
    return error.not_implemented;
}
