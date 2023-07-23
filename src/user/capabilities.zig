const lib = @import("lib");
const log = lib.log;
const assert = lib.assert;
const birth = @import("birth");
const user = @import("user");
const Syscall = user.Syscall;

// TODO: ref
pub fn frameCreate(bytes: usize) !birth.capabilities.Reference {
    return mappableCapabilityCreate(.cpu_memory, bytes);
}

fn mappableCapabilityCreate(capability: birth.capabilities.Type.Mappable, bytes: usize) !birth.capabilities.Reference {
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

    pub fn create(capability: birth.capabilities.Type.Mappable, size: usize) !birth.capabilities.Reference {
        const allocation = try Syscall(.ram, .allocate).blocking(size);
        const result = try retype(allocation, 0, capability.toCapability(), size, 1);
        try destroy(allocation);
        return result;
    }
};

pub fn retype(source: birth.capabilities.Reference, offset: usize, capability: birth.capabilities.Type, object_size: usize, object_count: usize) !birth.capabilities.Reference {
    _ = object_count;
    _ = object_size;
    _ = capability;
    _ = offset;
    _ = source;
    log.err("TODO: retype", .{});
    return error.not_implemented;
}

pub fn destroy(capability: birth.capabilities.Reference) !void {
    _ = capability;
    log.err("TODO: destroy", .{});
    return error.not_implemented;
}
