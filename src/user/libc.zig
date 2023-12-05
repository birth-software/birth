const user = @import("user");

pub export fn malloc(size: usize) ?*anyopaque {
    _ = size;
    @panic("TODO: malloc");
}
