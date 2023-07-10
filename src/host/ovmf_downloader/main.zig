const host = @import("host");

const Error = error{
    wrong_arguments,
};

pub fn main() !void {
    const allocator = @import("std").heap.page_allocator;
    const arguments = try host.allocateArguments(allocator);
    if (arguments.len != 2) {
        return Error.wrong_arguments;
    }

    const ovmf_path = arguments[1];

    const file_descriptor = blk: {
        if (host.fs.openFileAbsolute(ovmf_path, .{})) |file_descriptor| {
            break :blk file_descriptor;
        } else |_| {
            const url = "https://retrage.github.io/edk2-nightly/bin/RELEASEX64_OVMF.fd";
            const uri = try host.Uri.parse(url);

            var http_client = host.http.Client{ .allocator = allocator };
            defer http_client.deinit();

            var request_headers = host.http.Headers{ .allocator = allocator };
            defer request_headers.deinit();

            var request = try http_client.request(.GET, uri, request_headers, .{});
            defer request.deinit();

            try request.start();
            try request.wait();

            if (request.response.status != .ok) {
                return error.ResponseNotOk;
            }

            const content_length = request.response.content_length orelse {
                return error.OutOfMemory;
            };

            const buffer = try allocator.alloc(u8, content_length);
            const read_byte_count = try request.readAll(buffer);
            if (read_byte_count != buffer.len) {
                return error.OutOfMemory;
            }

            const ovmf_file_descriptor = try host.fs.createFileAbsolute(ovmf_path, .{});
            try ovmf_file_descriptor.writeAll(buffer);

            break :blk ovmf_file_descriptor;
        }
    };

    file_descriptor.close();
}
