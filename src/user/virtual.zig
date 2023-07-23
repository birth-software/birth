const Virtual = @This();

const birth = @import("birth");
const lib = @import("lib");
const user = @import("user");

const assert = lib.assert;
const log = lib.log;
const VirtualAddress = lib.VirtualAddress;

const paging = lib.arch.paging;

pub const AddressSpace = extern struct {
    // page_table: PageTable,
    region: Virtual.AddressSpace.Region,
    minimum: VirtualAddress = VirtualAddress.new(paging.user_address_space_start),
    maximum: VirtualAddress = VirtualAddress.new(paging.user_address_space_end),

    const Region = extern struct {
        list: Virtual.Region.List = .{},
        block_count: usize = 0,
    };

    pub fn create() !*AddressSpace {
        const scheduler = user.currentScheduler();
        const virtual_address_space = try scheduler.common.heapAllocateFast(AddressSpace);
        virtual_address_space.* = .{
            .page_table = undefined,
            .region = .{},
        };

        virtual_address_space.collectPageTables(0, 0, 0, &virtual_address_space.page_table.root.u.page_table.children);

        @panic("TODO: create");
    }

    fn collectPageTables(virtual_address_space: *AddressSpace, block: u7, index: u7, level: usize, page_table_buffer: *[512]birth.interface.PageTable) !void {
        _ = virtual_address_space;
        try user.Interface(.page_table, .get).blocking(.{
            .descriptor = .{
                .block = block,
                .index = index,
                .entry_type = .page_table,
            },
            .buffer = page_table_buffer,
        });

        for (page_table_buffer, 0..) |page_table_entry, i| {
            _ = i;
            if (page_table_entry.present) {
                switch (page_table_entry.entry_type) {
                    .page_table => {
                        const scheduler = user.currentScheduler();
                        const buffer = try scheduler.common.heapAllocateFast([512]birth.interface.PageTable);
                        collectPageTables(page_table_entry.block, page_table_entry.index, level + 1, buffer) catch unreachable;
                    },
                    .leaf => {
                        log.err("Leaf: {}", .{page_table_entry});
                    },
                }
            }
        }
    }
};

pub const Region = extern struct {
    foo: u32 = 0,

    pub const List = extern struct {
        regions: [region_count]Region = .{.{}} ** region_count,
        next: ?*List = null,

        const region_count = 20;
    };
};

// fn newPageTableNode(page_table: Virtual.PageTable.Node.PageTable, level: paging.Level) PageTable.Node {
//     return .{
//         .flags = .{
//             .type = .page_table,
//             .level = level,
//         },
//         .u = .{
//             .page_table = page_table,
//         },
//     };
// }

// pub const PageTable = extern struct {
//     root: Node,
//     foo: u32 = 0,
//
//     pub const Node = extern struct {
//         flags: Flags,
//         u: extern union {
//             leaf: Leaf,
//             page_table: Node.PageTable,
//         },
//
//         pub const Flags = packed struct(u32) {
//             type: birth.interface.PageTable.EntryType,
//             level: paging.Level,
//             reserved: u29 = 0,
//         };
//
//         pub const Leaf = extern struct {
//             foo: u32 = 0,
//         };
//
//         pub const PageTable = extern struct {
//             foo: u32 = 0,
//             children: Buffer = .{.{ .entry_type = .page_table }} ** node_count,
//         };
//     };
//
//     const node_count = paging.page_table_entry_count;
//     pub const Buffer = [node_count]birth.interface.PageTable;
// };
