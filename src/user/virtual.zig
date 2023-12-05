const Virtual = @This();

const birth = @import("birth");
const lib = @import("lib");
const user = @import("user");

const assert = lib.assert;
const log = lib.log;
const SparseArray = lib.data_structures.SparseArray;
const VirtualAddress = lib.VirtualAddress;

const paging = lib.arch.paging;

const Leaf = birth.interface.Leaf;

pub const AddressSpace = extern struct {
    // page_table: PageTable,
    region: Virtual.AddressSpace.Region = .{},
    minimum: VirtualAddress = VirtualAddress.new(paging.user_address_space_start),
    maximum: VirtualAddress = VirtualAddress.new(paging.user_address_space_end),
    root_page_table: PageTable = .{},
    page_table_buffer: SparseArray(PageTable) = .{
        .ptr = undefined,
        .len = 0,
        .capacity = 0,
    },
    leaf_buffer: SparseArray(Leaf) = .{
        .ptr = undefined,
        .len = 0,
        .capacity = 0,
    },

    const Region = extern struct {
        list: Virtual.Region.List = .{},
        block_count: usize = 0,
    };

    pub fn create() !*AddressSpace {
        const scheduler = user.currentScheduler();
        const virtual_address_space = try scheduler.fast_allocator.create(AddressSpace);
        virtual_address_space.* = .{};

        try virtual_address_space.collectPageTables(&virtual_address_space.root_page_table, .{});

        @panic("TODO: create");
    }

    fn collectPageTables(virtual_address_space: *Virtual.AddressSpace, page_table: *PageTable, descriptor: birth.interface.PageTable) !void {
        try user.Interface(.page_table, .get).blocking(.{
            .descriptor = descriptor,
            .buffer = &page_table.children_handles,
        });

        const allocator = &user.currentScheduler().fast_allocator;

        for (page_table.children_handles, &page_table.indices) |child, *index| {
            if (child.present) {
                switch (child.entry_type) {
                    .page_table => {
                        const page_table_index = virtual_address_space.page_table_buffer.len;
                        const new_page_table = try virtual_address_space.page_table_buffer.allocate(allocator);
                        //user.currentScheduler().fast_allocator.create(PageTable);
                        index.* = @intCast(page_table_index);

                        try virtual_address_space.collectPageTables(new_page_table, child);
                    },
                    .leaf => {
                        const new_leaf = try virtual_address_space.leaf_buffer.allocate(allocator);
                        index.* = @intCast(virtual_address_space.leaf_buffer.indexOf(new_leaf));
                        try getLeaf(child, new_leaf);
                        log.debug("New leaf: {}", .{new_leaf});
                    },
                }
            }
        }
    }

    fn getLeaf(leaf_descriptor: birth.interface.PageTable, leaf: *Leaf) !void {
        try user.Interface(.page_table, .get_leaf).blocking(.{
            .descriptor = leaf_descriptor,
            .buffer = leaf,
        });
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

pub const PageTable = extern struct {
    children_handles: [512]birth.interface.PageTable = .{.{}} ** 512,
    indices: [512]u32 = .{0} ** 512,
};
