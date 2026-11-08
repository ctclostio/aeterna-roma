#include "vfs_dispatch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static const rome2_vfs_open_dispatch32 sentinel = {{0x12345678}, {0x87654321}, 0xabcdef01};

static void put32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value; bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16); bytes[3] = (uint8_t)(value >> 24);
}

static void unchanged(const rome2_vfs_open_dispatch32 *out)
{
    CHECK(out->interface_address.value == sentinel.interface_address.value &&
        out->vtable_address.value == sentinel.vtable_address.value && out->open_target == sentinel.open_target);
}

static void alignment_and_truncation(void)
{
    const struct { uint32_t table, target; } candidates[] = {
        {0x11897994, 0x112bd0c0}, {0x118978e8, 0x112bd3b0}
    };
    size_t i, object_residue, table_residue, extent;
    for (i = 0; i < sizeof candidates / sizeof candidates[0]; ++i) {
        for (object_residue = 0; object_residue < 8; ++object_residue) {
            for (table_residue = 0; table_residue < 8; ++table_residue) {
                uint8_t object_bytes[12], table_bytes[12];
                const rome2_guest_addr32 manager = {0x41000001 + (uint32_t)object_residue};
                const uint32_t table = candidates[i].table + (uint32_t)table_residue;
                rome2_guest_read_view objects = {object_bytes + object_residue, manager.value + 4, 4};
                rome2_guest_read_view tables = {table_bytes + table_residue, table + 4, 4};
                rome2_vfs_open_dispatch32 out;
                memset(object_bytes, 0xa5, sizeof object_bytes); memset(table_bytes, 0x5a, sizeof table_bytes);
                put32(object_bytes + object_residue, table); put32(table_bytes + table_residue, candidates[i].target);
                CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_OK);
                CHECK(out.interface_address.value == manager.value + 4 && out.vtable_address.value == table &&
                    out.open_target == candidates[i].target);
                CHECK(object_bytes[11] == 0xa5 && table_bytes[11] == 0x5a);
                /* Map only the selected cells, so reading the primary table
                 * or slot zero would fail instead of accidentally passing. */
                for (extent = 0; extent < 4; ++extent) {
                    objects.byte_count = extent; out = sentinel;
                    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_RANGE_ERROR);
                    unchanged(&out); objects.byte_count = 4;
                    tables.byte_count = extent;
                    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_RANGE_ERROR);
                    unchanged(&out); tables.byte_count = 4;
                }
            }
        }
    }
}

static void static_and_active_identities(void)
{
    uint8_t objects_bytes[8], table_bytes[8];
    const rome2_guest_addr32 fallback = {0x119e1004}, active = {0x80000001};
    rome2_guest_read_view objects = {objects_bytes, fallback.value, sizeof objects_bytes};
    rome2_guest_read_view tables = {table_bytes, 0x11897994, sizeof table_bytes};
    rome2_vfs_open_dispatch32 out;
    put32(objects_bytes, 0x1189791c); put32(objects_bytes + 4, 0x11897994);
    put32(table_bytes, 0x112bd0c0); put32(table_bytes + 4, 0x112bd0c0);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, fallback, &tables, &out) == ROME2_VFS_DISPATCH_OK);
    CHECK(out.interface_address.value == 0x119e1008 && out.vtable_address.value == 0x11897994 && out.open_target == 0x112bd0c0);
    objects.guest_base = active.value; tables.guest_base = 0x118978e8;
    put32(objects_bytes, 0x11897870); put32(objects_bytes + 4, 0x118978e8);
    put32(table_bytes, 0x112bd130); put32(table_bytes + 4, 0x112bd3b0);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, active, &tables, &out) == ROME2_VFS_DISPATCH_OK);
    CHECK(out.interface_address.value == 0x80000005 && out.vtable_address.value == 0x118978e8 && out.open_target == 0x112bd3b0);
}

static void errors_and_endpoints(void)
{
    uint8_t object_bytes[4], table_bytes[4];
    rome2_guest_addr32 manager = {0xfffffff8}, zero = {0};
    rome2_guest_read_view objects = {object_bytes, 0xfffffffc, sizeof object_bytes};
    rome2_guest_read_view tables = {table_bytes, 0x118978ec, sizeof table_bytes};
    rome2_vfs_open_dispatch32 out = sentinel;
    put32(object_bytes, 0x118978e8); put32(table_bytes, 0x112bd3b0);
    CHECK(rome2_vfs_read_open_dispatch32(NULL, manager, &tables, &out) == ROME2_VFS_DISPATCH_BAD_ARGUMENT);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, NULL, &out) == ROME2_VFS_DISPATCH_BAD_ARGUMENT);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, NULL) == ROME2_VFS_DISPATCH_BAD_ARGUMENT);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, zero, &tables, &out) == ROME2_VFS_DISPATCH_BAD_ARGUMENT);
    unchanged(&out);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_OK);
    CHECK(out.interface_address.value == 0xfffffffc && out.open_target == 0x112bd3b0);
    out = sentinel; manager.value = 0xfffffffc;
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_RANGE_ERROR);
    unchanged(&out); manager.value = 0xfffffff9;
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_RANGE_ERROR);
    unchanged(&out); manager.value = 0xfffffff8;
    put32(object_bytes, 0xfffffff8); tables.guest_base = 0xfffffffc;
    put32(table_bytes, 0xfffffffe);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_OK);
    CHECK(out.vtable_address.value == 0xfffffff8 && out.open_target == 0xfffffffe);
    out = sentinel; put32(object_bytes, 0xfffffffc);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_RANGE_ERROR);
    unchanged(&out); put32(object_bytes, 0xfffffff9);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_RANGE_ERROR);
    unchanged(&out); put32(object_bytes, 0);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_NULL_TABLE);
    unchanged(&out); put32(object_bytes, 0xfffffff8); put32(table_bytes, 0);
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_NULL_TARGET);
    unchanged(&out); objects.host_base = NULL;
    CHECK(rome2_vfs_read_open_dispatch32(&objects, manager, &tables, &out) == ROME2_VFS_DISPATCH_RANGE_ERROR);
    unchanged(&out);
}

int main(void)
{
    static_and_active_identities(); alignment_and_truncation(); errors_and_endpoints();
    printf("VFS dispatch: %zu checks; secondary-interface slot, split views, 8x8 alignments, truncation and 32-bit boundaries\n", checks);
    return 0;
}
