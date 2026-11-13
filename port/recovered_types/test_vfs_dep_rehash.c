#include <stdio.h>
#include <string.h>

#include "vfs_dep_rehash.h"

static rome2_guest_addr32 addr32(uint32_t value)
{
    rome2_guest_addr32 a;
    a.value = value;
    return a;
}

static void write_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xffu);
    dst[1] = (uint8_t)((value >> 8u) & 0xffu);
    dst[2] = (uint8_t)((value >> 16u) & 0xffu);
    dst[3] = (uint8_t)((value >> 24u) & 0xffu);
}

static void write_dep_node(
    uint8_t *buf,
    uint32_t offset,
    uint32_t left,
    uint32_t parent,
    uint32_t right,
    uint8_t color,
    uint8_t is_nil,
    uint32_t a0,
    uint32_t b0)
{
    uint8_t *p = buf + offset;
    write_u32_le(p + 0x00u, left);
    write_u32_le(p + 0x04u, parent);
    write_u32_le(p + 0x08u, right);
    p[0x0cu] = color;
    p[0x0du] = is_nil;
    p[0x0eu] = 0u;
    p[0x0fu] = 0u;
    write_u32_le(p + 0x10u, a0);
    write_u32_le(p + 0x14u, 0u);
    write_u32_le(p + 0x18u, 0u);
    write_u32_le(p + 0x1cu, b0);
    write_u32_le(p + 0x20u, 0u);
    write_u32_le(p + 0x24u, 0u);
}

static int test_u32_triplet_less(
    const uint32_t lhs[3],
    const uint32_t rhs[3],
    void *ctx,
    int *out_is_less)
{
    int *fail_flag = (int *)ctx;
    size_t i = 0u;

    if (fail_flag != NULL && *fail_flag != 0) {
        return -1;
    }
    for (i = 0u; i < 3u; ++i) {
        if (lhs[i] != rhs[i]) {
            *out_is_less = (lhs[i] < rhs[i]) ? 1 : 0;
            return 0;
        }
    }
    *out_is_less = 0;
    return 0;
}

static int check_rehash_target(void)
{
    uint32_t out = 0x12345678u;
    const uint32_t load_1_0 = 0x3f800000u;
    const uint32_t load_0_75 = 0x3f400000u;
    const uint32_t nan_bits = 0x7fc00000u;
    const uint32_t neg_bits = 0xbf800000u;

    if (rome2_vfs_compute_rehash_target32(8u, 0u, load_1_0, NULL) != ROME2_VFS_REG_BAD_ARGUMENT) {
        return 1;
    }
    if (rome2_vfs_compute_rehash_target32(8u, 5u, 0u, &out) != ROME2_VFS_REG_INVALID_STATE ||
        out != 0x12345678u) {
        return 2;
    }
    if (rome2_vfs_compute_rehash_target32(8u, 5u, nan_bits, &out) != ROME2_VFS_REG_INVALID_STATE ||
        out != 0x12345678u) {
        return 3;
    }
    if (rome2_vfs_compute_rehash_target32(8u, 5u, neg_bits, &out) != ROME2_VFS_REG_INVALID_STATE ||
        out != 0x12345678u) {
        return 4;
    }
    if (rome2_vfs_compute_rehash_target32(16u, 5u, load_0_75, &out) != ROME2_VFS_REG_OK ||
        out != 16u) {
        return 5;
    }
    /* 10 / 0.75 = 13.333... -> ceilf = 14 */
    if (rome2_vfs_compute_rehash_target32(4u, 10u, load_0_75, &out) != ROME2_VFS_REG_OK ||
        out != 14u) {
        return 6;
    }
    /* Overflow past 2^32 fails closed and preserves output. */
    out = 0xabcdef01u;
    if (rome2_vfs_compute_rehash_target32(4u, 0xffffffffu, 0x3e800000u, &out) != ROME2_VFS_REG_RANGE_ERROR ||
        out != 0xabcdef01u) {
        return 7;
    }
    return 0;
}

static int check_dep_rb_decode_and_count(void)
{
    uint8_t mem[0xa0];
    const uint32_t base = 0x20000000u;
    const rome2_guest_read_view view = {mem, base, sizeof(mem)};
    rome2_vfs_dep_rb_node32 decoded;
    uint32_t count = 77u;

    memset(mem, 0, sizeof(mem));
    /* Sentinel head at +0x00, root at +0x28, left child at +0x50, right child at +0x78 */
    write_dep_node(mem, 0x00u, base + 0x50u, base + 0x28u, base + 0x78u, 1u, 1u, 0u, 0u);
    write_dep_node(mem, 0x28u, base + 0x50u, base + 0x00u, base + 0x78u, 1u, 0u, 20u, 200u);
    write_dep_node(mem, 0x50u, base + 0x00u, base + 0x28u, base + 0x00u, 0u, 0u, 10u, 100u);
    write_dep_node(mem, 0x78u, base + 0x00u, base + 0x28u, base + 0x00u, 0u, 0u, 30u, 300u);

    memset(&decoded, 0x5a, sizeof(decoded));
    if (rome2_vfs_decode_dep_rb_node32(&view, addr32(base + 0x28u), &decoded) != ROME2_VFS_REG_OK) {
        return 10;
    }
    if (decoded.is_nil != 0u || decoded.color != 1u ||
        decoded.name_a[0] != 20u || decoded.name_b[0] != 200u) {
        return 11;
    }

    decoded.name_a[0] = 0xfeedfaceu;
    if (rome2_vfs_decode_dep_rb_node32(&view, addr32(base + 0x80u), &decoded) != ROME2_VFS_REG_RANGE_ERROR ||
        decoded.name_a[0] != 0xfeedfaceu) {
        return 12;
    }

    if (rome2_vfs_count_dep_rb_nodes32(&view, addr32(base), 32u, &count) != ROME2_VFS_REG_OK ||
        count != 3u) {
        return 13;
    }

    count = 99u;
    if (rome2_vfs_count_dep_rb_nodes32(&view, addr32(base), 2u, &count) != ROME2_VFS_REG_STEP_LIMIT ||
        count != 99u) {
        return 14;
    }

    /* Non-nil head rejected without modifying out_node_count. */
    mem[0x0du] = 0u;
    if (rome2_vfs_count_dep_rb_nodes32(&view, addr32(base), 32u, &count) != ROME2_VFS_REG_INVALID_STATE ||
        count != 99u) {
        return 15;
    }

    /* Restore sentinel head, inject self-loop on right child -> rejected cleanly. */
    mem[0x0du] = 1u;
    write_u32_le(mem + 0x78u + 0x08u, base + 0x78u);
    if (rome2_vfs_count_dep_rb_nodes32(&view, addr32(base), 32u, &count) != ROME2_VFS_REG_INVALID_STATE ||
        count != 99u) {
        return 16;
    }

    return 0;
}

static int check_pair_compare_and_vtables(void)
{
    const uint32_t k1[3] = {10u, 1u, 0u};
    const uint32_t k2[3] = {10u, 2u, 0u};
    const uint32_t k3[3] = {20u, 0u, 0u};
    int32_t order = 123;
    int fail_flag = 0;
    uint8_t vt_mem[0x20];
    const uint32_t vt_base = 0x1189a424u;
    const rome2_guest_read_view vt_view = {vt_mem, vt_base, sizeof(vt_mem)};
    rome2_vfs_ref_block_vtable32 ref_vt;
    rome2_vfs_stream_wrap_vtable_prefix32 wrap_vt;
    uint32_t off = 0xdeadbeefu;

    if (rome2_vfs_dep_pair_compare32(k1, k2, k3, k1, test_u32_triplet_less, &fail_flag, &order) != ROME2_VFS_REG_OK ||
        order != -1) {
        return 20;
    }
    if (rome2_vfs_dep_pair_compare32(k1, k3, k1, k2, test_u32_triplet_less, &fail_flag, &order) != ROME2_VFS_REG_OK ||
        order != 1) {
        return 21;
    }
    if (rome2_vfs_dep_pair_compare32(k2, k1, k2, k1, test_u32_triplet_less, &fail_flag, &order) != ROME2_VFS_REG_OK ||
        order != 0) {
        return 22;
    }
    fail_flag = 1;
    order = 55;
    if (rome2_vfs_dep_pair_compare32(k1, k1, k2, k2, test_u32_triplet_less, &fail_flag, &order) != ROME2_VFS_REG_INVALID_STATE ||
        order != 55) {
        return 23;
    }

    write_u32_le(vt_mem + 0x00u, 0x112afce0u);
    write_u32_le(vt_mem + 0x04u, 0x1090bb10u);
    write_u32_le(vt_mem + 0x08u, 0x112acd50u);
    write_u32_le(vt_mem + 0x0cu, 0x10128c50u);
    write_u32_le(vt_mem + 0x10u, 0x112da9f0u);
    write_u32_le(vt_mem + 0x14u, 0x112c8b80u);
    write_u32_le(vt_mem + 0x18u, 0x112d9860u);
    write_u32_le(vt_mem + 0x1cu, 0x112badf0u);

    memset(&ref_vt, 0, sizeof(ref_vt));
    if (rome2_vfs_decode_ref_block_vtable32(&vt_view, addr32(vt_base), &ref_vt) != ROME2_VFS_REG_OK ||
        ref_vt.destroy_embedded != 0x112afce0u ||
        ref_vt.scalar_deleting_dtor != 0x112acd50u) {
        return 24;
    }
    memset(&wrap_vt, 0, sizeof(wrap_vt));
    if (rome2_vfs_decode_stream_wrap_vtable_prefix32(&vt_view, addr32(vt_base), &wrap_vt) != ROME2_VFS_REG_OK ||
        wrap_vt.slot_01c != 0x112badf0u) {
        return 25;
    }

    write_u32_le(vt_mem + 0x0cu, 0u);
    ref_vt.destroy_embedded = 0x11111111u;
    if (rome2_vfs_decode_ref_block_vtable32(&vt_view, addr32(vt_base), &ref_vt) != ROME2_VFS_REG_INVALID_STATE ||
        ref_vt.destroy_embedded != 0x11111111u) {
        return 26;
    }

    if (rome2_vfs_open_pack_stride20_slot_offset32(8u, 15u, 2u, &off) != ROME2_VFS_REG_OK ||
        off != 1u * ROME2_VFS_OPEN_PACK_SLOT_STRIDE) {
        return 27;
    }
    off = 0xdeadbeefu;
    if (rome2_vfs_open_pack_stride20_slot_offset32(8u, 15u, 8u, &off) != ROME2_VFS_REG_BAD_ARGUMENT ||
        off != 0xdeadbeefu) {
        return 28;
    }
    if (rome2_vfs_open_pack_stride20_slot_offset32(0x10000000u, 0x0ffffff0u, 0u, &off) != ROME2_VFS_REG_RANGE_ERROR ||
        off != 0xdeadbeefu) {
        return 29;
    }
    return 0;
}

int main(void)
{
    int rc = check_rehash_target();
    if (rc != 0) {
        fprintf(stderr, "rehash_target failed: %d\n", rc);
        return rc;
    }
    rc = check_dep_rb_decode_and_count();
    if (rc != 0) {
        fprintf(stderr, "dep_rb_decode_and_count failed: %d\n", rc);
        return rc;
    }
    rc = check_pair_compare_and_vtables();
    if (rc != 0) {
        fprintf(stderr, "pair_compare_and_vtables failed: %d\n", rc);
        return rc;
    }
    printf("vfs_dep_rehash_tests: 23 checks passed (0 failures)\n");
    return 0;
}
