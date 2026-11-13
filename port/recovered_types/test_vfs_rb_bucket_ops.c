#include <stdio.h>
#include <string.h>

#include "vfs_rb_bucket_ops.h"

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

static int check_rb_and_hash_bucket_math(void)
{
    uint32_t out = 0x11223344u;
    uint32_t buckets = 0x55667788u;
    uint32_t ptrs = 0x99aabbccu;
    const uint32_t load_1_0 = 0x3f800000u;
    const uint32_t load_0_5 = 0x3f000000u;
    const uint32_t nan_bits = 0x7fc00000u;

    if (rome2_vfs_dep_rb_can_allocate32(0x06666664u, &out) != ROME2_VFS_REG_OK ||
        out != 0x06666665u) {
        return 1;
    }
    out = 0xabcdef01u;
    if (rome2_vfs_dep_rb_can_allocate32(0x06666665u, &out) != ROME2_VFS_REG_RANGE_ERROR ||
        out != 0xabcdef01u) {
        return 2;
    }

    if (rome2_vfs_hash_next_power_of_2_buckets32(0u, &buckets, &ptrs) != ROME2_VFS_REG_BAD_ARGUMENT ||
        buckets != 0x55667788u || ptrs != 0x99aabbccu) {
        return 3;
    }
    if (rome2_vfs_hash_next_power_of_2_buckets32(1u, &buckets, &ptrs) != ROME2_VFS_REG_OK ||
        buckets != 2u || ptrs != 4u) {
        return 4;
    }
    if (rome2_vfs_hash_next_power_of_2_buckets32(9u, &buckets, &ptrs) != ROME2_VFS_REG_OK ||
        buckets != 16u || ptrs != 32u) {
        return 5;
    }
    if (rome2_vfs_hash_next_power_of_2_buckets32(0x10000000u, &buckets, &ptrs) != ROME2_VFS_REG_OK ||
        buckets != 0x10000000u || ptrs != 0x20000000u) {
        return 6;
    }
    if (rome2_vfs_hash_next_power_of_2_buckets32(0x10000001u, &buckets, &ptrs) != ROME2_VFS_REG_RANGE_ERROR ||
        buckets != 0x10000000u || ptrs != 0x20000000u) {
        return 7;
    }

    if (rome2_vfs_hash_desired_buckets32(2u, load_1_0, 8u, &out) != ROME2_VFS_REG_OK ||
        out != 8u) {
        return 8;
    }
    /* Small grow: 100 / 0.5 = 200 -> > 64 -> max(64*8=512, 200) = 512 */
    if (rome2_vfs_hash_desired_buckets32(100u, load_0_5, 64u, &out) != ROME2_VFS_REG_OK ||
        out != 512u) {
        return 9;
    }
    /* Large grow: current >= 0x200 (512) scales directly to needed (600 / 1.0 = 600). */
    if (rome2_vfs_hash_desired_buckets32(600u, load_1_0, 512u, &out) != ROME2_VFS_REG_OK ||
        out != 600u) {
        return 10;
    }
    out = 0xfeedfaceu;
    if (rome2_vfs_hash_desired_buckets32(10u, nan_bits, 8u, &out) != ROME2_VFS_REG_INVALID_STATE ||
        out != 0xfeedfaceu) {
        return 11;
    }
    return 0;
}

static int check_stream_handle_and_bucket_vec(void)
{
    uint8_t mem[0x30];
    const uint32_t base = 0x30000000u;
    const rome2_guest_read_view view = {mem, base, sizeof(mem)};
    rome2_vfs_stream_handle_box32 box;
    rome2_vfs_bucket_vec_header32 vec;
    uint32_t cap = 0x1111u;
    uint32_t bytes = 0x2222u;
    uint32_t free_bytes = 0x3333u;

    memset(mem, 0, sizeof(mem));
    write_u32_le(mem + 0x00u, 0x11220001u);
    write_u32_le(mem + 0x04u, 0x11220002u);
    write_u32_le(mem + 0x08u, 0x40001000u);
    write_u32_le(mem + 0x0cu, 0x40002000u);
    write_u32_le(mem + 0x10u, 0x40003000u);

    write_u32_le(mem + 0x14u, 8u);
    write_u32_le(mem + 0x18u, 5u);
    write_u32_le(mem + 0x1cu, 0x40004000u);

    memset(&box, 0, sizeof(box));
    if (rome2_vfs_decode_stream_handle_box32(&view, addr32(base), &box) != ROME2_VFS_REG_OK ||
        box.secondary_ctrl != 0x40001000u ||
        box.sentinel_or_state != 0x40002000u ||
        box.primary_ctrl != 0x40003000u) {
        return 20;
    }

    box.primary_ctrl = 0xdeadbeefu;
    if (rome2_vfs_decode_stream_handle_box32(&view, addr32(base + 0x20u), &box) != ROME2_VFS_REG_RANGE_ERROR ||
        box.primary_ctrl != 0xdeadbeefu) {
        return 21;
    }

    memset(&vec, 0, sizeof(vec));
    if (rome2_vfs_decode_bucket_vec_header32(&view, addr32(base + 0x14u), &vec) != ROME2_VFS_REG_OK ||
        vec.capacity != 8u || vec.count != 5u || vec.slots != 0x40004000u) {
        return 22;
    }

    /* count > capacity rejected without mutating vec. */
    write_u32_le(mem + 0x18u, 9u);
    vec.slots = 0x77778888u;
    if (rome2_vfs_decode_bucket_vec_header32(&view, addr32(base + 0x14u), &vec) != ROME2_VFS_REG_INVALID_STATE ||
        vec.slots != 0x77778888u) {
        return 23;
    }

    if (rome2_vfs_bucket_vec_next_capacity32(0u, 0u, &cap, &bytes) != ROME2_VFS_REG_OK ||
        cap != 1u || bytes != 0x0cu) {
        return 24;
    }
    if (rome2_vfs_bucket_vec_next_capacity32(4u, 20u, &cap, &bytes) != ROME2_VFS_REG_OK ||
        cap != 20u || bytes != 240u) {
        return 25;
    }
    if (rome2_vfs_bucket_vec_next_capacity32(0x10000000u, 0u, &cap, &bytes) != ROME2_VFS_REG_RANGE_ERROR ||
        cap != 20u || bytes != 240u) {
        return 26;
    }

    /* Small vector free (< 0x1000) ignores backing_base, rounds down to dword. */
    if (rome2_vfs_validate_aligned_vec_free32(0x50000000u, 0x50000203u, 0u, &free_bytes) != ROME2_VFS_REG_OK ||
        free_bytes != 0x200u) {
        return 27;
    }
    /* Large vector free (>= 0x1000) requires valid backing header gap <= 0x1f and adds 0x23. */
    if (rome2_vfs_validate_aligned_vec_free32(0x50001020u, 0x50003020u, 0x50001000u, &free_bytes) != ROME2_VFS_REG_OK ||
        free_bytes != 0x2023u) {
        return 28;
    }
    free_bytes = 0xfeed0001u;
    if (rome2_vfs_validate_aligned_vec_free32(0x50001040u, 0x50003040u, 0x50001000u, &free_bytes) != ROME2_VFS_REG_INVALID_STATE ||
        free_bytes != 0xfeed0001u) {
        return 29;
    }
    return 0;
}

int main(void)
{
    int rc = check_rb_and_hash_bucket_math();
    if (rc != 0) {
        fprintf(stderr, "rb_and_hash_bucket_math failed: %d\n", rc);
        return rc;
    }
    rc = check_stream_handle_and_bucket_vec();
    if (rc != 0) {
        fprintf(stderr, "stream_handle_and_bucket_vec failed: %d\n", rc);
        return rc;
    }
    printf("vfs_rb_bucket_ops_tests: 21 checks passed (0 failures)\n");
    return 0;
}
