#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs_quota_map.h"
#include "vfs_scan_mount.h"

static uint32_t g_checks = 0u;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                        \
        }                                                                    \
        g_checks++;                                                          \
    } while (0)

static void write_u32_le(uint8_t *buf, size_t offset, uint32_t v) {
    buf[offset + 0] = (uint8_t)(v & 0xffu);
    buf[offset + 1] = (uint8_t)((v >> 8) & 0xffu);
    buf[offset + 2] = (uint8_t)((v >> 16) & 0xffu);
    buf[offset + 3] = (uint8_t)((v >> 24) & 0xffu);
}

static void write_i32_le(uint8_t *buf, size_t offset, int32_t v) {
    write_u32_le(buf, offset, (uint32_t)v);
}

static rome2_guest_addr32 addr32(uint32_t v) {
    rome2_guest_addr32 a = {v};
    return a;
}

int main(void) {
    const uint32_t base = 0x50000000u;
    uint8_t mem[0x400];
    rome2_guest_read_view view = {mem, base, sizeof(mem)};

    memset(mem, 0, sizeof(mem));

    /* 1. Thread-ID bucket hash (0x101f4f90) & output preservation */
    {
        uint32_t bucket = 0x12345678u;
        CHECK(rome2_vfs_thread_bucket_hash32(0x11223344u, 8u, &bucket) == ROME2_VFS_REG_OK);
        CHECK(bucket == ((0x11223344u ^ ROME2_VFS_THREAD_HASH_XOR32) % 8u));
        bucket = 0xabcdef01u;
        CHECK(rome2_vfs_thread_bucket_hash32(1u, 0u, &bucket) == ROME2_VFS_REG_BAD_ARGUMENT);
        CHECK(bucket == 0xabcdef01u);
        CHECK(rome2_vfs_thread_bucket_hash32(1u, 8u, NULL) == ROME2_VFS_REG_BAD_ARGUMENT);
    }

    /* 2. Open bucket lookup (0x101f4f90): hit, miss at sentinel, cycle rejection */
    {
        uint32_t map_off = 0x00u;
        uint32_t buckets_off = 0x40u;
        uint32_t b_idx = (0x5555u ^ ROME2_VFS_THREAD_HASH_XOR32) % 4u;
        uint32_t slot_off = buckets_off + b_idx * 12u;
        uint32_t n1_off = 0x100u;
        uint32_t n2_off = 0x120u;
        rome2_guest_addr32 node = {0x99999999u};

        write_u32_le(mem, map_off + 0x08u, 4u);
        write_u32_le(mem, map_off + 0x0cu, base + buckets_off);
        /* Empty buckets point head to sentinel (&slot + 4). */
        for (uint32_t b = 0u; b < 4u; b++) {
            uint32_t off = buckets_off + b * 12u;
            write_u32_le(mem, off + 0x00u, base + off + 0x04u);
            write_u32_le(mem, off + 0x04u, base + off + 0x04u);
        }
        /* Two nodes in target bucket: n1 (key=0x4444) -> n2 (key=0x5555) -> sentinel */
        write_u32_le(mem, slot_off + 0x00u, base + n1_off);
        write_u32_le(mem, n1_off + 0x04u, base + n2_off);
        write_u32_le(mem, n1_off + 0x08u, 0x4444u);
        write_u32_le(mem, n2_off + 0x04u, base + slot_off + 0x04u);
        write_u32_le(mem, n2_off + 0x08u, 0x5555u);

        CHECK(rome2_vfs_thread_bucket_lookup32(
                  &view, addr32(base + map_off), 0x5555u, 8u, &node) ==
              ROME2_VFS_REG_OK);
        CHECK(node.value == base + n2_off);

        /* Miss in empty bucket preserves clean 0 result. */
        CHECK(rome2_vfs_thread_bucket_lookup32(
                  &view, addr32(base + map_off), 0x5556u, 8u, &node) ==
              ROME2_VFS_REG_OK);
        CHECK(node.value == 0u);

        /* Self-cycle rejects with INVALID_STATE and preserves output. */
        write_u32_le(mem, n1_off + 0x04u, base + n1_off);
        node.value = 0xfeedbeefu;
        CHECK(rome2_vfs_thread_bucket_lookup32(
                  &view, addr32(base + map_off), 0x5555u, 8u, &node) ==
              ROME2_VFS_REG_INVALID_STATE);
        CHECK(node.value == 0xfeedbeefu);
    }

    /* 3. Bucket map load-factor rehash calculation (0x112cbe10) */
    {
        uint32_t rehash = 9u;
        uint32_t new_b = 9u;
        CHECK(rome2_vfs_bucket_map_should_rehash32(8u, 8u, 1.0f, &rehash, &new_b) ==
              ROME2_VFS_REG_OK);
        CHECK(rehash == 0u && new_b == 8u);

        CHECK(rome2_vfs_bucket_map_should_rehash32(9u, 8u, 1.0f, &rehash, &new_b) ==
              ROME2_VFS_REG_OK);
        CHECK(rehash == 1u && new_b == 17u);

        rehash = 0x77u;
        new_b = 0x88u;
        CHECK(rome2_vfs_bucket_map_should_rehash32(1u, 0x80000000u, 0.0000000001f, &rehash, &new_b) ==
              ROME2_VFS_REG_RANGE_ERROR);
        CHECK(rehash == 0x77u && new_b == 0x88u);

        CHECK(rome2_vfs_bucket_map_should_rehash32(1u, 8u, NAN, &rehash, &new_b) ==
              ROME2_VFS_REG_BAD_ARGUMENT);
    }

    /* 4. 0x50-byte ref-counted pack block header + embedded pack_props (0x112d4160) */
    {
        uint32_t blk_off = 0x180u;
        rome2_vfs_ref_pack_block_header32 hdr = {0};
        uint32_t err_out = 99u;
        uint32_t cnt_out = 99u;

        write_u32_le(mem, blk_off + 0x00u, ROME2_VFS_REF_PACK_VTABLE32);
        write_i32_le(mem, blk_off + 0x04u, 2);
        write_i32_le(mem, blk_off + 0x08u, 1);
        write_u32_le(mem, blk_off + 0x0cu + 0x04u, ROME2_VFS_ERROR_HANDLE_EOF);
        write_u32_le(mem, blk_off + 0x0cu + 0x28u, 42u);

        CHECK(rome2_vfs_decode_ref_pack_block32(
                  &view, addr32(base + blk_off), &hdr, &err_out, &cnt_out) ==
              ROME2_VFS_REG_OK);
        CHECK(hdr.vtable == ROME2_VFS_REF_PACK_VTABLE32);
        CHECK(hdr.strong_ref == 2 && hdr.weak_ref == 1);
        CHECK(err_out == ROME2_VFS_ERROR_HANDLE_EOF && cnt_out == 42u);

        write_i32_le(mem, blk_off + 0x04u, -1);
        err_out = 0x55u;
        CHECK(rome2_vfs_decode_ref_pack_block32(
                  &view, addr32(base + blk_off), &hdr, &err_out, &cnt_out) ==
              ROME2_VFS_REG_INVALID_STATE);
        CHECK(err_out == 0x55u);
    }

    /* 5. Post-scan 8-byte slot table (0x112baf90 / 0x112b5450) */
    {
        uint32_t tbl_off = 0x200u;
        uint32_t arr_off = 0x240u;
        rome2_vfs_post_scan_table32 tbl = {0};
        uint32_t mismatches = 99u;

        write_u32_le(mem, tbl_off + 0x00u, base + arr_off);
        write_u32_le(mem, tbl_off + 0x04u, 3u);
        write_u32_le(mem, tbl_off + 0x08u, 0x11111111u);
        write_u32_le(mem, tbl_off + 0x0cu, 0x22222222u);

        write_u32_le(mem, arr_off + 0x00u, 0x11111111u);
        write_u32_le(mem, arr_off + 0x04u, 0x22222222u);
        write_u32_le(mem, arr_off + 0x08u, 0xdeadbeefu);
        write_u32_le(mem, arr_off + 0x0cu, 0x22222222u);
        write_u32_le(mem, arr_off + 0x10u, 0x11111111u);
        write_u32_le(mem, arr_off + 0x14u, 0x22222222u);

        CHECK(rome2_vfs_scan_post_mount_mismatches32(
                  &view,
                  addr32(base + tbl_off),
                  ROME2_VFS_POST_SCAN_SLOTS,
                  &tbl,
                  &mismatches) == ROME2_VFS_REG_OK);
        CHECK(tbl.entry_count == 3u && mismatches == 1u);

        mismatches = 77u;
        CHECK(rome2_vfs_scan_post_mount_mismatches32(
                  &view,
                  addr32(base + tbl_off),
                  2u,
                  &tbl,
                  &mismatches) == ROME2_VFS_REG_RANGE_ERROR);
        CHECK(mismatches == 77u);
    }

    /* 6. Stream wrapper A (0x112a7ae0) and B (0x112a94d0) validators */
    {
        rome2_vfs_stream_wrap_a32 wa = {0};
        rome2_vfs_stream_wrap_b32 wb = {0};

        wa.vtable = ROME2_VFS_STREAM_WRAP_A_VTABLE32;
        wa.flag_034 = 1u;
        CHECK(rome2_vfs_validate_stream_wrap_a32(&wa) == ROME2_VFS_REG_OK);
        wa.zero_02c = 1u;
        CHECK(rome2_vfs_validate_stream_wrap_a32(&wa) == ROME2_VFS_REG_INVALID_STATE);

        wb.vtable = ROME2_VFS_STREAM_WRAP_B_VTABLE32;
        wb.tag_00c = 3u;
        CHECK(rome2_vfs_validate_stream_wrap_b32(&wb) == ROME2_VFS_REG_OK);
        wb.zero_020[2] = 9u;
        CHECK(rome2_vfs_validate_stream_wrap_b32(&wb) == ROME2_VFS_REG_INVALID_STATE);
    }

    printf("vfs_scan_mount_tests: %u checks passed (0 failures)\n", g_checks);
    return 0;
}
