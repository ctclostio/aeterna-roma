#include "vfs_quota_map.h"

#include <stdio.h>
#include <string.h>

static int g_checks = 0;
static int g_failures = 0;

static void check(int cond, const char *name) {
    ++g_checks;
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        ++g_failures;
    }
}

static void put_u32_le(uint8_t *buf, size_t offset, uint32_t val) {
    buf[offset + 0u] = (uint8_t)(val & 0xffu);
    buf[offset + 1u] = (uint8_t)((val >> 8) & 0xffu);
    buf[offset + 2u] = (uint8_t)((val >> 16) & 0xffu);
    buf[offset + 3u] = (uint8_t)((val >> 24) & 0xffu);
}

static void put_u16_le(uint8_t *buf, size_t offset, uint16_t val) {
    buf[offset + 0u] = (uint8_t)(val & 0xffu);
    buf[offset + 1u] = (uint8_t)((val >> 8) & 0xffu);
}

static void put_utf16(uint8_t *buf, size_t offset, const uint16_t *u, size_t n) {
    for (size_t i = 0u; i < n; ++i) {
        put_u16_le(buf, offset + i * 2u, u[i]);
    }
}

static void test_utf16_hash_and_global_map_probe(void) {
    /*
     * Guest memory layout at 0x50000000:
     *   0x00..0x23: 36B global map (buckets=0x50000100, bucket_count=4)
     *   0x40..0x55: L"Unused_key" (10 units)
     *   0x60..0x77: L"Removed_key" (11 units)
     *   0x80..0x89: L"mod_a" (5 units)
     *   0x90..0x99: L"mod_b" (5 units)
     *   0x100..0x13f: 4 x 16B buckets
     */
    uint8_t mem[0x160];
    rome2_guest_read_view view = {mem, 0x50000000u, sizeof(mem)};
    const uint16_t k_unused[] = {'U', 'n', 'u', 's', 'e', 'd', '_', 'k', 'e', 'y'};
    const uint16_t k_removed[] = {'R', 'e', 'm', 'o', 'v', 'e', 'd', '_', 'k', 'e', 'y'};
    const uint16_t k_a[] = {'m', 'o', 'd', '_', 'a'};
    const uint16_t k_b[] = {'m', 'o', 'd', '_', 'b'};
    uint32_t hash_a = 0u;
    uint32_t hash_empty = 0u;
    uint32_t start_a = 0u;
    uint32_t next_idx = 0u;
    rome2_guest_addr32 found_slot = {0x99999999u};

    memset(mem, 0, sizeof(mem));
    check(rome2_vfs_hash_utf16_key32(k_a, 0u, &hash_empty) == ROME2_VFS_REG_OK &&
              hash_empty == ROME2_VFS_HASH_SEED32,
          "empty UTF-16 hash returns seed 0xf73a51c9");
    check(rome2_vfs_hash_utf16_key32(k_a, 5u, &hash_a) == ROME2_VFS_REG_OK,
          "hash mod_a");
    check(rome2_vfs_hash_utf16_key32(NULL, 2u, &hash_a) ==
              ROME2_VFS_REG_BAD_ARGUMENT,
          "null hash input rejected");

    put_utf16(mem, 0x40u, k_unused, 10u);
    put_utf16(mem, 0x60u, k_removed, 11u);
    put_utf16(mem, 0x80u, k_a, 5u);
    put_utf16(mem, 0x90u, k_b, 5u);

    /* Global map descriptor at 0x50000000 */
    put_u32_le(mem, 0x00u, 0x50000100u);
    put_u32_le(mem, 0x04u, 4u);
    put_u32_le(mem, 0x08u, 11u);
    put_u32_le(mem, 0x0cu, 16u);
    put_u32_le(mem, 0x10u, 0x50000060u);
    put_u32_le(mem, 0x14u, 10u);
    put_u32_le(mem, 0x18u, 16u);
    put_u32_le(mem, 0x1cu, 0x50000040u);

    /* Fill all 4 buckets initially with Unused_key, then place Removed_key at
     * hash_a % 4 and mod_a at (hash_a + 1) % 4 to test collision + wrap! */
    for (uint32_t i = 0u; i < 4u; ++i) {
        size_t b_off = 0x100u + (size_t)i * 16u;
        put_u32_le(mem, b_off + 0x00u, 10u);
        put_u32_le(mem, b_off + 0x04u, 16u);
        put_u32_le(mem, b_off + 0x08u, 0x50000040u);
    }
    start_a = hash_a % 4u;
    next_idx = (start_a + 1u) % 4u;
    put_u32_le(mem, 0x100u + (size_t)start_a * 16u + 0x00u, 11u);
    put_u32_le(mem, 0x100u + (size_t)start_a * 16u + 0x08u, 0x50000060u);
    put_u32_le(mem, 0x100u + (size_t)next_idx * 16u + 0x00u, 5u);
    put_u32_le(mem, 0x100u + (size_t)next_idx * 16u + 0x08u, 0x50000080u);
    put_u32_le(mem, 0x100u + (size_t)next_idx * 16u + 0x0cu, 0x12345678u);

    check(rome2_vfs_global_map_probe32(&view, (rome2_guest_addr32){0x50000000u},
                                       k_a, 5u, &found_slot) == ROME2_VFS_REG_OK,
          "probe mod_a past tombstone");
    check(found_slot.value == 0x50000100u + next_idx * 16u + 0x0cu,
          "probe returned exact +0x0c value slot");

    found_slot.value = 0xdeadbeefu;
    check(rome2_vfs_global_map_probe32(&view, (rome2_guest_addr32){0x50000000u},
                                       k_b, 5u, &found_slot) ==
              ROME2_VFS_REG_NOT_FOUND,
          "probe missing mod_b returns NOT_FOUND");
    check(found_slot.value == 0xdeadbeefu,
          "found_slot preserved on NOT_FOUND");
}

static void test_pack_wire_header_quota_and_rb_count(void) {
    uint8_t hdr_buf[ROME2_VFS_PACK_WIRE_HDR_BYTES];
    rome2_vfs_pack_header_wire32 hdr;
    rome2_vfs_quota_frame32 frame;
    uint32_t accepted = 99u;
    uint8_t rb_mem[0x50];
    rome2_guest_read_view rb_view = {rb_mem, 0x60000000u, sizeof(rb_mem)};
    uint32_t rb_count = 77u;
    rome2_vfs_stream_slice_view32 slice_in;
    rome2_vfs_stream_slice_view32 slice_out;

    memset(hdr_buf, 0, sizeof(hdr_buf));
    put_u32_le(hdr_buf, 0x00u, 0x34484650u); /* "PFH4" */
    put_u32_le(hdr_buf, 0x04u, 0x40u);
    put_u32_le(hdr_buf, 0x08u, 2u);
    put_u32_le(hdr_buf, 0x0cu, 24u);
    put_u32_le(hdr_buf, 0x10u, 150u);
    put_u32_le(hdr_buf, 0x14u, 4096u);
    put_u32_le(hdr_buf, 0x18u, 0x55667788u);

    memset(&hdr, 0, sizeof(hdr));
    check(rome2_vfs_pack_header_decode32(hdr_buf, sizeof(hdr_buf), &hdr) ==
              ROME2_VFS_REG_OK,
          "decode 28B pack wire header");
    check(hdr.signature == 0x34484650u && hdr.entry_count == 150u &&
              hdr.index_bytes == 4096u,
          "pack wire header fields");
    check(rome2_vfs_pack_header_decode32(hdr_buf, 27u, &hdr) ==
              ROME2_VFS_REG_RANGE_ERROR,
          "short pack wire header fails closed");
    check(hdr.entry_count == 150u, "pack wire header preserved on short read");

    memset(&frame, 0, sizeof(frame));
    frame.max_ops = 2u;
    frame.max_bytes = 1000u;
    frame.used_bytes = 900u;
    frame.used_ops = 1u;

    check(rome2_vfs_quota_check_and_reserve(&frame, 200u, &accepted) ==
              ROME2_VFS_REG_OK &&
              accepted == 0u,
          "over-budget byte delta rejected without mutation");
    check(frame.used_bytes == 900u && frame.used_ops == 1u,
          "quota frame unchanged on byte rejection");

    check(rome2_vfs_quota_check_and_reserve(&frame, 0xffffff00u, &accepted) ==
              ROME2_VFS_REG_OK &&
              accepted == 0u,
          "overflow byte_delta rejected");
    check(rome2_vfs_quota_check_and_reserve(&frame, 100u, &accepted) ==
              ROME2_VFS_REG_OK &&
              accepted == 1u,
          "exact remaining budget accepted");
    check(frame.used_bytes == 1000u && frame.used_ops == 2u,
          "quota counters incremented");
    check(rome2_vfs_quota_check_and_reserve(&frame, 0u, &accepted) ==
              ROME2_VFS_REG_OK &&
              accepted == 0u,
          "max_ops exhausted rejected");

    /* 3 nodes: root (0x00) -> left (0x14), right (0x28); 0x3c = sentinel is_nil=1 */
    memset(rb_mem, 0, sizeof(rb_mem));
    put_u32_le(rb_mem, 0x00u + 0x00u, 0x60000014u);
    put_u32_le(rb_mem, 0x00u + 0x08u, 0x60000028u);
    put_u32_le(rb_mem, 0x14u + 0x00u, 0x6000003cu);
    put_u32_le(rb_mem, 0x14u + 0x08u, 0x6000003cu);
    put_u32_le(rb_mem, 0x28u + 0x00u, 0x6000003cu);
    put_u32_le(rb_mem, 0x28u + 0x08u, 0x6000003cu);
    put_u32_le(rb_mem, 0x3cu + 0x0cu, 0x00000101u); /* color=1, is_nil=1 */

    check(rome2_vfs_count_rb_live_nodes32(&rb_view,
                                          (rome2_guest_addr32){0x60000000u},
                                          10u, &rb_count) == ROME2_VFS_REG_OK,
          "count 3 live RB nodes");
    check(rb_count == 3u, "rb_count == 3");

    rb_count = 88u;
    check(rome2_vfs_count_rb_live_nodes32(&rb_view,
                                          (rome2_guest_addr32){0x60000000u},
                                          2u, &rb_count) ==
              ROME2_VFS_REG_STEP_LIMIT,
          "rb step_limit preserves count");
    check(rb_count == 88u, "rb_count preserved on STEP_LIMIT");

    memset(&slice_in, 0, sizeof(slice_in));
    memset(&slice_out, 0, sizeof(slice_out));
    slice_in.entry = 0x70001000u;
    slice_in.offset = 64u;
    slice_in.length = 512u;
    slice_in.mode_flag = 1u;
    check(rome2_vfs_build_stream_slice_view32(&slice_in, &slice_out) ==
              ROME2_VFS_REG_OK,
          "build stream slice view");
    check(slice_out.entry == 0x70001000u && slice_out.length == 512u,
          "slice view fields match");
    slice_in.entry = 0u;
    check(rome2_vfs_build_stream_slice_view32(&slice_in, &slice_out) ==
              ROME2_VFS_REG_BAD_ARGUMENT,
          "null entry slice rejected");
    check(slice_out.entry == 0x70001000u, "slice_out preserved on error");
}

int main(void) {
    test_utf16_hash_and_global_map_probe();
    test_pack_wire_header_quota_and_rb_count();
    printf("vfs_quota_map_tests: %d checks passed (%d failures)\n",
           g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
