#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_channel_ops.h"

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
            return 1; \
        } \
        ++checks; \
    } while (0)

int main(void) {
    int checks = 0;

    /* 1. Layout invariants verified via _Static_assert in guest32_layouts.h */
    CHECK(sizeof(rome2_vfs_refcount_ctrl12_32) == 0x0c);
    CHECK(sizeof(rome2_vfs_bit_cursor12_32) == 0x0c);
    CHECK(sizeof(rome2_vfs_channel_slot_hdr24_32) == 0x18);

    /* 2. 0x10238c90 UTF-16 '%l...' format scanner */
    const uint16_t wfmt[] = {L'x', L'%', L'%', L'=', L'%', L'l', L'f'};
    uint16_t fidx = 0u;
    uint32_t fout_len = 0u;
    uint8_t hit = 0u;
    uint16_t fout[16] = {0};
    CHECK(rome2_vfs_scan_lfmt_token_wstr(wfmt, 7u, &fidx, fout, &fout_len, 16u, &hit) == ROME2_VFS_REG_OK);
    CHECK(fout_len == 3u && fout[0] == L'x' && fout[1] == L'%' && fout[2] == L'=' && fidx == 6u && hit == 1u);

    /* 3. 0x1039db80 _Ref_count_base::_Decref & 0x10524c30 large aligned unwrap */
    rome2_vfs_refcount_ctrl12_32 rc = {0x11800000u, 2, 1};
    uint8_t destroyed = 0u;
    uint8_t deleted = 0u;
    CHECK(rome2_vfs_refcount_decref(&rc, &destroyed, &deleted) == ROME2_VFS_REG_OK);
    CHECK(destroyed == 0u && deleted == 0u && rc.uses_04 == 1);
    CHECK(rome2_vfs_refcount_decref(&rc, &destroyed, &deleted) == ROME2_VFS_REG_OK);
    CHECK(destroyed == 1u && deleted == 1u && rc.uses_04 == 0 && rc.weaks_08 == 0);

    uint32_t free_va = 0u;
    CHECK(rome2_vfs_aligned_buf_check_unalign(0x20001020u, 0x1000u, 0x20001000u, &free_va) == ROME2_VFS_REG_OK);
    CHECK(free_va == 0x20001000u);
    CHECK(rome2_vfs_aligned_buf_check_unalign(0x20001040u, 0x1000u, 0x20001000u, &free_va) == ROME2_VFS_REG_INVALID_STATE);
    CHECK(rome2_vfs_aligned_buf_check_unalign(0x20000800u, 0x200u, 0u, &free_va) == ROME2_VFS_REG_OK);
    CHECK(free_va == 0x20000800u);

    /* 4. 0x1075c5a0 24B slab links, 0x107c9080 RB tree successor, 0x107e0650 find */
    uint32_t slab_links[4] = {0};
    CHECK(rome2_vfs_slab24_link_links(0x30000000u, 3u, slab_links, 4u) == ROME2_VFS_REG_OK);
    CHECK(slab_links[0] == 0x30000018u && slab_links[1] == 0x30000030u && slab_links[2] == 0u);

    const rome2_vfs_rbtree_node16 nodes[4] = {
        {1u, 3u, 2u, 0u},  /* 0: root */
        {3u, 0u, 3u, 0u},  /* 1: left leaf */
        {3u, 0u, 3u, 0u},  /* 2: right leaf */
        {1u, 0u, 2u, 1u},  /* 3: nil head */
    };
    CHECK(rome2_vfs_rbtree_step_next(nodes, 4u, 1u) == 0u);
    CHECK(rome2_vfs_rbtree_step_next(nodes, 4u, 0u) == 2u);
    CHECK(rome2_vfs_rbtree_step_next(nodes, 4u, 2u) == 3u);

    const char *list_items[3] = {"alpha", "beta", "gamma"};
    CHECK(rome2_vfs_cstr_range_find_idx(list_items, 0u, 3u, "beta") == 1u);
    CHECK(rome2_vfs_cstr_range_find_idx(list_items, 0u, 3u, "delta") == 3u);

    /* 5. 0x10cb03c0 UTF-16LE prefixed string reader & 0x1103d530 bucket reset range */
    const uint8_t pkt[] = {3u, 0u, 'R', 0u, 'o', 0u, 'm', 0u};
    uint32_t spos = 0u;
    uint32_t schars = 0u;
    uint16_t sbuf[8] = {0};
    CHECK(rome2_vfs_stream_read_u16_len_prefixed_wstr(pkt, sizeof(pkt), &spos, sbuf, 8u, &schars) == ROME2_VFS_REG_OK);
    CHECK(schars == 3u && spos == sizeof(pkt) && sbuf[0] == L'R' && sbuf[1] == L'o' && sbuf[2] == L'm' && sbuf[3] == 0u);

    rome2_vfs_bucket_slot12_32 bvec[2] = {{0}};
    rome2_vfs_bucket12_reset_range(bvec, 2u, 0x4000u);
    CHECK(bvec[0].begin_00 == 0x4004u && bvec[1].begin_00 == 0x4010u);

    /* 6. 0x10f78370..0x10fd9660 channel slot hdr24 & bit cursor ops */
    CHECK(rome2_vfs_channel_slot_is_valid(19u, 1u) == 1u);
    CHECK(rome2_vfs_channel_slot_is_valid(20u, 1u) == 0u);

    rome2_vfs_channel_slot_hdr24_32 src_ch = {0x7f000001u, 27015u, 0u, 11u, 22u, 42u, 0u, {0}};
    rome2_vfs_channel_slot_hdr24_32 dst_ch = {0};
    rome2_vfs_channel_hdr24_bind(&dst_ch, &src_ch, 0u);
    CHECK(dst_ch.addr_dword_00 == 0x7f000001u && dst_ch.port_or_tag_04 == 27015u && dst_ch.sock_fd_10 == 42u && dst_ch.active_flag_14 == 1u);
    rome2_vfs_channel_hdr24_bind(&dst_ch, NULL, 1u);
    CHECK(dst_ch.sock_fd_10 == 0xffffffffu && dst_ch.active_flag_14 == 0u);

    rome2_vfs_bit_cursor12_32 bc = {0x50000000u, 0x40u, 0x12u};
    uint32_t avail_bits = 0u;
    CHECK(rome2_vfs_bit_cursor_consume(&bc, 3u, &avail_bits) == ROME2_VFS_REG_OK);
    CHECK(avail_bits == (0x40u * 8u - 0x12u) && bc.bits_used_08 == 0x0fu);
    rome2_vfs_bit_cursor_normalize_tail(&bc);
    CHECK(bc.byte_cap_04 == 0x3fu && bc.bits_used_08 == 7u);

    printf("test_vfs_fs_engine_channel_ops: ALL PASSED (%d checks)\n", checks);
    return 0;
}
