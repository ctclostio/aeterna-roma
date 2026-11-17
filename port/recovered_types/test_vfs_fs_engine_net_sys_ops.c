#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_net_sys_ops.h"

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
    CHECK(sizeof(rome2_vfs_threadname_info16_32) == 0x10);
    CHECK(sizeof(rome2_vfs_seq_ack_ring36_32) == 0x24);
    CHECK(sizeof(rome2_vfs_channel_slot_meta36_32) == 0x24);

    /* 2. 0x100e7ff0, 0x10fddba0, 0x100f38b0 TLS zero vec, singleton, threadname */
    CHECK(rome2_vfs_sse_zero_tls_va() == ROME2_VFS_L39_SSE_ZERO_TLS_VA);
    int32_t guard1 = -1;
    uint8_t vec16[16];
    memset(vec16, 0xaa, sizeof(vec16));
    uint8_t init_done = 0u;
    CHECK(rome2_vfs_sse_zero_init16(&guard1, vec16, -2, &init_done) == ROME2_VFS_REG_OK);
    CHECK(init_done == 1u && guard1 == 0 && vec16[0] == 0u && vec16[15] == 0u);

    int32_t guard2 = -1;
    uint8_t mgr_ctor = 0u;
    CHECK(rome2_vfs_channel_mgr_singleton_va(&guard2, -2, &mgr_ctor) == ROME2_VFS_L39_CHANNEL_MGR_VA);
    CHECK(mgr_ctor == 1u && guard2 == 0);
    CHECK(rome2_vfs_channel_mgr_singleton_va(&guard2, -2, &mgr_ctor) == ROME2_VFS_L39_CHANNEL_MGR_VA);
    CHECK(mgr_ctor == 0u);

    rome2_vfs_threadname_info16_32 tni = {0};
    CHECK(rome2_vfs_threadname_info16_fill(&tni, 0x11740000u, 0x1234u) == ROME2_VFS_REG_OK);
    CHECK(tni.dw_type_00 == 0x1000u && tni.sz_name_04 == 0x11740000u && tni.dw_thread_id_08 == 0x1234u && tni.dw_flags_0c == 0u);

    /* 3. String prepending, padding, substr, int32/card32 formatting, and WSA strings */
    const uint16_t src_w[3] = {L'4', L'2', L'x'};
    uint16_t wout[64] = {0};
    uint32_t wlen = 0u;
    CHECK(rome2_vfs_wstr_prepend_char(L'-', src_w, 2u, wout, 64u, &wlen) == ROME2_VFS_REG_OK);
    CHECK(wlen == 3u && wout[0] == L'-' && wout[1] == L'4' && wout[2] == L'2');

    CHECK(rome2_vfs_wstr_pad_aligned(src_w, 2u, 4u, 0u, L'0', wout, 64u, &wlen) == ROME2_VFS_REG_OK);
    CHECK(wlen == 4u && wout[0] == L'0' && wout[1] == L'0' && wout[2] == L'4' && wout[3] == L'2');
    CHECK(rome2_vfs_wstr_pad_aligned(src_w, 2u, 4u, 1u, L' ', wout, 64u, &wlen) == ROME2_VFS_REG_OK);
    CHECK(wlen == 4u && wout[0] == L'4' && wout[2] == L' ' && wout[3] == L' ');

    CHECK(rome2_vfs_wstr_substr_slice(src_w, 3u, 1u, 10u, wout, 64u, &wlen) == ROME2_VFS_REG_OK);
    CHECK(wlen == 2u && wout[0] == L'2' && wout[1] == L'x');

    uint8_t fmt_ok = 0u;
    CHECK(rome2_vfs_format_int32_card32(0xffffffffu, 'd', 1u, wout, 64u, &wlen, &fmt_ok) == ROME2_VFS_REG_OK);
    CHECK(fmt_ok == 1u && wlen == 2u && wout[0] == L'-' && wout[1] == L'1');
    CHECK(rome2_vfs_format_int32_card32(0x1au, 'X', 0u, wout, 64u, &wlen, &fmt_ok) == ROME2_VFS_REG_OK);
    CHECK(fmt_ok == 1u && wlen == 2u && wout[0] == L'1' && wout[1] == L'A');
    CHECK(rome2_vfs_format_int32_card32(7u, 'q', 0u, wout, 64u, &wlen, &fmt_ok) == ROME2_VFS_REG_OK);
    CHECK(fmt_ok == 0u && wlen > 20u && wout[0] == L'U');

    CHECK(strcmp(rome2_vfs_winsock_err_str(8u, 0x2af9u), "Authoritative answer host not found.") == 0);
    CHECK(strcmp(rome2_vfs_winsock_err_str(8u, 0x9999u), "Undocumented error.") == 0);

    /* 4. 0x10123e40 dlmalloc sys_alloc, 0x10f74830 msb width, 0x10f79f60 bitcopy_msb */
    rome2_vfs_dlmalloc_mstate448_32 ms = {0};
    ms.mflags_1bc = 1u;
    uint32_t alloc_sz = 0u;
    uint8_t use_mmap = 0u;
    CHECK(rome2_vfs_dlmalloc_sys_alloc_plan(&ms, 0x40000u, 0x10000u, 0x40000u, &alloc_sz, &use_mmap) == ROME2_VFS_REG_OK);
    CHECK(use_mmap == 1u && alloc_sz == 0x50000u);
    ms.topsize_0c = 0x100u;
    CHECK(rome2_vfs_dlmalloc_sys_alloc_plan(&ms, 0x1000u, 0x10000u, 0x40000u, &alloc_sz, &use_mmap) == ROME2_VFS_REG_OK);
    CHECK(use_mmap == 0u && alloc_sz == 0x10000u);

    CHECK(rome2_vfs_msb_width_u32(0u) == 0u && rome2_vfs_msb_width_u32(5u) == 3u && rome2_vfs_msb_width_u32(0x80000001u) == 32u);

    const uint8_t bsrc[2] = {0xa0u, 0x00u};
    uint8_t bdst[2] = {0u, 0u};
    uint32_t dbit = 4u;
    uint32_t sbit = 0u;
    uint32_t bcopied = 0u;
    CHECK(rome2_vfs_bitcopy_msb(bdst, sizeof(bdst), &dbit, bsrc, sizeof(bsrc), &sbit, 3u, &bcopied) == ROME2_VFS_REG_OK);
    CHECK(bcopied == 3u && dbit == 7u && sbit == 3u && bdst[0] == 0x0au);

    /* 5. 0x10fa5d10 seq ring & 0x10fb2fb0..0x10fe47b0 channel transport */
    rome2_vfs_seq_ack_ring36_32 ring = {0};
    ring.base_seq_0c = 100u;
    ring.stride_18 = 10u;
    ring.cap_1c = 4u;
    uint8_t rmap[4] = {0u, 1u, 0u, 0u};
    uint32_t rack[4] = {0u};
    uint8_t acked = 0u;
    uint8_t freed_ext = 0u;
    CHECK(rome2_vfs_seq_ack_ring_pop(&ring, rmap, 4u, rack, 4u, 115, &acked, &freed_ext) == ROME2_VFS_REG_OK);
    CHECK(acked == 1u && freed_ext == 0u && rmap[1] == 0u && ring.ack_count_20 == 1u && rack[0] == 115u);

    rome2_vfs_channel_slot_meta36_32 dst_m = {0};
    rome2_vfs_channel_slot_meta36_32 src_m = {0x0100007fu, 27015u, 0u, 1u, 2u, 3u, 0u, 1u, 1u, {0}, 9u};
    rome2_vfs_channel_slot_hdr24_32 dst_h = {0};
    rome2_vfs_channel_slot_hdr24_32 src_h = {0};
    CHECK(rome2_vfs_channel_hdr24_reset(&dst_h) == ROME2_VFS_REG_OK && dst_h.sock_fd_10 == 0xffffffffu);
    CHECK(rome2_vfs_channel_meta36_reset(&dst_m) == ROME2_VFS_REG_OK && dst_m.aux_sock_10 == 0xffffffffu);
    dst_h.sock_fd_10 = 12u;
    dst_h.active_flag_14 = 1u;
    src_h.sock_fd_10 = 99u;
    src_h.active_flag_14 = 1u;
    uint8_t closed_prev = 0u;
    CHECK(rome2_vfs_channel_slot_meta_move(&dst_m, &dst_h, &src_m, &src_h, &closed_prev) == ROME2_VFS_REG_OK);
    CHECK(closed_prev == 1u && dst_h.sock_fd_10 == 99u && src_h.active_flag_14 == 0u && dst_m.ep_port_04 == 27015u);

    CHECK(rome2_vfs_steam_p2p_state_ready(1u, 1u, 1u) == 1u);
    uint8_t route = 0u;
    uint8_t fhdr2[2] = {0u, 0u};
    uint32_t wire = 0u;
    CHECK(rome2_vfs_channel_frame_send_plan(0x123u, 0u, 1u, 0u, &route, fhdr2, &wire) == ROME2_VFS_REG_OK);
    CHECK(route == 2u && fhdr2[0] == 0x23u && fhdr2[1] == 0x01u && wire == 0x125u);

    uint8_t bcast_ok = 0u;
    CHECK(rome2_vfs_channel_broadcast_validate(1u, 2u, 1u, 1u, 64u, &bcast_ok) == ROME2_VFS_REG_OK && bcast_ok == 1u);
    CHECK(rome2_vfs_channel_broadcast_validate(1u, 20u, 1u, 1u, 64u, &bcast_ok) == ROME2_VFS_REG_OK && bcast_ok == 0u);

    printf("test_vfs_fs_engine_net_sys_ops: ALL PASSED (%d checks)\n", checks);
    return 0;
}
