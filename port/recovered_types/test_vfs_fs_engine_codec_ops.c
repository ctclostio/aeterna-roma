#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_codec_ops.h"

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
    CHECK(sizeof(rome2_vfs_wstringbuf60_32) == 0x3c);
    CHECK(sizeof(rome2_vfs_channel_queue24_32) == 0x18);
    CHECK(sizeof(rome2_vfs_sock_endpoint12_32) == 0x0c);

    /* 2. 0x100d26e0, 0x113490a0, 0x11349180, 0x1134a060 wstringbuf lifecycle */
    CHECK(rome2_vfs_wstringbuf_state_from_openmode(3u) == 0u);
    CHECK(rome2_vfs_wstringbuf_state_from_openmode(1u) == 2u);
    CHECK(rome2_vfs_wstringbuf_state_from_openmode(0x0eu) == 0x1cu);

    rome2_vfs_wstringbuf60_32 sb = {0};
    CHECK(rome2_vfs_wstringbuf60_init_slots(&sb, 0x20001000u, ROME2_VFS_L38_WSTRBUF_BASE_VT_VA) == ROME2_VFS_REG_OK);
    CHECK(sb.vftable_00 == ROME2_VFS_L38_WSTRBUF_BASE_VT_VA && sb.g_first_ptr_0c == 0x20001004u && sb.p_count_ptr_30 == 0x20001028u);

    uint16_t wdst[8] = {0};
    const uint16_t wsrc[3] = {L'T', L'W', L'2'};
    CHECK(rome2_vfs_wstringbuf60_init_buf(&sb, wdst, 8u, 0x30000100u, wsrc, 3u, 0x10u) == ROME2_VFS_REG_OK);
    CHECK(wdst[0] == L'T' && wdst[2] == L'2' && sb.seek_high_34 == 0x30000106u && sb.g_count_val_24 == 3u && sb.p_next_val_18 == 0x30000106u);
    CHECK((sb.mystate_38 & 1u) != 0u);

    uint8_t should_free = 0u;
    uint32_t free_va = 0u;
    CHECK(rome2_vfs_wstringbuf60_tidy(&sb, &should_free, &free_va) == ROME2_VFS_REG_OK);
    CHECK(should_free == 1u && free_va == 0x30000100u && (sb.mystate_38 & 1u) == 0u && sb.seek_high_34 == 0u && sb.g_first_val_04 == 0u);

    /* 3. 0x100de0d0, 0x100f2af0, 0x100f2b00, 0x100de340, 0x101056d0, 0x10105850, 0x100f5860 */
    CHECK(rome2_vfs_sentinel_ctx_va() == ROME2_VFS_L38_SENTINEL_CTX_VA);
    CHECK(rome2_vfs_wstr_ptr_at_unchecked(wsrc, 2u) == &wsrc[2]);
    CHECK(rome2_vfs_wstr_char_at_checked(wsrc, 3u, 1u) == L'W');
    CHECK(rome2_vfs_wstr_char_at_checked(wsrc, 3u, 9u) == 0u);

    const char *afmt = "val=%% %ll-08.2f";
    uint16_t aidx = 0u;
    uint32_t aout_len = 0u;
    uint8_t ahit = 0u;
    char aout[32] = {0};
    rome2_vfs_fmt_spec aspec = {0};
    CHECK(rome2_vfs_scan_lfmt_spec_ascii(afmt, (uint32_t)strlen(afmt), &aidx, aout, &aout_len, 32u, &aspec, &ahit) == ROME2_VFS_REG_OK);
    CHECK(ahit == 1u && aout_len == 6u && memcmp(aout, "val=% ", 6) == 0);
    CHECK(aspec.is_minus == 1u && aspec.zero_pad_ch == '0' && aspec.width == 8u && aspec.precision == 2u && aspec.last_ch == 'f');

    const uint16_t wspec_in[] = {L'+', L'1', L'2', L'.', L'4', L'f'};
    uint16_t widx = 0u;
    rome2_vfs_fmt_spec wspec = {0};
    CHECK(rome2_vfs_parse_fmt_spec_wstr(wspec_in, 6u, &widx, &wspec) == ROME2_VFS_REG_OK);
    CHECK(wspec.sign_ch == L'+' && wspec.width == 12u && wspec.precision == 4u && wspec.last_ch == L'f' && widx == 6u);

    uint16_t fbuf[64] = {0};
    uint32_t flen = 0u;
    uint8_t fok = 0u;
    CHECK(rome2_vfs_format_float32_wstr(-3.5f, L'f', 0u, 0u, fbuf, 64u, &flen, &fok) == ROME2_VFS_REG_OK);
    CHECK(fok == 1u && flen == 4u && fbuf[0] == L'-' && fbuf[1] == L'3' && fbuf[2] == L'.' && fbuf[3] == L'5');
    CHECK(rome2_vfs_format_float32_wstr(1.0f, L'd', 2u, 0u, fbuf, 64u, &flen, &fok) == ROME2_VFS_REG_OK);
    CHECK(fok == 0u && flen > 10u && fbuf[0] == L'U');

    /* 4. 0x10114f00, 0x10114f60, 0x10fd7df0, 0x10fe4780 network/Steam ops */
    rome2_vfs_sock_endpoint12_32 ep = {0};
    CHECK(rome2_vfs_sock_endpoint12_set_ipv4(&ep, 0x0100007fu, 27015u) == ROME2_VFS_REG_OK);
    CHECK(ep.sin_family_04 == 2u && ep.sin_port_be_06 == 0x8769u && ep.sin_addr_08 == 0x0100007fu);

    uint32_t fionbio_arg = 9u;
    CHECK(rome2_vfs_sock_toggle_fionbio(0, 0u, &fionbio_arg) == ROME2_VFS_REG_OK && fionbio_arg == 1u);
    CHECK(rome2_vfs_sock_toggle_fionbio(-1, 1u, &fionbio_arg) == ROME2_VFS_REG_INVALID_STATE && fionbio_arg == 0u);
    CHECK(rome2_vfs_channel_slot_probe_ready(0u, -1, ROME2_VFS_L38_WSAEWOULDBLOCK) == 1u);
    CHECK(rome2_vfs_channel_slot_probe_ready(0u, -1, 10054u) == 0u);

    uint32_t steam_pair[2] = {0};
    CHECK(rome2_vfs_steam_p2p_close_pack(0x11223344u, 0x01100001u, steam_pair) == ROME2_VFS_REG_OK);
    CHECK(steam_pair[0] == 0x11223344u && steam_pair[1] == 0x01100001u);

    /* 5. 0x1011fcf0, 0x101236f0, 0x10123dd0, 0x101e3c50, 0x10f5f5c0, 0x10fd6850 */
    uint32_t fl4[4] = {0};
    CHECK(rome2_vfs_freelist4_link_links(0x40000000u, 3u, fl4, 4u) == ROME2_VFS_REG_OK);
    CHECK(fl4[0] == 0x40000004u && fl4[1] == 0x40000008u && fl4[2] == 0u);

    rome2_vfs_dlmalloc_mstate448_32 ms = {0};
    uint32_t top_va = 0u;
    uint32_t top_sz = 0u;
    uint32_t chunk_hdr = 0u;
    uint32_t fence_hdr = 0u;
    CHECK(rome2_vfs_dlmalloc_init_top(&ms, 0x50000003u, 0x1005u, 0x20000u, &top_va, &top_sz, &chunk_hdr, &fence_hdr) == ROME2_VFS_REG_OK);
    CHECK(top_va == 0x50000008u && top_sz == 0x1000u && chunk_hdr == 0x1001u && fence_hdr == 0x28u && ms.trim_check_1c == 0x20000u);

    const rome2_vfs_msegment_span segs[2] = {{0x10000u, 0x2000u}, {0x50000u, 0x4000u}};
    CHECK(rome2_vfs_dlmalloc_find_segment_idx(segs, 2u, 0x51000u) == 1u);
    CHECK(rome2_vfs_dlmalloc_find_segment_idx(segs, 2u, 0x60000u) == 2u);

    const uint32_t payloads[2] = {0x9001u, 0u};
    const uint32_t nodes[2] = {0x8001u, 0x8002u};
    uint32_t freed[4] = {0};
    uint32_t freed_cnt = 0u;
    uint32_t head_after = 0u;
    CHECK(rome2_vfs_intrusive_list_clear_range(payloads, nodes, 2u, 0x7000u, freed, 4u, &freed_cnt, &head_after) == ROME2_VFS_REG_OK);
    CHECK(freed_cnt == 3u && freed[0] == 0x9001u && freed[1] == 0x8001u && freed[2] == 0x8002u && head_after == 0x7004u);

    rome2_vfs_channel_queue24_32 cq = {0};
    CHECK(rome2_vfs_channel_queue24_init(&cq, 0x60000000u, 0x1234u) == ROME2_VFS_REG_OK);
    CHECK(cq.list_ptr_or_self_00 == 0x60000004u && cq.owner_or_arg_0c == 0x1234u);

    uint32_t reg_list[4] = {0x1111u, 0u, 0u, 0u};
    uint32_t reg_cnt = 1u;
    uint8_t inserted = 0u;
    CHECK(rome2_vfs_channel_adapter_register(reg_list, &reg_cnt, 4u, 0x1111u, &inserted) == ROME2_VFS_REG_OK && inserted == 0u);
    CHECK(rome2_vfs_channel_adapter_register(reg_list, &reg_cnt, 4u, 0x2222u, &inserted) == ROME2_VFS_REG_OK && inserted == 1u && reg_cnt == 2u);

    /* 6. 0x1055bff0, 0x10f71eb0, 0x10f78290, 0x10f80f40 */
    const uint8_t sbuf[4] = {0xaa, 0xbb, 0xcc, 0xdd};
    uint8_t sdst[4] = {0};
    uint32_t scursor = 2u;
    uint32_t savail = 2u;
    uint8_t need_fb = 0u;
    uint8_t hit_end = 0u;
    CHECK(rome2_vfs_stream_read_bytes_or_overflow(sbuf, 4u, &scursor, &savail, sdst, 2u, &need_fb, &hit_end) == ROME2_VFS_REG_OK);
    CHECK(need_fb == 0u && hit_end == 1u && sdst[0] == 0xccu && sdst[1] == 0xddu && scursor == 4u);
    CHECK(rome2_vfs_stream_read_bytes_or_overflow(sbuf, 4u, &scursor, &savail, sdst, 1u, &need_fb, &hit_end) == ROME2_VFS_REG_OK && need_fb == 1u);

    CHECK(rome2_vfs_bitrev8(0x05u) == 0xa0u);
    uint8_t bbuf[4] = {0};
    uint32_t bcursor = 0u;
    uint32_t bwritten = 0u;
    CHECK(rome2_vfs_write_ranged_bits(bbuf, 4u, &bcursor, 15u, 10u, 17u, &bwritten) == ROME2_VFS_REG_OK);
    CHECK(bwritten == 3u && bcursor == 3u && bbuf[0] == 0xa0u);

    uint32_t sub_dw[20] = {1u};
    uint8_t sub_by[20] = {1u};
    uint32_t st_40a8 = 5u;
    uint32_t st_40ac = 6u;
    CHECK(rome2_vfs_channel_slot_reset_flags(sub_dw, sub_by, &st_40a8, &st_40ac, 1u) == ROME2_VFS_REG_OK);
    CHECK(st_40a8 == 0u && st_40ac == 0u && sub_dw[0] == 0u && sub_by[0] == 0u);

    rome2_vfs_channel_slot_hdr24_32 cslots[2] = {
        {0x0100007fu, 27015u, 0u, 11u, 22u, 0u, 1u, {0}},
        {0x0200007fu, 27016u, 0u, 33u, 44u, 0u, 1u, {0}},
    };
    const uint32_t cstates[2] = {0u, 1u};
    const rome2_vfs_channel_slot_hdr24_32 ckey = {0x0200007fu, 27016u, 0u, 33u, 44u, 0u, 0u, {0}};
    CHECK(rome2_vfs_channel_find_active_slot(cslots, cstates, 2u, &ckey) == 1u);

    printf("test_vfs_fs_engine_codec_ops: ALL PASSED (%d checks)\n", checks);
    return 0;
}
