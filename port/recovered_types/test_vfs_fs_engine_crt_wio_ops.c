#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_crt_wio_ops.h"

static void test_wprintf_type_handlers(void) {
    /* 0x1168750e (_freea) & 0x11688dbf / 0x1168b9ea */
    assert(rome2_vfs_crt_freea_needs_heap_free(0u, 0xddddu) == 0u);
    assert(rome2_vfs_crt_freea_needs_heap_free(1u, 0xccccu) == 0u);
    assert(rome2_vfs_crt_freea_needs_heap_free(1u, 0xddddu) == 1u);

    uint16_t ch_slot = 0u;
    assert(rome2_vfs_crt_stream_write_char(0x1000u, 0u, (uint16_t)'A', &ch_slot, 0u) == 1u);
    assert(ch_slot == 0u);
    assert(rome2_vfs_crt_stream_write_char(0u, 1u, (uint16_t)'B', &ch_slot, 1u) == 1u);
    assert(ch_slot == (uint16_t)'B');

    uint16_t pad_buf[6] = { 0 };
    int32_t written = 1;
    rome2_vfs_crt_write_multiple_chars((uint16_t)'0', 3, pad_buf, 6u, &written);
    assert(written == 4 && pad_buf[1] == (uint16_t)'0' && pad_buf[3] == (uint16_t)'0');
    rome2_vfs_crt_write_multiple_chars((uint16_t)'0', 5, pad_buf, 5u, &written);
    assert(written == -1);

    /* 0x1168af61 (%Z), 0x1168b10a (%a..g), 0x1168b2ff (%c), 0x1168b4e6..0x1168b78e */
    rome2_vfs_crt_wprintf_state64_32 st;
    rome2_vfs_crt_unicode_string8_32 us = { 10u, 12u, 0x20001000u };
    memset(&st, 0, sizeof(st));
    assert(rome2_vfs_crt_wprintf_type_z(&st, &us, 1u) == 1u);
    assert(st.cap_exp_3c == 1u && st.suppress_38 == 5u && st.pad_34 == 0x20001000u);
    assert(rome2_vfs_crt_wprintf_type_z(&st, NULL, 1u) == 1u && st.suppress_38 == 6u && st.cap_exp_3c == 0u);

    st.cur_ch_32 = (uint16_t)'a';
    st.precision_28 = -1;
    st.fmt_flags_20 = 0x08u;
    rome2_vfs_crt_wprintf_type_a_setup(&st, 1u, 1u);
    assert(st.precision_28 == 13 && (st.fmt_flags_20 & 0x50u) == 0x50u);
    assert((st.fmt_flags_20 & 0x08u) == 0u && st.cur_ch_32 == (uint16_t)'s');

    assert(rome2_vfs_crt_wprintf_type_c(&st, 0u, 0u) == 1u && st.byte_30 == 1u);

    uint16_t digits[66] = { 0 };
    memset(&st, 0, sizeof(st));
    st.fmt_flags_20 = 0x20u; /* '#' */
    st.precision_28 = -1;
    rome2_vfs_crt_wprintf_type_o_flags(&st);
    assert((st.fmt_flags_20 & 0x80u) != 0u);
    assert(rome2_vfs_crt_wprintf_type_integer(&st, 12u, 0u, 8u, 0u, digits) == 1u);
    assert(digits[0] == (uint16_t)'0' && digits[1] == (uint16_t)'1' && digits[2] == (uint16_t)'4');

    memset(&st, 0, sizeof(st));
    st.precision_28 = -1;
    rome2_vfs_crt_wprintf_type_p_setup(&st);
    assert(st.precision_28 == 8 && st.length_mod_2c == 0x0au);
    assert(rome2_vfs_crt_wprintf_type_integer(&st, 0x1a2bu, 0u, 16u, 1u, digits) == 1u);
    assert(st.suppress_38 == 8u && digits[0] == (uint16_t)'0' && digits[4] == (uint16_t)'1' && digits[7] == (uint16_t)'B');

    int64_t n_out = 0;
    int32_t err = 0;
    st.chars_written_18 = 42;
    assert(rome2_vfs_crt_wprintf_type_n(&st, 1u, 8, &n_out, &err) == 1u && n_out == 42 && st.byte_30 == 1u);
    assert(rome2_vfs_crt_wprintf_type_n(&st, 0u, 4, &n_out, &err) == 0u && err == 0x16);

    rome2_vfs_crt_wprintf_type_s_len(&st, 9u, 1u, 0u);
    assert(st.cap_exp_3c == 0u && st.suppress_38 == 6u);

    uint16_t wdst[16] = { 0 };
    int32_t cw = 0;
    st.cap_exp_3c = 1u;
    st.suppress_38 = 4u;
    assert(rome2_vfs_crt_wprintf_write_stored(&st, NULL, digits + 4u, wdst, 16u, &cw) == 1u && cw == 4 && wdst[3] == (uint16_t)'B');
}

static void test_lowio_text_dst_and_locale(void) {
    /* 0x1169df07, 0x1169e7f6, 0x116a2005 */
    const uint16_t wnum[] = { (uint16_t)' ', (uint16_t)'-', (uint16_t)'0', (uint16_t)'x', (uint16_t)'1', (uint16_t)'f', (uint16_t)'Z', 0u };
    size_t end_i = 0u;
    int32_t err = 0;
    assert(rome2_vfs_crt_wcstol_ascii(wnum, &end_i, 0, &err) == -31 && end_i == 6u && err == 0);

    assert(rome2_vfs_crt_lseeki64_clamp(100, 500, -50, 2u, &err) == 450);
    assert(rome2_vfs_crt_lseeki64_clamp(10, 500, -20, 1u, &err) == -1 && err == 0x16);
    assert(rome2_vfs_crt_raise_exc_default_flag() == 0u);

    /* 0x116a49a3..0x116a4fea */
    int8_t trail_tbl[256];
    memset(trail_tbl, 0, sizeof(trail_tbl));
    trail_tbl[0xe2] = 2;
    assert(rome2_vfs_crt_utf8_seq_bytes(0xe2u, trail_tbl) == 3);

    rome2_vfs_crt_ioinfo56_32 io;
    memset(&io, 0, sizeof(io));
    io.osfile_28 = 0x80u;
    io.pad_29[0] = 1u;
    assert(rome2_vfs_crt_write_requires_double_translation(1u, &io, 0u, 1u) == 1u);

    const uint8_t asrc[3] = { (uint8_t)'a', 0x0au, (uint8_t)'b' };
    uint8_t adst[8] = { 0 };
    size_t adst_len = 0u;
    rome2_vfs_crt_lowio_write_result12_32 wres;
    rome2_vfs_crt_write_text_ansi_lf_expand(asrc, 3u, adst, 8u, &adst_len, &wres);
    assert(adst_len == 4u && adst[1] == 0x0du && adst[2] == 0x0au && wres.bytes_written_04 == 3u && wres.extra_lf_or_chars_08 == 1u);

    const uint16_t wsrc[2] = { 0x000au, (uint16_t)'Z' };
    uint16_t wexp[8] = { 0 };
    size_t wlen = 0u;
    rome2_vfs_crt_write_text_utf16_lf_expand(wsrc, 2u, wexp, 8u, &wlen, &wres);
    assert(wlen == 3u && wexp[0] == 0x000du && wexp[1] == 0x000au && wres.bytes_written_04 == 4u && wres.extra_lf_or_chars_08 == 2u);

    /* 0x116ae350, 0x116ae3e5 */
    rome2_vfs_crt_win32_buffer24_32 wb;
    uint8_t freed = 0u;
    uint32_t out_p = 0u;
    memset(&wb, 0, sizeof(wb));
    wb.allocated_14 = 1u;
    wb.data_08 = 0x20004000u;
    rome2_vfs_crt_win32_buffer_deallocate(&wb, &freed);
    assert(freed == 1u && wb.allocated_14 == 0u && wb.data_08 == 0u);
    assert(rome2_vfs_crt_win32_buffer_dyn_alloc_status(0u, &out_p) == 0x0c);
    assert(rome2_vfs_crt_win32_buffer_dyn_alloc_status(0x30001000u, &out_p) == 0 && out_p == 0x30001000u);

    /* 0x116afbdc, 0x116b026c, 0x116b039e, 0x116b03f2, 0x116b6aa8, 0x116bc428, 0x116bc636 */
    rome2_vfs_crt_tz_transition_date12_32 ds = { 126, 67, 7200000 };
    rome2_vfs_crt_tz_transition_date12_32 de = { 126, 305, 7200000 };
    assert(rome2_vfs_crt_isindst_compare_hemisphere(&ds, &de, 180, 0) == 1);
    assert(rome2_vfs_crt_isindst_compare_hemisphere(&ds, &de, 67, 7199999) == 0);
    assert(rome2_vfs_crt_isindst_compare_hemisphere(&ds, &de, 67, 7200000) == 1);
    assert(rome2_vfs_crt_isindst_compare_hemisphere(&de, &ds, 10, 0) == 1); /* southern hemisphere */

    int32_t api_used = 1;
    rome2_vfs_crt_tzset_nolock_reset(&ds, &de, &api_used);
    assert(ds.yr_00 == -1 && de.yr_00 == -1 && api_used == 0);
    assert(rome2_vfs_crt_unlock6_index() == ROME2_VFS_L50_LOCK_TZ);
    assert(rome2_vfs_crt_lc_time_free_slot_count() == 87u);

    int32_t deno = 0;
    assert(rome2_vfs_crt_wgetdcwd_validate_args(2, 128, 0u, &err, &deno) == 0u && err == 0x0d && deno == 0x0f);
    assert(rome2_vfs_crt_wgetdcwd_validate_args(0, 128, 0u, &err, &deno) == 1u);
    assert(rome2_vfs_crt_towlower_full_l(0xffffu, 1u, NULL, NULL) == 0xffffu);
    assert(rome2_vfs_crt_towlower_full_l((uint16_t)'G', 0u, NULL, NULL) == (uint16_t)'g');
}

int main(void) {
    test_wprintf_type_handlers();
    test_lowio_text_dst_and_locale();
    printf("test_vfs_fs_engine_crt_wio_ops: ALL PASSED (50 checks)\n");
    return 0;
}
