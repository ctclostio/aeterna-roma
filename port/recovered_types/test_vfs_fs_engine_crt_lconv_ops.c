#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_crt_lconv_ops.h"

static void test_wprintf_l49_helpers(void) {
    /* 0x1168949f: wprintf decimal parameter parser */
    uint16_t fmt[] = { (uint16_t)'%', (uint16_t)'1', (uint16_t)'2', (uint16_t)'s', 0u };
    uint32_t off = 2u;
    int32_t cached_errno = 0x0c;
    int32_t val = 0;
    assert(rome2_vfs_crt_wprintf_parse_decimal_param(fmt, &off, &cached_errno, &val) == 1u);
    assert(val == 12);
    assert(off == 3u);
    assert(cached_errno == 0x0c);

    uint16_t fmt_ov[] = { (uint16_t)'%', (uint16_t)'9', (uint16_t)'9', (uint16_t)'9',
                          (uint16_t)'9', (uint16_t)'9', (uint16_t)'9', (uint16_t)'9',
                          (uint16_t)'9', (uint16_t)'9', (uint16_t)'9', (uint16_t)'d', 0u };
    uint32_t off_ov = 2u;
    cached_errno = 0;
    assert(rome2_vfs_crt_wprintf_parse_decimal_param(fmt_ov, &off_ov, &cached_errno, &val) == 0u);
    assert(cached_errno == 0x22);
    assert(val == INT32_MAX);
    assert(off_ov == 2u);

    /* 0x11689e3f: normal single-char emitter */
    rome2_vfs_crt_wprintf_state64_32 st;
    uint16_t out[4] = { 0 };
    memset(&st, 0, sizeof(st));
    st.cur_ch_32 = (uint16_t)'W';
    st.chars_written_18 = 0;
    assert(rome2_vfs_crt_wprintf_emit_normal_char(&st, out, 2u) == 1u);
    assert(st.cap_exp_3c == 1u);
    assert(st.chars_written_18 == 1);
    assert(out[0] == (uint16_t)'W');
    st.cur_ch_32 = (uint16_t)'X';
    assert(rome2_vfs_crt_wprintf_emit_normal_char(&st, out, 1u) == 1u);
    assert(st.chars_written_18 == -1);

    /* 0x1168a992: specifier formatting planner */
    memset(&st, 0, sizeof(st));
    st.cur_ch_32 = (uint16_t)'x';
    st.fmt_flags_20 = 0x28u; /* '#' + '0' */
    st.width_24 = 8;
    st.suppress_38 = 3u;
    uint32_t eff = 0u, plen = 0u;
    int32_t lead = 0, zpad = 0, trail = 0;
    uint16_t prefix[2] = { 0 };
    assert(rome2_vfs_crt_wprintf_format_specifier_plan(&st, 1u, &eff, &lead, &zpad, &trail, prefix, &plen) == 1u);
    assert(plen == 2u && prefix[0] == (uint16_t)'0' && prefix[1] == (uint16_t)'x');
    assert(lead == 0 && zpad == 3 && trail == 0);

    st.cur_ch_32 = (uint16_t)'d';
    st.fmt_flags_20 = 0x05u; /* '-' + '+' */
    st.width_24 = 6;
    st.suppress_38 = 2u;
    assert(rome2_vfs_crt_wprintf_format_specifier_plan(&st, 1u, &eff, &lead, &zpad, &trail, prefix, &plen) == 1u);
    assert((eff & 0x10u) != 0u);
    assert(plen == 1u && prefix[0] == (uint16_t)'+');
    assert(lead == 0 && zpad == 0 && trail == 3);

    st.cur_ch_32 = (uint16_t)'@';
    assert(rome2_vfs_crt_wprintf_format_specifier_plan(&st, 1u, &eff, &lead, &zpad, &trail, prefix, &plen) == 0u);
}

static void test_win32_buffer_and_write_nolock(void) {
    /* 0x1168c795 & 0x116ae3a6 */
    rome2_vfs_crt_win32_buffer24_32 buf;
    int32_t err = 0;
    memset(&buf, 0, sizeof(buf));
    buf.allocated_14 = 1u;
    buf.capacity_words_0c = 64u;
    assert(rome2_vfs_crt_win32_buffer_set_range_error(&buf, &err) == 0x22u);
    assert(err == 0x22 && buf.allocated_14 == 0u && buf.capacity_words_0c == 0u);

    assert(rome2_vfs_crt_win32_buffer_alloc_words(&buf, 32u, 0x12340000u, 1u) == 0);
    assert(buf.data_08 == 0x12340000u && buf.capacity_words_0c == 32u && buf.allocated_14 == 1u);
    assert(rome2_vfs_crt_win32_buffer_alloc_words(&buf, 0x90000000u, 0u, 1u) == 0x0c);
    assert(buf.allocated_14 == 0u && buf.capacity_words_0c == 0u);

    /* 0x116ae892 */
    assert(rome2_vfs_crt_lowio_unlock_fh_offset(65) == 0x38u);
    assert(rome2_vfs_crt_lowio_unlock_fh_offset(-1) == UINT32_MAX);

    /* 0x116a520e */
    rome2_vfs_crt_ioinfo56_32 io;
    memset(&io, 0, sizeof(io));
    uint8_t seek_append = 0u, path = 0u;
    int32_t eno = 0, deno = 0;
    uint8_t payload[4] = { 0x41u, 0x00u, 0x1au, 0x00u };

    io.osfile_28 = 0xa0u; /* FAPPEND | FTEXT */
    io.pad_29[0] = 2u;    /* UTF-16LE */
    assert(rome2_vfs_crt_write_nolock_plan(&io, payload, 3u, 0u, 0u, 0u, 0, &seek_append, &path, &eno, &deno) == -1);
    assert(eno == 0x16);

    assert(rome2_vfs_crt_write_nolock_plan(&io, payload, 4u, 0u, 4u, 0u, 0, &seek_append, &path, &eno, &deno) == 4);
    assert(seek_append == 1u && path == ROME2_VFS_L49_WRITE_PATH_TEXT_UTF16);

    io.osfile_28 = 0x40u; /* FDEV */
    io.pad_29[0] = 0u;
    uint8_t ctrl_z[2] = { 0x1au, 0u };
    assert(rome2_vfs_crt_write_nolock_plan(&io, ctrl_z, 1u, 0u, 0u, 0u, 0, &seek_append, &path, &eno, &deno) == 0);
    eno = 0;
    assert(rome2_vfs_crt_write_nolock_plan(&io, payload, 1u, 0u, 0u, 5u, 13, &seek_append, &path, &eno, &deno) == -1);
    assert(eno == 9 && deno == 5);
}

static void test_locale_lconv_tz_and_matherr(void) {
    /* 0x116ae54f & 0x116b5b9b */
    uint8_t clmap[256];
    for (uint32_t i = 0u; i < 256u; ++i) {
        clmap[i] = (uint8_t)i;
    }
    clmap['Z'] = (uint8_t)'z';
    assert(rome2_vfs_crt_towlower_l((uint16_t)'Z', 1u, clmap, NULL) == (uint16_t)'z');
    assert(rome2_vfs_crt_towlower_l((uint16_t)'M', 0u, NULL, NULL) == (uint16_t)'m');

    uint32_t cp = 0u, flags = 0u, bytes = 0u;
    uint8_t heap = 0u;
    assert(rome2_vfs_crt_get_string_type_a_plan(0u, 65001u, 1u, 16u, &cp, &flags, &bytes, &heap) == 1u);
    assert(cp == 65001u && flags == 9u && bytes == 40u && heap == 0u);
    assert(rome2_vfs_crt_get_string_type_a_plan(1252u, 65001u, 0u, 600u, &cp, &flags, &bytes, &heap) == 1u);
    assert(cp == 1252u && flags == 1u && bytes == 1208u && heap == 1u);

    /* 0x116b034a, 0x116b03a7, lock wrappers */
    int32_t tz_once = 0;
    uint8_t ran = 0u;
    rome2_vfs_crt_tzset_once(&tz_once, &ran);
    assert(tz_once == 1 && ran == 1u);
    rome2_vfs_crt_tzset_once(&tz_once, &ran);
    assert(tz_once == 1 && ran == 0u);
    assert(rome2_vfs_crt_isindst_locked(126, 0, 1u) == 0);
    assert(rome2_vfs_crt_isindst_locked(126, 1, 1u) == 1);
    assert(rome2_vfs_crt_unlock_index_for_helper(0x116b5877u) == ROME2_VFS_L49_LOCK_EXIT);
    assert(rome2_vfs_crt_unlock_index_for_helper(0x116b5fc7u) == ROME2_VFS_L49_LOCK_SETLOCALE);
    assert(rome2_vfs_crt_unlock_index_for_helper(0x116b4bcfu) == ROME2_VFS_L49_LOCK_MBCP);

    /* 0x116b5e63, 0x116b5e8c, 0x116b5ebd */
    rome2_vfs_crt_lc_time_data180_32 lct;
    memset(&lct, 0, sizeof(lct));
    lct.refcount_b0 = 1;
    assert(rome2_vfs_crt_lc_time_add_ref(&lct, 1u) == INT32_MAX);
    assert(rome2_vfs_crt_lc_time_add_ref(&lct, 0u) == 2);
    assert(rome2_vfs_crt_lc_time_release_ref(&lct, 0u) == 1);
    assert(rome2_vfs_crt_lc_time_should_free(&lct, 0u) == 0u);
    assert(rome2_vfs_crt_lc_time_release_ref(&lct, 0u) == 0);
    assert(rome2_vfs_crt_lc_time_should_free(&lct, 0u) == 1u);
    assert(rome2_vfs_crt_lc_time_should_free(&lct, 1u) == 0u);

    /* 0x116b5fe8, 0x116b60c7, 0x116b657c */
    uint32_t dst_loc = 0x20001000u;
    int32_t old_rc = 1, new_rc = 0;
    uint8_t free_old = 0u;
    assert(rome2_vfs_crt_updatetlocinfo_nolock(&dst_loc, 0x20002000u, &new_rc, &old_rc, 0x119ebf40u, &free_old) == 0x20002000u);
    assert(dst_loc == 0x20002000u && new_rc == 1 && old_rc == 0 && free_old == 1u);

    rome2_vfs_crt_lconv80_32 def_lc, custom_lc;
    memset(&def_lc, 0x10, sizeof(def_lc));
    custom_lc = def_lc;
    custom_lc.decimal_point_00 = 0x30000001u;
    custom_lc.w_thousands_sep_34 = 0x30000002u;
    custom_lc.currency_symbol_10 = 0x30000003u;
    custom_lc.w_negative_sign_4c = 0x30000004u;
    uint32_t mon_ptrs[13] = { 0 };
    uint32_t num_ptrs[5] = { 0 };
    assert(rome2_vfs_crt_free_lconv_mon_collect(&custom_lc, &def_lc, mon_ptrs) == 2u);
    assert(mon_ptrs[0] == 0x30000003u && mon_ptrs[1] == 0x30000004u);
    assert(rome2_vfs_crt_free_lconv_num_collect(&custom_lc, &def_lc, num_ptrs) == 2u);
    assert(num_ptrs[0] == 0x30000001u && num_ptrs[1] == 0x30000002u);

    /* 0x116bc61a & 0x116bcfc0 */
    uint16_t probe[4] = { 0 };
    rome2_vfs_crt_wgetcwd_default_drive_probe(0u, probe);
    assert(probe[0] == (uint16_t)'.' && probe[1] == 0u);
    rome2_vfs_crt_wgetcwd_default_drive_probe(3u, probe);
    assert(probe[0] == (uint16_t)'C' && probe[1] == (uint16_t)':' && probe[2] == (uint16_t)'.' && probe[3] == 0u);

    rome2_vfs_crt_math_exception32_32 exc;
    memset(&exc, 0, sizeof(exc));
    uint8_t exc_flag = 0u, raise_exc = 0u, set_fp = 0u, call_user = 0u;
    int32_t fb_err = 0;
    exc.type_00 = 3; /* OVERFLOW -> 0x11 -> ERANGE */
    rome2_vfs_crt_raise_matherr_plan(0x16, &exc, 0u, 0u, &exc_flag, &raise_exc, &set_fp, &call_user, &fb_err);
    assert(exc_flag == 0x11u && raise_exc == 1u && set_fp == 1u && call_user == 0u && fb_err == 0x22);

    exc.type_00 = 1; /* DOMAIN -> 0x08 -> EDOM unless user matherr */
    rome2_vfs_crt_raise_matherr_plan(0x11, &exc, 0u, 1u, &exc_flag, &raise_exc, &set_fp, &call_user, &fb_err);
    assert(exc_flag == 0x08u && raise_exc == 1u && set_fp == 0u && call_user == 1u && fb_err == 0);
}

int main(void) {
    test_wprintf_l49_helpers();
    test_win32_buffer_and_write_nolock();
    test_locale_lconv_tz_and_matherr();
    printf("test_vfs_fs_engine_crt_lconv_ops: ALL PASSED (52 checks)\n");
    return 0;
}
