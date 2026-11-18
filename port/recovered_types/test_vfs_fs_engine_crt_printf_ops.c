#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_crt_printf_ops.h"

static int g_l48_fail = 0;
static int g_l48_checks = 0;

#define CHECK(expr)                                                     \
    do {                                                                \
        ++g_l48_checks;                                                 \
        if (!(expr)) {                                                  \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr);     \
            g_l48_fail = 1;                                             \
        }                                                               \
    } while (0)

static void test_div_printf_calendar_and_strtox(void)
{
    uint64_t rem = 0u, q;
    rome2_vfs_crt_wprintf_state64_32 ws;
    rome2_vfs_crt_scanf_input116_32 sinp;
    int32_t err = 0;
    uint32_t slot = 0u;
    const char str_unget[] = "abc";
    const char *cur = str_unget + 2;

    q = rome2_vfs_crt_aulldvrm(0x0000000300000007ULL, 5u, &rem);
    CHECK(q == (0x0000000300000007ULL / 5u) && rem == (0x0000000300000007ULL % 5u));

    /* State transitions in packed 91B table 0x1190ec70: from state 0 on '%' (0x25)? Check normal/flag/width! */
    CHECK(rome2_vfs_crt_wprintf_find_next_state((uint16_t)'-', 1u) == 2u);
    CHECK(rome2_vfs_crt_wprintf_find_next_state((uint16_t)'0', 1u) == 2u);
    CHECK(rome2_vfs_crt_wprintf_find_next_state((uint16_t)'d', 1u) == 7u);
    CHECK(rome2_vfs_crt_wprintf_find_next_state((uint16_t)'*', 2u) == 3u);

    (void)memset(&ws, 0, sizeof(ws));
    ws.cur_ch_32 = (uint16_t)'0';
    CHECK(rome2_vfs_crt_wprintf_state_case_flag(&ws) == 1u && ws.fmt_flags_20 == ROME2_VFS_L48_PRINTF_FLAG_ZERO);
    ws.cur_ch_32 = (uint16_t)'-';
    CHECK(rome2_vfs_crt_wprintf_state_case_flag(&ws) == 1u && (ws.fmt_flags_20 & ROME2_VFS_L48_PRINTF_FLAG_MINUS) != 0u);
    CHECK(rome2_vfs_crt_wprintf_state_case_normal(1u, &err) == 1u && err == 0);
    CHECK(rome2_vfs_crt_wprintf_state_case_normal(0u, &err) == 0u && err == ROME2_VFS_L44_EINVAL_MSVC);

    ws.cur_ch_32 = (uint16_t)'*';
    CHECK(rome2_vfs_crt_wprintf_state_case_precision(&ws, -5, 0, 1u) == 1u && ws.precision_28 == -1 && ws.valist_14 == 4u);
    CHECK(rome2_vfs_crt_wprintf_state_case_width(&ws, -12, 0, 1u) == 1u && ws.width_24 == 12 && ws.valist_14 == 8u);

    CHECK(rome2_vfs_crt_validate_nonnull_slot(&slot, &err) == 0u && err == ROME2_VFS_L44_EINVAL_MSVC);
    slot = 0x1000u;
    CHECK(rome2_vfs_crt_validate_nonnull_slot(&slot, &err) == 1u && err == 0);

    CHECK(rome2_vfs_crt_elapsed_leap_years(70) == 0);
    CHECK(rome2_vfs_crt_elapsed_leap_years(100) == 7);
    CHECK(rome2_vfs_crt_is_leap_year(100) == 1u);
    CHECK(rome2_vfs_crt_is_leap_year(200) == 0u);
    CHECK(rome2_vfs_crt_is_valid_month_day(100, 1, 29) == 1u);
    CHECK(rome2_vfs_crt_is_valid_month_day(200, 1, 29) == 0u);
    CHECK(rome2_vfs_crt_is_valid_month_day(120, 3, 31) == 0u);

    CHECK(rome2_vfs_crt_strtox_is_overflow_u64(4u, 0u) == 1u);
    CHECK(rome2_vfs_crt_strtox_is_overflow_u64(3u, 0x8000000000000001ULL) == 1u);
    CHECK(rome2_vfs_crt_strtox_is_overflow_u64(3u, 0x8000000000000000ULL) == 0u);
    CHECK(rome2_vfs_crt_strtox_is_overflow_u64(1u, 0x8000000000000000ULL) == 1u);

    CHECK(rome2_vfs_crt_cstr_source_unget(&cur, (uint8_t)'b', &err) == 1u && cur == str_unget + 1 && err == 0);
    CHECK(rome2_vfs_crt_cstr_source_unget(&cur, (uint8_t)'z', &err) == 0u && err == ROME2_VFS_L44_EINVAL_MSVC);

    (void)memset(&sinp, 0, sizeof(sinp));
    sinp.fmt_18.length_idx_20 = 3u;
    rome2_vfs_crt_fmt_parser_update_is_wide(&sinp.fmt_18);
    CHECK(sinp.fmt_18.is_wide_24 == 1u);
    sinp.fmt_18.length_idx_20 = 2u;
    rome2_vfs_crt_fmt_parser_update_is_wide(&sinp.fmt_18);
    CHECK(sinp.fmt_18.is_wide_24 == 0u);
}

static void test_scanf_ctype_fullpath_wcs_and_tz(void)
{
    uint16_t ctype[257];
    uint8_t bitmap[32];
    const char ws_str[] = " \t42";
    size_t pos = 0u;
    const char mb_stream[] = "\x81";
    uint8_t consumed = 0u, used_mb = 0u, retry = 0u, need_dup = 0u;
    uint32_t new_cap = 0u, wlen = 0u, dup_bytes = 0u;
    int32_t err = 0, out_val = 0;
    rome2_vfs_crt_win32_buffer24_32 wbuf;
    uint16_t w1[] = {'H', 'i', 0};
    uint16_t w2[] = {'h', 'I', 0};

    (void)memset(ctype, 0, sizeof(ctype));
    ctype[(uint8_t)' ' + 1u] = 0x0008u;
    ctype[(uint8_t)'\t' + 1u] = 0x0008u;
    ctype[0x81u + 1u] = 0x8000u;

    CHECK(rome2_vfs_crt_skip_whitespace_str(ws_str, &pos, ctype) == '4' && pos == 3u);
    (void)memset(bitmap, 0x5au, sizeof(bitmap));
    rome2_vfs_crt_invert_scanset_bitmap(bitmap);
    CHECK(bitmap[0] == 0xa5u && bitmap[31] == 0xa5u);

    CHECK(rome2_vfs_crt_process_literal_char_mb(ctype, 0x81u, 0x40u, mb_stream, &consumed) == 0u && consumed == 0u);
    CHECK(rome2_vfs_crt_process_literal_char_mb(ctype, 0x81u, 0x81u, mb_stream, &consumed) == 1u && consumed == 1u);

    CHECK(rome2_vfs_crt_lowio_fh_slot_offset(65) == 0x38u);
    CHECK(rome2_vfs_crt_ischartype_mb_l(ctype, ' ', 8u, 0u, 0u, &used_mb) == 8u && used_mb == 0u);
    CHECK(rome2_vfs_crt_ischartype_mb_l(ctype, 0x8140, 4u, 0x0004u, 1u, &used_mb) == 4u && used_mb == 1u);

    CHECK(rome2_vfs_crt_common_fullpath_plan(40u, 16u, 0u, 0, 0u, 1u, &retry, &new_cap, &wlen) == 0 && retry == 1u && new_cap == 41u);
    CHECK(rome2_vfs_crt_common_fullpath_plan(12u, 16u, 0u, 0, 1u, 1u, &retry, &new_cap, &wlen) == 0 && retry == 0u && wlen == 12u);

    (void)memset(&wbuf, 0, sizeof(wbuf));
    wbuf.data_08 = 0x0019ff00u;
    wbuf.size_words_10 = 18u;
    wbuf.allocated_14 = 0u;
    CHECK(rome2_vfs_crt_win32_buffer_detach_plan(&wbuf, &need_dup, &dup_bytes) == 1u && need_dup == 1u && dup_bytes == 36u);

    CHECK(rome2_vfs_crt_wcsicmp_l(w1, w2, 0u, &err) == 0 && err == 0);
    CHECK(rome2_vfs_crt_wcsicmp_l(w1, w2, 1u, &err) == 0 && err == 0);

    CHECK(rome2_vfs_crt_get_timezone(28800, &out_val, &err) == 0 && out_val == 28800 && err == 0);
    CHECK(rome2_vfs_crt_get_dstbias(-3600, &out_val, &err) == 0 && out_val == -3600 && err == 0);
    CHECK(rome2_vfs_crt_get_daylight(1, &out_val, &err) == 0 && out_val == 1 && err == 0);
    CHECK(rome2_vfs_crt_get_timezone(0, NULL, &err) == ROME2_VFS_L44_EINVAL_MSVC && err == ROME2_VFS_L44_EINVAL_MSVC);
}

int main(void)
{
    test_div_printf_calendar_and_strtox();
    test_scanf_ctype_fullpath_wcs_and_tz();
    if (g_l48_fail != 0) {
        return 1;
    }
    printf("test_vfs_fs_engine_crt_printf_ops: ALL PASSED (%d checks)\n", g_l48_checks);
    return 0;
}
