#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_fpfmt_ops.h"

static int g_checks = 0;
#define CHECK(cond) do { assert(cond); ++g_checks; } while (0)

static void test_fmt_buf_specifier_and_radix(void) {
    /* Layouts + 0x11688991 / 0x116889c2 / 0x11688a3f / 0x11688b3c */
    rome2_vfs_crt_formatting_buffer1032_32 fb;
    memset(&fb, 0, sizeof(fb));
    CHECK(sizeof(fb) == 1032u);
    CHECK(rome2_vfs_crt_fmt_buf_count_wchar(&fb) == 0x200u);
    CHECK(rome2_vfs_crt_fmt_buf_scratch_offset(&fb) == 0x200u);

    int32_t err = 0;
    CHECK(rome2_vfs_crt_fmt_buf_ensure_wchar(&fb, 0x80000000u, 1u, &err) == 0u && err == 12);
    CHECK(rome2_vfs_crt_fmt_buf_ensure_dword(&fb, 0x40000000u, 1u, &err) == 0u && err == 12);
    CHECK(rome2_vfs_crt_fmt_buf_ensure_wchar(&fb, 512u, 1u, &err) == 1u && fb.heap_ptr_404 == 0u);
    CHECK(rome2_vfs_crt_fmt_buf_ensure_wchar(&fb, 600u, 1u, &err) == 1u && fb.heap_ptr_404 == 1u);
    CHECK(rome2_vfs_crt_fmt_buf_count_wchar(&fb) == 600u);
    CHECK(rome2_vfs_crt_fmt_buf_ensure_dword(&fb, 400u, 1u, &err) == 1u && fb.allocated_bytes_400 == 1600u);
    CHECK(rome2_vfs_crt_fmt_buf_count_wchar(&fb) == 800u);

    /* 0x11688aee */
    CHECK(rome2_vfs_crt_is_wide_specifier(0u, (uint16_t)'c', 2) == 0u);
    CHECK(rome2_vfs_crt_is_wide_specifier(0u, (uint16_t)'s', 3) == 1u);
    CHECK(rome2_vfs_crt_is_wide_specifier(0u, (uint16_t)'s', 12) == 1u);
    CHECK(rome2_vfs_crt_is_wide_specifier(0u, (uint16_t)'s', 0) == 0u);
    CHECK(rome2_vfs_crt_is_wide_specifier(4u, (uint16_t)'s', 0) == 1u);
    CHECK(rome2_vfs_crt_is_wide_specifier(0u, (uint16_t)'S', 0) == 1u);
    CHECK(rome2_vfs_crt_is_wide_specifier(4u, (uint16_t)'S', 0) == 0u);

    /* 0x11688bcd & 0x11688ce2 */
    uint16_t wbuf[64] = { 0 };
    uint32_t start_i = 0u, wlen = 0u;
    int32_t min_d = 4;
    rome2_vfs_crt_uint32_to_wstring(0x2au, 16u, 1u, &min_d, wbuf, 64u, &start_i, &wlen);
    CHECK(wlen == 4u && start_i == 60u);
    CHECK(wbuf[60] == (uint16_t)'0' && wbuf[62] == (uint16_t)'2' && wbuf[63] == (uint16_t)'A');

    min_d = 1;
    rome2_vfs_crt_uint64_to_wstring(0x10000000aULL, 16u, 0u, &min_d, wbuf, 64u, &start_i, &wlen);
    CHECK(wlen == 9u && wbuf[start_i] == (uint16_t)'1' && wbuf[start_i + 8u] == (uint16_t)'a');

    /* 0x11689271 & 0x116893cf */
    char fp1[32] = "1.2500e+02";
    rome2_vfs_crt_crop_zeroes(fp1, sizeof(fp1), '.');
    CHECK(strcmp(fp1, "1.25e+02") == 0);
    char fp2[32] = "4.000";
    rome2_vfs_crt_crop_zeroes(fp2, sizeof(fp2), '.');
    CHECK(strcmp(fp2, "4") == 0);
    char fp3[32] = "0x1p+0";
    rome2_vfs_crt_force_decimal_point(fp3, sizeof(fp3), '.');
    CHECK(strcmp(fp3, "0x1.p+0") == 0);
    char fp4[32] = "3e+00";
    rome2_vfs_crt_force_decimal_point(fp4, sizeof(fp4), ',');
    CHECK(strcmp(fp4, "3,e+00") == 0);

    /* 0x1168b801 */
    uint8_t lead_tbl[256];
    memset(lead_tbl, 0, sizeof(lead_tbl));
    lead_tbl[0x82] = 1u;
    const uint8_t mb[] = { 'A', 0x82u, 0xa0u, 'B', 0u };
    CHECK(rome2_vfs_crt_wprintf_mbchar_count(mb, sizeof(mb), 10, lead_tbl) == 3);
    CHECK(rome2_vfs_crt_wprintf_mbchar_count(mb, sizeof(mb), 2, lead_tbl) == 2);
}

static void test_parse_utf8_seek_wcsnlen_and_tz(void) {
    /* 0x1168d62c */
    const uint16_t wneg[] = { ' ', ' ', '-', '0', 'x', '2', '0', 'Z', 0 };
    size_t end_i = 0u;
    int32_t err = 0;
    CHECK((int32_t)rome2_vfs_crt_parse_uint32_wstr(wneg, 9u, &end_i, 0, 1u, &err) == -32 && end_i == 7u && err == 0);
    CHECK(rome2_vfs_crt_parse_uint32_wstr(wneg, 9u, &end_i, 1, 1u, &err) == 0u && err == 22);
    const uint16_t wov[] = { '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', 0 };
    err = 0;
    CHECK(rome2_vfs_crt_parse_uint32_wstr(wov, 12u, &end_i, 10, 0u, &err) == 0xffffffffu && err == 34);

    /* 0x1169d3f9 */
    const uint8_t u8[] = { 0x41u, 0xf0u, 0x9fu, 0x98u, 0x80u, 0u }; /* "A" + U+1F600 */
    const uint8_t *ps = u8;
    CHECK(rome2_vfs_crt_mbsrtowcs_utf8(NULL, &ps, 0u, &err) == 3u);
    uint16_t wdst[8] = { 0 };
    err = 0;
    CHECK(rome2_vfs_crt_mbsrtowcs_utf8(wdst, &ps, 8u, &err) == 3u);
    CHECK(ps == NULL && wdst[0] == 0x41u && wdst[1] == 0xd83du && wdst[2] == 0xde00u && wdst[3] == 0u);

    /* 0x1169e75f & 0x116a4118 */
    rome2_vfs_crt_ioinfo56_32 io;
    memset(&io, 0, sizeof(io));
    io.osfile_28 = 0x03u;
    int32_t doserr = 0;
    CHECK(rome2_vfs_crt_common_lseek64_nolock(1u, 1u, 1024, 0u, &io, &err, &doserr) == 1024);
    CHECK((io.osfile_28 & 0x02u) == 0u);
    CHECK(rome2_vfs_crt_common_lseek64_nolock(0u, 1u, 0, 0u, &io, &err, &doserr) == -1 && err == 9);
    CHECK(rome2_vfs_crt_wcsnlen(wdst, 2u) == 2u);
    CHECK(rome2_vfs_crt_wcsnlen(wdst, 8u) == 3u);

    /* 0x116a59ef & 0x116a5b31 */
    uint16_t wc = 0u;
    uint32_t mw = 7u, ms = 9u;
    const uint8_t u8_euro[] = { 0xe2u, 0x82u, 0xacu, 0u };
    CHECK(rome2_vfs_crt_mbtowc_l(&wc, NULL, 0u, 0xfde9u, &mw, &ms, &err) == 0 && mw == 0u && ms == 0u);
    CHECK(rome2_vfs_crt_mbtowc_l(&wc, u8_euro, 3u, 0xfde9u, &mw, &ms, &err) == 3 && wc == 0x20acu);
    CHECK(rome2_vfs_crt_mbtowc(&wc, (const uint8_t *)"X", 1u, &err) == 1 && wc == (uint16_t)'X');

    /* 0x116a6568, 0x116a66d3, 0x116a67fc, 0x116a816e */
    char fbuf[32] = { 0 }, sbuf[32] = { 0 };
    double dv = -INFINITY;
    CHECK(rome2_vfs_crt_acrt_fp_format(&dv, fbuf, sizeof(fbuf), sbuf, sizeof(sbuf), 'A', 2, 0u, &err) == 0);
    CHECK(strcmp(fbuf, "-INF") == 0);
    dv = 12.5;
    CHECK(rome2_vfs_crt_acrt_fp_format(&dv, fbuf, sizeof(fbuf), sbuf, sizeof(sbuf), 'f', 2, 0x10u, &err) == 0);
    CHECK(strcmp(fbuf, "12.50") == 0);

    uint8_t io_out[8] = { 0 };
    size_t io_w = 0u;
    io.osfile_28 = 0x80u;
    io.pad_29[0] = 0u;
    CHECK(rome2_vfs_crt_fputwc_nolock(0x20acu, 0u, &io, io_out, sizeof(io_out), &io_w) == 0x20acu);
    CHECK(io_w == 3u && io_out[0] == 0xe2u && io_out[1] == 0x82u && io_out[2] == 0xacu);

    CHECK(rome2_vfs_crt_get_printf_count_output(0xbb40e64fu, 0xbb40e64eu) == 1);
    CHECK(rome2_vfs_crt_get_printf_count_output(0xbb40e64eu, 0xbb40e64eu) == 0);

    uint32_t out_fl = 0u;
    uint8_t keep_dc = 9u, keep_ud = 9u;
    rome2_vfs_crt_sanitize_wctomb_flags(0xfde9u, 0x80u, 1u, 1u, &out_fl, &keep_dc, &keep_ud);
    CHECK(out_fl == 0x80u && keep_dc == 0u && keep_ud == 0u);
    rome2_vfs_crt_sanitize_wctomb_flags(1252u, 0x80u, 1u, 1u, &out_fl, &keep_dc, &keep_ud);
    CHECK(out_fl == 0u && keep_dc == 1u && keep_ud == 1u);

    /* 0x116afdf6, 0x116aff36, 0x116b0111 */
    rome2_vfs_crt_tz_runtime_state tz;
    memset(&tz, 0, sizeof(tz));
    CHECK(rome2_vfs_crt_tz_cvtdate(&tz, 0, 1, 120, 2, 2, 0, 0, 2, 0, 0, 0, 0) == 1u);
    CHECK(tz.dststart.yr_00 == 120 && tz.dststart.yd_04 == 67 && tz.dststart.ms_08 == 7200000);
    CHECK(rome2_vfs_crt_tz_cvtdate(&tz, 1, 1, 120, 10, 1, 0, 0, 2, 0, 0, 0, -3600) == 1u);
    CHECK(tz.dstend.yr_00 == 120 && tz.dstend.yd_04 == 305 && tz.dstend.ms_08 == 3600000);

    rome2_vfs_crt_tzset_from_env_nolock(&tz, "PST8PDT");
    CHECK(tz.timezone_sec == 28800 && tz.daylight == 1);
    CHECK(strcmp(tz.std_name, "PST") == 0 && strcmp(tz.dst_name, "PDT") == 0);

    rome2_vfs_crt_time_zone_info172_32 tzi;
    rome2_vfs_crt_tzname_pair8_32 tzp = { 0x12126214u, 0x1212621cu };
    CHECK(sizeof(tzi) == 172u && sizeof(tzp) == 8u);
    memset(&tzi, 0, sizeof(tzi));
    tzi.bias_00 = 480;
    tzi.standard_name_04[0] = 'P'; tzi.standard_name_04[1] = 'S'; tzi.standard_name_04[2] = 'T';
    tzi.daylight_date_98[1] = 3u;
    tzi.daylight_bias_a8 = -60;
    tzi.daylight_name_58[0] = 'P'; tzi.daylight_name_58[1] = 'D'; tzi.daylight_name_58[2] = 'T';
    rome2_vfs_crt_tzset_from_system_nolock(&tz, 1u, &tzi);
    CHECK(tz.tz_api_used == 1 && tz.timezone_sec == 28800 && tz.daylight == 1 && tz.dstbias_sec == -3600);
    CHECK(strcmp(tz.std_name, "PST") == 0 && strcmp(tz.dst_name, "PDT") == 0);

    /* 0x116b608e, 0x116b67f4, 0x116bc582, 0x116bd871 */
    uint16_t put_ch = 0u;
    CHECK(rome2_vfs_crt_putwch_nolock(0x41u, 1u, 1u, &put_ch) == 0x41u && put_ch == 0x41u);
    CHECK(rome2_vfs_crt_putwch_nolock(0x41u, 0u, 1u, &put_ch) == 0xffffu);

    void *arr[2] = { malloc(8u), malloc(16u) };
    CHECK(rome2_vfs_crt_free_crt_array(arr, 2u) == 2u && arr[0] == NULL && arr[1] == NULL);

    uint16_t root_path[4] = { 0 };
    CHECK(rome2_vfs_crt_validdrive(0u, 0u, root_path, &err, &doserr) == 1);
    CHECK(rome2_vfs_crt_validdrive(3u, 3u, root_path, &err, &doserr) == 1 && root_path[0] == (uint16_t)'C');
    CHECK(rome2_vfs_crt_validdrive(27u, 3u, root_path, &err, &doserr) == 0 && err == 13 && doserr == 15);

    const uint16_t wsrc[] = { 'a', 'b', 0, 'c' };
    CHECK(rome2_vfs_crt_lcmap_wchar_len(wsrc, 4) == 3);
    CHECK(rome2_vfs_crt_lcmap_wchar_len(wsrc, 2) == 2);
}

int main(void) {
    test_fmt_buf_specifier_and_radix();
    test_parse_utf8_seek_wcsnlen_and_tz();
    printf("test_vfs_fs_engine_crt_fpfmt_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
