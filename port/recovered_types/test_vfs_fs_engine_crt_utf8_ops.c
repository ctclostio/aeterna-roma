#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_crt_utf8_ops.h"

static int g_checks = 0;
#define CHECK(cond) do { assert(cond); ++g_checks; } while (0)

static void test_buf_strtox_and_utf8(void) {
    /* Layouts + 0x116889a9, 0x11689010 */
    rome2_vfs_crt_mbstate8_32 st;
    rome2_vfs_crt_fp_nan_inf_table64_32 lut;
    rome2_vfs_crt_unique_heap_ptr4_32 p1 = { 0x1000u }, p2 = { 0x2000u };
    CHECK(sizeof(st) == 8u && sizeof(lut) == 64u && sizeof(p1) == 4u);

    rome2_vfs_crt_formatting_buffer1032_32 fb;
    memset(&fb, 0, sizeof(fb));
    CHECK(rome2_vfs_crt_fmt_buf_count_wide(&fb) == 0x100u);
    fb.heap_ptr_404 = 1u;
    fb.allocated_bytes_400 = 2048u;
    CHECK(rome2_vfs_crt_fmt_buf_count_wide(&fb) == 512u);

    uint32_t freed = 0u;
    CHECK(rome2_vfs_crt_unique_heap_ptr_assign(&p1, &p2, &freed) == 0x2000u);
    CHECK(freed == 0x1000u && p1.ptr_00 == 0x2000u && p2.ptr_00 == 0u);

    /* 0x1168d395, 0x1168e5d4, 0x1168e679 */
    CHECK(rome2_vfs_crt_is_overflow_condition_u32(4u, 0u) == 1u);
    CHECK(rome2_vfs_crt_is_overflow_condition_u32(3u, 0x80000001u) == 1u);
    CHECK(rome2_vfs_crt_is_overflow_condition_u32(3u, 0x80000000u) == 0u);
    CHECK(rome2_vfs_crt_is_overflow_condition_u32(1u, 0x80000000u) == 1u);

    const uint16_t wsrc[] = { 'a', 'b', 0 };
    size_t pos = 2u;
    int32_t err = 0;
    CHECK(rome2_vfs_crt_wstr_source_unget(wsrc, &pos, (uint16_t)'b', &err) == 1u && pos == 1u);
    CHECK(rome2_vfs_crt_wstr_source_unget(wsrc, &pos, (uint16_t)'Z', &err) == 0u && err == 22);

    CHECK(rome2_vfs_crt_atol("  -4250x", 16u) == -4250);
    CHECK(rome2_vfs_crt_atol("999999999999", 16u) == INT32_MAX);

    /* 0x1169d38d, 0x1169d3b9, 0x116b15ac */
    const uint8_t p_short[] = { 'A', 0 };
    const uint8_t p_long[] = { 'A', 'B', 'C', 'D' };
    CHECK(rome2_vfs_crt_utf8_lookahead_probe(p_short, 2u) == 2u);
    CHECK(rome2_vfs_crt_utf8_lookahead_probe(p_long, 4u) == 4u);

    memset(&st, 0, sizeof(st));
    const uint8_t u8_split[] = { 0xf0u, 0x9fu, 0x98u, 0x80u }; /* U+1F600 */
    uint32_t c32 = 0u;
    err = 0;
    CHECK(rome2_vfs_crt_mbrtoc32_utf8(&c32, u8_split, 2u, &st, &err) == (size_t)-2);
    CHECK(st.byte_04 == 4u && st.state_06 == 2u);
    CHECK(rome2_vfs_crt_mbrtoc32_utf8(&c32, u8_split + 2u, 2u, &st, &err) == 2u && c32 == 0x1f600u);
    CHECK(st.state_06 == 0u);

    uint16_t wc = 0u;
    CHECK(rome2_vfs_crt_mbrtowc_utf8(&wc, u8_split, 4u, &st, &err) == 4u && wc == 0xfffdu);
    const uint8_t bad_u8[] = { 0xc0u, 0x80u };
    CHECK(rome2_vfs_crt_mbrtoc32_utf8(&c32, bad_u8, 2u, &st, &err) == (size_t)-1 && err == 42);
}

static void test_stdio_fp_locale_and_lowio(void) {
    /* 0x1169e514, 0x116a66a3, 0x116a25d6, 0x116a5ca6 */
    uint8_t sbuf[8] = { 0 };
    size_t spos = 0u;
    int32_t scnt = 3;
    CHECK(rome2_vfs_crt_fputc_nolock('Z', sbuf, sizeof(sbuf), &spos, &scnt, 1u) == 'Z' && sbuf[0] == 'Z' && scnt == 2);
    CHECK(rome2_vfs_crt_fputwc_binary_nolock(0x1234u, sbuf, sizeof(sbuf), &spos, &scnt, 1u) == 0x1234u && sbuf[1] == 0x34u && sbuf[2] == 0x12u && scnt == 0);
    CHECK(rome2_vfs_crt_fputc_nolock('Q', sbuf, sizeof(sbuf), &spos, &scnt, 0u) == -1);

    rome2_vfs_crt_threadlocinfo184_32 tloc, gloc;
    memset(&tloc, 0, sizeof(tloc));
    memset(&gloc, 0, sizeof(gloc));
    tloc.lc_codepage_08 = 65001u;
    gloc.lc_codepage_08 = 1252u;
    CHECK(rome2_vfs_crt_lc_codepage_func(&tloc, &gloc, 1u) == 65001u);
    CHECK(rome2_vfs_crt_lc_codepage_func(&tloc, &gloc, 0u) == 1252u);

    uint8_t mbbuf[4] = { 0 };
    int32_t conv = 0;
    CHECK(rome2_vfs_crt_wctomb_s(&conv, mbbuf, sizeof(mbbuf), 0x20acu, 0xfde9u) == 0 && conv == 3 && mbbuf[0] == 0xe2u);
    CHECK(rome2_vfs_crt_wctomb_s(&conv, mbbuf, sizeof(mbbuf), 0x20acu, 0u) == 42);

    /* 0x116a5d7f, 0x116a6098, 0x116a6282, 0x116a63de, 0x116a649f */
    char fbuf[32] = { 0 };
    int32_t err = 0;
    CHECK(rome2_vfs_crt_fp_format_a(1.5, fbuf, sizeof(fbuf), 1, 0u, 2u, &err) == 0 && strncmp(fbuf, "0x", 2) == 0);
    CHECK(rome2_vfs_crt_fp_format_a(1.5, fbuf, 10u, 2, 0u, 2u, &err) == 34);
    CHECK(rome2_vfs_crt_fp_format_e(125.0, fbuf, sizeof(fbuf), 2, 1u, 2u, &err) == 0 && strchr(fbuf, 'E') != NULL);
    CHECK(rome2_vfs_crt_fp_format_f(3.25, fbuf, sizeof(fbuf), 2, &err) == 0 && strcmp(fbuf, "3.25") == 0);
    CHECK(rome2_vfs_crt_fp_format_g(0.5, fbuf, sizeof(fbuf), 2, 0u, 2u, &err) == 0 && strcmp(fbuf, "0.5") == 0);

    rome2_vfs_crt_fp_nan_inf_table64_32 glut;
    memset(&glut, 0, sizeof(glut));
    CHECK(rome2_vfs_crt_fp_format_nan_or_infinity(1u, 1u, fbuf, sizeof(fbuf), 1u, &glut) == 0 && strcmp(fbuf, "-INF") == 0);
    CHECK(rome2_vfs_crt_fp_format_nan_or_infinity(3u, 0u, fbuf, sizeof(fbuf), 0u, &glut) == 0 && strcmp(fbuf, "nan(snan)") == 0);
    CHECK(rome2_vfs_crt_fp_format_nan_or_infinity(4u, 0u, fbuf, 5u, 1u, &glut) == 0 && strcmp(fbuf, "NAN") == 0);

    /* 0x116a8a30, 0x116a8c79, 0x116aea59, 0x116afb0a, 0x116afb40..52, 0x116b1572, 0x116bd4f2, 0x116bd528 */
    CHECK(rome2_vfs_crt_lcmap_string_ex_uses_modern(1u) == 1u);
    CHECK(rome2_vfs_crt_lcmap_string_ex_uses_modern(0u) == 0u);

    uint16_t pw[256];
    memset(pw, 0, sizeof(pw));
    pw['A'] = 0x0001u;
    pw[0x81u] = 0x8000u;
    CHECK(rome2_vfs_crt_iswctype((uint16_t)'A', 0x0001u, pw, 0u) == 1);
    CHECK(rome2_vfs_crt_iswctype(0xffffu, 0x0001u, pw, 1u) == 0);
    CHECK(rome2_vfs_crt_isleadbyte_l(0x81, pw) == 1);
    CHECK(rome2_vfs_crt_isleadbyte_l('A', pw) == 0);

    rome2_vfs_crt_ioinfo56_32 ios[2];
    memset(ios, 0, sizeof(ios));
    ios[1].osfhnd_00 = 0x12345678u;
    ios[1].osfile_28 = 0x01u;
    int32_t doserr = 0;
    CHECK(rome2_vfs_crt_get_osfhandle(1, 2, ios, &err, &doserr) == 0x12345678u);
    CHECK(rome2_vfs_crt_get_osfhandle(0, 2, ios, &err, &doserr) == 0xffffffffu && err == 9);
    CHECK(rome2_vfs_crt_get_osfhandle(-2, 2, ios, &err, &doserr) == 0xffffffffu && err == 9);

    char snc[6];
    CHECK(rome2_vfs_crt_strncpy_s(snc, sizeof(snc), "abcdef", (size_t)-1, &err) == 80 && strcmp(snc, "abcde") == 0);
    CHECK(rome2_vfs_crt_strncpy_s(snc, sizeof(snc), "abcdef", 6u, &err) == 34 && snc[0] == '\0');
    CHECK(rome2_vfs_crt_strncpy_s(snc, sizeof(snc), "ok", 4u, &err) == 0 && strcmp(snc, "ok") == 0);

    int32_t tz = 28800, db = -3600, dl = 1;
    rome2_vfs_crt_tzname_pair8_32 tzp = { 0x11u, 0x22u };
    CHECK(rome2_vfs_crt_tz_timezone_ptr(&tz) == &tz);
    CHECK(rome2_vfs_crt_tz_dstbias_ptr(&db) == &db);
    CHECK(rome2_vfs_crt_tz_daylight_ptr(&dl) == &dl);
    CHECK(rome2_vfs_crt_tzname_base(&tzp)->dst_name_ptr_04 == 0x22u);

    uint32_t chnd = 0xfffffffeu;
    CHECK(rome2_vfs_crt_dcrt_console_output_ready(&chnd, 0x444u) == 1u && chnd == 0x444u);
    uint32_t attempts = 0u;
    CHECK(rome2_vfs_crt_dcrt_write_console(&chnd, 0u, 6u, 0x555u, 1u, &attempts) == 1u && chnd == 0x555u && attempts == 2u);
}

int main(void) {
    test_buf_strtox_and_utf8();
    test_stdio_fp_locale_and_lowio();
    printf("test_vfs_fs_engine_crt_utf8_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
