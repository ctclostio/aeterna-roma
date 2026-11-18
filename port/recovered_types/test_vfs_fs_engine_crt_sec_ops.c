#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_sec_ops.h"

static void check_fail(const char *msg, int line)
{
    fprintf(stderr, "FAIL line %d: %s\n", line, msg);
    exit(1);
}

#define CHECK(cond) do { if (!(cond)) check_fail(#cond, __LINE__); } while (0)

static void test_layouts_chkstk_and_security(void)
{
    rome2_vfs_win32_exception_pointers8_32 ptrs;
    rome2_vfs_win32_exception_record80_32 rec;
    rome2_vfs_crt_fmt_parser76_32 fp;
    rome2_vfs_crt_math_exception32_32 mex;
    uint32_t pages = 0u;

    CHECK(sizeof(ptrs) == 0x08u);
    CHECK(sizeof(rec) == 0x50u);
    CHECK(sizeof(fp) == 0x4cu);
    CHECK(sizeof(mex) == 0x20u);

    CHECK(rome2_vfs_crt_chkstk_plan(0x0019f020u, 0x3200u, &pages) == 0x0019be20u && pages == 4u);
    CHECK(rome2_vfs_crt_chkstk_plan(0x0019f100u, 0x40u, &pages) == 0x0019f0c0u && pages == 0u);
    CHECK(rome2_vfs_crt_security_check_cookie(0xbb40e64eu, 0xbb40e64eu) == 1u);
    CHECK(rome2_vfs_crt_security_check_cookie(0xdeadbeefu, 0xbb40e64eu) == 0u);

    CHECK(rome2_vfs_crt_raise_secfail_record_init(&rec, &ptrs, 0xc0000409u, 1u, 0x10101010u, 0x2000u, 0x2060u) == ROME2_VFS_REG_OK);
    CHECK(rec.exception_code_00 == 0xc0000409u && rec.exception_address_0c == 0x10101010u && ptrs.context_record_04 == 0x2060u);
}

static void test_stdio_input_and_mbs_to_wcs(void)
{
    const char text[] = "ab";
    rome2_vfs_crt_string_input_adapter ad;
    rome2_vfs_crt_fmt_parser76_32 fp;
    size_t off = 0u, wlen = 0u;
    int32_t err = 0;
    uint16_t wbuf[16];

    ad.begin = text;
    ad.end = text + 2;
    ad.cur = text;
    CHECK(rome2_vfs_crt_string_input_validate(&ad, &err) == 1u);
    CHECK(rome2_vfs_crt_string_input_get(&ad) == 'a' && rome2_vfs_crt_string_input_get(&ad) == 'b');
    CHECK(rome2_vfs_crt_string_input_get(&ad) == -1);
    rome2_vfs_crt_string_input_unget(&ad, 'b');
    CHECK(rome2_vfs_crt_string_input_get(&ad) == 'b');

    CHECK(rome2_vfs_crt_fmt_parser_init(&fp, 0x119ebf40u, 0u, 0x11740000u) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_crt_fmt_parser_validate(&fp, &err) == 1u);
    CHECK(rome2_vfs_crt_fmt_compat_allowed(0u, 0u) == 1u && rome2_vfs_crt_fmt_compat_allowed(8u, 1u) == 0u);
    CHECK(rome2_vfs_crt_fmt_parser_advance(&fp, "  %*d", &off, 5u) == 1u && fp.mode_10 == 2u);
    CHECK(rome2_vfs_crt_fmt_parser_advance(&fp, "  %*d", &off, 5u) == 1u && fp.mode_10 == 4u && fp.suppress_16 == 1u);

    CHECK(rome2_vfs_crt_mbs_to_wcs_cp("pack", wbuf, 16u, &wlen, &err) == 0 && wlen == 4u && wbuf[3] == 'k');
    CHECK(rome2_vfs_crt_mbs_to_wcs_cp("pack", wbuf, 3u, &wlen, &err) == ERANGE && wbuf[0] == 0u);
}

static void test_stat_fp_exc_and_initptd(void)
{
    int64_t fsz = 0;
    int32_t err = 0;
    uint32_t drv = 0u, mask = 0u, cause = 0u, hr = 0u, xtab = 0u, mbc = 0u;
    uint16_t wpath[] = {'C', ':', '\\', 'a', 0};
    double val = 10.0;
    rome2_vfs_crt_tiddata868_32 ptd;

    CHECK(rome2_vfs_crt_filetime_or_fallback(0u, 0u, 315532800, 0u, 999) == 315532800);
    CHECK(rome2_vfs_crt_filetime_or_fallback(1u, 0u, 315532800, 1u, 777) == 777);
    CHECK(rome2_vfs_crt_stat_store_size64(0u, 4096u, &fsz, &err) == 1u && fsz == 4096);
    CHECK(rome2_vfs_crt_stat_store_size64(0x80000000u, 0u, &fsz, &err) == 0u && err == ROME2_VFS_L43_EOVERFLOW_MSVC);

    CHECK(rome2_vfs_crt_dtoxmode_w(0x01u, 0u, ".EXE") == 0x816du);
    CHECK(rome2_vfs_crt_extract_drive_w(wpath, 3u, &drv, &err) == 1u && drv == 3u);
    CHECK(rome2_vfs_crt_validate_stat_path_w(wpath, 1u, 3u, 0u, 3u) == 1u);
    CHECK(rome2_vfs_crt_file_unlock_offset_va(0x119ebe18u) == 0x119ebe38u);

    CHECK(rome2_vfs_crt_fp_exc_to_matherr_type(0x28u) == 5u && rome2_vfs_crt_fp_exc_to_matherr_type(2u) == 4u);
    CHECK(rome2_vfs_crt_handle_exc_f64(1u, &val, 0x0808u, 1u, &mask) == 1u && isinf(val) && mask == 0u);
    rome2_vfs_crt_errcode_set_errno(1u, &err);
    CHECK(err == EDOM);
    CHECK(rome2_vfs_crt_raise_exc_map_code(0x04u, &cause) == 0xc000008eu && cause == 8u);
    CHECK(rome2_vfs_crt_umatherr_lookup_name_va(26) == 0x118d4af0u);

    CHECK(rome2_vfs_crt_initptd(&ptd, &hr, &xtab, &mbc) == ROME2_VFS_REG_OK);
    CHECK(hr == 1u && xtab == ROME2_VFS_L43_XCPT_ACT_TAB_VA && mbc == ROME2_VFS_L43_DEFAULT_MBCINFO_VA && ptd.ownlocale_350 == 1u);
}

int main(void)
{
    test_layouts_chkstk_and_security();
    test_stdio_input_and_mbs_to_wcs();
    test_stat_fp_exc_and_initptd();
    printf("test_vfs_fs_engine_crt_sec_ops: ALL PASSED (36 checks)\n");
    return 0;
}
