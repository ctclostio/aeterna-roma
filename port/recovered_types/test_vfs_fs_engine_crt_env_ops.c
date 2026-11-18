#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_env_ops.h"

static void check_fail(const char *msg, int line)
{
    fprintf(stderr, "FAIL line %d: %s\n", line, msg);
    exit(1);
}

#define CHECK(cond) do { if (!(cond)) check_fail(#cond, __LINE__); } while (0)

static double f64_from_u64(uint64_t bits)
{
    double v = 0.0;
    (void)memcpy(&v, &bits, sizeof(v));
    return v;
}

static void test_layouts_flush_malloc_and_fmt_scans(void)
{
    rome2_vfs_crt_onexit_table12_32 onexit_t;
    rome2_vfs_win32_critsec24_32 cs;
    rome2_vfs_crt_filex56_32 f;
    rome2_vfs_crt_fmt_parser76_32 fp;
    size_t off = 0u;
    uint32_t pending = 0u, alloc_bytes = 0u, ptr_va = 0u;
    int32_t err = 0;

    CHECK(sizeof(onexit_t) == 0x0cu && sizeof(cs) == 0x18u);

    (void)memset(&f, 0, sizeof(f));
    f.ptr_00 = 0x02000100u;
    f.cnt_04 = 0x02000040u;
    f.flag_0c = ROME2_VFS_L45_STDIO_IOWRT_BIT | ROME2_VFS_L45_STDIO_BUFFER_BITS | ROME2_VFS_L45_STDIO_IORW_BIT;
    CHECK(rome2_vfs_crt_stdio_flush_nolock(&f, 0xc0, &pending) == 0 && pending == 0xc0u);
    CHECK(f.ptr_00 == 0x02000040u && f.base_08 == 0u && (f.flag_0c & ROME2_VFS_L45_STDIO_IOWRT_BIT) == 0u);

    f.ptr_00 = 0x02000080u;
    f.flag_0c = ROME2_VFS_L45_STDIO_IOWRT_BIT | ROME2_VFS_L45_STDIO_BUFFER_BITS;
    CHECK(rome2_vfs_crt_stdio_flush_nolock(&f, 10, &pending) == -1 && (f.flag_0c & ROME2_VFS_L45_STDIO_IOERR_BIT) != 0u);

    CHECK(rome2_vfs_crt_malloc_plan(0u, &alloc_bytes, &err) == 1u && alloc_bytes == 1u && err == 0);
    CHECK(rome2_vfs_crt_malloc_plan(0xffffffefu, &alloc_bytes, &err) == 0u && err == ROME2_VFS_L44_ENOMEM_MSVC);
    CHECK(rome2_vfs_crt_win32_buffer_dyn_alloc(&ptr_va, 64u, 0x03001000u, &err) == 0 && ptr_va == 0x03001000u);
    CHECK(rome2_vfs_crt_win32_buffer_dyn_alloc(&ptr_va, 64u, 0u, &err) == ROME2_VFS_L44_ENOMEM_MSVC && ptr_va == 0u);

    (void)memset(&fp, 0, sizeof(fp));
    CHECK(rome2_vfs_crt_fmt_scan_field_width(&fp, "128I64d", &off, 7u) == 1u && fp.width_18 == 128u && off == 3u);
    rome2_vfs_crt_fmt_scan_length_modifier(&fp, "128I64d", &off, 7u);
    CHECK(fp.length_idx_20 == 10u && off == 6u);
    CHECK(rome2_vfs_crt_fmt_scan_field_width(&fp, "0d", &(size_t){0}, 2u) == 0u && fp.err_0c == ROME2_VFS_L44_EINVAL_MSVC);

    (void)memset(&fp, 0, sizeof(fp));
    fp.lit_ch_14 = 0x0082u;
    off = 0u;
    CHECK(rome2_vfs_crt_fmt_scan_trail_bytes(&fp, ROME2_VFS_L45_LEADBYTE_FLAG, "\x41x", &off, 2u) == 1u);
    CHECK(fp.lit_ch_14 == 0x4182u && off == 1u);
    CHECK(rome2_vfs_crt_fmt_scan_trail_bytes(&fp, ROME2_VFS_L45_LEADBYTE_FLAG, "", &(size_t){0}, 0u) == 0u && fp.err_0c == ROME2_VFS_L45_EILSEQ_MSVC);

    (void)memset(&fp, 0, sizeof(fp));
    off = 0u;
    rome2_vfs_crt_fmt_scan_wide_modifier(&fp, "ws", &off, 2u);
    CHECK(fp.is_wide_24 == 1u && off == 1u);
    fp.is_wide_24 = 0u;
    off = 0u;
    rome2_vfs_crt_fmt_scan_wide_modifier(&fp, "C", &off, 1u);
    CHECK(fp.is_wide_24 == 1u && off == 0u);
}

static void test_path_drive_fp_and_runtime_apis(void)
{
    uint16_t drive_root[] = {'C', ':', '\\', 0};
    uint16_t unc_root[] = {'\\', '\\', 's', 'r', 'v', '\\', 's', 'h', 'r', '/', 0};
    uint16_t unc_sub[] = {'\\', '\\', 's', 'r', 'v', '\\', 's', 'h', 'r', '\\', 'x', 0};
    uint16_t cwd_d[] = {'d', ':', '\\', 'p', 0};
    int32_t err = 0, exp_v = 0;
    uint32_t next_mx = 0u, cookie = 0x51a2b3c4u, cap = 0u, enc_fn = 0u, refc = 3u, loc_va = 0u, mbc_va = 0u;
    uint32_t api_slots[2] = {0u, 0u};
    uint8_t fresh = 0u;
    rome2_vfs_crt_onexit_table12_32 onexit_t;
    rome2_vfs_crt_tiddata868_32 ptd;
    rome2_vfs_crt_filex56_32 f;

    CHECK(rome2_vfs_crt_call_wfullpath_select(0x1000u, 0, 0x2000u, EINVAL, &err) == 0x1000u && err == EINVAL);
    CHECK(rome2_vfs_crt_call_wfullpath_select(0u, ROME2_VFS_L44_ERANGE_MSVC, 0x2000u, 0, &err) == 0x2000u && err == 0);

    CHECK(rome2_vfs_crt_is_root_or_empty_w(drive_root) == 1u && rome2_vfs_crt_is_root_or_empty_w(unc_sub) == 0u);
    CHECK(rome2_vfs_crt_is_root_unc_name_w(unc_root) == 1u && rome2_vfs_crt_is_root_unc_name_w(unc_sub) == 0u);
    CHECK(rome2_vfs_crt_getdrive_from_cwd_w(cwd_d, 4u, 0u, &err) == 4 && err == 0);
    CHECK(rome2_vfs_crt_getdrive_from_cwd_w(NULL, 300u, 0u, &err) == 0 && err == ROME2_VFS_L44_ENOMEM_MSVC);

    CHECK(rome2_vfs_crt_clearfp_sw(0x0001u, 0x1f84u, 1, &next_mx) == (ROME2_VFS_L45_FP_SW_INVALID | ROME2_VFS_L45_FP_SW_ZERODIVIDE));
    CHECK(next_mx == 0x1f80u);
    CHECK(rome2_vfs_crt_fp_decomp(0.0, &exp_v) == 0.0 && exp_v == 0);
    CHECK(rome2_vfs_crt_fp_decomp(f64_from_u64(0x0008000000000000ULL), &exp_v) == 0.5 && exp_v == -1022);
    CHECK(rome2_vfs_crt_signext_sw16(0xffffu) == -1 && rome2_vfs_crt_raise_fp_status_bits(0x3du) == 0x003du);

    CHECK(rome2_vfs_crt_isspace_dispatch(0u, ' ', ROME2_VFS_L45_ISSPACE_MASK, 0u) == 1u);
    (void)memset(&f, 0, sizeof(f));
    f.file_10 = 7;
    CHECK(rome2_vfs_crt_fileno(&f, &err) == 7 && rome2_vfs_crt_fileno(NULL, &err) == -1 && err == ROME2_VFS_L44_EINVAL_MSVC);

    CHECK(rome2_vfs_crt_lock_slot_va(2) == ROME2_VFS_L45_CRTLOCK_TABLE_VA + 0x30u);
    onexit_t.first_enc_00 = rome2_vfs_crt_encode_pointer32(0x04001000u, cookie);
    onexit_t.last_enc_04 = rome2_vfs_crt_encode_pointer32(0x04001000u, cookie);
    onexit_t.end_enc_08 = onexit_t.last_enc_04;
    CHECK(rome2_vfs_crt_onexit_append_step(&onexit_t, 0x11681234u, cookie, 1u, 1u, 0x04002000u, &cap, &enc_fn) == 0);
    CHECK(cap == 0x20u && rome2_vfs_crt_decode_pointer32(enc_fn, cookie) == 0x11681234u);
    CHECK(rome2_vfs_crt_decode_pointer32(onexit_t.last_enc_04, cookie) == 0x04002004u);

    (void)memset(&ptd, 0, sizeof(ptd));
    ptd.ptmbcinfo_48 = 0x119ec210u;
    CHECK(rome2_vfs_crt_retain_mbc_ref(&ptd, &refc, &mbc_va) == 1u && refc == 4u && mbc_va == 0x119ec210u);
    CHECK(rome2_vfs_crt_retain_locale_ref(&loc_va, 0x119ebf40u) == 1u && loc_va == 0x119ebf40u);

    api_slots[0] = rome2_vfs_crt_encode_pointer32(0u, cookie);
    CHECK(rome2_vfs_crt_try_get_are_file_apis_ansi(api_slots, 2u, cookie, 1u, 0x76001122u, &fresh) == 0x76001122u && fresh == 1u);
    CHECK(rome2_vfs_crt_try_get_are_file_apis_ansi(api_slots, 2u, cookie, 1u, 0x76009999u, &fresh) == 0x76001122u && fresh == 0u);
    api_slots[1] = rome2_vfs_crt_encode_pointer32(0u, cookie);
    CHECK(rome2_vfs_crt_try_get_function_slot(&api_slots[1], cookie, 0u, 0u, &fresh) == 0u);
    CHECK(rome2_vfs_crt_decode_pointer32(api_slots[1], cookie) == 0xffffffffu);
    CHECK(rome2_vfs_crt_try_get_function_slot(&api_slots[1], cookie, 1u, 0x76003344u, &fresh) == 0u);
}

int main(void)
{
    test_layouts_flush_malloc_and_fmt_scans();
    test_path_drive_fp_and_runtime_apis();
    printf("test_vfs_fs_engine_crt_env_ops: ALL PASSED (40 checks)\n");
    return 0;
}
