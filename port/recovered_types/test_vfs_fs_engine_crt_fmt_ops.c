#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_fmt_ops.h"

static void check_fail(const char *msg, int line)
{
    fprintf(stderr, "FAIL line %d: %s\n", line, msg);
    exit(1);
}

#define CHECK(cond) do { if (!(cond)) check_fail(#cond, __LINE__); } while (0)

static void test_layouts_and_queue_trim(void)
{
    rome2_vfs_ts_node16_32 node;
    rome2_vfs_ts_queue24_32 q24;
    rome2_vfs_crt_thread_param20_32 tp;
    rome2_vfs_ts_sample_queue sq;
    uint32_t evicted = 0u;

    CHECK(sizeof(node) == 0x10u);
    CHECK(sizeof(q24) == 0x18u);
    CHECK(sizeof(tp) == 0x14u);

    memset(&sq, 0, sizeof(sq));
    CHECK(rome2_vfs_ts_queue_push(&sq, 100u, 32u) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_ts_queue_push(&sq, 1500u, 64u) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_ts_queue_push(&sq, 5000u, 128u) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_ts_queue_trim_expired(&sq, 2u, 4000u, &evicted) == ROME2_VFS_REG_OK);
    CHECK(evicted == 2u && sq.count == 1u && sq.byte_sum == 128u && sq.timestamps[0] == 5000u);
    CHECK(rome2_vfs_steam_map_send_type(2) == 2u && rome2_vfs_steam_map_send_type(9) == 0u);
}

static void test_cstr_and_scalar_formatters(void)
{
    char outc[128];
    uint16_t outw[128];
    uint16_t pos = 0u;
    uint32_t len = 0u;
    uint8_t ok = 0u;

    CHECK(rome2_vfs_format_scan_char_cstr("x%%y%lc", 7u, &pos, 'Q', outc, 128u, &len, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 1u && strcmp(outc, "x%yQ") == 0);

    pos = 0u;
    CHECK(rome2_vfs_format_scan_char_cstr("%d", 2u, &pos, 'Q', outc, 128u, &len, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 0u && strstr(outc, "type char") != NULL);

    CHECK(rome2_vfs_format_cstr_arg('s', "ab", 4u, 1u, outw, 128u, &len, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 1u && len == 4u && outw[0] == 'a' && outw[1] == 'b' && outw[2] == ' ' && outw[3] == ' ');
    CHECK(rome2_vfs_format_cstr_arg('d', "ab", 0u, 0u, outw, 128u, &len, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 0u && len > 20u);

    CHECK(rome2_vfs_cstr_prepend_char('-', "42", 2u, outc, 128u, &len) == ROME2_VFS_REG_OK && strcmp(outc, "-42") == 0);
    CHECK(rome2_vfs_cstr_format_uint32_dec(0u, outc, 128u, &len) == ROME2_VFS_REG_OK && strcmp(outc, "0") == 0);
    CHECK(rome2_vfs_cstr_format_uint32_base(0x1fau, 16u, "0123456789ABCDEF", outc, 128u, &len) == ROME2_VFS_REG_OK && strcmp(outc, "1FA") == 0);
    CHECK(rome2_vfs_cstr_pad_aligned("hi", 2u, 4u, 0u, '.', outc, 128u, &len) == ROME2_VFS_REG_OK && strcmp(outc, "..hi") == 0);
}

static void test_crt_runtime_and_memops(void)
{
    uint32_t tbl[2] = {0u};
    uint32_t cnt = 0u;
    int32_t guard = -1, tls_ep = 0, glob_ep = 4, err = 0, doserr = 0, exc_type = 0;
    uint8_t timed_out = 0u, signaled = 0u, c_thr = 0u, c_mod = 0u;
    rome2_vfs_i10_out_result i10;
    char fbuf[32];
    int32_t decpt = 0, sign = 0;
    rome2_vfs_crt_stat56_summary st;
    rome2_vfs_crt_thread_param20_32 tp;
    uint8_t mbuf[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    uint8_t dst[6];

    CHECK(rome2_vfs_crt_onexit_append(tbl, 2u, &cnt, 0x10102020u) == 0x10102020u && cnt == 1u);
    CHECK(rome2_vfs_crt_init_thread_wait(&guard, 100u, &timed_out) == ROME2_VFS_REG_OK && timed_out == 1u);
    CHECK(rome2_vfs_crt_init_thread_footer(&guard, &tls_ep, &glob_ep, &signaled) == ROME2_VFS_REG_OK);
    CHECK(glob_ep == 5 && guard == 5 && tls_ep == 5 && signaled == 1u);

    CHECK(rome2_vfs_crt_dosmaperr(5u, &doserr) == EACCES && doserr == 5);
    CHECK(rome2_vfs_crt_errno_slot_va(0u) == ROME2_VFS_L41_IOB_ERRNO_VA);
    CHECK(rome2_vfs_crt_strnicmp_l("RoMe", "rOmA", 3u, &err) == 0 && err == 0);
    CHECK(rome2_vfs_crt_strnicmp_l("RoMe", "rOmA", 4u, &err) > 0);
    CHECK(rome2_vfs_crt_strnicmp_l(NULL, "a", 1u, &err) == (int32_t)ROME2_VFS_L41_STRNICMP_MAX && err == EINVAL);

    CHECK(rome2_vfs_crt_i10_output_f64(INFINITY, 6, 0u, &i10) == ROME2_VFS_REG_OK && strcmp(i10.digits, "1#INF") == 0);
    CHECK(rome2_vfs_crt_i10_output_f64(-12.5, 4, 0u, &i10) == ROME2_VFS_REG_OK && i10.decpt == 2 && i10.sign_ch == '-');
    CHECK(rome2_vfs_crt_fcvt_format_buf(fbuf, sizeof(fbuf), &i10, 4, &decpt, &sign) == 0 && sign == 1 && decpt == 2);

    CHECK(rome2_vfs_crt_stat56_validate_and_zero(NULL, &st, &err) == -1 && err == EINVAL);
    CHECK(rome2_vfs_crt_thread_param20_init(&tp, 0x100fcb80u, 0x1234u, 0x10u, 0x20u) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_crt_thread_param20_release(&tp, &c_thr, &c_mod) == ROME2_VFS_REG_OK && c_thr == 1u && c_mod == 1u);

    CHECK(strcmp(rome2_vfs_crt_libm_handle_error(0x4c, &err, &exc_type), "sqrt") == 0 && err == EDOM && exc_type == 1);
    CHECK(rome2_vfs_crt_memcpy(dst, mbuf + 2, 4u) == dst && dst[0] == 2u && dst[3] == 5u);
    CHECK(rome2_vfs_crt_memmove(mbuf + 2, mbuf, 5u) == mbuf + 2 && mbuf[2] == 0u && mbuf[6] == 4u);
}

int main(void)
{
    test_layouts_and_queue_trim();
    test_cstr_and_scalar_formatters();
    test_crt_runtime_and_memops();
    puts("test_vfs_fs_engine_crt_fmt_ops: ALL PASSED (39 checks)");
    return 0;
}
