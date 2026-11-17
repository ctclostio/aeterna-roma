#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_io_ops.h"

static void check_fail(const char *msg, int line)
{
    fprintf(stderr, "FAIL line %d: %s\n", line, msg);
    exit(1);
}

#define CHECK(cond) do { if (!(cond)) check_fail(#cond, __LINE__); } while (0)

static void test_layouts_and_cstr_repeat_fill(void)
{
    rome2_vfs_crt_locale_update16_32 lu;
    rome2_vfs_crt_errentry8_32 ee;
    rome2_vfs_crt_stat56_32 st;
    rome2_vfs_crt_tiddata868_32 td;
    char buf[32];
    uint32_t len = 0u;
    uint8_t sent = 0u;

    CHECK(sizeof(lu) == 0x10u);
    CHECK(sizeof(ee) == 0x08u);
    CHECK(sizeof(st) == 0x38u);
    CHECK(sizeof(td) == 0x364u);

    CHECK(rome2_vfs_cstr_repeat_fill('*', 0u, buf, sizeof(buf), &len, &sent) == ROME2_VFS_REG_OK);
    CHECK(len == 0u && sent == 1u && buf[0] == '\0');
    CHECK(rome2_vfs_cstr_repeat_fill('=', 5u, buf, sizeof(buf), &len, &sent) == ROME2_VFS_REG_OK);
    CHECK(len == 5u && sent == 0u && strcmp(buf, "=====") == 0);
    CHECK(rome2_vfs_cstr_repeat_fill('x', 40u, buf, sizeof(buf), &len, &sent) == ROME2_VFS_REG_RANGE_ERROR);
}

static void test_security_shift_and_locale_helpers(void)
{
    rome2_vfs_crt_locale_update16_32 lu;
    rome2_vfs_crt_tiddata868_32 ptd;
    uint32_t watson = 0u;
    uint32_t cookie = 0xbb40e64eu;
    uint32_t enc = (0x10012340u ^ cookie);
    uint32_t rot = cookie & 0x1fu;
    /* Encode matches 0x116879c0..0x116879d7: ROR32(encoded ^ cookie, cookie & 0x1f) */
    uint32_t encoded_ptr = ((0x10012340u << rot) | (0x10012340u >> (32u - rot))) ^ cookie;
    (void)enc;

    CHECK(rome2_vfs_crt_allshl(1, 0) == 1);
    CHECK(rome2_vfs_crt_allshl(3, 4) == 48);
    CHECK(rome2_vfs_crt_allshl(5, 33) == ((int64_t)5 << 33));
    CHECK(rome2_vfs_crt_allshl(1, 64) == 0);

    CHECK(rome2_vfs_crt_gs_entropy_fold(1u, 2u, 4u, 8u, 16u, 32u, 64u) == (1u ^ 2u ^ 4u ^ 8u ^ 16u ^ 32u ^ 64u));

    memset(&ptd, 0, sizeof(ptd));
    CHECK(rome2_vfs_crt_invalid_param_dispatch(&ptd, encoded_ptr, cookie, &watson) == 0x10012340u && watson == 0u);
    ptd.invalid_parameter_handler_35c = 0x10020000u;
    CHECK(rome2_vfs_crt_invalid_param_dispatch(&ptd, encoded_ptr, cookie, &watson) == 0x10020000u);
    ptd.invalid_parameter_handler_35c = 0u;
    CHECK(rome2_vfs_crt_invalid_param_dispatch(&ptd, cookie, cookie, &watson) == 0u);
    CHECK(watson == ROME2_VFS_L42_STATUS_INVALID_CRUNTIME_PARAMETER);

    CHECK(rome2_vfs_crt_file_lock_offset_va(0x119ebe18u) == 0x119ebe38u);
    CHECK(rome2_vfs_crt_locale_update_init(&lu, 0u, 0u, 0u, 1u, &ptd, 0x20001000u) == ROME2_VFS_REG_OK);
    CHECK(lu.updated_0c == 1u && (ptd.ownlocale_350 & 2u) == 2u);
    CHECK(rome2_vfs_crt_locale_update_release(&lu, &ptd) == ROME2_VFS_REG_OK && (ptd.ownlocale_350 & 2u) == 0u);
    CHECK(rome2_vfs_crt_is_utf8_or_clocale(ROME2_VFS_L42_UTF8_CP, 4u) == ROME2_VFS_L42_UTF8_CP);
    CHECK(rome2_vfs_crt_is_utf8_or_clocale(1252u, 0u) == 1u && rome2_vfs_crt_is_utf8_or_clocale(1252u, 2u) == 0u);
}

static void test_safe_strings_stat_errno_and_ptd(void)
{
    char sbuf[8];
    uint8_t mbuf[8] = {0};
    const uint8_t src[4] = {10u, 20u, 30u, 40u};
    uint16_t wpath[16];
    size_t wlen = 0u;
    int32_t err = 0;
    rome2_vfs_crt_stat56_32 st;
    uint32_t table[4] = {0u};
    uint32_t count = 0u;
    uint32_t cw = 0u;
    uint8_t is_new = 0u, freed = 0u;

    CHECK(rome2_vfs_crt_ascii_to_utf16_path("data\\a", wpath, 16u, &wlen) == ROME2_VFS_REG_OK);
    CHECK(wlen == 6u && wpath[4] == (uint16_t)'\\' && wpath[6] == 0u);

    CHECK(rome2_vfs_crt_memcpy_s(mbuf, sizeof(mbuf), src, 4u) == 0 && mbuf[2] == 30u);
    CHECK(rome2_vfs_crt_memcpy_s(mbuf, 2u, src, 4u) == ERANGE && mbuf[0] == 0u);
    CHECK(rome2_vfs_crt_strcpy_s(sbuf, sizeof(sbuf), "rome2") == 0 && strcmp(sbuf, "rome2") == 0);
    CHECK(rome2_vfs_crt_strcpy_s(sbuf, 4u, "rome2") == ERANGE && sbuf[0] == '\0');
    CHECK(rome2_vfs_crt_strnlen(NULL, 0u) == 0u && rome2_vfs_crt_strnlen("abcdef", 4u) == 4u);

    CHECK(rome2_vfs_crt_stdio_input_process(1u, 1u, 0, 2u, 1u, 1u, EINVAL, &err) == -1);
    CHECK(err == EINVAL);
    CHECK(rome2_vfs_crt_stdio_input_process(1u, 1u, 3, 2u, 0u, 0u, 0, &err) == 3 && err == 0);

    CHECK(rome2_vfs_crt_get_errno_from_oserr(2u) == 2 && rome2_vfs_crt_get_errno_from_oserr(1113u) == 42);
    CHECK(rome2_vfs_crt_get_errno_from_oserr(19u) == 13 && rome2_vfs_crt_get_errno_from_oserr(36u) == 13);
    CHECK(rome2_vfs_crt_get_errno_from_oserr(188u) == 8 && rome2_vfs_crt_get_errno_from_oserr(202u) == 8);
    CHECK(rome2_vfs_crt_get_errno_from_oserr(203u) == 22 && rome2_vfs_crt_doserrno_slot_va(0u) == ROME2_VFS_L42_DOSERRNO_FALLBACK_VA);

    memset(&st, 0, sizeof(st));
    CHECK(rome2_vfs_crt_stat56_init_epoch1980(&st, 3u, 0x81b6u, 315532800) == ROME2_VFS_REG_OK && st.st_dev_00 == 2u);
    CHECK(rome2_vfs_crt_stat56_classify_handle(&st, 3u, 5u, 4096u, 0u, &err) == 1u && st.st_mode_06 == 0x1000u && st.st_size_18 == 4096);
    CHECK(rome2_vfs_crt_stat56_classify_handle(&st, 0u, 5u, 0u, 0u, &err) == 0u && err == EBADF);

    CHECK(rome2_vfs_crt_onexit_root_push(table, 4u, &count, 0x10099999u) == 0x10099999u && count == 1u);
    CHECK(rome2_vfs_crt_libm_err_result(0x4c, 0, 0.5, 0u, &cw, &err) == 0.5 && cw == 0xffffu && err == EDOM);

    CHECK(rome2_vfs_crt_getptd_resolve(1u, 0u, 0x20008000u, 0u, &is_new, &freed) == 0u && is_new == 0u && freed == 1u);
    CHECK(rome2_vfs_crt_getptd_resolve(1u, 0x20004000u, 0u, 1u, &is_new, &freed) == 0x20004000u);
    err = 0;
    rome2_vfs_crt_free_check(1u, 0u, 6u, &err);
    CHECK(err == 9);
}

int main(void)
{
    test_layouts_and_cstr_repeat_fill();
    test_security_shift_and_locale_helpers();
    test_safe_strings_stat_errno_and_ptd();
    printf("test_vfs_fs_engine_crt_io_ops: ALL PASSED (46 checks)\n");
    return 0;
}
