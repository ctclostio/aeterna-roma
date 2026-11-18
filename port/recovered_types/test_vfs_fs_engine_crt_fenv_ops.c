#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_fenv_ops.h"

static void check_fail(const char *msg, int line)
{
    fprintf(stderr, "FAIL line %d: %s\n", line, msg);
    exit(1);
}

#define CHECK(cond) do { if (!(cond)) check_fail(#cond, __LINE__); } while (0)

static void test_layouts_encoding_locale_and_paths(void)
{
    rome2_vfs_crt_ioinfo56_32 ioinfo[64];
    rome2_vfs_x87_env28_32 env;
    rome2_vfs_crt_tiddata868_32 ptd;
    rome2_vfs_crt_locale_update16_32 lu;
    uint16_t ctype_tab[257];
    uint16_t wdrive[] = {'e', ':', '\\', 'x', 0};
    uint16_t whay[] = {'C', ':', '\\', 'a', '/', 'b', 0};
    uint16_t wctl[] = {'/', '\\', 0};
    const uint16_t *hit;
    const char *endp = NULL;
    int32_t err = 0;
    uint32_t cookie = 0xbb40e64eu, enc;
    uint8_t free_old = 0u, ret_new = 0u, ig = 0u, ex = 0u, na = 0u;

    CHECK(sizeof(ioinfo[0]) == 0x38u && sizeof(env) == 0x1cu);

    enc = rome2_vfs_crt_fast_encode_pointer32(0x11689999u, cookie);
    CHECK(rome2_vfs_crt_decode_pointer32(enc, cookie) == 0x11689999u);

    (void)memset(ctype_tab, 0, sizeof(ctype_tab));
    ctype_tab[1 + ' '] = 0x0008u;
    CHECK(rome2_vfs_crt_locale_get_ctype_value(ctype_tab, ' ', 0x0008u) == 0x0008u);
    CHECK(rome2_vfs_crt_locale_get_ctype_value(ctype_tab, -1, 0x0008u) == 0u);
    CHECK(rome2_vfs_crt_locale_get_ctype_value(ctype_tab, 300, 0x0008u) == 0u);

    CHECK(rome2_vfs_crt_is_slash_w('\\') == 1u && rome2_vfs_crt_is_slash_w('/') == 1u && rome2_vfs_crt_is_slash_w('a') == 0u);
    CHECK(rome2_vfs_crt_get_drive_number_from_path_w(wdrive) == 5u);

    CHECK(rome2_vfs_crt_strtoull_ascii(" 18446744073709551615!", &endp, 10, &err) == UINT64_MAX && *endp == '!' && err == 0);
    CHECK(rome2_vfs_crt_strtoull_ascii("18446744073709551616", &endp, 10, &err) == UINT64_MAX && err == ROME2_VFS_L44_ERANGE_MSVC);

    (void)memset(&ptd, 0, sizeof(ptd));
    (void)memset(&lu, 0, sizeof(lu));
    ptd.ownlocale_350 = 2u;
    lu.updated_0c = 1u;
    CHECK(rome2_vfs_crt_isspace_l(1u, &lu, &ptd) == 1u && ptd.ownlocale_350 == 0u);
    CHECK(rome2_vfs_crt_unlock_slot_va(3) == ROME2_VFS_L45_CRTLOCK_TABLE_VA + 0x48u);

    ptd.ptlocinfo_4c = 0x05001000u;
    CHECK(rome2_vfs_crt_pctype_func_resolve(&ptd, 0x119ebf40u, 0x119ebf40u, 0x11910000u) == 0x11910000u);
    CHECK(ptd.ptlocinfo_4c == 0x119ebf40u);

    ptd.ptlocinfo_4c = 0x05002000u;
    CHECK(rome2_vfs_crt_replace_thread_locinfo_nolock(&ptd, 0x119ebf40u, 0x119ebf40u, 0, &free_old, &ret_new) == 0x05002000u);
    CHECK(free_old == 1u && ret_new == 1u && ptd.ptlocinfo_4c == 0x119ebf40u);

    CHECK(rome2_vfs_crt_wfullpath_dispatch(0x0100u, 0x0200u, 260u, &ig, &ex, &na) == ROME2_VFS_REG_OK);
    CHECK(ig == 1u && ex == 0u && na == 0u);
    hit = rome2_vfs_crt_wcspbrk(whay, wctl);
    CHECK(hit == whay + 2u);
    hit = rome2_vfs_crt_wcsrchr(whay, (uint16_t)'/');
    CHECK(hit == whay + 4u);
    CHECK(rome2_vfs_crt_wcsrchr(whay, 0u) == whay + 6u);
}

static void test_module_recalloc_math_and_fenv(void)
{
    uint32_t cached_mods[2] = {0u, 0u};
    const uint32_t ids[2] = {0u, 1u};
    uint16_t api_name[] = {'a', 'p', 'i', '-', 'm', 's', '-', 'x', 0};
    uint16_t k32_name[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', 0};
    const uint16_t *names[2] = {api_name, k32_name};
    const uint32_t gmh_res[2] = {0u, 0u};
    const uint32_t gmh_errs[2] = {ROME2_VFS_L46_ERR_INVALID_PARAM_WIN32, ROME2_VFS_L46_ERR_INVALID_PARAM_WIN32};
    const uint32_t load_res[2] = {0x76000000u, 0x77000000u};
    uint8_t used_ll = 0u, invoked = 0u;
    uint32_t new_bytes = 0u, z_off = 0u, z_len = 0u, tgt = 0u, cookie = 0x12345678u, enc;
    uint32_t mxcsr = 0x1f80u;
    int32_t err = 0, libm_err = 0;
    rome2_vfs_crt_ioinfo56_32 ioinfo[64];
    rome2_vfs_crt_math_exception32_32 mex;
    rome2_vfs_x87_env28_32 env;
    double scaled;

    CHECK(rome2_vfs_crt_try_get_first_available_module(cached_mods, 2u, ids, names, 2u, gmh_res, gmh_errs, load_res, &used_ll) == 0x77000000u);
    CHECK(used_ll == 1u && cached_mods[0] == 0xffffffffu && cached_mods[1] == 0x77000000u);

    scaled = rome2_vfs_crt_set_exp(0.75, 4);
    CHECK(scaled == 12.0);
    CHECK(rome2_vfs_crt_f64_is_nan_or_inf_bits(0x7ff0000000000000ULL) == 1u);
    CHECK(rome2_vfs_crt_f64_is_nan_or_inf_bits(0x3ff0000000000000ULL) == 0u);
    CHECK(rome2_vfs_crt_log10_guarded(1000.0, &libm_err) == 3.0 && libm_err == 0);
    CHECK(isinf(rome2_vfs_crt_log10_guarded(0.0, &libm_err)) && libm_err == ROME2_VFS_L46_LOG10_ERR_ZERO);
    CHECK(isnan(rome2_vfs_crt_log10_guarded(-2.0, &libm_err)) && libm_err == ROME2_VFS_L46_LOG10_ERR_NEG);

    CHECK(rome2_vfs_crt_update_thread_mbc_gate(0x0100u, 0x12126304u, &tgt) == 1u && tgt == 0x12126304u);
    CHECK(rome2_vfs_crt_recalloc_plan(16u, 8u, 4u, &new_bytes, &z_off, &z_len, &err) == 1u);
    CHECK(new_bytes == 32u && z_off == 16u && z_len == 16u);
    CHECK(rome2_vfs_crt_callnewh_dispatch(0x10002000u, 1) == 1u && rome2_vfs_crt_query_new_mode(1) == 1);

    (void)memset(&mex, 0, sizeof(mex));
    enc = rome2_vfs_crt_encode_pointer32(0x10003000u, cookie);
    CHECK(rome2_vfs_crt_invoke_user_matherr(enc, cookie, &mex, 1, &invoked) == 1 && invoked == 1u);

    (void)memset(ioinfo, 0, sizeof(ioinfo));
    ioinfo[1].osfile_28 = ROME2_VFS_L46_OSFILE_DEV_BIT;
    CHECK(rome2_vfs_crt_isatty(1, 64, ioinfo, &err) == 0x40);
    CHECK(rome2_vfs_crt_isatty(-2, 64, ioinfo, &err) == 0 && err == ROME2_VFS_L46_EBADF_MSVC);

    CHECK(rome2_vfs_crt_fenv_pack_control(0x13u, 0x05u, 1) == 0x05130017u);
    CHECK(rome2_vfs_crt_fenv_get_status(0x0001u, 0x0004u, 1) == 0x08100018u);

    (void)memset(&env, 0, sizeof(env));
    env.cw_00 = 0x027fu;
    rome2_vfs_crt_fenv_set_control(&env, 0x033fu, 0x1f00u, 1, &mxcsr);
    CHECK(env.cw_00 == 0x037fu && mxcsr == 0x1f00u);
    rome2_vfs_crt_fenv_set_status(&env, 0x08100018u, 1, &mxcsr);
    CHECK((env.sw_04 & 0x3fu) == 0x01u && (mxcsr & 0x3fu) == 0x04u);
}

int main(void)
{
    test_layouts_encoding_locale_and_paths();
    test_module_recalloc_math_and_fenv();
    printf("test_vfs_fs_engine_crt_fenv_ops: ALL PASSED (39 checks)\n");
    return 0;
}
