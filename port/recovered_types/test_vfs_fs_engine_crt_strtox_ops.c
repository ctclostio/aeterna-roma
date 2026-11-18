#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_crt_strtox_ops.h"

static int g_l47_fail = 0;
static int g_l47_checks = 0;
#define CHECK(expr)                                                     \
    do {                                                                \
        ++g_l47_checks;                                                 \
        if (!(expr)) {                                                  \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr);     \
            g_l47_fail = 1;                                             \
        }                                                               \
    } while (0)

static void test_strtox_and_string_helpers(void)
{
    rome2_vfs_crt_cstr_source8_32 src;
    const char *endp = NULL;
    int32_t err = 0;
    uint16_t ctype[257];
    uint16_t w1[] = {'a', 'b', 'c', 0};
    uint16_t w2[] = {'a', 'B', 'C', 0};
    uint16_t w3[] = {'a', 'b', 'z', 0};
    uint32_t ret_va = 0u;
    uint8_t alloc_flag = 0u, use_m = 0u, use_f = 0u;
    uint16_t restored_cw = 0u;
    uint64_t qnan_bits;

    rome2_vfs_crt_cstr_source_init(&src, 0x11900010u, 0x0018ff00u);
    CHECK(src.cur_00 == 0x11900010u && src.endptr_slot_04 == 0x0018ff00u);

    CHECK(rome2_vfs_crt_parse_uint64_cstr("  0x2aZ", &endp, 0, 0u, &err) == 42ULL);
    CHECK(err == 0 && *endp == 'Z');
    CHECK(rome2_vfs_crt_parse_uint64_cstr("  -1234", &endp, 10, 1u, &err) == (uint64_t)(int64_t)-1234LL);
    CHECK(err == 0 && *endp == '\0');
    CHECK(rome2_vfs_crt_parse_uint64_cstr("999999999999999999999", &endp, 10, 0u, &err) == UINT64_MAX);
    CHECK(err == ROME2_VFS_L47_ERANGE_MSVC);
    CHECK(rome2_vfs_crt_parse_uint64_cstr("-999999999999999999999", &endp, 10, 1u, &err) == 0x8000000000000000ULL);
    CHECK(err == ROME2_VFS_L47_ERANGE_MSVC);
    CHECK(rome2_vfs_crt_parse_uint64_cstr("   xyz", &endp, 10, 0u, &err) == 0ULL && endp[0] == ' ');

    (void)memset(ctype, 0, sizeof(ctype));
    ctype[(uint8_t)' ' + 1u] = 0x0008u;
    CHECK(rome2_vfs_crt_ischartype_l(ctype, 1, ' ', 0x0008u, 1u) == 0x0008u);
    CHECK(rome2_vfs_crt_ischartype_l(ctype, 2, 0x0180, 0x0008u, 1u) == 1u);

    CHECK(rome2_vfs_crt_wcsncmp(w1, w3, 2u) == 0);
    CHECK(rome2_vfs_crt_wcsncmp(w1, w3, 3u) < 0);
    CHECK(rome2_vfs_crt_wcsicmp_ascii(w1, w2, &err) == 0 && err == 0);
    CHECK(rome2_vfs_crt_wcsicmp_ascii(NULL, w2, &err) == 0x7fffffff && err == ROME2_VFS_L44_EINVAL_MSVC);

    CHECK(rome2_vfs_crt_common_wfullpath_gate(0u, w1, 260u, &alloc_flag, &ret_va) == 1u && alloc_flag == 1u);
    CHECK(rome2_vfs_crt_realloc_base_plan(0u, 32u, 0x05000100u, 1, 0u, &ret_va, &use_m, &use_f, &err) == 1u && use_m == 1u);
    CHECK(rome2_vfs_crt_realloc_base_plan(0x05000100u, 0u, 0u, 0, 0u, &ret_va, &use_m, &use_f, &err) == 1u && use_f == 1u);
    CHECK(rome2_vfs_crt_realloc_base_plan(0x05000100u, 0xffffffe1u, 0u, 0, 0u, &ret_va, &use_m, &use_f, &err) == 0u && err == ROME2_VFS_L44_ENOMEM_MSVC);
    CHECK(rome2_vfs_crt_msize_base_gate(0u, 0, &err) == -1 && err == ROME2_VFS_L44_EINVAL_MSVC);
    CHECK(rome2_vfs_crt_msize_base_gate(0x05000100u, 64, &err) == 64 && err == 0);

    {
        uint32_t cookie = 0x55aacc33u;
        uint32_t enc = rome2_vfs_crt_encode_pointer32(0x10004400u, cookie);
        CHECK(rome2_vfs_crt_query_new_handler_decode(enc, cookie) == 0x10004400u);
    }

    CHECK(rome2_vfs_crt_errmath_restore_cw(2.5, 0x037fu, &restored_cw) == 2.5 && restored_cw == 0x037fu);
    qnan_bits = rome2_vfs_crt_f64_quiet_nan_widen(0u, 0x7ff0000000000001ULL);
    CHECK(qnan_bits == 0x7ff8000000000001ULL);
    CHECK(rome2_vfs_crt_ftol2_truncate(-42.75) == -42LL);
    CHECK(rome2_vfs_crt_ftol2_truncate(1e30) == (int64_t)0x8000000000000000ULL);
}

static void test_locale_fenv_bigint_and_parser(void)
{
    rome2_vfs_crt_threadlocinfo184_32 loc;
    int32_t ref_pools[10];
    int32_t cat_refs[6][2];
    int32_t wrefs[6];
    uint32_t lctime = 0u, mask;
    uint8_t free_loc = 0u, freed_old = 0u, aborted = 0u, updated_flag = 0u;
    rome2_vfs_crt_tiddata868_32 ptd;
    uint32_t global_mbc = 0x06002000u;
    int32_t old_mbc_rc = 1, new_mbc_rc = 2;
    size_t i;

    (void)memset(&loc, 0, sizeof(loc));
    (void)memset(ref_pools, 0, sizeof(ref_pools));
    (void)memset(cat_refs, 0, sizeof(cat_refs));
    (void)memset(wrefs, 0, sizeof(wrefs));
    loc.refcount_0c = 1;
    loc.lconv_intl_refcount_7c = 0x05010000u;
    loc.lconv_num_refcount_80 = 0x05010004u;
    loc.lconv_mon_refcount_84 = 0x05010008u;
    loc.lconv_88 = 0x05010020u;
    loc.ctype1_refcount_8c = 0x0501000cu;
    loc.lc_time_curr_9c = 0x05010080u;
    for (i = 0u; i < 6u; ++i) {
        loc.cats_1c[i].locale_name_00 = (i == 0u) ? 0x05020000u : 0u;
        loc.cats_1c[i].wlocale_name_04 = (i == 0u) ? 0x05020100u : ROME2_VFS_L47_C_LOCALE_NAME_VA;
        loc.cats_1c[i].refcount_ptr_08 = (i == 0u) ? 0x05020200u : 0u;
        loc.cats_1c[i].wrefcount_ptr_0c = (i == 0u) ? 0x05020300u : 0u;
        ref_pools[i] = 0;
        cat_refs[i][0] = 0;
        cat_refs[i][1] = 0;
    }

    CHECK(rome2_vfs_crt_locale_add_ref(&loc, ref_pools, cat_refs, &lctime) == 0x05010080u);
    CHECK(loc.refcount_0c == 2 && ref_pools[0] == 1 && cat_refs[0][0] == 1 && cat_refs[0][1] == 1);
    CHECK(rome2_vfs_crt_locale_release_ref(&loc, ref_pools, cat_refs, &lctime) == 0x05010080u);
    CHECK(loc.refcount_0c == 1 && ref_pools[0] == 0 && cat_refs[0][0] == 0 && cat_refs[0][1] == 0);

    for (i = 0u; i < 6u; ++i) {
        wrefs[i] = cat_refs[i][1];
    }
    mask = rome2_vfs_crt_free_locale_plan(&loc, ref_pools, wrefs, &lctime, &free_loc);
    CHECK(mask == 0x1fu && free_loc == 1u && lctime == 0x05010080u);

    (void)memset(&ptd, 0, sizeof(ptd));
    ptd.ptmbcinfo_48 = 0x06001000u;
    CHECK(rome2_vfs_crt_update_thread_mbc_internal(&ptd, &global_mbc, &old_mbc_rc, &new_mbc_rc, 0x02u, &freed_old, &aborted) == 0x06002000u);
    CHECK(freed_old == 1u && aborted == 0u && old_mbc_rc == 0 && new_mbc_rc == 3 && ptd.ptmbcinfo_48 == 0x06002000u);
    CHECK(rome2_vfs_crt_update_thread_locale_internal(&ptd, 0x07001000u, 0x07002000u, 0x02u, &updated_flag, &aborted) == 0x07002000u);
    CHECK(updated_flag == 1u && aborted == 0u && ptd.ptlocinfo_4c == 0x07002000u);

    {
        uint32_t fe_x = rome2_vfs_crt_x87_cw_to_fenv_ctrl(0x037fu);
        uint32_t fe_m = rome2_vfs_crt_mxcsr_to_fenv_ctrl(0x1f80u);
        uint32_t packed = rome2_vfs_crt_fenv_pack_control(fe_x, fe_m, 1);
        CHECK(rome2_vfs_crt_fenv_ctrl_to_x87_cw(packed) == 0x033fu);
        CHECK(rome2_vfs_crt_fenv_ctrl_to_mxcsr(packed) == 0x1f80u);
    }

    {
        uint16_t fmt_ok[] = {'a', '%', '%', 'b', 0};
        int32_t written = 0, err = 0;
        uint8_t ok = 0u;
        CHECK(rome2_vfs_crt_woutput_process_step(1u, fmt_ok, &written, &ok, &err) == 3 && ok == 1u);
    }

    {
        rome2_vfs_crt_bigint464 num, den;
        uint64_t q;
        (void)memset(&num, 0, sizeof(num));
        (void)memset(&den, 0, sizeof(den));
        num.used = 2u;
        num.data[0] = 5u;
        num.data[1] = 2u;
        den.used = 1u;
        den.data[0] = 3u;
        q = rome2_vfs_crt_bigint_div_u32(&num, &den);
        CHECK(q == ((2ULL << 32) | 5ULL) / 3ULL && num.data[0] == (uint32_t)(((2ULL << 32) | 5ULL) % 3ULL));

        (void)memset(&num, 0, sizeof(num));
        (void)memset(&den, 0, sizeof(den));
        num.used = 3u;
        num.data[0] = 10u;
        num.data[1] = 0u;
        num.data[2] = 6u;
        den.used = 2u;
        den.data[0] = 0u;
        den.data[1] = 2u;
        q = rome2_vfs_crt_bigint_div_u32(&num, &den);
        CHECK(q == (3ULL << 32) && num.used == 1u && num.data[0] == 10u);
    }

    {
        rome2_vfs_crt_fmt_parser76_32 fp;
        size_t off = 0u;
        const char scanset[] = "[^a-c]";
        uint32_t matched = 0u;
        rome2_vfs_crt_ioinfo56_32 ioinfo[64];
        int32_t err = 0;
        uint32_t doserr = 1u;

        (void)memset(&fp, 0, sizeof(fp));
        CHECK(rome2_vfs_crt_scan_conversion_specifier(&fp, scanset, &off, sizeof(scanset) - 1u) == 1u);
        CHECK(fp.conv_idx_28 == 8u && off == sizeof(scanset) - 1u);
        CHECK((fp.scanset_words_2c[(uint8_t)'b' >> 5] & (1u << ((uint8_t)'b' & 31u))) == 0u);
        CHECK((fp.scanset_words_2c[(uint8_t)'z' >> 5] & (1u << ((uint8_t)'z' & 31u))) != 0u);

        fp.mode_10 = 4u;
        fp.conv_idx_28 = 3u;
        fp.is_wide_24 = 0u;
        CHECK(rome2_vfs_crt_input_process_state(&fp, 0, 1u, 1u, 0u, &matched) == 1u && matched == 1u);

        (void)memset(ioinfo, 0, sizeof(ioinfo));
        ioinfo[3].osfile_28 = ROME2_VFS_L47_OSFILE_OPEN_BIT;
        CHECK(rome2_vfs_crt_write_gate(3, 64, ioinfo, 12u, 12, &err, &doserr) == 12 && err == 0 && doserr == 0u);
        CHECK(rome2_vfs_crt_write_gate(4, 64, ioinfo, 12u, 12, &err, &doserr) == -1 && err == ROME2_VFS_L46_EBADF_MSVC);

        CHECK(rome2_vfs_crt_loctotime64_utc(1970, 1, 1, 0, 0, 0, 0, 0, 0, 0u, &err) == 0LL && err == 0);
        CHECK(rome2_vfs_crt_loctotime64_utc(2000, 3, 1, 0, 0, 0, 0, 0, 0, 0u, &err) == 951868800LL && err == 0);
        CHECK(rome2_vfs_crt_loctotime64_utc(1969, 12, 31, 0, 0, 0, 0, 0, 0, 0u, &err) == -1LL && err == ROME2_VFS_L44_EINVAL_MSVC);
    }
}

int main(void)
{
    test_strtox_and_string_helpers();
    test_locale_fenv_bigint_and_parser();
    if (g_l47_fail != 0) {
        return 1;
    }
    printf("test_vfs_fs_engine_crt_strtox_ops: ALL PASSED (%d checks)\n", g_l47_checks);
    return 0;
}
