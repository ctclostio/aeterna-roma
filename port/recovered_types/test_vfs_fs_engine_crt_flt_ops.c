#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_flt_ops.h"

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

static void test_layouts_guard_output_adapter_and_win32_buffer(void)
{
    rome2_vfs_crt_win32_buffer24_32 wb;
    rome2_vfs_crt_strflt12_32 sf;
    rome2_vfs_crt_fp_env8_32 env;
    rome2_vfs_crt_output_adapter_base oa;
    uint32_t guard = 0xdeadbeefu;
    uint32_t freed_va = 0u, alloc_bytes = 0u;
    uint32_t args[7];
    uint16_t wfields[6] = {2026u, 11u, 18u, 9u, 55u, 12u};
    int32_t isdst = 1;

    CHECK(sizeof(wb) == 0x18u && sizeof(sf) == 0x0cu && sizeof(env) == 0x08u);
    rome2_vfs_crt_clear_u32_flag(&guard);
    CHECK(guard == 0u);

    (void)memset(&oa, 0xa5, sizeof(oa));
    CHECK(rome2_vfs_crt_output_adapter_base_init(&oa) == &oa);
    CHECK(oa.header_dwords_00[0] == 0u && oa.header_dwords_00[10] == 0u && oa.byte_30 == 0u);
    CHECK(oa.word_32 == 0u && oa.dword_38 == 0u && oa.byte_3c == 0u && oa.dword_440 == 0u && oa.dword_444 == 0u);
    CHECK(oa.inline_buf_3d[0] == 0xa5u);

    (void)memset(&wb, 0, sizeof(wb));
    wb.data_08 = 0x01002000u;
    wb.allocated_14 = 1u;
    CHECK(rome2_vfs_crt_win32_buffer_deallocate(&wb, &freed_va) == 1u);
    CHECK(freed_va == 0x01002000u && wb.allocated_14 == 0u);
    CHECK(rome2_vfs_crt_win32_buffer_alloc_wchar(&wb, 32u, 0, 0x01004000u, &freed_va, &alloc_bytes) == 0);
    CHECK(alloc_bytes == 64u && wb.data_08 == 0x01004000u && wb.capacity_words_0c == 32u && wb.allocated_14 == 1u);
    CHECK(rome2_vfs_crt_win32_buffer_alloc_wchar(&wb, 64u, ROME2_VFS_L44_ENOMEM_MSVC, 0u, &freed_va, &alloc_bytes) == ROME2_VFS_L44_ENOMEM_MSVC);
    CHECK(freed_va == 0x01004000u && alloc_bytes == 128u && wb.capacity_words_0c == 0u && wb.allocated_14 == 0u);

    CHECK(rome2_vfs_crt_unpack_loctotime_args(&wfields[0], &wfields[1], &wfields[2], &wfields[3], &wfields[4], &wfields[5], &isdst, args) == 1u);
    CHECK(args[0] == 2026u && args[5] == 12u && args[6] == 1u);
}

static void test_ptd_stdio_buffering_locale_and_winapi(void)
{
    rome2_vfs_crt_filex56_32 f;
    rome2_vfs_crt_tiddata868_32 ptd;
    uint32_t cflush = 0u, slot_buf = 0u, cached = 0x11110000u;
    uint8_t init_new = 0u, freed = 0u, aborted = 0u, cfg = 0u, invoked = 0u;
    int32_t err = 0;

    rome2_vfs_crt_free_wrap(1u, 1u, 0u, &err);
    CHECK(err == 0);
    CHECK(rome2_vfs_crt_getptd_or_abort(0xffffffffu, 0u, 0u, 0u, &init_new, &freed, &aborted) == 0u && aborted == 1u);
    CHECK(rome2_vfs_crt_getptd_or_abort(3u, 0u, 0x00401000u, 1u, &init_new, &freed, &aborted) == 0x00401000u && aborted == 0u && init_new == 1u);

    (void)memset(&f, 0, sizeof(f));
    CHECK(rome2_vfs_crt_stdio_begin_tmpbuf_nolock(&f, 0x119ebe50u, 1u, 1u, &cflush, &slot_buf, 0x02000000u) == 1u);
    CHECK(cflush == 1u && slot_buf == 0x02000000u && f.ptr_00 == 0x02000000u && f.bufsiz_18 == ROME2_VFS_L44_STDIO_TMPBUF_SIZE);
    CHECK((f.flag_0c & ROME2_VFS_L44_STDIO_TMPBUF_FLAGS) == ROME2_VFS_L44_STDIO_TMPBUF_FLAGS);
    CHECK(rome2_vfs_crt_stdio_end_tmpbuf_nolock(1u, &f) == 1u);
    CHECK(f.ptr_00 == 0u && f.bufsiz_18 == 0u && (f.flag_0c & 0x280u) == 0u);

    (void)memset(&f, 0, sizeof(f));
    slot_buf = 0u;
    CHECK(rome2_vfs_crt_stdio_begin_tmpbuf_nolock(&f, 0x119ebe88u, 1u, 2u, &cflush, &slot_buf, 0u) == 1u);
    CHECK(f.ptr_00 == 0x119ebe9cu && f.bufsiz_18 == 2u);

    (void)memset(&ptd, 0, sizeof(ptd));
    ptd.ownlocale_350 = 1u;
    CHECK(rome2_vfs_crt_sync_ptd_global_slot(&ptd, 2u, 0x119ebf40u, 0x119ebf40u, &cached) == 1u && cached == 0x119ebf40u);
    ptd.ownlocale_350 = 2u;
    cached = 0x22220000u;
    CHECK(rome2_vfs_crt_sync_ptd_global_slot(&ptd, 2u, 0x119ebf40u, 0x119ebf40u, &cached) == 0u && cached == 0x22220000u);

    CHECK(rome2_vfs_crt_normalize_mbtowc_flags(65001u, 8u) == 0u);
    CHECK(rome2_vfs_crt_normalize_mbtowc_flags(54936u, 0x19u) == 8u);
    CHECK(rome2_vfs_crt_normalize_mbtowc_flags(1252u, 9u) == 9u);
    CHECK(rome2_vfs_crt_are_file_apis_ansi_dispatch(0u, 0u, &invoked) == 1u && invoked == 0u);
    CHECK(rome2_vfs_crt_are_file_apis_ansi_dispatch(0x76001234u, 0u, &invoked) == 0u && invoked == 1u);
    CHECK(rome2_vfs_crt_fls_dispatch_mode(ROME2_VFS_L44_FLS_GET_VALUE_API, 0x76005678u, &cfg) == 1u && cfg == 1u);
    CHECK(rome2_vfs_crt_fls_dispatch_mode(ROME2_VFS_L44_FLS_SET_VALUE_API, 0u, &cfg) == 0u && cfg == 0u);
}

static void test_fp_classify_strflt_calloc_and_fpu_env(void)
{
    double finite_v = 12.25;
    double pinf_v = f64_from_u64(0x7ff0000000000000ULL);
    double ninf_v = f64_from_u64(0xfff0000000000000ULL);
    double ind_v = f64_from_u64(0xfff8000000000000ULL);
    double qnan_v = f64_from_u64(0x7ff8000000000001ULL);
    double snan_v = f64_from_u64(0x7ff0000000000001ULL);
    char out[16];
    rome2_vfs_crt_strflt12_32 flt;
    int32_t err = 0;
    uint32_t bytes = 0u, encoded_ptr = 0u, cookie = 0x13572468u, rot = 0u, masked_w0 = 0u;
    uint16_t next_cw = 0u;
    uint8_t cleared = 0u;
    rome2_vfs_crt_fp_env8_32 env_cur, env_saved, env_rb;

    CHECK(rome2_vfs_crt_fp_classify_ptr(&finite_v) == 0 && rome2_vfs_crt_fp_classify_ptr(&pinf_v) == 1);
    CHECK(rome2_vfs_crt_fp_classify_ptr(&ninf_v) == 1 && rome2_vfs_crt_fp_classify_ptr(&ind_v) == 4);
    CHECK(rome2_vfs_crt_fp_classify_ptr(&qnan_v) == 2 && rome2_vfs_crt_fp_classify_ptr(&snan_v) == 3);

    CHECK(rome2_vfs_crt_sptype_f64(finite_v) == 0 && rome2_vfs_crt_sptype_f64(pinf_v) == 1);
    CHECK(rome2_vfs_crt_sptype_f64(ninf_v) == 2 && rome2_vfs_crt_sptype_f64(qnan_v) == 3);
    CHECK(rome2_vfs_crt_sptype_f64(snan_v) == 4);

    flt.sign_00 = ' ';
    flt.decpt_04 = 2;
    flt.digits_ptr_08 = 0u;
    CHECK(rome2_vfs_crt_fp_strflt_to_string(out, sizeof(out), 3, &flt, "1236", &err) == 0);
    CHECK(strcmp(out, "124") == 0 && flt.decpt_04 == 2);

    flt.decpt_04 = 2;
    CHECK(rome2_vfs_crt_fp_strflt_to_string(out, sizeof(out), 2, &flt, "995", &err) == 0);
    CHECK(strcmp(out, "100") == 0 && flt.decpt_04 == 3);
    CHECK(rome2_vfs_crt_fp_strflt_to_string(out, 3u, 2, &flt, "12", &err) == ROME2_VFS_L44_ERANGE_MSVC);

    CHECK(rome2_vfs_crt_calloc_plan(0u, 16u, &bytes, &err) == 1u && bytes == 1u);
    CHECK(rome2_vfs_crt_calloc_plan(0x10000000u, 0x20u, &bytes, &err) == 0u && err == ROME2_VFS_L44_ENOMEM_MSVC);

    CHECK(rome2_vfs_crt_ctrlfp(0x027fu, 0x001fu, 0x003fu, &next_cw) == 0x027f && next_cw == 0x025fu);
    rot = cookie & 0x1fu;
    encoded_ptr = ((0x10101010u << rot) | (0x10101010u >> ((32u - rot) & 31u))) ^ cookie;
    CHECK(rome2_vfs_crt_has_user_matherr(encoded_ptr, cookie) == 1u);
    CHECK(rome2_vfs_crt_has_user_matherr(cookie, cookie) == 0u);

    CHECK(rome2_vfs_crt_fegetenv(&env_cur, 0x027fu, 0x1f80u) == 0);
    env_rb = env_cur;
    CHECK(rome2_vfs_crt_fesetenv_verify(&env_cur, 0, &env_rb) == 0);
    env_rb.word1_04 = 0x1f81u;
    CHECK(rome2_vfs_crt_fesetenv_verify(&env_cur, 0, &env_rb) == 1);
    CHECK(rome2_vfs_crt_feholdexcept(&env_cur, &env_saved, 0, &masked_w0, &cleared) == 0);
    CHECK(env_saved.word0_00 == 0x027fu && masked_w0 == 0x027fu && cleared == 1u);
    CHECK(rome2_vfs_crt_libm_use_sse2_fastpath(1u, 0x1f80u, 0x027fu) == 1u);
    CHECK(rome2_vfs_crt_libm_use_sse2_fastpath(1u, 0x3f80u, 0x027fu) == 0u);
    CHECK(rome2_vfs_crt_frnd(2.5) == 2.0 && rome2_vfs_crt_frnd(3.5) == 4.0);
}

int main(void)
{
    test_layouts_guard_output_adapter_and_win32_buffer();
    test_ptd_stdio_buffering_locale_and_winapi();
    test_fp_classify_strflt_calloc_and_fpu_env();
    printf("test_vfs_fs_engine_crt_flt_ops: ALL PASSED (57 checks)\n");
    return 0;
}
