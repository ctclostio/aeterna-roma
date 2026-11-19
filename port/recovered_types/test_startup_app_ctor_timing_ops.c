#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "startup_app_ctor_timing_ops.h"

static uint32_t g_checks = 0u;

#define CHECK(cond)                                                              \
    do {                                                                         \
        g_checks += 1u;                                                          \
        if (!(cond)) {                                                           \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            return 1;                                                            \
        }                                                                        \
    } while (0)

static void fill_u16_ascii(uint16_t *dst, size_t cap, const char *src) {
    size_t i = 0u;
    if (!dst || cap == 0u) {
        return;
    }
    while (i + 1u < cap && src[i] != '\0') {
        dst[i] = (uint16_t)(uint8_t)src[i];
        ++i;
    }
    dst[i] = 0u;
}

static int u16_eq_ascii(const uint16_t *u16, const char *ascii) {
    size_t i = 0u;
    if (!u16 || !ascii) {
        return 0;
    }
    while (ascii[i] != '\0') {
        if (u16[i] != (uint16_t)(uint8_t)ascii[i]) {
            return 0;
        }
        ++i;
    }
    return u16[i] == 0u;
}

typedef struct enum_capture {
    uint32_t seen_count;
    uint32_t times[8];
    uint8_t dirs[8];
} enum_capture;

static void capture_dir_cb(
    const uint16_t *dir_u16,
    const uint16_t *name_u16,
    const uint16_t *pattern_u16,
    const rome2_startup_enum_entry_info *info,
    void *ctx) {
    enum_capture *cap = (enum_capture *)ctx;
    (void)dir_u16;
    (void)name_u16;
    (void)pattern_u16;
    if (cap && info && cap->seen_count < 8u) {
        cap->times[cap->seen_count] = info->converted_unix_time_2c;
        cap->dirs[cap->seen_count] = info->is_dir_26;
        cap->seen_count += 1u;
    }
}

static uint8_t mock_diag_cb_cancel(
    uint8_t is_nonfatal,
    const uint16_t *wide_msg,
    uint8_t *out_continue,
    void *ctx) {
    uint32_t *calls = (uint32_t *)ctx;
    (void)is_nonfatal;
    (void)wide_msg;
    if (calls) {
        *calls += 1u;
    }
    if (out_continue) {
        *out_continue = 1u;
    }
    return 0u; /* handled internally -> skip MessageBoxW */
}

static int test_wprintf_engine(void) {
    uint16_t fmt[96];
    uint16_t out[128];
    uint16_t tiny[6];
    uint16_t warg[16];
    uintptr_t args[6];
    int32_t err = 0;
    int32_t r = 0;

    CHECK(sizeof(rome2_startup_observer_node12_32) == 12u);
    CHECK(sizeof(rome2_startup_pair8_32) == 8u);
    CHECK(sizeof(rome2_startup_wprintf_string_adapter16_32) == 16u);
    CHECK(sizeof(rome2_startup_timing_vec12_32) == 12u);

    /* Direct adapter primitive checks: 0x1168b96f, 0x1168bd56, 0x11688e2b */
    {
        rome2_startup_wprintf_target *t =
            (rome2_startup_wprintf_target *)calloc(1u, sizeof(*t));
        int32_t written = 0;
        CHECK(t != NULL);
        t->buf = tiny;
        t->max_chars = 4u;
        CHECK(rome2_startup_wprintf_write_char_1168b96f(t, 'A', &written) == 1u);
        rome2_startup_wprintf_write_multi_chars_11688e2b(t, 'B', 2, &written);
        CHECK(written == 3 && t->guest16.written_chars_08 == 3u);
        rome2_startup_wprintf_write_string_1168bd56(t, warg, 0, &written);
        CHECK(written == 3);
        free(t);
    }

    /* Full 0x100edfe0 / 0x1168c120 / 0x11688718 formatting */
    fill_u16_ascii(warg, 16u, "Rome2");
    fill_u16_ascii(fmt, 96u, "%s:%S:%+05d:%#x:%p:%%");
    args[0] = (uintptr_t)warg;
    args[1] = (uintptr_t)"ok";
    args[2] = (uintptr_t)(int32_t)42;
    args[3] = (uintptr_t)0xABu;
    args[4] = (uintptr_t)0x119f3140u;
    r = rome2_startup_wide_vswprintf_100edfe0(out, 128u, fmt, args, 5u);
    CHECK(r == 30);
    CHECK(u16_eq_ascii(out, "Rome2:ok:+0042:0xab:119F3140:%"));

    /* Length modifiers I32, I64, ll, hh + F tail-jump to type in state_case_size (0x1168a3b6) */
    {
        rome2_startup_wprintf_target *t =
            (rome2_startup_wprintf_target *)calloc(1u, sizeof(*t));
        rome2_startup_wprintf_processor *p =
            (rome2_startup_wprintf_processor *)calloc(1u, sizeof(*p));
        CHECK(t != NULL && p != NULL);
        t->buf = out;
        t->max_chars = 64u;
        p->target = t;
        p->current_ch = (uint16_t)'I';
        fill_u16_ascii(warg, 16u, "64d");
        p->fmt_cursor = warg;
        CHECK(rome2_startup_wprintf_state_size_1168a3b6(p) == 1u && p->length_mod == 11u);
        /* 'N' in size modifier without DISABLE_FN must set errno=22 and return 0 */
        p->length_mod = 0u;
        p->current_ch = (uint16_t)'N';
        CHECK(rome2_startup_wprintf_state_size_1168a3b6(p) == 0u && p->last_errno == 22);
        free(p);
        free(t);
    }

    /* Truncation behavior: common_vsprintf returns -2, 0x100edfe0 clamps to -1 */
    fill_u16_ascii(fmt, 96u, "%s instance");
    args[0] = (uintptr_t)warg;
    fill_u16_ascii(warg, 16u, "RomeII");
    r = rome2_startup_crt_common_vsprintf_wide_11688718(0ULL, tiny, 5u, fmt, args, 1u, &err);
    CHECK(r == -2 && tiny[4] == 0u);
    r = rome2_startup_wide_vswprintf_100edfe0(tiny, 5u, fmt, args, 1u);
    CHECK(r == -1);

    /* Count-only mode with NULL buf & STANDARD_SNPRINTF mode */
    r = rome2_startup_crt_common_vsprintf_wide_11688718(
        ROME2_STARTUP_WPRINTF_OPT_LEGACY_NULL_TERM, NULL, 0u, fmt, args, 1u, &err);
    CHECK(r == 15);
    err = 0;
    CHECK(rome2_startup_crt_common_vsprintf_wide_11688718(0ULL, out, 8u, NULL, NULL, 0u, &err) == -1);
    CHECK(err == 22);
    return 0;
}

static int test_fatal_diag_and_invalid_param(void) {
    uint32_t encoded = 0u;
    uint32_t cookie = 0x91a2b3c5u;
    uint32_t prev = 0u;
    char ptr_out[32];
    char diag_out[96];
    size_t ptr_len = 0u;
    rome2_startup_abort_env *aenv = (rome2_startup_abort_env *)calloc(1u, sizeof(*aenv));
    uint8_t reent = 0u;
    uint32_t cb_calls = 0u;
    CHECK(aenv != NULL);

    /* 0x11687a4a cookie encode/decode */
    prev = rome2_startup_crt_set_invalid_parameter_handler_11687a4a(&encoded, cookie, 0x10203040u);
    CHECK(prev == 0x2a69065eu || encoded != 0u); /* encoded starts 0 -> non-zero encoded value */
    prev = rome2_startup_crt_set_invalid_parameter_handler_11687a4a(&encoded, cookie, 0x11223344u);
    CHECK(prev == 0x10203040u);
    prev = rome2_startup_crt_set_invalid_parameter_handler_11687a4a(&encoded, cookie, 0u);
    CHECK(prev == 0x11223344u);

    /* 0x100f4a10 void* formatter */
    CHECK(rome2_startup_format_void_ptr_100f4a10(
              0x1a2bu, 'p', ptr_out, sizeof(ptr_out), &ptr_len, diag_out, sizeof(diag_out)) == 1u);
    CHECK(strcmp(ptr_out, "00001a2b") == 0 && ptr_len == 8u);
    CHECK(rome2_startup_format_void_ptr_100f4a10(
              0xdeadbeefu, 'X', ptr_out, sizeof(ptr_out), &ptr_len, diag_out, sizeof(diag_out)) == 1u);
    CHECK(strcmp(ptr_out, "DEADBEEF") == 0);
    CHECK(rome2_startup_format_void_ptr_100f4a10(
              0u, 'd', ptr_out, sizeof(ptr_out), &ptr_len, diag_out, sizeof(diag_out)) == 0u);
    CHECK(strcmp(diag_out, "Unexpected format %d used with type void*") == 0);

    /* 0x100de6d0 reentrancy guard & 0x101032a0 abort loop */
    aenv->active_hwnd = 0x1234u;
    aenv->prompt_responses[0] = ROME2_STARTUP_MB_ABORT;
    aenv->prompt_responses[1] = ROME2_STARTUP_MB_CANCEL; /* cancel "Are you sure?" -> loops */
    aenv->prompt_responses[2] = ROME2_STARTUP_MB_RETRY;  /* retry -> returns 1 */
    aenv->prompt_response_count = 3u;
    CHECK(rome2_startup_format_fatal_diag_100de6d0(aenv, 1u, "Ptr=%lp ok", 0xCAFEu, &reent) == 1u);
    CHECK(reent == 0u);
    CHECK(aenv->cached_hwnd == 0x1234u && aenv->msgbox_calls == 3u && aenv->debug_output_calls == 1u);
    CHECK(u16_eq_ascii(aenv->last_debug_msg_u16, "Ptr=0000cafe ok"));

    /* Abort -> OK triggers 0x10102850 TerminateProcess(0) */
    aenv->prompt_response_cursor = 0u;
    aenv->msgbox_calls = 0u;
    aenv->prompt_responses[0] = ROME2_STARTUP_MB_ABORT;
    aenv->prompt_responses[1] = ROME2_STARTUP_MB_OK;
    aenv->prompt_response_count = 2u;
    CHECK(rome2_startup_format_fatal_diag_100de6d0(aenv, 0u, "Fatal=%lP", 0xABCDu, &reent) == 0u);
    CHECK(aenv->terminate_called == 1u && aenv->terminate_exit_code == 0u && aenv->msgbox_calls == 2u);

    /* Reentrant guard blocks recursive call, callback override skips MessageBox */
    reent = 1u;
    CHECK(rome2_startup_format_fatal_diag_100de6d0(aenv, 0u, "Skip=%lp", 0u, &reent) == 0u);
    reent = 0u;
    aenv->diag_cb = mock_diag_cb_cancel;
    aenv->diag_ctx = &cb_calls;
    aenv->msgbox_calls = 0u;
    CHECK(rome2_startup_format_fatal_diag_100de6d0(aenv, 0u, "Bad=%d", 0u, &reent) == 1u);
    CHECK(cb_calls == 1u && aenv->msgbox_calls == 0u);
    CHECK(strcmp(aenv->last_diag_error_a, "Unexpected format %d used with type void*") == 0);

    free(aenv);
    return 0;
}

static int test_app_ctor_and_dir_clean(void) {
    rome2_startup_app_state *app = (rome2_startup_app_state *)calloc(1u, sizeof(*app));
    rome2_startup_app_host_env *host = (rome2_startup_app_host_env *)calloc(1u, sizeof(*host));
    rome2_startup_abort_env *aenv = (rome2_startup_abort_env *)calloc(1u, sizeof(*aenv));
    rome2_startup_path_env *penv = (rome2_startup_path_env *)calloc(1u, sizeof(*penv));
    rome2_startup_crash_singleton *cs = (rome2_startup_crash_singleton *)calloc(1u, sizeof(*cs));
    rome2_startup_handler_queue *hq = (rome2_startup_handler_queue *)calloc(1u, sizeof(*hq));
    rome2_startup_fs_mock_env *fenv = (rome2_startup_fs_mock_env *)calloc(1u, sizeof(*fenv));
    rome2_startup_app_params params;
    uint16_t s67[16], s6d[16], appdata[64], pat[8], dir_u16[128];
    enum_capture cap;
    CHECK(app && host && aenv && penv && cs && hq && fenv);

    /* Col-0 prefix lookup 0x10122e40 */
    CHECK(strcmp(rome2_startup_get_user_folder_col0_prefix_10122e40(0u), ".save") == 0);
    CHECK(strcmp(rome2_startup_get_user_folder_col0_prefix_10122e40(0x12u), ".fxc") == 0);
    CHECK(strcmp(rome2_startup_get_user_folder_col0_prefix_10122e40(0x16u), ".ui_cache") == 0);
    CHECK(strcmp(rome2_startup_get_user_folder_col0_prefix_10122e40(0x21u), ".temp") == 0);
    CHECK(strcmp(rome2_startup_get_user_folder_col0_prefix_10122e40(0x2du), ".txdb") == 0);
    CHECK(strcmp(rome2_startup_get_user_folder_col0_prefix_10122e40(49u), "") == 0);
    CHECK(rome2_startup_get_user_folder_col0_prefix_10122e40(50u) == NULL);

    /* 0x100fe770 directory enumerator + FILETIME conversion + '.'/'..' recursion skip */
    fenv->entry_count = 4u;
    fenv->entries[0] = (rome2_startup_fs_mock_entry){
        "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\texturedb",
        "cache0.txdb", 0x20u, 11644473600ULL * 10000000ULL, 100u, 0u, 0u
    };
    fenv->entries[1] = (rome2_startup_fs_mock_entry){
        "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\fx_cache",
        "shader.fxc", 0x20u, 11644473600ULL * 10000000ULL, 200u, 0u, 0u
    };
    fenv->entries[2] = (rome2_startup_fs_mock_entry){
        "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\temp",
        ".", 0x10u, 0ULL, 0u, 0u, 0u
    };
    fenv->entries[3] = (rome2_startup_fs_mock_entry){
        "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\temp",
        "sub", 0x10u, 0ULL, 0u, 0u, 0u
    };
    fill_u16_ascii(dir_u16, 128u, "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\texturedb\\");
    fill_u16_ascii(pat, 8u, "*.txdb");
    memset(&cap, 0, sizeof(cap));
    CHECK(rome2_startup_dir_enum_and_clean_100fe770(fenv, capture_dir_cb, dir_u16, pat, &cap, 1u) ==
          ROME2_VFS_REG_OK);
    CHECK(cap.seen_count == 1u && cap.times[0] == 3600u && cap.dirs[0] == 0u);

    /* 0x100df270 happy path */
    fill_u16_ascii(appdata, 64u, "C:\\Users\\Test\\AppData\\Roaming");
    penv->appdata_root_u16 = appdata;
    penv->shgetfolder_ok = 1u;
    cs->init_epoch = -1;
    hq->fail_on_push_index = UINT32_MAX;

    fill_u16_ascii(s67, 16u, "Total War ROME2");
    fill_u16_ascii(s6d, 16u, "ROME2_CLS");
    memset(&params, 0, sizeof(params));
    params.hinstance = 0x10000000u;
    host->res_string_67 = s67;
    host->res_string_6d = s6d;
    host->mutex_handle_value = 0x4444u;
    host->initial_mouse_trails = 5u;
    host->abort_env = aenv;
    host->path_env = penv;
    host->crash_singleton = cs;
    host->handler_queue = hq;
    host->fs_env = fenv;

    CHECK(rome2_startup_app_ctor_100df270(app, host, &params) == ROME2_VFS_REG_OK);
    CHECK(app->vtable_history_count == 2u);
    CHECK(app->vtable_history[0] == 0x1173f208u && app->vtable_history[1] == 0x1173f2f4u);
    CHECK(app->embedded_cfg_vtable_874 == 0x1173dc18u);
    CHECK(app->observer.vtable_00 == 0x11741e08u && app->observer.state_04 == 0u);
    CHECK(app->pair_tail.lo_00 == 0u && app->pair_tail.hi_04 == 0u);
    CHECK(app->spi_calls[0] == 0x5eu && app->spi_calls[1] == 0x5du && app->spi_saved_mouse_trails == 5u);
    CHECK(app->cache_magic == 0x4e3bu && app->cleaned_category_count == 4u);
    CHECK(app->cleaned_categories[0] == 0x2du && app->cleaned_categories[3] == 0x21u);
    CHECK(fenv->deleted_count == 2u && cs->initialized == 1u && hq->count == 6u);

    /* Repeat with persistent_cache_magic already 0x4e3b skips cleanup */
    fenv->entries[0].deleted = 0u;
    fenv->deleted_count = 0u;
    CHECK(rome2_startup_app_ctor_100df270(app, host, &params) == ROME2_VFS_REG_OK);
    CHECK(app->cleaned_category_count == 0u && fenv->deleted_count == 0u);

    /* Duplicate instance collision without allow_multi_instance_2c terminates via 0x10102850 */
    host->simulate_already_exists = 1u;
    CHECK(rome2_startup_app_ctor_100df270(app, host, &params) == ROME2_VFS_REG_OK);
    CHECK(app->mutex_error_msgbox_calls == 1u && aenv->terminate_called == 1u);
    CHECK(u16_eq_ascii(app->mutex_msgbox_title, "Mutex error"));

    free(fenv);
    free(hq);
    free(cs);
    free(penv);
    free(aenv);
    free(host);
    free(app);
    return 0;
}

static int test_timings_and_winmm_timer(void) {
    rome2_startup_winmm_env wmm;
    rome2_startup_timing_env *tbase = (rome2_startup_timing_env *)calloc(1u, sizeof(*tbase));
    rome2_startup_alloc_table alloc_tbl;
    rome2_startup_timing_report_env *rep = (rome2_startup_timing_report_env *)calloc(1u, sizeof(*rep));
    uint64_t us = 0ULL;
    uint16_t fmt2[32];
    char two_out[64];
    size_t two_len = 0u;
    CHECK(tbase != NULL && rep != NULL);

    /* 0x10115800 / 0x10115810 / 0x112e2bb0 */
    memset(&wmm, 0, sizeof(wmm));
    wmm.current_time_ms = 250u;
    wmm.baseline_us = 100000ULL;
    CHECK(rome2_startup_query_high_res_us_112e2bb0(&wmm, &us) == ROME2_VFS_REG_OK);
    CHECK(us == 150000ULL && wmm.begin_calls == 1u && wmm.end_calls == 1u && wmm.last_period_ms == 1u);

    /* 0x106b91a0 */
    fill_u16_ascii(fmt2, 32u, "[%ls -> %ls]");
    CHECK(rome2_startup_format_two_strings_106b91a0(fmt2, "BOOT", "VFS", two_out, sizeof(two_out), &two_len) ==
          ROME2_VFS_REG_OK);
    CHECK(strcmp(two_out, "[BOOT -> VFS]") == 0 && two_len == 13u);

    /* 0x112b2d40 sorted descending cap=3 & 0x112dcaf0 banner reporting */
    memset(&alloc_tbl, 0, sizeof(alloc_tbl));
    alloc_tbl.slot3 = 16u << 20;
    CHECK(rome2_startup_init_section_timings_112dc9f0(tbase, &alloc_tbl, "INIT", 3u, 100u) == ROME2_VFS_REG_OK);
    rep->base = tbase;
    rep->alloc_tbl = &alloc_tbl;
    rep->winmm = &wmm;
    rep->last_reported_ms = 100u;
    rep->last_reported_alloc = 10u << 20;

    wmm.current_time_ms = 120u; /* delta 20 */
    CHECK(rome2_startup_report_section_timing_done_112dcaf0(rep, "S1", 0, NULL) == ROME2_VFS_REG_OK);
    CHECK(strstr(rep->primary_banner, "INIT: Done S1 (20ms delta, 20ms total, 16MB allocated total") != NULL);
    CHECK(rep->secondary_banner[0] == '\0');

    wmm.current_time_ms = 200u; /* delta 80 */
    alloc_tbl.slot3 = 20u << 20;
    CHECK(rome2_startup_report_section_timing_done_112dcaf0(rep, "S2", 1, "sub") == ROME2_VFS_REG_OK);
    CHECK(strcmp(rep->primary_banner, "INIT: Done S2") == 0);
    CHECK(strstr(rep->secondary_banner, "80ms delta, 100ms total, 20MB allocated total") != NULL);

    /* Direct sorted timing cap enforcement: 20, 80, add 50, add 10 -> 10 ignored because cap=3 holds (80, 50, 20) */
    CHECK(rome2_startup_record_sorted_timing_slot_112b2d40(rep, 0x1001u, 50u, 0u, 0u) == ROME2_VFS_REG_OK);
    CHECK(rome2_startup_record_sorted_timing_slot_112b2d40(rep, 0x1002u, 10u, 0u, 0u) == ROME2_VFS_REG_OK);
    CHECK(rep->vec_header.count_04 == 3u);
    CHECK(tbase->slots[0].start_ms_04 == 80u &&
          tbase->slots[1].start_ms_04 == 50u &&
          tbase->slots[2].start_ms_04 == 20u);

    free(rep);
    free(tbase);
    return 0;
}

int main(void) {
    if (test_wprintf_engine() != 0 ||
        test_fatal_diag_and_invalid_param() != 0 ||
        test_app_ctor_and_dir_clean() != 0 ||
        test_timings_and_winmm_timer() != 0) {
        return 1;
    }
    printf("test_startup_app_ctor_timing_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
