#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_envinit_ops.h"

#define TEST_ASSERT(cond)                                                          \
    do {                                                                           \
        if (!(cond)) {                                                             \
            fprintf(stderr, "FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            return 1;                                                              \
        }                                                                          \
        ++g_checks;                                                                \
    } while (0)

typedef struct mock_l55_ctx {
    const char *stream_data;
    size_t stream_pos;
    int32_t ungot[4];
    size_t ungot_len;
    uint32_t lead_called;
    uint32_t mbtowc_called;
    uint32_t invalid_param_called;
    uint8_t fd_open[8];
    uint32_t lock_count;
    uint32_t unlock_count;
    int32_t last_fh;
    int64_t seek_res;
    const uint16_t *os_wblock;
    uint32_t wblock_freed;
    uint32_t alloc_fail_at;
    uint32_t alloc_calls;
    uint32_t free_calls;
    char *published[8];
    size_t published_count;
    uint32_t hook_calls;
    uint32_t last_locale_guest;
    uint32_t last_cmp_flags;
    uint32_t last_cp;
    int32_t stat_compare_return;
} mock_l55_ctx;

static int32_t mock_get(void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    if (!c->stream_data || c->stream_data[c->stream_pos] == '\0') {
        return -1;
    }
    return (uint8_t)c->stream_data[c->stream_pos++];
}

static void mock_unget(int32_t ch, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    if (c->ungot_len < 4u) {
        c->ungot[c->ungot_len++] = ch;
    }
}

static uint8_t mock_is_leadbyte(uint8_t ch, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    ++c->lead_called;
    return ch >= 0x81u ? 1u : 0u;
}

static int32_t mock_mbtowc(uint16_t *out_wc, const char *mb, size_t n, void *ctx) {
    (void)mb;
    (void)n;
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    ++c->mbtowc_called;
    if (out_wc) {
        *out_wc = 0x3042u;
    }
    return 1;
}

static void mock_invalid_param(void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    ++c->invalid_param_called;
}

static uint8_t mock_is_open(int32_t fh, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    return (fh >= 0 && fh < 8) ? c->fd_open[fh] : 0u;
}

static void mock_lock(int32_t fh, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    c->last_fh = fh;
    ++c->lock_count;
}

static void mock_unlock(int32_t fh, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    c->last_fh = fh;
    ++c->unlock_count;
}

static int64_t mock_lseek_nolock(int32_t fh, int64_t off, int32_t origin, void *ctx) {
    (void)fh;
    (void)origin;
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    c->seek_res += off;
    return c->seek_res;
}

static uint8_t mock_close_inside_lock(int32_t fh, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    if (c->lock_count > c->unlock_count && fh == 4) {
        return 0u;
    }
    return mock_is_open(fh, ctx);
}

static void *mock_calloc(size_t n, size_t sz, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    ++c->alloc_calls;
    if (c->alloc_fail_at != 0u && c->alloc_calls == c->alloc_fail_at) {
        return NULL;
    }
    return calloc(n, sz);
}

static void mock_free(void *ptr, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    ++c->free_calls;
    free(ptr);
}

static size_t mock_wcstombs(const uint16_t *w, int32_t wlen, char *dst, size_t cap, void *ctx) {
    (void)ctx;
    size_t len = 0u;
    if (wlen < 0) {
        while (w[len] != 0u) {
            ++len;
        }
        ++len; /* include NUL */
    } else {
        len = (size_t)wlen;
    }
    if (!dst || cap == 0u) {
        return len;
    }
    if (cap < len) {
        return 0u;
    }
    for (size_t i = 0u; i < len; ++i) {
        dst[i] = (char)(uint8_t)(w[i] & 0x7fu);
    }
    return len;
}

static const uint16_t *mock_get_env_w(void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    return c->os_wblock;
}

static void mock_free_env_w(const uint16_t *block, void *ctx) {
    (void)block;
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    ++c->wblock_freed;
}

static int32_t mock_setenv(char *entry, void *ctx) {
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    if (c->published_count < 8u) {
        c->published[c->published_count++] = entry;
        return 0;
    }
    return -1;
}

static void mock_mb_hook(int32_t mode, uint32_t flag, uint32_t mbcinfo, void *ctx) {
    (void)mode;
    (void)flag;
    (void)mbcinfo;
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    ++c->hook_calls;
}

static int32_t mock_c_strnicmp(const char *s1, const char *s2, size_t n, void *ctx) {
    (void)ctx;
    for (size_t i = 0u; i < n; ++i) {
        unsigned char a = (unsigned char)s1[i];
        unsigned char b = (unsigned char)s2[i];
        if (a >= 'A' && a <= 'Z') {
            a = (unsigned char)(a + 0x20u);
        }
        if (b >= 'A' && b <= 'Z') {
            b = (unsigned char)(b + 0x20u);
        }
        if (a != b || a == 0u) {
            return (int32_t)a - (int32_t)b;
        }
    }
    return 0;
}

static int32_t mock_compare_stat(
    uint32_t locale_name_guest,
    uint32_t cmp_flags,
    const char *s1,
    int32_t n1,
    const char *s2,
    int32_t n2,
    uint32_t cp,
    void *ctx) {
    (void)s1;
    (void)n1;
    (void)s2;
    (void)n2;
    mock_l55_ctx *c = (mock_l55_ctx *)ctx;
    c->last_locale_guest = locale_name_guest;
    c->last_cmp_flags = cmp_flags;
    c->last_cp = cp;
    return c->stat_compare_return;
}

int main(void) {
    int g_checks = 0;

    /* 1. Guest32 layouts added/refined in Layer 55 */
    TEST_ASSERT(sizeof(rome2_vfs_crt_input_char_source32_32) == 0x20u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_input_char_source32_32, width_lo_08) == 0x08u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_input_char_source32_32, read_count_lo_10) == 0x10u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_input_char_source32_32, succeeded_ptr_18) == 0x18u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_mbctype_table257_32) == 0x101u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_mbcasemap_table256_32) == 0x100u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_seh4_scope_entry16_32) == 0x10u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_seh4_scope_table32_32) == 0x20u);

    /* 2. input_adapter_character_source ctor/get/unget/restore/validate */
    mock_l55_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.stream_data = "Ab";

    rome2_vfs_crt_input_char_source32_32 src;
    uint8_t ok = 0u;
    TEST_ASSERT(rome2_vfs_crt_input_char_source_ctor(&src, 0x11002200u, 2ULL, 0x22003300u, &ok) == &src);
    TEST_ASSERT(ok == 1u && src.adapter_ptr_00 == 0x11002200u && src.width_lo_08 == 2u);
    TEST_ASSERT(rome2_vfs_crt_input_char_source_ctor(NULL, 1u, 0ULL, 1u, &ok) == NULL);

    int32_t err = 0;
    TEST_ASSERT(rome2_vfs_crt_input_char_source_validate(&src, &err, mock_invalid_param, &ctx) == 1u);
    src.succeeded_ptr_18 = 0u;
    TEST_ASSERT(rome2_vfs_crt_input_char_source_validate(&src, &err, mock_invalid_param, &ctx) == 0u);
    TEST_ASSERT(err == 22 && ctx.invalid_param_called == 1u);
    src.succeeded_ptr_18 = 0x22003300u;

    TEST_ASSERT(rome2_vfs_crt_input_char_source_get(&src, mock_get, &ctx) == 'A');
    TEST_ASSERT(rome2_vfs_crt_input_char_source_get(&src, mock_get, &ctx) == 'b');
    TEST_ASSERT(rome2_vfs_crt_input_char_source_get(&src, mock_get, &ctx) == 0u);
    TEST_ASSERT(src.read_count_lo_10 == 3u && ctx.stream_pos == 2u);

    TEST_ASSERT(rome2_vfs_crt_input_char_source_restore_state(&src, 3ULL, &ok) == 1u && ok == 1u);
    TEST_ASSERT(rome2_vfs_crt_input_char_source_restore_state(&src, 2ULL, &ok) == 0u && ok == 0u);

    rome2_vfs_crt_input_char_source_unget(&src, (int8_t)'b', mock_unget, &ctx);
    TEST_ASSERT(src.read_count_lo_10 == 2u && ctx.ungot_len == 1u && ctx.ungot[0] == 'b');
    rome2_vfs_crt_input_char_source_unget(&src, -1, mock_unget, &ctx);
    rome2_vfs_crt_input_char_source_unget(&src, 0, mock_unget, &ctx);
    TEST_ASSERT(src.read_count_lo_10 == 0u && ctx.ungot_len == 1u);

    /* 3. scanf length switches, scanset permission, write_stored_string_tchar_wide */
    TEST_ASSERT(rome2_vfs_crt_scanf_to_fp_length(0u) == 4u);
    TEST_ASSERT(rome2_vfs_crt_scanf_to_fp_length(3u) == 8u);
    TEST_ASSERT(rome2_vfs_crt_scanf_to_fp_length(8u) == 8u);
    TEST_ASSERT(rome2_vfs_crt_scanf_to_fp_length(5u) == 0u);

    const uint32_t expected_int_len[12] = { 4u, 1u, 2u, 4u, 8u, 8u, 4u, 4u, 0u, 4u, 8u, 0u };
    for (uint32_t m = 0u; m < 12u; ++m) {
        TEST_ASSERT(rome2_vfs_crt_scanf_to_int_length(m) == expected_int_len[m]);
    }

    rome2_vfs_crt_scanf_input116_32 in_st;
    memset(&in_st, 0, sizeof(in_st));
    in_st.fmt_18.scanset_words_2c[(uint8_t)'Z' >> 5] |= 1u << ((uint8_t)'Z' & 31u);
    TEST_ASSERT(rome2_vfs_crt_scanf_is_char_allowed(&in_st, 0u, -1) == 0u);
    TEST_ASSERT(rome2_vfs_crt_scanf_is_char_allowed(&in_st, 0u, ' ') == 1u);
    TEST_ASSERT(rome2_vfs_crt_scanf_is_char_allowed(&in_st, 1u, '\n') == 0u);
    TEST_ASSERT(rome2_vfs_crt_scanf_is_char_allowed(&in_st, 1u, ' ') == 0u);
    TEST_ASSERT(rome2_vfs_crt_scanf_is_char_allowed(&in_st, 1u, 'X') == 1u);
    TEST_ASSERT(rome2_vfs_crt_scanf_is_char_allowed(&in_st, 8u, 'Z') == 1u);
    TEST_ASSERT(rome2_vfs_crt_scanf_is_char_allowed(&in_st, 8u, 'Y') == 0u);
    TEST_ASSERT(rome2_vfs_crt_scanf_is_char_allowed(&in_st, 5u, 'Y') == 0u);

    uint16_t wout[4] = { 0 };
    uint16_t *wp = wout;
    int32_t rem = 4;
    ctx.stream_data = "Q";
    ctx.stream_pos = 0u;
    TEST_ASSERT(rome2_vfs_crt_scanf_write_stored_string_wide(&wp, &rem, (int8_t)-120, mock_is_leadbyte, mock_get, mock_mbtowc, &ctx) == 1u);
    TEST_ASSERT(ctx.lead_called == 1u && ctx.mbtowc_called == 1u && ctx.stream_pos == 1u);
    TEST_ASSERT(wp == &wout[1] && rem == 3 && wout[0] == (uint16_t)(int16_t)(int8_t)-120);

    /* 4. common_lseek<int64> & SEH4 finally unlock (0x1169e653 / 0x1169e728) */
    uint32_t doserr = 99u;
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_common_lseek64(-2, 10LL, 0, 8u, mock_is_open, mock_lock, mock_unlock, mock_lseek_nolock, mock_invalid_param, &err, &doserr, &ctx) == -1LL);
    TEST_ASSERT(err == 9 && doserr == 0u && ctx.unlock_count == 0u);

    ctx.fd_open[3] = 1u;
    ctx.seek_res = 100LL;
    TEST_ASSERT(rome2_vfs_crt_common_lseek64(3, 24LL, 1, 8u, mock_is_open, mock_lock, mock_unlock, mock_lseek_nolock, mock_invalid_param, &err, &doserr, &ctx) == 124LL);
    TEST_ASSERT(ctx.lock_count == 1u && ctx.unlock_count == 1u && ctx.last_fh == 3);

    ctx.fd_open[4] = 1u;
    err = 0;
    doserr = 5u;
    TEST_ASSERT(rome2_vfs_crt_common_lseek64(4, 1LL, 0, 8u, mock_close_inside_lock, mock_lock, mock_unlock, mock_lseek_nolock, mock_invalid_param, &err, &doserr, &ctx) == -1LL);
    TEST_ASSERT(err == 9 && doserr == 0u && ctx.lock_count == 2u && ctx.unlock_count == 2u);

    /* 5. Environment initialization, OS UTF-16LE block, create/free, wide bridge & multibyte */
    static const uint16_t k_wenv_block[] = {
        '=', 'C', ':', '=', 'X', 0u,
        'R', 'O', 'M', 'E', '=', '2', 0u,
        'M', 'O', 'D', '=', 'O', 'K', 0u,
        0u
    };
    const uint16_t *w_end = rome2_vfs_crt_find_end_of_double_null_u16(k_wenv_block);
    TEST_ASSERT(w_end == k_wenv_block + (sizeof(k_wenv_block) / sizeof(k_wenv_block[0])));

    ctx.os_wblock = k_wenv_block;
    char *narrow_blk = rome2_vfs_crt_get_narrow_environment_from_os(
        mock_get_env_w, mock_free_env_w, mock_wcstombs, mock_calloc, mock_free, &ctx);
    TEST_ASSERT(narrow_blk != NULL && ctx.wblock_freed == 1u);
    TEST_ASSERT(strcmp(narrow_blk, "=C:=X") == 0 && strcmp(narrow_blk + 6, "ROME=2") == 0);
    free(narrow_blk);

    char **envp = rome2_vfs_crt_create_environment_narrow("=Z:=1\0FOO=bar\0BAZ=qux\0", mock_calloc, mock_free, &ctx);
    TEST_ASSERT(envp != NULL && strcmp(envp[0], "FOO=bar") == 0 && strcmp(envp[1], "BAZ=qux") == 0 && envp[2] == NULL);
    rome2_vfs_crt_free_environment_narrow(envp, mock_free, &ctx);

    /* Simulate OOM on 2nd entry copy inside create_environment<char> and verify cleanup frees 1st + table */
    uint32_t frees_before = ctx.free_calls;
    ctx.alloc_calls = 0u;
    ctx.alloc_fail_at = 3u; /* 1=table, 2=entry0, 3=entry1 fails */
    TEST_ASSERT(rome2_vfs_crt_create_environment_narrow("A=1\0B=2\0", mock_calloc, mock_free, &ctx) == NULL);
    TEST_ASSERT(ctx.free_calls == frees_before + 2u);
    ctx.alloc_fail_at = 0u;

    uint8_t mb_flag = 0u;
    uint32_t mbci = 0u, mbct = 0u, mbcm = 0u;
    TEST_ASSERT(rome2_vfs_crt_initialize_multibyte(
        &mb_flag, &mbci, &mbct, &mbcm, 0x119ec210u, 0x119ec430u, 0x119ec538u, mock_mb_hook, &ctx) == 1u);
    TEST_ASSERT(mb_flag == 1u && mbci == 0x119ec210u && mbct == 0x119ec430u && mbcm == 0x119ec538u && ctx.hook_calls == 1u);
    TEST_ASSERT(rome2_vfs_crt_initialize_multibyte(
        &mb_flag, &mbci, &mbct, &mbcm, 1u, 2u, 3u, mock_mb_hook, &ctx) == 1u && ctx.hook_calls == 1u);

    char **g_env = NULL;
    char **g_init_env = NULL;
    const uint16_t *const wenv_dummy[1] = { NULL };
    mb_flag = 0u;
    TEST_ASSERT(rome2_vfs_crt_get_or_create_narrow_env_nolock(
        &g_env, &g_init_env, wenv_dummy, &mb_flag,
        mock_get_env_w, mock_free_env_w, mock_wcstombs, mock_calloc, mock_free, mock_setenv, &ctx) == g_env);
    TEST_ASSERT(g_env != NULL && g_init_env == g_env && strcmp(g_env[0], "ROME=2") == 0);
    rome2_vfs_crt_free_environment_narrow(g_env, mock_free, &ctx);

    static const uint16_t k_w0[] = { 'K', '1', '=', 'V', '1', 0u };
    static const uint16_t k_w1[] = { 'K', '2', '=', 'V', '2', 0u };
    const uint16_t *const w_list[3] = { k_w0, k_w1, NULL };
    TEST_ASSERT(rome2_vfs_crt_initialize_narrow_env_from_wide(
        w_list, mock_wcstombs, mock_calloc, mock_free, mock_setenv, &ctx) == 0);
    TEST_ASSERT(ctx.published_count == 2u && strcmp(ctx.published[0], "K1=V1") == 0 && strcmp(ctx.published[1], "K2=V2") == 0);
    for (size_t i = 0u; i < ctx.published_count; ++i) {
        free(ctx.published[i]);
    }

    /* 6. _strnicoll, _strnicoll_l, CompareStringA, ___ascii_wcsnicmp */
    ctx.stat_compare_return = 1; /* CSTR_LESS_THAN -> 1 - 2 = -1 */
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_strnicoll("Abc", "aBd", 3u, 0u, 0u, 0u, 0u, mock_c_strnicmp, mock_compare_stat, mock_invalid_param, &err, &ctx) < 0);
    TEST_ASSERT(rome2_vfs_crt_strnicoll("Abc", "aBc", 3u, 1u, 1u, 0u, 0u, mock_c_strnicmp, mock_compare_stat, mock_invalid_param, &err, &ctx) == 0);
    TEST_ASSERT(rome2_vfs_crt_strnicoll("alpha", "beta", 5u, 1u, 0u, 0x11910000u, 1252u, mock_c_strnicmp, mock_compare_stat, mock_invalid_param, &err, &ctx) == -1);
    TEST_ASSERT(ctx.last_cmp_flags == 0x1001u && ctx.last_cp == 1252u && ctx.last_locale_guest == 0x11910000u);

    ctx.stat_compare_return = 0; /* error */
    TEST_ASSERT(rome2_vfs_crt_strnicoll_l("a", "b", 1u, 0u, 0u, 1252u, mock_c_strnicmp, mock_compare_stat, mock_invalid_param, &err, &ctx) == 0x7fffffff && err == 22);
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_strnicoll_l(NULL, "b", 1u, 0u, 0u, 1252u, mock_c_strnicmp, mock_compare_stat, mock_invalid_param, &err, &ctx) == 0x7fffffff && err == 22);

    static const uint16_t k_u1[] = { 'R', 'o', 'm', 'e', '!', 0u };
    static const uint16_t k_u2[] = { 'r', 'O', 'M', 'E', '?', 0u };
    TEST_ASSERT(rome2_vfs_crt_ascii_wcsnicmp(k_u1, k_u2, 0u) == 0);
    TEST_ASSERT(rome2_vfs_crt_ascii_wcsnicmp(k_u1, k_u2, 4u) == 0);
    TEST_ASSERT(rome2_vfs_crt_ascii_wcsnicmp(k_u1, k_u2, 5u) == ('!' - '?'));

    printf("test_vfs_fs_engine_crt_envinit_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
