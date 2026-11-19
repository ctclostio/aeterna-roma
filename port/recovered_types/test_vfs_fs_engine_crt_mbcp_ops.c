#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_mbcp_ops.h"

#define TEST_ASSERT(cond)                                                          \
    do {                                                                           \
        if (!(cond)) {                                                             \
            fprintf(stderr, "FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            return 1;                                                              \
        }                                                                          \
        ++g_checks;                                                                \
    } while (0)

typedef struct mock_l56_ctx {
    void *fls_slot;
    uint8_t fail_fls_set;
    uint32_t alloc_calls;
    uint32_t free_calls;
    uint32_t construct_calls;
    uint32_t abort_calls;
    uint32_t lock_calls;
    uint32_t unlock_calls;
    uint32_t last_lock_id;
    uint32_t api_slot;
    char api_name[32];
    uint32_t compare_w_calls;
    uint32_t compare_ex_calls;
    uint32_t last_lcid;
    char os_name[32];
    char os_val[32];
    uint8_t os_val_is_null;
    uint8_t os_fail;
    uint8_t mb_freed;
} mock_l56_ctx;

static void *mock_fls_get(uint32_t idx, void *ctx) {
    (void)idx;
    return ((mock_l56_ctx *)ctx)->fls_slot;
}

static uint8_t mock_fls_set(uint32_t idx, void *ptr, void *ctx) {
    (void)idx;
    mock_l56_ctx *c = (mock_l56_ctx *)ctx;
    if (c->fail_fls_set != 0u) {
        return 0u;
    }
    c->fls_slot = ptr;
    return 1u;
}

static void *mock_calloc(size_t count, size_t sz, void *ctx) {
    mock_l56_ctx *c = (mock_l56_ctx *)ctx;
    ++c->alloc_calls;
    return calloc(count, sz);
}

static void *mock_recalloc(void *ptr, size_t count, size_t sz, void *ctx) {
    (void)ctx;
    return realloc(ptr, (count == 0u ? 1u : count) * sz);
}

static void mock_free(void *ptr, void *ctx) {
    if (ptr) {
        mock_l56_ctx *c = (mock_l56_ctx *)ctx;
        ++c->free_calls;
        free(ptr);
    }
}

static void mock_ptd_construct(void *ptd, void *init_loc, void *ctx) {
    (void)ptd;
    (void)init_loc;
    ++((mock_l56_ctx *)ctx)->construct_calls;
}

static void mock_abort(void *ctx) {
    ++((mock_l56_ctx *)ctx)->abort_calls;
}

static uint32_t mock_try_get_cmp(
    uint32_t slot,
    const char *name,
    const rome2_vfs_crt_api_mod_desc8_32 *beg,
    const rome2_vfs_crt_api_mod_desc8_32 *end,
    void *ctx) {
    (void)beg;
    (void)end;
    mock_l56_ctx *c = (mock_l56_ctx *)ctx;
    c->api_slot = slot;
    strncpy_s(c->api_name, sizeof(c->api_name), name, _TRUNCATE);
    return 0x66778899u;
}

static uint32_t mock_name_to_lcid(const uint16_t *name, uint32_t flags, void *ctx) {
    (void)flags;
    (void)ctx;
    return (name && name[0] == 'e') ? 0x0409u : 0x0411u;
}

static int32_t mock_compare_u16(
    const uint16_t *s1, int32_t n1, const uint16_t *s2, int32_t n2, uint32_t flags) {
    int32_t len1 = (n1 < 0) ? 0 : n1;
    int32_t len2 = (n2 < 0) ? 0 : n2;
    if (n1 < 0) {
        while (s1[len1] != 0u) {
            ++len1;
        }
    }
    if (n2 < 0) {
        while (s2[len2] != 0u) {
            ++len2;
        }
    }
    int32_t m = len1 < len2 ? len1 : len2;
    for (int32_t i = 0; i < m; ++i) {
        uint16_t a = s1[i];
        uint16_t b = s2[i];
        if ((flags & 1u) != 0u) {
            if (a >= 'A' && a <= 'Z') a = (uint16_t)(a + 0x20u);
            if (b >= 'A' && b <= 'Z') b = (uint16_t)(b + 0x20u);
        }
        if (a != b) {
            return (a < b) ? 1 : 3;
        }
    }
    return (len1 == len2) ? 2 : ((len1 < len2) ? 1 : 3);
}

static int32_t mock_compare_ex(
    const uint16_t *loc, uint32_t flags, const uint16_t *s1, int32_t n1,
    const uint16_t *s2, int32_t n2, void *ctx) {
    (void)loc;
    ++((mock_l56_ctx *)ctx)->compare_ex_calls;
    return mock_compare_u16(s1, n1, s2, n2, flags);
}

static int32_t mock_compare_w(
    uint32_t lcid, uint32_t flags, const uint16_t *s1, int32_t n1,
    const uint16_t *s2, int32_t n2, void *ctx) {
    mock_l56_ctx *c = (mock_l56_ctx *)ctx;
    ++c->compare_w_calls;
    c->last_lcid = lcid;
    return mock_compare_u16(s1, n1, s2, n2, flags);
}

static int32_t mock_mb2wc(
    uint32_t cp, uint32_t flags, const char *src, int32_t srclen,
    uint16_t *dst, int32_t dstlen, void *ctx) {
    (void)cp;
    (void)flags;
    (void)ctx;
    int32_t n = (srclen < 0) ? ((int32_t)strlen(src) + 1) : srclen;
    if (!dst || dstlen == 0) {
        return n;
    }
    int32_t k = (n < dstlen) ? n : dstlen;
    for (int32_t i = 0; i < k; ++i) {
        dst[i] = (uint8_t)src[i];
    }
    return k;
}

static int32_t mock_wc2mb(
    uint32_t cp, uint32_t flags, const uint16_t *src, int32_t srclen,
    char *dst, int32_t dstlen, void *ctx) {
    (void)cp;
    (void)flags;
    (void)ctx;
    int32_t n = (srclen < 0) ? 1 : srclen;
    if (!dst || dstlen == 0) {
        return n;
    }
    int32_t k = (n < dstlen) ? n : dstlen;
    for (int32_t i = 0; i < k; ++i) {
        dst[i] = (char)(uint8_t)(src[i] & 0xffu);
    }
    return k;
}

static int32_t mock_lcmap_ex(
    const uint16_t *loc, uint32_t flags, const uint16_t *src, int32_t srclen,
    uint16_t *dst, int32_t dstlen, void *ctx) {
    (void)loc;
    (void)ctx;
    int32_t n = (srclen < 0) ? 1 : srclen;
    if ((flags & 0x0400u) != 0u) {
        if (!dst || dstlen == 0) {
            return n;
        }
        uint8_t *b = (uint8_t *)(void *)dst;
        for (int32_t i = 0; i < n && i < dstlen; ++i) {
            b[i] = (uint8_t)(src[i] & 0xffu);
        }
        return n < dstlen ? n : dstlen;
    }
    if (!dst || dstlen == 0) {
        return n;
    }
    int32_t k = (n < dstlen) ? n : dstlen;
    for (int32_t i = 0; i < k; ++i) {
        uint16_t ch = src[i];
        if ((flags & 0x100u) != 0u && ch >= 'A' && ch <= 'Z') ch = (uint16_t)(ch + 0x20u);
        if ((flags & 0x200u) != 0u && ch >= 'a' && ch <= 'z') ch = (uint16_t)(ch - 0x20u);
        dst[i] = ch;
    }
    return k;
}

static uint8_t mock_get_cpinfo(uint32_t cp, rome2_vfs_crt_cpinfo20_32 *out, void *ctx) {
    (void)ctx;
    memset(out, 0, sizeof(*out));
    if (cp == 1252u) {
        out->max_char_size_00 = 1u;
        return 1u;
    }
    if (cp == 932u) {
        out->max_char_size_00 = 2u;
        out->lead_byte_06[0] = 0x81u;
        out->lead_byte_06[1] = 0x9fu;
        return 1u;
    }
    return 0u;
}

static uint8_t mock_is_valid_cp(uint32_t cp, void *ctx) {
    (void)ctx;
    return (cp == 1252u || cp == 65001u || cp == 932u) ? 1u : 0u;
}

static void mock_get_str_type_a(uint32_t cp, const char *ch, size_t n, uint16_t *out, void *ctx) {
    (void)cp;
    (void)ctx;
    for (size_t i = 0u; i < n; ++i) {
        uint8_t b = (uint8_t)ch[i];
        if (b >= 'A' && b <= 'Z') out[i] = 1u;
        else if (b >= 'a' && b <= 'z') out[i] = 2u;
        else out[i] = 0u;
    }
}

static void mock_lock(uint32_t id, void *ctx) {
    mock_l56_ctx *c = (mock_l56_ctx *)ctx;
    c->last_lock_id = id;
    ++c->lock_calls;
}

static void mock_unlock(uint32_t id, void *ctx) {
    mock_l56_ctx *c = (mock_l56_ctx *)ctx;
    c->last_lock_id = id;
    ++c->unlock_calls;
}

static void mock_mb_free(rome2_vfs_crt_multibyte_data544_32 *p, void *ctx) {
    (void)ctx;
    ((mock_l56_ctx *)ctx)->mb_freed = 1u;
    free(p);
}

static uint8_t mock_widen_env(uint16_t **out_w, const char *src, uint32_t cp, void *ctx) {
    (void)cp;
    (void)ctx;
    if (!src) {
        *out_w = NULL;
        return 1u;
    }
    size_t n = strlen(src) + 1u;
    uint16_t *w = (uint16_t *)calloc(n, sizeof(uint16_t));
    if (!w) {
        return 0u;
    }
    for (size_t i = 0u; i < n; ++i) {
        w[i] = (uint8_t)src[i];
    }
    *out_w = w;
    return 1u;
}

static uint8_t mock_set_os_env_w(const uint16_t *wname, const uint16_t *wval, void *ctx) {
    mock_l56_ctx *c = (mock_l56_ctx *)ctx;
    if (c->os_fail != 0u) {
        return 0u;
    }
    size_t i = 0u;
    for (; i + 1u < sizeof(c->os_name) && wname[i] != 0u; ++i) {
        c->os_name[i] = (char)(wname[i] & 0xffu);
    }
    c->os_name[i] = '\0';
    if (!wval) {
        c->os_val_is_null = 1u;
        c->os_val[0] = '\0';
    } else {
        c->os_val_is_null = 0u;
        size_t j = 0u;
        for (; j + 1u < sizeof(c->os_val) && wval[j] != 0u; ++j) {
            c->os_val[j] = (char)(wval[j] & 0xffu);
        }
        c->os_val[j] = '\0';
    }
    return 1u;
}

static int32_t mock_env_cmp(const char *a, const char *b, size_t n, void *ctx) {
    (void)ctx;
    for (size_t i = 0u; i < n; ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 0x20u);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 0x20u);
        if (ca != cb || ca == 0u) {
            return (int32_t)ca - (int32_t)cb;
        }
    }
    return 0;
}

int main(void) {
    int g_checks = 0;

    /* 1. Guest32 layouts added in Layer 56 */
    TEST_ASSERT(sizeof(rome2_vfs_crt_multibyte_data544_32) == 0x220u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_multibyte_data544_32, mbctype_18) == 0x18u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_multibyte_data544_32, mbcasemap_119) == 0x119u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_multibyte_data544_32, mblocalename_ptr_21c) == 0x21cu);
    TEST_ASSERT(sizeof(rome2_vfs_crt_codepage_info48_32) == 0x30u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_mbcs_locale_ptrs16_32) == 0x10u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_cpinfo20_32) == 0x14u);

    /* 2. strnlen_bounded (0x116a2c97), strchr (0x116bf200), set_locale_changed (0x116a6bcc), getptd (0x116a46ef) */
    TEST_ASSERT(rome2_vfs_crt_strnlen_bounded("", 10u) == 0u);
    TEST_ASSERT(rome2_vfs_crt_strnlen_bounded("rome2", 3u) == 3u);
    TEST_ASSERT(rome2_vfs_crt_strnlen_bounded("rome2", 10u) == 5u);

    const char *hay = "KEY=VAL";
    TEST_ASSERT(rome2_vfs_crt_strchr(hay, '=') == hay + 3);
    TEST_ASSERT(rome2_vfs_crt_strchr(hay, '\0') == hay + 7);
    TEST_ASSERT(rome2_vfs_crt_strchr(hay, 'Z') == NULL);

    int32_t loc_chg = 0;
    TEST_ASSERT(rome2_vfs_crt_set_locale_changed(&loc_chg) == 0 && loc_chg == 1);
    TEST_ASSERT(rome2_vfs_crt_set_locale_changed(&loc_chg) == 1 && loc_chg == 1);

    mock_l56_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    uint8_t sentinel = 0u;
    void *ptd = rome2_vfs_crt_getptd(
        1u, &sentinel, NULL, mock_fls_get, mock_fls_set, mock_calloc, mock_free, mock_ptd_construct, mock_abort, &ctx);
    TEST_ASSERT(ptd != NULL && ctx.alloc_calls == 1u && ctx.construct_calls == 1u && ctx.abort_calls == 0u);
    TEST_ASSERT(rome2_vfs_crt_getptd(
        1u, &sentinel, NULL, mock_fls_get, mock_fls_set, mock_calloc, mock_free, mock_ptd_construct, mock_abort, &ctx) == ptd);
    free(ptd);
    ctx.fls_slot = &sentinel;
    TEST_ASSERT(rome2_vfs_crt_getptd(
        1u, &sentinel, NULL, mock_fls_get, mock_fls_set, mock_calloc, mock_free, mock_ptd_construct, mock_abort, &ctx) == NULL);
    TEST_ASSERT(ctx.abort_calls == 1u);

    /* 3. try_get_CompareStringEx (0x116a82ed), CompareStringEx (0x116a85f4), LCMapStringA (0x116b1753/93d), CompareStringA_stat (0x116b1c66) */
    TEST_ASSERT(rome2_vfs_crt_try_get_compare_string_ex(mock_try_get_cmp, &ctx) == 0x66778899u);
    TEST_ASSERT(ctx.api_slot == 1u && strcmp(ctx.api_name, "CompareStringEx") == 0);

    static const uint16_t k_en_us[] = { 'e', 'n', '-', 'U', 'S', 0u };
    static const uint16_t k_w1[] = { 'A', 'l', 'p', 'h', 'a', 0u };
    static const uint16_t k_w2[] = { 'a', 'l', 'p', 'h', 'a', 0u };
    TEST_ASSERT(rome2_vfs_crt_compare_string_ex(k_en_us, 1u, k_w1, 5, k_w2, 5, mock_compare_ex, mock_name_to_lcid, mock_compare_w, &ctx) == 2);
    TEST_ASSERT(ctx.compare_ex_calls == 1u);
    TEST_ASSERT(rome2_vfs_crt_compare_string_ex(k_en_us, 0u, k_w1, 5, k_w2, 5, NULL, mock_name_to_lcid, mock_compare_w, &ctx) == 1);
    TEST_ASSERT(ctx.compare_w_calls == 1u && ctx.last_lcid == 0x0409u);

    char lc_out[16] = { 0 };
    int32_t lc_res = rome2_vfs_crt_lcmap_string_a(
        1252u, k_en_us, 0x100u, "RoMe", 4, lc_out, (int32_t)sizeof(lc_out), 0u, 0u,
        mock_mb2wc, mock_lcmap_ex, mock_wc2mb, &ctx);
    TEST_ASSERT(lc_res == 4 && memcmp(lc_out, "rome", 4) == 0);
    int32_t sk_res = rome2_vfs_crt_lcmap_string_a_stat(
        k_en_us, 0x400u, "AB", 2, lc_out, (int32_t)sizeof(lc_out), 1252u, 1u,
        mock_mb2wc, mock_lcmap_ex, mock_wc2mb, &ctx);
    TEST_ASSERT(sk_res == 2 && lc_out[0] == 'A' && lc_out[1] == 'B');

    TEST_ASSERT(rome2_vfs_crt_compare_string_a_stat(
        k_en_us, 1u, "", 0, "a", 1, 1252u, mock_get_cpinfo, mock_mb2wc, mock_compare_ex, mock_name_to_lcid, mock_compare_w, &ctx) == 1);
    TEST_ASSERT(rome2_vfs_crt_compare_string_a_stat(
        k_en_us, 1u, "Beta", 4, "bEtA", 4, 1252u, mock_get_cpinfo, mock_mb2wc, mock_compare_ex, mock_name_to_lcid, mock_compare_w, &ctx) == 2);

    /* 4. MBCP / SBCS / SEH4 lock-guarded global update (0x116b46d2..0x116b4c4b) */
    rome2_vfs_crt_multibyte_data544_32 initial_mb;
    memset(&initial_mb, 0, sizeof(initial_mb));
    initial_mb.mbctype_18[1u + (uint8_t)'A'] = 0x10u;
    initial_mb.mbcasemap_119[(uint8_t)'A'] = (uint8_t)'a';
    rome2_vfs_crt_multibyte_data544_32 *global_mb = &initial_mb;
    rome2_vfs_crt_multibyte_data544_32 *thread_mb = &initial_mb;
    initial_mb.refcount_00 = 2;

    static const rome2_vfs_crt_mbcs_locale_ptrs16_32 k_loc_ptrs = { 0x1190dcccu, 0x1190dfdcu, 0x1190dcd8u, 0x1190dc3cu };
    TEST_ASSERT(rome2_vfs_crt_cp_to_locale_name_guest(932, &k_loc_ptrs) == 0x1190dcccu);
    TEST_ASSERT(rome2_vfs_crt_cp_to_locale_name_guest(949, &k_loc_ptrs) == 0x1190dcd8u);
    TEST_ASSERT(rome2_vfs_crt_cp_to_locale_name_guest(1252, &k_loc_ptrs) == 0u);

    int32_t f_sys = 99;
    TEST_ASSERT(rome2_vfs_crt_get_system_cp(-2, &f_sys, 437, 1252, 65001) == 437 && f_sys == 1);
    TEST_ASSERT(rome2_vfs_crt_get_system_cp(-3, &f_sys, 437, 1252, 65001) == 1252 && f_sys == 1);
    TEST_ASSERT(rome2_vfs_crt_get_system_cp(-4, &f_sys, 437, 1252, 65001) == 65001 && f_sys == 1);
    TEST_ASSERT(rome2_vfs_crt_get_system_cp(932, &f_sys, 437, 1252, 65001) == 932 && f_sys == 0);

    static const rome2_vfs_crt_codepage_info48_32 k_rg[2] = {
        { 932u, { 0x81u, 0x9fu, 0u }, { { 0x81u, 0x9fu, 0xe0u, 0xfcu, 0u }, { 0x40u, 0x7eu, 0x80u, 0xfcu, 0u }, { 0u }, { 0u } } },
        { 936u, { 0x81u, 0xfeu, 0u }, { { 0x81u, 0xfeu, 0u }, { 0x40u, 0xfeu, 0u }, { 0u }, { 0u } } }
    };
    uint8_t mbct[257] = { 0 };
    uint8_t mbcm[256] = { 0 };
    int32_t err = 0;
    TEST_ASSERT(rome2_vfs_crt_setmbcp_internal(
        932, 1u, &thread_mb, &global_mb, &initial_mb, k_rg, 2u, &k_loc_ptrs,
        mbct, mbcm, &f_sys, 437, 1252, 1252,
        mock_is_valid_cp, mock_get_cpinfo, mock_get_str_type_a, mock_mb2wc, mock_lcmap_ex, mock_wc2mb,
        mock_lock, mock_unlock, mock_calloc, mock_mb_free, &err, &ctx) == 0);
    TEST_ASSERT(thread_mb == global_mb && thread_mb != &initial_mb && thread_mb->refcount_00 == 2);
    TEST_ASSERT(thread_mb->mbcodepage_04 == 932u && thread_mb->ismbcodepage_08 == 1 && thread_mb->mblocalename_ptr_21c == 0x1190dcccu);
    TEST_ASSERT((mbct[1u + 0x81u] & 0x01u) != 0u && (mbct[1u + 0x40u] & 0x02u) != 0u);
    TEST_ASSERT((mbct[1u + (uint8_t)'A'] & 0x10u) != 0u && mbcm[(uint8_t)'A'] == (uint8_t)'a');
    TEST_ASSERT(ctx.lock_calls == 1u && ctx.unlock_calls == 1u);

    TEST_ASSERT(rome2_vfs_crt_setmbcp_internal(
        1252, 1u, &thread_mb, &global_mb, &initial_mb, k_rg, 2u, &k_loc_ptrs,
        mbct, mbcm, &f_sys, 437, 1252, 1252,
        mock_is_valid_cp, mock_get_cpinfo, mock_get_str_type_a, mock_mb2wc, mock_lcmap_ex, mock_wc2mb,
        mock_lock, mock_unlock, mock_calloc, mock_mb_free, &err, &ctx) == 0);
    TEST_ASSERT(ctx.mb_freed == 1u && thread_mb->mbcodepage_04 == 1252u && thread_mb->ismbcodepage_08 == 0);

    rome2_vfs_crt_multibyte_data544_32 sbcs_tmp;
    memset(&sbcs_tmp, 0xff, sizeof(sbcs_tmp));
    rome2_vfs_crt_set_sbcs(&sbcs_tmp, &initial_mb);
    TEST_ASSERT(sbcs_tmp.mbcodepage_04 == 0u && sbcs_tmp.ismbcodepage_08 == 0 && sbcs_tmp.mbcasemap_119[(uint8_t)'A'] == (uint8_t)'a');

    /* Bad codepage & UTF-7 (65000) return -1 with EINVAL; UTF-8 (65001) & fast-path no-op succeed */
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_setmbcp_internal(
        99999, 0u, &thread_mb, &global_mb, &initial_mb, k_rg, 2u, &k_loc_ptrs,
        mbct, mbcm, &f_sys, 437, 1252, 1252,
        mock_is_valid_cp, mock_get_cpinfo, mock_get_str_type_a, mock_mb2wc, mock_lcmap_ex, mock_wc2mb,
        mock_lock, mock_unlock, mock_calloc, mock_mb_free, &err, &ctx) == -1 && err == 22);
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_setmbcp_internal(
        65000, 0u, &thread_mb, &global_mb, &initial_mb, k_rg, 2u, &k_loc_ptrs,
        mbct, mbcm, &f_sys, 437, 1252, 1252,
        mock_is_valid_cp, mock_get_cpinfo, mock_get_str_type_a, mock_mb2wc, mock_lcmap_ex, mock_wc2mb,
        mock_lock, mock_unlock, mock_calloc, mock_mb_free, &err, &ctx) == -1 && err == 22);
    uint32_t locks_before = ctx.lock_calls;
    TEST_ASSERT(rome2_vfs_crt_setmbcp_internal(
        1252, 0u, &thread_mb, &global_mb, &initial_mb, k_rg, 2u, &k_loc_ptrs,
        mbct, mbcm, &f_sys, 437, 1252, 1252,
        mock_is_valid_cp, mock_get_cpinfo, mock_get_str_type_a, mock_mb2wc, mock_lcmap_ex, mock_wc2mb,
        mock_lock, mock_unlock, mock_calloc, mock_mb_free, &err, &ctx) == 0);
    TEST_ASSERT(ctx.lock_calls == locks_before);
    TEST_ASSERT(rome2_vfs_crt_setmbcp_internal(
        65001, 0u, &thread_mb, &global_mb, &initial_mb, k_rg, 2u, &k_loc_ptrs,
        mbct, mbcm, &f_sys, 437, 1252, 1252,
        mock_is_valid_cp, mock_get_cpinfo, mock_get_str_type_a, mock_mb2wc, mock_lcmap_ex, mock_wc2mb,
        mock_lock, mock_unlock, mock_calloc, mock_mb_free, &err, &ctx) == 0);
    TEST_ASSERT(thread_mb->mbcodepage_04 == 65001u && thread_mb->ismbcodepage_08 == 0 && ctx.lock_calls == locks_before);
    TEST_ASSERT((thread_mb->mbctype_18[1u + (uint8_t)'B'] & 0x10u) != 0u && thread_mb->mbcasemap_119[(uint8_t)'b'] == (uint8_t)'B');
    free(thread_mb);

    /* Direct edge-case checks for LCMapStringA size query, CompareStringA_stat equal empties & direct set_var */
    TEST_ASSERT(rome2_vfs_crt_lcmap_string_a_stat(
        k_en_us, 0x200u, "ab", 2, NULL, 0, 1252u, 0u, mock_mb2wc, mock_lcmap_ex, mock_wc2mb, &ctx) == 2);
    TEST_ASSERT(rome2_vfs_crt_compare_string_a_stat(
        k_en_us, 1u, "", 0, "", 0, 1252u, mock_get_cpinfo, mock_mb2wc, mock_compare_ex, mock_name_to_lcid, mock_compare_w, &ctx) == 2);
    TEST_ASSERT(rome2_vfs_crt_set_var_in_system_env(
        "DIRECT", "VALUE", 1252u, mock_widen_env, mock_set_os_env_w, mock_free, &ctx) == 1u);
    TEST_ASSERT(strcmp(ctx.os_name, "DIRECT") == 0 && strcmp(ctx.os_val, "VALUE") == 0);
    TEST_ASSERT(rome2_vfs_crt_copy_environment_narrow(NULL, mock_calloc, mock_abort, &ctx) == NULL);

    /* 5. Environment copy / find / common_set_variable_in_environment_nolock<char> (0x116af5f5, 0x116b5462..0x116b56b1) */
    char *init_env[3] = { "ROME_MOD=vanilla", "DLC=rise", NULL };
    char **cur_env = init_env;
    rome2_vfs_crt_ensure_narrow_env_copied(&cur_env, init_env, mock_calloc, mock_abort, &ctx);
    TEST_ASSERT(cur_env != init_env && strcmp(cur_env[0], "ROME_MOD=vanilla") == 0 && strcmp(cur_env[1], "DLC=rise") == 0);
    TEST_ASSERT(rome2_vfs_crt_find_in_env_array_narrow((const char *const *)cur_env, "dlc=x", 3u, mock_env_cmp, &ctx) == 1);
    TEST_ASSERT(rome2_vfs_crt_find_in_env_array_narrow((const char *const *)cur_env, "DL", 2u, mock_env_cmp, &ctx) == -2);
    TEST_ASSERT(rome2_vfs_crt_find_in_env_array_narrow((const char *const *)cur_env, "NEWVAR=1", 6u, mock_env_cmp, &ctx) == -2);

    /* Replace existing entry */
    TEST_ASSERT(rome2_vfs_crt_common_set_env_var_nolock_narrow(
        "DLC=emperor", 1, &cur_env, init_env, 1u, 1252u,
        mock_calloc, mock_recalloc, mock_free, mock_env_cmp, mock_widen_env, mock_set_os_env_w, mock_abort, &err, &ctx) == 0);
    TEST_ASSERT(strcmp(cur_env[1], "DLC=emperor") == 0 && strcmp(ctx.os_name, "DLC") == 0 && strcmp(ctx.os_val, "emperor") == 0);

    /* Insert new entry */
    TEST_ASSERT(rome2_vfs_crt_common_set_env_var_nolock_narrow(
        "MOD_DIR=mods", 1, &cur_env, init_env, 1u, 1252u,
        mock_calloc, mock_recalloc, mock_free, mock_env_cmp, mock_widen_env, mock_set_os_env_w, mock_abort, &err, &ctx) == 0);
    TEST_ASSERT(strcmp(cur_env[2], "MOD_DIR=mods") == 0 && cur_env[3] == NULL);

    /* Delete entry ("MOD_DIR=") */
    TEST_ASSERT(rome2_vfs_crt_common_set_env_var_nolock_narrow(
        "MOD_DIR=", 1, &cur_env, init_env, 1u, 1252u,
        mock_calloc, mock_recalloc, mock_free, mock_env_cmp, mock_widen_env, mock_set_os_env_w, mock_abort, &err, &ctx) == 0);
    TEST_ASSERT(cur_env[2] == NULL && ctx.os_val_is_null == 1u);

    /* Invalid option rejected with EINVAL; OS failure sets EILSEQ */
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_common_set_env_var_nolock_narrow(
        "=bad", 1, &cur_env, init_env, 1u, 1252u,
        mock_calloc, mock_recalloc, mock_free, mock_env_cmp, mock_widen_env, mock_set_os_env_w, mock_abort, &err, &ctx) == -1 && err == 22);
    ctx.os_fail = 1u;
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_common_set_env_var_nolock_narrow(
        "ROME_MOD=dei", 1, &cur_env, init_env, 1u, 1252u,
        mock_calloc, mock_recalloc, mock_free, mock_env_cmp, mock_widen_env, mock_set_os_env_w, mock_abort, &err, &ctx) == -1 && err == 42);

    TEST_ASSERT(cur_env != NULL);
    for (size_t i = 0u; cur_env[i] != NULL; ++i) {
        free(cur_env[i]);
    }
    free(cur_env);

    printf("test_vfs_fs_engine_crt_mbcp_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
