#include "vfs_fs_engine_crt_mbcp_ops.h"

#include <stdlib.h>
#include <string.h>

enum {
    ROME2_VFS_L56_ENOMEM = 12,
    ROME2_VFS_L56_EINVAL = 22,
    ROME2_VFS_L56_EILSEQ = 42,
    ROME2_VFS_L56_CP_UTF8 = 65001u,
    ROME2_VFS_L56_CP_UTF7 = 65000u,
    ROME2_VFS_L56_LCMAP_LOWERCASE = 0x100u,
    ROME2_VFS_L56_LCMAP_UPPERCASE = 0x200u,
    ROME2_VFS_L56_PTD_BYTES = 0x364u,
    ROME2_VFS_L56_MB_UPPER = 0x10u,
    ROME2_VFS_L56_MB_LOWER = 0x20u
};

static void r2_l56_set_err(int32_t *out_errno, int32_t code) {
    if (out_errno) {
        *out_errno = code;
    }
}

/* `0x116a2c97` */
size_t rome2_vfs_crt_strnlen_bounded(const char *str, size_t max_count) {
    if (!str || str[0] == '\0') {
        return 0u;
    }
    size_t n = 0u;
    while (n < max_count && str[n] != '\0') {
        ++n;
    }
    return n;
}

/* `0x116bf200` */
const char *rome2_vfs_crt_strchr(const char *str, int32_t ch) {
    if (!str) {
        return NULL;
    }
    uint8_t target = (uint8_t)(ch & 0xff);
    const char *p = str;
    for (;;) {
        uint8_t c = (uint8_t)*p;
        if (c == target) {
            return p;
        }
        if (c == 0u) {
            return NULL;
        }
        ++p;
    }
}

/* `0x116a6bcc` */
int32_t rome2_vfs_crt_set_locale_changed(int32_t *inout_locale_changed) {
    if (!inout_locale_changed) {
        return 0;
    }
    int32_t prev = *inout_locale_changed;
    *inout_locale_changed = 1;
    return prev;
}

/* `0x116a46ef` */
void *rome2_vfs_crt_getptd(
    uint32_t fls_index,
    void *sentinel_in_progress,
    void *initial_locinfo,
    rome2_vfs_crt_fls_get_fn fls_get_fn,
    rome2_vfs_crt_fls_set_fn fls_set_fn,
    rome2_vfs_crt_ptd_alloc_fn alloc_fn,
    rome2_vfs_crt_ptd_free_fn free_fn,
    rome2_vfs_crt_ptd_construct_fn construct_fn,
    rome2_vfs_crt_abort_fn abort_fn,
    void *ctx) {
    if (!fls_get_fn || !fls_set_fn || !alloc_fn) {
        if (abort_fn) {
            abort_fn(ctx);
        }
        return NULL;
    }
    void *ptd = fls_get_fn(fls_index, ctx);
    if (ptd != NULL) {
        if (ptd == sentinel_in_progress) {
            if (abort_fn) {
                abort_fn(ctx);
            }
            return NULL;
        }
        return ptd;
    }
    if (fls_set_fn(fls_index, sentinel_in_progress, ctx) == 0u) {
        if (abort_fn) {
            abort_fn(ctx);
        }
        return NULL;
    }
    void *alloc = alloc_fn(1u, ROME2_VFS_L56_PTD_BYTES, ctx);
    if (!alloc) {
        (void)fls_set_fn(fls_index, NULL, ctx);
        if (abort_fn) {
            abort_fn(ctx);
        }
        return NULL;
    }
    if (fls_set_fn(fls_index, alloc, ctx) == 0u) {
        (void)fls_set_fn(fls_index, NULL, ctx);
        if (free_fn) {
            free_fn(alloc, ctx);
        }
        if (abort_fn) {
            abort_fn(ctx);
        }
        return NULL;
    }
    if (construct_fn) {
        construct_fn(alloc, initial_locinfo, ctx);
    }
    return alloc;
}

/* `0x116a82ed` */
uint32_t rome2_vfs_crt_try_get_compare_string_ex(
    rome2_vfs_crt_try_get_api_fn resolve_fn,
    void *ctx) {
    static const rome2_vfs_crt_api_mod_desc8_32 k_mods[2] = {
        { 0x6u, 0x10u },
        { 0x3u, 0x10u }
    };
    if (!resolve_fn) {
        return 0u;
    }
    return resolve_fn(1u, "CompareStringEx", &k_mods[0], &k_mods[1], ctx);
}

/* `0x116a85f4` */
int32_t rome2_vfs_crt_compare_string_ex(
    const uint16_t *locale_name,
    uint32_t flags,
    const uint16_t *s1,
    int32_t n1,
    const uint16_t *s2,
    int32_t n2,
    rome2_vfs_crt_compare_string_ex_fn dynamic_fn,
    rome2_vfs_crt_locale_name_to_lcid_fn name_to_lcid_fn,
    rome2_vfs_crt_compare_string_w_fn compare_w_fn,
    void *ctx) {
    if (dynamic_fn) {
        return dynamic_fn(locale_name, flags, s1, n1, s2, n2, ctx);
    }
    if (!compare_w_fn) {
        return 0;
    }
    uint32_t lcid = name_to_lcid_fn ? name_to_lcid_fn(locale_name, 0u, ctx) : 0u;
    return compare_w_fn(lcid, flags, s1, n1, s2, n2, ctx);
}

/* Helper to allocate bounded wide scratch buffer via CRT heap/fallback convention. */
static uint16_t *r2_l56_widen_arg(
    const char *src,
    int32_t src_len,
    uint32_t codepage,
    uint32_t mb_flags,
    rome2_vfs_crt_mb2wc_fn mb2wc_fn,
    void *ctx,
    int32_t *out_wlen) {
    if (!mb2wc_fn || !src || src_len == 0) {
        *out_wlen = 0;
        return NULL;
    }
    int32_t eff_len = (src_len > 0) ? (int32_t)rome2_vfs_crt_strnlen_bounded(src, (size_t)src_len) : -1;
    int32_t needed = mb2wc_fn(codepage, mb_flags, src, eff_len, NULL, 0, ctx);
    if (needed <= 0) {
        *out_wlen = -1;
        return NULL;
    }
    size_t wcount = (size_t)needed + (eff_len >= 0 ? 1u : 0u);
    uint16_t *wbuf = (uint16_t *)calloc(wcount, sizeof(uint16_t));
    if (!wbuf) {
        *out_wlen = -1;
        return NULL;
    }
    int32_t wrote = mb2wc_fn(codepage, mb_flags, src, eff_len, wbuf, needed, ctx);
    if (wrote == 0) {
        free(wbuf);
        *out_wlen = -1;
        return NULL;
    }
    *out_wlen = needed;
    return wbuf;
}

/* `0x116b1753` */
int32_t rome2_vfs_crt_lcmap_string_a_stat(
    const uint16_t *locale_name,
    uint32_t flags,
    const char *src,
    int32_t src_len,
    char *dst,
    int32_t dst_len,
    uint32_t codepage,
    uint8_t error_invalid_char,
    rome2_vfs_crt_mb2wc_fn mb2wc_fn,
    rome2_vfs_crt_lcmap_ex_fn lcmap_ex_fn,
    rome2_vfs_crt_wc2mb_fn wc2mb_fn,
    void *ctx) {
    if (!mb2wc_fn || !lcmap_ex_fn) {
        return 0;
    }
    int32_t eff_src_len = src_len;
    if (eff_src_len > 0 && src) {
        int32_t bounded = (int32_t)rome2_vfs_crt_strnlen_bounded(src, (size_t)eff_src_len);
        eff_src_len = (bounded < eff_src_len) ? (bounded + 1) : eff_src_len;
    }
    uint32_t mb_flags = error_invalid_char ? 8u : 1u;
    int32_t wide_src_len = 0;
    uint16_t *wsrc = r2_l56_widen_arg(src, eff_src_len, codepage, mb_flags, mb2wc_fn, ctx, &wide_src_len);
    if (!wsrc || wide_src_len <= 0) {
        return 0;
    }

    int32_t retval = 0;
    if ((flags & 0x0400u) != 0u) {
        /* LCMAP_SORTKEY path: write only when caller provided sufficient capacity. */
        int32_t sk_bytes = lcmap_ex_fn(locale_name, flags, wsrc, wide_src_len, NULL, 0, ctx);
        if (sk_bytes != 0) {
            if (dst && dst_len >= sk_bytes) {
                retval = lcmap_ex_fn(locale_name, flags, wsrc, wide_src_len, (uint16_t *)(void *)dst, dst_len, ctx);
            } else {
                retval = sk_bytes;
            }
        }
    } else {
        int32_t needed_w = lcmap_ex_fn(locale_name, flags, wsrc, wide_src_len, NULL, 0, ctx);
        if (needed_w > 0) {
            uint16_t *wdst = (uint16_t *)calloc((size_t)needed_w, sizeof(uint16_t));
            if (wdst) {
                if (lcmap_ex_fn(locale_name, flags, wsrc, wide_src_len, wdst, needed_w, ctx) != 0 && wc2mb_fn) {
                    if (dst_len == 0 || !dst) {
                        retval = wc2mb_fn(codepage, 0u, wdst, needed_w, NULL, 0, ctx);
                    } else {
                        retval = wc2mb_fn(codepage, 0u, wdst, needed_w, dst, dst_len, ctx);
                    }
                }
                free(wdst);
            }
        }
    }
    free(wsrc);
    return retval;
}

/* `0x116b193d` */
int32_t rome2_vfs_crt_lcmap_string_a(
    uint32_t default_cp,
    const uint16_t *locale_name,
    uint32_t flags,
    const char *src,
    int32_t src_len,
    char *dst,
    int32_t dst_len,
    uint32_t codepage,
    uint8_t error_invalid_char,
    rome2_vfs_crt_mb2wc_fn mb2wc_fn,
    rome2_vfs_crt_lcmap_ex_fn lcmap_ex_fn,
    rome2_vfs_crt_wc2mb_fn wc2mb_fn,
    void *ctx) {
    uint32_t effective_cp = (codepage == 0u) ? default_cp : codepage;
    return rome2_vfs_crt_lcmap_string_a_stat(
        locale_name, flags, src, src_len, dst, dst_len, effective_cp, error_invalid_char,
        mb2wc_fn, lcmap_ex_fn, wc2mb_fn, ctx);
}

/* `0x116b1c66` */
int32_t rome2_vfs_crt_compare_string_a_stat(
    const uint16_t *locale_name,
    uint32_t flags,
    const char *s1,
    int32_t n1,
    const char *s2,
    int32_t n2,
    uint32_t codepage,
    rome2_vfs_crt_get_cpinfo_fn get_cpinfo_fn,
    rome2_vfs_crt_mb2wc_fn mb2wc_fn,
    rome2_vfs_crt_compare_string_ex_fn dynamic_fn,
    rome2_vfs_crt_locale_name_to_lcid_fn name_to_lcid_fn,
    rome2_vfs_crt_compare_string_w_fn compare_w_fn,
    void *ctx) {
    if (!s1 || !s2 || !mb2wc_fn) {
        return 0;
    }
    int32_t len1 = (n1 > 0) ? (int32_t)rome2_vfs_crt_strnlen_bounded(s1, (size_t)n1) : n1;
    int32_t len2 = (n2 > 0) ? (int32_t)rome2_vfs_crt_strnlen_bounded(s2, (size_t)n2) : n2;

    if (len1 == 0 || len2 == 0) {
        uint8_t local_sbcs = 0u;
        if (codepage != ROME2_VFS_L56_CP_UTF7 && codepage != ROME2_VFS_L56_CP_UTF8 && get_cpinfo_fn) {
            rome2_vfs_crt_cpinfo20_32 cpi;
            memset(&cpi, 0, sizeof(cpi));
            if (get_cpinfo_fn(codepage, &cpi, ctx) != 0u && cpi.max_char_size_00 == 1u) {
                local_sbcs = 1u;
            }
        }
        if (local_sbcs != 0u || (len1 == 0 && len2 == 0)) {
            if (len1 == len2) {
                return 2; /* CSTR_EQUAL */
            }
            return (len1 > 0) ? 3 : 1; /* CSTR_GREATER_THAN / CSTR_LESS_THAN */
        }
    }

    int32_t wlen1 = 0;
    int32_t wlen2 = 0;
    uint16_t *ws1 = r2_l56_widen_arg(s1, len1, codepage, 8u, mb2wc_fn, ctx, &wlen1);
    uint16_t *ws2 = ws1 ? r2_l56_widen_arg(s2, len2, codepage, 8u, mb2wc_fn, ctx, &wlen2) : NULL;
    int32_t res = 0;
    if (ws1 && ws2 && wlen1 >= 0 && wlen2 >= 0) {
        res = rome2_vfs_crt_compare_string_ex(
            locale_name, flags, ws1, wlen1, ws2, wlen2, dynamic_fn, name_to_lcid_fn, compare_w_fn, ctx);
    }
    free(ws2);
    free(ws1);
    return res;
}

/* `0x116b4713` */
void rome2_vfs_crt_seh_finally_unlock(
    uint32_t lock_id,
    rome2_vfs_crt_lock_op_fn unlock_fn,
    void *ctx) {
    if (unlock_fn) {
        unlock_fn(lock_id, ctx);
    }
}

/* `0x116b471f` */
void rome2_vfs_crt_update_global_mb_lambda(
    rome2_vfs_crt_multibyte_data544_32 *new_mbcinfo,
    const rome2_vfs_crt_multibyte_data544_32 *initial_mbcinfo,
    rome2_vfs_crt_multibyte_data544_32 **global_mbcinfo,
    uint8_t *out_mbctype257,
    uint8_t *out_mbcasemap256,
    rome2_vfs_crt_mb_free_fn free_mb_fn,
    void *ctx) {
    if (!new_mbcinfo || !global_mbcinfo) {
        return;
    }
    if (out_mbctype257) {
        memcpy(out_mbctype257, new_mbcinfo->mbctype_18, sizeof(new_mbcinfo->mbctype_18));
    }
    if (out_mbcasemap256) {
        memcpy(out_mbcasemap256, new_mbcinfo->mbcasemap_119, sizeof(new_mbcinfo->mbcasemap_119));
    }
    rome2_vfs_crt_multibyte_data544_32 *old = *global_mbcinfo;
    if (old) {
        old->refcount_00 -= 1;
        if (old->refcount_00 == 0 && old != initial_mbcinfo && free_mb_fn) {
            free_mb_fn(old, ctx);
        }
    }
    *global_mbcinfo = new_mbcinfo;
    new_mbcinfo->refcount_00 += 1;
}

/* `0x116b46d2` */
void rome2_vfs_crt_seh_guarded_update_mb(
    uint32_t lock_id,
    rome2_vfs_crt_lock_op_fn lock_fn,
    rome2_vfs_crt_lock_op_fn unlock_fn,
    rome2_vfs_crt_multibyte_data544_32 *new_mbcinfo,
    const rome2_vfs_crt_multibyte_data544_32 *initial_mbcinfo,
    rome2_vfs_crt_multibyte_data544_32 **global_mbcinfo,
    uint8_t *out_mbctype257,
    uint8_t *out_mbcasemap256,
    rome2_vfs_crt_mb_free_fn free_mb_fn,
    void *ctx) {
    if (lock_fn) {
        lock_fn(lock_id, ctx);
    }
    rome2_vfs_crt_update_global_mb_lambda(
        new_mbcinfo, initial_mbcinfo, global_mbcinfo, out_mbctype257, out_mbcasemap256, free_mb_fn, ctx);
    rome2_vfs_crt_seh_finally_unlock(lock_id, unlock_fn, ctx);
}

/* `0x116b47a2` */
uint32_t rome2_vfs_crt_cp_to_locale_name_guest(
    int32_t codepage,
    const rome2_vfs_crt_mbcs_locale_ptrs16_32 *table) {
    if (!table) {
        return 0u;
    }
    switch (codepage) {
        case 932: return table->ja_jp_ptr_00;
        case 936: return table->zh_cn_ptr_04;
        case 949: return table->ko_kr_ptr_08;
        case 950: return table->zh_tw_ptr_0c;
        default:  return 0u;
    }
}

/* `0x116b47e0` */
int32_t rome2_vfs_crt_get_system_cp(
    int32_t codepage,
    int32_t *out_f_system_set,
    int32_t oem_cp,
    int32_t acp_cp,
    int32_t thread_lc_cp) {
    if (out_f_system_set) {
        *out_f_system_set = 0;
    }
    if (codepage == -2) {
        if (out_f_system_set) {
            *out_f_system_set = 1;
        }
        return oem_cp;
    }
    if (codepage == -3) {
        if (out_f_system_set) {
            *out_f_system_set = 1;
        }
        return acp_cp;
    }
    if (codepage == -4) {
        if (out_f_system_set) {
            *out_f_system_set = 1;
        }
        return thread_lc_cp;
    }
    return codepage;
}

/* `0x116b4851` */
void rome2_vfs_crt_set_sbcs(
    rome2_vfs_crt_multibyte_data544_32 *dst,
    const rome2_vfs_crt_multibyte_data544_32 *initial_mbcinfo) {
    if (!dst || !initial_mbcinfo) {
        return;
    }
    dst->mbcodepage_04 = 0u;
    dst->ismbcodepage_08 = 0;
    dst->mblocalename_ptr_21c = 0u;
    memset(dst->mbulinfo_0c, 0, sizeof(dst->mbulinfo_0c));
    memcpy(dst->mbctype_18, initial_mbcinfo->mbctype_18, sizeof(dst->mbctype_18));
    memcpy(dst->mbcasemap_119, initial_mbcinfo->mbcasemap_119, sizeof(dst->mbcasemap_119));
}

/* `0x116b48b6` */
void rome2_vfs_crt_set_sb_up_low(
    rome2_vfs_crt_multibyte_data544_32 *mbcinfo,
    rome2_vfs_crt_get_cpinfo_fn get_cpinfo_fn,
    rome2_vfs_crt_get_string_type_a_fn get_str_type_a_fn,
    rome2_vfs_crt_mb2wc_fn mb2wc_fn,
    rome2_vfs_crt_lcmap_ex_fn lcmap_ex_fn,
    rome2_vfs_crt_wc2mb_fn wc2mb_fn,
    void *ctx) {
    if (!mbcinfo) {
        return;
    }
    rome2_vfs_crt_cpinfo20_32 cpinfo;
    memset(&cpinfo, 0, sizeof(cpinfo));
    if (mbcinfo->mbcodepage_04 != ROME2_VFS_L56_CP_UTF8
        && get_cpinfo_fn
        && get_cpinfo_fn(mbcinfo->mbcodepage_04, &cpinfo, ctx) != 0u) {
        char chars[256] = { 0 };
        for (uint32_t i = 0u; i < 256u; ++i) {
            chars[i] = (char)(uint8_t)i;
        }
        chars[0] = ' ';
        for (size_t off = 0u; off + 1u < sizeof(cpinfo.lead_byte_06); off += 2u) {
            uint8_t lo = cpinfo.lead_byte_06[off];
            uint8_t hi = cpinfo.lead_byte_06[off + 1u];
            if (lo == 0u) {
                break;
            }
            for (uint32_t b = lo; b <= hi && b < 256u; ++b) {
                chars[b] = ' ';
            }
        }
        uint16_t ctype[256] = { 0 };
        char low_map[256] = { 0 };
        char up_map[256] = { 0 };
        if (get_str_type_a_fn) {
            get_str_type_a_fn(mbcinfo->mbcodepage_04, chars, 256u, ctype, ctx);
        }
        if (mb2wc_fn && lcmap_ex_fn && wc2mb_fn) {
            (void)rome2_vfs_crt_lcmap_string_a(
                mbcinfo->mbcodepage_04, NULL, ROME2_VFS_L56_LCMAP_LOWERCASE, chars, 256,
                low_map, 256, mbcinfo->mbcodepage_04, 0u, mb2wc_fn, lcmap_ex_fn, wc2mb_fn, ctx);
            (void)rome2_vfs_crt_lcmap_string_a(
                mbcinfo->mbcodepage_04, NULL, ROME2_VFS_L56_LCMAP_UPPERCASE, chars, 256,
                up_map, 256, mbcinfo->mbcodepage_04, 0u, mb2wc_fn, lcmap_ex_fn, wc2mb_fn, ctx);
        }
        for (size_t i = 0u; i < 256u; ++i) {
            if ((ctype[i] & 1u) != 0u) {
                mbcinfo->mbctype_18[1u + i] |= ROME2_VFS_L56_MB_UPPER;
                mbcinfo->mbcasemap_119[i] = (uint8_t)low_map[i];
            } else if ((ctype[i] & 2u) != 0u) {
                mbcinfo->mbctype_18[1u + i] |= ROME2_VFS_L56_MB_LOWER;
                mbcinfo->mbcasemap_119[i] = (uint8_t)up_map[i];
            } else {
                mbcinfo->mbcasemap_119[i] = 0u;
            }
        }
        return;
    }

    /* ASCII fallback for UTF-8 or GetCPInfo failure (0x116b49ea..0x116b4a26). */
    for (uint32_t ch = 0u; ch < 256u; ++ch) {
        if (ch >= (uint32_t)'A' && ch <= (uint32_t)'Z') {
            mbcinfo->mbctype_18[1u + ch] |= ROME2_VFS_L56_MB_UPPER;
            mbcinfo->mbcasemap_119[ch] = (uint8_t)(ch + 0x20u);
        } else if (ch >= (uint32_t)'a' && ch <= (uint32_t)'z') {
            mbcinfo->mbctype_18[1u + ch] |= ROME2_VFS_L56_MB_LOWER;
            mbcinfo->mbcasemap_119[ch] = (uint8_t)(ch - 0x20u);
        } else {
            mbcinfo->mbcasemap_119[ch] = 0u;
        }
    }
}

/* `0x116b4c4b` */
int32_t rome2_vfs_crt_setmbcp_nolock(
    int32_t codepage,
    rome2_vfs_crt_multibyte_data544_32 *mbcinfo,
    const rome2_vfs_crt_multibyte_data544_32 *initial_mbcinfo,
    const rome2_vfs_crt_codepage_info48_32 *rgctype_table,
    size_t rgctype_count,
    const rome2_vfs_crt_mbcs_locale_ptrs16_32 *locale_ptr_table,
    int32_t *out_f_system_set,
    int32_t oem_cp,
    int32_t acp_cp,
    int32_t thread_lc_cp,
    uint8_t (*is_valid_cp_fn)(uint32_t cp, void *ctx),
    rome2_vfs_crt_get_cpinfo_fn get_cpinfo_fn,
    rome2_vfs_crt_get_string_type_a_fn get_str_type_a_fn,
    rome2_vfs_crt_mb2wc_fn mb2wc_fn,
    rome2_vfs_crt_lcmap_ex_fn lcmap_ex_fn,
    rome2_vfs_crt_wc2mb_fn wc2mb_fn,
    void *ctx) {
    static const uint8_t k_mbctype_bits[4] = { 0x01u, 0x02u, 0x04u, 0x08u };
    if (!mbcinfo) {
        return -1;
    }
    int32_t cp = rome2_vfs_crt_get_system_cp(codepage, out_f_system_set, oem_cp, acp_cp, thread_lc_cp);
    if (cp == 0) {
        rome2_vfs_crt_set_sbcs(mbcinfo, initial_mbcinfo);
        return 0;
    }

    if (rgctype_table) {
        for (size_t idx = 0u; idx < rgctype_count; ++idx) {
            if (rgctype_table[idx].codepage_00 == (uint32_t)cp) {
                memset(mbcinfo->mbctype_18, 0, sizeof(mbcinfo->mbctype_18));
                memset(mbcinfo->mbcasemap_119, 0, sizeof(mbcinfo->mbcasemap_119));
                for (size_t r = 0u; r < 4u; ++r) {
                    const uint8_t *pairs = rgctype_table[idx].rgrange_10[r];
                    for (size_t p = 0u; p + 1u < 8u && pairs[p] != 0u; p += 2u) {
                        uint8_t hi = pairs[p + 1u];
                        if (hi == 0u) {
                            break;
                        }
                        for (uint32_t b = pairs[p]; b <= hi && b < 256u; ++b) {
                            mbcinfo->mbctype_18[1u + b] |= k_mbctype_bits[r];
                        }
                    }
                }
                mbcinfo->mbcodepage_04 = (uint32_t)cp;
                mbcinfo->ismbcodepage_08 = 1;
                mbcinfo->mblocalename_ptr_21c = rome2_vfs_crt_cp_to_locale_name_guest(cp, locale_ptr_table);
                memcpy(mbcinfo->mbulinfo_0c, rgctype_table[idx].mbulinfo_04, sizeof(mbcinfo->mbulinfo_0c));
                rome2_vfs_crt_set_sb_up_low(
                    mbcinfo, get_cpinfo_fn, get_str_type_a_fn, mb2wc_fn, lcmap_ex_fn, wc2mb_fn, ctx);
                return 0;
            }
        }
    }

    if ((uint32_t)cp == ROME2_VFS_L56_CP_UTF7 || !is_valid_cp_fn || is_valid_cp_fn((uint32_t)cp, ctx) == 0u) {
        return -1;
    }

    if ((uint32_t)cp == ROME2_VFS_L56_CP_UTF8) {
        mbcinfo->mbcodepage_04 = ROME2_VFS_L56_CP_UTF8;
        mbcinfo->mblocalename_ptr_21c = 0u;
        memset(mbcinfo->mbctype_18, 0, sizeof(mbcinfo->mbctype_18));
        memset(mbcinfo->mbcasemap_119, 0, sizeof(mbcinfo->mbcasemap_119));
        mbcinfo->ismbcodepage_08 = 0;
        rome2_vfs_crt_set_sb_up_low(
            mbcinfo, get_cpinfo_fn, get_str_type_a_fn, mb2wc_fn, lcmap_ex_fn, wc2mb_fn, ctx);
        return 0;
    }

    rome2_vfs_crt_cpinfo20_32 cpinfo;
    memset(&cpinfo, 0, sizeof(cpinfo));
    if (!get_cpinfo_fn || get_cpinfo_fn((uint32_t)cp, &cpinfo, ctx) == 0u) {
        if (out_f_system_set && *out_f_system_set != 0) {
            rome2_vfs_crt_set_sbcs(mbcinfo, initial_mbcinfo);
            return 0;
        }
        return -1;
    }
    memset(mbcinfo->mbctype_18, 0, sizeof(mbcinfo->mbctype_18));
    memset(mbcinfo->mbcasemap_119, 0, sizeof(mbcinfo->mbcasemap_119));
    mbcinfo->mbcodepage_04 = (uint32_t)cp;
    mbcinfo->mblocalename_ptr_21c = 0u;
    if (cpinfo.max_char_size_00 > 1u) {
        for (size_t p = 0u; p + 1u < sizeof(cpinfo.lead_byte_06) && cpinfo.lead_byte_06[p] != 0u; p += 2u) {
            uint8_t hi = cpinfo.lead_byte_06[p + 1u];
            if (hi == 0u) {
                break;
            }
            for (uint32_t b = cpinfo.lead_byte_06[p]; b <= hi && b < 256u; ++b) {
                mbcinfo->mbctype_18[1u + b] |= 0x04u;
            }
        }
        for (uint32_t b = 1u; b < 255u; ++b) {
            mbcinfo->mbctype_18[1u + b] |= 0x08u;
        }
        mbcinfo->mblocalename_ptr_21c = rome2_vfs_crt_cp_to_locale_name_guest(cp, locale_ptr_table);
        mbcinfo->ismbcodepage_08 = 1;
    } else {
        mbcinfo->ismbcodepage_08 = 0;
    }
    rome2_vfs_crt_set_sb_up_low(
        mbcinfo, get_cpinfo_fn, get_str_type_a_fn, mb2wc_fn, lcmap_ex_fn, wc2mb_fn, ctx);
    return 0;
}

/* `0x116b4a37` */
int32_t rome2_vfs_crt_setmbcp_internal(
    int32_t codepage,
    uint8_t is_for_init,
    rome2_vfs_crt_multibyte_data544_32 **thread_mbcinfo_slot,
    rome2_vfs_crt_multibyte_data544_32 **global_mbcinfo,
    const rome2_vfs_crt_multibyte_data544_32 *initial_mbcinfo,
    const rome2_vfs_crt_codepage_info48_32 *rgctype_table,
    size_t rgctype_count,
    const rome2_vfs_crt_mbcs_locale_ptrs16_32 *locale_ptr_table,
    uint8_t *out_mbctype257,
    uint8_t *out_mbcasemap256,
    int32_t *out_f_system_set,
    int32_t oem_cp,
    int32_t acp_cp,
    int32_t thread_lc_cp,
    uint8_t (*is_valid_cp_fn)(uint32_t cp, void *ctx),
    rome2_vfs_crt_get_cpinfo_fn get_cpinfo_fn,
    rome2_vfs_crt_get_string_type_a_fn get_str_type_a_fn,
    rome2_vfs_crt_mb2wc_fn mb2wc_fn,
    rome2_vfs_crt_lcmap_ex_fn lcmap_ex_fn,
    rome2_vfs_crt_wc2mb_fn wc2mb_fn,
    rome2_vfs_crt_lock_op_fn lock_fn,
    rome2_vfs_crt_lock_op_fn unlock_fn,
    rome2_vfs_crt_ptd_alloc_fn alloc_fn,
    rome2_vfs_crt_mb_free_fn free_mb_fn,
    int32_t *out_errno,
    void *ctx) {
    if (!thread_mbcinfo_slot || !global_mbcinfo || !alloc_fn) {
        return -1;
    }
    int32_t cp = rome2_vfs_crt_get_system_cp(codepage, out_f_system_set, oem_cp, acp_cp, thread_lc_cp);
    rome2_vfs_crt_multibyte_data544_32 *cur_thread = *thread_mbcinfo_slot;
    if (cur_thread && (uint32_t)cp == cur_thread->mbcodepage_04) {
        return 0;
    }
    rome2_vfs_crt_multibyte_data544_32 *new_mb =
        (rome2_vfs_crt_multibyte_data544_32 *)alloc_fn(1u, sizeof(*new_mb), ctx);
    if (!new_mb) {
        r2_l56_set_err(out_errno, ROME2_VFS_L56_ENOMEM);
        return -1;
    }
    if (cur_thread) {
        memcpy(new_mb, cur_thread, sizeof(*new_mb));
    } else if (initial_mbcinfo) {
        memcpy(new_mb, initial_mbcinfo, sizeof(*new_mb));
    } else {
        memset(new_mb, 0, sizeof(*new_mb));
    }
    new_mb->refcount_00 = 0;

    int32_t status = rome2_vfs_crt_setmbcp_nolock(
        cp, new_mb, initial_mbcinfo, rgctype_table, rgctype_count, locale_ptr_table,
        out_f_system_set, oem_cp, acp_cp, thread_lc_cp,
        is_valid_cp_fn, get_cpinfo_fn, get_str_type_a_fn, mb2wc_fn, lcmap_ex_fn, wc2mb_fn, ctx);
    if (status != 0) {
        if (free_mb_fn) {
            free_mb_fn(new_mb, ctx);
        }
        r2_l56_set_err(out_errno, ROME2_VFS_L56_EINVAL);
        return -1;
    }

    if (cur_thread) {
        cur_thread->refcount_00 -= 1;
        if (cur_thread->refcount_00 == 0 && (!initial_mbcinfo || cur_thread != initial_mbcinfo) && free_mb_fn) {
            free_mb_fn(cur_thread, ctx);
        }
    }
    *thread_mbcinfo_slot = new_mb;
    new_mb->refcount_00 += 1;
    if (is_for_init != 0u) {
        rome2_vfs_crt_seh_guarded_update_mb(
            2u, lock_fn, unlock_fn, new_mb, initial_mbcinfo, global_mbcinfo,
            out_mbctype257, out_mbcasemap256, free_mb_fn, ctx);
    }
    return 0;
}

/* `0x116af5f5` */
uint8_t rome2_vfs_crt_set_var_in_system_env(
    const char *name,
    const char *value,
    uint32_t codepage,
    rome2_vfs_crt_widen_env_fn widen_fn,
    rome2_vfs_crt_set_os_env_w_fn set_os_env_w_fn,
    rome2_vfs_crt_ptd_free_fn free_fn,
    void *ctx) {
    if (!widen_fn || !set_os_env_w_fn) {
        return 0u;
    }
    uint16_t *wname = NULL;
    uint16_t *wval = NULL;
    uint8_t ok = 0u;
    if (widen_fn(&wname, name, codepage, ctx) != 0u) {
        if (widen_fn(&wval, value, codepage, ctx) != 0u) {
            ok = set_os_env_w_fn(wname, wval, ctx);
        }
    }
    if (free_fn) {
        if (wval) {
            free_fn(wval, ctx);
        }
        if (wname) {
            free_fn(wname, ctx);
        }
    }
    return ok;
}

/* `0x116b5462` */
char **rome2_vfs_crt_copy_environment_narrow(
    const char *const *env_array,
    rome2_vfs_crt_ptd_alloc_fn calloc_fn,
    rome2_vfs_crt_abort_fn abort_fn,
    void *ctx) {
    if (!env_array) {
        return NULL;
    }
    if (!calloc_fn) {
        if (abort_fn) {
            abort_fn(ctx);
        }
        return NULL;
    }
    size_t count = 0u;
    while (env_array[count] != NULL) {
        ++count;
    }
    char **copy_arr = (char **)calloc_fn(count + 1u, sizeof(char *), ctx);
    if (!copy_arr) {
        if (abort_fn) {
            abort_fn(ctx);
        }
        return NULL;
    }
    for (size_t i = 0u; i < count; ++i) {
        size_t len = strlen(env_array[i]) + 1u;
        char *str = (char *)calloc_fn(len, 1u, ctx);
        copy_arr[i] = str;
        if (!str) {
            if (abort_fn) {
                abort_fn(ctx);
            }
            return NULL;
        }
        memcpy(str, env_array[i], len);
    }
    copy_arr[count] = NULL;
    return copy_arr;
}

/* `0x116b55d0` */
void rome2_vfs_crt_ensure_narrow_env_copied(
    char ***inout_environ,
    char *const *initial_environ,
    rome2_vfs_crt_ptd_alloc_fn calloc_fn,
    rome2_vfs_crt_abort_fn abort_fn,
    void *ctx) {
    if (inout_environ && *inout_environ == initial_environ) {
        *inout_environ = rome2_vfs_crt_copy_environment_narrow(
            (const char *const *)*inout_environ, calloc_fn, abort_fn, ctx);
    }
}

/* `0x116b5604` */
int32_t rome2_vfs_crt_find_in_env_array_narrow(
    const char *const *env_array,
    const char *option,
    size_t name_len,
    rome2_vfs_crt_env_cmp_fn strnicoll_fn,
    void *ctx) {
    if (!env_array || !option || !strnicoll_fn) {
        return 0;
    }
    int32_t idx = 0;
    while (env_array[idx] != NULL) {
        if (strnicoll_fn(option, env_array[idx], name_len, ctx) == 0) {
            char term = env_array[idx][name_len];
            if (term == '=' || term == '\0') {
                return idx;
            }
        }
        ++idx;
    }
    return -idx;
}

/* `0x116b56b1` (`0x116b4fd1..0x116b520d` + `0x116b56b1..0x116b56bb`) */
int32_t rome2_vfs_crt_common_set_env_var_nolock_narrow(
    const char *option,
    int32_t is_primary,
    char ***inout_environ,
    char *const *initial_environ,
    uint8_t has_wenviron,
    uint32_t codepage,
    rome2_vfs_crt_ptd_alloc_fn calloc_fn,
    void *(*recalloc_fn)(void *ptr, size_t count, size_t elem_size, void *ctx),
    rome2_vfs_crt_ptd_free_fn free_fn,
    rome2_vfs_crt_env_cmp_fn strnicoll_fn,
    rome2_vfs_crt_widen_env_fn widen_fn,
    rome2_vfs_crt_set_os_env_w_fn set_os_env_w_fn,
    rome2_vfs_crt_abort_fn abort_fn,
    int32_t *out_errno,
    void *ctx) {
    if (!option || !inout_environ || !calloc_fn || !recalloc_fn || !free_fn) {
        r2_l56_set_err(out_errno, ROME2_VFS_L56_EINVAL);
        return -1;
    }
    const char *eq = rome2_vfs_crt_strchr(option, '=');
    if (!eq || eq == option) {
        r2_l56_set_err(out_errno, ROME2_VFS_L56_EINVAL);
        return -1;
    }
    size_t name_len = (size_t)(eq - option);
    uint8_t has_value = (eq[1] != '\0') ? 1u : 0u;
    size_t opt_len = strlen(option) + 1u;

    char *dup = NULL;
    if (has_value != 0u) {
        dup = (char *)calloc_fn(opt_len, 1u, ctx);
        if (!dup) {
            return -1;
        }
        memcpy(dup, option, opt_len);
    }

    rome2_vfs_crt_ensure_narrow_env_copied(inout_environ, initial_environ, calloc_fn, abort_fn, ctx);
    if (*inout_environ == NULL) {
        if (has_wenviron == 0u || *inout_environ == NULL) {
            r2_l56_set_err(out_errno, ROME2_VFS_L56_EINVAL);
            free_fn(dup, ctx);
            return -1;
        }
    }

    int32_t rc = 0;
    int32_t pos = rome2_vfs_crt_find_in_env_array_narrow(
        (const char *const *)*inout_environ, option, name_len, strnicoll_fn, ctx);
    char **envp = *inout_environ;
    if (pos >= 0 && envp[0] != NULL) {
        free_fn(envp[pos], ctx);
        if (has_value == 0u) {
            size_t j = (size_t)pos;
            while (envp[j] != NULL) {
                envp[j] = envp[j + 1u];
                ++j;
            }
            char **shrunk = (char **)recalloc_fn(envp, j, sizeof(char *), ctx);
            if (shrunk) {
                *inout_environ = shrunk;
            }
        } else {
            envp[pos] = dup;
            dup = NULL;
        }
    } else if (has_value != 0u) {
        size_t count = (size_t)(-pos);
        if (count + 2u >= 0x3fffffffu) {
            free_fn(dup, ctx);
            r2_l56_set_err(out_errno, ROME2_VFS_L56_EINVAL);
            return -1;
        }
        char **grown = (char **)recalloc_fn(envp, count + 2u, sizeof(char *), ctx);
        if (!grown) {
            free_fn(dup, ctx);
            r2_l56_set_err(out_errno, ROME2_VFS_L56_EINVAL);
            return -1;
        }
        grown[count] = dup;
        grown[count + 1u] = NULL;
        dup = NULL;
        *inout_environ = grown;
    }

    if (is_primary != 0) {
        char *name_copy = (char *)calloc_fn(name_len + 2u, 1u, ctx);
        if (name_copy) {
            memcpy(name_copy, option, name_len);
            name_copy[name_len] = '\0';
            const char *val_arg = (has_value != 0u) ? (eq + 1) : NULL;
            if (rome2_vfs_crt_set_var_in_system_env(
                    name_copy, val_arg, codepage, widen_fn, set_os_env_w_fn, free_fn, ctx) == 0u) {
                r2_l56_set_err(out_errno, ROME2_VFS_L56_EILSEQ);
                rc = -1;
            }
            free_fn(name_copy, ctx);
        }
    }
    free_fn(dup, ctx);
    return rc;
}
