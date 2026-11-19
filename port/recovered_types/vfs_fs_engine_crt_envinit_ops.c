#include "vfs_fs_engine_crt_envinit_ops.h"

#include <string.h>

enum {
    ROME2_VFS_L55_EBADF = 9,
    ROME2_VFS_L55_EINVAL = 22,
    ROME2_VFS_L55_NLSCMPERROR = 0x7fffffff,
    ROME2_VFS_L55_CMP_FLAGS = 0x1001u /* NORM_IGNORECASE | SORT_STRINGSORT */
};

static void r2_l55_set_err(int32_t *out_errno, int32_t code) {
    if (out_errno) {
        *out_errno = code;
    }
}

static void r2_l55_set_u32(uint32_t *out_val, uint32_t value) {
    if (out_val) {
        *out_val = value;
    }
}

static uint64_t r2_l55_u64(uint32_t lo, uint32_t hi) {
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

static void r2_l55_store_count(rome2_vfs_crt_input_char_source32_32 *src, uint64_t val) {
    src->read_count_lo_10 = (uint32_t)(val & 0xffffffffULL);
    src->read_count_hi_14 = (uint32_t)(val >> 32);
}

static uint16_t r2_l55_ascii_tolower_u16(uint16_t ch) {
    if (ch >= (uint16_t)'A' && ch <= (uint16_t)'Z') {
        return (uint16_t)(ch + 0x20u);
    }
    return ch;
}

/* `0x11692d4c` */
rome2_vfs_crt_input_char_source32_32 *rome2_vfs_crt_input_char_source_ctor(
    rome2_vfs_crt_input_char_source32_32 *out_src,
    uint32_t adapter_ptr,
    uint64_t width_limit,
    uint32_t ok_flag_slot,
    uint8_t *out_succeeded) {
    if (!out_src) {
        return NULL;
    }
    out_src->adapter_ptr_00 = adapter_ptr;
    out_src->pad_04 = 0u;
    out_src->width_lo_08 = (uint32_t)(width_limit & 0xffffffffULL);
    out_src->width_hi_0c = (uint32_t)(width_limit >> 32);
    out_src->read_count_lo_10 = 0u;
    out_src->read_count_hi_14 = 0u;
    out_src->succeeded_ptr_18 = ok_flag_slot;
    out_src->pad_1c = 0u;
    if (out_succeeded) {
        *out_succeeded = 1u;
    }
    return out_src;
}

/* `0x11695a17` */
uint8_t rome2_vfs_crt_input_char_source_get(
    rome2_vfs_crt_input_char_source32_32 *src,
    rome2_vfs_crt_char_get_fn get_fn,
    void *ctx) {
    if (!src || !get_fn) {
        return 0u;
    }
    uint64_t next_count = r2_l55_u64(src->read_count_lo_10, src->read_count_hi_14) + 1ULL;
    r2_l55_store_count(src, next_count);
    uint64_t width = r2_l55_u64(src->width_lo_08, src->width_hi_0c);
    if (width != 0ULL && next_count > width) {
        return 0u;
    }
    int32_t ch = get_fn(ctx);
    return (ch == -1) ? 0u : (uint8_t)ch;
}

/* `0x116971c4` */
void rome2_vfs_crt_input_char_source_unget(
    rome2_vfs_crt_input_char_source32_32 *src,
    int8_t ch,
    rome2_vfs_crt_char_unget_fn unget_fn,
    void *ctx) {
    if (!src) {
        return;
    }
    uint64_t new_count = r2_l55_u64(src->read_count_lo_10, src->read_count_hi_14) - 1ULL;
    r2_l55_store_count(src, new_count);
    uint64_t width = r2_l55_u64(src->width_lo_08, src->width_hi_0c);
    if (width != 0ULL && new_count > width) {
        return;
    }
    if (ch == 0 || ch == -1 || !unget_fn) {
        return;
    }
    unget_fn((int32_t)ch, ctx);
}

/* `0x11696503` */
uint8_t rome2_vfs_crt_input_char_source_restore_state(
    const rome2_vfs_crt_input_char_source32_32 *src,
    uint64_t saved_count,
    uint8_t *out_succeeded) {
    if (src && saved_count == r2_l55_u64(src->read_count_lo_10, src->read_count_hi_14)) {
        return 1u;
    }
    if (out_succeeded) {
        *out_succeeded = 0u;
    }
    return 0u;
}

/* `0x116972d5` */
uint8_t rome2_vfs_crt_input_char_source_validate(
    const rome2_vfs_crt_input_char_source32_32 *src,
    int32_t *out_errno,
    rome2_vfs_crt_invalid_param_fn invalid_param_cb,
    void *ctx) {
    if (!src || src->adapter_ptr_00 == 0u || src->succeeded_ptr_18 == 0u) {
        r2_l55_set_err(out_errno, ROME2_VFS_L55_EINVAL);
        if (invalid_param_cb) {
            invalid_param_cb(ctx);
        }
        return 0u;
    }
    return 1u;
}

/* `0x11697107` */
uint32_t rome2_vfs_crt_scanf_to_fp_length(uint32_t length_modifier) {
    if (length_modifier == 0u) {
        return 4u;
    }
    if (length_modifier == 3u || length_modifier == 8u) {
        return 8u;
    }
    return 0u;
}

/* `0x1169712a` */
uint32_t rome2_vfs_crt_scanf_to_int_length(uint32_t length_modifier) {
    static const uint32_t k_int_lengths[11] = {
        4u, 1u, 2u, 4u, 8u, 8u, 4u, 4u, 0u, 4u, 8u
    };
    return (length_modifier <= 10u) ? k_int_lengths[length_modifier] : 0u;
}

/* `0x11695b59` */
uint8_t rome2_vfs_crt_scanf_is_char_allowed(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    uint32_t mode,
    int32_t ch) {
    if (ch == -1) {
        return 0u;
    }
    if (mode == 0u) {
        return 1u;
    }
    if (mode == 1u) {
        if ((ch >= 9 && ch <= 13) || ch == 0x20) {
            return 0u;
        }
        return 1u;
    }
    if (mode == 8u) {
        if (!input_state) {
            return 0u;
        }
        uint32_t idx = (uint32_t)(uint8_t)(ch & 0xff);
        return ((input_state->fmt_18.scanset_words_2c[idx >> 5] >> (idx & 31u)) & 1u) ? 1u : 0u;
    }
    return 0u;
}

/* `0x1169738e` */
uint8_t rome2_vfs_crt_scanf_write_stored_string_wide(
    uint16_t **inout_write_it,
    int32_t *inout_remaining,
    int8_t ch,
    rome2_vfs_crt_is_leadbyte_fn is_leadbyte_fn,
    rome2_vfs_crt_char_get_fn get_fn,
    rome2_vfs_crt_mbtowc_fn mbtowc_fn,
    void *ctx) {
    if (!inout_write_it || !*inout_write_it || !inout_remaining || *inout_remaining <= 0) {
        return 0u;
    }
    char mb_buf[2] = { (char)ch, '\0' };
    if (is_leadbyte_fn && is_leadbyte_fn((uint8_t)ch, ctx) != 0u && get_fn) {
        mb_buf[1] = (char)(uint8_t)get_fn(ctx);
    }
    uint16_t wide_tmp = 0x003fu;
    if (mbtowc_fn) {
        (void)mbtowc_fn(&wide_tmp, mb_buf, sizeof(mb_buf), ctx);
    }
    /* Preserve literal `movsx cx, bl` instruction at 0x116973e2..0x116973ea in empire.retail.dll. */
    uint16_t written = (uint16_t)(int16_t)ch;
    **inout_write_it = written;
    *inout_write_it += 1;
    *inout_remaining -= 1;
    return 1u;
}

/* `0x1169e728` */
void rome2_vfs_crt_lseek64_finally_unlock(
    int32_t fh,
    rome2_vfs_crt_fh_lock_fn unlock_fn,
    void *ctx) {
    if (unlock_fn) {
        unlock_fn(fh, ctx);
    }
}

/* `0x1169e653` */
int64_t rome2_vfs_crt_common_lseek64(
    int32_t fh,
    int64_t offset,
    int32_t origin,
    uint32_t max_fd_count,
    rome2_vfs_crt_fh_predicate_fn is_open_fn,
    rome2_vfs_crt_fh_lock_fn lock_fn,
    rome2_vfs_crt_fh_lock_fn unlock_fn,
    rome2_vfs_crt_fh_seek64_nolock_fn seek_nolock_fn,
    rome2_vfs_crt_invalid_param_fn invalid_param_cb,
    int32_t *out_errno,
    uint32_t *out_doserrno,
    void *ctx) {
    if (fh == -2) {
        r2_l55_set_u32(out_doserrno, 0u);
        r2_l55_set_err(out_errno, ROME2_VFS_L55_EBADF);
        return -1LL;
    }
    if (fh < 0 || (uint32_t)fh >= max_fd_count || !is_open_fn || is_open_fn(fh, ctx) == 0u) {
        r2_l55_set_u32(out_doserrno, 0u);
        r2_l55_set_err(out_errno, ROME2_VFS_L55_EBADF);
        if (invalid_param_cb) {
            invalid_param_cb(ctx);
        }
        return -1LL;
    }

    if (lock_fn) {
        lock_fn(fh, ctx);
    }
    int64_t result = -1LL;
    if (is_open_fn(fh, ctx) == 0u) {
        r2_l55_set_err(out_errno, ROME2_VFS_L55_EBADF);
        r2_l55_set_u32(out_doserrno, 0u);
    } else if (seek_nolock_fn) {
        result = seek_nolock_fn(fh, offset, origin, ctx);
    }
    rome2_vfs_crt_lseek64_finally_unlock(fh, unlock_fn, ctx);
    return result;
}

/* `0x116a159b` */
void rome2_vfs_crt_free_environment_narrow(
    char **env_array,
    rome2_vfs_crt_free_fn free_fn,
    void *ctx) {
    if (!env_array || !free_fn) {
        return;
    }
    for (size_t i = 0u; env_array[i] != NULL; ++i) {
        free_fn(env_array[i], ctx);
    }
    free_fn(env_array, ctx);
}

/* `0x116a13be` */
char **rome2_vfs_crt_create_environment_narrow(
    const char *env_block,
    rome2_vfs_crt_calloc_fn calloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    void *ctx) {
    if (!env_block || !calloc_fn || !free_fn) {
        return NULL;
    }
    size_t count = 0u;
    for (const char *p = env_block; *p != '\0'; p += strlen(p) + 1u) {
        if (*p != '=') {
            ++count;
        }
    }
    char **table = (char **)calloc_fn(count + 1u, sizeof(char *), ctx);
    if (!table) {
        return NULL;
    }
    size_t out_idx = 0u;
    for (const char *p = env_block; *p != '\0'; ) {
        size_t len_with_nul = strlen(p) + 1u;
        if (*p != '=') {
            char *copy = (char *)calloc_fn(len_with_nul, 1u, ctx);
            if (!copy) {
                rome2_vfs_crt_free_environment_narrow(table, free_fn, ctx);
                return NULL;
            }
            memcpy(copy, p, len_with_nul);
            table[out_idx++] = copy;
        }
        p += len_with_nul;
    }
    table[out_idx] = NULL;
    return table;
}

/* `0x116b4ec6` */
const uint16_t *rome2_vfs_crt_find_end_of_double_null_u16(const uint16_t *block) {
    if (!block) {
        return NULL;
    }
    const uint16_t *p = block;
    while (*p != 0u) {
        while (*p != 0u) {
            ++p;
        }
        ++p;
    }
    return p + 1;
}

/* `0x116b4efd` */
char *rome2_vfs_crt_get_narrow_environment_from_os(
    rome2_vfs_crt_get_env_strings_w_fn get_env_w_fn,
    rome2_vfs_crt_free_env_strings_w_fn free_env_w_fn,
    rome2_vfs_crt_wcstombs_fn wctomb_fn,
    rome2_vfs_crt_calloc_fn alloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    void *ctx) {
    if (!get_env_w_fn || !wctomb_fn || !alloc_fn) {
        return NULL;
    }
    const uint16_t *wide_block = get_env_w_fn(ctx);
    if (!wide_block) {
        return NULL;
    }
    char *result = NULL;
    const uint16_t *wide_end = rome2_vfs_crt_find_end_of_double_null_u16(wide_block);
    size_t wide_units = (size_t)(wide_end - wide_block);
    if (wide_units <= (size_t)INT32_MAX) {
        size_t needed = wctomb_fn(wide_block, (int32_t)wide_units, NULL, 0u, ctx);
        if (needed != 0u) {
            char *buf = (char *)alloc_fn(needed, 1u, ctx);
            if (buf) {
                if (wctomb_fn(wide_block, (int32_t)wide_units, buf, needed, ctx) != 0u) {
                    result = buf;
                } else if (free_fn) {
                    free_fn(buf, ctx);
                }
            }
        }
    }
    if (free_env_w_fn) {
        free_env_w_fn(wide_block, ctx);
    }
    return result;
}

/* `0x116b4bf0` */
uint8_t rome2_vfs_crt_initialize_multibyte(
    uint8_t *inout_initialized,
    uint32_t *out_mbcinfo_ptr,
    uint32_t *out_mbctype_ptr,
    uint32_t *out_mbcasemap_ptr,
    uint32_t initial_mbcinfo_guest,
    uint32_t initial_mbctype_guest,
    uint32_t initial_mbcasemap_guest,
    rome2_vfs_crt_multibyte_init_hook_fn init_hook,
    void *ctx) {
    if (inout_initialized && *inout_initialized == 0u) {
        r2_l55_set_u32(out_mbcinfo_ptr, initial_mbcinfo_guest);
        r2_l55_set_u32(out_mbcasemap_ptr, initial_mbcasemap_guest);
        r2_l55_set_u32(out_mbctype_ptr, initial_mbctype_guest);
        if (init_hook) {
            init_hook(-3, 1u, initial_mbcinfo_guest, ctx);
        }
        *inout_initialized = 1u;
    }
    return 1u;
}

/* `0x116a131d` */
int32_t rome2_vfs_crt_initialize_environment_narrow(
    char ***inout_environ,
    char ***out_initial_environ,
    uint8_t *inout_mb_init_flag,
    rome2_vfs_crt_get_env_strings_w_fn get_env_w_fn,
    rome2_vfs_crt_free_env_strings_w_fn free_env_w_fn,
    rome2_vfs_crt_wcstombs_fn wctomb_fn,
    rome2_vfs_crt_calloc_fn calloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    void *ctx) {
    if (!inout_environ || !free_fn) {
        return -1;
    }
    if (*inout_environ != NULL) {
        return 0;
    }
    (void)rome2_vfs_crt_initialize_multibyte(
        inout_mb_init_flag, NULL, NULL, NULL, 0x119ec210u, 0x119ec430u, 0x119ec538u, NULL, ctx);
    char *os_block = rome2_vfs_crt_get_narrow_environment_from_os(
        get_env_w_fn, free_env_w_fn, wctomb_fn, calloc_fn, free_fn, ctx);
    if (!os_block) {
        return -1;
    }
    char **envp = rome2_vfs_crt_create_environment_narrow(os_block, calloc_fn, free_fn, ctx);
    free_fn(os_block, ctx);
    if (!envp) {
        return -1;
    }
    if (out_initial_environ) {
        *out_initial_environ = envp;
    }
    *inout_environ = envp;
    return 0;
}

/* `0x116a15ca` */
int32_t rome2_vfs_crt_initialize_narrow_env_from_wide(
    const uint16_t *const *wenviron,
    rome2_vfs_crt_wcstombs_fn wctomb_fn,
    rome2_vfs_crt_calloc_fn calloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    rome2_vfs_crt_setenv_narrow_fn setenv_fn,
    void *ctx) {
    if (!wenviron || !wctomb_fn || !calloc_fn || !free_fn || !setenv_fn) {
        return -1;
    }
    for (size_t i = 0u; wenviron[i] != NULL; ++i) {
        size_t needed = wctomb_fn(wenviron[i], -1, NULL, 0u, ctx);
        if (needed == 0u) {
            return -1;
        }
        char *narrow = (char *)calloc_fn(needed, 1u, ctx);
        if (!narrow) {
            return -1;
        }
        if (wctomb_fn(wenviron[i], -1, narrow, needed, ctx) == 0u) {
            free_fn(narrow, ctx);
            return -1;
        }
        if (setenv_fn(narrow, ctx) != 0) {
            free_fn(narrow, ctx);
            return -1;
        }
    }
    return 0;
}

/* `0x116a1729` */
char **rome2_vfs_crt_get_or_create_narrow_env_nolock(
    char ***inout_environ,
    char ***out_initial_environ,
    const uint16_t *const *wenviron,
    uint8_t *inout_mb_init_flag,
    rome2_vfs_crt_get_env_strings_w_fn get_env_w_fn,
    rome2_vfs_crt_free_env_strings_w_fn free_env_w_fn,
    rome2_vfs_crt_wcstombs_fn wctomb_fn,
    rome2_vfs_crt_calloc_fn calloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    rome2_vfs_crt_setenv_narrow_fn setenv_fn,
    void *ctx) {
    if (!inout_environ) {
        return NULL;
    }
    if (*inout_environ != NULL) {
        return *inout_environ;
    }
    if (!wenviron) {
        return NULL;
    }
    int32_t rc = rome2_vfs_crt_initialize_environment_narrow(
        inout_environ,
        out_initial_environ,
        inout_mb_init_flag,
        get_env_w_fn,
        free_env_w_fn,
        wctomb_fn,
        calloc_fn,
        free_fn,
        ctx);
    if (rc != 0) {
        rc = rome2_vfs_crt_initialize_narrow_env_from_wide(
            wenviron, wctomb_fn, calloc_fn, free_fn, setenv_fn, ctx);
        if (rc != 0) {
            return NULL;
        }
    }
    return *inout_environ;
}

/* `0x116b1ef1` */
int32_t rome2_vfs_crt_compare_string_a(
    uint32_t locale_name_guest,
    uint32_t cmp_flags,
    const char *s1,
    int32_t n1,
    const char *s2,
    int32_t n2,
    uint32_t codepage,
    rome2_vfs_crt_compare_string_a_stat_fn stat_fn,
    void *ctx) {
    if (!stat_fn) {
        return 0;
    }
    return stat_fn(locale_name_guest, cmp_flags, s1, n1, s2, n2, codepage, ctx);
}

/* `0x116b1b45` */
int32_t rome2_vfs_crt_strnicoll_l(
    const char *s1,
    const char *s2,
    size_t max_count,
    uint8_t is_c_locale,
    uint32_t collate_locale_name_guest,
    uint32_t collate_codepage,
    rome2_vfs_crt_ascii_strnicmp_fn c_strnicmp_fn,
    rome2_vfs_crt_compare_string_a_stat_fn compare_stat_fn,
    rome2_vfs_crt_invalid_param_fn invalid_param_cb,
    int32_t *out_errno,
    void *ctx) {
    if (max_count == 0u) {
        return 0;
    }
    if (!s1 || !s2 || max_count > (size_t)ROME2_VFS_L55_NLSCMPERROR) {
        r2_l55_set_err(out_errno, ROME2_VFS_L55_EINVAL);
        if (invalid_param_cb) {
            invalid_param_cb(ctx);
        }
        return ROME2_VFS_L55_NLSCMPERROR;
    }
    if (is_c_locale != 0u) {
        return c_strnicmp_fn ? c_strnicmp_fn(s1, s2, max_count, ctx) : ROME2_VFS_L55_NLSCMPERROR;
    }
    int32_t res = rome2_vfs_crt_compare_string_a(
        collate_locale_name_guest,
        ROME2_VFS_L55_CMP_FLAGS,
        s1,
        (int32_t)max_count,
        s2,
        (int32_t)max_count,
        collate_codepage,
        compare_stat_fn,
        ctx);
    if (res == 0) {
        r2_l55_set_err(out_errno, ROME2_VFS_L55_EINVAL);
        return ROME2_VFS_L55_NLSCMPERROR;
    }
    return res - 2;
}

/* `0x116b1b1c` */
int32_t rome2_vfs_crt_strnicoll(
    const char *s1,
    const char *s2,
    size_t max_count,
    uint8_t locale_changed,
    uint8_t is_c_locale,
    uint32_t collate_locale_name_guest,
    uint32_t collate_codepage,
    rome2_vfs_crt_ascii_strnicmp_fn strnicmp_fn,
    rome2_vfs_crt_compare_string_a_stat_fn compare_stat_fn,
    rome2_vfs_crt_invalid_param_fn invalid_param_cb,
    int32_t *out_errno,
    void *ctx) {
    if (locale_changed == 0u) {
        return strnicmp_fn ? strnicmp_fn(s1, s2, max_count, ctx) : ROME2_VFS_L55_NLSCMPERROR;
    }
    return rome2_vfs_crt_strnicoll_l(
        s1,
        s2,
        max_count,
        is_c_locale,
        collate_locale_name_guest,
        collate_codepage,
        strnicmp_fn,
        compare_stat_fn,
        invalid_param_cb,
        out_errno,
        ctx);
}

/* `0x116b8400` */
int32_t rome2_vfs_crt_ascii_wcsnicmp(
    const uint16_t *s1,
    const uint16_t *s2,
    size_t count) {
    if (count == 0u || !s1 || !s2) {
        return 0;
    }
    for (size_t i = 0u; i < count; ++i) {
        uint16_t c1 = r2_l55_ascii_tolower_u16(s1[i]);
        uint16_t c2 = r2_l55_ascii_tolower_u16(s2[i]);
        int32_t diff = (int32_t)c1 - (int32_t)c2;
        if (diff != 0 || s1[i] == 0u) {
            return diff;
        }
    }
    return 0;
}
