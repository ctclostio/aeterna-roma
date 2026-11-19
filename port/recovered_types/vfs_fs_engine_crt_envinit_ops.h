#ifndef ROME2_VFS_FS_ENGINE_CRT_ENVINIT_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_ENVINIT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Adapter callbacks used by `0x11695a17`, `0x116971c4`, `0x116972d5`, and `0x1169738e`. */
typedef int32_t (*rome2_vfs_crt_char_get_fn)(void *ctx);
typedef void (*rome2_vfs_crt_char_unget_fn)(int32_t ch, void *ctx);
typedef uint8_t (*rome2_vfs_crt_is_leadbyte_fn)(uint8_t ch, void *ctx);
typedef int32_t (*rome2_vfs_crt_mbtowc_fn)(
    uint16_t *out_wc,
    const char *mb_bytes,
    size_t max_bytes,
    void *ctx);
typedef void (*rome2_vfs_crt_invalid_param_fn)(void *ctx);

/* `0x11692d4c`: __crt_strtox::input_adapter_character_source ctor (zeroes read_count, sets *out_ok = 1). */
rome2_vfs_crt_input_char_source32_32 *rome2_vfs_crt_input_char_source_ctor(
    rome2_vfs_crt_input_char_source32_32 *out_src,
    uint32_t adapter_ptr,
    uint64_t width_limit,
    uint32_t ok_flag_slot,
    uint8_t *out_succeeded);

/* `0x11695a17`: increments 64-bit read_count and returns next byte, or 0 past width limit / EOF. */
uint8_t rome2_vfs_crt_input_char_source_get(
    rome2_vfs_crt_input_char_source32_32 *src,
    rome2_vfs_crt_char_get_fn get_fn,
    void *ctx);

/* `0x116971c4`: decrements 64-bit read_count and pushes back non-0 / non-EOF byte to adapter. */
void rome2_vfs_crt_input_char_source_unget(
    rome2_vfs_crt_input_char_source32_32 *src,
    int8_t ch,
    rome2_vfs_crt_char_unget_fn unget_fn,
    void *ctx);

/* `0x11696503`: verifies saved 64-bit read_count matches current state, else clears *out_succeeded = 0. */
uint8_t rome2_vfs_crt_input_char_source_restore_state(
    const rome2_vfs_crt_input_char_source32_32 *src,
    uint64_t saved_count,
    uint8_t *out_succeeded);

/* `0x116972d5`: validates non-zero adapter & succeeded pointer, setting EINVAL (22) on failure. */
uint8_t rome2_vfs_crt_input_char_source_validate(
    const rome2_vfs_crt_input_char_source32_32 *src,
    int32_t *out_errno,
    rome2_vfs_crt_invalid_param_fn invalid_param_cb,
    void *ctx);

/* `0x11697107`: maps scanf floating-point length modifier (0 -> 4, 3/8 -> 8, else 0). */
uint32_t rome2_vfs_crt_scanf_to_fp_length(uint32_t length_modifier);

/* `0x1169712a`: maps scanf integer length modifier (0..10 switch table -> byte width). */
uint32_t rome2_vfs_crt_scanf_to_int_length(uint32_t length_modifier);

/* `0x11695b59`: checks scanf string/scanset character acceptance across modes 0, 1, 8. */
uint8_t rome2_vfs_crt_scanf_is_char_allowed(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    uint32_t mode,
    int32_t ch);

/*
 * `0x1169738e`: input_processor<char>::write_stored_string_tchar_wide.
 * Note: mirrors exact binary behavior observed at 0x116973a4..0x116973f5 — reads trail byte
 * for lead bytes, invokes mbtowc callback onto scratch local, and writes `(uint16_t)(int16_t)ch`
 * (`movsx cx, bl` at 0x116973e2) into `*(*inout_write_it)++`.
 */
uint8_t rome2_vfs_crt_scanf_write_stored_string_wide(
    uint16_t **inout_write_it,
    int32_t *inout_remaining,
    int8_t ch,
    rome2_vfs_crt_is_leadbyte_fn is_leadbyte_fn,
    rome2_vfs_crt_char_get_fn get_fn,
    rome2_vfs_crt_mbtowc_fn mbtowc_fn,
    void *ctx);

/* Callbacks for `0x1169e653` (common_lseek<int64>) and `0x1169e728` (SEH4 finally unlock). */
typedef uint8_t (*rome2_vfs_crt_fh_predicate_fn)(int32_t fh, void *ctx);
typedef void (*rome2_vfs_crt_fh_lock_fn)(int32_t fh, void *ctx);
typedef int64_t (*rome2_vfs_crt_fh_seek64_nolock_fn)(
    int32_t fh,
    int64_t offset,
    int32_t origin,
    void *ctx);

/* `0x1169e728`: SEH4 __finally helper forwarding file handle to lowio unlock. */
void rome2_vfs_crt_lseek64_finally_unlock(
    int32_t fh,
    rome2_vfs_crt_fh_lock_fn unlock_fn,
    void *ctx);

/* `0x1169e653`: SEH4-guarded 64-bit lowio seek returning position or -1 with EBADF (9). */
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
    void *ctx);

/* Heap allocator / environment callbacks for `0x116a131d..0x116b4efd`. */
typedef void *(*rome2_vfs_crt_calloc_fn)(size_t count, size_t elem_size, void *ctx);
typedef void (*rome2_vfs_crt_free_fn)(void *ptr, void *ctx);
typedef size_t (*rome2_vfs_crt_wcstombs_fn)(
    const uint16_t *wide_src,
    int32_t wide_len,
    char *mb_dst,
    size_t mb_cap,
    void *ctx);
typedef const uint16_t *(*rome2_vfs_crt_get_env_strings_w_fn)(void *ctx);
typedef void (*rome2_vfs_crt_free_env_strings_w_fn)(const uint16_t *block, void *ctx);
typedef int32_t (*rome2_vfs_crt_setenv_narrow_fn)(char *entry, void *ctx);
typedef void (*rome2_vfs_crt_multibyte_init_hook_fn)(
    int32_t mode,
    uint32_t flag,
    uint32_t mbcinfo_guest,
    void *ctx);

/* `0x116a159b`: free_environment<char> freeing each string and then the table pointer. */
void rome2_vfs_crt_free_environment_narrow(
    char **env_array,
    rome2_vfs_crt_free_fn free_fn,
    void *ctx);

/* `0x116a13be`: create_environment<char> parsing double-NUL block (skipping leading '=') with OOM cleanup. */
char **rome2_vfs_crt_create_environment_narrow(
    const char *env_block,
    rome2_vfs_crt_calloc_fn calloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    void *ctx);

/* `0x116b4ec6`: returns pointer one uint16_t past terminating double-NUL UTF-16LE sequence. */
const uint16_t *rome2_vfs_crt_find_end_of_double_null_u16(const uint16_t *block);

/* `0x116b4efd`: converts OS UTF-16LE environment block into a double-NUL narrow heap buffer. */
char *rome2_vfs_crt_get_narrow_environment_from_os(
    rome2_vfs_crt_get_env_strings_w_fn get_env_w_fn,
    rome2_vfs_crt_free_env_strings_w_fn free_env_w_fn,
    rome2_vfs_crt_wcstombs_fn wctomb_fn,
    rome2_vfs_crt_calloc_fn alloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    void *ctx);

/* `0x116b4bf0`: idempotently publishes initial mbcinfo/mbctype/mbcasemap guest pointers when flag==0. */
uint8_t rome2_vfs_crt_initialize_multibyte(
    uint8_t *inout_initialized,
    uint32_t *out_mbcinfo_ptr,
    uint32_t *out_mbctype_ptr,
    uint32_t *out_mbcasemap_ptr,
    uint32_t initial_mbcinfo_guest,
    uint32_t initial_mbctype_guest,
    uint32_t initial_mbcasemap_guest,
    rome2_vfs_crt_multibyte_init_hook_fn init_hook,
    void *ctx);

/* `0x116a131d`: initializes narrow environment array if NULL, returning 0 or -1. */
int32_t rome2_vfs_crt_initialize_environment_narrow(
    char ***inout_environ,
    char ***out_initial_environ,
    uint8_t *inout_mb_init_flag,
    rome2_vfs_crt_get_env_strings_w_fn get_env_w_fn,
    rome2_vfs_crt_free_env_strings_w_fn free_env_w_fn,
    rome2_vfs_crt_wcstombs_fn wctomb_fn,
    rome2_vfs_crt_calloc_fn calloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    void *ctx);

/* `0x116a15ca`: converts wide _wenviron entries to narrow strings and publishes via callback. */
int32_t rome2_vfs_crt_initialize_narrow_env_from_wide(
    const uint16_t *const *wenviron,
    rome2_vfs_crt_wcstombs_fn wctomb_fn,
    rome2_vfs_crt_calloc_fn calloc_fn,
    rome2_vfs_crt_free_fn free_fn,
    rome2_vfs_crt_setenv_narrow_fn setenv_fn,
    void *ctx);

/* `0x116a1729`: returns existing narrow env array or initializes from wide / OS environment block. */
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
    void *ctx);

/* String collation callbacks for `0x116b1b1c`, `0x116b1b45`, `0x116b1ef1`. */
typedef int32_t (*rome2_vfs_crt_ascii_strnicmp_fn)(
    const char *s1,
    const char *s2,
    size_t max_count,
    void *ctx);
typedef int32_t (*rome2_vfs_crt_compare_string_a_stat_fn)(
    uint32_t locale_name_guest,
    uint32_t cmp_flags,
    const char *s1,
    int32_t n1,
    const char *s2,
    int32_t n2,
    uint32_t codepage,
    void *ctx);

/* `0x116b1ef1`: ___acrt_CompareStringA LocaleUpdate wrapper around ___acrt_CompareStringA_stat. */
int32_t rome2_vfs_crt_compare_string_a(
    uint32_t locale_name_guest,
    uint32_t cmp_flags,
    const char *s1,
    int32_t n1,
    const char *s2,
    int32_t n2,
    uint32_t codepage,
    rome2_vfs_crt_compare_string_a_stat_fn stat_fn,
    void *ctx);

/* `0x116b1b45`: _strnicoll_l validating inputs <= INT_MAX and comparing under C or LC_COLLATE locale. */
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
    void *ctx);

/* `0x116b1b1c`: _strnicoll fast-pathing to _strnicmp when locale_changed == 0. */
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
    void *ctx);

/* `0x116b8400`: ___ascii_wcsnicmp bounded ASCII 'A'..'Z' case-folding wide-char comparator. */
int32_t rome2_vfs_crt_ascii_wcsnicmp(
    const uint16_t *s1,
    const uint16_t *s2,
    size_t count);

#ifdef __cplusplus
}
#endif

#endif
