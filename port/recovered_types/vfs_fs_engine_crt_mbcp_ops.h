#ifndef ROME2_VFS_FS_ENGINE_CRT_MBCP_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_MBCP_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

/* `0x116a2c97`: scans bytes of str returning index of first NUL or max_count. */
size_t rome2_vfs_crt_strnlen_bounded(const char *str, size_t max_count);

/* `0x116bf200`: finds first occurrence of `(uint8_t)ch` in `str` (including NUL terminator). */
const char *rome2_vfs_crt_strchr(const char *str, int32_t ch);

/* `0x116a6bcc`: atomically exchanges 1 into `*inout_locale_changed` and returns prior value. */
int32_t rome2_vfs_crt_set_locale_changed(int32_t *inout_locale_changed);

/* `0x116a46ef`: FLS-backed PTD getter/allocator callbacks and bounded lookup. */
typedef void *(*rome2_vfs_crt_fls_get_fn)(uint32_t fls_index, void *ctx);
typedef uint8_t (*rome2_vfs_crt_fls_set_fn)(uint32_t fls_index, void *ptr, void *ctx);
typedef void *(*rome2_vfs_crt_ptd_alloc_fn)(size_t count, size_t elem_size, void *ctx);
typedef void (*rome2_vfs_crt_ptd_free_fn)(void *ptr, void *ctx);
typedef void (*rome2_vfs_crt_ptd_construct_fn)(void *ptd, void *initial_locinfo, void *ctx);
typedef void (*rome2_vfs_crt_abort_fn)(void *ctx);

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
    void *ctx);

/* Win32 NLS & API resolution callbacks for `0x116a82ed`, `0x116a85f4`, `0x116b1753`, `0x116b193d`, `0x116b1c66`. */
typedef int32_t (*rome2_vfs_crt_compare_string_ex_fn)(
    const uint16_t *locale_name,
    uint32_t flags,
    const uint16_t *s1,
    int32_t n1,
    const uint16_t *s2,
    int32_t n2,
    void *ctx);
typedef int32_t (*rome2_vfs_crt_compare_string_w_fn)(
    uint32_t lcid,
    uint32_t flags,
    const uint16_t *s1,
    int32_t n1,
    const uint16_t *s2,
    int32_t n2,
    void *ctx);
typedef uint32_t (*rome2_vfs_crt_locale_name_to_lcid_fn)(const uint16_t *locale_name, uint32_t flags, void *ctx);
typedef uint32_t (*rome2_vfs_crt_try_get_api_fn)(
    uint32_t table_slot,
    const char *api_name,
    const rome2_vfs_crt_api_mod_desc8_32 *begin_desc,
    const rome2_vfs_crt_api_mod_desc8_32 *end_marker,
    void *ctx);
typedef uint8_t (*rome2_vfs_crt_get_cpinfo_fn)(uint32_t cp, rome2_vfs_crt_cpinfo20_32 *out_info, void *ctx);
typedef int32_t (*rome2_vfs_crt_mb2wc_fn)(
    uint32_t cp,
    uint32_t flags,
    const char *src,
    int32_t srclen,
    uint16_t *dst,
    int32_t dstlen,
    void *ctx);
typedef int32_t (*rome2_vfs_crt_wc2mb_fn)(
    uint32_t cp,
    uint32_t flags,
    const uint16_t *src,
    int32_t srclen,
    char *dst,
    int32_t dstlen,
    void *ctx);
typedef int32_t (*rome2_vfs_crt_lcmap_ex_fn)(
    const uint16_t *locale_name,
    uint32_t flags,
    const uint16_t *src,
    int32_t srclen,
    uint16_t *dst,
    int32_t dstlen,
    void *ctx);

/* `0x116a82ed`: resolves dynamic CompareStringEx slot 1 descriptor via try_get_function. */
uint32_t rome2_vfs_crt_try_get_compare_string_ex(
    rome2_vfs_crt_try_get_api_fn resolve_fn,
    void *ctx);

/* `0x116a85f4`: ___acrt_CompareStringEx dispatching CompareStringEx or LocaleNameToLCID + CompareStringW. */
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
    void *ctx);

/* `0x116b1753` & `0x116b193d`: ___acrt_LCMapStringA_stat & LocaleUpdate wrapper ___acrt_LCMapStringA. */
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
    void *ctx);

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
    void *ctx);

/* `0x116b1c66`: ___acrt_CompareStringA_stat bounded MBCS/SBCS widen + CompareStringEx comparator. */
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
    void *ctx);

/* `0x116b46d2`, `0x116b4713`, `0x116b471f`, `0x116b47a2`, `0x116b47e0`, `0x116b4851`, `0x116b48b6`, `0x116b4a37`, `0x116b4c4b`: MBCP / SBCS init & lock helpers. */
typedef void (*rome2_vfs_crt_lock_op_fn)(uint32_t lock_id, void *ctx);
typedef void (*rome2_vfs_crt_get_string_type_a_fn)(
    uint32_t codepage,
    const char *chars,
    size_t count,
    uint16_t *out_types,
    void *ctx);
typedef void (*rome2_vfs_crt_mb_free_fn)(rome2_vfs_crt_multibyte_data544_32 *ptr, void *ctx);

void rome2_vfs_crt_seh_finally_unlock(
    uint32_t lock_id,
    rome2_vfs_crt_lock_op_fn unlock_fn,
    void *ctx);

void rome2_vfs_crt_update_global_mb_lambda(
    rome2_vfs_crt_multibyte_data544_32 *new_mbcinfo,
    const rome2_vfs_crt_multibyte_data544_32 *initial_mbcinfo,
    rome2_vfs_crt_multibyte_data544_32 **global_mbcinfo,
    uint8_t *out_mbctype257,
    uint8_t *out_mbcasemap256,
    rome2_vfs_crt_mb_free_fn free_mb_fn,
    void *ctx);

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
    void *ctx);

uint32_t rome2_vfs_crt_cp_to_locale_name_guest(
    int32_t codepage,
    const rome2_vfs_crt_mbcs_locale_ptrs16_32 *table);

int32_t rome2_vfs_crt_get_system_cp(
    int32_t codepage,
    int32_t *out_f_system_set,
    int32_t oem_cp,
    int32_t acp_cp,
    int32_t thread_lc_cp);

void rome2_vfs_crt_set_sbcs(
    rome2_vfs_crt_multibyte_data544_32 *dst,
    const rome2_vfs_crt_multibyte_data544_32 *initial_mbcinfo);

void rome2_vfs_crt_set_sb_up_low(
    rome2_vfs_crt_multibyte_data544_32 *mbcinfo,
    rome2_vfs_crt_get_cpinfo_fn get_cpinfo_fn,
    rome2_vfs_crt_get_string_type_a_fn get_str_type_a_fn,
    rome2_vfs_crt_mb2wc_fn mb2wc_fn,
    rome2_vfs_crt_lcmap_ex_fn lcmap_ex_fn,
    rome2_vfs_crt_wc2mb_fn wc2mb_fn,
    void *ctx);

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
    void *ctx);

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
    void *ctx);

/* Environment array helpers: `0x116af5f5`, `0x116b5462`, `0x116b55d0`, `0x116b5604`, `0x116b56b1`. */
typedef uint8_t (*rome2_vfs_crt_widen_env_fn)(uint16_t **out_wstr, const char *src, uint32_t cp, void *ctx);
typedef uint8_t (*rome2_vfs_crt_set_os_env_w_fn)(const uint16_t *wname, const uint16_t *wval, void *ctx);
typedef int32_t (*rome2_vfs_crt_env_cmp_fn)(const char *a, const char *b, size_t n, void *ctx);

/* `0x116af5f5`: widens name/value and sets Win32 OS environment variable. */
uint8_t rome2_vfs_crt_set_var_in_system_env(
    const char *name,
    const char *value,
    uint32_t codepage,
    rome2_vfs_crt_widen_env_fn widen_fn,
    rome2_vfs_crt_set_os_env_w_fn set_os_env_w_fn,
    rome2_vfs_crt_ptd_free_fn free_fn,
    void *ctx);

/* `0x116b5462`: duplicates NULL-terminated narrow environment pointer array and strings. */
char **rome2_vfs_crt_copy_environment_narrow(
    const char *const *env_array,
    rome2_vfs_crt_ptd_alloc_fn calloc_fn,
    rome2_vfs_crt_abort_fn abort_fn,
    void *ctx);

/* `0x116b55d0`: duplicates `*inout_environ` if still aliases `initial_environ`. */
void rome2_vfs_crt_ensure_narrow_env_copied(
    char ***inout_environ,
    char *const *initial_environ,
    rome2_vfs_crt_ptd_alloc_fn calloc_fn,
    rome2_vfs_crt_abort_fn abort_fn,
    void *ctx);

/* `0x116b5604`: scans narrow env array matching `option` up to `name_len` followed by `=` or NUL. */
int32_t rome2_vfs_crt_find_in_env_array_narrow(
    const char *const *env_array,
    const char *option,
    size_t name_len,
    rome2_vfs_crt_env_cmp_fn strnicoll_fn,
    void *ctx);

/* `0x116b56b1`: validates `'='`, updates/inserts/deletes env array entry, and updates OS env if primary. */
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
    void *ctx);

#ifdef __cplusplus
}
#endif

#endif
