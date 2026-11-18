#ifndef ROME2_VFS_FS_ENGINE_CRT_FENV_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_FENV_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_env_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L46_EBADF_MSVC 9
#define ROME2_VFS_L46_OSFILE_DEV_BIT 0x40u
#define ROME2_VFS_L46_X87_CW_MASK 0x1f3fu
#define ROME2_VFS_L46_MXCSR_CTRL_MASK 0xffc0u
#define ROME2_VFS_L46_ERR_INVALID_PARAM_WIN32 0x57u
#define ROME2_VFS_L46_LOG10_ERR_NEG 1
#define ROME2_VFS_L46_LOG10_ERR_ZERO 2

/* `0x1168781e`: __crt_fast_encode_pointer<> wrapper. */
uint32_t rome2_vfs_crt_fast_encode_pointer32(uint32_t ptr_va, uint32_t security_cookie);

/* `0x1168bf06`: ___acrt_locale_get_ctype_array_value (0..256 index over EOF + byte range). */
uint32_t rome2_vfs_crt_locale_get_ctype_value(
    const uint16_t *ctype_257,
    int32_t ch,
    uint32_t mask);

/* `0x11699a26` & `0x11699b0d`: is_slash & get_drive_number_from_path. */
uint8_t rome2_vfs_crt_is_slash_w(uint16_t ch);
uint32_t rome2_vfs_crt_get_drive_number_from_path_w(const uint16_t *wpath);

/* `0x1169dedd` & `0x1169e117`: strtoull & __isspace_l. */
uint64_t rome2_vfs_crt_strtoull_ascii(
    const char *nptr,
    const char **endptr,
    int32_t base,
    int32_t *out_errno);

uint8_t rome2_vfs_crt_isspace_l(
    uint8_t is_ctype_space,
    rome2_vfs_crt_locale_update16_32 *lu,
    rome2_vfs_crt_tiddata868_32 *ptd);

/* `0x116a2525`, `0x116a430e`, `0x116a4428`, `0x116a2553`, `0x116a45bb`: locks, pctype, locale swap. */
uint32_t rome2_vfs_crt_unlock_slot_va(int32_t lock_id);

uint32_t rome2_vfs_crt_pctype_func_resolve(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t global_locinfo_va,
    uint32_t refreshed_locinfo_va,
    uint32_t deref_pctype_va);

uint32_t rome2_vfs_crt_replace_thread_locinfo_nolock(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t new_locinfo_va,
    uint32_t default_locinfo_slot_val,
    int32_t old_refcount,
    uint8_t *out_should_free_old,
    uint8_t *out_retained_new);

/* `0x116a840b`: try_get_first_available_module cache & api-set fallback. */
uint8_t rome2_vfs_crt_is_apiset_name_w(const uint16_t *mod_name);

uint32_t rome2_vfs_crt_try_get_first_available_module(
    uint32_t *cached_handles,
    size_t table_len,
    const uint32_t *mod_ids,
    const uint16_t *const *mod_names,
    size_t id_count,
    const uint32_t *gmh_results,
    const uint32_t *gmh_last_errs,
    const uint32_t *loadlib_results,
    uint8_t *out_used_loadlib_fallback);

/* `0x116ada62`, `0x116ae4a6`, `0x116ae4c4`, `0x116b3258`, `0x116b8348`, `0x116be8d3`: math & wide strings. */
double rome2_vfs_crt_set_exp(double x, int32_t exp_val);

rome2_vfs_reg_status rome2_vfs_crt_wfullpath_dispatch(
    uint32_t dst_va,
    uint32_t path_va,
    uint32_t max_words,
    uint8_t *out_ignore_case,
    uint8_t *out_must_exist,
    uint8_t *out_normal_alloc);

const uint16_t *rome2_vfs_crt_wcspbrk(const uint16_t *wstr, const uint16_t *control);
uint8_t rome2_vfs_crt_f64_is_nan_or_inf_bits(uint64_t f64_bits);
double rome2_vfs_crt_log10_guarded(double x, int32_t *out_libm_err_code);
const uint16_t *rome2_vfs_crt_wcsrchr(const uint16_t *wstr, uint16_t wc);

/* `0x116b4c38`, `0x116b56c7`, `0x116b57f7`, `0x116b58a7`, `0x116b6038`, `0x116b60c0`:
 * multibyte gate, recalloc, new handler, user matherr dispatch, isatty.
 */
uint8_t rome2_vfs_crt_update_thread_mbc_gate(
    uint32_t ptd_va,
    uint32_t global_mbc_slot_va,
    uint32_t *out_target_slot_va);

uint8_t rome2_vfs_crt_recalloc_plan(
    uint32_t old_bytes,
    uint32_t count,
    uint32_t elem_size,
    uint32_t *out_new_bytes,
    uint32_t *out_zero_tail_offset,
    uint32_t *out_zero_tail_bytes,
    int32_t *out_errno);

uint8_t rome2_vfs_crt_callnewh_dispatch(uint32_t decoded_handler_va, int32_t handler_ret);
int32_t rome2_vfs_crt_query_new_mode(int32_t newmode_global);

int32_t rome2_vfs_crt_invoke_user_matherr(
    uint32_t encoded_handler,
    uint32_t security_cookie,
    const rome2_vfs_crt_math_exception32_32 *exc,
    int32_t handler_ret,
    uint8_t *out_invoked);

int32_t rome2_vfs_crt_isatty(
    int32_t fh,
    int32_t nhandle,
    const rome2_vfs_crt_ioinfo56_32 *chunk64,
    int32_t *out_errno);

/* `0x116b89d3`, `0x116b8a53`, `0x116b8b0b`, `0x116b8b73`: fenv control & status pack/unpack. */
uint32_t rome2_vfs_crt_fenv_pack_control(
    uint32_t x87_ctrl_fe,
    uint32_t mxcsr_ctrl_fe,
    int32_t sse2_isa_level);

uint32_t rome2_vfs_crt_fenv_get_status(
    uint16_t x87_sw,
    uint32_t mxcsr,
    int32_t sse2_isa_level);

void rome2_vfs_crt_fenv_set_control(
    rome2_vfs_x87_env28_32 *x87_env,
    uint16_t x87_cw_mapped,
    uint32_t mxcsr_ctrl_mapped,
    int32_t sse2_isa_level,
    uint32_t *inout_mxcsr);

void rome2_vfs_crt_fenv_set_status(
    rome2_vfs_x87_env28_32 *x87_env,
    uint32_t fenv_stat_word,
    int32_t sse2_isa_level,
    uint32_t *inout_mxcsr);

#ifdef __cplusplus
}
#endif

#endif
