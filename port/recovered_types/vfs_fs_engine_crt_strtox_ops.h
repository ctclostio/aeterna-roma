#ifndef ROME2_VFS_FS_ENGINE_CRT_STRTOX_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_STRTOX_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_fenv_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L47_BIGINT_LIMBS 115u
#define ROME2_VFS_L47_ERANGE_MSVC 34
#define ROME2_VFS_L47_LCONV_DEFAULT_VA 0x119ebed0u
#define ROME2_VFS_L47_C_LOCALE_NAME_VA 0x119ec000u
#define ROME2_VFS_L47_OSFILE_OPEN_BIT 0x01u

/* 464B __crt_strtox::big_integer buffer (`used_00` + `115` 32-bit limbs = `0x1cc` data bytes) divided by `0x11695540`. */
typedef struct rome2_vfs_crt_bigint464 {
    uint32_t used;
    uint32_t data[ROME2_VFS_L47_BIGINT_LIMBS];
} rome2_vfs_crt_bigint464;

/* `0x1169de44` & `0x1168dc34`: c_string_character_source<char> & parse_integer<unsigned __int64>. */
void rome2_vfs_crt_cstr_source_init(
    rome2_vfs_crt_cstr_source8_32 *src,
    uint32_t cstr_va,
    uint32_t endptr_slot_va);

uint64_t rome2_vfs_crt_parse_uint64_cstr(
    const char *nptr,
    const char **endptr,
    int32_t base,
    uint8_t is_signed,
    int32_t *out_errno);

/* `0x1168e602`, `0x1169d0ad`, `0x116ae58e`: __ischartype_l, wcsncmp, __wcsicmp ASCII fallback. */
uint32_t rome2_vfs_crt_ischartype_l(
    const uint16_t *ctype_257,
    int32_t mb_cur_max,
    int32_t ch,
    uint32_t mask,
    uint8_t has_locinfo);

int32_t rome2_vfs_crt_wcsncmp(const uint16_t *lhs, const uint16_t *rhs, size_t count);
int32_t rome2_vfs_crt_wcsicmp_ascii(const uint16_t *lhs, const uint16_t *rhs, int32_t *out_errno);

/* `0x116ae2b8`, `0x116b1986`, `0x116b58d9`, `0x116b5824`: fullpath, realloc, msize, query_new_handler. */
uint8_t rome2_vfs_crt_common_wfullpath_gate(
    uint32_t buf_va,
    const uint16_t *path,
    size_t max_chars,
    uint8_t *out_alloc_result,
    uint32_t *out_ret_va);

uint8_t rome2_vfs_crt_realloc_base_plan(
    uint32_t block_va,
    uint32_t new_size,
    uint32_t heap_realloc_va,
    int32_t new_mode,
    uint8_t callnewh_retry,
    uint32_t *out_result_va,
    uint8_t *out_use_malloc,
    uint8_t *out_use_free,
    int32_t *out_errno);

int32_t rome2_vfs_crt_msize_base_gate(
    uint32_t block_va,
    int32_t heap_size_val,
    int32_t *out_errno);

uint32_t rome2_vfs_crt_query_new_handler_decode(
    uint32_t encoded_newh_slot,
    uint32_t security_cookie);

/* `0x116b3187`, `0x116b31fc`, `0x11683e00`: errmath tail, f64 quiet-NaN fadd, _ftol2_sse. */
double rome2_vfs_crt_errmath_restore_cw(double handled_val, uint16_t saved_cw, uint16_t *out_restored_cw);
uint64_t rome2_vfs_crt_f64_quiet_nan_widen(uint32_t fp_class_eax, uint64_t f64_bits);
int64_t rome2_vfs_crt_ftol2_truncate(double x);

/* `0x116b5c9e`, `0x116b5d1b`, `0x116b5ee6`, `0x116b4b50`, `0x116b5f67`: locale refcounts & thread data sync. */
uint32_t rome2_vfs_crt_locale_add_ref(
    rome2_vfs_crt_threadlocinfo184_32 *locinfo,
    int32_t ref_pools[10],
    int32_t cat_ref_pools[6][2],
    uint32_t *out_lctime_va);

uint32_t rome2_vfs_crt_locale_release_ref(
    rome2_vfs_crt_threadlocinfo184_32 *locinfo,
    int32_t ref_pools[10],
    int32_t cat_ref_pools[6][2],
    uint32_t *out_lctime_va);

uint32_t rome2_vfs_crt_free_locale_plan(
    const rome2_vfs_crt_threadlocinfo184_32 *locinfo,
    const int32_t ref_pools[10],
    const int32_t cat_wref_pools[6],
    uint32_t *out_lctime_destroy_va,
    uint8_t *out_free_locinfo);

uint32_t rome2_vfs_crt_update_thread_mbc_internal(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t *inout_global_mbc_slot_va,
    int32_t *inout_old_mbc_refcount,
    int32_t *inout_new_mbc_refcount,
    uint32_t per_thread_mask,
    uint8_t *out_freed_old,
    uint8_t *out_aborted);

uint32_t rome2_vfs_crt_update_thread_locale_internal(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t global_locinfo_va,
    uint32_t updated_locinfo_va,
    uint32_t per_thread_mask,
    uint8_t *out_updated_flag,
    uint8_t *out_aborted);

/* `0x116b86a4`, `0x116b8760`, `0x116b8819`, `0x116b88e6`: x87/MXCSR <-> MSVC fenv control maps. */
uint32_t rome2_vfs_crt_mxcsr_to_fenv_ctrl(uint32_t mxcsr);
uint32_t rome2_vfs_crt_x87_cw_to_fenv_ctrl(uint16_t x87_cw);
uint32_t rome2_vfs_crt_fenv_ctrl_to_mxcsr(uint32_t fenv_ctrl);
uint16_t rome2_vfs_crt_fenv_ctrl_to_x87_cw(uint32_t fenv_ctrl);

/* `0x11689985`, `0x11695540`, `0x11696308`, `0x11696528`, `0x116a511c`, `0x116ade23`:
 * woutput FSM, strtox bigint div, input state check, conversion specifier scan, write gate, loctotime64.
 */
int32_t rome2_vfs_crt_woutput_process_step(
    uint8_t has_valid_stream,
    const uint16_t *fmt,
    int32_t *inout_chars_written,
    uint8_t *out_ok,
    int32_t *out_errno);

uint64_t rome2_vfs_crt_bigint_div_u32(
    rome2_vfs_crt_bigint464 *numerator,
    const rome2_vfs_crt_bigint464 *denominator);

uint8_t rome2_vfs_crt_input_process_state(
    rome2_vfs_crt_fmt_parser76_32 *parser,
    int32_t next_char,
    uint8_t whitespace_ok,
    uint8_t has_suppress,
    uint8_t trailing_non_ws,
    uint32_t *inout_matched_count);

uint8_t rome2_vfs_crt_scan_conversion_specifier(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len);

int32_t rome2_vfs_crt_write_gate(
    int32_t fh,
    int32_t nhandle,
    const rome2_vfs_crt_ioinfo56_32 *chunk64,
    uint32_t buf_len,
    int32_t nolock_write_ret,
    int32_t *out_errno,
    uint32_t *out_doserrno);

int64_t rome2_vfs_crt_loctotime64_utc(
    int32_t tm_year,
    int32_t tm_mon,
    int32_t tm_mday,
    int32_t tm_hour,
    int32_t tm_min,
    int32_t tm_sec,
    int32_t isdst,
    int64_t tz_bias_sec,
    int64_t dst_bias_sec,
    uint8_t dst_active_flag,
    int32_t *out_errno);

#ifdef __cplusplus
}
#endif

#endif
