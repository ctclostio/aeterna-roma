#ifndef ROME2_VFS_FS_ENGINE_CRT_PRINTF_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_PRINTF_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_strtox_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L48_PRINTF_FLAG_PLUS 0x01u
#define ROME2_VFS_L48_PRINTF_FLAG_SPACE 0x02u
#define ROME2_VFS_L48_PRINTF_FLAG_MINUS 0x04u
#define ROME2_VFS_L48_PRINTF_FLAG_ZERO 0x08u
#define ROME2_VFS_L48_PRINTF_FLAG_HASH 0x20u
#define ROME2_VFS_L48_PRINTF_TBL_LEN 91u

/* `0x116842e0`: unsigned 64-bit __aulldvrm quotient and remainder. */
uint64_t rome2_vfs_crt_aulldvrm(uint64_t dividend, uint64_t divisor, uint64_t *out_rem);

/* `0x1168934e`, `0x11689d22`, `0x11689d9d`, `0x11689f7b`, `0x1168ae87`, `0x1168b869`:
 * output_processor<wchar_t> state transition table & flag/width/precision/normal/ptr helpers.
 */
uint32_t rome2_vfs_crt_wprintf_find_next_state(uint16_t ch, uint32_t prev_state);
uint8_t rome2_vfs_crt_wprintf_state_case_flag(rome2_vfs_crt_wprintf_state64_32 *st);
uint8_t rome2_vfs_crt_wprintf_state_case_normal(uint8_t emitter_ok, int32_t *out_errno);
uint8_t rome2_vfs_crt_wprintf_state_case_precision(
    rome2_vfs_crt_wprintf_state64_32 *st,
    int32_t va_prec,
    int32_t literal_prec,
    uint8_t literal_ok);
uint8_t rome2_vfs_crt_wprintf_state_case_width(
    rome2_vfs_crt_wprintf_state64_32 *st,
    int32_t va_width,
    int32_t literal_width,
    uint8_t literal_ok);
uint8_t rome2_vfs_crt_validate_nonnull_slot(const uint32_t *slot, int32_t *out_errno);

/* `0x1168c168`, `0x1168c1a2`, `0x116adde0`: Gregorian leap year & month-day validation. */
int32_t rome2_vfs_crt_elapsed_leap_years(int32_t tm_year);
uint8_t rome2_vfs_crt_is_leap_year(int32_t tm_year);
uint8_t rome2_vfs_crt_is_valid_month_day(int32_t tm_year, int32_t tm_mon, int32_t tm_mday);

/* `0x1168d3c6` & `0x1168e5ab`: strtox overflow check & c_string_character_source::unget. */
uint8_t rome2_vfs_crt_strtox_is_overflow_u64(uint8_t flags, uint64_t val);
uint8_t rome2_vfs_crt_cstr_source_unget(
    const char **inout_cur,
    uint8_t expected_ch,
    int32_t *out_errno);

/* `0x11692b1c`, `0x11695abd`, `0x11696278`, `0x11697068`: scanf whitespace, scanset invert, MB lit & wide update. */
int32_t rome2_vfs_crt_skip_whitespace_str(const char *s, size_t *inout_pos, const uint16_t *ctype_257);
void rome2_vfs_crt_invert_scanset_bitmap(uint8_t bitmap_32[32]);
uint8_t rome2_vfs_crt_process_literal_char_mb(
    const uint16_t *ctype_257,
    uint8_t ch0,
    uint8_t trail_ch,
    const char *stream_next,
    uint8_t *out_consumed);
void rome2_vfs_crt_fmt_parser_update_is_wide(rome2_vfs_crt_fmt_parser76_32 *fp);

/* `0x116a51db`, `0x116ae7dd`, `0x116a8ce2`: lowio fh lock/unlock & __ischartype_l multibyte. */
uint32_t rome2_vfs_crt_lowio_fh_slot_offset(int32_t fh);
uint32_t rome2_vfs_crt_ischartype_mb_l(
    const uint16_t *ctype_257,
    int32_t ch,
    uint32_t mask,
    uint16_t mb_ctype_result,
    uint8_t get_string_type_ok,
    uint8_t *out_used_mb_api);

/* `0x116ae1c9`, `0x116ae232`, `0x116ae454`, `0x116ae5d7`: common_fullpath & win32_buffer detach & __wcsicmp_l. */
int32_t rome2_vfs_crt_common_fullpath_plan(
    uint32_t gfpn_ret,
    uint32_t cap_words,
    uint32_t win32_err,
    int32_t mapped_errno,
    uint8_t is_dyn_buf,
    uint8_t resize_ok,
    uint8_t *out_retry_needed,
    uint32_t *out_new_cap,
    uint32_t *out_written_len);

uint8_t rome2_vfs_crt_win32_buffer_detach_plan(
    const rome2_vfs_crt_win32_buffer24_32 *buf,
    uint8_t *out_needs_heap_dup,
    uint32_t *out_dup_bytes);

int32_t rome2_vfs_crt_wcsicmp_l(
    const uint16_t *lhs,
    const uint16_t *rhs,
    uint8_t has_ctype_locale,
    int32_t *out_errno);

/* `0x116afb58`, `0x116afb84`, `0x116afbb0`: _get_timezone, _get_dstbias, _get_daylight. */
int32_t rome2_vfs_crt_get_timezone(int32_t global_tz, int32_t *out_seconds, int32_t *out_errno);
int32_t rome2_vfs_crt_get_dstbias(int32_t global_dstbias, int32_t *out_seconds, int32_t *out_errno);
int32_t rome2_vfs_crt_get_daylight(int32_t global_daylight, int32_t *out_flag, int32_t *out_errno);

#ifdef __cplusplus
}
#endif

#endif
