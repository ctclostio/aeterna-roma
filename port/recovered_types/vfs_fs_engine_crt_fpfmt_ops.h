#ifndef ROME2_VFS_FS_ENGINE_CRT_FPFMT_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_FPFMT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

/* `0x11688991`, `0x116889c2`, `0x11688a3f`, `0x11688b3c`:
 * formatting_buffer capacity query, growth guard, and midpoint scratch offset.
 */
uint32_t rome2_vfs_crt_fmt_buf_count_wchar(
    const rome2_vfs_crt_formatting_buffer1032_32 *fb);

uint8_t rome2_vfs_crt_fmt_buf_ensure_wchar(
    rome2_vfs_crt_formatting_buffer1032_32 *fb,
    uint32_t wchar_count,
    uint8_t alloc_succeeds,
    int32_t *out_errno);

uint8_t rome2_vfs_crt_fmt_buf_ensure_dword(
    rome2_vfs_crt_formatting_buffer1032_32 *fb,
    uint32_t dword_count,
    uint8_t alloc_succeeds,
    int32_t *out_errno);

uint32_t rome2_vfs_crt_fmt_buf_scratch_offset(
    const rome2_vfs_crt_formatting_buffer1032_32 *fb);

/* `0x11688aee`: wide-vs-narrow character specifier decision in wprintf. */
uint8_t rome2_vfs_crt_is_wide_specifier(
    uint32_t options_lo,
    uint16_t specifier,
    int32_t length_mod);

/* `0x11688bcd`, `0x11688ce2`: reverse unsigned radix digit emitters into wprintf state. */
void rome2_vfs_crt_uint32_to_wstring(
    uint32_t value,
    uint32_t radix,
    uint8_t is_upper,
    int32_t *inout_min_digits,
    uint16_t *out_buf,
    size_t out_cap_wchars,
    uint32_t *out_start_index,
    uint32_t *out_written_len);

void rome2_vfs_crt_uint64_to_wstring(
    uint64_t value,
    uint64_t radix,
    uint8_t is_upper,
    int32_t *inout_min_digits,
    uint16_t *out_buf,
    size_t out_cap_wchars,
    uint32_t *out_start_index,
    uint32_t *out_written_len);

/* `0x11689271`, `0x116893cf`: locale-aware floating-point decimal formatting fixups. */
void rome2_vfs_crt_crop_zeroes(
    char *buf,
    size_t buf_cap,
    char decimal_point);

void rome2_vfs_crt_force_decimal_point(
    char *buf,
    size_t buf_cap,
    char decimal_point);

/* `0x1168b801`: bounded multibyte glyph counter for narrow strings in wprintf. */
int32_t rome2_vfs_crt_wprintf_mbchar_count(
    const uint8_t *str,
    size_t buf_len,
    int32_t max_chars,
    const uint8_t is_lead_table[256]);

/* `0x1168d62c`: wide-string integer parser with base 0/2..36 and signed/unsigned bounds. */
uint32_t rome2_vfs_crt_parse_uint32_wstr(
    const uint16_t *src,
    size_t src_cap_wchars,
    size_t *out_end_index,
    int32_t base,
    uint8_t is_signed,
    int32_t *out_errno);

/* `0x1169d3f9`: UTF-8 to UTF-16LE decoder with surrogate pairs & measure-only mode. */
size_t rome2_vfs_crt_mbsrtowcs_utf8(
    uint16_t *dst,
    const uint8_t **inout_src,
    size_t dst_cap_wchars,
    int32_t *out_errno);

/* `0x1169e75f`: 64-bit common_lseek_nolock clearing FEOFLAG (bit 1) on valid seek. */
int64_t rome2_vfs_crt_common_lseek64_nolock(
    uint8_t valid_handle,
    uint8_t seek_ok,
    int64_t new_pos,
    uint32_t win32_err,
    rome2_vfs_crt_ioinfo56_32 *io,
    int32_t *out_errno,
    int32_t *out_doserrno);

/* `0x116a4118`: bounded UTF-16 string length scan (wcsnlen). */
size_t rome2_vfs_crt_wcsnlen(
    const uint16_t *s,
    size_t max_count);

/* `0x116a59ef`, `0x116a5b31`: _mbtowc_l and mbtowc bounded UTF-8/C-locale decoder. */
int32_t rome2_vfs_crt_mbtowc_l(
    uint16_t *pwc,
    const uint8_t *s,
    size_t n,
    uint32_t codepage,
    uint32_t *inout_mbstate_w,
    uint32_t *inout_mbstate_s,
    int32_t *out_errno);

int32_t rome2_vfs_crt_mbtowc(
    uint16_t *pwc,
    const uint8_t *s,
    size_t n,
    int32_t *out_errno);

/* `0x116a6568`: bounded floating-point formatter (__acrt_fp_format). */
int32_t rome2_vfs_crt_acrt_fp_format(
    const double *val,
    char *result_buf,
    size_t result_size,
    char *scratch_buf,
    size_t scratch_size,
    int32_t format,
    int32_t precision,
    uint64_t options,
    int32_t *out_errno);

/* `0x116a66d3`: _fputwc_nolock stream mode dispatcher (string/UTF-16/UTF-8/binary). */
uint16_t rome2_vfs_crt_fputwc_nolock(
    uint16_t ch,
    uint32_t file_flags,
    const rome2_vfs_crt_ioinfo56_32 *io,
    uint8_t *out_bytes,
    size_t out_cap,
    size_t *out_written_bytes);

/* `0x116a67fc`: _get_printf_count_output cookie-masked enablement query. */
int32_t rome2_vfs_crt_get_printf_count_output(
    uint32_t encoded_enable_percent_n,
    uint32_t security_cookie);

/* `0x116a816e`: __acrt_WideCharToMultiByte flag and default-char sanitization. */
void rome2_vfs_crt_sanitize_wctomb_flags(
    uint32_t codepage,
    uint32_t in_flags,
    uint8_t has_default_char,
    uint8_t has_used_default,
    uint32_t *out_flags,
    uint8_t *out_keep_default_char,
    uint8_t *out_keep_used_default);

/* `0x116afdf6`, `0x116aff36`, `0x116b0111`: DST transition computation & TZ loaders. */
typedef struct rome2_vfs_crt_tz_runtime_state {
    rome2_vfs_crt_tz_transition_date12_32 dststart;
    rome2_vfs_crt_tz_transition_date12_32 dstend;
    char std_name[64];
    char dst_name[64];
    int32_t timezone_sec;
    int32_t daylight;
    int32_t dstbias_sec;
    int32_t tz_api_used;
    char cached_tz_env[64];
    uint8_t has_cached_tz;
} rome2_vfs_crt_tz_runtime_state;

uint8_t rome2_vfs_crt_tz_cvtdate(
    rome2_vfs_crt_tz_runtime_state *tz,
    int32_t transition_type,
    int32_t datetype,
    int32_t year,
    int32_t month,
    int32_t week,
    int32_t dayofweek,
    int32_t day,
    int32_t hour,
    int32_t min,
    int32_t sec,
    int32_t msec,
    int32_t std_or_dst_bias_sec);

void rome2_vfs_crt_tzset_from_env_nolock(
    rome2_vfs_crt_tz_runtime_state *tz,
    const char *tz_env);

void rome2_vfs_crt_tzset_from_system_nolock(
    rome2_vfs_crt_tz_runtime_state *tz,
    uint8_t tz_api_ok,
    const rome2_vfs_crt_time_zone_info172_32 *tzi);

/* `0x116b608e`: _putwch_nolock single-wchar console write wrapper. */
uint16_t rome2_vfs_crt_putwch_nolock(
    uint16_t ch,
    uint8_t console_init_ok,
    uint8_t write_ok,
    uint16_t *out_written_ch);

/* `0x116b67f4`: free_crt_array_internal pointer-slot cleanup with overflow guard. */
uint32_t rome2_vfs_crt_free_crt_array(
    void **slots,
    uint32_t count);

/* `0x116bc582`: _validdrive index validation (0..26) and Win32 drive-type gate. */
int32_t rome2_vfs_crt_validdrive(
    uint32_t drive,
    uint32_t win32_drive_type,
    uint16_t out_root_path[4],
    int32_t *out_errno,
    int32_t *out_doserrno);

/* `0x116bd871`: __acrt_LCMapStringW bounded source length clamp. */
int32_t rome2_vfs_crt_lcmap_wchar_len(
    const uint16_t *src,
    int32_t cch_src);

#ifdef __cplusplus
}
#endif

#endif
