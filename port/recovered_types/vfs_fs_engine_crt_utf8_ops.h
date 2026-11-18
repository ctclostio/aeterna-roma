#ifndef ROME2_VFS_FS_ENGINE_CRT_UTF8_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_UTF8_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

/* `0x116889a9`: formatting_buffer::count<wchar_t> quarter-buffer output capacity. */
uint32_t rome2_vfs_crt_fmt_buf_count_wide(
    const rome2_vfs_crt_formatting_buffer1032_32 *fb);

/* `0x11689010`: __crt_unique_heap_ptr::operator= ownership transfer. */
uint32_t rome2_vfs_crt_unique_heap_ptr_assign(
    rome2_vfs_crt_unique_heap_ptr4_32 *self,
    rome2_vfs_crt_unique_heap_ptr4_32 *rhs,
    uint32_t *out_old_freed_ptr);

/* `0x1168d395`: __crt_strtox::is_overflow_condition<uint32>. */
uint8_t rome2_vfs_crt_is_overflow_condition_u32(
    uint32_t flags,
    uint32_t value);

/* `0x1168e5d4`: c_string_character_source<wchar_t>::unget. */
uint8_t rome2_vfs_crt_wstr_source_unget(
    const uint16_t *src,
    size_t *inout_pos,
    uint16_t expected_ch,
    int32_t *out_errno);

/* `0x1168e679`: _atol / _atoi narrow decimal string parser. */
int32_t rome2_vfs_crt_atol(const char *src, size_t max_len);

/* `0x1169d38d`, `0x1169d3b9`, `0x116b15ac`: UTF-8 lookahead, __mbrtoc32_utf8 & __mbrtowc_utf8. */
size_t rome2_vfs_crt_utf8_lookahead_probe(const uint8_t *s, size_t max_len);

size_t rome2_vfs_crt_mbrtoc32_utf8(
    uint32_t *pc32,
    const uint8_t *s,
    size_t n,
    rome2_vfs_crt_mbstate8_32 *ps,
    int32_t *out_errno);

size_t rome2_vfs_crt_mbrtowc_utf8(
    uint16_t *pwc,
    const uint8_t *s,
    size_t n,
    rome2_vfs_crt_mbstate8_32 *ps,
    int32_t *out_errno);

/* `0x1169e514` & `0x116a66a3`: buffered _fputc_nolock & fputwc_binary_nolock. */
int32_t rome2_vfs_crt_fputc_nolock(
    int32_t ch,
    uint8_t *buf,
    size_t buf_cap,
    size_t *inout_pos,
    int32_t *inout_cnt,
    uint8_t flush_ok);

uint16_t rome2_vfs_crt_fputwc_binary_nolock(
    uint16_t ch,
    uint8_t *buf,
    size_t buf_cap,
    size_t *inout_pos,
    int32_t *inout_cnt,
    uint8_t flush_ok);

/* `0x116a25d6`: ____lc_codepage_func reading updated thread locale codepage. */
uint32_t rome2_vfs_crt_lc_codepage_func(
    const rome2_vfs_crt_threadlocinfo184_32 *thread_loc,
    const rome2_vfs_crt_threadlocinfo184_32 *global_loc,
    uint8_t own_locale_enabled);

/* `0x116a5ca6`: _wctomb_s default-locale bounded wchar->multibyte converter. */
int32_t rome2_vfs_crt_wctomb_s(
    int32_t *out_converted,
    uint8_t *dst,
    size_t dst_cap,
    uint16_t wchar,
    uint32_t codepage);

/* `0x116a5d7f`, `0x116a6098`, `0x116a6282`, `0x116a63de`, `0x116a649f`: FP formatters. */
int32_t rome2_vfs_crt_fp_format_a(
    double val,
    char *buf,
    size_t buf_cap,
    int32_t precision,
    uint8_t caps,
    uint32_t min_exp_digits,
    int32_t *out_errno);

int32_t rome2_vfs_crt_fp_format_e(
    double val,
    char *buf,
    size_t buf_cap,
    int32_t precision,
    uint8_t caps,
    uint32_t min_exp_digits,
    int32_t *out_errno);

int32_t rome2_vfs_crt_fp_format_f(
    double val,
    char *buf,
    size_t buf_cap,
    int32_t precision,
    int32_t *out_errno);

int32_t rome2_vfs_crt_fp_format_g(
    double val,
    char *buf,
    size_t buf_cap,
    int32_t precision,
    uint8_t caps,
    uint32_t min_exp_digits,
    int32_t *out_errno);

int32_t rome2_vfs_crt_fp_format_nan_or_infinity(
    uint32_t fp_class,
    uint8_t is_negative,
    char *buf,
    size_t buf_cap,
    uint8_t caps,
    const rome2_vfs_crt_fp_nan_inf_table64_32 *guest_lut_addrs);

/* `0x116a8a30`: ___acrt_LCMapStringEx@36 API vs LCMapStringW fallback selector. */
uint8_t rome2_vfs_crt_lcmap_string_ex_uses_modern(
    uint8_t has_lcmap_ex_api);

/* `0x116a8c79`: _iswctype table/Unicode classification predicate. */
int32_t rome2_vfs_crt_iswctype(
    uint16_t ch,
    uint16_t mask,
    const uint16_t pwctype_256[256],
    uint16_t fallback_type_bits);

/* `0x116aea59`: _get_osfhandle mapping fd -> OS handle or EBADF. */
uint32_t rome2_vfs_crt_get_osfhandle(
    int32_t fh,
    int32_t nhandle,
    const rome2_vfs_crt_ioinfo56_32 *io_slots,
    int32_t *out_errno,
    int32_t *out_doserrno);

/* `0x116afb0a`: _strncpy_s / common_tcsncpy_s<char> secure bounded copy. */
int32_t rome2_vfs_crt_strncpy_s(
    char *dst,
    size_t dst_cap,
    const char *src,
    size_t max_count,
    int32_t *out_errno);

/* `0x116afb40`, `0x116afb46`, `0x116afb4c`, `0x116afb52`: TZ global accessors. */
int32_t *rome2_vfs_crt_tz_timezone_ptr(int32_t *tz_sec_slot);
int32_t *rome2_vfs_crt_tz_dstbias_ptr(int32_t *dstbias_slot);
int32_t *rome2_vfs_crt_tz_daylight_ptr(int32_t *daylight_slot);
const rome2_vfs_crt_tzname_pair8_32 *rome2_vfs_crt_tzname_base(
    const rome2_vfs_crt_tzname_pair8_32 *pair);

/* `0x116b1572`: _isleadbyte_l checking _LEADBYTE (0x8000). */
int32_t rome2_vfs_crt_isleadbyte_l(
    int32_t ch,
    const uint16_t ctype_table_256[256]);

/* `0x116bd4f2` & `0x116bd528`: lazy console init & WriteConsoleW retry-on-invalid-handle. */
uint8_t rome2_vfs_crt_dcrt_console_output_ready(
    uint32_t *inout_console_handle,
    uint32_t lazy_init_handle);

uint8_t rome2_vfs_crt_dcrt_write_console(
    uint32_t *inout_console_handle,
    uint8_t first_write_ok,
    uint32_t first_last_error,
    uint32_t reopened_handle,
    uint8_t retry_write_ok,
    uint32_t *out_attempts);

#ifdef __cplusplus
}
#endif

#endif
