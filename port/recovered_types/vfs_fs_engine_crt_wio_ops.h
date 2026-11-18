#ifndef ROME2_VFS_FS_ENGINE_CRT_WIO_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_WIO_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L50_LOCK_TZ 6u

/* `0x1168750e`: _freea heap marker predicate (0xdddd heap vs 0xcccc stack). */
uint8_t rome2_vfs_crt_freea_needs_heap_free(uint8_t has_non_null_ptr, uint32_t marker_word);

/* `0x11688dbf` & `0x1168b9ea`: stream output adapter char emit & repeated padding. */
uint8_t rome2_vfs_crt_stream_write_char(
    uint32_t file_flags,
    uint32_t file_ptr_or_null,
    uint16_t ch,
    uint16_t *out_slot,
    uint8_t fputwc_ok);

void rome2_vfs_crt_write_multiple_chars(
    uint16_t ch,
    int32_t count,
    uint16_t *out_buf,
    size_t out_cap,
    int32_t *inout_chars_written);

/* `0x1168af61`, `0x1168b10a`, `0x1168b2ff`, `0x1168b4e6`, `0x1168b63b`, `0x1168b6ce`, `0x1168b705`, `0x1168b78e`, `0x1168bb71`:
 * wprintf conversion specifier handlers & stored string writer.
 */
uint8_t rome2_vfs_crt_wprintf_type_z(
    rome2_vfs_crt_wprintf_state64_32 *st,
    const rome2_vfs_crt_unicode_string8_32 *ustr,
    uint8_t is_wide);

void rome2_vfs_crt_wprintf_type_a_setup(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint8_t is_negative,
    uint8_t is_inf_or_nan);

uint8_t rome2_vfs_crt_wprintf_type_c(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint8_t is_wide,
    uint8_t mbtowc_ok);

uint8_t rome2_vfs_crt_wprintf_type_integer(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint64_t raw_val,
    uint8_t is_signed,
    uint32_t radix,
    uint8_t is_upper,
    uint16_t out_digits[66]);

uint8_t rome2_vfs_crt_wprintf_type_n(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint8_t count_output_enabled,
    int32_t length_cat,
    void *out_target,
    int32_t *out_errno);

void rome2_vfs_crt_wprintf_type_o_flags(rome2_vfs_crt_wprintf_state64_32 *st);
void rome2_vfs_crt_wprintf_type_p_setup(rome2_vfs_crt_wprintf_state64_32 *st);
void rome2_vfs_crt_wprintf_type_s_len(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint32_t bounded_len,
    uint8_t is_null_ptr,
    uint8_t is_wide);

uint8_t rome2_vfs_crt_wprintf_write_stored(
    const rome2_vfs_crt_wprintf_state64_32 *st,
    const uint8_t *narrow_src,
    const uint16_t *wide_src,
    uint16_t *dst,
    size_t dst_cap,
    int32_t *inout_chars_written);

/* `0x1169df07`, `0x1169e7f6`, `0x116a2005`: _wcstol, _lseeki64_nolock, __raise_exc. */
int32_t rome2_vfs_crt_wcstol_ascii(
    const uint16_t *nptr,
    size_t *out_end_idx,
    int32_t base,
    int32_t *out_errno);

int64_t rome2_vfs_crt_lseeki64_clamp(
    int64_t cur_pos,
    int64_t end_pos,
    int64_t offset,
    uint32_t origin,
    int32_t *out_errno);

uint8_t rome2_vfs_crt_raise_exc_default_flag(void);

/* `0x116a49a3..0x116a4fea`: lowio text/UTF-8/UTF-16/double-translated console writers. */
int32_t rome2_vfs_crt_utf8_seq_bytes(uint8_t lead_byte, const int8_t *lookuptrailbytes_256);

uint8_t rome2_vfs_crt_write_requires_double_translation(
    uint8_t is_tty,
    const rome2_vfs_crt_ioinfo56_32 *ioinfo,
    uint8_t has_ctype_locale,
    uint8_t get_console_mode_ok);

void rome2_vfs_crt_write_text_ansi_lf_expand(
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    size_t *out_dst_len,
    rome2_vfs_crt_lowio_write_result12_32 *out_res);

void rome2_vfs_crt_write_text_utf16_lf_expand(
    const uint16_t *src,
    size_t src_words,
    uint16_t *dst,
    size_t dst_words_cap,
    size_t *out_dst_words,
    rome2_vfs_crt_lowio_write_result12_32 *out_res);

/* `0x116ae350` & `0x116ae3e5`: win32_buffer<wchar_t> deallocate & dyn alloc status. */
void rome2_vfs_crt_win32_buffer_deallocate(rome2_vfs_crt_win32_buffer24_32 *buf, uint8_t *out_freed);
int32_t rome2_vfs_crt_win32_buffer_dyn_alloc_status(uint32_t alloc_ptr, uint32_t *out_ptr);

/* `0x116afbdc`, `0x116b026c`, `0x116b039e`, `0x116b03f2`: DST/TZ & lock 6 thunks. */
int32_t rome2_vfs_crt_isindst_compare_hemisphere(
    const rome2_vfs_crt_tz_transition_date12_32 *start_d,
    const rome2_vfs_crt_tz_transition_date12_32 *end_d,
    int32_t tm_yday,
    int32_t ms_of_day);

void rome2_vfs_crt_tzset_nolock_reset(
    rome2_vfs_crt_tz_transition_date12_32 *start_d,
    rome2_vfs_crt_tz_transition_date12_32 *end_d,
    int32_t *out_tz_api_used);

uint32_t rome2_vfs_crt_unlock6_index(void);

/* `0x116b6aa8`, `0x116bc428`, `0x116bc636`: __lc_time_data free, __wgetdcwd_nolock, _towlower_l. */
uint32_t rome2_vfs_crt_lc_time_free_slot_count(void);

uint8_t rome2_vfs_crt_wgetdcwd_validate_args(
    int32_t drive,
    int32_t max_len,
    uint8_t drive_valid,
    int32_t *out_errno,
    int32_t *out_doserrno);

uint16_t rome2_vfs_crt_towlower_full_l(
    uint16_t ch,
    uint8_t has_ctype_handle,
    const uint8_t *clmap_256,
    const uint16_t *lcmap_high_256);

#ifdef __cplusplus
}
#endif

#endif
