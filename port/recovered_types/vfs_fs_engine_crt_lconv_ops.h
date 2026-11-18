#ifndef ROME2_VFS_FS_ENGINE_CRT_LCONV_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_LCONV_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L49_LOCK_EXIT 0u
#define ROME2_VFS_L49_LOCK_SETLOCALE 4u
#define ROME2_VFS_L49_LOCK_MBCP 5u

#define ROME2_VFS_L49_WRITE_PATH_NONE 0u
#define ROME2_VFS_L49_WRITE_PATH_TTY_WIDE 1u
#define ROME2_VFS_L49_WRITE_PATH_TTY_ANSI 2u
#define ROME2_VFS_L49_WRITE_PATH_TEXT_ANSI 3u
#define ROME2_VFS_L49_WRITE_PATH_TEXT_UTF8 4u
#define ROME2_VFS_L49_WRITE_PATH_TEXT_UTF16 5u
#define ROME2_VFS_L49_WRITE_PATH_BINARY 6u

/* `0x1168949f`, `0x11689e3f`, `0x1168a992`: output_processor<wchar_t> parameter/normal/type helpers. */
uint8_t rome2_vfs_crt_wprintf_parse_decimal_param(
    const uint16_t *fmt_base,
    uint32_t *inout_fmt_off_words,
    int32_t *inout_cached_errno,
    int32_t *out_val);

uint8_t rome2_vfs_crt_wprintf_emit_normal_char(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint16_t *out_buf,
    size_t out_cap);

uint8_t rome2_vfs_crt_wprintf_format_specifier_plan(
    const rome2_vfs_crt_wprintf_state64_32 *st,
    uint8_t subhandler_ok,
    uint32_t *out_eff_flags,
    int32_t *out_lead_spaces,
    int32_t *out_zero_pad,
    int32_t *out_trail_spaces,
    uint16_t out_prefix[2],
    uint32_t *out_prefix_len);

/* `0x1168c795` & `0x116ae3a6`: win32_buffer<wchar_t> range-error reset & word-buffer allocator. */
uint32_t rome2_vfs_crt_win32_buffer_set_range_error(
    rome2_vfs_crt_win32_buffer24_32 *buf,
    int32_t *out_errno);

int32_t rome2_vfs_crt_win32_buffer_alloc_words(
    rome2_vfs_crt_win32_buffer24_32 *buf,
    uint32_t word_count,
    uint32_t new_guest_ptr,
    uint8_t alloc_ok);

/* `0x116a520e` & `0x116ae892`: _write_nolock dispatch/error plan & lowio handle unlock offset. */
int32_t rome2_vfs_crt_write_nolock_plan(
    const rome2_vfs_crt_ioinfo56_32 *ioinfo,
    const void *buf,
    uint32_t cnt,
    uint8_t is_tty,
    uint32_t win32_bytes_written,
    uint32_t win32_err,
    int32_t mapped_errno,
    uint8_t *out_seek_append,
    uint8_t *out_path_kind,
    int32_t *out_errno,
    int32_t *out_doserrno);

uint32_t rome2_vfs_crt_lowio_unlock_fh_offset(int32_t fh);

/* `0x116ae54f` & `0x116b5b9b`: __towlower_l & __crtGetStringTypeA conversion planning. */
uint16_t rome2_vfs_crt_towlower_l(
    uint16_t ch,
    uint8_t has_custom_clmap,
    const uint8_t *clmap_256,
    const uint16_t *fallback_map_256);

uint8_t rome2_vfs_crt_get_string_type_a_plan(
    uint32_t requested_cp,
    uint32_t locale_cp,
    uint8_t b_error,
    uint32_t wchar_count,
    uint32_t *out_effective_cp,
    uint32_t *out_mb_flags,
    uint32_t *out_alloc_bytes,
    uint8_t *out_uses_heap);

/* `0x116b034a`, `0x116b03a7`, `0x116b4bcf`, `0x116b5877`, `0x116b5fc7`: TZ/DST & CRT lock wrappers. */
void rome2_vfs_crt_tzset_once(int32_t *tzset_called, uint8_t *out_ran_init);
int32_t rome2_vfs_crt_isindst_locked(int32_t tm_year, int32_t daylight_flag, uint8_t has_dst_rule);
uint32_t rome2_vfs_crt_unlock_index_for_helper(uint32_t helper_va);

/* `0x116b5e63`, `0x116b5e8c`, `0x116b5ebd`, `0x116b5fe8`, `0x116b60c7`, `0x116b657c`: locale/lconv lifecycle. */
int32_t rome2_vfs_crt_lc_time_add_ref(rome2_vfs_crt_lc_time_data180_32 *p, uint8_t is_static_c);
int32_t rome2_vfs_crt_lc_time_release_ref(rome2_vfs_crt_lc_time_data180_32 *p, uint8_t is_static_c);
uint8_t rome2_vfs_crt_lc_time_should_free(const rome2_vfs_crt_lc_time_data180_32 *p, uint8_t is_static_c);

uint32_t rome2_vfs_crt_updatetlocinfo_nolock(
    uint32_t *inout_dst_va,
    uint32_t new_loc_va,
    int32_t *new_refcount,
    int32_t *old_refcount,
    uint32_t static_initiallocinfo_va,
    uint8_t *out_should_free_old);

size_t rome2_vfs_crt_free_lconv_mon_collect(
    const rome2_vfs_crt_lconv80_32 *lconv,
    const rome2_vfs_crt_lconv80_32 *c_defaults,
    uint32_t out_ptrs[13]);

size_t rome2_vfs_crt_free_lconv_num_collect(
    const rome2_vfs_crt_lconv80_32 *lconv,
    const rome2_vfs_crt_lconv80_32 *c_defaults,
    uint32_t out_ptrs[5]);

/* `0x116bc61a` & `0x116bcfc0`: __wgetcwd probe prefix & _raise_matherr IEEE/errno dispatcher. */
void rome2_vfs_crt_wgetcwd_default_drive_probe(uint8_t drive_num, uint16_t out_probe[4]);

void rome2_vfs_crt_raise_matherr_plan(
    int32_t opcode,
    const rome2_vfs_crt_math_exception32_32 *exc,
    uint8_t handle_exc_handled,
    uint8_t has_user_matherr,
    uint8_t *out_exc_flag,
    uint8_t *out_call_raise_exc,
    uint8_t *out_set_fp_value,
    uint8_t *out_call_user_matherr,
    int32_t *out_fallback_errno);

#ifdef __cplusplus
}
#endif

#endif
