#ifndef ROME2_VFS_FS_ENGINE_CRT_SCANF_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_SCANF_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

/* `0x1168f338`: make_input_adapter_character_source 32B descriptor setup. */
rome2_vfs_crt_input_char_source32_32 *rome2_vfs_crt_make_input_char_source(
    rome2_vfs_crt_input_char_source32_32 *out_src,
    uint32_t adapter_ptr,
    uint64_t width_limit,
    uint32_t ok_flag_slot);

/* `0x11691750`: parse_integer<uint64, input_adapter_character_source<char>>. */
uint64_t rome2_vfs_crt_parse_uint64_adapter(
    const char *str,
    size_t max_chars,
    size_t *out_consumed,
    int32_t base,
    uint8_t is_signed,
    uint8_t *out_succeeded,
    int32_t *out_errno);

/* `0x11695bf3`: format_string_parser<char>::length() target byte width. */
uint32_t rome2_vfs_crt_scanf_format_length(
    const rome2_vfs_crt_fmt_parser76_32 *fmt);

/* `0x116974ef`: input_processor<char>::write_integer(uint64 value). */
uint8_t rome2_vfs_crt_scanf_write_integer(
    const rome2_vfs_crt_fmt_parser76_32 *fmt,
    void *target_ptr,
    uint64_t value,
    int32_t *out_errno);

/* `0x116960bc`: input_processor<char>::process_integer_specifier(base, is_signed). */
uint8_t rome2_vfs_crt_scanf_process_integer_specifier(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    const char *stream_text,
    size_t *inout_cursor,
    size_t max_len,
    int32_t base,
    uint8_t is_signed,
    void *out_value,
    int32_t *out_errno);

/* `0x116923d9`, `0x11692817`, `0x116963d4`: scanf string/char/scanset processors. */
uint8_t rome2_vfs_crt_scanf_process_string_narrow(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    const char *stream_text,
    size_t *inout_cursor,
    size_t max_len,
    uint32_t mode,
    uint8_t is_whitespace_delimited,
    char *out_buf,
    size_t out_cap,
    int32_t *out_errno);

uint8_t rome2_vfs_crt_scanf_process_string_wide(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    const char *stream_text,
    size_t *inout_cursor,
    size_t max_len,
    uint32_t mode,
    uint8_t is_whitespace_delimited,
    uint16_t *out_buf,
    size_t out_cap_wchars,
    int32_t *out_errno);

uint8_t rome2_vfs_crt_scanf_process_string_specifier(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    const char *stream_text,
    size_t *inout_cursor,
    size_t max_len,
    uint32_t mode,
    void *out_buf,
    size_t out_cap_units,
    int32_t *out_errno);

/* `0x1169e7db`: _lseeki64 forwarder. */
typedef int64_t (*rome2_vfs_crt_lseeki64_fn)(int32_t fh, int64_t offset, int32_t origin, void *ctx);

int64_t rome2_vfs_crt_lseeki64_forward(
    int32_t fh,
    int64_t offset,
    int32_t origin,
    rome2_vfs_crt_lseeki64_fn impl_fn,
    void *ctx);

/* `0x1169e998`, `0x1169eadf`, `0x1169eb47`: getenv_nolock, lock-11 unlock thunk & getenv_s_nolock. */
const char *rome2_vfs_crt_common_getenv_nolock(
    const char *varname,
    const char *const *envp,
    size_t env_count);

typedef void (*rome2_vfs_crt_unlock_fn)(uint32_t lock_idx, void *ctx);

void rome2_vfs_crt_getenv_seh_unlock(
    rome2_vfs_crt_unlock_fn unlock_fn,
    void *ctx);

int32_t rome2_vfs_crt_common_getenv_s_nolock(
    size_t *out_required_bytes,
    char *buf,
    size_t size_in_bytes,
    const char *varname,
    const char *const *envp,
    size_t env_count,
    int32_t *out_errno);

/* `0x116a5645` & `0x116a5711`: write_buffer_nolock<char> & <wchar_t>. */
typedef int32_t (*rome2_vfs_crt_lowio_write_fn)(
    int32_t fh,
    const void *buf,
    uint32_t byte_count,
    void *ctx);

typedef int64_t (*rome2_vfs_crt_lowio_seek_fn)(
    int32_t fh,
    int64_t offset,
    int32_t origin,
    void *ctx);

uint8_t rome2_vfs_crt_write_buffer_nolock_char(
    uint8_t ch,
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t *host_buf,
    size_t host_buf_cap,
    size_t *inout_pos,
    uint8_t is_append_mode,
    rome2_vfs_crt_lowio_seek_fn seek_fn,
    rome2_vfs_crt_lowio_write_fn write_fn,
    void *ctx);

uint8_t rome2_vfs_crt_write_buffer_nolock_wchar(
    uint16_t wch,
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t *host_buf,
    size_t host_buf_cap,
    size_t *inout_pos,
    uint8_t is_append_mode,
    rome2_vfs_crt_lowio_seek_fn seek_fn,
    rome2_vfs_crt_lowio_write_fn write_fn,
    void *ctx);

/* `0x116a57df`: is_at_eof_for_write_transition. */
uint8_t rome2_vfs_crt_is_at_eof_for_write_transition(
    const rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t has_valid_os_handle,
    uint8_t seek_ok,
    int64_t current_pos,
    uint8_t size_ok,
    int64_t file_size);

/* `0x116a6534`: fp_shift_bytes_right. */
void rome2_vfs_crt_fp_shift_bytes_right(
    char *buf,
    size_t buf_cap,
    size_t start_off,
    size_t count);

/* `0x116a83d7`: try_get_LocaleNameToLCID. */
typedef uint32_t (*rome2_vfs_crt_resolve_api54_fn)(
    uint32_t table_slot,
    const char *api_name,
    const rome2_vfs_crt_api_mod_desc8_32 *begin_desc,
    const rome2_vfs_crt_api_mod_desc8_32 *end_marker,
    void *ctx);

uint32_t rome2_vfs_crt_try_get_locale_name_to_lcid(
    rome2_vfs_crt_resolve_api54_fn resolve_fn,
    void *ctx);

/* `0x116b14bc`: __crt_mbstring::__c32rtomb_utf8. */
uint32_t rome2_vfs_crt_c32rtomb_utf8(
    uint8_t *dst,
    size_t dst_cap,
    uint32_t c32,
    rome2_vfs_crt_mbstate8_32 *ps,
    int32_t *out_errno);

/* `0x116b1c0d`: __acrt_stdio_allocate_buffer_nolock. */
void rome2_vfs_crt_stdio_allocate_buffer_nolock(
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint32_t allocated_buf_guest_ptr,
    uint32_t inline_charbuf_guest_ptr,
    uint32_t *inout_cflush);

/* `0x116b80ef` & `0x116b81e9`: downlevel locale binary search and LCID lookup. */
typedef struct rome2_vfs_crt_locale_entry_pair {
    const uint16_t *name;
    int32_t table_idx;
    uint32_t lcid;
} rome2_vfs_crt_locale_entry_pair;

int32_t rome2_vfs_crt_downlevel_locale_index(
    const uint16_t *name,
    const rome2_vfs_crt_locale_entry_pair *sorted_entries,
    size_t entry_count);

uint32_t rome2_vfs_crt_downlevel_locale_name_to_lcid(
    const uint16_t *name,
    const rome2_vfs_crt_locale_entry_pair *sorted_entries,
    const uint32_t *lcid_by_idx,
    size_t entry_count);

#ifdef __cplusplus
}
#endif

#endif
