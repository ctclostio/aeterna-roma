#ifndef ROME2_VFS_FS_ENGINE_CRT_FLS_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_FLS_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

/* `0x116847e0`: __aullshr unsigned 64-bit right shift. */
uint64_t rome2_vfs_crt_aullshr(uint64_t value, uint8_t shift);

/* `0x116d7120`: __alldvrm signed 64-bit truncating quotient + remainder. */
uint8_t rome2_vfs_crt_alldvrm(
    int64_t dividend,
    int64_t divisor,
    int64_t *out_quotient,
    int64_t *out_remainder);

/* `0x1168aeb3`: __crt_stdio_output::to_integer_size switch dispatcher. */
uint32_t rome2_vfs_crt_to_integer_size(uint32_t length_modifier);

/* `0x1168bcc3`: stream_output_adapter<wchar_t>::write_string callback & result. */
typedef uint8_t (*rome2_vfs_crt_wput_fn)(uint16_t wch, void *ctx, int32_t *out_errno);

void rome2_vfs_crt_wstream_write_string(
    const rome2_vfs_crt_stdio_stream56_32 *stream,
    const uint16_t *str,
    int32_t len,
    int32_t *inout_chars_written,
    rome2_vfs_crt_wput_fn put_fn,
    void *put_ctx,
    int32_t *out_errno);

/* `0x1168d407`: __crt_strtox::parse_integer<uint32, c_string_character_source<char>>. */
uint32_t rome2_vfs_crt_parse_uint32(
    const char *str,
    size_t *out_end_offset,
    int32_t base,
    uint8_t is_signed,
    int32_t *out_errno);

/* `0x11695ee2`: __crt_stdio_input::input_processor<char>::process_conversion_specifier. */
typedef struct rome2_vfs_crt_scanf_conv_action {
    uint8_t valid;
    uint8_t kind;        /* 0=invalid, 1=char(c), 2=string(s), 3=scanset([), 4=int, 5=float, 6=count(n) */
    uint8_t is_signed;
    uint8_t base;        /* 0, 8, 10, 16 */
    uint32_t mode_arg;   /* e.g. 0, 1, 8, or base */
} rome2_vfs_crt_scanf_conv_action;

uint8_t rome2_vfs_crt_scanf_dispatch_conversion(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    rome2_vfs_crt_scanf_conv_action *out_action);

/* `0x1169ecd8`: _getenv_s bounded environment lookup. */
typedef struct rome2_vfs_crt_env_kv {
    const char *name;
    const char *value;
} rome2_vfs_crt_env_kv;

int32_t rome2_vfs_crt_getenv_s(
    size_t *out_required_bytes,
    char *buf,
    size_t buf_cap,
    const char *varname,
    const rome2_vfs_crt_env_kv *env_entries,
    size_t env_count,
    int32_t *out_errno);

/* `0x116a5864` & `0x116a586f`: UCRT _flsbuf / _flswbuf state transitions. */
typedef uint8_t (*rome2_vfs_crt_stream_seek0_fn)(
    rome2_vfs_crt_stdio_stream56_32 *stream,
    void *ctx);

typedef uint8_t (*rome2_vfs_crt_stream_write_unit_fn)(
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint32_t unit,
    void *ctx);

int32_t rome2_vfs_crt_flsbuf(
    int32_t ch,
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t is_std_err_or_out_tty,
    rome2_vfs_crt_stream_seek0_fn seek_fn,
    rome2_vfs_crt_stream_write_unit_fn write_fn,
    void *ctx,
    int32_t *out_errno);

uint16_t rome2_vfs_crt_flswbuf(
    uint16_t wch,
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t is_std_err_or_out_tty,
    rome2_vfs_crt_stream_seek0_fn seek_fn,
    rome2_vfs_crt_stream_write_unit_fn write_fn,
    void *ctx,
    int32_t *out_errno);

/* `0x116a5b4b`: __wctomb_s_l bounded locale wchar->mb converter. */
int32_t rome2_vfs_crt_wctomb_s_l(
    int32_t *out_converted,
    uint8_t *mbchar,
    size_t size_in_bytes,
    uint16_t wchar,
    uint32_t codepage,
    uint8_t is_c_locale,
    int32_t *out_errno);

/* `0x116a613a` & `0x116a630d`: UCRT internal %e/%E and %f/%F float formatters. */
int32_t rome2_vfs_crt_fp_format_e_internal(
    char *result_buf,
    size_t buf_cap,
    int32_t precision,
    uint8_t cap_exp,
    uint32_t min_exponent_digits,
    const rome2_vfs_crt_strflt12_32 *strflt,
    const char *digits_buf,
    uint8_t g_mode,
    char decimal_point,
    int32_t *out_errno);

int32_t rome2_vfs_crt_fp_format_f_internal(
    char *result_buf,
    size_t buf_cap,
    int32_t precision,
    const rome2_vfs_crt_strflt12_32 *strflt,
    uint8_t g_mode,
    char decimal_point,
    int32_t *out_errno);

/* `0x116a83bd` & `0x116a8a8d`: try_get_LCMapStringEx descriptor scan & LocaleNameToLCID dispatch. */
typedef uint32_t (*rome2_vfs_crt_resolve_api_fn)(
    uint32_t table_slot,
    const char *api_name,
    const rome2_vfs_crt_api_mod_desc8_32 *begin_desc,
    const rome2_vfs_crt_api_mod_desc8_32 *end_desc,
    void *ctx);

uint32_t rome2_vfs_crt_try_get_lcmapstring_ex(
    rome2_vfs_crt_resolve_api_fn resolve_fn,
    void *ctx);

uint32_t rome2_vfs_crt_locale_name_to_lcid(
    const uint16_t *locale_name,
    uint32_t flags,
    uint8_t has_modern_api,
    uint32_t modern_lcid,
    uint32_t downlevel_lcid);

/* `0x116b149d`: __crt_mbstring::return_illegal_sequence clearing mbstate_t and setting EILSEQ. */
uint32_t rome2_vfs_crt_return_illegal_sequence(
    rome2_vfs_crt_mbstate8_32 *ps,
    int32_t *out_errno);

/* `0x116b8215`: ___acrt_GetStringTypeW CT_CTYPE1 classifier mirror. */
uint8_t rome2_vfs_crt_get_string_type_w(
    uint32_t dw_info_type,
    const uint16_t *src_str,
    int32_t cch_src,
    uint16_t *char_type_out);

/* `0x116bd4d3` & `0x116bd511`: CONOUT$ handle lifecycle. */
typedef uint32_t (*rome2_vfs_crt_open_conout_fn)(const uint16_t *device_name, void *ctx);
typedef uint8_t (*rome2_vfs_crt_close_handle_fn)(uint32_t handle, void *ctx);

void rome2_vfs_crt_console_output_init(
    uint32_t *out_console_handle,
    rome2_vfs_crt_open_conout_fn open_fn,
    void *ctx);

uint8_t rome2_vfs_crt_console_output_terminate(
    uint32_t console_handle,
    rome2_vfs_crt_close_handle_fn close_fn,
    void *ctx);

/* `0x116bf330`: strrchr scanning backward/last match under ISA dispatch hint. */
const char *rome2_vfs_crt_strrchr(
    const char *str,
    size_t max_len,
    int32_t ch,
    uint32_t isa_available);

#ifdef __cplusplus
}
#endif

#endif
