#ifndef ROME2_STARTUP_VFPRINTF_READ_OPS_H
#define ROME2_STARTUP_VFPRINTF_READ_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_sysinfo_vsprintf_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_STARTUP_L64_PRINTF_TBL_LEN   91u
#define ROME2_STARTUP_L64_IOSTRG           0x1000u

#define ROME2_STARTUP_LOWIO_FOPEN          0x01u
#define ROME2_STARTUP_LOWIO_FEOFLAG        0x02u
#define ROME2_STARTUP_LOWIO_FCRLF          0x04u
#define ROME2_STARTUP_LOWIO_FPIPE          0x08u
#define ROME2_STARTUP_LOWIO_FDEV           0x40u
#define ROME2_STARTUP_LOWIO_FTEXT          0x80u

#define ROME2_STARTUP_LOWIO_TM_ANSI        0u
#define ROME2_STARTUP_LOWIO_TM_UTF8        1u
#define ROME2_STARTUP_LOWIO_TM_UTF16LE     2u

/* -------------------------------------------------------------------------
 * 0x100edfb0 & 0x1168809c..0x1168bfab:
 * Narrow stream vfprintf / fprintf pipeline (stream_output_adapter<char> + format_validation_base)
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_fprintf_stream {
    uint32_t flags;                    /* FILE._flag (+0x0c); bit 0x1000 = _IOSTRG */
    int32_t fileno;                    /* -1 for string stream */
    uint8_t has_buffer;                /* FILE._ptr (+0x04) non-null check for _IOSTRG */
    uint8_t textmode;                  /* lowio +0x29 (0 = ANSI) */
    uint8_t utf8_crlf_flags;           /* lowio +0x2d (bit 0 = unicode) */
    char *out_buf;                     /* bounded synthetic capture buffer */
    size_t out_cap;
    size_t out_len;
    uint32_t lock_count;
    uint32_t unlock_count;
    uint8_t fail_next_write;
    int32_t simulated_write_errno;
} rome2_startup_fprintf_stream;

typedef struct rome2_startup_fprintf_processor {
    rome2_startup_nprintf_processor base;
    rome2_startup_fprintf_stream *stream;
    rome2_startup_vfprintf_stream_adapter8_32 guest_adapter;
    rome2_startup_vfprintf_lambda_ctx20_32 guest_lambda_ctx;
    uint8_t legacy_mb_leadbyte_fail;   /* mirrors ptd _ownlocale flag */
} rome2_startup_fprintf_processor;

/* `0x116892d1`: second UCRT narrow printf state table (0x1190ecd0). */
uint32_t rome2_startup_fprintf_find_next_state_116892d1(uint8_t ch, uint32_t prev_state);

/* `0x1168b848`, `0x1168b884`, `0x1168b8a6`: stream adapter & terminator validators. */
uint8_t rome2_startup_fprintf_validate_stream_flags_1168b8a6(
    const rome2_startup_fprintf_stream *stream,
    int32_t *out_errno,
    uint32_t *out_invalid_param);

uint8_t rome2_startup_fprintf_validate_adapter_1168b848(
    const rome2_startup_fprintf_processor *proc,
    int32_t *out_errno,
    uint32_t *out_invalid_param);

uint8_t rome2_startup_fprintf_validate_size_1168b884(
    const rome2_startup_fprintf_processor *proc,
    int32_t *out_errno,
    uint32_t *out_invalid_param);

/* `0x1168b9b4`, `0x11688d84`, `0x1168bc97`, `0x1168bdc7`: stream adapter writers. */
uint8_t rome2_startup_fprintf_write_char_1168b9b4(
    rome2_startup_fprintf_stream *stream,
    char ch);

void rome2_startup_fprintf_write_multi_chars_11688d84(
    rome2_startup_fprintf_stream *stream,
    char ch,
    int32_t count,
    int32_t *written_inout);

void rome2_startup_fprintf_write_string_1168bdc7(
    rome2_startup_fprintf_stream *stream,
    const char *s,
    int32_t len,
    int32_t *written_inout,
    int32_t *err_inout);

void rome2_startup_fprintf_write_string_dispatch_1168bc97(
    rome2_startup_fprintf_stream *stream,
    const char *s,
    int32_t len,
    int32_t *written_inout,
    int32_t *err_inout);

/* `0x1168ba23`: stream stored-string flush. */
uint8_t rome2_startup_fprintf_write_stored_tchar_1168ba23(
    rome2_startup_fprintf_processor *proc);

/* `0x11689e84`, `0x11689ddb`, `11689d5f`, `0x11689fa2`, `0x1168a52e`, `0x11689515`: FSM stages. */
uint8_t rome2_startup_fprintf_state_normal_tchar_11689e84(
    rome2_startup_fprintf_processor *proc);

uint8_t rome2_startup_fprintf_state_normal_common_11689ddb(
    rome2_startup_fprintf_processor *proc);

uint8_t rome2_startup_fprintf_state_normal_11689d5f(
    rome2_startup_fprintf_processor *proc);

uint8_t rome2_startup_fprintf_state_size_11689fa2(
    rome2_startup_fprintf_processor *proc);

uint8_t rome2_startup_fprintf_state_type_1168a52e(
    rome2_startup_fprintf_processor *proc);

int32_t rome2_startup_fprintf_process_11689515(
    rome2_startup_fprintf_processor *proc);

/* `0x116890f3`, `0x1168809c`, `0x116880eb`, `0x1168bfab`, `0x100edfb0`: top-level fprintf/vfprintf. */
int32_t rome2_startup_vfprintf_lambda_116890f3(
    rome2_startup_fprintf_stream *stream,
    uint64_t options,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno,
    uint32_t *out_invalid_param);

void rome2_startup_vfprintf_unlock_116880eb(
    rome2_startup_fprintf_stream *stream);

int32_t rome2_startup_vfprintf_guarded_lock_1168809c(
    rome2_startup_fprintf_stream *stream,
    uint64_t options,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno,
    uint32_t *out_invalid_param);

int32_t rome2_startup_common_vfprintf_char_1168bfab(
    uint64_t options,
    rome2_startup_fprintf_stream *stream,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno,
    uint32_t *out_invalid_param);

int32_t rome2_startup_crt_fprintf_100edfb0(
    rome2_startup_fprintf_stream *stream,
    const char *fmt,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno,
    uint32_t *out_invalid_param);

/* -------------------------------------------------------------------------
 * 0x116aa9e2..0x116aaffa:
 * Lowio _read / _read_nolock & text/UTF-8/UTF-16LE translators
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_lowio_read_device {
    rome2_startup_crt_ioinfo_read56_32 ioinfo;
    const uint8_t *raw_bytes;
    size_t raw_len;
    size_t raw_pos;
    uint8_t is_tty;                    /* _isatty() != 0 */
    uint8_t is_console_handle;         /* GetConsoleMode() != 0 */
    uint32_t forced_win32_error;       /* e.g. 5=ERROR_ACCESS_DENIED, 109=ERROR_BROKEN_PIPE */
    uint32_t lock_count;
    uint32_t unlock_count;
    int32_t last_errno;
    uint32_t last_doserrno;
    uint32_t invalid_param_count;
} rome2_startup_lowio_read_device;

/* `0x116aa9e2`: narrow CR-LF -> LF and Ctrl-Z (^Z) text-mode translator. */
uint32_t rome2_startup_crt_translate_text_char_116aa9e2(
    rome2_startup_lowio_read_device *dev,
    uint8_t *buf,
    uint32_t bytes_read);

/* `0x116aab43`: wide UTF-16LE CR-LF -> LF and Ctrl-Z text-mode translator. */
uint32_t rome2_startup_crt_translate_text_wchar_116aab43(
    rome2_startup_lowio_read_device *dev,
    uint16_t *wbuf,
    uint32_t wchar_count);

/* `0x116aad14`: UTF-8 text-mode -> UTF-16LE translator with partial-sequence lookahead. */
int32_t rome2_startup_crt_translate_utf8_to_utf16_116aad14(
    rome2_startup_lowio_read_device *dev,
    uint8_t *raw_buf,
    uint32_t bytes_read,
    uint16_t *out_wbuf,
    uint32_t out_wchars);

/* `0x116aae6b`: ReadConsoleW UTF-16LE CR-LF -> LF / ^Z translator. */
uint32_t rome2_startup_crt_translate_utf16_crlf_116aae6b(
    rome2_startup_lowio_read_device *dev,
    uint16_t *wbuf,
    uint32_t wchar_count);

/* `0x116aaffa`, `0x116aafc7`, `0x116aaee6`: lowio _read_nolock, unlock, and locked _read. */
int32_t rome2_startup_crt_read_nolock_116aaffa(
    int32_t fh,
    rome2_startup_lowio_read_device *dev,
    void *dst_buf,
    uint32_t count);

void rome2_startup_crt_read_unlock_116aafc7(
    rome2_startup_lowio_read_device *dev);

int32_t rome2_startup_crt_read_116aaee6(
    int32_t fh,
    rome2_startup_lowio_read_device *dev,
    void *dst_buf,
    uint32_t count);

#ifdef __cplusplus
}
#endif

#endif
