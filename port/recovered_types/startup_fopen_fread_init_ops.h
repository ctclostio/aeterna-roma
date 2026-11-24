#ifndef ROME2_STARTUP_FOPEN_FREAD_INIT_OPS_H
#define ROME2_STARTUP_FOPEN_FREAD_INIT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_stdio_stream_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_STARTUP_L66_MAX_PIOB          32u
#define ROME2_STARTUP_L66_STREAM_BUF_CAP    512u
#define ROME2_STARTUP_L66_IOALLOCATED       0x2000u
#define ROME2_STARTUP_L66_IOEOF             0x0008u
#define ROME2_STARTUP_L66_IOERR             0x0010u
#define ROME2_STARTUP_L66_IOYOURBUF         0x0100u
#define ROME2_STARTUP_L66_IOMYBUF           0x0040u
#define ROME2_STARTUP_L66_IOSETVBUF         0x0400u
#define ROME2_STARTUP_L66_INTSAFE_E_OVERFLOW 0x80070216u

typedef struct rome2_startup_l66_stream {
    rome2_startup_crt_iobuf_full56_32 guest;
    uint8_t buf[ROME2_STARTUP_L66_STREAM_BUF_CAP];
    size_t cursor_off;
    size_t valid_len;
    size_t bufsiz;
    uint32_t lock_depth;
    uint8_t is_locked_once;
} rome2_startup_l66_stream;

typedef struct rome2_startup_l66_env {
    rome2_startup_l65_crt_env io;
    rome2_startup_l66_stream *piob[ROME2_STARTUP_L66_MAX_PIOB];
    uint32_t nstream;
    uint32_t stdio_table_lock_count;
    uint32_t stdio_table_unlock_count;
    uint8_t fail_stream_calloc;
    uint8_t exit_called;
    int32_t exit_code;
    uint8_t manifest_mismatch_flag;
} rome2_startup_l66_env;

typedef struct rome2_startup_l66_file_box {
    rome2_startup_engine_file_box8_32 guest;
    rome2_startup_l66_stream *stream;
} rome2_startup_l66_file_box;

typedef struct rome2_startup_l66_disk_entry {
    const char *rel_path;
    uint64_t size_bytes;
} rome2_startup_l66_disk_entry;

void rome2_startup_l66_env_init(rome2_startup_l66_env *env);
void rome2_startup_l66_env_destroy(rome2_startup_l66_env *env);

/* `0x11684670`: CRT __alldiv (stdcall 64-bit signed division). */
int64_t rome2_startup_crt_alldiv_11684670(int64_t numerator, int64_t denominator);

/* `0x11699fb7`: CRT LongLongSub overflow-checked subtraction. */
int32_t rome2_startup_crt_longlongsub_11699fb7(int64_t a, int64_t b, int64_t *out);

/* `0x1168d37f`: CRT _exit. */
void rome2_startup_crt_exit_1168d37f(rome2_startup_l66_env *env, int32_t code);

/* `0x116aa25b`, `0x116aa1b7`, `0x116aa217`: stdio FILE* slot allocation & SEH unlock. */
rome2_startup_l66_stream *rome2_startup_crt_find_or_alloc_stream_nolock_116aa25b(rome2_startup_l66_env *env);
rome2_startup_l66_stream *rome2_startup_crt_stdio_allocate_stream_116aa1b7(rome2_startup_l66_env *env);
void rome2_startup_crt_stdio_alloc_unlock_116aa217(rome2_startup_l66_env *env);

/* `0x1168e7d7`, `0x1168e877`, `0x116aa9cc`, `0x1168e9a2`, `0x1168e9b9`: narrow fsopen / fopen / fopen_s. */
rome2_startup_l66_stream *rome2_startup_crt_common_openfile_char_thunk_116aa9cc(
    rome2_startup_l66_env *env,
    const char *filename,
    const char *mode,
    int32_t shflag,
    rome2_startup_l66_stream *stream);
void rome2_startup_crt_fsopen_cleanup_char_1168e877(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int32_t opened_ok);
rome2_startup_l66_stream *rome2_startup_crt_common_fsopen_char_1168e7d7(
    rome2_startup_l66_env *env,
    const char *filename,
    const char *mode,
    int32_t shflag);
rome2_startup_l66_stream *rome2_startup_crt_fopen_1168e9a2(
    rome2_startup_l66_env *env,
    const char *filename,
    const char *mode);
int32_t rome2_startup_crt_fopen_s_1168e9b9(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream **out_stream,
    const char *filename,
    const char *mode);

/* `0x1168e88e`, `0x1168e92d`, `0x116aa9d7`, `0x1168e95b`: wide fsopen / _wfopen_s. */
rome2_startup_l66_stream *rome2_startup_crt_common_openfile_wchar_thunk_116aa9d7(
    rome2_startup_l66_env *env,
    const uint16_t *filename,
    const uint16_t *mode,
    int32_t shflag,
    rome2_startup_l66_stream *stream);
void rome2_startup_crt_fsopen_cleanup_wchar_1168e92d(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int32_t opened_ok);
rome2_startup_l66_stream *rome2_startup_crt_common_fsopen_wchar_1168e88e(
    rome2_startup_l66_env *env,
    const uint16_t *filename,
    const uint16_t *mode,
    int32_t shflag);
int32_t rome2_startup_crt_wfopen_s_1168e95b(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream **out_stream,
    const uint16_t *filename,
    const uint16_t *mode);

/* `0x116ab3aa`, `0x116ab534`, `0x1168ea00`, `0x1168ec03`, `0x1168ec98`: stream refill & fread_s. */
int32_t rome2_startup_crt_refill_and_read_nolock_116ab3aa(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream);
int32_t rome2_startup_crt_refill_and_read_thunk_116ab534(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream);
size_t rome2_startup_crt_fread_nolock_s_1168ea00(
    rome2_startup_l66_env *env,
    void *dst_buf,
    size_t dst_size,
    size_t elem_size,
    size_t count,
    rome2_startup_l66_stream *stream);
size_t rome2_startup_crt_fread_s_1168ec03(
    rome2_startup_l66_env *env,
    void *dst_buf,
    size_t dst_size,
    size_t elem_size,
    size_t count,
    rome2_startup_l66_stream *stream);
void rome2_startup_crt_fread_unlock_1168ec98(rome2_startup_l66_stream *stream);

/* `0x1169a0bc`, `0x1169a195`, `0x1169a031`, `0x1169a0b2`, `0x1169a28e`: fseek stack. */
uint8_t rome2_startup_crt_fseek_fast_track_nolock_1169a0bc(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t offset,
    int32_t origin);
int32_t rome2_startup_crt_common_fseek_nolock_1169a195(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t offset,
    int32_t origin);
int32_t rome2_startup_crt_common_fseek_1169a031(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t offset,
    int32_t origin);
void rome2_startup_crt_fseek_unlock_1169a0b2(rome2_startup_l66_stream *stream);
int32_t rome2_startup_crt_fseek_1169a28e(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int32_t offset,
    int32_t origin);

/* `0x1169a8a1`, `0x1169a708`, `0x1169a549`, `0x1169a3c5`, `0x1169a92a`: ftell stack. */
int64_t rome2_startup_crt_count_newline_bytes_1169a8a1(
    const uint8_t *begin,
    const uint8_t *end,
    uint8_t textmode);
int64_t rome2_startup_crt_ftell_utf8_nolock_1169a708(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t raw_pos);
int64_t rome2_startup_crt_ftell_read_mode_nolock_1169a549(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t file_pos,
    int64_t rd_off);
int64_t rome2_startup_crt_ftell_i64_nolock_1169a3c5(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream);
int64_t rome2_startup_crt_ftell_i32_thunk_1169a92a(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream);

/* `0x1011fee0`, `0x100f21a0`, `0x10104a70`, `0x100edc70`, `0x100edcd0`, `0x113471f0`, `0x100e2980`: engine wrappers & manifest check. */
void rome2_startup_engine_file_box_init_1011fee0(rome2_startup_l66_file_box *box);
void rome2_startup_engine_file_box_close_100f21a0(rome2_startup_l66_env *env, rome2_startup_l66_file_box *box);
uint8_t rome2_startup_engine_file_box_open_10104a70(
    rome2_startup_l66_env *env,
    rome2_startup_l66_file_box *box,
    const char *path,
    uint8_t append_flag);
size_t rome2_startup_engine_file_box_write_100edc70(
    rome2_startup_l66_env *env,
    rome2_startup_l66_file_box *box,
    const void *buf,
    size_t len);
void rome2_startup_engine_exit_with_telemetry_100edcd0(
    rome2_startup_l66_env *env,
    const char *log_path,
    int32_t exit_code);
rome2_startup_l66_stream *rome2_startup_engine_fiopen_113471f0(
    rome2_startup_l66_env *env,
    const uint16_t *path,
    uint32_t ios_openmode);
void rome2_startup_engine_verify_data_manifest_100e2980(
    rome2_startup_l66_env *env,
    const char *exe_path,
    const char *manifest_rel_path,
    const char *log_path,
    const rome2_startup_l66_disk_entry *disk_files,
    size_t disk_file_count,
    uint8_t user_script_exists,
    char *out_log,
    size_t out_log_cap);

#ifdef __cplusplus
}
#endif

#endif
