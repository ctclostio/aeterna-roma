#ifndef ROME2_STARTUP_HANDLER_STDIO_CLOSE_OPS_H
#define ROME2_STARTUP_HANDLER_STDIO_CLOSE_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_app_ctor_timing_ops.h"
#include "vfs_archive_register.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_STARTUP_CRT_MAX_FDS 64u
#define ROME2_STARTUP_CRT_MAX_FREED 16u
#define ROME2_STARTUP_CRT_MAX_CLOSED_HANDLES 16u
#define ROME2_STARTUP_CRT_STREAM_BUF_CAP 64u

#define ROME2_STARTUP_VTABLE_BASE_ADAPTER 0x1173db9cu
#define ROME2_STARTUP_VTABLE_SINGLETON_385C 0x1173f2e4u
#define ROME2_STARTUP_VTABLE_CRASH_SLOT04 0x1173f2d4u
#define ROME2_STARTUP_VTABLE_VFS_SLOT50 0x1173f22cu
#define ROME2_STARTUP_VTABLE_CRASH_SLOTS_2C 0x1173f2bcu

#define ROME2_STARTUP_CRT_EBADF 9
#define ROME2_STARTUP_CRT_EINVAL 22
#define ROME2_STARTUP_CRT_INVALID_HANDLE 0xffffffffu
#define ROME2_STARTUP_STD_INPUT_HANDLE 0xfffffff6u
#define ROME2_STARTUP_STD_OUTPUT_HANDLE 0xfffffff5u
#define ROME2_STARTUP_STD_ERROR_HANDLE 0xfffffff4u

#define ROME2_STARTUP_IOFILE_FOPEN 0x01u
#define ROME2_STARTUP_IOEOF 0x0008u
#define ROME2_STARTUP_IOERR 0x0010u
#define ROME2_STARTUP_IOBUFFER_CRT 0x0040u
#define ROME2_STARTUP_IOBUFFER_USER 0x0080u
#define ROME2_STARTUP_IOBUFFER_NONE 0x0400u
#define ROME2_STARTUP_IOSTRG 0x1000u
#define ROME2_STARTUP_IOALLOCATED 0x2000u
#define ROME2_STARTUP_IOREAD 0x0001u

#define ROME2_STARTUP_LOG_END_LITERAL "End Logging\r\n"
#define ROME2_STARTUP_LOG_END_LEN 13u
#define ROME2_STARTUP_LOG_EOF_SENTINEL 0x26
#define ROME2_STARTUP_MAX_OBS_DESTROY_SLOTS 32u

typedef struct rome2_startup_crt_stream_model {
    rome2_vfs_crt_stdio_stream56_32 guest;
    uint8_t buffer[ROME2_STARTUP_CRT_STREAM_BUF_CAP];
    size_t buffer_cursor;
    uint8_t sink[256];
    size_t sink_len;
    uint8_t fail_write;
    uint8_t fail_flush;
    uint8_t simulate_eof_on_error;
} rome2_startup_crt_stream_model;

typedef struct rome2_startup_crt_stdio_env {
    rome2_startup_crt_ioinfo56_32 io_slots[ROME2_STARTUP_CRT_MAX_FDS];
    uint32_t nhandle;                  /* [0x12126118] */
    uint32_t std_handle_free_policy;   /* [0x12126338] read by 0x116bc6d8 */
    int32_t last_errno;
    uint32_t last_doserrno;
    uint32_t invalid_param_calls;      /* 0x116879e9 */
    uint32_t lock_file_calls;          /* 0x11699f8f */
    uint32_t unlock_file_calls;        /* 0x11699fa3 */
    uint32_t flock_lock_calls;         /* 0x116a587a */
    uint32_t flock_unlock_calls;       /* 0x116a592d */
    uint32_t lock_fhandle_calls;       /* 0x116ae7dd */
    uint32_t unlock_fhandle_calls;     /* 0x116ae892 */
    uint32_t set_std_handle_calls;     /* [0x1172f0bc] */
    uint32_t last_std_handle_id;
    uint32_t last_std_handle_value;
    uint32_t close_handle_calls;
    uint32_t closed_handles[ROME2_STARTUP_CRT_MAX_CLOSED_HANDLES];
    uint32_t closed_handle_count;
    uint32_t fail_close_os_handle;     /* non-zero triggers GetLastError() capture */
    uint32_t simulated_last_error;
    uint32_t freed_vas[ROME2_STARTUP_CRT_MAX_FREED];
    uint32_t freed_va_count;
} rome2_startup_crt_stdio_env;

/* `0x116bc6d8` */
uint32_t rome2_startup_crt_get_std_handle_policy_116bc6d8(
    const rome2_startup_crt_stdio_env *env);

/* `0x116ae9c8` */
int32_t rome2_startup_crt_free_osfhnd_116ae9c8(
    rome2_startup_crt_stdio_env *env,
    int32_t fh);

/* `0x116ab658` */
int32_t rome2_startup_crt_close_nolock_116ab658(
    rome2_startup_crt_stdio_env *env,
    int32_t fh);

/* `0x116ab5bf` */
void rome2_startup_crt_seh_close_unlock_116ab5bf(
    rome2_startup_crt_stdio_env *env,
    int32_t fh);

/* `0x116ab53f` */
int32_t rome2_startup_crt_seh_guarded_call_close_116ab53f(
    rome2_startup_crt_stdio_env *env,
    int32_t fh);

/* `0x116ab5cb` */
int32_t rome2_startup_crt_close_116ab5cb(
    rome2_startup_crt_stdio_env *env,
    int32_t fh);

/* `0x116aa220` */
void rome2_startup_crt_stdio_free_stream_116aa220(
    rome2_startup_crt_stream_model *stream);

/* `0x116ab6f4` */
void rome2_startup_crt_stdio_free_buffer_nolock_116ab6f4(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream);

/* `0x1168ed21` */
int32_t rome2_startup_crt_fclose_nolock_1168ed21(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream);

/* `0x1168ee12` */
void rome2_startup_crt_seh_fclose_unlock_1168ee12(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream);

/* `0x1168ed98` */
int32_t rome2_startup_crt_fclose_1168ed98(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream);

/* `0x11687a7a` */
int32_t rome2_startup_crt_feof_11687a7a(
    rome2_startup_crt_stdio_env *env,
    const rome2_startup_crt_stream_model *stream);

/* `0x11687eb8` */
size_t rome2_startup_crt_fwrite_nolock_11687eb8(
    rome2_startup_crt_stdio_env *env,
    const void *buf,
    size_t elem_size,
    size_t elem_count,
    rome2_startup_crt_stream_model *stream);

/* `0x11687e75` */
size_t rome2_startup_crt_fwrite_lambda_11687e75(
    rome2_startup_crt_stdio_env *env,
    const rome2_startup_fwrite_capture16_32 *capture_layout,
    const void *buf,
    size_t elem_size,
    size_t elem_count,
    rome2_startup_crt_stream_model *stream);

/* `0x11687e69` */
void rome2_startup_crt_seh_fwrite_unlock_11687e69(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream);

/* `0x11687e1a` */
size_t rome2_startup_crt_seh_guarded_call_fwrite_11687e1a(
    rome2_startup_crt_stdio_env *env,
    const void *buf,
    size_t elem_size,
    size_t elem_count,
    rome2_startup_crt_stream_model *stream);

/* `0x11688039` */
size_t rome2_startup_crt_fwrite_11688039(
    rome2_startup_crt_stdio_env *env,
    const void *buf,
    size_t elem_size,
    size_t elem_count,
    rome2_startup_crt_stream_model *stream);

/* -------------------------------------------------------------------------
 * 0x100d3620, 0x100e7690, 0x10121170, 0x100e32e0: App teardown & log close
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_app_teardown_buffers {
    uint32_t ptr_088;
    uint32_t ptr_094;
    uint32_t ptr_0a0;
    uint32_t ptr_0d4;
    uint32_t ptr_0e0;
    uint32_t freed_vas[8];
    uint32_t freed_count;
} rome2_startup_app_teardown_buffers;

typedef struct rome2_startup_app_observer_array {
    uint32_t slot_vas[ROME2_STARTUP_MAX_OBS_DESTROY_SLOTS];
    uint32_t active_count;             /* [this+0x86c] */
    uint32_t destroyed_vas[ROME2_STARTUP_MAX_OBS_DESTROY_SLOTS];
    uint32_t destroyed_flags[ROME2_STARTUP_MAX_OBS_DESTROY_SLOTS];
    uint32_t destroyed_count;
} rome2_startup_app_observer_array;

typedef struct rome2_startup_app_log_state {
    rome2_startup_log_file_box8_32 box;
    uint32_t box_va;                   /* [this+0x89c] */
    rome2_startup_crt_stream_model *open_stream;
    uint32_t freed_box_vas[4];
    uint32_t freed_box_count;
} rome2_startup_app_log_state;

/* `0x100d3620` */
void rome2_startup_app_cleanup_five_buffers_100d3620(
    rome2_startup_app_teardown_buffers *buffers);

/* `0x100e7690` */
void rome2_startup_app_destroy_observer_slots_100e7690(
    rome2_startup_app_observer_array *arr);

/* `0x10121170` */
uint8_t rome2_startup_log_file_box_close_10121170(
    rome2_startup_app_log_state *log_state,
    rome2_startup_crt_stdio_env *crt_env);

/* `0x100e32e0` */
uint8_t rome2_startup_app_close_log_100e32e0(
    rome2_startup_app_log_state *log_state,
    rome2_startup_crt_stdio_env *crt_env);

/* -------------------------------------------------------------------------
 * 0x100d38b0, 0x100e14d0, 0x100e16a0, 0x100e1820, 0x100e1a70,
 * 0x100e85d0, 0x100e8be0, 0x100e8e50, 0x100e9230, 0x100ea040:
 * Startup handler vtable slot0 / slot1 methods
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_handler_dispatch_env {
    uint32_t singleton_119f385c;       /* [0x119f385c] cleared by 0x100e14d0 */
    uint32_t crash_slot04;             /* [crash+0x04] cleared by 0x100e16a0 */
    uint32_t crash_slot24;             /* [crash+0x24] cleared by 0x100e1a70 */
    uint32_t crash_slot28;             /* [crash+0x28] cleared by 0x100e1a70 */
    uint32_t crash_slot2c;             /* [crash+0x2c] cleared by 0x100e1a70 */
    uint32_t destroyed_targets[8];
    uint32_t destroyed_count;
    uint32_t freed_handler_vas[8];
    uint32_t freed_handler_count;
    uint32_t vtable_trace[8];
    uint32_t vtable_trace_count;
    uint32_t vfs_slot50_calls;
    uint8_t vfs_slot08_ready;
    uint32_t vfs_slot08_calls;
    uint8_t vfs_slot58_ready;
    uint32_t vfs_slot58_calls;
    uint32_t vfs_slot54_arg;
    uint32_t vfs_slot54_calls;
    uint32_t crash_vslot104_obj;
    uint32_t crash_vslot104_calls;
    uint32_t crash_vslot68_calls;
    uint32_t crash_vslot344_calls;
    uint32_t flag_100d6560_last_arg;
    uint32_t flag_100d6560_calls;
    rome2_startup_timing_report_env *timing_env;
} rome2_startup_handler_dispatch_env;

/* `0x100d38b0` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_scalar_dtor_base_100d38b0(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env);

/* `0x100e14d0` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_singleton_dtor_100e14d0(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env);

/* `0x100e16a0` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_crash_slot04_dtor_100e16a0(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env);

/* `0x100e1820` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_vfs_slot50_dtor_100e1820(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env);

/* `0x100e1a70` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_crash_slots_2c_28_24_dtor_100e1a70(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env);

/* `0x100e85d0` */
uint8_t rome2_startup_handler_clear_flag_100e85d0(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va);

/* `0x100e8be0` */
uint8_t rome2_startup_handler_crash_vslot104_vslot68_100e8be0(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va);

/* `0x100e8e50` */
uint8_t rome2_startup_handler_vfs_load_release_100e8e50(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va);

/* `0x100e9230` */
uint8_t rome2_startup_handler_vfs_start_100e9230(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va);

/* `0x100ea040` */
uint8_t rome2_startup_handler_crash_vslot344_100ea040(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va);

#ifdef __cplusplus
}
#endif

#endif
