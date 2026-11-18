#ifndef ROME2_VFS_FS_ENGINE_CRT_FLT_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_FLT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_sec_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L44_ENOMEM_MSVC 12
#define ROME2_VFS_L44_EINVAL_MSVC 22
#define ROME2_VFS_L44_ERANGE_MSVC 34
#define ROME2_VFS_L44_STDIO_TMPBUF_SIZE 0x1000u
#define ROME2_VFS_L44_STDIO_BLOCK_MASK 0x4c0u
#define ROME2_VFS_L44_STDIO_TMPBUF_FLAGS 0x282u
#define ROME2_VFS_L44_STDIO_ALLOCATED_BIT 0x200u
#define ROME2_VFS_L44_FLS_GET_VALUE_API 5u
#define ROME2_VFS_L44_FLS_SET_VALUE_API 6u
#define ROME2_VFS_L44_OUTPUT_ADAPTER_BASE_SIZE 0x448u

/* 1096B (0x448) __crt_stdio_output::common_data<wchar_t> zero-init core (`0x11688ea1`). */
typedef struct rome2_vfs_crt_output_adapter_base {
    uint32_t header_dwords_00[11]; /* 00..2b */
    uint8_t pad_2c[4];             /* 2c..2f */
    uint8_t byte_30;               /* 30 */
    uint8_t pad_31;                /* 31 */
    uint16_t word_32;              /* 32 */
    uint8_t pad_34[4];             /* 34..37 */
    uint32_t dword_38;             /* 38 */
    uint8_t byte_3c;               /* 3c */
    uint8_t inline_buf_3d[0x403];  /* 3d..43f */
    uint32_t dword_440;            /* 440 */
    uint32_t dword_444;            /* 444 */
} rome2_vfs_crt_output_adapter_base;

/* `0x1168499d`: clear 4-byte guard flag. */
void rome2_vfs_crt_clear_u32_flag(uint32_t *flag);

/* `0x11688ea1`: __crt_stdio_output::common_data<wchar_t> base ctor. */
rome2_vfs_crt_output_adapter_base *rome2_vfs_crt_output_adapter_base_init(
    rome2_vfs_crt_output_adapter_base *self);

/* `0x1168c77b` & `0x1168c7bc`: __crt_win32_buffer<wchar_t>::deallocate & allocate. */
uint8_t rome2_vfs_crt_win32_buffer_deallocate(
    rome2_vfs_crt_win32_buffer24_32 *buf,
    uint32_t *out_freed_va);

int32_t rome2_vfs_crt_win32_buffer_alloc_wchar(
    rome2_vfs_crt_win32_buffer24_32 *buf,
    uint32_t count_words,
    int32_t alloc_err,
    uint32_t alloc_va,
    uint32_t *out_freed_va,
    uint32_t *out_alloc_bytes);

/* `0x1168d0a8`: CRT _free delegating wrapper. */
void rome2_vfs_crt_free_wrap(
    uint8_t ptr_non_null,
    uint8_t heap_free_ok,
    uint32_t last_err,
    int32_t *out_errno);

/* `0x116996a1`: __crt_integer_traits<__int64>::loctotime pointer-deref adapter. */
uint8_t rome2_vfs_crt_unpack_loctotime_args(
    const uint16_t *yr,
    const uint16_t *mon,
    const uint16_t *day,
    const uint16_t *hr,
    const uint16_t *min,
    const uint16_t *sec,
    const int32_t *isdst,
    uint32_t out_args[7]);

/* `0x116a4632`: ___acrt_getptd (aborting getptd wrapper). */
uint32_t rome2_vfs_crt_getptd_or_abort(
    uint32_t fls_index,
    uint32_t existing_ptd_va,
    uint32_t alloc_ptd_va,
    uint8_t fls_set_ok,
    uint8_t *out_initialized_new,
    uint8_t *out_freed_on_fail,
    uint8_t *out_aborted);

/* `0x116a587a` & `0x116a592d`: stdio temporary buffering begin / end nolock. */
uint8_t rome2_vfs_crt_stdio_begin_tmpbuf_nolock(
    rome2_vfs_crt_filex56_32 *stream,
    uint32_t stream_va,
    uint8_t is_tty,
    uint32_t stream_slot,
    uint32_t *inout_cflush,
    uint32_t *inout_slot_buf_va,
    uint32_t alloc_buf_va);

uint8_t rome2_vfs_crt_stdio_end_tmpbuf_nolock(
    uint8_t enabled_flag,
    rome2_vfs_crt_filex56_32 *stream);

/* `0x116a5cc3` & `0x116a5cf0`: ___acrt_update_locale_info & ___acrt_update_multibyte_info. */
uint8_t rome2_vfs_crt_sync_ptd_global_slot(
    const rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t per_thread_flag_mask,
    uint32_t global_va,
    uint32_t refreshed_va,
    uint32_t *inout_slot_va);

/* `0x116a5d1d` & `0x116ada8f`: __acrt_fp_classify & __sptype IEEE-754 double classifiers. */
int32_t rome2_vfs_crt_fp_classify_bits(uint64_t f64_bits);
int32_t rome2_vfs_crt_fp_classify_ptr(const double *px);
int32_t rome2_vfs_crt_sptype_bits(uint64_t f64_bits);
int32_t rome2_vfs_crt_sptype_f64(double x);

/* `0x116a80f2`: ___acrt_MultiByteToWideChar dwFlags sanitizer. */
uint32_t rome2_vfs_crt_normalize_mbtowc_flags(uint32_t code_page, uint32_t dw_flags);

/* `0x116a85d5`, `0x116a8723`, `0x116a8762`: ___acrt_AreFileApisANSI & FLS dispatchers. */
uint32_t rome2_vfs_crt_are_file_apis_ansi_dispatch(
    uint32_t resolved_proc_va,
    uint32_t invoked_result,
    uint8_t *out_invoked);

uint8_t rome2_vfs_crt_fls_dispatch_mode(
    uint32_t api_id,
    uint32_t resolved_proc_va,
    uint8_t *out_cfg_checked);

/* `0x116a8dad`: ___acrt_fp_strflt_to_string digit formatting & carry rounding. */
int32_t rome2_vfs_crt_fp_strflt_to_string(
    char *buf,
    size_t size_in_bytes,
    int32_t digits,
    rome2_vfs_crt_strflt12_32 *flt,
    const char *src_digits,
    int32_t *out_errno);

/* `0x116ab734`: __calloc_base overflow guard & zero-size clamp. */
uint8_t rome2_vfs_crt_calloc_plan(
    uint32_t count,
    uint32_t elem_size,
    uint32_t *out_alloc_bytes,
    int32_t *out_errno);

/* `0x116adb7e`: __ctrlfp masked x87 control word update. */
int32_t rome2_vfs_crt_ctrlfp(
    uint16_t current_cw,
    uint32_t new_val,
    uint32_t mask,
    uint16_t *out_next_cw);

/* `0x116b5880`: ___acrt_has_user_matherr encoded-pointer check. */
uint8_t rome2_vfs_crt_has_user_matherr(uint32_t encoded_handler, uint32_t security_cookie);

/* `0x116b822e`, `0x116b824b`, `0x116b8296`: fegetenv, fesetenv, feholdexcept. */
int32_t rome2_vfs_crt_fegetenv(rome2_vfs_crt_fp_env8_32 *env, uint32_t w0, uint32_t w1);

int32_t rome2_vfs_crt_fesetenv_verify(
    const rome2_vfs_crt_fp_env8_32 *target,
    int32_t readback_rc,
    const rome2_vfs_crt_fp_env8_32 *readback);

int32_t rome2_vfs_crt_feholdexcept(
    const rome2_vfs_crt_fp_env8_32 *current,
    rome2_vfs_crt_fp_env8_32 *out_saved,
    int32_t apply_verify_rc,
    uint32_t *out_masked_w0,
    uint8_t *out_cleared_fp);

/* `0x116b82f0` & `0x116bcc58`: libm SSE2 fast-path check & __frnd round-to-even. */
uint8_t rome2_vfs_crt_libm_use_sse2_fastpath(
    uint32_t sse2_enabled,
    uint32_t mxcsr,
    uint16_t x87_cw);

double rome2_vfs_crt_frnd(double x);

#ifdef __cplusplus
}
#endif

#endif
