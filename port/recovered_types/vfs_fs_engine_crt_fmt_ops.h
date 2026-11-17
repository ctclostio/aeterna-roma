#ifndef ROME2_VFS_FS_ENGINE_CRT_FMT_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_FMT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L41_STRNICMP_MAX 0x7fffffffu
#define ROME2_VFS_L41_IOB_ERRNO_VA 0x119ebe10u
#define ROME2_VFS_L41_LIBM_STAT_EDOM 1
#define ROME2_VFS_L41_LIBM_STAT_ERANGE 2

typedef struct rome2_vfs_i10_out_result {
    char sign_ch;
    uint8_t zero_flag;
    int32_t decpt;
    char digits[32];
} rome2_vfs_i10_out_result;

typedef struct rome2_vfs_crt_stat56_summary {
    uint32_t mode;
    uint64_t size_bytes;
    uint64_t mtime_unix;
} rome2_vfs_crt_stat56_summary;

/* `0x100ee800` & `0x100f5d40`: ASCII %c scanner and const char* (%s/%S) format dispatcher. */
rome2_vfs_reg_status rome2_vfs_format_scan_char_cstr(
    const char *fmt,
    uint32_t fmt_len,
    uint16_t *inout_pos,
    char ch_val,
    char *out_cstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok);

rome2_vfs_reg_status rome2_vfs_format_cstr_arg(
    char spec_ch,
    const char *arg_s,
    uint16_t min_width,
    uint8_t left_align,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok);

/* `0x100f2cc0`, `0x101002b0`, `0x10100380`, `0x10104d70`: CA_ASCIIString formatters/padders. */
rome2_vfs_reg_status rome2_vfs_cstr_prepend_char(
    char prefix_ch,
    const char *src,
    uint32_t src_len,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_cstr_format_uint32_base(
    uint32_t val,
    uint32_t radix,
    const char *digits,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_cstr_format_uint32_dec(
    uint32_t val,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_cstr_pad_aligned(
    const char *src,
    uint32_t src_len,
    uint16_t min_width,
    uint8_t left_align,
    char pad_ch,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len);

/* `0x10fba190` & `0x10fdec30`: sliding timestamp queue eviction and Steam EP2PSend mapper. */
rome2_vfs_reg_status rome2_vfs_ts_queue_trim_expired(
    rome2_vfs_ts_sample_queue *q,
    uint32_t window_secs,
    uint32_t now_ms,
    uint32_t *out_evicted);

uint32_t rome2_vfs_steam_map_send_type(int8_t mode);

/* `0x116838bd`, `0x11683aba`, `0x116839e8`: CRT onexit slot & MSVC static init wait/footer. */
uint32_t rome2_vfs_crt_onexit_append(
    uint32_t *table,
    uint32_t cap,
    uint32_t *inout_count,
    uint32_t fn_va);

rome2_vfs_reg_status rome2_vfs_crt_init_thread_wait(
    const int32_t *guard,
    uint32_t timeout_ms,
    uint8_t *out_timed_out);

rome2_vfs_reg_status rome2_vfs_crt_init_thread_footer(
    int32_t *inout_guard,
    int32_t *inout_tls_epoch,
    int32_t *inout_global_epoch,
    uint8_t *out_signaled);

/* `0x116879e9`, `0x11698ae0`, `0x11698b16`: invalid parameter, dosmaperr, errno fallback VA. */
int32_t rome2_vfs_crt_dosmaperr(uint32_t win32_err, int32_t *out_doserrno);
uint32_t rome2_vfs_crt_errno_slot_va(uint32_t ptd_va);

/* `0x116880f7`, `0x1168f167`, `0x116b85db`: bounded stdio workers and _strnicmp_l. */
int32_t rome2_vfs_crt_strnicmp_l(
    const char *s1,
    const char *s2,
    size_t max_count,
    int32_t *out_errno);

/* `0x1168e69c` & `0x116a8e6d`: $I10_OUTPUT double formatting & _ecvt digit clamp helper. */
rome2_vfs_reg_status rome2_vfs_crt_i10_output_f64(
    double x,
    int32_t ndigits,
    uint8_t dec_mode,
    rome2_vfs_i10_out_result *out);

int32_t rome2_vfs_crt_fcvt_format_buf(
    char *buf,
    size_t cap,
    const rome2_vfs_i10_out_result *i10,
    int32_t ndigit,
    int32_t *out_decpt,
    int32_t *out_sign);

/* `0x11699af7`, `0x11699b02`, `0x1169b55f`, `0x1169b5ed`: _stat32i64 & CRT thread params20. */
int32_t rome2_vfs_crt_stat56_validate_and_zero(
    const char *path,
    rome2_vfs_crt_stat56_summary *out_stat,
    int32_t *out_errno);

rome2_vfs_reg_status rome2_vfs_crt_thread_param20_init(
    rome2_vfs_crt_thread_param20_32 *blk,
    uint32_t start_addr_va,
    uint32_t arg_va,
    uint32_t thread_handle_va,
    uint32_t module_handle_va);

rome2_vfs_reg_status rome2_vfs_crt_thread_param20_release(
    rome2_vfs_crt_thread_param20_32 *blk,
    uint8_t *out_closed_thread,
    uint8_t *out_freed_module);

/* `0x116b0763`: libm _handle_error exception classification. */
const char *rome2_vfs_crt_libm_handle_error(
    int32_t op_code,
    int32_t *out_errno,
    int32_t *out_exc_type);

/* `0x116bd8d0` & `0x116bde50`: CRT memcpy & overlap-safe memmove. */
void *rome2_vfs_crt_memcpy(void *dst, const void *src, size_t n);
void *rome2_vfs_crt_memmove(void *dst, const void *src, size_t n);

#ifdef __cplusplus
}
#endif

#endif
