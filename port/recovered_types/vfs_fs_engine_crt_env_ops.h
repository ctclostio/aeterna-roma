#ifndef ROME2_VFS_FS_ENGINE_CRT_ENV_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_ENV_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_flt_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L45_EILSEQ_MSVC 42
#define ROME2_VFS_L45_STDIO_IOERR_BIT 0x10u
#define ROME2_VFS_L45_STDIO_IORW_BIT 0x04u
#define ROME2_VFS_L45_STDIO_IOWRT_BIT 0x02u
#define ROME2_VFS_L45_STDIO_IOMASK_RW 0x03u
#define ROME2_VFS_L45_STDIO_BUFFER_BITS 0xc0u
#define ROME2_VFS_L45_ISSPACE_MASK 0x0008u
#define ROME2_VFS_L45_LEADBYTE_FLAG 0x8000u
#define ROME2_VFS_L45_CRTLOCK_TABLE_VA 0x12125da8u
#define ROME2_VFS_L45_LOCK_STRIDE_BYTES 0x18u
#define ROME2_VFS_L45_ARE_FILE_APIS_ANSI_ID 0u
#define ROME2_VFS_L45_FP_SW_INVALID 0x00000010u
#define ROME2_VFS_L45_FP_SW_ZERODIVIDE 0x00000008u
#define ROME2_VFS_L45_FP_SW_OVERFLOW 0x00000004u
#define ROME2_VFS_L45_FP_SW_UNDERFLOW 0x00000002u
#define ROME2_VFS_L45_FP_SW_INEXACT 0x00000001u
#define ROME2_VFS_L45_FP_SW_DENORMAL 0x00080000u

/* `0x11687d0f`: ___acrt_stdio_flush_nolock buffering state update and error propagation. */
int32_t rome2_vfs_crt_stdio_flush_nolock(
    rome2_vfs_crt_filex56_32 *stream,
    int32_t write_rc,
    uint32_t *out_pending_bytes);

/* `0x1168c7fb` & `0x116a59a1`: win32_buffer dynamic resize alloc & __malloc_base plan. */
uint8_t rome2_vfs_crt_malloc_plan(
    uint32_t size_bytes,
    uint32_t *out_alloc_bytes,
    int32_t *out_errno);

int32_t rome2_vfs_crt_win32_buffer_dyn_alloc(
    uint32_t *out_ptr_va,
    uint32_t size_bytes,
    uint32_t heap_alloc_va,
    int32_t *out_errno);

/* `0x116967fd`, `0x11696ac0`, `0x11696d09`, `0x11696d5b`:
 * format_string_parser<char> width, length modifier, trail byte, and wide modifier scans.
 */
uint8_t rome2_vfs_crt_fmt_scan_field_width(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len);

void rome2_vfs_crt_fmt_scan_length_modifier(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len);

uint8_t rome2_vfs_crt_fmt_scan_trail_bytes(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    uint16_t lead_ctype,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len);

void rome2_vfs_crt_fmt_scan_wide_modifier(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len);

/* `0x11699757`, `0x11699900`, `0x11699953`, `0x11699b38`: path/drive helpers. */
uint32_t rome2_vfs_crt_call_wfullpath_select(
    uint32_t fixed_res_va,
    int32_t internal_errno,
    uint32_t dyn_res_va,
    int32_t caller_errno,
    int32_t *out_errno);

uint8_t rome2_vfs_crt_is_root_or_empty_w(const uint16_t *wpath);
uint8_t rome2_vfs_crt_is_root_unc_name_w(const uint16_t *wpath);

int32_t rome2_vfs_crt_getdrive_from_cwd_w(
    const uint16_t *cwd_w,
    uint32_t cwd_req_len,
    uint8_t heap_alloc_ok,
    int32_t *out_errno);

/* `0x1169af6a`, `0x116ad990`, `0x116adb6d`, `0x116adba8`, `0x116adc01`: FP control/status & _decomp. */
uint32_t rome2_vfs_crt_clearfp_sw(
    uint16_t x87_sw,
    uint32_t mxcsr,
    int32_t sse2_isa_level,
    uint32_t *out_next_mxcsr);

double rome2_vfs_crt_fp_decomp(double x, int32_t *out_exp);
int32_t rome2_vfs_crt_signext_sw16(uint16_t sw);
uint16_t rome2_vfs_crt_raise_fp_status_bits(uint32_t exc_mask);

/* `0x1169e350` & `0x116a53f0`: _isspace dispatch & __fileno. */
uint8_t rome2_vfs_crt_isspace_dispatch(
    uint8_t locale_changed,
    int32_t ch,
    uint16_t ctype_flags,
    uint8_t locale_result);

int32_t rome2_vfs_crt_fileno(const rome2_vfs_crt_filex56_32 *stream, int32_t *out_errno);

/* `0x116a1819`, `0x116a1825`, `0x116a24dd`, `0x116a42c8`, `0x116a43da`: locks, onexit vector grow, & ref retain. */
uint32_t rome2_vfs_crt_lock_slot_va(int32_t lock_id);

uint32_t rome2_vfs_crt_encode_pointer32(uint32_t ptr_va, uint32_t security_cookie);

int32_t rome2_vfs_crt_onexit_append_step(
    rome2_vfs_crt_onexit_table12_32 *tbl,
    uint32_t fn_va,
    uint32_t security_cookie,
    uint8_t grow_primary_ok,
    uint8_t grow_fallback_ok,
    uint32_t new_base_va,
    uint32_t *out_new_capacity,
    uint32_t *out_written_slot_enc);

uint8_t rome2_vfs_crt_retain_mbc_ref(
    const rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t *inout_mbc_refcount,
    uint32_t *out_mbcinfo_va);

uint8_t rome2_vfs_crt_retain_locale_ref(
    uint32_t *out_locinfo_ptr_va,
    uint32_t global_locinfo_va);

/* `0x116a82d3` & `0x116a84d2`: encoded Win32 API cache resolver (`try_get_function`). */
uint32_t rome2_vfs_crt_try_get_function_slot(
    uint32_t *inout_encoded_slot,
    uint32_t security_cookie,
    uint8_t module_ok,
    uint32_t proc_va,
    uint8_t *out_resolved_fresh);

uint32_t rome2_vfs_crt_try_get_are_file_apis_ansi(
    uint32_t *table_base_encoded,
    uint32_t table_len,
    uint32_t security_cookie,
    uint8_t module_ok,
    uint32_t proc_va,
    uint8_t *out_resolved_fresh);

#ifdef __cplusplus
}
#endif

#endif
