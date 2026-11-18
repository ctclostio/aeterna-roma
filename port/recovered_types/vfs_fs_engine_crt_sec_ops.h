#ifndef ROME2_VFS_FS_ENGINE_CRT_SEC_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_SEC_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_io_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L43_XCPT_ACT_TAB_VA 0x11913628u
#define ROME2_VFS_L43_DEFAULT_MBCINFO_VA 0x119ec210u
#define ROME2_VFS_L43_FMT_COMPAT_ROWS 10u
#define ROME2_VFS_L43_FMT_COMPAT_COLS 12u
#define ROME2_VFS_L43_UMATHERR_OP_COUNT 29u
#define ROME2_VFS_L43_EOVERFLOW_MSVC 0x84

/* `0x11683dd0` & `0x11684b3c`: __chkstk target/page-probe plan & @__security_check_cookie@4. */
uint32_t rome2_vfs_crt_chkstk_plan(
    uint32_t stack_top,
    uint32_t alloc_bytes,
    uint32_t *out_touched_pages);

uint8_t rome2_vfs_crt_security_check_cookie(uint32_t ecx_cookie, uint32_t global_cookie);

/* `0x1168783d`: __raise_securityfailure populating Win32 EXCEPTION_RECORD + EXCEPTION_POINTERS. */
rome2_vfs_reg_status rome2_vfs_crt_raise_secfail_record_init(
    rome2_vfs_win32_exception_record80_32 *rec,
    rome2_vfs_win32_exception_pointers8_32 *ptrs,
    uint32_t exc_code,
    uint32_t exc_flags,
    uint32_t caller_ip,
    uint32_t rec_va,
    uint32_t ctx_va);

/* `0x11688f27`, `0x11688ff6`, `0x11692cc4`, `0x11692f4e`, `0x11695a8d`, `0x11697274`, `0x116972b9`, `0x116972f6`:
 * __crt_stdio_input adapter & format parser helpers.
 */
typedef struct rome2_vfs_crt_string_input_adapter {
    const char *begin;
    const char *end;
    const char *cur;
} rome2_vfs_crt_string_input_adapter;

int32_t rome2_vfs_crt_string_input_get(rome2_vfs_crt_string_input_adapter *ad);
void rome2_vfs_crt_string_input_unget(rome2_vfs_crt_string_input_adapter *ad, int32_t ch);
uint8_t rome2_vfs_crt_string_input_validate(const rome2_vfs_crt_string_input_adapter *ad, int32_t *out_errno);
uint8_t rome2_vfs_crt_fmt_parser_validate(const rome2_vfs_crt_fmt_parser76_32 *fp, int32_t *out_errno);

rome2_vfs_reg_status rome2_vfs_crt_fmt_parser_init(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    uint32_t locinfo_va,
    uint32_t state_val,
    uint32_t fmt_va);

uint8_t rome2_vfs_crt_fmt_compat_allowed(uint32_t conv_idx, uint32_t length_idx);

uint8_t rome2_vfs_crt_fmt_parser_advance(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len);

/* `0x1168c5c8`: __acrt_mbs_to_wcs_cp internal buffer converter. */
int32_t rome2_vfs_crt_mbs_to_wcs_cp(
    const char *src,
    uint16_t *dst_w,
    size_t dst_cap_words,
    size_t *out_len_words,
    int32_t *out_errno);

/* `0x1169961a`, `0x116997b7`, `0x116997f6`, `0x116998a4`, `0x11699a41`, `0x11699fa3`: stat64 & FILE unlock. */
int64_t rome2_vfs_crt_filetime_or_fallback(
    uint32_t ft_lo,
    uint32_t ft_hi,
    int64_t fallback_unix,
    uint8_t sys_time_ok,
    int64_t converted_unix);

uint8_t rome2_vfs_crt_stat_store_size64(
    uint32_t size_hi,
    uint32_t size_lo,
    int64_t *out_size,
    int32_t *out_errno);

uint16_t rome2_vfs_crt_dtoxmode_w(uint32_t dw_file_attrs, uint8_t is_root_dir, const char *path_ext_ascii);

uint8_t rome2_vfs_crt_extract_drive_w(
    const uint16_t *wpath,
    uint32_t fallback_drive,
    uint32_t *out_drive,
    int32_t *out_errno);

uint8_t rome2_vfs_crt_validate_stat_path_w(
    const uint16_t *wpath,
    uint8_t has_dot_or_slash,
    uint32_t full_len,
    uint8_t root_unc_valid,
    uint32_t drive_type);

uint32_t rome2_vfs_crt_file_unlock_offset_va(uint32_t filex_va);

/* `0x116a17ca`, `0x116a1c29`, `0x116a1e0d`, `0x116a2028`, `0x116a231e`, `0x116a234d`, `0x116a4434`:
 * CRT onexit core, FP exception dispatch/matherr, & __initptd.
 */
uint32_t rome2_vfs_crt_fp_exc_to_matherr_type(uint32_t fp_flags);

uint8_t rome2_vfs_crt_handle_exc_f64(
    uint32_t exc_flags,
    double *inout_val,
    uint32_t fp_cw,
    uint8_t frexp_ok,
    uint32_t *out_cleared_mask);

void rome2_vfs_crt_errcode_set_errno(uint32_t matherr_type, int32_t *out_errno);

uint32_t rome2_vfs_crt_raise_exc_map_code(
    uint32_t exc_flags,
    uint32_t *out_cause_bits);

uint32_t rome2_vfs_crt_umatherr_lookup_name_va(int32_t op_code);

rome2_vfs_reg_status rome2_vfs_crt_initptd(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t *out_holdrand,
    uint32_t *out_xcptacttab_va,
    uint32_t *out_ptmbcinfo_va);

#ifdef __cplusplus
}
#endif

#endif
