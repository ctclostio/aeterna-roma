#ifndef ROME2_VFS_FS_ENGINE_CRT_IO_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_IO_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_fmt_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L42_DOSERRNO_FALLBACK_VA 0x119ebe14u
#define ROME2_VFS_L42_DEFAULT_LOCINFO_VA 0x119ebf40u
#define ROME2_VFS_L42_DEFAULT_MBCINFO_VA 0x119ec210u
#define ROME2_VFS_L42_UTF8_CP 0xfde9u
#define ROME2_VFS_L42_STATUS_INVALID_CRUNTIME_PARAMETER 0xc0000417u
#define ROME2_VFS_L42_FILEX_LOCK_CS_OFFSET 0x20u
#define ROME2_VFS_L42_ERRENTRY_COUNT 45u

/* `0x100f17a0`: CA_ASCIIString(count, ch) fill constructor (empty sentinel when count == 0). */
rome2_vfs_reg_status rome2_vfs_cstr_repeat_fill(
    char fill_ch,
    uint32_t count,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len,
    uint8_t *out_used_empty_sentinel);

/* `0x11684800`: __allshl 64-bit left shift matching x86 EDX:EAX, CL behavior. */
int64_t rome2_vfs_crt_allshl(int64_t val, uint8_t shift);

/* `0x116849b0` / `0x11684a0b`: security cookie entropy XOR accumulator. */
uint32_t rome2_vfs_crt_gs_entropy_fold(
    uint32_t ft_lo,
    uint32_t ft_hi,
    uint32_t tid,
    uint32_t pid,
    uint32_t qpc_lo,
    uint32_t qpc_hi,
    uint32_t slot_addr_hint);

/* `0x11687985` & `0x11687a16`: DecodePointer32 + _invalid_parameter / __invoke_watson plan. */
uint32_t rome2_vfs_crt_decode_pointer32(uint32_t encoded, uint32_t security_cookie);

uint32_t rome2_vfs_crt_invalid_param_dispatch(
    const rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t encoded_global_handler,
    uint32_t security_cookie,
    uint32_t *out_watson_status);

/* `0x11688146`, `0x11688f63`, `0x11698f1e`, `0x11699f8f`: FILE* lock VA + _LocaleUpdate + UTF-8 check. */
uint32_t rome2_vfs_crt_file_lock_offset_va(uint32_t filex_va);

rome2_vfs_reg_status rome2_vfs_crt_locale_update_init(
    rome2_vfs_crt_locale_update16_32 *lu,
    uint8_t has_caller_locale,
    uint32_t caller_locinfo_va,
    uint32_t caller_mbcinfo_va,
    uint8_t locale_changed,
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t ptd_va);

rome2_vfs_reg_status rome2_vfs_crt_locale_update_release(
    const rome2_vfs_crt_locale_update16_32 *lu,
    rome2_vfs_crt_tiddata868_32 *ptd);

uint32_t rome2_vfs_crt_is_utf8_or_clocale(uint32_t locinfo_cp, uint32_t mb_cur_max);

/* `0x1168c741`, `0x1168eca0`, `0x1169d0e7`, `0x116a3ece`: path widen, memcpy_s, strcpy_s, strnlen. */
rome2_vfs_reg_status rome2_vfs_crt_ascii_to_utf16_path(
    const char *src,
    uint16_t *dst_w,
    size_t dst_words,
    size_t *out_written);

int32_t rome2_vfs_crt_memcpy_s(void *dst, size_t dst_cap, const void *src, size_t count);
int32_t rome2_vfs_crt_strcpy_s(char *dst, size_t dst_cap, const char *src);
size_t rome2_vfs_crt_strnlen(const char *str, size_t max_count);

/* `0x116891b2`, `0x11692dc6`, `0x11695d17`: __crt_stdio_input::input_processor<char> state loop. */
int32_t rome2_vfs_crt_stdio_input_process(
    uint8_t adapter_ok,
    uint8_t fmt_ok,
    int32_t matched_count,
    uint32_t state_mode,
    uint8_t at_eof,
    uint32_t flags,
    int32_t tracked_err,
    int32_t *out_errno);

/* `0x11698a9d` & `0x11698b03`: 45-entry _doserrno->_errno lookup table + _doserrno slot VA. */
int32_t rome2_vfs_crt_get_errno_from_oserr(uint32_t oserr);
uint32_t rome2_vfs_crt_doserrno_slot_va(uint32_t ptd_va);

/* `0x1169941c` & `0x116994a6`: _stat32i64 FindFirst epoch-1980 & handle-type classifier. */
rome2_vfs_reg_status rome2_vfs_crt_stat56_init_epoch1980(
    rome2_vfs_crt_stat56_32 *st,
    uint32_t drive_1based,
    uint16_t st_mode,
    int64_t epoch1980_unix);

uint8_t rome2_vfs_crt_stat56_classify_handle(
    rome2_vfs_crt_stat56_32 *st,
    uint32_t file_type_raw,
    uint32_t fd_num,
    uint32_t pipe_avail_bytes,
    uint32_t win32_err,
    int32_t *out_errno);

/* `0x116a1a28`, `0x116a1a94`, `0x116a1c5d`: onexit root table push & libm FPU error return. */
uint32_t rome2_vfs_crt_onexit_root_push(
    uint32_t *table,
    uint32_t cap,
    uint32_t *inout_count,
    uint32_t fn_va);

double rome2_vfs_crt_libm_err_result(
    int32_t op_code,
    int32_t mode,
    double y_res,
    uint8_t has_sse2,
    uint32_t *out_cw_mask,
    int32_t *out_errno);

/* `0x116a4789` & `0x116a5967`: __getptd_noexit slot plan & _free_crt errno-preserving failure. */
uint32_t rome2_vfs_crt_getptd_resolve(
    uint32_t fls_index,
    uint32_t existing_ptd_va,
    uint32_t alloc_ptd_va,
    uint8_t fls_set_ok,
    uint8_t *out_initialized_new,
    uint8_t *out_freed_on_fail);

void rome2_vfs_crt_free_check(
    uint8_t ptr_non_null,
    uint8_t heap_free_ok,
    uint32_t last_err,
    int32_t *out_errno);

#ifdef __cplusplus
}
#endif

#endif
