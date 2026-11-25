#ifndef ROME2_STARTUP_CRT_STRTOD_SETJMP_OPS_H
#define ROME2_STARTUP_CRT_STRTOD_SETJMP_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_crt_strtox_fp_ops.h"

/*
 * Layer 74 Partition 9 recovery:
 * 23 CRT __crt_strtox::c_string_character_source<char> FP parser, __libm_sse2_powf/pow,
 * _strtoul/_strtod/_strncpy/_strcspn/_strncat/_strcoll, and _setjmp3/_longjmp/
 * __rt_probe_read4/RtlUnwind functions (0x116982e7..0x116d7042).
 *
 * Native adaptations: bounded host/C17 models replace raw x86 stack/SEH
 * unwinding, SSE2 pow table dispatch delegates special cases + libm pow,
 * and _setjmp3 / ___longjmp_internal operate over a guest32 jump buffer model
 * with injected unwind callbacks rather than mutating live native registers.
 */

#define ROME2_L74_VC20_COOKIE 0x56433230u
#define ROME2_L74_STATUS_LONGJUMP 0x80000026u

/* 0x116982e7..0x1169896c */
rome2_l73_sld_status rome2_l74_cstr_parse_fp_double(
    const rome2_l73_locale_info *loc,
    const char *input,
    const char **out_endptr,
    double *out_val,
    int32_t *out_errno);
uint8_t rome2_l74_cstr_source_rollback(const char **cursor, char *ch, const char *saved_pos);

/* 0x1169b981, 0x1169f29b */
float rome2_l74_powf(float x, float y);
double rome2_l74_pow(double x, double y);

/* 0x1169deb3, 0x1169e3f0, 0x1169efaa, 0x1169f033, 0x1169f050, 0x1169f0a0, 0x1169f1d5, 0x1169f284 */
uint32_t rome2_l74_strtoul(const char *str, const char **endptr, int32_t radix, int32_t *out_errno);
char *rome2_l74_strncpy(char *dst, const char *src, size_t count);
double rome2_l74_strtod(const char *str, const char **endptr, const rome2_l73_locale_info *loc, int32_t *out_errno);
size_t rome2_l74_strcspn(const char *str, const char *control);
char *rome2_l74_strncat(char *dst, const char *src, size_t count);
int32_t rome2_l74_strcoll_l(
    const char *s1,
    const char *s2,
    uint32_t lcid,
    int32_t (*custom_collate)(void *user, uint32_t lcid, const char *a, const char *b),
    void *user,
    int32_t *out_errno);
int32_t rome2_l74_strcoll(const char *s1, const char *s2, int32_t *out_errno);

/* 0x116bf467, 0x116bf480, 0x116c0fcd, 0x116c1eb0, 0x116c223f, 0x116d7042 */
typedef struct rome2_l74_longjmp_env {
    void *user;
    uint32_t current_seh_frame;
    uint8_t cookie_mem_valid;
    void (*rtl_unwind)(void *user, uint32_t target_frame, uint32_t target_ip, const rome2_startup_crt_exc_record24_32 *rec);
    void (*seh4_unwind)(void *user, const rome2_startup_crt_jump_buf64_32 *jbuf);
    void (*eh3_local_unwind)(void *user, uint32_t seh_frame, uint32_t trylevel);
    void (*nlg_notify)(void *user, uint32_t target_ip, uint32_t ebp, uint32_t code);
    void (*target_transfer)(void *user, uint32_t target_ip, int32_t ret_val);
} rome2_l74_longjmp_env;

int32_t rome2_l74_setjmp3_init(
    rome2_startup_crt_jump_buf64_32 *jbuf,
    uint32_t current_seh_frame,
    uint32_t seh_trylevel,
    uint32_t eip,
    uint32_t ebp,
    uint32_t esp,
    uint32_t extra_count,
    uint32_t unwind_func,
    const uint32_t *extra_data);
uint8_t rome2_l74_except_validate_jump_buffer(const rome2_startup_crt_jump_buf64_32 *jbuf);
uint8_t rome2_l74_probe_read4(const uint32_t *addr, uint8_t simulate_fault, uint32_t *out_val);
void rome2_l74_longjmp_internal(
    const rome2_l74_longjmp_env *env,
    const rome2_startup_crt_jump_buf64_32 *jbuf,
    int32_t value);
void rome2_l74_longjmp(
    const rome2_l74_longjmp_env *env,
    const rome2_startup_crt_jump_buf64_32 *jbuf,
    int32_t value);

#endif