#ifndef ROME2_STARTUP_CRT_STRTOX_FP_OPS_H
#define ROME2_STARTUP_CRT_STRTOX_FP_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

/*
 * Layer 73 Partition 9 recovery:
 * 35 indexed CRT __crt_strtox / __crt_stdio_input / fegetround functions
 * (0x1168f0d4..0x116b89b1, including decimal big-integer parser 0x11693706
 * and jump target 0x11695ffa) plus the 9-byte non-indexed tail 0x11695e3c
 * entered from 0x11695ee2.
 *
 * Native adaptations: IEEE-754 bit patterns are assembled with explicit uint32/uint64
 * memcpy stores into caller float/double slots, big-integer arithmetic uses
 * bounded limb arrays (max 115 words), and host <fenv.h> / errno are avoided
 * where injected callbacks or explicit out-parameters suffice.
 */

typedef enum rome2_l73_sld_status {
    ROME2_L73_SLD_OK = 0,
    ROME2_L73_SLD_UNDERFLOW = 1,
    ROME2_L73_SLD_OVERFLOW = 2,
    ROME2_L73_SLD_NODIGITS = 3
} rome2_l73_sld_status;

typedef enum rome2_l73_fp_parse_kind {
    ROME2_L73_FP_NODIGITS = 0,
    ROME2_L73_FP_DECIMAL = 1,
    ROME2_L73_FP_HEXADECIMAL = 2,
    ROME2_L73_FP_ZERO = 3,
    ROME2_L73_FP_INFINITY = 4,
    ROME2_L73_FP_QNAN = 5,
    ROME2_L73_FP_IND = 6,
    ROME2_L73_FP_SNAN = 7
} rome2_l73_fp_parse_kind;

typedef struct rome2_l73_fp_target {
    uint8_t is_double;
    float *f_out;
    double *d_out;
} rome2_l73_fp_target;

typedef struct rome2_l73_char_source {
    const char *buf;
    size_t len;
    size_t pos;
    uint64_t width_limit;
    uint64_t consumed;
} rome2_l73_char_source;

typedef struct rome2_l73_locale_info {
    char decimal_point;
    uint32_t round_mode;                         /* FE_TONEAREST=0, FE_DOWNWARD=0x100, FE_UPWARD=0x200, FE_TOWARDZERO=0x300 */
    uint32_t reset_gle_calls;
} rome2_l73_locale_info;

/* 0x1168f0d4, 0x1168f0f5, 0x1168f125, 0x1169316a, 0x1169318f, 0x116931b4, 0x116936d1 */
void rome2_l73_assemble_snan_double(uint8_t is_negative, double *out);
rome2_l73_sld_status rome2_l73_assemble_fp_float(uint8_t is_negative, int32_t exp_val, uint64_t mantissa, float *out);
rome2_l73_sld_status rome2_l73_assemble_fp_double(uint8_t is_negative, int32_t exp_val, uint64_t mantissa, double *out);
void rome2_l73_assemble_infinity(uint8_t is_negative, const rome2_l73_fp_target *target);
void rome2_l73_assemble_zero(uint8_t is_negative, const rome2_l73_fp_target *target);
uint64_t rome2_l73_denormal_mantissa_mask(uint8_t is_double);
uint64_t rome2_l73_normal_mantissa_mask(uint8_t is_double);

/* 0x1169353d, 0x116931f4 */
rome2_l73_sld_status rome2_l73_assemble_fp_value(
    uint64_t mantissa,
    int32_t exp_val,
    uint8_t is_negative,
    uint8_t has_zero_tail,
    uint32_t round_mode,
    const rome2_l73_fp_target *target);
rome2_l73_sld_status rome2_l73_assemble_fp_from_big_integer(
    const rome2_startup_crt_big_int464_32 *bi,
    uint32_t bits_count,
    uint8_t is_negative,
    uint8_t has_zero_tail,
    uint32_t round_mode,
    const rome2_l73_fp_target *target);

/* 0x11695540 */
uint64_t rome2_l73_big_int_divide(
    rome2_startup_crt_big_int464_32 *numerator,
    const rome2_startup_crt_big_int464_32 *denominator);

/* 0x1168f2b4, 0x1168f2d5, 0x1168f2f6, 0x1168f317, 0x11693706, 0x11695445 */
rome2_l73_sld_status rome2_l73_convert_decimal_common(
    const rome2_startup_crt_fp_string780_32 *fp_str,
    uint32_t round_mode,
    const rome2_l73_fp_target *target);
rome2_l73_sld_status rome2_l73_convert_hex_common(
    const rome2_startup_crt_fp_string780_32 *fp_str,
    uint32_t round_mode,
    const rome2_l73_fp_target *target);

/* 0x1168fa89, 0x11690ba7, 0x11690e4e, 0x116910d4, 0x11691188, 0x11691202 */
uint8_t rome2_l73_possible_nan_is_ind(char *ch, rome2_l73_char_source *src);
uint8_t rome2_l73_possible_nan_is_snan(char *ch, rome2_l73_char_source *src);
uint8_t rome2_l73_possible_nan_is_char_seq(char *ch, rome2_l73_char_source *src);
rome2_l73_fp_parse_kind rome2_l73_parse_possible_infinity(char *ch, rome2_l73_char_source *src);
rome2_l73_fp_parse_kind rome2_l73_parse_possible_nan(char *ch, rome2_l73_char_source *src);
rome2_l73_fp_parse_kind rome2_l73_parse_fp_from_source(
    const rome2_l73_locale_info *loc,
    rome2_l73_char_source *src,
    rome2_startup_crt_fp_string780_32 *out_str);

/* 0x1168f448, 0x1168f4c1, 0x1169136e */
rome2_l73_sld_status rome2_l73_write_fp_parse_result(
    rome2_l73_fp_parse_kind kind,
    const rome2_startup_crt_fp_string780_32 *fp_str,
    uint32_t round_mode,
    const rome2_l73_fp_target *target);
rome2_l73_sld_status rome2_l73_parse_floating_point_string(
    const rome2_l73_locale_info *loc,
    const char *input,
    const rome2_l73_fp_target *target,
    const char **out_endptr,
    int32_t *out_errno);

/* 0x1169206a, 0x1169219c, 0x11692bae, 0x11692c50, 0x11692f24, 0x11695e3c, 0x11695ffa, 0x11696481 */
void rome2_l73_process_whitespace(rome2_l73_char_source *src);
uint8_t rome2_l73_process_literal_tail(
    uint8_t suppress_assignment,
    const char *match,
    char *out_buf,
    size_t out_cap);
uint8_t rome2_l73_process_fp_specifier(
    const rome2_startup_crt_input_proc112_32 *proc,
    const rome2_l73_locale_info *loc,
    rome2_l73_char_source *src,
    const rome2_l73_fp_target *target,
    int32_t *out_errno);
void rome2_l73_scope_cleanup_guard(
    rome2_l73_locale_info *loc,
    rome2_l73_char_source *src,
    uint8_t *dirty_flag);

/* 0x116ab791, 0x116b89b1 */
uint32_t rome2_l73_fenv_get_common_round_control(uint32_t mxcsr_or_cw, uint8_t use_sse);
uint32_t rome2_l73_fegetround(uint32_t round_control_bits);

#endif