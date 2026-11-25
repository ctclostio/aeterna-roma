#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "startup_crt_strtox_fp_ops.h"

static uint64_t dbl_bits(double d) {
    uint64_t u = 0u;
    memcpy(&u, &d, sizeof(u));
    return u;
}

static uint32_t flt_bits(float f) {
    uint32_t u = 0u;
    memcpy(&u, &f, sizeof(u));
    return u;
}

int main(void) {
    rome2_l73_locale_info loc;
    rome2_l73_fp_target f_tgt;
    rome2_l73_fp_target d_tgt;
    rome2_startup_crt_fp_string780_32 fp_str;
    rome2_startup_crt_big_int464_32 bi_num;
    rome2_startup_crt_big_int464_32 bi_den;
    rome2_l73_char_source src;
    rome2_startup_crt_input_proc112_32 iproc;
    float f_val = 0.0f;
    double d_val = 0.0;
    const char *endp = NULL;
    int32_t err = 0;
    uint32_t checks = 0u;
    char lit_buf[16];
    uint8_t dirty = 1u;

    memset(&loc, 0, sizeof(loc));
    loc.decimal_point = '.';
    loc.round_mode = 0u;

    f_tgt.is_double = 0u;
    f_tgt.f_out = &f_val;
    f_tgt.d_out = NULL;

    d_tgt.is_double = 1u;
    d_tgt.f_out = NULL;
    d_tgt.d_out = &d_val;

    /* 1. Low-level IEEE assembly helpers */
    rome2_l73_assemble_snan_double(1u, &d_val);
    assert(dbl_bits(d_val) == 0xfff0000000000001ULL);
    assert(rome2_l73_assemble_fp_float(0u, 1, 0x400000ULL, &f_val) == ROME2_L73_SLD_OK);
    assert(flt_bits(f_val) == 0x40400000u); /* 3.0f */
    assert(rome2_l73_assemble_fp_double(1u, 2, 0x8000000000000ULL, &d_val) == ROME2_L73_SLD_OK);
    assert(dbl_bits(d_val) == 0xc018000000000000ULL); /* -6.0 */
    assert(rome2_l73_denormal_mantissa_mask(0u) == 0x7fffffULL);
    assert(rome2_l73_denormal_mantissa_mask(1u) == 0xfffffffffffffULL);
    assert(rome2_l73_normal_mantissa_mask(0u) == 0xffffffULL);
    assert(rome2_l73_normal_mantissa_mask(1u) == 0x1fffffffffffffULL);
    rome2_l73_assemble_infinity(1u, &f_tgt);
    assert(flt_bits(f_val) == 0xff800000u);
    rome2_l73_assemble_zero(1u, &d_tgt);
    assert(dbl_bits(d_val) == 0x8000000000000000ULL);
    checks += 9u;

    /* 2. big_int_divide (0x11695540) */
    memset(&bi_num, 0, sizeof(bi_num));
    memset(&bi_den, 0, sizeof(bi_den));
    bi_num.used_words_00 = 2u;
    bi_num.words_04[0] = 0x00000003u;
    bi_num.words_04[1] = 0x00000002u; /* 0x200000003 */
    bi_den.used_words_00 = 1u;
    bi_den.words_04[0] = 0x00000002u;
    assert(rome2_l73_big_int_divide(&bi_num, &bi_den) == 0x100000001ULL);
    assert(bi_num.used_words_00 == 1u && bi_num.words_04[0] == 1u);
    checks += 2u;

    /* 3. Decimal & hex floating-point parsing (0x1168fa89, 0x11693706, 0x11695445) */
    assert(rome2_l73_parse_floating_point_string(&loc, "  -12.5xyz", &d_tgt, &endp, &err) == ROME2_L73_SLD_OK);
    assert(fabs(d_val - (-12.5)) < 1e-12 && endp != NULL && strcmp(endp, "xyz") == 0 && err == 0);
    assert(rome2_l73_parse_floating_point_string(&loc, "0x1.8p2!", &f_tgt, &endp, &err) == ROME2_L73_SLD_OK);
    assert(fabsf(f_val - 6.0f) < 1e-6f && endp != NULL && strcmp(endp, "!") == 0);
    assert(rome2_l73_parse_floating_point_string(&loc, "1e500", &d_tgt, &endp, &err) == ROME2_L73_SLD_OVERFLOW);
    assert(isinf(d_val) && err == 0x22);
    assert(rome2_l73_parse_floating_point_string(&loc, "1e-500", &d_tgt, &endp, &err) == ROME2_L73_SLD_UNDERFLOW);
    assert(d_val == 0.0 && err == 0x22);
    checks += 8u;

    /* 4. Special tokens infinity / nan / ind / snan / charseq */
    assert(rome2_l73_parse_floating_point_string(&loc, "+INFINITY", &f_tgt, &endp, &err) == ROME2_L73_SLD_OK);
    assert(flt_bits(f_val) == 0x7f800000u && *endp == '\0');
    assert(rome2_l73_parse_floating_point_string(&loc, "infinitude", &f_tgt, &endp, &err) == ROME2_L73_SLD_OK);
    assert(flt_bits(f_val) == 0x7f800000u && strcmp(endp, "initude") == 0);
    assert(rome2_l73_parse_floating_point_string(&loc, "nan(ind)", &d_tgt, &endp, &err) == ROME2_L73_SLD_OK);
    assert(dbl_bits(d_val) == 0xfff8000000000000ULL && *endp == '\0');
    assert(rome2_l73_parse_floating_point_string(&loc, "nan(snan)", &d_tgt, &endp, &err) == ROME2_L73_SLD_OK);
    assert(dbl_bits(d_val) == 0x7ff0000000000001ULL && *endp == '\0');
    assert(rome2_l73_parse_floating_point_string(&loc, "nan(abc_1)", &f_tgt, &endp, &err) == ROME2_L73_SLD_OK);
    assert((flt_bits(f_val) & 0x7fc00000u) == 0x7fc00000u && *endp == '\0');
    assert(rome2_l73_parse_floating_point_string(&loc, "nope", &f_tgt, &endp, &err) == ROME2_L73_SLD_NODIGITS);
    assert(f_val == 0.0f && strcmp(endp, "nope") == 0);
    checks += 12u;

    /* 5. input_processor specifier + 0x11695e3c literal tail + cleanup guard + fegetround */
    memset(&iproc, 0, sizeof(iproc));
    iproc.field_width_lo_30 = 4u;
    iproc.suppress_assignment_2e = 0u;
    memset(&src, 0, sizeof(src));
    src.buf = "3.259";
    src.len = 5u;
    d_val = 0.0;
    assert(rome2_l73_process_fp_specifier(&iproc, &loc, &src, &d_tgt, &err) == 1u && fabs(d_val - 3.25) < 1e-12);
    iproc.suppress_assignment_2e = 1u;
    src.pos = 0u;
    d_val = 99.0;
    assert(rome2_l73_process_fp_specifier(&iproc, &loc, &src, &d_tgt, &err) == 1u && d_val == 99.0);
    lit_buf[0] = 'X';
    lit_buf[1] = '\0';
    assert(rome2_l73_process_literal_tail(1u, "ok", lit_buf, sizeof(lit_buf)) == 1u && lit_buf[0] == 'X');
    assert(rome2_l73_process_literal_tail(0u, "ok", lit_buf, sizeof(lit_buf)) == 1u && strcmp(lit_buf, "ok") == 0);
    rome2_l73_scope_cleanup_guard(&loc, &src, &dirty);
    assert(dirty == 0u && loc.reset_gle_calls == 1u);
    assert(rome2_l73_fegetround(rome2_l73_fenv_get_common_round_control(0x6000u, 1u)) == 0x300u);
    assert(rome2_l73_fegetround(rome2_l73_fenv_get_common_round_control(0x0c00u, 0u)) == 0x300u);
    checks += 7u;

    (void)fp_str;
    (void)checks;
    return 0;
}
