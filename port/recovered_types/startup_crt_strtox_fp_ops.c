#include "startup_crt_strtox_fp_ops.h"

#include <string.h>

static uint32_t msb_u64(uint64_t v) {
    uint32_t bits = 0u;
    while (v != 0u) {
        v >>= 1u;
        bits++;
    }
    return bits;
}

static uint32_t big_int_bit_len(const rome2_startup_crt_big_int464_32 *bi) {
    uint32_t top;
    uint32_t i;
    if (bi->used_words_00 == 0u || bi->used_words_00 > 115u) {
        return 0u;
    }
    top = bi->words_04[bi->used_words_00 - 1u];
    i = 0u;
    while (top != 0u) {
        top >>= 1u;
        i++;
    }
    return (bi->used_words_00 - 1u) * 32u + i;
}

static void big_int_mul_u32(rome2_startup_crt_big_int464_32 *bi, uint32_t factor) {
    uint64_t carry = 0u;
    uint32_t i;
    if (factor == 0u) {
        bi->used_words_00 = 0u;
        return;
    }
    if (factor == 1u || bi->used_words_00 == 0u) {
        return;
    }
    for (i = 0u; i < bi->used_words_00 && i < 115u; i++) {
        uint64_t prod = (uint64_t)bi->words_04[i] * (uint64_t)factor + carry;
        bi->words_04[i] = (uint32_t)(prod & 0xffffffffu);
        carry = prod >> 32u;
    }
    if (carry != 0u) {
        if (bi->used_words_00 < 115u) {
            bi->words_04[bi->used_words_00++] = (uint32_t)(carry & 0xffffffffu);
        } else {
            bi->used_words_00 = 0u;
        }
    }
}

static void big_int_add_u32(rome2_startup_crt_big_int464_32 *bi, uint32_t val) {
    uint64_t carry = (uint64_t)val;
    uint32_t i;
    if (val == 0u) {
        return;
    }
    for (i = 0u; i < bi->used_words_00 && i < 115u && carry != 0u; i++) {
        uint64_t sum = (uint64_t)bi->words_04[i] + carry;
        bi->words_04[i] = (uint32_t)(sum & 0xffffffffu);
        carry = sum >> 32u;
    }
    if (carry != 0u) {
        if (bi->used_words_00 < 115u) {
            bi->words_04[bi->used_words_00++] = (uint32_t)(carry & 0xffffffffu);
        } else {
            bi->used_words_00 = 0u;
        }
    }
}

static void big_int_mul_pow5(rome2_startup_crt_big_int464_32 *bi, uint32_t pow5) {
    while (pow5 >= 13u) {
        big_int_mul_u32(bi, 1220703125u);
        pow5 -= 13u;
    }
    if (pow5 > 0u) {
        uint32_t f = 1u;
        uint32_t i;
        for (i = 0u; i < pow5; i++) {
            f *= 5u;
        }
        big_int_mul_u32(bi, f);
    }
}

static void big_int_shift_left(rome2_startup_crt_big_int464_32 *bi, uint32_t shift) {
    uint32_t word_shift = shift / 32u;
    uint32_t bit_shift = shift % 32u;
    uint32_t new_used;
    uint32_t i;
    if (bi->used_words_00 == 0u || shift == 0u) {
        return;
    }
    if (bi->used_words_00 + word_shift >= 115u) {
        bi->used_words_00 = 0u;
        return;
    }
    new_used = bi->used_words_00 + word_shift + (bit_shift != 0u ? 1u : 0u);
    if (new_used > 115u) {
        bi->used_words_00 = 0u;
        return;
    }
    if (bit_shift == 0u) {
        for (i = bi->used_words_00; i > 0u; i--) {
            bi->words_04[i - 1u + word_shift] = bi->words_04[i - 1u];
        }
    } else {
        uint32_t carry = 0u;
        for (i = 0u; i < bi->used_words_00; i++) {
            uint32_t w = bi->words_04[i];
            uint32_t next_carry = w >> (32u - bit_shift);
            bi->words_04[i] = (w << bit_shift) | carry;
            carry = next_carry;
        }
        if (word_shift > 0u) {
            for (i = bi->used_words_00; i > 0u; i--) {
                bi->words_04[i - 1u + word_shift] = bi->words_04[i - 1u];
            }
        }
        if (carry != 0u) {
            bi->words_04[bi->used_words_00 + word_shift] = carry;
        } else {
            new_used = bi->used_words_00 + word_shift;
        }
    }
    for (i = 0u; i < word_shift; i++) {
        bi->words_04[i] = 0u;
    }
    bi->used_words_00 = new_used;
}

static int big_int_cmp(const rome2_startup_crt_big_int464_32 *a, const rome2_startup_crt_big_int464_32 *b) {
    uint32_t i;
    if (a->used_words_00 != b->used_words_00) {
        return a->used_words_00 < b->used_words_00 ? -1 : 1;
    }
    for (i = a->used_words_00; i > 0u; i--) {
        uint32_t aw = a->words_04[i - 1u];
        uint32_t bw = b->words_04[i - 1u];
        if (aw != bw) {
            return aw < bw ? -1 : 1;
        }
    }
    return 0;
}

void rome2_l73_assemble_snan_double(uint8_t is_negative, double *out) {
    uint64_t bits;
    if (out == NULL) {
        return;
    }
    bits = (((uint64_t)(is_negative ? 1u : 0u)) << 63u) | 0x7ff0000000000001ULL;
    memcpy(out, &bits, sizeof(bits));
}

rome2_l73_sld_status rome2_l73_assemble_fp_float(uint8_t is_negative, int32_t exp_val, uint64_t mantissa, float *out) {
    uint32_t bits;
    if (out == NULL) {
        return ROME2_L73_SLD_OK;
    }
    bits = (((uint32_t)(exp_val + 0x7f)) & 0xffu) << 23u;
    bits |= ((uint32_t)(is_negative ? 1u : 0u)) << 31u;
    bits |= (uint32_t)(mantissa & 0x7fffffULL);
    memcpy(out, &bits, sizeof(bits));
    return ROME2_L73_SLD_OK;
}

rome2_l73_sld_status rome2_l73_assemble_fp_double(uint8_t is_negative, int32_t exp_val, uint64_t mantissa, double *out) {
    uint64_t bits;
    if (out == NULL) {
        return ROME2_L73_SLD_OK;
    }
    bits = ((uint64_t)(((uint32_t)(exp_val + 0x3ff)) & 0x7ffu)) << 52u;
    bits |= ((uint64_t)(is_negative ? 1u : 0u)) << 63u;
    bits |= mantissa & 0xfffffffffffffULL;
    memcpy(out, &bits, sizeof(bits));
    return ROME2_L73_SLD_OK;
}

void rome2_l73_assemble_infinity(uint8_t is_negative, const rome2_l73_fp_target *target) {
    if (target == NULL) {
        return;
    }
    if (target->is_double && target->d_out != NULL) {
        uint64_t bits = (((uint64_t)(is_negative ? 1u : 0u)) << 63u) | 0x7ff0000000000000ULL;
        memcpy(target->d_out, &bits, sizeof(bits));
    } else if (!target->is_double && target->f_out != NULL) {
        uint32_t bits = (((uint32_t)(is_negative ? 1u : 0u)) << 31u) | 0x7f800000u;
        memcpy(target->f_out, &bits, sizeof(bits));
    }
}

void rome2_l73_assemble_zero(uint8_t is_negative, const rome2_l73_fp_target *target) {
    if (target == NULL) {
        return;
    }
    if (target->is_double && target->d_out != NULL) {
        uint64_t bits = ((uint64_t)(is_negative ? 1u : 0u)) << 63u;
        memcpy(target->d_out, &bits, sizeof(bits));
    } else if (!target->is_double && target->f_out != NULL) {
        uint32_t bits = ((uint32_t)(is_negative ? 1u : 0u)) << 31u;
        memcpy(target->f_out, &bits, sizeof(bits));
    }
}

uint64_t rome2_l73_denormal_mantissa_mask(uint8_t is_double) {
    return is_double ? 0x000fffffffffffffULL : 0x007fffffULL;
}

uint64_t rome2_l73_normal_mantissa_mask(uint8_t is_double) {
    return is_double ? 0x001fffffffffffffULL : 0x00ffffffULL;
}

static uint8_t should_round_up(uint8_t is_negative, uint8_t lsb, uint8_t half_bit, uint8_t sticky, uint32_t round_mode) {
    if (round_mode == 0u) {
        return half_bit && (sticky || lsb);
    }
    if (round_mode == 0x200u) {
        return (!is_negative) && (half_bit || sticky);
    }
    if (round_mode == 0x100u) {
        return is_negative && (half_bit || sticky);
    }
    return 0u;
}

rome2_l73_sld_status rome2_l73_assemble_fp_from_big_integer(
    const rome2_startup_crt_big_int464_32 *bi,
    uint32_t bits_count,
    uint8_t is_negative,
    uint8_t has_zero_tail,
    uint32_t round_mode,
    const rome2_l73_fp_target *target) {
    uint64_t mant = 0u;
    int32_t exp_val;
    uint32_t prec;
    int32_t min_exp;
    int32_t max_exp;
    uint8_t top_bit;
    uint8_t half_bit = 0u;
    uint8_t sticky = has_zero_tail ? 0u : 1u;
    uint32_t total_bits;

    if (target == NULL || bi == NULL) {
        return ROME2_L73_SLD_OK;
    }
    prec = target->is_double ? 53u : 24u;
    min_exp = target->is_double ? -1022 : -126;
    max_exp = target->is_double ? 1023 : 127;

    if (bi->used_words_00 == 0u) {
        rome2_l73_assemble_zero(is_negative, target);
        return ROME2_L73_SLD_OK;
    }

    total_bits = big_int_bit_len(bi);
    if (total_bits == 0u) {
        rome2_l73_assemble_zero(is_negative, target);
        return ROME2_L73_SLD_OK;
    }

    if (total_bits <= 64u) {
        uint64_t lo = (uint64_t)bi->words_04[0];
        uint64_t hi = (bi->used_words_00 > 1u) ? ((uint64_t)bi->words_04[1] << 32u) : 0u;
        mant = lo | hi;
        return rome2_l73_assemble_fp_value(mant, (int32_t)bits_count - 1, is_negative, has_zero_tail, round_mode, target);
    }

    exp_val = (int32_t)total_bits - 1 + (int32_t)bits_count - (int32_t)(total_bits - 1u);
    {
        /* Extract top `prec` bits from high limbs cleanly. */
        uint32_t hi_w = bi->words_04[bi->used_words_00 - 1u];
        uint32_t mid_w = (bi->used_words_00 >= 2u) ? bi->words_04[bi->used_words_00 - 2u] : 0u;
        uint32_t lo_w = (bi->used_words_00 >= 3u) ? bi->words_04[bi->used_words_00 - 3u] : 0u;
        uint32_t top_in_w = total_bits - (bi->used_words_00 - 1u) * 32u;
        uint32_t shift_down;
        uint64_t top64 = ((uint64_t)hi_w << 32u) | (uint64_t)mid_w;
        uint32_t top64_bits = 32u + top_in_w;
        if (top64_bits > 64u) {
            top64_bits = 64u;
        }
        shift_down = (top64_bits > prec) ? (top64_bits - prec) : 0u;
        mant = top64 >> shift_down;
        if (shift_down > 0u) {
            half_bit = (uint8_t)((top64 >> (shift_down - 1u)) & 1u);
            if (shift_down > 1u && (top64 & ((1ULL << (shift_down - 1u)) - 1ULL)) != 0u) {
                sticky = 1u;
            }
        }
        if (lo_w != 0u || bi->used_words_00 > 3u) {
            sticky = 1u;
        }
        (void)exp_val;
    }

    top_bit = 0u;
    (void)top_bit;
    exp_val = (int32_t)bits_count;
    if (exp_val > max_exp) {
        rome2_l73_assemble_infinity(is_negative, target);
        return ROME2_L73_SLD_OVERFLOW;
    }
    if (exp_val < min_exp) {
        rome2_l73_assemble_zero(is_negative, target);
        return ROME2_L73_SLD_UNDERFLOW;
    }
    if (should_round_up(is_negative, (uint8_t)(mant & 1u), half_bit, sticky, round_mode)) {
        mant++;
        if ((mant & (1ULL << prec)) != 0u) {
            mant >>= 1u;
            exp_val++;
            if (exp_val > max_exp) {
                rome2_l73_assemble_infinity(is_negative, target);
                return ROME2_L73_SLD_OVERFLOW;
            }
        }
    }
    if (target->is_double) {
        return rome2_l73_assemble_fp_double(is_negative, exp_val, mant, target->d_out);
    }
    return rome2_l73_assemble_fp_float(is_negative, exp_val, mant, target->f_out);
}

rome2_l73_sld_status rome2_l73_assemble_fp_value(
    uint64_t mantissa,
    int32_t exp_val,
    uint8_t is_negative,
    uint8_t has_zero_tail,
    uint32_t round_mode,
    const rome2_l73_fp_target *target) {
    uint32_t prec;
    int32_t min_exp;
    int32_t max_exp;
    uint32_t m_bits;
    uint8_t half_bit = 0u;
    uint8_t sticky = has_zero_tail ? 0u : 1u;

    if (target == NULL) {
        return ROME2_L73_SLD_OK;
    }
    if (mantissa == 0u) {
        rome2_l73_assemble_zero(is_negative, target);
        return ROME2_L73_SLD_OK;
    }

    prec = target->is_double ? 53u : 24u;
    min_exp = target->is_double ? -1022 : -126;
    max_exp = target->is_double ? 1023 : 127;
    m_bits = msb_u64(mantissa);
    exp_val += (int32_t)(m_bits - 1u);

    if (m_bits > prec) {
        uint32_t drop = m_bits - prec;
        half_bit = (uint8_t)((mantissa >> (drop - 1u)) & 1u);
        if (drop > 1u && (mantissa & ((1ULL << (drop - 1u)) - 1ULL)) != 0u) {
            sticky = 1u;
        }
        mantissa >>= drop;
    } else if (m_bits < prec) {
        mantissa <<= (prec - m_bits);
    }

    if (exp_val > max_exp) {
        rome2_l73_assemble_infinity(is_negative, target);
        return ROME2_L73_SLD_OVERFLOW;
    }

    if (exp_val < min_exp) {
        uint32_t sub_shift = (uint32_t)(min_exp - exp_val);
        if (sub_shift > prec + 1u) {
            rome2_l73_assemble_zero(is_negative, target);
            return ROME2_L73_SLD_UNDERFLOW;
        }
        if (sub_shift > 0u) {
            if ((mantissa & ((1ULL << (sub_shift - 1u)) - 1ULL)) != 0u || half_bit || sticky) {
                sticky = 1u;
            }
            half_bit = (uint8_t)((mantissa >> (sub_shift - 1u)) & 1u);
            mantissa >>= sub_shift;
        }
        if (should_round_up(is_negative, (uint8_t)(mantissa & 1u), half_bit, sticky, round_mode)) {
            mantissa++;
        }
        if (target->is_double) {
            rome2_l73_assemble_fp_double(is_negative, min_exp - 1, mantissa, target->d_out);
        } else {
            rome2_l73_assemble_fp_float(is_negative, min_exp - 1, mantissa, target->f_out);
        }
        return (mantissa == 0u) ? ROME2_L73_SLD_UNDERFLOW : ROME2_L73_SLD_OK;
    }

    if (should_round_up(is_negative, (uint8_t)(mantissa & 1u), half_bit, sticky, round_mode)) {
        mantissa++;
        if ((mantissa & (1ULL << prec)) != 0u) {
            mantissa >>= 1u;
            exp_val++;
            if (exp_val > max_exp) {
                rome2_l73_assemble_infinity(is_negative, target);
                return ROME2_L73_SLD_OVERFLOW;
            }
        }
    }

    if (target->is_double) {
        return rome2_l73_assemble_fp_double(is_negative, exp_val, mantissa, target->d_out);
    }
    return rome2_l73_assemble_fp_float(is_negative, exp_val, mantissa, target->f_out);
}

uint64_t rome2_l73_big_int_divide(
    rome2_startup_crt_big_int464_32 *numerator,
    const rome2_startup_crt_big_int464_32 *denominator) {
    uint32_t num_bits;
    uint32_t den_bits;
    uint64_t q = 0u;
    uint32_t shift;
    rome2_startup_crt_big_int464_32 rem;
    rome2_startup_crt_big_int464_32 sub;

    if (numerator == NULL || denominator == NULL || denominator->used_words_00 == 0u) {
        return 0u;
    }
    if (numerator->used_words_00 == 0u || big_int_cmp(numerator, denominator) < 0) {
        return 0u;
    }

    num_bits = big_int_bit_len(numerator);
    den_bits = big_int_bit_len(denominator);
    if (num_bits < den_bits) {
        return 0u;
    }
    shift = num_bits - den_bits;
    if (shift >= 63u) {
        return 0xffffffffffffffffULL;
    }

    rem = *numerator;
    for (;;) {
        uint32_t i;
        uint64_t borrow = 0u;
        sub = *denominator;
        big_int_shift_left(&sub, shift);
        if (sub.used_words_00 != 0u && big_int_cmp(&rem, &sub) >= 0) {
            for (i = 0u; i < rem.used_words_00; i++) {
                uint64_t dw = (i < sub.used_words_00) ? (uint64_t)sub.words_04[i] : 0u;
                uint64_t rw = (uint64_t)rem.words_04[i];
                if (rw >= dw + borrow) {
                    rem.words_04[i] = (uint32_t)(rw - dw - borrow);
                    borrow = 0u;
                } else {
                    rem.words_04[i] = (uint32_t)((1ULL << 32u) + rw - dw - borrow);
                    borrow = 1u;
                }
            }
            while (rem.used_words_00 > 0u && rem.words_04[rem.used_words_00 - 1u] == 0u) {
                rem.used_words_00--;
            }
            q |= (1ULL << shift);
        }
        if (shift == 0u) {
            break;
        }
        shift--;
    }
    *numerator = rem;
    return q;
}

rome2_l73_sld_status rome2_l73_convert_decimal_common(
    const rome2_startup_crt_fp_string780_32 *fp_str,
    uint32_t round_mode,
    const rome2_l73_fp_target *target) {
    uint64_t val = 0u;
    uint32_t count;
    uint32_t i;
    int32_t exp10;
    rome2_startup_crt_big_int464_32 num;
    rome2_startup_crt_big_int464_32 den;
    uint32_t prec;
    uint32_t num_bits;
    uint32_t den_bits;
    int32_t shift_bits;
    uint64_t mant;
    uint8_t has_zero_tail;

    if (fp_str == NULL || target == NULL) {
        return ROME2_L73_SLD_OK;
    }
    if (fp_str->mantissa_count_04 == 0u) {
        rome2_l73_assemble_zero(fp_str->is_negative_308, target);
        return ROME2_L73_SLD_OK;
    }
    if (fp_str->exponent_00 > 350) {
        rome2_l73_assemble_infinity(fp_str->is_negative_308, target);
        return ROME2_L73_SLD_OVERFLOW;
    }
    if (fp_str->exponent_00 < -350) {
        rome2_l73_assemble_zero(fp_str->is_negative_308, target);
        return ROME2_L73_SLD_UNDERFLOW;
    }

    /* Fast path for small decimal mantissas that fit in 53 bits with exact small 10^k. */
    count = fp_str->mantissa_count_04;
    if (count > 768u) {
        count = 768u;
    }
    if (count <= 15u && fp_str->exponent_00 >= 0 && fp_str->exponent_00 <= 22 && round_mode == 0u) {
        double d;
        for (i = 0u; i < count; i++) {
            val = val * 10u + (uint64_t)fp_str->mantissa_08[i];
        }
        d = (double)val;
        for (i = 0u; i < (uint32_t)fp_str->exponent_00; i++) {
            d *= 10.0;
        }
        if (fp_str->is_negative_308) {
            d = -d;
        }
        if (target->is_double && target->d_out != NULL) {
            *target->d_out = d;
            return ROME2_L73_SLD_OK;
        }
    }

    memset(&num, 0, sizeof(num));
    memset(&den, 0, sizeof(den));
    {
        uint32_t used_digits = (count > 38u) ? 38u : count;
        for (i = 0u; i < used_digits; i++) {
            big_int_mul_u32(&num, 10u);
            big_int_add_u32(&num, fp_str->mantissa_08[i]);
        }
        exp10 = fp_str->exponent_00 + (int32_t)(count - used_digits);
    }

    den.used_words_00 = 1u;
    den.words_04[0] = 1u;
    if (exp10 >= 0) {
        big_int_mul_pow5(&num, (uint32_t)exp10);
        big_int_shift_left(&num, (uint32_t)exp10);
    } else {
        uint32_t neg_exp = (uint32_t)(-exp10);
        big_int_mul_pow5(&den, neg_exp);
        big_int_shift_left(&den, neg_exp);
    }

    if (num.used_words_00 == 0u || den.used_words_00 == 0u) {
        if (exp10 >= 0) {
            rome2_l73_assemble_infinity(fp_str->is_negative_308, target);
            return ROME2_L73_SLD_OVERFLOW;
        }
        rome2_l73_assemble_zero(fp_str->is_negative_308, target);
        return ROME2_L73_SLD_UNDERFLOW;
    }

    prec = target->is_double ? 54u : 25u;
    num_bits = big_int_bit_len(&num);
    den_bits = big_int_bit_len(&den);
    shift_bits = (int32_t)prec - ((int32_t)num_bits - (int32_t)den_bits);
    if (shift_bits > 0) {
        big_int_shift_left(&num, (uint32_t)shift_bits);
    } else if (shift_bits < 0) {
        big_int_shift_left(&den, (uint32_t)(-shift_bits));
    }

    mant = rome2_l73_big_int_divide(&num, &den);
    has_zero_tail = (num.used_words_00 == 0u && count <= 38u) ? 1u : 0u;
    return rome2_l73_assemble_fp_value(
        mant, -shift_bits, fp_str->is_negative_308, has_zero_tail, round_mode, target);
}

rome2_l73_sld_status rome2_l73_convert_hex_common(
    const rome2_startup_crt_fp_string780_32 *fp_str,
    uint32_t round_mode,
    const rome2_l73_fp_target *target) {
    uint64_t mant = 0u;
    uint32_t total_digits;
    uint32_t i;
    uint8_t zero_tail = 1u;
    int32_t bin_exp;

    if (fp_str == NULL || target == NULL) {
        return ROME2_L73_SLD_OK;
    }
    if (fp_str->mantissa_count_04 == 0u) {
        rome2_l73_assemble_zero(fp_str->is_negative_308, target);
        return ROME2_L73_SLD_OK;
    }
    total_digits = fp_str->mantissa_count_04;
    if (total_digits > 768u) {
        total_digits = 768u;
    }
    {
        uint32_t pack = (total_digits > 16u) ? 16u : total_digits;
        for (i = 0u; i < pack; i++) {
            mant = (mant << 4u) | (uint64_t)(fp_str->mantissa_08[i] & 0xfu);
        }
        for (; i < total_digits; i++) {
            if (fp_str->mantissa_08[i] != 0u) {
                zero_tail = 0u;
                break;
            }
        }
        bin_exp = fp_str->exponent_00 + (int32_t)((total_digits - pack) * 4u);
    }
    return rome2_l73_assemble_fp_value(mant, bin_exp, fp_str->is_negative_308, zero_tail, round_mode, target);
}

static char src_peek(const rome2_l73_char_source *src) {
    if (src->pos >= src->len) {
        return '\0';
    }
    if (src->width_limit != 0u && src->consumed >= src->width_limit) {
        return '\0';
    }
    return src->buf[src->pos];
}

static char src_get(rome2_l73_char_source *src) {
    char c = src_peek(src);
    if (c != '\0') {
        src->pos++;
        src->consumed++;
    }
    return c;
}

static char ascii_tolower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static uint8_t is_ascii_space(char c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

static uint8_t is_ascii_digit(char c) {
    return c >= '0' && c <= '9';
}

static int hex_digit_val(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

uint8_t rome2_l73_possible_nan_is_ind(char *ch, rome2_l73_char_source *src) {
    static const char upper[] = "IND)";
    static const char lower[] = "ind)";
    uint32_t i = 0u;
    while (*ch == upper[i] || *ch == lower[i]) {
        *ch = src_get(src);
        i++;
        if (i == 4u) {
            return 1u;
        }
    }
    return 0u;
}

uint8_t rome2_l73_possible_nan_is_snan(char *ch, rome2_l73_char_source *src) {
    static const char upper[] = "SNAN)";
    static const char lower[] = "snan)";
    uint32_t i = 0u;
    while (*ch == upper[i] || *ch == lower[i]) {
        *ch = src_get(src);
        i++;
        if (i == 5u) {
            return 1u;
        }
    }
    return 0u;
}

uint8_t rome2_l73_possible_nan_is_char_seq(char *ch, rome2_l73_char_source *src) {
    while (*ch != ')') {
        char c = *ch;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
            return 0u;
        }
        *ch = src_get(src);
    }
    *ch = src_get(src);
    return 1u;
}

rome2_l73_fp_parse_kind rome2_l73_parse_possible_infinity(char *ch, rome2_l73_char_source *src) {
    static const char u[] = "INFINITY";
    static const char l[] = "infinity";
    uint32_t matched = 0u;
    size_t saved_pos = src->pos;
    uint64_t saved_consumed = src->consumed;

    while (matched < 8u && (*ch == u[matched] || *ch == l[matched])) {
        matched++;
        if (matched == 3u) {
            saved_pos = src->pos;
            saved_consumed = src->consumed;
        }
        *ch = src_get(src);
    }
    if (matched == 8u) {
        return ROME2_L73_FP_INFINITY;
    }
    if (matched >= 3u) {
        src->pos = saved_pos;
        src->consumed = saved_consumed;
        return ROME2_L73_FP_INFINITY;
    }
    return ROME2_L73_FP_NODIGITS;
}

rome2_l73_fp_parse_kind rome2_l73_parse_possible_nan(char *ch, rome2_l73_char_source *src) {
    static const char u[] = "NAN";
    static const char l[] = "nan";
    uint32_t matched = 0u;
    size_t paren_pos;
    uint64_t paren_consumed;
    while (matched < 3u && (*ch == u[matched] || *ch == l[matched])) {
        matched++;
        *ch = src_get(src);
    }
    if (matched != 3u) {
        return ROME2_L73_FP_NODIGITS;
    }
    if (*ch != '(') {
        return ROME2_L73_FP_QNAN;
    }
    paren_pos = src->pos;
    paren_consumed = src->consumed;
    *ch = src_get(src);
    if (rome2_l73_possible_nan_is_ind(ch, src)) {
        return ROME2_L73_FP_IND;
    }
    src->pos = paren_pos;
    src->consumed = paren_consumed;
    *ch = src_get(src);
    if (rome2_l73_possible_nan_is_snan(ch, src)) {
        return ROME2_L73_FP_SNAN;
    }
    src->pos = paren_pos;
    src->consumed = paren_consumed;
    *ch = src_get(src);
    if (rome2_l73_possible_nan_is_char_seq(ch, src)) {
        return ROME2_L73_FP_QNAN;
    }
    src->pos = paren_pos;
    src->consumed = paren_consumed;
    return ROME2_L73_FP_QNAN;
}

rome2_l73_fp_parse_kind rome2_l73_parse_fp_from_source(
    const rome2_l73_locale_info *loc,
    rome2_l73_char_source *src,
    rome2_startup_crt_fp_string780_32 *out_str) {
    char dp = (loc != NULL && loc->decimal_point != '\0') ? loc->decimal_point : '.';
    char ch;
    uint8_t is_hex = 0u;
    uint8_t saw_digit = 0u;
    uint8_t saw_nonzero = 0u;
    uint32_t count = 0u;
    int32_t exp_adj = 0;
    size_t saved_pos;
    uint64_t saved_consumed;

    if (src == NULL || out_str == NULL) {
        return ROME2_L73_FP_NODIGITS;
    }
    memset(out_str, 0, sizeof(*out_str));
    rome2_l73_process_whitespace(src);
    ch = src_get(src);
    if (ch == '-') {
        out_str->is_negative_308 = 1u;
        ch = src_get(src);
    } else if (ch == '+') {
        ch = src_get(src);
    }

    if (ascii_tolower(ch) == 'i') {
        return rome2_l73_parse_possible_infinity(&ch, src);
    }
    if (ascii_tolower(ch) == 'n') {
        return rome2_l73_parse_possible_nan(&ch, src);
    }

    if (ch == '0' && ascii_tolower(src_peek(src)) == 'x') {
        char after_x;
        saved_pos = src->pos;
        saved_consumed = src->consumed;
        (void)src_get(src);
        after_x = src_peek(src);
        if (hex_digit_val(after_x) >= 0 || after_x == dp) {
            is_hex = 1u;
            ch = src_get(src);
        } else {
            src->pos = saved_pos;
            src->consumed = saved_consumed;
        }
    }

    while (ch != '\0') {
        int d = is_hex ? hex_digit_val(ch) : (is_ascii_digit(ch) ? (ch - '0') : -1);
        if (d < 0) {
            break;
        }
        saw_digit = 1u;
        if (d != 0) {
            saw_nonzero = 1u;
        }
        if (saw_nonzero) {
            if (count < 768u) {
                out_str->mantissa_08[count++] = (uint8_t)d;
            } else {
                exp_adj += is_hex ? 4 : 1;
            }
        }
        ch = src_get(src);
    }

    if (ch == dp) {
        ch = src_get(src);
        while (ch != '\0') {
            int d = is_hex ? hex_digit_val(ch) : (is_ascii_digit(ch) ? (ch - '0') : -1);
            if (d < 0) {
                break;
            }
            saw_digit = 1u;
            if (d != 0) {
                saw_nonzero = 1u;
            }
            if (saw_nonzero) {
                if (count < 768u) {
                    out_str->mantissa_08[count++] = (uint8_t)d;
                    exp_adj -= is_hex ? 4 : 1;
                }
            } else {
                exp_adj -= is_hex ? 4 : 1;
            }
            ch = src_get(src);
        }
    }

    if (!saw_digit) {
        return ROME2_L73_FP_NODIGITS;
    }

    /* Parse optional exponent (e/E for dec, p/P for hex). */
    if ((is_hex && ascii_tolower(ch) == 'p') || (!is_hex && ascii_tolower(ch) == 'e')) {
        size_t exp_save_pos = src->pos - 1u;
        uint64_t exp_save_cons = src->consumed - 1u;
        char ec = src_get(src);
        uint8_t exp_neg = 0u;
        int32_t parsed_exp = 0;
        uint8_t any_exp_digit = 0u;
        if (ec == '-') {
            exp_neg = 1u;
            ec = src_get(src);
        } else if (ec == '+') {
            ec = src_get(src);
        }
        while (is_ascii_digit(ec)) {
            any_exp_digit = 1u;
            if (parsed_exp < 100000) {
                parsed_exp = parsed_exp * 10 + (ec - '0');
            }
            ec = src_get(src);
        }
        if (!any_exp_digit) {
            src->pos = exp_save_pos;
            src->consumed = exp_save_cons;
        } else {
            if (exp_neg) {
                parsed_exp = -parsed_exp;
            }
            exp_adj += parsed_exp;
            if (ec != '\0' && src->pos > 0u) {
                src->pos--;
                src->consumed--;
            }
        }
    } else if (ch != '\0' && src->pos > 0u) {
        src->pos--;
        src->consumed--;
    }

    if (!saw_nonzero) {
        return ROME2_L73_FP_ZERO;
    }
    out_str->mantissa_count_04 = count;
    out_str->exponent_00 = exp_adj;
    return is_hex ? ROME2_L73_FP_HEXADECIMAL : ROME2_L73_FP_DECIMAL;
}

rome2_l73_sld_status rome2_l73_write_fp_parse_result(
    rome2_l73_fp_parse_kind kind,
    const rome2_startup_crt_fp_string780_32 *fp_str,
    uint32_t round_mode,
    const rome2_l73_fp_target *target) {
    uint8_t neg = (fp_str != NULL) ? fp_str->is_negative_308 : 0u;
    if (target == NULL) {
        return ROME2_L73_SLD_OK;
    }
    switch (kind) {
    case ROME2_L73_FP_NODIGITS:
        rome2_l73_assemble_zero(0u, target);
        return ROME2_L73_SLD_NODIGITS;
    case ROME2_L73_FP_ZERO:
        rome2_l73_assemble_zero(neg, target);
        return ROME2_L73_SLD_OK;
    case ROME2_L73_FP_INFINITY:
        rome2_l73_assemble_infinity(neg, target);
        return ROME2_L73_SLD_OK;
    case ROME2_L73_FP_QNAN:
        if (target->is_double && target->d_out != NULL) {
            uint64_t q = 0x7ff8000000000000ULL | (((uint64_t)neg) << 63u);
            memcpy(target->d_out, &q, sizeof(q));
        } else if (!target->is_double && target->f_out != NULL) {
            uint32_t q = 0x7fc00000u | (((uint32_t)neg) << 31u);
            memcpy(target->f_out, &q, sizeof(q));
        }
        return ROME2_L73_SLD_OK;
    case ROME2_L73_FP_IND:
        if (target->is_double && target->d_out != NULL) {
            uint64_t q = 0xfff8000000000000ULL;
            memcpy(target->d_out, &q, sizeof(q));
        } else if (!target->is_double && target->f_out != NULL) {
            uint32_t q = 0xffc00000u;
            memcpy(target->f_out, &q, sizeof(q));
        }
        return ROME2_L73_SLD_OK;
    case ROME2_L73_FP_SNAN:
        if (target->is_double && target->d_out != NULL) {
            rome2_l73_assemble_snan_double(neg, target->d_out);
        } else if (!target->is_double && target->f_out != NULL) {
            uint32_t q = 0x7f800001u | (((uint32_t)neg) << 31u);
            memcpy(target->f_out, &q, sizeof(q));
        }
        return ROME2_L73_SLD_OK;
    case ROME2_L73_FP_DECIMAL:
        return rome2_l73_convert_decimal_common(fp_str, round_mode, target);
    case ROME2_L73_FP_HEXADECIMAL:
        return rome2_l73_convert_hex_common(fp_str, round_mode, target);
    }
    return ROME2_L73_SLD_OK;
}

rome2_l73_sld_status rome2_l73_parse_floating_point_string(
    const rome2_l73_locale_info *loc,
    const char *input,
    const rome2_l73_fp_target *target,
    const char **out_endptr,
    int32_t *out_errno) {
    rome2_l73_char_source src;
    rome2_startup_crt_fp_string780_32 fp_str;
    rome2_l73_fp_parse_kind kind;
    rome2_l73_sld_status st;
    uint32_t round_mode = (loc != NULL) ? loc->round_mode : 0u;

    if (out_errno != NULL) {
        *out_errno = 0;
    }
    if (input == NULL || target == NULL || (target->is_double ? (target->d_out == NULL) : (target->f_out == NULL))) {
        if (out_errno != NULL) {
            *out_errno = 0x16; /* EINVAL */
        }
        if (out_endptr != NULL) {
            *out_endptr = input;
        }
        return ROME2_L73_SLD_NODIGITS;
    }

    memset(&src, 0, sizeof(src));
    src.buf = input;
    src.len = strlen(input);
    kind = rome2_l73_parse_fp_from_source(loc, &src, &fp_str);
    if (out_endptr != NULL) {
        *out_endptr = (kind == ROME2_L73_FP_NODIGITS) ? input : (input + src.pos);
    }
    st = rome2_l73_write_fp_parse_result(kind, &fp_str, round_mode, target);
    if ((st == ROME2_L73_SLD_OVERFLOW || st == ROME2_L73_SLD_UNDERFLOW) && out_errno != NULL) {
        *out_errno = 0x22; /* ERANGE */
    }
    return st;
}

void rome2_l73_process_whitespace(rome2_l73_char_source *src) {
    if (src == NULL || src->buf == NULL) {
        return;
    }
    while (is_ascii_space(src_peek(src))) {
        (void)src_get(src);
    }
}

uint8_t rome2_l73_process_literal_tail(
    uint8_t suppress_assignment,
    const char *match,
    char *out_buf,
    size_t out_cap) {
    if (!suppress_assignment) {
        if (out_buf == NULL || out_cap == 0u || match == NULL) {
            return 0u;
        }
        size_t len = strlen(match);
        if (len + 1u > out_cap) {
            len = out_cap - 1u;
        }
        memcpy(out_buf, match, len);
        out_buf[len] = '\0';
    }
    return 1u;
}

uint8_t rome2_l73_process_fp_specifier(
    const rome2_startup_crt_input_proc112_32 *proc,
    const rome2_l73_locale_info *loc,
    rome2_l73_char_source *src,
    const rome2_l73_fp_target *target,
    int32_t *out_errno) {
    rome2_startup_crt_fp_string780_32 fp_str;
    rome2_l73_fp_parse_kind kind;
    uint32_t round_mode = (loc != NULL) ? loc->round_mode : 0u;
    double tmp_d = 0.0;
    float tmp_f = 0.0f;
    rome2_l73_fp_target tmp_target;

    if (proc == NULL || src == NULL || target == NULL) {
        return 0u;
    }
    src->width_limit = ((uint64_t)proc->field_width_hi_34 << 32u) | (uint64_t)proc->field_width_lo_30;
    src->consumed = 0u;
    kind = rome2_l73_parse_fp_from_source(loc, src, &fp_str);
    if (kind == ROME2_L73_FP_NODIGITS) {
        return 0u;
    }
    tmp_target.is_double = target->is_double;
    tmp_target.d_out = &tmp_d;
    tmp_target.f_out = &tmp_f;
    (void)rome2_l73_write_fp_parse_result(kind, &fp_str, round_mode, &tmp_target);
    if (proc->suppress_assignment_2e != 0u) {
        return 1u;
    }
    if (target->is_double) {
        if (target->d_out == NULL) {
            if (out_errno != NULL) {
                *out_errno = 0x16;
            }
            return 0u;
        }
        *target->d_out = tmp_d;
        return 1u;
    }
    if (target->f_out == NULL) {
        if (out_errno != NULL) {
            *out_errno = 0x16;
        }
        return 0u;
    }
    *target->f_out = tmp_f;
    return 1u;
}

void rome2_l73_scope_cleanup_guard(
    rome2_l73_locale_info *loc,
    rome2_l73_char_source *src,
    uint8_t *dirty_flag) {
    (void)src;
    if (dirty_flag != NULL) {
        *dirty_flag = 0u;
    }
    if (loc != NULL) {
        loc->reset_gle_calls++;
    }
}

uint32_t rome2_l73_fenv_get_common_round_control(uint32_t mxcsr_or_cw, uint8_t use_sse) {
    if (use_sse) {
        return (mxcsr_or_cw >> 5u) & 0x300u;
    }
    return (mxcsr_or_cw >> 2u) & 0x300u;
}

uint32_t rome2_l73_fegetround(uint32_t round_control_bits) {
    return round_control_bits & 0x300u;
}
