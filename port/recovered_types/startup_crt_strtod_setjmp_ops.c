#include "startup_crt_strtod_setjmp_ops.h"

#include <math.h>
#include <string.h>

rome2_l73_sld_status rome2_l74_cstr_parse_fp_double(
    const rome2_l73_locale_info *loc,
    const char *input,
    const char **out_endptr,
    double *out_val,
    int32_t *out_errno) {
    rome2_l73_fp_target target;
    target.is_double = 1u;
    target.f_out = NULL;
    target.d_out = out_val;
    return rome2_l73_parse_floating_point_string(loc, input, &target, out_endptr, out_errno);
}

uint8_t rome2_l74_cstr_source_rollback(const char **cursor, char *ch, const char *saved_pos) {
    if (ch != NULL) {
        *ch = '\0';
    }
    if (cursor != NULL) {
        *cursor = saved_pos;
    }
    return 1u;
}

float rome2_l74_powf(float x, float y) {
    return powf(x, y);
}

double rome2_l74_pow(double x, double y) {
    return pow(x, y);
}

static uint8_t is_space_ascii(char c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

static int digit_for_base(char c, int32_t base) {
    int v = -1;
    if (c >= '0' && c <= '9') {
        v = c - '0';
    } else if (c >= 'a' && c <= 'z') {
        v = 10 + (c - 'a');
    } else if (c >= 'A' && c <= 'Z') {
        v = 10 + (c - 'A');
    }
    return (v >= 0 && v < base) ? v : -1;
}

uint32_t rome2_l74_strtoul(const char *str, const char **endptr, int32_t radix, int32_t *out_errno) {
    const char *p = str;
    const char *start_digits;
    uint8_t neg = 0u;
    uint8_t overflow = 0u;
    uint64_t acc = 0u;
    uint8_t any = 0u;

    if (out_errno != NULL) {
        *out_errno = 0;
    }
    if (str == NULL || (radix != 0 && (radix < 2 || radix > 36))) {
        if (out_errno != NULL) {
            *out_errno = 0x16; /* EINVAL */
        }
        if (endptr != NULL) {
            *endptr = str;
        }
        return 0u;
    }

    while (is_space_ascii(*p)) {
        p++;
    }
    if (*p == '-') {
        neg = 1u;
        p++;
    } else if (*p == '+') {
        p++;
    }

    if ((radix == 0 || radix == 16) && p[0] == '0' && (p[1] == 'x' || p[1] == 'X') &&
        digit_for_base(p[2], 16) >= 0) {
        p += 2;
        radix = 16;
    }
    if (radix == 0) {
        radix = (*p == '0') ? 8 : 10;
    }

    start_digits = p;
    (void)start_digits;
    while (*p != '\0') {
        int d = digit_for_base(*p, radix);
        if (d < 0) {
            break;
        }
        any = 1u;
        if (!overflow) {
            acc = acc * (uint64_t)(uint32_t)radix + (uint64_t)(uint32_t)d;
            if (acc > 0xffffffffULL) {
                overflow = 1u;
            }
        }
        p++;
    }

    if (endptr != NULL) {
        *endptr = any ? p : str;
    }
    if (overflow) {
        if (out_errno != NULL) {
            *out_errno = 0x22; /* ERANGE */
        }
        return 0xffffffffu;
    }
    {
        uint32_t res = (uint32_t)(acc & 0xffffffffu);
        return neg ? (uint32_t)(0u - res) : res;
    }
}

char *rome2_l74_strncpy(char *dst, const char *src, size_t count) {
    size_t i = 0u;
    if (dst == NULL || src == NULL || count == 0u) {
        return dst;
    }
    while (i < count && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    while (i < count) {
        dst[i] = '\0';
        i++;
    }
    return dst;
}

double rome2_l74_strtod(const char *str, const char **endptr, const rome2_l73_locale_info *loc, int32_t *out_errno) {
    double val = 0.0;
    rome2_l73_locale_info def_loc;
    const rome2_l73_locale_info *use_loc = loc;
    if (use_loc == NULL) {
        memset(&def_loc, 0, sizeof(def_loc));
        def_loc.decimal_point = '.';
        use_loc = &def_loc;
    }
    (void)rome2_l74_cstr_parse_fp_double(use_loc, str, endptr, &val, out_errno);
    return val;
}

size_t rome2_l74_strcspn(const char *str, const char *control) {
    uint8_t map[32];
    const char *p = str;
    size_t idx = 0u;

    if (str == NULL || control == NULL) {
        return 0u;
    }
    memset(map, 0, sizeof(map));
    while (*control != '\0') {
        uint8_t uc = (uint8_t)*control;
        map[uc >> 3u] |= (uint8_t)(1u << (uc & 7u));
        control++;
    }
    while (p[idx] != '\0') {
        uint8_t uc = (uint8_t)p[idx];
        if ((map[uc >> 3u] & (uint8_t)(1u << (uc & 7u))) != 0u) {
            break;
        }
        idx++;
    }
    return idx;
}

char *rome2_l74_strncat(char *dst, const char *src, size_t count) {
    size_t dlen;
    size_t i = 0u;
    if (dst == NULL || src == NULL || count == 0u) {
        return dst;
    }
    dlen = strlen(dst);
    while (i < count && src[i] != '\0') {
        dst[dlen + i] = src[i];
        i++;
    }
    dst[dlen + i] = '\0';
    return dst;
}

int32_t rome2_l74_strcoll_l(
    const char *s1,
    const char *s2,
    uint32_t lcid,
    int32_t (*custom_collate)(void *user, uint32_t lcid, const char *a, const char *b),
    void *user,
    int32_t *out_errno) {
    if (out_errno != NULL) {
        *out_errno = 0;
    }
    if (s1 == NULL || s2 == NULL) {
        if (out_errno != NULL) {
            *out_errno = 0x16; /* EINVAL */
        }
        return 0x7fffffff;
    }
    if (lcid == 0u || custom_collate == NULL) {
        for (;;) {
            uint8_t a = (uint8_t)*s1++;
            uint8_t b = (uint8_t)*s2++;
            if (a != b) {
                return (a < b) ? -1 : 1;
            }
            if (a == 0u) {
                return 0;
            }
        }
    }
    {
        int32_t rc = custom_collate(user, lcid, s1, s2);
        if (rc == 0) {
            if (out_errno != NULL) {
                *out_errno = 0x16;
            }
            return 0x7fffffff;
        }
        return rc - 2;
    }
}

int32_t rome2_l74_strcoll(const char *s1, const char *s2, int32_t *out_errno) {
    return rome2_l74_strcoll_l(s1, s2, 0u, NULL, NULL, out_errno);
}

int32_t rome2_l74_setjmp3_init(
    rome2_startup_crt_jump_buf64_32 *jbuf,
    uint32_t current_seh_frame,
    uint32_t seh_trylevel,
    uint32_t eip,
    uint32_t ebp,
    uint32_t esp,
    uint32_t extra_count,
    uint32_t unwind_func,
    const uint32_t *extra_data) {
    uint32_t i;
    if (jbuf == NULL) {
        return -1;
    }
    memset(jbuf, 0, sizeof(*jbuf));
    jbuf->ebp_00 = ebp;
    jbuf->esp_10 = esp;
    jbuf->eip_14 = eip;
    if (current_seh_frame == 0u || current_seh_frame == 0xffffffffu) {
        jbuf->registration_18 = 0xffffffffu;
        jbuf->trylevel_1c = 0xffffffffu;
        return 0;
    }
    jbuf->cookie_20 = ROME2_L74_VC20_COOKIE;
    jbuf->unwind_func_24 = unwind_func;
    jbuf->registration_18 = current_seh_frame;
    if (extra_count == 0u) {
        jbuf->trylevel_1c = seh_trylevel;
        return 0;
    }
    jbuf->unwind_func_24 = (extra_data != NULL) ? extra_data[0] : unwind_func;
    if (extra_count == 1u) {
        jbuf->trylevel_1c = seh_trylevel;
        return 0;
    }
    jbuf->trylevel_1c = (extra_data != NULL) ? extra_data[1] : seh_trylevel;
    if (extra_data != NULL) {
        uint32_t copy_n = extra_count - 2u;
        if (copy_n > 6u) {
            copy_n = 6u;
        }
        for (i = 0u; i < copy_n; i++) {
            jbuf->unwind_data_28[i] = extra_data[2u + i];
        }
    }
    return 0;
}

uint8_t rome2_l74_except_validate_jump_buffer(const rome2_startup_crt_jump_buf64_32 *jbuf) {
    return (jbuf != NULL && jbuf->eip_14 != 0u) ? 1u : 0u;
}

uint8_t rome2_l74_probe_read4(const uint32_t *addr, uint8_t simulate_fault, uint32_t *out_val) {
    if (addr == NULL || simulate_fault != 0u) {
        return 0u;
    }
    if (out_val != NULL) {
        *out_val = *addr;
    }
    return 1u;
}

void rome2_l74_longjmp_internal(
    const rome2_l74_longjmp_env *env,
    const rome2_startup_crt_jump_buf64_32 *jbuf,
    int32_t value) {
    rome2_startup_crt_exc_record24_32 exc;
    int32_t ret_val = (value == 0) ? 1 : value;

    if (env == NULL || jbuf == NULL) {
        return;
    }
    memset(&exc, 0, sizeof(exc));
    exc.exception_code_00 = ROME2_L74_STATUS_LONGJUMP;

    if (jbuf->registration_18 != env->current_seh_frame && env->rtl_unwind != NULL) {
        env->rtl_unwind(env->user, jbuf->registration_18, 0x116c1efeU, &exc);
    }
    if (jbuf->registration_18 != 0u) {
        uint32_t probed = 0u;
        if (rome2_l74_probe_read4(&jbuf->cookie_20, env->cookie_mem_valid ? 0u : 1u, &probed) != 0u &&
            probed == ROME2_L74_VC20_COOKIE) {
            if (jbuf->unwind_func_24 != 0u && env->seh4_unwind != NULL) {
                env->seh4_unwind(env->user, jbuf);
            }
        } else if (env->eh3_local_unwind != NULL) {
            env->eh3_local_unwind(env->user, jbuf->registration_18, jbuf->trylevel_1c);
        }
    }
    if (env->nlg_notify != NULL) {
        env->nlg_notify(env->user, jbuf->eip_14, jbuf->ebp_00, 0u);
    }
    if (env->target_transfer != NULL) {
        env->target_transfer(env->user, jbuf->eip_14, ret_val);
    }
}

void rome2_l74_longjmp(
    const rome2_l74_longjmp_env *env,
    const rome2_startup_crt_jump_buf64_32 *jbuf,
    int32_t value) {
    if (rome2_l74_except_validate_jump_buffer(jbuf) == 0u) {
        return;
    }
    rome2_l74_longjmp_internal(env, jbuf, value);
}
