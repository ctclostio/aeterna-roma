#include "startup_prefs_seh_tail_ops.h"

#include <math.h>
#include <string.h>

static uint16_t l72_read_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t l72_read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void l72_emit_wch(rome2_l72_wstream *stream, uint16_t ch, uint8_t *failed) {
    if (*failed) {
        return;
    }
    if (stream->sink_fail || !stream->rdbuf_present || stream->buf == NULL || stream->len >= stream->capacity) {
        *failed = 1u;
        return;
    }
    stream->buf[stream->len++] = ch;
}

void rome2_l72_stream_set_badbit(rome2_l72_wstream *stream) {
    if (stream != NULL) {
        stream->rdstate = (stream->rdstate | 2u) & 0xfu;
    }
}

void rome2_l72_wostream_insert_cstr(rome2_l72_wstream *stream, const char *cstr) {
    size_t slen = 0u;
    size_t pad = 0u;
    uint32_t err_bits = 0u;
    uint8_t failed = 0u;

    if (stream == NULL || cstr == NULL) {
        return;
    }
    slen = strlen(cstr);
    if (stream->width > 0u && (size_t)stream->width > slen) {
        pad = (size_t)stream->width - slen;
    }
    if (!stream->sentry_ok) {
        err_bits = 9u;
    } else {
        for (size_t i = 0u; i < slen; ++i) {
            l72_emit_wch(stream, (uint16_t)(uint8_t)cstr[i], &failed);
        }
        if (!failed) {
            for (size_t i = 0u; i < pad; ++i) {
                l72_emit_wch(stream, stream->fill, &failed);
            }
        }
        stream->width = 0u;
        if (failed) {
            err_bits = 9u;
        }
    }
    if (err_bits != 0u) {
        uint32_t next = stream->rdstate | err_bits;
        if (!stream->rdbuf_present) {
            next |= 8u;
        }
        stream->rdstate = next & 0xfu;
    }
}

void rome2_l72_wostream_insert_wstr(rome2_l72_wstream *stream, const uint16_t *wstr, size_t wlen) {
    size_t pad = 0u;
    uint32_t err_bits = 0u;
    uint8_t failed = 0u;

    if (stream == NULL || (wstr == NULL && wlen > 0u)) {
        return;
    }
    if (stream->width > 0u && (size_t)stream->width > wlen) {
        pad = (size_t)stream->width - wlen;
    }
    if (!stream->sentry_ok) {
        err_bits = 9u;
    } else {
        for (size_t i = 0u; i < wlen; ++i) {
            l72_emit_wch(stream, wstr[i], &failed);
        }
        if (!failed) {
            for (size_t i = 0u; i < pad; ++i) {
                l72_emit_wch(stream, stream->fill, &failed);
            }
        }
        stream->width = 0u;
        if (failed) {
            err_bits = 9u;
        }
    }
    if (err_bits != 0u) {
        uint32_t next = stream->rdstate | err_bits;
        if (!stream->rdbuf_present) {
            next |= 8u;
        }
        stream->rdstate = next & 0xfu;
    }
}

void rome2_l72_pref_write_line(const rome2_l72_pref_item *item, rome2_l72_wstream *stream) {
    static const uint16_t k_space[1] = {0x0020u};
    static const uint16_t k_quote[1] = {0x0022u};

    if (item == NULL || stream == NULL) {
        return;
    }
    if (item->name != NULL) {
        rome2_l72_wostream_insert_cstr(stream, item->name);
    }
    rome2_l72_wostream_insert_wstr(stream, k_space, 1u);
    if (item->quote != 0u) {
        rome2_l72_wostream_insert_wstr(stream, k_quote, 1u);
    }
    if (item->format_value != NULL) {
        item->format_value(item->user, stream);
    }
    if (item->quote != 0u) {
        rome2_l72_wostream_insert_wstr(stream, k_quote, 1u);
    }
    rome2_l72_wostream_insert_cstr(stream, "; # ");
    if (item->group != NULL) {
        rome2_l72_wostream_insert_cstr(stream, item->group);
    }
    rome2_l72_wostream_insert_cstr(stream, ", ");
    if (item->desc != NULL) {
        rome2_l72_wostream_insert_cstr(stream, item->desc);
    }
    rome2_l72_wostream_insert_cstr(stream, " #\r\n");
}

uint8_t rome2_l72_open_write_wstr(
    const rome2_l72_prefs_env *env,
    const uint16_t *path_hint,
    uint8_t append,
    rome2_startup_crt_file_box8_32 *out_box) {
    int32_t err = 0;
    uint8_t ok = 0u;

    if (out_box == NULL) {
        return 0u;
    }
    if (env == NULL || env->open_prefs_file == NULL) {
        out_box->file_00 = 0u;
        out_box->err_04 = 22;
        return 0u;
    }
    ok = env->open_prefs_file(env->user, path_hint, append, &err);
    if (!ok) {
        out_box->file_00 = 0u;
        out_box->err_04 = (err != 0) ? err : 2;
        return 0u;
    }
    out_box->file_00 = 1u;
    out_box->err_04 = 0;
    return 1u;
}

int32_t rome2_l72_write_preferences(
    const rome2_l72_prefs_env *env,
    const rome2_l72_pref_item *items,
    size_t item_count,
    rome2_l72_wstream *scratch_stream,
    const uint16_t *path_hint) {
    rome2_startup_crt_file_box8_32 box;
    size_t byte_len = 0u;
    size_t written = 0u;
    int32_t result = 0;

    if (env == NULL || scratch_stream == NULL || (items == NULL && item_count > 0u)) {
        return -1;
    }
    for (size_t i = 0u; i < item_count; ++i) {
        rome2_l72_pref_write_line(&items[i], scratch_stream);
    }
    if (!rome2_l72_open_write_wstr(env, path_hint, 1u, &box)) {
        if (env->log_line != NULL) {
            env->log_line(env->user, "preferences_open_failed");
        }
        return box.err_04;
    }
    if (env->stream_good == NULL || env->stream_good(env->user)) {
        byte_len = scratch_stream->len * sizeof(uint16_t);
        if (env->write_prefs_bytes != NULL && scratch_stream->buf != NULL && byte_len > 0u) {
            if (!env->write_prefs_bytes(env->user, (const uint8_t *)scratch_stream->buf, byte_len, &written) ||
                written != byte_len) {
                result = 0x26;
            }
        }
    }
    if (env->close_prefs_file != NULL) {
        int32_t close_rc = env->close_prefs_file(env->user);
        if (result == 0 && close_rc != 0) {
            result = close_rc;
        }
    }
    return result;
}

int32_t rome2_l72_ascii_strnicmp(const char *lhs, const char *rhs, size_t max_count) {
    uint8_t c1 = 0u;
    uint8_t c2 = 0u;

    if (max_count == 0u || lhs == NULL || rhs == NULL) {
        return 0;
    }
    do {
        c1 = (uint8_t)*lhs;
        c2 = (uint8_t)*rhs;
        if (c1 == 0u || c2 == 0u) {
            break;
        }
        ++lhs;
        ++rhs;
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 = (uint8_t)(c1 + 0x20u);
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 = (uint8_t)(c2 + 0x20u);
        }
        if (c1 != c2) {
            return (c1 < c2) ? -1 : 1;
        }
        --max_count;
    } while (max_count != 0u);

    if (c1 == c2) {
        return 0;
    }
    return (c1 < c2) ? -1 : 1;
}

uint8_t rome2_l72_fpu_cw_restore_needed(uint16_t saved_cw) {
    return (saved_cw != ROME2_L72_X87_DEFAULT_CW) ? 1u : 0u;
}

uint8_t rome2_l72_math_exit(uint16_t saved_cw, uint16_t fpu_sw, uint8_t *out_raised_exc) {
    if (out_raised_exc != NULL) {
        *out_raised_exc = 0u;
    }
    if (saved_cw != ROME2_L72_X87_DEFAULT_CW &&
        (saved_cw & ROME2_L72_X87_PRECISION_MASK) != 0u &&
        (fpu_sw & ROME2_L72_X87_PRECISION_MASK) != 0u) {
        if (out_raised_exc != NULL) {
            *out_raised_exc = 8u;
        }
        return 0u;
    }
    return rome2_l72_fpu_cw_restore_needed(saved_cw);
}

double rome2_l72_log10(double x, uint32_t *out_matherr_code) {
    if (out_matherr_code != NULL) {
        *out_matherr_code = 0u;
    }
    if (isnan(x)) {
        if (out_matherr_code != NULL) {
            *out_matherr_code = 9u;
        }
        return x;
    }
    if (x == 0.0) {
        if (out_matherr_code != NULL) {
            *out_matherr_code = 8u;
        }
        return -HUGE_VAL;
    }
    if (x < 0.0) {
        if (out_matherr_code != NULL) {
            *out_matherr_code = 9u;
        }
        return -NAN;
    }
    if (isinf(x)) {
        return HUGE_VAL;
    }
    return log10(x);
}

uint32_t rome2_l72_seh_restore_chain(uint32_t saved_ebp_m0c) {
    return saved_ebp_m0c;
}

uint8_t rome2_l72_validate_image_base(const uint8_t *image, size_t image_size) {
    uint32_t pe_off = 0u;
    uint16_t opt_magic = 0u;

    if (image == NULL || image_size < 0x40u) {
        return 0u;
    }
    if (l72_read_u16(image) != 0x5a4du) {
        return 0u;
    }
    pe_off = l72_read_u32(image + 0x3cu);
    if (pe_off > image_size || image_size - pe_off < 0x1au) {
        return 0u;
    }
    if (l72_read_u32(image + pe_off) != 0x00004550u) {
        return 0u;
    }
    opt_magic = l72_read_u16(image + pe_off + 0x18u);
    return (opt_magic == 0x010bu) ? 1u : 0u;
}

const rome2_startup_pe_sec_hdr40_32 *rome2_l72_find_pe_section(
    const uint8_t *image,
    size_t image_size,
    uint32_t rva,
    rome2_startup_pe_sec_hdr40_32 *out_copy) {
    uint32_t pe_off = 0u;
    uint16_t sec_count = 0u;
    uint16_t opt_size = 0u;
    size_t sec_table = 0u;

    if (out_copy == NULL || !rome2_l72_validate_image_base(image, image_size)) {
        return NULL;
    }
    pe_off = l72_read_u32(image + 0x3cu);
    sec_count = l72_read_u16(image + pe_off + 6u);
    opt_size = l72_read_u16(image + pe_off + 0x14u);
    sec_table = (size_t)pe_off + 0x18u + (size_t)opt_size;
    if (sec_table > image_size || (size_t)sec_count > (image_size - sec_table) / sizeof(rome2_startup_pe_sec_hdr40_32)) {
        return NULL;
    }
    for (uint16_t i = 0u; i < sec_count; ++i) {
        const uint8_t *sec_bytes = image + sec_table + (size_t)i * sizeof(rome2_startup_pe_sec_hdr40_32);
        uint32_t va = l72_read_u32(sec_bytes + 0x0cu);
        uint32_t vsz = l72_read_u32(sec_bytes + 0x08u);
        if (rva >= va && (uint64_t)rva < (uint64_t)va + (uint64_t)vsz) {
            memcpy(out_copy, sec_bytes, sizeof(*out_copy));
            return out_copy;
        }
    }
    return NULL;
}

uint8_t rome2_l72_is_nonwritable_in_image(
    const uint8_t *image,
    size_t image_size,
    uint32_t base_va,
    uint32_t target_va) {
    rome2_startup_pe_sec_hdr40_32 sec;

    if (target_va < base_va || !rome2_l72_validate_image_base(image, image_size)) {
        return 0u;
    }
    if (rome2_l72_find_pe_section(image, image_size, target_va - base_va, &sec) == NULL) {
        return 0u;
    }
    return ((sec.characteristics_24 & ROME2_L72_PE_SCN_MEM_WRITE) == 0u) ? 1u : 0u;
}

static uint8_t l72_check_exec_page(
    const uint8_t *image,
    size_t image_size,
    uint32_t base_va,
    uint32_t target_va,
    uint32_t *cached_page,
    rome2_startup_pe_sec_hdr40_32 *cached_sec,
    uint8_t *has_cached_sec) {
    uint32_t page_rva = (target_va - base_va) & 0xfffff000u;

    if (page_rva == *cached_page) {
        return 1u;
    }
    *cached_page = page_rva;
    if (!*has_cached_sec ||
        page_rva < cached_sec->virtual_address_0c ||
        (uint64_t)page_rva >= (uint64_t)cached_sec->virtual_address_0c + (uint64_t)cached_sec->virtual_size_08) {
        if (rome2_l72_find_pe_section(image, image_size, page_rva, cached_sec) == NULL ||
            (cached_sec->characteristics_24 & ROME2_L72_PE_SCN_MEM_EXECUTE) == 0u) {
            return 0u;
        }
        *has_cached_sec = 1u;
    }
    return 1u;
}

uint8_t rome2_l72_validate_scope_table_handlers(
    const uint8_t *image,
    size_t image_size,
    uint32_t base_va,
    const rome2_startup_seh_scope12_32 *scopes,
    size_t scope_count,
    uint32_t try_level) {
    rome2_startup_pe_sec_hdr40_32 cached_sec;
    uint8_t has_cached = 0u;
    uint32_t cached_page = 0xffffffffu;
    size_t steps = 0u;

    if (try_level == 0xffffffffu) {
        return 1u;
    }
    if (scopes == NULL || !rome2_l72_validate_image_base(image, image_size)) {
        return 0u;
    }
    memset(&cached_sec, 0, sizeof(cached_sec));
    while (try_level != 0xffffffffu) {
        const rome2_startup_seh_scope12_32 *entry = NULL;

        if ((size_t)try_level >= scope_count || steps >= scope_count) {
            return 0u;
        }
        entry = &scopes[try_level];
        if (entry->handler_08 < base_va ||
            !l72_check_exec_page(image, image_size, base_va, entry->handler_08, &cached_page, &cached_sec, &has_cached)) {
            return 0u;
        }
        if (entry->filter_04 != 0u) {
            if (entry->filter_04 < base_va ||
                !l72_check_exec_page(image, image_size, base_va, entry->filter_04, &cached_page, &cached_sec, &has_cached)) {
                return 0u;
            }
        }
        try_level = (uint32_t)entry->enclosing_level_00;
        ++steps;
    }
    return 1u;
}

int32_t rome2_l72_validate_eh3_rn(const rome2_l72_eh3_env *env) {
    uint8_t has_filter = 0u;
    rome2_startup_pe_sec_hdr40_32 sec;

    if (env == NULL || env->reg == NULL) {
        return 0;
    }
    if ((env->reg->scope_table_08 & 3u) != 0u) {
        return 0;
    }
    if (env->reg->scope_table_08 >= env->stack_low_va && env->reg->scope_table_08 < env->stack_high_va) {
        return 0;
    }
    if (env->reg->try_level_0c == 0xffffffffu) {
        return 1;
    }
    if (env->scopes == NULL || (size_t)env->reg->try_level_0c >= env->scope_count) {
        return 0;
    }
    for (uint32_t i = 0u; i <= env->reg->try_level_0c; ++i) {
        int32_t enc = env->scopes[i].enclosing_level_00;
        if (enc != -1 && (uint32_t)enc >= i) {
            return 0;
        }
        if (env->scopes[i].filter_04 != 0u) {
            has_filter = 1u;
        }
    }
    if (has_filter) {
        if (env->saved_ebp_va < env->stack_low_va || env->saved_ebp_va >= env->reg_va) {
            return 0;
        }
    }
    if (!rome2_l72_validate_image_base(env->image, env->image_size)) {
        return -1;
    }
    if (env->reg->scope_table_08 < env->image_base_va) {
        return 0;
    }
    if (env->region_writable_page) {
        if (rome2_l72_find_pe_section(env->image, env->image_size, env->reg->scope_table_08 - env->image_base_va, &sec) == NULL) {
            return 0;
        }
        if ((sec.characteristics_24 & ROME2_L72_PE_SCN_MEM_WRITE) != 0u) {
            return 0;
        }
    }
    if (!rome2_l72_validate_scope_table_handlers(
            env->image,
            env->image_size,
            env->image_base_va,
            env->scopes,
            env->scope_count,
            env->reg->try_level_0c)) {
        return 0;
    }
    if (rome2_l72_find_pe_section(env->image, env->image_size, env->handler_rva, &sec) == NULL) {
        return 0;
    }
    return 1;
}

uint32_t rome2_l72_local_unwind2(
    const rome2_l72_unwind_env *env,
    const rome2_startup_seh_scope12_32 *scopes,
    size_t scope_count,
    uint32_t current_try_level,
    uint32_t stop_try_level,
    uint32_t frame_ebp_va,
    uint32_t cookie) {
    uint32_t cur = current_try_level;
    size_t steps = 0u;

    if (scopes == NULL) {
        return cur;
    }
    while (cur != 0xffffffffu && (stop_try_level == 0xffffffffu || cur > stop_try_level)) {
        const rome2_startup_seh_scope12_32 *entry = NULL;

        if ((size_t)cur >= scope_count || steps >= scope_count) {
            break;
        }
        entry = &scopes[cur];
        cur = (uint32_t)entry->enclosing_level_00;
        if (entry->filter_04 == 0u && env != NULL) {
            if (env->nlg_notify != NULL) {
                rome2_startup_nlg_dest16_32 dest;
                dest.sig_00 = ROME2_L72_NLG_SIG;
                dest.eax_04 = entry->handler_08;
                dest.code_08 = 0x101u;
                dest.frame_ebp_0c = frame_ebp_va;
                env->nlg_notify(env->user, &dest);
            }
            if (env->nlg_call != NULL) {
                env->nlg_call(env->user, entry->handler_08, cookie);
            }
        }
        ++steps;
    }
    return cur;
}

void rome2_l72_global_unwind2(const rome2_l72_unwind_env *env, uint32_t target_frame_va) {
    if (env != NULL && env->rtl_unwind != NULL) {
        env->rtl_unwind(env->user, target_frame_va, 0x116c0a09u);
    }
}

uint8_t rome2_l72_call_destruct_exception_object(
    const uint8_t *image,
    size_t image_size,
    uint32_t base_va,
    uint32_t exc_code,
    uint32_t dtor_va,
    uint32_t dtor_slot_va,
    void (*guard_and_call)(void *user, uint32_t dtor_va),
    void *user) {
    if (exc_code != ROME2_L72_CPP_EH_CODE || dtor_va == 0u) {
        return 0u;
    }
    if (!rome2_l72_is_nonwritable_in_image(image, image_size, base_va, dtor_slot_va)) {
        return 0u;
    }
    if (guard_and_call != NULL) {
        guard_and_call(user, dtor_va);
    }
    return 1u;
}
