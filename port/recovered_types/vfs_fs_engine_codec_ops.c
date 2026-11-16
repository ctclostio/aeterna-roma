#include "vfs_fs_engine_codec_ops.h"

#include <stdio.h>
#include <string.h>

static uint16_t rome2_read_code_unit(
    const char *narrow_buf,
    const uint16_t *wide_buf,
    uint32_t len,
    uint32_t idx) {
    if (idx >= len) {
        return 0u;
    }
    if (wide_buf != NULL) {
        return wide_buf[idx];
    }
    return (uint16_t)(uint8_t)narrow_buf[idx];
}

static rome2_vfs_reg_status rome2_parse_fmt_spec_units(
    const char *narrow_buf,
    const uint16_t *wide_buf,
    uint32_t len,
    uint16_t *inout_idx,
    rome2_vfs_fmt_spec *out_spec) {
    uint16_t ch = 0u;
    uint16_t idx = 0u;
    uint16_t acc = 0u;
    uint8_t prec_acc = 0u;
    uint8_t is_narrow = (wide_buf == NULL) ? 1u : 0u;

    if ((narrow_buf == NULL && wide_buf == NULL) || inout_idx == NULL || out_spec == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    memset(out_spec, 0, sizeof(*out_spec));
    idx = *inout_idx;
    ch = rome2_read_code_unit(narrow_buf, wide_buf, len, idx);

    out_spec->is_minus = (ch == (uint16_t)'-') ? 1u : 0u;
    if (out_spec->is_minus != 0u) {
        ++idx;
        ch = rome2_read_code_unit(narrow_buf, wide_buf, len, idx);
    }

    if (ch == (uint16_t)'+' || ch == (uint16_t)' ') {
        out_spec->sign_ch = ch;
        if (ch != 0u) {
            ++idx;
            ch = rome2_read_code_unit(narrow_buf, wide_buf, len, idx);
        }
    } else {
        out_spec->sign_ch = 0u;
    }

    if (ch == (uint16_t)'0') {
        out_spec->zero_pad_ch = (uint16_t)'0';
        ++idx;
        ch = rome2_read_code_unit(narrow_buf, wide_buf, len, idx);
    } else {
        out_spec->zero_pad_ch = (uint16_t)' ';
    }

    acc = 0u;
    while (ch >= (uint16_t)'0' && ch <= (uint16_t)'9') {
        if (is_narrow != 0u) {
            uint8_t next_b = (uint8_t)((uint8_t)acc * 10u + (uint8_t)(ch - (uint16_t)'0'));
            acc = (uint16_t)next_b;
        } else {
            acc = (uint16_t)(acc * 10u + (ch - (uint16_t)'0'));
        }
        ++idx;
        ch = rome2_read_code_unit(narrow_buf, wide_buf, len, idx);
    }
    out_spec->width = acc;

    out_spec->precision = 0u;
    if (ch == (uint16_t)'.') {
        ++idx;
        ch = rome2_read_code_unit(narrow_buf, wide_buf, len, idx);
        acc = 0u;
        prec_acc = 0u;
        while (ch >= (uint16_t)'0' && ch <= (uint16_t)'9') {
            if (is_narrow != 0u) {
                prec_acc = (uint8_t)(prec_acc * 10u + (uint8_t)(ch - (uint16_t)'0'));
                acc = (uint16_t)(int16_t)(int8_t)prec_acc;
            } else {
                acc = (uint16_t)(acc * 10u + (ch - (uint16_t)'0'));
            }
            ++idx;
            ch = rome2_read_code_unit(narrow_buf, wide_buf, len, idx);
        }
        out_spec->precision = acc;
    }

    ++idx;
    out_spec->last_ch = ch;
    *inout_idx = idx;
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_wstringbuf_state_from_openmode(uint32_t openmode) {
    uint32_t state = ((~openmode) & 1u) << 2;
    if ((openmode & 2u) == 0u) {
        state |= 2u;
    }
    if ((openmode & 8u) != 0u) {
        state |= 8u;
    }
    if ((openmode & 4u) != 0u) {
        state |= 0x10u;
    }
    return state;
}

rome2_vfs_reg_status rome2_vfs_wstringbuf60_init_slots(
    rome2_vfs_wstringbuf60_32 *sb,
    uint32_t self_va,
    uint32_t vftable_va) {
    if (sb == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    sb->vftable_00 = vftable_va;
    sb->g_first_ptr_0c = self_va + 0x04u;
    sb->p_first_ptr_10 = self_va + 0x08u;
    sb->g_next_ptr_1c = self_va + 0x14u;
    sb->p_next_ptr_20 = self_va + 0x18u;
    sb->g_count_ptr_2c = self_va + 0x24u;
    sb->p_count_ptr_30 = self_va + 0x28u;
    sb->g_first_val_04 = 0u;
    sb->p_first_val_08 = 0u;
    sb->g_next_val_14 = 0u;
    sb->p_next_val_18 = 0u;
    sb->g_count_val_24 = 0u;
    sb->p_count_val_28 = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstringbuf60_init_buf(
    rome2_vfs_wstringbuf60_32 *sb,
    uint16_t *dst_buf,
    uint32_t dst_cap,
    uint32_t dst_guest_va,
    const uint16_t *src,
    uint32_t count,
    uint32_t str_state) {
    uint32_t end_va = 0u;

    if (sb == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    sb->seek_high_34 = 0u;
    sb->mystate_38 = str_state;

    if (count == 0u || (str_state & 6u) == 6u) {
        return ROME2_VFS_REG_OK;
    }
    if (dst_buf == NULL || src == NULL || count > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    memcpy(dst_buf, src, (size_t)count * sizeof(uint16_t));
    end_va = dst_guest_va + count * 2u;
    sb->seek_high_34 = end_va;

    if ((sb->mystate_38 & 4u) == 0u) {
        sb->g_first_val_04 = dst_guest_va;
        sb->g_next_val_14 = dst_guest_va;
        sb->g_count_val_24 = count;
    }
    if ((sb->mystate_38 & 2u) == 0u) {
        uint32_t pnext = ((sb->mystate_38 & 0x10u) != 0u) ? end_va : dst_guest_va;
        sb->p_first_val_08 = dst_guest_va;
        sb->p_next_val_18 = pnext;
        sb->p_count_val_28 = (uint32_t)(((int32_t)(end_va - pnext)) >> 1);
        if (sb->g_next_val_14 == 0u) {
            sb->g_first_val_04 = dst_guest_va;
            sb->g_next_val_14 = 0u;
            sb->g_count_val_24 = (uint32_t)(((int32_t)dst_guest_va) >> 1);
        }
    }
    sb->mystate_38 |= 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstringbuf60_tidy(
    rome2_vfs_wstringbuf60_32 *sb,
    uint8_t *out_should_free,
    uint32_t *out_free_va) {
    if (sb == NULL || out_should_free == NULL || out_free_va == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_should_free = ((sb->mystate_38 & 1u) != 0u) ? 1u : 0u;
    *out_free_va = (*out_should_free != 0u) ? sb->g_first_val_04 : 0u;
    sb->g_first_val_04 = 0u;
    sb->g_next_val_14 = 0u;
    sb->g_count_val_24 = 0u;
    sb->p_first_val_08 = 0u;
    sb->p_next_val_18 = 0u;
    sb->p_count_val_28 = 0u;
    sb->mystate_38 &= ~1u;
    sb->seek_high_34 = 0u;
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_sentinel_ctx_va(void) {
    return ROME2_VFS_L38_SENTINEL_CTX_VA;
}

const uint16_t *rome2_vfs_wstr_ptr_at_unchecked(const uint16_t *buf, uint32_t idx) {
    return (buf != NULL) ? (buf + idx) : NULL;
}

uint16_t rome2_vfs_wstr_char_at_checked(const uint16_t *buf, uint32_t len, uint32_t idx) {
    if (buf == NULL || idx >= len) {
        return 0u;
    }
    return buf[idx];
}

rome2_vfs_reg_status rome2_vfs_parse_fmt_spec_ascii(
    const char *str,
    uint32_t len,
    uint16_t *inout_idx,
    rome2_vfs_fmt_spec *out_spec) {
    return rome2_parse_fmt_spec_units(str, NULL, len, inout_idx, out_spec);
}

rome2_vfs_reg_status rome2_vfs_parse_fmt_spec_wstr(
    const uint16_t *wstr,
    uint32_t len,
    uint16_t *inout_idx,
    rome2_vfs_fmt_spec *out_spec) {
    return rome2_parse_fmt_spec_units(NULL, wstr, len, inout_idx, out_spec);
}

rome2_vfs_reg_status rome2_vfs_scan_lfmt_spec_ascii(
    const char *fmt,
    uint32_t fmt_len,
    uint16_t *inout_idx,
    char *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap,
    rome2_vfs_fmt_spec *out_spec,
    uint8_t *out_hit_spec) {
    uint16_t idx = 0u;

    if (fmt == NULL || inout_idx == NULL || out_buf == NULL ||
        inout_out_len == NULL || out_spec == NULL || out_hit_spec == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    memset(out_spec, 0, sizeof(*out_spec));
    *out_hit_spec = 0u;
    idx = *inout_idx;

    while ((uint32_t)idx < fmt_len) {
        char ch = fmt[idx];
        if (ch == '%') {
            do {
                ++idx;
                ch = ((uint32_t)idx < fmt_len) ? fmt[idx] : '\0';
            } while (ch == 'l');

            if (ch != '%') {
                *inout_idx = idx;
                *out_hit_spec = 1u;
                return rome2_vfs_parse_fmt_spec_ascii(fmt, fmt_len, inout_idx, out_spec);
            }
        }

        if (*inout_out_len >= out_cap) {
            *inout_idx = idx;
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_buf[*inout_out_len] = ch;
        *inout_out_len += 1u;
        ++idx;
    }

    *inout_idx = idx;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_format_float32_wstr(
    float val,
    uint16_t spec_ch,
    uint16_t prec,
    uint16_t prefix_ch,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok) {
    char num_buf[96];
    uint16_t tmp[98];
    uint32_t total = 0u;
    uint32_t trim = 0u;
    uint16_t eff_prec = 0u;
    int32_t n = 0;
    uint32_t len = 0u;
    float mag = val;

    if (out_wstr == NULL || out_len == NULL || out_ok == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_len = 0u;
    *out_ok = 0u;

    if (spec_ch != (uint16_t)'f') {
        n = snprintf(num_buf, sizeof(num_buf), "Unexpected format %%%c used with type %s",
            (int)(uint8_t)spec_ch, "float32");
        if (n < 0 || (uint32_t)n >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        for (uint32_t i = 0u; i < (uint32_t)n; ++i) {
            out_wstr[i] = (uint16_t)(uint8_t)num_buf[i];
        }
        out_wstr[(uint32_t)n] = 0u;
        *out_len = (uint32_t)n;
        *out_ok = 0u;
        return ROME2_VFS_REG_OK;
    }

    eff_prec = (prec != 0u) ? prec : 6u;
    if (eff_prec > 12u) {
        eff_prec = 12u;
    }
    if (mag < 0.0f) {
        mag = -mag;
        tmp[total++] = (uint16_t)'-';
    } else if (prefix_ch != 0u) {
        tmp[total++] = prefix_ch;
    }

    n = snprintf(num_buf, sizeof(num_buf), "%.*f", (int)eff_prec, (double)mag);
    if (n <= 0 || total + (uint32_t)n >= (uint32_t)(sizeof(tmp) / sizeof(tmp[0]))) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (int32_t i = 0; i < n; ++i) {
        tmp[total++] = (uint16_t)(uint8_t)num_buf[i];
    }

    if (prec == 0u) {
        for (uint32_t k = 1u; k <= 5u && k <= total; ++k) {
            if (tmp[total - k] != (uint16_t)'0') {
                break;
            }
            trim = k;
        }
        total -= trim;
    }

    len = total;
    if (len + 1u > out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (uint32_t i = 0u; i < len; ++i) {
        out_wstr[i] = tmp[i];
    }
    out_wstr[len] = 0u;
    *out_len = len;
    *out_ok = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sock_endpoint12_set_ipv4(
    rome2_vfs_sock_endpoint12_32 *ep,
    uint32_t ipv4_addr_dword,
    uint16_t host_port) {
    if (ep == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    ep->sin_family_04 = 2u;
    ep->sin_port_be_06 = (uint16_t)(((host_port & 0xffu) << 8) | ((host_port >> 8) & 0xffu));
    ep->sin_addr_08 = ipv4_addr_dword;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sock_toggle_fionbio(
    int32_t ioctl_ret,
    uint8_t blocking_flag,
    uint32_t *out_argp) {
    if (out_argp == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_argp = (uint32_t)((blocking_flag != 0u ? 1u : 0u) ^ 1u);
    if (ioctl_ret == -1) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_channel_slot_probe_ready(
    uint8_t steam_ready,
    int32_t peek_ret,
    uint32_t wsa_last_error) {
    if (steam_ready != 0u || peek_ret != -1) {
        return 1u;
    }
    return (wsa_last_error == ROME2_VFS_L38_WSAEWOULDBLOCK) ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_steam_p2p_close_pack(
    uint32_t steam_id_lo,
    uint32_t steam_id_hi,
    uint32_t out_pair[2]) {
    if (out_pair == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    out_pair[0] = steam_id_lo;
    out_pair[1] = steam_id_hi;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_freelist4_link_links(
    uint32_t base_va,
    uint32_t count,
    uint32_t *out_links,
    uint32_t links_cap) {
    if (out_links == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (count > links_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (uint32_t i = 0u; i < count; ++i) {
        out_links[i] = (i + 1u < count) ? (base_va + (i + 1u) * 4u) : 0u;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dlmalloc_init_top(
    rome2_vfs_dlmalloc_mstate448_32 *ms,
    uint32_t tbase_va,
    uint32_t tsize,
    uint32_t trim_threshold,
    uint32_t *out_aligned_top_va,
    uint32_t *out_aligned_size,
    uint32_t *out_chunk_head,
    uint32_t *out_fencepost_head) {
    uint32_t align_off = (0u - tbase_va) & 7u;
    uint32_t aligned = tbase_va + align_off;
    uint32_t psize = 0u;

    if (ms == NULL || out_aligned_top_va == NULL || out_aligned_size == NULL ||
        out_chunk_head == NULL || out_fencepost_head == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (tsize <= align_off) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    psize = tsize - align_off;
    ms->top_ptr_18 = aligned;
    ms->topsize_0c = psize;
    ms->trim_check_1c = trim_threshold;
    *out_aligned_top_va = aligned;
    *out_aligned_size = psize;
    *out_chunk_head = psize | 1u;
    *out_fencepost_head = 0x28u;
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_dlmalloc_find_segment_idx(
    const rome2_vfs_msegment_span *segs,
    uint32_t seg_count,
    uint32_t addr_va) {
    if (segs == NULL) {
        return seg_count;
    }
    for (uint32_t i = 0u; i < seg_count; ++i) {
        uint32_t base = segs[i].base_va;
        if (addr_va >= base && (addr_va - base) < segs[i].size) {
            return i;
        }
    }
    return seg_count;
}

rome2_vfs_reg_status rome2_vfs_intrusive_list_clear_range(
    const uint32_t *payload_vas,
    const uint32_t *node_vas,
    uint32_t count,
    uint32_t self_va,
    uint32_t *out_freed_vas,
    uint32_t freed_cap,
    uint32_t *out_freed_count,
    uint32_t *out_head_after) {
    uint32_t freed = 0u;

    if (out_freed_count == NULL || out_head_after == NULL ||
        (count > 0u && (payload_vas == NULL || node_vas == NULL || out_freed_vas == NULL))) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (uint32_t i = 0u; i < count; ++i) {
        if (payload_vas[i] != 0u) {
            if (freed >= freed_cap) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            out_freed_vas[freed++] = payload_vas[i];
        }
        if (freed >= freed_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_freed_vas[freed++] = node_vas[i];
    }
    *out_freed_count = freed;
    *out_head_after = self_va + 4u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_queue24_init(
    rome2_vfs_channel_queue24_32 *q,
    uint32_t self_va,
    uint32_t owner_arg) {
    if (q == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    q->list_ptr_or_self_00 = self_va + 4u;
    q->head_04 = 0u;
    q->tail_08 = 0u;
    q->owner_or_arg_0c = owner_arg;
    q->count_or_size_10 = 0u;
    q->payload_or_flags_14 = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_adapter_register(
    uint32_t *list_slots,
    uint32_t *inout_count,
    uint32_t cap,
    uint32_t adapter_va,
    uint8_t *out_inserted) {
    if (list_slots == NULL || inout_count == NULL || out_inserted == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_inserted = 0u;
    for (uint32_t i = 0u; i < *inout_count; ++i) {
        if (list_slots[i] == adapter_va) {
            return ROME2_VFS_REG_OK;
        }
    }
    if (*inout_count >= cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    list_slots[*inout_count] = adapter_va;
    *inout_count += 1u;
    *out_inserted = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_read_bytes_or_overflow(
    const uint8_t *buf,
    uint32_t cap,
    uint32_t *inout_cursor,
    uint32_t *inout_avail,
    uint8_t *dst,
    uint32_t size,
    uint8_t *out_need_fallback,
    uint8_t *out_hit_end) {
    if (buf == NULL || inout_cursor == NULL || inout_avail == NULL ||
        out_need_fallback == NULL || out_hit_end == NULL || (size > 0u && dst == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (size > cap || *inout_cursor > cap - size) {
        *out_need_fallback = 1u;
        *out_hit_end = 0u;
        return ROME2_VFS_REG_OK;
    }
    if (size > 0u) {
        memcpy(dst, buf + *inout_cursor, (size_t)size);
    }
    *inout_cursor += size;
    *inout_avail += size;
    *out_need_fallback = 0u;
    *out_hit_end = (*inout_cursor == cap) ? 1u : 0u;
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_bitrev8(uint8_t v) {
    uint32_t a = ((uint32_t)v * 0x0802u) & 0x22110u;
    uint32_t b = ((uint32_t)v * 0x8020u) & 0x88440u;
    return (uint8_t)(((a | b) * 0x10101u) >> 16);
}

static uint32_t rome2_msb_bit_width(uint32_t span) {
    uint32_t clz = 0u;
    uint32_t mask = 0x80000000u;
    if ((span & mask) != 0u) {
        return 32u;
    }
    while (mask != 0u) {
        mask >>= 1;
        ++clz;
        if ((span & mask) != 0u) {
            break;
        }
    }
    return 32u - clz;
}

rome2_vfs_reg_status rome2_vfs_write_ranged_bits(
    uint8_t *buf,
    uint32_t byte_cap,
    uint32_t *inout_bit_cursor,
    uint32_t value,
    uint32_t min_val,
    uint32_t max_val,
    uint32_t *out_bits_written) {
    uint32_t bits = 0u;
    uint32_t delta = 0u;
    uint8_t rev_bytes[4] = {0};

    if (buf == NULL || inout_bit_cursor == NULL || out_bits_written == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_bits_written = 0u;

    if (min_val > value || value > max_val || min_val == max_val) {
        return ROME2_VFS_REG_OK;
    }
    bits = rome2_msb_bit_width(max_val - min_val);
    if (bits == 0u || byte_cap > 0x1fffffffu || bits > byte_cap * 8u ||
        *inout_bit_cursor > byte_cap * 8u - bits) {
        return ROME2_VFS_REG_OK;
    }

    delta = value - min_val;
    for (uint32_t b = 0u; b < 4u; ++b) {
        rev_bytes[b] = rome2_vfs_bitrev8((uint8_t)(delta >> (b * 8u)));
    }

    for (uint32_t k = 0u; k < bits; ++k) {
        uint32_t bit = (uint32_t)((rev_bytes[k >> 3] >> (7u - (k & 7u))) & 1u);
        uint32_t dbit = *inout_bit_cursor + k;
        uint32_t dshift = 7u - (dbit & 7u);
        buf[dbit >> 3] = (uint8_t)((buf[dbit >> 3] & ~(1u << dshift)) | (bit << dshift));
    }
    *inout_bit_cursor += bits;
    *out_bits_written = bits;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_slot_reset_flags(
    uint32_t *sub_dwords20,
    uint8_t *sub_bytes20,
    uint32_t *state_40a8,
    uint32_t *aux_40ac,
    uint8_t clear_aux) {
    if (sub_dwords20 == NULL || sub_bytes20 == NULL || state_40a8 == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *state_40a8 = 0u;
    if (clear_aux != 0u && aux_40ac != NULL) {
        *aux_40ac = 0u;
    }
    for (uint32_t i = 0u; i < ROME2_VFS_L37_MAX_CHANNELS; ++i) {
        sub_dwords20[i] = 0u;
        sub_bytes20[i] = 0u;
    }
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_channel_find_active_slot(
    const rome2_vfs_channel_slot_hdr24_32 *slots,
    const uint32_t *states,
    uint32_t count,
    const rome2_vfs_channel_slot_hdr24_32 *key) {
    if (slots == NULL || states == NULL || key == NULL) {
        return count;
    }
    for (uint32_t i = 0u; i < count && i < ROME2_VFS_L37_MAX_CHANNELS; ++i) {
        if (states[i] == 1u &&
            slots[i].addr_dword_00 == key->addr_dword_00 &&
            slots[i].port_or_tag_04 == key->port_or_tag_04 &&
            slots[i].id_lo_08 == key->id_lo_08 &&
            slots[i].id_hi_0c == key->id_hi_0c) {
            return i;
        }
    }
    return count;
}
