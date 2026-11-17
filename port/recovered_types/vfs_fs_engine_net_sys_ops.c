#include "vfs_fs_engine_net_sys_ops.h"

#include <stdio.h>
#include <string.h>

static rome2_vfs_reg_status rome2_widen_ascii_buf(
    const char *src,
    uint32_t src_len,
    uint16_t *dst,
    uint32_t dst_cap) {
    if (src == NULL || dst == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (src_len + 1u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (uint32_t i = 0u; i < src_len; ++i) {
        dst[i] = (uint16_t)(uint8_t)src[i];
    }
    dst[src_len] = 0u;
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_sse_zero_tls_va(void) {
    return ROME2_VFS_L39_SSE_ZERO_TLS_VA;
}

rome2_vfs_reg_status rome2_vfs_sse_zero_init16(
    int32_t *inout_guard,
    uint8_t out_vec16[16],
    int32_t tls_epoch,
    uint8_t *out_initialized) {
    if (inout_guard == NULL || out_vec16 == NULL || out_initialized == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_initialized = 0u;
    if (*inout_guard > tls_epoch && *inout_guard == -1) {
        memset(out_vec16, 0, 16u);
        *inout_guard = 0;
        *out_initialized = 1u;
    }
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_channel_mgr_singleton_va(
    int32_t *inout_guard,
    int32_t tls_epoch,
    uint8_t *out_constructed) {
    if (out_constructed != NULL) {
        *out_constructed = 0u;
    }
    if (inout_guard != NULL && *inout_guard > tls_epoch && *inout_guard == -1) {
        *inout_guard = 0;
        if (out_constructed != NULL) {
            *out_constructed = 1u;
        }
    }
    return ROME2_VFS_L39_CHANNEL_MGR_VA;
}

rome2_vfs_reg_status rome2_vfs_threadname_info16_fill(
    rome2_vfs_threadname_info16_32 *info,
    uint32_t sz_name_va,
    uint32_t thread_id) {
    if (info == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    info->dw_type_00 = 0x1000u;
    info->sz_name_04 = sz_name_va;
    info->dw_thread_id_08 = thread_id;
    info->dw_flags_0c = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstr_prepend_char(
    uint16_t prefix_ch,
    const uint16_t *src,
    uint32_t src_len,
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len) {
    if (dst == NULL || out_len == NULL || (src_len > 0u && src == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (src_len > 0xfffffffdu || src_len + 2u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    dst[0] = prefix_ch;
    for (uint32_t i = 0u; i < src_len; ++i) {
        dst[i + 1u] = src[i];
    }
    dst[src_len + 1u] = 0u;
    *out_len = src_len + 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstr_pad_aligned(
    const uint16_t *src,
    uint32_t src_len,
    uint16_t min_width,
    uint8_t left_align,
    uint16_t pad_ch,
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len) {
    uint32_t total = src_len;
    uint32_t pad = 0u;
    uint32_t pos = 0u;

    if (dst == NULL || out_len == NULL || (src_len > 0u && src == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if ((uint32_t)min_width > src_len) {
        pad = (uint32_t)min_width - src_len;
        total = (uint32_t)min_width;
    }
    if (total > 0xfffffffeu || total + 1u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (left_align == 0u) {
        for (uint32_t i = 0u; i < pad; ++i) {
            dst[pos++] = pad_ch;
        }
    }
    for (uint32_t i = 0u; i < src_len; ++i) {
        dst[pos++] = src[i];
    }
    if (left_align != 0u) {
        for (uint32_t i = 0u; i < pad; ++i) {
            dst[pos++] = pad_ch;
        }
    }
    dst[pos] = 0u;
    *out_len = total;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstr_substr_slice(
    const uint16_t *src,
    uint32_t src_len,
    uint32_t pos,
    uint32_t count,
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len) {
    uint32_t avail = 0u;
    uint32_t n = 0u;

    if (dst == NULL || out_len == NULL || (src_len > 0u && src == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (pos > src_len) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    avail = src_len - pos;
    n = (count < avail) ? count : avail;
    if (n + 1u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (uint32_t i = 0u; i < n; ++i) {
        dst[i] = src[pos + i];
    }
    dst[n] = 0u;
    *out_len = n;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_format_scalar_type_error(
    char spec_ch,
    const char *type_name,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len) {
    char tmp[128];
    int32_t n = 0;

    if (type_name == NULL || out_wstr == NULL || out_len == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_len = 0u;
    n = snprintf(tmp, sizeof(tmp), "Unexpected format %%%c used with type %s",
        (int)(uint8_t)spec_ch, type_name);
    if (n < 0 || (uint32_t)n >= sizeof(tmp)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (rome2_widen_ascii_buf(tmp, (uint32_t)n, out_wstr, out_cap) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_len = (uint32_t)n;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_format_int32_card32(
    uint32_t val,
    char spec_ch,
    uint8_t is_signed,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok) {
    char tmp[64];
    int32_t n = -1;

    if (out_wstr == NULL || out_len == NULL || out_ok == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_len = 0u;
    *out_ok = 0u;

    switch (spec_ch) {
        case 'd':
        case 'i':
            n = (is_signed != 0u)
                ? snprintf(tmp, sizeof(tmp), "%d", (int32_t)val)
                : snprintf(tmp, sizeof(tmp), "%u", val);
            break;
        case 'u':
            n = snprintf(tmp, sizeof(tmp), "%u", val);
            break;
        case 'o':
            n = snprintf(tmp, sizeof(tmp), "%o", val);
            break;
        case 'x':
            n = snprintf(tmp, sizeof(tmp), "%x", val);
            break;
        case 'X':
            n = snprintf(tmp, sizeof(tmp), "%X", val);
            break;
        case 'c':
            n = snprintf(tmp, sizeof(tmp), "%c", (int)(uint8_t)val);
            break;
        default:
            return rome2_vfs_format_scalar_type_error(
                spec_ch,
                (is_signed != 0u) ? "int32" : "card32",
                out_wstr,
                out_cap,
                out_len);
    }

    if (n < 0 || (uint32_t)n >= sizeof(tmp)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (rome2_widen_ascii_buf(tmp, (uint32_t)n, out_wstr, out_cap) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_len = (uint32_t)n;
    *out_ok = 1u;
    return ROME2_VFS_REG_OK;
}

const char *rome2_vfs_winsock_err_str(uint32_t slot_idx, uint32_t wsa_err) {
    if (slot_idx <= 7u) {
        switch (slot_idx) {
            case 0u:
            case 1u:
            case 2u:
            case 3u:
            case 4u:
            case 5u:
            case 6u:
            case 7u:
            default:
                break;
        }
    }
    switch (wsa_err) {
        case 0x2af9u:
            return "Authoritative answer host not found.";
        case 0x2afau:
            return "Nonauthoritative host not found, or server failure.";
        case 0x2afbu:
            return "A nonrecoverable error occurred.";
        case 0x2afcu:
            return "Valid name, no data record of requested type.";
        default:
            return "Undocumented error.";
    }
}

rome2_vfs_reg_status rome2_vfs_dlmalloc_sys_alloc_plan(
    const rome2_vfs_dlmalloc_mstate448_32 *ms,
    uint32_t nb,
    uint32_t granularity,
    uint32_t mmap_threshold,
    uint32_t *out_alloc_sz,
    uint8_t *out_use_mmap) {
    uint32_t gmask = 0u;
    uint32_t asize = 0u;

    if (ms == NULL || out_alloc_sz == NULL || out_use_mmap == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (granularity == 0u || (granularity & (granularity - 1u)) != 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    gmask = granularity - 1u;
    *out_alloc_sz = 0u;
    *out_use_mmap = 0u;

    if ((ms->mflags_1bc & 1u) != 0u && nb >= mmap_threshold && ms->topsize_0c == 0u) {
        if (nb > 0xffffffffu - 0x1eu - gmask) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        asize = (nb + 0x1eu + gmask) & ~gmask;
        if (asize > nb && (ms->footprint_limit_1b8 == 0u ||
            (ms->footprint_1b0 + asize > ms->footprint_1b0 &&
             ms->footprint_1b0 + asize <= ms->footprint_limit_1b8))) {
            *out_alloc_sz = asize;
            *out_use_mmap = 1u;
            return ROME2_VFS_REG_OK;
        }
    }

    if (nb > 0xffffffffu - 0x2fu - gmask) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    asize = (nb + 0x2fu + gmask) & ~gmask;
    if (asize <= nb) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (ms->footprint_limit_1b8 != 0u &&
        (ms->footprint_1b0 + asize <= ms->footprint_1b0 ||
         ms->footprint_1b0 + asize > ms->footprint_limit_1b8)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_alloc_sz = asize;
    *out_use_mmap = 0u;
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_msb_width_u32(uint32_t val) {
    uint32_t clz = 0u;
    uint32_t mask = 0x80000000u;
    if ((val & mask) != 0u) {
        return 32u;
    }
    while (mask != 0u) {
        mask >>= 1;
        ++clz;
        if ((val & mask) != 0u) {
            break;
        }
    }
    return 32u - clz;
}

rome2_vfs_reg_status rome2_vfs_bitcopy_msb(
    uint8_t *dst,
    uint32_t dst_byte_cap,
    uint32_t *inout_dst_bit,
    const uint8_t *src,
    uint32_t src_byte_cap,
    uint32_t *inout_src_bit,
    uint32_t bit_count,
    uint32_t *out_copied) {
    if (dst == NULL || inout_dst_bit == NULL || src == NULL ||
        inout_src_bit == NULL || out_copied == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_copied = 0u;
    if (bit_count == 0u) {
        return ROME2_VFS_REG_OK;
    }
    if (dst_byte_cap > 0x1fffffffu || src_byte_cap > 0x1fffffffu ||
        bit_count > dst_byte_cap * 8u || *inout_dst_bit > dst_byte_cap * 8u - bit_count ||
        bit_count > src_byte_cap * 8u || *inout_src_bit > src_byte_cap * 8u - bit_count) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    for (uint32_t k = 0u; k < bit_count; ++k) {
        uint32_t sbit = *inout_src_bit + k;
        uint32_t dbit = *inout_dst_bit + k;
        uint32_t bit = (uint32_t)((src[sbit >> 3] >> (7u - (sbit & 7u))) & 1u);
        uint32_t dshift = 7u - (dbit & 7u);
        dst[dbit >> 3] = (uint8_t)((dst[dbit >> 3] & ~(1u << dshift)) | (bit << dshift));
    }
    *inout_dst_bit += bit_count;
    *inout_src_bit += bit_count;
    *out_copied = bit_count;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_seq_ack_ring_pop(
    rome2_vfs_seq_ack_ring36_32 *ring,
    uint8_t *bitmap,
    uint32_t bitmap_len,
    uint32_t *ack_out_arr,
    uint32_t ack_cap,
    int32_t seq_val,
    uint8_t *out_acked,
    uint8_t *out_freed_external) {
    int32_t base = 0;
    int32_t stride = 0;

    if (ring == NULL || out_acked == NULL || out_freed_external == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_acked = 0u;
    *out_freed_external = 0u;
    base = (int32_t)ring->base_seq_0c;
    stride = (int32_t)ring->stride_18;

    if (stride > 0 && seq_val >= base &&
        (int64_t)(seq_val - base) < (int64_t)ring->cap_1c * (int64_t)stride) {
        uint32_t bidx = (uint32_t)((seq_val - base) / stride);
        if (bitmap != NULL && bidx < bitmap_len && bitmap[bidx] != 0u) {
            if (ack_out_arr == NULL || ring->ack_count_20 >= ack_cap) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            bitmap[bidx] = 0u;
            ack_out_arr[ring->ack_count_20] = (uint32_t)seq_val;
            ring->ack_count_20 += 1u;
            *out_acked = 1u;
            return ROME2_VFS_REG_OK;
        }
    }
    *out_freed_external = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_hdr24_reset(rome2_vfs_channel_slot_hdr24_32 *hdr) {
    if (hdr == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(hdr, 0, sizeof(*hdr));
    hdr->sock_fd_10 = 0xffffffffu;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_meta36_reset(rome2_vfs_channel_slot_meta36_32 *meta) {
    if (meta == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(meta, 0, sizeof(*meta));
    meta->aux_sock_10 = 0xffffffffu;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_slot_meta_move(
    rome2_vfs_channel_slot_meta36_32 *dst_meta,
    rome2_vfs_channel_slot_hdr24_32 *dst_hdr,
    const rome2_vfs_channel_slot_meta36_32 *src_meta,
    rome2_vfs_channel_slot_hdr24_32 *src_hdr,
    uint8_t *out_closed_prev_sock) {
    if (dst_meta == NULL || dst_hdr == NULL || src_meta == NULL ||
        src_hdr == NULL || out_closed_prev_sock == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_closed_prev_sock = (dst_hdr->active_flag_14 != 0u && dst_hdr->sock_fd_10 != 0xffffffffu) ? 1u : 0u;
    *dst_meta = *src_meta;
    dst_hdr->sock_fd_10 = src_hdr->sock_fd_10;
    dst_hdr->active_flag_14 = src_hdr->active_flag_14;
    src_hdr->active_flag_14 = 0u;
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_channel_hdr24_endpoint_matches(
    const rome2_vfs_channel_slot_hdr24_32 *a,
    const rome2_vfs_channel_slot_hdr24_32 *b,
    uint8_t steam_id_valid) {
    if (a == NULL || b == NULL) {
        return 0u;
    }
    if (steam_id_valid != 0u && a->id_lo_08 == b->id_lo_08 && a->id_hi_0c == b->id_hi_0c) {
        return 1u;
    }
    if (a->addr_dword_00 != 0u && a->addr_dword_00 == b->addr_dword_00) {
        return 1u;
    }
    return 0u;
}

uint8_t rome2_vfs_steam_p2p_state_ready(
    uint8_t ctx_nonnull,
    uint8_t id_valid,
    uint8_t session_state_ok) {
    return (ctx_nonnull != 0u && id_valid != 0u && session_state_ok != 0u) ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_channel_frame_send_plan(
    uint32_t payload_len,
    uint8_t steam_ready,
    uint8_t tcp_ready,
    uint8_t reliable,
    uint8_t *out_route,
    uint8_t out_framed_hdr2[2],
    uint32_t *out_wire_bytes) {
    (void)reliable;
    if (out_route == NULL || out_framed_hdr2 == NULL || out_wire_bytes == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    out_framed_hdr2[0] = 0u;
    out_framed_hdr2[1] = 0u;
    *out_wire_bytes = 0u;

    if (steam_ready != 0u) {
        *out_route = 1u;
        *out_wire_bytes = payload_len;
        return ROME2_VFS_REG_OK;
    }
    if (tcp_ready == 0u) {
        *out_route = 0u;
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (payload_len > ROME2_VFS_L39_MAX_TCP_FRAME_BYTES - 2u) {
        *out_route = 0u;
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_route = 2u;
    out_framed_hdr2[0] = (uint8_t)(payload_len & 0xffu);
    out_framed_hdr2[1] = (uint8_t)((payload_len >> 8) & 0xffu);
    *out_wire_bytes = payload_len + 2u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_broadcast_validate(
    uint32_t sender_ch,
    uint32_t target_ch,
    uint32_t target_state,
    uint8_t slot_ready,
    uint32_t ack_seq_delta_bytes,
    uint8_t *out_ok) {
    if (out_ok == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_ok = 0u;
    if (sender_ch >= ROME2_VFS_L37_MAX_CHANNELS ||
        target_ch >= ROME2_VFS_L37_MAX_CHANNELS ||
        target_state != 1u ||
        slot_ready == 0u ||
        ack_seq_delta_bytes > ROME2_VFS_L39_MAX_BCAST_PATCH_BYTES) {
        return ROME2_VFS_REG_OK;
    }
    *out_ok = 1u;
    return ROME2_VFS_REG_OK;
}
