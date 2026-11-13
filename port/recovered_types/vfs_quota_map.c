#include "vfs_quota_map.h"

#include <string.h>

#include "vfs_pool_slab.h"

static rome2_vfs_reg_status map_guest_status(rome2_guest_status st) {
    switch (st) {
    case ROME2_GUEST_OK:
        return ROME2_VFS_REG_OK;
    case ROME2_GUEST_BAD_ARGUMENT:
    case ROME2_GUEST_NULL_ADDRESS:
        return ROME2_VFS_REG_BAD_ARGUMENT;
    case ROME2_GUEST_RANGE_OVERFLOW:
    case ROME2_GUEST_OUT_OF_RANGE:
        return ROME2_VFS_REG_RANGE_ERROR;
    default:
        return ROME2_VFS_REG_INVALID_STATE;
    }
}

static rome2_vfs_reg_status read_u32_at(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t offset,
    uint32_t *out_val) {
    rome2_guest_addr32 addr = {0};
    rome2_guest_addr32 raw = {0};
    rome2_guest_status gst = rome2_guest_add_checked(base, offset, &addr);
    if (gst != ROME2_GUEST_OK) {
        return map_guest_status(gst);
    }
    gst = rome2_guest_read_addr32_le(view, addr, &raw);
    if (gst != ROME2_GUEST_OK) {
        return map_guest_status(gst);
    }
    *out_val = raw.value;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status read_u16_at(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t offset,
    uint16_t *out_val) {
    rome2_guest_addr32 addr = {0};
    rome2_guest_status gst = rome2_guest_add_checked(base, offset, &addr);
    if (gst != ROME2_GUEST_OK) {
        return map_guest_status(gst);
    }
    gst = rome2_guest_read_u16_le(view, addr, out_val);
    if (gst != ROME2_GUEST_OK) {
        return map_guest_status(gst);
    }
    return ROME2_VFS_REG_OK;
}

static uint32_t read_le_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static rome2_vfs_reg_status read_string16_desc(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_string16_layout32 *out_str) {
    uint32_t len_u32 = 0u;
    uint32_t cap_u32 = 0u;
    uint32_t data_u32 = 0u;
    rome2_vfs_reg_status st;

    st = read_u32_at(view, addr, 0x00u, &len_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, addr, 0x04u, &cap_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, addr, 0x08u, &data_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    out_str->length_units = (int32_t)len_u32;
    out_str->capacity_units = (int32_t)cap_u32;
    out_str->data = data_u32;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status compare_utf16_desc_raw(
    const rome2_guest_read_view *view,
    const rome2_string16_layout32 *desc,
    const uint16_t *key_units,
    size_t key_unit_count,
    int *out_equal) {
    if (desc->length_units < 0) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if ((size_t)desc->length_units != key_unit_count) {
        *out_equal = 0;
        return ROME2_VFS_REG_OK;
    }
    if (key_unit_count == 0u) {
        *out_equal = 1;
        return ROME2_VFS_REG_OK;
    }
    if (desc->data == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (key_unit_count > UINT32_MAX / 2u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (size_t i = 0u; i < key_unit_count; ++i) {
        uint16_t unit = 0u;
        rome2_vfs_reg_status st = read_u16_at(
            view, (rome2_guest_addr32){desc->data}, (uint32_t)(i * 2u), &unit);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (unit != key_units[i]) {
            *out_equal = 0;
            return ROME2_VFS_REG_OK;
        }
    }
    *out_equal = 1;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status compare_two_utf16_descs(
    const rome2_guest_read_view *view,
    const rome2_string16_layout32 *a,
    const rome2_string16_layout32 *b,
    int *out_equal) {
    if (a->length_units < 0 || b->length_units < 0) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (a->length_units != b->length_units) {
        *out_equal = 0;
        return ROME2_VFS_REG_OK;
    }
    if (a->length_units == 0) {
        *out_equal = 1;
        return ROME2_VFS_REG_OK;
    }
    if (a->data == 0u || b->data == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if ((uint32_t)a->length_units > UINT32_MAX / 2u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (uint32_t i = 0u; i < (uint32_t)a->length_units; ++i) {
        uint16_t ua = 0u;
        uint16_t ub = 0u;
        rome2_vfs_reg_status st =
            read_u16_at(view, (rome2_guest_addr32){a->data}, i * 2u, &ua);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        st = read_u16_at(view, (rome2_guest_addr32){b->data}, i * 2u, &ub);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (ua != ub) {
            *out_equal = 0;
            return ROME2_VFS_REG_OK;
        }
    }
    *out_equal = 1;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_hash_utf16_key32(
    const uint16_t *units,
    size_t unit_count,
    uint32_t *out_hash) {
    uint32_t hash = ROME2_VFS_HASH_SEED32;
    uint32_t shift = 0u;

    if (out_hash == NULL || (units == NULL && unit_count > 0u)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (unit_count > UINT32_MAX / 2u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (size_t i = unit_count; i > 0u; --i) {
        hash ^= ((uint32_t)units[i - 1u]) << shift;
        shift = (shift + 8u) & 0x1fu;
    }
    *out_hash = hash;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_global_map_probe32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 map_addr,
    const uint16_t *key_units,
    size_t key_unit_count,
    rome2_guest_addr32 *out_value_slot_addr) {
    rome2_vfs_global_map32 map;
    uint32_t bucket_bytes = 0u;
    uint32_t hash = 0u;
    uint32_t start_idx = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || out_value_slot_addr == NULL || map_addr.value == 0u ||
        (key_units == NULL && key_unit_count > 0u)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&map, 0, sizeof(map));
    st = rome2_vfs_decode_global_map32(view, map_addr, &map, &bucket_bytes);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (map.buckets == 0u || map.bucket_count == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    st = rome2_vfs_hash_utf16_key32(key_units, key_unit_count, &hash);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    start_idx = hash % map.bucket_count;

    for (uint32_t step = 0u; step < map.bucket_count; ++step) {
        uint32_t idx = (start_idx + step) % map.bucket_count;
        rome2_guest_addr32 slot_addr = {0};
        rome2_string16_layout32 slot_key;
        int matched = 0;

        if (rome2_guest_add_checked((rome2_guest_addr32){map.buckets},
                                    idx * ROME2_VFS_MAP_BUCKET_STRIDE,
                                    &slot_addr) != ROME2_GUEST_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        memset(&slot_key, 0, sizeof(slot_key));
        st = read_string16_desc(view, slot_addr, &slot_key);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        st = compare_utf16_desc_raw(view, &slot_key, key_units, key_unit_count,
                                    &matched);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (matched != 0) {
            rome2_guest_addr32 val_addr = {0};
            if (rome2_guest_add_checked(slot_addr, 0x0cu, &val_addr) !=
                ROME2_GUEST_OK) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            *out_value_slot_addr = val_addr;
            return ROME2_VFS_REG_OK;
        }
        st = compare_two_utf16_descs(view, &slot_key, &map.unused_key,
                                     &matched);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (matched != 0) {
            return ROME2_VFS_REG_NOT_FOUND;
        }
    }
    return ROME2_VFS_REG_NOT_FOUND;
}

rome2_vfs_reg_status rome2_vfs_pack_header_decode32(
    const uint8_t *header_bytes,
    size_t byte_count,
    rome2_vfs_pack_header_wire32 *out_header) {
    rome2_vfs_pack_header_wire32 tmp;

    if (header_bytes == NULL || out_header == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (byte_count < ROME2_VFS_PACK_WIRE_HDR_BYTES) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memset(&tmp, 0, sizeof(tmp));
    tmp.signature = read_le_u32(header_bytes + 0x00u);
    tmp.flags = read_le_u32(header_bytes + 0x04u);
    tmp.dep_count = read_le_u32(header_bytes + 0x08u);
    tmp.dep_bytes = read_le_u32(header_bytes + 0x0cu);
    tmp.entry_count = read_le_u32(header_bytes + 0x10u);
    tmp.index_bytes = read_le_u32(header_bytes + 0x14u);
    tmp.default_entry_meta = read_le_u32(header_bytes + 0x18u);
    *out_header = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_quota_check_and_reserve(
    rome2_vfs_quota_frame32 *io_frame,
    uint32_t byte_delta,
    uint32_t *out_accepted) {
    if (io_frame == NULL || out_accepted == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (io_frame->used_ops >= io_frame->max_ops ||
        byte_delta > io_frame->max_bytes ||
        io_frame->used_bytes > io_frame->max_bytes - byte_delta) {
        *out_accepted = 0u;
        return ROME2_VFS_REG_OK;
    }
    io_frame->used_bytes += byte_delta;
    io_frame->used_ops += 1u;
    *out_accepted = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_count_rb_live_nodes32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 root_addr,
    uint32_t step_limit,
    uint32_t *out_node_count) {
    rome2_guest_addr32 stack[ROME2_VFS_MAX_RB_STACK_DEPTH];
    size_t sp = 0u;
    uint32_t count = 0u;

    if (view == NULL || out_node_count == NULL || root_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    stack[sp++] = root_addr;
    while (sp > 0u) {
        rome2_guest_addr32 cur = stack[--sp];
        uint32_t meta_word = 0u;
        uint8_t is_nil = 0u;
        uint32_t left_u32 = 0u;
        uint32_t right_u32 = 0u;
        rome2_vfs_reg_status st;

        st = read_u32_at(view, cur, 0x0cu, &meta_word);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        is_nil = (uint8_t)((meta_word >> 8) & 0xffu);
        if (is_nil != 0u) {
            continue;
        }
        if (count >= step_limit) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        ++count;
        st = read_u32_at(view, cur, 0x00u, &left_u32);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        st = read_u32_at(view, cur, 0x08u, &right_u32);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (left_u32 != 0u) {
            if (sp >= ROME2_VFS_MAX_RB_STACK_DEPTH) {
                return ROME2_VFS_REG_STEP_LIMIT;
            }
            stack[sp++] = (rome2_guest_addr32){left_u32};
        }
        if (right_u32 != 0u) {
            if (sp >= ROME2_VFS_MAX_RB_STACK_DEPTH) {
                return ROME2_VFS_REG_STEP_LIMIT;
            }
            stack[sp++] = (rome2_guest_addr32){right_u32};
        }
    }
    *out_node_count = count;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_build_stream_slice_view32(
    const rome2_vfs_stream_slice_view32 *src,
    rome2_vfs_stream_slice_view32 *out_dst) {
    if (src == NULL || out_dst == NULL || src->entry == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_dst = *src;
    return ROME2_VFS_REG_OK;
}
