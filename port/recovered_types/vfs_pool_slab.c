#include "vfs_pool_slab.h"

#include <string.h>

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

static rome2_vfs_reg_status read_u32_field(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t offset,
    uint32_t *out_value) {
    rome2_guest_addr32 field_addr = {0};
    rome2_guest_addr32 raw = {0};
    rome2_guest_status gst = rome2_guest_add_checked(base, offset, &field_addr);
    if (gst != ROME2_GUEST_OK) {
        return map_guest_status(gst);
    }
    gst = rome2_guest_read_addr32_le(view, field_addr, &raw);
    if (gst != ROME2_GUEST_OK) {
        return map_guest_status(gst);
    }
    *out_value = raw.value;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status read_string16_layout(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t offset,
    rome2_string16_layout32 *out_str) {
    rome2_string16_layout32 tmp;
    uint32_t len_u32 = 0;
    uint32_t cap_u32 = 0;
    uint32_t data_u32 = 0;
    rome2_vfs_reg_status st;

    memset(&tmp, 0, sizeof(tmp));
    st = read_u32_field(view, base, offset + 0x00u, &len_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, base, offset + 0x04u, &cap_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, base, offset + 0x08u, &data_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    tmp.length_units = (int32_t)len_u32;
    tmp.capacity_units = (int32_t)cap_u32;
    tmp.data = data_u32;
    *out_str = tmp;
    return ROME2_VFS_REG_OK;
}

static void write_u32_le(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t)(val & 0xffu);
    dst[1] = (uint8_t)((val >> 8) & 0xffu);
    dst[2] = (uint8_t)((val >> 16) & 0xffu);
    dst[3] = (uint8_t)((val >> 24) & 0xffu);
}

rome2_vfs_reg_status rome2_vfs_decode_freelist_pool_header32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 pool_addr,
    rome2_vfs_freelist_pool_header32 *out_header) {
    rome2_vfs_freelist_pool_header32 tmp;
    rome2_vfs_reg_status st;

    if (view == NULL || out_header == NULL || pool_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));
    st = read_u32_field(view, pool_addr, 0x00u, &tmp.freelist_head);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, pool_addr, 0x04u, &tmp.slab_chain_head);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, pool_addr, 0x08u, &tmp.reserved_008);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_header = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_slab_descriptor32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 desc_addr,
    rome2_vfs_slab_descriptor32 *out_desc) {
    rome2_vfs_slab_descriptor32 tmp;
    rome2_vfs_reg_status st;

    if (view == NULL || out_desc == NULL || desc_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));
    st = read_u32_field(view, desc_addr, 0x00u, &tmp.node_array);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, desc_addr, 0x04u, &tmp.next_slab);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_desc = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stride28_slab_byte_size(
    uint32_t node_count,
    uint32_t *out_bytes) {
    if (out_bytes == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (node_count > UINT32_MAX / ROME2_VFS_SLAB_NODE_STRIDE) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_bytes = node_count * ROME2_VFS_SLAB_NODE_STRIDE;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_init_stride28_slab(
    uint8_t *slab_bytes,
    size_t slab_byte_capacity,
    rome2_guest_addr32 slab_guest_base,
    uint32_t node_count) {
    uint32_t total_bytes = 0u;
    rome2_guest_addr32 end_guard = {0};
    rome2_vfs_reg_status st;

    if ((slab_bytes == NULL && node_count > 0u) ||
        slab_guest_base.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = rome2_vfs_stride28_slab_byte_size(node_count, &total_bytes);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if ((size_t)total_bytes > slab_byte_capacity) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (node_count == 0u) {
        return ROME2_VFS_REG_OK;
    }
    if (rome2_guest_add_checked(slab_guest_base, total_bytes - 1u, &end_guard) !=
        ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memset(slab_bytes, 0, total_bytes);
    for (uint32_t i = 0u; i < node_count; ++i) {
        size_t offset = (size_t)i * ROME2_VFS_SLAB_NODE_STRIDE;
        uint32_t next_addr = 0u;
        if (i + 1u < node_count) {
            next_addr = slab_guest_base.value +
                        (i + 1u) * ROME2_VFS_SLAB_NODE_STRIDE;
        }
        write_u32_le(slab_bytes + offset, next_addr);
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_verify_stride28_slab_chain(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 slab_guest_base,
    uint32_t node_count,
    rome2_guest_addr32 *out_last_next) {
    uint32_t total_bytes = 0u;
    uint32_t last_next = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || out_last_next == NULL || slab_guest_base.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = rome2_vfs_stride28_slab_byte_size(node_count, &total_bytes);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (node_count == 0u) {
        out_last_next->value = 0u;
        return ROME2_VFS_REG_OK;
    }
    for (uint32_t i = 0u; i < node_count; ++i) {
        uint32_t next_val = 0u;
        uint32_t offset = i * ROME2_VFS_SLAB_NODE_STRIDE;
        st = read_u32_field(view, slab_guest_base, offset, &next_val);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (i + 1u < node_count) {
            uint32_t expected =
                slab_guest_base.value + (i + 1u) * ROME2_VFS_SLAB_NODE_STRIDE;
            if (next_val != expected) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
        } else {
            last_next = next_val;
        }
    }
    out_last_next->value = last_next;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_archive_disposer32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 obj_addr,
    rome2_vfs_archive_name_disposer32 *out_disposer) {
    rome2_vfs_archive_name_disposer32 tmp;
    rome2_vfs_reg_status st;

    if (view == NULL || out_disposer == NULL || obj_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));
    st = read_u32_field(view, obj_addr, 0x00u, &tmp.vtable);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (tmp.vtable != ROME2_VFS_ARCHIVE_DISPOSER_VT32) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    st = read_u32_field(view, obj_addr, 0x04u, &tmp.unobserved_004);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, obj_addr, 0x08u, &tmp.unobserved_008);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, obj_addr, 0x0cu, &tmp.subobj_00c);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, obj_addr, 0x10u, &tmp.owned_node);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, obj_addr, 0x14u, &tmp.tail_014);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_disposer = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_pack_entry_base_vtable32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    uint32_t out_concrete_slots[ROME2_VFS_BASE_CONCRETE_SLOTS]) {
    uint32_t concrete[ROME2_VFS_BASE_CONCRETE_SLOTS];

    if (view == NULL || out_concrete_slots == NULL || vtable_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(concrete, 0, sizeof(concrete));
    for (uint32_t i = 0u; i < ROME2_VFS_BASE_VTABLE_SLOT_COUNT; ++i) {
        uint32_t slot = 0u;
        rome2_vfs_reg_status st = read_u32_field(view, vtable_addr, i * 4u, &slot);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (i < ROME2_VFS_BASE_PURECALL_PREFIX) {
            if (slot != ROME2_VFS_PURECALL32) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
        } else {
            if (slot == 0u || slot == ROME2_VFS_PURECALL32) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
            concrete[i - ROME2_VFS_BASE_PURECALL_PREFIX] = slot;
        }
    }
    memcpy(out_concrete_slots, concrete, sizeof(concrete));
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_mutex_box32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 box_addr,
    rome2_vfs_mutex_box32 *out_box) {
    rome2_vfs_mutex_box32 tmp;
    uint32_t w1 = 0u;
    uint32_t w2 = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || out_box == NULL || box_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));
    st = read_u32_field(view, box_addr, 0x00u, &tmp.vtable_or_tag);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, box_addr, 0x04u, &tmp.cs_debug_info);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, box_addr, 0x08u, &w1);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, box_addr, 0x0cu, &w2);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    tmp.cs_lock_count = (int32_t)w1;
    tmp.cs_recursion_count = (int32_t)w2;
    st = read_u32_field(view, box_addr, 0x10u, &tmp.cs_owning_thread);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, box_addr, 0x14u, &tmp.cs_lock_semaphore);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, box_addr, 0x18u, &tmp.cs_spin_count);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_box = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_global_map32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 map_addr,
    rome2_vfs_global_map32 *out_map,
    uint32_t *out_bucket_bytes) {
    rome2_vfs_global_map32 tmp;
    uint32_t bucket_bytes = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || out_map == NULL || out_bucket_bytes == NULL ||
        map_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));
    st = read_u32_field(view, map_addr, 0x00u, &tmp.buckets);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, map_addr, 0x04u, &tmp.bucket_count);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (tmp.bucket_count > UINT32_MAX / ROME2_VFS_MAP_BUCKET_STRIDE) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    bucket_bytes = tmp.bucket_count * ROME2_VFS_MAP_BUCKET_STRIDE;
    st = read_string16_layout(view, map_addr, 0x08u, &tmp.removed_key);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_string16_layout(view, map_addr, 0x14u, &tmp.unused_key);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_field(view, map_addr, 0x20u, &tmp.reserved_020);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_map = tmp;
    *out_bucket_bytes = bucket_bytes;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_setting_flags_compute32(
    uint32_t existing_flags,
    uint32_t vb_ptr_val,
    uint32_t arg_flags,
    uint32_t resolved_status,
    uint32_t *out_next_flags) {
    uint32_t effective;
    uint32_t next;

    if (out_next_flags == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if ((arg_flags & 4u) != 0u) {
        effective = arg_flags | 4u;
    } else {
        effective = resolved_status;
    }
    if (effective == 1u) {
        *out_next_flags = existing_flags;
        return ROME2_VFS_REG_OK;
    }
    next = existing_flags | effective;
    if (vb_ptr_val == 0u) {
        next |= 8u;
    }
    *out_next_flags = next & 0xfu;
    return ROME2_VFS_REG_OK;
}
