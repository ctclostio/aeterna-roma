#include "vfs_scan_mount.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>

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

static rome2_guest_addr32 addr32(uint32_t value) {
    rome2_guest_addr32 out = {value};
    return out;
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

rome2_vfs_reg_status rome2_vfs_thread_bucket_hash32(
    uint32_t thread_id,
    uint32_t bucket_count,
    uint32_t *out_bucket) {
    if (out_bucket == NULL || bucket_count == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_bucket = (thread_id ^ ROME2_VFS_THREAD_HASH_XOR32) % bucket_count;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_thread_bucket_lookup32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 map_addr,
    uint32_t thread_id,
    uint32_t step_limit,
    rome2_guest_addr32 *out_node_addr) {
    uint32_t bucket_count = 0u;
    uint32_t buckets_base_u32 = 0u;
    uint32_t bucket_idx = 0u;
    uint64_t bucket_off = 0u;
    rome2_guest_addr32 bucket_addr = {0};
    rome2_guest_addr32 sentinel_addr = {0};
    uint32_t cur_u32 = 0u;
    uint32_t step = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || map_addr.value == 0u || out_node_addr == NULL ||
        step_limit == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    st = read_u32_at(view, map_addr, 0x08u, &bucket_count);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, map_addr, 0x0cu, &buckets_base_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (bucket_count == 0u || buckets_base_u32 == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    (void)rome2_vfs_thread_bucket_hash32(thread_id, bucket_count, &bucket_idx);
    bucket_off = (uint64_t)bucket_idx * sizeof(rome2_vfs_open_bucket_slot32);
    if (bucket_off > (uint64_t)UINT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (rome2_guest_add_checked(
            addr32(buckets_base_u32),
            (uint32_t)bucket_off,
            &bucket_addr) != ROME2_GUEST_OK ||
        rome2_guest_add_checked(bucket_addr, 0x04u, &sentinel_addr) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    st = read_u32_at(view, bucket_addr, 0x00u, &cur_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }

    while (cur_u32 != sentinel_addr.value) {
        uint32_t node_key = 0u;
        uint32_t next_u32 = 0u;
        rome2_guest_addr32 node_addr = {0};

        if (cur_u32 == 0u || step >= step_limit) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        node_addr = addr32(cur_u32);
        st = read_u32_at(view, node_addr, 0x08u, &node_key);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (node_key == thread_id) {
            out_node_addr->value = cur_u32;
            return ROME2_VFS_REG_OK;
        }
        st = read_u32_at(view, node_addr, 0x04u, &next_u32);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (next_u32 == cur_u32) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        cur_u32 = next_u32;
        step++;
    }

    out_node_addr->value = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_bucket_map_should_rehash32(
    uint32_t next_element_count,
    uint32_t bucket_count,
    float max_load_factor,
    uint32_t *out_should_rehash,
    uint32_t *out_new_buckets) {
    float load_factor = 0.0f;
    uint32_t should_rehash = 0u;
    uint64_t doubled = 0u;

    if (out_should_rehash == NULL || out_new_buckets == NULL ||
        bucket_count == 0u || !isfinite(max_load_factor) ||
        max_load_factor <= 0.0f) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    /* Matches 0x112cbe10: CVTDQ2PD -> CVTPD2PS + DIVSS compared against max_load_factor. */
    load_factor = (float)((double)next_element_count) / (float)((double)bucket_count);
    should_rehash = (load_factor > max_load_factor) ? 1u : 0u;

    if (should_rehash != 0u) {
        doubled = (uint64_t)bucket_count * 2u + 1u;
        if (doubled > (uint64_t)UINT32_MAX) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        *out_should_rehash = 1u;
        *out_new_buckets = (uint32_t)doubled;
        return ROME2_VFS_REG_OK;
    }

    *out_should_rehash = 0u;
    *out_new_buckets = bucket_count;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_ref_pack_block32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 block_addr,
    rome2_vfs_ref_pack_block_header32 *out_header,
    uint32_t *out_embedded_last_error,
    uint32_t *out_embedded_entry_count) {
    rome2_vfs_ref_pack_block_header32 hdr = {0};
    uint32_t strong_u32 = 0u;
    uint32_t weak_u32 = 0u;
    uint32_t last_err = 0u;
    uint32_t entry_cnt = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || block_addr.value == 0u || out_header == NULL ||
        out_embedded_last_error == NULL || out_embedded_entry_count == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    st = read_u32_at(view, block_addr, 0x00u, &hdr.vtable);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, block_addr, 0x04u, &strong_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, block_addr, 0x08u, &weak_u32);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    hdr.strong_ref = (int32_t)strong_u32;
    hdr.weak_ref = (int32_t)weak_u32;
    if (hdr.vtable != ROME2_VFS_REF_PACK_VTABLE32 || hdr.strong_ref < 0 ||
        hdr.weak_ref < 0) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    /* Embedded pack_props begins at block + 0x0c; last_error is +0x04, entry_count is +0x28. */
    st = read_u32_at(view, block_addr, 0x0cu + 0x04u, &last_err);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, block_addr, 0x0cu + 0x28u, &entry_cnt);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }

    *out_header = hdr;
    *out_embedded_last_error = last_err;
    *out_embedded_entry_count = entry_cnt;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_scan_post_mount_mismatches32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 table_addr,
    uint32_t max_slots,
    rome2_vfs_post_scan_table32 *out_table,
    uint32_t *out_mismatch_count) {
    rome2_vfs_post_scan_table32 tbl = {0};
    uint32_t def_lo = 0u;
    uint32_t def_hi = 0u;
    uint32_t mismatches = 0u;
    uint32_t i = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || table_addr.value == 0u || max_slots == 0u ||
        out_table == NULL || out_mismatch_count == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    st = read_u32_at(view, table_addr, 0x00u, &tbl.entries);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, table_addr, 0x04u, &tbl.entry_count);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, table_addr, 0x08u, &def_lo);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at(view, table_addr, 0x0cu, &def_hi);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    tbl.default_entry = (uint64_t)def_lo | ((uint64_t)def_hi << 32);

    if (tbl.entry_count > max_slots) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (tbl.entry_count > 0u && tbl.entries == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    for (i = 0u; i < tbl.entry_count; i++) {
        uint64_t off = (uint64_t)i * 8u;
        uint32_t lo = 0u;
        uint32_t hi = 0u;
        uint64_t slot_val = 0u;

        if (off + 4u > (uint64_t)UINT32_MAX) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        st = read_u32_at(view, addr32(tbl.entries), (uint32_t)off, &lo);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        st = read_u32_at(
            view,
            addr32(tbl.entries),
            (uint32_t)(off + 4u),
            &hi);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        slot_val = (uint64_t)lo | ((uint64_t)hi << 32);
        if (slot_val != tbl.default_entry) {
            mismatches++;
        }
    }

    *out_table = tbl;
    *out_mismatch_count = mismatches;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_validate_stream_wrap_a32(
    const rome2_vfs_stream_wrap_a32 *wrap) {
    if (wrap == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (wrap->vtable != ROME2_VFS_STREAM_WRAP_A_VTABLE32 ||
        wrap->flag_004 != 0u || wrap->zero_020 != 0u || wrap->zero_024 != 0u ||
        wrap->flag_028 != 0u || wrap->zero_02c != 0u || wrap->zero_030 != 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_validate_stream_wrap_b32(
    const rome2_vfs_stream_wrap_b32 *wrap) {
    size_t i = 0u;

    if (wrap == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (wrap->vtable != ROME2_VFS_STREAM_WRAP_B_VTABLE32 ||
        wrap->flag_004 != 0u || wrap->flag_030 != 0u || wrap->flag_034 != 0u ||
        wrap->zero_038 != 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    for (i = 0u; i < 4u; i++) {
        if (wrap->zero_020[i] != 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
    }
    return ROME2_VFS_REG_OK;
}
