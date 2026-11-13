#include "vfs_pack_stream.h"

rome2_vfs_reg_status rome2_vfs_plan_aligned_alloc(
    uint32_t requested_bytes, uint32_t requested_align, uint64_t raw_base,
    rome2_vfs_aligned_alloc_plan *out_plan)
{
    uint32_t align;
    uint64_t overhead;
    uint64_t total64;
    uint64_t start;
    uint64_t rem;
    rome2_vfs_aligned_alloc_plan plan;

    if (out_plan == NULL || raw_base == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    align = (requested_align < 4u) ? 4u : requested_align;
    overhead = UINT64_C(4) + (uint64_t)align;
    total64 = (uint64_t)requested_bytes + overhead;
    if (total64 > (uint64_t)UINT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (raw_base > UINT64_MAX - overhead) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    start = raw_base + overhead;
    rem = start % (uint64_t)align;
    plan.effective_align = align;
    plan.alloc_bytes = (uint32_t)total64;
    plan.aligned_addr = start - rem;
    if (plan.aligned_addr < raw_base + UINT64_C(4)) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    plan.backptr_slot_addr = plan.aligned_addr - UINT64_C(4);

    *out_plan = plan;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_entry_clamp_slice32(
    const rome2_guest_read_view *entries, rome2_guest_addr32 entry_addr,
    uint32_t req_len, uint32_t req_offset,
    rome2_vfs_entry_slice_clamp32 *output)
{
    rome2_vfs_pack_entry_info32 entry;
    rome2_vfs_reg_status status;
    uint32_t avail;
    uint32_t clamped;
    rome2_vfs_entry_slice_clamp32 parsed;

    if (entries == NULL || output == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    status = rome2_vfs_entry_read32(entries, entry_addr, &entry);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }
    if (req_offset > entry.byte_size) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    avail = entry.byte_size - req_offset;
    if (req_len != 0u && avail >= req_len) {
        clamped = req_len;
    } else {
        clamped = avail;
    }
    if ((uint64_t)req_offset > UINT64_MAX - entry.data_offset) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    parsed.clamped_len = clamped;
    parsed.relative_offset = req_offset;
    parsed.entry_byte_size = entry.byte_size;
    parsed.entry_pack_offset = entry.data_offset;
    parsed.slice_pack_offset = entry.data_offset + (uint64_t)req_offset;
    parsed.stream_state = entry.stream_state;

    *output = parsed;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_entry_has_per_entry_meta32(
    const rome2_guest_read_view *entries, rome2_guest_addr32 entry_addr,
    const rome2_guest_read_view *carriers,
    const rome2_guest_read_view *pack_props_view,
    bool *out_has_meta)
{
    rome2_vfs_pack_entry_info32 entry;
    rome2_vfs_reg_status status;
    rome2_guest_addr32 carrier_props = { 0 };
    rome2_vfs_pack_props_prefix_info32 pinfo;

    if (entries == NULL || carriers == NULL || pack_props_view == NULL ||
        out_has_meta == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    status = rome2_vfs_entry_read32(entries, entry_addr, &entry);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }
    if (entry.carrier == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    if (rome2_guest_read_addr32_le(carriers, (rome2_guest_addr32){ entry.carrier },
            &carrier_props) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (carrier_props.value == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    status = rome2_vfs_pack_props_read_prefix32(pack_props_view, carrier_props, &pinfo);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }

    *out_has_meta = pinfo.has_per_entry_meta;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_entry_read_stream_info32(
    const rome2_guest_read_view *entries, rome2_guest_addr32 entry_addr,
    const rome2_guest_read_view *streams_view,
    rome2_vfs_pack_entry_stream_info32 *output)
{
    rome2_vfs_pack_entry_info32 entry;
    rome2_vfs_reg_status status;
    rome2_vfs_pack_entry_stream_info32 parsed;
    rome2_guest_addr32 vt_word = { 0 };

    if (entries == NULL || output == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    status = rome2_vfs_entry_read32(entries, entry_addr, &entry);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }

    parsed.entry_meta = entry.entry_meta;
    parsed.byte_size = entry.byte_size;
    parsed.stream_state = entry.stream_state;
    parsed.winner_notified = entry.winner_notified;

    if (entry.stream_state == 0u) {
        parsed.has_stream_state = false;
        parsed.stream_vtable = 0u;
    } else {
        if (streams_view == NULL) {
            return ROME2_VFS_REG_BAD_ARGUMENT;
        }
        if (rome2_guest_read_addr32_le(streams_view,
                (rome2_guest_addr32){ entry.stream_state }, &vt_word) != ROME2_GUEST_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (vt_word.value == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        parsed.has_stream_state = true;
        parsed.stream_vtable = (rome2_vtable_address32)vt_word.value;
    }

    *output = parsed;
    return ROME2_VFS_REG_OK;
}
