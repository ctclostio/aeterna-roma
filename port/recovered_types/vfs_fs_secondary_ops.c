#include "vfs_fs_secondary_ops.h"

#include <string.h>

#include "vfs_stream_completion_ops.h"

rome2_vfs_reg_status rome2_vfs_base_fs_init_static(
    rome2_vfs_base_fs_obj32 *obj)
{
    if (obj == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    obj->primary_vptr_00 = ROME2_VFS_BASE_FS_PRIMARY_VTABLE32;
    obj->secondary_vptr_04 = ROME2_VFS_BASE_FS_SECONDARY_VTABLE32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_base_fs_deleting_dtor(
    rome2_vfs_base_fs_obj32 *obj,
    uint32_t flags,
    int *out_should_free)
{
    if (obj == NULL || out_should_free == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    obj->primary_vptr_00 = ROME2_VFS_BASE_FS_PRIMARY_VTABLE32;
    obj->secondary_vptr_04 = ROME2_VFS_BASE_FS_SECONDARY_VTABLE32;
    *out_should_free = ((flags & 1u) != 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_base_fs_default_pair_zero(
    rome2_vfs_u64_pair32 *pair)
{
    if (pair == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    pair->low_00 = 0u;
    pair->high_04 = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_base_fs_default_entry_info(
    rome2_vfs_entry_info32 *info,
    uint32_t empty_name_str_addr)
{
    if (info == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    info->size_lo_00 = 0xffffffffu;
    info->size_hi_04 = 0xffffffffu;
    info->name_str_08 = empty_name_str_addr;
    info->zero_10 = 0u;
    info->zero_14 = 0u;
    info->zero_18 = 0u;
    info->flag_1c = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_vec12_end_ptr(
    uint32_t base_addr,
    uint32_t count,
    uint32_t *out_end_addr)
{
    uint32_t span = 0u;
    rome2_guest_addr32 base = { base_addr };
    rome2_guest_addr32 end = { 0u };

    if (out_end_addr == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (count > (UINT32_MAX / 12u)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    span = count * 12u;
    if (rome2_guest_add_checked(base, span, &end) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_end_addr = end.value;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sp_ctrl_init(
    rome2_vfs_sp_ctrl_block32 *ctrl,
    uint32_t ctrl_guest_addr,
    uint32_t payload_guest_addr,
    rome2_vfs_sp_pair32 *out_pair)
{
    if (ctrl == NULL || out_pair == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    ctrl->vtable_00 = ROME2_VFS_SP_CTRL_VTABLE32;
    ctrl->uses_04 = 1u;
    ctrl->weaks_08 = 1u;
    ctrl->payload_ptr_0c = payload_guest_addr;
    out_pair->ptr_00 = payload_guest_addr;
    out_pair->rep_04 = ctrl_guest_addr;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sp_ctrl_release_strong(
    rome2_vfs_sp_ctrl_block32 *ctrl,
    int *out_destroy_payload,
    int *out_delete_ctrl)
{
    if (ctrl == NULL || out_destroy_payload == NULL || out_delete_ctrl == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (ctrl->uses_04 == 0u || ctrl->weaks_08 == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    *out_destroy_payload = 0;
    *out_delete_ctrl = 0;

    ctrl->uses_04 -= 1u;
    if (ctrl->uses_04 == 0u) {
        if (ctrl->payload_ptr_0c != 0u) {
            *out_destroy_payload = 1;
            ctrl->payload_ptr_0c = 0u;
        }
        ctrl->weaks_08 -= 1u;
        if (ctrl->weaks_08 == 0u) {
            *out_delete_ctrl = 1;
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sp_pair_assign_retain(
    rome2_vfs_sp_ctrl_block32 *src_ctrl,
    uint32_t src_ctrl_addr,
    uint32_t src_ptr,
    rome2_vfs_sp_pair32 *out_pair)
{
    if (out_pair == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    out_pair->ptr_00 = 0u;
    out_pair->rep_04 = 0u;
    if (src_ctrl != NULL) {
        if (src_ctrl->uses_04 == UINT32_MAX) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        src_ctrl->uses_04 += 1u;
        out_pair->rep_04 = src_ctrl_addr;
    }
    out_pair->ptr_00 = src_ptr;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_wrap_singleton_init(
    rome2_vfs_pack_wrap_singleton28_32 *singleton,
    uint32_t empty_file_str_addr)
{
    if (singleton == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    singleton->vtable_00 = ROME2_VFS_PACK_WRAP_SINGLETON_VTABLE32;
    singleton->name_str_04 = empty_file_str_addr;
    singleton->zero_08 = 0u;
    singleton->zero_0c = 0u;
    singleton->zero_10 = 0u;
    singleton->zero_14 = 0u;
    singleton->zero_18 = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_wrap_singleton_atexit_reset(
    rome2_vfs_pack_wrap_singleton28_32 *singleton)
{
    if (singleton == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    singleton->vtable_00 = ROME2_VFS_DTOR_BASE_VTABLE32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sec_classify_handle(
    uint32_t handle,
    uint32_t pack_count,
    uint32_t loose_count,
    uint32_t sentinel_bound,
    rome2_vfs_handle_domain *out_domain,
    uint32_t *out_index)
{
    uint32_t loose_idx = 0u;

    if (out_domain == NULL || out_index == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_domain = ROME2_VFS_HANDLE_INVALID;
    *out_index = 0u;

    if (handle < pack_count) {
        *out_domain = ROME2_VFS_HANDLE_PACK;
        *out_index = handle;
        return ROME2_VFS_REG_OK;
    }
    if (handle > 0x80000000u && handle < sentinel_bound) {
        loose_idx = handle + 0x7fffffffu; /* == handle - 0x80000001u in uint32_t */
        if (loose_idx < loose_count) {
            *out_domain = ROME2_VFS_HANDLE_LOOSE;
            *out_index = loose_idx;
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sec_read_whole_file_dispatch(
    uint8_t mounted,
    uint8_t entry_valid,
    uint32_t stream_flags,
    const uint8_t *src_bytes,
    uint32_t src_len,
    uint8_t *dst_buf,
    uint32_t dst_cap,
    uint32_t *out_bytes_read,
    int *out_succeeded)
{
    if (out_bytes_read == NULL || out_succeeded == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (src_len > 0u && (src_bytes == NULL || dst_buf == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    *out_bytes_read = 0u;
    *out_succeeded = 0;

    if (mounted == 0u || entry_valid == 0u) {
        return ROME2_VFS_REG_OK;
    }
    if (src_len > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (src_len > 0u) {
        memcpy(dst_buf, src_bytes, src_len);
        if ((stream_flags & ROME2_VFS_STREAM_FLAG_ENCRYPTED32) != 0u) {
            uint32_t key = 0u;
            size_t processed = 0u;
            if (rome2_vfs_stream_xor_deobfuscate_blocks32(
                    dst_buf, (size_t)src_len, dst_buf, &key, &processed) != ROME2_VFS_REG_OK) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
        }
    }
    *out_bytes_read = src_len;
    *out_succeeded = 1;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sec_apply_quota_update(
    uint8_t flag_2738,
    uint8_t flag_1ace,
    uint8_t map_inserted,
    uint32_t file_size,
    uint32_t max_items,
    uint32_t max_bytes,
    uint32_t *io_used_items,
    uint32_t *io_used_bytes,
    int *out_updated)
{
    if (io_used_items == NULL || io_used_bytes == NULL || out_updated == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_updated = 0;

    if (flag_2738 == 0u || flag_1ace == 0u) {
        return ROME2_VFS_REG_OK;
    }
    if (*io_used_items >= max_items || *io_used_bytes > max_bytes) {
        return ROME2_VFS_REG_OK;
    }
    if (file_size > (max_bytes - *io_used_bytes)) {
        return ROME2_VFS_REG_OK;
    }
    if (map_inserted != 0u) {
        *io_used_bytes += file_size;
        *io_used_items += 1u;
        *out_updated = 1;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sec_gate_and_mounted_ready(
    uint8_t mode_flag_25e0,
    uint8_t runtime_probe_ok,
    uint8_t mounted_1a88,
    uint8_t *io_cached_flag_2af8,
    int *io_initialized,
    int *out_ready)
{
    if (io_cached_flag_2af8 == NULL || io_initialized == NULL || out_ready == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (*io_initialized == 0) {
        *io_cached_flag_2af8 = (mode_flag_25e0 == 1u) ? (runtime_probe_ok ? 1u : 0u) : 1u;
        *io_initialized = 1;
    }
    *out_ready = (*io_cached_flag_2af8 != 0u && mounted_1a88 != 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_sec_unlink_list_node(
    int ready,
    rome2_vfs_dlink_node32 *nodes,
    size_t node_count,
    int32_t *io_head_idx,
    uint32_t target_key_id,
    int *out_removed)
{
    int32_t cur = 0;
    size_t steps = 0u;

    if (nodes == NULL || io_head_idx == NULL || out_removed == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_removed = 0;

    if (ready == 0) {
        return ROME2_VFS_REG_OK;
    }

    cur = *io_head_idx;
    while (cur >= 0) {
        int32_t prev_idx;
        int32_t next_idx;
        if ((size_t)cur >= node_count || steps >= node_count) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        steps += 1u;
        if (nodes[cur].active != 0u && nodes[cur].key_id == target_key_id) {
            prev_idx = nodes[cur].prev_idx;
            next_idx = nodes[cur].next_idx;
            if (cur == *io_head_idx) {
                *io_head_idx = next_idx;
                if (next_idx >= 0) {
                    if ((size_t)next_idx >= node_count) {
                        return ROME2_VFS_REG_INVALID_STATE;
                    }
                    nodes[next_idx].prev_idx = -1;
                }
            } else {
                if (prev_idx < 0 || (size_t)prev_idx >= node_count) {
                    return ROME2_VFS_REG_INVALID_STATE;
                }
                nodes[prev_idx].next_idx = next_idx;
                if (next_idx >= 0) {
                    if ((size_t)next_idx >= node_count) {
                        return ROME2_VFS_REG_INVALID_STATE;
                    }
                    nodes[next_idx].prev_idx = prev_idx;
                }
            }
            nodes[cur].prev_idx = -1;
            nodes[cur].next_idx = -1;
            nodes[cur].active = 0u;
            nodes[cur].freed = 1u;
            *out_removed = 1;
            return ROME2_VFS_REG_OK;
        }
        cur = nodes[cur].next_idx;
    }
    return ROME2_VFS_REG_OK;
}
