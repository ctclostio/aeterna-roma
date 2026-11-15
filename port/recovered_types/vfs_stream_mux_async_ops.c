#include "vfs_stream_mux_async_ops.h"

#include <string.h>

#include "vfs_stream_completion_ops.h"

static rome2_vfs_reg_status read_u32_disp(
    const rome2_guest_read_view *view,
    uint32_t base_addr,
    uint32_t disp,
    uint32_t *out_val)
{
    rome2_guest_addr32 base = { base_addr };
    rome2_guest_addr32 cell;
    rome2_guest_addr32 tmp;

    if (rome2_guest_add_checked(base, disp, &cell) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (rome2_guest_read_addr32_le(view, cell, &tmp) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_val = tmp.value;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status read_u8_disp(
    const rome2_guest_read_view *view,
    uint32_t base_addr,
    uint32_t disp,
    uint8_t *out_val)
{
    rome2_guest_addr32 base = { base_addr };
    rome2_guest_addr32 cell;
    uint16_t tmp16 = 0u;

    if (rome2_guest_add_checked(base, disp, &cell) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (rome2_guest_read_u16_le(view, cell, &tmp16) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_val = (uint8_t)(tmp16 & 0xffu);
    return ROME2_VFS_REG_OK;
}

static const rome2_vfs_dual_slot_entry32 *slot_const_at(
    const rome2_vfs_dual_slot_view32 *view,
    uint8_t idx)
{
    return (idx == 0u) ? &view->slot0_28 : &view->slot1_38;
}

static rome2_vfs_dual_slot_entry32 *slot_mut_at(
    rome2_vfs_dual_slot_view32 *view,
    uint8_t idx)
{
    return (idx == 0u) ? &view->slot0_28 : &view->slot1_38;
}

static uint32_t *rel_off_mut_at(
    rome2_vfs_dual_slot_view32 *view,
    uint8_t idx)
{
    return (idx == 0u) ? &view->slot0_rel_off_48 : &view->slot1_rel_off_4c;
}

static uint32_t rel_off_const_at(
    const rome2_vfs_dual_slot_view32 *view,
    uint8_t idx)
{
    return (idx == 0u) ? view->slot0_rel_off_48 : view->slot1_rel_off_4c;
}

static int slot_matches_offset(
    const rome2_vfs_dual_slot_entry32 *slot,
    uint32_t req_offset)
{
    if (slot->task_ptr_00 == 0u) {
        return 0;
    }
    if (slot->window_off_08 == 0u && slot->window_len_04 == 0u) {
        return 1;
    }
    return (req_offset >= slot->window_off_08 &&
            (req_offset - slot->window_off_08) < slot->window_len_04) ? 1 : 0;
}

static uint32_t release_slot_task(rome2_vfs_dual_slot_entry32 *slot)
{
    if (slot->task_ptr_00 != 0u) {
        slot->task_ptr_00 = 0u;
        return 1u;
    }
    return 0u;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_entry_zero_init(
    rome2_vfs_dual_slot_entry32 *entry)
{
    if (entry == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    entry->task_ptr_00 = 0u;
    entry->window_len_04 = 0u;
    entry->window_off_08 = 0u;
    entry->flags_0c = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_init(
    rome2_vfs_dual_slot_view32 *view,
    uint32_t name_str_addr,
    uint32_t path_str_addr,
    uint32_t total_size,
    uint32_t file_handle,
    uint32_t aux_handle,
    uint32_t chunk_cap,
    uint32_t cipher_flags)
{
    if (view == NULL || chunk_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    view->vtable = ROME2_VFS_DUAL_SLOT_VIEW_VTABLE32;
    view->ref_or_reserved_04 = 0u;
    view->name_str_08 = name_str_addr;
    view->path_str_0c = path_str_addr;
    view->total_size_10 = total_size;
    view->file_handle_14 = file_handle;
    view->aux_handle_18 = aux_handle;
    view->chunk_cap_1c = chunk_cap;
    view->cipher_flags_20 = cipher_flags;
    view->active_ref_count_24 = 0u;
    (void)rome2_vfs_dual_slot_entry_zero_init(&view->slot0_28);
    (void)rome2_vfs_dual_slot_entry_zero_init(&view->slot1_38);
    view->slot0_rel_off_48 = 0u;
    view->slot1_rel_off_4c = 0u;
    view->active_slot_idx_50 = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_destroy(
    rome2_vfs_dual_slot_view32 *view,
    uint32_t *out_released_tasks)
{
    uint32_t released = 0u;

    if (view == NULL || out_released_tasks == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    /* Match 0x112ad210 reverse destruction order: slot1_38 before slot0_28. */
    released += release_slot_task(&view->slot1_38);
    released += release_slot_task(&view->slot0_28);
    view->slot0_rel_off_48 = 0u;
    view->slot1_rel_off_4c = 0u;
    view->vtable = ROME2_VFS_BACKING_VIEW_BASE_VTABLE32;
    *out_released_tasks = released;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_has_active_task(
    const rome2_vfs_dual_slot_view32 *view,
    int *out_has_task)
{
    const rome2_vfs_dual_slot_entry32 *slot;

    if (view == NULL || out_has_task == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (view->active_slot_idx_50 > 1u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    slot = slot_const_at(view, view->active_slot_idx_50);
    *out_has_task = (slot->task_ptr_00 != 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_is_active_task_ready(
    const rome2_vfs_dual_slot_view32 *view,
    const rome2_guest_read_view *guest_mem,
    int *out_ready)
{
    const rome2_vfs_dual_slot_entry32 *slot;
    uint32_t inner_0c = 0u;
    uint8_t ready_byte = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || guest_mem == NULL || out_ready == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (view->active_slot_idx_50 > 1u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    slot = slot_const_at(view, view->active_slot_idx_50);
    if (slot->task_ptr_00 == 0u) {
        *out_ready = 0;
        return ROME2_VFS_REG_OK;
    }
    st = read_u32_disp(guest_mem, slot->task_ptr_00, 0x0cu, &inner_0c);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u8_disp(guest_mem, inner_0c, 0x0cu, &ready_byte);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_ready = (ready_byte != 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_active_remaining_bytes(
    const rome2_vfs_dual_slot_view32 *view,
    const rome2_guest_read_view *guest_mem,
    uint32_t *out_remaining)
{
    const rome2_vfs_dual_slot_entry32 *slot;
    uint32_t task_bytes = 0u;
    uint32_t rel_off;
    rome2_vfs_reg_status st;

    if (view == NULL || guest_mem == NULL || out_remaining == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (view->active_slot_idx_50 > 1u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    slot = slot_const_at(view, view->active_slot_idx_50);
    if (slot->task_ptr_00 == 0u) {
        *out_remaining = 0u;
        return ROME2_VFS_REG_OK;
    }
    st = read_u32_disp(guest_mem, slot->task_ptr_00, 0x00u, &task_bytes);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    rel_off = rel_off_const_at(view, view->active_slot_idx_50);
    if (rel_off > task_bytes) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_remaining = task_bytes - rel_off;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_has_active_refs(
    const rome2_vfs_dual_slot_view32 *view,
    int *out_has_refs)
{
    if (view == NULL || out_has_refs == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_has_refs = (view->active_ref_count_24 != 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_release_ref(
    rome2_vfs_dual_slot_view32 *view,
    uint32_t *out_new_ref_count,
    uint32_t *out_released_tasks)
{
    uint32_t released = 0u;

    if (view == NULL || out_new_ref_count == NULL || out_released_tasks == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (view->active_ref_count_24 == 0u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    view->active_ref_count_24 -= 1u;
    if (view->active_ref_count_24 == 0u) {
        released += release_slot_task(&view->slot0_28);
        released += release_slot_task(&view->slot1_38);
        view->slot0_rel_off_48 = 0u;
        view->slot1_rel_off_4c = 0u;
    }
    *out_new_ref_count = view->active_ref_count_24;
    *out_released_tasks = released;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_is_window_cache_miss(
    const rome2_vfs_dual_slot_view32 *view,
    uint32_t req_offset,
    int *out_is_miss)
{
    uint8_t active_idx;
    uint8_t alt_idx;

    if (view == NULL || out_is_miss == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (view->active_slot_idx_50 > 1u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    active_idx = view->active_slot_idx_50;
    alt_idx = (uint8_t)(1u - active_idx);
    if (slot_matches_offset(slot_const_at(view, active_idx), req_offset) != 0 ||
        slot_matches_offset(slot_const_at(view, alt_idx), req_offset) != 0) {
        *out_is_miss = 0;
    } else {
        *out_is_miss = 1;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dual_slot_view_map_and_prefetch(
    rome2_vfs_dual_slot_view32 *view,
    uint32_t req_length,
    uint32_t req_offset,
    uint32_t next_task_id,
    int *out_toggled,
    int *out_prefetched)
{
    uint8_t active_idx;
    rome2_vfs_dual_slot_entry32 *active;
    uint64_t end64;
    int toggled = 0;
    int prefetched = 0;

    if (view == NULL || out_toggled == NULL || out_prefetched == NULL ||
        next_task_id == 0u || view->chunk_cap_1c == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (view->active_slot_idx_50 > 1u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    view->active_ref_count_24 += 1u;
    active_idx = view->active_slot_idx_50;
    active = slot_mut_at(view, active_idx);
    if (slot_matches_offset(active, req_offset) != 0) {
        *rel_off_mut_at(view, active_idx) = req_offset - active->window_off_08;
        *out_toggled = 0;
        *out_prefetched = 0;
        return ROME2_VFS_REG_OK;
    }

    active_idx = (uint8_t)(active_idx ^ 1u);
    view->active_slot_idx_50 = active_idx;
    toggled = 1;
    active = slot_mut_at(view, active_idx);

    if (slot_matches_offset(active, req_offset) != 0) {
        *rel_off_mut_at(view, active_idx) = req_offset - active->window_off_08;
    } else {
        uint32_t clamped = req_length;
        if (clamped >= view->chunk_cap_1c) {
            clamped = view->chunk_cap_1c;
        }
        active->window_len_04 = clamped;
        active->window_off_08 = req_offset;
        active->flags_0c = 0u;
        active->task_ptr_00 = next_task_id;
        next_task_id += 1u;
        *rel_off_mut_at(view, active_idx) = 0u;
    }

    end64 = (uint64_t)active->window_off_08 + (uint64_t)active->window_len_04;
    if (end64 < (uint64_t)view->total_size_10) {
        uint8_t alt_idx = (uint8_t)(1u - active_idx);
        rome2_vfs_dual_slot_entry32 *alt = slot_mut_at(view, alt_idx);
        uint32_t rem = view->total_size_10 - (uint32_t)end64;
        if (rem >= view->chunk_cap_1c) {
            rem = view->chunk_cap_1c;
        }
        alt->window_len_04 = rem;
        alt->window_off_08 = (uint32_t)end64;
        alt->flags_0c = 0u;
        alt->task_ptr_00 = next_task_id;
        *rel_off_mut_at(view, alt_idx) = 0u;
        prefetched = 1;
    }

    *out_toggled = toggled;
    *out_prefetched = prefetched;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cipher_mem_view_init(
    rome2_vfs_cipher_mem_view32 *view,
    uint32_t name_str_addr,
    uint32_t cipher_flags)
{
    if (view == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    view->vtable = ROME2_VFS_CIPHER_MEM_VIEW_VTABLE32;
    view->ref_or_reserved_04 = 0u;
    view->name_str_08 = name_str_addr;
    view->cipher_flags_0c = cipher_flags;
    view->valid_flag_10 = 1u;
    view->ready_flag_11 = 0u;
    view->buffer_ptr_14 = 0u;
    view->buffer_size_18 = 0u;
    view->active_ref_count_1c = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cipher_mem_view_inc_ref(
    rome2_vfs_cipher_mem_view32 *view)
{
    if (view == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    view->active_ref_count_1c += 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cipher_mem_view_dec_ref(
    rome2_vfs_cipher_mem_view32 *view,
    uint32_t *out_new_ref_count)
{
    if (view == NULL || out_new_ref_count == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (view->active_ref_count_1c != 0u) {
        view->active_ref_count_1c -= 1u;
    }
    *out_new_ref_count = view->active_ref_count_1c;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cipher_mem_view_is_valid(
    const rome2_vfs_cipher_mem_view32 *view,
    uint8_t *out_valid)
{
    if (view == NULL || out_valid == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_valid = view->valid_flag_10;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cipher_mem_view_is_ready(
    const rome2_vfs_cipher_mem_view32 *view,
    uint8_t *out_ready)
{
    if (view == NULL || out_ready == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_ready = view->ready_flag_11;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cipher_mem_view_install_buffer(
    rome2_vfs_cipher_mem_view32 *view,
    uint32_t buf_guest_addr,
    uint8_t *host_buf,
    uint32_t buf_size)
{
    if (view == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (buf_guest_addr == 0u) {
        view->valid_flag_10 = 0u;
        view->ready_flag_11 = 1u;
        return ROME2_VFS_REG_OK;
    }
    if (buf_size > 0u && host_buf == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if ((view->cipher_flags_0c & 1u) != 0u) {
        uint32_t key = 0u;
        size_t processed = 0u;
        rome2_vfs_reg_status st = rome2_vfs_stream_xor_deobfuscate_blocks32(
            host_buf, (size_t)buf_size, host_buf, &key, &processed);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    view->buffer_size_18 = buf_size;
    view->buffer_ptr_14 = buf_guest_addr;
    view->ready_flag_11 = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cipher_mem_view_get_buffer(
    const rome2_vfs_cipher_mem_view32 *view,
    uint32_t *out_buffer_ptr)
{
    if (view == NULL || out_buffer_ptr == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (view->ready_flag_11 == 0u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_buffer_ptr = view->buffer_ptr_14;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_init_base(
    rome2_vfs_stream_delegate_adapter32 *adapter)
{
    if (adapter == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    adapter->vtable = ROME2_VFS_STREAM_ADAPTER_BASE_VTABLE32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_init(
    rome2_vfs_stream_delegate_adapter32 *adapter,
    uint32_t inner_stream_addr,
    uint32_t wide_path_len,
    uint32_t wide_path_cap,
    uint32_t wide_path_buf_addr)
{
    if (adapter == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    adapter->vtable = ROME2_VFS_STREAM_DELEGATE_VTABLE32;
    adapter->inner_stream_04 = inner_stream_addr;
    adapter->wide_path_len_08 = wide_path_len;
    adapter->wide_path_cap_0c = wide_path_cap;
    adapter->wide_path_buf_10 = wide_path_buf_addr;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_destroy(
    rome2_vfs_stream_delegate_adapter32 *adapter)
{
    if (adapter == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    adapter->wide_path_len_08 = 0u;
    adapter->wide_path_cap_0c = 0u;
    adapter->wide_path_buf_10 = 0u;
    adapter->vtable = ROME2_VFS_STREAM_ADAPTER_BASE_VTABLE32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_query_interface(
    uint32_t *out_obj,
    uint32_t *out_hresult)
{
    if (out_obj == NULL || out_hresult == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_obj = 0u;
    *out_hresult = ROME2_VFS_E_NOINTERFACE32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_resolve_thunk_target(
    const rome2_vfs_stream_delegate_adapter32 *adapter,
    const rome2_guest_read_view *guest_mem,
    uint32_t slot_offset,
    uint32_t *out_target_addr)
{
    uint32_t inner_vtable = 0u;
    rome2_vfs_reg_status st;

    if (adapter == NULL || guest_mem == NULL || out_target_addr == NULL ||
        slot_offset < 0x10u || slot_offset > 0x34u || (slot_offset & 3u) != 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (adapter->inner_stream_04 == 0u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    st = read_u32_disp(guest_mem, adapter->inner_stream_04, 0x00u, &inner_vtable);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    return read_u32_disp(guest_mem, inner_vtable, slot_offset, out_target_addr);
}

rome2_vfs_reg_status rome2_vfs_file_stat32_from_mode_and_meta(
    rome2_vfs_file_stat32 *out_stat,
    uint32_t st_mode,
    uint64_t st_mtime,
    uint32_t st_size,
    int *out_matched)
{
    if (out_stat == NULL || out_matched == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if ((st_mode & ROME2_VFS_STAT_REG_OR_READ_MASK32) == 0u) {
        *out_matched = 0;
        return ROME2_VFS_REG_OK;
    }
    out_stat->mtime_lo_00 = (uint32_t)(st_mtime & 0xffffffffu);
    out_stat->mtime_hi_04 = (uint32_t)(st_mtime >> 32u);
    out_stat->file_size_08 = st_size;
    out_stat->is_readable_0c = (uint8_t)((st_mode >> 8u) & 1u);
    out_stat->is_writable_0d = (uint8_t)((st_mode >> 7u) & 1u);
    out_stat->is_dir_0e = (uint8_t)((st_mode >> 14u) & 1u);
    *out_matched = 1;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_widen_ascii_to_utf16(
    const uint8_t *src,
    uint16_t *dst_utf16,
    size_t dst_cap_units,
    size_t *out_units_written)
{
    size_t len = 0u;
    size_t i;

    if (src == NULL || dst_utf16 == NULL || out_units_written == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    while (src[len] != 0u) {
        len += 1u;
    }
    if (len + 1u > dst_cap_units) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (i = 0u; i <= len; ++i) {
        dst_utf16[i] = (uint16_t)src[i];
    }
    *out_units_written = len;
    return ROME2_VFS_REG_OK;
}
