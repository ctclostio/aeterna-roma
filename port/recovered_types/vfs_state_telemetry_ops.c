#include "vfs_state_telemetry_ops.h"

static rome2_vfs_state_telemetry_status read_u32_field(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t disp,
    uint32_t *out_val)
{
    rome2_guest_addr32 cell;
    rome2_guest_addr32 tmp;

    if (rome2_guest_add_checked(base, disp, &cell) != ROME2_GUEST_OK ||
        rome2_guest_read_addr32_le(view, cell, &tmp) != ROME2_GUEST_OK) {
        return ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL;
    }
    *out_val = tmp.value;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

static int is_power_of_two_u32(uint32_t x) {
    return x != 0u && (x & (x - 1u)) == 0u;
}

rome2_vfs_state_telemetry_status rome2_vfs_decode_state_ref_block28_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_state_ref_block28_32 *out_block)
{
    rome2_vfs_state_ref_block28_32 parsed;
    rome2_vfs_state_telemetry_status st;
    uint32_t flags_word;

    if (view == NULL || out_block == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    if ((size_t)sizeof(parsed) > view->byte_count) {
        return ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL;
    }
    st = read_u32_field(view, addr, 0x00u, &parsed.vtable);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x04u, &parsed.use_count);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x08u, &parsed.weak_count);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x0cu, &parsed.inner_vtable);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x10u, &parsed.view_box_ptr_010);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x14u, &parsed.size_014);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x18u, &flags_word);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    if (parsed.vtable != ROME2_VFS_REF_BLOCK1C_A474_VTABLE32) {
        return ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE;
    }
    if (parsed.inner_vtable != ROME2_VFS_INNER_STATE_77BC_VTABLE32 &&
        parsed.inner_vtable != ROME2_VFS_INNER_STATE_77E0_VTABLE32) {
        return ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE;
    }
    parsed.eof_or_closed_018 = (uint8_t)(flags_word & 0xffu);
    parsed.closed_019 = (uint8_t)((flags_word >> 8u) & 0xffu);
    parsed.unobserved_01a[0] = (uint8_t)((flags_word >> 16u) & 0xffu);
    parsed.unobserved_01a[1] = (uint8_t)((flags_word >> 24u) & 0xffu);
    *out_block = parsed;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_decode_state_inner_listener28_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_state_inner_listener28_32 *out_state)
{
    rome2_vfs_state_inner_listener28_32 parsed;
    rome2_vfs_state_telemetry_status st;
    uint32_t flags_word;

    if (view == NULL || out_state == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    if ((size_t)sizeof(parsed) > view->byte_count) {
        return ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL;
    }
    st = read_u32_field(view, addr, 0x00u, &parsed.vtable);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x04u, &parsed.view_box_ptr_004);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x08u, &parsed.size_008);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x0cu, &flags_word);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x10u, &parsed.listener_head_010);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x14u, &parsed.listener_sentinel_014);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x18u, &parsed.unobserved_018);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    if (parsed.vtable != ROME2_VFS_INNER_STATE_77C8_VTABLE32 &&
        parsed.vtable != ROME2_VFS_INNER_STATE_77BC_VTABLE32) {
        return ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE;
    }
    parsed.eof_or_closed_00c = (uint8_t)(flags_word & 0xffu);
    parsed.closed_00d = (uint8_t)((flags_word >> 8u) & 0xffu);
    parsed.unobserved_00e[0] = (uint8_t)((flags_word >> 16u) & 0xffu);
    parsed.unobserved_00e[1] = (uint8_t)((flags_word >> 24u) & 0xffu);
    *out_state = parsed;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_decode_sys_info32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_sys_info32 *out_info)
{
    rome2_vfs_sys_info32 parsed;
    rome2_vfs_state_telemetry_status st;
    size_t i;

    if (view == NULL || out_info == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    if ((size_t)sizeof(parsed) > view->byte_count) {
        return ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL;
    }
    st = read_u32_field(view, addr, 0x00u, &parsed.oem_id_000);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x04u, &parsed.page_size_004);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    for (i = 0u; i < 5u; ++i) {
        st = read_u32_field(view, addr, (uint32_t)(0x08u + i * 4u), &parsed.unobserved_008[i]);
        if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
            return st;
        }
    }
    st = read_u32_field(view, addr, 0x1cu, &parsed.allocation_granularity_01c);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    st = read_u32_field(view, addr, 0x20u, &parsed.unobserved_020);
    if (st != ROME2_VFS_STATE_TELEMETRY_OK) {
        return st;
    }
    if (!is_power_of_two_u32(parsed.page_size_004) ||
        !is_power_of_two_u32(parsed.allocation_granularity_01c)) {
        return ROME2_VFS_STATE_TELEMETRY_BAD_GRANULARITY;
    }
    *out_info = parsed;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_state_inner_deleting_dtor_size32(
    uint32_t dtor_va,
    uint32_t delete_flag,
    uint32_t *out_free_bytes)
{
    uint32_t sz;

    if (out_free_bytes == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    switch (dtor_va) {
        case ROME2_VFS_INNER_DTOR_112ACD90:
            sz = 0x10u;
            break;
        case ROME2_VFS_INNER_DTOR_112ACFE0:
            sz = 0x1cu;
            break;
        case ROME2_VFS_INNER_DTOR_112AD140:
            sz = 0x20u;
            break;
        default:
            return ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE;
    }
    *out_free_bytes = ((delete_flag & 1u) != 0u) ? sz : 0u;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_state_d97f0_plan_complete32(
    uint8_t eof_or_closed_00c,
    uint8_t closed_00d,
    uint32_t flags_014,
    uint32_t data_ptr,
    uint32_t size_bytes,
    rome2_vfs_state_d97f0_plan *out_plan)
{
    rome2_vfs_state_d97f0_plan plan;

    if (out_plan == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    plan.next_eof_00c = 1u;
    if (closed_00d != 0u) {
        plan.already_closed = 1;
        plan.compressed = (int)((flags_014 & 1u) != 0u);
        plan.completion_target_va = 0u;
        plan.src_addr = 0u;
        plan.src_end = 0u;
        plan.size_bytes = 0u;
        *out_plan = plan;
        return ROME2_VFS_STATE_TELEMETRY_OK;
    }
    (void)eof_or_closed_00c;
    if (data_ptr > UINT32_MAX - size_bytes) {
        return ROME2_VFS_STATE_TELEMETRY_ARITHMETIC_OVERFLOW;
    }
    plan.already_closed = 0;
    plan.compressed = (int)((flags_014 & 1u) != 0u);
    plan.completion_target_va = plan.compressed
        ? ROME2_VFS_COMPLETE_COMPRESSED_FN32
        : ROME2_VFS_COMPLETE_UNCOMPRESSED_FN32;
    plan.src_addr = data_ptr;
    plan.src_end = data_ptr + size_bytes;
    plan.size_bytes = size_bytes;
    *out_plan = plan;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_state_baf00_poll_extra32(
    uint8_t eof_or_closed_00c,
    uint8_t closed_00d,
    uint32_t extra_deref_010,
    int *out_needs_spin,
    uint32_t *out_result_ptr)
{
    if (out_needs_spin == NULL || out_result_ptr == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    *out_needs_spin = (closed_00d == 0u && eof_or_closed_00c == 0u) ? 1 : 0;
    *out_result_ptr = (closed_00d != 0u) ? 0u : extra_deref_010;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_prefetch_pages_cancellable_sum32(
    const uint8_t *buf,
    size_t buf_len,
    uint32_t len_bytes,
    uint32_t page_stride,
    uint32_t initial_acc,
    const uint8_t *cancel_flag,
    uint32_t *out_acc,
    size_t *out_steps)
{
    uint32_t acc = initial_acc;
    size_t offset = 0u;
    size_t steps = 0u;

    if (out_acc == NULL || out_steps == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    if (!is_power_of_two_u32(page_stride)) {
        return ROME2_VFS_STATE_TELEMETRY_BAD_GRANULARITY;
    }
    if (len_bytes == 0u) {
        *out_acc = initial_acc;
        *out_steps = 0u;
        return ROME2_VFS_STATE_TELEMETRY_OK;
    }
    if (buf == NULL || cancel_flag == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    if ((size_t)len_bytes > buf_len || buf_len < 4u) {
        return ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL;
    }
    while (offset < (size_t)len_bytes) {
        uint32_t word;
        if (*cancel_flag != 0u) {
            break;
        }
        if (offset > buf_len - 4u) {
            return ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL;
        }
        word = (uint32_t)buf[offset] |
               ((uint32_t)buf[offset + 1u] << 8u) |
               ((uint32_t)buf[offset + 2u] << 16u) |
               ((uint32_t)buf[offset + 3u] << 24u);
        acc += word;
        steps += 1u;
        if (offset > SIZE_MAX - (size_t)page_stride) {
            return ROME2_VFS_STATE_TELEMETRY_ARITHMETIC_OVERFLOW;
        }
        offset += (size_t)page_stride;
    }
    *out_acc = acc;
    *out_steps = steps;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_telemetry_acquire_id32(
    uint32_t *free_ids,
    size_t *free_count,
    uint32_t *next_id,
    uint32_t *out_id)
{
    if (free_count == NULL || next_id == NULL || out_id == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    if (*free_count > 0u) {
        if (free_ids == NULL) {
            return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
        }
        *free_count -= 1u;
        *out_id = free_ids[*free_count];
        return ROME2_VFS_STATE_TELEMETRY_OK;
    }
    if (*next_id == UINT32_MAX) {
        return ROME2_VFS_STATE_TELEMETRY_ARITHMETIC_OVERFLOW;
    }
    *out_id = *next_id;
    *next_id += 1u;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_telemetry_release_id32(
    uint32_t *free_ids,
    size_t *free_count,
    size_t stack_cap,
    uint32_t released_id)
{
    if (free_ids == NULL || free_count == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    if (*free_count >= stack_cap) {
        return ROME2_VFS_STATE_TELEMETRY_CAPACITY_EXCEEDED;
    }
    free_ids[*free_count] = released_id;
    *free_count += 1u;
    return ROME2_VFS_STATE_TELEMETRY_OK;
}

rome2_vfs_state_telemetry_status rome2_vfs_async_view_high_water32(
    uint32_t *active_count,
    uint32_t *high_water)
{
    uint32_t next_active;

    if (active_count == NULL || high_water == NULL) {
        return ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT;
    }
    if (*active_count == UINT32_MAX) {
        return ROME2_VFS_STATE_TELEMETRY_ARITHMETIC_OVERFLOW;
    }
    next_active = *active_count + 1u;
    *active_count = next_active;
    if (next_active > *high_water) {
        *high_water = next_active;
    }
    return ROME2_VFS_STATE_TELEMETRY_OK;
}
