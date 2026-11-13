#include "vfs_stream_wrap_ops.h"

#include <string.h>

static rome2_guest_addr32 wrap_guest_addr(rome2_data_address32 raw) {
    rome2_guest_addr32 addr;
    addr.value = raw;
    return addr;
}

static rome2_vfs_reg_status map_guest_status(rome2_guest_status st) {
    return (st == ROME2_GUEST_OK) ? ROME2_VFS_REG_OK : ROME2_VFS_REG_RANGE_ERROR;
}

static rome2_vfs_reg_status read_guest_u32_at(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t disp,
    uint32_t *out_val)
{
    rome2_guest_addr32 cell;
    rome2_guest_addr32 tmp;
    rome2_guest_status gs;

    gs = rome2_guest_add_checked(base, disp, &cell);
    if (gs != ROME2_GUEST_OK) {
        return map_guest_status(gs);
    }
    gs = rome2_guest_read_addr32_le(view, cell, &tmp);
    if (gs != ROME2_GUEST_OK) {
        return map_guest_status(gs);
    }
    *out_val = tmp.value;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status read_guest_u16_at(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t disp,
    uint16_t *out_val)
{
    rome2_guest_addr32 unit;
    uint16_t tmp = 0u;
    rome2_guest_status gs;

    gs = rome2_guest_add_checked(base, disp, &unit);
    if (gs != ROME2_GUEST_OK) {
        return map_guest_status(gs);
    }
    gs = rome2_guest_read_u16_le(view, unit, &tmp);
    if (gs != ROME2_GUEST_OK) {
        return map_guest_status(gs);
    }
    *out_val = tmp;
    return ROME2_VFS_REG_OK;
}

/*
 * Shared checked decoder for `stream_wrap_a -> handle_box -> state_prefix`
 * (used by 0x112d9860 and 0x112badf0).
 */
static rome2_vfs_reg_status load_wrap_a_state(
    const rome2_guest_read_view *view,
    rome2_data_address32 handle_addr,
    int *out_has_state,
    rome2_data_address32 *out_state_addr,
    rome2_vfs_stream_state_prefix32 *out_state)
{
    rome2_vfs_reg_status st;
    rome2_guest_addr32 box_addr;
    rome2_guest_addr32 state_addr_w;
    rome2_vfs_stream_handle_box32 box;
    rome2_vfs_stream_state_prefix32 tmp_state;
    uint16_t flags16 = 0u;

    if (handle_addr == 0u) {
        *out_has_state = 0;
        *out_state_addr = 0u;
        memset(out_state, 0, sizeof(*out_state));
        return ROME2_VFS_REG_OK;
    }
    if (view == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    box_addr = wrap_guest_addr(handle_addr);
    memset(&box, 0, sizeof(box));
    st = read_guest_u32_at(view, box_addr, 0x08u, &box.secondary_ctrl);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_guest_u32_at(view, box_addr, 0x0cu, &box.sentinel_or_state);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_guest_u32_at(view, box_addr, 0x10u, &box.primary_ctrl);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }

    if (box.sentinel_or_state == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    state_addr_w = wrap_guest_addr(box.sentinel_or_state);
    memset(&tmp_state, 0, sizeof(tmp_state));
    st = read_guest_u32_at(view, state_addr_w, 0x00u, &tmp_state.vtable);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_guest_u16_at(view, state_addr_w, 0x0cu, &flags16);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    tmp_state.eof_or_closed_00c = (uint8_t)(flags16 & 0xffu);
    tmp_state.closed_00d = (uint8_t)((flags16 >> 8u) & 0xffu);

    *out_has_state = 1;
    *out_state_addr = box.sentinel_or_state;
    *out_state = tmp_state;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_a_release_ref32(
    rome2_vfs_stream_wrap_a32 *wrap,
    uint32_t *out_remaining_refs,
    int *out_should_release_handle,
    rome2_data_address32 *out_released_handle)
{
    uint32_t next_refs;
    rome2_data_address32 old_handle;

    if (wrap == NULL || out_remaining_refs == NULL ||
        out_should_release_handle == NULL || out_released_handle == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (wrap->zero_02c == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    next_refs = wrap->zero_02c - 1u;
    wrap->zero_02c = next_refs;
    if (next_refs == 0u) {
        old_handle = wrap->zero_030;
        wrap->zero_020 = 0u;
        wrap->zero_024 = 0u;
        wrap->flag_028 = 0u;
        wrap->zero_030 = 0u;
        *out_should_release_handle = (old_handle != 0u) ? 1 : 0;
        *out_released_handle = old_handle;
    } else {
        *out_should_release_handle = 0;
        *out_released_handle = 0u;
    }
    *out_remaining_refs = next_refs;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_b_release_ref32(
    rome2_vfs_stream_wrap_b32 *wrap,
    uint32_t *out_remaining_refs,
    int *out_should_free_view,
    rome2_data_address32 *out_view_box_addr)
{
    uint32_t next_refs;
    rome2_data_address32 old_view;

    if (wrap == NULL || out_remaining_refs == NULL ||
        out_should_free_view == NULL || out_view_box_addr == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (wrap->zero_038 == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    next_refs = wrap->zero_038 - 1u;
    wrap->zero_038 = next_refs;
    if (next_refs == 0u) {
        old_view = wrap->zero_020[0];
        wrap->zero_020[0] = 0u;
        wrap->zero_020[1] = 0u;
        wrap->zero_020[2] = 0u;
        wrap->zero_020[3] = 0u;
        wrap->flag_030 = 0u;
        wrap->flag_034 = 0u;
        *out_should_free_view = (old_view != 0u) ? 1 : 0;
        *out_view_box_addr = old_view;
    } else {
        *out_should_free_view = 0;
        *out_view_box_addr = 0u;
    }
    *out_remaining_refs = next_refs;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_a_has_handle32(
    const rome2_vfs_stream_wrap_a32 *wrap,
    int *out_has_handle)
{
    if (wrap == NULL || out_has_handle == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_has_handle = (wrap->zero_030 != 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_a_is_open32(
    const rome2_guest_read_view *view,
    const rome2_vfs_stream_wrap_a32 *wrap,
    int *out_is_open)
{
    int has_state = 0;
    rome2_data_address32 state_addr = 0u;
    rome2_vfs_stream_state_prefix32 state;
    rome2_vfs_reg_status st;

    if (wrap == NULL || out_is_open == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = load_wrap_a_state(view, wrap->zero_030, &has_state, &state_addr, &state);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_is_open = (has_state != 0 && state.eof_or_closed_00c == 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_a_plan_slot1c32(
    const rome2_guest_read_view *view,
    const rome2_vfs_stream_wrap_a32 *wrap,
    rome2_vfs_stream_wrap_a_slot1c_plan32 *out_plan)
{
    int has_state = 0;
    rome2_data_address32 state_addr = 0u;
    rome2_vfs_stream_state_prefix32 state;
    rome2_vfs_reg_status st;

    if (wrap == NULL || out_plan == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = load_wrap_a_state(view, wrap->zero_030, &has_state, &state_addr, &state);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (!has_state) {
        out_plan->has_state = 0;
        out_plan->needs_sync_call = 0;
        out_plan->state_addr = 0u;
        out_plan->tail_slot_008_vtable_offset = 0u;
        return ROME2_VFS_REG_OK;
    }
    out_plan->has_state = 1;
    out_plan->needs_sync_call = (state.eof_or_closed_00c == 0u) ? 1 : 0;
    out_plan->state_addr = state_addr;
    out_plan->tail_slot_008_vtable_offset = ROME2_VFS_STREAM_STATE_SLOT_008_OFF;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_b_has_view32(
    const rome2_vfs_stream_wrap_b32 *wrap,
    int *out_has_view)
{
    if (wrap == NULL || out_has_view == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_has_view = (wrap->zero_020[0] != 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_b_is_at_bound32(
    const rome2_vfs_stream_wrap_b32 *wrap,
    int *out_is_at_bound)
{
    uint32_t target;

    if (wrap == NULL || out_is_at_bound == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (wrap->zero_020[0] == 0u || wrap->tag_00c == 0u) {
        *out_is_at_bound = 0;
        return ROME2_VFS_REG_OK;
    }
    target = (wrap->zero_020[2] != 0u) ? wrap->zero_020[2] : wrap->tag_00c;
    *out_is_at_bound = (wrap->zero_020[1] == target) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_b_read_view_box32(
    const rome2_guest_read_view *view,
    const rome2_vfs_stream_wrap_b32 *wrap,
    rome2_vfs_stream_view_box32 *out_box)
{
    rome2_guest_addr32 box_addr;
    rome2_vfs_stream_view_box32 tmp;
    rome2_vfs_reg_status st;

    if (view == NULL || wrap == NULL || out_box == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (wrap->zero_020[0] == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    box_addr = wrap_guest_addr(wrap->zero_020[0]);
    st = read_guest_u32_at(view, box_addr, 0x00u, &tmp.mapped_view_base);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_guest_u32_at(view, box_addr, 0x04u, &tmp.data_ptr);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_box = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_rb_find_extreme_index(
    const rome2_vfs_rb_sentinel_node32 *nodes,
    size_t node_count,
    uint32_t start_idx,
    int walk_right,
    uint32_t *out_extreme_idx)
{
    uint32_t cur;
    size_t steps = 0u;
    size_t limit;

    if (nodes == NULL || out_extreme_idx == NULL || node_count == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if ((size_t)start_idx >= node_count) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (nodes[start_idx].is_nil != 0u) {
        *out_extreme_idx = start_idx;
        return ROME2_VFS_REG_OK;
    }

    limit = (node_count < ROME2_VFS_RB_MAX_WALK_STEPS) ? node_count : ROME2_VFS_RB_MAX_WALK_STEPS;
    cur = start_idx;
    while (steps < limit) {
        uint32_t next = (walk_right != 0) ? nodes[cur].right : nodes[cur].left;
        if ((size_t)next >= node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (nodes[next].is_nil != 0u) {
            *out_extreme_idx = cur;
            return ROME2_VFS_REG_OK;
        }
        cur = next;
        steps += 1u;
    }
    return ROME2_VFS_REG_STEP_LIMIT;
}

static uint32_t rb_get_child(const rome2_vfs_rb_sentinel_node32 *n, int right_side) {
    return (right_side != 0) ? n->right : n->left;
}

static void rb_set_child(rome2_vfs_rb_sentinel_node32 *n, int right_side, uint32_t val) {
    if (right_side != 0) {
        n->right = val;
    } else {
        n->left = val;
    }
}

rome2_vfs_reg_status rome2_vfs_rb_rotate_and_refresh_extremes(
    rome2_vfs_rb_sentinel_node32 *nodes,
    size_t node_count,
    uint32_t sentinel_idx,
    uint32_t pivot_idx,
    int rotate_left)
{
    /*
     * Parameterize Lrotate (`0x112b0710`, dir=1) and Rrotate (`0x112b07a0`, dir=0):
     *   other_side = !dir_side.
     */
    int dir_side = (rotate_left != 0) ? 1 : 0;
    int opp_side = (rotate_left != 0) ? 0 : 1;
    uint32_t child_idx;
    uint32_t grandchild_idx;
    uint32_t parent_idx;
    uint32_t root_idx;
    uint32_t lmost;
    uint32_t rmost;
    rome2_vfs_reg_status st;

    if (nodes == NULL || node_count == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if ((size_t)sentinel_idx >= node_count || (size_t)pivot_idx >= node_count) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (nodes[sentinel_idx].is_nil == 0u || nodes[pivot_idx].is_nil != 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    child_idx = rb_get_child(&nodes[pivot_idx], dir_side);
    if ((size_t)child_idx >= node_count) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (nodes[child_idx].is_nil != 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    grandchild_idx = rb_get_child(&nodes[child_idx], opp_side);
    parent_idx = nodes[pivot_idx].parent;
    if ((size_t)grandchild_idx >= node_count || (size_t)parent_idx >= node_count) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if ((size_t)nodes[sentinel_idx].parent >= node_count) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (pivot_idx != nodes[sentinel_idx].parent &&
        pivot_idx != rb_get_child(&nodes[parent_idx], opp_side) &&
        pivot_idx != rb_get_child(&nodes[parent_idx], dir_side)) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    /* Commit rotation pointer updates after all index and parent checks pass. */
    rb_set_child(&nodes[pivot_idx], dir_side, grandchild_idx);
    if (nodes[grandchild_idx].is_nil == 0u) {
        nodes[grandchild_idx].parent = pivot_idx;
    }

    nodes[child_idx].parent = parent_idx;
    if (pivot_idx == nodes[sentinel_idx].parent) {
        nodes[sentinel_idx].parent = child_idx;
    } else if (pivot_idx == rb_get_child(&nodes[parent_idx], opp_side)) {
        rb_set_child(&nodes[parent_idx], opp_side, child_idx);
    } else {
        rb_set_child(&nodes[parent_idx], dir_side, child_idx);
    }

    rb_set_child(&nodes[child_idx], opp_side, pivot_idx);
    nodes[pivot_idx].parent = child_idx;

    /* Refresh sentinel->left (_Min) and sentinel->right (_Max) like 0x112a2470. */
    root_idx = nodes[sentinel_idx].parent;
    st = rome2_vfs_rb_find_extreme_index(nodes, node_count, root_idx, 0, &lmost);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = rome2_vfs_rb_find_extreme_index(nodes, node_count, root_idx, 1, &rmost);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    nodes[sentinel_idx].left = lmost;
    nodes[sentinel_idx].right = rmost;
    return ROME2_VFS_REG_OK;
}
