#include "vfs_adj_open_ops.h"

#include <string.h>

static rome2_vfs_reg_status read_guest_u32_disp(
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
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    gs = rome2_guest_read_addr32_le(view, cell, &tmp);
    if (gs != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_val = tmp.value;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_adj_hash_can_allocate32(
    uint32_t current_count,
    uint32_t *out_next_count)
{
    if (out_next_count == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (current_count >= ROME2_VFS_ADJ_HASH_MAX_NODES) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_next_count = current_count + 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_adj_hash_node32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_adj_hash_node32 *out_node)
{
    rome2_vfs_adj_hash_node32 tmp;
    rome2_vfs_reg_status st;
    uint32_t words[9];
    size_t i;

    if (view == NULL || out_node == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (addr.value == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    for (i = 0u; i < 9u; ++i) {
        st = read_guest_u32_disp(view, addr, (uint32_t)(i * 4u), &words[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }

    memset(&tmp, 0, sizeof(tmp));
    tmp.next = words[0];
    tmp.prev = words[1];
    tmp.key_name[0] = words[2];
    tmp.key_name[1] = words[3];
    tmp.key_name[2] = words[4];
    tmp.sub_tree_a.sentinel = words[5];
    tmp.sub_tree_a.size = words[6];
    tmp.sub_tree_b.sentinel = words[7];
    tmp.sub_tree_b.size = words[8];
    *out_node = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_u32_vec_plan_push32(
    const rome2_vfs_u32_ptr_vec32 *vec,
    uint32_t *out_size,
    uint32_t *out_next_capacity,
    int *out_needs_grow)
{
    uint32_t used_bytes;
    uint32_t cap_bytes;
    uint32_t size;
    uint32_t cap;
    uint32_t min_cap;
    uint32_t half_cap;
    uint32_t next_cap;

    if (vec == NULL || out_size == NULL ||
        out_next_capacity == NULL || out_needs_grow == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (vec->last < vec->first || vec->end < vec->last) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    used_bytes = vec->last - vec->first;
    cap_bytes = vec->end - vec->first;
    if ((used_bytes & 3u) != 0u || (cap_bytes & 3u) != 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    size = used_bytes >> 2u;
    cap = cap_bytes >> 2u;
    if (vec->last < vec->end) {
        *out_size = size;
        *out_next_capacity = cap;
        *out_needs_grow = 0;
        return ROME2_VFS_REG_OK;
    }

    if (size >= ROME2_VFS_U32_VEC_MAX_ELEMENTS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    min_cap = size + 1u;
    half_cap = cap >> 1u;
    if (cap > ROME2_VFS_U32_VEC_MAX_ELEMENTS - half_cap) {
        next_cap = min_cap;
    } else {
        next_cap = cap + half_cap;
        if (next_cap < min_cap) {
            next_cap = min_cap;
        }
    }

    *out_size = size;
    *out_next_capacity = next_cap;
    *out_needs_grow = 1;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_state_wait_plan32(
    const rome2_vfs_stream_state_prefix32 *state,
    uint32_t current_lock_depth,
    int *out_should_wait,
    uint32_t *out_leaves_needed,
    uint32_t *out_reenters_needed)
{
    if (state == NULL || out_should_wait == NULL ||
        out_leaves_needed == NULL || out_reenters_needed == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (state->eof_or_closed_00c != 0u) {
        *out_should_wait = 0;
        *out_leaves_needed = 0u;
        *out_reenters_needed = 0u;
        return ROME2_VFS_REG_OK;
    }
    if (current_lock_depth == UINT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    *out_should_wait = 1;
    *out_leaves_needed = current_lock_depth + 1u;
    *out_reenters_needed = current_lock_depth;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_wrap_check_open_reentry32(
    uint32_t ref_count,
    uint32_t cur_lo,
    uint32_t cur_hi,
    uint32_t req_lo,
    uint32_t req_hi,
    int is_normals_prefix,
    uint32_t *out_next_ref_count)
{
    if (out_next_ref_count == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (ref_count == UINT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (ref_count != 0u && !(cur_lo == req_lo && cur_hi == req_hi)) {
        if (is_normals_prefix == 0) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
    }
    *out_next_ref_count = ref_count + 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_clear_flag_chain_bounded(
    rome2_vfs_flag_chain_node32 *nodes,
    size_t node_count,
    uint32_t head_idx,
    size_t *out_cleared_count)
{
    size_t limit;
    size_t steps = 0u;
    uint32_t cur = head_idx;

    if (out_cleared_count == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (head_idx == UINT32_MAX) {
        *out_cleared_count = 0u;
        return ROME2_VFS_REG_OK;
    }
    if (nodes == NULL || node_count == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    limit = (node_count < ROME2_VFS_FLAG_CHAIN_MAX_STEPS)
        ? node_count
        : ROME2_VFS_FLAG_CHAIN_MAX_STEPS;

    /* Pass 1: validate indices and acyclicity before mutating any node. */
    while (cur != UINT32_MAX) {
        if (steps >= limit) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        if ((size_t)cur >= node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        cur = nodes[cur].next;
        steps += 1u;
    }

    /* Pass 2: clear flag_004 along the verified chain. */
    cur = head_idx;
    while (cur != UINT32_MAX) {
        nodes[cur].flag_004 = 0u;
        cur = nodes[cur].next;
    }
    *out_cleared_count = steps;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_ref_block_delete_size32(
    rome2_vtable_address32 vtable,
    uint8_t delete_flags,
    uint32_t *out_free_bytes)
{
    static const struct {
        rome2_vtable_address32 vtable;
        uint32_t bytes;
    } kRefBlocks[] = {
        { ROME2_VFS_REF_BLOCK_A_VTABLE32, ROME2_VFS_REF_BLOCK_A_BYTES },
        { ROME2_VFS_REF_BLOCK_B_VTABLE32, ROME2_VFS_REF_BLOCK_B_BYTES },
        { ROME2_VFS_REF_BLOCK_C_VTABLE32, ROME2_VFS_REF_BLOCK_C_BYTES },
    };
    size_t i;

    if (out_free_bytes == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (i = 0u; i < sizeof(kRefBlocks) / sizeof(kRefBlocks[0]); ++i) {
        if (kRefBlocks[i].vtable == vtable) {
            *out_free_bytes = ((delete_flags & 1u) != 0u) ? kRefBlocks[i].bytes : 0u;
            return ROME2_VFS_REG_OK;
        }
    }
    return ROME2_VFS_REG_INVALID_STATE;
}
