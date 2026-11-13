#include "vfs_dep_rehash.h"

#include <math.h>
#include <string.h>

static rome2_vfs_reg_status map_guest_status(rome2_guest_status status)
{
    switch (status) {
        case ROME2_GUEST_OK:
            return ROME2_VFS_REG_OK;
        case ROME2_GUEST_NULL_ADDRESS:
        case ROME2_GUEST_BAD_ARGUMENT:
            return ROME2_VFS_REG_BAD_ARGUMENT;
        case ROME2_GUEST_RANGE_OVERFLOW:
        case ROME2_GUEST_OUT_OF_RANGE:
        default:
            return ROME2_VFS_REG_RANGE_ERROR;
    }
}

static rome2_guest_addr32 make_guest_addr32(uint32_t raw)
{
    rome2_guest_addr32 addr;
    addr.value = raw;
    return addr;
}

static rome2_vfs_reg_status read_u32_at_offset(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t disp,
    uint32_t *out_value)
{
    rome2_guest_addr32 target = {0u};
    rome2_guest_addr32 cell_val = {0u};
    rome2_guest_status gst = ROME2_GUEST_OK;

    if (out_value == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    gst = rome2_guest_add_checked(base, disp, &target);
    if (gst != ROME2_GUEST_OK) {
        return map_guest_status(gst);
    }
    gst = rome2_guest_read_addr32_le(view, target, &cell_val);
    if (gst != ROME2_GUEST_OK) {
        return map_guest_status(gst);
    }
    *out_value = cell_val.value;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status read_nonnull_code_table(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    rome2_code_address32 *slots,
    size_t slot_count)
{
    size_t i = 0u;

    if (view == NULL || slots == NULL || slot_count == 0u || base.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (i = 0u; i < slot_count; ++i) {
        uint32_t raw = 0u;
        rome2_vfs_reg_status st = read_u32_at_offset(
            view, base, (uint32_t)(i * 4u), &raw);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (raw == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        slots[i] = raw;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_compute_rehash_target32(
    uint32_t requested_buckets,
    uint32_t element_count,
    uint32_t max_load_factor_bits,
    uint32_t *out_bucket_count)
{
    float max_load = 0.0f;
    float min_buckets_f = 0.0f;
    float req_f = 0.0f;
    float needed_f = 0.0f;

    if (out_bucket_count == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memcpy(&max_load, &max_load_factor_bits, sizeof(max_load));
    if (!isfinite(max_load) || !(max_load > 0.0f)) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    min_buckets_f = (float)((double)element_count) / max_load;
    if (!isfinite(min_buckets_f) || min_buckets_f < 0.0f) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    req_f = (float)((double)requested_buckets);
    if (req_f < min_buckets_f) {
        /* 0x112d9e84 sets x87 RC=10 (round toward +infinity) before FISTP. */
        needed_f = ceilf(min_buckets_f);
        if (!isfinite(needed_f) || needed_f < 0.0f || needed_f >= 4294967296.0f) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        *out_bucket_count = (uint32_t)needed_f;
        return ROME2_VFS_REG_OK;
    }

    *out_bucket_count = requested_buckets;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_dep_rb_node32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 node_addr,
    rome2_vfs_dep_rb_node32 *out_node)
{
    rome2_vfs_dep_rb_node32 tmp;
    uint32_t flags_word = 0u;
    size_t i = 0u;
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;

    if (view == NULL || out_node == NULL || node_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));

    st = read_u32_at_offset(view, node_addr, 0x00u, &tmp.left);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at_offset(view, node_addr, 0x04u, &tmp.parent);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at_offset(view, node_addr, 0x08u, &tmp.right);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_at_offset(view, node_addr, 0x0cu, &flags_word);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    tmp.color = (uint8_t)(flags_word & 0xffu);
    tmp.is_nil = (uint8_t)((flags_word >> 8u) & 0xffu);
    tmp.unobserved_00e[0] = (uint8_t)((flags_word >> 16u) & 0xffu);
    tmp.unobserved_00e[1] = (uint8_t)((flags_word >> 24u) & 0xffu);

    for (i = 0u; i < 3u; ++i) {
        st = read_u32_at_offset(view, node_addr, 0x10u + (uint32_t)(i * 4u), &tmp.name_a[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        st = read_u32_at_offset(view, node_addr, 0x1cu + (uint32_t)(i * 4u), &tmp.name_b[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }

    *out_node = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_count_dep_rb_nodes32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 head_addr,
    size_t max_steps,
    uint32_t *out_node_count)
{
    rome2_vfs_dep_rb_node32 head_node;
    rome2_guest_addr32 stack[ROME2_VFS_MAX_RB_STACK_DEPTH];
    size_t sp = 0u;
    size_t limit = 0u;
    uint32_t visited = 0u;
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;

    if (view == NULL || out_node_count == NULL || head_addr.value == 0u || max_steps == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    st = rome2_vfs_decode_dep_rb_node32(view, head_addr, &head_node);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (head_node.is_nil == 0u || head_node.parent == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    limit = max_steps > ROME2_VFS_MAX_DEP_RB_VISIT ? ROME2_VFS_MAX_DEP_RB_VISIT : max_steps;
    stack[sp++] = make_guest_addr32(head_node.parent);

    while (sp > 0u) {
        rome2_guest_addr32 cur_addr = stack[--sp];
        rome2_vfs_dep_rb_node32 cur;

        if (cur_addr.value == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        st = rome2_vfs_decode_dep_rb_node32(view, cur_addr, &cur);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (cur.is_nil != 0u) {
            continue;
        }
        if ((size_t)visited >= limit) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        visited += 1u;

        if (cur.right == cur_addr.value || cur.left == cur_addr.value) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        if (cur.right == 0u || cur.left == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        if (sp + 2u > ROME2_VFS_MAX_RB_STACK_DEPTH) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        /* Match 0x112a2760: handle right subtree and continue left subtree. */
        stack[sp++] = make_guest_addr32(cur.left);
        stack[sp++] = make_guest_addr32(cur.right);
    }

    *out_node_count = visited;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dep_pair_compare32(
    const uint32_t lhs_a[3],
    const uint32_t lhs_b[3],
    const uint32_t rhs_a[3],
    const uint32_t rhs_b[3],
    rome2_vfs_key12_less_fn less_fn,
    void *ctx,
    int32_t *out_order)
{
    int a_lt = 0;
    int a_gt = 0;
    int b_lt = 0;
    int b_gt = 0;
    int rc = 0;

    if (lhs_a == NULL || lhs_b == NULL || rhs_a == NULL || rhs_b == NULL ||
        less_fn == NULL || out_order == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    rc = less_fn(lhs_a, rhs_a, ctx, &a_lt);
    if (rc != 0) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (a_lt != 0) {
        *out_order = -1;
        return ROME2_VFS_REG_OK;
    }

    rc = less_fn(rhs_a, lhs_a, ctx, &a_gt);
    if (rc != 0) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (a_gt != 0) {
        *out_order = 1;
        return ROME2_VFS_REG_OK;
    }

    rc = less_fn(lhs_b, rhs_b, ctx, &b_lt);
    if (rc != 0) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (b_lt != 0) {
        *out_order = -1;
        return ROME2_VFS_REG_OK;
    }

    rc = less_fn(rhs_b, lhs_b, ctx, &b_gt);
    if (rc != 0) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    *out_order = (b_gt != 0) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_ref_block_vtable32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_ref_block_vtable32 *out_vtable)
{
    rome2_code_address32 slots[4];
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;

    if (out_vtable == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_nonnull_code_table(view, vtable_addr, slots, 4u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    out_vtable->destroy_embedded = slots[0];
    out_vtable->get_deleter = slots[1];
    out_vtable->scalar_deleting_dtor = slots[2];
    out_vtable->noop_release = slots[3];
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_stream_wrap_vtable_prefix32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_stream_wrap_vtable_prefix32 *out_prefix)
{
    rome2_code_address32 slots[8];
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;

    if (out_prefix == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_nonnull_code_table(view, vtable_addr, slots, 8u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    out_prefix->scalar_deleting_dtor = slots[0];
    out_prefix->open_checked = slots[1];
    out_prefix->slot_008 = slots[2];
    out_prefix->slot_00c = slots[3];
    out_prefix->slot_010 = slots[4];
    out_prefix->slot_014 = slots[5];
    out_prefix->slot_018 = slots[6];
    out_prefix->slot_01c = slots[7];
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_open_pack_stride20_slot_offset32(
    uint32_t bucket_count,
    uint32_t hash_value,
    uint32_t probe_step,
    uint32_t *out_byte_offset)
{
    uint32_t base_slot = 0u;
    uint32_t slot = 0u;
    uint64_t byte_offset = 0u;

    if (out_byte_offset == NULL || bucket_count == 0u || probe_step >= bucket_count) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    base_slot = hash_value % bucket_count;
    slot = (base_slot + probe_step) % bucket_count;
    byte_offset = (uint64_t)slot * (uint64_t)ROME2_VFS_OPEN_PACK_SLOT_STRIDE;
    if (byte_offset > (uint64_t)UINT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_byte_offset = (uint32_t)byte_offset;
    return ROME2_VFS_REG_OK;
}
