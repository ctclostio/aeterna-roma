#include "vfs_rb_bucket_ops.h"

#include <math.h>
#include <string.h>

static rome2_vfs_reg_status read_box_u32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t disp,
    uint32_t *out_value)
{
    rome2_guest_addr32 target = {0u};
    rome2_guest_addr32 cell = {0u};
    rome2_guest_status gst = ROME2_GUEST_OK;

    if (view == NULL || out_value == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    gst = rome2_guest_add_checked(base, disp, &target);
    if (gst != ROME2_GUEST_OK) {
        return (gst == ROME2_GUEST_NULL_ADDRESS) ? ROME2_VFS_REG_BAD_ARGUMENT : ROME2_VFS_REG_RANGE_ERROR;
    }
    gst = rome2_guest_read_addr32_le(view, target, &cell);
    if (gst != ROME2_GUEST_OK) {
        return (gst == ROME2_GUEST_BAD_ARGUMENT || gst == ROME2_GUEST_NULL_ADDRESS)
            ? ROME2_VFS_REG_BAD_ARGUMENT
            : ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_value = cell.value;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dep_rb_can_allocate32(
    uint32_t current_count,
    uint32_t *out_next_count)
{
    if (out_next_count == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (current_count >= ROME2_VFS_DEP_RB_MAX_NODES) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_next_count = current_count + 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_hash_next_power_of_2_buckets32(
    uint32_t requested_buckets,
    uint32_t *out_bucket_count,
    uint32_t *out_pointer_slots)
{
    uint32_t v = 0u;
    uint32_t msb = 0u;
    uint32_t buckets = 0u;

    if (out_bucket_count == NULL || out_pointer_slots == NULL || requested_buckets == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (requested_buckets > ROME2_VFS_HASH_MAX_BUCKETS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    v = (requested_buckets - 1u) | 1u;
    msb = 0u;
    while ((v >> 1u) != 0u) {
        v >>= 1u;
        msb += 1u;
    }
    buckets = 1u << (msb + 1u);
    if (buckets > ROME2_VFS_HASH_MAX_BUCKETS * 2u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    *out_bucket_count = buckets;
    *out_pointer_slots = buckets * 2u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_hash_desired_buckets32(
    uint32_t element_count,
    uint32_t max_load_factor_bits,
    uint32_t current_buckets,
    uint32_t *out_buckets)
{
    float max_load = 0.0f;
    float needed_f = 0.0f;
    uint32_t needed = 0u;
    uint32_t grown = 0u;

    if (out_buckets == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memcpy(&max_load, &max_load_factor_bits, sizeof(max_load));
    if (!isfinite(max_load) || !(max_load > 0.0f)) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    needed_f = ceilf((float)((double)element_count) / max_load);
    if (!isfinite(needed_f) || needed_f < 0.0f || needed_f >= 4294967296.0f) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    needed = (uint32_t)needed_f;
    if (needed < ROME2_VFS_HASH_MIN_BUCKETS) {
        needed = ROME2_VFS_HASH_MIN_BUCKETS;
    }
    if (needed <= current_buckets) {
        *out_buckets = current_buckets;
        return ROME2_VFS_REG_OK;
    }
    if (current_buckets < ROME2_VFS_HASH_SMALL_GROW_CAP) {
        uint64_t scaled = (uint64_t)current_buckets * 8u;
        if (scaled <= (uint64_t)UINT32_MAX) {
            grown = (uint32_t)scaled;
            *out_buckets = (grown < needed) ? needed : grown;
            return ROME2_VFS_REG_OK;
        }
    }

    *out_buckets = needed;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_stream_handle_box32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 box_addr,
    rome2_vfs_stream_handle_box32 *out_box)
{
    rome2_vfs_stream_handle_box32 tmp;
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;

    if (view == NULL || out_box == NULL || box_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));

    st = read_box_u32(view, box_addr, 0x00u, &tmp.unobserved_000[0]);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_box_u32(view, box_addr, 0x04u, &tmp.unobserved_000[1]);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_box_u32(view, box_addr, 0x08u, &tmp.secondary_ctrl);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_box_u32(view, box_addr, 0x0cu, &tmp.sentinel_or_state);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_box_u32(view, box_addr, 0x10u, &tmp.primary_ctrl);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }

    *out_box = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_bucket_vec_header32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 header_addr,
    rome2_vfs_bucket_vec_header32 *out_header)
{
    rome2_vfs_bucket_vec_header32 tmp;
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;

    if (view == NULL || out_header == NULL || header_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));

    st = read_box_u32(view, header_addr, 0x00u, &tmp.capacity);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_box_u32(view, header_addr, 0x04u, &tmp.count);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_box_u32(view, header_addr, 0x08u, &tmp.slots);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (tmp.count > tmp.capacity) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    *out_header = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_bucket_vec_next_capacity32(
    uint32_t current_capacity,
    uint32_t min_required,
    uint32_t *out_new_capacity,
    uint32_t *out_alloc_bytes)
{
    uint64_t next_cap = 0u;
    uint64_t bytes = 0u;

    if (out_new_capacity == NULL || out_alloc_bytes == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    next_cap = (current_capacity == 0u) ? 1u : (uint64_t)current_capacity * 2u;
    if ((uint64_t)min_required > next_cap) {
        next_cap = (uint64_t)min_required;
    }
    /* Both 0x112d8550 and 0x112dbe10 reject signed-negative (< 0) capacity. */
    if (next_cap > (uint64_t)INT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    bytes = next_cap * (uint64_t)ROME2_VFS_BUCKET_SLOT_BYTES;
    if (bytes > (uint64_t)UINT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    *out_new_capacity = (uint32_t)next_cap;
    *out_alloc_bytes = (uint32_t)bytes;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_validate_aligned_vec_free32(
    uint32_t vec_begin,
    uint32_t vec_cap,
    uint32_t backing_base,
    uint32_t *out_free_bytes)
{
    uint32_t aligned_bytes = 0u;
    uint64_t diff_from_header = 0u;
    uint64_t total = 0u;

    if (out_free_bytes == NULL || vec_begin == 0u || vec_cap < vec_begin) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    aligned_bytes = (vec_cap - vec_begin) & 0xfffffffcu;
    if (aligned_bytes < ROME2_VFS_VEC_ALIGN_THRESHOLD_BYTES) {
        *out_free_bytes = aligned_bytes;
        return ROME2_VFS_REG_OK;
    }

    if (backing_base == 0u || vec_begin < 4u || (vec_begin - 4u) < backing_base) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    diff_from_header = (uint64_t)(vec_begin - 4u) - (uint64_t)backing_base;
    if (diff_from_header > (uint64_t)ROME2_VFS_VEC_ALIGN_HEADER_MAX_GAP) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    total = (uint64_t)aligned_bytes + (uint64_t)ROME2_VFS_VEC_ALIGN_ADJUST_BYTES;
    if (total > (uint64_t)UINT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_free_bytes = (uint32_t)total;
    return ROME2_VFS_REG_OK;
}
