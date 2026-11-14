#include "vfs_view_map_ops.h"

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

static rome2_vfs_reg_status read_guest_u32_block(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t *words_out,
    size_t word_count)
{
    size_t i;
    rome2_vfs_reg_status st;

    for (i = 0u; i < word_count; ++i) {
        st = read_guest_u32_disp(view, base, (uint32_t)(i * 4u), &words_out[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status bounded_cstr_len(
    const char *s,
    size_t max_len,
    size_t *out_len)
{
    size_t i;

    if (s == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (i = 0u; i < max_len; ++i) {
        if (s[i] == '\0') {
            *out_len = i;
            return ROME2_VFS_REG_OK;
        }
    }
    return ROME2_VFS_REG_RANGE_ERROR;
}

rome2_vfs_reg_status rome2_vfs_plan_u32_aligned_alloc32(
    uint32_t element_count,
    uint32_t *out_raw_bytes,
    int *out_use_aligned32)
{
    uint32_t payload;

    if (out_raw_bytes == NULL || out_use_aligned32 == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (element_count > ROME2_VFS_U32_VEC_MAX_ELEMENTS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (element_count == 0u) {
        *out_raw_bytes = 0u;
        *out_use_aligned32 = 0;
        return ROME2_VFS_REG_OK;
    }
    payload = element_count * 4u;
    if (payload >= ROME2_VFS_ALIGNED_ALLOC_THRESHOLD) {
        if (payload > UINT32_MAX - ROME2_VFS_ALIGNED_ALLOC_PAD) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        *out_raw_bytes = payload + ROME2_VFS_ALIGNED_ALLOC_PAD;
        *out_use_aligned32 = 1;
        return ROME2_VFS_REG_OK;
    }
    *out_raw_bytes = payload;
    *out_use_aligned32 = 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_u32_vec_plan_rebind32(
    const rome2_guest_read_view *view,
    const rome2_vfs_u32_ptr_vec32 *old_vec,
    rome2_guest_addr32 new_first,
    uint32_t new_size,
    uint32_t new_cap,
    int *out_needs_free,
    rome2_guest_addr32 *out_free_addr,
    uint32_t *out_free_bytes,
    rome2_vfs_u32_ptr_vec32 *out_new_vec)
{
    uint32_t cap_span;
    uint32_t size_bytes;
    uint32_t cap_bytes;
    rome2_guest_addr32 next_last;
    rome2_guest_addr32 next_end;
    rome2_guest_addr32 hdr_cell;
    rome2_guest_addr32 free_addr;
    uint32_t free_bytes = 0u;
    int needs_free = 0;

    if (old_vec == NULL || out_needs_free == NULL || out_free_addr == NULL ||
        out_free_bytes == NULL || out_new_vec == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (new_size > new_cap || new_cap > ROME2_VFS_U32_VEC_MAX_ELEMENTS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (new_cap > 0u && new_first.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    size_bytes = new_size * 4u;
    cap_bytes = new_cap * 4u;
    if (rome2_guest_add_checked(new_first, size_bytes, &next_last) != ROME2_GUEST_OK ||
        rome2_guest_add_checked(new_first, cap_bytes, &next_end) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    free_addr.value = 0u;
    if (old_vec->first != 0u) {
        if (old_vec->end < old_vec->first) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        cap_span = (old_vec->end - old_vec->first) & 0xfffffffcu;
        needs_free = 1;
        if (cap_span >= ROME2_VFS_ALIGNED_ALLOC_THRESHOLD) {
            uint32_t raw_val;
            uint32_t gap;

            if (view == NULL) {
                return ROME2_VFS_REG_BAD_ARGUMENT;
            }
            if (old_vec->first < 4u ||
                cap_span > UINT32_MAX - ROME2_VFS_ALIGNED_ALLOC_PAD) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            hdr_cell.value = old_vec->first - 4u;
            if (read_guest_u32_disp(view, hdr_cell, 0u, &raw_val) != ROME2_VFS_REG_OK) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            if (hdr_cell.value < raw_val) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
            gap = hdr_cell.value - raw_val;
            if (gap > ROME2_VFS_ALIGNED_ALLOC_MAX_GAP) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
            free_addr.value = raw_val;
            free_bytes = cap_span + ROME2_VFS_ALIGNED_ALLOC_PAD;
        } else {
            free_addr.value = old_vec->first;
            free_bytes = cap_span;
        }
    }

    *out_needs_free = needs_free;
    *out_free_addr = free_addr;
    *out_free_bytes = free_bytes;
    out_new_vec->first = new_first.value;
    out_new_vec->last = next_last.value;
    out_new_vec->end = next_end.value;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_plan_view_map_window32(
    uint64_t file_offset,
    uint32_t requested_bytes,
    uint32_t alloc_granularity,
    uint32_t *out_aligned_lo,
    uint32_t *out_aligned_hi,
    uint32_t *out_sub_offset,
    uint32_t *out_map_bytes,
    uint32_t *out_probe_bytes)
{
    uint64_t mask;
    uint64_t aligned;
    uint32_t sub_off;
    uint64_t map_len;
    uint64_t gran_m1;

    if (out_aligned_lo == NULL || out_aligned_hi == NULL ||
        out_sub_offset == NULL || out_map_bytes == NULL ||
        out_probe_bytes == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (alloc_granularity == 0u ||
        (alloc_granularity & (alloc_granularity - 1u)) != 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    gran_m1 = (uint64_t)(alloc_granularity - 1u);
    mask = ~gran_m1;
    aligned = file_offset & mask;
    sub_off = (uint32_t)(file_offset - aligned);
    map_len = (uint64_t)sub_off + (uint64_t)requested_bytes;
    if (map_len > (uint64_t)UINT32_MAX - gran_m1) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    *out_aligned_lo = (uint32_t)(aligned & 0xffffffffu);
    *out_aligned_hi = (uint32_t)(aligned >> 32u);
    *out_sub_offset = sub_off;
    *out_map_bytes = (uint32_t)map_len;
    *out_probe_bytes = (uint32_t)((map_len + gran_m1) & mask);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_state_ref_block32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_state_ref_block32 *out_block)
{
    uint32_t words[11];
    rome2_vfs_state_ref_block32 tmp;
    rome2_vfs_reg_status st;

    if (view == NULL || out_block == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (addr.value == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    st = read_guest_u32_block(view, addr, words, 11u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }

    memset(&tmp, 0, sizeof(tmp));
    tmp.vtable = words[0];
    tmp.use_count = words[1];
    tmp.weak_count = words[2];
    tmp.inner_vtable = words[3];
    tmp.state_word_010 = words[4];
    tmp.view_box_ptr = words[5];
    tmp.eof_or_closed_018 = (uint8_t)(words[6] & 0xffu);
    tmp.closed_019 = (uint8_t)((words[6] >> 8u) & 0xffu);
    tmp.unobserved_01a[0] = (uint8_t)((words[6] >> 16u) & 0xffu);
    tmp.unobserved_01a[1] = (uint8_t)((words[6] >> 24u) & 0xffu);
    tmp.handle_ptr = words[7];
    tmp.word_020 = words[8];
    tmp.word_024 = words[9];
    tmp.flag_028 = (uint8_t)(words[10] & 0xffu);
    tmp.unobserved_029[0] = (uint8_t)((words[10] >> 8u) & 0xffu);
    tmp.unobserved_029[1] = (uint8_t)((words[10] >> 16u) & 0xffu);
    tmp.unobserved_029[2] = (uint8_t)((words[10] >> 24u) & 0xffu);
    *out_block = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_pack_telemetry_mgr32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_pack_telemetry_mgr32 *out_mgr)
{
    uint32_t words[27];
    rome2_vfs_pack_telemetry_mgr32 tmp;
    rome2_vfs_reg_status st;
    size_t i;

    if (view == NULL || out_mgr == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (addr.value == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    st = read_guest_u32_block(view, addr, words, 27u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }

    memset(&tmp, 0, sizeof(tmp));
    tmp.vtable = words[0];
    tmp.unobserved_004 = words[1];
    tmp.unobserved_008 = (uint16_t)(words[2] & 0xffffu);
    tmp.flag_00a = (uint8_t)((words[2] >> 16u) & 0xffu);
    tmp.unobserved_00b = (uint8_t)((words[2] >> 24u) & 0xffu);
    tmp.process_id = words[3];
    tmp.zero_010 = words[4];
    for (i = 0u; i < 6u; ++i) {
        tmp.cs_014[i] = words[5u + i];
        tmp.table_words_02c[i] = words[11u + i];
        tmp.cs_054[i] = words[21u + i];
    }
    tmp.bucket_cap_044 = words[17];
    tmp.bucket_count_048 = words[18];
    tmp.buckets_04c = words[19];
    tmp.zero_050 = words[20];
    *out_mgr = tmp;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_ascii_contains_bounded(
    const char *haystack,
    size_t haystack_max,
    const char *needle,
    size_t needle_max,
    int *out_found)
{
    size_t h_len;
    size_t n_len;
    size_t i;
    rome2_vfs_reg_status st;

    if (out_found == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = bounded_cstr_len(haystack, haystack_max, &h_len);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = bounded_cstr_len(needle, needle_max, &n_len);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (h_len == 0u) {
        *out_found = 0;
        return ROME2_VFS_REG_OK;
    }
    if (n_len == 0u) {
        *out_found = 1;
        return ROME2_VFS_REG_OK;
    }
    if (n_len > h_len) {
        *out_found = 0;
        return ROME2_VFS_REG_OK;
    }
    for (i = 0u; i <= h_len - n_len; ++i) {
        if (memcmp(haystack + i, needle, n_len) == 0) {
            *out_found = 1;
            return ROME2_VFS_REG_OK;
        }
    }
    *out_found = 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_prefetch_pages_sum32(
    const uint8_t *buf,
    uint32_t byte_len,
    uint32_t page_stride,
    uint32_t initial_acc,
    uint32_t *out_acc)
{
    uint32_t acc = initial_acc;
    uint32_t off = 0u;

    if (out_acc == NULL || page_stride == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (byte_len > 0u && buf == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    while (off < byte_len) {
        acc += (uint32_t)buf[off];
        if (byte_len - off <= page_stride) {
            break;
        }
        off += page_stride;
    }
    *out_acc = acc;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_entry_read_archive_bit6_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 entry_addr,
    uint8_t *out_bit)
{
    uint32_t carrier_val;
    uint32_t inner_val;
    uint32_t flags_word;
    rome2_guest_addr32 carrier_addr;
    rome2_guest_addr32 inner_addr;
    rome2_vfs_reg_status st;

    if (view == NULL || out_bit == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (entry_addr.value == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    st = read_guest_u32_disp(view, entry_addr, 0x1cu, &carrier_val);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (carrier_val == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    carrier_addr.value = carrier_val;
    st = read_guest_u32_disp(view, carrier_addr, 0x00u, &inner_val);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (inner_val == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    inner_addr.value = inner_val;
    st = read_guest_u32_disp(view, inner_addr, 0x1cu, &flags_word);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_bit = (uint8_t)((flags_word >> 6u) & 1u);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_deleting_dtor_size32(
    rome2_code_address32 dtor_addr,
    uint8_t delete_flags,
    uint32_t *out_free_bytes,
    rome2_vtable_address32 *out_reset_vtable)
{
    static const struct {
        rome2_code_address32 dtor_addr;
        uint32_t object_bytes;
        rome2_vtable_address32 reset_vtable;
    } table[] = {
        { ROME2_VFS_DTOR_112ACCD0, 0x38u, 0u },
        { ROME2_VFS_DTOR_112ACCF0, 0x20u, 0u },
        { ROME2_VFS_DTOR_112ACD10, 0x1cu, 0u },
        { ROME2_VFS_DTOR_112ACD30, 0x2cu, 0u },
        { ROME2_VFS_DTOR_112ACD50, 0x50u, 0u },
        { ROME2_VFS_DTOR_112ACD70, 0x18u, 0u },
        { ROME2_VFS_DTOR_112AD1B0, 0x28u, ROME2_VFS_PACK_ENTRY_BASE_VTABLE32 },
    };
    size_t i;

    if (out_free_bytes == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (i = 0u; i < sizeof(table) / sizeof(table[0]); ++i) {
        if (table[i].dtor_addr == dtor_addr) {
            *out_free_bytes = ((delete_flags & 1u) != 0u) ? table[i].object_bytes : 0u;
            if (out_reset_vtable != NULL) {
                *out_reset_vtable = table[i].reset_vtable;
            }
            return ROME2_VFS_REG_OK;
        }
    }
    return ROME2_VFS_REG_INVALID_STATE;
}
