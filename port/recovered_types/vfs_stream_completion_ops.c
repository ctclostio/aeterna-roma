#include "vfs_stream_completion_ops.h"

#include <string.h>

static rome2_vfs_reg_status checked_guest_offset(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    size_t byte_len,
    size_t *out_offset)
{
    uint32_t delta;

    if (view == NULL || view->host_base == NULL || out_offset == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (addr.value == 0u || addr.value < view->guest_base) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    delta = addr.value - view->guest_base;
    if ((size_t)delta > view->byte_count || byte_len > view->byte_count - (size_t)delta) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_offset = (size_t)delta;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status read_guest_u8_byte(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    uint8_t *out_val)
{
    size_t offset = 0u;
    rome2_vfs_reg_status st = checked_guest_offset(view, addr, 1u, &offset);

    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_val = view->host_base[offset];
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status read_guest_bytes_checked(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    uint8_t *dst_buf,
    size_t byte_len)
{
    size_t offset = 0u;
    rome2_vfs_reg_status st;

    if (byte_len > 0u && dst_buf == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = checked_guest_offset(view, addr, byte_len, &offset);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (byte_len > 0u) {
        memcpy(dst_buf, view->host_base + offset, byte_len);
    }
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status read_guest_u32_disp(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t disp,
    uint32_t *out_val)
{
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

static rome2_vfs_reg_status read_guest_u32_array(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 base,
    uint32_t *out_words,
    size_t word_count)
{
    size_t i;

    for (i = 0u; i < word_count; ++i) {
        rome2_vfs_reg_status st = read_guest_u32_disp(
            view, base, (uint32_t)(i * 4u), &out_words[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    return ROME2_VFS_REG_OK;
}

static uint32_t load_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) |
           ((uint32_t)p[3] << 24u);
}

static void store_u32_le(uint8_t *p, uint32_t val)
{
    p[0] = (uint8_t)(val & 0xffu);
    p[1] = (uint8_t)((val >> 8u) & 0xffu);
    p[2] = (uint8_t)((val >> 16u) & 0xffu);
    p[3] = (uint8_t)((val >> 24u) & 0xffu);
}

static rome2_vfs_reg_status stream_state_u64_ne_common(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 stream_obj_addr,
    uint32_t flag_disp,
    uint32_t u64_disp,
    uint64_t expected_u64,
    int *out_result)
{
    uint32_t flag_word;
    uint32_t lo_word;
    uint32_t hi_word;
    uint64_t actual_u64;
    rome2_vfs_reg_status st;

    if (view == NULL || out_result == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_guest_u32_disp(view, stream_obj_addr, flag_disp, &flag_word);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (flag_word == 0u) {
        *out_result = 0;
        return ROME2_VFS_REG_OK;
    }
    st = read_guest_u32_disp(view, stream_obj_addr, u64_disp + 4u, &hi_word);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_guest_u32_disp(view, stream_obj_addr, u64_disp, &lo_word);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    actual_u64 = ((uint64_t)hi_word << 32u) | (uint64_t)lo_word;
    *out_result = (actual_u64 != expected_u64) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_xor_deobfuscate_blocks32(
    const uint8_t *src_bytes,
    size_t byte_len,
    uint8_t *dst_bytes,
    uint32_t *inout_key,
    size_t *out_bytes_processed)
{
    size_t aligned_len;
    size_t blocks;
    size_t i;
    uint32_t key;

    if (out_bytes_processed == NULL ||
        (byte_len > 0u && (src_bytes == NULL || dst_bytes == NULL))) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    aligned_len = byte_len - (byte_len & 7u);
    blocks = (aligned_len + 7u) >> 3u;
    key = (inout_key != NULL) ? *inout_key : 0u;

    for (i = 0u; i < blocks; ++i) {
        uint32_t not_k = ~key;
        uint64_t prod_lo = (uint64_t)not_k * 0x40a6920eULL;
        uint32_t mask_lo = (uint32_t)prod_lo;
        uint32_t mask_hi = (uint32_t)(not_k * 0x8feb2a67u) + (uint32_t)(prod_lo >> 32u);
        size_t off = i * 8u;
        uint32_t in_lo = load_u32_le(src_bytes + off);
        uint32_t in_hi = load_u32_le(src_bytes + off + 4u);

        store_u32_le(dst_bytes + off, in_lo ^ mask_lo);
        store_u32_le(dst_bytes + off + 4u, in_hi ^ mask_hi);
        key += 8u;
    }

    if (inout_key != NULL) {
        *inout_key = key;
    }
    *out_bytes_processed = blocks * 8u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_page_copy_cancellable32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 src_addr,
    uint32_t byte_count,
    uint32_t page_size,
    rome2_guest_addr32 cancel_flag_addr,
    uint8_t *dst_buf,
    uint32_t *out_copied_bytes,
    int *out_cancelled)
{
    uint8_t cancel_flag = 0u;
    uint32_t copied = 0u;
    uint32_t remaining = byte_count;
    rome2_guest_addr32 cur_src = src_addr;
    rome2_guest_addr32 end_addr;

    if (view == NULL || page_size == 0u ||
        out_copied_bytes == NULL || out_cancelled == NULL ||
        (byte_count > 0u && dst_buf == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    if (read_guest_u8_byte(view, cancel_flag_addr, &cancel_flag) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (cancel_flag != 0u) {
        *out_copied_bytes = 0u;
        *out_cancelled = 1;
        return ROME2_VFS_REG_OK;
    }

    if (rome2_guest_add_checked(src_addr, byte_count, &end_addr) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (byte_count > 0u) {
        size_t full_off = 0u;
        if (checked_guest_offset(view, src_addr, (size_t)byte_count, &full_off) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
    }

    while (cancel_flag == 0u && remaining >= page_size) {
        if (read_guest_bytes_checked(view, cur_src, dst_buf + copied, (size_t)page_size) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        cur_src.value += page_size;
        copied += page_size;
        remaining -= page_size;
        if (read_guest_u8_byte(view, cancel_flag_addr, &cancel_flag) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
    }

    if (cancel_flag == 0u && remaining > 0u) {
        if (read_guest_bytes_checked(view, cur_src, dst_buf + copied, (size_t)remaining) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        copied += remaining;
    }

    *out_copied_bytes = copied;
    *out_cancelled = (cancel_flag != 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_crt_allmul32(
    uint32_t a_lo,
    uint32_t a_hi,
    uint32_t b_lo,
    uint32_t b_hi,
    uint32_t *out_lo,
    uint32_t *out_hi)
{
    uint64_t a;
    uint64_t b;
    uint64_t prod;

    if (out_lo == NULL || out_hi == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    a = ((uint64_t)a_hi << 32u) | (uint64_t)a_lo;
    b = ((uint64_t)b_hi << 32u) | (uint64_t)b_lo;
    prod = a * b;
    *out_lo = (uint32_t)prod;
    *out_hi = (uint32_t)(prod >> 32u);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_crt_aulldiv32(
    uint32_t dvd_lo,
    uint32_t dvd_hi,
    uint32_t dvs_lo,
    uint32_t dvs_hi,
    uint32_t *out_lo,
    uint32_t *out_hi)
{
    uint64_t dvd;
    uint64_t dvs;
    uint64_t quot;

    if (out_lo == NULL || out_hi == NULL || (dvs_lo == 0u && dvs_hi == 0u)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    dvd = ((uint64_t)dvd_hi << 32u) | (uint64_t)dvd_lo;
    dvs = ((uint64_t)dvs_hi << 32u) | (uint64_t)dvs_lo;
    quot = dvd / dvs;
    *out_lo = (uint32_t)quot;
    *out_hi = (uint32_t)(quot >> 32u);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_open_cache_entry_init32(
    rome2_vfs_open_cache_entry16_32 *entry,
    uint32_t token_lo_arg,
    uint32_t token_hi_arg,
    uint32_t resolved_lo,
    uint32_t resolved_hi)
{
    if (entry == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    entry->zero_004 = 0u;
    entry->token_lo_008 = (token_lo_arg == UINT32_MAX) ? resolved_lo : token_lo_arg;
    entry->token_hi_00c = (token_hi_arg == UINT32_MAX) ? resolved_hi : token_hi_arg;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_open_cache_entry_read_pair32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 entry_addr,
    uint32_t *out_token_lo,
    uint32_t *out_token_hi)
{
    uint32_t lo_val;
    uint32_t hi_val;
    rome2_vfs_reg_status st;

    if (view == NULL || out_token_lo == NULL || out_token_hi == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_guest_u32_disp(view, entry_addr, 0x08u, &lo_val);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_guest_u32_disp(view, entry_addr, 0x0cu, &hi_val);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_token_lo = lo_val;
    *out_token_hi = hi_val;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_read_backing_pair32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 pack_entry_addr,
    uint32_t *out_token_lo,
    uint32_t *out_token_hi)
{
    uint32_t carrier_val;
    uint32_t inner_val;
    rome2_guest_addr32 carrier_addr;
    rome2_guest_addr32 inner_addr;
    rome2_guest_addr32 entry_addr;
    rome2_vfs_reg_status st;

    if (view == NULL || out_token_lo == NULL || out_token_hi == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_guest_u32_disp(view, pack_entry_addr, 0x1cu, &carrier_val);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    carrier_addr.value = carrier_val;
    st = read_guest_u32_disp(view, carrier_addr, 0x00u, &inner_val);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    inner_addr.value = inner_val;
    if (rome2_guest_add_checked(inner_addr, 0x08u, &entry_addr) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    return rome2_vfs_open_cache_entry_read_pair32(view, entry_addr, out_token_lo, out_token_hi);
}

rome2_vfs_reg_status rome2_vfs_pack_extract_archive_flags_4_5_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 pack_entry_addr,
    uint32_t *out_flags)
{
    uint32_t carrier_val;
    uint32_t props_val;
    uint32_t raw_flags;
    rome2_guest_addr32 carrier_addr;
    rome2_guest_addr32 props_addr;
    rome2_vfs_reg_status st;

    if (view == NULL || out_flags == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_guest_u32_disp(view, pack_entry_addr, 0x1cu, &carrier_val);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    carrier_addr.value = carrier_val;
    st = read_guest_u32_disp(view, carrier_addr, 0x00u, &props_val);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    props_addr.value = props_val;
    st = read_guest_u32_disp(view, props_addr, 0x1cu, &raw_flags);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_flags = ((raw_flags >> 4u) & 1u) | (((raw_flags & 0x20u) != 0u) ? 2u : 0u);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_stream_state_u64_ne_28_38_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 stream_obj_addr,
    uint64_t expected_u64,
    int *out_result)
{
    return stream_state_u64_ne_common(view, stream_obj_addr, 0x38u, 0x28u, expected_u64, out_result);
}

rome2_vfs_reg_status rome2_vfs_stream_state_u64_ne_20_2c_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 stream_obj_addr,
    uint64_t expected_u64,
    int *out_result)
{
    return stream_state_u64_ne_common(view, stream_obj_addr, 0x2cu, 0x20u, expected_u64, out_result);
}

rome2_vfs_reg_status rome2_vfs_decode_async_worker_ref_block56_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_async_worker_ref_block56_32 *out_block)
{
    uint32_t words[14];
    rome2_vfs_reg_status st;
    size_t i;

    if (view == NULL || out_block == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_guest_u32_array(view, addr, words, 14u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    out_block->vtable = words[0];
    out_block->strong_refs_004 = words[1];
    out_block->weak_refs_008 = words[2];
    out_block->queue_head_00c = words[3];
    out_block->queue_tail_010 = words[4];
    out_block->zero_014 = words[5];
    out_block->active_count_018 = words[6];
    for (i = 0u; i < 6u; ++i) {
        out_block->cs_01c[i] = words[7u + i];
    }
    out_block->semaphore_034 = words[13];
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_stream_vtable_11slot32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_stream_vtable_11slot32 *out_vt)
{
    uint32_t words[11];
    rome2_vfs_reg_status st;

    if (view == NULL || out_vt == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_guest_u32_array(view, addr, words, 11u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    out_vt->scalar_deleting_dtor_000 = words[0];
    out_vt->open_checked_004 = words[1];
    out_vt->slot_008 = words[2];
    out_vt->slot_00c = words[3];
    out_vt->slot_010 = words[4];
    out_vt->slot_014 = words[5];
    out_vt->slot_018 = words[6];
    out_vt->slot_01c = words[7];
    out_vt->get_field_020 = words[8];
    out_vt->has_state_024 = words[9];
    out_vt->state_u64_ne_028 = words[10];
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_decode_pack_vtable_76c0_full32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_pack_vtable_76c0_full32 *out_vt)
{
    uint32_t words[20];
    rome2_vfs_reg_status st;

    if (view == NULL || out_vt == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_guest_u32_array(view, addr, words, 20u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    out_vt->slot_000_ad1b0 = words[0];
    out_vt->slot_004_d3270 = words[1];
    out_vt->slot_008_e0d80 = words[2];
    out_vt->slot_00c_71400 = words[3];
    out_vt->slot_010_01a40 = words[4];
    out_vt->slot_014_c8be0 = words[5];
    out_vt->slot_018_c9540 = words[6];
    out_vt->slot_01c_d0c90 = words[7];
    out_vt->slot_020_d0d80 = words[8];
    out_vt->slot_024_dab70 = words[9];
    out_vt->slot_028_69610 = words[10];
    out_vt->slot_02c_baf20 = words[11];
    out_vt->slot_030_d9890 = words[12];
    out_vt->slot_034_d2900 = words[13];
    out_vt->slot_038_d0bd0 = words[14];
    out_vt->slot_03c_c0dd0 = words[15];
    out_vt->slot_040_dd2f0 = words[16];
    out_vt->slot_044_e0d80 = words[17];
    out_vt->slot_048_c0090 = words[18];
    out_vt->slot_04c_c0c40 = words[19];
    return ROME2_VFS_REG_OK;
}
