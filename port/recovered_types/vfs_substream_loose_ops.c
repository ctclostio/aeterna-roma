#include "vfs_substream_loose_ops.h"

#include <string.h>

static rome2_vfs_reg_status read_u32_disp(
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

static rome2_vfs_reg_status decode_and_match_u32_table(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    const uint32_t *expected,
    size_t slot_count,
    void *out_vt,
    size_t vt_bytes,
    int *out_matches)
{
    uint32_t words[20];
    size_t i;
    int matches = 1;

    if (view == NULL || out_vt == NULL || out_matches == NULL ||
        slot_count > (sizeof(words) / sizeof(words[0])) || vt_bytes != slot_count * 4u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (i = 0u; i < slot_count; ++i) {
        rome2_vfs_reg_status st = read_u32_disp(view, vtable_addr, (uint32_t)(i * 4u), &words[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        if (words[i] != expected[i]) {
            matches = 0;
        }
    }
    memcpy(out_vt, words, vt_bytes);
    *out_matches = matches;
    return ROME2_VFS_REG_OK;
}

static void remap_substream_window(
    rome2_vfs_buffered_substream40_32 *sub,
    uint32_t new_window_base,
    uint32_t new_window_size,
    uint32_t new_stream_pos,
    int *out_remapped)
{
    sub->window_base_04 = new_window_base;
    sub->window_size_08 = new_window_size;
    sub->window_offset_0c = 0u;
    sub->stream_pos_10 = new_stream_pos;
    *out_remapped = 1;
}

rome2_vfs_reg_status rome2_vfs_close_handle_bool_6fd0(
    const rome2_vfs_win32_handle_ops *ops,
    uint32_t handle,
    int *out_closed_ok)
{
    int rc;

    if (ops == NULL || ops->close_handle == NULL || out_closed_ok == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    rc = ops->close_handle(ops->ctx, handle);
    *out_closed_ok = (rc == 1) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_create_file_flags_4cc0(
    uint8_t unbuffered_or_async,
    uint32_t *out_desired_access,
    uint32_t *out_share_mode,
    uint32_t *out_creation_disposition,
    uint32_t *out_flags_and_attrs)
{
    if (out_desired_access == NULL || out_share_mode == NULL ||
        out_creation_disposition == NULL || out_flags_and_attrs == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_desired_access = ROME2_VFS_CREATE_FILE_GENERIC_READ32;
    *out_share_mode = ROME2_VFS_CREATE_FILE_SHARE_RW32;
    *out_creation_disposition = ROME2_VFS_CREATE_FILE_OPEN_EXISTING32;
    *out_flags_and_attrs = (unbuffered_or_async != 0u)
        ? ROME2_VFS_CREATE_FILE_ATTR_ASYNC_DIRECT32
        : ROME2_VFS_CREATE_FILE_ATTR_BUFFERED32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_file_stat20_zero_fda0(
    rome2_vfs_file_stat20_32 *stat_out)
{
    if (stat_out == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    stat_out->file_size_low_00 = 0u;
    stat_out->file_size_high_04 = 0u;
    stat_out->mtime_low_08 = 0u;
    stat_out->mtime_high_0c = 0u;
    stat_out->attr_flags_10 = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_aligned16_or_memcpy_43d0(
    uintptr_t dst_guest_addr,
    uintptr_t src_guest_addr,
    uint8_t *dst_buf,
    const uint8_t *src_buf,
    size_t byte_count,
    int *out_used_aligned16)
{
    uintptr_t d_ptr;
    uintptr_t s_ptr;

    if (dst_buf == NULL || src_buf == NULL || out_used_aligned16 == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (byte_count > 0u) {
        d_ptr = (uintptr_t)dst_buf;
        s_ptr = (uintptr_t)src_buf;
        if ((d_ptr >= s_ptr && (d_ptr - s_ptr) < byte_count) ||
            (s_ptr > d_ptr && (s_ptr - d_ptr) < byte_count)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        memcpy(dst_buf, src_buf, byte_count);
    }
    *out_used_aligned16 =
        (((dst_guest_addr | src_guest_addr | (uintptr_t)byte_count) & (uintptr_t)0x0fu) == 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_std_exception_what_5df0(
    const rome2_vfs_bad_alloc_exc8_32 *exc,
    uint32_t *out_what_addr)
{
    if (exc == NULL || out_what_addr == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_what_addr = (exc->what_str_04 != 0u)
        ? exc->what_str_04
        : ROME2_VFS_STD_EXCEPTION_UNKNOWN32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_loose_entry_clamp_window_0d20(
    const rome2_vfs_loose_file_entry32 *entry,
    uint32_t req_length,
    uint32_t req_offset,
    uint32_t *out_clamped_length,
    uint32_t *out_offset)
{
    uint32_t rem;

    if (entry == NULL || out_clamped_length == NULL || out_offset == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (req_offset > entry->file_size_14) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    rem = entry->file_size_14 - req_offset;
    if (req_length != 0u && rem >= req_length) {
        rem = req_length;
    }
    *out_clamped_length = rem;
    *out_offset = req_offset;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_loose_entry_teardown_handles_aa40(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_loose_file_entry32 *entry,
    int *out_closed_ok)
{
    rome2_vfs_reg_status st;

    if (ops == NULL || ops->close_handle == NULL || entry == NULL || out_closed_ok == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    entry->backing_view_1c = 0u;
    st = rome2_vfs_close_handle_bool_6fd0(ops, entry->file_handle_0c, out_closed_ok);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    entry->file_handle_0c = ROME2_VFS_INVALID_HANDLE32;
    entry->aux_handle_10 = ROME2_VFS_INVALID_HANDLE32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_loose_vtable_7710_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_loose_vtable_7710_20slot32 *out_vt,
    int *out_matches)
{
    static const uint32_t expected[20] = {
        0x112acf40u, 0x112d3270u, 0x10a34b40u, 0x10171400u,
        0x101d9800u, 0x112c8b90u, 0x100d6900u, 0x112d0bf0u,
        0x112d0d20u, 0x112daa40u, 0x101d97f0u, 0x112baeb0u,
        0x112d9880u, 0x100d6560u, 0x112d0bb0u, 0x112c0db0u,
        0x112dd2e0u, 0x112d3270u, 0x112bffe0u, 0x100dbc00u
    };

    return decode_and_match_u32_table(
        view, vtable_addr, expected, 20u, out_vt, sizeof(*out_vt), out_matches);
}

rome2_vfs_reg_status rome2_vfs_pack_wrap_vtable_7760_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_pack_wrap_vtable_7760_12slot32 *out_vt,
    int *out_matches)
{
    static const uint32_t expected[12] = {
        0x112ace20u, 0x112d3270u, 0x112d3270u, 0x101d9800u,
        0x101a0430u, 0x10abbf90u, 0x112c9520u, 0x100e22c0u,
        0x100f3d00u, 0x100dbc00u, 0x100dbc00u, 0x112c8c80u
    };

    return decode_and_match_u32_table(
        view, vtable_addr, expected, 12u, out_vt, sizeof(*out_vt), out_matches);
}

rome2_vfs_reg_status rome2_vfs_pack_wrap_flag_bit6_9520(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 obj_addr,
    uint8_t *out_bit)
{
    uint32_t ptr18 = 0u;
    uint32_t inner = 0u;
    uint32_t flags1c = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || out_bit == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_u32_disp(view, obj_addr, 0x18u, &ptr18);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (ptr18 == 0u) {
        *out_bit = 1u;
        return ROME2_VFS_REG_OK;
    }
    st = read_u32_disp(view, (rome2_guest_addr32){ptr18}, 0x00u, &inner);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_disp(view, (rome2_guest_addr32){inner}, 0x1cu, &flags1c);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_bit = (uint8_t)((flags1c >> 6) & 1u);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_substream_vtable_7c24_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_substream_vtable_7c24_8slot32 *out_vt,
    int *out_matches)
{
    static const uint32_t expected[8] = {
        0x112ad6a0u, 0x112c8c40u, 0x112d98c0u, 0x112c0cf0u,
        0x112dc1a0u, 0x112d3290u, 0x112d5690u, 0x112d57d0u
    };

    return decode_and_match_u32_table(
        view, vtable_addr, expected, 8u, out_vt, sizeof(*out_vt), out_matches);
}

rome2_vfs_reg_status rome2_vfs_substream_can_read_8c40(
    const rome2_vfs_buffered_substream40_32 *sub,
    int parent_ready,
    int *out_can_read)
{
    if (sub == NULL || out_can_read == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_can_read = (sub->eof_flag_24 == 0u && sub->error_flag_25 == 0u && parent_ready != 0) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_substream_refresh_eof_57d0(
    rome2_vfs_buffered_substream40_32 *sub,
    uint32_t parent_size)
{
    if (sub == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    sub->eof_flag_24 = (sub->stream_pos_10 >= parent_size) ? 1u : 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_substream_advance_0cf0(
    rome2_vfs_buffered_substream40_32 *sub,
    uint32_t delta,
    uint32_t new_window_base,
    uint32_t new_window_size,
    int *out_remapped)
{
    uint32_t next_win_off;
    uint32_t next_pos;

    if (sub == NULL || out_remapped == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (delta == 0u) {
        remap_substream_window(
            sub, new_window_base, new_window_size, sub->initial_pos_or_cursor_1c, out_remapped);
        return ROME2_VFS_REG_OK;
    }
    if (delta > UINT32_MAX - sub->window_offset_0c || delta > UINT32_MAX - sub->stream_pos_10) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    next_win_off = sub->window_offset_0c + delta;
    next_pos = sub->stream_pos_10 + delta;
    if (next_win_off < sub->window_size_08) {
        sub->window_offset_0c = next_win_off;
        sub->stream_pos_10 = next_pos;
        *out_remapped = 0;
    } else {
        remap_substream_window(sub, new_window_base, new_window_size, next_pos, out_remapped);
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_substream_rewind_c1a0(
    rome2_vfs_buffered_substream40_32 *sub,
    uint32_t delta,
    uint32_t new_window_base,
    uint32_t new_window_size,
    int *out_remapped)
{
    if (sub == NULL || out_remapped == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (delta == 0u) {
        remap_substream_window(
            sub, new_window_base, new_window_size, sub->initial_pos_or_cursor_1c, out_remapped);
        return ROME2_VFS_REG_OK;
    }
    if (delta > sub->stream_pos_10) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (sub->window_offset_0c >= delta) {
        sub->window_offset_0c -= delta;
        sub->stream_pos_10 -= delta;
        *out_remapped = 0;
    } else {
        remap_substream_window(
            sub, new_window_base, new_window_size, sub->stream_pos_10 - delta, out_remapped);
    }
    return ROME2_VFS_REG_OK;
}
