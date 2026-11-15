#include "vfs_handle_lifecycle_ops.h"

#include <string.h>

static uint32_t map_err_default(const rome2_vfs_win32_handle_ops *ops, uint32_t raw_err)
{
    if (ops->map_win32_error != NULL) {
        return ops->map_win32_error(ops->ctx, raw_err);
    }
    return raw_err;
}

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

static void close_owned_handle_slot(
    const rome2_vfs_win32_handle_ops *ops,
    uint32_t *inout_handle,
    uint32_t *inout_flags,
    uint32_t flag_mask)
{
    if (*inout_handle != ROME2_VFS_INVALID_HANDLE32 && (*inout_flags & flag_mask) != 0u) {
        (void)ops->close_handle(ops->ctx, *inout_handle);
        *inout_flags ^= flag_mask;
        *inout_handle = ROME2_VFS_INVALID_HANDLE32;
    }
}

rome2_vfs_reg_status rome2_vfs_semaphore_handle_init_12c0(
    const rome2_vfs_win32_handle_ops *ops,
    int32_t initial_count,
    int32_t max_count,
    const char *name,
    uint32_t *out_handle)
{
    uint32_t handle;
    uint32_t last_err;

    if (ops == NULL || ops->create_semaphore_a == NULL ||
        ops->close_handle == NULL || ops->get_last_error == NULL || out_handle == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    handle = ops->create_semaphore_a(ops->ctx, initial_count, max_count, name);
    last_err = ops->get_last_error(ops->ctx);
    if (last_err == ROME2_VFS_ERR_ALREADY_EXISTS32) {
        (void)ops->close_handle(ops->ctx, handle);
        *out_handle = 0u;
    } else {
        *out_handle = handle;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_semaphore_handle_close_2230(
    const rome2_vfs_win32_handle_ops *ops,
    const uint32_t *handle_cell,
    int *out_closed)
{
    int did_close = 0;

    if (ops == NULL || ops->close_handle == NULL || handle_cell == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (*handle_cell != 0u) {
        (void)ops->close_handle(ops->ctx, *handle_cell);
        did_close = 1;
    }
    if (out_closed != NULL) {
        *out_closed = did_close;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_win32_handle_box_init_1080(
    rome2_vfs_win32_handle_box8_32 *box)
{
    if (box == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    box->handle_00 = ROME2_VFS_INVALID_HANDLE32;
    box->last_status_04 = ROME2_VFS_HANDLE_BOX_CLOSED_STATUS;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_win32_handle_box_close_2170(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_win32_handle_box8_32 *box,
    uint32_t *out_close_error)
{
    uint32_t close_err = 0u;

    if (ops == NULL || ops->close_handle == NULL || ops->get_last_error == NULL || box == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (box->handle_00 != ROME2_VFS_INVALID_HANDLE32) {
        if (ops->close_handle(ops->ctx, box->handle_00) == 0) {
            close_err = ops->get_last_error(ops->ctx);
        }
    }
    box->handle_00 = ROME2_VFS_INVALID_HANDLE32;
    box->last_status_04 = ROME2_VFS_HANDLE_BOX_CLOSED_STATUS;
    if (out_close_error != NULL) {
        *out_close_error = close_err;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_open_file_mapping_init_1a30(
    rome2_vfs_open_file_mapping16_32 *entry)
{
    if (entry == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    entry->open_flags_04 = 0u;
    entry->file_handle_08 = ROME2_VFS_INVALID_HANDLE32;
    entry->mapping_handle_0c = ROME2_VFS_INVALID_HANDLE32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_open_file_mapping_close_2350(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_open_file_mapping16_32 *entry)
{
    if (ops == NULL || ops->close_handle == NULL || entry == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    close_owned_handle_slot(ops, &entry->mapping_handle_0c, &entry->open_flags_04, ROME2_VFS_OPEN_FLAG_MAPPING);
    close_owned_handle_slot(ops, &entry->file_handle_08, &entry->open_flags_04, ROME2_VFS_OPEN_FLAG_FILE);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_open_file_mapping_map_cb00(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_open_file_mapping16_32 *entry,
    uint64_t *out_file_size)
{
    uint32_t high_size = 0u;
    uint32_t low_size;
    uint32_t err = 0u;
    uint32_t map_handle;

    if (ops == NULL || ops->get_file_size == NULL || ops->create_file_mapping_w == NULL ||
        ops->get_last_error == NULL || entry == NULL || out_file_size == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    low_size = ops->get_file_size(ops->ctx, entry->file_handle_08, &high_size);
    if (low_size == ROME2_VFS_INVALID_HANDLE32) {
        err = map_err_default(ops, ops->get_last_error(ops->ctx));
    }
    entry->last_error_00 = err;

    map_handle = ops->create_file_mapping_w(ops->ctx, entry->file_handle_08, high_size, low_size);
    entry->mapping_handle_0c = map_handle;
    if (map_handle == 0u) {
        entry->last_error_00 = map_err_default(ops, ops->get_last_error(ops->ctx));
        *out_file_size = 0ULL;
        return ROME2_VFS_REG_OK;
    }

    entry->open_flags_04 |= ROME2_VFS_OPEN_FLAG_MAPPING;
    *out_file_size = ((uint64_t)high_size << 32u) | (uint64_t)low_size;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_open_file_mapping_open_4b60(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_open_file_mapping16_32 *entry,
    const char *path,
    uint64_t *out_file_size)
{
    uint32_t fh;
    uint32_t err;
    rome2_vfs_reg_status st;

    if (ops == NULL || ops->create_file_read_a == NULL || ops->close_handle == NULL ||
        ops->get_file_size == NULL || ops->create_file_mapping_w == NULL ||
        ops->get_last_error == NULL || entry == NULL || path == NULL || out_file_size == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    st = rome2_vfs_open_file_mapping_close_2350(ops, entry);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }

    fh = ops->create_file_read_a(ops->ctx, path);
    entry->file_handle_08 = fh;
    if (fh == ROME2_VFS_INVALID_HANDLE32) {
        err = map_err_default(ops, ops->get_last_error(ops->ctx));
        entry->last_error_00 = (err != 0u) ? err : ROME2_VFS_OPEN_DEFAULT_ERR_FALLBACK;
        *out_file_size = 0ULL;
        return ROME2_VFS_REG_OK;
    }

    entry->open_flags_04 |= ROME2_VFS_OPEN_FLAG_FILE;
    return rome2_vfs_open_file_mapping_map_cb00(ops, entry, out_file_size);
}

rome2_vfs_reg_status rome2_vfs_bad_alloc_init_1c50(
    rome2_vfs_bad_alloc_exc8_32 *exc)
{
    if (exc == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    exc->vtable_00 = ROME2_VFS_BAD_ALLOC_VTABLE32;
    exc->what_str_04 = ROME2_VFS_BAD_ALLOC_WHAT32;
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
    uint32_t words[17];
    int matches = 1;
    size_t i;

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

rome2_vfs_reg_status rome2_vfs_pack_vtable_7be0_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_pack_vtable_7be0_17slot32 *out_vt,
    int *out_matches)
{
    static const uint32_t expected[17] = {
        0x112acf80u, 0x112d3270u, 0x112d3270u, 0x100dbc00u,
        0x100dbc00u, 0x100d6770u, 0x100d6900u, 0x112d0c80u,
        0x100f3d00u, 0x112daae0u, 0x100dbc00u, 0x100dbc00u,
        0x100d6770u, 0x100d6560u, 0x100d6770u, 0x100d6770u,
        0x100dbc00u
    };

    return decode_and_match_u32_table(
        view, vtable_addr, expected, 17u, out_vt, sizeof(*out_vt), out_matches);
}

rome2_vfs_reg_status rome2_vfs_pack_ref_release_aae0(
    uint32_t *inout_ref_count,
    int *out_deleted)
{
    uint32_t next;

    if (inout_ref_count == NULL || out_deleted == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (*inout_ref_count == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    next = *inout_ref_count - 1u;
    *inout_ref_count = next;
    *out_deleted = (next == 0u) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_vtable_7c44_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_pack_vtable_7c44_8slot32 *out_vt,
    int *out_matches)
{
    static const uint32_t expected[8] = {
        0x112ad6d0u, 0x112c8c60u, 0x100d6900u, 0x112c0d90u,
        0x112dc250u, 0x112d32b0u, 0x101e48d0u, 0x100d6560u
    };

    return decode_and_match_u32_table(
        view, vtable_addr, expected, 8u, out_vt, sizeof(*out_vt), out_matches);
}

rome2_vfs_reg_status rome2_vfs_pack_substream_can_read_8c60(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 obj_addr,
    int *out_can_read)
{
    uint32_t ptr_14 = 0u;
    uint32_t cur_1c = 0u;
    uint32_t end_20 = 0u;
    rome2_vfs_reg_status st;

    if (view == NULL || out_can_read == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = read_u32_disp(view, obj_addr, 0x14u, &ptr_14);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (ptr_14 == 0u) {
        *out_can_read = 0;
        return ROME2_VFS_REG_OK;
    }
    st = read_u32_disp(view, obj_addr, 0x1cu, &cur_1c);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = read_u32_disp(view, obj_addr, 0x20u, &end_20);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    *out_can_read = (cur_1c < end_20) ? 1 : 0;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_substream_advance_0d90(
    uint32_t *inout_cursor_1c,
    uint32_t delta)
{
    if (inout_cursor_1c == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (delta == 0u) {
        *inout_cursor_1c = 0u;
        return ROME2_VFS_REG_OK;
    }
    if (delta > UINT32_MAX - *inout_cursor_1c) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *inout_cursor_1c += delta;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_substream_rewind_c250(
    uint32_t *inout_cursor_1c,
    uint32_t delta)
{
    if (inout_cursor_1c == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (delta == 0u) {
        *inout_cursor_1c = 0u;
        return ROME2_VFS_REG_OK;
    }
    if (delta > *inout_cursor_1c) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *inout_cursor_1c -= delta;
    return ROME2_VFS_REG_OK;
}
