#include "vfs_pack_entry.h"

static bool read_view_span(const rome2_guest_read_view *view, uint32_t address,
    uint64_t size, const uint8_t **output)
{
    uint64_t delta;
    uintptr_t host;
    if (view == NULL || view->host_base == NULL || address == 0u) {
        return false;
    }
    if (view->byte_count > UINT64_C(0x100000000) - view->guest_base ||
        view->byte_count > (uint64_t)SIZE_MAX ||
        address < view->guest_base) {
        return false;
    }
    delta = (uint64_t)address - view->guest_base;
    if (delta > view->byte_count || size > view->byte_count - delta) {
        return false;
    }
    host = (uintptr_t)view->host_base;
    if (view->byte_count != 0u &&
        view->byte_count - 1u > (uint64_t)(UINTPTR_MAX - host)) {
        return false;
    }
    *output = view->host_base + (size_t)delta;
    return true;
}

static bool write_view_span(const rome2_vfs_guest_write_view32 *view, uint32_t address,
    uint64_t size, uint8_t **output)
{
    uint64_t delta;
    uintptr_t host;
    if (view == NULL || view->host_base == NULL || address == 0u) {
        return false;
    }
    if (view->byte_count > UINT64_C(0x100000000) - view->guest_base ||
        view->byte_count > (uint64_t)SIZE_MAX ||
        address < view->guest_base) {
        return false;
    }
    delta = (uint64_t)address - view->guest_base;
    if (delta > view->byte_count || size > view->byte_count - delta) {
        return false;
    }
    host = (uintptr_t)view->host_base;
    if (view->byte_count != 0u &&
        view->byte_count - 1u > (uint64_t)(UINTPTR_MAX - host)) {
        return false;
    }
    *output = view->host_base + (size_t)delta;
    return true;
}

static uint32_t load_le_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

rome2_vfs_reg_status rome2_vfs_decode_pack_index_record(
    const uint8_t *index_buf, size_t index_bytes, size_t cursor,
    uint32_t pack_flags, uint32_t default_entry_meta, uint32_t max_path_bytes,
    uint64_t *io_data_offset, rome2_vfs_pack_index_record32 *out_record)
{
    bool has_meta;
    size_t header_bytes;
    size_t pos;
    size_t path_start;
    size_t path_len;
    uint32_t byte_size;
    uint32_t entry_meta;
    uint64_t start_offset;
    uint64_t next_offset;
    rome2_vfs_pack_index_record32 parsed;

    if (index_buf == NULL || io_data_offset == NULL || out_record == NULL ||
        max_path_bytes == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (cursor > index_bytes) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    has_meta = ((pack_flags & 0x40u) != 0u);
    header_bytes = has_meta ? 8u : 4u;
    if (index_bytes - cursor < header_bytes) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    byte_size = load_le_u32(index_buf + cursor);
    entry_meta = has_meta ? load_le_u32(index_buf + cursor + 4u) : default_entry_meta;
    pos = cursor + header_bytes;

    /* FUN_112a9800..0x112a9807 skips leading 0x00 padding bytes before path. */
    while (pos < index_bytes && index_buf[pos] == 0u) {
        ++pos;
    }
    if (pos >= index_bytes) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    path_start = pos;
    path_len = 0u;
    while (pos < index_bytes && index_buf[pos] != 0u) {
        if (path_len >= (size_t)max_path_bytes) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        ++path_len;
        ++pos;
    }
    if (pos >= index_bytes) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    start_offset = *io_data_offset;
    if ((uint64_t)byte_size > UINT64_MAX - start_offset) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    next_offset = start_offset + (uint64_t)byte_size;

    parsed.byte_size = byte_size;
    parsed.entry_meta = entry_meta;
    parsed.data_offset = start_offset;
    parsed.path_offset = path_start;
    parsed.path_length = path_len;
    parsed.next_cursor = pos + 1u;

    *io_data_offset = next_offset;
    *out_record = parsed;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_props_read_prefix32(
    const rome2_guest_read_view *view, rome2_guest_addr32 pack_props_addr,
    rome2_vfs_pack_props_prefix_info32 *output)
{
    const uint8_t *raw = NULL;
    rome2_vfs_pack_props_prefix_info32 parsed;

    if (view == NULL || output == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!read_view_span(view, pack_props_addr.value,
            (uint64_t)sizeof(rome2_vfs_pack_props_prefix32), &raw)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    parsed.file_handle = load_le_u32(raw + 0x00u);
    parsed.last_error = load_le_u32(raw + 0x04u);
    parsed.flags = load_le_u32(raw + 0x1cu);
    parsed.low_nibble_01c = (uint8_t)(parsed.flags & 0x0fu);
    parsed.has_per_entry_meta = ((parsed.flags & 0x40u) != 0u);
    parsed.open_ok = (parsed.last_error == 0u);
    parsed.header_base = load_le_u32(raw + 0x24u);
    parsed.entry_count = load_le_u32(raw + 0x28u);
    parsed.index_bytes = load_le_u32(raw + 0x2cu);
    parsed.default_entry_meta = load_le_u32(raw + 0x30u);
    parsed.pack_path_len = load_le_u32(raw + 0x34u);
    parsed.pack_path_cap = load_le_u32(raw + 0x38u);
    parsed.pack_path_ptr = (rome2_data_address32)load_le_u32(raw + 0x3cu);
    parsed.flag_040 = raw[0x40u];

    *output = parsed;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_entry_read32(
    const rome2_guest_read_view *view, rome2_guest_addr32 entry_addr,
    rome2_vfs_pack_entry_info32 *output)
{
    const uint8_t *raw = NULL;
    uint32_t vtable_raw;
    uint32_t lo;
    uint32_t hi;
    rome2_vfs_pack_entry_info32 parsed;

    if (view == NULL || output == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!read_view_span(view, entry_addr.value,
            (uint64_t)sizeof(rome2_vfs_pack_entry_layout32), &raw)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    vtable_raw = load_le_u32(raw + 0x00u);
    if (vtable_raw != ROME2_VFS_PACK_ENTRY_VTABLE32) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    lo = load_le_u32(raw + 0x10u);
    hi = load_le_u32(raw + 0x14u);

    parsed.vtable = (rome2_vtable_address32)vtable_raw;
    parsed.name_id = load_le_u32(raw + 0x04u);
    parsed.byte_size = load_le_u32(raw + 0x08u);
    parsed.data_offset = ((uint64_t)hi << 32) | (uint64_t)lo;
    parsed.entry_meta = load_le_u32(raw + 0x18u);
    parsed.carrier = (rome2_data_address32)load_le_u32(raw + 0x1cu);
    parsed.unobserved_020 = load_le_u32(raw + 0x20u);
    parsed.winner_notified = raw[0x24u];

    *output = parsed;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_entry_notify_winner32(
    const rome2_vfs_guest_write_view32 *view, rome2_guest_addr32 entry_addr)
{
    uint8_t *raw = NULL;
    if (view == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!write_view_span(view, entry_addr.value,
            (uint64_t)sizeof(rome2_vfs_pack_entry_layout32), &raw)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (load_le_u32(raw + 0x00u) != ROME2_VFS_PACK_ENTRY_VTABLE32) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    raw[0x24u] = 1u;
    return ROME2_VFS_REG_OK;
}
