#include "vfs_archive_mount_step.h"

static rome2_vfs_reg_status map_dep_status(rome2_vfs_dep_status status)
{
    switch (status) {
    case ROME2_VFS_DEP_OK:
        return ROME2_VFS_REG_OK;
    case ROME2_VFS_DEP_NOT_FOUND:
        return ROME2_VFS_REG_NOT_FOUND;
    case ROME2_VFS_DEP_BAD_ARGUMENT:
        return ROME2_VFS_REG_BAD_ARGUMENT;
    case ROME2_VFS_DEP_INVALID_GRAPH:
        return ROME2_VFS_REG_INVALID_STATE;
    case ROME2_VFS_DEP_RANGE_ERROR:
        return ROME2_VFS_REG_RANGE_ERROR;
    case ROME2_VFS_DEP_STEP_LIMIT:
        return ROME2_VFS_REG_STEP_LIMIT;
    default:
        return ROME2_VFS_REG_INVALID_STATE;
    }
}

static bool view_span(const rome2_guest_read_view *view, uint32_t address,
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

static bool read_u32(const rome2_guest_read_view *view, rome2_guest_addr32 base,
    uint32_t offset, uint32_t *output)
{
    rome2_guest_addr32 cell, word;
    if (rome2_guest_add_checked(base, offset, &cell) != ROME2_GUEST_OK ||
        rome2_guest_read_addr32_le(view, cell, &word) != ROME2_GUEST_OK) {
        return false;
    }
    *output = word.value;
    return true;
}

static bool read_u8(const rome2_guest_read_view *view, rome2_guest_addr32 base,
    uint32_t offset, uint8_t *output)
{
    rome2_guest_addr32 cell;
    const uint8_t *ptr = NULL;
    if (rome2_guest_add_checked(base, offset, &cell) != ROME2_GUEST_OK ||
        !view_span(view, cell.value, 1u, &ptr)) {
        return false;
    }
    *output = *ptr;
    return true;
}

static rome2_vfs_reg_status find_last_backslash(
    const char *path, size_t path_len, uint32_t max_bytes,
    bool *out_found, size_t *out_index)
{
    size_t idx;
    if (path == NULL || out_found == NULL || out_index == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (path_len > (size_t)max_bytes) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    for (idx = path_len; idx > 0u; --idx) {
        if (path[idx - 1u] == '\\') {
            *out_found = true;
            *out_index = idx - 1u;
            return ROME2_VFS_REG_OK;
        }
    }
    *out_found = false;
    *out_index = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_archive_leaf_name(
    const char *path, size_t path_len, uint32_t max_bytes,
    size_t *out_offset, size_t *out_length)
{
    bool found = false;
    size_t pos = 0u;
    rome2_vfs_reg_status status;
    if (out_offset == NULL || out_length == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    status = find_last_backslash(path, path_len, max_bytes, &found, &pos);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }
    if (found) {
        *out_offset = pos + 1u;
        *out_length = path_len - (pos + 1u);
    } else {
        *out_offset = 0u;
        *out_length = path_len;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_entry_dir_prefix(
    const char *entry_path, size_t path_len, uint32_t max_bytes,
    size_t *out_prefix_length, bool *out_has_dir)
{
    bool found = false;
    size_t pos = 0u;
    rome2_vfs_reg_status status;
    if (out_prefix_length == NULL || out_has_dir == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    status = find_last_backslash(entry_path, path_len, max_bytes, &found, &pos);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }
    if (found) {
        *out_has_dir = true;
        *out_prefix_length = pos;
    } else {
        *out_has_dir = false;
        *out_prefix_length = 0u;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_carrier_pack_props_gate32(
    const rome2_guest_read_view *candidates, rome2_guest_addr32 carrier_addr,
    const rome2_guest_read_view *pack_props,
    rome2_vfs_pack_props_gate32 *output)
{
    uint32_t props_raw = 0u;
    rome2_guest_addr32 props_addr;
    uint8_t byte_01c = 0u;
    uint8_t nibble;
    if (candidates == NULL || pack_props == NULL || output == NULL ||
        carrier_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!read_u32(candidates, carrier_addr, 0x00u, &props_raw)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (props_raw == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    props_addr.value = props_raw;
    if (!read_u8(pack_props, props_addr, 0x1cu, &byte_01c)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    nibble = (uint8_t)(byte_01c & 0x0fu);
    output->pack_props_addr = props_raw;
    output->low_nibble_01c = nibble;
    output->is_type3 = (nibble == 3u);
    output->is_type4 = (nibble == 4u);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_carrier_next_nonempty_slot32(
    const rome2_guest_read_view *candidates, rome2_guest_addr32 carrier_addr,
    const rome2_guest_read_view *slots,
    uint32_t start_index, uint32_t max_slots,
    rome2_vfs_carrier_slot_match32 *output)
{
    uint32_t items_raw = 0u, bucket_count = 0u, empty_name = 0u, idx;
    rome2_guest_addr32 items_addr;
    if (candidates == NULL || slots == NULL || output == NULL ||
        carrier_addr.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!read_u32(candidates, carrier_addr, 0x04u, &items_raw) ||
        !read_u32(candidates, carrier_addr, 0x08u, &bucket_count) ||
        !read_u32(candidates, carrier_addr, 0x0cu, &empty_name)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (bucket_count > max_slots) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    if (bucket_count == 0u || start_index >= bucket_count) {
        return ROME2_VFS_REG_NOT_FOUND;
    }
    if (items_raw == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    items_addr.value = items_raw;
    for (idx = start_index; idx < bucket_count; ++idx) {
        rome2_guest_addr32 slot_addr;
        uint32_t slot_name = 0u, slot_val = 0u;
        if (idx > UINT32_MAX / 8u ||
            rome2_guest_add_checked(items_addr, idx * 8u, &slot_addr) != ROME2_GUEST_OK ||
            !read_u32(slots, slot_addr, 0x00u, &slot_name) ||
            !read_u32(slots, slot_addr, 0x04u, &slot_val)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (slot_name != empty_name) {
            output->slot_address = slot_addr;
            output->slot_index = idx;
            output->name_id = slot_name;
            output->entry_ptr = slot_val;
            return ROME2_VFS_REG_OK;
        }
    }
    return ROME2_VFS_REG_NOT_FOUND;
}

static rome2_vfs_reg_status scan_pending_deps_pass(
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *open_tables,
    rome2_guest_addr32 items_addr,
    uint32_t bucket_count,
    rome2_guest_addr32 empty_key_addr,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 pack_string8,
    const rome2_vfs_dep_limits *limits,
    rome2_vfs_open_pack_match32 *out_deps,
    size_t max_deps,
    bool emit,
    size_t *out_count)
{
    uint32_t idx;
    size_t found_count = 0u;
    for (idx = 0u; idx < bucket_count; ++idx) {
        rome2_guest_addr32 slot_addr, payload_addr;
        bool is_empty = false, is_dep = false;
        rome2_vfs_dep_status dstatus;
        if (idx > UINT32_MAX / 0x14u ||
            rome2_guest_add_checked(items_addr, idx * 0x14u, &slot_addr) != ROME2_GUEST_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        dstatus = rome2_vfs_string8_equals32(descriptors, slot_addr,
            open_tables, empty_key_addr, payloads, limits->max_name_bytes, &is_empty);
        if (dstatus != ROME2_VFS_DEP_OK) {
            return map_dep_status(dstatus);
        }
        if (is_empty) {
            continue;
        }
        dstatus = rome2_vfs_dep_reachable32(maps, hashmap_addr, nodes, buckets,
            edge_nodes, descriptors, payloads, pack_string8, slot_addr, limits,
            &is_dep);
        if (dstatus != ROME2_VFS_DEP_OK) {
            return map_dep_status(dstatus);
        }
        if (!is_dep) {
            continue;
        }
        if (found_count >= max_deps ||
            rome2_guest_add_checked(slot_addr, 0x0cu, &payload_addr) != ROME2_GUEST_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (emit) {
            out_deps[found_count].slot_address = slot_addr;
            out_deps[found_count].payload_address = payload_addr;
            out_deps[found_count].slot_index = idx;
            out_deps[found_count].probes = idx + 1u;
        }
        found_count += 1u;
    }
    *out_count = found_count;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_collect_pending_deps32(
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *open_tables,
    rome2_guest_addr32 open_table_addr,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 pack_string8,
    const rome2_vfs_dep_limits *limits,
    uint32_t max_open_buckets,
    rome2_vfs_open_pack_match32 *out_deps,
    size_t max_deps,
    size_t *out_count)
{
    uint32_t items_raw = 0u, bucket_count = 0u;
    rome2_guest_addr32 items_addr, empty_key_addr;
    size_t validated_count = 0u;
    rome2_vfs_reg_status status;
    if (maps == NULL || nodes == NULL || buckets == NULL || edge_nodes == NULL ||
        open_tables == NULL || descriptors == NULL || payloads == NULL ||
        limits == NULL || out_count == NULL ||
        (max_deps > 0u && out_deps == NULL) ||
        hashmap_addr.value == 0u || open_table_addr.value == 0u ||
        pack_string8.value == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!read_u32(open_tables, open_table_addr, 0x00u, &items_raw) ||
        !read_u32(open_tables, open_table_addr, 0x04u, &bucket_count) ||
        rome2_guest_add_checked(open_table_addr, 0x08u, &empty_key_addr) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (bucket_count > max_open_buckets) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    if (bucket_count == 0u) {
        *out_count = 0u;
        return ROME2_VFS_REG_OK;
    }
    if (items_raw == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    items_addr.value = items_raw;
    status = scan_pending_deps_pass(maps, hashmap_addr, nodes, buckets, edge_nodes,
        open_tables, items_addr, bucket_count, empty_key_addr, descriptors,
        payloads, pack_string8, limits, out_deps, max_deps, false,
        &validated_count);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }
    return scan_pending_deps_pass(maps, hashmap_addr, nodes, buckets, edge_nodes,
        open_tables, items_addr, bucket_count, empty_key_addr, descriptors,
        payloads, pack_string8, limits, out_deps, max_deps, true, out_count);
}

bool rome2_vfs_dep_status_acceptable(uint32_t recursive_reg_code)
{
    return recursive_reg_code == 0u || recursive_reg_code == 1u;
}
