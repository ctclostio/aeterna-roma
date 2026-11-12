#include "vfs_archive_tree.h"

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

static bool read_word(const rome2_guest_read_view *view, rome2_guest_addr32 base,
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

static bool read_byte(const rome2_guest_read_view *view, rome2_guest_addr32 base,
    uint32_t offset, uint8_t *output)
{
    rome2_guest_addr32 cell;
    const uint8_t *ptr;
    if (rome2_guest_add_checked(base, offset, &cell) != ROME2_GUEST_OK ||
        !view_span(view, cell.value, 1u, &ptr)) {
        return false;
    }
    *output = *ptr;
    return true;
}

rome2_vfs_tree_status rome2_vfs_compare_name_less32(
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    uint32_t lhs_name, uint32_t rhs_name,
    uint32_t max_bytes, bool *is_less)
{
    rome2_guest_addr32 lhs_addr, rhs_addr;
    uint32_t len_lhs, len_rhs, data_lhs, data_rhs, common_len, i;
    const uint8_t *lhs_bytes = NULL;
    const uint8_t *rhs_bytes = NULL;
    if (descriptors == NULL || payloads == NULL || is_less == NULL) {
        return ROME2_VFS_TREE_BAD_ARGUMENT;
    }
    if (lhs_name == 0u) {
        *is_less = true;
        return ROME2_VFS_TREE_OK;
    }
    if (rhs_name == 0u) {
        *is_less = false;
        return ROME2_VFS_TREE_OK;
    }
    lhs_addr.value = lhs_name;
    rhs_addr.value = rhs_name;
    if (!read_word(descriptors, lhs_addr, 0u, &len_lhs) ||
        !read_word(descriptors, lhs_addr, 8u, &data_lhs) ||
        !read_word(descriptors, rhs_addr, 0u, &len_rhs) ||
        !read_word(descriptors, rhs_addr, 8u, &data_rhs)) {
        return ROME2_VFS_TREE_RANGE_ERROR;
    }
    common_len = len_lhs < len_rhs ? len_lhs : len_rhs;
    if (common_len > max_bytes) {
        return ROME2_VFS_TREE_STEP_LIMIT;
    }
    if (common_len != 0u) {
        if (!view_span(payloads, data_lhs, common_len, &lhs_bytes) ||
            !view_span(payloads, data_rhs, common_len, &rhs_bytes)) {
            return ROME2_VFS_TREE_RANGE_ERROR;
        }
        for (i = 0u; i < common_len; ++i) {
            if (lhs_bytes[i] != rhs_bytes[i]) {
                const int32_t lhs_s = (int32_t)(int8_t)lhs_bytes[i];
                const int32_t rhs_s = (int32_t)(int8_t)rhs_bytes[i];
                *is_less = (lhs_s - rhs_s) < 0;
                return ROME2_VFS_TREE_OK;
            }
        }
    }
    *is_less = len_lhs < len_rhs;
    return ROME2_VFS_TREE_OK;
}

rome2_vfs_tree_status rome2_vfs_search_archive_tree32(
    const rome2_guest_read_view *headers, rome2_guest_addr32 header,
    const rome2_guest_read_view *tree_nodes,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    const rome2_guest_read_view *candidate_sets,
    const rome2_guest_read_view *candidate_nodes,
    uint32_t query_name, uint32_t max_steps, uint32_t max_name_bytes,
    bool resolve_archive_table, rome2_vfs_archive_tree_match32 *output)
{
    rome2_guest_addr32 head, candidate, node, archive_table;
    rome2_vfs_archive_tree_match32 result;
    uint32_t steps = 0u, candidate_key = 0u, candidate_set = 0u;
    uint32_t winner_node = 0u, archive = 0u;
    uint8_t is_nil = 0u;
    bool less = false;
    rome2_vfs_tree_status status;

    if (headers == NULL || tree_nodes == NULL || descriptors == NULL ||
        payloads == NULL || output == NULL || header.value == 0u ||
        max_steps == 0u ||
        (resolve_archive_table && (candidate_sets == NULL || candidate_nodes == NULL))) {
        return ROME2_VFS_TREE_BAD_ARGUMENT;
    }
    if (!read_word(headers, header, 0u, &head.value)) {
        return ROME2_VFS_TREE_RANGE_ERROR;
    }
    if (head.value == 0u) {
        return ROME2_VFS_TREE_INVALID_TREE;
    }
    if (!read_byte(tree_nodes, head, 0x0du, &is_nil) ||
        !read_word(tree_nodes, head, 4u, &node.value)) {
        return ROME2_VFS_TREE_RANGE_ERROR;
    }
    if (is_nil == 0u) {
        return ROME2_VFS_TREE_INVALID_TREE;
    }
    candidate = head;
    for (;;) {
        uint32_t node_key, next_addr;
        if (node.value == 0u) {
            return ROME2_VFS_TREE_INVALID_TREE;
        }
        if (!read_byte(tree_nodes, node, 0x0du, &is_nil)) {
            return ROME2_VFS_TREE_RANGE_ERROR;
        }
        if (is_nil != 0u) {
            break;
        }
        if (node.value == head.value) {
            return ROME2_VFS_TREE_INVALID_TREE;
        }
        if (steps == max_steps) {
            return ROME2_VFS_TREE_STEP_LIMIT;
        }
        ++steps;
        if (!read_word(tree_nodes, node, 0x10u, &node_key)) {
            return ROME2_VFS_TREE_RANGE_ERROR;
        }
        status = rome2_vfs_compare_name_less32(
            descriptors, payloads, node_key, query_name, max_name_bytes, &less);
        if (status != ROME2_VFS_TREE_OK) {
            return status;
        }
        if (less) {
            if (!read_word(tree_nodes, node, 8u, &next_addr)) {
                return ROME2_VFS_TREE_RANGE_ERROR;
            }
        } else {
            candidate = node;
            if (!read_word(tree_nodes, node, 0u, &next_addr)) {
                return ROME2_VFS_TREE_RANGE_ERROR;
            }
        }
        node.value = next_addr;
    }
    if (candidate.value == head.value) {
        return ROME2_VFS_TREE_NOT_FOUND;
    }
    if (!read_word(tree_nodes, candidate, 0x10u, &candidate_key)) {
        return ROME2_VFS_TREE_RANGE_ERROR;
    }
    status = rome2_vfs_compare_name_less32(
        descriptors, payloads, query_name, candidate_key, max_name_bytes, &less);
    if (status != ROME2_VFS_TREE_OK) {
        return status;
    }
    if (less) {
        return ROME2_VFS_TREE_NOT_FOUND;
    }
    if (!read_word(tree_nodes, candidate, 0x14u, &candidate_set)) {
        return ROME2_VFS_TREE_RANGE_ERROR;
    }
    archive_table.value = 0u;
    if (resolve_archive_table) {
        rome2_guest_addr32 set_addr, set_head, winner_addr, archive_addr;
        uint8_t set_head_nil = 0u, winner_nil = 0u;
        if (candidate_set == 0u) {
            return ROME2_VFS_TREE_INVALID_TREE;
        }
        set_addr.value = candidate_set;
        if (!read_word(candidate_sets, set_addr, 4u, &set_head.value)) {
            return ROME2_VFS_TREE_RANGE_ERROR;
        }
        if (set_head.value == 0u) {
            return ROME2_VFS_TREE_INVALID_TREE;
        }
        if (!read_byte(candidate_nodes, set_head, 0x0du, &set_head_nil) ||
            !read_word(candidate_nodes, set_head, 0u, &winner_node)) {
            return ROME2_VFS_TREE_RANGE_ERROR;
        }
        if (set_head_nil == 0u || winner_node == 0u ||
            winner_node == set_head.value) {
            return ROME2_VFS_TREE_INVALID_TREE;
        }
        winner_addr.value = winner_node;
        if (!read_byte(candidate_nodes, winner_addr, 0x0du, &winner_nil) ||
            !read_word(candidate_nodes, winner_addr, 0x10u, &archive)) {
            return ROME2_VFS_TREE_RANGE_ERROR;
        }
        if (winner_nil != 0u || archive == 0u) {
            return ROME2_VFS_TREE_INVALID_TREE;
        }
        archive_addr.value = archive;
        if (rome2_guest_add_checked(archive_addr, 4u, &archive_table) != ROME2_GUEST_OK) {
            return ROME2_VFS_TREE_RANGE_ERROR;
        }
    }
    result.node_address = candidate;
    result.key_name = candidate_key;
    result.candidate_set = candidate_set;
    result.winner_node = winner_node;
    result.archive = archive;
    result.archive_table = archive_table;
    result.steps = steps;
    *output = result;
    return ROME2_VFS_TREE_OK;
}
