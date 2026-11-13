#include "vfs_archive_register.h"

static rome2_vfs_reg_status map_name_status(rome2_vfs_name_status status)
{
    switch (status) {
    case ROME2_VFS_NAME_OK:
        return ROME2_VFS_REG_OK;
    case ROME2_VFS_NAME_NOT_FOUND:
        return ROME2_VFS_REG_NOT_FOUND;
    case ROME2_VFS_NAME_BAD_ARGUMENT:
        return ROME2_VFS_REG_BAD_ARGUMENT;
    case ROME2_VFS_NAME_INVALID_TABLE:
    case ROME2_VFS_NAME_TABLE_FULL:
        return ROME2_VFS_REG_INVALID_STATE;
    case ROME2_VFS_NAME_RANGE_ERROR:
        return ROME2_VFS_REG_RANGE_ERROR;
    case ROME2_VFS_NAME_PROBE_LIMIT:
        return ROME2_VFS_REG_STEP_LIMIT;
    default:
        return ROME2_VFS_REG_INVALID_STATE;
    }
}

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

static rome2_vfs_reg_status hash_string8_cstr32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 query_str,
    const rome2_guest_read_view *payloads, uint32_t max_name_bytes,
    uint32_t *out_hash)
{
    uint32_t cstr_ptr = 0u;
    uint32_t len = 0u;
    uint32_t i;
    const uint8_t *first_byte = NULL;
    bool found_nul = false;

    if (!read_u32(descriptors, query_str, 8u, &cstr_ptr) || cstr_ptr == 0u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    for (i = 0u; i <= max_name_bytes; ++i) {
        rome2_guest_addr32 cur;
        const uint8_t *ch = NULL;
        if (rome2_guest_add_checked((rome2_guest_addr32){cstr_ptr}, i, &cur) != ROME2_GUEST_OK ||
            !view_span(payloads, cur.value, 1u, &ch)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (i == 0u) {
            first_byte = ch;
        }
        if (*ch == 0u) {
            len = i;
            found_nul = true;
            break;
        }
        if (i == max_name_bytes) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
    }

    if (!found_nul || first_byte == NULL) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    if (!rome2_vfs_hash_name_bytes(first_byte, (size_t)len, out_hash)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_open_pack_find32(
    const rome2_guest_read_view *tables, rome2_guest_addr32 table_addr,
    const rome2_guest_read_view *slots,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 query_str, uint32_t max_probes,
    uint32_t max_name_bytes, rome2_vfs_open_pack_match32 *output)
{
    uint32_t items = 0u;
    uint32_t bucket_count = 0u;
    uint32_t hash = 0u;
    uint32_t start_bucket, probe;
    rome2_guest_addr32 empty_key_addr;
    rome2_vfs_reg_status status;

    const uint8_t *table_bytes = NULL;

    if (tables == NULL || slots == NULL || descriptors == NULL ||
        payloads == NULL || output == NULL ||
        table_addr.value == 0u || query_str.value == 0u || max_probes == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!view_span(tables, table_addr.value, 0x14u, &table_bytes) ||
        !read_u32(tables, table_addr, 0u, &items) ||
        !read_u32(tables, table_addr, 4u, &bucket_count) ||
        rome2_guest_add_checked(table_addr, 8u, &empty_key_addr) != ROME2_GUEST_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    (void)table_bytes;
    if (items == 0u || bucket_count == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if ((uint64_t)bucket_count * 0x14u > UINT64_C(0x100000000) - items) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    status = hash_string8_cstr32(descriptors, query_str, payloads, max_name_bytes, &hash);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }

    start_bucket = hash % bucket_count;
    for (probe = 0u; probe < bucket_count && probe < max_probes; ++probe) {
        uint32_t idx = (uint32_t)(((uint64_t)start_bucket + probe) % bucket_count);
        uint64_t slot_byte_offset = (uint64_t)idx * 0x14u;
        rome2_guest_addr32 slot_addr, payload_addr;
        bool eq = false;
        rome2_vfs_dep_status dep_status;

        if (slot_byte_offset > UINT32_MAX ||
            rome2_guest_add_checked((rome2_guest_addr32){items},
                (uint32_t)slot_byte_offset, &slot_addr) != ROME2_GUEST_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }

        dep_status = rome2_vfs_string8_equals32(
            slots, slot_addr, descriptors, query_str, payloads, max_name_bytes, &eq);
        if (dep_status != ROME2_VFS_DEP_OK) {
            return map_dep_status(dep_status);
        }
        if (eq) {
            if (rome2_guest_add_checked(slot_addr, 0x0cu, &payload_addr) != ROME2_GUEST_OK) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            output->slot_address = slot_addr;
            output->payload_address = payload_addr;
            output->slot_index = idx;
            output->probes = probe + 1u;
            return ROME2_VFS_REG_OK;
        }

        dep_status = rome2_vfs_string8_equals32(
            slots, slot_addr, tables, empty_key_addr, payloads, max_name_bytes, &eq);
        if (dep_status != ROME2_VFS_DEP_OK) {
            return map_dep_status(dep_status);
        }
        if (eq) {
            return ROME2_VFS_REG_NOT_FOUND;
        }
    }

    if (probe < bucket_count) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    return ROME2_VFS_REG_NOT_FOUND;
}

rome2_vfs_reg_status rome2_vfs_blacklist_contains32(
    const rome2_guest_read_view *edge_nodes, rome2_guest_addr32 blacklist_head,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 query_str, uint32_t max_tree_steps,
    uint32_t max_name_bytes, bool *is_blacklisted)
{
    uint8_t head_nil = 0u;
    uint32_t cur = 0u;
    uint32_t step;

    if (edge_nodes == NULL || descriptors == NULL || payloads == NULL ||
        is_blacklisted == NULL || blacklist_head.value == 0u ||
        query_str.value == 0u || max_tree_steps == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!read_u8(edge_nodes, blacklist_head, 0x0du, &head_nil) ||
        !read_u32(edge_nodes, blacklist_head, 0u, &cur)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (head_nil == 0u || cur == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    for (step = 0u; cur != blacklist_head.value; ++step) {
        uint8_t cur_nil = 0u;
        rome2_guest_addr32 entry_name_addr, next_node;
        bool eq = false;
        rome2_vfs_dep_status dep_status;

        if (step >= max_tree_steps) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        if (!read_u8(edge_nodes, (rome2_guest_addr32){cur}, 0x0du, &cur_nil)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (cur_nil != 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        if (rome2_guest_add_checked((rome2_guest_addr32){cur}, 0x10u,
                &entry_name_addr) != ROME2_GUEST_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }

        dep_status = rome2_vfs_string8_equals32(
            edge_nodes, entry_name_addr, descriptors, query_str,
            payloads, max_name_bytes, &eq);
        if (dep_status != ROME2_VFS_DEP_OK) {
            return map_dep_status(dep_status);
        }
        if (eq) {
            *is_blacklisted = true;
            return ROME2_VFS_REG_OK;
        }

        dep_status = rome2_vfs_dep_edge_next32(
            edge_nodes, (rome2_guest_addr32){cur}, max_tree_steps, &next_node, NULL);
        if (dep_status != ROME2_VFS_DEP_OK) {
            return map_dep_status(dep_status);
        }
        if (next_node.value == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        cur = next_node.value;
    }

    *is_blacklisted = false;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_check_registration_preconditions32(
    const rome2_guest_read_view *reg_tables, rome2_guest_addr32 reg_table_addr,
    const rome2_guest_read_view *reg_slots,
    const rome2_guest_read_view *blacklist_nodes,
    rome2_guest_addr32 blacklist_head,
    const rome2_guest_read_view *open_tables, rome2_guest_addr32 open_table_addr,
    const rome2_guest_read_view *open_slots,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    uint32_t archive_name_id, uint32_t archive_name_hash,
    rome2_guest_addr32 archive_string8,
    uint32_t max_probes, uint32_t max_tree_steps, uint32_t max_name_bytes,
    rome2_vfs_reg_precondition_result32 *output)
{
    rome2_vfs_reg_precondition_result32 res = {0};
    rome2_vfs_name_match32 reg_match = {0};
    rome2_vfs_name_status name_status;
    rome2_vfs_open_pack_match32 open_match = {0};
    rome2_vfs_reg_status reg_status;
    bool blacklisted = false;

    if (reg_tables == NULL || reg_slots == NULL || blacklist_nodes == NULL ||
        open_tables == NULL || open_slots == NULL || descriptors == NULL ||
        payloads == NULL || output == NULL || reg_table_addr.value == 0u ||
        blacklist_head.value == 0u || open_table_addr.value == 0u ||
        archive_string8.value == 0u || max_probes == 0u || max_tree_steps == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    name_status = rome2_vfs_probe_name32(
        reg_tables, reg_table_addr, reg_slots, archive_name_id, archive_name_hash,
        max_probes, &reg_match);
    if (name_status == ROME2_VFS_NAME_OK) {
        res.code = ROME2_VFS_REG_ALREADY_REGISTERED;
        res.registered_archive = reg_match.value;
        *output = res;
        return ROME2_VFS_REG_OK;
    }
    if (name_status != ROME2_VFS_NAME_NOT_FOUND) {
        return map_name_status(name_status);
    }

    reg_status = rome2_vfs_blacklist_contains32(
        blacklist_nodes, blacklist_head, descriptors, payloads,
        archive_string8, max_tree_steps, max_name_bytes, &blacklisted);
    if (reg_status != ROME2_VFS_REG_OK) {
        return reg_status;
    }
    if (blacklisted) {
        res.code = ROME2_VFS_REG_BLACKLISTED;
        *output = res;
        return ROME2_VFS_REG_OK;
    }

    reg_status = rome2_vfs_open_pack_find32(
        open_tables, open_table_addr, open_slots, descriptors, payloads,
        archive_string8, max_probes, max_name_bytes, &open_match);
    if (reg_status == ROME2_VFS_REG_NOT_FOUND) {
        res.code = ROME2_VFS_REG_PACK_NOT_OPEN;
        *output = res;
        return ROME2_VFS_REG_OK;
    }
    if (reg_status != ROME2_VFS_REG_OK) {
        return reg_status;
    }

    res.code = ROME2_VFS_REG_ELIGIBLE;
    res.open_pack_payload = open_match.payload_address;
    *output = res;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status candidate_tree_predecessor32(
    const rome2_guest_read_view *candidate_nodes,
    uint32_t set_head, uint32_t node, uint32_t max_tree_steps,
    uint32_t *out_pred)
{
    uint32_t left = 0u;
    uint8_t left_nil = 0u;
    uint32_t step = 0u;
    uint32_t cur = node;

    if (!read_u32(candidate_nodes, (rome2_guest_addr32){node}, 0u, &left)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (left == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (!read_u8(candidate_nodes, (rome2_guest_addr32){left}, 0x0du, &left_nil)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    if (left_nil == 0u) {
        cur = left;
        while (step < max_tree_steps) {
            uint32_t right = 0u;
            uint8_t right_nil = 0u;
            ++step;
            if (!read_u32(candidate_nodes, (rome2_guest_addr32){cur}, 8u, &right)) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            if (right == 0u) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
            if (!read_u8(candidate_nodes, (rome2_guest_addr32){right}, 0x0du, &right_nil)) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            if (right_nil != 0u) {
                *out_pred = cur;
                return ROME2_VFS_REG_OK;
            }
            cur = right;
        }
        return ROME2_VFS_REG_STEP_LIMIT;
    }

    while (step < max_tree_steps) {
        uint32_t parent = 0u;
        uint32_t parent_left = 0u;
        uint8_t parent_nil = 0u;
        ++step;
        if (!read_u32(candidate_nodes, (rome2_guest_addr32){cur}, 4u, &parent)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (parent == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        if (!read_u8(candidate_nodes, (rome2_guest_addr32){parent}, 0x0du, &parent_nil)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (parent_nil != 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        if (!read_u32(candidate_nodes, (rome2_guest_addr32){parent}, 0u, &parent_left)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (parent_left == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        if (cur != parent_left) {
            if (parent == set_head) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
            *out_pred = parent;
            return ROME2_VFS_REG_OK;
        }
        cur = parent;
    }

    return ROME2_VFS_REG_STEP_LIMIT;
}

rome2_vfs_reg_status rome2_vfs_probe_candidate_insert32(
    const rome2_guest_read_view *candidate_sets,
    rome2_guest_addr32 candidate_set_addr,
    const rome2_guest_read_view *candidate_nodes,
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *candidates,
    const rome2_guest_read_view *pack_props,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 new_candidate, bool only_update_existing,
    const rome2_vfs_dep_limits *limits,
    rome2_vfs_candidate_probe_result32 *output)
{
    uint32_t set_head = 0u;
    uint8_t head_nil = 0u;
    uint32_t leftmost = 0u;
    uint32_t root = 0u;
    uint32_t cur, parent, steps;
    bool go_left = true;
    rome2_vfs_candidate_probe_result32 res = {0};

    if (candidate_sets == NULL || candidate_nodes == NULL || maps == NULL ||
        nodes == NULL || buckets == NULL || edge_nodes == NULL ||
        candidates == NULL || pack_props == NULL || payloads == NULL ||
        limits == NULL || output == NULL || candidate_set_addr.value == 0u ||
        hashmap_addr.value == 0u || new_candidate.value == 0u ||
        limits->max_tree_steps == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    if (!read_u32(candidate_sets, candidate_set_addr, 4u, &set_head)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (set_head == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (!read_u8(candidate_nodes, (rome2_guest_addr32){set_head}, 0x0du, &head_nil) ||
        !read_u32(candidate_nodes, (rome2_guest_addr32){set_head}, 0u, &leftmost) ||
        !read_u32(candidate_nodes, (rome2_guest_addr32){set_head}, 4u, &root)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (head_nil == 0u || leftmost == 0u || root == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    parent = set_head;
    cur = root;
    steps = 0u;
    for (;;) {
        uint8_t cur_nil = 0u;
        uint32_t cur_archive = 0u;
        uint32_t next = 0u;
        bool less = false;
        rome2_vfs_dep_status dep_status;

        if (!read_u8(candidate_nodes, (rome2_guest_addr32){cur}, 0x0du, &cur_nil)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (cur_nil != 0u) {
            break;
        }
        if (cur == set_head) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        if (steps >= limits->max_tree_steps) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        ++steps;

        if (!read_u32(candidate_nodes, (rome2_guest_addr32){cur}, 0x10u, &cur_archive)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (cur_archive == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }

        dep_status = rome2_vfs_compare_archive_candidates32(
            maps, hashmap_addr, nodes, buckets, edge_nodes, candidates,
            pack_props, payloads, new_candidate, (rome2_guest_addr32){cur_archive},
            limits, &less);
        if (dep_status != ROME2_VFS_DEP_OK) {
            return map_dep_status(dep_status);
        }

        parent = cur;
        go_left = less;
        if (!read_u32(candidate_nodes, (rome2_guest_addr32){cur}, less ? 0u : 8u, &next)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (next == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        cur = next;
    }

    if (go_left && parent == leftmost) {
        res.would_insert = true;
        res.becomes_winner = true;
        res.insert_left = true;
        res.parent_node.value = parent;
        if (parent != set_head) {
            uint32_t leftmost_archive = 0u;
            if (!read_u32(candidate_nodes, (rome2_guest_addr32){parent}, 0x10u,
                    &leftmost_archive)) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            if (leftmost_archive == 0u) {
                return ROME2_VFS_REG_INVALID_STATE;
            }
            res.displaced_winner_node.value = parent;
            res.displaced_winner_archive = leftmost_archive;
        }
    } else {
        uint32_t bound_node = parent;
        uint32_t bound_archive = 0u;
        bool bound_less = false;
        rome2_vfs_dep_status dep_status;

        if (go_left) {
            rome2_vfs_reg_status reg_status = candidate_tree_predecessor32(
                candidate_nodes, set_head, parent, limits->max_tree_steps, &bound_node);
            if (reg_status != ROME2_VFS_REG_OK) {
                return reg_status;
            }
        } else if (parent == set_head) {
            return ROME2_VFS_REG_INVALID_STATE;
        }

        if (!read_u32(candidate_nodes, (rome2_guest_addr32){bound_node}, 0x10u,
                &bound_archive)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (bound_archive == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        dep_status = rome2_vfs_compare_archive_candidates32(
            maps, hashmap_addr, nodes, buckets, edge_nodes, candidates,
            pack_props, payloads, (rome2_guest_addr32){bound_archive},
            new_candidate, limits, &bound_less);
        if (dep_status != ROME2_VFS_DEP_OK) {
            return map_dep_status(dep_status);
        }
        if (bound_less) {
            res.would_insert = true;
            res.becomes_winner = false;
            res.insert_left = go_left;
            res.parent_node.value = parent;
        } else {
            res.would_insert = false;
            res.becomes_winner = false;
            res.existing_node.value = bound_node;
            res.existing_archive = bound_archive;
        }
    }

    res.code = (res.would_insert && only_update_existing)
        ? ROME2_VFS_REG_NEW_CANDIDATE_REJECTED
        : ROME2_VFS_REG_ELIGIBLE;
    *output = res;
    return ROME2_VFS_REG_OK;
}
