#include "vfs_dependency_graph.h"

#include <string.h>

typedef struct rome2_vfs_dep_dfs_frame {
    rome2_guest_addr32 tree_head;
    rome2_guest_addr32 current_edge;
    uint32_t edge_steps;
} rome2_vfs_dep_dfs_frame;

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

static bool limits_valid(const rome2_vfs_dep_limits *limits)
{
    return limits != NULL &&
        limits->max_chain_steps != 0u &&
        limits->max_tree_steps != 0u &&
        limits->max_depth != 0u &&
        limits->max_depth <= ROME2_VFS_DEP_MAX_DEPTH_CAP &&
        limits->max_visits != 0u;
}

rome2_vfs_dep_status rome2_vfs_string8_equals32(
    const rome2_guest_read_view *lhs_descriptors, rome2_guest_addr32 lhs,
    const rome2_guest_read_view *rhs_descriptors, rome2_guest_addr32 rhs,
    const rome2_guest_read_view *payloads, uint32_t max_bytes, bool *is_equal)
{
    uint32_t len_lhs, len_rhs, data_lhs, data_rhs;
    const uint8_t *lhs_bytes = NULL;
    const uint8_t *rhs_bytes = NULL;
    if (lhs_descriptors == NULL || rhs_descriptors == NULL || payloads == NULL ||
        is_equal == NULL || lhs.value == 0u || rhs.value == 0u) {
        return ROME2_VFS_DEP_BAD_ARGUMENT;
    }
    if (!read_word(lhs_descriptors, lhs, 0u, &len_lhs) ||
        !read_word(rhs_descriptors, rhs, 0u, &len_rhs)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (len_lhs != len_rhs) {
        *is_equal = false;
        return ROME2_VFS_DEP_OK;
    }
    if (len_lhs == 0u) {
        *is_equal = true;
        return ROME2_VFS_DEP_OK;
    }
    if (len_lhs > max_bytes) {
        return ROME2_VFS_DEP_STEP_LIMIT;
    }
    if (!read_word(lhs_descriptors, lhs, 8u, &data_lhs) ||
        !read_word(rhs_descriptors, rhs, 8u, &data_rhs) ||
        !view_span(payloads, data_lhs, len_lhs, &lhs_bytes) ||
        !view_span(payloads, data_rhs, len_lhs, &rhs_bytes)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    *is_equal = memcmp(lhs_bytes, rhs_bytes, (size_t)len_lhs) == 0;
    return ROME2_VFS_DEP_OK;
}

static rome2_vfs_dep_status hash_query_cstr32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 query_str,
    const rome2_guest_read_view *payloads, uint32_t max_name_bytes,
    uint32_t *out_hash)
{
    uint32_t cstr_ptr, i;
    const uint8_t *first_byte = NULL;
    uint32_t len = 0u;
    bool found_nul = false;
    if (!read_word(descriptors, query_str, 8u, &cstr_ptr)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (cstr_ptr == 0u) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    for (i = 0u; i <= max_name_bytes; ++i) {
        rome2_guest_addr32 cur;
        const uint8_t *ch = NULL;
        cur.value = cstr_ptr;
        if (rome2_guest_add_checked(cur, i, &cur) != ROME2_GUEST_OK ||
            !view_span(payloads, cur.value, 1u, &ch)) {
            return ROME2_VFS_DEP_RANGE_ERROR;
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
            return ROME2_VFS_DEP_STEP_LIMIT;
        }
    }
    if (!found_nul || first_byte == NULL) {
        return ROME2_VFS_DEP_STEP_LIMIT;
    }
    if (!rome2_vfs_hash_name_bytes(first_byte, (size_t)len, out_hash)) {
        return ROME2_VFS_DEP_BAD_ARGUMENT;
    }
    return ROME2_VFS_DEP_OK;
}

rome2_vfs_dep_status rome2_vfs_dep_hashmap_find32(
    const rome2_guest_read_view *maps, rome2_guest_addr32 map_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 query_str, uint32_t max_chain_steps,
    uint32_t max_name_bytes, rome2_vfs_dep_hashmap_match32 *output)
{
    uint32_t hash = 0u;
    uint32_t list_head, buckets_addr, mask, bucket_index;
    uint64_t bucket_byte_offset;
    rome2_guest_addr32 pair_addr;
    uint32_t first, last, cur, step;
    rome2_vfs_dep_status status;

    if (maps == NULL || nodes == NULL || buckets == NULL ||
        descriptors == NULL || payloads == NULL || output == NULL ||
        map_addr.value == 0u || query_str.value == 0u || max_chain_steps == 0u) {
        return ROME2_VFS_DEP_BAD_ARGUMENT;
    }

    status = hash_query_cstr32(descriptors, query_str, payloads, max_name_bytes, &hash);
    if (status != ROME2_VFS_DEP_OK) {
        return status;
    }
    if (!read_word(maps, map_addr, 0x04u, &list_head) ||
        !read_word(maps, map_addr, 0x0cu, &buckets_addr) ||
        !read_word(maps, map_addr, 0x18u, &mask)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (list_head == 0u || buckets_addr == 0u) {
        return ROME2_VFS_DEP_INVALID_GRAPH;
    }

    bucket_index = hash & mask;
    bucket_byte_offset = (uint64_t)bucket_index * 8u;
    if (bucket_byte_offset > UINT32_MAX ||
        rome2_guest_add_checked((rome2_guest_addr32){buckets_addr},
            (uint32_t)bucket_byte_offset, &pair_addr) != ROME2_GUEST_OK ||
        !read_word(buckets, pair_addr, 0u, &first)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (first == 0u) {
        return ROME2_VFS_DEP_INVALID_GRAPH;
    }
    if (first == list_head) {
        return ROME2_VFS_DEP_NOT_FOUND;
    }
    if (!read_word(buckets, pair_addr, 4u, &last)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (last == 0u) {
        return ROME2_VFS_DEP_INVALID_GRAPH;
    }

    cur = first;
    for (step = 0u; step < max_chain_steps; ++step) {
        rome2_guest_addr32 key_addr;
        uint32_t next;
        bool eq = false;
        if (rome2_guest_add_checked((rome2_guest_addr32){cur}, 8u, &key_addr) != ROME2_GUEST_OK) {
            return ROME2_VFS_DEP_RANGE_ERROR;
        }
        status = rome2_vfs_string8_equals32(
            nodes, key_addr, descriptors, query_str, payloads, max_name_bytes, &eq);
        if (status != ROME2_VFS_DEP_OK) {
            return status;
        }
        if (eq) {
            output->node = cur;
            output->list_head = list_head;
            output->bucket_index = bucket_index;
            output->chain_steps = step + 1u;
            return ROME2_VFS_DEP_OK;
        }
        if (cur == last) {
            return ROME2_VFS_DEP_NOT_FOUND;
        }
        if (!read_word(nodes, (rome2_guest_addr32){cur}, 0u, &next)) {
            return ROME2_VFS_DEP_RANGE_ERROR;
        }
        if (next == 0u || next == list_head) {
            return ROME2_VFS_DEP_INVALID_GRAPH;
        }
        cur = next;
    }
    return ROME2_VFS_DEP_STEP_LIMIT;
}

rome2_vfs_dep_status rome2_vfs_dep_edge_next32(
    const rome2_guest_read_view *edge_nodes, rome2_guest_addr32 current,
    uint32_t max_tree_steps, rome2_guest_addr32 *next_node,
    uint32_t *steps_used)
{
    uint8_t cur_nil = 0u;
    uint32_t right, step = 0u;
    uint8_t right_nil = 0u;

    if (edge_nodes == NULL || next_node == NULL ||
        current.value == 0u || max_tree_steps == 0u) {
        return ROME2_VFS_DEP_BAD_ARGUMENT;
    }
    if (!read_byte(edge_nodes, current, 0x0du, &cur_nil)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (cur_nil != 0u) {
        return ROME2_VFS_DEP_INVALID_GRAPH;
    }
    if (!read_word(edge_nodes, current, 8u, &right)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (right == 0u) {
        return ROME2_VFS_DEP_INVALID_GRAPH;
    }
    if (!read_byte(edge_nodes, (rome2_guest_addr32){right}, 0x0du, &right_nil)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }

    if (right_nil == 0u) {
        uint32_t node = right;
        while (step < max_tree_steps) {
            uint32_t left;
            uint8_t left_nil = 0u;
            ++step;
            if (!read_word(edge_nodes, (rome2_guest_addr32){node}, 0u, &left)) {
                return ROME2_VFS_DEP_RANGE_ERROR;
            }
            if (left == 0u) {
                return ROME2_VFS_DEP_INVALID_GRAPH;
            }
            if (!read_byte(edge_nodes, (rome2_guest_addr32){left}, 0x0du, &left_nil)) {
                return ROME2_VFS_DEP_RANGE_ERROR;
            }
            if (left_nil != 0u) {
                next_node->value = node;
                if (steps_used != NULL) {
                    *steps_used = step;
                }
                return ROME2_VFS_DEP_OK;
            }
            node = left;
        }
        return ROME2_VFS_DEP_STEP_LIMIT;
    }

    {
        uint32_t cur = current.value;
        while (step < max_tree_steps) {
            uint32_t parent, parent_right;
            uint8_t parent_nil = 0u;
            ++step;
            if (!read_word(edge_nodes, (rome2_guest_addr32){cur}, 4u, &parent)) {
                return ROME2_VFS_DEP_RANGE_ERROR;
            }
            if (parent == 0u) {
                return ROME2_VFS_DEP_INVALID_GRAPH;
            }
            if (!read_byte(edge_nodes, (rome2_guest_addr32){parent}, 0x0du, &parent_nil)) {
                return ROME2_VFS_DEP_RANGE_ERROR;
            }
            if (parent_nil != 0u) {
                next_node->value = parent;
                if (steps_used != NULL) {
                    *steps_used = step;
                }
                return ROME2_VFS_DEP_OK;
            }
            if (!read_word(edge_nodes, (rome2_guest_addr32){parent}, 8u, &parent_right)) {
                return ROME2_VFS_DEP_RANGE_ERROR;
            }
            if (parent_right == 0u) {
                return ROME2_VFS_DEP_INVALID_GRAPH;
            }
            if (cur != parent_right) {
                next_node->value = parent;
                if (steps_used != NULL) {
                    *steps_used = step;
                }
                return ROME2_VFS_DEP_OK;
            }
            cur = parent;
        }
        return ROME2_VFS_DEP_STEP_LIMIT;
    }
}

static rome2_vfs_dep_status advance_frame_edge(
    const rome2_guest_read_view *edge_nodes,
    rome2_vfs_dep_dfs_frame *frame, uint32_t max_tree_steps)
{
    rome2_guest_addr32 next_edge;
    uint32_t next_steps = 0u;
    rome2_vfs_dep_status status;
    if (frame->edge_steps >= max_tree_steps) {
        return ROME2_VFS_DEP_STEP_LIMIT;
    }
    status = rome2_vfs_dep_edge_next32(
        edge_nodes, frame->current_edge, max_tree_steps, &next_edge, &next_steps);
    if (status != ROME2_VFS_DEP_OK) {
        return status;
    }
    frame->current_edge = next_edge;
    return ROME2_VFS_DEP_OK;
}

static rome2_vfs_dep_status init_dfs_frame(
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *edge_nodes,
    rome2_guest_addr32 graph_node,
    rome2_vfs_dep_dfs_frame *frame)
{
    uint32_t tree_head, first_edge;
    uint8_t head_nil = 0u, edge_nil = 0u;
    if (!read_word(nodes, graph_node, 0x1cu, &tree_head)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (tree_head == 0u) {
        return ROME2_VFS_DEP_INVALID_GRAPH;
    }
    if (!read_byte(edge_nodes, (rome2_guest_addr32){tree_head}, 0x0du, &head_nil) ||
        !read_word(edge_nodes, (rome2_guest_addr32){tree_head}, 0u, &first_edge)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    if (head_nil == 0u || first_edge == 0u) {
        return ROME2_VFS_DEP_INVALID_GRAPH;
    }
    if (first_edge != tree_head) {
        if (!read_byte(edge_nodes, (rome2_guest_addr32){first_edge}, 0x0du, &edge_nil)) {
            return ROME2_VFS_DEP_RANGE_ERROR;
        }
        if (edge_nil != 0u) {
            return ROME2_VFS_DEP_INVALID_GRAPH;
        }
    }
    frame->tree_head.value = tree_head;
    frame->current_edge.value = first_edge;
    frame->edge_steps = 0u;
    return ROME2_VFS_DEP_OK;
}

rome2_vfs_dep_status rome2_vfs_dep_reachable32(
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 source_str, rome2_guest_addr32 target_str,
    const rome2_vfs_dep_limits *limits, bool *is_reachable)
{
    rome2_vfs_dep_status status;
    bool eq = false;
    rome2_vfs_dep_hashmap_match32 src_match, dst_match;
    rome2_vfs_dep_dfs_frame stack[ROME2_VFS_DEP_MAX_DEPTH_CAP + 1u];
    uint32_t depth = 0u;
    uint32_t visits = 1u;

    if (maps == NULL || nodes == NULL || buckets == NULL || edge_nodes == NULL ||
        descriptors == NULL || payloads == NULL || is_reachable == NULL ||
        hashmap_addr.value == 0u || source_str.value == 0u || target_str.value == 0u ||
        !limits_valid(limits)) {
        return ROME2_VFS_DEP_BAD_ARGUMENT;
    }

    status = rome2_vfs_string8_equals32(
        descriptors, source_str, descriptors, target_str,
        payloads, limits->max_name_bytes, &eq);
    if (status != ROME2_VFS_DEP_OK) {
        return status;
    }
    if (eq) {
        *is_reachable = false;
        return ROME2_VFS_DEP_OK;
    }

    status = rome2_vfs_dep_hashmap_find32(
        maps, hashmap_addr, nodes, buckets, descriptors, payloads,
        source_str, limits->max_chain_steps, limits->max_name_bytes, &src_match);
    if (status == ROME2_VFS_DEP_NOT_FOUND) {
        *is_reachable = false;
        return ROME2_VFS_DEP_OK;
    }
    if (status != ROME2_VFS_DEP_OK) {
        return status;
    }

    status = rome2_vfs_dep_hashmap_find32(
        maps, hashmap_addr, nodes, buckets, descriptors, payloads,
        target_str, limits->max_chain_steps, limits->max_name_bytes, &dst_match);
    if (status == ROME2_VFS_DEP_NOT_FOUND) {
        *is_reachable = false;
        return ROME2_VFS_DEP_OK;
    }
    if (status != ROME2_VFS_DEP_OK) {
        return status;
    }

    status = init_dfs_frame(nodes, edge_nodes, (rome2_guest_addr32){src_match.node}, &stack[0]);
    if (status != ROME2_VFS_DEP_OK) {
        return status;
    }

    for (;;) {
        rome2_vfs_dep_dfs_frame *frame = &stack[depth];
        if (frame->current_edge.value == frame->tree_head.value) {
            if (depth == 0u) {
                *is_reachable = false;
                return ROME2_VFS_DEP_OK;
            }
            --depth;
            status = advance_frame_edge(edge_nodes, &stack[depth], limits->max_tree_steps);
            if (status != ROME2_VFS_DEP_OK) {
                return status;
            }
            continue;
        }

        if (frame->edge_steps >= limits->max_tree_steps) {
            return ROME2_VFS_DEP_STEP_LIMIT;
        }
        ++frame->edge_steps;

        {
            rome2_guest_addr32 edge_name_addr;
            bool edge_eq = false;
            rome2_vfs_dep_hashmap_match32 child_match;
            if (rome2_guest_add_checked(frame->current_edge, 0x10u, &edge_name_addr) != ROME2_GUEST_OK) {
                return ROME2_VFS_DEP_RANGE_ERROR;
            }
            status = rome2_vfs_string8_equals32(
                edge_nodes, edge_name_addr, descriptors, target_str,
                payloads, limits->max_name_bytes, &edge_eq);
            if (status != ROME2_VFS_DEP_OK) {
                return status;
            }
            if (edge_eq) {
                *is_reachable = true;
                return ROME2_VFS_DEP_OK;
            }

            status = rome2_vfs_dep_hashmap_find32(
                maps, hashmap_addr, nodes, buckets, edge_nodes, payloads,
                edge_name_addr, limits->max_chain_steps, limits->max_name_bytes, &child_match);
            if (status == ROME2_VFS_DEP_OK) {
                if (depth >= limits->max_depth || visits >= limits->max_visits) {
                    return ROME2_VFS_DEP_STEP_LIMIT;
                }
                ++visits;
                ++depth;
                status = init_dfs_frame(nodes, edge_nodes, (rome2_guest_addr32){child_match.node}, &stack[depth]);
                if (status != ROME2_VFS_DEP_OK) {
                    return status;
                }
                continue;
            }
            if (status != ROME2_VFS_DEP_NOT_FOUND) {
                return status;
            }
        }

        status = advance_frame_edge(edge_nodes, frame, limits->max_tree_steps);
        if (status != ROME2_VFS_DEP_OK) {
            return status;
        }
    }
}

rome2_vfs_dep_status rome2_vfs_compare_archive_candidates32(
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *candidates,
    const rome2_guest_read_view *pack_props,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 candidate_a, rome2_guest_addr32 candidate_b,
    const rome2_vfs_dep_limits *limits, bool *lhs_less_than_rhs)
{
    rome2_guest_addr32 name_a, name_b;
    rome2_vfs_dep_status status;
    bool reachable = false;
    uint32_t props_a, props_b;
    uint8_t byte_a = 0u, byte_b = 0u;

    if (candidates == NULL || pack_props == NULL || lhs_less_than_rhs == NULL ||
        candidate_a.value == 0u || candidate_b.value == 0u) {
        return ROME2_VFS_DEP_BAD_ARGUMENT;
    }
    if (rome2_guest_add_checked(candidate_a, 0x14u, &name_a) != ROME2_GUEST_OK ||
        rome2_guest_add_checked(candidate_b, 0x14u, &name_b) != ROME2_GUEST_OK) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }

    status = rome2_vfs_dep_reachable32(
        maps, hashmap_addr, nodes, buckets, edge_nodes, candidates, payloads,
        name_b, name_a, limits, &reachable);
    if (status != ROME2_VFS_DEP_OK) {
        return status;
    }
    if (reachable) {
        *lhs_less_than_rhs = true;
        return ROME2_VFS_DEP_OK;
    }

    status = rome2_vfs_dep_reachable32(
        maps, hashmap_addr, nodes, buckets, edge_nodes, candidates, payloads,
        name_a, name_b, limits, &reachable);
    if (status != ROME2_VFS_DEP_OK) {
        return status;
    }
    if (reachable) {
        *lhs_less_than_rhs = false;
        return ROME2_VFS_DEP_OK;
    }

    if (!read_word(candidates, candidate_a, 0u, &props_a) ||
        !read_word(candidates, candidate_b, 0u, &props_b) ||
        !read_byte(pack_props, (rome2_guest_addr32){props_a}, 0x1cu, &byte_a) ||
        !read_byte(pack_props, (rome2_guest_addr32){props_b}, 0x1cu, &byte_b)) {
        return ROME2_VFS_DEP_RANGE_ERROR;
    }
    *lhs_less_than_rhs = (byte_a & 0x0fu) > (byte_b & 0x0fu);
    return ROME2_VFS_DEP_OK;
}
