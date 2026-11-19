#include "vfs_fs_engine_tail_thunk_ops.h"

#include <string.h>

static uint8_t l57_utf16_eq(
    const uint16_t *a,
    uint32_t alen,
    const uint16_t *b,
    uint32_t blen) {
    uint32_t i = 0u;
    if (alen != blen) {
        return 0u;
    }
    if (alen == 0u) {
        return 1u;
    }
    if (!a || !b) {
        return 0u;
    }
    for (i = 0u; i < alen; ++i) {
        if (a[i] != b[i]) {
            return 0u;
        }
    }
    return 1u;
}

static rome2_vfs_reg_status l57_unlink_peer_from_channel(
    rome2_vfs_l57_channel_graph *graph,
    uint32_t ch_idx,
    uint32_t match_peer_idx) {
    rome2_vfs_l57_channel_slot *ch = NULL;
    uint32_t cur = ROME2_VFS_L57_INVALID_INDEX;
    uint32_t steps = 0u;
    if (!graph || ch_idx >= graph->channel_count) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    ch = &graph->channels[ch_idx];
    cur = ch->head_idx;
    while (cur != ROME2_VFS_L57_INVALID_INDEX) {
        rome2_vfs_l57_peer_node *node = NULL;
        if (steps++ > graph->node_count || cur >= graph->node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        node = &graph->nodes[cur];
        if (!node->in_use) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (node->peer_channel_idx == match_peer_idx) {
            uint32_t prev = node->prev_idx;
            uint32_t next = node->next_idx;
            if (cur == ch->head_idx) {
                ch->head_idx = next;
            } else if (prev < graph->node_count) {
                graph->nodes[prev].next_idx = next;
            } else {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            if (next != ROME2_VFS_L57_INVALID_INDEX) {
                if (next >= graph->node_count) {
                    return ROME2_VFS_REG_RANGE_ERROR;
                }
                graph->nodes[next].prev_idx = prev;
            } else {
                ch->tail_idx = prev;
            }
            node->in_use = 0u;
            node->prev_idx = ROME2_VFS_L57_INVALID_INDEX;
            node->next_idx = ROME2_VFS_L57_INVALID_INDEX;
            graph->freed_node_count += 1u;
            return ROME2_VFS_REG_OK;
        }
        cur = node->next_idx;
    }
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status l57_compact_duplicate_peers(
    rome2_vfs_l57_channel_graph *graph,
    uint32_t ch_idx,
    uint32_t target_peer_idx) {
    rome2_vfs_l57_channel_slot *ch = NULL;
    uint32_t dst = ROME2_VFS_L57_INVALID_INDEX;
    uint32_t src = ROME2_VFS_L57_INVALID_INDEX;
    uint32_t steps = 0u;
    if (!graph || ch_idx >= graph->channel_count) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    ch = &graph->channels[ch_idx];
    dst = ch->head_idx;
    while (dst != ROME2_VFS_L57_INVALID_INDEX &&
           dst < graph->node_count &&
           graph->nodes[dst].peer_channel_idx != target_peer_idx) {
        if (steps++ > graph->node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        dst = graph->nodes[dst].next_idx;
    }
    if (dst == ROME2_VFS_L57_INVALID_INDEX) {
        return ROME2_VFS_REG_OK;
    }
    if (dst >= graph->node_count) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    src = graph->nodes[dst].next_idx;
    while (src != ROME2_VFS_L57_INVALID_INDEX) {
        if (steps++ > graph->node_count || src >= graph->node_count || dst >= graph->node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (graph->nodes[src].peer_channel_idx != target_peer_idx) {
            graph->nodes[dst].peer_channel_idx = graph->nodes[src].peer_channel_idx;
            dst = graph->nodes[dst].next_idx;
        }
        src = graph->nodes[src].next_idx;
    }
    /* Truncate [dst .. end) identically to 0x101cfbc4..0x101cfbf0. */
    if (dst == ch->head_idx) {
        ch->head_idx = ROME2_VFS_L57_INVALID_INDEX;
        ch->tail_idx = ROME2_VFS_L57_INVALID_INDEX;
    } else {
        uint32_t prev = graph->nodes[dst].prev_idx;
        if (prev >= graph->node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        graph->nodes[prev].next_idx = ROME2_VFS_L57_INVALID_INDEX;
        ch->tail_idx = prev;
    }
    while (dst != ROME2_VFS_L57_INVALID_INDEX) {
        uint32_t next = ROME2_VFS_L57_INVALID_INDEX;
        if (steps++ > graph->node_count || dst >= graph->node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        next = graph->nodes[dst].next_idx;
        graph->nodes[dst].in_use = 0u;
        graph->nodes[dst].prev_idx = ROME2_VFS_L57_INVALID_INDEX;
        graph->nodes[dst].next_idx = ROME2_VFS_L57_INVALID_INDEX;
        graph->freed_node_count += 1u;
        dst = next;
    }
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status l57_folder_dtor_rec(
    rome2_vfs_l57_folder_node_model *nodes,
    uint32_t node_count,
    uint32_t idx,
    uint32_t depth,
    uint8_t *visited,
    rome2_vfs_l57_folder_dtor_stats *stats) {
    static const uint16_t k_unused_key[] = {'u','n','u','s','e','d','_','k','e','y',0};
    static const uint16_t k_removed_key[] = {'r','e','m','o','v','e','d','_','k','e','y',0};
    rome2_vfs_l57_folder_node_model *node = NULL;
    rome2_vfs_l57_hash_dtor_stats fstats;
    rome2_vfs_l57_hash_dtor_stats sstats;
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;
    uint32_t i = 0u;

    if (depth >= ROME2_VFS_L57_MAX_FOLDER_DEPTH || idx >= node_count || visited[idx] != 0u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    visited[idx] = 1u;
    node = &nodes[idx];
    if (node->subdir_slot_count > 8u || node->files_slot_count > 8u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    for (i = 0u; i < node->subdir_slot_count; ++i) {
        const rome2_vfs_l57_folder_subdir_slot *slot = &node->subdirs[i];
        uint32_t klen = slot->key_len;
        if (klen > 19u) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (l57_utf16_eq(slot->key, klen, node->subdirs_empty_key, node->subdirs_empty_len) ||
            l57_utf16_eq(slot->key, klen, node->subdirs_deleted_key, node->subdirs_deleted_len)) {
            continue;
        }
        if (rome2_vfs_utf16_str_ne_cstr_100f2a70(slot->key, klen, k_unused_key, 16u, 0u) != 0u &&
            rome2_vfs_utf16_str_ne_cstr_100f2a70(slot->key, klen, k_removed_key, 16u, 0u) != 0u &&
            slot->has_vec != 0u) {
            uint32_t j = 0u;
            if (slot->child_count > 4u) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            for (j = 0u; j < slot->child_count; ++j) {
                uint32_t cidx = slot->child_indices[j];
                if (cidx != ROME2_VFS_L57_INVALID_INDEX) {
                    st = l57_folder_dtor_rec(nodes, node_count, cidx, depth + 1u, visited, stats);
                    if (st != ROME2_VFS_REG_OK) {
                        return st;
                    }
                    stats->child_nodes_freed80 += 1u;
                }
            }
            if (slot->child_count > 0u) {
                stats->child_vec_arrays_freed += 1u;
            }
            stats->child_vec_headers_freed12 += 1u;
        }
    }

    if (node->raw.tuples_count_78 > 0u || node->raw.tuples_base_74 != 0u) {
        stats->tuple_arrays_torndown += 1u;
        node->raw.tuples_count_78 = 0u;
        node->raw.tuples_base_74 = 0u;
    }
    if (node->raw.aux_buf_70 != 0u) {
        stats->aux_buffers_freed += 1u;
        node->raw.aux_buf_70 = 0u;
    }

    memset(&fstats, 0, sizeof(fstats));
    st = rome2_vfs_hash48_table_dtor_112ab150(
        &node->raw.files_map_44,
        node->files,
        node->files_slot_count,
        node->files_empty_key,
        node->files_empty_len,
        node->files_deleted_key,
        node->files_deleted_len,
        &fstats);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    stats->files_tables_torndown += 1u;

    memset(&sstats, 0, sizeof(sstats));
    st = rome2_vfs_hash16_table_dtor_112ab060(&node->raw.subdirs_map_20, &sstats);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    stats->subdirs_tables_torndown += 1u;
    stats->path_and_name_strs_destroyed += 2u;
    stats->nodes_destroyed += 1u;
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_tail_free_thunk_100d12c0(
    uint32_t ptr_va,
    rome2_vfs_tail_free_fn free_cb,
    void *ctx) {
    if (!free_cb) {
        return 0u;
    }
    free_cb(ptr_va, ctx);
    return 1u;
}

uint8_t rome2_vfs_utf16_str_ne_cstr_100f2a70(
    const uint16_t *view_units,
    uint32_t view_count,
    const uint16_t *cstr,
    uint32_t cstr_max_units,
    uint16_t sentinel_word) {
    uint32_t i = 0u;
    if (!cstr || (view_count > 0u && !view_units)) {
        return 1u;
    }
    for (i = 0u; i < view_count; ++i) {
        uint16_t cc = 0u;
        if (i >= cstr_max_units) {
            return 1u;
        }
        cc = cstr[i];
        if (view_units[i] != cc || cc == sentinel_word) {
            return 1u;
        }
    }
    if (view_count >= cstr_max_units) {
        return 1u;
    }
    return (cstr[view_count] != sentinel_word) ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_elem12_vec_push_plan_1011fc50(
    rome2_vfs_elem12_vec12_32 *vec,
    uint32_t new_buf_va,
    uint8_t alloc_ok,
    rome2_vfs_elem12_push_plan *out_plan) {
    if (!vec || !out_plan) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(out_plan, 0, sizeof(*out_plan));
    if (vec->count_04 > vec->cap_08) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (vec->count_04 == vec->cap_08) {
        uint32_t new_cap = (vec->cap_08 == 0u) ? 8u : 0u;
        uint32_t old_count = vec->count_04;
        uint32_t old_data = vec->data_00;
        if (vec->cap_08 > 0u) {
            if (vec->cap_08 > (UINT32_MAX / 24u)) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            new_cap = vec->cap_08 * 2u;
        }
        if (!alloc_ok || new_buf_va == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        out_plan->did_grow = 1u;
        out_plan->new_cap = new_cap;
        out_plan->alloc_bytes = new_cap * 12u;
        out_plan->move_count = old_count;
        out_plan->old_data_va = old_data;
        vec->cap_08 = new_cap;
        vec->data_00 = new_buf_va;
        vec->count_04 = old_count + 1u;
        out_plan->append_dst_va = new_buf_va + (old_count * 12u);
        return ROME2_VFS_REG_OK;
    }

    if (vec->count_04 > (UINT32_MAX / 12u)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    out_plan->did_grow = 0u;
    out_plan->new_cap = vec->cap_08;
    out_plan->append_dst_va = vec->data_00 + (vec->count_04 * 12u);
    vec->count_04 += 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_base_dtor_101cfaf0(
    rome2_vfs_l57_channel_graph *graph,
    uint32_t self_channel_idx) {
    rome2_vfs_l57_channel_slot *self = NULL;
    uint32_t steps = 0u;
    if (!graph || self_channel_idx >= graph->channel_count ||
        graph->channel_count > 8u || graph->node_count > ROME2_VFS_L57_MAX_CHANNEL_NODES) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    self = &graph->channels[self_channel_idx];
    self->vtable_va = ROME2_VFS_L57_CH_BASE_VTABLE_VA;

    while (self->head_idx != ROME2_VFS_L57_INVALID_INDEX) {
        uint32_t head = self->head_idx;
        uint32_t peer_idx = 0u;
        uint32_t next = ROME2_VFS_L57_INVALID_INDEX;
        rome2_vfs_reg_status st = ROME2_VFS_REG_OK;
        if (steps++ > graph->node_count || head >= graph->node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (!graph->nodes[head].in_use) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        peer_idx = graph->nodes[head].peer_channel_idx;
        next = graph->nodes[head].next_idx;
        self->head_idx = next;
        if (next != ROME2_VFS_L57_INVALID_INDEX) {
            if (next >= graph->node_count) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            graph->nodes[next].prev_idx = ROME2_VFS_L57_INVALID_INDEX;
        } else {
            self->tail_idx = ROME2_VFS_L57_INVALID_INDEX;
        }
        graph->nodes[head].in_use = 0u;
        graph->nodes[head].prev_idx = ROME2_VFS_L57_INVALID_INDEX;
        graph->nodes[head].next_idx = ROME2_VFS_L57_INVALID_INDEX;
        graph->freed_node_count += 1u;

        if (peer_idx < graph->channel_count && peer_idx != self_channel_idx) {
            st = l57_unlink_peer_from_channel(graph, peer_idx, self_channel_idx);
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
            st = l57_compact_duplicate_peers(graph, self_channel_idx, peer_idx);
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
        }
    }
    self->tail_idx = ROME2_VFS_L57_INVALID_INDEX;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_derived_dtor_10f69830(
    rome2_vfs_l57_channel_graph *graph,
    uint32_t self_channel_idx,
    rome2_vfs_l57_derived_channel_state *state) {
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;
    if (!graph || !state || self_channel_idx >= graph->channel_count) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    graph->channels[self_channel_idx].vtable_va = ROME2_VFS_L57_CH_DERIVED_VTABLE_VA;
    state->did_reset_slots = 1u;
    if (state->aux_owner_ptr_4048 != 0u) {
        state->aux_owner_link_04 = 0u;
        state->aux_owner_ptr_4048 = 0u;
    }
    state->queue_nodes_freed = state->queue_406c_len + state->queue_4054_len;
    state->queue_406c_len = 0u;
    state->queue_4054_len = 0u;
    state->did_close_socket = 0u;
    state->closed_sock_fd = 0xffffffffu;
    if (state->active_24 != 0u && state->sock_fd_10 != 0xffffffffu) {
        state->did_close_socket = 1u;
        state->closed_sock_fd = state->sock_fd_10;
        state->sock_fd_10 = 0xffffffffu;
    }
    st = rome2_vfs_channel_base_dtor_101cfaf0(graph, self_channel_idx);
    return st;
}

rome2_vfs_reg_status rome2_vfs_write_signed_ranged_bits_10f71f70(
    uint8_t *buf,
    uint32_t byte_cap,
    uint32_t *inout_bit_cursor,
    int32_t value,
    int32_t min_val,
    int32_t max_val,
    uint32_t *out_bits_written) {
    uint32_t u_val = 0u;
    uint32_t u_span = 0u;
    if (!buf || !inout_bit_cursor || !out_bits_written) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (value < min_val || value > max_val) {
        *out_bits_written = 0u;
        return ROME2_VFS_REG_OK;
    }
    u_val = (uint32_t)value - (uint32_t)min_val;
    u_span = (uint32_t)max_val - (uint32_t)min_val;
    return rome2_vfs_write_ranged_bits(buf, byte_cap, inout_bit_cursor, u_val, 0u, u_span, out_bits_written);
}

rome2_vfs_reg_status rome2_vfs_hash16_table_dtor_112ab060(
    rome2_vfs_folder_hashtable32_32 *hdr,
    rome2_vfs_l57_hash_dtor_stats *out_stats) {
    if (!hdr || !out_stats) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    out_stats->keys_destroyed = hdr->cap_04;
    if (hdr->data_00 != 0u) {
        out_stats->data_freed = 1u;
        hdr->data_00 = 0u;
    }
    hdr->cap_04 = 0u;
    out_stats->sentinels_destroyed = 2u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_hash48_table_dtor_112ab150(
    rome2_vfs_folder_hashtable32_32 *hdr,
    const rome2_vfs_l57_hash48_slot *slots,
    uint32_t slot_cap,
    const uint16_t *empty_key,
    uint32_t empty_key_len,
    const uint16_t *deleted_key,
    uint32_t deleted_key_len,
    rome2_vfs_l57_hash_dtor_stats *out_stats) {
    uint32_t i = 0u;
    if (!hdr || !out_stats || (slot_cap > 0u && !slots) || slot_cap > ROME2_VFS_L57_MAX_HASH_SLOTS) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    for (i = 0u; i < slot_cap; ++i) {
        uint32_t klen = slots[i].key_len;
        if (klen > 16u) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (!l57_utf16_eq(slots[i].key, klen, empty_key, empty_key_len) &&
            !l57_utf16_eq(slots[i].key, klen, deleted_key, deleted_key_len)) {
            out_stats->values_destroyed +=
                (slots[i].val0_live ? 1u : 0u) +
                (slots[i].val1_live ? 1u : 0u) +
                (slots[i].val2_live ? 1u : 0u);
        }
        out_stats->keys_destroyed += 1u;
    }
    if (hdr->data_00 != 0u) {
        out_stats->data_freed = 1u;
        hdr->data_00 = 0u;
    }
    hdr->cap_04 = 0u;
    out_stats->sentinels_destroyed = 2u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_entry_map_dtor_112ab6b0(
    uint32_t empty_name_tag,
    const rome2_vfs_l57_pack_entry_slot *slots,
    uint32_t cap,
    rome2_vfs_l57_pack_map_dtor_stats *out_stats) {
    uint32_t i = 0u;
    if (!out_stats || (cap > 0u && !slots) || cap > ROME2_VFS_L57_MAX_HASH_SLOTS) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    for (i = 0u; i < cap; ++i) {
        if (slots[i].name_tag != empty_name_tag) {
            out_stats->virtual_dtor_calls += 1u;
            out_stats->pool_freelist_pushes += 1u;
        }
    }
    out_stats->path_str_destroyed = 1u;
    out_stats->array_teardown_called = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_folder_node_dtor_112ab8b0(
    rome2_vfs_l57_folder_node_model *nodes,
    uint32_t node_count,
    uint32_t root_idx,
    rome2_vfs_l57_folder_dtor_stats *out_stats) {
    uint8_t visited[ROME2_VFS_L57_MAX_FOLDER_NODES];
    if (!nodes || !out_stats || node_count == 0u ||
        node_count > ROME2_VFS_L57_MAX_FOLDER_NODES || root_idx >= node_count) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(visited, 0, sizeof(visited));
    memset(out_stats, 0, sizeof(*out_stats));
    return l57_folder_dtor_rec(nodes, node_count, root_idx, 0u, visited, out_stats);
}

uint32_t rome2_vfs_crt_alloca_probe_16_11684240(
    uint32_t stack_top,
    uint32_t alloc_bytes,
    uint32_t *out_aligned_bytes,
    uint32_t *out_touched_pages) {
    uint32_t slack = (uint32_t)(stack_top - alloc_bytes) & 0x0fu;
    uint32_t aligned = alloc_bytes + slack;
    if (aligned < alloc_bytes) {
        aligned = 0xffffffffu;
    }
    if (out_aligned_bytes) {
        *out_aligned_bytes = aligned;
    }
    return rome2_vfs_crt_chkstk_plan(stack_top, aligned, out_touched_pages);
}

uint8_t rome2_vfs_crt_wprintf_state_case_size_1168a23e(
    rome2_vfs_crt_wprintf_state64_32 *st,
    const uint16_t *fmt_units,
    uint32_t fmt_rem_units,
    uint32_t *inout_fmt_off,
    int32_t *out_errno,
    uint8_t *out_invparam,
    uint8_t *out_delegated_type_case) {
    uint16_t ch = 0u;
    uint16_t next0 = 0u;
    uint16_t next1 = 0u;

    if (!st || !inout_fmt_off || !out_errno || !out_invparam || !out_delegated_type_case) {
        return 0u;
    }
    *out_invparam = 0u;
    *out_delegated_type_case = 0u;
    ch = st->cur_ch_32;

    if (fmt_units && fmt_rem_units >= 1u) {
        next0 = fmt_units[0];
    }
    if (fmt_units && fmt_rem_units >= 2u) {
        next1 = fmt_units[1];
    }

    if (ch == (uint16_t)'F') {
        if ((st->flags_opt_00 & 8u) == 0u) {
            st->fsm_state_1c = 7u;
            *out_delegated_type_case = 1u;
        }
        return 1u;
    }
    if (ch == (uint16_t)'N') {
        if ((st->flags_opt_00 & 8u) == 0u) {
            st->fsm_state_1c = 8u;
            *out_errno = ROME2_VFS_L57_EINVAL_MSVC;
            *out_invparam = 1u;
            return 0u;
        }
        return 1u;
    }

    if (st->length_mod_2c != 0u) {
        *out_errno = ROME2_VFS_L57_EINVAL_MSVC;
        *out_invparam = 1u;
        return 0u;
    }

    switch (ch) {
    case 'h':
        if (next0 == (uint16_t)'h') {
            *inout_fmt_off += 1u;
            st->fmt_ptr_10 += 2u;
            st->length_mod_2c = 1u;
        } else {
            st->length_mod_2c = 2u;
        }
        break;
    case 'l':
        if (next0 == (uint16_t)'l') {
            *inout_fmt_off += 1u;
            st->fmt_ptr_10 += 2u;
            st->length_mod_2c = 4u;
        } else {
            st->length_mod_2c = 3u;
        }
        break;
    case 'j':
        st->length_mod_2c = 5u;
        break;
    case 'z':
        st->length_mod_2c = 6u;
        break;
    case 't':
        st->length_mod_2c = 7u;
        break;
    case 'L':
        st->length_mod_2c = 8u;
        break;
    case 'I':
        if (next0 == (uint16_t)'3' && next1 == (uint16_t)'2') {
            *inout_fmt_off += 2u;
            st->fmt_ptr_10 += 4u;
            st->length_mod_2c = 10u;
        } else if (next0 == (uint16_t)'6' && next1 == (uint16_t)'4') {
            *inout_fmt_off += 2u;
            st->fmt_ptr_10 += 4u;
            st->length_mod_2c = 11u;
        } else if (next0 == (uint16_t)'d' || next0 == (uint16_t)'i' ||
                   next0 == (uint16_t)'o' || next0 == (uint16_t)'u' ||
                   next0 == (uint16_t)'x' || next0 == (uint16_t)'X') {
            st->length_mod_2c = 9u;
        }
        break;
    case 'w':
        st->length_mod_2c = 12u;
        break;
    case 'T':
        st->length_mod_2c = 13u;
        break;
    default:
        break;
    }
    return 1u;
}

uint8_t rome2_vfs_crt_malloc_thunk_1168d0c3(
    uint32_t size_bytes,
    uint32_t *out_alloc_bytes,
    int32_t *out_errno) {
    return rome2_vfs_crt_malloc_plan(size_bytes, out_alloc_bytes, out_errno);
}

uint8_t rome2_vfs_iat_thunk_describe(
    uint32_t thunk_va,
    rome2_vfs_iat_thunk_desc *out_desc) {
    static const rome2_vfs_iat_thunk_desc k_thunks[] = {
        { 0x100f3880u, 0x1172f1d8u, "KERNEL32.dll", "GetLastError", 0u },
        { 0x100f3890u, 0x1172f234u, "KERNEL32.dll", "GetTickCount", 0u },
        { 0x116c80c5u, 0x1172f880u, "WS2_32.dll", "#3 (closesocket)", 4u },
        { 0x116c80d1u, 0x1172f81cu, "WS2_32.dll", "#10 (ioctlsocket)", 12u },
        { 0x116c80d7u, 0x1172f820u, "WS2_32.dll", "#9 (htons)", 4u },
        { 0x116c80efu, 0x1172f830u, "WS2_32.dll", "#16 (recv)", 16u },
        { 0x116c80fbu, 0x1172f838u, "WS2_32.dll", "#19 (send)", 16u },
        { 0x116c810du, 0x1172f844u, "WS2_32.dll", "#23 (socket)", 12u },
        { 0x116c8125u, 0x1172f854u, "WS2_32.dll", "#111 (WSAGetLastError)", 0u },
    };
    size_t i = 0u;
    if (!out_desc) {
        return 0u;
    }
    for (i = 0u; i < sizeof(k_thunks) / sizeof(k_thunks[0]); ++i) {
        if (k_thunks[i].thunk_va == thunk_va) {
            *out_desc = k_thunks[i];
            return 1u;
        }
    }
    return 0u;
}

uint32_t rome2_vfs_win32_get_last_error_100f3880(uint32_t recorded_err) {
    return recorded_err;
}

uint32_t rome2_vfs_win32_get_tick_count_100f3890(uint32_t monotonic_ms) {
    return monotonic_ms;
}

int32_t rome2_vfs_ws2_closesocket_116c80c5(rome2_vfs_ws2_mock_socket *sock) {
    if (!sock || sock->open == 0u || sock->fd == 0xffffffffu) {
        if (sock) {
            sock->last_error = 10038u; /* WSAENOTSOCK */
        }
        return -1;
    }
    sock->open = 0u;
    sock->fd = 0xffffffffu;
    sock->last_error = 0u;
    return 0;
}

int32_t rome2_vfs_ws2_ioctlsocket_116c80d1(
    rome2_vfs_ws2_mock_socket *sock,
    uint32_t cmd,
    uint32_t *argp) {
    if (!sock || sock->open == 0u || !argp) {
        if (sock) {
            sock->last_error = 10038u;
        }
        return -1;
    }
    if (cmd == 0x8004667eu) { /* FIONBIO */
        sock->nonblocking = (*argp != 0u) ? 1u : 0u;
        sock->last_error = 0u;
        return 0;
    }
    if (cmd == 0x4004667fu) { /* FIONREAD */
        *argp = sock->rx_len;
        sock->last_error = 0u;
        return 0;
    }
    sock->last_error = 10022u; /* WSAEINVAL */
    return -1;
}

uint16_t rome2_vfs_ws2_htons_116c80d7(uint16_t hostshort) {
    return (uint16_t)(((hostshort & 0x00ffu) << 8) | ((hostshort >> 8) & 0x00ffu));
}

int32_t rome2_vfs_ws2_recv_116c80ef(
    rome2_vfs_ws2_mock_socket *sock,
    uint8_t *buf,
    uint32_t len,
    uint32_t flags) {
    uint32_t n = 0u;
    uint32_t rem = 0u;
    if (!sock || sock->open == 0u || (!buf && len > 0u) || flags != 0u) {
        if (sock) {
            sock->last_error = 10022u;
        }
        return -1;
    }
    if (len == 0u) {
        sock->last_error = 0u;
        return 0;
    }
    if (sock->rx_len == 0u) {
        sock->last_error = sock->nonblocking ? ROME2_VFS_L38_WSAEWOULDBLOCK : 0u;
        return sock->nonblocking ? -1 : 0;
    }
    n = (len < sock->rx_len) ? len : sock->rx_len;
    if (n > sizeof(sock->rx_buf)) {
        n = (uint32_t)sizeof(sock->rx_buf);
    }
    memcpy(buf, sock->rx_buf, n);
    rem = sock->rx_len - n;
    if (rem > 0u) {
        memmove(sock->rx_buf, sock->rx_buf + n, rem);
    }
    sock->rx_len = rem;
    sock->last_error = 0u;
    return (int32_t)n;
}

int32_t rome2_vfs_ws2_send_116c80fb(
    rome2_vfs_ws2_mock_socket *sock,
    const uint8_t *buf,
    uint32_t len,
    uint32_t flags) {
    uint32_t avail = 0u;
    uint32_t n = 0u;
    if (!sock || sock->open == 0u || (!buf && len > 0u) || flags != 0u) {
        if (sock) {
            sock->last_error = 10022u;
        }
        return -1;
    }
    avail = (sock->tx_len <= sizeof(sock->tx_buf)) ? ((uint32_t)sizeof(sock->tx_buf) - sock->tx_len) : 0u;
    if (avail == 0u && len > 0u) {
        sock->last_error = ROME2_VFS_L38_WSAEWOULDBLOCK;
        return -1;
    }
    n = (len < avail) ? len : avail;
    if (n > 0u) {
        memcpy(sock->tx_buf + sock->tx_len, buf, n);
        sock->tx_len += n;
    }
    sock->last_error = 0u;
    return (int32_t)n;
}

uint32_t rome2_vfs_ws2_socket_116c810d(
    rome2_vfs_ws2_mock_socket *sock,
    int32_t af,
    int32_t type,
    int32_t protocol,
    uint32_t next_fd) {
    if (!sock || af != 2 || (type != 1 && type != 2) ||
        (protocol != 0 && protocol != 6 && protocol != 17) || next_fd == 0xffffffffu) {
        if (sock) {
            sock->last_error = 10047u; /* WSAEAFNOSUPPORT / invalid */
        }
        return 0xffffffffu;
    }
    memset(sock, 0, sizeof(*sock));
    sock->fd = next_fd;
    sock->open = 1u;
    return next_fd;
}

uint32_t rome2_vfs_ws2_get_last_error_116c8125(const rome2_vfs_ws2_mock_socket *sock) {
    return sock ? sock->last_error : 0u;
}
