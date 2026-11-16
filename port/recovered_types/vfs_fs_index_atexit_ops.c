#include "vfs_fs_index_atexit_ops.h"

#include <stdio.h>
#include <string.h>

static uint8_t vfs_ascii_upper(uint8_t ch) {
    if ((uint8_t)(ch - (uint8_t)'a') <= 25u) {
        return (uint8_t)(ch - 0x20u);
    }
    return ch;
}

static rome2_vfs_reg_status vfs_copy_bounded(char *dst, uint32_t dst_cap, const char *src) {
    size_t len;
    if (!dst || dst_cap == 0u || !src) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    len = strlen(src);
    if (len >= (size_t)dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memcpy(dst, src, len + 1u);
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status vfs_append_bounded(char *dst, uint32_t dst_cap, const char *suffix) {
    size_t cur_len;
    size_t add_len;
    if (!dst || dst_cap == 0u || !suffix) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    cur_len = strlen(dst);
    add_len = strlen(suffix);
    if (cur_len >= (size_t)dst_cap || add_len >= (size_t)dst_cap - cur_len) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memcpy(dst + cur_len, suffix, add_len + 1u);
    return ROME2_VFS_REG_OK;
}

const rome2_vfs_pack_index_table *rome2_vfs_pack_index_get_primary(rome2_vfs_pack_index_env *env) {
    if (!env) {
        return NULL;
    }
    if (!env->primary_ready) {
        env->primary_singleton.count = 0u;
        env->primary_ready = 1u;
    }
    return &env->primary_singleton;
}

const rome2_vfs_pack_index_table *rome2_vfs_pack_index_get_empty(rome2_vfs_pack_index_env *env) {
    if (!env) {
        return NULL;
    }
    if (!env->empty_ready) {
        env->empty_singleton.count = 1u;
        env->empty_singleton.entries[0][0] = '\0';
        env->empty_ready = 1u;
    }
    return &env->empty_singleton;
}

static uint8_t vfs_wildcard_match_depth(const char *str, const char *pattern, uint32_t depth) {
    if (!str || !pattern || depth > 128u) {
        return 0u;
    }
    if (strcmp(pattern, "*") == 0 || strcmp(pattern, "*.*") == 0) {
        return 1u;
    }
    while (*str != '\0') {
        if (*pattern == '\0') {
            return 0u;
        }
        if (*pattern == '?') {
            ++str;
            ++pattern;
            continue;
        }
        if (*pattern == '*') {
            ++pattern;
            if (*pattern == '\0') {
                return 1u;
            }
            while (*str != '\0') {
                if (vfs_wildcard_match_depth(str, pattern, depth + 1u) != 0u) {
                    return 1u;
                }
                ++str;
            }
            return 0u;
        }
        if (vfs_ascii_upper((uint8_t)*str) != vfs_ascii_upper((uint8_t)*pattern)) {
            return 0u;
        }
        ++str;
        ++pattern;
    }
    while (*pattern == '*') {
        ++pattern;
    }
    return *pattern == '\0' ? 1u : 0u;
}

uint8_t rome2_vfs_wildcard_match_nocase(const char *str, const char *pattern) {
    return vfs_wildcard_match_depth(str, pattern, 0u);
}

rome2_vfs_reg_status rome2_vfs_strip_trailing_separators(
    const char *path,
    char *out_buf,
    uint32_t out_cap) {
    size_t len;
    if (!path || !out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    len = strlen(path);
    while (len > 0u && (path[len - 1u] == '\\' || path[len - 1u] == '/')) {
        --len;
    }
    if (len >= (size_t)out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (len > 0u) {
        memcpy(out_buf, path, len);
    }
    out_buf[len] = '\0';
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_pack_index_can_open(
    const rome2_vfs_pack_index_table *table,
    const char *rel_path,
    rome2_vfs_idx_direct_pred_fn direct_pred,
    rome2_vfs_idx_probe_open_fn probe_open,
    void *ctx) {
    uint32_t i;
    uint32_t count;
    char candidate[ROME2_VFS_IDX_MAX_PATH * 2u + 2u];

    if (!table || !rel_path || !probe_open || rel_path[0] == '\0') {
        return 0u;
    }
    if (direct_pred && direct_pred(rel_path, ctx) != 0u) {
        return probe_open(rel_path, ctx) != 0u ? 1u : 0u;
    }
    count = table->count;
    if (count > ROME2_VFS_IDX_MAX_PREFIXES) {
        count = ROME2_VFS_IDX_MAX_PREFIXES;
    }
    for (i = 0u; i < count; ++i) {
        if (vfs_copy_bounded(candidate, sizeof(candidate), table->entries[i]) != ROME2_VFS_REG_OK) {
            continue;
        }
        if (vfs_append_bounded(candidate, sizeof(candidate), rel_path) != ROME2_VFS_REG_OK) {
            continue;
        }
        if (probe_open(candidate, ctx) != 0u) {
            return 1u;
        }
    }
    return 0u;
}

const char *rome2_vfs_pack_index_resolve_root(
    rome2_vfs_pack_index_env *env,
    const char *rel_path,
    rome2_vfs_idx_direct_pred_fn direct_pred,
    rome2_vfs_idx_probe_open_fn probe_open,
    void *ctx) {
    const rome2_vfs_pack_index_table *primary;
    const rome2_vfs_pack_index_table *empty_tbl;
    uint32_t i;
    uint32_t count;
    char candidate[ROME2_VFS_IDX_MAX_PATH * 2u + 2u];

    if (!env || !rel_path) {
        return NULL;
    }
    primary = rome2_vfs_pack_index_get_primary(env);
    empty_tbl = rome2_vfs_pack_index_get_empty(env);
    if (!primary || !empty_tbl) {
        return NULL;
    }
    if ((direct_pred && direct_pred(rel_path, ctx) != 0u) || !probe_open) {
        return empty_tbl->entries[0];
    }
    count = primary->count;
    if (count > ROME2_VFS_IDX_MAX_PREFIXES) {
        count = ROME2_VFS_IDX_MAX_PREFIXES;
    }
    for (i = 0u; i < count; ++i) {
        if (vfs_copy_bounded(candidate, sizeof(candidate), primary->entries[i]) != ROME2_VFS_REG_OK) {
            continue;
        }
        if (vfs_append_bounded(candidate, sizeof(candidate), rel_path) != ROME2_VFS_REG_OK) {
            continue;
        }
        if (probe_open(candidate, ctx) != 0u) {
            return primary->entries[i];
        }
    }
    return empty_tbl->entries[0];
}

rome2_vfs_reg_status rome2_vfs_pack_index_resolve_path(
    const rome2_vfs_pack_index_table *table,
    const char *rel_path,
    rome2_vfs_idx_direct_pred_fn direct_pred,
    rome2_vfs_idx_probe_open_fn probe_open,
    void *ctx,
    char *out_path,
    uint32_t out_cap) {
    uint32_t i;
    uint32_t count;
    char candidate[ROME2_VFS_IDX_MAX_PATH * 2u + 2u];

    if (!table || !rel_path || !out_path || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (direct_pred && direct_pred(rel_path, ctx) != 0u) {
        return vfs_copy_bounded(out_path, out_cap, rel_path);
    }
    if (probe_open) {
        count = table->count;
        if (count > ROME2_VFS_IDX_MAX_PREFIXES) {
            count = ROME2_VFS_IDX_MAX_PREFIXES;
        }
        for (i = 0u; i < count; ++i) {
            if (vfs_copy_bounded(candidate, sizeof(candidate), table->entries[i]) != ROME2_VFS_REG_OK) {
                continue;
            }
            if (vfs_append_bounded(candidate, sizeof(candidate), rel_path) != ROME2_VFS_REG_OK) {
                continue;
            }
            if (probe_open(candidate, ctx) != 0u) {
                return vfs_copy_bounded(out_path, out_cap, candidate);
            }
        }
    }
    out_path[0] = '\0';
    return ROME2_VFS_REG_NOT_FOUND;
}

rome2_vfs_reg_status rome2_vfs_wrap_new_stream_from_path(
    rome2_vfs_pack_index_env *env,
    const char *path,
    uint32_t *out_handle) {
    if (!env || !path || !out_handle) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    env->open_handle_seq += 1u;
    *out_handle = env->open_handle_seq;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_build_prefixed_entry(
    rome2_vfs_pack_index_env *env,
    const char *prefix,
    const char *rel_path,
    uint32_t *out_handle,
    char *out_joined,
    uint32_t out_cap) {
    rome2_vfs_reg_status st;
    if (!env || !prefix || !rel_path || !out_handle || !out_joined || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = vfs_copy_bounded(out_joined, out_cap, prefix);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = vfs_append_bounded(out_joined, out_cap, "\\");
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = vfs_append_bounded(out_joined, out_cap, rel_path);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    env->open_handle_seq += 1u;
    *out_handle = env->open_handle_seq;
    return ROME2_VFS_REG_OK;
}

void rome2_vfs_decode_win32_find_info(
    uint32_t file_size_low,
    uint32_t attributes,
    uint64_t last_write_filetime,
    rome2_vfs_win32_find_info *out_info) {
    uint64_t total_sec;
    uint32_t sec_low32;

    if (!out_info) {
        return;
    }
    /* Match `0x100fec00`: uint64 divide by 10,000,000 then `+ 0x49ef7d10` mod 2^32. */
    total_sec = last_write_filetime / 10000000ULL;
    sec_low32 = (uint32_t)total_sec;
    out_info->file_size_low = file_size_low;
    out_info->mtime_unix_low32 = sec_low32 + ROME2_WIN32_EPOCH_LOW32_ADD;
    out_info->valid = 1u;
    out_info->writable = (uint8_t)((~attributes) & ROME2_WIN32_ATTR_READONLY);
    out_info->is_dir = (uint8_t)((attributes >> 4u) & 1u);
    out_info->hidden = (uint8_t)((attributes >> 1u) & 1u);
}

static rome2_vfs_reg_status vfs_traverse_sim_impl(
    const rome2_vfs_win32_sim_fs *fs,
    const char *dir_path,
    const char *pattern,
    uint8_t recursive,
    rome2_vfs_win32_visit_fn visit,
    void *user_ctx,
    uint32_t depth,
    uint32_t depth_limit) {
    char norm_dir[ROME2_VFS_IDX_MAX_PATH * 2u + 2u];
    char entry_norm_dir[ROME2_VFS_IDX_MAX_PATH * 2u + 2u];
    char next_dir[ROME2_VFS_IDX_MAX_PATH * 2u + 4u];
    uint32_t i;
    uint32_t count;

    if (!fs || !dir_path || !pattern || !visit) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (depth > depth_limit) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    if (rome2_vfs_strip_trailing_separators(dir_path, norm_dir, sizeof(norm_dir)) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    count = fs->count;
    if (count > ROME2_VFS_IDX_MAX_ELEMS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    for (i = 0u; i < count; ++i) {
        rome2_vfs_win32_find_info info;
        if (rome2_vfs_strip_trailing_separators(
                fs->entries[i].dir, entry_norm_dir, sizeof(entry_norm_dir)) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (strcmp(entry_norm_dir, norm_dir) != 0) {
            continue;
        }
        if (rome2_vfs_wildcard_match_nocase(fs->entries[i].name, pattern) == 0u) {
            continue;
        }
        rome2_vfs_decode_win32_find_info(
            fs->entries[i].file_size_low,
            fs->entries[i].attributes,
            fs->entries[i].last_write_filetime,
            &info);
        visit(dir_path, fs->entries[i].name, pattern, &info, user_ctx);
    }

    if (recursive == 0u) {
        return ROME2_VFS_REG_OK;
    }

    for (i = 0u; i < count; ++i) {
        rome2_vfs_reg_status st;
        if ((fs->entries[i].attributes & ROME2_WIN32_ATTR_DIRECTORY) == 0u) {
            continue;
        }
        if (strcmp(fs->entries[i].name, ".") == 0 || strcmp(fs->entries[i].name, "..") == 0) {
            continue;
        }
        if (rome2_vfs_strip_trailing_separators(
                fs->entries[i].dir, entry_norm_dir, sizeof(entry_norm_dir)) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (strcmp(entry_norm_dir, norm_dir) != 0) {
            continue;
        }
        if (vfs_copy_bounded(next_dir, sizeof(next_dir), norm_dir) != ROME2_VFS_REG_OK ||
            vfs_append_bounded(next_dir, sizeof(next_dir), "\\") != ROME2_VFS_REG_OK ||
            vfs_append_bounded(next_dir, sizeof(next_dir), fs->entries[i].name) != ROME2_VFS_REG_OK ||
            vfs_append_bounded(next_dir, sizeof(next_dir), "\\") != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        st = vfs_traverse_sim_impl(
            fs, next_dir, pattern, recursive, visit, user_ctx, depth + 1u, depth_limit);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }

    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_traverse_sim_directory(
    const rome2_vfs_win32_sim_fs *fs,
    const char *dir_path,
    const char *pattern,
    uint8_t recursive,
    rome2_vfs_win32_visit_fn visit,
    void *user_ctx,
    uint32_t depth_limit) {
    return vfs_traverse_sim_impl(fs, dir_path, pattern, recursive, visit, user_ctx, 0u, depth_limit);
}

void rome2_vfs_pair_array_clear(uint32_t *elem_count, uint32_t *destroyed_count) {
    uint32_t total;
    if (!elem_count) {
        return;
    }
    total = *elem_count;
    *elem_count = 0u;
    if (destroyed_count) {
        *destroyed_count += total;
    }
}

static rome2_vfs_reg_status vfs_rb_erase_depth(
    rome2_vfs_rb_ref_node *nodes,
    uint32_t node_count,
    int32_t root_idx,
    uint32_t depth,
    uint32_t *out_erased_nodes,
    uint32_t *out_destroyed_payloads,
    uint32_t *out_deallocated_ctrls) {
    int32_t cur = root_idx;
    uint32_t steps = 0u;

    if (!nodes || !out_erased_nodes || !out_destroyed_payloads || !out_deallocated_ctrls) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (depth > ROME2_VFS_IDX_MAX_NODES) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    while (cur >= 0) {
        int32_t next_left;
        if ((uint32_t)cur >= node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (nodes[cur].is_nil != 0u || nodes[cur].active == 0u) {
            break;
        }
        if (steps >= node_count) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        ++steps;
        if (nodes[cur].right >= 0) {
            rome2_vfs_reg_status st = vfs_rb_erase_depth(
                nodes,
                node_count,
                nodes[cur].right,
                depth + 1u,
                out_erased_nodes,
                out_destroyed_payloads,
                out_deallocated_ctrls);
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
        }
        next_left = nodes[cur].left;
        if (nodes[cur].strong_refs > 0u) {
            nodes[cur].strong_refs -= 1u;
            if (nodes[cur].strong_refs == 0u) {
                nodes[cur].destroyed_payloads += 1u;
                *out_destroyed_payloads += 1u;
                if (nodes[cur].weak_refs > 0u) {
                    nodes[cur].weak_refs -= 1u;
                    if (nodes[cur].weak_refs == 0u) {
                        nodes[cur].deallocated_ctrls += 1u;
                        *out_deallocated_ctrls += 1u;
                    }
                }
            }
        }
        nodes[cur].active = 0u;
        nodes[cur].left = -1;
        nodes[cur].right = -1;
        *out_erased_nodes += 1u;
        cur = next_left;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_rb_erase_subtree(
    rome2_vfs_rb_ref_node *nodes,
    uint32_t node_count,
    int32_t root_idx,
    uint32_t *out_erased_nodes,
    uint32_t *out_destroyed_payloads,
    uint32_t *out_deallocated_ctrls) {
    if (!out_erased_nodes || !out_destroyed_payloads || !out_deallocated_ctrls) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_erased_nodes = 0u;
    *out_destroyed_payloads = 0u;
    *out_deallocated_ctrls = 0u;
    return vfs_rb_erase_depth(
        nodes, node_count, root_idx, 0u, out_erased_nodes, out_destroyed_payloads, out_deallocated_ctrls);
}

rome2_vfs_reg_status rome2_vfs_mount_node_list_free(
    rome2_vfs_mount_free_node *nodes,
    uint32_t node_count,
    int32_t head_idx,
    uint32_t *out_freed_nodes,
    uint32_t *out_freed_aux,
    uint32_t *out_freed_children) {
    int32_t cur = head_idx;
    uint32_t steps = 0u;

    if (!nodes || !out_freed_nodes || !out_freed_aux || !out_freed_children) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_freed_nodes = 0u;
    *out_freed_aux = 0u;
    *out_freed_children = 0u;
    while (cur >= 0) {
        int32_t next_idx;
        if ((uint32_t)cur >= node_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (nodes[cur].active == 0u || steps >= node_count) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        ++steps;
        next_idx = nodes[cur].next;
        *out_freed_children += nodes[cur].child_count;
        nodes[cur].child_count = 0u;
        if (nodes[cur].has_aux_buf != 0u) {
            nodes[cur].has_aux_buf = 0u;
            *out_freed_aux += 1u;
        }
        nodes[cur].active = 0u;
        nodes[cur].next = -1;
        *out_freed_nodes += 1u;
        cur = next_idx;
    }
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_fnv1a_cstr_lower_or_raw(const char *key) {
    uint32_t h = 2166136261u;
    if (!key) {
        return h;
    }
    while (*key != '\0') {
        h ^= (uint8_t)*key;
        h *= 16777619u;
        ++key;
    }
    return h;
}

rome2_vfs_reg_status rome2_vfs_umap_rehash(
    rome2_vfs_umap_rehash_state *state,
    uint32_t requested_buckets) {
    uint32_t pow2_buckets = 2u;
    uint32_t i;

    if (!state) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (requested_buckets > ROME2_VFS_IDX_UMAP_MAX_BUCKETS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    while (pow2_buckets < requested_buckets || pow2_buckets <= 8u) {
        if (pow2_buckets >= ROME2_VFS_IDX_MAX_BUCKETS) {
            break;
        }
        pow2_buckets <<= 1u;
    }
    if (pow2_buckets > ROME2_VFS_IDX_MAX_BUCKETS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    state->bucket_count = pow2_buckets;
    state->bucket_mask = pow2_buckets - 1u;
    for (i = 0u; i < pow2_buckets; ++i) {
        state->bucket_heads[i] = UINT32_MAX;
        state->bucket_counts[i] = 0u;
    }
    if (state->node_count > ROME2_VFS_IDX_MAX_NODES) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (i = 0u; i < state->node_count; ++i) {
        uint32_t bkt;
        if (state->nodes[i].active == 0u) {
            continue;
        }
        bkt = rome2_vfs_fnv1a_cstr_lower_or_raw(state->nodes[i].key) & state->bucket_mask;
        if (bkt >= ROME2_VFS_IDX_MAX_BUCKETS) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (state->bucket_heads[bkt] == UINT32_MAX) {
            state->bucket_heads[bkt] = i;
        }
        state->bucket_counts[bkt] += 1u;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_chunked_str_clear(
    rome2_vfs_str_chunk *chunks,
    uint32_t chunk_count,
    int32_t head_idx,
    uint32_t *out_destroyed_strings) {
    int32_t cur = head_idx;
    uint32_t steps = 0u;

    if (!chunks || !out_destroyed_strings) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_destroyed_strings = 0u;
    while (cur >= 0) {
        if ((uint32_t)cur >= chunk_count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (steps >= chunk_count) {
            return ROME2_VFS_REG_STEP_LIMIT;
        }
        ++steps;
        *out_destroyed_strings += chunks[cur].count;
        chunks[cur].count = 0u;
        cur = chunks[cur].next;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_entry48_vec_push_back(
    rome2_vfs_entry48_vec *vec,
    const rome2_vfs_entry48_rec *elem) {
    rome2_vfs_entry48_rec copy_elem;
    uint32_t new_cap;

    if (!vec || !elem) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (vec->count >= ROME2_VFS_IDX_MAX_ELEMS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    /* Match `0x112d7b40` self-aliasing handling by capturing value before growth. */
    copy_elem = *elem;
    if (vec->count >= vec->capacity) {
        new_cap = vec->capacity == 0u ? 1u : vec->capacity * 2u;
        if (new_cap > ROME2_VFS_IDX_MAX_ELEMS) {
            new_cap = ROME2_VFS_IDX_MAX_ELEMS;
        }
        vec->capacity = new_cap;
    }
    vec->items[vec->count] = copy_elem;
    vec->count += 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_u32_vec_push_back(
    rome2_vfs_u32_vec *vec,
    const uint32_t *elem) {
    uint32_t val;
    uint32_t new_cap;

    if (!vec || !elem) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (vec->count >= ROME2_VFS_IDX_MAX_ELEMS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    /* Match `0x100eaf40` self-aliasing handling when `elem` points inside `vec->items`. */
    val = *elem;
    if (vec->count >= vec->capacity) {
        new_cap = vec->capacity == 0u ? 1u : vec->capacity * 2u;
        if (new_cap > ROME2_VFS_IDX_MAX_ELEMS) {
            new_cap = ROME2_VFS_IDX_MAX_ELEMS;
        }
        vec->capacity = new_cap;
    }
    vec->items[vec->count] = val;
    vec->count += 1u;
    return ROME2_VFS_REG_OK;
}

void rome2_vfs_get_static_key_c2370(uint32_t out_tag[4]) {
    if (!out_tag) {
        return;
    }
    /* Exact 16B constant loaded from `0x117402b0` into `0x119f3868` in `0x112c2370`. */
    out_tag[0] = 0u;
    out_tag[1] = 0u;
    out_tag[2] = 0u;
    out_tag[3] = 0x352fce2du;
}

const rome2_vfs_diag_kv *rome2_vfs_diag_find_primary(
    const rome2_vfs_diag_kv *table,
    uint32_t table_count,
    const uint32_t key_tag[4]) {
    uint32_t i;
    if (!table || !key_tag) {
        return NULL;
    }
    for (i = 0u; i < table_count; ++i) {
        if (table[i].valid != 0u &&
            memcmp(table[i].tag_dwords, key_tag, sizeof(uint32_t) * 4u) == 0) {
            return &table[i];
        }
    }
    return NULL;
}

rome2_vfs_reg_status rome2_vfs_diag_format_composite(
    const rome2_vfs_diag_kv *table,
    uint32_t table_count,
    const char *prefix_name,
    const char *suffix_name,
    char *out_buf,
    uint32_t out_cap) {
    /* Constant at `0x1189a6b0` copied into `0x12032b64` in `0x112a56d0`. */
    static const uint32_t k_tag_c2b64[4] = {0u, 0u, 0u, 0x31104a80u};
    uint32_t tag_c2370[4];
    const rome2_vfs_diag_kv *hit;

    if (!out_buf || out_cap == 0u || !prefix_name) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    rome2_vfs_get_static_key_c2370(tag_c2370);
    hit = rome2_vfs_diag_find_primary(table, table_count, tag_c2370);
    if (!hit) {
        hit = rome2_vfs_diag_find_primary(table, table_count, k_tag_c2b64);
    }
    if (hit && suffix_name && suffix_name[0] != '\0') {
        int written = snprintf(out_buf, out_cap, "%s%s%s", prefix_name, hit->text, suffix_name);
        if (written < 0 || (uint32_t)written >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        return ROME2_VFS_REG_OK;
    }
    return vfs_copy_bounded(out_buf, out_cap, prefix_name);
}

rome2_vfs_reg_status rome2_vfs_format_bitmask_flags(
    const rome2_vfs_diag_provider *provider,
    uint32_t flags,
    char *out_buf,
    uint32_t out_cap) {
    uint32_t i;
    uint32_t bit_count;
    uint8_t has_flag = 0u;
    rome2_vfs_reg_status st;

    if (!provider || !out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    bit_count = provider->bit_count;
    if (bit_count > ROME2_VFS_IDX_MAX_FLAGS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    /* Match `0x112f0b90`: initializes output buffer to " " (`0x1178821c`) and separates with "|" (`0x1183815c`). */
    st = vfs_copy_bounded(out_buf, out_cap, " ");
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    for (i = 0u; i < bit_count; ++i) {
        uint32_t bit_mask = (1u << i);
        if ((flags & bit_mask) == 0u) {
            continue;
        }
        if ((provider->excluded_mask & bit_mask) != 0u) {
            continue;
        }
        if (has_flag != 0u) {
            st = vfs_append_bounded(out_buf, out_cap, "|");
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
        }
        st = vfs_append_bounded(out_buf, out_cap, provider->bit_names[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        has_flag = 1u;
    }
    return ROME2_VFS_REG_OK;
}

void rome2_vfs_run_all_atexit_destructors(rome2_vfs_atexit_globals_state *state) {
    if (!state) {
        return;
    }
    /* 0x11724a10 */
    if (state->ptr_119e11d8_allocated != 0u) {
        state->ptr_119e11d8_allocated = 0u;
        state->freed_allocs += 1u;
    }
    /* 0x11724a80 */
    if (state->ptr_120328f4_allocated != 0u) {
        state->ptr_120328f4_allocated = 0u;
        state->freed_allocs += 1u;
    }
    /* 0x11724ab0 */
    if (state->str_arr_119e11c0_buf_allocated != 0u) {
        state->destroyed_strings += state->str_arr_119e11bc_count;
        state->str_arr_119e11bc_count = 0u;
        state->str_arr_119e11c0_buf_allocated = 0u;
        state->freed_allocs += 1u;
    }
    /* 0x11724b00 */
    if (state->rb_12032a34_nodes_alive > 0u) {
        state->destroyed_strings += state->rb_12032a34_nodes_alive;
        state->freed_allocs += state->rb_12032a34_nodes_alive;
        state->rb_12032a34_nodes_alive = 0u;
    }
    /* 0x11724b30 */
    if (state->list_119e11dc_nodes_alive > 0u) {
        state->freed_allocs += state->list_119e11dc_nodes_alive;
        state->list_119e11dc_nodes_alive = 0u;
    }
    state->list_119e11dc_head_reset = 1u;
    /* 0x11724b70 */
    if (state->ptr_119e122c_allocated != 0u) {
        state->ptr_119e122c_allocated = 0u;
        state->freed_allocs += 1u;
    }
    /* 0x11724b90 */
    if (state->hash_120329fc_entries_alive > 0u) {
        state->destroyed_strings += state->hash_120329fc_entries_alive;
        state->hash_120329fc_entries_alive = 0u;
    }
    if (state->hash_120329fc_buf_allocated != 0u) {
        state->hash_120329fc_buf_allocated = 0u;
        state->freed_allocs += 1u;
    }
    /* 0x11724be0 */
    if (state->str_arr_119e11cc_buf_allocated != 0u) {
        state->destroyed_strings += state->str_arr_119e11c8_count;
        state->str_arr_119e11c8_count = 0u;
        state->str_arr_119e11cc_buf_allocated = 0u;
        state->freed_allocs += 1u;
    }
    /* 0x11724e30 */
    if (state->ptr_12032a84_allocated != 0u) {
        state->ptr_12032a84_allocated = 0u;
        state->freed_allocs += 1u;
    }
    /* 0x11724e50 */
    if (state->handle_12032b30_open != 0u) {
        state->handle_12032b30_open = 0u;
        state->freed_handles += 1u;
    }
}
