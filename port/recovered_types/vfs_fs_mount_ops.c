#include "vfs_fs_mount_ops.h"

#include <stddef.h>
#include <string.h>

static rome2_vfs_reg_status r2_copy_mount_str(
    const char *src,
    char *dst,
    uint32_t dst_cap) {
    size_t len;
    if (src == NULL || dst == NULL || dst_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    len = strnlen(src, (size_t)dst_cap);
    if (len >= (size_t)dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (len > 0u) {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
    return ROME2_VFS_REG_OK;
}

static uint8_t r2_mount_str_eq(const char *a, const char *b) {
    size_t i;
    if (a == NULL || b == NULL) {
        return 0u;
    }
    for (i = 0u; i < ROME2_VFS_MOUNT_MAX_NAME; ++i) {
        if (a[i] != b[i]) {
            return 0u;
        }
        if (a[i] == '\0') {
            return 1u;
        }
    }
    return 0u;
}

/* Matches `0x100f3040` FNV/byte-mix CAString hash reduced modulo `bucket_count`. */
static uint32_t r2_mount_hash_str(const char *s, uint32_t bucket_count) {
    uint32_t h = 2166136261u;
    size_t i;
    for (i = 0u; i < ROME2_VFS_MOUNT_MAX_NAME && s[i] != '\0'; ++i) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h % bucket_count;
}

static uint8_t r2_is_sentinel_key(
    const rome2_vfs_mount_hash_table *table,
    const char *key) {
    if (r2_mount_str_eq(key, table->sentinel_a) != 0u) {
        return 1u;
    }
    if (table->sentinel_b[0] != '\0' && r2_mount_str_eq(key, table->sentinel_b) != 0u) {
        return 1u;
    }
    return 0u;
}

static rome2_vfs_reg_status r2_hash_probe_slot(
    const rome2_vfs_mount_hash_table *table,
    const char *key,
    uint8_t *out_found,
    uint32_t *out_slot_idx) {
    uint32_t start_idx;
    uint32_t step;
    uint32_t first_empty = UINT32_MAX;

    if (table == NULL || key == NULL || out_found == NULL || out_slot_idx == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (table->bucket_count == 0u || table->bucket_count > ROME2_VFS_MOUNT_MAX_BUCKETS) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    *out_found = 0u;
    start_idx = r2_mount_hash_str(key, table->bucket_count);

    for (step = 0u; step < table->bucket_count; ++step) {
        uint32_t idx = (start_idx + step) % table->bucket_count;
        const rome2_vfs_mount_hash_slot *slot = &table->slots[idx];
        if (slot->occupied == 0u || r2_is_sentinel_key(table, slot->key) != 0u) {
            if (first_empty == UINT32_MAX) {
                first_empty = idx;
            }
            if (slot->occupied == 0u) {
                *out_slot_idx = first_empty;
                return ROME2_VFS_REG_OK;
            }
            continue;
        }
        if (r2_mount_str_eq(slot->key, key) != 0u) {
            *out_found = 1u;
            *out_slot_idx = idx;
            return ROME2_VFS_REG_OK;
        }
    }

    if (first_empty == UINT32_MAX) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_slot_idx = first_empty;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_hash_init(
    rome2_vfs_mount_hash_table *table,
    uint32_t bucket_count,
    const char *sentinel_a,
    const char *sentinel_b) {
    uint32_t i;
    rome2_vfs_reg_status st;
    if (table == NULL || sentinel_a == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (bucket_count == 0u || bucket_count > ROME2_VFS_MOUNT_MAX_BUCKETS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memset(table, 0, sizeof(*table));
    table->bucket_count = bucket_count;
    st = r2_copy_mount_str(sentinel_a, table->sentinel_a, ROME2_VFS_MOUNT_MAX_NAME);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (sentinel_b != NULL) {
        st = r2_copy_mount_str(sentinel_b, table->sentinel_b, ROME2_VFS_MOUNT_MAX_NAME);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    for (i = 0u; i < bucket_count; ++i) {
        st = r2_copy_mount_str(table->sentinel_a, table->slots[i].key, ROME2_VFS_MOUNT_MAX_NAME);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        table->slots[i].occupied = 0u;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_hash_rehash(
    rome2_vfs_mount_hash_table *table,
    uint32_t new_bucket_count) {
    rome2_vfs_mount_hash_slot saved[ROME2_VFS_MOUNT_MAX_BUCKETS];
    uint32_t old_count;
    uint32_t i;
    rome2_vfs_reg_status st;

    if (table == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (new_bucket_count == 0u || new_bucket_count > ROME2_VFS_MOUNT_MAX_BUCKETS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (table->bucket_count > ROME2_VFS_MOUNT_MAX_BUCKETS) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    old_count = table->bucket_count;
    memcpy(saved, table->slots, (size_t)old_count * sizeof(saved[0]));
    table->bucket_count = new_bucket_count;
    table->entry_count = 0u;
    for (i = 0u; i < ROME2_VFS_MOUNT_MAX_BUCKETS; ++i) {
        memset(&table->slots[i], 0, sizeof(table->slots[i]));
        if (i < new_bucket_count) {
            (void)r2_copy_mount_str(table->sentinel_a, table->slots[i].key, ROME2_VFS_MOUNT_MAX_NAME);
        }
    }

    for (i = 0u; i < old_count; ++i) {
        uint8_t inserted = 0u;
        if (saved[i].occupied == 0u || r2_is_sentinel_key(table, saved[i].key) != 0u) {
            continue;
        }
        st = rome2_vfs_mount_hash_insert_or_assign(
            table, saved[i].key, saved[i].value, 1u, &inserted);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_hash_insert_or_assign(
    rome2_vfs_mount_hash_table *table,
    const char *key,
    uint32_t value,
    uint8_t overwrite_existing,
    uint8_t *out_inserted) {
    uint8_t found = 0u;
    uint32_t idx = 0u;
    rome2_vfs_reg_status st;

    if (table == NULL || key == NULL || out_inserted == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (r2_is_sentinel_key(table, key) != 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = r2_hash_probe_slot(table, key, &found, &idx);
    if (st == ROME2_VFS_REG_RANGE_ERROR) {
        uint32_t grown = table->bucket_count * 2u + 1u;
        if (grown > ROME2_VFS_MOUNT_MAX_BUCKETS) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        st = rome2_vfs_mount_hash_rehash(table, grown);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        st = r2_hash_probe_slot(table, key, &found, &idx);
    }
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (found != 0u) {
        *out_inserted = 0u;
        if (overwrite_existing != 0u) {
            table->slots[idx].value = value;
        }
        return ROME2_VFS_REG_OK;
    }
    st = r2_copy_mount_str(key, table->slots[idx].key, ROME2_VFS_MOUNT_MAX_NAME);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    table->slots[idx].value = value;
    table->slots[idx].occupied = 1u;
    table->entry_count += 1u;
    *out_inserted = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_hash_find(
    const rome2_vfs_mount_hash_table *table,
    const char *key,
    uint8_t *out_found,
    uint32_t *out_value) {
    uint8_t found = 0u;
    uint32_t idx = 0u;
    rome2_vfs_reg_status st;

    if (table == NULL || key == NULL || out_found == NULL || out_value == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_found = 0u;
    *out_value = 0u;
    if (r2_is_sentinel_key(table, key) != 0u) {
        return ROME2_VFS_REG_OK;
    }
    st = r2_hash_probe_slot(table, key, &found, &idx);
    if (st == ROME2_VFS_REG_RANGE_ERROR) {
        return ROME2_VFS_REG_OK;
    }
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (found != 0u) {
        *out_found = 1u;
        *out_value = table->slots[idx].value;
    }
    return ROME2_VFS_REG_OK;
}

static void r2_advance_iter(rome2_vfs_mount_hash_iter *iter) {
    while (iter->index < iter->table->bucket_count) {
        const rome2_vfs_mount_hash_slot *slot = &iter->table->slots[iter->index];
        if (slot->occupied != 0u && r2_is_sentinel_key(iter->table, slot->key) == 0u) {
            iter->at_end = 0u;
            return;
        }
        iter->index += 1u;
    }
    iter->at_end = 1u;
}

rome2_vfs_reg_status rome2_vfs_mount_hash_iter_begin(
    const rome2_vfs_mount_hash_table *table,
    rome2_vfs_mount_hash_iter *iter) {
    if (table == NULL || iter == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (table->bucket_count > ROME2_VFS_MOUNT_MAX_BUCKETS) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    iter->table = table;
    iter->index = 0u;
    iter->at_end = 1u;
    r2_advance_iter(iter);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_hash_iter_next(
    rome2_vfs_mount_hash_iter *iter,
    const rome2_vfs_mount_hash_slot **out_slot) {
    if (iter == NULL || out_slot == NULL || iter->table == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (iter->at_end != 0u || iter->index >= iter->table->bucket_count) {
        *out_slot = NULL;
        iter->at_end = 1u;
        return ROME2_VFS_REG_OK;
    }
    *out_slot = &iter->table->slots[iter->index];
    iter->index += 1u;
    r2_advance_iter(iter);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_str_vec_push_back(
    rome2_vfs_mount_str_vec *vec,
    const char *str) {
    char tmp[ROME2_VFS_MOUNT_MAX_NAME];
    rome2_vfs_reg_status st;
    if (vec == NULL || str == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (vec->count >= ROME2_VFS_MOUNT_MAX_STRS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    st = r2_copy_mount_str(str, tmp, ROME2_VFS_MOUNT_MAX_NAME);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (vec->count == vec->capacity) {
        uint32_t next_cap = (vec->capacity == 0u) ? 1u : (vec->capacity * 2u);
        if (next_cap > ROME2_VFS_MOUNT_MAX_STRS) {
            next_cap = ROME2_VFS_MOUNT_MAX_STRS;
        }
        vec->capacity = next_cap;
    }
    st = r2_copy_mount_str(tmp, vec->items[vec->count], ROME2_VFS_MOUNT_MAX_NAME);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    vec->count += 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_str_vec_push_self_index(
    rome2_vfs_mount_str_vec *vec,
    uint32_t existing_index) {
    if (vec == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (vec->count > ROME2_VFS_MOUNT_MAX_STRS || existing_index >= vec->count) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    return rome2_vfs_mount_str_vec_push_back(vec, vec->items[existing_index]);
}

rome2_vfs_reg_status rome2_vfs_mount_str_vec_copy(
    rome2_vfs_mount_str_vec *dst,
    const rome2_vfs_mount_str_vec *src) {
    uint32_t i;
    if (dst == NULL || src == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (src->count > ROME2_VFS_MOUNT_MAX_STRS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (dst == src) {
        return ROME2_VFS_REG_OK;
    }
    memset(dst, 0, sizeof(*dst));
    dst->capacity = src->count;
    for (i = 0u; i < src->count; ++i) {
        rome2_vfs_reg_status st = rome2_vfs_mount_str_vec_push_back(dst, src->items[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_enum_filter_append(
    rome2_vfs_mount_str_vec *out_vec,
    uint8_t flag_0e,
    const char *dir_prefix,
    const char *entry_name,
    uint8_t *out_appended) {
    char joined[ROME2_VFS_MOUNT_MAX_NAME * 2u + 2u];
    size_t dir_len;
    size_t name_len;
    size_t total_len;
    uint8_t need_sep = 0u;

    if (out_vec == NULL || dir_prefix == NULL || entry_name == NULL || out_appended == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_appended = 0u;
    if (flag_0e == 0u) {
        return ROME2_VFS_REG_OK;
    }
    if (r2_mount_str_eq(entry_name, ".") != 0u || r2_mount_str_eq(entry_name, "..") != 0u) {
        return ROME2_VFS_REG_OK;
    }

    dir_len = strnlen(dir_prefix, ROME2_VFS_MOUNT_MAX_NAME);
    name_len = strnlen(entry_name, ROME2_VFS_MOUNT_MAX_NAME);
    if (dir_len > 0u && dir_prefix[dir_len - 1u] != '/' && dir_prefix[dir_len - 1u] != '\\' && name_len > 0u) {
        need_sep = 1u;
    }
    total_len = dir_len + (size_t)need_sep + name_len;
    if (total_len >= ROME2_VFS_MOUNT_MAX_NAME) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (dir_len > 0u) {
        memcpy(joined, dir_prefix, dir_len);
    }
    if (need_sep != 0u) {
        joined[dir_len] = '/';
    }
    if (name_len > 0u) {
        memcpy(joined + dir_len + (size_t)need_sep, entry_name, name_len);
    }
    joined[total_len] = '\0';

    {
        rome2_vfs_reg_status st = rome2_vfs_mount_str_vec_push_back(out_vec, joined);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    *out_appended = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_umap_check_rehash(
    uint32_t next_size,
    uint32_t bucket_count,
    float max_load_factor,
    uint32_t *out_next_buckets) {
    uint32_t cur_buckets;
    if (out_next_buckets == NULL || max_load_factor <= 0.0f) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (next_size > ROME2_VFS_UMAP_MAX_ELEMS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    cur_buckets = (bucket_count == 0u) ? 8u : bucket_count;
    if ((double)next_size / (double)cur_buckets > (double)max_load_factor) {
        uint64_t grown = (uint64_t)cur_buckets * 2u;
        while ((double)next_size / (double)grown > (double)max_load_factor) {
            if (grown >= (uint64_t)ROME2_VFS_UMAP_MAX_ELEMS * 2u) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            grown *= 2u;
        }
        if (grown > UINT32_MAX) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        *out_next_buckets = (uint32_t)grown;
    } else {
        *out_next_buckets = cur_buckets;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_subsystem_init(
    rome2_vfs_mount_subsystem_state *state) {
    rome2_vfs_reg_status st;
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(state, 0, sizeof(*state));
    state->umap_bucket_count = 8u;
    state->umap_max_load_factor = 1.0f;
    st = rome2_vfs_mount_hash_init(&state->hash_table, 17u, "<empty>", "");
    return st;
}

rome2_vfs_reg_status rome2_vfs_mount_subsystem_rebuild(
    rome2_vfs_mount_subsystem_state *state,
    const char *const *candidates,
    uint32_t candidate_count,
    const char *const *excluded,
    uint32_t excluded_count) {
    uint32_t i;
    if (state == NULL || (candidate_count > 0u && candidates == NULL) ||
        (excluded_count > 0u && excluded == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&state->rebuild_names, 0, sizeof(state->rebuild_names));
    for (i = 0u; i < candidate_count; ++i) {
        uint32_t j;
        uint8_t skip = 0u;
        if (candidates[i] == NULL) {
            return ROME2_VFS_REG_BAD_ARGUMENT;
        }
        for (j = 0u; j < excluded_count; ++j) {
            if (excluded[j] != NULL && r2_mount_str_eq(candidates[i], excluded[j]) != 0u) {
                skip = 1u;
                break;
            }
        }
        if (skip == 0u) {
            rome2_vfs_reg_status st = rome2_vfs_mount_str_vec_push_back(
                &state->rebuild_names, candidates[i]);
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_subsystem_flush(
    rome2_vfs_mount_subsystem_state *state) {
    uint32_t i;
    rome2_vfs_reg_status st;
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = rome2_vfs_mount_str_vec_copy(&state->flushed_names, &state->rebuild_names);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (state->rebuild_flag_1f14 == 0u) {
        return ROME2_VFS_REG_OK;
    }
    for (i = 0u; i < state->flushed_names.count; ++i) {
        uint8_t inserted = 0u;
        st = rome2_vfs_mount_hash_insert_or_assign(
            &state->hash_table, state->flushed_names.items[i], i + 1u, 1u, &inserted);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_subsystem_teardown(
    rome2_vfs_mount_subsystem_state *state,
    rome2_vfs_worker_wait_fn wait_fn,
    void *wait_ctx) {
    uint32_t i;
    rome2_vfs_reg_status st;
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (state->worker_valid_2b34 != 0u && state->worker_handle_2b30 != 0u && wait_fn != NULL) {
        if (wait_fn(state->worker_handle_2b30, ROME2_VFS_WAIT_INFINITE, wait_ctx) == 0u) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        state->worker_waits_completed += 1u;
    }
    state->vfs_active_1a88 = 0u;
    for (i = 0u; i < ROME2_VFS_TEARDOWN_CACHED_PTRS; ++i) {
        state->cached_slot_occupied[i] = 0u;
        state->cached_slot_names[i][0] = '\0';
    }
    memset(&state->rebuild_names, 0, sizeof(state->rebuild_names));
    memset(&state->flushed_names, 0, sizeof(state->flushed_names));
    state->mount_entry_count = 0u;
    st = rome2_vfs_mount_hash_init(
        &state->hash_table, state->hash_table.bucket_count ? state->hash_table.bucket_count : 17u,
        "<empty>", "");
    return st;
}

rome2_vfs_reg_status rome2_vfs_mount_probe_startpos_cmdline(
    rome2_vfs_mount_subsystem_state *state,
    const char *cmdline,
    uint8_t *out_match) {
    static const char needle[] = "process_campaign_startpos";
    if (state == NULL || out_match == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (state->cmdline_checked_5150 != 0u) {
        *out_match = state->cmdline_match_5151;
        return ROME2_VFS_REG_OK;
    }
    if (cmdline != NULL && strstr(cmdline, needle) != NULL) {
        state->cmdline_match_5151 = 1u;
    } else {
        state->cmdline_match_5151 = 0u;
    }
    state->cmdline_checked_5150 = 1u;
    *out_match = state->cmdline_match_5151;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_mount_probe_platform_cap(
    rome2_vfs_mount_subsystem_state *state,
    uint8_t hardware_probe_result,
    uint8_t *out_enabled) {
    if (state == NULL || out_enabled == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (state->cap_once_done_2afc == 0u) {
        state->cap_cached_2af8 = (state->cap_enable_25e0 == 1u) ? hardware_probe_result : 1u;
        state->cap_once_done_2afc = 1u;
    }
    *out_enabled = state->cap_cached_2af8;
    return ROME2_VFS_REG_OK;
}
