#include "vfs_fs_primary_ops.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

static rome2_vfs_reg_status r2_copy_bounded_str(
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

static uint8_t r2_str_eq_bounded(const char *a, const char *b) {
    size_t i;
    if (a == NULL || b == NULL) {
        return 0u;
    }
    for (i = 0u; i < ROME2_VFS_PRIMARY_MAX_NAME; ++i) {
        if (a[i] != b[i]) {
            return 0u;
        }
        if (a[i] == '\0') {
            return 1u;
        }
    }
    return 0u;
}

static rome2_vfs_primary_entry_record *r2_find_entry_mut(
    rome2_vfs_primary_fs_state *state,
    const char *path) {
    uint32_t i;
    if (state == NULL || path == NULL) {
        return NULL;
    }
    for (i = 0u; i < state->entry_count; ++i) {
        if (state->entries[i].occupied != 0u && r2_str_eq_bounded(state->entries[i].path, path) != 0u) {
            return &state->entries[i];
        }
    }
    return NULL;
}

static const rome2_vfs_primary_entry_record *r2_find_entry_const(
    const rome2_vfs_primary_fs_state *state,
    const char *path) {
    uint32_t i;
    if (state == NULL || path == NULL) {
        return NULL;
    }
    for (i = 0u; i < state->entry_count; ++i) {
        if (state->entries[i].occupied != 0u && r2_str_eq_bounded(state->entries[i].path, path) != 0u) {
            return &state->entries[i];
        }
    }
    return NULL;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_state_init(rome2_vfs_primary_fs_state *state) {
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(state, 0, sizeof(*state));
    state->next_dynamic_id = ROME2_VFS_DYNAMIC_ID_SEED;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_vec_grow_capacity(
    uint32_t current_cap,
    uint32_t *out_next_cap) {
    uint64_t doubled;
    if (out_next_cap == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_next_cap = 0u;
    if (current_cap == 0u) {
        *out_next_cap = 1u;
        return ROME2_VFS_REG_OK;
    }
    doubled = (uint64_t)current_cap * 2u;
    /* `0x100eb330` clamps negative signed counts (`cmovs eax, ecx`) before `* 12`; keep byte size <= UINT32_MAX. */
    if (doubled > (uint64_t)(UINT32_MAX / 12u)) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    *out_next_cap = (uint32_t)doubled;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_add_active_root(
    rome2_vfs_primary_fs_state *state,
    const char *root_path) {
    rome2_vfs_reg_status status;
    uint32_t next_cap;
    if (state == NULL || root_path == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (state->active_root_count >= ROME2_VFS_PRIMARY_MAX_ROOTS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (state->active_root_count >= state->active_root_cap) {
        next_cap = state->active_root_cap;
        status = rome2_vfs_fs_primary_vec_grow_capacity(next_cap, &next_cap);
        if (status != ROME2_VFS_REG_OK) {
            return status;
        }
        state->active_root_cap = next_cap;
    }
    status = r2_copy_bounded_str(
        root_path,
        state->active_roots[state->active_root_count],
        ROME2_VFS_PRIMARY_MAX_NAME);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }
    state->active_root_count += 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_add_archive_root(
    rome2_vfs_primary_fs_state *state,
    const char *root_path) {
    rome2_vfs_reg_status status;
    if (state == NULL || root_path == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (state->archive_root_count >= ROME2_VFS_PRIMARY_MAX_ROOTS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    status = r2_copy_bounded_str(
        root_path,
        state->archive_roots[state->archive_root_count],
        ROME2_VFS_PRIMARY_MAX_NAME);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }
    state->archive_root_count += 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_seed_entry(
    rome2_vfs_primary_fs_state *state,
    const char *path,
    uint32_t size_lo,
    uint32_t size_hi,
    uint8_t in_pack,
    uint8_t in_loose,
    uint8_t flag_1c) {
    rome2_vfs_primary_entry_record *existing;
    rome2_vfs_reg_status status;
    if (state == NULL || path == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    existing = r2_find_entry_mut(state, path);
    if (existing == NULL) {
        if (state->entry_count >= ROME2_VFS_PRIMARY_MAX_ENTRIES) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        existing = &state->entries[state->entry_count];
        memset(existing, 0, sizeof(*existing));
        status = r2_copy_bounded_str(path, existing->path, ROME2_VFS_PRIMARY_MAX_NAME);
        if (status != ROME2_VFS_REG_OK) {
            return status;
        }
        existing->occupied = 1u;
        state->entry_count += 1u;
    }
    existing->size_lo = size_lo;
    existing->size_hi = size_hi;
    existing->in_pack = in_pack ? 1u : 0u;
    existing->in_loose = in_loose ? 1u : 0u;
    existing->flag_1c = flag_1c ? 1u : 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_filter_active_roots(
    rome2_vfs_primary_fs_state *state,
    const char *const *excluded_roots,
    uint32_t excluded_count) {
    uint32_t i;
    uint32_t j;
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (excluded_count > ROME2_VFS_PRIMARY_MAX_EXCLUDED ||
        (excluded_count > 0u && excluded_roots == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (j = 0u; j < excluded_count; ++j) {
        if (excluded_roots[j] == NULL) {
            return ROME2_VFS_REG_BAD_ARGUMENT;
        }
    }
    /* `0x112e36f0` clears `0x119e11b8` count to 0 before iterating `0x119e11e8`. */
    state->active_root_count = 0u;
    if (state->archive_root_count == 0u) {
        return ROME2_VFS_REG_OK;
    }
    for (i = 0u; i < state->archive_root_count; ++i) {
        uint8_t excluded = 0u;
        for (j = 0u; j < excluded_count; ++j) {
            if (r2_str_eq_bounded(state->archive_roots[i], excluded_roots[j]) != 0u) {
                excluded = 1u;
                break;
            }
        }
        if (excluded == 0u) {
            rome2_vfs_reg_status status = rome2_vfs_fs_primary_add_active_root(
                state,
                state->archive_roots[i]);
            if (status != ROME2_VFS_REG_OK) {
                return status;
            }
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_copy_pending_roots(
    rome2_vfs_primary_fs_state *state,
    char out_paths[][ROME2_VFS_PRIMARY_MAX_NAME],
    uint32_t out_capacity,
    uint32_t *out_copied) {
    uint32_t i;
    if (state == NULL || out_copied == NULL || (out_capacity > 0u && out_paths == NULL)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_copied = 0u;
    if (state->pending_root_count > out_capacity) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (i = 0u; i < state->pending_root_count; ++i) {
        rome2_vfs_reg_status status = r2_copy_bounded_str(
            state->pending_roots[i],
            out_paths[i],
            ROME2_VFS_PRIMARY_MAX_NAME);
        if (status != ROME2_VFS_REG_OK) {
            return status;
        }
    }
    *out_copied = state->pending_root_count;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_get_entry_at_clamped(
    const rome2_vfs_primary_fs_state *state,
    uint32_t index,
    char *out_path,
    uint32_t out_path_cap,
    uint8_t *out_found) {
    uint32_t clamped;
    if (state == NULL || out_path == NULL || out_path_cap == 0u || out_found == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_found = 0u;
    out_path[0] = '\0';
    if (state->entry_count == 0u) {
        return ROME2_VFS_REG_OK;
    }
    clamped = index >= state->entry_count ? (state->entry_count - 1u) : index;
    *out_found = 1u;
    return r2_copy_bounded_str(state->entries[clamped].path, out_path, out_path_cap);
}

rome2_vfs_reg_status rome2_vfs_fs_primary_entry_exists(
    const rome2_vfs_primary_fs_state *state,
    const char *path,
    uint8_t *out_exists) {
    const rome2_vfs_primary_entry_record *rec;
    if (state == NULL || path == NULL || out_exists == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    rec = r2_find_entry_const(state, path);
    *out_exists = (rec != NULL && (rec->in_pack != 0u || rec->in_loose != 0u)) ? 1u : 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_get_entry_size(
    const rome2_vfs_primary_fs_state *state,
    const char *path,
    uint32_t *out_size_or_sentinel) {
    const rome2_vfs_primary_entry_record *rec;
    if (state == NULL || path == NULL || out_size_or_sentinel == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    rec = r2_find_entry_const(state, path);
    *out_size_or_sentinel = (rec != NULL) ? rec->size_lo : ROME2_VFS_SENTINEL_U32;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_set_override_path(
    rome2_vfs_primary_fs_state *state,
    const char *override_path) {
    rome2_vfs_reg_status status;
    if (state == NULL || override_path == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    status = r2_copy_bounded_str(override_path, state->override_path, ROME2_VFS_PRIMARY_MAX_NAME);
    if (status != ROME2_VFS_REG_OK) {
        return status;
    }
    state->override_active = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_set_flag_1a8a(
    rome2_vfs_primary_fs_state *state,
    uint8_t value) {
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    state->flag_1a8a = value ? 1u : 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_set_val_1ad8(
    rome2_vfs_primary_fs_state *state,
    uint32_t value) {
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    state->val_1ad8 = value;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_destroy_subfs(rome2_vfs_primary_fs_state *state) {
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    state->sub_fs_mounted = 0u;
    state->sub_fs_mode = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_dtor(rome2_vfs_primary_fs_state *state) {
    if (state == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    state->sub_fs_mounted = 0u;
    state->sub_fs_mode = 0u;
    state->active_ops = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_query_entry_info(
    rome2_vfs_primary_fs_state *state,
    const char *path,
    rome2_vfs_entry_info32 *out_info,
    char *out_name,
    uint32_t out_name_cap) {
    const rome2_vfs_primary_entry_record *rec;
    rome2_vfs_reg_status status;
    if (state == NULL || path == NULL || out_info == NULL || out_name == NULL || out_name_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(out_info, 0, sizeof(*out_info));
    out_info->size_lo_00 = ROME2_VFS_SENTINEL_U32;
    out_info->size_hi_04 = ROME2_VFS_SENTINEL_U32;
    out_name[0] = '\0';

    if (state->vfs_initialized == 0u) {
        return ROME2_VFS_REG_OK;
    }
    state->active_ops += 1u;
    rec = r2_find_entry_const(state, path);
    if (rec != NULL) {
        out_info->size_lo_00 = rec->size_lo;
        out_info->size_hi_04 = rec->size_hi;
        out_info->flag_1c = rec->flag_1c;
        status = r2_copy_bounded_str(rec->path, out_name, out_name_cap);
        state->active_ops -= 1u;
        return status;
    }
    state->active_ops -= 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_register_or_get_id(
    rome2_vfs_primary_fs_state *state,
    const char *path,
    uint32_t *out_id) {
    rome2_vfs_primary_entry_record *rec;
    if (state == NULL || path == NULL || out_id == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_id = ROME2_VFS_SENTINEL_U32;
    if (state->vfs_initialized == 0u) {
        return ROME2_VFS_REG_OK;
    }
    state->active_ops += 1u;
    rec = r2_find_entry_mut(state, path);
    if (rec == NULL) {
        state->active_ops -= 1u;
        return ROME2_VFS_REG_OK;
    }
    if (rec->dynamic_id != 0u) {
        *out_id = rec->dynamic_id;
        state->active_ops -= 1u;
        return ROME2_VFS_REG_OK;
    }
    if (rec->in_pack == 0u && rec->in_loose == 0u) {
        state->active_ops -= 1u;
        return ROME2_VFS_REG_OK;
    }
    if (state->next_dynamic_id == UINT32_MAX) {
        state->active_ops -= 1u;
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    rec->dynamic_id = state->next_dynamic_id;
    state->next_dynamic_id += 1u;
    *out_id = rec->dynamic_id;
    state->active_ops -= 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_fs_primary_mount_subfs_and_register(
    rome2_vfs_primary_fs_state *state,
    const char *path,
    uint8_t create_subfs,
    uint8_t subfs_mode_value,
    uint8_t *out_result) {
    rome2_vfs_primary_entry_record *rec;
    if (state == NULL || path == NULL || out_result == NULL) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_result = 0u;
    state->active_ops += 1u;
    if (create_subfs != 0u) {
        if (state->sub_fs_mounted == 0u) {
            state->sub_fs_mounted = 1u;
            state->sub_fs_mode = subfs_mode_value ? 1u : 0u;
        }
        if (state->sub_fs_mode != 0u) {
            /* `0x112c0121..0x112c014c`: checks whether already indexed, returns `setne bl`. */
            rec = r2_find_entry_mut(state, path);
            *out_result = (rec != NULL && rec->dynamic_id != 0u) ? 1u : 0u;
            state->active_ops -= 1u;
            return ROME2_VFS_REG_OK;
        }
    }
    rec = r2_find_entry_mut(state, path);
    if (rec == NULL) {
        /* Not registered in archive-name/loose index unless present and valid. */
        state->active_ops -= 1u;
        return ROME2_VFS_REG_OK;
    }
    if (rec->dynamic_id != 0u) {
        *out_result = 1u;
        state->active_ops -= 1u;
        return ROME2_VFS_REG_OK;
    }
    if (rec->in_loose != 0u || rec->in_pack != 0u) {
        if (state->next_dynamic_id == UINT32_MAX) {
            state->active_ops -= 1u;
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        rec->dynamic_id = state->next_dynamic_id;
        state->next_dynamic_id += 1u;
        *out_result = 1u;
        state->active_ops -= 1u;
        return ROME2_VFS_REG_OK;
    }
    state->active_ops -= 1u;
    return ROME2_VFS_REG_OK;
}
