#include "vfs_fs_init_xml_pack_ops.h"

#include <stdio.h>
#include <string.h>

static char vfs32_ascii_lower(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return (char)(ch + 0x20);
    }
    return ch;
}

static rome2_vfs_reg_status vfs32_copy_str(char *dst, uint32_t dst_cap, const char *src) {
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

static rome2_vfs_reg_status vfs32_append_str(char *dst, uint32_t dst_cap, const char *suffix) {
    size_t cur;
    size_t add;
    if (!dst || dst_cap == 0u || !suffix) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    cur = strlen(dst);
    add = strlen(suffix);
    if (cur >= (size_t)dst_cap || add >= (size_t)dst_cap - cur) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memcpy(dst + cur, suffix, add + 1u);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_pack_index_bootstrap(
    rome2_vfs_pack_index_table *table,
    const char *cwd,
    uint8_t has_boot_pack,
    uint8_t *out_retail_mode) {
    static const char *const k_dev_suffixes[6] = {
        "\\working_data_rome2\\",
        "\\working_data\\",
        "\\..\\..\\..\\common\\data\\working_data\\",
        "\\old_working_data\\",
        "\\editor_working_data\\",
        "\\raw_data\\empiredesigndata\\",
    };
    uint32_t i;

    if (!table || !cwd || !out_retail_mode) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    table->count = 0u;
    if (has_boot_pack != 0u) {
        *out_retail_mode = 1u;
        if (rome2_vfs_cstr_join_c(cwd, "\\data\\", table->entries[0], ROME2_VFS_IDX_MAX_PATH) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        table->count = 1u;
        return ROME2_VFS_REG_OK;
    }

    *out_retail_mode = 0u;
    for (i = 0u; i < 6u; ++i) {
        const char *suf = (i == 2u) ? "\\common\\data\\working_data\\" : k_dev_suffixes[i];
        if (i >= ROME2_VFS_IDX_MAX_PREFIXES) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (rome2_vfs_cstr_join_c(cwd, suf, table->entries[i], ROME2_VFS_IDX_MAX_PATH) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        table->count += 1u;
    }
    return ROME2_VFS_REG_OK;
}

const char *rome2_vfs_intern_path(
    rome2_vfs_path_intern_env *env,
    const char *path,
    uint8_t preserve_case) {
    char normalized[ROME2_VFS_IDX_MAX_PATH];
    size_t len;
    size_t k;
    uint32_t i;

    if (!env || !path) {
        return NULL;
    }
    if (!env->empty_ready) {
        vfs32_copy_str(env->empty_name, sizeof(env->empty_name), "<empty_file_name>");
        env->empty_ready = 1u;
    }
    if (path[0] == '\0') {
        return env->empty_name;
    }

    if (!env->lock_ready) {
        env->lock_spin_count = ROME2_VFS_L32_CRIT_SPIN;
        env->lock_ready = 1u;
    }
    env->lock_depth += 1u;
    if (env->lock_depth > env->max_lock_depth) {
        env->max_lock_depth = env->lock_depth;
    }

    if (!env->table_ready) {
        env->table_mask = 7u;
        env->table_buckets = 8u;
        env->max_load_factor = 1.0f;
        env->table_ready = 1u;
    }

    len = strlen(path);
    if (len >= sizeof(normalized)) {
        env->lock_depth -= 1u;
        return NULL;
    }
    for (k = 0u; k < len; ++k) {
        char c = path[k] == '/' ? '\\' : path[k];
        normalized[k] = (preserve_case == 0u) ? vfs32_ascii_lower(c) : c;
    }
    normalized[len] = '\0';

    for (i = 0u; i < env->count && i < ROME2_VFS_L32_MAX_INTERN; ++i) {
        if (env->entries[i].active != 0u && strcmp(env->entries[i].value, normalized) == 0) {
            env->lock_depth -= 1u;
            return env->entries[i].value;
        }
    }
    if (env->count >= ROME2_VFS_L32_MAX_INTERN) {
        env->lock_depth -= 1u;
        return NULL;
    }
    i = env->count;
    env->entries[i].active = 1u;
    memcpy(env->entries[i].value, normalized, len + 1u);
    env->count += 1u;
    env->lock_depth -= 1u;
    return env->entries[i].value;
}

uint32_t rome2_vfs_map_handle_status(uint32_t handle_val) {
    return handle_val == ROME2_VFS_L32_INVALID_HANDLE ? ROME2_VFS_L32_ERR_INVALID_HANDLE : 0u;
}

uint32_t rome2_vfs_cstr_find(const char *haystack, const char *needle, uint32_t start_pos) {
    size_t hlen;
    size_t nlen;
    size_t i;

    if (!haystack || !needle) {
        return ROME2_VFS_L32_INVALID_HANDLE;
    }
    hlen = strlen(haystack);
    nlen = strlen(needle);
    if ((size_t)start_pos > hlen) {
        start_pos = (uint32_t)hlen;
    }
    if (hlen - (size_t)start_pos < nlen) {
        return ROME2_VFS_L32_INVALID_HANDLE;
    }
    for (i = (size_t)start_pos; i <= hlen - nlen; ++i) {
        if (memcmp(haystack + i, needle, nlen) == 0) {
            return (uint32_t)i;
        }
    }
    return ROME2_VFS_L32_INVALID_HANDLE;
}

int32_t rome2_vfs_cstr_compare_sub(
    const char *lhs,
    uint32_t pos,
    uint32_t len,
    const char *rhs) {
    size_t llen;
    size_t rlen;
    size_t avail;
    size_t cmp_len;
    int diff;

    if (!lhs || !rhs) {
        return 0;
    }
    llen = strlen(lhs);
    if ((size_t)pos > llen) {
        pos = (uint32_t)llen;
    }
    avail = llen - (size_t)pos;
    if ((size_t)len > avail) {
        len = (uint32_t)avail;
    }
    rlen = strlen(rhs);
    cmp_len = ((size_t)len < rlen) ? (size_t)len : rlen;
    diff = (cmp_len > 0u) ? memcmp(lhs + pos, rhs, cmp_len) : 0;
    if (diff != 0) {
        return diff < 0 ? -1 : 1;
    }
    if ((size_t)len < rlen) {
        return -1;
    }
    if ((size_t)len > rlen) {
        return 1;
    }
    return 0;
}

char rome2_vfs_cstr_at_or_nul(const char *s, uint32_t index) {
    size_t len;
    if (!s) {
        return '\0';
    }
    len = strlen(s);
    return (size_t)index < len ? s[index] : '\0';
}

rome2_vfs_reg_status rome2_vfs_cstr_join_c(
    const char *prefix,
    const char *suffix,
    char *out_buf,
    uint32_t out_cap) {
    rome2_vfs_reg_status st;
    if (!prefix || !suffix || !out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = vfs32_copy_str(out_buf, out_cap, prefix);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    return vfs32_append_str(out_buf, out_cap, suffix);
}

uint8_t rome2_vfs_os_handle_close(
    rome2_vfs_os_handle_box *box,
    uint8_t sim_close_ok,
    uint32_t sim_err) {
    if (!box || box->handle == ROME2_VFS_L32_INVALID_HANDLE) {
        return 0u;
    }
    box->handle = ROME2_VFS_L32_INVALID_HANDLE;
    box->last_error = (sim_close_ok != 0u) ? 0u : sim_err;
    return box->last_error == 0u ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_format_mod_banner(
    const char *const *mods,
    uint32_t mod_count,
    char *out_buf,
    uint32_t out_cap) {
    uint32_t i;
    rome2_vfs_reg_status st;

    if (!out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (mod_count == 0u || !mods) {
        return vfs32_copy_str(out_buf, out_cap, "no mods");
    }
    st = vfs32_copy_str(out_buf, out_cap, "mods: ");
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    for (i = 0u; i < mod_count; ++i) {
        if (!mods[i]) {
            return ROME2_VFS_REG_BAD_ARGUMENT;
        }
        if (i > 0u) {
            st = vfs32_append_str(out_buf, out_cap, ", ");
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
        }
        st = vfs32_append_str(out_buf, out_cap, mods[i]);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    return ROME2_VFS_REG_OK;
}

void rome2_vfs_get_static_key_c2190(uint32_t out_tag[4]) {
    if (!out_tag) {
        return;
    }
    /* Exact 16B constant at `0x1189a640` copied to `0x12032b3c` in `0x112c2190`. */
    out_tag[0] = 0u;
    out_tag[1] = 0u;
    out_tag[2] = 0u;
    out_tag[3] = 0x030dc5c8u;
}

void rome2_vfs_get_static_key_c21f0(uint32_t out_tag[4]) {
    if (!out_tag) {
        return;
    }
    /* Exact 16B constant at `0x1189a630` copied to `0x12032b50` in `0x112c21f0`. */
    out_tag[0] = 0u;
    out_tag[1] = 0u;
    out_tag[2] = 0u;
    out_tag[3] = 0x030dc5c5u;
}

uint8_t rome2_vfs_thread_budget_try_consume(
    rome2_vfs_thread_budget_state *state,
    uint32_t add_bytes,
    uint8_t key_matched) {
    if (!state || state->global_enabled == 0u || state->thread_active == 0u) {
        return 0u;
    }
    if (state->cur_thread_id != state->owner_thread_id) {
        return 0u;
    }
    if (state->chunk_used_count >= state->chunk_cap_count) {
        return 0u;
    }
    if (add_bytes > state->byte_cap || state->byte_used > state->byte_cap - add_bytes) {
        return 0u;
    }
    if (key_matched == 0u) {
        return 0u;
    }
    state->byte_used += add_bytes;
    state->chunk_used_count += 1u;
    return 1u;
}

rome2_vfs_reg_status rome2_vfs_hash12_emplace(
    rome2_vfs_hash12_map *map,
    const char *key,
    uint32_t value,
    uint8_t *out_inserted) {
    uint32_t i;
    float load;

    if (!map || !key || !out_inserted) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (map->bucket_count == 0u) {
        map->bucket_count = 8u;
    }
    if (map->max_load_factor <= 0.0f) {
        map->max_load_factor = 1.0f;
    }
    for (i = 0u; i < ROME2_VFS_L32_MAX_BUCKETS; ++i) {
        if (map->slots[i].occupied != 0u && strcmp(map->slots[i].key, key) == 0) {
            *out_inserted = 0u;
            return ROME2_VFS_REG_OK;
        }
    }
    for (i = 0u; i < ROME2_VFS_L32_MAX_BUCKETS; ++i) {
        if (map->slots[i].occupied == 0u) {
            rome2_vfs_reg_status st = vfs32_copy_str(
                map->slots[i].key, ROME2_VFS_L32_MAX_NAME, key);
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
            map->slots[i].occupied = 1u;
            map->slots[i].value = value;
            map->size += 1u;
            load = (float)map->size / (float)map->bucket_count;
            if (load > map->max_load_factor) {
                map->bucket_count = map->bucket_count * 2u + 1u;
                map->rehash_count += 1u;
            }
            *out_inserted = 1u;
            return ROME2_VFS_REG_OK;
        }
    }
    return ROME2_VFS_REG_RANGE_ERROR;
}

rome2_vfs_xml_save_outcome rome2_vfs_xml_save_classify(
    uint32_t type_code,
    uint8_t helper_112e4050_ok,
    uint32_t *out_normalized_type,
    char *out_problem_prefix,
    uint32_t out_cap) {
    if (type_code == 0x29u || type_code == 0x28u || type_code == 0x18u || type_code == 0x19u) {
        if (out_normalized_type) {
            *out_normalized_type = 0x1cu;
        }
        return ROME2_VFS_XML_SAVE_NORMALIZED_1C;
    }
    if (type_code == 0x1f6u) {
        if (out_normalized_type) {
            *out_normalized_type = 0x1f6u;
        }
        if (helper_112e4050_ok != 0u) {
            return ROME2_VFS_XML_SAVE_TYPE_1F6_OK;
        }
        if (out_problem_prefix && out_cap > 0u) {
            vfs32_copy_str(out_problem_prefix, out_cap, "Problem saving type in XML with ");
        }
        return ROME2_VFS_XML_SAVE_TYPE_1F6_PROBLEM;
    }
    if (type_code >= 1u && (type_code - 1u) <= 0x5eu) {
        if (out_normalized_type) {
            *out_normalized_type = type_code;
        }
        return ROME2_VFS_XML_SAVE_SWITCH;
    }
    if (out_normalized_type) {
        *out_normalized_type = type_code;
    }
    return ROME2_VFS_XML_SAVE_FALLBACK;
}
