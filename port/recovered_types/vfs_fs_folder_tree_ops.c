#include "vfs_fs_folder_tree_ops.h"

#include <string.h>

static rome2_vfs_reg_status vfs33_copy_str(char *dst, uint32_t dst_cap, const char *src) {
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

rome2_vfs_reg_status rome2_vfs_folder_forest_add_node(
    rome2_vfs_folder_forest *forest,
    int32_t parent_idx,
    const char *name,
    const char *root,
    const char *tag,
    int32_t *out_idx) {
    int32_t idx;
    rome2_vfs_folder_node60 *node;

    if (!forest || !name || !root || !tag || !out_idx) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (forest->count >= ROME2_VFS_L33_MAX_FOLDERS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (parent_idx >= 0) {
        if ((uint32_t)parent_idx >= forest->count || forest->nodes[parent_idx].active == 0u) {
            return ROME2_VFS_REG_BAD_ARGUMENT;
        }
    }

    idx = (int32_t)forest->count;
    node = &forest->nodes[idx];
    memset(node, 0, sizeof(*node));
    if (vfs33_copy_str(node->name, sizeof(node->name), name) != ROME2_VFS_REG_OK ||
        vfs33_copy_str(node->root, sizeof(node->root), root) != ROME2_VFS_REG_OK ||
        vfs33_copy_str(node->tag, sizeof(node->tag), tag) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    node->active = 1u;
    node->first_child = -1;
    node->next_sibling = -1;
    forest->count += 1u;

    if (parent_idx >= 0) {
        node->next_sibling = forest->nodes[parent_idx].first_child;
        forest->nodes[parent_idx].first_child = idx;
    }
    *out_idx = idx;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_folder_add_kv_pair(
    rome2_vfs_folder_forest *forest,
    int32_t folder_idx,
    const char *key,
    const char *value) {
    rome2_vfs_folder_node60 *node;
    uint32_t new_cap;

    if (!forest || !key || !value || folder_idx < 0 || (uint32_t)folder_idx >= forest->count) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    node = &forest->nodes[folder_idx];
    if (node->active == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    if (node->pair_count >= ROME2_VFS_L33_MAX_PAIRS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    /* Match `0x10127900`: zero capacity grows directly to 8, otherwise doubles. */
    if (node->pair_count >= node->pair_capacity) {
        new_cap = (node->pair_capacity == 0u) ? 8u : node->pair_capacity * 2u;
        if (new_cap > ROME2_VFS_L33_MAX_PAIRS) {
            new_cap = ROME2_VFS_L33_MAX_PAIRS;
        }
        node->pair_capacity = new_cap;
    }
    if (vfs33_copy_str(node->pairs[node->pair_count].key, sizeof(node->pairs[0].key), key) != ROME2_VFS_REG_OK ||
        vfs33_copy_str(node->pairs[node->pair_count].value, sizeof(node->pairs[0].value), value) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    node->pair_count += 1u;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status vfs33_clone_depth(
    const rome2_vfs_folder_forest *src,
    int32_t src_idx,
    rome2_vfs_folder_forest *dst,
    int32_t dst_parent_idx,
    uint32_t depth,
    int32_t *out_new_idx) {
    const rome2_vfs_folder_node60 *snode;
    int32_t child;
    int32_t created = -1;
    uint32_t i;
    rome2_vfs_reg_status st;

    if (!src || !dst || !out_new_idx || src_idx < 0 || (uint32_t)src_idx >= src->count) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (depth >= ROME2_VFS_L33_MAX_FOLDERS) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    snode = &src->nodes[src_idx];
    if (snode->active == 0u) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    st = rome2_vfs_folder_forest_add_node(dst, dst_parent_idx, snode->name, snode->root, snode->tag, &created);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    for (i = 0u; i < snode->pair_count && i < ROME2_VFS_L33_MAX_PAIRS; ++i) {
        st = rome2_vfs_folder_add_kv_pair(dst, created, snode->pairs[i].key, snode->pairs[i].value);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
    }
    child = snode->first_child;
    while (child >= 0) {
        int32_t ignored = -1;
        if ((uint32_t)child >= src->count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        st = vfs33_clone_depth(src, child, dst, created, depth + 1u, &ignored);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        child = src->nodes[child].next_sibling;
    }
    *out_new_idx = created;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_folder_clone_subtree(
    const rome2_vfs_folder_forest *src,
    int32_t src_idx,
    rome2_vfs_folder_forest *dst,
    int32_t dst_parent_idx,
    int32_t *out_new_idx) {
    return vfs33_clone_depth(src, src_idx, dst, dst_parent_idx, 0u, out_new_idx);
}

static rome2_vfs_reg_status vfs33_destroy_depth(
    rome2_vfs_folder_forest *forest,
    int32_t folder_idx,
    uint32_t depth,
    uint32_t *out_destroyed_folders,
    uint32_t *out_destroyed_pairs) {
    int32_t child;
    rome2_vfs_folder_node60 *node;

    if (!forest || !out_destroyed_folders || !out_destroyed_pairs || folder_idx < 0 || (uint32_t)folder_idx >= forest->count) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (depth >= ROME2_VFS_L33_MAX_FOLDERS) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    node = &forest->nodes[folder_idx];
    if (node->active == 0u) {
        return ROME2_VFS_REG_OK;
    }
    child = node->first_child;
    while (child >= 0) {
        int32_t next;
        if ((uint32_t)child >= forest->count) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        next = forest->nodes[child].next_sibling;
        {
            rome2_vfs_reg_status st = vfs33_destroy_depth(
                forest, child, depth + 1u, out_destroyed_folders, out_destroyed_pairs);
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
        }
        child = next;
    }
    *out_destroyed_pairs += node->pair_count;
    node->pair_count = 0u;
    node->first_child = -1;
    node->active = 0u;
    *out_destroyed_folders += 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_folder_destroy_subtree(
    rome2_vfs_folder_forest *forest,
    int32_t folder_idx,
    uint32_t *out_destroyed_folders,
    uint32_t *out_destroyed_pairs) {
    if (!out_destroyed_folders || !out_destroyed_pairs) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_destroyed_folders = 0u;
    *out_destroyed_pairs = 0u;
    return vfs33_destroy_depth(forest, folder_idx, 0u, out_destroyed_folders, out_destroyed_pairs);
}

rome2_vfs_reg_status rome2_vfs_parse_tab_kv_lines(
    rome2_vfs_folder_forest *forest,
    int32_t folder_idx,
    const char *text) {
    const char *p;
    char key[64];
    char val[128];

    if (!forest || !text) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    p = text;
    while (*p != '\0') {
        size_t klen = 0u;
        size_t vlen = 0u;
        while (*p == '\t' || *p == '\n' || *p == '\r') {
            ++p;
        }
        if (*p == '\0') {
            break;
        }
        while (*p != '\0' && *p != '\t' && *p != '\n' && *p != '\r') {
            if (klen + 1u >= sizeof(key)) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            key[klen++] = *p++;
        }
        key[klen] = '\0';
        while (*p == '\t') {
            ++p;
        }
        while (*p != '\0' && *p != '\t' && *p != '\n' && *p != '\r') {
            if (vlen + 1u >= sizeof(val)) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            val[vlen++] = *p++;
        }
        val[vlen] = '\0';
        {
            rome2_vfs_reg_status st = rome2_vfs_folder_add_kv_pair(forest, folder_idx, key, val);
            if (st != ROME2_VFS_REG_OK) {
                return st;
            }
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_strip_data_prefix(
    const char *in_path,
    char *out_path,
    uint32_t out_cap,
    uint8_t *out_stripped) {
    uint32_t pos;
    if (!in_path || !out_path || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    pos = rome2_vfs_cstr_find(in_path, "data\\", 0u);
    if (pos != ROME2_VFS_L32_INVALID_HANDLE && pos <= 3u) {
        if (out_stripped) {
            *out_stripped = 1u;
        }
        return vfs33_copy_str(out_path, out_cap, in_path + pos + 5u);
    }
    if (out_stripped) {
        *out_stripped = 0u;
    }
    return vfs33_copy_str(out_path, out_cap, in_path);
}

rome2_vfs_reg_status rome2_vfs_normalize_dot_segments(
    const char *in_path,
    uint8_t single_dot_only,
    char *out_path,
    uint32_t out_cap,
    uint8_t *out_changed) {
    char work[ROME2_VFS_IDX_MAX_PATH * 2u];
    const char *needle = single_dot_only != 0u ? ".\\" : "..\\";
    size_t needle_len = strlen(needle);
    uint8_t changed = 0u;
    uint32_t pos;

    if (!in_path || !out_path || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (vfs33_copy_str(work, sizeof(work), in_path) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    while ((pos = rome2_vfs_cstr_find(work, needle, 0u)) != ROME2_VFS_L32_INVALID_HANDLE) {
        changed = 1u;
        if (single_dot_only != 0u || pos == 0u) {
            size_t tail_len = strlen(work + pos + needle_len);
            memmove(work + pos, work + pos + needle_len, tail_len + 1u);
        } else {
            uint32_t scan = pos - 1u;
            uint32_t cut_start = 0u;
            if (scan > 0u && work[scan] == '\\') {
                scan -= 1u;
            }
            while (scan > 0u) {
                if (work[scan] == '\\') {
                    cut_start = scan + 1u;
                    break;
                }
                scan -= 1u;
            }
            {
                size_t tail_len = strlen(work + pos + needle_len);
                memmove(work + cut_start, work + pos + needle_len, tail_len + 1u);
            }
        }
    }
    if (out_changed) {
        *out_changed = changed;
    }
    return vfs33_copy_str(out_path, out_cap, work);
}

rome2_vfs_reg_status rome2_vfs_split_path_parts48(
    const char *full_path,
    rome2_vfs_split_path48 *out_parts) {
    const char *last_sep;
    const char *slash1;
    const char *slash2;
    const char *dot;
    size_t len;

    if (!full_path || !out_parts) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(out_parts, 0, sizeof(*out_parts));
    slash1 = strrchr(full_path, '\\');
    slash2 = strrchr(full_path, '/');
    last_sep = (slash1 && (!slash2 || slash1 > slash2)) ? slash1 : slash2;

    if (full_path[0] != '\0' && full_path[1] == ':') {
        out_parts->drive[0] = full_path[0];
        out_parts->drive[1] = ':';
        out_parts->drive[2] = '\0';
        full_path += 2;
    }
    if (last_sep && last_sep >= full_path) {
        size_t dlen = (size_t)(last_sep - full_path) + 1u;
        if (dlen >= sizeof(out_parts->dir)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        memcpy(out_parts->dir, full_path, dlen);
        out_parts->dir[dlen] = '\0';
        full_path = last_sep + 1;
    }
    dot = strrchr(full_path, '.');
    if (dot) {
        len = (size_t)(dot - full_path);
        if (len >= sizeof(out_parts->stem)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        memcpy(out_parts->stem, full_path, len);
        out_parts->stem[len] = '\0';
        if (vfs33_copy_str(out_parts->ext, sizeof(out_parts->ext), dot) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
    } else {
        if (vfs33_copy_str(out_parts->stem, sizeof(out_parts->stem), full_path) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_slab20_init(
    rome2_vfs_slab20_pool *pool,
    uint32_t count) {
    uint32_t i;
    if (!pool || count == 0u || count > ROME2_VFS_L33_MAX_SLAB) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    pool->count = count;
    pool->head = 0;
    for (i = 0u; i < count; ++i) {
        pool->next_idx[i] = (i + 1u < count) ? (int32_t)(i + 1u) : -1;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_intern_check_limit(uint32_t current_size) {
    return current_size >= ROME2_VFS_L33_UMAP_MAX_ELEMS ? ROME2_VFS_REG_RANGE_ERROR : ROME2_VFS_REG_OK;
}

void rome2_vfs_fill_u32_range(uint32_t *dst, uint32_t count, uint32_t value) {
    uint32_t i;
    if (!dst) {
        return;
    }
    for (i = 0u; i < count; ++i) {
        dst[i] = value;
    }
}

rome2_vfs_reg_status rome2_vfs_utf8_to_utf16(
    const char *utf8_src,
    uint16_t *utf16_dst,
    uint32_t dst_cap,
    uint32_t *out_len) {
    const uint8_t *p;
    uint32_t written = 0u;

    if (!utf8_src || !utf16_dst || dst_cap == 0u || !out_len) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    p = (const uint8_t *)utf8_src;
    while (*p != 0u) {
        uint32_t cp;
        if ((*p & 0x80u) == 0u) {
            cp = *p++;
        } else if ((*p & 0xe0u) == 0xc0u && (p[1] & 0xc0u) == 0x80u) {
            cp = ((uint32_t)(p[0] & 0x1fu) << 6u) | (uint32_t)(p[1] & 0x3fu);
            p += 2;
        } else if ((*p & 0xf0u) == 0xe0u && (p[1] & 0xc0u) == 0x80u && (p[2] & 0xc0u) == 0x80u) {
            cp = ((uint32_t)(p[0] & 0x0fu) << 12u) |
                 ((uint32_t)(p[1] & 0x3fu) << 6u) |
                 (uint32_t)(p[2] & 0x3fu);
            p += 3;
        } else {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        if (written + 1u >= dst_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        utf16_dst[written++] = (uint16_t)cp;
    }
    utf16_dst[written] = 0u;
    *out_len = written;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_assign_utf16(
    uint16_t *dst,
    uint32_t dst_cap,
    const uint16_t *src,
    uint32_t *out_len) {
    uint32_t len = 0u;
    if (!dst || dst_cap == 0u || !src || !out_len) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    while (src[len] != 0u) {
        ++len;
        if (len >= dst_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
    }
    memcpy(dst, src, ((size_t)len + 1u) * sizeof(uint16_t));
    *out_len = len;
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_archive_entry_name_matches_tail(
    const char *archive_rel,
    const char *full_candidate) {
    const char *sep;
    const char *tail;
    if (!archive_rel || !full_candidate) {
        return 0u;
    }
    sep = strrchr(full_candidate, '\\');
    tail = sep ? (sep + 1) : full_candidate;
    return strcmp(archive_rel, tail) == 0 ? 1u : 0u;
}

uint8_t rome2_vfs_validate_switch_tag_1_to_d(uint32_t tag) {
    return (tag >= 1u && (tag - 1u) <= ROME2_VFS_L33_SWITCH_MAX_CODE) ? 1u : 0u;
}
