#include "startup_video_device_cfg_ops.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rome2_l68_wslice_eq_cstr(const uint16_t *slice, size_t slice_len, const uint16_t *cstr) {
    size_t i;
    if (slice == NULL || cstr == NULL) {
        return 0;
    }
    for (i = 0u; i < slice_len; ++i) {
        if (slice[i] != cstr[i] || cstr[i] == 0u) {
            return 0;
        }
    }
    return cstr[slice_len] == 0u ? 1 : 0;
}

size_t rome2_l68_wstr_strip_dot_suffix(const char *src, char *dst, size_t dst_cap) {
    const char *dot;
    size_t len;

    if (src == NULL || dst == NULL || dst_cap == 0u) {
        return 0u;
    }
    dot = strrchr(src, '.');
    len = (dot != NULL) ? (size_t)(dot - src) : strlen(src);
    if (len >= dst_cap) {
        len = dst_cap - 1u;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return len;
}

void rome2_l68_db_resolve_table_path(
    const char *table_name, uint32_t flags, char *out_path, size_t out_cap) {
    (void)flags;
    if (out_path == NULL || out_cap == 0u) {
        return;
    }
    if (table_name == NULL) {
        out_path[0] = '\0';
        return;
    }
    snprintf(out_path, out_cap, "db\\%s", table_name);
}

void rome2_l68_win32_show_cursor_loop(rome2_l68_video_mgr *mgr, uint8_t show) {
    if (mgr == NULL) {
        return;
    }
    if (show == 0u) {
        do {
            mgr->cursor_counter--;
            mgr->show_cursor_calls++;
        } while (mgr->cursor_counter > 0);
        return;
    }
    do {
        mgr->cursor_counter++;
        mgr->show_cursor_calls++;
    } while (mgr->cursor_counter < 0);
}

void rome2_l68_set_cursor_visible_cached(rome2_l68_video_mgr *mgr, uint8_t visible) {
    if (mgr == NULL || visible == mgr->dat_11970645_cursor_vis) {
        return;
    }
    mgr->dat_11970645_cursor_vis = visible;
    if (visible != 0u && mgr->dat_11970646_cursor_allowed != 0u) {
        rome2_l68_win32_show_cursor_loop(mgr, 1u);
        return;
    }
    rome2_l68_win32_show_cursor_loop(mgr, 0u);
}

int rome2_l68_u32_vec_reserve(uint32_t **vec_ptr, uint32_t *cap, uint32_t count, uint32_t new_cap) {
    uint32_t *grown;
    if (vec_ptr == NULL || cap == NULL) {
        return 0;
    }
    if (*cap >= new_cap) {
        return 1;
    }
    if (new_cap > SIZE_MAX / sizeof(uint32_t)) {
        return 0;
    }
    grown = (new_cap == 0u) ? NULL : (uint32_t *)calloc(new_cap, sizeof(uint32_t));
    if (new_cap != 0u && grown == NULL) {
        return 0;
    }
    if (*vec_ptr != NULL && count > 0u) {
        uint32_t n = (count < new_cap) ? count : new_cap;
        memcpy(grown, *vec_ptr, (size_t)n * sizeof(uint32_t));
    }
    free(*vec_ptr);
    *vec_ptr = grown;
    *cap = new_cap;
    return 1;
}

int rome2_l68_video_req_push_back(
    rome2_startup_video_overlay_req20_32 **vec_ptr, uint32_t *count, uint32_t *cap,
    const rome2_startup_video_overlay_req20_32 *elem) {
    uint32_t c;
    uint32_t cp;

    if (vec_ptr == NULL || count == NULL || cap == NULL || elem == NULL) {
        return 0;
    }
    c = *count;
    cp = *cap;
    if (c >= cp) {
        uint32_t ncap = (cp == 0u) ? 1u : (cp <= UINT32_MAX / 2u ? cp * 2u : 0u);
        rome2_startup_video_overlay_req20_32 *grown;
        rome2_startup_video_overlay_req20_32 copy = *elem;
        if (ncap == 0u || ncap > SIZE_MAX / sizeof(rome2_startup_video_overlay_req20_32)) {
            return 0;
        }
        grown = (rome2_startup_video_overlay_req20_32 *)calloc(
            ncap, sizeof(rome2_startup_video_overlay_req20_32));
        if (grown == NULL) {
            return 0;
        }
        if (*vec_ptr != NULL && c > 0u) {
            memcpy(grown, *vec_ptr, (size_t)c * sizeof(rome2_startup_video_overlay_req20_32));
        }
        free(*vec_ptr);
        *vec_ptr = grown;
        *cap = ncap;
        (*vec_ptr)[c] = copy;
        *count = c + 1u;
        return 1;
    }
    (*vec_ptr)[c] = *elem;
    *count = c + 1u;
    return 1;
}

int rome2_l68_video_device_is_playing(const rome2_l68_video_mgr *mgr) {
    return (mgr != NULL && mgr->playing != 0u) ? 1 : 0;
}

int rome2_l68_video_mode_from_name(const char *name, uint32_t *out_mode) {
    static const char *const names[16] = {
        "CAMPAIGN_DUEL", "CAMPAIGN_DUEL_RESULT", "CAMPAIGN_INTRO", "CAMPAIGN_LOSE",
        "CAMPAIGN_OUTRO", "CAMPAIGN_WIN", "FULLSCREEN_BATTLE_INTRO", "FULLSCREEN_FRONTEND",
        "FULLSCREEN_INTRO", "WINDOWED_BATTLE_INTRO", "CAMPAIGN_ASSASSINATION",
        "CAMPAIGN_ESTABLISH", "CAMPAIGN_INFILTRATION", "CAMPAIGN_ESCAPE",
        "CAMPAIGN_SABOTAGE", "VIDEO_TUTORIAL",
    };
    size_t i;

    if (name == NULL || out_mode == NULL) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        if (strcmp(name, names[i]) == 0) {
            *out_mode = (uint32_t)i;
            return 1;
        }
    }
    return 0;
}

void rome2_l68_db_table_base_init(rome2_l68_db_table *tbl, uint32_t locale_id) {
    if (tbl == NULL) {
        return;
    }
    memset(tbl, 0, sizeof(*tbl));
    tbl->vptr = 0x11768574u;
    tbl->locale_id = locale_id;
}

void rome2_l68_videos_reader_init(rome2_l68_db_table *tbl, uint32_t vptr) {
    rome2_l68_db_table_base_init(tbl, 0x3f800000u);
    if (tbl != NULL) {
        tbl->vptr = vptr;
    }
}

void rome2_l68_subtitles_reader_init(rome2_l68_db_table *tbl, uint32_t vptr) {
    rome2_l68_db_table_base_init(tbl, 0x3f800000u);
    if (tbl != NULL) {
        tbl->vptr = vptr;
    }
}

int rome2_l68_videos_parse_rows(
    rome2_l68_db_table *tbl, const rome2_l68_db_row *src_rows, uint32_t src_count) {
    uint32_t i;

    if (tbl == NULL) {
        return 0;
    }
    free(tbl->rows);
    tbl->rows = NULL;
    tbl->count = 0u;
    if (src_rows == NULL || src_count == 0u) {
        return 1;
    }
    tbl->rows = (rome2_l68_db_row *)calloc(src_count, sizeof(rome2_l68_db_row));
    if (tbl->rows == NULL) {
        return 0;
    }
    for (i = 0u; i < src_count; ++i) {
        uint32_t mode = 0u;
        tbl->rows[i] = src_rows[i];
        if (rome2_l68_video_mode_from_name(src_rows[i].key, &mode) != 0) {
            tbl->rows[i].mode = mode;
        }
    }
    tbl->count = src_count;
    return 1;
}

int rome2_l68_subtitles_parse_rows(
    rome2_l68_db_table *tbl, const rome2_l68_db_row *src_rows, uint32_t src_count) {
    if (tbl == NULL) {
        return 0;
    }
    free(tbl->rows);
    tbl->rows = NULL;
    tbl->count = 0u;
    if (src_rows == NULL || src_count == 0u) {
        return 1;
    }
    tbl->rows = (rome2_l68_db_row *)calloc(src_count, sizeof(rome2_l68_db_row));
    if (tbl->rows == NULL) {
        return 0;
    }
    memcpy(tbl->rows, src_rows, (size_t)src_count * sizeof(rome2_l68_db_row));
    tbl->count = src_count;
    return 1;
}

int rome2_l68_videos_loader_exec(
    rome2_l68_db_table *tbl, const rome2_l68_db_row *src_rows, uint32_t src_count) {
    rome2_l68_videos_reader_init(tbl, 0x117e2a04u);
    return rome2_l68_videos_parse_rows(tbl, src_rows, src_count);
}

int rome2_l68_subtitles_loader_exec(
    rome2_l68_db_table *tbl, const rome2_l68_db_row *src_rows, uint32_t src_count) {
    rome2_l68_subtitles_reader_init(tbl, 0x117ee52cu);
    return rome2_l68_subtitles_parse_rows(tbl, src_rows, src_count);
}

void rome2_l68_db_table_parsed_dtor(rome2_l68_db_table *tbl) {
    if (tbl == NULL) {
        return;
    }
    tbl->vptr = 0x11768574u;
    free(tbl->rows);
    tbl->rows = NULL;
    tbl->count = 0u;
    tbl->parsed_freed = 1;
}

uint32_t rome2_l68_db_get_locale_id(const rome2_l68_db_table *tbl) {
    return (tbl != NULL) ? tbl->locale_id : 0u;
}

rome2_l68_db_table *rome2_l68_get_subtitles_table(
    rome2_l68_video_mgr *mgr, const rome2_l68_db_row *seed, uint32_t seed_count) {
    if (mgr == NULL) {
        return NULL;
    }
    if (mgr->subtitles_tbl == NULL) {
        rome2_l68_db_table *t = (rome2_l68_db_table *)calloc(1u, sizeof(rome2_l68_db_table));
        if (t == NULL) {
            return NULL;
        }
        (void)rome2_l68_subtitles_loader_exec(t, seed, seed_count);
        mgr->subtitles_tbl = t;
    }
    return mgr->subtitles_tbl;
}

rome2_l68_db_table *rome2_l68_get_videos_table(
    rome2_l68_video_mgr *mgr, const rome2_l68_db_row *seed, uint32_t seed_count) {
    if (mgr == NULL) {
        return NULL;
    }
    if (mgr->videos_tbl == NULL) {
        rome2_l68_db_table *t = (rome2_l68_db_table *)calloc(1u, sizeof(rome2_l68_db_table));
        if (t == NULL) {
            return NULL;
        }
        (void)rome2_l68_videos_loader_exec(t, seed, seed_count);
        mgr->videos_tbl = t;
    }
    return mgr->videos_tbl;
}

int rome2_l68_fx_name_map_find(const rome2_l68_db_table *tbl, const char *key, uint32_t *out_idx) {
    uint32_t i;

    if (tbl == NULL || key == NULL || tbl->rows == NULL) {
        return 0;
    }
    for (i = 0u; i < tbl->count; ++i) {
        if (strcmp(tbl->rows[i].key, key) == 0) {
            if (out_idx != NULL) {
                *out_idx = i;
            }
            return 1;
        }
    }
    return 0;
}

rome2_l68_rb_node *rome2_l68_rb_tree_iter_find_u32(
    rome2_l68_rb_node *first, rome2_l68_rb_node *nil_node, uint32_t target) {
    rome2_l68_rb_node *cur = first;

    while (cur != NULL && cur != nil_node) {
        if (cur->key == target) {
            return cur;
        }
        if (cur->right != NULL && cur->right->is_nil == 0u) {
            cur = cur->right;
            while (cur->left != NULL && cur->left->is_nil == 0u) {
                cur = cur->left;
            }
        } else {
            rome2_l68_rb_node *p = cur->parent;
            while (p != NULL && p->is_nil == 0u && cur == p->right) {
                cur = p;
                p = p->parent;
            }
            cur = p;
        }
    }
    return nil_node;
}

int rome2_l68_rb_tree_insert_u32(
    rome2_l68_rb_tree *tree, rome2_l68_rb_node *nodes, size_t max_nodes, uint32_t key) {
    rome2_l68_rb_node *nil_node;
    rome2_l68_rb_node *parent;
    rome2_l68_rb_node *cur;
    rome2_l68_rb_node *fresh;

    if (tree == NULL || nodes == NULL || max_nodes == 0u || tree->head == NULL) {
        return 0;
    }
    nil_node = tree->head;
    parent = nil_node;
    cur = nil_node->parent;
    while (cur != NULL && cur != nil_node && cur->is_nil == 0u) {
        parent = cur;
        if (key == cur->key) {
            return 0;
        }
        cur = (key < cur->key) ? cur->left : cur->right;
    }
    if (tree->count >= max_nodes) {
        return 0;
    }
    fresh = &nodes[tree->count++];
    fresh->key = key;
    fresh->left = nil_node;
    fresh->right = nil_node;
    fresh->parent = parent;
    fresh->is_nil = 0u;
    fresh->color = 1u;
    if (parent == nil_node) {
        nil_node->parent = fresh;
        nil_node->left = fresh;
        nil_node->right = fresh;
    } else if (key < parent->key) {
        parent->left = fresh;
    } else {
        parent->right = fresh;
    }
    return 1;
}

void rome2_l68_utf16_log_fmt(char *out_buf, size_t out_cap, const char *table_name, const char *key) {
    if (out_buf == NULL || out_cap == 0u) {
        return;
    }
    snprintf(
        out_buf, out_cap, "In table %s: '%s' is not a valid key for this table\n",
        table_name ? table_name : "", key ? key : "");
}

int rome2_l68_db_validate_join_keys(
    const uint32_t *left_keys, size_t left_n, const uint32_t *right_keys, size_t right_n) {
    size_t i;
    size_t j;

    if (left_n == 0u || left_keys == NULL) {
        return 1;
    }
    if (right_keys == NULL) {
        return 0;
    }
    for (i = 0u; i < left_n; ++i) {
        int found = 0;
        for (j = 0u; j < right_n; ++j) {
            if (left_keys[i] == right_keys[j]) {
                found = 1;
                break;
            }
        }
        if (found == 0) {
            return 0;
        }
    }
    return 1;
}

uint32_t rome2_l68_db_lookup_payload_by_key(
    const rome2_l68_db_table *tbl, const char *key, uint8_t log_on_miss) {
    uint32_t idx = 0u;
    (void)log_on_miss;
    if (tbl == NULL) {
        return 0u;
    }
    if (rome2_l68_fx_name_map_find(tbl, key, &idx) != 0) {
        return tbl->rows[idx].payload;
    }
    return tbl->count;
}

const rome2_l68_db_row *rome2_l68_db_lookup_row_by_name(
    const rome2_l68_db_table *tbl, const char *key) {
    uint32_t idx;
    if (tbl == NULL || key == NULL) {
        return NULL;
    }
    idx = rome2_l68_db_lookup_payload_by_key(tbl, key, 1u);
    if (idx < tbl->count) {
        return &tbl->rows[idx];
    }
    return NULL;
}

uint32_t rome2_l68_db_lookup_mode_checked(const rome2_l68_db_table *tbl, const char *key) {
    uint32_t idx = 0u;
    if (tbl == NULL) {
        return 0u;
    }
    if (rome2_l68_fx_name_map_find(tbl, key, &idx) != 0) {
        return tbl->rows[idx].mode;
    }
    return 0u;
}

int rome2_l68_video_play_from_db(
    rome2_l68_video_mgr *mgr, const char *video_key, const rome2_startup_video_play_opts36_32 *opts) {
    const rome2_l68_db_row *row;

    if (mgr == NULL || video_key == NULL) {
        return 0;
    }
    row = rome2_l68_db_lookup_row_by_name(mgr->videos_tbl, video_key);
    if (row == NULL) {
        char stripped[64];
        (void)rome2_l68_wstr_strip_dot_suffix(video_key, stripped, sizeof(stripped));
        row = rome2_l68_db_lookup_row_by_name(mgr->videos_tbl, stripped);
    }
    if (row == NULL || row->payload == 0u) {
        return 0;
    }
    snprintf(mgr->last_video_key, sizeof(mgr->last_video_key), "%s", row->key);
    if (opts != NULL) {
        mgr->last_play_opts = *opts;
    }
    if (strcmp(mgr->locale_code, "PO") == 0) {
        snprintf(mgr->locale_code, sizeof(mgr->locale_code), "%s", "PL");
    }
    mgr->playing = 1u;
    return 1;
}

void rome2_l68_video_overlay_pop_and_apply(rome2_l68_video_mgr *mgr) {
    rome2_startup_video_overlay_req20_32 req;
    rome2_startup_video_play_opts36_32 opts;
    float aspect;

    if (mgr == NULL || mgr->active_1b8 == 0u || rome2_l68_video_device_is_playing(mgr) == 0) {
        return;
    }
    if (mgr->queue_count == 0u) {
        mgr->active_1b8 = 0u;
        rome2_l68_set_cursor_visible_cached(mgr, 1u);
        if (mgr->dat_119f308c != 0u) {
            mgr->dat_119f308d = 1u;
        }
        if (mgr->dat_119f308d != 0u) {
            mgr->flag_cf = 1u;
            mgr->dat_119f308d = 0u;
        }
        return;
    }
    req = mgr->queue[mgr->queue_count - 1u];
    memset(&opts, 0, sizeof(opts));
    opts.mode_flags_00 = 0x10001u;
    opts.b04 = req.flag_10;
    opts.b06 = 1u;
    opts.b07 = (mgr->queue_count < 2u) ? 1u : 0u;
    aspect = (mgr->view_h > 0) ? ((float)mgr->view_w / (float)mgr->view_h) : 1.0f;
    if (req.scale_mode_0c == 1) {
        if (aspect < 1.4f) {
            opts.crop_h_14 = (int32_t)llround((double)mgr->view_w * 0.5625);
            opts.crop_w_10 = mgr->view_w;
            opts.crop_top_0c = (mgr->view_h - opts.crop_h_14) / 2;
        } else if (aspect > 1.7f) {
            opts.crop_w_10 = (int32_t)llround((double)mgr->view_h * 1.7777778);
            opts.crop_h_14 = mgr->view_h;
            opts.crop_left_08 = (mgr->view_w - opts.crop_w_10) / 2;
        }
    } else if (req.scale_mode_0c == 0 && aspect > 1.4f) {
        opts.crop_w_10 = (int32_t)llround((double)mgr->view_h * 1.3333334);
        opts.crop_h_14 = mgr->view_h;
        opts.crop_left_08 = (mgr->view_w - opts.crop_w_10) / 2;
    }
    (void)rome2_l68_video_play_from_db(mgr, mgr->last_video_key, &opts);
    if (req.flag_11 != 0u) {
        mgr->dat_119f308d = 1u;
    }
    if (req.flag_12 != 0u) {
        mgr->dat_119f308c = 1u;
    }
    mgr->dat_11933000 = (req.flag_13 == 0u) ? 1u : 0u;
    mgr->queue_count--;
}
