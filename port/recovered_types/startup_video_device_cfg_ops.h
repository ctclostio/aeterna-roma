#ifndef ROME2_STARTUP_VIDEO_DEVICE_CFG_OPS_H
#define ROME2_STARTUP_VIDEO_DEVICE_CFG_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_engine_db_fp_ops.h"

/*
 * Layer 68 Partition 8 recovery:
 * 30 video / cursor / database-table (`videos_tables`, `subtitle_timings_tables`) /
 * RB-tree & FxName hash lookup functions (0x100dd4c0..0x112d9960).
 */

typedef struct rome2_l68_rb_node {
    struct rome2_l68_rb_node *left;
    struct rome2_l68_rb_node *parent;
    struct rome2_l68_rb_node *right;
    uint8_t color;
    uint8_t is_nil;
    uint32_t key;
} rome2_l68_rb_node;

typedef struct rome2_l68_rb_tree {
    rome2_l68_rb_node *head;
    size_t count;
} rome2_l68_rb_tree;

typedef struct rome2_l68_db_row {
    char key[48];
    uint32_t mode;
    uint32_t payload;
    int32_t col18;
    int32_t col04;
    int32_t split_idx_28;
    char subtitle[128];
} rome2_l68_db_row;

typedef struct rome2_l68_db_table {
    uint32_t vptr;
    uint32_t locale_id;
    uint32_t count;
    rome2_l68_db_row *rows;
    void *sub_objs[4];
    int parsed_freed;
} rome2_l68_db_table;

typedef struct rome2_l68_video_mgr {
    uint8_t playing;
    uint8_t active_1b8;
    uint8_t flag_cf;
    uint8_t dat_119f308c;
    uint8_t dat_119f308d;
    uint32_t dat_11933000;
    uint8_t dat_11970645_cursor_vis;
    uint8_t dat_11970646_cursor_allowed;
    int32_t cursor_counter;
    int32_t show_cursor_calls;
    int32_t view_w;
    int32_t view_h;
    char locale_code[8];
    rome2_startup_video_overlay_req20_32 *queue;
    uint32_t queue_count;
    uint32_t queue_cap;
    rome2_startup_video_play_opts36_32 last_play_opts;
    char last_video_key[64];
    rome2_l68_db_table *videos_tbl;
    rome2_l68_db_table *subtitles_tbl;
} rome2_l68_video_mgr;

/* 0x100f2960 */
int rome2_l68_wslice_eq_cstr(const uint16_t *slice, size_t slice_len, const uint16_t *cstr);

/* 0x101223e0 */
size_t rome2_l68_wstr_strip_dot_suffix(const char *src, char *dst, size_t dst_cap);

/* 0x100efd80 */
void rome2_l68_db_resolve_table_path(
    const char *table_name, uint32_t flags, char *out_path, size_t out_cap);

/* 0x10115370 */
void rome2_l68_win32_show_cursor_loop(rome2_l68_video_mgr *mgr, uint8_t show);

/* 0x10ca63f0 */
void rome2_l68_set_cursor_visible_cached(rome2_l68_video_mgr *mgr, uint8_t visible);

/* 0x102b4f20 */
int rome2_l68_u32_vec_reserve(uint32_t **vec_ptr, uint32_t *cap, uint32_t count, uint32_t new_cap);

/* 0x10c8b3a0 */
int rome2_l68_video_req_push_back(
    rome2_startup_video_overlay_req20_32 **vec_ptr, uint32_t *count, uint32_t *cap,
    const rome2_startup_video_overlay_req20_32 *elem);

/* 0x10c84040 */
int rome2_l68_video_device_is_playing(const rome2_l68_video_mgr *mgr);

/* 0x10ce6120 */
int rome2_l68_video_mode_from_name(const char *name, uint32_t *out_mode);

/* 0x10c99c60 */
void rome2_l68_db_table_base_init(rome2_l68_db_table *tbl, uint32_t locale_id);

/* 0x10cc18c0 / 0x10dd83c0 */
void rome2_l68_videos_reader_init(rome2_l68_db_table *tbl, uint32_t vptr);
void rome2_l68_subtitles_reader_init(rome2_l68_db_table *tbl, uint32_t vptr);

/* 0x10cc9090 / 0x10de06e0 */
int rome2_l68_videos_parse_rows(
    rome2_l68_db_table *tbl, const rome2_l68_db_row *src_rows, uint32_t src_count);
int rome2_l68_subtitles_parse_rows(
    rome2_l68_db_table *tbl, const rome2_l68_db_row *src_rows, uint32_t src_count);

/* 0x10cc4b50 / 0x10ddb580 */
int rome2_l68_videos_loader_exec(
    rome2_l68_db_table *tbl, const rome2_l68_db_row *src_rows, uint32_t src_count);
int rome2_l68_subtitles_loader_exec(
    rome2_l68_db_table *tbl, const rome2_l68_db_row *src_rows, uint32_t src_count);

/* 0x112ab5e0 */
void rome2_l68_db_table_parsed_dtor(rome2_l68_db_table *tbl);

/* 0x10d33170 */
uint32_t rome2_l68_db_get_locale_id(const rome2_l68_db_table *tbl);

/* 0x10d33280 / 0x10d39b50 */
rome2_l68_db_table *rome2_l68_get_subtitles_table(
    rome2_l68_video_mgr *mgr, const rome2_l68_db_row *seed, uint32_t seed_count);
rome2_l68_db_table *rome2_l68_get_videos_table(
    rome2_l68_video_mgr *mgr, const rome2_l68_db_row *seed, uint32_t seed_count);

/* 0x110e2700 */
int rome2_l68_fx_name_map_find(const rome2_l68_db_table *tbl, const char *key, uint32_t *out_idx);

/* 0x112a4ae0 / 0x112a58b0 */
rome2_l68_rb_node *rome2_l68_rb_tree_iter_find_u32(
    rome2_l68_rb_node *first, rome2_l68_rb_node *nil_node, uint32_t target);
int rome2_l68_rb_tree_insert_u32(
    rome2_l68_rb_tree *tree, rome2_l68_rb_node *nodes, size_t max_nodes, uint32_t key);

/* 0x112a5af0 */
void rome2_l68_utf16_log_fmt(char *out_buf, size_t out_cap, const char *table_name, const char *key);

/* 0x112bb070 */
int rome2_l68_db_validate_join_keys(
    const uint32_t *left_keys, size_t left_n, const uint32_t *right_keys, size_t right_n);

/* 0x112d9960 / 0x112d9900 / 0x112bdc00 */
uint32_t rome2_l68_db_lookup_payload_by_key(
    const rome2_l68_db_table *tbl, const char *key, uint8_t log_on_miss);
const rome2_l68_db_row *rome2_l68_db_lookup_row_by_name(
    const rome2_l68_db_table *tbl, const char *key);
uint32_t rome2_l68_db_lookup_mode_checked(const rome2_l68_db_table *tbl, const char *key);

/* 0x10c8a0b0 / 0x100dd4c0 */
int rome2_l68_video_play_from_db(
    rome2_l68_video_mgr *mgr, const char *video_key, const rome2_startup_video_play_opts36_32 *opts);
void rome2_l68_video_overlay_pop_and_apply(rome2_l68_video_mgr *mgr);

#endif
