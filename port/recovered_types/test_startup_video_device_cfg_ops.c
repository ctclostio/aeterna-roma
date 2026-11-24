#include "startup_video_device_cfg_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks = 0;
#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAILED at line %d: %s\n", __LINE__, #cond); \
        return 1; \
    } \
    g_checks++; \
} while (0)

int main(void) {
    /* 1. Layer 68 guest32 layout checks */
    rome2_startup_video_overlay_req20_32 req;
    rome2_startup_video_play_opts36_32 opts;
    rome2_startup_db_record_base24_32 rec;
    rome2_startup_subtitle_row68_32 srow;
    CHECK(sizeof(req) == 20u && sizeof(opts) == 36u && sizeof(rec) == 24u && sizeof(srow) == 68u);

    /* 2. UTF-16 slice eq, strip suffix, resolve db path, ShowCursor + cached cursor */
    const uint16_t u16_po[3] = {'P', 'O', 0};
    CHECK(rome2_l68_wslice_eq_cstr(u16_po, 2u, u16_po) == 1);
    CHECK(rome2_l68_wslice_eq_cstr(u16_po, 1u, u16_po) == 0);
    char stripped[32];
    CHECK(rome2_l68_wstr_strip_dot_suffix("CAMPAIGN_INTRO.bik", stripped, sizeof(stripped)) == 14u);
    CHECK(strcmp(stripped, "CAMPAIGN_INTRO") == 0);
    char dbp[64];
    rome2_l68_db_resolve_table_path("videos_table", 0x40u, dbp, sizeof(dbp));
    CHECK(strcmp(dbp, "db\\videos_table") == 0);

    uint32_t mode = 99u;
    CHECK(rome2_l68_video_mode_from_name("FULLSCREEN_INTRO", &mode) == 1 && mode == 8u);
    CHECK(rome2_l68_video_mode_from_name("VIDEO_TUTORIAL", &mode) == 1 && mode == 15u);
    CHECK(rome2_l68_video_mode_from_name("UNKNOWN", &mode) == 0);

    /* 3. Database tables, FxName lookups, RB-tree insert/find, join validation */
    rome2_l68_db_row vseed[2];
    memset(vseed, 0, sizeof(vseed));
    snprintf(vseed[0].key, sizeof(vseed[0].key), "CAMPAIGN_INTRO");
    vseed[0].payload = 0u;
    vseed[1].mode = 0u;
    snprintf(vseed[1].key, sizeof(vseed[1].key), "VIDEO_TUTORIAL");
    vseed[1].payload = 1u;

    rome2_l68_db_row sseed[1];
    memset(sseed, 0, sizeof(sseed));
    snprintf(sseed[0].key, sizeof(sseed[0].key), "sub0");
    sseed[0].payload = 0u;

    rome2_l68_video_mgr *mgr = (rome2_l68_video_mgr *)calloc(1u, sizeof(rome2_l68_video_mgr));
    CHECK(mgr != NULL);
    snprintf(mgr->locale_code, sizeof(mgr->locale_code), "PO");
    mgr->dat_11970646_cursor_allowed = 1u;
    mgr->cursor_counter = -1;
    CHECK(rome2_l68_get_videos_table(mgr, vseed, 2u) != NULL);
    CHECK(rome2_l68_get_subtitles_table(mgr, sseed, 1u) != NULL);
    CHECK(mgr->videos_tbl->vptr == 0x117e2a04u && mgr->videos_tbl->count == 2u);
    CHECK(mgr->videos_tbl->rows[1].mode == 15u);
    CHECK(rome2_l68_db_get_locale_id(mgr->videos_tbl) == 0x3f800000u);
    CHECK(rome2_l68_db_lookup_mode_checked(mgr->videos_tbl, "CAMPAIGN_INTRO") == 2u);
    CHECK(rome2_l68_db_lookup_payload_by_key(mgr->videos_tbl, "missing", 1u) == 2u);

    uint32_t *uvec = NULL;
    uint32_t ucap = 0u;
    CHECK(rome2_l68_u32_vec_reserve(&uvec, &ucap, 0u, 4u) == 1 && ucap == 4u);
    free(uvec);

    rome2_l68_rb_node rbnil;
    rome2_l68_rb_node rbpool[4];
    memset(&rbnil, 0, sizeof(rbnil));
    memset(rbpool, 0, sizeof(rbpool));
    rbnil.is_nil = 1u;
    rbnil.parent = &rbnil;
    rbnil.left = &rbnil;
    rbnil.right = &rbnil;
    rome2_l68_rb_tree tree = {&rbnil, 0u};
    CHECK(rome2_l68_rb_tree_insert_u32(&tree, rbpool, 4u, 42u) == 1);
    CHECK(rome2_l68_rb_tree_insert_u32(&tree, rbpool, 4u, 42u) == 0);
    CHECK(rome2_l68_rb_tree_insert_u32(&tree, rbpool, 4u, 7u) == 1);
    CHECK(rome2_l68_rb_tree_iter_find_u32(rbnil.left, &rbnil, 42u) == &rbpool[0]);
    const uint32_t lkeys[2] = {7u, 42u};
    const uint32_t rkeys[3] = {1u, 7u, 42u};
    CHECK(rome2_l68_db_validate_join_keys(lkeys, 2u, rkeys, 3u) == 1);
    char fmtbuf[128];
    rome2_l68_utf16_log_fmt(fmtbuf, sizeof(fmtbuf), "videos_table", "bad_key");
    CHECK(strstr(fmtbuf, "In table videos_table:") != NULL);

    /* 4. Video overlay pop & aspect ratio calculation */
    memset(&req, 0, sizeof(req));
    req.scale_mode_0c = 1;
    req.flag_10 = 1u;
    req.flag_11 = 1u;
    req.flag_13 = 0u;
    CHECK(rome2_l68_video_req_push_back(&mgr->queue, &mgr->queue_count, &mgr->queue_cap, &req) == 1);
    mgr->playing = 1u;
    mgr->active_1b8 = 1u;
    mgr->view_w = 1920;
    mgr->view_h = 800; /* aspect = 2.4 > 1.7 */
    snprintf(mgr->last_video_key, sizeof(mgr->last_video_key), "VIDEO_TUTORIAL.bik");
    rome2_l68_video_overlay_pop_and_apply(mgr);
    CHECK(mgr->queue_count == 0u && mgr->last_play_opts.crop_left_08 > 0);
    CHECK(strcmp(mgr->locale_code, "PL") == 0);
    CHECK(mgr->dat_11933000 == 1u && mgr->dat_119f308d == 1u);
    rome2_l68_video_overlay_pop_and_apply(mgr);
    CHECK(mgr->active_1b8 == 0u && mgr->flag_cf == 1u && mgr->show_cursor_calls > 0);

    rome2_l68_db_table_parsed_dtor(mgr->videos_tbl);
    rome2_l68_db_table_parsed_dtor(mgr->subtitles_tbl);
    CHECK(mgr->videos_tbl->parsed_freed == 1);
    free(mgr->videos_tbl);
    free(mgr->subtitles_tbl);
    free(mgr->queue);
    free(mgr);

    printf("test_startup_video_device_cfg_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
