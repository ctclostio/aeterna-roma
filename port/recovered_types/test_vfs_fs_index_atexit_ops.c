#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_index_atexit_ops.h"

static uint32_t g_checks = 0u;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond);            \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

typedef struct test_probe_ctx {
    const char *match_full;
    uint8_t allow_direct;
} test_probe_ctx;

typedef struct test_visit_log {
    uint32_t count;
    char joined[16][256];
    rome2_vfs_win32_find_info infos[16];
} test_visit_log;

/* Keep large test structs in static storage for `/W4 /WX /analyze` C6262 stack budget. */
static rome2_vfs_pack_index_env g_idx_env;
static rome2_vfs_win32_sim_fs g_sim_fs;
static test_visit_log g_visit_log;
static rome2_vfs_umap_rehash_state g_umap;
static rome2_vfs_entry48_vec g_vec48;
static rome2_vfs_u32_vec g_vec32;
static rome2_vfs_rb_ref_node g_rb_nodes[8];
static rome2_vfs_mount_free_node g_mount_nodes[6];
static rome2_vfs_str_chunk g_chunks[4];
static rome2_vfs_diag_kv g_diag_tbl[3];
static rome2_vfs_diag_provider g_diag_prov;
static rome2_vfs_atexit_globals_state g_atexit_state;

static uint8_t test_direct_pred(const char *rel_path, void *ctx) {
    const test_probe_ctx *p = (const test_probe_ctx *)ctx;
    return (p && p->allow_direct != 0u && rel_path[0] == 'X') ? 1u : 0u;
}

static uint8_t test_probe_open(const char *full_path, void *ctx) {
    const test_probe_ctx *p = (const test_probe_ctx *)ctx;
    return (p && p->match_full && strcmp(full_path, p->match_full) == 0) ? 1u : 0u;
}

static void test_visit_cb(
    const char *dir_path,
    const char *file_name,
    const char *pattern,
    const rome2_vfs_win32_find_info *info,
    void *user_ctx) {
    test_visit_log *log = (test_visit_log *)user_ctx;
    (void)pattern;
    if (log && log->count < 16u) {
        snprintf(log->joined[log->count], sizeof(log->joined[log->count]), "%s|%s", dir_path, file_name);
        log->infos[log->count] = *info;
        log->count += 1u;
    }
}

static void test_pack_index_and_wildcards(void) {
    const rome2_vfs_pack_index_table *empty_tbl;
    const rome2_vfs_pack_index_table *primary;
    test_probe_ctx ctx;
    char out_buf[256];
    uint32_t h1 = 0u;
    uint32_t h2 = 0u;

    memset(&g_idx_env, 0, sizeof(g_idx_env));
    empty_tbl = rome2_vfs_pack_index_get_empty(&g_idx_env);
    primary = rome2_vfs_pack_index_get_primary(&g_idx_env);
    CHECK(empty_tbl != NULL && empty_tbl->count == 1u && empty_tbl->entries[0][0] == '\0');
    CHECK(primary != NULL && primary->count == 0u);

    g_idx_env.primary_singleton.count = 2u;
    snprintf(g_idx_env.primary_singleton.entries[0], ROME2_VFS_IDX_MAX_PATH, "data/");
    snprintf(g_idx_env.primary_singleton.entries[1], ROME2_VFS_IDX_MAX_PATH, "mods/");

    ctx.match_full = "mods/unit.pack";
    ctx.allow_direct = 0u;
    CHECK(rome2_vfs_pack_index_can_open(primary, "unit.pack", test_direct_pred, test_probe_open, &ctx) == 1u);
    CHECK(rome2_vfs_pack_index_can_open(primary, "missing.pack", test_direct_pred, test_probe_open, &ctx) == 0u);
    CHECK(strcmp(rome2_vfs_pack_index_resolve_root(&g_idx_env, "unit.pack", test_direct_pred, test_probe_open, &ctx), "mods/") == 0);
    CHECK(strcmp(rome2_vfs_pack_index_resolve_root(&g_idx_env, "nope.pack", test_direct_pred, test_probe_open, &ctx), "") == 0);

    CHECK(rome2_vfs_pack_index_resolve_path(primary, "unit.pack", test_direct_pred, test_probe_open, &ctx, out_buf, sizeof(out_buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(out_buf, "mods/unit.pack") == 0);
    CHECK(rome2_vfs_pack_index_resolve_path(primary, "missing.pack", test_direct_pred, test_probe_open, &ctx, out_buf, sizeof(out_buf)) == ROME2_VFS_REG_NOT_FOUND);
    CHECK(out_buf[0] == '\0');

    CHECK(rome2_vfs_wrap_new_stream_from_path(&g_idx_env, "mods/unit.pack", &h1) == ROME2_VFS_REG_OK && h1 == 1u);
    CHECK(rome2_vfs_build_prefixed_entry(&g_idx_env, "data", "a.txt", &h2, out_buf, sizeof(out_buf)) == ROME2_VFS_REG_OK && h2 == 2u);
    CHECK(strcmp(out_buf, "data\\a.txt") == 0);

    CHECK(rome2_vfs_strip_trailing_separators("C:\\Rome2\\data\\//", out_buf, sizeof(out_buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(out_buf, "C:\\Rome2\\data") == 0);

    /* Wildcard `0x10121d80` coverage including `*`, `*.*`, `?`, and case-insensitive match. */
    CHECK(rome2_vfs_wildcard_match_nocase("Anything.pack", "*") == 1u);
    CHECK(rome2_vfs_wildcard_match_nocase("Anything.pack", "*.*") == 1u);
    CHECK(rome2_vfs_wildcard_match_nocase("Data_Rome2.PACK", "data_????2.p*k") == 1u);
    CHECK(rome2_vfs_wildcard_match_nocase("Data_Rome2.PACK", "data_??2.pack") == 0u);
}

static void test_win32_traverse_and_decode(void) {
    rome2_vfs_win32_find_info info;
    /* FileTime for Unix t=1700000000: (1700000000 + 11644473600) * 10^7; 0x100fec00 adds 0x49ef7d10 (-11644470000 mod 2^32), yielding t + 3600. */
    uint64_t ft = (1700000000ULL + ROME2_WIN32_EPOCH_OFFSET_SEC) * 10000000ULL;

    rome2_vfs_decode_win32_find_info(4096u, ROME2_WIN32_ATTR_DIRECTORY | ROME2_WIN32_ATTR_HIDDEN, ft, &info);
    CHECK(info.file_size_low == 4096u);
    CHECK(info.mtime_unix_low32 == 1700003600u);
    CHECK(info.valid == 1u && info.writable == 1u && info.is_dir == 1u && info.hidden == 1u);

    rome2_vfs_decode_win32_find_info(128u, ROME2_WIN32_ATTR_READONLY, ft, &info);
    CHECK(info.writable == 0u && info.is_dir == 0u && info.hidden == 0u);

    memset(&g_sim_fs, 0, sizeof(g_sim_fs));
    g_sim_fs.count = 4u;
    snprintf(g_sim_fs.entries[0].dir, ROME2_VFS_IDX_MAX_PATH, "root");
    snprintf(g_sim_fs.entries[0].name, ROME2_VFS_IDX_MAX_PATH, ".");
    g_sim_fs.entries[0].attributes = ROME2_WIN32_ATTR_DIRECTORY;

    snprintf(g_sim_fs.entries[1].dir, ROME2_VFS_IDX_MAX_PATH, "root");
    snprintf(g_sim_fs.entries[1].name, ROME2_VFS_IDX_MAX_PATH, "sub");
    g_sim_fs.entries[1].attributes = ROME2_WIN32_ATTR_DIRECTORY;

    snprintf(g_sim_fs.entries[2].dir, ROME2_VFS_IDX_MAX_PATH, "root");
    snprintf(g_sim_fs.entries[2].name, ROME2_VFS_IDX_MAX_PATH, "top.PACK");
    g_sim_fs.entries[2].file_size_low = 100u;
    g_sim_fs.entries[2].last_write_filetime = ft;

    snprintf(g_sim_fs.entries[3].dir, ROME2_VFS_IDX_MAX_PATH, "root\\sub");
    snprintf(g_sim_fs.entries[3].name, ROME2_VFS_IDX_MAX_PATH, "nested.pack");
    g_sim_fs.entries[3].file_size_low = 200u;
    g_sim_fs.entries[3].last_write_filetime = ft;

    memset(&g_visit_log, 0, sizeof(g_visit_log));
    CHECK(rome2_vfs_traverse_sim_directory(&g_sim_fs, "root\\", "*.pack", 1u, test_visit_cb, &g_visit_log, 4u) == ROME2_VFS_REG_OK);
    CHECK(g_visit_log.count == 2u);
    CHECK(strcmp(g_visit_log.joined[0], "root\\|top.PACK") == 0 && g_visit_log.infos[0].file_size_low == 100u);
    CHECK(strcmp(g_visit_log.joined[1], "root\\sub\\|nested.pack") == 0 && g_visit_log.infos[1].file_size_low == 200u);
}

static void test_containers_diag_and_atexit(void) {
    uint32_t erased = 0u, payloads = 0u, ctrls = 0u;
    uint32_t freed_n = 0u, freed_a = 0u, freed_c = 0u;
    uint32_t cleared_s = 0u, pair_count = 3u, pair_dest = 0u;
    uint32_t v = 77u;
    char diag_buf[256];

    rome2_vfs_pair_array_clear(&pair_count, &pair_dest);
    CHECK(pair_count == 0u && pair_dest == 3u);

    memset(g_rb_nodes, 0, sizeof(g_rb_nodes));
    g_rb_nodes[0].active = 1u; g_rb_nodes[0].left = 1; g_rb_nodes[0].right = 2; g_rb_nodes[0].strong_refs = 1u; g_rb_nodes[0].weak_refs = 1u;
    g_rb_nodes[1].active = 1u; g_rb_nodes[1].left = -1; g_rb_nodes[1].right = -1; g_rb_nodes[1].strong_refs = 2u; g_rb_nodes[1].weak_refs = 1u;
    g_rb_nodes[2].active = 1u; g_rb_nodes[2].left = -1; g_rb_nodes[2].right = -1; g_rb_nodes[2].strong_refs = 1u; g_rb_nodes[2].weak_refs = 1u;
    CHECK(rome2_vfs_rb_erase_subtree(g_rb_nodes, 3u, 0, &erased, &payloads, &ctrls) == ROME2_VFS_REG_OK);
    CHECK(erased == 3u && payloads == 2u && ctrls == 2u);

    memset(g_mount_nodes, 0, sizeof(g_mount_nodes));
    g_mount_nodes[0].active = 1u; g_mount_nodes[0].has_aux_buf = 1u; g_mount_nodes[0].child_count = 3u; g_mount_nodes[0].next = 1;
    g_mount_nodes[1].active = 1u; g_mount_nodes[1].has_aux_buf = 0u; g_mount_nodes[1].child_count = 2u; g_mount_nodes[1].next = -1;
    CHECK(rome2_vfs_mount_node_list_free(g_mount_nodes, 2u, 0, &freed_n, &freed_a, &freed_c) == ROME2_VFS_REG_OK);
    CHECK(freed_n == 2u && freed_a == 1u && freed_c == 5u);

    memset(&g_umap, 0, sizeof(g_umap));
    g_umap.node_count = 2u;
    g_umap.nodes[0].active = 1u; snprintf(g_umap.nodes[0].key, ROME2_VFS_IDX_MAX_PATH, "alpha");
    g_umap.nodes[1].active = 1u; snprintf(g_umap.nodes[1].key, ROME2_VFS_IDX_MAX_PATH, "beta");
    CHECK(rome2_vfs_umap_rehash(&g_umap, 0x40000000u) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(rome2_vfs_umap_rehash(&g_umap, 12u) == ROME2_VFS_REG_OK);
    CHECK(g_umap.bucket_count == 16u && g_umap.bucket_mask == 15u);

    memset(g_chunks, 0, sizeof(g_chunks));
    g_chunks[0].count = 4u; g_chunks[0].next = 1;
    g_chunks[1].count = 5u; g_chunks[1].next = -1;
    CHECK(rome2_vfs_chunked_str_clear(g_chunks, 2u, 0, &cleared_s) == ROME2_VFS_REG_OK && cleared_s == 9u);

    /* Self-aliased `push_back` for `0x112d7b40` and `0x100eaf40` triggering growth mid-push. */
    memset(&g_vec48, 0, sizeof(g_vec48));
    memset(&g_vec32, 0, sizeof(g_vec32));
    CHECK(rome2_vfs_u32_vec_push_back(&g_vec32, &v) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_u32_vec_push_back(&g_vec32, &g_vec32.items[0]) == ROME2_VFS_REG_OK);
    CHECK(g_vec32.count == 2u && g_vec32.capacity == 2u && g_vec32.items[1] == 77u);
    {
        rome2_vfs_entry48_rec r;
        memset(&r, 0, sizeof(r));
        r.key = 11u;
        CHECK(rome2_vfs_entry48_vec_push_back(&g_vec48, &r) == ROME2_VFS_REG_OK);
        CHECK(rome2_vfs_entry48_vec_push_back(&g_vec48, &g_vec48.items[0]) == ROME2_VFS_REG_OK);
        CHECK(g_vec48.count == 2u && g_vec48.items[1].key == 11u);
    }

    memset(g_diag_tbl, 0, sizeof(g_diag_tbl));
    rome2_vfs_get_static_key_c2370(g_diag_tbl[0].tag_dwords);
    g_diag_tbl[0].valid = 1u;
    snprintf(g_diag_tbl[0].text, sizeof(g_diag_tbl[0].text), "::");
    CHECK(rome2_vfs_diag_format_composite(g_diag_tbl, 1u, "vfs", "ok", diag_buf, sizeof(diag_buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(diag_buf, "vfs::ok") == 0);

    memset(&g_diag_prov, 0, sizeof(g_diag_prov));
    g_diag_prov.bit_count = 3u;
    g_diag_prov.excluded_mask = 0x02u;
    snprintf(g_diag_prov.bit_names[0], 32, "READ");
    snprintf(g_diag_prov.bit_names[1], 32, "SKIP");
    snprintf(g_diag_prov.bit_names[2], 32, "PACK");
    CHECK(rome2_vfs_format_bitmask_flags(&g_diag_prov, 0x07u, diag_buf, sizeof(diag_buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(diag_buf, " READ|PACK") == 0);

    memset(&g_atexit_state, 0, sizeof(g_atexit_state));
    g_atexit_state.ptr_119e11d8_allocated = 1u;
    g_atexit_state.ptr_120328f4_allocated = 1u;
    g_atexit_state.ptr_119e122c_allocated = 1u;
    g_atexit_state.ptr_12032a84_allocated = 1u;
    g_atexit_state.handle_12032b30_open = 1u;
    g_atexit_state.str_arr_119e11c0_buf_allocated = 1u;
    g_atexit_state.str_arr_119e11bc_count = 3u;
    g_atexit_state.str_arr_119e11cc_buf_allocated = 1u;
    g_atexit_state.str_arr_119e11c8_count = 2u;
    g_atexit_state.list_119e11dc_nodes_alive = 4u;
    g_atexit_state.hash_120329fc_entries_alive = 5u;
    g_atexit_state.hash_120329fc_buf_allocated = 1u;
    g_atexit_state.rb_12032a34_nodes_alive = 6u;
    rome2_vfs_run_all_atexit_destructors(&g_atexit_state);
    CHECK(g_atexit_state.freed_handles == 1u);
    CHECK(g_atexit_state.destroyed_strings == 16u);
    CHECK(g_atexit_state.freed_allocs == 17u);
    CHECK(g_atexit_state.list_119e11dc_head_reset == 1u);
}

int main(void) {
    test_pack_index_and_wildcards();
    test_win32_traverse_and_decode();
    test_containers_diag_and_atexit();
    printf("test_vfs_fs_index_atexit_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
