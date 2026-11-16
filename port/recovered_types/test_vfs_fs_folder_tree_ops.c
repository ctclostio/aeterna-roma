#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_folder_tree_ops.h"

static uint32_t g_checks = 0u;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond);            \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static rome2_vfs_folder_forest g_src_forest;
static rome2_vfs_folder_forest g_dst_forest;
static rome2_vfs_slab20_pool g_slab20;
static rome2_vfs_split_path48 g_parts48;

static void test_folder_forest_and_parser(void) {
    int32_t root = -1;
    int32_t child = -1;
    int32_t cloned = -1;
    uint32_t d_folders = 0u;
    uint32_t d_pairs = 0u;

    memset(&g_src_forest, 0, sizeof(g_src_forest));
    memset(&g_dst_forest, 0, sizeof(g_dst_forest));
    CHECK(rome2_vfs_folder_forest_add_node(&g_src_forest, -1, "root", "C:\\Rome2\\data", "retail", &root) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_folder_forest_add_node(&g_src_forest, root, "sub", "C:\\Rome2\\data\\sub", "pack", &child) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_parse_tab_kv_lines(&g_src_forest, root, "removed_key\t0\r\nunused_key\t1\n") == ROME2_VFS_REG_OK);
    CHECK(g_src_forest.nodes[root].pair_count == 2u && g_src_forest.nodes[root].pair_capacity == 8u);
    CHECK(strcmp(g_src_forest.nodes[root].pairs[1].key, "unused_key") == 0);
    CHECK(strcmp(g_src_forest.nodes[root].pairs[1].value, "1") == 0);

    CHECK(rome2_vfs_folder_clone_subtree(&g_src_forest, root, &g_dst_forest, -1, &cloned) == ROME2_VFS_REG_OK);
    CHECK(g_dst_forest.count == 2u && g_dst_forest.nodes[cloned].pair_count == 2u);
    CHECK(rome2_vfs_folder_destroy_subtree(&g_dst_forest, cloned, &d_folders, &d_pairs) == ROME2_VFS_REG_OK);
    CHECK(d_folders == 2u && d_pairs == 2u);
}

static void test_path_slab_utf8_and_switch(void) {
    char out_buf[256];
    uint8_t flag = 0u;
    uint32_t vals[6];
    uint16_t wbuf[32];
    uint16_t wcopy[32];
    uint32_t wlen = 0u;

    CHECK(rome2_vfs_strip_data_prefix("C:\\data\\units.pack", out_buf, sizeof(out_buf), &flag) == ROME2_VFS_REG_OK);
    CHECK(flag == 1u && strcmp(out_buf, "units.pack") == 0);
    CHECK(rome2_vfs_strip_data_prefix("mods\\extra\\a.pack", out_buf, sizeof(out_buf), &flag) == ROME2_VFS_REG_OK);
    CHECK(flag == 0u && strcmp(out_buf, "mods\\extra\\a.pack") == 0);

    CHECK(rome2_vfs_normalize_dot_segments("a\\b\\.\\c\\.\\d.pack", 1u, out_buf, sizeof(out_buf), &flag) == ROME2_VFS_REG_OK);
    CHECK(flag == 1u && strcmp(out_buf, "a\\b\\c\\d.pack") == 0);
    CHECK(rome2_vfs_normalize_dot_segments("a\\b\\..\\c\\d.pack", 0u, out_buf, sizeof(out_buf), &flag) == ROME2_VFS_REG_OK);
    CHECK(flag == 1u && strcmp(out_buf, "a\\c\\d.pack") == 0);

    CHECK(rome2_vfs_split_path_parts48("X:\\Rome2\\data\\boot.pack", &g_parts48) == ROME2_VFS_REG_OK);
    CHECK(strcmp(g_parts48.drive, "X:") == 0 && strcmp(g_parts48.dir, "\\Rome2\\data\\") == 0);
    CHECK(strcmp(g_parts48.stem, "boot") == 0 && strcmp(g_parts48.ext, ".pack") == 0);

    CHECK(rome2_vfs_slab20_init(&g_slab20, 4u) == ROME2_VFS_REG_OK);
    CHECK(g_slab20.head == 0 && g_slab20.next_idx[0] == 1 && g_slab20.next_idx[3] == -1);
    CHECK(rome2_vfs_intern_check_limit(ROME2_VFS_L33_UMAP_MAX_ELEMS) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(rome2_vfs_intern_check_limit(10u) == ROME2_VFS_REG_OK);

    rome2_vfs_fill_u32_range(vals, 6u, 0x12345678u);
    CHECK(vals[0] == 0x12345678u && vals[5] == 0x12345678u);

    CHECK(rome2_vfs_utf8_to_utf16("Roma\xc3\xa6", wbuf, 32u, &wlen) == ROME2_VFS_REG_OK);
    CHECK(wlen == 5u && wbuf[4] == 0x00e6u);
    CHECK(rome2_vfs_assign_utf16(wcopy, 32u, wbuf, &wlen) == ROME2_VFS_REG_OK && wlen == 5u && wcopy[4] == 0x00e6u);

    CHECK(rome2_vfs_archive_entry_name_matches_tail("boot.pack", "data\\boot.pack") == 1u);
    CHECK(rome2_vfs_validate_switch_tag_1_to_d(0x0du) == 1u);
    CHECK(rome2_vfs_validate_switch_tag_1_to_d(0x0eu) == 1u);
    CHECK(rome2_vfs_validate_switch_tag_1_to_d(0x0fu) == 0u);
}

int main(void) {
    test_folder_forest_and_parser();
    test_path_slab_utf8_and_switch();
    printf("test_vfs_fs_folder_tree_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
