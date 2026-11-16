#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_init_xml_pack_ops.h"

static uint32_t g_checks = 0u;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond);            \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static rome2_vfs_pack_index_table g_boot_tbl;
static rome2_vfs_path_intern_env g_intern_env;
static rome2_vfs_hash12_map g_h12_map;

static void test_pack_bootstrap_and_intern(void) {
    uint8_t retail = 0u;
    const char *p1;
    const char *p2;
    const char *p3;
    const char *pe;

    memset(&g_boot_tbl, 0, sizeof(g_boot_tbl));
    CHECK(rome2_vfs_pack_index_bootstrap(&g_boot_tbl, "C:\\Rome2", 1u, &retail) == ROME2_VFS_REG_OK);
    CHECK(retail == 1u && g_boot_tbl.count == 1u && strcmp(g_boot_tbl.entries[0], "C:\\Rome2\\data\\") == 0);

    CHECK(rome2_vfs_pack_index_bootstrap(&g_boot_tbl, "C:\\Rome2", 0u, &retail) == ROME2_VFS_REG_OK);
    CHECK(retail == 0u && g_boot_tbl.count == 6u);
    CHECK(strcmp(g_boot_tbl.entries[0], "C:\\Rome2\\working_data_rome2\\") == 0);
    CHECK(strcmp(g_boot_tbl.entries[5], "C:\\Rome2\\raw_data\\empiredesigndata\\") == 0);

    memset(&g_intern_env, 0, sizeof(g_intern_env));
    pe = rome2_vfs_intern_path(&g_intern_env, "", 0u);
    CHECK(pe != NULL && strcmp(pe, "<empty_file_name>") == 0);
    p1 = rome2_vfs_intern_path(&g_intern_env, "Data/Packs/Rome.PACK", 0u);
    p2 = rome2_vfs_intern_path(&g_intern_env, "data\\packs\\rome.pack", 0u);
    p3 = rome2_vfs_intern_path(&g_intern_env, "Data/Packs/Rome.PACK", 1u);
    CHECK(p1 != NULL && p1 == p2 && p3 != p1);
    CHECK(strcmp(p1, "data\\packs\\rome.pack") == 0);
    CHECK(strcmp(p3, "Data\\Packs\\Rome.PACK") == 0);
    CHECK(g_intern_env.lock_spin_count == 0x2710u && g_intern_env.lock_depth == 0u && g_intern_env.max_lock_depth == 1u);
    CHECK(g_intern_env.table_buckets == 8u && g_intern_env.table_mask == 7u && g_intern_env.count == 2u);
}

static void test_cstr_and_handle_ops(void) {
    rome2_vfs_os_handle_box hbox;
    char joined[128];

    CHECK(rome2_vfs_map_handle_status(0xffffffffu) == 0x18u);
    CHECK(rome2_vfs_map_handle_status(42u) == 0u);
    CHECK(rome2_vfs_cstr_find("data/boot.pack", "boot", 2u) == 5u);
    CHECK(rome2_vfs_cstr_find("data/boot.pack", "boot", 6u) == 0xffffffffu);
    CHECK(rome2_vfs_cstr_compare_sub("ab_hello_yz", 3u, 5u, "hello") == 0);
    CHECK(rome2_vfs_cstr_compare_sub("ab_hello_yz", 3u, 4u, "hello") < 0);
    CHECK(rome2_vfs_cstr_at_or_nul("pack", 2u) == 'c');
    CHECK(rome2_vfs_cstr_at_or_nul("pack", 9u) == '\0');
    CHECK(rome2_vfs_cstr_join_c("prefix\\", "file.xml", joined, sizeof(joined)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(joined, "prefix\\file.xml") == 0);

    hbox.handle = 100u;
    hbox.last_error = 99u;
    CHECK(rome2_vfs_os_handle_close(&hbox, 1u, 5u) == 1u);
    CHECK(hbox.handle == 0xffffffffu && hbox.last_error == 0u);
    CHECK(rome2_vfs_os_handle_close(&hbox, 1u, 5u) == 0u);
    hbox.handle = 101u;
    CHECK(rome2_vfs_os_handle_close(&hbox, 0u, 5u) == 0u && hbox.last_error == 5u);
}

static void test_mod_xml_hash_and_budget(void) {
    static const char *const k_mods[2] = {"divide_et_impera.pack", "radious.pack"};
    char buf[256];
    uint32_t k1[4], k2[4], norm_type = 0u;
    uint8_t inserted = 0u;
    rome2_vfs_thread_budget_state bud;

    CHECK(rome2_vfs_format_mod_banner(NULL, 0u, buf, sizeof(buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(buf, "no mods") == 0);
    CHECK(rome2_vfs_format_mod_banner(k_mods, 2u, buf, sizeof(buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(buf, "mods: divide_et_impera.pack, radious.pack") == 0);

    rome2_vfs_get_static_key_c2190(k1);
    rome2_vfs_get_static_key_c21f0(k2);
    CHECK(k1[3] == 0x030dc5c8u && k2[3] == 0x030dc5c5u);

    bud.global_enabled = 1u;
    bud.thread_active = 1u;
    bud.cur_thread_id = 777u;
    bud.owner_thread_id = 777u;
    bud.chunk_cap_count = 4u;
    bud.chunk_used_count = 1u;
    bud.byte_cap = 1024u;
    bud.byte_used = 1000u;
    CHECK(rome2_vfs_thread_budget_try_consume(&bud, 32u, 1u) == 0u);
    CHECK(rome2_vfs_thread_budget_try_consume(&bud, 24u, 1u) == 1u);
    CHECK(bud.chunk_used_count == 2u && bud.byte_used == 1024u);

    memset(&g_h12_map, 0, sizeof(g_h12_map));
    g_h12_map.bucket_count = 2u;
    g_h12_map.max_load_factor = 1.0f;
    CHECK(rome2_vfs_hash12_emplace(&g_h12_map, "k1", 10u, &inserted) == ROME2_VFS_REG_OK && inserted == 1u);
    CHECK(rome2_vfs_hash12_emplace(&g_h12_map, "k1", 99u, &inserted) == ROME2_VFS_REG_OK && inserted == 0u);
    CHECK(rome2_vfs_hash12_emplace(&g_h12_map, "k2", 20u, &inserted) == ROME2_VFS_REG_OK && inserted == 1u);
    CHECK(g_h12_map.rehash_count == 0u);
    CHECK(rome2_vfs_hash12_emplace(&g_h12_map, "k3", 30u, &inserted) == ROME2_VFS_REG_OK && inserted == 1u);
    CHECK(g_h12_map.rehash_count == 1u && g_h12_map.bucket_count == 5u);

    CHECK(rome2_vfs_xml_save_classify(0x28u, 0u, &norm_type, NULL, 0u) == ROME2_VFS_XML_SAVE_NORMALIZED_1C && norm_type == 0x1cu);
    CHECK(rome2_vfs_xml_save_classify(0x1f6u, 1u, &norm_type, NULL, 0u) == ROME2_VFS_XML_SAVE_TYPE_1F6_OK);
    CHECK(rome2_vfs_xml_save_classify(0x1f6u, 0u, &norm_type, buf, sizeof(buf)) == ROME2_VFS_XML_SAVE_TYPE_1F6_PROBLEM);
    CHECK(strcmp(buf, "Problem saving type in XML with ") == 0);
    CHECK(rome2_vfs_xml_save_classify(0x30u, 0u, &norm_type, NULL, 0u) == ROME2_VFS_XML_SAVE_SWITCH);
    CHECK(rome2_vfs_xml_save_classify(0x250u, 0u, &norm_type, NULL, 0u) == ROME2_VFS_XML_SAVE_FALLBACK);
}

int main(void) {
    test_pack_bootstrap_and_intern();
    test_cstr_and_handle_ops();
    test_mod_xml_hash_and_budget();
    printf("test_vfs_fs_init_xml_pack_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
