#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_primary_ops.h"

static int g_checks = 0;
static rome2_vfs_primary_fs_state g_test_state;

#define CHECK(expr)                                                          \
    do {                                                                     \
        g_checks += 1;                                                       \
        if (!(expr)) {                                                       \
            fprintf(stderr, "CHECK FAILED (%s:%d): %s\n", __FILE__, __LINE__, #expr); \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static int test_layouts_and_growth(void) {
    uint32_t cap = 0u;
    CHECK(sizeof(rome2_vfs_active_fs_obj32) == ROME2_VFS_PRIMARY_OBJ_BYTES);
    CHECK(sizeof(rome2_vfs_mount_vec_header12_32) == 12u);
    CHECK(sizeof(rome2_vfs_root_archive_header20_32) == 20u);
    CHECK(sizeof(rome2_vfs_loose_table12_32) == 12u);
    CHECK(sizeof(rome2_vfs_large_hash16_32) == 16u);

    CHECK(rome2_vfs_fs_primary_vec_grow_capacity(0u, &cap) == ROME2_VFS_REG_OK && cap == 1u);
    CHECK(rome2_vfs_fs_primary_vec_grow_capacity(1u, &cap) == ROME2_VFS_REG_OK && cap == 2u);
    CHECK(rome2_vfs_fs_primary_vec_grow_capacity(16u, &cap) == ROME2_VFS_REG_OK && cap == 32u);
    CHECK(rome2_vfs_fs_primary_vec_grow_capacity(0x10000000u, &cap) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(rome2_vfs_fs_primary_vec_grow_capacity(0u, NULL) == ROME2_VFS_REG_BAD_ARGUMENT);
    return 0;
}

static int test_roots_filter_and_clamped_index(void) {
    const char *excluded[2] = { "data_rome2.pack", "boot.pack" };
    char path_buf[ROME2_VFS_PRIMARY_MAX_NAME];
    char pending_out[4][ROME2_VFS_PRIMARY_MAX_NAME];
    uint32_t copied = 0u;
    uint8_t found = 0u;
    uint32_t size_val = 0u;

    CHECK(rome2_vfs_fs_primary_state_init(&g_test_state) == ROME2_VFS_REG_OK);
    CHECK(g_test_state.next_dynamic_id == ROME2_VFS_DYNAMIC_ID_SEED);

    /* Uninitialized / empty clamped lookup (+0x2c) returns found=0. */
    CHECK(rome2_vfs_fs_primary_get_entry_at_clamped(&g_test_state, 9u, path_buf, sizeof(path_buf), &found) == ROME2_VFS_REG_OK);
    CHECK(found == 0u && path_buf[0] == '\0');

    CHECK(rome2_vfs_fs_primary_add_archive_root(&g_test_state, "boot.pack") == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_fs_primary_add_archive_root(&g_test_state, "data.pack") == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_fs_primary_add_archive_root(&g_test_state, "data_rome2.pack") == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_fs_primary_add_archive_root(&g_test_state, "local_en.pack") == ROME2_VFS_REG_OK);

    CHECK(rome2_vfs_fs_primary_filter_active_roots(&g_test_state, excluded, 2u) == ROME2_VFS_REG_OK);
    CHECK(g_test_state.active_root_count == 2u);
    CHECK(strcmp(g_test_state.active_roots[0], "data.pack") == 0);
    CHECK(strcmp(g_test_state.active_roots[1], "local_en.pack") == 0);

    memcpy(g_test_state.pending_roots[0], "mod/pending.pack", 17u);
    g_test_state.pending_root_count = 1u;
    CHECK(rome2_vfs_fs_primary_copy_pending_roots(&g_test_state, pending_out, 4u, &copied) == ROME2_VFS_REG_OK);
    CHECK(copied == 1u && strcmp(pending_out[0], "mod/pending.pack") == 0);

    CHECK(rome2_vfs_fs_primary_seed_entry(&g_test_state, "db/units_tables/units", 4096u, 0u, 1u, 0u, 1u) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_fs_primary_seed_entry(&g_test_state, "script/campaign.lua", 1024u, 0u, 0u, 1u, 0u) == ROME2_VFS_REG_OK);

    CHECK(rome2_vfs_fs_primary_get_entry_at_clamped(&g_test_state, 99u, path_buf, sizeof(path_buf), &found) == ROME2_VFS_REG_OK);
    CHECK(found == 1u && strcmp(path_buf, "script/campaign.lua") == 0);

    CHECK(rome2_vfs_fs_primary_entry_exists(&g_test_state, "db/units_tables/units", &found) == ROME2_VFS_REG_OK);
    CHECK(found == 1u);
    CHECK(rome2_vfs_fs_primary_entry_exists(&g_test_state, "missing.txt", &found) == ROME2_VFS_REG_OK);
    CHECK(found == 0u);

    CHECK(rome2_vfs_fs_primary_get_entry_size(&g_test_state, "db/units_tables/units", &size_val) == ROME2_VFS_REG_OK);
    CHECK(size_val == 4096u);
    CHECK(rome2_vfs_fs_primary_get_entry_size(&g_test_state, "missing.txt", &size_val) == ROME2_VFS_REG_OK);
    CHECK(size_val == ROME2_VFS_SENTINEL_U32);
    return 0;
}

static int test_entry_info_dynamic_ids_and_subfs(void) {
    rome2_vfs_entry_info32 info;
    char name_buf[ROME2_VFS_PRIMARY_MAX_NAME];
    uint32_t dyn_id = 0u;
    uint32_t dyn_id2 = 0u;
    uint8_t ok = 0u;

    CHECK(rome2_vfs_fs_primary_state_init(&g_test_state) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_fs_primary_seed_entry(&g_test_state, "text/localisation.loc", 512u, 0u, 0u, 1u, 1u) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_fs_primary_seed_entry(&g_test_state, "ui/frontend.twui", 888u, 0u, 1u, 0u, 0u) == ROME2_VFS_REG_OK);

    /* Uninitialized query (+0x64) returns -1/-1 bounds and register (+0x68) returns 0xffffffffu. */
    CHECK(rome2_vfs_fs_primary_query_entry_info(&g_test_state, "text/localisation.loc", &info, name_buf, sizeof(name_buf)) == ROME2_VFS_REG_OK);
    CHECK(info.size_lo_00 == ROME2_VFS_SENTINEL_U32 && info.size_hi_04 == ROME2_VFS_SENTINEL_U32);
    CHECK(rome2_vfs_fs_primary_register_or_get_id(&g_test_state, "text/localisation.loc", &dyn_id) == ROME2_VFS_REG_OK);
    CHECK(dyn_id == ROME2_VFS_SENTINEL_U32);

    g_test_state.vfs_initialized = 1u;
    CHECK(rome2_vfs_fs_primary_query_entry_info(&g_test_state, "text/localisation.loc", &info, name_buf, sizeof(name_buf)) == ROME2_VFS_REG_OK);
    CHECK(info.size_lo_00 == 512u && info.flag_1c == 1u && strcmp(name_buf, "text/localisation.loc") == 0);
    CHECK(g_test_state.active_ops == 0u);

    CHECK(rome2_vfs_fs_primary_register_or_get_id(&g_test_state, "text/localisation.loc", &dyn_id) == ROME2_VFS_REG_OK);
    CHECK(dyn_id == ROME2_VFS_DYNAMIC_ID_SEED);
    CHECK(rome2_vfs_fs_primary_register_or_get_id(&g_test_state, "text/localisation.loc", &dyn_id2) == ROME2_VFS_REG_OK);
    CHECK(dyn_id2 == dyn_id);

    /* +0x70 mounts lazy sub-FS when create_subfs=1; mode_value=1 short-circuits on already-registered check. */
    CHECK(rome2_vfs_fs_primary_mount_subfs_and_register(&g_test_state, "ui/frontend.twui", 1u, 1u, &ok) == ROME2_VFS_REG_OK);
    CHECK(g_test_state.sub_fs_mounted == 1u && g_test_state.sub_fs_mode == 1u && ok == 0u);

    /* +0x50 clears lazy sub-FS, then create_subfs=0 registers ui/frontend.twui at next ID. */
    CHECK(rome2_vfs_fs_primary_destroy_subfs(&g_test_state) == ROME2_VFS_REG_OK);
    CHECK(g_test_state.sub_fs_mounted == 0u);
    CHECK(rome2_vfs_fs_primary_mount_subfs_and_register(&g_test_state, "ui/frontend.twui", 0u, 0u, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 1u);
    CHECK(rome2_vfs_fs_primary_register_or_get_id(&g_test_state, "ui/frontend.twui", &dyn_id2) == ROME2_VFS_REG_OK);
    CHECK(dyn_id2 == ROME2_VFS_DYNAMIC_ID_SEED + 1u);

    /* Flags & dtor (+0x4c, +0x54, +0x6c, +0x74). */
    CHECK(rome2_vfs_fs_primary_set_override_path(&g_test_state, "mod_override") == ROME2_VFS_REG_OK);
    CHECK(g_test_state.override_active == 1u && strcmp(g_test_state.override_path, "mod_override") == 0);
    CHECK(rome2_vfs_fs_primary_set_flag_1a8a(&g_test_state, 1u) == ROME2_VFS_REG_OK && g_test_state.flag_1a8a == 1u);
    CHECK(rome2_vfs_fs_primary_set_val_1ad8(&g_test_state, 0x1234u) == ROME2_VFS_REG_OK && g_test_state.val_1ad8 == 0x1234u);
    CHECK(rome2_vfs_fs_primary_dtor(&g_test_state) == ROME2_VFS_REG_OK && g_test_state.active_ops == 0u);

    /* Bad argument guards. */
    CHECK(rome2_vfs_fs_primary_state_init(NULL) == ROME2_VFS_REG_BAD_ARGUMENT);
    CHECK(rome2_vfs_fs_primary_filter_active_roots(&g_test_state, NULL, 1u) == ROME2_VFS_REG_BAD_ARGUMENT);
    return 0;
}

int main(void) {
    if (test_layouts_and_growth() != 0) {
        return 1;
    }
    if (test_roots_filter_and_clamped_index() != 0) {
        return 1;
    }
    if (test_entry_info_dynamic_ids_and_subfs() != 0) {
        return 1;
    }
    printf("test_vfs_fs_primary_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
