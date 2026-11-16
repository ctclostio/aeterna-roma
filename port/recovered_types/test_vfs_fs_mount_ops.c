#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_mount_ops.h"

static int g_checks = 0;
static rome2_vfs_mount_subsystem_state g_state;
static rome2_vfs_mount_hash_table g_hash;
static rome2_vfs_mount_str_vec g_vec;
static rome2_vfs_mount_str_vec g_vec_copy;

#define CHECK(expr)                                                          \
    do {                                                                     \
        g_checks += 1;                                                       \
        if (!(expr)) {                                                       \
            fprintf(stderr, "CHECK FAILED (%s:%d): %s\n", __FILE__, __LINE__, #expr); \
            return 1;                                                        \
        }                                                                    \
    } while (0)

typedef struct test_wait_probe_ctx {
    uint32_t expected_handle;
    uint32_t last_timeout;
    uint32_t calls;
    uint8_t allow_success;
} test_wait_probe_ctx;

static uint8_t test_wait_worker_callback(uint32_t handle_token, uint32_t timeout_ms, void *ctx) {
    test_wait_probe_ctx *p = (test_wait_probe_ctx *)ctx;
    if (p == NULL) {
        return 0u;
    }
    p->calls += 1u;
    p->last_timeout = timeout_ms;
    return (p->allow_success != 0u && handle_token == p->expected_handle) ? 1u : 0u;
}

static int test_layouts_and_open_hash_rehash(void) {
    uint8_t inserted = 0u;
    uint8_t found = 0u;
    uint32_t val = 0u;
    uint32_t iter_seen = 0u;
    uint32_t next_buckets = 0u;
    rome2_vfs_mount_hash_iter iter;
    const rome2_vfs_mount_hash_slot *slot = NULL;
    uint32_t i;

    CHECK(sizeof(rome2_vfs_hash_entry8_32) == 8u);
    CHECK(sizeof(rome2_vfs_open_hash16_32) == 16u);
    CHECK(sizeof(rome2_vfs_hash_iter20_32) == 20u);
    CHECK(sizeof(rome2_vfs_unordered_map32_32) == 32u);
    CHECK(sizeof(rome2_vfs_rbtree_header12_32) == 12u);
    CHECK(sizeof(rome2_vfs_mount_entry48_32) == 48u);

    /* Init 5-bucket open-address hash and verify 2*n+1 rehash growth on saturation (0x112de360/0x112dc030). */
    CHECK(rome2_vfs_mount_hash_init(&g_hash, 5u, "<empty>", "<tomb>") == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_mount_hash_insert_or_assign(&g_hash, "<empty>", 1u, 1u, &inserted) == ROME2_VFS_REG_BAD_ARGUMENT);
    for (i = 0u; i < 9u; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "data/pack_%u.pack", i);
        CHECK(rome2_vfs_mount_hash_insert_or_assign(&g_hash, key, 100u + i, 1u, &inserted) == ROME2_VFS_REG_OK);
        CHECK(inserted == 1u);
    }
    CHECK(g_hash.bucket_count == 11u); /* grew 5 -> 11 */
    CHECK(g_hash.entry_count == 9u);

    /* Overwrite vs preserve behavior on existing key (`0x112de360` vs `0x112ddd70`). */
    CHECK(rome2_vfs_mount_hash_insert_or_assign(&g_hash, "data/pack_3.pack", 999u, 0u, &inserted) == ROME2_VFS_REG_OK);
    CHECK(inserted == 0u);
    CHECK(rome2_vfs_mount_hash_find(&g_hash, "data/pack_3.pack", &found, &val) == ROME2_VFS_REG_OK);
    CHECK(found == 1u && val == 103u);

    CHECK(rome2_vfs_mount_hash_insert_or_assign(&g_hash, "data/pack_3.pack", 999u, 1u, &inserted) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_mount_hash_find(&g_hash, "data/pack_3.pack", &found, &val) == ROME2_VFS_REG_OK);
    CHECK(found == 1u && val == 999u);

    /* Iterator skips sentinel slots and visits all 9 occupied entries (`0x112c0940` / `0x112ac3b0`). */
    CHECK(rome2_vfs_mount_hash_iter_begin(&g_hash, &iter) == ROME2_VFS_REG_OK);
    while (rome2_vfs_mount_hash_iter_next(&iter, &slot) == ROME2_VFS_REG_OK && slot != NULL) {
        iter_seen += 1u;
    }
    CHECK(iter_seen == 9u);

    /* `0x112a2ba0` unordered_map load factor & max_size ceiling guard. */
    CHECK(rome2_vfs_umap_check_rehash(5u, 8u, 1.0f, &next_buckets) == ROME2_VFS_REG_OK && next_buckets == 8u);
    CHECK(rome2_vfs_umap_check_rehash(9u, 8u, 1.0f, &next_buckets) == ROME2_VFS_REG_OK && next_buckets == 16u);
    CHECK(rome2_vfs_umap_check_rehash(ROME2_VFS_UMAP_MAX_ELEMS + 1u, 8u, 1.0f, &next_buckets) == ROME2_VFS_REG_RANGE_ERROR);
    return 0;
}

static int test_str_vec_alias_and_enum_filter(void) {
    uint8_t appended = 0u;

    memset(&g_vec, 0, sizeof(g_vec));
    CHECK(rome2_vfs_mount_str_vec_push_back(&g_vec, "root/alpha") == ROME2_VFS_REG_OK);
    CHECK(g_vec.capacity == 1u && g_vec.count == 1u);
    CHECK(rome2_vfs_mount_str_vec_push_self_index(&g_vec, 0u) == ROME2_VFS_REG_OK);
    CHECK(g_vec.capacity == 2u && g_vec.count == 2u);
    CHECK(strcmp(g_vec.items[1], "root/alpha") == 0);

    /* `0x112e3f20` filter skips disabled flags, `.` and `..`, joins prefix & name cleanly. */
    CHECK(rome2_vfs_mount_enum_filter_append(&g_vec, 0u, "data", "ignored.xml", &appended) == ROME2_VFS_REG_OK);
    CHECK(appended == 0u);
    CHECK(rome2_vfs_mount_enum_filter_append(&g_vec, 1u, "data", ".", &appended) == ROME2_VFS_REG_OK);
    CHECK(appended == 0u);
    CHECK(rome2_vfs_mount_enum_filter_append(&g_vec, 1u, "data", "..", &appended) == ROME2_VFS_REG_OK);
    CHECK(appended == 0u);
    CHECK(rome2_vfs_mount_enum_filter_append(&g_vec, 1u, "data/db", "units.bin", &appended) == ROME2_VFS_REG_OK);
    CHECK(appended == 1u && g_vec.count == 3u && strcmp(g_vec.items[2], "data/db/units.bin") == 0);

    CHECK(rome2_vfs_mount_str_vec_copy(&g_vec_copy, &g_vec) == ROME2_VFS_REG_OK);
    CHECK(g_vec_copy.count == 3u && strcmp(g_vec_copy.items[2], "data/db/units.bin") == 0);
    return 0;
}

static int test_rebuild_flush_probes_and_teardown(void) {
    const char *candidates[4] = { "boot.pack", "mod_a.pack", "local_en.pack", "excluded.pack" };
    const char *excluded[2] = { "boot.pack", "excluded.pack" };
    test_wait_probe_ctx wait_ctx = { 0x1234u, 0u, 0u, 1u };
    uint8_t match = 0u;
    uint8_t cap_enabled = 0u;
    uint8_t found = 0u;
    uint32_t val = 0u;

    CHECK(rome2_vfs_mount_subsystem_init(&g_state) == ROME2_VFS_REG_OK);
    g_state.vfs_active_1a88 = 1u;
    g_state.rebuild_flag_1f14 = 1u;
    g_state.worker_valid_2b34 = 1u;
    g_state.worker_handle_2b30 = 0x1234u;
    g_state.cached_slot_occupied[0] = 1u;
    memcpy(g_state.cached_slot_names[0], "cached_root", 12u);

    /* `0x112d5cc0` rebuild + `0x112da500` flush populates flushed names & hash table. */
    CHECK(rome2_vfs_mount_subsystem_rebuild(&g_state, candidates, 4u, excluded, 2u) == ROME2_VFS_REG_OK);
    CHECK(g_state.rebuild_names.count == 2u);
    CHECK(strcmp(g_state.rebuild_names.items[0], "mod_a.pack") == 0);
    CHECK(strcmp(g_state.rebuild_names.items[1], "local_en.pack") == 0);

    CHECK(rome2_vfs_mount_subsystem_flush(&g_state) == ROME2_VFS_REG_OK);
    CHECK(g_state.flushed_names.count == 2u);
    CHECK(rome2_vfs_mount_hash_find(&g_state.hash_table, "local_en.pack", &found, &val) == ROME2_VFS_REG_OK);
    CHECK(found == 1u && val == 2u);

    /* `0x11302c40` cached cmdline probe caches match & ignores subsequent cmdline argument changes. */
    CHECK(rome2_vfs_mount_probe_startpos_cmdline(&g_state, "rome2.exe process_campaign_startpos", &match) == ROME2_VFS_REG_OK);
    CHECK(match == 1u && g_state.cmdline_checked_5150 == 1u);
    CHECK(rome2_vfs_mount_probe_startpos_cmdline(&g_state, "rome2.exe --normal", &match) == ROME2_VFS_REG_OK);
    CHECK(match == 1u);

    /* `0x112b3040` cached capability probe: when cap_enable_25e0 == 0 returns 1 without hardware failure. */
    g_state.cap_enable_25e0 = 0u;
    CHECK(rome2_vfs_mount_probe_platform_cap(&g_state, 0u, &cap_enabled) == ROME2_VFS_REG_OK);
    CHECK(cap_enabled == 1u);
    g_state.cap_once_done_2afc = 0u;
    g_state.cap_enable_25e0 = 1u;
    CHECK(rome2_vfs_mount_probe_platform_cap(&g_state, 0u, &cap_enabled) == ROME2_VFS_REG_OK);
    CHECK(cap_enabled == 0u);

    /* `0x112e1a00` teardown awaits worker handle with INFINITE (`0xffffffff`), resets active flag & clears caches. */
    CHECK(rome2_vfs_mount_subsystem_teardown(&g_state, test_wait_worker_callback, &wait_ctx) == ROME2_VFS_REG_OK);
    CHECK(wait_ctx.calls == 1u && wait_ctx.last_timeout == ROME2_VFS_WAIT_INFINITE);
    CHECK(g_state.worker_waits_completed == 1u);
    CHECK(g_state.vfs_active_1a88 == 0u);
    CHECK(g_state.cached_slot_occupied[0] == 0u);
    CHECK(g_state.rebuild_names.count == 0u && g_state.flushed_names.count == 0u);
    CHECK(g_state.hash_table.entry_count == 0u);
    return 0;
}

int main(void) {
    if (test_layouts_and_open_hash_rehash() != 0) {
        return 1;
    }
    if (test_str_vec_alias_and_enum_filter() != 0) {
        return 1;
    }
    if (test_rebuild_flush_probes_and_teardown() != 0) {
        return 1;
    }
    printf("test_vfs_fs_mount_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
