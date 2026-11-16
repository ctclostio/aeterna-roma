#ifndef ROME2_VFS_FS_MOUNT_OPS_H
#define ROME2_VFS_FS_MOUNT_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_archive_register.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Active VFS FileSystem rebuild, teardown, hash-container, and cmdline probe constants (Layer 30). */
#define ROME2_VFS_HASH_409_BUCKETS 0x199u
#define ROME2_VFS_HASH_LARGE_BUCKETS 0x124f8u
#define ROME2_VFS_UMAP_MAX_ELEMS 0x5555555u
#define ROME2_VFS_WAIT_INFINITE 0xffffffffu
#define ROME2_VFS_MOUNT_MAX_BUCKETS 64u
#define ROME2_VFS_MOUNT_MAX_STRS 64u
#define ROME2_VFS_MOUNT_MAX_ITEMS 32u
#define ROME2_VFS_MOUNT_MAX_NAME 96u
#define ROME2_VFS_TEARDOWN_CACHED_PTRS 10u

typedef struct rome2_vfs_mount_hash_slot {
    char key[ROME2_VFS_MOUNT_MAX_NAME];
    uint32_t value;
    uint8_t occupied;
} rome2_vfs_mount_hash_slot;

typedef struct rome2_vfs_mount_hash_table {
    uint32_t bucket_count;
    uint32_t entry_count;
    char sentinel_a[ROME2_VFS_MOUNT_MAX_NAME];
    char sentinel_b[ROME2_VFS_MOUNT_MAX_NAME];
    rome2_vfs_mount_hash_slot slots[ROME2_VFS_MOUNT_MAX_BUCKETS];
} rome2_vfs_mount_hash_table;

typedef struct rome2_vfs_mount_hash_iter {
    const rome2_vfs_mount_hash_table *table;
    uint32_t index;
    uint8_t at_end;
} rome2_vfs_mount_hash_iter;

typedef struct rome2_vfs_mount_str_vec {
    uint32_t capacity;
    uint32_t count;
    char items[ROME2_VFS_MOUNT_MAX_STRS][ROME2_VFS_MOUNT_MAX_NAME];
} rome2_vfs_mount_str_vec;

typedef struct rome2_vfs_mount_entry48_model {
    char name[ROME2_VFS_MOUNT_MAX_NAME];
    uint32_t flags;
    rome2_vfs_mount_str_vec child_vec;
} rome2_vfs_mount_entry48_model;

typedef uint8_t (*rome2_vfs_worker_wait_fn)(uint32_t handle_token, uint32_t timeout_ms, void *ctx);

typedef struct rome2_vfs_mount_subsystem_state {
    uint8_t vfs_active_1a88;
    uint8_t rebuild_flag_1f14;
    uint8_t cap_enable_25e0;
    uint8_t cap_once_done_2afc;
    uint8_t cap_cached_2af8;
    uint8_t cmdline_checked_5150;
    uint8_t cmdline_match_5151;
    uint8_t worker_valid_2b34;
    uint32_t worker_handle_2b30;
    uint32_t worker_waits_completed;
    uint8_t cached_slot_occupied[ROME2_VFS_TEARDOWN_CACHED_PTRS];
    char cached_slot_names[ROME2_VFS_TEARDOWN_CACHED_PTRS][ROME2_VFS_MOUNT_MAX_NAME];
    uint32_t umap_bucket_count;
    float umap_max_load_factor;
    rome2_vfs_mount_hash_table hash_table;
    rome2_vfs_mount_str_vec rebuild_names;
    rome2_vfs_mount_str_vec flushed_names;
    uint32_t mount_entry_count;
    rome2_vfs_mount_entry48_model mount_entries[ROME2_VFS_MOUNT_MAX_ITEMS];
} rome2_vfs_mount_subsystem_state;

/* Initializes bounded open-addressing hash table (`0x112d2e80` / `0x112de360`). */
rome2_vfs_reg_status rome2_vfs_mount_hash_init(
    rome2_vfs_mount_hash_table *table,
    uint32_t bucket_count,
    const char *sentinel_a,
    const char *sentinel_b);

/* Rehashes table to `new_bucket_count` (typically `2 * n + 1`), filtering sentinels (`0x112dc030`). */
rome2_vfs_reg_status rome2_vfs_mount_hash_rehash(
    rome2_vfs_mount_hash_table *table,
    uint32_t new_bucket_count);

/* Linear-probed insert/assign (`0x112de360` / `0x112ddd70`); triggers rehash `2*n+1` if full. */
rome2_vfs_reg_status rome2_vfs_mount_hash_insert_or_assign(
    rome2_vfs_mount_hash_table *table,
    const char *key,
    uint32_t value,
    uint8_t overwrite_existing,
    uint8_t *out_inserted);

/* Looks up key in open-addressing hash table (`0x112ddd70` find path). */
rome2_vfs_reg_status rome2_vfs_mount_hash_find(
    const rome2_vfs_mount_hash_table *table,
    const char *key,
    uint8_t *out_found,
    uint32_t *out_value);

/* Initializes and advances forward hash iterator skipping sentinels (`0x112c0940` / `0x112ac3b0`). */
rome2_vfs_reg_status rome2_vfs_mount_hash_iter_begin(
    const rome2_vfs_mount_hash_table *table,
    rome2_vfs_mount_hash_iter *iter);

rome2_vfs_reg_status rome2_vfs_mount_hash_iter_next(
    rome2_vfs_mount_hash_iter *iter,
    const rome2_vfs_mount_hash_slot **out_slot);

/* `vec<CAString>::push_back` with `0 -> 1` / `2x` growth and aliased index push (`0x112d89f0` / `0x112a74d0`). */
rome2_vfs_reg_status rome2_vfs_mount_str_vec_push_back(
    rome2_vfs_mount_str_vec *vec,
    const char *str);

rome2_vfs_reg_status rome2_vfs_mount_str_vec_push_self_index(
    rome2_vfs_mount_str_vec *vec,
    uint32_t existing_index);

rome2_vfs_reg_status rome2_vfs_mount_str_vec_copy(
    rome2_vfs_mount_str_vec *dst,
    const rome2_vfs_mount_str_vec *src);

/* Directory enum filter callback (`0x112e3f20`): checks `flag_0e`, skips `.` & `..`, appends `dir/name`. */
rome2_vfs_reg_status rome2_vfs_mount_enum_filter_append(
    rome2_vfs_mount_str_vec *out_vec,
    uint8_t flag_0e,
    const char *dir_prefix,
    const char *entry_name,
    uint8_t *out_appended);

/* Models `0x112a2ba0` unordered_map load-factor & max-size ceiling check (`0x5555555`). */
rome2_vfs_reg_status rome2_vfs_umap_check_rehash(
    uint32_t next_size,
    uint32_t bucket_count,
    float max_load_factor,
    uint32_t *out_next_buckets);

/* Initializes host model of Layer 30 mount rebuild/teardown subsystem. */
rome2_vfs_reg_status rome2_vfs_mount_subsystem_init(
    rome2_vfs_mount_subsystem_state *state);

/* Models `0x112d5cc0` / `0x112be150`: copies non-excluded mount roots into `rebuild_names`. */
rome2_vfs_reg_status rome2_vfs_mount_subsystem_rebuild(
    rome2_vfs_mount_subsystem_state *state,
    const char *const *candidates,
    uint32_t candidate_count,
    const char *const *excluded,
    uint32_t excluded_count);

/* Models `0x112da500`: commits rebuild entries under `[0x12031f14]` into `flushed_names` & hash map. */
rome2_vfs_reg_status rome2_vfs_mount_subsystem_flush(
    rome2_vfs_mount_subsystem_state *state);

/* Models `0x112e1a00`: tears down cached pointers `[0x12031a90]`, awaits worker `[0x12032b30]`, clears tables. */
rome2_vfs_reg_status rome2_vfs_mount_subsystem_teardown(
    rome2_vfs_mount_subsystem_state *state,
    rome2_vfs_worker_wait_fn wait_fn,
    void *wait_ctx);

/* Models `0x11302c40`: probes cached command line for `process_campaign_startpos`. */
rome2_vfs_reg_status rome2_vfs_mount_probe_startpos_cmdline(
    rome2_vfs_mount_subsystem_state *state,
    const char *cmdline,
    uint8_t *out_match);

/* Models `0x112b3040`: cached platform capability probe guarded by `[0x12032afc]` & `[0x120325e0]`. */
rome2_vfs_reg_status rome2_vfs_mount_probe_platform_cap(
    rome2_vfs_mount_subsystem_state *state,
    uint8_t hardware_probe_result,
    uint8_t *out_enabled);

#ifdef __cplusplus
}
#endif

#endif
