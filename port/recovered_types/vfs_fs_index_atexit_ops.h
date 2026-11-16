#ifndef ROME2_VFS_FS_INDEX_ATEXIT_OPS_H
#define ROME2_VFS_FS_INDEX_ATEXIT_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_archive_register.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Layer 31 bounded model limits matching reconstructed VFS 32-bit structures. */
#define ROME2_VFS_IDX_MAX_PREFIXES 32u
#define ROME2_VFS_IDX_MAX_PATH 160u
#define ROME2_VFS_IDX_MAX_BUCKETS 64u
#define ROME2_VFS_IDX_UMAP_MAX_BUCKETS 0x3fffffffu
#define ROME2_VFS_IDX_MAX_NODES 32u
#define ROME2_VFS_IDX_MAX_CHUNKS 16u
#define ROME2_VFS_IDX_MAX_ELEMS 32u
#define ROME2_VFS_IDX_MAX_FLAGS 32u

/* Windows FILETIME (1601-01-01) to Unix time_t (1970-01-01) epoch offset in seconds. */
#define ROME2_WIN32_EPOCH_OFFSET_SEC 11644473600ULL
/* Win32 `0x100fec00` adds `0x49ef7d10` == `(-11644470000) mod 2^32` (3600s off true epoch). */
#define ROME2_WIN32_EPOCH_LOW32_ADD 0x49ef7d10u

#define ROME2_WIN32_ATTR_READONLY 0x01u
#define ROME2_WIN32_ATTR_HIDDEN 0x02u
#define ROME2_WIN32_ATTR_DIRECTORY 0x10u

/* Pack-entry index prefix table (`0x10122cb0` / `0x10122640` singletons). */
typedef struct rome2_vfs_pack_index_table {
    uint32_t count;
    char entries[ROME2_VFS_IDX_MAX_PREFIXES][ROME2_VFS_IDX_MAX_PATH];
} rome2_vfs_pack_index_table;

typedef uint8_t (*rome2_vfs_idx_direct_pred_fn)(const char *rel_path, void *ctx);
typedef uint8_t (*rome2_vfs_idx_probe_open_fn)(const char *full_path, void *ctx);

/* Host model of `0x10122cb0` / `0x10122640` TLS-guarded singletons + resolution helpers. */
typedef struct rome2_vfs_pack_index_env {
    uint8_t primary_ready;
    uint8_t empty_ready;
    rome2_vfs_pack_index_table primary_singleton;
    rome2_vfs_pack_index_table empty_singleton;
    uint32_t open_handle_seq;
} rome2_vfs_pack_index_env;

/* Decoded Win32 find entry delivered by `0x100fec00` to its callback. */
typedef struct rome2_vfs_win32_find_info {
    uint32_t file_size_low;
    uint32_t mtime_unix_low32;
    uint8_t valid;
    uint8_t writable;
    uint8_t is_dir;
    uint8_t hidden;
} rome2_vfs_win32_find_info;

/* Simulated filesystem entry fed into deterministic `0x100fec00` host directory traversal. */
typedef struct rome2_vfs_win32_sim_entry {
    char dir[ROME2_VFS_IDX_MAX_PATH];
    char name[ROME2_VFS_IDX_MAX_PATH];
    uint32_t attributes;
    uint32_t file_size_low;
    uint64_t last_write_filetime;
} rome2_vfs_win32_sim_entry;

typedef struct rome2_vfs_win32_sim_fs {
    uint32_t count;
    rome2_vfs_win32_sim_entry entries[ROME2_VFS_IDX_MAX_ELEMS];
} rome2_vfs_win32_sim_fs;

typedef void (*rome2_vfs_win32_visit_fn)(
    const char *dir_path,
    const char *file_name,
    const char *pattern,
    const rome2_vfs_win32_find_info *info,
    void *user_ctx);

/* Host RB-tree node + refcount control model for `0x112a26f0` and `0x11724b00`. */
typedef struct rome2_vfs_rb_ref_node {
    uint8_t active;
    uint8_t is_nil;
    int32_t left;
    int32_t right;
    uint32_t strong_refs;
    uint32_t weak_refs;
    uint32_t destroyed_payloads;
    uint32_t deallocated_ctrls;
} rome2_vfs_rb_ref_node;

/* Host 48B mount node model for `0x112a28a0` (`_Free_nodes`). */
typedef struct rome2_vfs_mount_free_node {
    uint8_t active;
    uint8_t has_aux_buf;
    uint32_t child_count;
    int32_t next;
} rome2_vfs_mount_free_node;

/* Host `unordered_map::_Rehash` (`0x112b03b0`) bucket model. */
typedef struct rome2_vfs_umap_node {
    uint8_t active;
    char key[ROME2_VFS_IDX_MAX_PATH];
    uint32_t value;
} rome2_vfs_umap_node;

typedef struct rome2_vfs_umap_rehash_state {
    uint32_t bucket_count;
    uint32_t bucket_mask;
    uint32_t node_count;
    rome2_vfs_umap_node nodes[ROME2_VFS_IDX_MAX_NODES];
    uint32_t bucket_heads[ROME2_VFS_IDX_MAX_BUCKETS];
    uint32_t bucket_counts[ROME2_VFS_IDX_MAX_BUCKETS];
} rome2_vfs_umap_rehash_state;

/* Host chunked string chain (`0x112b5420`). */
typedef struct rome2_vfs_str_chunk {
    uint32_t count;
    int32_t next;
} rome2_vfs_str_chunk;

/* Host 48B-record and dword-vector states (`0x112d7b40`, `0x100eaf40`). */
typedef struct rome2_vfs_entry48_rec {
    uint32_t key;
    uint32_t tag;
    uint8_t payload[40];
} rome2_vfs_entry48_rec;
_Static_assert(sizeof(rome2_vfs_entry48_rec) == 48u, "host entry48 size");

typedef struct rome2_vfs_entry48_vec {
    uint32_t capacity;
    uint32_t count;
    rome2_vfs_entry48_rec items[ROME2_VFS_IDX_MAX_ELEMS];
} rome2_vfs_entry48_vec;

typedef struct rome2_vfs_u32_vec {
    uint32_t capacity;
    uint32_t count;
    uint32_t items[ROME2_VFS_IDX_MAX_ELEMS];
} rome2_vfs_u32_vec;

/* Host diagnostics provider (`0x112c2370`, `0x112a5530`, `0x112a56d0`, `0x112f0b90`). */
typedef struct rome2_vfs_diag_kv {
    uint32_t tag_dwords[4];
    uint8_t valid;
    char text[64];
} rome2_vfs_diag_kv;

typedef struct rome2_vfs_diag_provider {
    uint32_t bit_count;
    uint32_t excluded_mask;
    char bit_names[ROME2_VFS_IDX_MAX_FLAGS][32];
} rome2_vfs_diag_provider;

/* Layer 31 singleton atexit teardown snapshot (`0x11724a10` .. `0x11724e50`). */
typedef struct rome2_vfs_atexit_globals_state {
    uint8_t ptr_119e11d8_allocated;
    uint8_t ptr_120328f4_allocated;
    uint8_t ptr_119e122c_allocated;
    uint8_t ptr_12032a84_allocated;
    uint8_t handle_12032b30_open;
    uint32_t str_arr_119e11bc_count;
    uint8_t str_arr_119e11c0_buf_allocated;
    uint32_t str_arr_119e11c8_count;
    uint8_t str_arr_119e11cc_buf_allocated;
    uint32_t list_119e11dc_nodes_alive;
    uint8_t list_119e11dc_head_reset;
    uint32_t hash_120329fc_entries_alive;
    uint8_t hash_120329fc_buf_allocated;
    uint32_t rb_12032a34_nodes_alive;
    uint32_t freed_allocs;
    uint32_t freed_handles;
    uint32_t destroyed_strings;
} rome2_vfs_atexit_globals_state;

/* Initializes/fetches singletons `0x10122cb0` and `0x10122640`. */
const rome2_vfs_pack_index_table *rome2_vfs_pack_index_get_primary(rome2_vfs_pack_index_env *env);
const rome2_vfs_pack_index_table *rome2_vfs_pack_index_get_empty(rome2_vfs_pack_index_env *env);

/* Case-insensitive `?` / `*` glob match (`0x10121d80`). */
uint8_t rome2_vfs_wildcard_match_nocase(const char *str, const char *pattern);

/* Strips trailing `'\\'` / `'/'` path separators (`0x10122d70`). */
rome2_vfs_reg_status rome2_vfs_strip_trailing_separators(
    const char *path,
    char *out_buf,
    uint32_t out_cap);

/* Pack-index existence/root/path resolution & stream/entry wrappers (`0x101217e0`, `0x10121c40`, `0x10122260`, `0x10122380`, `0x10121250`). */
uint8_t rome2_vfs_pack_index_can_open(
    const rome2_vfs_pack_index_table *table,
    const char *rel_path,
    rome2_vfs_idx_direct_pred_fn direct_pred,
    rome2_vfs_idx_probe_open_fn probe_open,
    void *ctx);

const char *rome2_vfs_pack_index_resolve_root(
    rome2_vfs_pack_index_env *env,
    const char *rel_path,
    rome2_vfs_idx_direct_pred_fn direct_pred,
    rome2_vfs_idx_probe_open_fn probe_open,
    void *ctx);

rome2_vfs_reg_status rome2_vfs_pack_index_resolve_path(
    const rome2_vfs_pack_index_table *table,
    const char *rel_path,
    rome2_vfs_idx_direct_pred_fn direct_pred,
    rome2_vfs_idx_probe_open_fn probe_open,
    void *ctx,
    char *out_path,
    uint32_t out_cap);

rome2_vfs_reg_status rome2_vfs_wrap_new_stream_from_path(
    rome2_vfs_pack_index_env *env,
    const char *path,
    uint32_t *out_handle);

rome2_vfs_reg_status rome2_vfs_build_prefixed_entry(
    rome2_vfs_pack_index_env *env,
    const char *prefix,
    const char *rel_path,
    uint32_t *out_handle,
    char *out_joined,
    uint32_t out_cap);

/* Win32 FILETIME->Unix epoch conversion & attribute decoding (`0x100fec00`). */
void rome2_vfs_decode_win32_find_info(
    uint32_t file_size_low,
    uint32_t attributes,
    uint64_t last_write_filetime,
    rome2_vfs_win32_find_info *out_info);

rome2_vfs_reg_status rome2_vfs_traverse_sim_directory(
    const rome2_vfs_win32_sim_fs *fs,
    const char *dir_path,
    const char *pattern,
    uint8_t recursive,
    rome2_vfs_win32_visit_fn visit,
    void *user_ctx,
    uint32_t depth_limit);

/* Containers: array clear (`0x112ab1f0`), RB erase (`0x112a26f0`), node pool free (`0x112a28a0`), rehash (`0x112b03b0`), chunk clear (`0x112b5420`), vector push_back (`0x112d7b40`, `0x100eaf40`). */
void rome2_vfs_pair_array_clear(uint32_t *elem_count, uint32_t *destroyed_count);

rome2_vfs_reg_status rome2_vfs_rb_erase_subtree(
    rome2_vfs_rb_ref_node *nodes,
    uint32_t node_count,
    int32_t root_idx,
    uint32_t *out_erased_nodes,
    uint32_t *out_destroyed_payloads,
    uint32_t *out_deallocated_ctrls);

rome2_vfs_reg_status rome2_vfs_mount_node_list_free(
    rome2_vfs_mount_free_node *nodes,
    uint32_t node_count,
    int32_t head_idx,
    uint32_t *out_freed_nodes,
    uint32_t *out_freed_aux,
    uint32_t *out_freed_children);

uint32_t rome2_vfs_fnv1a_cstr_lower_or_raw(const char *key);

rome2_vfs_reg_status rome2_vfs_umap_rehash(
    rome2_vfs_umap_rehash_state *state,
    uint32_t requested_buckets);

rome2_vfs_reg_status rome2_vfs_chunked_str_clear(
    rome2_vfs_str_chunk *chunks,
    uint32_t chunk_count,
    int32_t head_idx,
    uint32_t *out_destroyed_strings);

rome2_vfs_reg_status rome2_vfs_entry48_vec_push_back(
    rome2_vfs_entry48_vec *vec,
    const rome2_vfs_entry48_rec *elem);

rome2_vfs_reg_status rome2_vfs_u32_vec_push_back(
    rome2_vfs_u32_vec *vec,
    const uint32_t *elem);

/* Diagnostics (`0x112c2370`, `0x112a5530`, `0x112a56d0`, `0x112f0b90`). */
void rome2_vfs_get_static_key_c2370(uint32_t out_tag[4]);

const rome2_vfs_diag_kv *rome2_vfs_diag_find_primary(
    const rome2_vfs_diag_kv *table,
    uint32_t table_count,
    const uint32_t key_tag[4]);

rome2_vfs_reg_status rome2_vfs_diag_format_composite(
    const rome2_vfs_diag_kv *table,
    uint32_t table_count,
    const char *prefix_name,
    const char *suffix_name,
    char *out_buf,
    uint32_t out_cap);

rome2_vfs_reg_status rome2_vfs_format_bitmask_flags(
    const rome2_vfs_diag_provider *provider,
    uint32_t flags,
    char *out_buf,
    uint32_t out_cap);

/* Executes all 10 RET-bearing VFS singleton atexit destructors (`0x11724a10`..`0x11724e50`). */
void rome2_vfs_run_all_atexit_destructors(rome2_vfs_atexit_globals_state *state);

#ifdef __cplusplus
}
#endif

#endif
