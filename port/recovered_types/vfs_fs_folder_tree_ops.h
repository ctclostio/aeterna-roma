#ifndef ROME2_VFS_FS_FOLDER_TREE_OPS_H
#define ROME2_VFS_FS_FOLDER_TREE_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_init_xml_pack_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Layer 33 bounded limits matching reconstructed VFS 32-bit folder-tree & intern helpers. */
#define ROME2_VFS_L33_MAX_PAIRS 16u
#define ROME2_VFS_L33_MAX_FOLDERS 16u
#define ROME2_VFS_L33_MAX_SLAB 32u
#define ROME2_VFS_L33_MAX_WSTR 128u
#define ROME2_VFS_L33_UMAP_MAX_ELEMS 0x0cccccccu
#define ROME2_VFS_L33_SWITCH_MAX_CODE 0x0du

/* Bounded host model for `0x10126e50..0x10127900` 24B pairs & 60B folder nodes. */
typedef struct rome2_vfs_kv_pair24 {
    char key[64];
    char value[128];
} rome2_vfs_kv_pair24;

typedef struct rome2_vfs_folder_node60 {
    uint8_t active;
    char name[64];
    char root[128];
    char tag[32];
    uint32_t pair_capacity;
    uint32_t pair_count;
    rome2_vfs_kv_pair24 pairs[ROME2_VFS_L33_MAX_PAIRS];
    int32_t first_child;
    int32_t next_sibling;
} rome2_vfs_folder_node60;

typedef struct rome2_vfs_folder_forest {
    uint32_t count;
    rome2_vfs_folder_node60 nodes[ROME2_VFS_L33_MAX_FOLDERS];
} rome2_vfs_folder_forest;

/* `0x1011fd40` 20B freelist slab model. */
typedef struct rome2_vfs_slab20_pool {
    uint32_t count;
    int32_t head;
    int32_t next_idx[ROME2_VFS_L33_MAX_SLAB];
} rome2_vfs_slab20_pool;

/* `0x100f0a80` 48B split-path carrier. */
typedef struct rome2_vfs_split_path48 {
    char drive[16];
    char dir[128];
    char stem[64];
    char ext[32];
} rome2_vfs_split_path48;

/* `0x10126e50` / `0x10126f40` / `0x10126f60` / `0x10126fa0` / `0x10127510` / `0x10127900` recursive folder ops. */
rome2_vfs_reg_status rome2_vfs_folder_forest_add_node(
    rome2_vfs_folder_forest *forest,
    int32_t parent_idx,
    const char *name,
    const char *root,
    const char *tag,
    int32_t *out_idx);

rome2_vfs_reg_status rome2_vfs_folder_add_kv_pair(
    rome2_vfs_folder_forest *forest,
    int32_t folder_idx,
    const char *key,
    const char *value);

rome2_vfs_reg_status rome2_vfs_folder_clone_subtree(
    const rome2_vfs_folder_forest *src,
    int32_t src_idx,
    rome2_vfs_folder_forest *dst,
    int32_t dst_parent_idx,
    int32_t *out_new_idx);

rome2_vfs_reg_status rome2_vfs_folder_destroy_subtree(
    rome2_vfs_folder_forest *forest,
    int32_t folder_idx,
    uint32_t *out_destroyed_folders,
    uint32_t *out_destroyed_pairs);

/* `0x10127390` whitespace-delimited config key/value parser (`\t`, `\n`, `\r`). */
rome2_vfs_reg_status rome2_vfs_parse_tab_kv_lines(
    rome2_vfs_folder_forest *forest,
    int32_t folder_idx,
    const char *text);

/* `0x10122760` & `0x10122830` path normalization (`"data\\"` strip + `"..\\"` / `".\\"` collapse). */
rome2_vfs_reg_status rome2_vfs_strip_data_prefix(
    const char *in_path,
    char *out_path,
    uint32_t out_cap,
    uint8_t *out_stripped);

rome2_vfs_reg_status rome2_vfs_normalize_dot_segments(
    const char *in_path,
    uint8_t single_dot_only,
    char *out_path,
    uint32_t out_cap,
    uint8_t *out_changed);

/* `0x100f0a80` splits executable/archive path into 48B drive/dir/stem/ext record. */
rome2_vfs_reg_status rome2_vfs_split_path_parts48(
    const char *full_path,
    rome2_vfs_split_path48 *out_parts);

/* `0x1011fd40` links 20B freelist slab slots (`next[i] = i + 1`, tail = -1). */
rome2_vfs_reg_status rome2_vfs_slab20_init(
    rome2_vfs_slab20_pool *pool,
    uint32_t count);

/* `0x1011f7c0` enforces unordered_map `0x0cccccccu` limit before insert. */
rome2_vfs_reg_status rome2_vfs_intern_check_limit(uint32_t current_size);

/* `0x1011f6e0` fills `[dst .. dst+count)` with repeated 32-bit value. */
void rome2_vfs_fill_u32_range(uint32_t *dst, uint32_t count, uint32_t value);

/* `0x10103ec0` decodes UTF-8 string into UTF-16 code units. */
rome2_vfs_reg_status rome2_vfs_utf8_to_utf16(
    const char *utf8_src,
    uint16_t *utf16_dst,
    uint32_t dst_cap,
    uint32_t *out_len);

/* `0x100f26b0` & `0x100f2750` assign ASCII and wide strings safely. */
rome2_vfs_reg_status rome2_vfs_assign_utf16(
    uint16_t *dst,
    uint32_t dst_cap,
    const uint16_t *src,
    uint32_t *out_len);

/* `0x112d6a10`, `0x112dc5e0`, & `0x112e4050` archive resolve helpers & tag switch. */
uint8_t rome2_vfs_archive_entry_name_matches_tail(
    const char *archive_rel,
    const char *full_candidate);

uint8_t rome2_vfs_validate_switch_tag_1_to_d(uint32_t tag);

#ifdef __cplusplus
}
#endif

#endif
