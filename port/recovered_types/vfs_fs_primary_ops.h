#ifndef ROME2_VFS_FS_PRIMARY_OPS_H
#define ROME2_VFS_FS_PRIMARY_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_archive_register.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Active FileSystem primary interface (`0x11897870`) & companion singleton constants (Layer 29). */
#define ROME2_VFS_PRIMARY_OBJ_BYTES 0x28u
#define ROME2_VFS_MOUNT_VEC_INIT_CAP 0x10u
#define ROME2_VFS_ROOT_ARCHIVE_INIT_CAP 0x20u
#define ROME2_VFS_LOOSE_TABLE_BUCKETS 0x3cbu
#define ROME2_VFS_LARGE_HASH_BUCKETS 0x23b1bu
#define ROME2_VFS_DYNAMIC_ID_SEED 0x80000001u
#define ROME2_VFS_SENTINEL_U32 0xffffffffu

#define ROME2_VFS_PRIMARY_MAX_ROOTS 32u
#define ROME2_VFS_PRIMARY_MAX_EXCLUDED 32u
#define ROME2_VFS_PRIMARY_MAX_ENTRIES 64u
#define ROME2_VFS_PRIMARY_MAX_NAME 128u

typedef struct rome2_vfs_primary_entry_record {
    char path[ROME2_VFS_PRIMARY_MAX_NAME];
    uint32_t size_lo;
    uint32_t size_hi;
    uint32_t dynamic_id;
    uint8_t in_pack;
    uint8_t in_loose;
    uint8_t flag_1c;
    uint8_t occupied;
} rome2_vfs_primary_entry_record;

typedef struct rome2_vfs_primary_fs_state {
    uint32_t active_ops;
    uint8_t mode_flag_24;
    uint8_t vfs_initialized;
    uint8_t flag_1a8a;
    uint8_t flag_1ae7;
    uint8_t flag_2080;
    uint8_t override_active;
    uint8_t sub_fs_mounted;
    uint8_t sub_fs_mode;
    uint32_t val_1ad8;
    uint32_t val_1ae0;
    uint32_t next_dynamic_id;
    uint32_t active_root_cap;
    uint32_t active_root_count;
    char active_roots[ROME2_VFS_PRIMARY_MAX_ROOTS][ROME2_VFS_PRIMARY_MAX_NAME];
    uint32_t archive_root_count;
    char archive_roots[ROME2_VFS_PRIMARY_MAX_ROOTS][ROME2_VFS_PRIMARY_MAX_NAME];
    uint32_t pending_root_count;
    char pending_roots[ROME2_VFS_PRIMARY_MAX_ROOTS][ROME2_VFS_PRIMARY_MAX_NAME];
    uint32_t entry_count;
    rome2_vfs_primary_entry_record entries[ROME2_VFS_PRIMARY_MAX_ENTRIES];
    char override_path[ROME2_VFS_PRIMARY_MAX_NAME];
} rome2_vfs_primary_fs_state;

/* Initializes host model of `0x11897870` (`0x112a8ff0` ctor + static image state). */
rome2_vfs_reg_status rome2_vfs_fs_primary_state_init(rome2_vfs_primary_fs_state *state);

/* Simulates `0x100eb330` vector capacity growth (`0 -> 1`, else `2 * cap`) with overflow check. */
rome2_vfs_reg_status rome2_vfs_fs_primary_vec_grow_capacity(
    uint32_t current_cap,
    uint32_t *out_next_cap);

/* Slot +0x00 (`0x112beac0` -> `0x112beb10` + `0x100eb330`): appends active root path. */
rome2_vfs_reg_status rome2_vfs_fs_primary_add_active_root(
    rome2_vfs_primary_fs_state *state,
    const char *root_path);

/* Registers a root candidate into modeled `0x119e11e8` archive root table. */
rome2_vfs_reg_status rome2_vfs_fs_primary_add_archive_root(
    rome2_vfs_primary_fs_state *state,
    const char *root_path);

/* Registers or updates an indexed/loose entry record used by lookup/info/exists slots. */
rome2_vfs_reg_status rome2_vfs_fs_primary_seed_entry(
    rome2_vfs_primary_fs_state *state,
    const char *path,
    uint32_t size_lo,
    uint32_t size_hi,
    uint8_t in_pack,
    uint8_t in_loose,
    uint8_t flag_1c);

/* Slot +0x04 (`0x112e36f0`): rebuilds `active_roots` from `archive_roots` omitting excluded roots. */
rome2_vfs_reg_status rome2_vfs_fs_primary_filter_active_roots(
    rome2_vfs_primary_fs_state *state,
    const char *const *excluded_roots,
    uint32_t excluded_count);

/* Slot +0x0c (`0x112df040`): appends a pending root and copies pending roots to caller buffer. */
rome2_vfs_reg_status rome2_vfs_fs_primary_copy_pending_roots(
    rome2_vfs_primary_fs_state *state,
    char out_paths[][ROME2_VFS_PRIMARY_MAX_NAME],
    uint32_t out_capacity,
    uint32_t *out_copied);

/* Slot +0x2c (`0x112e4000`): reads entry path at `index`, clamping `>= count` to `count - 1`. */
rome2_vfs_reg_status rome2_vfs_fs_primary_get_entry_at_clamped(
    const rome2_vfs_primary_fs_state *state,
    uint32_t index,
    char *out_path,
    uint32_t out_path_cap,
    uint8_t *out_found);

/* Slot +0x3c (`0x112bbaa0`): tests presence in pack or loose map. */
rome2_vfs_reg_status rome2_vfs_fs_primary_entry_exists(
    const rome2_vfs_primary_fs_state *state,
    const char *path,
    uint8_t *out_exists);

/* Slot +0x40 (`0x112d4f00`): queries 32-bit entry size or `0xffffffffu` sentinel if absent. */
rome2_vfs_reg_status rome2_vfs_fs_primary_get_entry_size(
    const rome2_vfs_primary_fs_state *state,
    const char *path,
    uint32_t *out_size_or_sentinel);

/* Slot +0x48 / +0x4c / +0x54 / +0x58 / +0x6c flag and word accessors. */
rome2_vfs_reg_status rome2_vfs_fs_primary_set_override_path(
    rome2_vfs_primary_fs_state *state,
    const char *override_path);

rome2_vfs_reg_status rome2_vfs_fs_primary_set_flag_1a8a(
    rome2_vfs_primary_fs_state *state,
    uint8_t value);

rome2_vfs_reg_status rome2_vfs_fs_primary_set_val_1ad8(
    rome2_vfs_primary_fs_state *state,
    uint32_t value);

/* Slot +0x50 (`0x112e3460`) and Slot +0x74 (`0x112ad070`): destroys sub-FS / tears down active FS. */
rome2_vfs_reg_status rome2_vfs_fs_primary_destroy_subfs(rome2_vfs_primary_fs_state *state);
rome2_vfs_reg_status rome2_vfs_fs_primary_dtor(rome2_vfs_primary_fs_state *state);

/* Slots +0x60 / +0x64 (`0x112c9550` / `0x112c95a0`): populates 32-byte entry info descriptor. */
rome2_vfs_reg_status rome2_vfs_fs_primary_query_entry_info(
    rome2_vfs_primary_fs_state *state,
    const char *path,
    rome2_vfs_entry_info32 *out_info,
    char *out_name,
    uint32_t out_name_cap);

/* Slot +0x68 (`0x112c9430`): returns existing dynamic ID or registers `next_dynamic_id++` if in loose/index. */
rome2_vfs_reg_status rome2_vfs_fs_primary_register_or_get_id(
    rome2_vfs_primary_fs_state *state,
    const char *path,
    uint32_t *out_id);

/* Slot +0x70 (`0x112c00b0`): mounts lazy `0x12031f10` sub-FS when requested and conditionally registers entry. */
rome2_vfs_reg_status rome2_vfs_fs_primary_mount_subfs_and_register(
    rome2_vfs_primary_fs_state *state,
    const char *path,
    uint8_t create_subfs,
    uint8_t subfs_mode_value,
    uint8_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
