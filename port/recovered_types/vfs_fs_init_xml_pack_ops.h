#ifndef ROME2_VFS_FS_INIT_XML_PACK_OPS_H
#define ROME2_VFS_FS_INIT_XML_PACK_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_index_atexit_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Layer 32 bounded capacity constants matching reconstructed 32-bit VFS structures. */
#define ROME2_VFS_L32_MAX_INTERN 64u
#define ROME2_VFS_L32_MAX_BUCKETS 64u
#define ROME2_VFS_L32_MAX_MODS 32u
#define ROME2_VFS_L32_MAX_NAME 128u
#define ROME2_VFS_L32_CRIT_SPIN 0x2710u
#define ROME2_VFS_L32_INVALID_HANDLE 0xffffffffu
#define ROME2_VFS_L32_ERR_INVALID_HANDLE 0x18u

typedef struct rome2_vfs_intern_entry {
    uint8_t active;
    char value[ROME2_VFS_IDX_MAX_PATH];
} rome2_vfs_intern_entry;

/* Models `0x10122dc0` lock + `0x10121930` intern table + `0x101225a0` <empty_file_name>. */
typedef struct rome2_vfs_path_intern_env {
    uint8_t lock_ready;
    uint32_t lock_spin_count;
    uint32_t lock_depth;
    uint32_t max_lock_depth;
    uint8_t table_ready;
    uint32_t table_mask;
    uint32_t table_buckets;
    float max_load_factor;
    uint8_t empty_ready;
    char empty_name[32];
    uint32_t count;
    rome2_vfs_intern_entry entries[ROME2_VFS_L32_MAX_INTERN];
} rome2_vfs_path_intern_env;

/* Models `0x100f6ee0` close-handle wrapper result & `0x100ff8e0` status mapping. */
typedef struct rome2_vfs_os_handle_box {
    uint32_t handle;
    uint32_t last_error;
} rome2_vfs_os_handle_box;

/* Models `0x112cc200` 12B-bucket hash table insert/emplace with float load-factor rehash. */
typedef struct rome2_vfs_hash12_slot {
    uint8_t occupied;
    char key[ROME2_VFS_L32_MAX_NAME];
    uint32_t value;
} rome2_vfs_hash12_slot;

typedef struct rome2_vfs_hash12_map {
    uint32_t bucket_count;
    uint32_t size;
    float max_load_factor;
    uint32_t rehash_count;
    rome2_vfs_hash12_slot slots[ROME2_VFS_L32_MAX_BUCKETS];
} rome2_vfs_hash12_map;

/* Models `0x112a4690` active thread-budget chunk update. */
typedef struct rome2_vfs_thread_budget_state {
    uint8_t global_enabled;
    uint8_t thread_active;
    uint32_t cur_thread_id;
    uint32_t owner_thread_id;
    uint32_t chunk_cap_count;
    uint32_t chunk_used_count;
    uint32_t byte_cap;
    uint32_t byte_used;
} rome2_vfs_thread_budget_state;

/* Models `0x112c5460` XML type save switch classification. */
typedef enum rome2_vfs_xml_save_outcome {
    ROME2_VFS_XML_SAVE_NORMALIZED_1C = 0,
    ROME2_VFS_XML_SAVE_TYPE_1F6_OK = 1,
    ROME2_VFS_XML_SAVE_TYPE_1F6_PROBLEM = 2,
    ROME2_VFS_XML_SAVE_FALLBACK = 3,
    ROME2_VFS_XML_SAVE_SWITCH = 4
} rome2_vfs_xml_save_outcome;

/* Pack-index primary bootstrap (`0x1011fef0`) choosing retail `\data\` or 6 working-data search roots. */
rome2_vfs_reg_status rome2_vfs_pack_index_bootstrap(
    rome2_vfs_pack_index_table *table,
    const char *cwd,
    uint8_t has_boot_pack,
    uint8_t *out_retail_mode);

/* Lazy singleton accessors & thread-safe string interning (`0x10122dc0`, `0x10121930`, `0x101225a0`, `0x10120b30`, `0x10120c10`). */
const char *rome2_vfs_intern_path(
    rome2_vfs_path_intern_env *env,
    const char *path,
    uint8_t preserve_case);

/* `CA_ASCIIString` & OS handle primitives (`0x100ff8e0`, `0x100ff8f0`, `0x100f70f0`, `0x100f2ad0`, `0x100f2c40`, `0x100f2de0`, `0x100f6ea0`, `0x100f6ee0`). */
uint32_t rome2_vfs_map_handle_status(uint32_t handle_val);
uint32_t rome2_vfs_cstr_find(const char *haystack, const char *needle, uint32_t start_pos);
int32_t rome2_vfs_cstr_compare_sub(
    const char *lhs,
    uint32_t pos,
    uint32_t len,
    const char *rhs);
char rome2_vfs_cstr_at_or_nul(const char *s, uint32_t index);
rome2_vfs_reg_status rome2_vfs_cstr_join_c(
    const char *prefix,
    const char *suffix,
    char *out_buf,
    uint32_t out_cap);
uint8_t rome2_vfs_os_handle_close(
    rome2_vfs_os_handle_box *box,
    uint8_t sim_close_ok,
    uint32_t sim_err);

/* Mod banner formatter (`0x11300140`): "no mods" or "mods: m1, m2...". */
rome2_vfs_reg_status rome2_vfs_format_mod_banner(
    const char *const *mods,
    uint32_t mod_count,
    char *out_buf,
    uint32_t out_cap);

/* Static keys (`0x112c2190`, `0x112c21f0`) copied from `.rdata` `0x1189a640` / `0x1189a630`. */
void rome2_vfs_get_static_key_c2190(uint32_t out_tag[4]);
void rome2_vfs_get_static_key_c21f0(uint32_t out_tag[4]);

/* `0x112a4690` active thread-budget accounting. */
uint8_t rome2_vfs_thread_budget_try_consume(
    rome2_vfs_thread_budget_state *state,
    uint32_t add_bytes,
    uint8_t key_matched);

/* `0x112cc200` 12B hash map emplace with float `max_load_factor` checking and `2*n+1` rehash. */
rome2_vfs_reg_status rome2_vfs_hash12_emplace(
    rome2_vfs_hash12_map *map,
    const char *key,
    uint32_t value,
    uint8_t *out_inserted);

/* `0x112c5460` XML save type dispatch classifier. */
rome2_vfs_xml_save_outcome rome2_vfs_xml_save_classify(
    uint32_t type_code,
    uint8_t helper_112e4050_ok,
    uint32_t *out_normalized_type,
    char *out_problem_prefix,
    uint32_t out_cap);

#ifdef __cplusplus
}
#endif

#endif
