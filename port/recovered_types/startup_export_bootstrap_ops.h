#ifndef ROME2_STARTUP_EXPORT_BOOTSTRAP_OPS_H
#define ROME2_STARTUP_EXPORT_BOOTSTRAP_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_archive_register.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_STARTUP_MAX_REG_ENTRIES 16u
#define ROME2_STARTUP_USER_FOLDER_COUNT 50u
#define ROME2_STARTUP_MAX_PATH_U16 260u
#define ROME2_STARTUP_MAX_RB_NODES 64u
#define ROME2_STARTUP_MAX_HANDLERS 32u
#define ROME2_STARTUP_MAX_TIMING_SLOTS 32u

#define ROME2_STARTUP_MOD_OPT_NOTIFY_EXPECTED 0x00020004u

/* `0x11302cc0`, `0x11303db0`, `0x113048b0`, `0x11304980`: Mod-options exports (#521, #522) & HKCU model. */
typedef struct rome2_startup_reg_dword_entry {
    char name[48];
    uint32_t value;
    uint8_t valid;
} rome2_startup_reg_dword_entry;

typedef struct rome2_startup_reg_env {
    uint8_t has_launcher_214950_key;
    uint8_t has_rome2_key;
    uint32_t cached_subkey_va; /* 0 = unset, 0x117e2e7c = Launcher\\214950, 0x117e2eac = Rome2 */
    rome2_startup_reg_dword_entry entries[ROME2_STARTUP_MAX_REG_ENTRIES];
    uint32_t entry_count;
    uint32_t open_count;
    uint32_t close_count;
    uint32_t write_count;
} rome2_startup_reg_env;

uint32_t rome2_startup_read_mod_option_reg_bool_11302cc0(
    rome2_startup_reg_env *env,
    const char *value_name);

void rome2_startup_write_mod_option_reg_bool_11303db0(
    rome2_startup_reg_env *env,
    const char *value_name,
    uint8_t value,
    uint8_t only_if_missing);

uint8_t rome2_startup_need_to_show_mod_options_notification_113048b0(
    rome2_startup_reg_env *env);

void rome2_startup_set_or_get_mod_options_11304980(
    rome2_startup_reg_env *env,
    rome2_startup_mod_options2_32 *options,
    uint8_t write_mode);

/* `0x10122e30`, `0x101016c0`, `0x100e1050`, `0x10120d90`, `0x100e8240`, `0x116be670`. */
const char *rome2_startup_get_user_folder_subpath_10122e30(
    uint32_t category_idx,
    uint32_t *out_flags);

typedef struct rome2_startup_path_env {
    const char *command_line_a;
    const uint16_t *module_file_name_u16;
    const uint16_t *appdata_root_u16;
    uint8_t shgetfolder_ok;
    uint32_t created_dirs;
    uint16_t cache_paths[ROME2_STARTUP_USER_FOLDER_COUNT][ROME2_STARTUP_MAX_PATH_U16];
    uint8_t cache_populated[ROME2_STARTUP_USER_FOLDER_COUNT];
} rome2_startup_path_env;

typedef struct rome2_startup_crash_singleton {
    int32_t init_epoch;
    uint8_t initialized;
    uint8_t has_perf_config;
    rome2_startup_perf_config228_32 perf_config;
    uint16_t crash_stack_path[ROME2_STARTUP_MAX_PATH_U16];
    size_t crash_stack_len;
    uint16_t crash_dmp_path[ROME2_STARTUP_MAX_PATH_U16];
    size_t crash_dmp_len;
    uint32_t alloc_ptrs[8];
    uint32_t alloc_ptr_count;
    uint32_t virtual_free_count;
    uint8_t atexit_registered;
    uint8_t zeroed_fields_ok;
} rome2_startup_crash_singleton;

rome2_vfs_reg_status rome2_startup_utf16_concat_100e1050(
    const uint16_t *prefix_u16,
    const uint16_t *suffix_u16,
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len);

rome2_vfs_reg_status rome2_startup_resolve_appdata_dir_101016c0(
    rome2_startup_path_env *env,
    uint32_t category_idx,
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len);

const uint16_t *rome2_startup_get_cached_user_folder_path_10120d90(
    rome2_startup_path_env *env,
    uint32_t category_idx);

rome2_startup_crash_singleton *rome2_startup_crash_reporter_instance_100e8240(
    rome2_startup_crash_singleton *singleton,
    rome2_startup_path_env *path_env,
    int32_t tls_epoch);

const char *rome2_startup_strstr_116be670(
    const char *haystack,
    const char *needle,
    uint32_t isa_available);

/* `0x10102c10`, `0x100f71b0`, `0x100f3000`, `0x100ea5e0`, `0x100e3360`: UTF-16 slice, RB-tree & dir scan. */
typedef struct rome2_startup_utf16_slice {
    uint32_t len;
    uint32_t cap;
    uint16_t *buf;
} rome2_startup_utf16_slice;

typedef struct rome2_startup_utf16_cslice {
    uint32_t len;
    uint32_t cap;
    const uint16_t *buf;
} rome2_startup_utf16_cslice;

void rome2_startup_utf16_slice_init_lower_ascii_10102c10(
    rome2_startup_utf16_slice *out_slice,
    uint32_t len,
    uint32_t cap,
    uint16_t *buf);

int32_t rome2_startup_utf16_slice_compare_100f71b0(
    const rome2_startup_utf16_cslice *lhs,
    const rome2_startup_utf16_cslice *rhs);

uint32_t rome2_startup_utf16_slice_less_100f3000(
    const rome2_startup_utf16_cslice *lhs,
    const rome2_startup_utf16_cslice *rhs);

typedef struct rome2_startup_rb_slot {
    rome2_startup_dir_rb_node48_32 guest;
    uint16_t key_u16[128];
    uint32_t left_idx;
    uint32_t parent_idx;
    uint32_t right_idx;
} rome2_startup_rb_slot;

typedef struct rome2_startup_rb_tree {
    rome2_startup_rb_slot nodes[ROME2_STARTUP_MAX_RB_NODES + 1u]; /* [0] is nil sentinel */
    uint32_t count; /* excludes sentinel [0] */
    uint32_t root_idx;
    uint32_t leftmost_idx;
    uint32_t rightmost_idx;
} rome2_startup_rb_tree;

void rome2_startup_rb_tree_init(rome2_startup_rb_tree *tree);

rome2_vfs_reg_status rome2_startup_rb_insert_hint_100ea5e0(
    rome2_startup_rb_tree *tree,
    uint8_t insert_left,
    uint32_t hint_idx,
    const uint16_t *key_u16,
    uint32_t key_len,
    uint64_t size_bytes,
    uint32_t *out_idx);

rome2_vfs_reg_status rome2_startup_rb_find(
    const rome2_startup_rb_tree *tree,
    const uint16_t *key_u16,
    uint32_t key_len,
    uint32_t *out_idx,
    uint64_t *out_size);

typedef struct rome2_startup_dir_entry {
    const char *parent_rel;
    const char *name_ascii;
    uint8_t is_dir;
    uint64_t file_size;
} rome2_startup_dir_entry;

uint8_t rome2_startup_is_excluded_dlc_or_manifest(const char *lower_rel_path);

rome2_vfs_reg_status rome2_startup_scan_dir_tree_100e3360(
    const rome2_startup_dir_entry *entries,
    size_t entry_count,
    const char *parent_rel,
    const char *vfs_prefix,
    rome2_startup_rb_tree *tree);

/* `0x101136d0`, `0x101150f0`, `0x100d24c0`, `0x100fcc30`, `0x112dc9f0`, `0x100ea060`, `0x100ea4d0`, `0x100f4920`, `0x100de500`, `0x101c89e0`. */
void rome2_startup_set_keeper_flag_101136d0(uint8_t *keeper_byte, uint8_t value);
void rome2_startup_set_keeper_dword_101150f0(uint32_t *keeper_dword, uint32_t value);

rome2_vfs_reg_status rome2_startup_init_perf_config_100d24c0(
    rome2_startup_perf_config228_32 *cfg);

typedef struct rome2_startup_alloc_table {
    uint32_t slots[8];
    uint32_t slot3;
} rome2_startup_alloc_table;

uint32_t rome2_startup_get_allocator_slot_100fcc30(
    const rome2_startup_alloc_table *tbl,
    int32_t slot_index);

typedef struct rome2_startup_timing_env {
    const char *active_label;
    uint32_t init_start_ms;
    uint32_t init_last_ms;
    uint32_t max_cap_param;
    uint32_t alloc_cap;
    uint32_t active_count;
    rome2_startup_timing_slot16_32 slots[ROME2_STARTUP_MAX_TIMING_SLOTS];
    uint32_t cached_allocator;
    char log_banner[96];
} rome2_startup_timing_env;

rome2_vfs_reg_status rome2_startup_init_section_timings_112dc9f0(
    rome2_startup_timing_env *env,
    const rome2_startup_alloc_table *alloc_tbl,
    const char *section_label,
    uint32_t capacity,
    uint32_t current_time_ms);

typedef struct rome2_startup_handler_obj {
    uint32_t vtable_va;
    uint32_t alloc_bytes;
} rome2_startup_handler_obj;

typedef struct rome2_startup_handler_queue {
    rome2_startup_handler_obj items[ROME2_STARTUP_MAX_HANDLERS];
    uint32_t count;
    uint32_t fail_on_push_index; /* UINT32_MAX = never fail */
    rome2_startup_crash_singleton *crash_singleton;
    rome2_startup_path_env *path_env;
    rome2_startup_timing_env timing_env;
    rome2_startup_alloc_table alloc_tbl;
} rome2_startup_handler_queue;

rome2_vfs_reg_status rome2_startup_register_handlers_part1_100ea060(
    rome2_startup_handler_queue *queue);

rome2_vfs_reg_status rome2_startup_register_handlers_part2_100ea4d0(
    rome2_startup_handler_queue *queue);

uint8_t rome2_startup_format_const_char_spec_100f4920(
    const char *val,
    char spec_char,
    char *out_buf,
    size_t out_cap,
    size_t *out_len,
    char *diag_buf,
    size_t diag_cap);

uint8_t rome2_startup_format_named_kv_100de500(
    const uint16_t *fmt_u16,
    const char *const *str_args,
    size_t str_arg_count,
    char *out_buf,
    size_t out_cap,
    size_t *out_len,
    char *diag_buf,
    size_t diag_cap);

rome2_vfs_reg_status rome2_startup_format_ansi_va_101c89e0(
    const uint16_t *fmt_u16,
    const char *const *str_args,
    size_t str_arg_count,
    char *out_buf,
    size_t out_cap,
    size_t *out_len,
    uint8_t *out_ok,
    char *diag_buf,
    size_t diag_cap);

#ifdef __cplusplus
}
#endif

#endif
