#ifndef ROME2_STARTUP_INPUT_MSG_CONSOLE_OPS_H
#define ROME2_STARTUP_INPUT_MSG_CONSOLE_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_app_ctor_timing_ops.h"
#include "startup_export_bootstrap_ops.h"
#include "startup_handler_stdio_close_ops.h"
#include "vfs_archive_register.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_STARTUP_VTABLE_WARSCAPE_RELOAD 0x1173deb0u
#define ROME2_STARTUP_VTABLE_WARSCAPE_CVAR   0x1173dbb4u
#define ROME2_STARTUP_VTABLE_CONSOLE_BASE    0x11744dd8u
#define ROME2_STARTUP_VTABLE_CONSOLE_REG     0x11744de4u
#define ROME2_STARTUP_VTABLE_CONSOLE_HANDLER 0x1173f2acu
#define ROME2_STARTUP_VTABLE_OBSERVER_NODE   0x11741e08u

#define ROME2_STARTUP_MSG_WM_QUIT       0x0012u
#define ROME2_STARTUP_MSG_WM_SYSCHAR    0x0119u
#define ROME2_STARTUP_DIERR_INPUTLOST   0x8007001Eu
#define ROME2_STARTUP_DIERR_NOTACQUIRED 0x8007000Cu
#define ROME2_STARTUP_MAX_MSG_QUEUE     16u
#define ROME2_STARTUP_MAX_CMD_REG       16u
#define ROME2_STARTUP_WFSTREAM_BUFSIZ   68u

/* -------------------------------------------------------------------------
 * 0x112bff20, 0x112ac3f0, 0x11683d60, 0x112e2c20, 0x112e2b00: Flag & 64-bit timing math
 * ------------------------------------------------------------------------- */
/* `0x112bff20` */
uint8_t rome2_startup_get_vfs_flag_112bff20(uint8_t global_12031ae5);

/* `0x112ac3f0` */
void rome2_startup_sub_u64_112ac3f0(uint64_t *out, const uint64_t *lhs, const uint64_t *rhs);

/* `0x11683d60` */
double rome2_startup_crt_ultod3_11683d60(uint32_t lo_ecx, uint32_t hi_edx);

/* `0x112e2c20` */
uint32_t rome2_startup_u64_us_to_ms_112e2c20(uint64_t us);

/* `0x112e2b00` */
float rome2_startup_u64_us_to_seconds_112e2b00(uint64_t us);

/* -------------------------------------------------------------------------
 * 0x10101980, 0x101061b0, 0x1010eda0: Power, Win32 msg pump & DirectInput8
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_power_info {
    int32_t ac_status;                 /* 0=online, 1=offline, -1=unknown */
    int32_t battery_state;             /* 0=high, 1=low/none, 2=crit, 3=no battery, -1=unset */
    uint8_t is_charging;               /* +8 */
    uint32_t battery_life_time_sec;    /* +0x0c */
} rome2_startup_power_info;

/* `0x10101980` */
rome2_startup_power_info *rome2_startup_query_power_info_10101980(
    rome2_startup_power_info *out,
    const rome2_startup_sys_power_status12_32 *os_status);

typedef struct rome2_startup_msg_entry {
    uint32_t message;
    uint32_t wparam;
    uint32_t lparam;
} rome2_startup_msg_entry;

typedef struct rome2_startup_msg_pump_env {
    rome2_startup_msg_entry queue[ROME2_STARTUP_MAX_MSG_QUEUE];
    uint32_t count;
    uint32_t cursor;
    uint32_t translated_count;
    uint32_t dispatched_count;
} rome2_startup_msg_pump_env;

/* `0x101061b0` */
uint32_t rome2_startup_pump_messages_101061b0(rome2_startup_msg_pump_env *env);

typedef struct rome2_startup_dinput_env {
    uint8_t has_keyboard;
    uint8_t has_mouse;
    uint32_t kbd_poll_hr;
    uint32_t kbd_reacquire_hr;
    uint32_t kbd_retry_hr;
    uint32_t mouse_poll_hr;
    uint32_t mouse_reacquire_hr;
    uint32_t mouse_retry_hr;
    uint8_t next_keys[256];
    uint8_t curr_keys[256];            /* 0x119f3b78 */
    uint8_t prev_keys[256];            /* 0x119f3c78 */
    rome2_startup_dinput_mouse16_32 next_mouse; /* simulated device output -> 0x119f3d78 */
    rome2_startup_dinput_mouse16_32 scratch_mouse; /* 0x119f3d78 */
    rome2_startup_mouse_pub16_32 pub_mouse;        /* 0x119344d8 */
    uint32_t kbd_acquire_calls;
    uint32_t kbd_unacquire_calls;
    uint32_t mouse_acquire_calls;
    uint32_t mouse_unacquire_calls;
} rome2_startup_dinput_env;

/* `0x1010eda0` */
uint8_t rome2_startup_poll_dinput_1010eda0(rome2_startup_dinput_env *env);

/* -------------------------------------------------------------------------
 * 0x100e0ff0, 0x100e7920, 0x100e7960, 0x100eaba0, 0x100eabf0, 0x100eac10, 0x100ec560:
 * RB-tree erase / balance / iteration on rome2_startup_rb_tree
 * ------------------------------------------------------------------------- */
/* `0x100eabf0` */
uint32_t rome2_startup_dir_rb_max_100eabf0(const rome2_startup_rb_tree *tree, uint32_t idx);

/* `0x100eac10` */
uint32_t rome2_startup_dir_rb_min_100eac10(const rome2_startup_rb_tree *tree, uint32_t idx);

/* `0x100eaba0` */
void rome2_startup_dir_rb_lrotate_100eaba0(rome2_startup_rb_tree *tree, uint32_t idx);

/* `0x100ec560` */
void rome2_startup_dir_rb_rrotate_100ec560(rome2_startup_rb_tree *tree, uint32_t idx);

/* `0x100e0ff0` */
void rome2_startup_dir_rb_iter_next_100e0ff0(const rome2_startup_rb_tree *tree, uint32_t *idx_inout);

/* `0x100e7920` */
void rome2_startup_dir_rb_erase_subtree_100e7920(rome2_startup_rb_tree *tree, uint32_t root_idx);

/* `0x100e7960` */
uint32_t rome2_startup_dir_rb_erase_100e7960(rome2_startup_rb_tree *tree, uint32_t where_idx);

/* -------------------------------------------------------------------------
 * 0x100f2d60, 0x100f5f20, 0x100f7260, 0x10114380, 0x1011fb70, 0x10121350, 0x100ddfc0:
 * Strings, UTF-16 slice ops & AppData user-subpath builder
 * ------------------------------------------------------------------------- */
/* `0x100f2d60` */
rome2_vfs_reg_status rome2_startup_concat_cstr_and_str_100f2d60(
    const char *prefix,
    const char *suffix,
    char *out_buf,
    size_t out_cap,
    size_t *out_len);

/* `0x100f7260` */
int32_t rome2_startup_utf16_slice_compare_range_100f7260(
    const rome2_startup_utf16_cslice *lhs,
    uint32_t offset,
    uint32_t count,
    const rome2_startup_utf16_cslice *rhs);

/* `0x10114380` */
int32_t rome2_startup_utf16_slice_rfind_char_10114380(
    const rome2_startup_utf16_cslice *slice,
    uint16_t ch,
    uint32_t max_pos);

/* `0x100f5f20` */
uint8_t rome2_startup_format_utf16_str_spec_100f5f20(
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len,
    uint16_t spec_ch,
    const uint16_t *arg_u16,
    char *err_diag_ascii,
    size_t err_cap);

/* `0x1011fb70` */
uint8_t rome2_startup_format_next_utf16_spec_1011fb70(
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len,
    const uint16_t *fmt_u16,
    size_t *fmt_pos_inout,
    const uint16_t *arg_u16,
    char *err_diag_ascii,
    size_t err_cap);

/* `0x10121350` */
rome2_vfs_reg_status rome2_startup_build_user_subpath_10121350(
    rome2_startup_path_env *path_env,
    uint32_t category_idx,
    const uint16_t *rel_name_u16,
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len);

/* `0x100ddfc0` */
rome2_vfs_reg_status rome2_startup_format_user_appdata_rel_100ddfc0(
    rome2_startup_path_env *path_env,
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len);

/* -------------------------------------------------------------------------
 * 0x11347290, 0x11349100: Wide basic_filebuf reset & open-init
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_wfstream_filebuf_state {
    uint32_t locale_38;
    uint32_t slot_08;
    uint32_t ptr_0c;
    uint32_t ptr_10;
    uint32_t ptr_1c;
    uint32_t ptr_20;
    uint32_t ptr_2c;
    uint32_t ptr_30;
    uint8_t dirty_36;
    uint8_t is_wide_mode_3c;
    rome2_startup_crt_stream_model *file_40;
} rome2_startup_wfstream_filebuf_state;

/* `0x11349100` */
void rome2_startup_wfstream_filebuf_init_open_11349100(
    rome2_startup_wfstream_filebuf_state *fb,
    rome2_startup_crt_stream_model *file_stream,
    int32_t open_mode,
    uint32_t global_locale_120351cc);

/* `0x11347290` */
rome2_startup_wfstream_filebuf_state *rome2_startup_wfstream_filebuf_close_11347290(
    rome2_startup_wfstream_filebuf_state *fb,
    rome2_startup_crt_stdio_env *crt_env,
    uint32_t global_locale_120351cc);

/* -------------------------------------------------------------------------
 * 0x100d1e30, 0x100d2860, 0x100d32b0, 0x100d3690, 0x100e12e0,
 * 0x100e8660, 0x100f0fd0, 0x100fc8f0, 0x100fd130:
 * Warscape debug/console registry & 0x1173f2ac startup handler closure
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_ptr_vec12 {
    uint32_t cap;
    uint32_t count;
    uint32_t element_vas[8];
    uint32_t backing_va;
    uint32_t destroyed_element_vas[8];
    uint32_t destroyed_count;
    uint8_t backing_freed;
} rome2_startup_ptr_vec12;

typedef struct rome2_startup_console_cmd_entry {
    rome2_startup_console_node_prefix64_32 layout;
    char name[48];
    char desc[24];
    uint32_t node_va;
    uint8_t registered;
} rome2_startup_console_cmd_entry;

typedef struct rome2_startup_warscape_console_group {
    rome2_startup_console_cmd_entry slots[8];
    uint32_t slot_vas[8];
    uint32_t destroyed_slot_vas[8];
    uint32_t destroyed_count;
} rome2_startup_warscape_console_group;

typedef struct rome2_startup_console_registry_env {
    uint32_t handler_vtable_00;        /* 0x1173f2ac -> 0x1173db9c */
    uint32_t handler_va;
    uint32_t global_registry_va;       /* [0x119f3dc8] */
    uint32_t registry_raw_va;          /* base block returned by malloc(0x5c) */
    uint32_t registry_vtable_00;       /* 0x11744de4 */
    uint32_t registry_observer_vtable_3c; /* 0x11741e08 */
    uint32_t cfg_field_04;
    uint32_t cfg_field_08;
    rome2_startup_console_cmd_entry registry_base_node;
    rome2_startup_warscape_console_group *group_04;
    uint32_t group_04_va;
    rome2_startup_ptr_vec12 *vec_08;
    uint32_t vec_08_va;
    uint32_t registered_node_vas[8];
    uint32_t registered_count;
    uint32_t crash_singleton_va;
    uint32_t crash_iface_slots[5];     /* +0x39c, +0x3a0, +0x3a4, +0x3a8, +0x3ac */
    uint32_t flag_100d6560;
    uint32_t freed_vas[16];
    uint32_t freed_count;
} rome2_startup_console_registry_env;

/* `0x100d1e30` */
void rome2_startup_ptr_vec12_init_100d1e30(rome2_startup_ptr_vec12 *vec);

/* `0x100d32b0` */
void rome2_startup_ptr_vec12_destroy_100d32b0(rome2_startup_ptr_vec12 *vec);

/* `0x100d3690` */
void rome2_startup_warscape_console_group_destroy_100d3690(
    rome2_startup_warscape_console_group *group);

/* `0x100f0fd0` */
void rome2_startup_console_node_init_100f0fd0(
    rome2_startup_console_cmd_entry *node,
    const char *name);

/* `0x100fc8f0` */
void rome2_startup_init_global_console_registry_100fc8f0(
    rome2_startup_console_registry_env *env,
    uint32_t cfg_word_04,
    uint32_t cfg_word_08);

/* `0x100fd130` */
void rome2_startup_destroy_global_console_registry_100fd130(
    rome2_startup_console_registry_env *env);

/* `0x100d2860` */
void rome2_startup_warscape_console_group_init_100d2860(
    rome2_startup_console_registry_env *env,
    rome2_startup_warscape_console_group *group);

/* `0x100e8660` */
uint8_t rome2_startup_handler_warscape_console_init_100e8660(
    rome2_startup_console_registry_env *env,
    uint32_t ctx_va,
    uint32_t empire_app_va,
    rome2_startup_warscape_console_group *group_storage,
    rome2_startup_ptr_vec12 *vec_storage);

/* `0x100e12e0` */
uint32_t rome2_startup_handler_warscape_console_dtor_100e12e0(
    rome2_startup_console_registry_env *env,
    uint8_t flags);

#ifdef __cplusplus
}
#endif

#endif
