#ifndef ROME2_STARTUP_APP_CTOR_TIMING_OPS_H
#define ROME2_STARTUP_APP_CTOR_TIMING_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_export_bootstrap_ops.h"
#include "vfs_archive_register.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_STARTUP_MAX_FS_ENTRIES 32u
#define ROME2_STARTUP_MAX_ABORT_RESPONSES 8u
#define ROME2_STARTUP_WPRINTF_MAX_ARGS 16u

/* Win32 UI / message-box constants referenced by 0x100df270 and 0x101032a0 */
#define ROME2_STARTUP_SPI_GETMOUSETRAILS 0x005Eu
#define ROME2_STARTUP_SPI_SETMOUSETRAILS 0x005Du
#define ROME2_STARTUP_ERROR_ALREADY_EXISTS 0x00B7u
#define ROME2_STARTUP_CACHE_MAGIC_INITIALIZED 0x4E3Bu
#define ROME2_STARTUP_MB_OK 1
#define ROME2_STARTUP_MB_CANCEL 2
#define ROME2_STARTUP_MB_ABORT 3
#define ROME2_STARTUP_MB_RETRY 4

/* UCRT common_vsprintf option bits verified in 0x11688718 */
#define ROME2_STARTUP_WPRINTF_OPT_STANDARD_SNPRINTF 0x01ULL
#define ROME2_STARTUP_WPRINTF_OPT_LEGACY_NULL_TERM  0x02ULL
#define ROME2_STARTUP_WPRINTF_OPT_DISABLE_FN        0x08ULL

/* -------------------------------------------------------------------------
 * 0x11688718..0x1168c120 & 0x100edfe0: wide string_output_adapter vswprintf
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_wprintf_target {
    rome2_startup_wprintf_string_adapter16_32 guest16;
    uint16_t *buf;
    uint32_t max_chars;
    uint32_t written_chars;
    uint8_t continue_on_truncation;
} rome2_startup_wprintf_target;

typedef struct rome2_startup_wprintf_processor {
    uint64_t options;
    const uint16_t *fmt_cursor;
    int32_t characters_written;
    int32_t state;
    uint32_t flags;
    int32_t field_width;
    int32_t precision;
    uint32_t length_mod;
    uint8_t suppress_output;
    uint16_t current_ch;
    uint8_t is_wide;
    char narrow_buf[96];
    uint16_t wide_buf[96];
    const char *narrow_ptr;
    const uint16_t *wide_ptr;
    int32_t str_len;
    int32_t passes;
    int32_t last_errno;
    uint32_t invalid_param_count;
    rome2_startup_wprintf_target *target;
    const uintptr_t *args;
    size_t arg_count;
    size_t arg_idx;
} rome2_startup_wprintf_processor;

uint8_t rome2_startup_wprintf_write_char_1168b96f(
    rome2_startup_wprintf_target *target,
    uint16_t ch,
    int32_t *written_inout);

void rome2_startup_wprintf_write_string_1168bd56(
    rome2_startup_wprintf_target *target,
    const uint16_t *s,
    int32_t len,
    int32_t *written_inout);

void rome2_startup_wprintf_write_multi_chars_11688e2b(
    rome2_startup_wprintf_target *target,
    char ch,
    int32_t count,
    int32_t *written_inout);

uint8_t rome2_startup_wprintf_write_stored_tchar_1168bc04(
    rome2_startup_wprintf_processor *proc,
    uint16_t unused_ch);

uint8_t rome2_startup_wprintf_state_normal_common_11689e69(
    rome2_startup_wprintf_processor *proc);

uint8_t rome2_startup_wprintf_state_normal_11689dbc(
    rome2_startup_wprintf_processor *proc);

uint8_t rome2_startup_wprintf_state_size_1168a3b6(
    rome2_startup_wprintf_processor *proc);

uint8_t rome2_startup_wprintf_state_type_1168abf7(
    rome2_startup_wprintf_processor *proc);

int32_t rome2_startup_wprintf_process_11689bc9(
    rome2_startup_wprintf_processor *proc);

int32_t rome2_startup_crt_common_vsprintf_wide_11688718(
    uint64_t options,
    uint16_t *buf,
    uint32_t max_chars,
    const uint16_t *fmt,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno);

int32_t rome2_startup_stdio_common_vswprintf_1168c120(
    uint64_t options,
    uint16_t *buf,
    uint32_t max_chars,
    const uint16_t *fmt,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno);

int32_t rome2_startup_wide_vswprintf_100edfe0(
    uint16_t *dst,
    uint32_t max_chars,
    const uint16_t *fmt,
    const uintptr_t *args,
    size_t arg_count);

/* -------------------------------------------------------------------------
 * 0x11687a4a, 0x100f4a10, 0x101032a0, 0x100de6d0: invalid-param, pointer fmt & fatal diag
 * ------------------------------------------------------------------------- */
uint32_t rome2_startup_crt_set_invalid_parameter_handler_11687a4a(
    uint32_t *encoded_slot_inout,
    uint32_t security_cookie,
    uint32_t new_handler);

uint8_t rome2_startup_format_void_ptr_100f4a10(
    uintptr_t ptr_val,
    char spec_char,
    char *out_buf,
    size_t out_cap,
    size_t *out_len,
    char *diag_buf,
    size_t diag_cap);

typedef uint8_t (*rome2_startup_diag_cb)(
    uint8_t is_nonfatal,
    const uint16_t *wide_msg,
    uint8_t *out_continue,
    void *ctx);

typedef struct rome2_startup_abort_env {
    rome2_startup_diag_cb diag_cb;
    void *diag_ctx;
    uint16_t module_path_u16[ROME2_STARTUP_MAX_PATH_U16];
    uint32_t active_hwnd;
    uint32_t cached_hwnd;
    int32_t prompt_responses[ROME2_STARTUP_MAX_ABORT_RESPONSES];
    size_t prompt_response_count;
    size_t prompt_response_cursor;
    uint32_t msgbox_calls;
    uint32_t debug_output_calls;
    uint16_t last_debug_msg_u16[ROME2_STARTUP_MAX_PATH_U16];
    char last_diag_error_a[96];
    uint8_t terminate_called;
    uint32_t terminate_exit_code;
} rome2_startup_abort_env;

void rome2_startup_terminate_zero_10102850(rome2_startup_abort_env *env);

uint8_t rome2_startup_prompt_fatal_abort_101032a0(
    rome2_startup_abort_env *env,
    uint8_t is_nonfatal,
    const uint16_t *wide_msg);

uint8_t rome2_startup_format_fatal_diag_100de6d0(
    rome2_startup_abort_env *env,
    uint8_t is_nonfatal,
    const char *fmt_a,
    uintptr_t ptr_val,
    uint8_t *reentrancy_guard);

/* -------------------------------------------------------------------------
 * 0x10122e40, 0x100fe770, 0x101046d0, 0x100f0eb0, 0x1014d170, 0x100df270
 * ------------------------------------------------------------------------- */
const char *rome2_startup_get_user_folder_col0_prefix_10122e40(uint32_t category_idx);

typedef struct rome2_startup_fs_mock_entry {
    const char *parent_rel;
    const char *name;
    uint32_t file_attributes;
    uint64_t write_time_100ns;
    uint32_t size_lo;
    uint32_t size_hi;
    uint8_t deleted;
} rome2_startup_fs_mock_entry;

typedef struct rome2_startup_fs_mock_env {
    rome2_startup_fs_mock_entry entries[ROME2_STARTUP_MAX_FS_ENTRIES];
    uint32_t entry_count;
    uint32_t find_first_calls;
    uint32_t find_close_calls;
    uint32_t deleted_count;
} rome2_startup_fs_mock_env;

typedef struct rome2_startup_enum_entry_info {
    uint32_t converted_unix_time_2c;
    uint32_t raw_attributes_34;
    uint32_t size_lo;
    uint8_t is_readonly_27;
    uint8_t is_dir_26;
    uint8_t is_hidden_25;
    uint8_t is_present_28;
} rome2_startup_enum_entry_info;

typedef void (*rome2_startup_dir_enum_cb)(
    const uint16_t *dir_u16,
    const uint16_t *name_u16,
    const uint16_t *pattern_u16,
    const rome2_startup_enum_entry_info *info,
    void *ctx);

rome2_vfs_reg_status rome2_startup_dir_enum_and_clean_100fe770(
    rome2_startup_fs_mock_env *fs_env,
    rome2_startup_dir_enum_cb cb,
    const uint16_t *dir_u16,
    const uint16_t *pattern_u16,
    void *cb_ctx,
    uint8_t recurse);

rome2_vfs_reg_status rome2_startup_clean_user_category_dir_101046d0(
    rome2_startup_path_env *path_env,
    rome2_startup_fs_mock_env *fs_env,
    uint32_t category_idx);

rome2_startup_observer_node12_32 *rome2_startup_init_observer_node_100f0eb0(
    rome2_startup_observer_node12_32 *node,
    uint32_t owner_va);

rome2_startup_pair8_32 *rome2_startup_init_zero_pair8_1014d170(
    rome2_startup_pair8_32 *pair);

typedef struct rome2_startup_app_params {
    uint32_t hinstance;
    uint32_t unused_04;
    const uint16_t *arg_str1_u16;
    const uint16_t *arg_str2_u16;
    uint32_t flags_20;
    uint8_t byte_24;
    uint32_t dword_28;
    uint8_t allow_multi_instance_2c;
} rome2_startup_app_params;

typedef struct rome2_startup_app_state {
    uint32_t vtable_00;
    uint32_t vtable_history[4];
    uint32_t vtable_history_count;
    uint32_t embedded_cfg_vtable_874; /* 0x1173dc18 */
    uint32_t hinstance_04;
    uint16_t string_67[64];
    uint16_t string_6d[64];
    uint32_t mutex_handle_808;
    uint8_t mutex_already_existed;
    uint8_t allow_multi_instance_copy;
    uint32_t spi_calls[2];
    uint32_t spi_saved_mouse_trails; /* 0x119f3854 */
    rome2_startup_observer_node12_32 observer;
    rome2_startup_pair8_32 pair_tail;
    uint32_t global_app_ptr; /* 0x119f3140 */
    uint32_t cache_magic;    /* 0x4e3b */
    uint32_t cleaned_categories[8];
    uint32_t cleaned_category_count;
    uint32_t mutex_error_msgbox_calls;
    uint16_t mutex_msgbox_text[96];
    uint16_t mutex_msgbox_title[32];
} rome2_startup_app_state;

typedef struct rome2_startup_app_host_env {
    const uint16_t *res_string_67;
    const uint16_t *res_string_6d;
    uint32_t mutex_handle_value;
    uint8_t simulate_already_exists;
    uint32_t initial_mouse_trails;
    rome2_startup_abort_env *abort_env;
    rome2_startup_path_env *path_env;
    rome2_startup_crash_singleton *crash_singleton;
    rome2_startup_handler_queue *handler_queue;
    rome2_startup_fs_mock_env *fs_env;
    int32_t tls_epoch;
    uint32_t persistent_cache_magic;
} rome2_startup_app_host_env;

rome2_vfs_reg_status rome2_startup_app_ctor_100df270(
    rome2_startup_app_state *app,
    rome2_startup_app_host_env *host,
    const rome2_startup_app_params *params);

/* -------------------------------------------------------------------------
 * 0x10115800, 0x10115810, 0x112e2bb0, 0x106b91a0, 0x112b2d40, 0x112dcaf0
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_winmm_env {
    uint32_t current_time_ms;
    uint64_t baseline_us; /* [0x12031ae8..0x12031aef] */
    uint32_t begin_calls;
    uint32_t end_calls;
    uint32_t last_period_ms;
} rome2_startup_winmm_env;

uint32_t rome2_startup_winmm_time_begin_period_10115800(
    rome2_startup_winmm_env *env,
    uint32_t period_ms);

uint32_t rome2_startup_winmm_time_end_period_10115810(
    rome2_startup_winmm_env *env,
    uint32_t period_ms);

rome2_vfs_reg_status rome2_startup_query_high_res_us_112e2bb0(
    rome2_startup_winmm_env *env,
    uint64_t *out_us);

rome2_vfs_reg_status rome2_startup_format_two_strings_106b91a0(
    const uint16_t *fmt_u16,
    const char *s1,
    const char *s2,
    char *out_buf,
    size_t out_cap,
    size_t *out_len);

typedef struct rome2_startup_timing_report_env {
    rome2_startup_timing_env *base;
    rome2_startup_alloc_table *alloc_tbl;
    rome2_startup_winmm_env *winmm;
    rome2_startup_timing_vec12_32 vec_header;
    uint32_t last_reported_ms;
    uint32_t last_reported_alloc;
    char primary_banner[160];
    char secondary_banner[160];
} rome2_startup_timing_report_env;

rome2_vfs_reg_status rome2_startup_record_sorted_timing_slot_112b2d40(
    rome2_startup_timing_report_env *env,
    uint32_t label_ptr_va,
    uint32_t delta_ms,
    uint32_t detail_tag,
    uint32_t detail_arg);

rome2_vfs_reg_status rome2_startup_report_section_timing_done_112dcaf0(
    rome2_startup_timing_report_env *env,
    const char *subsection,
    int32_t detail_tag,
    const char *detail_arg);

#ifdef __cplusplus
}
#endif

#endif
