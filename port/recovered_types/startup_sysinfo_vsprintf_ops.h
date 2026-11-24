#ifndef ROME2_STARTUP_SYSINFO_VSPRINTF_OPS_H
#define ROME2_STARTUP_SYSINFO_VSPRINTF_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_app_ctor_timing_ops.h"
#include "vfs_fs_engine_crt_fpfmt_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_STARTUP_NPRINTF_MAX_ARGS     16u
#define ROME2_STARTUP_NPRINTF_SCRATCH_CAP  256u
#define ROME2_STARTUP_SYSINFO_MAX_ENTRIES  32u
#define ROME2_STARTUP_SYSINFO_MEM_CAP      1024u
#define ROME2_STARTUP_SYSINFO_PATH_CAP     1024u
#define ROME2_STARTUP_SYSINFO_LANG_CAP     256u

#define ROME2_STARTUP_SYSINFO_FLAG_HASH    0x20u
#define ROME2_STARTUP_SYSINFO_FLAG_ALT     0x80u

/* -------------------------------------------------------------------------
 * 0x1168859a..0x1168c0d8 & 0x10126cd0, 0x1169de89:
 * Narrow UCRT string_output_adapter<char> / output_processor<char> vsprintf
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_nprintf_target {
    rome2_startup_narrow_printf_adapter16_32 guest16;
    char *buf;
    uint32_t max_chars;
    uint32_t written_chars;
    uint8_t continue_on_truncation;
} rome2_startup_nprintf_target;

typedef struct rome2_startup_nprintf_unicode_view {
    rome2_vfs_crt_unicode_string8_32 guest8;
    const char *narrow_buf;
    const uint16_t *wide_buf;
} rome2_startup_nprintf_unicode_view;

typedef struct rome2_startup_nprintf_processor {
    uint64_t options;                  /* +00/+04 */
    uint8_t has_locale;                /* +08 */
    uint8_t suppress_leadbyte_failure; /* +09 */
    const uint8_t *lead_table;         /* optional 256-entry _isleadbyte table */
    const char *fmt_cursor;            /* +10 */
    const uintptr_t *args;             /* +14 */
    size_t arg_count;
    size_t arg_idx;
    int32_t characters_written;        /* +18 */
    int32_t state;                     /* +1c */
    uint32_t flags;                    /* +20 */
    int32_t field_width;               /* +24 */
    int32_t precision;                 /* +28 */
    uint32_t length_mod;               /* +2c */
    uint8_t suppress_output;           /* +30 */
    uint8_t current_ch;                /* +31 */
    const char *narrow_ptr;            /* +34 (string_or_wchar union narrow) */
    const uint16_t *wide_ptr;          /* +34 (string_or_wchar union wide) */
    int32_t str_len;                   /* +38 */
    uint8_t is_wide;                   /* +3c */
    char narrow_buf[ROME2_STARTUP_NPRINTF_SCRATCH_CAP];
    uint16_t wide_buf[64];
    int32_t passes;                    /* +450 */
    int32_t last_errno;
    uint32_t invalid_param_count;
    rome2_startup_nprintf_target *target;
    rome2_startup_narrow_printf_processor1100_32 guest_state;
} rome2_startup_nprintf_processor;

/* `0x1169de89`: CRT strtol on ASCII base 0/2..36. */
int32_t rome2_startup_crt_strtol_1169de89(
    const char *nptr,
    const char **out_endptr,
    int32_t base,
    int32_t *out_errno);

/* `0x1168942b`: parse decimal field width or precision from fmt_cursor. */
uint8_t rome2_startup_nprintf_parse_int_1168942b(
    rome2_startup_nprintf_processor *proc,
    int32_t *out_val);

/* `0x11688abd`: narrow specifier width rule is_wide_character_specifier<char>. */
uint8_t rome2_startup_nprintf_is_wide_specifier_11688abd(
    uint64_t options,
    uint8_t specifier,
    int32_t length_mod);

/* `0x11689311`: printf state-table transition find_next_state (0x1190ec70). */
uint32_t rome2_startup_nprintf_find_next_state_11689311(
    uint8_t ch,
    uint32_t prev_state);

/* `0x11688e5c` & `0x11688eeb`: common_data<char> & output_adapter_data<char> init. */
void rome2_startup_nprintf_common_data_init_11688e5c(
    rome2_startup_nprintf_processor *proc);

void rome2_startup_nprintf_adapter_data_init_11688eeb(
    rome2_startup_nprintf_processor *proc,
    rome2_startup_nprintf_target *target,
    uint64_t options,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count);

/* `0x1168b92d`, `0x1168bcef`, `0x11688dff`: narrow adapter character & string writers. */
uint8_t rome2_startup_nprintf_write_char_1168b92d(
    rome2_startup_nprintf_target *target,
    char ch,
    int32_t *written_inout);

void rome2_startup_nprintf_write_string_1168bcef(
    rome2_startup_nprintf_target *target,
    const char *s,
    int32_t len,
    int32_t *written_inout);

void rome2_startup_nprintf_write_multi_chars_11688dff(
    rome2_startup_nprintf_target *target,
    char ch,
    int32_t count,
    int32_t *written_inout);

/* `0x1168baca`: emit narrow or wide stored string with UTF-16->char fallback on narrow target. */
uint8_t rome2_startup_nprintf_write_stored_tchar_1168baca(
    rome2_startup_nprintf_processor *proc);

/* `0x11689ce5`, `0x1168ae5c`, `0x11689f55`, `0x1168a0f0`: flag/width/prec/size state handlers. */
uint8_t rome2_startup_nprintf_state_flag_11689ce5(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_state_width_1168ae5c(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_state_precision_11689f55(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_state_size_1168a0f0(
    rome2_startup_nprintf_processor *proc);

/* `0x11689ef1`, `0x11689e15`, `0x11689d7e`: normal-character state handlers. */
uint8_t rome2_startup_nprintf_state_normal_tchar_11689ef1(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_state_normal_common_11689e15(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_state_normal_11689d7e(
    rome2_startup_nprintf_processor *proc);

/* `0x11688b5a`, `0x11688c54`, `0x1168b395`, `0x1168b6af`, `0x1168b6ed`: integer/octal/ptr formatting. */
void rome2_startup_nprintf_int32_into_buf_11688b5a(
    rome2_startup_nprintf_processor *proc,
    uint32_t val,
    uint32_t radix,
    uint8_t is_upper);

void rome2_startup_nprintf_int64_into_buf_11688c54(
    rome2_startup_nprintf_processor *proc,
    uint64_t val,
    uint64_t radix,
    uint8_t is_upper);

uint8_t rome2_startup_nprintf_type_integer_1168b395(
    rome2_startup_nprintf_processor *proc,
    uint32_t radix,
    uint8_t is_upper);

uint8_t rome2_startup_nprintf_type_o_1168b6af(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_type_p_1168b6ed(
    rome2_startup_nprintf_processor *proc);

/* `0x1168af07`, `0x1168b71d`, `0x1168b26f`, `0x1168afbb`, `0x1168a760`: Z/s/c/float & dispatcher. */
uint8_t rome2_startup_nprintf_type_Z_1168af07(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_type_s_1168b71d(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_type_c_tchar_1168b26f(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_type_a_1168afbb(
    rome2_startup_nprintf_processor *proc);

uint8_t rome2_startup_nprintf_state_type_1168a760(
    rome2_startup_nprintf_processor *proc);

/* `0x11689871`, `0x1168859a`, `0x1168c0d8`, `0x10126cd0`: top-level narrow sprintf entrypoints. */
int32_t rome2_startup_nprintf_process_11689871(
    rome2_startup_nprintf_processor *proc);

int32_t rome2_startup_crt_common_vsprintf_char_1168859a(
    uint64_t options,
    char *buf,
    uint32_t max_chars,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno);

int32_t rome2_startup_stdio_common_vsprintf_1168c0d8(
    uint64_t options,
    char *buf,
    uint32_t max_chars,
    const char *fmt,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno);

int32_t rome2_startup_crt_sprintf_10126cd0(
    char *buf,
    const char *fmt,
    const uintptr_t *args,
    size_t arg_count);

/* -------------------------------------------------------------------------
 * 0x112f6190: os_build_system_info_string
 * ------------------------------------------------------------------------- */
typedef struct rome2_startup_sysinfo_find_entry {
    char file_name[64];
    uint32_t file_attributes;          /* Win32 FILE_ATTRIBUTE_DIRECTORY = 0x10 */
} rome2_startup_sysinfo_find_entry;

typedef struct rome2_startup_sysinfo_env {
    rome2_startup_memory_status_ex64_32 mem_status;
    char module_file_name_a[ROME2_STARTUP_SYSINFO_PATH_CAP];
    rome2_startup_sysinfo_find_entry data_entries[ROME2_STARTUP_SYSINFO_MAX_ENTRIES];
    uint32_t data_entry_count;
    uint8_t find_first_succeeds;       /* 0 simulates INVALID_HANDLE_VALUE (-1) */
    char locale_lang_in[ROME2_STARTUP_SYSINFO_LANG_CAP];
    uint8_t get_locale_info_succeeds;

    /* Observable calls and outputs matching globals 0x12033e68, 0x12034268, 0x12034b88 */
    char last_search_pattern[ROME2_STARTUP_SYSINFO_PATH_CAP];
    char global_mem_info_12033e68[ROME2_STARTUP_SYSINFO_MEM_CAP];
    char global_exe_data_12034268[ROME2_STARTUP_SYSINFO_PATH_CAP];
    char global_locale_12034b88[ROME2_STARTUP_SYSINFO_LANG_CAP];
    int32_t counted_data_dirs;
    uint32_t find_close_calls;
} rome2_startup_sysinfo_env;

/* `0x112f6190` */
void rome2_startup_os_build_system_info_string_112f6190(
    rome2_startup_sysinfo_env *env);

#ifdef __cplusplus
}
#endif

#endif
