#ifndef ROME2_STARTUP_STDIO_STREAM_OPS_H
#define ROME2_STARTUP_STDIO_STREAM_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_vfprintf_read_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_STARTUP_L65_IOINFO_ARRAY_LEN   64u
#define ROME2_STARTUP_L65_MAX_IO_PAGES       16u
#define ROME2_STARTUP_L65_MAX_FILES          32u
#define ROME2_STARTUP_L65_FILE_DATA_CAP      512u

/* CRT lowio open flags & permissions mirrored cleanly from binary constants. */
#define ROME2_STARTUP_O_RDONLY               0x00000u
#define ROME2_STARTUP_O_WRONLY               0x00001u
#define ROME2_STARTUP_O_RDWR                 0x00002u
#define ROME2_STARTUP_O_APPEND               0x00008u
#define ROME2_STARTUP_O_RANDOM               0x00010u
#define ROME2_STARTUP_O_SEQUENTIAL           0x00020u
#define ROME2_STARTUP_O_TEMPORARY            0x00040u
#define ROME2_STARTUP_O_NOINHERIT            0x00080u
#define ROME2_STARTUP_O_CREAT                0x00100u
#define ROME2_STARTUP_O_TRUNC                0x00200u
#define ROME2_STARTUP_O_EXCL                 0x00400u
#define ROME2_STARTUP_O_SHORT_LIVED          0x01000u
#define ROME2_STARTUP_O_OBTAIN_DIR           0x02000u
#define ROME2_STARTUP_O_TEXT                 0x04000u
#define ROME2_STARTUP_O_BINARY               0x08000u
#define ROME2_STARTUP_O_WTEXT                0x10000u
#define ROME2_STARTUP_O_U16TEXT              0x20000u
#define ROME2_STARTUP_O_U8TEXT               0x40000u

#define ROME2_STARTUP_SH_COMPAT              0x00u
#define ROME2_STARTUP_SH_DENYRW              0x10u
#define ROME2_STARTUP_SH_DENYWR              0x20u
#define ROME2_STARTUP_SH_DENYRD              0x30u
#define ROME2_STARTUP_SH_DENYNO              0x40u
#define ROME2_STARTUP_SH_SECURE              0x80u

#define ROME2_STARTUP_IOREAD                 0x0001u
#define ROME2_STARTUP_IOWRT                  0x0002u
#define ROME2_STARTUP_IORW                   0x0004u
#define ROME2_STARTUP_IOCOMMIT               0x0800u

#define ROME2_STARTUP_LOWIO_FNOINHERIT       0x10u
#define ROME2_STARTUP_LOWIO_FAPPEND          0x20u

typedef struct rome2_startup_l65_vfs_file {
    char path[128];
    uint8_t exists;
    uint8_t is_readonly;
    uint32_t file_type;                /* 1=DISK, 2=CHAR/DEV, 3=PIPE */
    uint8_t data[ROME2_STARTUP_L65_FILE_DATA_CAP];
    size_t len;
    int64_t cursor;
} rome2_startup_l65_vfs_file;

typedef struct rome2_startup_l65_critsec_state {
    uint32_t spin_count;
    uint32_t flags;
    uint8_t used_ex_api;
    uint8_t initialized;
} rome2_startup_l65_critsec_state;

typedef struct rome2_startup_l65_stdio_stream {
    uint32_t flags;
    int32_t file_handle;
    uintptr_t ptr_val;
    uintptr_t base_val;
    int32_t cnt;
    uintptr_t tmpfname_val;
} rome2_startup_l65_stdio_stream;

typedef struct rome2_startup_l65_ioinfo_slot {
    rome2_startup_crt_ioinfo_read56_32 guest;
    rome2_startup_l65_critsec_state cs;
    int32_t backed_file_idx;
    uint32_t lock_depth;
    uint8_t handle_allocated;
    uint32_t os_handle;
} rome2_startup_l65_ioinfo_slot;

typedef struct rome2_startup_l65_crt_env {
    uint32_t commode;                  /* DAT_121262f4 */
    uint32_t umask;                    /* DAT_1212633c */
    uint32_t fmode;                    /* DAT_12126340 */
    uint32_t open_stream_count;        /* DAT_12125c3c */
    uint32_t lowio_lock_count;
    uint32_t lowio_unlock_count;
    uint8_t is_gui_app;                /* 116bc6d8 == 1 triggers SetStdHandle */
    uint8_t has_ex_cs_api;
    uint8_t has_custom_locale;         /* DAT_12125f10 */
    uint32_t nhandle;                  /* DAT_12126118 */
    uint8_t fail_alloc_array;
    uint8_t force_first_open_rw_denied;
    uint32_t set_std_handle_calls;
    uint32_t last_std_handle_id;
    uint32_t last_std_handle_val;
    int32_t last_errno;
    uint32_t last_doserrno;
    uint32_t invalid_param_calls;
    uint32_t watson_calls;
    rome2_startup_l65_vfs_file files[ROME2_STARTUP_L65_MAX_FILES];
    rome2_startup_l65_ioinfo_slot *pages[ROME2_STARTUP_L65_MAX_IO_PAGES];
} rome2_startup_l65_crt_env;

/* Lifecycle helper for deterministic zeroed synthetic CRT environment. */
void rome2_startup_l65_env_init(rome2_startup_l65_crt_env *env);
void rome2_startup_l65_env_destroy(rome2_startup_l65_crt_env *env);
int32_t rome2_startup_l65_env_add_file(
    rome2_startup_l65_crt_env *env,
    const char *path,
    const uint8_t *data,
    size_t len,
    uint32_t file_type,
    uint8_t is_readonly);

/* `0x1168d030`: CRT _strncmp (disjoint 2-range function). */
int32_t rome2_startup_crt_strncmp_1168d030(const char *s1, const char *s2, size_t max_count);

/* `0x116b844f` / `0x116b849b`: CRT __wcsnicmp / __wcsnicmp_l (UTF-16 units). */
int32_t rome2_startup_crt_wcsnicmp_116b844f(
    rome2_startup_l65_crt_env *env,
    const uint16_t *s1,
    const uint16_t *s2,
    size_t max_count);

int32_t rome2_startup_crt_wcsnicmp_l_116b849b(
    rome2_startup_l65_crt_env *env,
    const uint16_t *s1,
    const uint16_t *s2,
    size_t max_count,
    uint8_t has_locale);

/* `0x116a896e`: ___acrt_InitializeCriticalSectionEx@12. */
uint8_t rome2_startup_crt_init_cs_ex_116a896e(
    const rome2_startup_l65_crt_env *env,
    rome2_startup_l65_critsec_state *cs,
    uint32_t spin_count,
    uint32_t flags);

/* `0x116aa8b8..0x116aa9ac`: __acrt_stdio_parse_mode sub-flag parsers. */
uint8_t rome2_startup_crt_parse_mode_D_116aa8b8(rome2_startup_crt_stdio_mode12_32 *mode);
uint8_t rome2_startup_crt_parse_mode_T_116aa8d3(rome2_startup_crt_stdio_mode12_32 *mode);
uint8_t rome2_startup_crt_parse_mode_b_116aa8f2(rome2_startup_crt_stdio_mode12_32 *mode);
uint8_t rome2_startup_crt_parse_mode_c_116aa912(rome2_startup_crt_stdio_mode12_32 *mode, uint8_t *seen_commit);
uint8_t rome2_startup_crt_parse_mode_n_116aa934(rome2_startup_crt_stdio_mode12_32 *mode, uint8_t *seen_commit);
uint8_t rome2_startup_crt_parse_mode_plus_116aa956(rome2_startup_crt_stdio_mode12_32 *mode, uint8_t *seen_plus);
uint8_t rome2_startup_crt_parse_mode_t_116aa98c(rome2_startup_crt_stdio_mode12_32 *mode);
uint8_t rome2_startup_crt_parse_mode_x_116aa9ac(rome2_startup_crt_stdio_mode12_32 *mode);

/* `0x116aa31d` / `0x116aa547`: __acrt_stdio_parse_mode<char/wchar_t>. */
rome2_startup_crt_stdio_mode12_32 rome2_startup_crt_parse_mode_char_116aa31d(
    rome2_startup_l65_crt_env *env,
    const char *mode_str);

rome2_startup_crt_stdio_mode12_32 rome2_startup_crt_parse_mode_wchar_116aa547(
    rome2_startup_l65_crt_env *env,
    const uint16_t *mode_wstr);

/* `0x116aa7b2` / `0x116aa835`: common_openfile<char/wchar_t>. */
rome2_startup_l65_stdio_stream *rome2_startup_crt_common_openfile_char_116aa7b2(
    rome2_startup_l65_crt_env *env,
    const char *filename,
    const char *mode_str,
    int32_t shflag,
    rome2_startup_l65_stdio_stream *stream);

rome2_startup_l65_stdio_stream *rome2_startup_crt_common_openfile_wchar_116aa835(
    rome2_startup_l65_crt_env *env,
    const uint16_t *filename,
    const uint16_t *mode_wstr,
    int32_t shflag,
    rome2_startup_l65_stdio_stream *stream);

/* `0x116ae68f`, `0x116ae800`, `0x116ae8b5`, `0x116ae9bf`: lowio handle array & osfhnd allocation. */
rome2_startup_l65_ioinfo_slot *rome2_startup_crt_lowio_create_handle_array_116ae68f(
    rome2_startup_l65_crt_env *env);

int32_t rome2_startup_crt_lowio_set_os_handle_116ae800(
    rome2_startup_l65_crt_env *env,
    int32_t fh,
    uint32_t osfhnd);

int32_t rome2_startup_crt_alloc_osfhnd_116ae8b5(rome2_startup_l65_crt_env *env);
void rome2_startup_crt_alloc_osfhnd_seh_unlock_116ae9bf(rome2_startup_l65_crt_env *env);

/* `0x116bc6de`, `0x116bc70b`, `0x116bc7da`, `0x116bc827`: fmode / setmode / seek_guard / chsize_nolock. */
int32_t rome2_startup_crt_get_fmode_116bc6de(
    rome2_startup_l65_crt_env *env,
    uint32_t *out_fmode);

int32_t rome2_startup_crt_setmode_nolock_116bc70b(
    rome2_startup_l65_crt_env *env,
    int32_t fh,
    int32_t mode);

void rome2_startup_crt_seek_guard_init_116bc7da(
    rome2_startup_l65_crt_env *env,
    rome2_startup_crt_seek_guard28_32 *guard,
    int32_t fh,
    int64_t target_size);

int32_t rome2_startup_crt_chsize_nolock_116bc827(
    rome2_startup_l65_crt_env *env,
    int32_t fh,
    int64_t new_size);

/* `0x116aef71`, `0x116aefe1`, `0x116aef4c`, `0x116af15b`, `0x116aecf9`: open flag decoders & BOM/^Z helpers. */
uint32_t rome2_startup_crt_decode_open_create_flags_116aef71(
    rome2_startup_l65_crt_env *env,
    int32_t oflag);

rome2_startup_crt_file_options24_32 *rome2_startup_crt_decode_options_116aefe1(
    rome2_startup_l65_crt_env *env,
    rome2_startup_crt_file_options24_32 *out_opts,
    uint32_t oflag,
    int32_t shflag,
    uint8_t pmode);

int32_t rome2_startup_crt_create_file_116aef4c(
    rome2_startup_l65_crt_env *env,
    const uint16_t *filename,
    const rome2_startup_crt_file_options24_32 *opts);

int32_t rome2_startup_crt_truncate_ctrl_z_116af15b(
    rome2_startup_l65_crt_env *env,
    int32_t fh);

int32_t rome2_startup_crt_configure_text_mode_116aecf9(
    rome2_startup_l65_crt_env *env,
    int32_t fh,
    const rome2_startup_crt_file_options24_32 *opts,
    uint32_t oflag,
    uint8_t *out_textmode);

/* `0x116aeb77`, `0x116aec0c`, `0x116aec38`, `0x116aeccd`, `0x116af21d`, `0x116af28b`, `0x116af2ab`, `0x116af5d5`: sopen stack. */
void rome2_startup_crt_sopen_cleanup_char_116aec0c(
    rome2_startup_l65_crt_env *env,
    int32_t err,
    int32_t unlock_flag,
    const int32_t *pfh);

void rome2_startup_crt_sopen_cleanup_wchar_116aeccd(
    rome2_startup_l65_crt_env *env,
    int32_t err,
    int32_t unlock_flag,
    const int32_t *pfh);

int32_t rome2_startup_crt_wsopen_nolock_116af2ab(
    rome2_startup_l65_crt_env *env,
    int32_t *unlock_flag,
    int32_t *out_fh,
    const uint16_t *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode,
    int32_t secure);

int32_t rome2_startup_crt_sopen_nolock_116af21d(
    rome2_startup_l65_crt_env *env,
    int32_t *unlock_flag,
    int32_t *out_fh,
    const char *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode,
    int32_t secure);

int32_t rome2_startup_crt_common_sopen_dispatch_char_116aeb77(
    rome2_startup_l65_crt_env *env,
    const char *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode,
    int32_t *out_fh,
    int32_t secure);

int32_t rome2_startup_crt_common_sopen_dispatch_wchar_116aec38(
    rome2_startup_l65_crt_env *env,
    const uint16_t *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode,
    int32_t *out_fh,
    int32_t secure);

int32_t rome2_startup_crt_sopen_s_116af28b(
    rome2_startup_l65_crt_env *env,
    int32_t *out_fh,
    const char *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode);

int32_t rome2_startup_crt_wsopen_s_116af5d5(
    rome2_startup_l65_crt_env *env,
    int32_t *out_fh,
    const uint16_t *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode);

#ifdef __cplusplus
}
#endif

#endif
