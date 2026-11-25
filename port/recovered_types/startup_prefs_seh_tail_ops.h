#ifndef ROME2_STARTUP_PREFS_SEH_TAIL_OPS_H
#define ROME2_STARTUP_PREFS_SEH_TAIL_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

/*
 * Layer 72 Partition 9 recovery:
 * 25 functions closing 6 of the 9 open jump targets from Layer 71
 * (0x100dacb0 preferences writer closure, 0x10fd964a SEH restore,
 * 0x116b326e/0x116b327b math CW/exit, 0x116bd580/0x116bd59e log10,
 * 0x116bd810 __ascii_strnicmp) plus the 11 callees of entry_point's
 * _except_handler4 (0x116be3d8) and RaiseException invalid-parameter
 * helper observation (0x100ee5d0).
 *
 * Native adaptations: virtual slots, CRT file I/O, PE memory/section
 * queries and exception unwinding are bounded native models or injected
 * callbacks; no live SEH frames, global CRT locks or filesystem I/O are
 * mutated implicitly.
 */

#define ROME2_L72_NLG_SIG 0x19930520u
#define ROME2_L72_CPP_EH_CODE 0xe06d7363u
#define ROME2_L72_X87_DEFAULT_CW 0x027fu
#define ROME2_L72_X87_PRECISION_MASK 0x0020u
#define ROME2_L72_PE_SCN_MEM_EXECUTE 0x20000000u
#define ROME2_L72_PE_SCN_MEM_WRITE 0x80000000u

/* Bounded UTF-16 output stream model for 0x100d12d0 / 0x100d14d0 / 0x11346aa0 / 0x11349f80. */
typedef struct rome2_l72_wstream {
    uint16_t *buf;
    size_t capacity;
    size_t len;
    uint32_t width;                              /* ios_base width (+0x10) */
    uint16_t fill;                               /* ios_base fill (+0x1c), default L' ' */
    uint32_t rdstate;                            /* ios_base state (+0x04), low 4 bits */
    uint8_t rdbuf_present;                       /* nonzero when streambuf != NULL */
    uint8_t sink_fail;                           /* test hook: simulate sputc == WEOF */
    uint8_t sentry_ok;                           /* sentry result (0 forces badbit/failbit) */
} rome2_l72_wstream;

typedef struct rome2_l72_pref_item {
    const char *name;
    const char *group;
    const char *desc;
    uint8_t quote;
    void (*format_value)(void *user, rome2_l72_wstream *stream);
    void *user;
} rome2_l72_pref_item;

/* Bounded C17 models for 0x100d6570, 0x11346aa0, 0x11349f80, 0x100d12d0, 0x100d14d0, 0x100dacb0. */
void rome2_l72_stream_set_badbit(rome2_l72_wstream *stream);
void rome2_l72_wostream_insert_cstr(rome2_l72_wstream *stream, const char *cstr);
void rome2_l72_wostream_insert_wstr(rome2_l72_wstream *stream, const uint16_t *wstr, size_t wlen);
void rome2_l72_pref_write_line(const rome2_l72_pref_item *item, rome2_l72_wstream *stream);

typedef struct rome2_l72_prefs_env {
    void *user;
    uint8_t (*open_prefs_file)(void *user, const uint16_t *path_hint, uint8_t append, int32_t *out_errno);
    uint8_t (*write_prefs_bytes)(void *user, const uint8_t *bytes, size_t len, size_t *out_written);
    uint8_t (*stream_good)(void *user);
    int32_t (*close_prefs_file)(void *user);
    void (*log_line)(void *user, const char *line);
} rome2_l72_prefs_env;

/* 0x10104ac0 / 0x1168e944 */
uint8_t rome2_l72_open_write_wstr(
    const rome2_l72_prefs_env *env,
    const uint16_t *path_hint,
    uint8_t append,
    rome2_startup_crt_file_box8_32 *out_box);

/* 0x100dacb0: formats preference items and writes serialized UTF-16 bytes unless disabled. */
int32_t rome2_l72_write_preferences(
    const rome2_l72_prefs_env *env,
    const rome2_l72_pref_item *items,
    size_t item_count,
    rome2_l72_wstream *scratch_stream,
    const uint16_t *path_hint);

/* 0x116bd810: ___ascii_strnicmp */
int32_t rome2_l72_ascii_strnicmp(const char *lhs, const char *rhs, size_t max_count);

/* 0x116b326e / 0x116b327b: x87 control-word restore and math exit */
uint8_t rome2_l72_fpu_cw_restore_needed(uint16_t saved_cw);
uint8_t rome2_l72_math_exit(uint16_t saved_cw, uint16_t fpu_sw, uint8_t *out_raised_exc);

/* 0x116bd580 / 0x116bd59e: log10_pentium4 bounded model */
double rome2_l72_log10(double x, uint32_t *out_matherr_code);

/* 0x10fd964a / 0x116c09ae..0x116c0f9d / 0x116d7200..0x116d7310: PE/SEH validation & unwind */
uint32_t rome2_l72_seh_restore_chain(uint32_t saved_ebp_m0c);
uint8_t rome2_l72_validate_image_base(const uint8_t *image, size_t image_size);
const rome2_startup_pe_sec_hdr40_32 *rome2_l72_find_pe_section(
    const uint8_t *image,
    size_t image_size,
    uint32_t rva,
    rome2_startup_pe_sec_hdr40_32 *out_copy);
uint8_t rome2_l72_is_nonwritable_in_image(
    const uint8_t *image,
    size_t image_size,
    uint32_t base_va,
    uint32_t target_va);
uint8_t rome2_l72_validate_scope_table_handlers(
    const uint8_t *image,
    size_t image_size,
    uint32_t base_va,
    const rome2_startup_seh_scope12_32 *scopes,
    size_t scope_count,
    uint32_t try_level);

typedef struct rome2_l72_eh3_env {
    const uint8_t *image;
    size_t image_size;
    uint32_t image_base_va;
    uint32_t reg_va;
    uint32_t stack_low_va;
    uint32_t stack_high_va;
    uint32_t saved_ebp_va;
    uint32_t handler_rva;
    const rome2_startup_eh3_reg16_32 *reg;
    const rome2_startup_seh_scope12_32 *scopes;
    size_t scope_count;
    uint8_t region_writable_page;
} rome2_l72_eh3_env;

/* 0x116c0bf0: __ValidateEH3RN (returns 1 valid, 0 invalid, -1 non-image/mismatch) */
int32_t rome2_l72_validate_eh3_rn(const rome2_l72_eh3_env *env);

typedef struct rome2_l72_unwind_env {
    void *user;
    void (*nlg_notify)(void *user, const rome2_startup_nlg_dest16_32 *dest);
    void (*nlg_call)(void *user, uint32_t funclet_va, uint32_t cookie);
    void (*rtl_unwind)(void *user, uint32_t target_frame_va, uint32_t target_ip_va);
} rome2_l72_unwind_env;

/* 0x116c0a56 / 0x116c0b0c / 0x116c0b2b / 0x116c09f0 */
uint32_t rome2_l72_local_unwind2(
    const rome2_l72_unwind_env *env,
    const rome2_startup_seh_scope12_32 *scopes,
    size_t scope_count,
    uint32_t current_try_level,
    uint32_t stop_try_level,
    uint32_t frame_ebp_va,
    uint32_t cookie);
void rome2_l72_global_unwind2(const rome2_l72_unwind_env *env, uint32_t target_frame_va);

/* 0x116c09ae: _CallDestructExceptionObject */
uint8_t rome2_l72_call_destruct_exception_object(
    const uint8_t *image,
    size_t image_size,
    uint32_t base_va,
    uint32_t exc_code,
    uint32_t dtor_va,
    uint32_t dtor_slot_va,
    void (*guard_and_call)(void *user, uint32_t dtor_va),
    void *user);

#endif
