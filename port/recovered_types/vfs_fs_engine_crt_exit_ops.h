#ifndef ROME2_VFS_FS_ENGINE_CRT_EXIT_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_EXIT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_crt_env_ops.h"
#include "vfs_fs_engine_crt_mbcp_ops.h"
#include "vfs_fs_engine_crt_sec_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L58_STD_EXCEPTION_VT_VA 0x1190bbd0u
#define ROME2_VFS_L58_STD_LENGTH_ERROR_VT_VA 0x1190bbf4u
#define ROME2_VFS_L58_LENGTH_ERROR_THROW_INFO_VA 0x11925254u
#define ROME2_VFS_L58_VECTOR_TOO_LONG_VA 0x11745c68u
#define ROME2_VFS_L58_XT_A_VA 0x1173945cu
#define ROME2_VFS_L58_XT_Z_VA 0x11739470u
#define ROME2_VFS_L58_XP_A_VA 0x11739474u
#define ROME2_VFS_L58_XP_Z_VA 0x11739478u
#define ROME2_VFS_L58_ATEXIT_TABLE_VA 0x12125d90u
#define ROME2_VFS_L58_QUICK_EXIT_TABLE_VA 0x12125d9cu
#define ROME2_VFS_L58_ABORT_BEHAVIOR_CALL_REPORTFAULT 0x02u
#define ROME2_VFS_L58_STATUS_NOT_FOUND 0xc0000225u
#define ROME2_VFS_L58_SIG_DFL_VA 0u
#define ROME2_VFS_L58_SIG_IGN_VA 1u
#define ROME2_VFS_L58_FPE_EXPLICITGEN 0x8cu
#define ROME2_VFS_L58_XCPT_ACT_TAB_COUNT 12u
#define ROME2_VFS_L58_FIRST_FPE_INDX 3u
#define ROME2_VFS_L58_NUM_FPE 9u
#define ROME2_VFS_L58_EINVAL_MSVC 0x16
#define ROME2_VFS_L58_MAX_ONEXIT_ENTRIES 32u
#define ROME2_VFS_L58_MAX_ONEXIT_STEPS 64u

/* `0x116bf74d`, `0x1168601c`, `0x1168606c`, `0x11686192`, `0x10120b20`: exception & throw helpers. */
typedef struct rome2_vfs_l58_throw_record {
    uint8_t thrown;
    rome2_vfs_crt_std_exception12_32 exc;
    uint32_t throw_info_va;
    uint32_t msg_va;
    char what_copy[64];
} rome2_vfs_l58_throw_record;

void rome2_vfs_crt_std_exception_copy_116bf74d(
    const rome2_vfs_crt_std_exception12_32 *from,
    const char *from_what,
    rome2_vfs_crt_std_exception12_32 *to,
    char *to_buf,
    size_t to_buf_cap,
    uint8_t alloc_ok,
    uint32_t alloc_what_va);

rome2_vfs_reg_status rome2_vfs_crt_std_exception_ctor_1168601c(
    rome2_vfs_crt_std_exception12_32 *self,
    uint32_t what_va,
    const char *what_str,
    char *copy_buf,
    size_t copy_buf_cap,
    uint8_t alloc_ok,
    uint32_t alloc_what_va);

rome2_vfs_reg_status rome2_vfs_crt_std_length_error_ctor_1168606c(
    rome2_vfs_crt_std_exception12_32 *self,
    uint32_t what_va,
    const char *what_str,
    char *copy_buf,
    size_t copy_buf_cap,
    uint8_t alloc_ok,
    uint32_t alloc_what_va);

void rome2_vfs_crt_xlength_error_11686192(
    const char *msg,
    uint32_t msg_va,
    uint8_t alloc_ok,
    rome2_vfs_l58_throw_record *out_throw);

void rome2_vfs_vector_too_long_10120b20(
    uint8_t alloc_ok,
    rome2_vfs_l58_throw_record *out_throw);

/* `0x116879f9`: _invalid_parameter_noinfo_noreturn calling _invalid_parameter_noinfo + __invoke_watson. */
typedef struct rome2_vfs_l58_watson_report {
    uint8_t invparam_called;
    uint8_t watson_invoked;
    uint32_t watson_args_zero_count;
} rome2_vfs_l58_watson_report;

void rome2_vfs_crt_invalid_parameter_noinfo_noreturn_116879f9(
    rome2_vfs_l58_watson_report *out_report);

/* `0x116a23ed`, `0x116a176f`, `0x116a17be`, `0x116a194e`, `0x116a1a3e`: __initterm & __execute_onexit_table. */
typedef struct rome2_vfs_l58_onexit_table_model {
    uint32_t cookie;
    uint8_t valid_table;
    uint32_t slots[ROME2_VFS_L58_MAX_ONEXIT_ENTRIES];
    uint32_t count;
    uint32_t cap;
    uint8_t freed_backing;
    uint8_t is_sentinel_minus1;
} rome2_vfs_l58_onexit_table_model;

typedef void (*rome2_vfs_l58_pvfv_fn)(void *ctx);

void rome2_vfs_crt_initterm_116a23ed(
    const rome2_vfs_l58_pvfv_fn *callbacks,
    size_t begin_idx,
    size_t end_idx,
    void *ctx,
    uint32_t *out_invoked);

typedef int32_t (*rome2_vfs_l58_onexit_entry_fn)(
    uint32_t entry_va,
    rome2_vfs_l58_onexit_table_model *table,
    void *ctx);

int32_t rome2_vfs_crt_execute_onexit_table_116a1a3e(
    rome2_vfs_l58_onexit_table_model *table,
    rome2_vfs_l58_onexit_entry_fn callback,
    void *ctx,
    uint32_t *out_calls,
    uint32_t *out_lock_cycles,
    uint8_t *out_step_limited);

/* `0x1168d2ae`, `0x1168d2f1`, `0x116a8555`, `0x116a8c48`, `0x1168d0ce..0x1168d362`: exit & managed checks. */
uint8_t rome2_vfs_crt_is_managed_app_1168d2ae(const uint8_t *image_hdr, size_t hdr_len);

uint8_t rome2_vfs_crt_try_cor_exit_process_1168d2f1(
    uint8_t mscoree_loaded,
    uint8_t proc_resolved,
    int32_t exit_code,
    int32_t *out_cor_exit_code,
    uint8_t *out_freed_library);

uint32_t rome2_vfs_crt_app_policy_termination_116a8555(
    uint8_t api_available,
    uint32_t resolved_policy,
    uint32_t *out_policy);

uint32_t rome2_vfs_crt_get_process_end_policy_116a8c48(
    int32_t proc_params_flags,
    uint8_t api_available,
    uint32_t resolved_policy);

typedef struct rome2_vfs_l58_exit_env {
    const uint8_t *module_hdr;
    size_t module_hdr_len;
    uint8_t mscoree_loaded;
    uint8_t cor_proc_resolved;
    int32_t peb_proc_flags;
    uint32_t peb_misc_flags;
    uint8_t app_policy_available;
    uint32_t app_policy_method;
    uint32_t cookie;
    uint8_t exit_complete;
    uint32_t c_termination_done;
    uint32_t pre_exit_encoded_va;
    rome2_vfs_l58_onexit_table_model atexit_table;
    rome2_vfs_l58_onexit_table_model quick_exit_table;
    uint32_t c_terminators_count;
    uint32_t pre_terminators_count;
    /* Observed trace outputs */
    uint8_t locked_done_set;
    uint32_t locks_acquired;
    uint32_t locks_released;
    uint32_t pre_exit_invoked;
    uint32_t onexit_ran_from_va;
    uint32_t terminators_invoked;
    uint8_t cor_exit_attempted;
    uint8_t terminated_via_terminate_process;
    uint8_t terminated_via_exit_process;
    int32_t final_exit_code;
} rome2_vfs_l58_exit_env;

void rome2_vfs_crt_common_exit_1168d208(
    int32_t return_code,
    uint32_t cleanup_mode,
    uint32_t return_mode,
    rome2_vfs_l58_exit_env *env);

void rome2_vfs_crt_exit_1168d362(
    int32_t return_code,
    rome2_vfs_l58_exit_env *env);

/* `0x116b03fb..0x116b06aa` & `0x1169b93d`: CRT global/PTD signal lookup, raise & abort. */
typedef struct rome2_vfs_l58_signal_env {
    uint32_t cookie;
    uint32_t ctrlc_action_enc;
    uint32_t ctrlbreak_action_enc;
    uint32_t abort_action_enc;
    uint32_t term_action_enc;
    uint8_t has_ptd;
    uint32_t ptd_tpxcptinfoptrs;
    int32_t ptd_tfpecode;
    rome2_vfs_crt_xcpt_action12_32 xcpt_tab[ROME2_VFS_L58_XCPT_ACT_TAB_COUNT];
    uint32_t abort_behavior;
    uint8_t fastfail_feature_present;
    /* Callbacks & trace */
    int32_t last_errno;
    uint8_t invparam_called;
    uint32_t lock3_acquires;
    uint32_t lock3_releases;
    uint32_t handler_invoked_va;
    int32_t handler_arg0;
    int32_t handler_arg1;
    uint8_t handler_saw_null_infoptrs;
    int32_t handler_saw_fpecode;
    uint8_t fastfail_raised;
    uint8_t reportfault_called;
    uint8_t exited_with_code3;
} rome2_vfs_l58_signal_env;

uint32_t rome2_vfs_crt_get_global_action_slot_116b045f(int32_t signum);

const rome2_vfs_crt_xcpt_action12_32 *rome2_vfs_crt_siglookup_116b04a1(
    int32_t signum,
    const rome2_vfs_crt_xcpt_action12_32 *table,
    uint32_t count);

uint32_t rome2_vfs_crt_get_sigabrt_handler_116b04c9(rome2_vfs_l58_signal_env *env);

int32_t *rome2_vfs_crt_fpecode_116b050e(rome2_vfs_l58_signal_env *env);

int32_t rome2_vfs_crt_raise_116b0517(
    int32_t signum,
    rome2_vfs_l58_signal_env *env);

void rome2_vfs_crt_abort_1169b93d(rome2_vfs_l58_signal_env *env);

#ifdef __cplusplus
}
#endif

#endif
