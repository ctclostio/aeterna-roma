#include "vfs_fs_engine_crt_exit_ops.h"

#include <string.h>

static uint32_t l58_decode_ptr32(uint32_t enc, uint32_t cookie) {
    uint32_t val = enc ^ cookie;
    uint32_t shift = cookie & 0x1fu;
    if (shift == 0u) {
        return val;
    }
    return (val >> shift) | (val << (32u - shift));
}

static uint32_t l58_read_u16_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint32_t l58_read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t *l58_select_global_slot(rome2_vfs_l58_signal_env *env, int32_t signum) {
    if (!env) {
        return NULL;
    }
    switch (signum) {
    case 2:
        return &env->ctrlc_action_enc;
    case 21:
        return &env->ctrlbreak_action_enc;
    case 6:
    case 22:
        return &env->abort_action_enc;
    case 15:
        return &env->term_action_enc;
    default:
        return NULL;
    }
}

void rome2_vfs_crt_std_exception_copy_116bf74d(
    const rome2_vfs_crt_std_exception12_32 *from,
    const char *from_what,
    rome2_vfs_crt_std_exception12_32 *to,
    char *to_buf,
    size_t to_buf_cap,
    uint8_t alloc_ok,
    uint32_t alloc_what_va) {
    size_t len = 0u;
    if (!from || !to) {
        return;
    }
    if (from->do_free_08 == 0u || from->what_ptr_04 == 0u) {
        to->what_ptr_04 = from->what_ptr_04;
        to->do_free_08 = 0u;
        return;
    }
    if (!alloc_ok || alloc_what_va == 0u || !from_what || !to_buf || to_buf_cap == 0u) {
        return;
    }
    len = rome2_vfs_crt_strnlen_bounded(from_what, to_buf_cap - 1u);
    if (from_what[len] != '\0') {
        return;
    }
    memcpy(to_buf, from_what, len + 1u);
    to->what_ptr_04 = alloc_what_va;
    to->do_free_08 = 1u;
}

rome2_vfs_reg_status rome2_vfs_crt_std_exception_ctor_1168601c(
    rome2_vfs_crt_std_exception12_32 *self,
    uint32_t what_va,
    const char *what_str,
    char *copy_buf,
    size_t copy_buf_cap,
    uint8_t alloc_ok,
    uint32_t alloc_what_va) {
    rome2_vfs_crt_std_exception12_32 tmp;
    if (!self) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(&tmp, 0, sizeof(tmp));
    tmp.what_ptr_04 = what_va;
    tmp.do_free_08 = 1u;

    self->vtable_00 = ROME2_VFS_L58_STD_EXCEPTION_VT_VA;
    self->what_ptr_04 = 0u;
    self->do_free_08 = 0u;
    rome2_vfs_crt_std_exception_copy_116bf74d(&tmp, what_str, self, copy_buf, copy_buf_cap, alloc_ok, alloc_what_va);
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_crt_std_length_error_ctor_1168606c(
    rome2_vfs_crt_std_exception12_32 *self,
    uint32_t what_va,
    const char *what_str,
    char *copy_buf,
    size_t copy_buf_cap,
    uint8_t alloc_ok,
    uint32_t alloc_what_va) {
    rome2_vfs_reg_status st = rome2_vfs_crt_std_exception_ctor_1168601c(
        self, what_va, what_str, copy_buf, copy_buf_cap, alloc_ok, alloc_what_va);
    if (st == ROME2_VFS_REG_OK) {
        self->vtable_00 = ROME2_VFS_L58_STD_LENGTH_ERROR_VT_VA;
    }
    return st;
}

void rome2_vfs_crt_xlength_error_11686192(
    const char *msg,
    uint32_t msg_va,
    uint8_t alloc_ok,
    rome2_vfs_l58_throw_record *out_throw) {
    if (!out_throw) {
        return;
    }
    memset(out_throw, 0, sizeof(*out_throw));
    (void)rome2_vfs_crt_std_length_error_ctor_1168606c(
        &out_throw->exc,
        msg_va,
        msg,
        out_throw->what_copy,
        sizeof(out_throw->what_copy),
        alloc_ok,
        (alloc_ok && msg_va != 0u) ? 0x20001000u : 0u);
    out_throw->throw_info_va = ROME2_VFS_L58_LENGTH_ERROR_THROW_INFO_VA;
    out_throw->msg_va = msg_va;
    out_throw->thrown = 1u;
}

void rome2_vfs_vector_too_long_10120b20(
    uint8_t alloc_ok,
    rome2_vfs_l58_throw_record *out_throw) {
    rome2_vfs_crt_xlength_error_11686192(
        "vector<T> too long",
        ROME2_VFS_L58_VECTOR_TOO_LONG_VA,
        alloc_ok,
        out_throw);
}

void rome2_vfs_crt_invalid_parameter_noinfo_noreturn_116879f9(
    rome2_vfs_l58_watson_report *out_report) {
    if (!out_report) {
        return;
    }
    out_report->invparam_called = 1u;
    out_report->watson_invoked = 1u;
    out_report->watson_args_zero_count = 5u;
}

void rome2_vfs_crt_initterm_116a23ed(
    const rome2_vfs_l58_pvfv_fn *callbacks,
    size_t begin_idx,
    size_t end_idx,
    void *ctx,
    uint32_t *out_invoked) {
    size_t i = 0u;
    uint32_t count = 0u;
    if (out_invoked) {
        *out_invoked = 0u;
    }
    if (!callbacks || begin_idx >= end_idx) {
        return;
    }
    for (i = begin_idx; i < end_idx; ++i) {
        if (callbacks[i] != NULL) {
            callbacks[i](ctx);
            count += 1u;
        }
    }
    if (out_invoked) {
        *out_invoked = count;
    }
}

int32_t rome2_vfs_crt_execute_onexit_table_116a1a3e(
    rome2_vfs_l58_onexit_table_model *table,
    rome2_vfs_l58_onexit_entry_fn callback,
    void *ctx,
    uint32_t *out_calls,
    uint32_t *out_lock_cycles,
    uint8_t *out_step_limited) {
    uint32_t steps = 0u;
    uint32_t idx = 0u;
    uint32_t snap_count = 0u;

    if (out_calls) {
        *out_calls = 0u;
    }
    if (out_step_limited) {
        *out_step_limited = 0u;
    }
    if (out_lock_cycles) {
        *out_lock_cycles += 1u;
    }
    if (!table || !table->valid_table) {
        return -1;
    }
    if (table->is_sentinel_minus1 || table->count == 0u) {
        return 0;
    }
    if (table->count > ROME2_VFS_L58_MAX_ONEXIT_ENTRIES) {
        return -1;
    }

    snap_count = table->count;
    idx = table->count;
    while (idx > 0u) {
        uint32_t entry_enc = 0u;
        if (steps++ >= ROME2_VFS_L58_MAX_ONEXIT_STEPS) {
            if (out_step_limited) {
                *out_step_limited = 1u;
            }
            return -1;
        }
        --idx;
        entry_enc = table->slots[idx];
        if (entry_enc != table->cookie) {
            uint32_t entry_va = l58_decode_ptr32(entry_enc, table->cookie);
            table->slots[idx] = table->cookie;
            if (callback) {
                (void)callback(entry_va, table, ctx);
            }
            if (out_calls) {
                *out_calls += 1u;
            }
            if (table->count != snap_count) {
                if (table->count > ROME2_VFS_L58_MAX_ONEXIT_ENTRIES) {
                    return -1;
                }
                snap_count = table->count;
                idx = table->count;
            }
        }
    }

    if (!table->is_sentinel_minus1) {
        table->freed_backing = 1u;
    }
    table->count = 0u;
    table->is_sentinel_minus1 = 1u;
    return 0;
}

uint8_t rome2_vfs_crt_is_managed_app_1168d2ae(const uint8_t *image_hdr, size_t hdr_len) {
    uint32_t lfanew = 0u;
    uint32_t opt_off = 0u;
    if (!image_hdr || hdr_len < 0x40u) {
        return 0u;
    }
    if (l58_read_u16_le(image_hdr) != 0x5a4du) {
        return 0u;
    }
    lfanew = l58_read_u32_le(image_hdr + 0x3cu);
    if ((uint64_t)lfanew + 0x18u > (uint64_t)hdr_len) {
        return 0u;
    }
    if (l58_read_u32_le(image_hdr + lfanew) != 0x4550u) {
        return 0u;
    }
    opt_off = lfanew + 0x18u;
    if ((uint64_t)lfanew + 0xecu > (uint64_t)hdr_len) {
        return 0u;
    }
    if (l58_read_u16_le(image_hdr + opt_off) != 0x010bu) {
        return 0u;
    }
    if (l58_read_u32_le(image_hdr + lfanew + 0x74u) <= 0x0eu) {
        return 0u;
    }
    return (l58_read_u32_le(image_hdr + lfanew + 0xe8u) != 0u) ? 1u : 0u;
}

uint8_t rome2_vfs_crt_try_cor_exit_process_1168d2f1(
    uint8_t mscoree_loaded,
    uint8_t proc_resolved,
    int32_t exit_code,
    int32_t *out_cor_exit_code,
    uint8_t *out_freed_library) {
    uint8_t called = 0u;
    if (out_freed_library) {
        *out_freed_library = 0u;
    }
    if (!mscoree_loaded) {
        return 0u;
    }
    if (proc_resolved) {
        called = 1u;
        if (out_cor_exit_code) {
            *out_cor_exit_code = exit_code;
        }
    }
    if (out_freed_library) {
        *out_freed_library = 1u;
    }
    return called;
}

uint32_t rome2_vfs_crt_app_policy_termination_116a8555(
    uint8_t api_available,
    uint32_t resolved_policy,
    uint32_t *out_policy) {
    if (!api_available) {
        return ROME2_VFS_L58_STATUS_NOT_FOUND;
    }
    if (out_policy) {
        *out_policy = resolved_policy;
    }
    return 0u;
}

uint32_t rome2_vfs_crt_get_process_end_policy_116a8c48(
    int32_t proc_params_flags,
    uint8_t api_available,
    uint32_t resolved_policy) {
    uint32_t policy = 0u;
    if (proc_params_flags >= 0) {
        (void)rome2_vfs_crt_app_policy_termination_116a8555(api_available, resolved_policy, &policy);
        if (policy == 1u) {
            return 0u;
        }
    }
    return 1u;
}

void rome2_vfs_crt_common_exit_1168d208(
    int32_t return_code,
    uint32_t cleanup_mode,
    uint32_t return_mode,
    rome2_vfs_l58_exit_env *env) {
    uint8_t lock_2_done = 0u;
    if (!env) {
        return;
    }
    env->final_exit_code = return_code;
    if (return_mode == 0u && rome2_vfs_crt_is_managed_app_1168d2ae(env->module_hdr, env->module_hdr_len)) {
        uint8_t freed = 0u;
        env->cor_exit_attempted += 1u;
        (void)rome2_vfs_crt_try_cor_exit_process_1168d2f1(
            env->mscoree_loaded, env->cor_proc_resolved, return_code, &env->final_exit_code, &freed);
    }

    env->locks_acquired += 1u;
    if (env->exit_complete == 0u) {
        uint32_t onexit_calls = 0u;
        uint32_t onexit_locks = 0u;
        uint8_t limited = 0u;
        env->c_termination_done = 1u;
        env->locked_done_set = 1u;

        if (cleanup_mode == 0u) {
            if (env->pre_exit_encoded_va != env->cookie) {
                env->pre_exit_invoked += 1u;
            }
            (void)rome2_vfs_crt_execute_onexit_table_116a1a3e(
                &env->atexit_table, NULL, NULL, &onexit_calls, &onexit_locks, &limited);
            env->onexit_ran_from_va = ROME2_VFS_L58_ATEXIT_TABLE_VA;
            env->locks_acquired += onexit_locks;
            env->locks_released += onexit_locks;
            env->terminators_invoked += env->c_terminators_count;
        } else if (cleanup_mode == 1u) {
            (void)rome2_vfs_crt_execute_onexit_table_116a1a3e(
                &env->quick_exit_table, NULL, NULL, &onexit_calls, &onexit_locks, &limited);
            env->onexit_ran_from_va = ROME2_VFS_L58_QUICK_EXIT_TABLE_VA;
            env->locks_acquired += onexit_locks;
            env->locks_released += onexit_locks;
        }
        env->terminators_invoked += env->pre_terminators_count;
        if (return_mode == 0u) {
            env->exit_complete = 1u;
            lock_2_done = 1u;
            (void)lock_2_done;
        }
    }
    env->locks_released += 1u;

    if (return_mode != 0u) {
        return;
    }

    if (rome2_vfs_crt_get_process_end_policy_116a8c48(
            env->peb_proc_flags, env->app_policy_available, env->app_policy_method) != 1u &&
        ((env->peb_misc_flags >> 8) & 1u) == 0u) {
        env->terminated_via_terminate_process = 1u;
    }
    {
        uint8_t freed2 = 0u;
        (void)rome2_vfs_crt_try_cor_exit_process_1168d2f1(
            env->mscoree_loaded, env->cor_proc_resolved, return_code, &env->final_exit_code, &freed2);
    }
    env->terminated_via_exit_process = 1u;
}

void rome2_vfs_crt_exit_1168d362(
    int32_t return_code,
    rome2_vfs_l58_exit_env *env) {
    rome2_vfs_crt_common_exit_1168d208(return_code, 2u, 0u, env);
}

uint32_t rome2_vfs_crt_get_global_action_slot_116b045f(int32_t signum) {
    switch (signum) {
    case 2:
        return 0x121262d0u;
    case 21:
        return 0x121262d4u;
    case 6:
    case 22:
        return 0x121262d8u;
    case 15:
        return 0x121262dcu;
    default:
        return 0u;
    }
}

const rome2_vfs_crt_xcpt_action12_32 *rome2_vfs_crt_siglookup_116b04a1(
    int32_t signum,
    const rome2_vfs_crt_xcpt_action12_32 *table,
    uint32_t count) {
    uint32_t i = 0u;
    if (!table || count > ROME2_VFS_L58_XCPT_ACT_TAB_COUNT) {
        return NULL;
    }
    for (i = 0u; i < count; ++i) {
        if (table[i].sig_num_04 == signum) {
            return &table[i];
        }
    }
    return NULL;
}

uint32_t rome2_vfs_crt_get_sigabrt_handler_116b04c9(rome2_vfs_l58_signal_env *env) {
    uint32_t fn_va = 0u;
    if (!env) {
        return 0u;
    }
    env->lock3_acquires += 1u;
    fn_va = l58_decode_ptr32(env->abort_action_enc, env->cookie);
    env->lock3_releases += 1u;
    return fn_va;
}

int32_t *rome2_vfs_crt_fpecode_116b050e(rome2_vfs_l58_signal_env *env) {
    if (!env || !env->has_ptd) {
        return NULL;
    }
    return &env->ptd_tfpecode;
}

int32_t rome2_vfs_crt_raise_116b0517(
    int32_t signum,
    rome2_vfs_l58_signal_env *env) {
    uint8_t is_global = 0u;
    uint32_t *global_slot = NULL;
    rome2_vfs_crt_xcpt_action12_32 *ptd_slot = NULL;
    uint32_t saved_infoptrs = 0u;
    int32_t saved_fpecode = 0;
    uint32_t handler_va = 0u;
    uint8_t has_exc_sig = 0u;

    if (!env) {
        return -1;
    }
    if (signum == 8 || signum == 11 || signum == 4) {
        uint32_t i = 0u;
        if (!env->has_ptd) {
            return -1;
        }
        for (i = 0u; i < ROME2_VFS_L58_XCPT_ACT_TAB_COUNT; ++i) {
            if (env->xcpt_tab[i].sig_num_04 == signum) {
                ptd_slot = &env->xcpt_tab[i];
                break;
            }
        }
        if (!ptd_slot) {
            env->last_errno = ROME2_VFS_L58_EINVAL_MSVC;
            env->invparam_called = 1u;
            return -1;
        }
        handler_va = ptd_slot->action_ptr_08;
        is_global = 0u;
        has_exc_sig = 1u;
    } else if (signum == 2 || signum == 6 || signum == 15 || signum == 21 || signum == 22) {
        global_slot = l58_select_global_slot(env, signum);
        if (!global_slot) {
            env->last_errno = ROME2_VFS_L58_EINVAL_MSVC;
            env->invparam_called = 1u;
            return -1;
        }
        is_global = 1u;
        env->lock3_acquires += 1u;
        handler_va = l58_decode_ptr32(*global_slot, env->cookie);
    } else {
        env->last_errno = ROME2_VFS_L58_EINVAL_MSVC;
        env->invparam_called = 1u;
        return -1;
    }

    if (handler_va == ROME2_VFS_L58_SIG_IGN_VA) {
        if (is_global) {
            env->lock3_releases += 1u;
        }
        return 0;
    }
    if (handler_va == ROME2_VFS_L58_SIG_DFL_VA) {
        if (is_global) {
            env->lock3_releases += 1u;
        }
        env->exited_with_code3 = 1u;
        return 0;
    }

    if (has_exc_sig) {
        saved_infoptrs = env->ptd_tpxcptinfoptrs;
        env->ptd_tpxcptinfoptrs = 0u;
        if (signum == 8) {
            uint32_t j = 0u;
            saved_fpecode = env->ptd_tfpecode;
            env->ptd_tfpecode = (int32_t)ROME2_VFS_L58_FPE_EXPLICITGEN;
            for (j = ROME2_VFS_L58_FIRST_FPE_INDX;
                 j < ROME2_VFS_L58_FIRST_FPE_INDX + ROME2_VFS_L58_NUM_FPE && j < ROME2_VFS_L58_XCPT_ACT_TAB_COUNT;
                 ++j) {
                env->xcpt_tab[j].action_ptr_08 = ROME2_VFS_L58_SIG_DFL_VA;
            }
        } else {
            ptd_slot->action_ptr_08 = ROME2_VFS_L58_SIG_DFL_VA;
        }
    } else if (global_slot) {
        *global_slot = env->cookie;
    }

    if (is_global) {
        env->lock3_releases += 1u;
    }

    env->handler_invoked_va = handler_va;
    env->handler_arg0 = signum;
    env->handler_arg1 = (signum == 8 && env->has_ptd) ? env->ptd_tfpecode : 0;
    env->handler_saw_null_infoptrs = (env->ptd_tpxcptinfoptrs == 0u) ? 1u : 0u;
    env->handler_saw_fpecode = env->ptd_tfpecode;

    if (has_exc_sig) {
        env->ptd_tpxcptinfoptrs = saved_infoptrs;
        if (signum == 8) {
            env->ptd_tfpecode = saved_fpecode;
        }
    }
    return 0;
}

void rome2_vfs_crt_abort_1169b93d(rome2_vfs_l58_signal_env *env) {
    uint32_t handler_va = 0u;
    if (!env) {
        return;
    }
    handler_va = rome2_vfs_crt_get_sigabrt_handler_116b04c9(env);
    if (handler_va != 0u) {
        (void)rome2_vfs_crt_raise_116b0517(22, env);
    }
    if ((env->abort_behavior & ROME2_VFS_L58_ABORT_BEHAVIOR_CALL_REPORTFAULT) != 0u) {
        if (env->fastfail_feature_present != 0u) {
            env->fastfail_raised = 1u;
        }
        env->reportfault_called = 1u;
    }
    env->exited_with_code3 = 1u;
}
