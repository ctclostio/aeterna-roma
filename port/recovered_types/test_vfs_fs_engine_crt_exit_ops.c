#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_crt_exit_ops.h"

static unsigned int g_checks = 0u;

#define CHECK(cond)                                                               \
    do {                                                                          \
        if (!(cond)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
            return 1;                                                             \
        }                                                                         \
        g_checks++;                                                               \
    } while (0)

static uint32_t encode_ptr32(uint32_t ptr_va, uint32_t cookie) {
    return rome2_vfs_crt_encode_pointer32(ptr_va, cookie);
}

typedef struct initterm_log {
    uint32_t order[4];
    uint32_t count;
} initterm_log;

static void term_fn1(void *ctx) {
    initterm_log *log = (initterm_log *)ctx;
    log->order[log->count++] = 1u;
}

static void term_fn2(void *ctx) {
    initterm_log *log = (initterm_log *)ctx;
    log->order[log->count++] = 2u;
}

static int32_t onexit_reentrant_cb(
    uint32_t entry_va,
    rome2_vfs_l58_onexit_table_model *table,
    void *ctx) {
    initterm_log *log = (initterm_log *)ctx;
    log->order[log->count++] = entry_va;
    if (entry_va == 0x1002u && table->count < ROME2_VFS_L58_MAX_ONEXIT_ENTRIES) {
        table->slots[table->count++] = encode_ptr32(0x1003u, table->cookie);
    }
    return 0;
}

static int test_exceptions_and_watson(void) {
    rome2_vfs_crt_std_exception12_32 exc;
    rome2_vfs_crt_std_exception12_32 copy;
    char buf[64];
    rome2_vfs_l58_throw_record th;
    rome2_vfs_l58_watson_report wr;

    memset(&exc, 0, sizeof(exc));
    memset(&copy, 0, sizeof(copy));
    memset(buf, 0, sizeof(buf));
    CHECK(rome2_vfs_crt_std_exception_ctor_1168601c(NULL, 0u, NULL, NULL, 0u, 0u, 0u) == ROME2_VFS_REG_BAD_ARGUMENT);
    CHECK(rome2_vfs_crt_std_exception_ctor_1168601c(&exc, 0x11740000u, "oom", buf, sizeof(buf), 1u, 0x20000100u) == ROME2_VFS_REG_OK);
    CHECK(exc.vtable_00 == ROME2_VFS_L58_STD_EXCEPTION_VT_VA);
    CHECK(exc.what_ptr_04 == 0x20000100u);
    CHECK(exc.do_free_08 == 1u);
    CHECK(strcmp(buf, "oom") == 0);

    /* OOM or oversized message leaves destination untouched when do_free != 0 */
    copy.what_ptr_04 = 0xaaaaaaaau;
    copy.do_free_08 = 0u;
    rome2_vfs_crt_std_exception_copy_116bf74d(&exc, buf, &copy, buf, sizeof(buf), 0u, 0u);
    CHECK(copy.what_ptr_04 == 0xaaaaaaaau);
    rome2_vfs_crt_std_exception_copy_116bf74d(&exc, "too_long_str", &copy, buf, 4u, 1u, 0x20000300u);
    CHECK(copy.what_ptr_04 == 0xaaaaaaaau);

    /* Static non-owned copy resets do_free to 0 */
    exc.do_free_08 = 0u;
    exc.what_ptr_04 = 0x11745c68u;
    rome2_vfs_crt_std_exception_copy_116bf74d(&exc, NULL, &copy, NULL, 0u, 0u, 0u);
    CHECK(copy.what_ptr_04 == 0x11745c68u);
    CHECK(copy.do_free_08 == 0u);

    /* length_error + _Xlength_error + 0x10120b20 */
    CHECK(rome2_vfs_crt_std_length_error_ctor_1168606c(&exc, 0x11745c68u, "vector<T> too long", buf, sizeof(buf), 1u, 0x20000200u) == ROME2_VFS_REG_OK);
    CHECK(exc.vtable_00 == ROME2_VFS_L58_STD_LENGTH_ERROR_VT_VA);

    rome2_vfs_vector_too_long_10120b20(1u, &th);
    CHECK(th.thrown == 1u);
    CHECK(th.throw_info_va == ROME2_VFS_L58_LENGTH_ERROR_THROW_INFO_VA);
    CHECK(th.exc.vtable_00 == ROME2_VFS_L58_STD_LENGTH_ERROR_VT_VA);
    CHECK(th.msg_va == ROME2_VFS_L58_VECTOR_TOO_LONG_VA);
    CHECK(strcmp(th.what_copy, "vector<T> too long") == 0);

    memset(&wr, 0, sizeof(wr));
    rome2_vfs_crt_invalid_parameter_noinfo_noreturn_116879f9(&wr);
    CHECK(wr.invparam_called == 1u);
    CHECK(wr.watson_invoked == 1u);
    CHECK(wr.watson_args_zero_count == 5u);
    return 0;
}

static int32_t self_reappend_cb(
    uint32_t entry_va,
    rome2_vfs_l58_onexit_table_model *table,
    void *ctx) {
    (void)ctx;
    (void)entry_va;
    /* Simulate compacted re-registration changing table count (1 <-> 2) so step guard trips. */
    table->count = (table->count == 1u) ? 2u : 1u;
    table->slots[table->count - 1u] = encode_ptr32(0x1004u, table->cookie);
    return 0;
}

static int test_initterm_and_onexit_table(void) {
    initterm_log ilog = { {0}, 0u };
    const rome2_vfs_l58_pvfv_fn cbs[4] = { NULL, term_fn1, NULL, term_fn2 };
    uint32_t invoked = 0u;
    rome2_vfs_l58_onexit_table_model tab;
    uint32_t calls = 0u;
    uint32_t locks = 0u;
    uint8_t limited = 0u;
    const uint32_t cookie = 0xbb40e64eu;

    rome2_vfs_crt_initterm_116a23ed(cbs, 2u, 2u, &ilog, &invoked);
    CHECK(invoked == 0u);
    rome2_vfs_crt_initterm_116a23ed(cbs, 0u, 4u, &ilog, &invoked);
    CHECK(invoked == 2u);
    CHECK(ilog.count == 2u && ilog.order[0] == 1u && ilog.order[1] == 2u);

    memset(&tab, 0, sizeof(tab));
    tab.cookie = cookie;
    tab.valid_table = 0u;
    CHECK(rome2_vfs_crt_execute_onexit_table_116a1a3e(&tab, onexit_reentrant_cb, &ilog, &calls, &locks, &limited) == -1);
    CHECK(locks == 1u);

    tab.valid_table = 1u;
    tab.is_sentinel_minus1 = 1u;
    CHECK(rome2_vfs_crt_execute_onexit_table_116a1a3e(&tab, onexit_reentrant_cb, &ilog, &calls, &locks, &limited) == 0);
    CHECK(calls == 0u);

    memset(&ilog, 0, sizeof(ilog));
    tab.is_sentinel_minus1 = 0u;
    tab.count = 2u;
    tab.slots[0] = encode_ptr32(0x1001u, cookie);
    tab.slots[1] = encode_ptr32(0x1002u, cookie);
    CHECK(rome2_vfs_crt_execute_onexit_table_116a1a3e(&tab, onexit_reentrant_cb, &ilog, &calls, &locks, &limited) == 0);
    /* LIFO: 0x1002 registers 0x1003, which runs before 0x1001 */
    CHECK(calls == 3u);
    CHECK(ilog.order[0] == 0x1002u);
    CHECK(ilog.order[1] == 0x1003u);
    CHECK(ilog.order[2] == 0x1001u);
    CHECK(tab.freed_backing == 1u);
    CHECK(tab.is_sentinel_minus1 == 1u);
    CHECK(tab.count == 0u);
    CHECK(limited == 0u);

    /* Step limit prevents runaway self-reappend */
    memset(&tab, 0, sizeof(tab));
    tab.cookie = cookie;
    tab.valid_table = 1u;
    tab.count = 1u;
    tab.slots[0] = encode_ptr32(0x1004u, cookie);
    CHECK(rome2_vfs_crt_execute_onexit_table_116a1a3e(&tab, self_reappend_cb, NULL, &calls, &locks, &limited) == -1);
    CHECK(limited == 1u);
    return 0;
}

static int test_managed_policy_and_common_exit(void) {
    uint8_t pe_hdr[0x140];
    uint32_t policy = 99u;
    int32_t cor_code = 0;
    uint8_t freed = 0u;
    rome2_vfs_l58_exit_env env;

    memset(pe_hdr, 0, sizeof(pe_hdr));
    pe_hdr[0] = 'M'; pe_hdr[1] = 'Z';
    pe_hdr[0x3c] = 0x40u; /* e_lfanew */
    pe_hdr[0x40] = 'P'; pe_hdr[0x41] = 'E';
    pe_hdr[0x58] = 0x0bu; pe_hdr[0x59] = 0x01u; /* PE32 0x10b */
    pe_hdr[0xb4] = 0x10u; /* NumberOfRvaAndSizes = 16 > 14 */
    CHECK(rome2_vfs_crt_is_managed_app_1168d2ae(pe_hdr, sizeof(pe_hdr)) == 0u);
    pe_hdr[0x128] = 0x10u; /* e_lfanew + 0xe8 CLR COMDescriptor RVA != 0 */
    CHECK(rome2_vfs_crt_is_managed_app_1168d2ae(pe_hdr, sizeof(pe_hdr)) == 1u);
    CHECK(rome2_vfs_crt_is_managed_app_1168d2ae(pe_hdr, 0x30u) == 0u);
    pe_hdr[0x59] = 0x02u; /* PE32+ 0x20b rejected by 32-bit check */
    CHECK(rome2_vfs_crt_is_managed_app_1168d2ae(pe_hdr, sizeof(pe_hdr)) == 0u);
    pe_hdr[0x59] = 0x01u;

    CHECK(rome2_vfs_crt_try_cor_exit_process_1168d2f1(1u, 1u, 77, &cor_code, &freed) == 1u);
    CHECK(cor_code == 77);
    CHECK(freed == 1u);
    CHECK(rome2_vfs_crt_try_cor_exit_process_1168d2f1(1u, 0u, 88, &cor_code, &freed) == 0u);
    CHECK(freed == 1u);
    CHECK(rome2_vfs_crt_try_cor_exit_process_1168d2f1(0u, 1u, 77, &cor_code, &freed) == 0u);
    CHECK(freed == 0u);

    CHECK(rome2_vfs_crt_app_policy_termination_116a8555(0u, 1u, &policy) == ROME2_VFS_L58_STATUS_NOT_FOUND);
    CHECK(rome2_vfs_crt_app_policy_termination_116a8555(1u, 1u, &policy) == 0u);
    CHECK(policy == 1u);
    CHECK(rome2_vfs_crt_get_process_end_policy_116a8c48(0, 1u, 1u) == 0u);
    CHECK(rome2_vfs_crt_get_process_end_policy_116a8c48(-1, 1u, 1u) == 1u);

    /* common_exit return_mode=1 (c_exit): does NOT terminate, keeps exit_complete=0 */
    memset(&env, 0, sizeof(env));
    env.cookie = 0xbb40e64eu;
    env.pre_exit_encoded_va = encode_ptr32(0x10001234u, env.cookie);
    env.atexit_table.cookie = env.cookie;
    env.atexit_table.valid_table = 1u;
    env.atexit_table.is_sentinel_minus1 = 1u;
    env.quick_exit_table = env.atexit_table;
    env.c_terminators_count = 3u;
    env.pre_terminators_count = 2u;

    rome2_vfs_crt_common_exit_1168d208(5, 0u, 1u, &env);
    CHECK(env.locked_done_set == 1u);
    CHECK(env.pre_exit_invoked == 1u);
    CHECK(env.terminators_invoked == 5u);
    CHECK(env.onexit_ran_from_va == ROME2_VFS_L58_ATEXIT_TABLE_VA);
    CHECK(env.exit_complete == 0u);
    CHECK(env.terminated_via_exit_process == 0u);
    CHECK(env.locks_acquired == env.locks_released && env.locks_acquired == 2u);

    /* cleanup_mode=1 runs quick_exit_table + pre_terminators_count only */
    env.terminators_invoked = 0u;
    rome2_vfs_crt_common_exit_1168d208(6, 1u, 1u, &env);
    CHECK(env.onexit_ran_from_va == ROME2_VFS_L58_QUICK_EXIT_TABLE_VA);
    CHECK(env.terminators_invoked == 2u);

    /* __exit(3): quick mode cleanup=2 return_mode=0 with managed CLR + TerminateProcess */
    env.module_hdr = pe_hdr;
    env.module_hdr_len = sizeof(pe_hdr);
    env.mscoree_loaded = 1u;
    env.cor_proc_resolved = 1u;
    env.app_policy_available = 1u;
    env.app_policy_method = 1u;
    rome2_vfs_crt_exit_1168d362(3, &env);
    CHECK(env.exit_complete == 1u);
    CHECK(env.cor_exit_attempted == 1u);
    CHECK(env.terminated_via_terminate_process == 1u);
    CHECK(env.terminated_via_exit_process == 1u);
    CHECK(env.final_exit_code == 3);
    return 0;
}

static int test_signals_raise_and_abort(void) {
    rome2_vfs_l58_signal_env senv;
    const uint32_t cookie = 0xbb40e64eu;
    int32_t *fpe_ptr = NULL;

    CHECK(rome2_vfs_crt_get_global_action_slot_116b045f(2) == 0x121262d0u);
    CHECK(rome2_vfs_crt_get_global_action_slot_116b045f(15) == 0x121262dcu);
    CHECK(rome2_vfs_crt_get_global_action_slot_116b045f(21) == 0x121262d4u);
    CHECK(rome2_vfs_crt_get_global_action_slot_116b045f(22) == 0x121262d8u);
    CHECK(rome2_vfs_crt_get_global_action_slot_116b045f(99) == 0u);

    memset(&senv, 0, sizeof(senv));
    senv.cookie = cookie;
    senv.has_ptd = 1u;
    senv.ptd_tpxcptinfoptrs = 0x55551111u;
    senv.ptd_tfpecode = 123;
    senv.ctrlc_action_enc = encode_ptr32(ROME2_VFS_L58_SIG_IGN_VA, cookie);
    senv.term_action_enc = cookie; /* encoded SIG_DFL */
    senv.abort_action_enc = encode_ptr32(0x10109999u, cookie);
    senv.xcpt_tab[0] = (rome2_vfs_crt_xcpt_action12_32){ 0xc0000005u, 11, 0x10205555u };
    senv.xcpt_tab[3] = (rome2_vfs_crt_xcpt_action12_32){ 0xc000008eu, 8, 0x10203040u };
    senv.xcpt_tab[4] = (rome2_vfs_crt_xcpt_action12_32){ 0xc0000090u, 8, 0x11112222u };

    CHECK(rome2_vfs_crt_siglookup_116b04a1(8, senv.xcpt_tab, ROME2_VFS_L58_XCPT_ACT_TAB_COUNT) == &senv.xcpt_tab[3]);
    CHECK(rome2_vfs_crt_siglookup_116b04a1(99, senv.xcpt_tab, ROME2_VFS_L58_XCPT_ACT_TAB_COUNT) == NULL);
    CHECK(rome2_vfs_crt_siglookup_116b04a1(8, senv.xcpt_tab, 99u) == NULL);

    fpe_ptr = rome2_vfs_crt_fpecode_116b050e(&senv);
    CHECK(fpe_ptr == &senv.ptd_tfpecode);
    CHECK(*fpe_ptr == 123);

    /* SIGINT (2) with SIG_IGN */
    CHECK(rome2_vfs_crt_raise_116b0517(2, &senv) == 0);
    CHECK(senv.handler_invoked_va == 0u);
    CHECK(senv.lock3_acquires == senv.lock3_releases);

    /* SIGTERM (15) with SIG_DFL triggers exit(3) */
    CHECK(rome2_vfs_crt_raise_116b0517(15, &senv) == 0);
    CHECK(senv.exited_with_code3 == 1u);
    senv.exited_with_code3 = 0u;

    /* Invalid signum sets errno=0x16 and flags invalid_parameter */
    CHECK(rome2_vfs_crt_raise_116b0517(999, &senv) == -1);
    CHECK(senv.last_errno == ROME2_VFS_L58_EINVAL_MSVC);
    CHECK(senv.invparam_called == 1u);

    /* SIGFPE (8) resets [3..11] action_ptr, sets tfpecode=0x8c & tpxcptinfoptrs=0 during handler, then restores */
    CHECK(rome2_vfs_crt_raise_116b0517(8, &senv) == 0);
    CHECK(senv.handler_invoked_va == 0x10203040u);
    CHECK(senv.handler_arg0 == 8);
    CHECK(senv.handler_arg1 == (int32_t)0x8cu);
    CHECK(senv.handler_saw_null_infoptrs == 1u);
    CHECK(senv.handler_saw_fpecode == (int32_t)0x8cu);
    CHECK(senv.ptd_tpxcptinfoptrs == 0x55551111u);
    CHECK(senv.ptd_tfpecode == 123);
    CHECK(senv.xcpt_tab[3].action_ptr_08 == 0u);
    CHECK(senv.xcpt_tab[4].action_ptr_08 == 0u);
    CHECK(senv.xcpt_tab[0].action_ptr_08 == 0x10205555u);

    /* SIGSEGV (11) clears only its PTD entry and preserves tpxcptinfoptrs */
    CHECK(rome2_vfs_crt_raise_116b0517(11, &senv) == 0);
    CHECK(senv.handler_invoked_va == 0x10205555u);
    CHECK(senv.handler_arg0 == 11);
    CHECK(senv.xcpt_tab[0].action_ptr_08 == 0u);
    CHECK(senv.ptd_tpxcptinfoptrs == 0x55551111u);

    /* abort() calls SIGABRT handler, clears abort_action to SIG_DFL (cookie), runs __fastfail + reportfault + exit(3) */
    senv.abort_behavior = ROME2_VFS_L58_ABORT_BEHAVIOR_CALL_REPORTFAULT;
    senv.fastfail_feature_present = 1u;
    rome2_vfs_crt_abort_1169b93d(&senv);
    CHECK(senv.handler_invoked_va == 0x10109999u);
    CHECK(senv.handler_arg0 == 22);
    CHECK(senv.abort_action_enc == cookie);
    CHECK(rome2_vfs_crt_get_sigabrt_handler_116b04c9(&senv) == 0u);
    CHECK(senv.fastfail_raised == 1u);
    CHECK(senv.reportfault_called == 1u);
    CHECK(senv.exited_with_code3 == 1u);
    return 0;
}

int main(void) {
    if (test_exceptions_and_watson() != 0 ||
        test_initterm_and_onexit_table() != 0 ||
        test_managed_policy_and_common_exit() != 0 ||
        test_signals_raise_and_abort() != 0) {
        return 1;
    }
    printf("test_vfs_fs_engine_crt_exit_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
