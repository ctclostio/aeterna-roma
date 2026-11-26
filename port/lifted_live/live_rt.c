/*
 * live_rt.c - the lifted runtime with real control transfers. See live.h.
 *
 * lift_rt.c is compiled unchanged; only the two entry points that stand in
 * for the outside world during a trial are replaced:
 *
 *   lift_leave      a trial records a call event and applies a stub; here the
 *                   transfer is real and goes back to the dispatch loop.
 *   lift_stub_insn  a trial writes seed-derived values; here CPUID, RDTSC,
 *                   RDTSCP and XGETBV execute on the host.
 *
 * Faults, exceptions, untranslated instructions and the instruction budget
 * keep lift_rt.c's behaviour and end the run (LIVE_JMP_STOP).
 */
#include "../lifted_runtime/lift_model.h"

/* A guest page is valid when the runner has mapped it (lift_ctx.pt), not
 * when the trial model's fixed image and arena ranges say so. */
static int live_access_fault(const lm_env *env, uint32_t addr, uint32_t len, uint32_t *fault_addr);

#define lm_access_fault live_access_fault
#define lift_leave lift_leave_trial
#define lift_stub_insn lift_stub_insn_trial
#include "../lifted_runtime/lift_rt.c"
#undef lm_access_fault
#undef lift_leave
#undef lift_stub_insn

static int live_access_fault(const lm_env *env, uint32_t addr, uint32_t len, uint32_t *fault_addr) {
    const lift_ctx *c = (const lift_ctx *)((const char *)env - offsetof(lift_ctx, env));
    uint32_t last = addr + (len - 1u);
    if (c->pt[addr >> 12] == NULL) {
        *fault_addr = addr;
        return 1;
    }
    if (((addr ^ last) >> 12) != 0u && c->pt[last >> 12] == NULL) {
        *fault_addr = last & ~(LM_PAGE - 1u);
        return 1;
    }
    return 0;
}

#include "live.h"

#include <intrin.h>

/* fnstcw word ptr [rcx]; ret */
LIFT_THUNK(live_fnstcw) = {0xd9, 0x39, 0xc3};

void lift_leave(lift_ctx *c) {
    /* longjmp reloads MXCSR and the x87 control word from the buffer; they
     * are the guest's and must survive the transfer. (It also executes
     * FNCLEX, so pending x87 exception flags do not survive a transfer.) */
    _JUMP_BUFFER *jb = (_JUMP_BUFFER *)c->jb;
    jb->MxCsr = _mm_getcsr();
    LIFT_TX(live_fnstcw)(&jb->FpCsr);
    longjmp(c->jb, LIVE_JMP_TRANSFER);
}

void lift_stub_insn(lift_ctx *c, uint32_t kind) {
    int r[4];
    uint64_t v;
    unsigned aux;
    switch (kind) {
    case LM_INSN_CPUID:
        __cpuidex(r, (int)c->r[LM_EAX], (int)c->r[LM_ECX]);
        c->r[LM_EAX] = (uint32_t)r[0];
        c->r[LM_EBX] = (uint32_t)r[1];
        c->r[LM_ECX] = (uint32_t)r[2];
        c->r[LM_EDX] = (uint32_t)r[3];
        break;
    case LM_INSN_RDTSC:
        v = __rdtsc();
        c->r[LM_EAX] = (uint32_t)v;
        c->r[LM_EDX] = (uint32_t)(v >> 32);
        break;
    case LM_INSN_RDTSCP:
        v = __rdtscp(&aux);
        c->r[LM_EAX] = (uint32_t)v;
        c->r[LM_EDX] = (uint32_t)(v >> 32);
        c->r[LM_ECX] = aux;
        break;
    case LM_INSN_XGETBV:
        v = _xgetbv(c->r[LM_ECX]);
        c->r[LM_EAX] = (uint32_t)v;
        c->r[LM_EDX] = (uint32_t)(v >> 32);
        break;
    default:
        lift_exc(c, LM_X_TRAP);
    }
}

const live_core *live_core_get(void) {
    static live_core core;
    uint32_t i = 0u, j = 0u, k = 0u;
    lift_fn_entry *fns;
    lift_thunk_desc *thunks;
    if (core.fns != NULL) {
        return &core;
    }
    /* Both function tables ascend by entry; the host-fault handler needs every thunk in one table. */
    core.n_fns = lift_batch_fn_count + live_extra_fn_count;
    core.n_thunks = lift_batch_thunk_count + live_extra_thunk_count;
    fns = malloc((size_t)(core.n_fns + 1u) * sizeof *fns);
    thunks = malloc((size_t)(core.n_thunks + 1u) * sizeof *thunks);
    if (fns == NULL || thunks == NULL) {
        fprintf(stderr, "live_rt: out of memory\n");
        exit(3);
    }
    while (i < lift_batch_fn_count || j < live_extra_fn_count) {
        if (j == live_extra_fn_count || (i < lift_batch_fn_count && lift_batch_fns[i].entry < live_extra_fns[j].entry)) {
            fns[k++] = lift_batch_fns[i++];
        } else {
            fns[k++] = live_extra_fns[j++];
        }
    }
    memcpy(thunks, lift_batch_thunks, (size_t)lift_batch_thunk_count * sizeof *thunks);
    memcpy(thunks + lift_batch_thunk_count, live_extra_thunks, (size_t)live_extra_thunk_count * sizeof *thunks);
    core.fns = fns;
    core.thunks = thunks;
    core.ranges = live_ranges;
    core.n_ranges = live_range_count;
    return &core;
}

void live_fp_enter(lift_ctx *c) {
    c->host_mxcsr = _mm_getcsr();
    _fxsave64(c->host_fx);
    memset(c->fx, 0, LM_FX_SIZE);
    lm_put16(c->fx + LM_FX_FCW, 0x027fu);
    lm_put32(c->fx + LM_FX_MXCSR, 0x1f80u);
    memset(c->xmm, 0, sizeof c->xmm);
    c->fx_valid = 0u;
    c->in_trial = 1u;
    _mm_setcsr(0x1f80u);
    x87_load(c->fx);
}
