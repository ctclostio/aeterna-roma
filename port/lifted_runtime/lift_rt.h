/*
 * lift_rt.h - runtime for mechanically lifted functions (64-bit host).
 *
 * A generated batch defines one `void lifted_<entry>(lift_ctx *c)` per
 * function plus the byte thunks its x87/SIMD instructions execute, and is
 * linked with lift_rt.c and lift_main.c. Everything a generated function
 * touches is declared here; the trial protocol is in docs/lifted_tier.md and
 * the shared model in lift_model.h.
 *
 * A trial never returns from the lifted function: every way out (leaving the
 * body, a fault, an exception, the step budget) records the terminal and
 * unwinds with longjmp, so helpers can fault from any depth and the generated
 * code needs no error checks.
 */
#ifndef ROME2_LIFT_RT_H
#define ROME2_LIFT_RT_H

#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "lift_model.h"

#define LIFT_NORETURN __declspec(noreturn)

/* Offsets the byte thunks address through the context pointer. */
#define LIFT_OFF_R 0x00
#define LIFT_OFF_XMM 0x40
#define LIFT_OFF_SAVE_XMM 0xc0
#define LIFT_OFF_SAVE_GPR 0xe0

/* Safety budgets; a trial that exceeds one ends with LM_S_BUDGET. The page and
 * event limits are far beyond what the reference can serve within its
 * wall-clock limit (every first touch of a page and every call is a debug
 * event there), so they only cut trials the reference times out on. */
#define LIFT_FAST_BUDGET 50000000ull /* instructions in fast mode */
#define LIFT_MAX_PAGES 8192u         /* guest pages one trial may materialise */
#define LIFT_MAX_EVENTS 250000u      /* call events and stubbed instructions in one trial */

typedef struct lift_range {
    uint32_t lo, hi; /* hi exclusive */
} lift_range;

typedef struct lift_callsite {
    uint32_t ret;       /* return address of a call instruction in the body */
    uint32_t pop_bytes; /* stack bytes the stubbed callee removes */
    uint32_t fp_ret;    /* stub leaves a value in ST(0) */
} lift_callsite;

/* Thunk descriptor: what the host-fault handler must restore when an
 * exception is raised inside the thunk. */
#define LIFT_TF_XMM 0x01u /* host xmm6/xmm7 are in save_xmm */
#define LIFT_TF_RBX 0x02u /* host rbx/rbp/rsi/rdi are in save_gpr[0..3] */
#define LIFT_TF_RBP 0x04u
#define LIFT_TF_RSI 0x08u
#define LIFT_TF_RDI 0x10u

typedef struct lift_thunk_desc {
    const unsigned char *code;
    uint32_t size;
    uint32_t flags;
} lift_thunk_desc;

typedef struct lift_ctx lift_ctx;
typedef void (*lift_fn)(lift_ctx *c);

typedef struct lift_fn_entry {
    uint32_t entry;
    lift_fn fn;
    uint32_t n_insn;
} lift_fn_entry;

/* What a generated batch exports. */
extern const lift_fn_entry lift_batch_fns[];
extern const uint32_t lift_batch_fn_count;
extern const lift_thunk_desc lift_batch_thunks[];
extern const uint32_t lift_batch_thunk_count;

#pragma warning(push)
#pragma warning(disable : 4324) /* jmp_buf is 16-byte aligned; the padding before it is intended */
struct lift_ctx {
    /* ---- guest CPU state; the first 0x100 bytes are addressed by thunks ---- */
    uint32_t r[LM_GPR_COUNT];           /* 0x00 general registers, x86 encoding order */
    uint32_t eip;                       /* 0x20 address of the instruction being executed */
    uint8_t cf, pf, af, zf, sf, of, df; /* 0x24 each flag is 0 or 1 */
    uint8_t in_trial;                   /* 0x2b */
    uint32_t seed;                      /* 0x2c */
    uint32_t stub_n;                    /* 0x30 stub events so far (calls and stubbed instructions) */
    uint32_t mode;                      /* 0x34 0 = fast, 1 = step */
    uint32_t eflags_other;              /* 0x38 EFLAGS bits outside the seven modelled flags */
    uint32_t bounce_len;                /* 0x3c nonzero while a thunk operand lives in the bounce buffer */
    uint8_t xmm[8][16];                 /* 0x40 guest XMM0..7 (the context is 64-byte aligned) */
    uint8_t save_xmm[2][16];            /* 0xc0 host xmm6, xmm7 while a SIMD thunk runs */
    uint64_t save_gpr[4];               /* 0xe0 host rbx, rbp, rsi, rdi while a SIMD thunk runs */

    /* ---- accounting ---- */
    uint64_t steps;  /* 0x100 instructions started; a faulting instruction is un-counted on exit */
    uint64_t budget; /* step count at which LIFT_I calls lift_step_limit */
    uint64_t limit;  /* step budget (step mode) or safety budget (fast mode) */
    uint8_t *cov;    /* one byte per instruction of the current function, set when reached */

    /* ---- environment and guest memory ---- */
    lm_env env;
    uint8_t **pt;         /* host page for each guest page number, NULL until touched */
    uint32_t *touched;    /* guest page numbers in first-touch order */
    uint32_t n_touched;
    uint8_t **chunks;     /* host page pool, grown in LIFT_CHUNK_PAGES steps */
    uint32_t n_chunks;
    const uint8_t *image; /* flat mapped image, env.image_size bytes */
    uint8_t *teb;         /* TEB page snapshot (zeros without an environment file) */
    lift_range *foreign;  /* ranges the reference child has mapped for itself */
    uint32_t n_foreign;
    uint8_t *bounce;      /* two pages, page aligned: page-straddling thunk operands */
    uint32_t bounce_addr;

    /* ---- current function ---- */
    const lift_range *ranges;
    uint32_t n_ranges;
    const lift_callsite *calls; /* ascending by ret */
    uint32_t n_calls;
    const lift_thunk_desc *thunks;
    uint32_t n_thunks;

    /* ---- trial outcome ---- */
    lm_hash hash;
    uint32_t status; /* LM_S_* */
    uint32_t tkind;  /* LM_T_* */
    uint32_t ta, tb;
    uint32_t fx_valid;   /* fx already holds the guest state at the terminal */
    uint32_t veh_status; /* outcome the host-fault handler hands to its landing routine */
    uint32_t veh_tkind, veh_tb;
    uint32_t host_mxcsr;
    FILE *trace; /* event trace sink, NULL when not tracing */

    uint8_t *fx;      /* guest FXSAVE image, 64-byte aligned, XSAVE layout (legacy area + header) */
    uint8_t *host_fx; /* host x87 state to restore after the trial, same layout */
    jmp_buf jb;
};
#pragma warning(pop)

_Static_assert(offsetof(lift_ctx, r) == LIFT_OFF_R, "thunk offset: r");
_Static_assert(offsetof(lift_ctx, xmm) == LIFT_OFF_XMM, "thunk offset: xmm");
_Static_assert(offsetof(lift_ctx, save_xmm) == LIFT_OFF_SAVE_XMM, "thunk offset: save_xmm");
_Static_assert(offsetof(lift_ctx, save_gpr) == LIFT_OFF_SAVE_GPR, "thunk offset: save_gpr");

/* ---- runner interface ------------------------------------------------------ */

typedef struct lift_result {
    uint32_t status, tkind, a, b;
    uint64_t digest;
    uint64_t steps; /* result-line field: steps of a step-mode trial, 0 in fast mode */
    uint64_t insns; /* instructions completed in either mode (diagnostic only) */
} lift_result;

/* Restricts the process to the performance cores of a hybrid CPU. Flags the
 * manual leaves undefined differ between core types of the same package, and
 * the flag helpers model the performance cores; the reference must run on the
 * same kind of core. LIFT_AFFINITY (hex mask) overrides the choice and
 * LIFT_AFFINITY=0 leaves the affinity alone. Returns the mask in effect. */
uint64_t lift_pin_performance_cores(void);

lift_ctx *lift_ctx_create(void);
void lift_ctx_destroy(lift_ctx *c);
/* The image and TEB buffers are borrowed; foreign ranges are copied. */
void lift_set_image(lift_ctx *c, const uint8_t *image, uint32_t image_size);
void lift_set_env(lift_ctx *c, uint32_t fs_base, const uint8_t *teb_page, const lift_range *foreign,
                  uint32_t n_foreign);
void lift_set_thunks(lift_ctx *c, const lift_thunk_desc *thunks, uint32_t n);
void lift_set_function(lift_ctx *c, const lift_range *ranges, uint32_t n_ranges, const lift_callsite *calls,
                       uint32_t n_calls);
/* Runs one trial. cov points at n_insn bytes (cleared by the caller). */
void lift_run_trial(lift_ctx *c, lift_fn fn, uint32_t entry, uint32_t seed, uint32_t mode, uint64_t budget,
                    uint8_t *cov, lift_result *out);

/* ---- instruction prologue --------------------------------------------------- */

/* Called when the step count reaches c->budget, before the instruction at
 * addr starts. Ends the trial with LM_T_STEP(addr) (step mode) or LM_S_BUDGET
 * (fast mode) at the real limit; returns only while tracing a step-mode
 * trial, where it runs before every step. */
void lift_step_limit(lift_ctx *c, uint32_t addr);
LIFT_NORETURN void lift_unsupported(lift_ctx *c);
LIFT_NORETURN void lift_fault(lift_ctx *c, uint32_t addr); /* LM_T_FAULT at c->eip */
LIFT_NORETURN void lift_fault_gp(lift_ctx *c);             /* LM_T_FAULT(eip, 0xffffffff) */
LIFT_NORETURN void lift_exc(lift_ctx *c, uint32_t cls);    /* LM_T_EXC(eip, LM_X_*) */

/* Every instruction starts with LIFT_I: the step is counted up front (exits
 * that happen inside the instruction take it back), eip is published for
 * fault reporting and the coverage byte is set. */
#define LIFT_I(addr, k) \
    if (c->steps >= c->budget) lift_step_limit(c, (addr)); \
    c->steps++; \
    c->eip = (addr); \
    c->cov[k] = 1;
#define LIFT_UNSUPPORTED(addr) lift_unsupported(c)

/* ---- registers ---------------------------------------------------------------- */

#define LIFT_R16(i) (c->r[i] & 0xffffu)
#define LIFT_R8L(i) (c->r[i] & 0xffu)
#define LIFT_R8H(i) ((c->r[i] >> 8) & 0xffu)
#define LIFT_W16(i, v) (c->r[i] = (c->r[i] & 0xffff0000u) | ((uint32_t)(v) & 0xffffu))
#define LIFT_W8L(i, v) (c->r[i] = (c->r[i] & 0xffffff00u) | ((uint32_t)(v) & 0xffu))
#define LIFT_W8H(i, v) (c->r[i] = (c->r[i] & 0xffff00ffu) | (((uint32_t)(v) & 0xffu) << 8))
#define LIFT_SX8(v) ((uint32_t)(int32_t)(int8_t)(v))
#define LIFT_SX16(v) ((uint32_t)(int32_t)(int16_t)(v))
#define LIFT_FS (c->env.fs_base)

/* Condition codes, indexed like the low nibble of Jcc/SETcc/CMOVcc opcodes. */
#define LIFT_CC_O (c->of)
#define LIFT_CC_NO (!c->of)
#define LIFT_CC_B (c->cf)
#define LIFT_CC_AE (!c->cf)
#define LIFT_CC_E (c->zf)
#define LIFT_CC_NE (!c->zf)
#define LIFT_CC_BE (c->cf | c->zf)
#define LIFT_CC_A (!(c->cf | c->zf))
#define LIFT_CC_S (c->sf)
#define LIFT_CC_NS (!c->sf)
#define LIFT_CC_P (c->pf)
#define LIFT_CC_NP (!c->pf)
#define LIFT_CC_L (c->sf != c->of)
#define LIFT_CC_GE (c->sf == c->of)
#define LIFT_CC_LE (c->zf | (c->sf != c->of))
#define LIFT_CC_G (!(c->zf | (c->sf != c->of)))
int lift_cc(const lift_ctx *c, unsigned cc);

/* ---- guest memory --------------------------------------------------------------
 * Every accessor checks the whole access against the model before touching
 * anything and ends the trial with LM_T_FAULT(eip, lm_access_fault address)
 * when it is not valid, so an instruction that reads, computes and then writes
 * the same location, or probes its writes before updating registers, is
 * atomic. */
uint32_t lift_r8(lift_ctx *c, uint32_t addr);
uint32_t lift_r16(lift_ctx *c, uint32_t addr);
uint32_t lift_r32(lift_ctx *c, uint32_t addr);
void lift_w8(lift_ctx *c, uint32_t addr, uint32_t v);
void lift_w16(lift_ctx *c, uint32_t addr, uint32_t v);
void lift_w32(lift_ctx *c, uint32_t addr, uint32_t v);
void lift_probe(lift_ctx *c, uint32_t addr, uint32_t len);

/* Host pointer for a thunk memory operand of len bytes (1..4096). The pointer
 * has the guest address's offset within a page, so alignment faults happen
 * exactly as they would natively. A page-straddling operand is copied into
 * the bounce buffer; LIFT_MDONE writes it back after the thunk. The a16
 * variant raises the general-protection fault of an aligned SSE access first,
 * as the CPU orders it before the page check. */
uint8_t *lift_mptr(lift_ctx *c, uint32_t addr, uint32_t len);
uint8_t *lift_mptr_a16(lift_ctx *c, uint32_t addr, uint32_t len);
void lift_bounce_commit(lift_ctx *c);
#define LIFT_MDONE() \
    if (c->bounce_len) lift_bounce_commit(c)

/* Stack. A push writes before it moves ESP; a pop reads before it moves ESP. */
void lift_push32(lift_ctx *c, uint32_t v);
void lift_push16(lift_ctx *c, uint32_t v);
uint32_t lift_pop32(lift_ctx *c);
uint32_t lift_pop16(lift_ctx *c);

/* ---- flags ----------------------------------------------------------------------
 * Each helper returns the result truncated to the operand size and updates the
 * flags the instruction updates. Operands may carry garbage above the operand
 * size. Flags the manual leaves undefined follow the host CPU the reference
 * runs on (Intel family 6 model 183); each such choice is noted at the helper
 * and checked by lift_flagtest.c against the real instruction. */
uint32_t lift_add8(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_add16(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_add32(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_adc8(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_adc16(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_adc32(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_sub8(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_sub16(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_sub32(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_sbb8(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_sbb16(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_sbb32(lift_ctx *c, uint32_t a, uint32_t b);
/* AND/OR/XOR/TEST: pass the already combined value. */
uint32_t lift_logic8(lift_ctx *c, uint32_t r);
uint32_t lift_logic16(lift_ctx *c, uint32_t r);
uint32_t lift_logic32(lift_ctx *c, uint32_t r);
uint32_t lift_inc8(lift_ctx *c, uint32_t a);
uint32_t lift_inc16(lift_ctx *c, uint32_t a);
uint32_t lift_inc32(lift_ctx *c, uint32_t a);
uint32_t lift_dec8(lift_ctx *c, uint32_t a);
uint32_t lift_dec16(lift_ctx *c, uint32_t a);
uint32_t lift_dec32(lift_ctx *c, uint32_t a);
uint32_t lift_neg8(lift_ctx *c, uint32_t a);
uint32_t lift_neg16(lift_ctx *c, uint32_t a);
uint32_t lift_neg32(lift_ctx *c, uint32_t a);

/* Shifts and rotates: n is the raw count operand (CL or the immediate). ROL
 * and ROR have a second form for immediate counts (including the by-one
 * encodings), whose undefined OF differs on the host from the CL form. */
uint32_t lift_shl8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_shl16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_shl32(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_shr8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_shr16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_shr32(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_sar8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_sar16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_sar32(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rol8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rol16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rol32(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_ror8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_ror16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_ror32(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_roli8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_roli16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_roli32(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rori8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rori16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rori32(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rcl8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rcl16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rcl32(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rcr8(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rcr16(lift_ctx *c, uint32_t a, uint32_t n);
uint32_t lift_rcr32(lift_ctx *c, uint32_t a, uint32_t n);
/* SHLD/SHRD: a is the destination, b supplies the bits shifted in. */
uint32_t lift_shld16(lift_ctx *c, uint32_t a, uint32_t b, uint32_t n);
uint32_t lift_shld32(lift_ctx *c, uint32_t a, uint32_t b, uint32_t n);
uint32_t lift_shrd16(lift_ctx *c, uint32_t a, uint32_t b, uint32_t n);
uint32_t lift_shrd32(lift_ctx *c, uint32_t a, uint32_t b, uint32_t n);

/* Two- and three-operand IMUL: truncated product. */
uint32_t lift_imul16(lift_ctx *c, uint32_t a, uint32_t b);
uint32_t lift_imul32(lift_ctx *c, uint32_t a, uint32_t b);
/* One-operand MUL/IMUL/DIV/IDIV work on AL/AX/EAX (and AH/DX/EDX) in the
 * context. The divides end the trial with LM_T_EXC(LM_X_DIV) before changing
 * anything when the CPU would raise a divide error. */
void lift_mul8(lift_ctx *c, uint32_t src);
void lift_mul16(lift_ctx *c, uint32_t src);
void lift_mul32(lift_ctx *c, uint32_t src);
void lift_imul1_8(lift_ctx *c, uint32_t src);
void lift_imul1_16(lift_ctx *c, uint32_t src);
void lift_imul1_32(lift_ctx *c, uint32_t src);
void lift_div8(lift_ctx *c, uint32_t src);
void lift_div16(lift_ctx *c, uint32_t src);
void lift_div32(lift_ctx *c, uint32_t src);
void lift_idiv8(lift_ctx *c, uint32_t src);
void lift_idiv16(lift_ctx *c, uint32_t src);
void lift_idiv32(lift_ctx *c, uint32_t src);

/* BSF/BSR return the new destination (dst is kept when src is zero). */
uint32_t lift_bsf16(lift_ctx *c, uint32_t dst, uint32_t src);
uint32_t lift_bsf32(lift_ctx *c, uint32_t dst, uint32_t src);
uint32_t lift_bsr16(lift_ctx *c, uint32_t dst, uint32_t src);
uint32_t lift_bsr32(lift_ctx *c, uint32_t dst, uint32_t src);
/* BT/BTS/BTR/BTC flag update for the selected bit value (0 or 1). */
void lift_bt_flags(lift_ctx *c, uint32_t bit);

/* Packed status flags as LAHF plus SETO produce them: bits 15..8 are
 * SF:ZF:0:AF:0:PF:1:CF and bit 0 is OF. Thunks take and return this form. */
uint32_t lift_flags_pack(const lift_ctx *c);
void lift_flags_unpack(lift_ctx *c, uint32_t ax);
void lift_sahf(lift_ctx *c, uint32_t ah);
uint32_t lift_eflags_get(const lift_ctx *c);    /* PUSHFD image */
void lift_eflags_set(lift_ctx *c, uint32_t v);  /* POPFD (32-bit operand) */
void lift_eflags_set16(lift_ctx *c, uint32_t v); /* POPF (16-bit operand) */

/* ---- string instructions ---------------------------------------------------------
 * size is 1, 2 or 4. rep is LIFT_REP_NONE, LIFT_REP_E (rep / repe) or
 * LIFT_REP_NE. seg_base is the base of the source segment (ESI side). Each
 * iteration is atomic and counts one step. */
enum { LIFT_REP_NONE = 0, LIFT_REP_E = 1, LIFT_REP_NE = 2 };
void lift_movs(lift_ctx *c, uint32_t size, uint32_t rep, uint32_t seg_base);
void lift_stos(lift_ctx *c, uint32_t size, uint32_t rep);
void lift_lods(lift_ctx *c, uint32_t size, uint32_t rep, uint32_t seg_base);
void lift_scas(lift_ctx *c, uint32_t size, uint32_t rep);
void lift_cmps(lift_ctx *c, uint32_t size, uint32_t rep, uint32_t seg_base);

/* ---- control ----------------------------------------------------------------------- */

/* Called with c->eip = T when T is not an instruction start of the function.
 * Applies rule 2 of the trial protocol: a call event followed by its stub
 * (returns with c->eip at the call's return address), or the end of the trial
 * with LM_T_LEAVE(T). A T inside the body ranges is a transfer into the
 * middle of an instruction, which the lifted code cannot follow. */
void lift_leave(lift_ctx *c);
/* Stubbed instruction at c->eip (rule 3). LM_INSN_TRAP ends the trial. */
void lift_stub_insn(lift_ctx *c, uint32_t kind);

/* ---- thunks -------------------------------------------------------------------------
 * x87 form:  code(mem)              memory operand at [rcx]
 *            code(mem, flags) -> ax when the instruction reads or writes EFLAGS,
 *                                   or is FNSTSW AX
 * SIMD form: code(c, flags, mem) -> packed flags; memory operand at [r8]
 * Thunks are leaf code in the .lthk section and never move rsp. */
typedef void (*lift_tx_fn)(void *mem);
typedef uint32_t (*lift_txr_fn)(void *mem, uint32_t flags);
typedef uint32_t (*lift_ts_fn)(lift_ctx *c, uint32_t flags, void *mem);
#define LIFT_TX(t) ((lift_tx_fn)(void *)(t))
#define LIFT_TXR(t) ((lift_txr_fn)(void *)(t))
#define LIFT_TS(t) ((lift_ts_fn)(void *)(t))

/* A batch defines each thunk once with LIFT_THUNK and declares it to its other
 * translation units with LIFT_THUNK_DECL. */
#pragma section(".lthk", read, execute)
#define LIFT_THUNK(name) __declspec(allocate(".lthk")) const unsigned char name[]
#define LIFT_THUNK_DECL(name) extern const unsigned char name[]

#endif /* ROME2_LIFT_RT_H */
