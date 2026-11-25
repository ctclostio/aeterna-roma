/*
 * lift_model.h - shared trial model for the lifted tier.
 *
 * Included by both sides of the differential test:
 *   - the reference debugger (32-bit), which runs the original function bytes
 *     on the host CPU inside an inert child process, and
 *   - the lifted runner (64-bit), which runs the generated C.
 *
 * Everything that decides a trial's inputs, the callee stubs and the digest
 * lives here so the two sides cannot drift apart. Pure integer C17, no
 * floating point, no host-width assumptions. See docs/lifted_tier.md.
 */
#ifndef ROME2_LIFT_MODEL_H
#define ROME2_LIFT_MODEL_H

#include <stdint.h>
#include <string.h>

#define LM_MODEL_VERSION 1u

/* ---- guest address space ------------------------------------------------ */

#define LM_PAGE 4096u
#define LM_IMAGE_BASE 0x10000000u   /* preferred base; image mapped unrelocated */
#define LM_ARENA_LO 0x20000000u     /* lazily filled read/write memory */
#define LM_ARENA_HI 0x60000000u     /* exclusive */
#define LM_PTR_LO 0x20000000u       /* shaped pointers land in [PTR_LO, PTR_LO + PTR_SPAN) */
#define LM_PTR_SPAN 0x30000000u
#define LM_STACK_TOP 0x5ff00000u    /* initial ESP; [ESP] holds LM_RET_SENTINEL */
#define LM_RET_SENTINEL 0x0000deadu /* never mapped: first 64 KiB of the address space */

typedef struct lm_env {
    uint32_t image_size; /* SizeOfImage rounded up to a page; 0 when no image is loaded */
    uint32_t fs_base;    /* page-aligned TEB address; 0 when the TEB page is not modelled */
} lm_env;

/* A page is model-valid when it is image, arena or the TEB page. Anything
 * else is a fault on both sides. */
static inline int lm_valid_page(const lm_env *env, uint32_t addr) {
    uint32_t page = addr & ~(LM_PAGE - 1u);
    if ((uint32_t)(page - LM_IMAGE_BASE) < env->image_size) {
        return 1;
    }
    if ((uint32_t)(page - LM_ARENA_LO) < (LM_ARENA_HI - LM_ARENA_LO)) {
        return 1;
    }
    return env->fs_base != 0u && page == env->fs_base;
}

/* First faulting byte of an access [addr, addr + len), len in 1..4096.
 * Returns 1 and stores the address the CPU reports (the first byte when its
 * page is invalid, otherwise the start of the next page) or returns 0. */
static inline int lm_access_fault(const lm_env *env, uint32_t addr, uint32_t len, uint32_t *fault_addr) {
    uint32_t last = addr + (len - 1u);
    if (!lm_valid_page(env, addr)) {
        *fault_addr = addr;
        return 1;
    }
    if (((addr ^ last) & ~(LM_PAGE - 1u)) != 0u && !lm_valid_page(env, last)) {
        *fault_addr = last & ~(LM_PAGE - 1u);
        return 1;
    }
    return 0;
}

/* ---- deterministic inputs ----------------------------------------------- */

static inline uint32_t lm_mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return x;
}

static inline uint32_t lm_hash2(uint32_t a, uint32_t b) {
    return lm_mix32((a * 0x9e3779b1u) ^ lm_mix32(b + 0x7f4a7c15u));
}

static inline uint32_t lm_shape_ptr(uint32_t h) {
    return LM_PTR_LO + (((h >> 3) % (LM_PTR_SPAN >> 4)) << 4); /* 16-byte aligned */
}

/* Value classes: 3/8 arena pointer, 1/8 zero, 1/8 small int, 1/8 tiny int,
 * 1/8 common float bit pattern, 1/8 unshaped. */
static inline uint32_t lm_shape(uint32_t h) {
    static const uint32_t floats[8] = {
        0x3f800000u, 0x3f000000u, 0x40000000u, 0xbf800000u,
        0x42c80000u, 0x3e800000u, 0x40400000u, 0x41200000u,
    };
    switch (h & 7u) {
    case 0u:
    case 1u:
    case 2u:
        return lm_shape_ptr(h);
    case 3u:
        return 0u;
    case 4u:
        return (h >> 3) & 0x3fu;
    case 5u:
        return (h >> 3) & 3u;
    case 6u:
        return floats[(h >> 3) & 7u];
    default:
        return lm_mix32(h ^ 0xa5a5a5a5u);
    }
}

/* Pristine dword at a 4-aligned arena address. */
static inline uint32_t lm_fill_dword(uint32_t seed, uint32_t addr) {
    if (addr == LM_STACK_TOP) {
        return LM_RET_SENTINEL;
    }
    return lm_shape(lm_hash2(seed, addr >> 2));
}

/* Pristine contents of the arena page at page_addr (little-endian dwords). */
static inline void lm_fill_page(uint32_t seed, uint32_t page_addr, uint8_t out[LM_PAGE]) {
    uint32_t i;
    for (i = 0u; i < LM_PAGE; i += 4u) {
        uint32_t v = lm_fill_dword(seed, page_addr + i);
        out[i] = (uint8_t)v;
        out[i + 1u] = (uint8_t)(v >> 8);
        out[i + 2u] = (uint8_t)(v >> 16);
        out[i + 3u] = (uint8_t)(v >> 24);
    }
}

/* General registers use the x86 encoding order. */
enum { LM_EAX, LM_ECX, LM_EDX, LM_EBX, LM_ESP, LM_EBP, LM_ESI, LM_EDI, LM_GPR_COUNT };

#define LM_EFLAGS_INIT 0x00000202u /* IF set, DF clear */
#define LM_EFLAGS_DF 0x00000400u

static inline void lm_init_gpr(uint32_t seed, uint32_t r[LM_GPR_COUNT]) {
    uint32_t i;
    for (i = 0u; i < LM_GPR_COUNT; ++i) {
        r[i] = lm_shape(lm_hash2(seed ^ 0x52454753u, i));
    }
    r[LM_ECX] = lm_shape_ptr(lm_hash2(seed ^ 0x52454753u, 0x100u)); /* this */
    r[LM_ESP] = LM_STACK_TOP;
}

/* FXSAVE image offsets (identical in 32-bit and 64-bit mode for these fields). */
#define LM_FX_SIZE 512u
#define LM_FX_FCW 0u
#define LM_FX_FSW 2u
#define LM_FX_FTW 4u /* abridged: bit i set when physical register i is not empty */
#define LM_FX_MXCSR 24u
#define LM_FX_ST 32u   /* ST(i) at LM_FX_ST + 16 * i, 10 significant bytes, stack order */
#define LM_FX_XMM 160u /* XMM(i) at LM_FX_XMM + 16 * i; only XMM0..XMM7 are modelled */

#define LM_FCW_INIT 0x027fu /* MSVC 32-bit default: 53-bit precision, all masked */
#define LM_MXCSR_INIT 0x1f80u

static inline void lm_put16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void lm_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t lm_get16(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static inline uint32_t lm_get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Initial x87/SSE state: empty x87 stack, default control words, shaped XMM0..7. */
static inline void lm_init_fx(uint32_t seed, uint8_t fx[LM_FX_SIZE]) {
    uint32_t i;
    memset(fx, 0, LM_FX_SIZE);
    lm_put16(fx + LM_FX_FCW, LM_FCW_INIT);
    lm_put32(fx + LM_FX_MXCSR, LM_MXCSR_INIT);
    for (i = 0u; i < 32u; ++i) {
        lm_put32(fx + LM_FX_XMM + 4u * i, lm_shape(lm_hash2(seed ^ 0x584d4d30u, i)));
    }
}

/* ---- stubs ---------------------------------------------------------------
 * Callees and a few instructions are never executed; both sides replace them
 * with these deterministic effects. `n` is the zero-based index of the stub
 * event within the trial (calls and stubbed instructions share one counter). */

static inline void lm_stub_call_regs(uint32_t seed, uint32_t n, uint32_t *eax, uint32_t *ecx, uint32_t *edx) {
    *eax = lm_shape(lm_hash2(seed ^ 0x43414c4cu, 4u * n));
    *ecx = lm_shape(lm_hash2(seed ^ 0x43414c4cu, 4u * n + 1u));
    *edx = lm_shape(lm_hash2(seed ^ 0x43414c4cu, 4u * n + 2u));
}

/* 80-bit value a floating-point-returning callee stub leaves in ST(0). */
static inline const uint8_t *lm_stub_call_st0(uint32_t seed, uint32_t n) {
    static const uint8_t values[8][10] = {
        {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f}, /* 1.0 */
        {0, 0, 0, 0, 0, 0, 0, 0x80, 0xfe, 0x3f}, /* 0.5 */
        {0, 0, 0, 0, 0, 0, 0, 0x80, 0x00, 0x40}, /* 2.0 */
        {0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00}, /* 0.0 */
        {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0xbf}, /* -1.0 */
        {0, 0, 0, 0, 0, 0, 0, 0xc8, 0x05, 0x40}, /* 100.0 */
        {0, 0, 0, 0, 0, 0, 0, 0x80, 0xfd, 0x3f}, /* 0.25 */
        {0, 0, 0, 0, 0, 0, 0, 0xc0, 0x00, 0x40}, /* 3.0 */
    };
    return values[lm_hash2(seed ^ 0x43414c4cu, 4u * n + 3u) & 7u];
}

/* Raw x87 push on an FXSAVE image: no overflow semantics, the slot is
 * overwritten. Both sides apply exactly this edit for a float-returning stub. */
static inline void lm_fx_push(uint8_t fx[LM_FX_SIZE], const uint8_t value[10]) {
    uint32_t fsw = lm_get16(fx + LM_FX_FSW);
    uint32_t top = ((fsw >> 11) - 1u) & 7u;
    int i;
    for (i = 7; i > 0; --i) {
        memcpy(fx + LM_FX_ST + 16u * (uint32_t)i, fx + LM_FX_ST + 16u * (uint32_t)(i - 1), 10u);
    }
    memcpy(fx + LM_FX_ST, value, 10u);
    lm_put16(fx + LM_FX_FSW, (fsw & ~0x3800u) | (top << 11));
    fx[LM_FX_FTW] = (uint8_t)(fx[LM_FX_FTW] | (1u << top));
}

/* Stubbed instructions. CPUID and RDTSC are replaced because their results
 * depend on the core and the clock. INT n, SYSCALL and SYSENTER end the trial. */
enum { LM_INSN_CPUID = 1, LM_INSN_RDTSC = 2, LM_INSN_TRAP = 3, LM_INSN_XGETBV = 4, LM_INSN_RDTSCP = 5 };

static inline void lm_stub_insn_regs(uint32_t seed, uint32_t n, uint32_t out[4] /* eax, ebx, ecx, edx */) {
    out[0] = lm_mix32(lm_hash2(seed ^ 0x494e534eu, 4u * n));
    out[1] = lm_mix32(lm_hash2(seed ^ 0x494e534eu, 4u * n + 1u));
    out[2] = lm_mix32(lm_hash2(seed ^ 0x494e534eu, 4u * n + 2u));
    out[3] = lm_mix32(lm_hash2(seed ^ 0x494e534eu, 4u * n + 3u));
}

/* ---- trial outcome -------------------------------------------------------- */

/* Terminal kinds that take part in the digest. */
enum {
    LM_T_LEAVE = 1, /* control left the body; target == LM_RET_SENTINEL is a clean return */
    LM_T_FAULT = 2, /* access to a page that is not model-valid, or #GP (addr 0xffffffff) */
    LM_T_EXC = 3,   /* CPU exception, see LM_X_* */
    LM_T_STEP = 4,  /* step budget reached (step mode only) */
};

/* Outcomes that exclude a trial from comparison. */
enum {
    LM_S_OK = 0,
    LM_S_TIMEOUT = 1,     /* reference: wall-clock limit */
    LM_S_FOREIGN = 2,     /* lifted: touched an address the reference child has mapped for itself */
    LM_S_BUDGET = 3,      /* lifted: safety instruction budget exhausted */
    LM_S_UNSUPPORTED = 4, /* lifted: reached an instruction the lifter did not translate, or the
                             trial changed bytes of the function's own body */
    LM_S_HARNESS = 5,     /* reference: harness failure (child died, setup failed) */
};

enum { LM_X_DIV = 1, LM_X_BKPT = 2, LM_X_ILL = 3, LM_X_PRIV = 4, LM_X_FP = 5, LM_X_TRAP = 6, LM_X_OTHER = 7 };

/* Windows exception code -> LM_X_* (0 for access violation / single step,
 * which the caller handles itself). */
static inline uint32_t lm_exc_class(uint32_t code) {
    switch (code) {
    case 0xc0000094u: /* integer divide by zero */
    case 0xc0000095u: /* integer overflow (quotient too large) */
        return LM_X_DIV;
    case 0x80000003u:
    case 0x4000001fu: /* WOW64 breakpoint */
        return LM_X_BKPT;
    case 0xc000001du:
        return LM_X_ILL;
    case 0xc0000096u:
        return LM_X_PRIV;
    case 0xc000008du:
    case 0xc000008eu:
    case 0xc000008fu:
    case 0xc0000090u:
    case 0xc0000091u:
    case 0xc0000092u:
    case 0xc0000093u:
    case 0xc00002b4u:
    case 0xc00002b5u:
        return LM_X_FP;
    case 0xc0000005u:
    case 0x80000004u:
    case 0x4000001eu: /* WOW64 single step */
        return 0u;
    default:
        return LM_X_OTHER;
    }
}

/* ---- digest ---------------------------------------------------------------- */

typedef struct lm_hash {
    uint64_t h;
} lm_hash;

static inline void lm_hash_init(lm_hash *s) {
    s->h = 0xcbf29ce484222325ull;
}

static inline void lm_hash_bytes(lm_hash *s, const uint8_t *p, uint32_t n) {
    uint32_t i;
    for (i = 0u; i < n; ++i) {
        s->h = (s->h ^ p[i]) * 0x100000001b3ull;
    }
}

static inline void lm_hash_u32(lm_hash *s, uint32_t v) {
    uint8_t b[4];
    lm_put32(b, v);
    lm_hash_bytes(s, b, 4u);
}

/* x87 control/status/tag, ST(0..7), MXCSR and XMM0..7. Last-instruction
 * pointers and reserved bytes are left out. */
static inline void lm_hash_fx(lm_hash *s, const uint8_t fx[LM_FX_SIZE]) {
    uint32_t i;
    lm_hash_bytes(s, fx + LM_FX_FCW, 2u);
    lm_hash_bytes(s, fx + LM_FX_FSW, 2u);
    lm_hash_bytes(s, fx + LM_FX_FTW, 1u);
    for (i = 0u; i < 8u; ++i) {
        lm_hash_bytes(s, fx + LM_FX_ST + 16u * i, 10u);
    }
    lm_hash_bytes(s, fx + LM_FX_MXCSR, 4u);
    lm_hash_bytes(s, fx + LM_FX_XMM, 128u);
}

/* Machine state common to every record: the eight general registers, the
 * direction flag and the x87/SSE state. Arithmetic flags are left out; they
 * are dead at calls and returns under every convention the image uses. */
static inline void lm_hash_state(lm_hash *s, const uint32_t r[LM_GPR_COUNT], uint32_t eflags,
                                 const uint8_t fx[LM_FX_SIZE]) {
    uint32_t i;
    for (i = 0u; i < LM_GPR_COUNT; ++i) {
        lm_hash_u32(s, r[i]);
    }
    lm_hash_u32(s, (eflags & LM_EFLAGS_DF) != 0u);
    lm_hash_fx(s, fx);
}

#define LM_CALL_STACK_WORDS 8u
#define LM_PEEK_INVALID 0xffffffffu /* recorded for a stack word on a page that is not model-valid */

/* Call event. `r[LM_ESP]` is ESP after the return address was pushed, `site`
 * is that return address, `stack[i]` is the dword at ESP + 4 + 4 * i (reading
 * it materialises the page like any other access; LM_PEEK_INVALID when the
 * dword is not entirely on model-valid pages). */
static inline void lm_hash_call(lm_hash *s, uint32_t target, uint32_t site, const uint32_t r[LM_GPR_COUNT],
                                uint32_t eflags, const uint8_t fx[LM_FX_SIZE],
                                const uint32_t stack[LM_CALL_STACK_WORDS]) {
    uint32_t i;
    lm_hash_u32(s, 0x43u);
    lm_hash_u32(s, target);
    lm_hash_u32(s, site);
    lm_hash_state(s, r, eflags, fx);
    for (i = 0u; i < LM_CALL_STACK_WORDS; ++i) {
        lm_hash_u32(s, stack[i]);
    }
}

/* Stubbed-instruction event (CPUID, RDTSC, ...): kind and the instruction address. */
static inline void lm_hash_insn(lm_hash *s, uint32_t kind, uint32_t eip) {
    lm_hash_u32(s, 0x49u);
    lm_hash_u32(s, kind);
    lm_hash_u32(s, eip);
}

/* Terminal record.
 *   LM_T_LEAVE: a = target, b = 0; r[LM_ESP] is ESP after the transfer (after RET popped).
 *   LM_T_FAULT: a = address of the faulting instruction, b = faulting data address.
 *   LM_T_EXC:   a = address of the faulting instruction, b = LM_X_* class.
 *   LM_T_STEP:  a = address of the next instruction, b = 0.
 * For FAULT and EXC the state is the state before the faulting instruction. */
static inline void lm_hash_terminal(lm_hash *s, uint32_t kind, uint32_t a, uint32_t b,
                                    const uint32_t r[LM_GPR_COUNT], uint32_t eflags,
                                    const uint8_t fx[LM_FX_SIZE]) {
    lm_hash_u32(s, 0x54u);
    lm_hash_u32(s, kind);
    lm_hash_u32(s, a);
    lm_hash_u32(s, b);
    lm_hash_state(s, r, eflags, fx);
}

/* Memory record: after the terminal record, call lm_hash_mem_begin, then
 * lm_hash_mem_byte for every byte that differs from its pristine value, in
 * ascending address order, then lm_hash_mem_end with the number of bytes. */
static inline void lm_hash_mem_begin(lm_hash *s) {
    lm_hash_u32(s, 0x4du);
}

static inline void lm_hash_mem_byte(lm_hash *s, uint32_t addr, uint8_t value) {
    lm_hash_u32(s, addr);
    lm_hash_bytes(s, &value, 1u);
}

static inline void lm_hash_mem_end(lm_hash *s, uint32_t count) {
    lm_hash_u32(s, 0x45u);
    lm_hash_u32(s, count);
}

#endif /* ROME2_LIFT_MODEL_H */
