/*
 * lift_rt.c - runtime for mechanically lifted functions. See lift_rt.h.
 */
#include "lift_rt.h"

#include <immintrin.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define LIFT_NPAGES (1u << 20)
#define LIFT_CHUNK_PAGES 256u
#define LIFT_FX_AREA 576u /* FXSAVE legacy area plus the 64-byte XSAVE header */
#define PAGE_MASK (LM_PAGE - 1u)

/* EFLAGS bits POPFD can change at CPL 3 besides the seven modelled flags. */
#define EFLAGS_TF 0x00000100u
#define EFLAGS_USER_OTHER 0x00244000u /* NT, AC, ID */
#define EFLAGS_MODELLED 0x00000cd5u   /* CF PF AF ZF SF DF OF */

static lift_ctx *g_ctx; /* the context whose trial the host-fault handler serves */
static PVOID g_veh;

/* ---- host x87/SSE state ------------------------------------------------------
 * During a trial the live host x87 state and MXCSR are the guest's. XRSTOR
 * with only the x87 component requested replaces the x87 state and leaves
 * MXCSR and every XMM register alone. */

static void fx_capture(lift_ctx *c) {
    _fxsave64(c->fx);
    memcpy(c->fx + LM_FX_XMM, c->xmm, sizeof c->xmm);
}

static void x87_load(const uint8_t *area) {
    _xrstor64(area, 1u);
}

static void host_fp_restore(lift_ctx *c) {
    _mm_setcsr(c->host_mxcsr);
    x87_load(c->host_fx);
}

/* ---- ending a trial ------------------------------------------------------------ */

LIFT_NORETURN static void lift_exit(lift_ctx *c) {
    if (!c->fx_valid) {
        fx_capture(c);
        c->fx_valid = 1u;
    }
    host_fp_restore(c);
    c->in_trial = 0u;
    c->bounce_len = 0u;
    longjmp(c->jb, 1);
}

static int is_foreign(const lift_ctx *c, uint32_t addr) {
    uint32_t i;
    for (i = 0u; i < c->n_foreign; ++i) {
        if (addr >= c->foreign[i].lo && addr < c->foreign[i].hi) {
            return 1;
        }
    }
    return 0;
}

LIFT_NORETURN void lift_fault(lift_ctx *c, uint32_t addr) {
    c->tkind = LM_T_FAULT;
    c->ta = c->eip;
    c->tb = addr;
    if (is_foreign(c, addr)) {
        c->status = LM_S_FOREIGN;
    }
    c->steps--;
    lift_exit(c);
}

LIFT_NORETURN void lift_fault_gp(lift_ctx *c) {
    c->tkind = LM_T_FAULT;
    c->ta = c->eip;
    c->tb = 0xffffffffu;
    c->steps--;
    lift_exit(c);
}

LIFT_NORETURN void lift_exc(lift_ctx *c, uint32_t cls) {
    c->tkind = LM_T_EXC;
    c->ta = c->eip;
    c->tb = cls;
    c->steps--;
    lift_exit(c);
}

LIFT_NORETURN void lift_unsupported(lift_ctx *c) {
    c->status = LM_S_UNSUPPORTED;
    c->ta = c->eip;
    c->steps--;
    lift_exit(c);
}

static void trace_regs(FILE *f, const lift_ctx *c);

void lift_step_limit(lift_ctx *c, uint32_t addr) {
    c->eip = addr;
    if (c->steps >= c->limit) {
        c->tkind = LM_T_STEP;
        c->ta = addr;
        c->tb = 0u;
        if (c->mode == 0u) {
            c->status = LM_S_BUDGET;
        }
        lift_exit(c);
    }
    /* Step-mode trace: the trigger follows the step count, so this runs
     * before every step and prints the state the step starts from. */
    fprintf(c->trace, "step %llu %08x", (unsigned long long)c->steps, addr);
    trace_regs(c->trace, c);
    fputc('\n', c->trace);
    c->budget = c->steps + 1u;
}

LIFT_NORETURN static void exit_status(lift_ctx *c, uint32_t status) {
    c->status = status;
    c->ta = c->eip;
    lift_exit(c);
}

int lift_cc(const lift_ctx *c, unsigned cc) {
    switch (cc & 15u) {
    case 0u: return LIFT_CC_O;
    case 1u: return LIFT_CC_NO;
    case 2u: return LIFT_CC_B;
    case 3u: return LIFT_CC_AE;
    case 4u: return LIFT_CC_E;
    case 5u: return LIFT_CC_NE;
    case 6u: return LIFT_CC_BE;
    case 7u: return LIFT_CC_A;
    case 8u: return LIFT_CC_S;
    case 9u: return LIFT_CC_NS;
    case 10u: return LIFT_CC_P;
    case 11u: return LIFT_CC_NP;
    case 12u: return LIFT_CC_L;
    case 13u: return LIFT_CC_GE;
    case 14u: return LIFT_CC_LE;
    default: return LIFT_CC_G;
    }
}

/* ---- guest memory ---------------------------------------------------------------- */

static void pristine_page(const lift_ctx *c, uint32_t page_addr, uint8_t out[LM_PAGE]) {
    if ((uint32_t)(page_addr - LM_IMAGE_BASE) < c->env.image_size) {
        memcpy(out, c->image + (page_addr - LM_IMAGE_BASE), LM_PAGE);
    } else if ((uint32_t)(page_addr - LM_ARENA_LO) < (LM_ARENA_HI - LM_ARENA_LO)) {
        lm_fill_page(c->seed, page_addr, out);
    } else {
        memcpy(out, c->teb, LM_PAGE);
    }
}

static uint8_t *pool_page(lift_ctx *c, uint32_t index) {
    uint32_t chunk = index / LIFT_CHUNK_PAGES;
    while (chunk >= c->n_chunks) {
        uint8_t *mem = VirtualAlloc(NULL, (SIZE_T)LIFT_CHUNK_PAGES * LM_PAGE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (mem == NULL) {
            fprintf(stderr, "lift_rt: out of memory for guest pages\n");
            exit(3);
        }
        c->chunks[c->n_chunks++] = mem;
    }
    return c->chunks[chunk] + (size_t)(index % LIFT_CHUNK_PAGES) * LM_PAGE;
}

/* Materialises a model-valid page on first touch. */
static uint8_t *page_in(lift_ctx *c, uint32_t pn) {
    uint8_t *p;
    if (c->n_touched == LIFT_MAX_PAGES) {
        c->steps--;
        exit_status(c, LM_S_BUDGET);
    }
    p = pool_page(c, c->n_touched);
    pristine_page(c, pn << 12, p);
    c->pt[pn] = p;
    c->touched[c->n_touched++] = pn;
    if (c->trace != NULL) {
        fprintf(c->trace, "page %08x\n", pn << 12);
    }
    return p;
}

static __forceinline uint8_t *page_for(lift_ctx *c, uint32_t addr) {
    uint8_t *p = c->pt[addr >> 12];
    return p != NULL ? p : page_in(c, addr >> 12);
}

static __forceinline void check(lift_ctx *c, uint32_t addr, uint32_t len) {
    uint32_t fault_addr;
    if (lm_access_fault(&c->env, addr, len, &fault_addr)) {
        lift_fault(c, fault_addr);
    }
}

static uint32_t read_slow(lift_ctx *c, uint32_t addr, uint32_t len) {
    uint32_t v = 0u, i;
    check(c, addr, len);
    for (i = 0u; i < len; ++i) {
        v |= (uint32_t)page_for(c, addr + i)[(addr + i) & PAGE_MASK] << (8u * i);
    }
    return v;
}

static void write_slow(lift_ctx *c, uint32_t addr, uint32_t len, uint32_t v) {
    uint32_t i;
    check(c, addr, len);
    for (i = 0u; i < len; ++i) {
        page_for(c, addr + i)[(addr + i) & PAGE_MASK] = (uint8_t)(v >> (8u * i));
    }
}

uint32_t lift_r8(lift_ctx *c, uint32_t addr) {
    const uint8_t *p = c->pt[addr >> 12];
    if (p != NULL) {
        return p[addr & PAGE_MASK];
    }
    return read_slow(c, addr, 1u);
}

uint32_t lift_r16(lift_ctx *c, uint32_t addr) {
    const uint8_t *p = c->pt[addr >> 12];
    uint32_t off = addr & PAGE_MASK;
    if (p != NULL && off <= LM_PAGE - 2u) {
        uint16_t v;
        memcpy(&v, p + off, 2u);
        return v;
    }
    return read_slow(c, addr, 2u);
}

uint32_t lift_r32(lift_ctx *c, uint32_t addr) {
    const uint8_t *p = c->pt[addr >> 12];
    uint32_t off = addr & PAGE_MASK;
    if (p != NULL && off <= LM_PAGE - 4u) {
        uint32_t v;
        memcpy(&v, p + off, 4u);
        return v;
    }
    return read_slow(c, addr, 4u);
}

void lift_w8(lift_ctx *c, uint32_t addr, uint32_t v) {
    uint8_t *p = c->pt[addr >> 12];
    if (p != NULL) {
        p[addr & PAGE_MASK] = (uint8_t)v;
        return;
    }
    write_slow(c, addr, 1u, v);
}

void lift_w16(lift_ctx *c, uint32_t addr, uint32_t v) {
    uint8_t *p = c->pt[addr >> 12];
    uint32_t off = addr & PAGE_MASK;
    if (p != NULL && off <= LM_PAGE - 2u) {
        uint16_t w = (uint16_t)v;
        memcpy(p + off, &w, 2u);
        return;
    }
    write_slow(c, addr, 2u, v);
}

void lift_w32(lift_ctx *c, uint32_t addr, uint32_t v) {
    uint8_t *p = c->pt[addr >> 12];
    uint32_t off = addr & PAGE_MASK;
    if (p != NULL && off <= LM_PAGE - 4u) {
        memcpy(p + off, &v, 4u);
        return;
    }
    write_slow(c, addr, 4u, v);
}

void lift_probe(lift_ctx *c, uint32_t addr, uint32_t len) {
    check(c, addr, len);
    (void)page_for(c, addr);
    (void)page_for(c, addr + (len - 1u));
}

uint8_t *lift_mptr(lift_ctx *c, uint32_t addr, uint32_t len) {
    uint32_t off = addr & PAGE_MASK;
    uint32_t first;
    /* A straddling operand that was only read is never committed and would
     * otherwise still be pending when a later instruction's LIFT_MDONE runs. */
    c->bounce_len = 0u;
    if (off + len <= LM_PAGE) {
        uint8_t *p = c->pt[addr >> 12];
        if (p == NULL) {
            check(c, addr, len);
            p = page_in(c, addr >> 12);
        }
        return p + off;
    }
    check(c, addr, len);
    first = LM_PAGE - off;
    memcpy(c->bounce + off, page_for(c, addr) + off, first);
    memcpy(c->bounce + LM_PAGE, page_for(c, addr + first), len - first);
    c->bounce_addr = addr;
    c->bounce_len = len;
    return c->bounce + off;
}

uint8_t *lift_mptr_a16(lift_ctx *c, uint32_t addr, uint32_t len) {
    if ((addr & 15u) != 0u) {
        lift_fault_gp(c);
    }
    return lift_mptr(c, addr, len);
}

void lift_bounce_commit(lift_ctx *c) {
    uint32_t addr = c->bounce_addr;
    uint32_t off = addr & PAGE_MASK;
    uint32_t first = LM_PAGE - off;
    memcpy(page_for(c, addr) + off, c->bounce + off, first);
    memcpy(page_for(c, addr + first), c->bounce + LM_PAGE, c->bounce_len - first);
    c->bounce_len = 0u;
}

void lift_push32(lift_ctx *c, uint32_t v) {
    uint32_t sp = c->r[LM_ESP] - 4u;
    lift_w32(c, sp, v);
    c->r[LM_ESP] = sp;
}

void lift_push16(lift_ctx *c, uint32_t v) {
    uint32_t sp = c->r[LM_ESP] - 2u;
    lift_w16(c, sp, v);
    c->r[LM_ESP] = sp;
}

uint32_t lift_pop32(lift_ctx *c) {
    uint32_t v = lift_r32(c, c->r[LM_ESP]);
    c->r[LM_ESP] += 4u;
    return v;
}

uint32_t lift_pop16(lift_ctx *c) {
    uint32_t v = lift_r16(c, c->r[LM_ESP]);
    c->r[LM_ESP] += 2u;
    return v;
}

/* ---- flags -------------------------------------------------------------------------- */

static __forceinline uint32_t mask_of(uint32_t bits) {
    return bits == 32u ? 0xffffffffu : ((1u << bits) - 1u);
}

/* PF is set when the low byte has an even number of one bits. */
static __forceinline uint8_t parity8(uint32_t x) {
    x ^= x >> 4;
    return (uint8_t)((0x9669u >> (x & 15u)) & 1u);
}

static __forceinline void set_szp(lift_ctx *c, uint32_t r, uint32_t bits) {
    c->zf = (uint8_t)(r == 0u);
    c->sf = (uint8_t)((r >> (bits - 1u)) & 1u);
    c->pf = parity8(r);
}

static __forceinline uint32_t add_n(lift_ctx *c, uint32_t a, uint32_t b, uint32_t carry, uint32_t bits) {
    uint32_t m = mask_of(bits), r;
    uint64_t wide;
    a &= m;
    b &= m;
    wide = (uint64_t)a + b + carry;
    r = (uint32_t)wide & m;
    c->cf = (uint8_t)((wide >> bits) & 1u);
    c->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1u);
    c->of = (uint8_t)((((a ^ r) & (b ^ r)) >> (bits - 1u)) & 1u);
    set_szp(c, r, bits);
    return r;
}

static __forceinline uint32_t sub_n(lift_ctx *c, uint32_t a, uint32_t b, uint32_t borrow, uint32_t bits) {
    uint32_t m = mask_of(bits), r;
    uint64_t wide;
    a &= m;
    b &= m;
    wide = (uint64_t)a - b - borrow;
    r = (uint32_t)wide & m;
    c->cf = (uint8_t)(wide >> 63);
    c->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1u);
    c->of = (uint8_t)((((a ^ b) & (a ^ r)) >> (bits - 1u)) & 1u);
    set_szp(c, r, bits);
    return r;
}

/* AND/OR/XOR/TEST: CF = OF = 0. AF is undefined; the host clears it. */
static __forceinline uint32_t logic_n(lift_ctx *c, uint32_t r, uint32_t bits) {
    r &= mask_of(bits);
    c->cf = 0u;
    c->of = 0u;
    c->af = 0u;
    set_szp(c, r, bits);
    return r;
}

static __forceinline uint32_t inc_n(lift_ctx *c, uint32_t a, uint32_t bits) {
    uint32_t m = mask_of(bits);
    uint32_t r = (a + 1u) & m;
    c->af = (uint8_t)((r & 15u) == 0u);
    c->of = (uint8_t)(r == (1u << (bits - 1u)));
    set_szp(c, r, bits);
    return r;
}

static __forceinline uint32_t dec_n(lift_ctx *c, uint32_t a, uint32_t bits) {
    uint32_t m = mask_of(bits);
    uint32_t r = (a - 1u) & m;
    c->af = (uint8_t)((r & 15u) == 15u);
    c->of = (uint8_t)(r == (m >> 1));
    set_szp(c, r, bits);
    return r;
}

/* Shifts and rotates share two host rules for what the manual leaves
 * undefined (measured on the performance cores of the reference CPU; its
 * efficiency cores compute a result-based OF instead, which is why both tools
 * pin themselves to performance cores):
 *   - OF for a count above one is the OF of the one-bit form of the same
 *     instruction applied to the original operand (and original CF);
 *   - AF is cleared by SHL/SHR/SAR/SHLD/SHRD and untouched by rotates.
 * A masked count of zero changes nothing. */
static __forceinline uint32_t shl_n(lift_ctx *c, uint32_t a, uint32_t n, uint32_t bits) {
    uint32_t m = mask_of(bits), r;
    uint64_t wide;
    a &= m;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    wide = (uint64_t)a << n;
    r = (uint32_t)wide & m;
    c->cf = (uint8_t)((wide >> bits) & 1u);
    c->of = (uint8_t)(((a >> (bits - 1u)) ^ (a >> (bits - 2u))) & 1u);
    c->af = 0u;
    set_szp(c, r, bits);
    return r;
}

static __forceinline uint32_t shr_n(lift_ctx *c, uint32_t a, uint32_t n, uint32_t bits) {
    uint32_t m = mask_of(bits), r;
    a &= m;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    r = a >> n;
    c->cf = (uint8_t)((a >> (n - 1u)) & 1u);
    c->of = (uint8_t)((a >> (bits - 1u)) & 1u);
    c->af = 0u;
    set_szp(c, r, bits);
    return r;
}

static __forceinline uint32_t sar_n(lift_ctx *c, uint32_t a, uint32_t n, uint32_t bits) {
    uint32_t m = mask_of(bits), r;
    int64_t wide;
    a &= m;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    wide = (int64_t)((uint64_t)a << (64u - bits)) >> (64u - bits); /* sign-extend from the operand size */
    r = (uint32_t)(wide >> n) & m;
    c->cf = (uint8_t)((wide >> (n - 1u)) & 1);
    c->of = 0u;
    c->af = 0u;
    set_szp(c, r, bits);
    return r;
}

/* Rotates change only CF and OF. The count is masked to five bits before the
 * zero test, so an 8- or 16-bit rotate by a nonzero multiple of the operand
 * size leaves the value alone but still sets CF and OF. ROL/ROR with an
 * immediate count above one are the exception to the host's OF rule: they
 * leave OF unchanged (imm is nonzero for those encodings). */
static __forceinline uint32_t rol_n(lift_ctx *c, uint32_t a, uint32_t n, uint32_t bits, int imm) {
    uint32_t m = mask_of(bits), r, k;
    a &= m;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    k = n % bits;
    r = k != 0u ? ((a << k) | (a >> (bits - k))) & m : a;
    c->cf = (uint8_t)(r & 1u);
    if (!imm || n == 1u) {
        c->of = (uint8_t)(((a >> (bits - 1u)) ^ (a >> (bits - 2u))) & 1u);
    }
    return r;
}

static __forceinline uint32_t ror_n(lift_ctx *c, uint32_t a, uint32_t n, uint32_t bits, int imm) {
    uint32_t m = mask_of(bits), r, k;
    a &= m;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    k = n % bits;
    r = k != 0u ? ((a >> k) | (a << (bits - k))) & m : a;
    c->cf = (uint8_t)((r >> (bits - 1u)) & 1u);
    if (!imm || n == 1u) {
        c->of = (uint8_t)(((a >> (bits - 1u)) ^ a) & 1u);
    }
    return r;
}

/* RCL/RCR rotate the (bits + 1)-bit value CF:operand. The effective count is
 * the five-bit count modulo bits + 1; zero changes nothing. */
static __forceinline uint32_t rcl_n(lift_ctx *c, uint32_t a, uint32_t n, uint32_t bits) {
    uint32_t m = mask_of(bits), r;
    uint64_t wide, wmask = ((uint64_t)1 << (bits + 1u)) - 1u;
    a &= m;
    n = (n & 31u) % (bits + 1u);
    if (n == 0u) {
        return a;
    }
    wide = ((uint64_t)c->cf << bits) | a;
    wide = ((wide << n) | (wide >> (bits + 1u - n))) & wmask;
    r = (uint32_t)wide & m;
    c->cf = (uint8_t)((wide >> bits) & 1u);
    c->of = (uint8_t)(((a >> (bits - 1u)) ^ (a >> (bits - 2u))) & 1u);
    return r;
}

static __forceinline uint32_t rcr_n(lift_ctx *c, uint32_t a, uint32_t n, uint32_t bits) {
    uint32_t m = mask_of(bits), r;
    uint64_t wide, wmask = ((uint64_t)1 << (bits + 1u)) - 1u;
    a &= m;
    n = (n & 31u) % (bits + 1u);
    if (n == 0u) {
        return a;
    }
    wide = ((uint64_t)c->cf << bits) | a;
    c->of = (uint8_t)(((a >> (bits - 1u)) ^ c->cf) & 1u);
    wide = ((wide >> n) | (wide << (bits + 1u - n))) & wmask;
    r = (uint32_t)wide & m;
    c->cf = (uint8_t)((wide >> bits) & 1u);
    return r;
}

#define DEF_BINARY(name, expr) \
    uint32_t lift_##name##8(lift_ctx *c, uint32_t a, uint32_t b) { enum { BITS = 8 }; return expr; } \
    uint32_t lift_##name##16(lift_ctx *c, uint32_t a, uint32_t b) { enum { BITS = 16 }; return expr; } \
    uint32_t lift_##name##32(lift_ctx *c, uint32_t a, uint32_t b) { enum { BITS = 32 }; return expr; }
#define DEF_UNARY(name, expr) \
    uint32_t lift_##name##8(lift_ctx *c, uint32_t a) { enum { BITS = 8 }; return expr; } \
    uint32_t lift_##name##16(lift_ctx *c, uint32_t a) { enum { BITS = 16 }; return expr; } \
    uint32_t lift_##name##32(lift_ctx *c, uint32_t a) { enum { BITS = 32 }; return expr; }

DEF_BINARY(add, add_n(c, a, b, 0u, BITS))
DEF_BINARY(adc, add_n(c, a, b, c->cf, BITS))
DEF_BINARY(sub, sub_n(c, a, b, 0u, BITS))
DEF_BINARY(sbb, sub_n(c, a, b, c->cf, BITS))
DEF_UNARY(logic, logic_n(c, a, BITS))
DEF_UNARY(inc, inc_n(c, a, BITS))
DEF_UNARY(dec, dec_n(c, a, BITS))
DEF_UNARY(neg, sub_n(c, 0u, a, 0u, BITS))
DEF_BINARY(shl, shl_n(c, a, b, BITS))
DEF_BINARY(shr, shr_n(c, a, b, BITS))
DEF_BINARY(sar, sar_n(c, a, b, BITS))
DEF_BINARY(rol, rol_n(c, a, b, BITS, 0))
DEF_BINARY(ror, ror_n(c, a, b, BITS, 0))
DEF_BINARY(roli, rol_n(c, a, b, BITS, 1))
DEF_BINARY(rori, ror_n(c, a, b, BITS, 1))
DEF_BINARY(rcl, rcl_n(c, a, b, BITS))
DEF_BINARY(rcr, rcr_n(c, a, b, BITS))

/* SHLD/SHRD. CF is the last bit shifted out and SF/ZF/PF follow the result;
 * OF and AF follow the host rules above. A 16-bit count above 16 is
 * undefined; the host shifts the 48-bit pattern dest:src:dest. */
uint32_t lift_shld32(lift_ctx *c, uint32_t a, uint32_t b, uint32_t n) {
    uint32_t r;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    r = (a << n) | (b >> (32u - n));
    c->cf = (uint8_t)((a >> (32u - n)) & 1u);
    set_szp(c, r, 32u);
    c->of = (uint8_t)(((a >> 31) ^ (a >> 30)) & 1u);
    c->af = 0u;
    return r;
}

uint32_t lift_shrd32(lift_ctx *c, uint32_t a, uint32_t b, uint32_t n) {
    uint32_t r;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    r = (a >> n) | (b << (32u - n));
    c->cf = (uint8_t)((a >> (n - 1u)) & 1u);
    set_szp(c, r, 32u);
    c->of = (uint8_t)(((a >> 31) ^ b) & 1u);
    c->af = 0u;
    return r;
}

uint32_t lift_shld16(lift_ctx *c, uint32_t a, uint32_t b, uint32_t n) {
    uint64_t wide;
    uint32_t r;
    a &= 0xffffu;
    b &= 0xffffu;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    wide = ((uint64_t)a << 32) | ((uint64_t)b << 16) | a;
    wide <<= n;
    r = (uint32_t)(wide >> 32) & 0xffffu;
    c->cf = (uint8_t)((wide >> 48) & 1u);
    set_szp(c, r, 16u);
    c->of = (uint8_t)(((a >> 15) ^ (a >> 14)) & 1u);
    c->af = 0u;
    return r;
}

uint32_t lift_shrd16(lift_ctx *c, uint32_t a, uint32_t b, uint32_t n) {
    uint64_t wide;
    uint32_t r;
    a &= 0xffffu;
    b &= 0xffffu;
    n &= 31u;
    if (n == 0u) {
        return a;
    }
    wide = ((uint64_t)a << 32) | ((uint64_t)b << 16) | a;
    r = (uint32_t)(wide >> n) & 0xffffu;
    c->cf = (uint8_t)((wide >> (n - 1u)) & 1u);
    set_szp(c, r, 16u);
    c->of = (uint8_t)(((a >> 15) ^ b) & 1u);
    c->af = 0u;
    return r;
}

/* Multiplies. CF = OF = the upper half is significant. SF, ZF, AF and PF are
 * undefined; the host's performance cores give SF and PF from the low half
 * and clear ZF and AF (its efficiency cores set ZF from the low half). */
static __forceinline void mul_flags(lift_ctx *c, uint32_t lo, uint32_t bits, uint32_t overflow) {
    c->cf = (uint8_t)overflow;
    c->of = (uint8_t)overflow;
    c->af = 0u;
    set_szp(c, lo & mask_of(bits), bits);
    c->zf = 0u;
}

uint32_t lift_imul16(lift_ctx *c, uint32_t a, uint32_t b) {
    int32_t wide = (int32_t)(int16_t)a * (int32_t)(int16_t)b;
    uint32_t r = (uint32_t)wide & 0xffffu;
    mul_flags(c, r, 16u, wide != (int32_t)(int16_t)r);
    return r;
}

uint32_t lift_imul32(lift_ctx *c, uint32_t a, uint32_t b) {
    int64_t wide = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
    uint32_t r = (uint32_t)wide;
    mul_flags(c, r, 32u, wide != (int64_t)(int32_t)r);
    return r;
}

void lift_mul8(lift_ctx *c, uint32_t src) {
    uint32_t wide = LIFT_R8L(LM_EAX) * (src & 0xffu);
    LIFT_W16(LM_EAX, wide);
    mul_flags(c, wide, 8u, (wide >> 8) != 0u);
}

void lift_mul16(lift_ctx *c, uint32_t src) {
    uint32_t wide = LIFT_R16(LM_EAX) * (src & 0xffffu);
    LIFT_W16(LM_EAX, wide);
    LIFT_W16(LM_EDX, wide >> 16);
    mul_flags(c, wide, 16u, (wide >> 16) != 0u);
}

void lift_mul32(lift_ctx *c, uint32_t src) {
    uint64_t wide = (uint64_t)c->r[LM_EAX] * src;
    c->r[LM_EAX] = (uint32_t)wide;
    c->r[LM_EDX] = (uint32_t)(wide >> 32);
    mul_flags(c, (uint32_t)wide, 32u, (wide >> 32) != 0u);
}

void lift_imul1_8(lift_ctx *c, uint32_t src) {
    int32_t wide = (int32_t)(int8_t)LIFT_R8L(LM_EAX) * (int32_t)(int8_t)src;
    LIFT_W16(LM_EAX, (uint32_t)wide);
    mul_flags(c, (uint32_t)wide, 8u, wide != (int32_t)(int8_t)wide);
}

void lift_imul1_16(lift_ctx *c, uint32_t src) {
    int32_t wide = (int32_t)(int16_t)LIFT_R16(LM_EAX) * (int32_t)(int16_t)src;
    LIFT_W16(LM_EAX, (uint32_t)wide);
    LIFT_W16(LM_EDX, (uint32_t)wide >> 16);
    mul_flags(c, (uint32_t)wide, 16u, wide != (int32_t)(int16_t)wide);
}

void lift_imul1_32(lift_ctx *c, uint32_t src) {
    int64_t wide = (int64_t)(int32_t)c->r[LM_EAX] * (int64_t)(int32_t)src;
    c->r[LM_EAX] = (uint32_t)wide;
    c->r[LM_EDX] = (uint32_t)((uint64_t)wide >> 32);
    mul_flags(c, (uint32_t)wide, 32u, wide != (int64_t)(int32_t)wide);
}

/* Divides. All six status flags are undefined; the host leaves them unchanged. */
static __forceinline void div_flags(lift_ctx *c) {
    (void)c;
}

void lift_div8(lift_ctx *c, uint32_t src) {
    uint32_t n = LIFT_R16(LM_EAX), d = src & 0xffu, q;
    if (d == 0u || (q = n / d) > 0xffu) {
        lift_exc(c, LM_X_DIV);
    }
    LIFT_W16(LM_EAX, q | ((n % d) << 8));
    div_flags(c);
}

void lift_div16(lift_ctx *c, uint32_t src) {
    uint32_t n = (LIFT_R16(LM_EDX) << 16) | LIFT_R16(LM_EAX), d = src & 0xffffu, q;
    if (d == 0u || (q = n / d) > 0xffffu) {
        lift_exc(c, LM_X_DIV);
    }
    LIFT_W16(LM_EAX, q);
    LIFT_W16(LM_EDX, n % d);
    div_flags(c);
}

void lift_div32(lift_ctx *c, uint32_t src) {
    uint64_t n = ((uint64_t)c->r[LM_EDX] << 32) | c->r[LM_EAX], q;
    if (src == 0u || (q = n / src) > 0xffffffffu) {
        lift_exc(c, LM_X_DIV);
    }
    c->r[LM_EAX] = (uint32_t)q;
    c->r[LM_EDX] = (uint32_t)(n % src);
    div_flags(c);
}

void lift_idiv8(lift_ctx *c, uint32_t src) {
    int32_t n = (int16_t)LIFT_R16(LM_EAX), d = (int8_t)src, q;
    if (d == 0 || (q = n / d) > 127 || q < -128) {
        lift_exc(c, LM_X_DIV);
    }
    LIFT_W16(LM_EAX, ((uint32_t)q & 0xffu) | (((uint32_t)(n % d) & 0xffu) << 8));
    div_flags(c);
}

void lift_idiv16(lift_ctx *c, uint32_t src) {
    int64_t n = (int32_t)((LIFT_R16(LM_EDX) << 16) | LIFT_R16(LM_EAX)), d = (int16_t)src, q;
    if (d == 0 || (q = n / d) > 32767 || q < -32768) {
        lift_exc(c, LM_X_DIV);
    }
    LIFT_W16(LM_EAX, (uint32_t)q);
    LIFT_W16(LM_EDX, (uint32_t)(n % d));
    div_flags(c);
}

void lift_idiv32(lift_ctx *c, uint32_t src) {
    int64_t n = (int64_t)(((uint64_t)c->r[LM_EDX] << 32) | c->r[LM_EAX]), d = (int32_t)src, q;
    /* INT64_MIN / -1 overflows in C and is a divide error on the CPU as well. */
    if (d == 0 || (d == -1 && n == INT64_MIN) || (q = n / d) > INT32_MAX || q < INT32_MIN) {
        lift_exc(c, LM_X_DIV);
    }
    c->r[LM_EAX] = (uint32_t)q;
    c->r[LM_EDX] = (uint32_t)(n % d);
    div_flags(c);
}

/* Bit scans. ZF is set from the source; a zero source leaves the destination
 * alone. CF, OF, SF, AF and PF are undefined; the host clears CF, OF, SF and
 * AF and sets PF from the bit index (index 0 for a zero source). */
static __forceinline void bitscan_flags(lift_ctx *c, uint32_t src, uint32_t index) {
    c->zf = (uint8_t)(src == 0u);
    c->cf = 0u;
    c->of = 0u;
    c->sf = 0u;
    c->af = 0u;
    c->pf = parity8(index);
}

static __forceinline uint32_t bsf_n(lift_ctx *c, uint32_t dst, uint32_t src, uint32_t bits) {
    unsigned long index = 0u;
    src &= mask_of(bits);
    if (src != 0u) {
        _BitScanForward(&index, src);
        dst = index;
    }
    bitscan_flags(c, src, index);
    return dst & mask_of(bits);
}

static __forceinline uint32_t bsr_n(lift_ctx *c, uint32_t dst, uint32_t src, uint32_t bits) {
    unsigned long index = 0u;
    src &= mask_of(bits);
    if (src != 0u) {
        _BitScanReverse(&index, src);
        dst = index;
    }
    bitscan_flags(c, src, index);
    return dst & mask_of(bits);
}

uint32_t lift_bsf16(lift_ctx *c, uint32_t dst, uint32_t src) { return bsf_n(c, dst, src, 16u); }
uint32_t lift_bsf32(lift_ctx *c, uint32_t dst, uint32_t src) { return bsf_n(c, dst, src, 32u); }
uint32_t lift_bsr16(lift_ctx *c, uint32_t dst, uint32_t src) { return bsr_n(c, dst, src, 16u); }
uint32_t lift_bsr32(lift_ctx *c, uint32_t dst, uint32_t src) { return bsr_n(c, dst, src, 32u); }

/* BT family: CF is the selected bit. OF, SF, AF and PF are undefined and the
 * host leaves them (and ZF) unchanged. */
void lift_bt_flags(lift_ctx *c, uint32_t bit) {
    c->cf = (uint8_t)(bit & 1u);
}

uint32_t lift_flags_pack(const lift_ctx *c) {
    return ((uint32_t)c->sf << 15) | ((uint32_t)c->zf << 14) | ((uint32_t)c->af << 12) | ((uint32_t)c->pf << 10) |
           0x200u | ((uint32_t)c->cf << 8) | c->of;
}

void lift_flags_unpack(lift_ctx *c, uint32_t ax) {
    lift_sahf(c, ax >> 8);
    c->of = (uint8_t)(ax & 1u);
}

void lift_sahf(lift_ctx *c, uint32_t ah) {
    c->cf = (uint8_t)(ah & 1u);
    c->pf = (uint8_t)((ah >> 2) & 1u);
    c->af = (uint8_t)((ah >> 4) & 1u);
    c->zf = (uint8_t)((ah >> 6) & 1u);
    c->sf = (uint8_t)((ah >> 7) & 1u);
}

uint32_t lift_eflags_get(const lift_ctx *c) {
    return c->eflags_other | c->cf | ((uint32_t)c->pf << 2) | ((uint32_t)c->af << 4) | ((uint32_t)c->zf << 6) |
           ((uint32_t)c->sf << 7) | ((uint32_t)c->df << 10) | ((uint32_t)c->of << 11);
}

static void eflags_set(lift_ctx *c, uint32_t v, uint32_t user_mask) {
    /* A popped TF would single-step the following instruction, which the
     * lifted code does not model. */
    if ((v & EFLAGS_TF) != 0u) {
        lift_unsupported(c);
    }
    lift_sahf(c, v);
    c->df = (uint8_t)((v >> 10) & 1u);
    c->of = (uint8_t)((v >> 11) & 1u);
    c->eflags_other = (c->eflags_other & ~user_mask) | (v & user_mask);
}

void lift_eflags_set(lift_ctx *c, uint32_t v) {
    eflags_set(c, v, EFLAGS_USER_OTHER);
}

void lift_eflags_set16(lift_ctx *c, uint32_t v) {
    eflags_set(c, v & 0xffffu, EFLAGS_USER_OTHER & 0xffffu);
}

/* ---- string instructions ------------------------------------------------------------- */

static __forceinline uint32_t rd_n(lift_ctx *c, uint32_t addr, uint32_t size) {
    return size == 1u ? lift_r8(c, addr) : size == 2u ? lift_r16(c, addr) : lift_r32(c, addr);
}

static __forceinline void wr_n(lift_ctx *c, uint32_t addr, uint32_t v, uint32_t size) {
    if (size == 1u) {
        lift_w8(c, addr, v);
    } else if (size == 2u) {
        lift_w16(c, addr, v);
    } else {
        lift_w32(c, addr, v);
    }
}

static __forceinline void cmp_n(lift_ctx *c, uint32_t a, uint32_t b, uint32_t size) {
    if (size == 1u) {
        (void)lift_sub8(c, a, b);
    } else if (size == 2u) {
        (void)lift_sub16(c, a, b);
    } else {
        (void)lift_sub32(c, a, b);
    }
}

static __forceinline uint32_t acc_get(const lift_ctx *c, uint32_t size) {
    return size == 1u ? LIFT_R8L(LM_EAX) : size == 2u ? LIFT_R16(LM_EAX) : c->r[LM_EAX];
}

/* A completed iteration with more to come is a step of its own. */
static __forceinline void rep_next(lift_ctx *c) {
    if (c->steps >= c->budget) {
        lift_step_limit(c, c->eip);
    }
    c->steps++;
}

void lift_movs(lift_ctx *c, uint32_t size, uint32_t rep, uint32_t seg_base) {
    uint32_t delta = c->df ? 0u - size : size;
    if (rep != LIFT_REP_NONE && c->r[LM_ECX] == 0u) {
        return;
    }
    for (;;) {
        uint32_t v = rd_n(c, seg_base + c->r[LM_ESI], size);
        wr_n(c, c->r[LM_EDI], v, size);
        c->r[LM_ESI] += delta;
        c->r[LM_EDI] += delta;
        if (rep == LIFT_REP_NONE || --c->r[LM_ECX] == 0u) {
            return;
        }
        rep_next(c);
    }
}

void lift_stos(lift_ctx *c, uint32_t size, uint32_t rep) {
    uint32_t delta = c->df ? 0u - size : size;
    if (rep != LIFT_REP_NONE && c->r[LM_ECX] == 0u) {
        return;
    }
    for (;;) {
        wr_n(c, c->r[LM_EDI], c->r[LM_EAX], size);
        c->r[LM_EDI] += delta;
        if (rep == LIFT_REP_NONE || --c->r[LM_ECX] == 0u) {
            return;
        }
        rep_next(c);
    }
}

void lift_lods(lift_ctx *c, uint32_t size, uint32_t rep, uint32_t seg_base) {
    uint32_t delta = c->df ? 0u - size : size;
    if (rep != LIFT_REP_NONE && c->r[LM_ECX] == 0u) {
        return;
    }
    for (;;) {
        uint32_t v = rd_n(c, seg_base + c->r[LM_ESI], size);
        if (size == 1u) {
            LIFT_W8L(LM_EAX, v);
        } else if (size == 2u) {
            LIFT_W16(LM_EAX, v);
        } else {
            c->r[LM_EAX] = v;
        }
        c->r[LM_ESI] += delta;
        if (rep == LIFT_REP_NONE || --c->r[LM_ECX] == 0u) {
            return;
        }
        rep_next(c);
    }
}

void lift_scas(lift_ctx *c, uint32_t size, uint32_t rep) {
    uint32_t delta = c->df ? 0u - size : size;
    if (rep != LIFT_REP_NONE && c->r[LM_ECX] == 0u) {
        return;
    }
    for (;;) {
        uint32_t v = rd_n(c, c->r[LM_EDI], size);
        cmp_n(c, acc_get(c, size), v, size);
        c->r[LM_EDI] += delta;
        if (rep == LIFT_REP_NONE || --c->r[LM_ECX] == 0u || c->zf != (rep == LIFT_REP_E)) {
            return;
        }
        rep_next(c);
    }
}

void lift_cmps(lift_ctx *c, uint32_t size, uint32_t rep, uint32_t seg_base) {
    uint32_t delta = c->df ? 0u - size : size;
    if (rep != LIFT_REP_NONE && c->r[LM_ECX] == 0u) {
        return;
    }
    for (;;) {
        uint32_t a = rd_n(c, seg_base + c->r[LM_ESI], size);
        uint32_t b = rd_n(c, c->r[LM_EDI], size);
        cmp_n(c, a, b, size);
        c->r[LM_ESI] += delta;
        c->r[LM_EDI] += delta;
        if (rep == LIFT_REP_NONE || --c->r[LM_ECX] == 0u || c->zf != (rep == LIFT_REP_E)) {
            return;
        }
        rep_next(c);
    }
}

/* ---- events ----------------------------------------------------------------------------- */

/* Trace lines have the same text as the reference debugger's, so the two
 * traces of a trial can be compared with a plain diff. */
static void trace_regs(FILE *f, const lift_ctx *c) {
    fprintf(f, " eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x df=%u", c->r[LM_EAX],
            c->r[LM_ECX], c->r[LM_EDX], c->r[LM_EBX], c->r[LM_ESP], c->r[LM_EBP], c->r[LM_ESI], c->r[LM_EDI],
            (unsigned)c->df);
}

static void trace_hex(FILE *f, const char *name, uint32_t index, const uint8_t *p, uint32_t n) {
    uint32_t i;
    fprintf(f, "%s%u ", name, index);
    for (i = 0u; i < n; ++i) {
        fprintf(f, "%02x", p[i]);
    }
    fputc('\n', f);
}

static void trace_fx(FILE *f, const uint8_t *fx) {
    uint32_t i;
    fprintf(f, "fx fcw=%04x fsw=%04x ftw=%02x mxcsr=%08x\n", lm_get16(fx + LM_FX_FCW), lm_get16(fx + LM_FX_FSW),
            fx[LM_FX_FTW], lm_get32(fx + LM_FX_MXCSR));
    for (i = 0u; i < 8u; ++i) {
        trace_hex(f, "st", i, fx + LM_FX_ST + 16u * i, 10u);
    }
    for (i = 0u; i < 8u; ++i) {
        trace_hex(f, "xmm", i, fx + LM_FX_XMM + 16u * i, 16u);
    }
}

static int in_body(const lift_ctx *c, uint32_t addr) {
    uint32_t i;
    for (i = 0u; i < c->n_ranges; ++i) {
        if (addr >= c->ranges[i].lo && addr < c->ranges[i].hi) {
            return 1;
        }
    }
    return 0;
}

static const lift_callsite *find_call(const lift_ctx *c, uint32_t ret) {
    uint32_t lo = 0u, hi = c->n_calls;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        if (c->calls[mid].ret < ret) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo < c->n_calls && c->calls[lo].ret == ret ? &c->calls[lo] : NULL;
}

/* Dword for a call event's stack record: materialises like any access, but an
 * invalid location is recorded instead of faulting. */
static uint32_t peek32(lift_ctx *c, uint32_t addr) {
    uint32_t fault_addr;
    if (lm_access_fault(&c->env, addr, 4u, &fault_addr)) {
        return LM_PEEK_INVALID;
    }
    return lift_r32(c, addr);
}

void lift_leave(lift_ctx *c) {
    uint32_t target = c->eip, esp = c->r[LM_ESP], site = 0u, fault_addr, i;
    uint32_t eflags = c->df ? LM_EFLAGS_DF : 0u;
    uint32_t stack[LM_CALL_STACK_WORDS];
    const lift_callsite *cs = NULL;

    if (in_body(c, target)) {
        exit_status(c, LM_S_UNSUPPORTED);
    }
    if (!lm_access_fault(&c->env, esp, 4u, &fault_addr)) {
        site = lift_r32(c, esp);
        cs = find_call(c, site);
    }
    if (cs == NULL) {
        c->tkind = LM_T_LEAVE;
        c->ta = target;
        c->tb = 0u;
        lift_exit(c);
    }
    if (c->stub_n >= LIFT_MAX_EVENTS) {
        exit_status(c, LM_S_BUDGET);
    }
    for (i = 0u; i < LM_CALL_STACK_WORDS; ++i) {
        stack[i] = peek32(c, esp + 4u + 4u * i);
    }
    fx_capture(c);
    lm_hash_call(&c->hash, target, site, c->r, eflags, c->fx, stack);
    if (c->trace != NULL) {
        lm_hash fxh;
        lm_hash_init(&fxh);
        lm_hash_fx(&fxh, c->fx);
        fprintf(c->trace, "call %u target=%08x site=%08x", c->stub_n, target, site);
        trace_regs(c->trace, c);
        fprintf(c->trace, " fx=%016llx stack=", (unsigned long long)fxh.h);
        for (i = 0u; i < LM_CALL_STACK_WORDS; ++i) {
            fprintf(c->trace, i == 0u ? "%08x" : ",%08x", stack[i]);
        }
        fputc('\n', c->trace);
    }
    lm_stub_call_regs(c->seed, c->stub_n, &c->r[LM_EAX], &c->r[LM_ECX], &c->r[LM_EDX]);
    c->r[LM_ESP] = esp + 4u + cs->pop_bytes;
    if (cs->fp_ret) {
        lm_fx_push(c->fx, lm_stub_call_st0(c->seed, c->stub_n));
        x87_load(c->fx);
    }
    c->eip = site;
    c->stub_n++;
}

void lift_stub_insn(lift_ctx *c, uint32_t kind) {
    uint32_t out[4];
    if (kind == LM_INSN_TRAP) {
        lift_exc(c, LM_X_TRAP);
    }
    if (kind != LM_INSN_CPUID && kind != LM_INSN_RDTSC && kind != LM_INSN_XGETBV && kind != LM_INSN_RDTSCP) {
        lift_unsupported(c);
    }
    if (c->stub_n >= LIFT_MAX_EVENTS) {
        c->steps--;
        exit_status(c, LM_S_BUDGET);
    }
    lm_hash_insn(&c->hash, kind, c->eip);
    if (c->trace != NULL) {
        fprintf(c->trace, "insn %u kind=%u addr=%08x\n", c->stub_n, kind, c->eip);
    }
    lm_stub_insn_regs(c->seed, c->stub_n, out);
    c->r[LM_EAX] = out[0];
    c->r[LM_EDX] = out[3];
    if (kind == LM_INSN_CPUID) {
        c->r[LM_EBX] = out[1];
    }
    if (kind == LM_INSN_CPUID || kind == LM_INSN_RDTSCP) {
        c->r[LM_ECX] = out[2];
    }
    c->stub_n++;
}

/* ---- host faults ----------------------------------------------------------------------------
 * A thunk executes one guest x87/SIMD instruction on the host and can raise
 * #GP (misaligned aligned access, bad MXCSR), #MF/#XM (unmasked FP exception)
 * or #UD. The vectored handler turns those into the guest's terminal: it
 * takes the pre-instruction x87/MXCSR state from the exception context,
 * puts back the non-volatile registers the thunk borrowed, and resumes in
 * veh_landing as if the generated code had called it instead of the thunk.
 * Any other hard fault during a trial is a harness failure for that trial. */

static const lift_thunk_desc *find_thunk(const lift_ctx *c, DWORD64 rip) {
    uint32_t i;
    for (i = 0u; i < c->n_thunks; ++i) {
        DWORD64 lo = (DWORD64)(uintptr_t)c->thunks[i].code;
        if (rip >= lo && rip < lo + c->thunks[i].size) {
            return &c->thunks[i];
        }
    }
    return NULL;
}

LIFT_NORETURN static void veh_landing(lift_ctx *c) {
    c->status = c->veh_status;
    c->tkind = c->veh_tkind;
    c->ta = c->eip;
    c->tb = c->veh_tb;
    c->steps--;
    lift_exit(c);
}

static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep) {
    lift_ctx *c = g_ctx;
    const EXCEPTION_RECORD *er = ep->ExceptionRecord;
    CONTEXT *hc = ep->ContextRecord;
    DWORD code = er->ExceptionCode;
    const lift_thunk_desc *td;

    if (c == NULL || !c->in_trial || (code & 0xf0000000u) != 0xc0000000u || code == EXCEPTION_STACK_OVERFLOW) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    td = find_thunk(c, hc->Rip);
    c->veh_status = LM_S_OK;
    c->veh_tkind = LM_T_EXC;
    if (td != NULL) {
        uint32_t cls = lm_exc_class(code);
        if (code == EXCEPTION_ACCESS_VIOLATION) {
            if (er->NumberParameters >= 2u && er->ExceptionInformation[1] == ~(ULONG_PTR)0) {
                c->veh_tkind = LM_T_FAULT;
                c->veh_tb = 0xffffffffu;
            } else {
                /* A thunk operand outside guest pages: the probe before the thunk was wrong. */
                c->veh_status = LM_S_HARNESS;
            }
        } else {
            c->veh_tb = cls;
        }
        if (td->flags & LIFT_TF_XMM) {
            memcpy(&hc->Xmm6, c->save_xmm[0], 16u);
            memcpy(&hc->Xmm7, c->save_xmm[1], 16u);
        }
        if (td->flags & LIFT_TF_RBX) {
            hc->Rbx = c->save_gpr[0];
        }
        if (td->flags & LIFT_TF_RBP) {
            hc->Rbp = c->save_gpr[1];
        }
        if (td->flags & LIFT_TF_RSI) {
            hc->Rsi = c->save_gpr[2];
        }
        if (td->flags & LIFT_TF_RDI) {
            hc->Rdi = c->save_gpr[3];
        }
        memcpy(c->fx, &hc->FltSave, LM_FX_SIZE);
        lm_put32(c->fx + LM_FX_MXCSR, hc->MxCsr);
        memcpy(c->fx + LM_FX_XMM, c->xmm, sizeof c->xmm);
        c->fx_valid = 1u;
    } else {
        fprintf(stderr, "lift_rt: host exception %08lx at %p during trial (eip %08x)\n", (unsigned long)code,
                (void *)(uintptr_t)hc->Rip, c->eip);
        c->veh_status = LM_S_HARNESS;
        c->veh_tb = 0u;
        hc->Rsp = ((hc->Rsp - 512u) & ~(DWORD64)15) - 8u;
    }
    /* Resume with a quiet FPU so nothing between here and the exit re-raises. */
    hc->FltSave.StatusWord = 0u;
    hc->FltSave.ControlWord = 0x027fu;
    hc->FltSave.MxCsr = c->host_mxcsr;
    hc->MxCsr = c->host_mxcsr;
    hc->EFlags &= ~0x500u; /* DF, TF */
    hc->Rcx = (DWORD64)(uintptr_t)c;
    hc->Rip = (DWORD64)(uintptr_t)veh_landing;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ---- runner interface --------------------------------------------------------------------------- */

uint64_t lift_pin_performance_cores(void) {
    HANDLE process = GetCurrentProcess();
    DWORD_PTR process_mask = 0u, system_mask = 0u, want = 0u;
    const char *override = getenv("LIFT_AFFINITY");
    ULONG size = 0u;
    BYTE best = 0u;

    if (!GetProcessAffinityMask(process, &process_mask, &system_mask)) {
        return 0u;
    }
    if (override != NULL) {
        want = (DWORD_PTR)strtoull(override, NULL, 16);
    } else {
        /* The cores with the highest efficiency class are the performance cores. */
        GetSystemCpuSetInformation(NULL, 0u, &size, process, 0u);
        if (size != 0u) {
            BYTE *buf = malloc(size);
            ULONG off;
            int pass;
            if (buf != NULL && GetSystemCpuSetInformation((PSYSTEM_CPU_SET_INFORMATION)buf, size, &size, process, 0u)) {
                for (pass = 0; pass < 2; ++pass) {
                    for (off = 0u; off < size;) {
                        const SYSTEM_CPU_SET_INFORMATION *info = (const SYSTEM_CPU_SET_INFORMATION *)(buf + off);
                        if (info->Type == CpuSetInformation && info->CpuSet.Group == 0u) {
                            if (pass == 0 && info->CpuSet.EfficiencyClass > best) {
                                best = info->CpuSet.EfficiencyClass;
                            } else if (pass == 1 && info->CpuSet.EfficiencyClass == best) {
                                want |= (DWORD_PTR)1 << info->CpuSet.LogicalProcessorIndex;
                            }
                        }
                        off += info->Size;
                    }
                }
            }
            free(buf);
        }
    }
    want &= process_mask;
    if (want != 0u && want != process_mask && SetProcessAffinityMask(process, want)) {
        return want;
    }
    return process_mask;
}

static void *alloc_zero(size_t size) {
    void *p = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p == NULL) {
        fprintf(stderr, "lift_rt: out of memory\n");
        exit(3);
    }
    return p;
}

lift_ctx *lift_ctx_create(void) {
    lift_ctx *c = _aligned_malloc(sizeof *c, 64u);
    if (c == NULL) {
        fprintf(stderr, "lift_rt: out of memory\n");
        exit(3);
    }
    memset(c, 0, sizeof *c);
    c->pt = alloc_zero((size_t)LIFT_NPAGES * sizeof *c->pt);
    c->touched = alloc_zero((size_t)LIFT_MAX_PAGES * sizeof *c->touched);
    c->chunks = alloc_zero((size_t)(LIFT_MAX_PAGES / LIFT_CHUNK_PAGES) * sizeof *c->chunks);
    c->teb = alloc_zero(LM_PAGE);
    c->bounce = alloc_zero(2u * LM_PAGE);
    /* VirtualAlloc memory is page aligned, which covers the 64-byte XSAVE alignment. */
    c->fx = alloc_zero(LM_PAGE);
    c->host_fx = alloc_zero(LM_PAGE);
    c->fx[LM_FX_SIZE] = 1u; /* XSAVE header XSTATE_BV: x87 component present */
    c->host_fx[LM_FX_SIZE] = 1u;
    g_ctx = c;
    if (g_veh == NULL) {
        g_veh = AddVectoredExceptionHandler(1u, veh_handler);
    }
    return c;
}

void lift_ctx_destroy(lift_ctx *c) {
    uint32_t i;
    if (c == NULL) {
        return;
    }
    if (g_ctx == c) {
        g_ctx = NULL;
    }
    for (i = 0u; i < c->n_chunks; ++i) {
        VirtualFree(c->chunks[i], 0u, MEM_RELEASE);
    }
    VirtualFree(c->pt, 0u, MEM_RELEASE);
    VirtualFree(c->touched, 0u, MEM_RELEASE);
    VirtualFree(c->chunks, 0u, MEM_RELEASE);
    VirtualFree(c->teb, 0u, MEM_RELEASE);
    VirtualFree(c->bounce, 0u, MEM_RELEASE);
    VirtualFree(c->fx, 0u, MEM_RELEASE);
    VirtualFree(c->host_fx, 0u, MEM_RELEASE);
    free(c->foreign);
    _aligned_free(c);
}

void lift_set_image(lift_ctx *c, const uint8_t *image, uint32_t image_size) {
    c->image = image;
    c->env.image_size = image_size;
}

void lift_set_env(lift_ctx *c, uint32_t fs_base, const uint8_t *teb_page, const lift_range *foreign,
                  uint32_t n_foreign) {
    c->env.fs_base = fs_base;
    if (teb_page != NULL) {
        memcpy(c->teb, teb_page, LM_PAGE);
    } else {
        memset(c->teb, 0, LM_PAGE);
    }
    free(c->foreign);
    c->foreign = NULL;
    c->n_foreign = 0u;
    if (n_foreign != 0u) {
        c->foreign = malloc((size_t)n_foreign * sizeof *c->foreign);
        if (c->foreign == NULL) {
            fprintf(stderr, "lift_rt: out of memory\n");
            exit(3);
        }
        memcpy(c->foreign, foreign, (size_t)n_foreign * sizeof *c->foreign);
        c->n_foreign = n_foreign;
    }
}

void lift_set_thunks(lift_ctx *c, const lift_thunk_desc *thunks, uint32_t n) {
    c->thunks = thunks;
    c->n_thunks = n;
}

void lift_set_function(lift_ctx *c, const lift_range *ranges, uint32_t n_ranges, const lift_callsite *calls,
                       uint32_t n_calls) {
    c->ranges = ranges;
    c->n_ranges = n_ranges;
    c->calls = calls;
    c->n_calls = n_calls;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* Memory record: every byte that differs from its pristine value, ascending.
 * Returns nonzero when one of those bytes belongs to the body of the function
 * under test. */
static int hash_memory(lift_ctx *c) {
    uint8_t pristine[LM_PAGE];
    uint32_t i, k, off, count = 0u;
    int body_changed = 0;
    qsort(c->touched, c->n_touched, sizeof *c->touched, cmp_u32);
    lm_hash_mem_begin(&c->hash);
    for (i = 0u; i < c->n_touched; ++i) {
        uint32_t page_addr = c->touched[i] << 12;
        const uint8_t *p = c->pt[c->touched[i]];
        int body_page = 0;
        pristine_page(c, page_addr, pristine);
        if (memcmp(p, pristine, LM_PAGE) == 0) {
            continue;
        }
        for (k = 0u; k < c->n_ranges; ++k) {
            body_page |= c->ranges[k].lo < page_addr + LM_PAGE && c->ranges[k].hi > page_addr;
        }
        for (off = 0u; off < LM_PAGE; ++off) {
            if (p[off] != pristine[off]) {
                lm_hash_mem_byte(&c->hash, page_addr + off, p[off]);
                ++count;
                if (body_page && in_body(c, page_addr + off)) {
                    body_changed = 1;
                }
                if (c->trace != NULL) {
                    fprintf(c->trace, "mem %08x %02x\n", page_addr + off, p[off]);
                }
            }
        }
    }
    lm_hash_mem_end(&c->hash, count);
    return body_changed;
}

void lift_run_trial(lift_ctx *c, lift_fn fn, uint32_t entry, uint32_t seed, uint32_t mode, uint64_t budget,
                    uint8_t *cov, lift_result *out) {
    uint32_t i;

    lm_init_gpr(seed, c->r);
    c->eip = entry;
    c->cf = c->pf = c->af = c->zf = c->sf = c->of = c->df = 0u;
    c->eflags_other = LM_EFLAGS_INIT & ~EFLAGS_MODELLED;
    c->seed = seed;
    c->stub_n = 0u;
    c->mode = mode;
    c->steps = 0u;
    /* The step budget is looked at after a step, so 0 behaves like 1. */
    c->limit = mode == 0u ? LIFT_FAST_BUDGET : budget != 0u ? budget : 1u;
    c->budget = (mode != 0u && c->trace != NULL) ? 0u : c->limit;
    c->cov = cov;
    c->bounce_len = 0u;
    c->status = LM_S_OK;
    c->tkind = 0u;
    c->ta = 0u;
    c->tb = 0u;
    c->fx_valid = 0u;
    lm_hash_init(&c->hash);
    if (c->trace != NULL) {
        fprintf(c->trace, "trial %08x %08x %u\n", entry, seed, mode);
    }

    c->host_mxcsr = _mm_getcsr();
    _fxsave64(c->host_fx);
    if (setjmp(c->jb) == 0) {
        /* A zero frame makes longjmp restore registers without unwinding, so
         * it is safe from the host-fault landing routine too. */
        ((_JUMP_BUFFER *)c->jb)->Frame = 0u;
        lm_init_fx(seed, c->fx);
        memcpy(c->xmm, c->fx + LM_FX_XMM, sizeof c->xmm);
        c->in_trial = 1u;
        _mm_setcsr(lm_get32(c->fx + LM_FX_MXCSR));
        x87_load(c->fx);
        fn(c);
        /* A lifted function only ever leaves through lift_exit. */
        exit_status(c, LM_S_HARNESS);
    }

    if (c->status == LM_S_OK) {
        lm_hash_terminal(&c->hash, c->tkind, c->ta, c->tb, c->r, c->df ? LM_EFLAGS_DF : 0u, c->fx);
        if (c->trace != NULL) {
            fprintf(c->trace, "term kind=%u a=%08x b=%08x", c->tkind, c->ta, c->tb);
            trace_regs(c->trace, c);
            fputc('\n', c->trace);
            trace_fx(c->trace, c->fx);
        }
        if (hash_memory(c)) {
            /* The trial rewrote instructions of the function itself. The
             * original goes on with the new bytes; this translation of the
             * old ones cannot follow, so the trial is not comparable. */
            c->status = LM_S_UNSUPPORTED;
        }
    }
    out->status = c->status;
    out->a = c->ta;
    out->b = c->tb;
    out->insns = c->steps;
    out->steps = mode != 0u ? c->steps : 0u;
    if (c->status == LM_S_OK) {
        out->tkind = c->tkind;
        out->digest = c->hash.h;
    } else {
        /* Not comparable: no terminal record. a and b keep where and why it stopped. */
        out->tkind = 0u;
        out->digest = 0u;
    }
    if (c->trace != NULL) {
        fprintf(c->trace, "end status=%u digest=%016llx steps=%llu\n", out->status, (unsigned long long)out->digest,
                (unsigned long long)out->steps);
    }

    for (i = 0u; i < c->n_touched; ++i) {
        c->pt[c->touched[i]] = NULL;
    }
    c->n_touched = 0u;
}
