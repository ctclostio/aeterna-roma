/*
 * lift_flagtest.c - checks the lifted runtime's integer helpers against the
 * host CPU.
 *
 * Default mode: for every arithmetic, logic, shift, rotate, multiply, divide
 * and bit instruction family and operand size, the real instruction is
 * executed on the host through a small code thunk for edge-case and random
 * operands and flag inputs, and the result registers and the six status
 * flags are compared with the C helpers in lift_rt.c. This is what pins the
 * "undefined" flag behaviour to the CPU the reference runs on.
 *
 * --exec mode: executes arbitrary register-only instruction bytes on the host
 * with given register and flag inputs and prints the outputs, so the lifter's
 * own instruction decoding can be compared end to end (selftest_lift.py).
 *
 *   lift_flagtest.exe [--cpu <logical cpu>] [--iters <n>] [--verbose]
 *   lift_flagtest.exe [--cpu <n>] --exec <vector file>
 *   lift_flagtest.exe [--cpu <n>] [--iters <n>] --dump <family> <bits>
 *
 * Without --cpu the process runs on the cores lift_pin_performance_cores
 * selects, like the runner. Undefined flags differ between the core types of
 * a hybrid CPU, so --cpu with an efficiency core is expected to report
 * mismatches.
 */
#include "lift_rt.h"

#include <immintrin.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct host_io {
    uint32_t a, b, n; /* eax, edx, ecx in */
    uint32_t fl_in;   /* packed flags, see lift_flags_pack */
    uint32_t ra, rb, rn;
    uint32_t fl_out;
} host_io;

typedef void (*host_fn)(host_io *io);

static uint8_t *g_code;      /* executable scratch page */
static uint32_t g_rng = 0x1234567u;

static uint32_t rnd(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

static const uint32_t k_edges[] = {
    0x00000000u, 0x00000001u, 0x00000002u, 0x00000003u, 0x0000000fu, 0x00000010u, 0x0000007fu, 0x00000080u,
    0x000000ffu, 0x00000100u, 0x00007fffu, 0x00008000u, 0x0000ffffu, 0x00010000u, 0x7fffffffu, 0x80000000u,
    0xffffffffu, 0xfffffffeu, 0x55555555u, 0xaaaaaaaau, 0x00ff00ffu, 0x80008080u, 0x7f7f7f7fu, 0xffff8000u,
    0xffffff80u, 0x000000feu, 0x0000fffeu, 0x40000000u, 0xc0000000u, 0x00004000u, 0x00000040u, 0x000000c0u,
};
#define N_EDGES (sizeof k_edges / sizeof k_edges[0])

static uint32_t operand(void) {
    uint32_t r = rnd();
    switch (r & 7u) {
    case 0u: return k_edges[(r >> 3) % N_EDGES];
    case 1u: return (r >> 3) & 0xffu;
    case 2u: return 0u - ((r >> 3) & 0xffu);
    default: return rnd();
    }
}

/* Packed flags hold SF ZF AF PF CF in bits 15,14,12,10,8 and OF in bit 0. */
#define FL_MASK 0xd501u

static uint32_t random_flags(void) {
    return (rnd() & FL_MASK) | 0x200u;
}

/* host thunk:  r8 = io; flags, eax, edx, ecx loaded; <insn>; outputs stored. */
static host_fn build_thunk(const uint8_t *insn, size_t len) {
    static const uint8_t pre[] = {
        0x49, 0x89, 0xc8,       /* mov r8, rcx */
        0x41, 0x8b, 0x40, 0x0c, /* mov eax, [r8+12] */
        0x04, 0x7f,             /* add al, 7fh      ; OF from bit 0 */
        0x9e,                   /* sahf */
        0x41, 0x8b, 0x00,       /* mov eax, [r8] */
        0x41, 0x8b, 0x50, 0x04, /* mov edx, [r8+4] */
        0x41, 0x8b, 0x48, 0x08, /* mov ecx, [r8+8] */
    };
    static const uint8_t post[] = {
        0x41, 0x89, 0x40, 0x10, /* mov [r8+16], eax */
        0x41, 0x89, 0x50, 0x14, /* mov [r8+20], edx */
        0x41, 0x89, 0x48, 0x18, /* mov [r8+24], ecx */
        0x0f, 0x90, 0xc0,       /* seto al */
        0x9f,                   /* lahf */
        0x41, 0x89, 0x40, 0x1c, /* mov [r8+28], eax */
        0xc3,                   /* ret */
    };
    uint8_t *p = g_code;
    memcpy(p, pre, sizeof pre);
    p += sizeof pre;
    memcpy(p, insn, len);
    p += len;
    memcpy(p, post, sizeof post);
    FlushInstructionCache(GetCurrentProcess(), g_code, 256u);
    return (host_fn)(void *)g_code;
}

/* Runs the thunk; returns 0 when the instruction raised a divide error. */
static int run_host(host_fn fn, host_io *io) {
    __try {
        fn(io);
    } __except (GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO || GetExceptionCode() == EXCEPTION_INT_OVERFLOW
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        return 0;
    }
    return 1;
}

/* ---- model side: the helper calls the lifter emits for each family ---------- */

enum {
    K_ADD, K_OR, K_ADC, K_SBB, K_AND, K_SUB, K_XOR, K_CMP, K_TEST,
    K_INC, K_DEC, K_NOT, K_NEG,
    K_ROL, K_ROR, K_ROLI, K_RORI, K_RCL, K_RCR, K_SHL, K_SHR, K_SAR,
    K_MUL, K_IMUL1, K_IMUL2, K_DIV, K_IDIV,
    K_BT, K_BTS, K_BTR, K_BTC, K_BSF, K_BSR,
    K_XADD, K_CMPXCHG, K_SHLD, K_SHRD, K_SETCC, K_CMOVCC,
};

static uint32_t reg_get(const lift_ctx *c, unsigned bits, unsigned reg) {
    return bits == 8u ? LIFT_R8L(reg) : bits == 16u ? LIFT_R16(reg) : c->r[reg];
}

static void reg_set(lift_ctx *c, unsigned bits, unsigned reg, uint32_t v) {
    if (bits == 8u) {
        LIFT_W8L(reg, v);
    } else if (bits == 16u) {
        LIFT_W16(reg, v);
    } else {
        c->r[reg] = v;
    }
}

#define BY_SIZE(name, args) (bits == 8u ? lift_##name##8 args : bits == 16u ? lift_##name##16 args : lift_##name##32 args)
#define BY_SIZE2(name, args) (bits == 16u ? lift_##name##16 args : lift_##name##32 args)

/* count_src: the shift count operand (CL, 1 or an immediate); imm: immediate
 * for the three-operand multiply; cc: condition code. */
static void model(lift_ctx *c, int kind, unsigned bits, uint32_t count, uint32_t cc) {
    uint32_t a = reg_get(c, bits, LM_EAX), b = reg_get(c, bits, LM_EDX);
    switch (kind) {
    case K_ADD: reg_set(c, bits, LM_EAX, BY_SIZE(add, (c, a, b))); break;
    case K_ADC: reg_set(c, bits, LM_EAX, BY_SIZE(adc, (c, a, b))); break;
    case K_SUB: reg_set(c, bits, LM_EAX, BY_SIZE(sub, (c, a, b))); break;
    case K_SBB: reg_set(c, bits, LM_EAX, BY_SIZE(sbb, (c, a, b))); break;
    case K_CMP: (void)BY_SIZE(sub, (c, a, b)); break;
    case K_OR: reg_set(c, bits, LM_EAX, BY_SIZE(logic, (c, a | b))); break;
    case K_AND: reg_set(c, bits, LM_EAX, BY_SIZE(logic, (c, a & b))); break;
    case K_XOR: reg_set(c, bits, LM_EAX, BY_SIZE(logic, (c, a ^ b))); break;
    case K_TEST: (void)BY_SIZE(logic, (c, a & b)); break;
    case K_INC: reg_set(c, bits, LM_EAX, BY_SIZE(inc, (c, a))); break;
    case K_DEC: reg_set(c, bits, LM_EAX, BY_SIZE(dec, (c, a))); break;
    case K_NOT: reg_set(c, bits, LM_EAX, ~a); break;
    case K_NEG: reg_set(c, bits, LM_EAX, BY_SIZE(neg, (c, a))); break;
    case K_ROL: reg_set(c, bits, LM_EAX, BY_SIZE(rol, (c, a, count))); break;
    case K_ROR: reg_set(c, bits, LM_EAX, BY_SIZE(ror, (c, a, count))); break;
    case K_ROLI: reg_set(c, bits, LM_EAX, BY_SIZE(roli, (c, a, count))); break;
    case K_RORI: reg_set(c, bits, LM_EAX, BY_SIZE(rori, (c, a, count))); break;
    case K_RCL: reg_set(c, bits, LM_EAX, BY_SIZE(rcl, (c, a, count))); break;
    case K_RCR: reg_set(c, bits, LM_EAX, BY_SIZE(rcr, (c, a, count))); break;
    case K_SHL: reg_set(c, bits, LM_EAX, BY_SIZE(shl, (c, a, count))); break;
    case K_SHR: reg_set(c, bits, LM_EAX, BY_SIZE(shr, (c, a, count))); break;
    case K_SAR: reg_set(c, bits, LM_EAX, BY_SIZE(sar, (c, a, count))); break;
    case K_MUL:
        if (bits == 8u) lift_mul8(c, b); else if (bits == 16u) lift_mul16(c, b); else lift_mul32(c, b);
        break;
    case K_IMUL1:
        if (bits == 8u) lift_imul1_8(c, b); else if (bits == 16u) lift_imul1_16(c, b); else lift_imul1_32(c, b);
        break;
    case K_IMUL2: reg_set(c, bits, LM_EAX, BY_SIZE2(imul, (c, count, b))); break; /* count carries the multiplicand */
    case K_DIV:
        if (bits == 8u) lift_div8(c, c->r[LM_ECX]); else if (bits == 16u) lift_div16(c, c->r[LM_ECX]); else lift_div32(c, c->r[LM_ECX]);
        break;
    case K_IDIV:
        if (bits == 8u) lift_idiv8(c, c->r[LM_ECX]); else if (bits == 16u) lift_idiv16(c, c->r[LM_ECX]); else lift_idiv32(c, c->r[LM_ECX]);
        break;
    case K_BT: lift_bt_flags(c, a >> (b & (bits - 1u))); break;
    case K_BTS: lift_bt_flags(c, a >> (b & (bits - 1u))); reg_set(c, bits, LM_EAX, a | (1u << (b & (bits - 1u)))); break;
    case K_BTR: lift_bt_flags(c, a >> (b & (bits - 1u))); reg_set(c, bits, LM_EAX, a & ~(1u << (b & (bits - 1u)))); break;
    case K_BTC: lift_bt_flags(c, a >> (b & (bits - 1u))); reg_set(c, bits, LM_EAX, a ^ (1u << (b & (bits - 1u)))); break;
    case K_BSF: reg_set(c, bits, LM_EAX, BY_SIZE2(bsf, (c, a, b))); break;
    case K_BSR: reg_set(c, bits, LM_EAX, BY_SIZE2(bsr, (c, a, b))); break;
    case K_XADD: {
        uint32_t sum = BY_SIZE(add, (c, a, b));
        reg_set(c, bits, LM_EDX, a);
        reg_set(c, bits, LM_EAX, sum);
        break;
    }
    case K_CMPXCHG: { /* cmpxchg dl, cl: accumulator eax, destination edx, source ecx */
        uint32_t dst = b;
        (void)BY_SIZE(sub, (c, a, dst));
        if (c->zf) {
            reg_set(c, bits, LM_EDX, reg_get(c, bits, LM_ECX));
        } else {
            reg_set(c, bits, LM_EAX, dst);
        }
        break;
    }
    case K_SHLD: reg_set(c, bits, LM_EAX, BY_SIZE2(shld, (c, a, b, count))); break;
    case K_SHRD: reg_set(c, bits, LM_EAX, BY_SIZE2(shrd, (c, a, b, count))); break;
    case K_SETCC: reg_set(c, 8u, LM_EAX, (uint32_t)(lift_cc(c, cc) != 0)); break;
    case K_CMOVCC:
        if (lift_cc(c, cc)) {
            reg_set(c, bits, LM_EAX, b);
        }
        break;
    default: break;
    }
}

/* ---- comparison -------------------------------------------------------------------- */

typedef struct tally {
    unsigned long long runs, bad;
    unsigned long long bad_reg, bad_fault;
    unsigned long long bad_flag[6]; /* CF PF AF ZF SF OF */
} tally;

static const uint32_t k_flag_bits[6] = {0x0100u, 0x0400u, 0x1000u, 0x4000u, 0x8000u, 0x0001u};
static const char *const k_flag_names[6] = {"CF", "PF", "AF", "ZF", "SF", "OF"};
static int g_verbose;
static unsigned long long g_total_bad, g_total_runs;

/* count_mode: 0 = count from CL, otherwise the fixed count the encoding implies. */
static void one(lift_ctx *c, host_fn fn, const char *name, int kind, unsigned bits, int fixed_count,
                uint32_t count_or_imm, uint32_t cc, host_io *io, tally *t) {
    volatile int model_fault = 0;
    int host_ok, i, bad = 0;
    uint32_t count = fixed_count ? count_or_imm : io->n;
    uint32_t fl_model;

    c->r[LM_EAX] = io->a;
    c->r[LM_EDX] = io->b;
    c->r[LM_ECX] = io->n;
    lift_flags_unpack(c, io->fl_in);
    c->fx_valid = 1u;
    if (setjmp(c->jb) == 0) {
        ((_JUMP_BUFFER *)c->jb)->Frame = 0u;
        model(c, kind, bits, count, cc);
    } else {
        model_fault = 1;
    }
    host_ok = run_host(fn, io);
    t->runs++;
    if (!host_ok || model_fault) {
        if (host_ok == model_fault) {
            t->bad_fault++;
            bad = 1;
        } else if (c->r[LM_EAX] != io->a || c->r[LM_EDX] != io->b || c->r[LM_ECX] != io->n) {
            /* A faulting divide must leave the registers alone. */
            t->bad_reg++;
            bad = 1;
        }
    } else {
        fl_model = lift_flags_pack(c);
        if (c->r[LM_EAX] != io->ra || c->r[LM_EDX] != io->rb || c->r[LM_ECX] != io->rn) {
            t->bad_reg++;
            bad = 1;
        }
        for (i = 0; i < 6; ++i) {
            if ((fl_model ^ io->fl_out) & k_flag_bits[i]) {
                t->bad_flag[i]++;
                bad = 1;
            }
        }
        if (bad && g_verbose && t->bad < 6u) {
            printf("  %s/%u a=%08x b=%08x n=%08x fl=%04x: host eax=%08x edx=%08x ecx=%08x fl=%04x | model eax=%08x "
                   "edx=%08x ecx=%08x fl=%04x\n",
                   name, bits, io->a, io->b, io->n, io->fl_in & FL_MASK, io->ra, io->rb, io->rn, io->fl_out & FL_MASK,
                   c->r[LM_EAX], c->r[LM_EDX], c->r[LM_ECX], fl_model & FL_MASK);
        }
    }
    if (bad) {
        t->bad++;
    }
}

static void report(const char *name, unsigned bits, const tally *t) {
    int i;
    g_total_bad += t->bad;
    g_total_runs += t->runs;
    if (t->bad == 0u && !g_verbose) {
        return;
    }
    printf("%-10s %2u  runs=%llu bad=%llu", name, bits, t->runs, t->bad);
    if (t->bad != 0u) {
        printf("  reg=%llu fault=%llu", t->bad_reg, t->bad_fault);
        for (i = 0; i < 6; ++i) {
            printf(" %s=%llu", k_flag_names[i], t->bad_flag[i]);
        }
    }
    printf("\n");
}

typedef struct family {
    const char *name;
    int kind;
    uint8_t op8[3], op16[4], op32[3]; /* encodings on al/ax/eax, dl/dx/edx, cl; 0-terminated by length */
    uint8_t len8, len16, len32;
    int uses_count; /* the instruction reads CL as a count */
} family;

static const family k_families[] = {
    {"add", K_ADD, {0x00, 0xd0}, {0x66, 0x01, 0xd0}, {0x01, 0xd0}, 2, 3, 2, 0},
    {"or", K_OR, {0x08, 0xd0}, {0x66, 0x09, 0xd0}, {0x09, 0xd0}, 2, 3, 2, 0},
    {"adc", K_ADC, {0x10, 0xd0}, {0x66, 0x11, 0xd0}, {0x11, 0xd0}, 2, 3, 2, 0},
    {"sbb", K_SBB, {0x18, 0xd0}, {0x66, 0x19, 0xd0}, {0x19, 0xd0}, 2, 3, 2, 0},
    {"and", K_AND, {0x20, 0xd0}, {0x66, 0x21, 0xd0}, {0x21, 0xd0}, 2, 3, 2, 0},
    {"sub", K_SUB, {0x28, 0xd0}, {0x66, 0x29, 0xd0}, {0x29, 0xd0}, 2, 3, 2, 0},
    {"xor", K_XOR, {0x30, 0xd0}, {0x66, 0x31, 0xd0}, {0x31, 0xd0}, 2, 3, 2, 0},
    {"cmp", K_CMP, {0x38, 0xd0}, {0x66, 0x39, 0xd0}, {0x39, 0xd0}, 2, 3, 2, 0},
    {"test", K_TEST, {0x84, 0xd0}, {0x66, 0x85, 0xd0}, {0x85, 0xd0}, 2, 3, 2, 0},
    {"inc", K_INC, {0xfe, 0xc0}, {0x66, 0xff, 0xc0}, {0xff, 0xc0}, 2, 3, 2, 0},
    {"dec", K_DEC, {0xfe, 0xc8}, {0x66, 0xff, 0xc8}, {0xff, 0xc8}, 2, 3, 2, 0},
    {"not", K_NOT, {0xf6, 0xd0}, {0x66, 0xf7, 0xd0}, {0xf7, 0xd0}, 2, 3, 2, 0},
    {"neg", K_NEG, {0xf6, 0xd8}, {0x66, 0xf7, 0xd8}, {0xf7, 0xd8}, 2, 3, 2, 0},
    {"rol", K_ROL, {0xd2, 0xc0}, {0x66, 0xd3, 0xc0}, {0xd3, 0xc0}, 2, 3, 2, 1},
    {"ror", K_ROR, {0xd2, 0xc8}, {0x66, 0xd3, 0xc8}, {0xd3, 0xc8}, 2, 3, 2, 1},
    {"rcl", K_RCL, {0xd2, 0xd0}, {0x66, 0xd3, 0xd0}, {0xd3, 0xd0}, 2, 3, 2, 1},
    {"rcr", K_RCR, {0xd2, 0xd8}, {0x66, 0xd3, 0xd8}, {0xd3, 0xd8}, 2, 3, 2, 1},
    {"shl", K_SHL, {0xd2, 0xe0}, {0x66, 0xd3, 0xe0}, {0xd3, 0xe0}, 2, 3, 2, 1},
    {"shr", K_SHR, {0xd2, 0xe8}, {0x66, 0xd3, 0xe8}, {0xd3, 0xe8}, 2, 3, 2, 1},
    {"sal", K_SHL, {0xd2, 0xf0}, {0x66, 0xd3, 0xf0}, {0xd3, 0xf0}, 2, 3, 2, 1},
    {"sar", K_SAR, {0xd2, 0xf8}, {0x66, 0xd3, 0xf8}, {0xd3, 0xf8}, 2, 3, 2, 1},
    {"mul", K_MUL, {0xf6, 0xe2}, {0x66, 0xf7, 0xe2}, {0xf7, 0xe2}, 2, 3, 2, 0},
    {"imul1", K_IMUL1, {0xf6, 0xea}, {0x66, 0xf7, 0xea}, {0xf7, 0xea}, 2, 3, 2, 0},
    {"div", K_DIV, {0xf6, 0xf1}, {0x66, 0xf7, 0xf1}, {0xf7, 0xf1}, 2, 3, 2, 0},
    {"idiv", K_IDIV, {0xf6, 0xf9}, {0x66, 0xf7, 0xf9}, {0xf7, 0xf9}, 2, 3, 2, 0},
    {"bt", K_BT, {0}, {0x66, 0x0f, 0xa3, 0xd0}, {0x0f, 0xa3, 0xd0}, 0, 4, 3, 0},
    {"bts", K_BTS, {0}, {0x66, 0x0f, 0xab, 0xd0}, {0x0f, 0xab, 0xd0}, 0, 4, 3, 0},
    {"btr", K_BTR, {0}, {0x66, 0x0f, 0xb3, 0xd0}, {0x0f, 0xb3, 0xd0}, 0, 4, 3, 0},
    {"btc", K_BTC, {0}, {0x66, 0x0f, 0xbb, 0xd0}, {0x0f, 0xbb, 0xd0}, 0, 4, 3, 0},
    {"bsf", K_BSF, {0}, {0x66, 0x0f, 0xbc, 0xc2}, {0x0f, 0xbc, 0xc2}, 0, 4, 3, 0},
    {"bsr", K_BSR, {0}, {0x66, 0x0f, 0xbd, 0xc2}, {0x0f, 0xbd, 0xc2}, 0, 4, 3, 0},
    {"xadd", K_XADD, {0x0f, 0xc0, 0xd0}, {0x66, 0x0f, 0xc1, 0xd0}, {0x0f, 0xc1, 0xd0}, 3, 4, 3, 0},
    {"cmpxchg", K_CMPXCHG, {0x0f, 0xb0, 0xca}, {0x66, 0x0f, 0xb1, 0xca}, {0x0f, 0xb1, 0xca}, 3, 4, 3, 0},
    {"shld", K_SHLD, {0}, {0x66, 0x0f, 0xa5, 0xd0}, {0x0f, 0xa5, 0xd0}, 0, 4, 3, 1},
    {"shrd", K_SHRD, {0}, {0x66, 0x0f, 0xad, 0xd0}, {0x0f, 0xad, 0xd0}, 0, 4, 3, 1},
};

static void fill_inputs(host_io *io, int kind, unsigned bits, int uses_count, unsigned long long i) {
    io->a = operand();
    io->b = operand();
    io->n = uses_count ? ((i & 1u) ? rnd() & 0xffu : rnd() & 0x3fu) : operand();
    io->fl_in = random_flags();
    if ((kind == K_DIV || kind == K_IDIV) && (i & 3u) != 0u) {
        /* Mostly dividends that fit, so the non-faulting path gets coverage. */
        if (bits == 32u) {
            io->b = (kind == K_IDIV) ? (uint32_t)((int32_t)io->a >> 31) : ((i & 4u) ? 0u : rnd() % ((io->n | 1u)));
        } else if (bits == 16u) {
            io->b = (kind == K_IDIV) ? (uint32_t)((int32_t)(int16_t)io->a >> 15) : ((i & 4u) ? 0u : rnd() % ((io->n & 0xffffu) | 1u));
        } else {
            io->a = (kind == K_IDIV) ? (uint32_t)(int32_t)(int8_t)io->a : ((i & 4u) ? io->a & 0xffu : io->a & 0x7fffu);
        }
    }
}

static void run_family(lift_ctx *c, const family *f, unsigned bits, unsigned long long iters) {
    const uint8_t *enc = bits == 8u ? f->op8 : bits == 16u ? f->op16 : f->op32;
    size_t len = bits == 8u ? f->len8 : bits == 16u ? f->len16 : f->len32;
    host_fn fn;
    host_io io;
    tally t;
    unsigned long long i;
    size_t x, y;
    if (len == 0u) {
        return;
    }
    memset(&t, 0, sizeof t);
    fn = build_thunk(enc, len);
    /* Exhaustive edge pairs, with every count for the count-taking families. */
    for (x = 0u; x < N_EDGES; ++x) {
        for (y = 0u; y < N_EDGES; ++y) {
            unsigned n, n_hi = f->uses_count ? 72u : 4u;
            for (n = 0u; n < n_hi; ++n) {
                io.a = k_edges[x];
                io.b = k_edges[y];
                io.n = f->uses_count ? n : k_edges[(x + y + n) % N_EDGES];
                io.fl_in = random_flags();
                one(c, fn, f->name, f->kind, bits, 0, 0u, 0u, &io, &t);
            }
        }
    }
    for (i = 0u; i < iters; ++i) {
        fill_inputs(&io, f->kind, bits, f->uses_count, i);
        one(c, fn, f->name, f->kind, bits, 0, 0u, 0u, &io, &t);
    }
    report(f->name, bits, &t);
}

/* Shift/rotate group with the count in the encoding: D0/D1 (by one) and
 * C0/C1 ib (immediate). ext is the ModRM /digit. */
static void run_shift_fixed(lift_ctx *c, const char *name, int kind, unsigned ext, unsigned bits,
                            unsigned long long iters) {
    static const uint8_t k_counts[] = {0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 63, 64, 65, 0x80, 0xff};
    char label[32];
    size_t k;
    for (k = 0u; k <= sizeof k_counts; ++k) {
        uint8_t enc[5];
        size_t len = 0u;
        uint32_t count = k == sizeof k_counts ? 1u : k_counts[k];
        host_fn fn;
        host_io io;
        tally t;
        unsigned long long i;
        memset(&t, 0, sizeof t);
        if (bits == 16u) {
            enc[len++] = 0x66;
        }
        if (k == sizeof k_counts) { /* the by-one opcode */
            enc[len++] = bits == 8u ? 0xd0 : 0xd1;
            enc[len++] = (uint8_t)(0xc0u | (ext << 3));
            snprintf(label, sizeof label, "%s,1", name);
        } else {
            enc[len++] = bits == 8u ? 0xc0 : 0xc1;
            enc[len++] = (uint8_t)(0xc0u | (ext << 3));
            enc[len++] = (uint8_t)count;
            snprintf(label, sizeof label, "%s,i%u", name, count);
        }
        fn = build_thunk(enc, len);
        for (i = 0u; i < iters; ++i) {
            fill_inputs(&io, kind, bits, 0, i);
            one(c, fn, label, kind, bits, 1, count, 0u, &io, &t);
        }
        report(label, bits, &t);
    }
}

static void run_shiftd_fixed(lift_ctx *c, const char *name, int kind, uint8_t opcode, unsigned bits,
                             unsigned long long iters) {
    static const uint8_t k_counts[] = {0, 1, 2, 7, 8, 15, 16, 17, 24, 31, 32, 33, 0xff};
    char label[32];
    size_t k;
    for (k = 0u; k < sizeof k_counts; ++k) {
        uint8_t enc[6];
        size_t len = 0u;
        host_fn fn;
        host_io io;
        tally t;
        unsigned long long i;
        memset(&t, 0, sizeof t);
        if (bits == 16u) {
            enc[len++] = 0x66;
        }
        enc[len++] = 0x0f;
        enc[len++] = opcode; /* A4: shld r/m, r, ib   AC: shrd r/m, r, ib */
        enc[len++] = 0xd0;
        enc[len++] = k_counts[k];
        snprintf(label, sizeof label, "%s,i%u", name, k_counts[k]);
        fn = build_thunk(enc, len);
        for (i = 0u; i < iters; ++i) {
            fill_inputs(&io, kind, bits, 0, i);
            one(c, fn, label, kind, bits, 1, k_counts[k], 0u, &io, &t);
        }
        report(label, bits, &t);
    }
}

/* imul r, r/m and imul r, r/m, imm: eax = edx * (eax | imm). */
static void run_imul(lift_ctx *c, unsigned bits, unsigned long long iters) {
    static const uint32_t k_imms[] = {0u, 1u, 2u, 3u, 0x7fu, 0xffffff80u, 0xffffffffu, 0x100u, 0x7fffu, 0xffff8000u,
                                      0x12345678u, 0x80000000u, 0x7fffffffu};
    size_t k;
    for (k = 0u; k <= sizeof k_imms / sizeof k_imms[0]; ++k) {
        uint8_t enc[8];
        size_t len = 0u;
        char label[32];
        host_fn fn;
        host_io io;
        tally t;
        unsigned long long i;
        int fixed = k != 0u;
        uint32_t imm = fixed ? k_imms[k - 1u] : 0u;
        memset(&t, 0, sizeof t);
        if (bits == 16u) {
            enc[len++] = 0x66;
        }
        if (!fixed) {
            enc[len++] = 0x0f;
            enc[len++] = 0xaf;
            enc[len++] = 0xc2;
            snprintf(label, sizeof label, "imul2");
        } else if ((uint32_t)(int32_t)(int8_t)imm == imm) {
            enc[len++] = 0x6b;
            enc[len++] = 0xc2;
            enc[len++] = (uint8_t)imm;
            snprintf(label, sizeof label, "imul3,%x", imm);
        } else {
            enc[len++] = 0x69;
            enc[len++] = 0xc2;
            enc[len++] = (uint8_t)imm;
            enc[len++] = (uint8_t)(imm >> 8);
            if (bits == 32u) {
                enc[len++] = (uint8_t)(imm >> 16);
                enc[len++] = (uint8_t)(imm >> 24);
            }
            snprintf(label, sizeof label, "imul3,%x", imm);
        }
        fn = build_thunk(enc, len);
        for (i = 0u; i < iters; ++i) {
            fill_inputs(&io, K_IMUL2, bits, 0, i);
            /* The model multiplies edx by "count": the immediate, or eax for the two-operand form. */
            one(c, fn, label, K_IMUL2, bits, 1, fixed ? imm : io.a, 0u, &io, &t);
        }
        report(label, bits, &t);
    }
}

/* SETcc and CMOVcc for every condition and every combination of the six flags. */
static void run_conditions(lift_ctx *c) {
    unsigned cc, combo, bit;
    tally t;
    memset(&t, 0, sizeof t);
    for (cc = 0u; cc < 16u; ++cc) {
        uint8_t set_enc[3] = {0x0f, (uint8_t)(0x90u + cc), 0xc0};
        uint8_t cmov_enc[3] = {0x0f, (uint8_t)(0x40u + cc), 0xc2};
        uint8_t cmov16_enc[4] = {0x66, 0x0f, (uint8_t)(0x40u + cc), 0xc2};
        int form;
        for (form = 0; form < 3; ++form) {
            host_fn fn = form == 0 ? build_thunk(set_enc, 3u) : form == 1 ? build_thunk(cmov_enc, 3u) : build_thunk(cmov16_enc, 4u);
            for (combo = 0u; combo < 64u; ++combo) {
                host_io io;
                io.a = rnd();
                io.b = rnd();
                io.n = rnd();
                io.fl_in = 0x200u;
                for (bit = 0u; bit < 6u; ++bit) {
                    if (combo & (1u << bit)) {
                        io.fl_in |= k_flag_bits[bit];
                    }
                }
                one(c, fn, form == 0 ? "setcc" : "cmovcc", form == 0 ? K_SETCC : K_CMOVCC, form == 2 ? 16u : 32u, 1, 0u, cc,
                    &io, &t);
            }
        }
    }
    report("setcc/cmov", 0u, &t);
}

static int run_families(lift_ctx *c, unsigned long long iters) {
    static const unsigned k_sizes[3] = {8u, 16u, 32u};
    static const struct { const char *name; int kind; unsigned ext; } k_shifts[] = {
        {"rol", K_ROLI, 0u}, {"ror", K_RORI, 1u}, {"rcl", K_RCL, 2u}, {"rcr", K_RCR, 3u},
        {"shl", K_SHL, 4u}, {"shr", K_SHR, 5u}, {"sal", K_SHL, 6u}, {"sar", K_SAR, 7u},
    };
    size_t f, s, k;
    for (f = 0u; f < sizeof k_families / sizeof k_families[0]; ++f) {
        for (s = 0u; s < 3u; ++s) {
            run_family(c, &k_families[f], k_sizes[s], iters);
        }
    }
    for (k = 0u; k < sizeof k_shifts / sizeof k_shifts[0]; ++k) {
        for (s = 0u; s < 3u; ++s) {
            run_shift_fixed(c, k_shifts[k].name, k_shifts[k].kind, k_shifts[k].ext, k_sizes[s], iters / 8u + 1u);
        }
    }
    for (s = 1u; s < 3u; ++s) {
        run_shiftd_fixed(c, "shld", K_SHLD, 0xa4, k_sizes[s], iters / 8u + 1u);
        run_shiftd_fixed(c, "shrd", K_SHRD, 0xac, k_sizes[s], iters / 8u + 1u);
        run_imul(c, k_sizes[s], iters / 4u + 1u);
    }
    run_conditions(c);
    printf("flagtest: %llu comparisons, %llu mismatches\n", g_total_runs, g_total_bad);
    return g_total_bad == 0u ? 0 : 1;
}

/* ---- --exec: run instruction bytes on the host -------------------------------------
 * Vector line:  <hex bytes> <eax> <ecx> <edx> <ebx> <esi> <edi> <packed flags>
 * Output line:  <eax> <ecx> <edx> <ebx> <esi> <edi> <packed flags>   or   FAULT
 * The instruction may use only those six registers. */

typedef struct exec_io {
    uint32_t r[6];  /* eax ecx edx ebx esi edi */
    uint32_t fl;    /* in and out */
    uint32_t pad;
    uint64_t save[3]; /* host rbx rsi rdi */
} exec_io;

typedef void (*exec_fn)(exec_io *io);

static exec_fn build_exec(const uint8_t *insn, size_t len) {
    static const uint8_t pre[] = {
        0x49, 0x89, 0xc8,             /* mov r8, rcx */
        0x49, 0x89, 0x58, 0x20,       /* mov [r8+32], rbx */
        0x49, 0x89, 0x70, 0x28,       /* mov [r8+40], rsi */
        0x49, 0x89, 0x78, 0x30,       /* mov [r8+48], rdi */
        0x41, 0x8b, 0x40, 0x18,       /* mov eax, [r8+24] */
        0x04, 0x7f,                   /* add al, 7fh */
        0x9e,                         /* sahf */
        0x41, 0x8b, 0x00,             /* mov eax, [r8] */
        0x41, 0x8b, 0x48, 0x04,       /* mov ecx, [r8+4] */
        0x41, 0x8b, 0x50, 0x08,       /* mov edx, [r8+8] */
        0x41, 0x8b, 0x58, 0x0c,       /* mov ebx, [r8+12] */
        0x41, 0x8b, 0x70, 0x10,       /* mov esi, [r8+16] */
        0x41, 0x8b, 0x78, 0x14,       /* mov edi, [r8+20] */
    };
    static const uint8_t post[] = {
        0x41, 0x89, 0x00,             /* mov [r8], eax */
        0x41, 0x89, 0x48, 0x04,       /* mov [r8+4], ecx */
        0x41, 0x89, 0x50, 0x08,       /* mov [r8+8], edx */
        0x41, 0x89, 0x58, 0x0c,       /* mov [r8+12], ebx */
        0x41, 0x89, 0x70, 0x10,       /* mov [r8+16], esi */
        0x41, 0x89, 0x78, 0x14,       /* mov [r8+20], edi */
        0x0f, 0x90, 0xc0,             /* seto al */
        0x9f,                         /* lahf */
        0x41, 0x89, 0x40, 0x18,       /* mov [r8+24], eax */
        0x49, 0x8b, 0x58, 0x20,       /* mov rbx, [r8+32] */
        0x49, 0x8b, 0x70, 0x28,       /* mov rsi, [r8+40] */
        0x49, 0x8b, 0x78, 0x30,       /* mov rdi, [r8+48] */
        0xc3,                         /* ret */
    };
    uint8_t *p = g_code;
    memcpy(p, pre, sizeof pre);
    p += sizeof pre;
    memcpy(p, insn, len);
    p += len;
    memcpy(p, post, sizeof post);
    FlushInstructionCache(GetCurrentProcess(), g_code, 256u);
    return (exec_fn)(void *)g_code;
}

/* The filter runs before any unwinding, so the callee-saved registers the
 * thunk borrowed can be put back from the save slots there. */
static exec_io *g_exec_io;

static int exec_filter(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_INT_DIVIDE_BY_ZERO && code != EXCEPTION_INT_OVERFLOW && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_PRIV_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ep->ContextRecord->Rbx = g_exec_io->save[0];
    ep->ContextRecord->Rsi = g_exec_io->save[1];
    ep->ContextRecord->Rdi = g_exec_io->save[2];
    /* Return to the thunk's caller as if the thunk had returned. */
    ep->ContextRecord->Rip = *(DWORD64 *)(uintptr_t)ep->ContextRecord->Rsp;
    ep->ContextRecord->Rsp += 8u;
    g_exec_io->pad = 1u;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG CALLBACK exec_veh(EXCEPTION_POINTERS *ep) {
    DWORD64 rip = ep->ContextRecord->Rip;
    if (g_exec_io == NULL || rip < (DWORD64)(uintptr_t)g_code || rip >= (DWORD64)(uintptr_t)g_code + 256u) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return (LONG)exec_filter(ep);
}

static int run_exec(const char *path) {
    FILE *f = fopen(path, "r");
    char line[512];
    if (f == NULL) {
        fprintf(stderr, "flagtest: cannot open %s\n", path);
        return 2;
    }
    AddVectoredExceptionHandler(1u, exec_veh);
    while (fgets(line, sizeof line, f) != NULL) {
        char hex[64];
        uint8_t insn[16];
        exec_io io;
        size_t len, i;
        memset(&io, 0, sizeof io);
        if (sscanf(line, "%63s %x %x %x %x %x %x %x", hex, &io.r[0], &io.r[1], &io.r[2], &io.r[3], &io.r[4], &io.r[5],
                   &io.fl) != 8) {
            continue;
        }
        len = strlen(hex) / 2u;
        if (len == 0u || len > sizeof insn) {
            printf("BAD\n");
            continue;
        }
        for (i = 0u; i < len; ++i) {
            unsigned byte = 0u;
            sscanf(hex + 2u * i, "%2x", &byte);
            insn[i] = (uint8_t)byte;
        }
        g_exec_io = &io;
        build_exec(insn, len)(&io);
        g_exec_io = NULL;
        if (io.pad) {
            printf("FAULT\n");
        } else {
            printf("%08x %08x %08x %08x %08x %08x %04x\n", io.r[0], io.r[1], io.r[2], io.r[3], io.r[4], io.r[5],
                   io.fl & FL_MASK);
        }
    }
    fclose(f);
    return 0;
}

/* --dump: raw host results for one family, for studying undefined flags.
 * Line: a b n fl_in -> eax edx ecx fl_out (FAULT when the divide trapped). */
static int run_dump(const char *name, unsigned bits, unsigned long long iters) {
    size_t f;
    if (bits == 0u) { /* name is the instruction as hex bytes */
        uint8_t insn[16];
        size_t len = strlen(name) / 2u, k;
        unsigned long long i;
        host_fn fn;
        if (len == 0u || len > sizeof insn) {
            return 2;
        }
        for (k = 0u; k < len; ++k) {
            unsigned byte = 0u;
            sscanf(name + 2u * k, "%2x", &byte);
            insn[k] = (uint8_t)byte;
        }
        fn = build_thunk(insn, len);
        for (i = 0u; i < iters; ++i) {
            host_io io;
            fill_inputs(&io, K_ADD, 32u, 0, i);
            if (run_host(fn, &io)) {
                printf("%08x %08x %08x %04x %08x %08x %08x %04x\n", io.a, io.b, io.n, io.fl_in & FL_MASK, io.ra, io.rb,
                       io.rn, io.fl_out & FL_MASK);
            }
        }
        return 0;
    }
    for (f = 0u; f < sizeof k_families / sizeof k_families[0]; ++f) {
        const family *fam = &k_families[f];
        const uint8_t *enc = bits == 8u ? fam->op8 : bits == 16u ? fam->op16 : fam->op32;
        size_t len = bits == 8u ? fam->len8 : bits == 16u ? fam->len16 : fam->len32;
        unsigned long long i;
        host_fn fn;
        if (strcmp(fam->name, name) != 0 || len == 0u) {
            continue;
        }
        fn = build_thunk(enc, len);
        for (i = 0u; i < iters; ++i) {
            host_io io;
            fill_inputs(&io, fam->kind, bits, fam->uses_count, i);
            if (run_host(fn, &io)) {
                printf("%08x %08x %08x %04x %08x %08x %08x %04x\n", io.a, io.b, io.n, io.fl_in & FL_MASK, io.ra, io.rb,
                       io.rn, io.fl_out & FL_MASK);
            } else {
                printf("%08x %08x %08x %04x FAULT\n", io.a, io.b, io.n, io.fl_in & FL_MASK);
            }
        }
        return 0;
    }
    fprintf(stderr, "flagtest: no family %s/%u\n", name, bits);
    return 2;
}

int main(int argc, char **argv) {
    unsigned long long iters = 20000u;
    const char *exec_path = NULL;
    const char *dump_name = NULL;
    unsigned dump_bits = 32u;
    lift_ctx *c;
    int i, rc;
    /* Same cores as the runner unless --cpu names one. */
    lift_pin_performance_cores();
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--cpu") == 0 && i + 1 < argc) {
            DWORD_PTR mask = (DWORD_PTR)1 << strtoul(argv[++i], NULL, 10);
            if (SetProcessAffinityMask(GetCurrentProcess(), mask) == 0) {
                fprintf(stderr, "flagtest: cannot pin to cpu %s\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--exec") == 0 && i + 1 < argc) {
            exec_path = argv[++i];
        } else if (strcmp(argv[i], "--dump") == 0 && i + 2 < argc) {
            dump_name = argv[++i];
            dump_bits = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else {
            fprintf(stderr, "usage: lift_flagtest [--cpu n] [--iters n] [--verbose] [--exec file] [--dump family bits]\n");
            return 2;
        }
    }
    g_code = VirtualAlloc(NULL, 4096u, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (g_code == NULL) {
        fprintf(stderr, "flagtest: cannot allocate executable memory\n");
        return 2;
    }
    if (exec_path != NULL) {
        return run_exec(exec_path);
    }
    if (dump_name != NULL) {
        return run_dump(dump_name, dump_bits, iters);
    }
    c = lift_ctx_create();
    c->host_mxcsr = _mm_getcsr();
    _fxsave64(c->host_fx);
    rc = run_families(c, iters);
    lift_ctx_destroy(c);
    return rc;
}
