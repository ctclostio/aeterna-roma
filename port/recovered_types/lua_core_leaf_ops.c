#include "lua_core_leaf_ops.h"
#include "startup_crt_strtod_setjmp_ops.h"

#include <ctype.h>
#include <string.h>

static const rome2_lua_tvalue_32 k_nil_object = { 0u, ROME2_LUA_TNIL };
static const rome2_lua_node_32 k_dummy_node = {
    { 0u, ROME2_LUA_TNIL },
    { 0u, ROME2_LUA_TNIL },
    0u
};

/* Pinned image byte table from 0x11846c30[256] (used by 0x10f46280 luaO_log2) */
static const uint8_t k_log2_table_256[256] = {
    0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
};

/* Pinned image byte table from 0x11847350[38] (used by 0x10f47870 symbexec) */
static const uint8_t k_luaP_opmodes[38] = {
    0x60u, 0x71u, 0x54u, 0x60u, 0x50u, 0x71u, 0x6cu, 0x31u,
    0x10u, 0x3cu, 0x54u, 0x6cu, 0x7cu, 0x7cu, 0x7cu, 0x7cu,
    0x7cu, 0x7cu, 0x60u, 0x60u, 0x60u, 0x68u, 0x22u, 0xbcu,
    0xbcu, 0xbcu, 0xe4u, 0xe4u, 0x54u, 0x54u, 0x10u, 0x62u,
    0x62u, 0x84u, 0x14u, 0x00u, 0x51u, 0x50u
};

static float bits_to_f32(uint32_t u) {
    float f = 0.0f;
    memcpy(&f, &u, sizeof(f));
    return f;
}

static uint32_t f32_to_bits(float f) {
    uint32_t u = 0u;
    memcpy(&u, &f, sizeof(u));
    return u;
}

void rome2_l75_arena_init(rome2_l75_arena *a, uint32_t base_va, uint8_t *bytes, uint32_t size) {
    if (a == NULL) {
        return;
    }
    a->base_va = base_va;
    a->bytes = bytes;
    a->size = size;
    a->ro_nil = &k_nil_object;
    a->ro_dummy = &k_dummy_node;
}

void *rome2_l75_mut_ptr(const rome2_l75_arena *a, uint32_t va, uint32_t bytes) {
    uint32_t off;
    if (a == NULL || a->bytes == NULL || va < a->base_va) {
        return NULL;
    }
    off = va - a->base_va;
    if (off > a->size || bytes > (a->size - off)) {
        return NULL;
    }
    return a->bytes + off;
}

const void *rome2_l75_const_ptr(const rome2_l75_arena *a, uint32_t va, uint32_t bytes) {
    if (va == ROME2_LUA_VA_NILOBJECT && bytes <= sizeof(k_nil_object)) {
        return (a != NULL && a->ro_nil != NULL) ? a->ro_nil : &k_nil_object;
    }
    if (va == ROME2_LUA_VA_DUMMYNODE && bytes <= sizeof(k_dummy_node)) {
        return (a != NULL && a->ro_dummy != NULL) ? a->ro_dummy : &k_dummy_node;
    }
    return rome2_l75_mut_ptr(a, va, bytes);
}

const char *rome2_l75_cstr_at(const rome2_l75_arena *a, uint32_t va) {
    uint32_t off;
    uint32_t i;
    switch (va) {
        case ROME2_LUA_VA_EMPTY: return "";
        case ROME2_LUA_VA_STR_C: return "C";
        case ROME2_LUA_VA_STR_MAIN: return "main";
        case ROME2_LUA_VA_STR_GLOBAL: return "global";
        case ROME2_LUA_VA_STR_TAIL: return "tail";
        case ROME2_LUA_VA_STR_QMARK: return "?";
        case ROME2_LUA_VA_STR_METHOD: return "method";
        case ROME2_LUA_VA_STR_TEMP: return "(*temporary)";
        case ROME2_LUA_VA_STR_EQC: return "=[C]";
        case ROME2_LUA_VA_STR_LUA: return "Lua";
        case ROME2_LUA_VA_STR_TAILCALL: return "=(tail call)";
        case ROME2_LUA_VA_STR_LOCAL: return "local";
        case ROME2_LUA_VA_STR_FIELD: return "field";
        case ROME2_LUA_VA_STR_UPVALUE: return "upvalue";
        default: break;
    }
    if (a == NULL || a->bytes == NULL || va < a->base_va) {
        return NULL;
    }
    off = va - a->base_va;
    if (off >= a->size) {
        return NULL;
    }
    for (i = off; i < a->size; ++i) {
        if (a->bytes[i] == 0u) {
            return (const char *)(a->bytes + off);
        }
    }
    return NULL;
}

/* 0x10f43cb0 */
void rome2_l75_luaA_pushobject(rome2_l75_arena *a, uint32_t l_va, const rome2_lua_tvalue_32 *o) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    rome2_lua_tvalue_32 *slot;
    if (L == NULL || o == NULL) {
        return;
    }
    slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*slot));
    if (slot == NULL) {
        return;
    }
    *slot = *o;
    L->top_va += (uint32_t)sizeof(rome2_lua_tvalue_32);
}

/* 0x10f460e0 */
void rome2_l75_luaO_chunkid(char *out, const char *source, size_t bufflen) {
    if (out == NULL || source == NULL || bufflen == 0u) {
        return;
    }
    if (*source == '=') {
        rome2_l74_strncpy(out, source + 1u, bufflen);
        out[bufflen - 1u] = '\0';
        return;
    }
    if (*source == '@') {
        size_t l = strlen(source + 1u);
        const char *p = source + 1u;
        out[0] = '\0';
        if (bufflen > 8u && l > (bufflen - 8u)) {
            p += l - (bufflen - 8u);
            rome2_l74_strncat(out, "...", 4u);
        }
        rome2_l74_strncat(out, p, bufflen - 1u - strlen(out));
        return;
    }
    {
        size_t len = rome2_l74_strcspn(source, "\n\r");
        size_t cap = (bufflen > 17u) ? (bufflen - 17u) : 0u;
        if (len > cap) {
            len = cap;
        }
        memcpy(out, "[string \"", 10u);
        if (source[len] == '\0') {
            rome2_l74_strncat(out, source, len + 1u);
        } else {
            rome2_l74_strncat(out, source, len);
            rome2_l74_strncat(out, "...", 4u);
        }
        rome2_l74_strncat(out, "\"]", 3u);
    }
}

/* 0x10f46230 */
uint32_t rome2_l75_luaO_fb2int(uint32_t x) {
    uint32_t e = (x >> 3) & 0x1fu;
    if (e == 0u) {
        return x;
    }
    return ((x & 7u) + 8u) << ((e - 1u) & 0x1fu);
}

/* 0x10f46280 */
int32_t rome2_l75_luaO_log2(uint32_t x) {
    int32_t l = -1;
    while (x >= 0x100u) {
        l += 8;
        x >>= 8;
    }
    return l + (int32_t)k_log2_table_256[x & 0xffu];
}

/* 0x10f46610 */
int32_t rome2_l75_luaO_rawequalObj(const rome2_lua_tvalue_32 *t1, const rome2_lua_tvalue_32 *t2) {
    if (t1 == NULL || t2 == NULL || t1->tt != t2->tt) {
        return 0;
    }
    if (t1->tt == ROME2_LUA_TNIL) {
        return 1;
    }
    if (t1->tt == ROME2_LUA_TNUMBER) {
        return bits_to_f32(t1->value_u32) == bits_to_f32(t2->value_u32) ? 1 : 0;
    }
    return (t1->value_u32 == t2->value_u32) ? 1 : 0;
}

/* 0x10f46670 */
int32_t rome2_l75_luaO_str2d(const char *s, float *out_num) {
    const char *endptr = NULL;
    int32_t err = 0;
    double d;
    if (s == NULL || out_num == NULL) {
        return 0;
    }
    d = rome2_l74_strtod(s, &endptr, NULL, &err);
    *out_num = (float)d;
    if (endptr == s) {
        return 0;
    }
    if (*endptr == 'x' || *endptr == 'X') {
        uint32_t u = rome2_l74_strtoul(s, &endptr, 16, &err);
        *out_num = (float)u;
    }
    while (*endptr != '\0' && isspace((unsigned char)*endptr)) {
        ++endptr;
    }
    return (*endptr == '\0') ? 1 : 0;
}

/* 0x10f46c40 */
void rome2_l75_preinit_state(rome2_l75_arena *a, uint32_t l_va, uint32_t g_va) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    if (L == NULL) {
        return;
    }
    L->l_g_va = g_va;
    L->stack_va = 0u;
    L->stacksize = 0;
    L->error_jmp_va = 0u;
    L->hook_va = 0u;
    L->nCcalls = 0u;
    L->hookmask = 0u;
    L->allowhook = 1u;
    L->basehookcount = 0;
    L->hookcount = 0;
    L->openupval_va = 0u;
    L->size_ci = 0;
    L->status = 0u;
    L->ci_va = 0u;
    L->base_ci_va = 0u;
    L->savedpc_va = 0u;
    L->errfunc = 0;
    L->l_gt.tt = ROME2_LUA_TNIL;
}

/* 0x10f46fc0 */
int32_t rome2_l75_checkArgMode(const rome2_lua_proto_32 *pt, uint32_t r, int32_t mode) {
    if (pt == NULL) {
        return 0;
    }
    if (mode == 0) {
        return (r == 0u) ? 1 : 0;
    }
    if (mode == 2) {
        return ((int32_t)r < (int32_t)pt->maxstacksize) ? 1 : 0;
    }
    if (mode == 3) {
        if ((r & 0x100u) == 0u) {
            return ((int32_t)r < (int32_t)pt->maxstacksize) ? 1 : 0;
        }
        return ((int32_t)(r & 0xfffffeffu) < pt->sizek) ? 1 : 0;
    }
    return 1;
}

/* 0x10f47070 */
int32_t rome2_l75_currentpc(rome2_l75_arena *a, uint32_t l_va, uint32_t ci_va) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    rome2_lua_callinfo_32 *ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(a, ci_va, sizeof(*ci));
    const rome2_lua_tvalue_32 *fn_val;
    const rome2_lua_closure_hdr_32 *cl;
    const rome2_lua_proto_32 *pt;
    int32_t pc_bytes;
    if (L == NULL || ci == NULL) {
        return -1;
    }
    fn_val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, ci->func_va, sizeof(*fn_val));
    if (fn_val == NULL || fn_val->tt != ROME2_LUA_TFUNCTION) {
        return -1;
    }
    cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, fn_val->value_u32, sizeof(*cl));
    if (cl == NULL || cl->isC != 0u) {
        return -1;
    }
    pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(a, cl->f_or_p_va, sizeof(*pt));
    if (pt == NULL) {
        return -1;
    }
    if (ci_va == L->ci_va) {
        ci->savedpc_va = L->savedpc_va;
    }
    pc_bytes = (int32_t)(ci->savedpc_va - pt->code_va);
    return (pc_bytes >> 2) - 1;
}

/* 0x10f47020 */
int32_t rome2_l75_currentline(rome2_l75_arena *a, uint32_t l_va, uint32_t ci_va) {
    const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(a, ci_va, sizeof(*ci));
    const rome2_lua_tvalue_32 *fn_val;
    const rome2_lua_closure_hdr_32 *cl;
    const rome2_lua_proto_32 *pt;
    int32_t pc = rome2_l75_currentpc(a, l_va, ci_va);
    const int32_t *line_ptr;
    if (pc < 0 || ci == NULL) {
        return -1;
    }
    fn_val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, ci->func_va, sizeof(*fn_val));
    if (fn_val == NULL) {
        return -1;
    }
    cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, fn_val->value_u32, sizeof(*cl));
    if (cl == NULL) {
        return -1;
    }
    pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(a, cl->f_or_p_va, sizeof(*pt));
    if (pt == NULL) {
        return -1;
    }
    if (pt->lineinfo_va == 0u) {
        return 0;
    }
    line_ptr = (const int32_t *)rome2_l75_const_ptr(a, pt->lineinfo_va + (uint32_t)pc * 4u, 4u);
    return (line_ptr != NULL) ? *line_ptr : -1;
}

/* 0x10f48c90 */
uint32_t rome2_l75_luaF_getlocalname(
    const rome2_l75_arena *a,
    uint32_t f_proto_va,
    int32_t local_number,
    int32_t pc) {
    const rome2_lua_proto_32 *pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(a, f_proto_va, sizeof(*pt));
    int32_t i;
    if (pt == NULL || pt->sizelocvars <= 0) {
        return 0u;
    }
    for (i = 0; i < pt->sizelocvars; ++i) {
        const rome2_lua_locvar_32 *lv = (const rome2_lua_locvar_32 *)rome2_l75_const_ptr(
            a, pt->locvars_va + (uint32_t)i * (uint32_t)sizeof(*lv), sizeof(*lv));
        if (lv == NULL) {
            return 0u;
        }
        if (pc < lv->startpc) {
            return 0u;
        }
        if (pc < lv->endpc) {
            --local_number;
            if (local_number == 0) {
                return lv->varname_va + (uint32_t)sizeof(rome2_lua_tstring_hdr_32);
            }
        }
    }
    return 0u;
}

/* 0x10f470c0 */
uint32_t rome2_l75_findlocal(rome2_l75_arena *a, uint32_t l_va, uint32_t ci_va, int32_t n) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(a, ci_va, sizeof(*ci));
    const rome2_lua_tvalue_32 *fn_val;
    const rome2_lua_closure_hdr_32 *cl;
    uint32_t limit_va;
    int32_t max_slots;
    if (L == NULL || ci == NULL) {
        return 0u;
    }
    fn_val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, ci->func_va, sizeof(*fn_val));
    if (fn_val != NULL && fn_val->tt == ROME2_LUA_TFUNCTION) {
        cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, fn_val->value_u32, sizeof(*cl));
        if (cl != NULL && cl->isC == 0u && cl->f_or_p_va != 0u) {
            int32_t pc = rome2_l75_currentpc(a, l_va, ci_va);
            uint32_t name_va = rome2_l75_luaF_getlocalname(a, cl->f_or_p_va, n, pc);
            if (name_va != 0u) {
                return name_va;
            }
        }
    }
    limit_va = (ci_va == L->ci_va) ? L->top_va : ci->top_va;
    max_slots = (int32_t)(limit_va - ci->base_va) / (int32_t)sizeof(rome2_lua_tvalue_32);
    if (n > 0 && n <= max_slots) {
        return ROME2_LUA_VA_STR_TEMP;
    }
    return 0u;
}

/* 0x10f47290 */
uint32_t rome2_l75_kname(const rome2_l75_arena *a, const rome2_lua_proto_32 *pt, uint32_t c) {
    if (pt != NULL && (c & 0x100u) != 0u) {
        uint32_t idx = c & 0xfffffeffu;
        const rome2_lua_tvalue_32 *kv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            a, pt->k_va + idx * (uint32_t)sizeof(*kv), sizeof(*kv));
        if (kv != NULL && kv->tt == ROME2_LUA_TSTRING) {
            return kv->value_u32 + (uint32_t)sizeof(rome2_lua_tstring_hdr_32);
        }
    }
    return ROME2_LUA_VA_STR_QMARK;
}

/* 0x10f47870 */
uint32_t rome2_l75_symbexec(
    const rome2_l75_arena *a,
    uint32_t pt_va,
    int32_t lastpc,
    uint32_t reg) {
    const rome2_lua_proto_32 *pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(a, pt_va, sizeof(*pt));
    int32_t last;
    int32_t pc;
    uint32_t last_inst_val = 0u;
    const uint32_t *last_insn_ptr;
    if (pt == NULL || pt->maxstacksize > 0xfau ||
        (int32_t)pt->nups < pt->sizeupvalues ||
        (pt->sizelineinfo != pt->sizecode && pt->sizelineinfo != 0) ||
        pt->sizecode <= 0) {
        return 0u;
    }
    last_insn_ptr = (const uint32_t *)rome2_l75_const_ptr(
        a, pt->code_va + (uint32_t)(pt->sizecode - 1) * 4u, 4u);
    if (last_insn_ptr == NULL || ((*last_insn_ptr & 0x3fu) != 0x1eu)) {
        return 0u;
    }
    last = pt->sizecode - 1;
    if (lastpc <= 0) {
        const uint32_t *res = (const uint32_t *)rome2_l75_const_ptr(
            a, pt->code_va + (uint32_t)last * 4u, 4u);
        return (res != NULL) ? *res : 0u;
    }
    for (pc = 0; pc < lastpc && pc < pt->sizecode; ++pc) {
        const uint32_t *ip = (const uint32_t *)rome2_l75_const_ptr(
            a, pt->code_va + (uint32_t)pc * 4u, 4u);
        uint32_t inst;
        uint32_t op;
        uint32_t reg_a;
        uint32_t b = 0u;
        uint32_t c = 0u;
        uint8_t mode;
        if (ip == NULL) {
            return 0u;
        }
        inst = *ip;
        op = inst & 0x3fu;
        reg_a = (inst >> 6) & 0xffu;
        if (op > 0x25u || reg_a >= (uint32_t)pt->maxstacksize) {
            return 0u;
        }
        mode = k_luaP_opmodes[op];
        if ((mode & 3u) == 0u) {
            b = inst >> 23;
            c = (inst >> 14) & 0x1ffu;
            if (!rome2_l75_checkArgMode(pt, b, (int32_t)((mode >> 4) & 3u)) ||
                !rome2_l75_checkArgMode(pt, c, (int32_t)((mode >> 2) & 3u))) {
                return 0u;
            }
        } else if ((mode & 3u) == 1u) {
            b = inst >> 14;
            if ((mode & 0x30u) == 0x30u && (int32_t)b >= pt->sizek) {
                return 0u;
            }
        } else if ((mode & 3u) == 2u) {
            int32_t sbx = (int32_t)(inst >> 14) - 0x1ffff;
            b = (uint32_t)sbx;
            if ((mode & 0x30u) == 0x20u) {
                int32_t dest = pc + 1 + sbx;
                if (dest < 0 || dest >= pt->sizecode) {
                    return 0u;
                }
                if (dest > 0) {
                    const uint32_t *prev = (const uint32_t *)rome2_l75_const_ptr(
                        a, pt->code_va + (uint32_t)(dest - 1) * 4u, 4u);
                    if (prev != NULL && ((*prev & 0x3fu) == 0x22u) && ((*prev & 0x7fc000u) == 0u)) {
                        return 0u;
                    }
                }
            }
        }
        if ((mode & 0x40u) != 0u && reg_a == reg) {
            last = pc;
        }
        if ((mode & 0x80u) != 0u) {
            const uint32_t *nxt = (const uint32_t *)rome2_l75_const_ptr(
                a, pt->code_va + (uint32_t)(pc + 1) * 4u, 4u);
            if (pc + 2 >= pt->sizecode || nxt == NULL || ((*nxt & 0x3fu) != 0x16u)) {
                return 0u;
            }
        }
        switch (op) {
            case 2u:
                if (c != 0u && (pc + 2 >= pt->sizecode)) {
                    return 0u;
                }
                break;
            case 3u:
                if ((int32_t)reg_a <= (int32_t)reg && (int32_t)reg <= (int32_t)b) {
                    last = pc;
                }
                break;
            case 4u:
            case 8u:
                if ((int32_t)b >= pt->sizeupvalues) {
                    return 0u;
                }
                break;
            case 5u:
            case 7u: {
                const rome2_lua_tvalue_32 *kv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    a, pt->k_va + b * (uint32_t)sizeof(*kv), sizeof(*kv));
                if (kv == NULL || kv->tt != ROME2_LUA_TSTRING) {
                    return 0u;
                }
                break;
            }
            case 11u:
                if (reg_a + 1u >= (uint32_t)pt->maxstacksize) {
                    return 0u;
                }
                if (reg == reg_a + 1u) {
                    last = pc;
                }
                break;
            case 21u:
                if ((int32_t)c >= (int32_t)b) {
                    return 0u;
                }
                break;
            case 22u:
            case 31u:
            case 32u: {
                int32_t dest = pc + 1 + (int32_t)b;
                if ((op == 31u || op == 32u) && reg_a + 3u >= (uint32_t)pt->maxstacksize) {
                    return 0u;
                }
                if (reg != 0xffu && pc < dest && dest < lastpc) {
                    pc += (int32_t)b;
                }
                break;
            }
            case 28u:
            case 29u:
                if (b != 0u && (int32_t)(reg_a + b - 1u) >= (int32_t)pt->maxstacksize) {
                    return 0u;
                }
                if (c == 0u) {
                    const uint32_t *nxt = (const uint32_t *)rome2_l75_const_ptr(
                        a, pt->code_va + (uint32_t)(pc + 1) * 4u, 4u);
                    uint32_t nop;
                    if (nxt == NULL) {
                        return 0u;
                    }
                    nop = *nxt & 0x3fu;
                    if (nop < 0x1cu || (nop > 0x1eu && nop != 0x22u) || *nxt >= 0x800000u) {
                        return 0u;
                    }
                } else if (c != 1u && (int32_t)(reg_a + c - 2u) >= (int32_t)pt->maxstacksize) {
                    return 0u;
                }
                if ((int32_t)reg >= (int32_t)reg_a) {
                    last = pc;
                }
                break;
            case 30u:
                if ((int32_t)(b - 1u) > 0 &&
                    (int32_t)(reg_a + b - 2u) >= (int32_t)pt->maxstacksize) {
                    return 0u;
                }
                break;
            case 33u:
                if (c == 0u || (int32_t)(reg_a + 2u + c) >= (int32_t)pt->maxstacksize) {
                    return 0u;
                }
                if ((int32_t)reg >= (int32_t)(reg_a + 2u)) {
                    last = pc;
                }
                break;
            case 34u:
                if ((int32_t)b > 0 && (int32_t)(reg_a + b) >= (int32_t)pt->maxstacksize) {
                    return 0u;
                }
                if (c == 0u) {
                    ++pc;
                }
                break;
            case 36u: {
                const uint32_t *pptr;
                const rome2_lua_proto_32 *sub;
                uint32_t nup;
                uint32_t j;
                if ((int32_t)b >= pt->sizep) {
                    return 0u;
                }
                pptr = (const uint32_t *)rome2_l75_const_ptr(a, pt->p_va + b * 4u, 4u);
                if (pptr == NULL) {
                    return 0u;
                }
                sub = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(a, *pptr, sizeof(*sub));
                if (sub == NULL) {
                    return 0u;
                }
                nup = sub->nups;
                if (pc + (int32_t)nup >= pt->sizecode) {
                    return 0u;
                }
                for (j = 1u; j <= nup; ++j) {
                    const uint32_t *upop = (const uint32_t *)rome2_l75_const_ptr(
                        a, pt->code_va + (uint32_t)(pc + (int32_t)j) * 4u, 4u);
                    if (upop == NULL || ((*upop & 0x3fu) != 4u && (*upop & 0x3fu) != 0u)) {
                        return 0u;
                    }
                }
                pc += (int32_t)nup;
                break;
            }
            case 37u:
                if ((pt->is_vararg & 2u) == 0u || (pt->is_vararg & 4u) != 0u) {
                    return 0u;
                }
                if (b == 0u) {
                    const uint32_t *nxt = (const uint32_t *)rome2_l75_const_ptr(
                        a, pt->code_va + (uint32_t)(pc + 1) * 4u, 4u);
                    uint32_t nop;
                    if (nxt == NULL) {
                        return 0u;
                    }
                    nop = *nxt & 0x3fu;
                    if (nop < 0x1cu || (nop > 0x1eu && nop != 0x22u) || *nxt >= 0x800000u) {
                        return 0u;
                    }
                }
                if ((int32_t)(reg_a + b - 2u) >= (int32_t)pt->maxstacksize) {
                    return 0u;
                }
                break;
            default:
                break;
        }
    }
    {
        const uint32_t *res = (const uint32_t *)rome2_l75_const_ptr(
            a, pt->code_va + (uint32_t)last * 4u, 4u);
        last_inst_val = (res != NULL) ? *res : 0u;
    }
    return last_inst_val;
}

/* 0x10f47140 */
uint32_t rome2_l75_getobjname(
    rome2_l75_arena *a,
    uint32_t l_va,
    uint32_t ci_va,
    uint32_t stackpos,
    uint32_t *out_name_va) {
    uint32_t cur_pos = stackpos;
    const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(a, ci_va, sizeof(*ci));
    const rome2_lua_tvalue_32 *fn_val;
    const rome2_lua_closure_hdr_32 *cl;
    if (out_name_va == NULL || ci == NULL) {
        return 0u;
    }
    fn_val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, ci->func_va, sizeof(*fn_val));
    if (fn_val == NULL || fn_val->tt != ROME2_LUA_TFUNCTION) {
        return 0u;
    }
    cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, fn_val->value_u32, sizeof(*cl));
    while (cl != NULL && cl->isC == 0u) {
        uint32_t pt_va = cl->f_or_p_va;
        const rome2_lua_proto_32 *pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(a, pt_va, sizeof(*pt));
        int32_t pc = rome2_l75_currentpc(a, l_va, ci_va);
        uint32_t lname = rome2_l75_luaF_getlocalname(a, pt_va, (int32_t)(cur_pos + 1u), pc);
        uint32_t insn;
        *out_name_va = lname;
        if (lname != 0u) {
            return ROME2_LUA_VA_STR_LOCAL;
        }
        if (pt == NULL) {
            return 0u;
        }
        insn = rome2_l75_symbexec(a, pt_va, pc, cur_pos);
        switch (insn & 0x3fu) {
            case 0u:
                cur_pos = insn >> 23;
                if (((insn >> 6) & 0xffu) <= cur_pos) {
                    return 0u;
                }
                break;
            case 4u:
                if (pt->upvalues_va == 0u) {
                    *out_name_va = ROME2_LUA_VA_STR_QMARK;
                } else {
                    const uint32_t *up = (const uint32_t *)rome2_l75_const_ptr(
                        a, pt->upvalues_va + (insn >> 23) * 4u, 4u);
                    *out_name_va = (up != NULL)
                        ? (*up + (uint32_t)sizeof(rome2_lua_tstring_hdr_32))
                        : ROME2_LUA_VA_STR_QMARK;
                }
                return ROME2_LUA_VA_STR_UPVALUE;
            case 5u: {
                const rome2_lua_tvalue_32 *kv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    a, pt->k_va + (insn >> 14) * (uint32_t)sizeof(*kv), sizeof(*kv));
                *out_name_va = (kv != NULL)
                    ? (kv->value_u32 + (uint32_t)sizeof(rome2_lua_tstring_hdr_32))
                    : ROME2_LUA_VA_STR_QMARK;
                return ROME2_LUA_VA_STR_GLOBAL;
            }
            case 6u:
                *out_name_va = rome2_l75_kname(a, pt, (insn >> 14) & 0x1ffu);
                return ROME2_LUA_VA_STR_FIELD;
            case 11u:
                *out_name_va = rome2_l75_kname(a, pt, (insn >> 14) & 0x1ffu);
                return ROME2_LUA_VA_STR_METHOD;
            default:
                return 0u;
        }
    }
    return 0u;
}

/* 0x10f46d50 */
int32_t rome2_l75_aux_getinfo(
    rome2_l75_arena *a,
    uint32_t l_va,
    const char *what,
    rome2_lua_debug_32 *ar,
    uint32_t f_cl_va,
    uint32_t ci_va) {
    const rome2_lua_closure_hdr_32 *cl;
    int32_t status = 1;
    if (what == NULL || ar == NULL) {
        return 0;
    }
    if (f_cl_va == 0u) {
        ar->namewhat_va = ROME2_LUA_VA_EMPTY;
        ar->name_va = ROME2_LUA_VA_EMPTY;
        ar->what_va = ROME2_LUA_VA_STR_TAIL;
        ar->currentline = -1;
        ar->linedefined = -1;
        ar->lastlinedefined = -1;
        ar->source_va = ROME2_LUA_VA_STR_TAILCALL;
        rome2_l75_luaO_chunkid(ar->short_src, "=(tail call)", 0xffu);
        ar->nups = 0;
        return 1;
    }
    cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, f_cl_va, sizeof(*cl));
    if (cl == NULL) {
        return 0;
    }
    for (; *what != '\0'; ++what) {
        switch (*what) {
            case 'S':
                if (cl->isC == 0u) {
                    const rome2_lua_proto_32 *pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(
                        a, cl->f_or_p_va, sizeof(*pt));
                    if (pt == NULL) {
                        status = 0;
                        break;
                    }
                    ar->source_va = pt->source_va + (uint32_t)sizeof(rome2_lua_tstring_hdr_32);
                    ar->linedefined = pt->linedefined;
                    ar->lastlinedefined = pt->lastlinedefined;
                    ar->what_va = (pt->linedefined == 0) ? ROME2_LUA_VA_STR_MAIN : ROME2_LUA_VA_STR_LUA;
                } else {
                    ar->source_va = ROME2_LUA_VA_STR_EQC;
                    ar->what_va = ROME2_LUA_VA_STR_C;
                    ar->linedefined = -1;
                    ar->lastlinedefined = -1;
                }
                {
                    const char *src_c = rome2_l75_cstr_at(a, ar->source_va);
                    rome2_l75_luaO_chunkid(ar->short_src, (src_c != NULL) ? src_c : "", 0xffu);
                }
                break;
            case 'l':
                ar->currentline = (ci_va != 0u) ? rome2_l75_currentline(a, l_va, ci_va) : -1;
                break;
            case 'u':
                ar->nups = (int32_t)cl->nupvalues;
                break;
            case 'n': {
                const rome2_lua_callinfo_32 *ci = (ci_va != 0u)
                    ? (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(a, ci_va, sizeof(*ci))
                    : NULL;
                const rome2_lua_tvalue_32 *cfn = (ci != NULL)
                    ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, ci->func_va, sizeof(*cfn))
                    : NULL;
                const rome2_lua_closure_hdr_32 *ccl = (cfn != NULL)
                    ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, cfn->value_u32, sizeof(*ccl))
                    : NULL;
                const rome2_lua_callinfo_32 *caller_ci = (ci_va != 0u)
                    ? (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(a, ci_va - (uint32_t)sizeof(*ci), sizeof(*caller_ci))
                    : NULL;
                const rome2_lua_tvalue_32 *pfn = (caller_ci != NULL)
                    ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, caller_ci->func_va, sizeof(*pfn))
                    : NULL;
                const rome2_lua_closure_hdr_32 *pcl = (pfn != NULL)
                    ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, pfn->value_u32, sizeof(*pcl))
                    : NULL;
                uint32_t nw = 0u;
                if (ci != NULL &&
                    !(ccl != NULL && ccl->isC == 0u && ci->tailcalls > 0) &&
                    pcl != NULL && pcl->isC == 0u) {
                    int32_t ppc = rome2_l75_currentpc(a, l_va, ci_va - (uint32_t)sizeof(*ci));
                    const rome2_lua_proto_32 *ppt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(
                        a, pcl->f_or_p_va, sizeof(*ppt));
                    if (ppt != NULL && ppc >= 0) {
                        const uint32_t *ip = (const uint32_t *)rome2_l75_const_ptr(
                            a, ppt->code_va + (uint32_t)ppc * 4u, 4u);
                        if (ip != NULL) {
                            uint32_t op = *ip & 0x3fu;
                            if (op == 0x1cu || op == 0x1du || op == 0x21u) {
                                nw = rome2_l75_getobjname(
                                    a, l_va, ci_va - (uint32_t)sizeof(*ci),
                                    (*ip >> 6) & 0xffu, &ar->name_va);
                            }
                        }
                    }
                }
                ar->namewhat_va = nw;
                if (nw == 0u) {
                    ar->namewhat_va = ROME2_LUA_VA_EMPTY;
                    ar->name_va = 0u;
                }
                break;
            }
            case 'L':
            case 'f':
                break;
            default:
                status = 0;
                break;
        }
    }
    return status;
}

/* 0x10f47720 */
uint32_t rome2_l75_lua_getlocal(
    rome2_l75_arena *a,
    uint32_t l_va,
    const rome2_lua_debug_32 *ar,
    int32_t n) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    uint32_t ci_va;
    const rome2_lua_callinfo_32 *ci;
    uint32_t name_va;
    if (L == NULL || ar == NULL) {
        return 0u;
    }
    ci_va = L->base_ci_va + (uint32_t)ar->i_ci * (uint32_t)sizeof(rome2_lua_callinfo_32);
    ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(a, ci_va, sizeof(*ci));
    if (ci == NULL) {
        return 0u;
    }
    name_va = rome2_l75_findlocal(a, l_va, ci_va, n);
    if (name_va != 0u) {
        const rome2_lua_tvalue_32 *slot = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            a, ci->base_va + (uint32_t)(n - 1) * (uint32_t)sizeof(*slot), sizeof(*slot));
        if (slot != NULL) {
            rome2_l75_luaA_pushobject(a, l_va, slot);
        }
    }
    return name_va;
}

/* 0x10f47770 */
int32_t rome2_l75_lua_getstack(
    const rome2_l75_arena *a,
    uint32_t l_va,
    int32_t level,
    rome2_lua_debug_32 *ar) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    uint32_t ci_va;
    if (L == NULL || ar == NULL) {
        return 0;
    }
    ci_va = L->ci_va;
    while (level > 0 && ci_va > L->base_ci_va) {
        const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
            a, ci_va, sizeof(*ci));
        const rome2_lua_tvalue_32 *fn_val;
        const rome2_lua_closure_hdr_32 *cl;
        if (ci == NULL) {
            return 0;
        }
        --level;
        fn_val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, ci->func_va, sizeof(*fn_val));
        if (fn_val != NULL && fn_val->tt == ROME2_LUA_TFUNCTION) {
            cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, fn_val->value_u32, sizeof(*cl));
            if (cl != NULL && cl->isC == 0u) {
                level -= ci->tailcalls;
            }
        }
        ci_va -= (uint32_t)sizeof(rome2_lua_callinfo_32);
    }
    if (level == 0 && ci_va > L->base_ci_va) {
        ar->i_ci = (int32_t)((ci_va - L->base_ci_va) / (uint32_t)sizeof(rome2_lua_callinfo_32));
        return 1;
    }
    if (level < 0) {
        ar->i_ci = 0;
        return 1;
    }
    return 0;
}

/* 0x10f48620 */
int32_t rome2_l75_luaD_rawrunprotected(
    rome2_l75_arena *a,
    uint32_t l_va,
    void (*fn)(rome2_l75_arena *a, uint32_t l_va, uint32_t ud_va, int32_t *status_slot),
    uint32_t ud_va) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    uint32_t saved_errjmp;
    int32_t status = 0;
    if (L == NULL) {
        return 0;
    }
    saved_errjmp = L->error_jmp_va;
    L->error_jmp_va = l_va;
    if (fn != NULL) {
        fn(a, l_va, ud_va, &status);
    }
    L->error_jmp_va = saved_errjmp;
    return status;
}

static int is_cleared(const rome2_l75_arena *a, const rome2_lua_tvalue_32 *o, int iskey) {
    if (o->tt <= 3) {
        return 0;
    }
    const uint8_t *obj = (const uint8_t *)rome2_l75_const_ptr(a, o->value_u32, 6u);
    if (obj == NULL) {
        return 0;
    }
    if (o->tt == ROME2_LUA_TSTRING) {
        /* 0x10f490a0 / 0x10f49e60 marks literal keys white bit off */
        return 0;
    }
    if ((obj[5] & 3u) != 0u) {
        return 1;
    }
    if (o->tt == ROME2_LUA_TUSERDATA && !iskey && (obj[5] & 8u) != 0u) {
        return 1;
    }
    return 0;
}

/* 0x10f490a0 */
void rome2_l75_cleartable(rome2_l75_arena *a, uint32_t table_va) {
    uint32_t cur = table_va;
    uint32_t guard = 0u;
    while (cur != 0u && guard++ < 4096u) {
        rome2_lua_table_32 *t = (rome2_lua_table_32 *)rome2_l75_mut_ptr(a, cur, sizeof(*t));
        int32_t i;
        uint32_t sizenode;
        if (t == NULL) {
            return;
        }
        i = t->sizearray;
        if ((t->marked & 0x10u) != 0u) {
            while (i-- > 0) {
                rome2_lua_tvalue_32 *o = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    a, t->array_va + (uint32_t)i * (uint32_t)sizeof(*o), sizeof(*o));
                if (o != NULL && is_cleared(a, o, 0)) {
                    o->tt = ROME2_LUA_TNIL;
                }
            }
        }
        sizenode = 1u << (t->lsizenode & 0x1fu);
        while (sizenode-- > 0u) {
            rome2_lua_node_32 *n = (rome2_lua_node_32 *)rome2_l75_mut_ptr(
                a, t->node_va + sizenode * (uint32_t)sizeof(*n), sizeof(*n));
            if (n != NULL && n->i_val.tt != ROME2_LUA_TNIL) {
                if (is_cleared(a, &n->i_key, 1) || is_cleared(a, &n->i_val, 0)) {
                    n->i_val.tt = ROME2_LUA_TNIL;
                    if (n->i_key.tt >= ROME2_LUA_TSTRING) {
                        n->i_key.tt = ROME2_LUA_TDEADKEY;
                    }
                }
            }
        }
        cur = t->gclist_va;
    }
}

/* 0x10f491a0 */
void rome2_l75_luaC_barrierback(rome2_l75_arena *a, uint32_t l_va, uint32_t table_va) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    rome2_lua_global_state_32 *g;
    rome2_lua_table_32 *t = (rome2_lua_table_32 *)rome2_l75_mut_ptr(a, table_va, sizeof(*t));
    if (L == NULL || t == NULL) {
        return;
    }
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(a, L->l_g_va, sizeof(*g));
    if (g == NULL) {
        return;
    }
    t->marked &= 0xfbu;
    t->gclist_va = g->grayagain_va;
    g->grayagain_va = table_va;
}

/* 0x10f491c0 */
void rome2_l75_luaC_barrierf(rome2_l75_arena *a, uint32_t l_va, uint32_t o_va, uint32_t v_va) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    const rome2_lua_global_state_32 *g;
    uint8_t *o;
    if (L == NULL) {
        return;
    }
    g = (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(a, L->l_g_va, sizeof(*g));
    if (g == NULL) {
        return;
    }
    if (g->gcstate == 1u) {
        rome2_l75_reallymarkobject(a, L->l_g_va, v_va);
        return;
    }
    o = (uint8_t *)rome2_l75_mut_ptr(a, o_va, 6u);
    if (o != NULL) {
        o[5] = (uint8_t)((g->currentwhite & 3u) | (o[5] & 0xf8u));
    }
}

/* 0x10f494e0 */
void rome2_l75_luaC_link(rome2_l75_arena *a, uint32_t l_va, uint32_t o_va, uint8_t tt) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    rome2_lua_global_state_32 *g;
    uint8_t *o = (uint8_t *)rome2_l75_mut_ptr(a, o_va, 6u);
    if (L == NULL || o == NULL) {
        return;
    }
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(a, L->l_g_va, sizeof(*g));
    if (g == NULL) {
        return;
    }
    memcpy(o, &g->rootgc_va, 4u);
    g->rootgc_va = o_va;
    o[5] = g->currentwhite & 3u;
    o[4] = tt;
}

/* 0x10f49510 */
void rome2_l75_luaC_linkupval(rome2_l75_arena *a, uint32_t l_va, uint32_t uv_va) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    rome2_lua_global_state_32 *g;
    rome2_lua_upval_32 *uv = (rome2_lua_upval_32 *)rome2_l75_mut_ptr(a, uv_va, sizeof(*uv));
    if (L == NULL || uv == NULL) {
        return;
    }
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(a, L->l_g_va, sizeof(*g));
    if (g == NULL) {
        return;
    }
    uv->next_va = g->rootgc_va;
    g->rootgc_va = uv_va;
    if ((uv->marked & 7u) == 0u) {
        if (g->gcstate == 1u) {
            uv->marked |= 4u;
            {
                const rome2_lua_tvalue_32 *v = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    a, uv->v_va, sizeof(*v));
                if (v != NULL && v->tt > 3) {
                    const uint8_t *target = (const uint8_t *)rome2_l75_const_ptr(a, v->value_u32, 6u);
                    if (target != NULL && (target[5] & 3u) != 0u) {
                        rome2_l75_luaC_barrierf(a, l_va, uv_va, v->value_u32);
                    }
                }
            }
        } else {
            uv->marked = (uint8_t)((g->currentwhite & 3u) | (uv->marked & 0xf8u));
        }
    }
}

/* 0x10f49e60 */
void rome2_l75_reallymarkobject(rome2_l75_arena *a, uint32_t g_va, uint32_t o_va) {
    uint32_t cur = o_va;
    uint32_t depth = 0u;
    rome2_lua_global_state_32 *g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(a, g_va, sizeof(*g));
    if (g == NULL) {
        return;
    }
    while (cur != 0u && depth++ < 64u) {
        uint8_t *o = (uint8_t *)rome2_l75_mut_ptr(a, cur, 6u);
        uint32_t link_off;
        if (o == NULL) {
            return;
        }
        o[5] &= 0xfcu;
        switch (o[4]) {
            case ROME2_LUA_TTABLE:
                link_off = 0x18u;
                break;
            case ROME2_LUA_TFUNCTION:
                link_off = 0x08u;
                break;
            case ROME2_LUA_TUSERDATA: {
                uint32_t mt_va = 0u;
                uint32_t env_va = 0u;
                const uint8_t *ud = (const uint8_t *)rome2_l75_const_ptr(a, cur, 16u);
                if (ud == NULL) {
                    return;
                }
                memcpy(&mt_va, ud + 8u, 4u);
                memcpy(&env_va, ud + 12u, 4u);
                o[5] |= 4u;
                if (mt_va != 0u) {
                    const uint8_t *mt = (const uint8_t *)rome2_l75_const_ptr(a, mt_va, 6u);
                    if (mt != NULL && (mt[5] & 3u) != 0u) {
                        rome2_l75_reallymarkobject(a, g_va, mt_va);
                    }
                }
                if (env_va != 0u) {
                    const uint8_t *env = (const uint8_t *)rome2_l75_const_ptr(a, env_va, 6u);
                    if (env != NULL && (env[5] & 3u) != 0u) {
                        cur = env_va;
                        continue;
                    }
                }
                return;
            }
            case ROME2_LUA_TTHREAD:
                link_off = 0x58u;
                break;
            case ROME2_LUA_TPROTO:
                link_off = 0x44u;
                break;
            case ROME2_LUA_TUPVAL: {
                rome2_lua_upval_32 *uv = (rome2_lua_upval_32 *)rome2_l75_mut_ptr(a, cur, sizeof(*uv));
                if (uv != NULL) {
                    const rome2_lua_tvalue_32 *v = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                        a, uv->v_va, sizeof(*v));
                    if (v != NULL && v->tt > 3) {
                        const uint8_t *obj = (const uint8_t *)rome2_l75_const_ptr(a, v->value_u32, 6u);
                        if (obj != NULL && (obj[5] & 3u) != 0u) {
                            rome2_l75_reallymarkobject(a, g_va, v->value_u32);
                        }
                    }
                    if (uv->v_va == cur + 0x0cu) {
                        uv->marked |= 4u;
                    }
                }
                return;
            }
            default:
                return;
        }
        {
            uint8_t *gcl = (uint8_t *)rome2_l75_mut_ptr(a, cur + link_off, 4u);
            if (gcl != NULL) {
                memcpy(gcl, &g->gray_va, 4u);
                g->gray_va = cur;
            }
            return;
        }
    }
}

/* 0x10f49830 */
void rome2_l75_marktmu_mt(rome2_l75_arena *a, uint32_t g_va) {
    const rome2_lua_global_state_32 *g = (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(a, g_va, sizeof(*g));
    uint32_t i;
    if (g == NULL) {
        return;
    }
    for (i = 0u; i < 9u; ++i) {
        uint32_t mt_va = g->mt_va[i];
        if (mt_va != 0u) {
            const uint8_t *mt = (const uint8_t *)rome2_l75_const_ptr(a, mt_va, 6u);
            if (mt != NULL && (mt[5] & 3u) != 0u) {
                rome2_l75_reallymarkobject(a, g_va, mt_va);
            }
        }
    }
}

/* 0x10f49920 */
void rome2_l75_markroot(rome2_l75_arena *a, uint32_t l_va) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    rome2_lua_global_state_32 *g;
    const rome2_lua_state_32 *mt;
    if (L == NULL) {
        return;
    }
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(a, L->l_g_va, sizeof(*g));
    if (g == NULL) {
        return;
    }
    g->gray_va = 0u;
    g->grayagain_va = 0u;
    g->weak_va = 0u;
    if (g->mainthread_va != 0u) {
        const uint8_t *mto = (const uint8_t *)rome2_l75_const_ptr(a, g->mainthread_va, 6u);
        if (mto != NULL && (mto[5] & 3u) != 0u) {
            rome2_l75_reallymarkobject(a, L->l_g_va, g->mainthread_va);
        }
        mt = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, g->mainthread_va, sizeof(*mt));
        if (mt != NULL && mt->l_gt.tt > 3) {
            const uint8_t *gt = (const uint8_t *)rome2_l75_const_ptr(a, mt->l_gt.value_u32, 6u);
            if (gt != NULL && (gt[5] & 3u) != 0u) {
                rome2_l75_reallymarkobject(a, L->l_g_va, mt->l_gt.value_u32);
            }
        }
    }
    if (g->l_registry.tt > 3) {
        const uint8_t *reg = (const uint8_t *)rome2_l75_const_ptr(a, g->l_registry.value_u32, 6u);
        if (reg != NULL && (reg[5] & 3u) != 0u) {
            rome2_l75_reallymarkobject(a, L->l_g_va, g->l_registry.value_u32);
        }
    }
    rome2_l75_marktmu_mt(a, L->l_g_va);
    g->gcstate = 1u;
}

/* 0x10f4a1e0 */
void rome2_l75_traverseclosure(rome2_l75_arena *a, uint32_t g_va, uint32_t cl_va) {
    const rome2_lua_closure_hdr_32 *cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(
        a, cl_va, sizeof(*cl));
    uint32_t i;
    if (cl == NULL) {
        return;
    }
    if (cl->env_va != 0u) {
        const uint8_t *env = (const uint8_t *)rome2_l75_const_ptr(a, cl->env_va, 6u);
        if (env != NULL && (env[5] & 3u) != 0u) {
            rome2_l75_reallymarkobject(a, g_va, cl->env_va);
        }
    }
    if (cl->isC == 0u) {
        if (cl->f_or_p_va != 0u) {
            const uint8_t *pt = (const uint8_t *)rome2_l75_const_ptr(a, cl->f_or_p_va, 6u);
            if (pt != NULL && (pt[5] & 3u) != 0u) {
                rome2_l75_reallymarkobject(a, g_va, cl->f_or_p_va);
            }
        }
        for (i = 0u; i < cl->nupvalues; ++i) {
            const uint32_t *up_va = (const uint32_t *)rome2_l75_const_ptr(
                a, cl_va + (uint32_t)sizeof(*cl) + i * 4u, 4u);
            if (up_va != NULL && *up_va != 0u) {
                const uint8_t *uv = (const uint8_t *)rome2_l75_const_ptr(a, *up_va, 6u);
                if (uv != NULL && (uv[5] & 3u) != 0u) {
                    rome2_l75_reallymarkobject(a, g_va, *up_va);
                }
            }
        }
    } else {
        for (i = 0u; i < cl->nupvalues; ++i) {
            const rome2_lua_tvalue_32 *tv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                a, cl_va + (uint32_t)sizeof(*cl) + i * (uint32_t)sizeof(*tv), sizeof(*tv));
            if (tv != NULL && tv->tt > 3) {
                const uint8_t *obj = (const uint8_t *)rome2_l75_const_ptr(a, tv->value_u32, 6u);
                if (obj != NULL && (obj[5] & 3u) != 0u) {
                    rome2_l75_reallymarkobject(a, g_va, tv->value_u32);
                }
            }
        }
    }
}

/* 0x10f4a340 */
int32_t rome2_l75_traversetable(rome2_l75_arena *a, uint32_t g_va, uint32_t table_va) {
    rome2_lua_global_state_32 *g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(a, g_va, sizeof(*g));
    rome2_lua_table_32 *t = (rome2_lua_table_32 *)rome2_l75_mut_ptr(a, table_va, sizeof(*t));
    int weakkey = 0;
    int weakvalue = 0;
    uint32_t sizenode;
    if (g == NULL || t == NULL) {
        return 0;
    }
    if (t->metatable_va != 0u) {
        const uint8_t *mt = (const uint8_t *)rome2_l75_const_ptr(a, t->metatable_va, 6u);
        if (mt != NULL && (mt[5] & 3u) != 0u) {
            rome2_l75_reallymarkobject(a, g_va, t->metatable_va);
        }
        {
            const rome2_lua_table_32 *mtt = (const rome2_lua_table_32 *)rome2_l75_const_ptr(
                a, t->metatable_va, sizeof(*mtt));
            if (mtt != NULL && (mtt->flags & 8u) == 0u) {
                uint32_t mode_va = rome2_l75_luaT_gettm(
                    a, t->metatable_va, 3u, g->tmname_va[3]);
                const rome2_lua_tvalue_32 *mv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    a, mode_va, sizeof(*mv));
                if (mv != NULL && mv->tt == ROME2_LUA_TSTRING) {
                    const char *mstr = rome2_l75_cstr_at(
                        a, mv->value_u32 + (uint32_t)sizeof(rome2_lua_tstring_hdr_32));
                    if (mstr != NULL) {
                        weakkey = (strchr(mstr, 'k') != NULL) ? 1 : 0;
                        weakvalue = (strchr(mstr, 'v') != NULL) ? 1 : 0;
                        if (weakkey || weakvalue) {
                            t->marked = (uint8_t)(((weakkey | (weakvalue << 1)) << 3) | (t->marked & 0xe7u));
                            t->gclist_va = g->weak_va;
                            g->weak_va = table_va;
                        }
                    }
                }
            }
        }
    }
    if (weakkey && weakvalue) {
        return 1;
    }
    if (!weakvalue) {
        int32_t i = t->sizearray;
        while (i-- > 0) {
            const rome2_lua_tvalue_32 *av = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                a, t->array_va + (uint32_t)i * (uint32_t)sizeof(*av), sizeof(*av));
            if (av != NULL && av->tt > 3) {
                const uint8_t *obj = (const uint8_t *)rome2_l75_const_ptr(a, av->value_u32, 6u);
                if (obj != NULL && (obj[5] & 3u) != 0u) {
                    rome2_l75_reallymarkobject(a, g_va, av->value_u32);
                }
            }
        }
    }
    sizenode = 1u << (t->lsizenode & 0x1fu);
    while (sizenode-- > 0u) {
        rome2_lua_node_32 *n = (rome2_lua_node_32 *)rome2_l75_mut_ptr(
            a, t->node_va + sizenode * (uint32_t)sizeof(*n), sizeof(*n));
        if (n == NULL) {
            break;
        }
        if (n->i_val.tt == ROME2_LUA_TNIL) {
            if (n->i_key.tt >= ROME2_LUA_TSTRING) {
                n->i_key.tt = ROME2_LUA_TDEADKEY;
            }
        } else {
            if (!weakkey && n->i_key.tt > 3) {
                const uint8_t *obj = (const uint8_t *)rome2_l75_const_ptr(a, n->i_key.value_u32, 6u);
                if (obj != NULL && (obj[5] & 3u) != 0u) {
                    rome2_l75_reallymarkobject(a, g_va, n->i_key.value_u32);
                }
            }
            if (!weakvalue && n->i_val.tt > 3) {
                const uint8_t *obj = (const uint8_t *)rome2_l75_const_ptr(a, n->i_val.value_u32, 6u);
                if (obj != NULL && (obj[5] & 3u) != 0u) {
                    rome2_l75_reallymarkobject(a, g_va, n->i_val.value_u32);
                }
            }
        }
    }
    return (weakkey || weakvalue) ? 1 : 0;
}

/* 0x10f4aea0 */
uint32_t rome2_l75_mainposition(
    const rome2_l75_arena *a,
    uint32_t t_va,
    const rome2_lua_tvalue_32 *key) {
    const rome2_lua_table_32 *t = (const rome2_lua_table_32 *)rome2_l75_const_ptr(a, t_va, sizeof(*t));
    uint32_t pow2;
    uint32_t odd_mod;
    uint32_t bucket;
    if (t == NULL || key == NULL) {
        return 0u;
    }
    pow2 = 1u << (t->lsizenode & 0x1fu);
    odd_mod = (pow2 - 1u) | 1u;
    switch (key->tt) {
        case ROME2_LUA_TNUMBER: {
            float f = bits_to_f32(key->value_u32) + 1.0f;
            bucket = ((uint32_t)f) % odd_mod;
            break;
        }
        case ROME2_LUA_TSTRING: {
            const rome2_lua_tstring_hdr_32 *ts = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
                a, key->value_u32, sizeof(*ts));
            if (ts == NULL) {
                return 0u;
            }
            bucket = ts->hash & (pow2 - 1u);
            break;
        }
        case ROME2_LUA_TBOOLEAN:
            bucket = key->value_u32 & (pow2 - 1u);
            break;
        default: {
            float f = bits_to_f32(key->value_u32);
            bucket = ((uint32_t)f) % odd_mod;
            break;
        }
    }
    return t->node_va + bucket * (uint32_t)sizeof(rome2_lua_node_32);
}

/* 0x10f4aa60 */
uint32_t rome2_l75_luaH_getnum(const rome2_l75_arena *a, uint32_t t_va, int32_t key) {
    const rome2_lua_table_32 *t = (const rome2_lua_table_32 *)rome2_l75_const_ptr(a, t_va, sizeof(*t));
    uint32_t n_va;
    uint32_t odd_mod;
    if (t == NULL) {
        return ROME2_LUA_VA_NILOBJECT;
    }
    if ((uint32_t)(key - 1) < (uint32_t)t->sizearray) {
        return t->array_va + (uint32_t)(key - 1) * (uint32_t)sizeof(rome2_lua_tvalue_32);
    }
    odd_mod = ((1u << (t->lsizenode & 0x1fu)) - 1u) | 1u;
    n_va = t->node_va + (((uint32_t)((float)key + 1.0f)) % odd_mod) * (uint32_t)sizeof(rome2_lua_node_32);
    while (n_va != 0u) {
        const rome2_lua_node_32 *n = (const rome2_lua_node_32 *)rome2_l75_const_ptr(a, n_va, sizeof(*n));
        if (n == NULL) {
            return ROME2_LUA_VA_NILOBJECT;
        }
        if (n->i_key.tt == ROME2_LUA_TNUMBER && bits_to_f32(n->i_key.value_u32) == (float)key) {
            return n_va;
        }
        n_va = n->next_va;
    }
    return ROME2_LUA_VA_NILOBJECT;
}

/* 0x10f4aae0 */
uint32_t rome2_l75_luaH_getstr(const rome2_l75_arena *a, uint32_t t_va, uint32_t key_ts_va) {
    const rome2_lua_table_32 *t = (const rome2_lua_table_32 *)rome2_l75_const_ptr(a, t_va, sizeof(*t));
    const rome2_lua_tstring_hdr_32 *ts = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
        a, key_ts_va, sizeof(*ts));
    uint32_t n_va;
    if (t == NULL || ts == NULL) {
        return ROME2_LUA_VA_NILOBJECT;
    }
    n_va = t->node_va + (((1u << (t->lsizenode & 0x1fu)) - 1u) & ts->hash) * (uint32_t)sizeof(rome2_lua_node_32);
    while (n_va != 0u) {
        const rome2_lua_node_32 *n = (const rome2_lua_node_32 *)rome2_l75_const_ptr(a, n_va, sizeof(*n));
        if (n == NULL) {
            return ROME2_LUA_VA_NILOBJECT;
        }
        if (n->i_key.tt == ROME2_LUA_TSTRING && n->i_key.value_u32 == key_ts_va) {
            return n_va;
        }
        n_va = n->next_va;
    }
    return ROME2_LUA_VA_NILOBJECT;
}

/* 0x10f4a900 */
uint32_t rome2_l75_luaH_get(const rome2_l75_arena *a, uint32_t t_va, const rome2_lua_tvalue_32 *key) {
    uint32_t n_va;
    if (key == NULL || key->tt == ROME2_LUA_TNIL) {
        return ROME2_LUA_VA_NILOBJECT;
    }
    if (key->tt == ROME2_LUA_TNUMBER) {
        float fn = bits_to_f32(key->value_u32);
        int32_t k = (int32_t)fn;
        if ((float)k == fn) {
            return rome2_l75_luaH_getnum(a, t_va, k);
        }
    } else if (key->tt == ROME2_LUA_TSTRING) {
        return rome2_l75_luaH_getstr(a, t_va, key->value_u32);
    }
    n_va = rome2_l75_mainposition(a, t_va, key);
    while (n_va != 0u) {
        const rome2_lua_node_32 *n = (const rome2_lua_node_32 *)rome2_l75_const_ptr(a, n_va, sizeof(*n));
        if (n == NULL) {
            return ROME2_LUA_VA_NILOBJECT;
        }
        if (rome2_l75_luaO_rawequalObj(&n->i_key, key)) {
            return n_va;
        }
        n_va = n->next_va;
    }
    return ROME2_LUA_VA_NILOBJECT;
}

/* 0x10f4a980 */
uint32_t rome2_l75_luaH_getn(const rome2_l75_arena *a, uint32_t t_va) {
    const rome2_lua_table_32 *t = (const rome2_lua_table_32 *)rome2_l75_const_ptr(a, t_va, sizeof(*t));
    uint32_t j;
    if (t == NULL) {
        return 0u;
    }
    j = (uint32_t)t->sizearray;
    if (j > 0u) {
        const rome2_lua_tvalue_32 *last = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            a, t->array_va + (j - 1u) * (uint32_t)sizeof(*last), sizeof(*last));
        if (last != NULL && last->tt == ROME2_LUA_TNIL) {
            uint32_t i = 0u;
            while (j - i > 1u) {
                uint32_t m = (i + j) >> 1;
                const rome2_lua_tvalue_32 *mv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    a, t->array_va + (m - 1u) * (uint32_t)sizeof(*mv), sizeof(*mv));
                if (mv != NULL && mv->tt == ROME2_LUA_TNIL) {
                    j = m;
                } else {
                    i = m;
                }
            }
            return i;
        }
    }
    if (t->node_va != ROME2_LUA_VA_DUMMYNODE) {
        uint32_t i = j;
        uint32_t nj = j + 1u;
        const rome2_lua_tvalue_32 *v = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            a, rome2_l75_luaH_getnum(a, t_va, (int32_t)nj), sizeof(*v));
        while (v != NULL && v->tt != ROME2_LUA_TNIL) {
            i = nj;
            if (nj > 0x3ffffffeu) {
                uint32_t u = 1u;
                for (;;) {
                    const rome2_lua_tvalue_32 *uv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                        a, rome2_l75_luaH_getnum(a, t_va, (int32_t)u), sizeof(*uv));
                    if (uv == NULL || uv->tt == ROME2_LUA_TNIL) {
                        return u - 1u;
                    }
                    ++u;
                }
            }
            nj *= 2u;
            v = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                a, rome2_l75_luaH_getnum(a, t_va, (int32_t)nj), sizeof(*v));
        }
        while (nj - i > 1u) {
            uint32_t m = (i + nj) >> 1;
            const rome2_lua_tvalue_32 *mv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                a, rome2_l75_luaH_getnum(a, t_va, (int32_t)m), sizeof(*mv));
            if (mv != NULL && mv->tt == ROME2_LUA_TNIL) {
                nj = m;
            } else {
                i = m;
            }
        }
        return i;
    }
    return j;
}

/* 0x10f4dee0 */
uint32_t rome2_l75_luaT_gettm(
    rome2_l75_arena *a,
    uint32_t events_va,
    uint32_t event,
    uint32_t ename_va) {
    rome2_lua_table_32 *ev = (rome2_lua_table_32 *)rome2_l75_mut_ptr(a, events_va, sizeof(*ev));
    uint32_t tm_va = rome2_l75_luaH_getstr(a, events_va, ename_va);
    const rome2_lua_tvalue_32 *tv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        a, tm_va, sizeof(*tv));
    if (tv != NULL && tv->tt == ROME2_LUA_TNIL) {
        if (ev != NULL) {
            ev->flags |= (uint8_t)(1u << (event & 0x1fu));
        }
        return 0u;
    }
    return tm_va;
}

/* 0x10f4df10 */
uint32_t rome2_l75_luaT_gettmbyobj(
    const rome2_l75_arena *a,
    uint32_t l_va,
    const rome2_lua_tvalue_32 *o,
    int32_t event) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    const rome2_lua_global_state_32 *g;
    uint32_t mt_va = 0u;
    if (L == NULL || o == NULL || o->tt < 0 || o->tt >= 9 || event < 0 || event >= 17) {
        return ROME2_LUA_VA_NILOBJECT;
    }
    g = (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(a, L->l_g_va, sizeof(*g));
    if (g == NULL) {
        return ROME2_LUA_VA_NILOBJECT;
    }
    if (o->tt == ROME2_LUA_TTABLE) {
        const rome2_lua_table_32 *t = (const rome2_lua_table_32 *)rome2_l75_const_ptr(
            a, o->value_u32, sizeof(*t));
        if (t != NULL) {
            mt_va = t->metatable_va;
        }
    } else if (o->tt == ROME2_LUA_TUSERDATA) {
        const uint8_t *ud = (const uint8_t *)rome2_l75_const_ptr(a, o->value_u32, 12u);
        if (ud != NULL) {
            memcpy(&mt_va, ud + 8u, 4u);
        }
    } else {
        mt_va = g->mt_va[o->tt];
    }
    return (mt_va != 0u)
        ? rome2_l75_luaH_getstr(a, mt_va, g->tmname_va[event])
        : ROME2_LUA_VA_NILOBJECT;
}

/* 0x10f4bd40 */
uint32_t rome2_l75_get_compTM(
    rome2_l75_arena *a,
    uint32_t l_va,
    uint32_t mt1_va,
    uint32_t mt2_va,
    uint32_t event) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    const rome2_lua_global_state_32 *g;
    const rome2_lua_table_32 *mt1 = (const rome2_lua_table_32 *)rome2_l75_const_ptr(a, mt1_va, sizeof(*mt1));
    uint8_t flag_bit = (uint8_t)(1u << (event & 0x1fu));
    uint32_t tm1_va;
    if (L == NULL || mt1 == NULL || (mt1->flags & flag_bit) != 0u || event >= 17u) {
        return 0u;
    }
    g = (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(a, L->l_g_va, sizeof(*g));
    if (g == NULL) {
        return 0u;
    }
    tm1_va = rome2_l75_luaT_gettm(a, mt1_va, event, g->tmname_va[event]);
    if (tm1_va == 0u) {
        return 0u;
    }
    if (mt1_va == mt2_va) {
        return tm1_va;
    }
    {
        const rome2_lua_table_32 *mt2 = (const rome2_lua_table_32 *)rome2_l75_const_ptr(a, mt2_va, sizeof(*mt2));
        uint32_t tm2_va;
        const rome2_lua_tvalue_32 *tv1;
        const rome2_lua_tvalue_32 *tv2;
        if (mt2 == NULL || (mt2->flags & flag_bit) != 0u) {
            return 0u;
        }
        tm2_va = rome2_l75_luaT_gettm(a, mt2_va, event, g->tmname_va[event]);
        if (tm2_va == 0u) {
            return 0u;
        }
        tv1 = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, tm1_va, sizeof(*tv1));
        tv2 = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, tm2_va, sizeof(*tv2));
        if (rome2_l75_luaO_rawequalObj(tv1, tv2)) {
            return tm1_va;
        }
    }
    return 0u;
}

/* 0x10f4bdd0 */
int32_t rome2_l75_l_strcmp(
    const rome2_l75_arena *a,
    uint32_t ls_va,
    uint32_t rs_va) {
    const rome2_lua_tstring_hdr_32 *ls = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
        a, ls_va, sizeof(*ls));
    const rome2_lua_tstring_hdr_32 *rs = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
        a, rs_va, sizeof(*rs));
    size_t ll;
    size_t rl;
    const char *l;
    const char *r;
    if (ls == NULL || rs == NULL) {
        return 0;
    }
    ll = ls->len;
    rl = rs->len;
    l = (const char *)rome2_l75_const_ptr(a, ls_va + (uint32_t)sizeof(*ls), (uint32_t)ll + 1u);
    r = (const char *)rome2_l75_const_ptr(a, rs_va + (uint32_t)sizeof(*rs), (uint32_t)rl + 1u);
    if (l == NULL || r == NULL) {
        return 0;
    }
    for (;;) {
        int32_t err = 0;
        int32_t temp = rome2_l74_strcoll(l, r, &err);
        size_t len;
        if (temp != 0) {
            return temp;
        }
        len = strlen(l);
        if (len == rl) {
            return (len == ll) ? 0 : 1;
        }
        if (len == ll) {
            return -1;
        }
        ++len;
        l += len;
        r += len;
        ll -= len;
        rl -= len;
    }
}

/* 0x10f4de20 */
const rome2_lua_tvalue_32 *rome2_l75_luaV_tonumber(
    const rome2_l75_arena *a,
    const rome2_lua_tvalue_32 *obj,
    rome2_lua_tvalue_32 *n) {
    float num = 0.0f;
    if (obj == NULL) {
        return NULL;
    }
    if (obj->tt == ROME2_LUA_TNUMBER) {
        return obj;
    }
    if (obj->tt == ROME2_LUA_TSTRING && n != NULL) {
        const char *s = rome2_l75_cstr_at(a, obj->value_u32 + (uint32_t)sizeof(rome2_lua_tstring_hdr_32));
        if (s != NULL && rome2_l75_luaO_str2d(s, &num)) {
            n->value_u32 = f32_to_bits(num);
            n->tt = ROME2_LUA_TNUMBER;
            return n;
        }
    }
    return NULL;
}
