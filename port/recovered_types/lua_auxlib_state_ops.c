#include "lua_auxlib_state_ops.h"

#include <stdio.h>
#include <string.h>

static uint32_t l78_alloc_zero(rome2_l77_ctx *ctx, uint32_t bytes) {
    uint32_t aligned;
    uint32_t va;
    void *p;
    if (ctx == NULL || ctx->arena == NULL || bytes == 0u) {
        return 0u;
    }
    aligned = (bytes + 7u) & ~7u;
    if (ctx->heap_cursor + aligned > ctx->heap_end) {
        return 0u;
    }
    va = ctx->heap_cursor;
    ctx->heap_cursor += aligned;
    p = rome2_l75_mut_ptr(ctx->arena, va, aligned);
    if (p != NULL) {
        memset(p, 0, aligned);
    }
    return va;
}

static uint32_t l78_push_tvalue(rome2_l77_ctx *ctx, uint32_t l_va, const rome2_lua_tvalue_32 *val) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_tvalue_32 *slot;
    uint32_t slot_va;
    if (L == NULL || val == NULL) {
        return 0u;
    }
    slot_va = L->top_va;
    slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, slot_va, sizeof(*slot));
    if (slot == NULL) {
        return 0u;
    }
    *slot = *val;
    L->top_va += (uint32_t)sizeof(rome2_lua_tvalue_32);
    return slot_va;
}

static void l78_gc_step_if_over(rome2_l77_ctx *ctx, uint32_t l_va) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    const rome2_lua_global_state_32 *g = (L != NULL)
        ? (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    if (g != NULL && g->gc_threshold != 0u && g->totalbytes >= g->gc_threshold) {
        (void)rome2_l77_singlestep(ctx, l_va);
    }
}

static uint32_t l78_stack_base_off(const rome2_l75_arena *a, uint32_t l_va, uint32_t va) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    return (L != NULL && va >= L->stack_va) ? (va - L->stack_va) : 0u;
}

/* 0x10f43cd0 */
void rome2_l78_lua_call(rome2_l77_ctx *ctx, uint32_t l_va, int32_t nargs, int32_t nresults) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t func_va;
    if (L == NULL || nargs < 0) {
        return;
    }
    func_va = L->top_va - (uint32_t)(nargs + 1) * (uint32_t)sizeof(rome2_lua_tvalue_32);
    rome2_l77_luaD_call(ctx, l_va, func_va, nresults);
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L != NULL && nresults == ROME2_LUA_MULTRET) {
        rome2_lua_callinfo_32 *ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(
            ctx->arena, L->ci_va, sizeof(*ci));
        if (ci != NULL && L->top_va > ci->top_va) {
            ci->top_va = L->top_va;
        }
    }
}

/* 0x10f43d70 */
void rome2_l78_lua_concat(rome2_l77_ctx *ctx, uint32_t l_va, int32_t n) {
    rome2_lua_state_32 *L;
    if (ctx == NULL) {
        return;
    }
    l78_gc_step_if_over(ctx, l_va);
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L == NULL) {
        return;
    }
    if (n >= 2) {
        int32_t last = (int32_t)((L->top_va - L->base_va) / (uint32_t)sizeof(rome2_lua_tvalue_32)) - 1;
        rome2_l77_luaV_concat(ctx, l_va, n, last);
        L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
        if (L != NULL) {
            L->top_va -= (uint32_t)(n - 1) * (uint32_t)sizeof(rome2_lua_tvalue_32);
        }
    } else if (n == 0) {
        rome2_lua_tvalue_32 tv;
        tv.value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, "", 0u);
        tv.tt = ROME2_LUA_TSTRING;
        (void)l78_push_tvalue(ctx, l_va, &tv);
    }
}

/* 0x10f43df0 */
void rome2_l78_lua_createtable(rome2_l77_ctx *ctx, uint32_t l_va, int32_t narray, int32_t nrec) {
    rome2_lua_tvalue_32 tv;
    if (ctx == NULL) {
        return;
    }
    l78_gc_step_if_over(ctx, l_va);
    tv.value_u32 = rome2_l77_luaH_new(ctx, l_va, narray, nrec);
    tv.tt = ROME2_LUA_TTABLE;
    (void)l78_push_tvalue(ctx, l_va, &tv);
}

/* 0x10f47340 */
void rome2_l78_luaG_errormsg(rome2_l77_ctx *ctx, uint32_t l_va) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    if (L == NULL) {
        return;
    }
    if (L->errfunc != 0) {
        uint32_t errfunc_va = L->stack_va + (uint32_t)L->errfunc;
        const rome2_lua_tvalue_32 *ef = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, errfunc_va, sizeof(*ef));
        const rome2_lua_tvalue_32 *msg = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, L->top_va - 8u, sizeof(*msg));
        if (ef == NULL || ef->tt != ROME2_LUA_TFUNCTION) {
            rome2_l77_luaD_throw(ctx, l_va, ROME2_LUA_ERRERR);
            return;
        }
        if (msg != NULL) {
            rome2_lua_tvalue_32 *call_slots = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                ctx->arena, L->top_va - 8u, 16u);
            if (call_slots != NULL) {
                rome2_lua_tvalue_32 saved = *msg;
                call_slots[0] = *ef;
                call_slots[1] = saved;
                L->top_va += 8u;
                rome2_l77_luaD_call(ctx, l_va, L->top_va - 16u, 1);
            }
        }
    }
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L != NULL && L->error_jmp_va != 0u) {
        const rome2_lua_tvalue_32 *errv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, L->top_va - 8u, sizeof(*errv));
        rome2_lua_tvalue_32 *slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
            ctx->arena, L->error_jmp_va, sizeof(*slot));
        if (errv != NULL && slot != NULL) {
            *slot = *errv;
        }
    }
    rome2_l77_luaD_throw(ctx, l_va, ROME2_LUA_ERRRUN);
}

/* 0x10f43e70 */
int32_t rome2_l78_lua_error(rome2_l77_ctx *ctx, uint32_t l_va) {
    rome2_l78_luaG_errormsg(ctx, l_va);
    return 0;
}

/* 0x10f43fe0 */
void rome2_l78_lua_getfield(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx, const char *k) {
    rome2_lua_state_32 *L;
    uint32_t t_va;
    const rome2_lua_tvalue_32 *t;
    rome2_lua_tvalue_32 key;
    uint32_t top_va;
    if (ctx == NULL || k == NULL) {
        return;
    }
    t_va = rome2_l76_index2adr(ctx->arena, l_va, idx);
    t = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, t_va, sizeof(*t));
    if (t == NULL) {
        return;
    }
    key.value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, k, strlen(k));
    key.tt = ROME2_LUA_TSTRING;
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L == NULL) {
        return;
    }
    top_va = L->top_va;
    L->top_va += (uint32_t)sizeof(rome2_lua_tvalue_32);
    rome2_l77_luaV_gettable(ctx, l_va, t, &key, top_va);
}

/* 0x10f44090 */
void rome2_l78_lua_gettable(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t t_va;
    const rome2_lua_tvalue_32 *t;
    const rome2_lua_tvalue_32 *k;
    if (L == NULL) {
        return;
    }
    t_va = rome2_l76_index2adr(ctx->arena, l_va, idx);
    t = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, t_va, sizeof(*t));
    k = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, L->top_va - 8u, sizeof(*k));
    if (t != NULL && k != NULL) {
        rome2_lua_tvalue_32 key_copy = *k;
        rome2_l77_luaV_gettable(ctx, l_va, t, &key_copy, L->top_va - 8u);
    }
}

/* 0x10f46cc0 */
void rome2_l78_stack_init(rome2_l77_ctx *ctx, uint32_t l1_va, uint32_t l_va) {
    rome2_lua_state_32 *L1 = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l1_va, sizeof(*L1))
        : NULL;
    uint32_t ci_va;
    uint32_t stk_va;
    int32_t i;
    rome2_lua_callinfo_32 *ci;
    if (L1 == NULL) {
        return;
    }
    ci_va = rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, 8u * (uint32_t)sizeof(rome2_lua_callinfo_32));
    stk_va = rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, 45u * (uint32_t)sizeof(rome2_lua_tvalue_32));
    L1 = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l1_va, sizeof(*L1));
    if (L1 == NULL || ci_va == 0u || stk_va == 0u) {
        return;
    }
    L1->base_ci_va = ci_va;
    L1->ci_va = ci_va;
    L1->size_ci = 8;
    L1->end_ci_va = ci_va + 7u * (uint32_t)sizeof(rome2_lua_callinfo_32);
    L1->stack_va = stk_va;
    L1->stacksize = 45;
    for (i = 0; i < 45; ++i) {
        rome2_lua_tvalue_32 *slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
            ctx->arena, stk_va + (uint32_t)i * 8u, sizeof(*slot));
        if (slot != NULL) {
            slot->tt = ROME2_LUA_TNIL;
            slot->value_u32 = 0u;
        }
    }
    L1->stack_last_va = stk_va + 40u * (uint32_t)sizeof(rome2_lua_tvalue_32);
    ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(ctx->arena, ci_va, sizeof(*ci));
    if (ci != NULL) {
        ci->func_va = stk_va;
        L1->top_va = stk_va + 8u;
        L1->base_va = stk_va + 8u;
        ci->base_va = L1->base_va;
        ci->top_va = L1->top_va + 20u * (uint32_t)sizeof(rome2_lua_tvalue_32);
    }
}

/* 0x10f46a20 */
uint32_t rome2_l78_luaE_newthread(rome2_l77_ctx *ctx, uint32_t l_va) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t l1_va;
    rome2_lua_state_32 *L1;
    if (L == NULL) {
        return 0u;
    }
    l1_va = rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, (uint32_t)sizeof(rome2_lua_state_32));
    if (l1_va == 0u) {
        return 0u;
    }
    rome2_l75_luaC_link(ctx->arena, l_va, l1_va, ROME2_LUA_TTHREAD);
    rome2_l75_preinit_state(ctx->arena, l1_va, L->l_g_va);
    rome2_l78_stack_init(ctx, l1_va, l_va);
    L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L));
    L1 = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l1_va, sizeof(*L1));
    if (L != NULL && L1 != NULL) {
        L1->l_gt = L->l_gt;
        L1->hookmask = L->hookmask;
        L1->basehookcount = L->basehookcount;
        L1->hook_va = L->hook_va;
        L1->hookcount = L1->basehookcount;
    }
    return l1_va;
}

/* 0x10f44310 */
uint32_t rome2_l78_lua_newthread(rome2_l77_ctx *ctx, uint32_t l_va) {
    uint32_t l1_va;
    rome2_lua_tvalue_32 tv;
    if (ctx == NULL) {
        return 0u;
    }
    l78_gc_step_if_over(ctx, l_va);
    l1_va = rome2_l78_luaE_newthread(ctx, l_va);
    if (l1_va != 0u) {
        tv.value_u32 = l1_va;
        tv.tt = ROME2_LUA_TTHREAD;
        (void)l78_push_tvalue(ctx, l_va, &tv);
    }
    return l1_va;
}

/* 0x10f4a750 */
uint32_t rome2_l78_luaS_newudata(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    size_t s,
    uint32_t e_va) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    uint32_t u_va;
    rome2_lua_userdata_hdr_32 *u;
    rome2_lua_state_32 *mt;
    if (g == NULL) {
        return 0u;
    }
    if (s > 0xffffffe5u) {
        return rome2_l77_luaM_toobig(ctx, l_va);
    }
    u_va = rome2_l77_luaM_realloc(
        ctx, l_va, 0u, 0u, (uint32_t)sizeof(rome2_lua_userdata_hdr_32) + (uint32_t)s);
    u = (rome2_lua_userdata_hdr_32 *)rome2_l75_mut_ptr(ctx->arena, u_va, sizeof(*u));
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g));
    if (u == NULL || g == NULL) {
        return 0u;
    }
    u->tt = ROME2_LUA_TUSERDATA;
    u->marked = (uint8_t)(g->currentwhite & 3u);
    u->len = (uint32_t)s;
    u->metatable_va = 0u;
    u->env_va = e_va;
    mt = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, g->mainthread_va, sizeof(*mt));
    if (mt != NULL) {
        u->next_va = mt->next_va;
        mt->next_va = u_va;
    } else {
        u->next_va = g->rootgc_va;
        g->rootgc_va = u_va;
    }
    return u_va;
}

/* 0x10f44350 */
uint32_t rome2_l78_lua_newuserdata(rome2_l77_ctx *ctx, uint32_t l_va, size_t size) {
    const rome2_lua_state_32 *L;
    const rome2_lua_callinfo_32 *ci;
    const rome2_lua_tvalue_32 *fn;
    const rome2_lua_closure_hdr_32 *cl;
    uint32_t env_va = 0u;
    uint32_t u_va;
    rome2_lua_tvalue_32 tv;
    if (ctx == NULL) {
        return 0u;
    }
    l78_gc_step_if_over(ctx, l_va);
    L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L));
    if (L == NULL) {
        return 0u;
    }
    ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(ctx->arena, L->ci_va, sizeof(*ci));
    fn = (ci != NULL)
        ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, ci->func_va, sizeof(*fn))
        : NULL;
    cl = (fn != NULL && fn->tt == ROME2_LUA_TFUNCTION)
        ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(ctx->arena, fn->value_u32, sizeof(*cl))
        : NULL;
    if (cl != NULL) {
        env_va = cl->env_va;
    } else if (L->l_gt.tt == ROME2_LUA_TTABLE) {
        env_va = L->l_gt.value_u32;
    }
    u_va = rome2_l78_luaS_newudata(ctx, l_va, size, env_va);
    if (u_va == 0u) {
        return 0u;
    }
    tv.value_u32 = u_va;
    tv.tt = ROME2_LUA_TUSERDATA;
    (void)l78_push_tvalue(ctx, l_va, &tv);
    return u_va + (uint32_t)sizeof(rome2_lua_userdata_hdr_32);
}

/* 0x10f4de70 */
int32_t rome2_l78_luaV_tostring(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t obj_va) {
    rome2_lua_tvalue_32 *obj = (ctx != NULL)
        ? (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, obj_va, sizeof(*obj))
        : NULL;
    float num = 0.0f;
    char buf[32];
    uint32_t ts_va;
    if (obj == NULL || obj->tt != ROME2_LUA_TNUMBER) {
        return 0;
    }
    memcpy(&num, &obj->value_u32, sizeof(num));
    (void)snprintf(buf, sizeof(buf), "%.14g", (double)num);
    ts_va = rome2_l77_luaS_newlstr(ctx, l_va, buf, strlen(buf));
    obj = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, obj_va, sizeof(*obj));
    if (obj != NULL && ts_va != 0u) {
        obj->value_u32 = ts_va;
        obj->tt = ROME2_LUA_TSTRING;
    }
    return 1;
}

/* 0x10f443f0 */
size_t rome2_l78_lua_objlen(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx) {
    uint32_t o_va;
    const rome2_lua_tvalue_32 *o;
    if (ctx == NULL) {
        return 0u;
    }
    o_va = rome2_l76_index2adr(ctx->arena, l_va, idx);
    o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, o_va, sizeof(*o));
    if (o == NULL) {
        return 0u;
    }
    switch (o->tt) {
        case ROME2_LUA_TSTRING: {
            const rome2_lua_tstring_hdr_32 *ts = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
                ctx->arena, o->value_u32, sizeof(*ts));
            return (ts != NULL) ? (size_t)ts->len : 0u;
        }
        case ROME2_LUA_TNUMBER: {
            if (rome2_l78_luaV_tostring(ctx, l_va, o_va) != 0) {
                o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, o_va, sizeof(*o));
                if (o != NULL && o->tt == ROME2_LUA_TSTRING) {
                    const rome2_lua_tstring_hdr_32 *ts = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
                        ctx->arena, o->value_u32, sizeof(*ts));
                    return (ts != NULL) ? (size_t)ts->len : 0u;
                }
            }
            return 0u;
        }
        case ROME2_LUA_TTABLE:
            return (size_t)rome2_l75_luaH_getn(ctx->arena, o->value_u32);
        case ROME2_LUA_TUSERDATA: {
            const rome2_lua_userdata_hdr_32 *ud = (const rome2_lua_userdata_hdr_32 *)rome2_l75_const_ptr(
                ctx->arena, o->value_u32, sizeof(*ud));
            return (ud != NULL) ? (size_t)ud->len : 0u;
        }
        default:
            return 0u;
    }
}

/* 0x10f47ff0 */
int32_t rome2_l78_luaD_pcall(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    rome2_l78_pfunc func,
    uint32_t ud_va,
    int32_t old_top,
    int32_t ef) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint16_t oldnCcalls;
    int32_t old_ci;
    uint8_t old_allowhooks;
    int32_t old_errfunc;
    uint32_t old_error_jmp;
    uint32_t err_slot_va;
    int32_t status = ROME2_LUA_OK;
    if (L == NULL || func == NULL) {
        return ROME2_LUA_ERRRUN;
    }
    oldnCcalls = L->nCcalls;
    old_ci = (int32_t)(L->ci_va - L->base_ci_va);
    old_allowhooks = L->allowhook;
    old_errfunc = L->errfunc;
    old_error_jmp = L->error_jmp_va;
    err_slot_va = l78_alloc_zero(ctx, (uint32_t)sizeof(rome2_lua_tvalue_32));
    L->error_jmp_va = err_slot_va;
    L->errfunc = ef;
    ctx->last_thrown_err = ROME2_LUA_OK;
    func(ctx, l_va, ud_va);
    status = ctx->last_thrown_err;
    if (status != ROME2_LUA_OK) {
        uint32_t oldtop_va;
        const rome2_lua_tvalue_32 *saved_err = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, err_slot_va, sizeof(*saved_err));
        L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
        if (L != NULL) {
            if (saved_err != NULL && saved_err->tt != ROME2_LUA_TNIL) {
                rome2_lua_tvalue_32 *top_slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, L->top_va, sizeof(*top_slot));
                if (top_slot != NULL) {
                    *top_slot = *saved_err;
                    L->top_va += (uint32_t)sizeof(*top_slot);
                }
            }
            oldtop_va = L->stack_va + (uint32_t)old_top;
            rome2_l77_luaF_close(ctx, l_va, oldtop_va);
            rome2_l77_luaD_seterrorobj(ctx, l_va, status, oldtop_va);
            L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
            if (L != NULL) {
                L->nCcalls = oldnCcalls;
                L->ci_va = L->base_ci_va + (uint32_t)old_ci;
                {
                    const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
                        ctx->arena, L->ci_va, sizeof(*ci));
                    if (ci != NULL) {
                        L->base_va = ci->base_va;
                        L->savedpc_va = ci->savedpc_va;
                    }
                }
                L->allowhook = old_allowhooks;
            }
        }
        ctx->last_thrown_err = ROME2_LUA_OK;
    }
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L != NULL) {
        L->error_jmp_va = old_error_jmp;
        L->errfunc = old_errfunc;
    }
    return status;
}

typedef struct l78_calls {
    uint32_t func_va;
    int32_t nresults;
} l78_calls;

static void l78_f_call(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t ud_va) {
    const l78_calls *c = (const l78_calls *)rome2_l75_const_ptr(ctx->arena, ud_va, sizeof(*c));
    if (c != NULL) {
        rome2_l77_luaD_call(ctx, l_va, c->func_va, c->nresults);
    }
}

/* 0x10f44460 */
int32_t rome2_l78_lua_pcall(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    int32_t nargs,
    int32_t nresults,
    int32_t errfunc) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    int32_t ef = 0;
    uint32_t ud_va;
    l78_calls *c;
    int32_t old_top;
    int32_t status;
    if (L == NULL || nargs < 0) {
        return ROME2_LUA_ERRRUN;
    }
    if (errfunc != 0) {
        uint32_t ef_va = rome2_l76_index2adr(ctx->arena, l_va, errfunc);
        ef = (int32_t)l78_stack_base_off(ctx->arena, l_va, ef_va);
    }
    ud_va = l78_alloc_zero(ctx, (uint32_t)sizeof(*c));
    c = (l78_calls *)rome2_l75_mut_ptr(ctx->arena, ud_va, sizeof(*c));
    if (c == NULL) {
        return ROME2_LUA_ERRMEM;
    }
    c->func_va = L->top_va - (uint32_t)(nargs + 1) * (uint32_t)sizeof(rome2_lua_tvalue_32);
    c->nresults = nresults;
    old_top = (int32_t)l78_stack_base_off(ctx->arena, l_va, c->func_va);
    status = rome2_l78_luaD_pcall(ctx, l_va, l78_f_call, ud_va, old_top, ef);
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L != NULL && nresults == ROME2_LUA_MULTRET) {
        rome2_lua_callinfo_32 *ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(
            ctx->arena, L->ci_va, sizeof(*ci));
        if (ci != NULL && L->top_va > ci->top_va) {
            ci->top_va = L->top_va;
        }
    }
    return status;
}

/* 0x10f48ce0 */
uint32_t rome2_l78_luaF_newCclosure(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    int32_t nelems,
    uint32_t e_va) {
    uint32_t size = (uint32_t)sizeof(rome2_lua_closure_hdr_32)
        + (uint32_t)(nelems > 0 ? nelems : 0) * (uint32_t)sizeof(rome2_lua_tvalue_32);
    uint32_t c_va = rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, size);
    rome2_lua_closure_hdr_32 *c;
    if (c_va == 0u) {
        return 0u;
    }
    rome2_l75_luaC_link(ctx->arena, l_va, c_va, ROME2_LUA_TFUNCTION);
    c = (rome2_lua_closure_hdr_32 *)rome2_l75_mut_ptr(ctx->arena, c_va, sizeof(*c));
    if (c != NULL) {
        c->isC = 1u;
        c->env_va = e_va;
        c->nupvalues = (uint8_t)nelems;
    }
    return c_va;
}

/* 0x10f44500 */
void rome2_l78_lua_pushcclosure(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t fn_va, int32_t n) {
    const rome2_lua_state_32 *L;
    const rome2_lua_callinfo_32 *ci;
    const rome2_lua_tvalue_32 *fn;
    const rome2_lua_closure_hdr_32 *cur_cl;
    uint32_t env_va = 0u;
    uint32_t cl_va;
    rome2_lua_closure_hdr_32 *cl;
    rome2_lua_tvalue_32 tv;
    if (ctx == NULL || n < 0) {
        return;
    }
    l78_gc_step_if_over(ctx, l_va);
    L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L));
    if (L == NULL) {
        return;
    }
    ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(ctx->arena, L->ci_va, sizeof(*ci));
    fn = (ci != NULL)
        ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, ci->func_va, sizeof(*fn))
        : NULL;
    cur_cl = (fn != NULL && fn->tt == ROME2_LUA_TFUNCTION)
        ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(ctx->arena, fn->value_u32, sizeof(*cur_cl))
        : NULL;
    if (cur_cl != NULL) {
        env_va = cur_cl->env_va;
    } else if (L->l_gt.tt == ROME2_LUA_TTABLE) {
        env_va = L->l_gt.value_u32;
    }
    cl_va = rome2_l78_luaF_newCclosure(ctx, l_va, n, env_va);
    cl = (rome2_lua_closure_hdr_32 *)rome2_l75_mut_ptr(ctx->arena, cl_va, sizeof(*cl));
    if (cl == NULL) {
        return;
    }
    cl->f_or_p_va = fn_va;
    {
        rome2_lua_state_32 *Lm = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*Lm));
        int32_t i;
        if (Lm != NULL) {
            Lm->top_va -= (uint32_t)n * (uint32_t)sizeof(rome2_lua_tvalue_32);
            for (i = 0; i < n; ++i) {
                const rome2_lua_tvalue_32 *src = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, Lm->top_va + (uint32_t)i * 8u, sizeof(*src));
                rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, cl_va + (uint32_t)sizeof(*cl) + (uint32_t)i * 8u, sizeof(*dst));
                if (src != NULL && dst != NULL) {
                    *dst = *src;
                }
            }
        }
    }
    tv.value_u32 = cl_va;
    tv.tt = ROME2_LUA_TFUNCTION;
    (void)l78_push_tvalue(ctx, l_va, &tv);
}

/* 0x10f44750 */
const char *rome2_l78_lua_pushvfstring(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const char *fmt,
    va_list argp) {
    uint32_t cstr_va;
    if (ctx == NULL || fmt == NULL) {
        return NULL;
    }
    l78_gc_step_if_over(ctx, l_va);
    cstr_va = rome2_l77_luaO_pushvfstring(ctx, l_va, fmt, argp);
    return rome2_l75_cstr_at(ctx->arena, cstr_va);
}

/* 0x10f445a0 */
const char *rome2_l78_lua_pushfstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, ...) {
    va_list ap;
    const char *res;
    va_start(ap, fmt);
    res = rome2_l78_lua_pushvfstring(ctx, l_va, fmt, ap);
    va_end(ap);
    return res;
}

/* 0x10f44610 */
void rome2_l78_lua_pushlstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *s, size_t len) {
    rome2_lua_tvalue_32 tv;
    if (ctx == NULL || s == NULL) {
        return;
    }
    l78_gc_step_if_over(ctx, l_va);
    tv.value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, s, len);
    tv.tt = ROME2_LUA_TSTRING;
    (void)l78_push_tvalue(ctx, l_va, &tv);
}

/* 0x10f44690 */
void rome2_l78_lua_pushstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *s) {
    if (s == NULL) {
        if (ctx != NULL) {
            rome2_l76_lua_pushnil(ctx->arena, l_va);
        }
        return;
    }
    rome2_l78_lua_pushlstring(ctx, l_va, s, strlen(s));
}

/* 0x10f44890 */
void rome2_l78_lua_rawseti(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx, int32_t n) {
    rome2_lua_state_32 *L;
    uint32_t t_va;
    const rome2_lua_tvalue_32 *t;
    uint32_t slot_va;
    rome2_lua_tvalue_32 *dst;
    const rome2_lua_tvalue_32 *val;
    if (ctx == NULL) {
        return;
    }
    t_va = rome2_l76_index2adr(ctx->arena, l_va, idx);
    t = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, t_va, sizeof(*t));
    if (t == NULL || t->tt != ROME2_LUA_TTABLE) {
        return;
    }
    slot_va = rome2_l77_luaH_setnum(ctx, l_va, t->value_u32, n);
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L == NULL) {
        return;
    }
    val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, L->top_va - 8u, sizeof(*val));
    dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, slot_va, sizeof(*dst));
    if (dst != NULL && val != NULL) {
        *dst = *val;
        if (val->tt > ROME2_LUA_TNUMBER) {
            rome2_l75_luaC_barrierback(ctx->arena, l_va, t->value_u32);
        }
    }
    L->top_va -= 8u;
}

/* 0x10f44a70 */
void rome2_l78_lua_setfield(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx, const char *k) {
    rome2_lua_state_32 *L;
    uint32_t t_va;
    const rome2_lua_tvalue_32 *t;
    const rome2_lua_tvalue_32 *val;
    rome2_lua_tvalue_32 key;
    if (ctx == NULL || k == NULL) {
        return;
    }
    t_va = rome2_l76_index2adr(ctx->arena, l_va, idx);
    t = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, t_va, sizeof(*t));
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (t == NULL || L == NULL) {
        return;
    }
    val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, L->top_va - 8u, sizeof(*val));
    if (val == NULL) {
        return;
    }
    key.value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, k, strlen(k));
    key.tt = ROME2_LUA_TSTRING;
    {
        rome2_lua_tvalue_32 t_copy = *t;
        rome2_lua_tvalue_32 v_copy = *val;
        rome2_l77_luaV_settable(ctx, l_va, &t_copy, &key, &v_copy);
    }
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L != NULL) {
        L->top_va -= 8u;
    }
}

/* 0x10f44b80 */
void rome2_l78_lua_settable(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx) {
    rome2_lua_state_32 *L;
    uint32_t t_va;
    const rome2_lua_tvalue_32 *t;
    const rome2_lua_tvalue_32 *key;
    const rome2_lua_tvalue_32 *val;
    if (ctx == NULL) {
        return;
    }
    t_va = rome2_l76_index2adr(ctx->arena, l_va, idx);
    t = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, t_va, sizeof(*t));
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (t == NULL || L == NULL) {
        return;
    }
    key = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, L->top_va - 16u, sizeof(*key));
    val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, L->top_va - 8u, sizeof(*val));
    if (key != NULL && val != NULL) {
        rome2_lua_tvalue_32 t_copy = *t;
        rome2_lua_tvalue_32 k_copy = *key;
        rome2_lua_tvalue_32 v_copy = *val;
        rome2_l77_luaV_settable(ctx, l_va, &t_copy, &k_copy, &v_copy);
    }
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L != NULL) {
        L->top_va -= 16u;
    }
}

/* 0x10f44d70 */
const char *rome2_l78_lua_tolstring(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    int32_t idx,
    size_t *len_out) {
    uint32_t s_va;
    const rome2_lua_tvalue_32 *s;
    const rome2_lua_tstring_hdr_32 *ts;
    if (ctx == NULL) {
        return NULL;
    }
    s_va = rome2_l76_index2adr(ctx->arena, l_va, idx);
    s = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, s_va, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    if (s->tt != ROME2_LUA_TSTRING) {
        if (rome2_l78_luaV_tostring(ctx, l_va, s_va) == 0) {
            if (len_out != NULL) {
                *len_out = 0u;
            }
            return NULL;
        }
        l78_gc_step_if_over(ctx, l_va);
        s_va = rome2_l76_index2adr(ctx->arena, l_va, idx);
        s = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, s_va, sizeof(*s));
        if (s == NULL || s->tt != ROME2_LUA_TSTRING) {
            return NULL;
        }
    }
    ts = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(ctx->arena, s->value_u32, sizeof(*ts));
    if (len_out != NULL) {
        *len_out = (ts != NULL) ? (size_t)ts->len : 0u;
    }
    return rome2_l75_cstr_at(ctx->arena, s->value_u32 + (uint32_t)sizeof(rome2_lua_tstring_hdr_32));
}

/* 0x10f475e0 */
int32_t rome2_l78_lua_getinfo(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const char *what,
    rome2_lua_debug_32 *ar) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t func_va = 0u;
    uint32_t ci_va = 0u;
    int32_t status;
    const rome2_lua_tvalue_32 *func;
    if (L == NULL || what == NULL || ar == NULL) {
        return 0;
    }
    if (*what == '>') {
        func_va = L->top_va - 8u;
        ++what;
        {
            rome2_lua_state_32 *Lm = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*Lm));
            if (Lm != NULL) {
                Lm->top_va -= 8u;
            }
        }
    } else if (ar->i_ci != 0) {
        ci_va = L->base_ci_va + (uint32_t)ar->i_ci * (uint32_t)sizeof(rome2_lua_callinfo_32);
        {
            const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
                ctx->arena, ci_va, sizeof(*ci));
            if (ci != NULL) {
                func_va = ci->func_va;
            }
        }
    }
    func = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, func_va, sizeof(*func));
    if (func == NULL) {
        return 0;
    }
    status = rome2_l75_aux_getinfo(ctx->arena, l_va, what, ar, func->value_u32, ci_va);
    if (strchr(what, 'f') != NULL) {
        (void)l78_push_tvalue(ctx, l_va, func);
    }
    if (strchr(what, 'L') != NULL) {
        rome2_lua_tvalue_32 tv;
        if (func->tt == ROME2_LUA_TFUNCTION) {
            const rome2_lua_closure_hdr_32 *cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(
                ctx->arena, func->value_u32, sizeof(*cl));
            if (cl != NULL && cl->isC == 0u) {
                const rome2_lua_proto_32 *pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(
                    ctx->arena, cl->f_or_p_va, sizeof(*pt));
                if (pt != NULL) {
                    uint32_t tbl_va = rome2_l77_luaH_new(ctx, l_va, 0, pt->sizelineinfo);
                    int32_t i;
                    for (i = 0; i < pt->sizelineinfo; ++i) {
                        const int32_t *lp = (const int32_t *)rome2_l75_const_ptr(
                            ctx->arena, pt->lineinfo_va + (uint32_t)i * 4u, 4u);
                        if (lp != NULL) {
                            uint32_t slot_va = rome2_l77_luaH_setnum(ctx, l_va, tbl_va, *lp);
                            rome2_lua_tvalue_32 *dv = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                                ctx->arena, slot_va, sizeof(*dv));
                            if (dv != NULL) {
                                dv->value_u32 = 1u;
                                dv->tt = ROME2_LUA_TBOOLEAN;
                            }
                        }
                    }
                    tv.value_u32 = tbl_va;
                    tv.tt = ROME2_LUA_TTABLE;
                    (void)l78_push_tvalue(ctx, l_va, &tv);
                    return status;
                }
            }
        }
        rome2_l76_lua_pushnil(ctx->arena, l_va);
    }
    return status;
}

/* 0x10f45680 */
int32_t rome2_l78_luaL_error(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, ...) {
    rome2_lua_debug_32 ar;
    va_list ap;
    if (ctx == NULL || fmt == NULL) {
        return 0;
    }
    memset(&ar, 0, sizeof(ar));
    if (rome2_l75_lua_getstack(ctx->arena, l_va, 1, &ar) != 0 &&
        rome2_l78_lua_getinfo(ctx, l_va, "Sl", &ar) != 0 &&
        ar.currentline > 0) {
        (void)rome2_l78_lua_pushfstring(ctx, l_va, "%s:%d: ", ar.short_src, ar.currentline);
    } else {
        rome2_l78_lua_pushlstring(ctx, l_va, "", 0u);
    }
    va_start(ap, fmt);
    (void)rome2_l78_lua_pushvfstring(ctx, l_va, fmt, ap);
    va_end(ap);
    rome2_l78_lua_concat(ctx, l_va, 2);
    return rome2_l78_lua_error(ctx, l_va);
}

/* 0x10f45710 */
const char *rome2_l78_luaL_findtable(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    int32_t idx,
    const char *fname,
    int32_t szhint) {
    const char *e;
    if (ctx == NULL || fname == NULL) {
        return NULL;
    }
    rome2_l76_lua_pushvalue(ctx->arena, l_va, idx);
    do {
        char part[128];
        size_t len;
        e = strchr(fname, '.');
        len = (e != NULL) ? (size_t)(e - fname) : strlen(fname);
        if (len >= sizeof(part)) {
            len = sizeof(part) - 1u;
        }
        memcpy(part, fname, len);
        part[len] = '\0';
        rome2_l78_lua_pushlstring(ctx, l_va, part, len);
        {
            const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(
                ctx->arena, l_va, sizeof(*L));
            uint32_t t_va = rome2_l76_index2adr(ctx->arena, l_va, -2);
            const rome2_lua_tvalue_32 *t = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, t_va, sizeof(*t));
            const rome2_lua_tvalue_32 *k = (L != NULL)
                ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, L->top_va - 8u, sizeof(*k))
                : NULL;
            uint32_t slot_va = (t != NULL && t->tt == ROME2_LUA_TTABLE && k != NULL)
                ? rome2_l75_luaH_get(ctx->arena, t->value_u32, k)
                : ROME2_LUA_VA_NILOBJECT;
            const rome2_lua_tvalue_32 *slot = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, slot_va, sizeof(*slot));
            if (slot != NULL && slot->tt != ROME2_LUA_TNIL) {
                rome2_lua_tvalue_32 *topm = (L != NULL)
                    ? (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, L->top_va - 8u, sizeof(*topm))
                    : NULL;
                if (topm != NULL) {
                    *topm = *slot;
                }
            } else {
                rome2_l76_lua_settop(ctx->arena, l_va, -2);
                if (t == NULL || t->tt != ROME2_LUA_TTABLE) {
                    rome2_l76_lua_settop(ctx->arena, l_va, -2);
                    return fname;
                }
                rome2_l78_lua_createtable(ctx, l_va, 0, (e != NULL) ? 1 : szhint);
                rome2_l78_lua_pushlstring(ctx, l_va, part, len);
                rome2_l76_lua_pushvalue(ctx->arena, l_va, -2);
                rome2_l78_lua_settable(ctx, l_va, -4);
                rome2_l76_lua_remove(ctx->arena, l_va, -2);
                fname = (e != NULL) ? (e + 1) : fname;
                continue;
            }
        }
        if (rome2_l76_lua_type(ctx->arena, l_va, -1) != ROME2_LUA_TTABLE) {
            rome2_l76_lua_settop(ctx->arena, l_va, -3);
            return fname;
        }
        rome2_l76_lua_remove(ctx->arena, l_va, -2);
        fname = (e != NULL) ? (e + 1) : fname;
    } while (e != NULL);
    return NULL;
}

/* 0x10f45bc0 */
int32_t rome2_l78_luaL_newmetatable(rome2_l77_ctx *ctx, uint32_t l_va, const char *tname) {
    if (ctx == NULL || tname == NULL) {
        return 0;
    }
    rome2_l78_lua_getfield(ctx, l_va, ROME2_LUA_REGISTRYINDEX, tname);
    if (rome2_l76_lua_type(ctx->arena, l_va, -1) != ROME2_LUA_TNIL) {
        return 0;
    }
    rome2_l76_lua_settop(ctx->arena, l_va, -2);
    rome2_l78_lua_createtable(ctx, l_va, 0, 0);
    rome2_l76_lua_pushvalue(ctx->arena, l_va, -1);
    rome2_l78_lua_setfield(ctx, l_va, ROME2_LUA_REGISTRYINDEX, tname);
    return 1;
}

/* 0x10f45e20 */
int32_t rome2_l78_luaL_ref(rome2_l77_ctx *ctx, uint32_t l_va, int32_t t) {
    int32_t abs_t;
    int32_t ref;
    if (ctx == NULL) {
        return ROME2_LUA_NOREF;
    }
    abs_t = (t > 0 || t <= ROME2_LUA_REGISTRYINDEX)
        ? t
        : (rome2_l76_lua_gettop(ctx->arena, l_va) + t + 1);
    if (rome2_l76_lua_type(ctx->arena, l_va, -1) == ROME2_LUA_TNIL) {
        rome2_l76_lua_settop(ctx->arena, l_va, -2);
        return ROME2_LUA_REFNIL;
    }
    rome2_l76_lua_rawgeti(ctx->arena, l_va, abs_t, 0);
    ref = rome2_l76_lua_tointeger(ctx->arena, l_va, -1);
    rome2_l76_lua_settop(ctx->arena, l_va, -2);
    if (ref != 0) {
        rome2_l76_lua_rawgeti(ctx->arena, l_va, abs_t, ref);
        rome2_l78_lua_rawseti(ctx, l_va, abs_t, 0);
    } else {
        ref = (int32_t)rome2_l78_lua_objlen(ctx, l_va, abs_t) + 1;
    }
    rome2_l78_lua_rawseti(ctx, l_va, abs_t, ref);
    return ref;
}

/* 0x10f45ed0 */
void rome2_l78_luaL_register(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const char *libname,
    const rome2_l78_reg *regs) {
    int32_t size = 0;
    const rome2_l78_reg *p;
    if (ctx == NULL || regs == NULL) {
        return;
    }
    for (p = regs; p->name != NULL; ++p) {
        ++size;
    }
    if (libname != NULL) {
        const char *conflict = rome2_l78_luaL_findtable(ctx, l_va, ROME2_LUA_REGISTRYINDEX, "_LOADED", 1);
        (void)conflict;
        rome2_l78_lua_getfield(ctx, l_va, -1, libname);
        if (rome2_l76_lua_type(ctx->arena, l_va, -1) != ROME2_LUA_TTABLE) {
            rome2_l76_lua_settop(ctx->arena, l_va, -2);
            if (rome2_l78_luaL_findtable(ctx, l_va, ROME2_LUA_GLOBALSINDEX, libname, size) != NULL) {
                (void)rome2_l78_luaL_error(ctx, l_va, "name conflict for module '%s'", libname);
                return;
            }
            rome2_l76_lua_pushvalue(ctx->arena, l_va, -1);
            rome2_l78_lua_setfield(ctx, l_va, -3, libname);
        }
        rome2_l76_lua_remove(ctx->arena, l_va, -2);
    }
    for (p = regs; p->name != NULL; ++p) {
        rome2_l78_lua_pushcclosure(ctx, l_va, p->func_va, 0);
        rome2_l78_lua_setfield(ctx, l_va, -2, p->name);
    }
}

/* 0x10f492d0 */
void rome2_l78_luaC_freeall(rome2_l77_ctx *ctx, uint32_t l_va) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    int32_t i;
    if (g == NULL) {
        return;
    }
    g->currentwhite = 0x23u;
    (void)rome2_l77_sweeplist(
        ctx,
        l_va,
        L->l_g_va + (uint32_t)offsetof(rome2_lua_global_state_32, rootgc_va),
        0xffffffffu);
    for (i = 0; i < g->strt_size; ++i) {
        (void)rome2_l77_sweeplist(ctx, l_va, g->strt_hash_va + (uint32_t)i * 4u, 0xffffffffu);
    }
    g->rootgc_va = 0u;
    g->tmudata_va = 0u;
}

/* 0x10f468c0 */
void rome2_l78_close_state(rome2_l77_ctx *ctx, uint32_t l_va) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g;
    if (L == NULL) {
        return;
    }
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g));
    rome2_l77_luaF_close(ctx, l_va, L->stack_va);
    rome2_l78_luaC_freeall(ctx, l_va);
    if (g != NULL) {
        if (g->strt_hash_va != 0u) {
            (void)rome2_l77_luaM_realloc(
                ctx, l_va, g->strt_hash_va, (uint32_t)g->strt_size * 4u, 0u);
            g->strt_hash_va = 0u;
            g->strt_size = 0;
        }
        if (g->buff_va != 0u) {
            (void)rome2_l77_luaM_realloc(ctx, l_va, g->buff_va, g->buff_size, 0u);
            g->buff_va = 0u;
            g->buff_size = 0u;
        }
    }
    if (L->base_ci_va != 0u) {
        (void)rome2_l77_luaM_realloc(
            ctx, l_va, L->base_ci_va, (uint32_t)L->size_ci * (uint32_t)sizeof(rome2_lua_callinfo_32), 0u);
    }
    if (L->stack_va != 0u) {
        (void)rome2_l77_luaM_realloc(
            ctx, l_va, L->stack_va, (uint32_t)L->stacksize * (uint32_t)sizeof(rome2_lua_tvalue_32), 0u);
    }
}

/* 0x10f46ae0 */
uint32_t rome2_l78_lua_newstate(rome2_l77_ctx *ctx, uint32_t frealloc_va, uint32_t ud_va) {
    uint32_t lg_va;
    rome2_lua_lg_32 *lg;
    uint32_t g_va;
    uint32_t gt_va;
    uint32_t reg_va;
    if (ctx == NULL) {
        return 0u;
    }
    lg_va = l78_alloc_zero(ctx, (uint32_t)sizeof(rome2_lua_lg_32));
    if (lg_va == 0u) {
        return 0u;
    }
    g_va = lg_va + (uint32_t)offsetof(rome2_lua_lg_32, g);
    rome2_l75_preinit_state(ctx->arena, lg_va, g_va);
    lg = (rome2_lua_lg_32 *)rome2_l75_mut_ptr(ctx->arena, lg_va, sizeof(*lg));
    if (lg == NULL) {
        return 0u;
    }
    lg->l.marked = 0x21u;
    lg->g.currentwhite = 0x21u;
    lg->g.frealloc_va = frealloc_va;
    lg->g.ud_va = ud_va;
    lg->g.mainthread_va = lg_va;
    lg->g.uvhead_pad[0] = 0u;
    lg->g.totalbytes = (uint32_t)sizeof(rome2_lua_lg_32);
    lg->g.gcpause = 200;
    lg->g.gcstepmul = 200;
    lg->g.gc_threshold = 0x1000000u;

    rome2_l78_stack_init(ctx, lg_va, lg_va);
    rome2_l77_luaS_resize(ctx, lg_va, 32u);
    gt_va = rome2_l77_luaH_new(ctx, lg_va, 0, 2);
    reg_va = rome2_l77_luaH_new(ctx, lg_va, 0, 2);
    lg = (rome2_lua_lg_32 *)rome2_l75_mut_ptr(ctx->arena, lg_va, sizeof(*lg));
    if (lg != NULL) {
        lg->l.l_gt.value_u32 = gt_va;
        lg->l.l_gt.tt = ROME2_LUA_TTABLE;
        lg->g.l_registry.value_u32 = reg_va;
        lg->g.l_registry.tt = ROME2_LUA_TTABLE;
        lg->g.gc_threshold = 4u * lg->g.totalbytes;
    }
    return lg_va;
}

/* 0x116cfa80 */
void rome2_l78_luaopen_string(rome2_l77_ctx *ctx, uint32_t l_va) {
    static const rome2_l78_reg strlib[] = {
        { "byte",    0x116cd010u },
        { "char",    0x116cd170u },
        { "dump",    0x116cd270u },
        { "find",    0x116cf870u },
        { "format",  0x116cf390u },
        { "gfind",   0x116ce3f0u },
        { "gmatch",  0x116ce390u },
        { "gsub",    0x116ce420u },
        { "len",     0x116cd000u },
        { "lower",   0x116cd0c0u },
        { "match",   0x116cf890u },
        { "rep",     0x116cd1e0u },
        { "reverse", 0x116cd080u },
        { "sub",     0x116cd020u },
        { "upper",   0x116cd120u },
        { NULL, 0u }
    };
    if (ctx == NULL) {
        return;
    }
    rome2_l78_luaL_register(ctx, l_va, "string", strlib);
    rome2_l78_lua_createtable(ctx, l_va, 0, 1);
    rome2_l78_lua_pushstring(ctx, l_va, "");
    rome2_l76_lua_pushvalue(ctx->arena, l_va, -2);
    (void)rome2_l76_lua_setmetatable(ctx->arena, l_va, -2);
    rome2_l76_lua_settop(ctx->arena, l_va, -2);
    rome2_l76_lua_pushvalue(ctx->arena, l_va, -2);
    rome2_l78_lua_setfield(ctx, l_va, -2, "__index");
    rome2_l76_lua_settop(ctx->arena, l_va, -2);
}
