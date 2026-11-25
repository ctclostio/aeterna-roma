#include "lua_stack_api_ops.h"

#include <stdio.h>
#include <string.h>

static float l76_bits_to_f32(uint32_t u) {
    float f = 0.0f;
    memcpy(&f, &u, sizeof(f));
    return f;
}

static const char *const k_type_names[9] = {
    "nil",
    "boolean",
    "userdata",
    "number",
    "string",
    "table",
    "function",
    "userdata",
    "thread"
};

/* 0x10f43c00 */
uint32_t rome2_l76_index2adr(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    if (L == NULL) {
        return ROME2_LUA_VA_NILOBJECT;
    }
    if (idx > 0) {
        uint32_t o_va = L->base_va + (uint32_t)(idx - 1) * (uint32_t)sizeof(rome2_lua_tvalue_32);
        return (o_va < L->top_va) ? o_va : ROME2_LUA_VA_NILOBJECT;
    }
    if (idx > ROME2_LUA_REGISTRYINDEX) {
        return L->top_va + (uint32_t)idx * (uint32_t)sizeof(rome2_lua_tvalue_32);
    }
    if (idx == ROME2_LUA_GLOBALSINDEX) {
        return l_va + 0x44u;
    }
    if (idx == ROME2_LUA_ENVIRONINDEX) {
        const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
            a, L->ci_va, sizeof(*ci));
        const rome2_lua_tvalue_32 *fn_val = (ci != NULL)
            ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, ci->func_va, sizeof(*fn_val))
            : NULL;
        const rome2_lua_closure_hdr_32 *cl = (fn_val != NULL)
            ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, fn_val->value_u32, sizeof(*cl))
            : NULL;
        if (cl != NULL) {
            L->env.value_u32 = cl->env_va;
            L->env.tt = ROME2_LUA_TTABLE;
        }
        return l_va + 0x4cu;
    }
    if (idx == ROME2_LUA_REGISTRYINDEX) {
        return L->l_g_va + 0x5cu;
    }
    {
        const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
            a, L->ci_va, sizeof(*ci));
        const rome2_lua_tvalue_32 *fn_val = (ci != NULL)
            ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, ci->func_va, sizeof(*fn_val))
            : NULL;
        const rome2_lua_closure_hdr_32 *cl = (fn_val != NULL)
            ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, fn_val->value_u32, sizeof(*cl))
            : NULL;
        int32_t uidx = ROME2_LUA_GLOBALSINDEX - idx;
        if (cl != NULL && uidx >= 1 && uidx <= (int32_t)cl->nupvalues) {
            return fn_val->value_u32 + 0x0cu + (uint32_t)uidx * 8u;
        }
    }
    return ROME2_LUA_VA_NILOBJECT;
}

/* 0x10f44040 */
int32_t rome2_l76_lua_getmetatable(rome2_l75_arena *a, uint32_t l_va, int32_t objindex) {
    uint32_t obj_va = rome2_l76_index2adr(a, l_va, objindex);
    const rome2_lua_tvalue_32 *obj = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, obj_va, sizeof(*obj));
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    uint32_t mt_va = 0u;
    if (L == NULL || obj == NULL || obj->tt < 0 || obj->tt >= 9) {
        return 0;
    }
    if (obj->tt == ROME2_LUA_TTABLE) {
        const rome2_lua_table_32 *t = (const rome2_lua_table_32 *)rome2_l75_const_ptr(
            a, obj->value_u32, sizeof(*t));
        if (t != NULL) {
            mt_va = t->metatable_va;
        }
    } else if (obj->tt == ROME2_LUA_TUSERDATA) {
        const rome2_lua_userdata_hdr_32 *u = (const rome2_lua_userdata_hdr_32 *)rome2_l75_const_ptr(
            a, obj->value_u32, sizeof(*u));
        if (u != NULL) {
            mt_va = u->metatable_va;
        }
    } else {
        const rome2_lua_global_state_32 *g = (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(
            a, L->l_g_va, sizeof(*g));
        if (g != NULL) {
            mt_va = g->mt_va[obj->tt];
        }
    }
    if (mt_va == 0u) {
        return 0;
    }
    {
        rome2_lua_tvalue_32 *top = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*top));
        if (top != NULL) {
            top->value_u32 = mt_va;
            top->tt = ROME2_LUA_TTABLE;
            L->top_va += (uint32_t)sizeof(*top);
        }
    }
    return 1;
}

/* 0x10f440c0 */
int32_t rome2_l76_lua_gettop(const rome2_l75_arena *a, uint32_t l_va) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    if (L == NULL) {
        return 0;
    }
    return (int32_t)(L->top_va - L->base_va) >> 3;
}

/* 0x10f440d0 */
uint32_t rome2_l76_lua_getupvalue(rome2_l75_arena *a, uint32_t l_va, int32_t funcindex, int32_t n) {
    uint32_t fi_va = rome2_l76_index2adr(a, l_va, funcindex);
    const rome2_lua_tvalue_32 *fi = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, fi_va, sizeof(*fi));
    const rome2_lua_closure_hdr_32 *cl;
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    uint32_t name_va = 0u;
    const rome2_lua_tvalue_32 *val = NULL;
    if (L == NULL || fi == NULL || fi->tt != ROME2_LUA_TFUNCTION || n <= 0) {
        return 0u;
    }
    cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(a, fi->value_u32, sizeof(*cl));
    if (cl == NULL) {
        return 0u;
    }
    if (cl->isC == 0u) {
        const rome2_lua_proto_32 *pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(
            a, cl->f_or_p_va, sizeof(*pt));
        if (pt != NULL && n <= pt->sizeupvalues) {
            const uint32_t *uv_va_ptr = (const uint32_t *)rome2_l75_const_ptr(
                a, fi->value_u32 + 0x10u + (uint32_t)n * 4u, 4u);
            const uint32_t *un_va_ptr = (const uint32_t *)rome2_l75_const_ptr(
                a, pt->upvalues_va + (uint32_t)(n - 1) * 4u, 4u);
            if (uv_va_ptr != NULL && un_va_ptr != NULL) {
                const rome2_lua_upval_32 *uv = (const rome2_lua_upval_32 *)rome2_l75_const_ptr(
                    a, *uv_va_ptr, sizeof(*uv));
                if (uv != NULL) {
                    val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, uv->v_va, sizeof(*val));
                    name_va = *un_va_ptr + (uint32_t)sizeof(rome2_lua_tstring_hdr_32);
                }
            }
        }
    } else if (n <= (int32_t)cl->nupvalues) {
        name_va = ROME2_LUA_VA_EMPTY;
        val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            a, fi->value_u32 + 0x0cu + (uint32_t)n * 8u, sizeof(*val));
    }
    if (name_va != 0u && val != NULL) {
        rome2_lua_tvalue_32 *top = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*top));
        if (top != NULL) {
            *top = *val;
            L->top_va += (uint32_t)sizeof(*top);
            return name_va;
        }
    }
    return 0u;
}

/* 0x10f44160 */
void rome2_l76_lua_insert(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    uint32_t p_va = rome2_l76_index2adr(a, l_va, idx);
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    uint32_t q_va;
    const rome2_lua_tvalue_32 *top_val;
    rome2_lua_tvalue_32 *p_dst;
    if (L == NULL) {
        return;
    }
    for (q_va = L->top_va; q_va > p_va; q_va -= (uint32_t)sizeof(rome2_lua_tvalue_32)) {
        rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, q_va, sizeof(*dst));
        const rome2_lua_tvalue_32 *src = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            a, q_va - (uint32_t)sizeof(*src), sizeof(*src));
        if (dst != NULL && src != NULL) {
            *dst = *src;
        }
    }
    top_val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, L->top_va, sizeof(*top_val));
    p_dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, p_va, sizeof(*p_dst));
    if (top_val != NULL && p_dst != NULL) {
        *p_dst = *top_val;
    }
}

/* 0x10f44250 */
int32_t rome2_l76_lua_isuserdata(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    const rome2_lua_tvalue_32 *o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        a, rome2_l76_index2adr(a, l_va, idx), sizeof(*o));
    return (o != NULL && (o->tt == ROME2_LUA_TUSERDATA || o->tt == ROME2_LUA_TLIGHTUSERDATA)) ? 1 : 0;
}

/* 0x10f444e0 */
void rome2_l76_lua_pushboolean(rome2_l75_arena *a, uint32_t l_va, int32_t b) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    rome2_lua_tvalue_32 *top = (L != NULL)
        ? (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*top))
        : NULL;
    if (top == NULL) {
        return;
    }
    top->value_u32 = (b != 0) ? 1u : 0u;
    top->tt = ROME2_LUA_TBOOLEAN;
    L->top_va += (uint32_t)sizeof(*top);
}

/* 0x10f445f0 */
void rome2_l76_lua_pushlightuserdata(rome2_l75_arena *a, uint32_t l_va, uint32_t ptr_va) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    rome2_lua_tvalue_32 *top = (L != NULL)
        ? (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*top))
        : NULL;
    if (top == NULL) {
        return;
    }
    top->value_u32 = ptr_va;
    top->tt = ROME2_LUA_TLIGHTUSERDATA;
    L->top_va += (uint32_t)sizeof(*top);
}

/* 0x10f44650 */
void rome2_l76_lua_pushnil(rome2_l75_arena *a, uint32_t l_va) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    rome2_lua_tvalue_32 *top = (L != NULL)
        ? (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*top))
        : NULL;
    if (top == NULL) {
        return;
    }
    top->tt = ROME2_LUA_TNIL;
    L->top_va += (uint32_t)sizeof(*top);
}

/* 0x10f44720 */
void rome2_l76_lua_pushvalue(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    uint32_t src_va = rome2_l76_index2adr(a, l_va, idx);
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    const rome2_lua_tvalue_32 *src = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, src_va, sizeof(*src));
    rome2_lua_tvalue_32 *top = (L != NULL)
        ? (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*top))
        : NULL;
    if (src == NULL || top == NULL) {
        return;
    }
    *top = *src;
    L->top_va += (uint32_t)sizeof(*top);
}

/* 0x10f447c0 */
void rome2_l76_lua_rawget(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    uint32_t t_slot_va = rome2_l76_index2adr(a, l_va, idx);
    const rome2_lua_tvalue_32 *t_slot = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, t_slot_va, sizeof(*t_slot));
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    rome2_lua_tvalue_32 *key_slot;
    uint32_t val_va;
    const rome2_lua_tvalue_32 *val;
    if (t_slot == NULL || L == NULL) {
        return;
    }
    key_slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
        a, L->top_va - (uint32_t)sizeof(*key_slot), sizeof(*key_slot));
    if (key_slot == NULL) {
        return;
    }
    val_va = rome2_l75_luaH_get(a, t_slot->value_u32, key_slot);
    val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, val_va, sizeof(*val));
    if (val != NULL) {
        *key_slot = *val;
    }
}

/* 0x10f447f0 */
void rome2_l76_lua_rawgeti(rome2_l75_arena *a, uint32_t l_va, int32_t idx, int32_t n) {
    uint32_t t_slot_va = rome2_l76_index2adr(a, l_va, idx);
    const rome2_lua_tvalue_32 *t_slot = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, t_slot_va, sizeof(*t_slot));
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    uint32_t val_va;
    const rome2_lua_tvalue_32 *val;
    rome2_lua_tvalue_32 *top;
    if (t_slot == NULL || L == NULL) {
        return;
    }
    val_va = rome2_l75_luaH_getnum(a, t_slot->value_u32, n);
    val = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, val_va, sizeof(*val));
    top = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*top));
    if (val != NULL && top != NULL) {
        *top = *val;
        L->top_va += (uint32_t)sizeof(*top);
    }
}

/* 0x10f44900 */
void rome2_l76_lua_remove(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    uint32_t p_va = rome2_l76_index2adr(a, l_va, idx);
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    uint32_t cur_va;
    if (L == NULL) {
        return;
    }
    for (cur_va = p_va + (uint32_t)sizeof(rome2_lua_tvalue_32);
         cur_va < L->top_va;
         cur_va += (uint32_t)sizeof(rome2_lua_tvalue_32)) {
        rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
            a, cur_va - (uint32_t)sizeof(*dst), sizeof(*dst));
        const rome2_lua_tvalue_32 *src = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            a, cur_va, sizeof(*src));
        if (dst != NULL && src != NULL) {
            *dst = *src;
        }
    }
    L->top_va -= (uint32_t)sizeof(rome2_lua_tvalue_32);
}

/* 0x10f449f0 */
int32_t rome2_l76_lua_setfenv(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    uint32_t o_va = rome2_l76_index2adr(a, l_va, idx);
    const rome2_lua_tvalue_32 *o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, o_va, sizeof(*o));
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    const rome2_lua_tvalue_32 *env_top;
    int32_t res = 1;
    if (L == NULL || o == NULL) {
        return 0;
    }
    env_top = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        a, L->top_va - (uint32_t)sizeof(*env_top), sizeof(*env_top));
    if (env_top == NULL) {
        return 0;
    }
    if (o->tt == ROME2_LUA_TFUNCTION) {
        rome2_lua_closure_hdr_32 *cl = (rome2_lua_closure_hdr_32 *)rome2_l75_mut_ptr(
            a, o->value_u32, sizeof(*cl));
        if (cl != NULL) {
            cl->env_va = env_top->value_u32;
        }
    } else if (o->tt == ROME2_LUA_TUSERDATA) {
        rome2_lua_userdata_hdr_32 *u = (rome2_lua_userdata_hdr_32 *)rome2_l75_mut_ptr(
            a, o->value_u32, sizeof(*u));
        if (u != NULL) {
            u->env_va = env_top->value_u32;
        }
    } else if (o->tt == ROME2_LUA_TTHREAD) {
        rome2_lua_state_32 *th = (rome2_lua_state_32 *)rome2_l75_mut_ptr(
            a, o->value_u32, sizeof(*th));
        if (th != NULL) {
            th->l_gt.value_u32 = env_top->value_u32;
            th->l_gt.tt = ROME2_LUA_TTABLE;
        }
    } else {
        res = 0;
    }
    if (res != 0) {
        const uint8_t *env_hdr = (const uint8_t *)rome2_l75_const_ptr(a, env_top->value_u32, 6u);
        const uint8_t *obj_hdr = (const uint8_t *)rome2_l75_const_ptr(a, o->value_u32, 6u);
        if (env_hdr != NULL && obj_hdr != NULL && (env_hdr[5] & 3u) != 0u && (obj_hdr[5] & 4u) != 0u) {
            rome2_l75_luaC_barrierf(a, l_va, o->value_u32, env_top->value_u32);
        }
    }
    L->top_va -= (uint32_t)sizeof(rome2_lua_tvalue_32);
    return res;
}

/* 0x10f44ad0 */
int32_t rome2_l76_lua_setmetatable(rome2_l75_arena *a, uint32_t l_va, int32_t objindex) {
    uint32_t obj_va = rome2_l76_index2adr(a, l_va, objindex);
    const rome2_lua_tvalue_32 *obj = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, obj_va, sizeof(*obj));
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    const rome2_lua_tvalue_32 *mt_top;
    uint32_t mt_va;
    if (L == NULL || obj == NULL || obj->tt < 0 || obj->tt >= 9) {
        return 0;
    }
    mt_top = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        a, L->top_va - (uint32_t)sizeof(*mt_top), sizeof(*mt_top));
    if (mt_top == NULL) {
        return 0;
    }
    mt_va = (mt_top->tt == ROME2_LUA_TNIL) ? 0u : mt_top->value_u32;
    if (obj->tt == ROME2_LUA_TTABLE) {
        rome2_lua_table_32 *t = (rome2_lua_table_32 *)rome2_l75_mut_ptr(a, obj->value_u32, sizeof(*t));
        if (t != NULL) {
            t->metatable_va = mt_va;
            if (mt_va != 0u) {
                const uint8_t *mth = (const uint8_t *)rome2_l75_const_ptr(a, mt_va, 6u);
                if (mth != NULL && (mth[5] & 3u) != 0u && (t->marked & 4u) != 0u) {
                    rome2_l75_luaC_barrierback(a, l_va, obj->value_u32);
                }
            }
        }
    } else if (obj->tt == ROME2_LUA_TUSERDATA) {
        rome2_lua_userdata_hdr_32 *u = (rome2_lua_userdata_hdr_32 *)rome2_l75_mut_ptr(
            a, obj->value_u32, sizeof(*u));
        if (u != NULL) {
            u->metatable_va = mt_va;
            if (mt_va != 0u) {
                const uint8_t *mth = (const uint8_t *)rome2_l75_const_ptr(a, mt_va, 6u);
                if (mth != NULL && (mth[5] & 3u) != 0u && (u->marked & 4u) != 0u) {
                    rome2_l75_luaC_barrierf(a, l_va, obj->value_u32, mt_va);
                }
            }
        }
    } else {
        rome2_lua_global_state_32 *g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(
            a, L->l_g_va, sizeof(*g));
        if (g != NULL) {
            g->mt_va[obj->tt] = mt_va;
        }
    }
    L->top_va -= (uint32_t)sizeof(rome2_lua_tvalue_32);
    return 1;
}

/* 0x10f44bb0 */
void rome2_l76_lua_settop(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    if (L == NULL) {
        return;
    }
    if (idx >= 0) {
        uint32_t target_top = L->base_va + (uint32_t)idx * (uint32_t)sizeof(rome2_lua_tvalue_32);
        while (L->top_va < target_top) {
            rome2_lua_tvalue_32 *slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*slot));
            if (slot == NULL) {
                return;
            }
            slot->tt = ROME2_LUA_TNIL;
            L->top_va += (uint32_t)sizeof(*slot);
        }
        L->top_va = target_top;
        return;
    }
    L->top_va += (uint32_t)(idx + 1) * (uint32_t)sizeof(rome2_lua_tvalue_32);
}

/* 0x10f44cd0 */
int32_t rome2_l76_lua_toboolean(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    const rome2_lua_tvalue_32 *o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        a, rome2_l76_index2adr(a, l_va, idx), sizeof(*o));
    if (o == NULL || o->tt == ROME2_LUA_TNIL) {
        return 0;
    }
    if (o->tt == ROME2_LUA_TBOOLEAN && o->value_u32 == 0u) {
        return 0;
    }
    return 1;
}

/* 0x10f44d30 */
int32_t rome2_l76_lua_tointeger(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    rome2_lua_tvalue_32 n;
    const rome2_lua_tvalue_32 *o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        a, rome2_l76_index2adr(a, l_va, idx), sizeof(*o));
    o = rome2_l75_luaV_tonumber(a, o, &n);
    if (o == NULL) {
        return 0;
    }
    return (int32_t)l76_bits_to_f32(o->value_u32);
}

/* 0x10f44df0 */
float rome2_l76_lua_tonumber(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    rome2_lua_tvalue_32 n;
    const rome2_lua_tvalue_32 *o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        a, rome2_l76_index2adr(a, l_va, idx), sizeof(*o));
    o = rome2_l75_luaV_tonumber(a, o, &n);
    if (o == NULL) {
        return 0.0f;
    }
    return l76_bits_to_f32(o->value_u32);
}

/* 0x10f44ec0 */
uint32_t rome2_l76_lua_touserdata(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    const rome2_lua_tvalue_32 *o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        a, rome2_l76_index2adr(a, l_va, idx), sizeof(*o));
    if (o == NULL) {
        return 0u;
    }
    if (o->tt == ROME2_LUA_TLIGHTUSERDATA) {
        return o->value_u32;
    }
    if (o->tt == ROME2_LUA_TUSERDATA) {
        return o->value_u32 + (uint32_t)sizeof(rome2_lua_userdata_hdr_32);
    }
    return 0u;
}

/* 0x10f44ef0 */
int32_t rome2_l76_lua_type(rome2_l75_arena *a, uint32_t l_va, int32_t idx) {
    uint32_t o_va = rome2_l76_index2adr(a, l_va, idx);
    const rome2_lua_tvalue_32 *o;
    if (o_va == ROME2_LUA_VA_NILOBJECT) {
        return -1;
    }
    o = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, o_va, sizeof(*o));
    return (o != NULL) ? o->tt : -1;
}

/* 0x10f44f10 */
const char *rome2_l76_lua_typename(int32_t t) {
    if (t == -1) {
        return "no value";
    }
    if (t < 0 || t >= 9) {
        return "no value";
    }
    return k_type_names[t];
}

/* 0x112a5480 */
char *rome2_l76_lua_format_3args(
    char *out,
    size_t cap,
    const char *fmt,
    const char *s1,
    const char *s2,
    const char *s3) {
    if (out == NULL || cap == 0u) {
        return out;
    }
    if (fmt == NULL) {
        out[0] = '\0';
        return out;
    }
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4774)
#endif
    (void)snprintf(
        out,
        cap,
        fmt,
        s1 != NULL ? s1 : "",
        s2 != NULL ? s2 : "",
        s3 != NULL ? s3 : "");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    out[cap - 1u] = '\0';
    return out;
}

/* 0x112c0df0 */
char *rome2_l76_lua_pointer_type_name(char *out, size_t cap, const char *full_type) {
    const char *lt;
    const char *gt;
    const char *cpos;
    const char *end;
    const char *start;
    size_t len;
    char inner[256];
    if (out == NULL || cap == 0u) {
        return out;
    }
    if (full_type == NULL) {
        out[0] = '\0';
        return out;
    }
    lt = strchr(full_type, '<');
    gt = strrchr(full_type, '>');
    if (lt == NULL || gt == NULL || gt <= lt + 1) {
        (void)snprintf(out, cap, "Pointer<%s>", full_type);
        out[cap - 1u] = '\0';
        return out;
    }
    len = (size_t)(gt - (lt + 1));
    if (len >= sizeof(inner)) {
        len = sizeof(inner) - 1u;
    }
    memcpy(inner, lt + 1, len);
    inner[len] = '\0';
    cpos = strstr(inner, " const");
    end = (cpos != NULL) ? cpos : (inner + strlen(inner));
    start = inner;
    {
        const char *p;
        for (p = inner; p < end; ++p) {
            if (*p == ' ' || *p == ':') {
                start = p + 1;
            }
        }
    }
    {
        size_t clean_len = (size_t)(end - start);
        char clean[256];
        if (clean_len >= sizeof(clean)) {
            clean_len = sizeof(clean) - 1u;
        }
        memcpy(clean, start, clean_len);
        clean[clean_len] = '\0';
        (void)snprintf(out, cap, "Pointer<%s>", clean);
    }
    out[cap - 1u] = '\0';
    return out;
}
