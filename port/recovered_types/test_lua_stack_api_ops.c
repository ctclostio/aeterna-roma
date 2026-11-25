#include "lua_stack_api_ops.h"

#include <assert.h>
#include <string.h>

static uint32_t f32_bits(float f) {
    uint32_t u = 0u;
    memcpy(&u, &f, sizeof(u));
    return u;
}

static uint32_t alloc_str(uint8_t *buf, uint32_t base, uint32_t *cursor, const char *s, size_t len, uint32_t hash) {
    uint32_t va = base + *cursor;
    rome2_lua_tstring_hdr_32 *ts = (rome2_lua_tstring_hdr_32 *)(buf + *cursor);
    ts->tt = ROME2_LUA_TSTRING;
    ts->marked = 0u;
    ts->hash = hash;
    ts->len = (uint32_t)len;
    memcpy(buf + *cursor + sizeof(*ts), s, len + 1u);
    *cursor += (uint32_t)sizeof(*ts) + (uint32_t)((len + 1u + 3u) & ~3u);
    return va;
}

static void test_lua_stack_push_to_raw(void) {
    static uint8_t buf[32768];
    rome2_l75_arena a;
    uint32_t base = 0x40000000u;
    uint32_t cur = 0x100u;
    uint32_t l_va, g_va, ci_va, stk_va, tbl_va, arr_va, node_va, mt_va, ud_va, ts_num, ts_up;
    uint32_t cl_va, pt_va, unames_va, uv_va, light_va;
    rome2_lua_state_32 *L;
    rome2_lua_global_state_32 *g;
    rome2_lua_callinfo_32 *ci;
    rome2_lua_table_32 *tbl, *mt;
    rome2_lua_tvalue_32 *arr;
    rome2_lua_userdata_hdr_32 *ud;
    rome2_lua_closure_hdr_32 *cl;
    rome2_lua_proto_32 *pt;
    rome2_lua_upval_32 *uv;

    memset(buf, 0, sizeof(buf));
    rome2_l75_arena_init(&a, base, buf, sizeof(buf));

    l_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_state_32) + 8u;
    g_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_global_state_32) + 8u;
    rome2_l75_preinit_state(&a, l_va, g_va);
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(&a, l_va, sizeof(*L));
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(&a, g_va, sizeof(*g));
    g->currentwhite = 1u;

    stk_va = base + cur; cur += 256u;
    ci_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_callinfo_32) * 2u;
    L->base_ci_va = ci_va;
    L->ci_va = ci_va + (uint32_t)sizeof(rome2_lua_callinfo_32);
    L->base_va = stk_va + 8u;
    L->top_va = stk_va + 8u;

    ts_num = alloc_str(buf, base, &cur, "256", 3u, 0x10u);
    ts_up = alloc_str(buf, base, &cur, "up0", 3u, 0x11u);
    unames_va = base + cur; cur += 8u;
    *(uint32_t *)rome2_l75_mut_ptr(&a, unames_va, 4u) = ts_up;

    pt_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_proto_32);
    pt = (rome2_lua_proto_32 *)rome2_l75_mut_ptr(&a, pt_va, sizeof(*pt));
    pt->tt = ROME2_LUA_TPROTO;
    pt->upvalues_va = unames_va;
    pt->sizeupvalues = 1;

    uv_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_upval_32);
    uv = (rome2_lua_upval_32 *)rome2_l75_mut_ptr(&a, uv_va, sizeof(*uv));
    uv->v_va = uv_va + 0x0cu;
    uv->u_value.tt = ROME2_LUA_TNUMBER;
    uv->u_value.value_u32 = f32_bits(77.0f);

    cl_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_closure_hdr_32) + 8u;
    cl = (rome2_lua_closure_hdr_32 *)rome2_l75_mut_ptr(&a, cl_va, sizeof(*cl));
    cl->tt = ROME2_LUA_TFUNCTION; cl->isC = 0u; cl->nupvalues = 1u; cl->f_or_p_va = pt_va;
    *(uint32_t *)rome2_l75_mut_ptr(&a, cl_va + (uint32_t)sizeof(*cl), 4u) = uv_va;

    tbl_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_table_32);
    mt_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_table_32);
    arr_va = base + cur; cur += 4u * (uint32_t)sizeof(rome2_lua_tvalue_32);
    node_va = base + cur; cur += 2u * (uint32_t)sizeof(rome2_lua_node_32);
    ud_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_userdata_hdr_32) + 16u;
    light_va = base + cur;

    tbl = (rome2_lua_table_32 *)rome2_l75_mut_ptr(&a, tbl_va, sizeof(*tbl));
    mt = (rome2_lua_table_32 *)rome2_l75_mut_ptr(&a, mt_va, sizeof(*mt));
    arr = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&a, arr_va, 4u * sizeof(*arr));
    ud = (rome2_lua_userdata_hdr_32 *)rome2_l75_mut_ptr(&a, ud_va, sizeof(*ud));
    tbl->tt = ROME2_LUA_TTABLE; tbl->array_va = arr_va; tbl->node_va = node_va; tbl->sizearray = 4;
    mt->tt = ROME2_LUA_TTABLE; mt->node_va = node_va;
    arr[0].tt = ROME2_LUA_TSTRING; arr[0].value_u32 = ts_num;
    ud->tt = ROME2_LUA_TUSERDATA; ud->metatable_va = mt_va;

    {
        rome2_lua_tvalue_32 *func_slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&a, stk_va, sizeof(*func_slot));
        func_slot->tt = ROME2_LUA_TFUNCTION; func_slot->value_u32 = cl_va;
    }
    ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(&a, L->ci_va, sizeof(*ci));
    ci->func_va = stk_va;
    ci->base_va = L->base_va;

    rome2_l76_lua_pushboolean(&a, l_va, 5);
    rome2_l76_lua_pushlightuserdata(&a, l_va, light_va);
    rome2_l76_lua_pushnil(&a, l_va);
    rome2_l76_lua_pushvalue(&a, l_va, 1);
    assert(rome2_l76_lua_gettop(&a, l_va) == 4);
    assert(rome2_l76_lua_toboolean(&a, l_va, 1) == 1);
    assert(rome2_l76_lua_toboolean(&a, l_va, 3) == 0);
    assert(rome2_l76_lua_isuserdata(&a, l_va, 2) == 1);
    assert(rome2_l76_lua_touserdata(&a, l_va, 2) == light_va);
    assert(rome2_l76_lua_type(&a, l_va, 99) == -1);
    assert(strcmp(rome2_l76_lua_typename(-1), "no value") == 0);
    assert(strcmp(rome2_l76_lua_typename(ROME2_LUA_TFUNCTION), "function") == 0);

    rome2_l76_lua_insert(&a, l_va, 1);
    assert(rome2_l76_lua_type(&a, l_va, 1) == ROME2_LUA_TBOOLEAN);
    rome2_l76_lua_remove(&a, l_va, 2);
    assert(rome2_l76_lua_gettop(&a, l_va) == 3);
    rome2_l76_lua_settop(&a, l_va, 5);
    assert(rome2_l76_lua_gettop(&a, l_va) == 5 && rome2_l76_lua_type(&a, l_va, 5) == ROME2_LUA_TNIL);
    rome2_l76_lua_settop(&a, l_va, -3);
    assert(rome2_l76_lua_gettop(&a, l_va) == 3);

    /* Table + rawgeti/rawget + tointeger/tonumber + metatable + setfenv + getupvalue */
    {
        rome2_lua_tvalue_32 *s1 = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&a, L->base_va, sizeof(*s1));
        s1->tt = ROME2_LUA_TTABLE; s1->value_u32 = tbl_va;
        L->top_va = L->base_va + 8u;
    }
    rome2_l76_lua_rawgeti(&a, l_va, 1, 1);
    assert(rome2_l76_lua_tointeger(&a, l_va, -1) == 256);
    assert(rome2_l76_lua_tonumber(&a, l_va, -1) == 256.0f);
    {
        rome2_lua_tvalue_32 num_key = { f32_bits(1.0f), ROME2_LUA_TNUMBER };
        rome2_l75_luaA_pushobject(&a, l_va, &num_key);
        rome2_l76_lua_rawget(&a, l_va, 1);
        assert(rome2_l76_lua_tointeger(&a, l_va, -1) == 256);
    }
    {
        rome2_lua_tvalue_32 mtv = { mt_va, ROME2_LUA_TTABLE };
        rome2_l75_luaA_pushobject(&a, l_va, &mtv);
        assert(rome2_l76_lua_setmetatable(&a, l_va, 1) == 1);
        assert(rome2_l76_lua_getmetatable(&a, l_va, 1) == 1);
        assert(rome2_l76_lua_setfenv(&a, l_va, 0) == 0);
    }
    {
        rome2_lua_tvalue_32 udv = { ud_va, ROME2_LUA_TUSERDATA };
        rome2_l75_luaA_pushobject(&a, l_va, &udv);
        assert(rome2_l76_lua_touserdata(&a, l_va, -1) == ud_va + 0x18u);
        {
            rome2_lua_tvalue_32 fnv = { cl_va, ROME2_LUA_TFUNCTION };
            rome2_l75_luaA_pushobject(&a, l_va, &fnv);
            assert(rome2_l76_lua_getupvalue(&a, l_va, -1, 1) == ts_up + 0x10u);
            assert(rome2_l76_lua_tointeger(&a, l_va, -1) == 77);
            {
                rome2_lua_tvalue_32 ev = { mt_va, ROME2_LUA_TTABLE };
                rome2_l75_luaA_pushobject(&a, l_va, &ev);
                assert(rome2_l76_lua_setfenv(&a, l_va, -3) == 1);
                assert(cl->env_va == mt_va);
            }
        }
    }
}

static void test_binding_string_helpers(void) {
    char buf[128];
    rome2_l76_lua_format_3args(buf, sizeof(buf), "%s:%s:%s", "A", "B", "C");
    assert(strcmp(buf, "A:B:C") == 0);
    rome2_l76_lua_pointer_type_name(
        buf,
        sizeof(buf),
        "class UTILITYDLL::LUA::Pointer<class EMPIREUTILITY::EVENT const >");
    assert(strcmp(buf, "Pointer<EVENT>") == 0);
}

int main(void) {
    test_lua_stack_push_to_raw();
    test_binding_string_helpers();
    return 0;
}
