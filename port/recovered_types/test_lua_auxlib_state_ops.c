#include "lua_auxlib_state_ops.h"

#include <assert.h>
#include <string.h>

static uint8_t g_l78_buf[65536];

static uint32_t f32_bits(float f) {
    uint32_t u = 0u;
    memcpy(&u, &f, sizeof(u));
    return u;
}

static uint32_t g_l78_openlib_va[16];
static char g_l78_openlib_name[16][16];
static uint32_t g_l78_openlib_count = 0u;

static int32_t mock_l78_c_handler(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t cfn_va) {
    if (cfn_va >= 0x116d0000u && cfn_va < 0x116d8000u) {
        const char *name = rome2_l78_lua_tolstring(ctx, l_va, 1, NULL);
        assert(g_l78_openlib_count < 16u && name != NULL);
        g_l78_openlib_va[g_l78_openlib_count] = cfn_va;
        (void)strncpy_s(g_l78_openlib_name[g_l78_openlib_count], 16u, name, 15u);
        ++g_l78_openlib_count;
        return 0;
    }
    if (cfn_va == 0xdead0001u) {
        const char *msg = rome2_l78_lua_tolstring(ctx, l_va, 1, NULL);
        (void)rome2_l78_lua_pushfstring(ctx, l_va, "handled:%s", msg != NULL ? msg : "");
        return 1;
    }
    if (cfn_va == 0xdead0002u) {
        float x = rome2_l76_lua_tonumber(ctx->arena, l_va, 1);
        float y = rome2_l76_lua_tonumber(ctx->arena, l_va, 2);
        rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
        rome2_lua_tvalue_32 *top = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, L->top_va, sizeof(*top));
        top->value_u32 = f32_bits(x + y);
        top->tt = ROME2_LUA_TNUMBER;
        L->top_va += 8u;
        return 1;
    }
    if (cfn_va == 0xdead0003u) {
        rome2_l78_luaL_error(ctx, l_va, "boom:%d", 42);
        return 0;
    }
    return 0;
}

static void test_l78_state_lifecycle_and_api(void) {
    rome2_l75_arena arena;
    rome2_l77_ctx ctx;
    uint32_t base = 0x51000000u;
    uint32_t l_va, th_va, ud_payload;
    size_t slen = 0u;
    const char *s;

    memset(g_l78_buf, 0, sizeof(g_l78_buf));
    rome2_l75_arena_init(&arena, base, g_l78_buf, sizeof(g_l78_buf));
    rome2_l77_ctx_init(&ctx, &arena, base + 0x100u, base + (uint32_t)sizeof(g_l78_buf));
    ctx.c_call = mock_l78_c_handler;

    l_va = rome2_l78_lua_newstate(&ctx, 0x11110000u, 0x22220000u);
    assert(l_va != 0u);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);

    /* Strings, concat, tolstring, objlen */
    rome2_l78_lua_pushstring(&ctx, l_va, "rome");
    rome2_l78_lua_pushlstring(&ctx, l_va, "-ii", 3u);
    rome2_l78_lua_concat(&ctx, l_va, 2);
    s = rome2_l78_lua_tolstring(&ctx, l_va, -1, &slen);
    assert(s != NULL && strcmp(s, "rome-ii") == 0 && slen == 7u);
    assert(rome2_l78_lua_objlen(&ctx, l_va, -1) == 7u);
    rome2_l76_lua_settop(&arena, l_va, 0);

    /* Number-to-string conversion via luaV_tostring & lua_objlen */
    {
        rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(&arena, l_va, sizeof(*L));
        rome2_lua_tvalue_32 *slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&arena, L->top_va, sizeof(*slot));
        const char *ns;
        slot->value_u32 = f32_bits(123.0f);
        slot->tt = ROME2_LUA_TNUMBER;
        L->top_va += 8u;
        assert(rome2_l78_lua_objlen(&ctx, l_va, -1) == 3u);
        ns = rome2_l78_lua_tolstring(&ctx, l_va, -1, NULL);
        assert(ns != NULL && strcmp(ns, "123") == 0);
        rome2_l76_lua_settop(&arena, l_va, 0);
    }

    /* Tables: setfield/getfield, settable/gettable, rawseti */
    rome2_l78_lua_createtable(&ctx, l_va, 4, 2);
    rome2_l78_lua_pushstring(&ctx, l_va, "legion");
    rome2_l78_lua_setfield(&ctx, l_va, -2, "unit");
    rome2_l78_lua_getfield(&ctx, l_va, -1, "unit");
    s = rome2_l78_lua_tolstring(&ctx, l_va, -1, NULL);
    assert(s != NULL && strcmp(s, "legion") == 0);
    rome2_l76_lua_settop(&arena, l_va, -2);

    rome2_l78_lua_pushstring(&ctx, l_va, "rank");
    rome2_l78_lua_pushstring(&ctx, l_va, "cohort");
    rome2_l78_lua_settable(&ctx, l_va, -3);
    rome2_l78_lua_pushstring(&ctx, l_va, "rank");
    rome2_l78_lua_gettable(&ctx, l_va, -2);
    s = rome2_l78_lua_tolstring(&ctx, l_va, -1, NULL);
    assert(s != NULL && strcmp(s, "cohort") == 0);
    rome2_l76_lua_settop(&arena, l_va, -2);

    rome2_l78_lua_pushstring(&ctx, l_va, "first");
    rome2_l78_lua_rawseti(&ctx, l_va, -2, 1);
    assert(rome2_l78_lua_objlen(&ctx, l_va, -1) == 1u);

    /* Userdata & coroutine thread */
    ud_payload = rome2_l78_lua_newuserdata(&ctx, l_va, 16u);
    assert(ud_payload != 0u);
    assert(rome2_l78_lua_objlen(&ctx, l_va, -1) == 16u);
    th_va = rome2_l78_lua_newthread(&ctx, l_va);
    assert(th_va != 0u && th_va != l_va);

    /* Call & pcall */
    rome2_l78_lua_pushcclosure(&ctx, l_va, 0xdead0002u, 0);
    {
        rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(&arena, l_va, sizeof(*L));
        rome2_lua_tvalue_32 *s1 = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&arena, L->top_va, 16u);
        s1[0].value_u32 = f32_bits(10.0f); s1[0].tt = ROME2_LUA_TNUMBER;
        s1[1].value_u32 = f32_bits(5.0f); s1[1].tt = ROME2_LUA_TNUMBER;
        L->top_va += 16u;
        rome2_l78_lua_call(&ctx, l_va, 2, 1);
        assert(rome2_l76_lua_tointeger(&arena, l_va, -1) == 15);
    }

    rome2_l78_close_state(&ctx, l_va);
}

static void test_l78_auxlib_refs_errors_and_stringlib(void) {
    rome2_l75_arena arena;
    rome2_l77_ctx ctx;
    uint32_t base = 0x52000000u;
    uint32_t l_va;
    int32_t r1, r2, status;

    memset(g_l78_buf, 0, sizeof(g_l78_buf));
    rome2_l75_arena_init(&arena, base, g_l78_buf, sizeof(g_l78_buf));
    rome2_l77_ctx_init(&ctx, &arena, base + 0x100u, base + (uint32_t)sizeof(g_l78_buf));
    ctx.c_call = mock_l78_c_handler;

    l_va = rome2_l78_lua_newstate(&ctx, 0u, 0u);
    assert(l_va != 0u);

    /* New metatable & findtable */
    assert(rome2_l78_luaL_newmetatable(&ctx, l_va, "Pointer<Test>") == 1);
    assert(rome2_l78_luaL_newmetatable(&ctx, l_va, "Pointer<Test>") == 0);
    rome2_l76_lua_settop(&arena, l_va, 0);

    assert(rome2_l78_luaL_findtable(&ctx, l_va, ROME2_LUA_GLOBALSINDEX, "a.b.c", 2) == NULL);
    assert(rome2_l76_lua_type(&arena, l_va, -1) == ROME2_LUA_TTABLE);
    rome2_l76_lua_settop(&arena, l_va, 0);

    /* luaL_ref */
    rome2_l78_lua_pushstring(&ctx, l_va, "item1");
    r1 = rome2_l78_luaL_ref(&ctx, l_va, ROME2_LUA_REGISTRYINDEX);
    rome2_l78_lua_pushstring(&ctx, l_va, "item2");
    r2 = rome2_l78_luaL_ref(&ctx, l_va, ROME2_LUA_REGISTRYINDEX);
    assert(r1 >= 1 && r2 > r1);
    rome2_l76_lua_rawgeti(&arena, l_va, ROME2_LUA_REGISTRYINDEX, r2);
    {
        const char *rs = rome2_l78_lua_tolstring(&ctx, l_va, -1, NULL);
        assert(rs != NULL && strcmp(rs, "item2") == 0);
    }
    rome2_l76_lua_settop(&arena, l_va, 0);

    /* luaL_openlibs calls each lualibs[] opener once, in table order, with its name */
    g_l78_openlib_count = 0u;
    rome2_l78_luaL_openlibs(&ctx, l_va);
    assert(g_l78_openlib_count == 9u);
    assert(g_l78_openlib_va[0] == 0x116d0ba0u && g_l78_openlib_name[0][0] == '\0');
    assert(g_l78_openlib_va[1] == 0x116d6af0u && strcmp(g_l78_openlib_name[1], "package") == 0);
    assert(g_l78_openlib_va[5] == 0x116d3ea0u && strcmp(g_l78_openlib_name[5], "string") == 0);
    assert(g_l78_openlib_va[8] == 0x116d7000u && strcmp(g_l78_openlib_name[8], "bit") == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);

    /* lua_newstate leaves the 17 tag-method names interned, so __index dispatch works */
    rome2_l78_lua_createtable(&ctx, l_va, 0, 0);
    rome2_l78_lua_createtable(&ctx, l_va, 0, 1);
    rome2_l78_lua_createtable(&ctx, l_va, 0, 1);
    rome2_l78_lua_pushstring(&ctx, l_va, "inherited");
    rome2_l78_lua_setfield(&ctx, l_va, -2, "k");
    rome2_l78_lua_setfield(&ctx, l_va, -2, "__index");
    (void)rome2_l76_lua_setmetatable(&arena, l_va, -2);
    rome2_l78_lua_getfield(&ctx, l_va, -1, "k");
    {
        const char *ks = rome2_l78_lua_tolstring(&ctx, l_va, -1, NULL);
        assert(ks != NULL && strcmp(ks, "inherited") == 0);
    }
    rome2_l76_lua_settop(&arena, l_va, 0);

    /* Protected pcall + error handler + lua_getinfo */
    {
        rome2_lua_debug_32 ar;
        memset(&ar, 0, sizeof(ar));
        rome2_l78_lua_pushcclosure(&ctx, l_va, 0xdead0001u, 0);
        assert(rome2_l78_lua_getinfo(&ctx, l_va, ">S", &ar) != 0);
    }

    rome2_l78_lua_pushcclosure(&ctx, l_va, 0xdead0001u, 0);
    rome2_l78_lua_pushcclosure(&ctx, l_va, 0xdead0003u, 0);
    status = rome2_l78_lua_pcall(&ctx, l_va, 0, 1, 1);
    assert(status == ROME2_LUA_ERRRUN);
    {
        const char *es = rome2_l78_lua_tolstring(&ctx, l_va, -1, NULL);
        assert(es != NULL && strcmp(es, "handled:boom:42") == 0);
    }

    rome2_l78_close_state(&ctx, l_va);
}

int main(void) {
    test_l78_state_lifecycle_and_api();
    test_l78_auxlib_refs_errors_and_stringlib();
    return 0;
}
