#include "lua_vm_gc_table_ops.h"

#include <assert.h>
#include <string.h>

static float bits_f32(uint32_t u) {
    float f = 0.0f;
    memcpy(&f, &u, sizeof(f));
    return f;
}

static uint32_t f32_bits(float f) {
    uint32_t u = 0u;
    memcpy(&u, &f, sizeof(u));
    return u;
}

static int32_t mock_c_add(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t cfn_va) {
    float a = rome2_l76_lua_tonumber(ctx->arena, l_va, 1);
    float b = rome2_l76_lua_tonumber(ctx->arena, l_va, 2);
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    rome2_lua_tvalue_32 *top = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, L->top_va, sizeof(*top));
    (void)cfn_va;
    top->value_u32 = f32_bits(a + b);
    top->tt = ROME2_LUA_TNUMBER;
    L->top_va += 8u;
    return 1;
}

static void test_vm_strings_tables_and_execute(void) {
    static uint8_t buf[65536];
    rome2_l75_arena arena;
    rome2_l77_ctx ctx;
    uint32_t base = 0x50000000u;
    uint32_t l_va, g_va, ci_va, stk_va, strt_va, tbl_va;
    rome2_lua_state_32 *L;
    rome2_lua_global_state_32 *g;
    rome2_lua_callinfo_32 *ci;
    uint32_t k_hello, k_world;

    memset(buf, 0, sizeof(buf));
    rome2_l75_arena_init(&arena, base, buf, sizeof(buf));
    rome2_l77_ctx_init(&ctx, &arena, base + 0x2000u, base + (uint32_t)sizeof(buf));
    ctx.c_call = mock_c_add;

    l_va = base + 0x100u;
    g_va = base + 0x200u;
    rome2_l75_preinit_state(&arena, l_va, g_va);
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(&arena, l_va, sizeof(*L));
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(&arena, g_va, sizeof(*g));
    g->currentwhite = 1u;
    g->mainthread_va = l_va;
    g->gc_threshold = 0x1000000u;

    strt_va = rome2_l77_luaM_realloc(&ctx, l_va, 0u, 0u, 32u * 4u);
    g->strt_hash_va = strt_va;
    g->strt_size = 32;

    stk_va = rome2_l77_luaM_realloc(&ctx, l_va, 0u, 0u, 45u * 8u);
    ci_va = rome2_l77_luaM_realloc(&ctx, l_va, 0u, 0u, 8u * (uint32_t)sizeof(rome2_lua_callinfo_32));
    L->stack_va = stk_va;
    L->stacksize = 45;
    L->stack_last_va = stk_va + 39u * 8u;
    L->base_va = stk_va + 8u;
    L->top_va = stk_va + 8u;
    L->base_ci_va = ci_va;
    L->ci_va = ci_va;
    L->size_ci = 8;
    L->end_ci_va = ci_va + 7u * (uint32_t)sizeof(rome2_lua_callinfo_32);
    ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(&arena, ci_va, sizeof(*ci));
    ci->base_va = L->base_va;
    ci->func_va = stk_va;
    ci->top_va = stk_va + 0xa8u;

    /* String interning + resize + pushfstring + concat */
    k_hello = rome2_l77_luaS_newlstr(&ctx, l_va, "hello", 5u);
    assert(rome2_l77_luaS_newlstr(&ctx, l_va, "hello", 5u) == k_hello);
    k_world = rome2_l77_luaS_newlstr(&ctx, l_va, "world", 5u);
    assert(k_world != k_hello);
    {
        uint32_t pstr = rome2_l77_luaO_pushfstring(&ctx, l_va, "%s-%d", "lua", 51);
        assert(strcmp(rome2_l75_cstr_at(&arena, pstr), "lua-51") == 0);
        L->top_va = L->base_va;
    }

    /* Table creation, newkey/rehash, gettable/settable */
    tbl_va = rome2_l77_luaH_new(&ctx, l_va, 0, 2);
    {
        rome2_lua_tvalue_32 kv = { k_hello, ROME2_LUA_TSTRING };
        rome2_lua_tvalue_32 vv = { f32_bits(123.0f), ROME2_LUA_TNUMBER };
        rome2_lua_tvalue_32 tv = { tbl_va, ROME2_LUA_TTABLE };
        rome2_lua_tvalue_32 outv;
        uint32_t s_va;
        rome2_l77_luaV_settable(&ctx, l_va, &tv, &kv, &vv);
        outv.tt = ROME2_LUA_TNIL;
        s_va = base + 0x1800u;
        rome2_l77_luaV_gettable(&ctx, l_va, &tv, &kv, s_va);
        outv = *(const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(&arena, s_va, sizeof(outv));
        assert(outv.tt == ROME2_LUA_TNUMBER && bits_f32(outv.value_u32) == 123.0f);
        rome2_l77_luaH_resizearray(&ctx, l_va, tbl_va, 4);
        {
            uint32_t ns = rome2_l77_luaH_setnum(&ctx, l_va, tbl_va, 2);
            rome2_lua_tvalue_32 *sp = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&arena, ns, 8u);
            sp->value_u32 = f32_bits(9.0f);
            sp->tt = ROME2_LUA_TNUMBER;
        }
    }

    /* UpVal open/find/close lifecycle */
    {
        uint32_t slot = L->base_va;
        rome2_lua_tvalue_32 *sv = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&arena, slot, 8u);
        uint32_t uv;
        sv->tt = ROME2_LUA_TNUMBER; sv->value_u32 = f32_bits(42.0f);
        uv = rome2_l77_luaF_findupval(&ctx, l_va, slot);
        assert(uv != 0u && rome2_l77_luaF_findupval(&ctx, l_va, slot) == uv);
        rome2_l77_luaF_close(&ctx, l_va, slot);
        assert(L->openupval_va == 0u);
    }

    /* Bytecode VM execution: R0 = K0 (10), R1 = K1 (20), R2 = R0 + R1, RETURN R2 2 */
    {
        uint32_t cl_va = rome2_l77_luaF_newLclosure(&ctx, l_va, 0, tbl_va);
        uint32_t pt_va = rome2_l77_luaM_realloc(&ctx, l_va, 0u, 0u, sizeof(rome2_lua_proto_32));
        uint32_t code_va = rome2_l77_luaM_realloc(&ctx, l_va, 0u, 0u, 16u);
        uint32_t k_va = rome2_l77_luaM_realloc(&ctx, l_va, 0u, 0u, 16u);
        rome2_lua_closure_hdr_32 *cl = (rome2_lua_closure_hdr_32 *)rome2_l75_mut_ptr(&arena, cl_va, sizeof(*cl));
        rome2_lua_proto_32 *pt = (rome2_lua_proto_32 *)rome2_l75_mut_ptr(&arena, pt_va, sizeof(*pt));
        uint32_t *code = (uint32_t *)rome2_l75_mut_ptr(&arena, code_va, 16u);
        rome2_lua_tvalue_32 *karr = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&arena, k_va, 16u);
        karr[0].tt = ROME2_LUA_TNUMBER; karr[0].value_u32 = f32_bits(10.0f);
        karr[1].tt = ROME2_LUA_TNUMBER; karr[1].value_u32 = f32_bits(20.0f);
        code[0] = 1u | (0u << 6) | (0u << 14);
        code[1] = 1u | (1u << 6) | (1u << 14);
        code[2] = 12u | (2u << 6) | (0u << 23) | (1u << 14);
        code[3] = 0x1eu | (2u << 6) | (2u << 23);
        pt->tt = ROME2_LUA_TPROTO; pt->k_va = k_va; pt->code_va = code_va;
        pt->sizek = 2; pt->sizecode = 4; pt->maxstacksize = 4;
        cl->f_or_p_va = pt_va;

        {
            rome2_lua_tvalue_32 *fn = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&arena, L->top_va, 8u);
            fn->tt = ROME2_LUA_TFUNCTION; fn->value_u32 = cl_va;
            L->top_va += 8u;
            rome2_l77_luaD_call(&ctx, l_va, L->top_va - 8u, 1);
            assert(rome2_l76_lua_tointeger(&arena, l_va, -1) == 30);
        }
    }

    /* Single-step GC progression + CClosure call + panic throw */
    {
        uint32_t ccl_va = rome2_l77_luaM_realloc(&ctx, l_va, 0u, 0u, sizeof(rome2_lua_closure_hdr_32));
        rome2_lua_closure_hdr_32 *ccl = (rome2_lua_closure_hdr_32 *)rome2_l75_mut_ptr(&arena, ccl_va, sizeof(*ccl));
        rome2_lua_tvalue_32 *s;
        ccl->tt = ROME2_LUA_TFUNCTION; ccl->isC = 1u; ccl->f_or_p_va = 0xdeadbeefu;
        L->top_va = L->base_va;
        s = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&arena, L->top_va, 24u);
        s[0].tt = ROME2_LUA_TFUNCTION; s[0].value_u32 = ccl_va;
        s[1].tt = ROME2_LUA_TNUMBER; s[1].value_u32 = f32_bits(7.0f);
        s[2].tt = ROME2_LUA_TNUMBER; s[2].value_u32 = f32_bits(8.0f);
        L->top_va += 24u;
        rome2_l77_luaD_call(&ctx, l_va, L->top_va - 24u, 1);
        assert(rome2_l76_lua_tointeger(&arena, l_va, -1) == 15);
    }

    g->panic_va = 0x11111111u;
    rome2_l77_luaD_throw(&ctx, l_va, ROME2_LUA_ERRRUN);
    assert(ctx.panic_calls == 1 && ctx.fatal_exit_calls == 1);

    rome2_l77_singlestep(&ctx, l_va);
    rome2_l77_atomic(&ctx, l_va);
    rome2_l77_luaH_free(&ctx, l_va, tbl_va);
}

int main(void) {
    test_vm_strings_tables_and_execute();
    return 0;
}
