#include "lua_core_leaf_ops.h"

#include <assert.h>
#include <string.h>

static uint32_t f32_bits(float f) {
    uint32_t u = 0u;
    memcpy(&u, &f, sizeof(u));
    return u;
}

static float bits_f32(uint32_t u) {
    float f = 0.0f;
    memcpy(&f, &u, sizeof(f));
    return f;
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

static void rawrun_cb(rome2_l75_arena *a, uint32_t l_va, uint32_t ud_va, int32_t *status_slot) {
    const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(a, l_va, sizeof(*L));
    (void)ud_va;
    assert(L->error_jmp_va == l_va);
    *status_slot = 2;
}

static void test_luaO_and_state_basics(void) {
    static uint8_t buf[16384];
    rome2_l75_arena a;
    char idbuf[64];
    float outf = 0.0f;
    rome2_lua_tvalue_32 tv1, tv2, nbuf;
    const rome2_lua_tvalue_32 *res;
    uint32_t cur = 0x100u;
    uint32_t s_hex;
    uint32_t base = 0x20000000u;

    memset(buf, 0, sizeof(buf));
    rome2_l75_arena_init(&a, base, buf, sizeof(buf));

    assert(rome2_l75_luaO_fb2int(0u) == 0u);
    assert(rome2_l75_luaO_fb2int(7u) == 7u);
    assert(rome2_l75_luaO_fb2int(8u) == 8u);
    assert(rome2_l75_luaO_fb2int(0x12u) == 20u);

    assert(rome2_l75_luaO_log2(0u) == -1);
    assert(rome2_l75_luaO_log2(1u) == 0);
    assert(rome2_l75_luaO_log2(256u) == 8);
    assert(rome2_l75_luaO_log2(513u) == 9);

    rome2_l75_luaO_chunkid(idbuf, "=custom_name", sizeof(idbuf));
    assert(strcmp(idbuf, "custom_name") == 0);
    rome2_l75_luaO_chunkid(idbuf, "@scripts/campaign/rome2_main.lua", sizeof(idbuf));
    assert(strcmp(idbuf, "@scripts/campaign/rome2_main.lua" + 1) == 0);
    rome2_l75_luaO_chunkid(idbuf, "return 1\nnext line", sizeof(idbuf));
    assert(strcmp(idbuf, "[string \"return 1...\"]") == 0);

    assert(rome2_l75_luaO_str2d(" 12.5 ", &outf) == 1 && outf == 12.5f);
    assert(rome2_l75_luaO_str2d("0x2a", &outf) == 1 && outf == 42.0f);
    assert(rome2_l75_luaO_str2d("12abc", &outf) == 0);

    s_hex = alloc_str(buf, base, &cur, "128", 3u, 0x1111u);
    tv1.value_u32 = s_hex;
    tv1.tt = ROME2_LUA_TSTRING;
    res = rome2_l75_luaV_tonumber(&a, &tv1, &nbuf);
    assert(res == &nbuf && res->tt == ROME2_LUA_TNUMBER && bits_f32(res->value_u32) == 128.0f);

    tv2 = nbuf;
    assert(rome2_l75_luaO_rawequalObj(&nbuf, &tv2) == 1);
    tv2.value_u32 = f32_bits(99.0f);
    assert(rome2_l75_luaO_rawequalObj(&nbuf, &tv2) == 0);
}

static void test_table_str_and_gc(void) {
    static uint8_t buf[32768];
    rome2_l75_arena a;
    uint32_t base = 0x30000000u;
    uint32_t cur = 0x100u;
    uint32_t l_va, g_va, t_va, arr_va, node_va, mt_va;
    uint32_t ts_foo, ts_bar, ts_mode, ts_kv, ts_nul1, ts_nul2;
    uint32_t cl_va, pt_va, code_va, k_va, line_va, lv_va, src_va, uv_va, ci_base, ci1, stk_va;
    rome2_lua_state_32 *L;
    rome2_lua_global_state_32 *g;
    rome2_lua_table_32 *t, *mt;
    rome2_lua_tvalue_32 *arr;
    rome2_lua_node_32 *nodes;
    rome2_lua_tvalue_32 kquery;
    rome2_lua_debug_32 ar;

    memset(buf, 0, sizeof(buf));
    rome2_l75_arena_init(&a, base, buf, sizeof(buf));

    l_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_state_32) + 8u;
    g_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_global_state_32) + 8u;
    rome2_l75_preinit_state(&a, l_va, g_va);
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(&a, l_va, sizeof(*L));
    g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(&a, g_va, sizeof(*g));
    assert(L->allowhook == 1u);
    g->currentwhite = 1u;
    g->mainthread_va = l_va;

    ts_foo = alloc_str(buf, base, &cur, "foo", 3u, 0x05u);
    ts_bar = alloc_str(buf, base, &cur, "bar", 3u, 0x06u);
    ts_mode = alloc_str(buf, base, &cur, "__mode", 6u, 0x01u);
    ts_kv = alloc_str(buf, base, &cur, "v", 1u, 0x02u);
    ts_nul1 = alloc_str(buf, base, &cur, "ab\0c", 4u, 0x10u);
    ts_nul2 = alloc_str(buf, base, &cur, "ab\0d", 4u, 0x11u);
    assert(rome2_l75_l_strcmp(&a, ts_nul1, ts_nul2) < 0);
    assert(rome2_l75_l_strcmp(&a, ts_nul1, ts_nul1) == 0);
    g->tmname_va[3] = ts_mode;

    t_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_table_32);
    mt_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_table_32);
    arr_va = base + cur; cur += 4u * (uint32_t)sizeof(rome2_lua_tvalue_32);
    node_va = base + cur; cur += 4u * (uint32_t)sizeof(rome2_lua_node_32);
    uint32_t mtnodes = base + cur; cur += 4u * (uint32_t)sizeof(rome2_lua_node_32);

    t = (rome2_lua_table_32 *)rome2_l75_mut_ptr(&a, t_va, sizeof(*t));
    mt = (rome2_lua_table_32 *)rome2_l75_mut_ptr(&a, mt_va, sizeof(*mt));
    arr = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&a, arr_va, 4u * sizeof(*arr));
    nodes = (rome2_lua_node_32 *)rome2_l75_mut_ptr(&a, node_va, 4u * sizeof(*nodes));
    rome2_lua_node_32 *mn = (rome2_lua_node_32 *)rome2_l75_mut_ptr(&a, mtnodes, 4u * sizeof(*mn));

    t->tt = ROME2_LUA_TTABLE; t->marked = 1u; t->lsizenode = 2u; t->metatable_va = mt_va;
    t->array_va = arr_va; t->node_va = node_va; t->sizearray = 4;
    arr[0].tt = ROME2_LUA_TNUMBER; arr[0].value_u32 = f32_bits(10.0f);
    arr[1].tt = ROME2_LUA_TNUMBER; arr[1].value_u32 = f32_bits(20.0f);
    arr[2].tt = ROME2_LUA_TNUMBER; arr[2].value_u32 = f32_bits(30.0f);
    arr[3].tt = ROME2_LUA_TNIL;
    assert(rome2_l75_luaH_getn(&a, t_va) == 3u);

    nodes[0x05u & 3u].i_key.tt = ROME2_LUA_TSTRING;
    nodes[0x05u & 3u].i_key.value_u32 = ts_foo;
    nodes[0x05u & 3u].i_val.tt = ROME2_LUA_TNUMBER;
    nodes[0x05u & 3u].i_val.value_u32 = f32_bits(77.0f);
    kquery.tt = ROME2_LUA_TSTRING;
    kquery.value_u32 = ts_foo;
    assert(rome2_l75_luaH_get(&a, t_va, &kquery) == node_va + (0x05u & 3u) * sizeof(*nodes));

    mt->tt = ROME2_LUA_TTABLE; mt->marked = 1u; mt->lsizenode = 2u; mt->node_va = mtnodes;
    mn[0x01u & 3u].i_key.tt = ROME2_LUA_TSTRING; mn[0x01u & 3u].i_key.value_u32 = ts_mode;
    mn[0x01u & 3u].i_val.tt = ROME2_LUA_TSTRING; mn[0x01u & 3u].i_val.value_u32 = ts_kv;

    /* Put collectable table in nodes[2] with value = t2_white; verify traversetable + cleartable */
    uint32_t child_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_table_32);
    rome2_lua_table_32 *child = (rome2_lua_table_32 *)rome2_l75_mut_ptr(&a, child_va, sizeof(*child));
    child->tt = ROME2_LUA_TTABLE; child->marked = 1u;
    nodes[2].i_key.tt = ROME2_LUA_TNUMBER; nodes[2].i_key.value_u32 = f32_bits(99.0f);
    nodes[2].i_val.tt = ROME2_LUA_TTABLE; nodes[2].i_val.value_u32 = child_va;

    assert(rome2_l75_traversetable(&a, g_va, t_va) == 1);
    assert((t->marked & 0x10u) != 0u);
    rome2_l75_cleartable(&a, t_va);
    assert(nodes[2].i_val.tt == ROME2_LUA_TNIL);

    /* GC link, markroot, barrier */
    rome2_l75_luaC_link(&a, l_va, t_va, ROME2_LUA_TTABLE);
    assert(g->rootgc_va == t_va);
    g->l_registry.tt = ROME2_LUA_TTABLE; g->l_registry.value_u32 = t_va;
    rome2_l75_markroot(&a, l_va);
    assert(g->gcstate == 1u);
    rome2_l75_luaC_barrierback(&a, l_va, t_va);
    assert(g->grayagain_va == t_va);

    /* Bytecode symbexec + debug stack/getinfo/getlocal */
    src_va = alloc_str(buf, base, &cur, "@lua/test.lua", 13u, 0x22u);
    pt_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_proto_32);
    cl_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_closure_hdr_32) + 4u;
    code_va = base + cur; cur += 16u;
    k_va = base + cur; cur += 16u;
    line_va = base + cur; cur += 16u;
    lv_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_locvar_32);
    uv_va = base + cur; cur += (uint32_t)sizeof(rome2_lua_upval_32);

    /* Inst 0: OP_GETGLOBAL R0 = K[0] ("bar"), Inst 1: OP_RETURN R0 1 */
    uint32_t *code = (uint32_t *)rome2_l75_mut_ptr(&a, code_va, 16u);
    code[0] = 5u | (0u << 6) | (0u << 14);
    code[1] = 0x1eu | (0u << 6) | (1u << 23);
    rome2_lua_tvalue_32 *karr = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&a, k_va, 16u);
    karr[0].tt = ROME2_LUA_TSTRING; karr[0].value_u32 = ts_bar;
    int32_t *lines = (int32_t *)rome2_l75_mut_ptr(&a, line_va, 16u);
    lines[0] = 11; lines[1] = 12;
    rome2_lua_locvar_32 *lv = (rome2_lua_locvar_32 *)rome2_l75_mut_ptr(&a, lv_va, sizeof(*lv));
    lv->varname_va = ts_foo; lv->startpc = 0; lv->endpc = 1;

    rome2_lua_proto_32 *pt = (rome2_lua_proto_32 *)rome2_l75_mut_ptr(&a, pt_va, sizeof(*pt));
    pt->tt = ROME2_LUA_TPROTO; pt->k_va = k_va; pt->code_va = code_va;
    pt->lineinfo_va = line_va; pt->locvars_va = lv_va; pt->source_va = src_va;
    pt->sizek = 1; pt->sizecode = 2; pt->sizelineinfo = 2; pt->sizelocvars = 1;
    pt->linedefined = 10; pt->lastlinedefined = 12; pt->maxstacksize = 4;

    rome2_lua_closure_hdr_32 *cl = (rome2_lua_closure_hdr_32 *)rome2_l75_mut_ptr(&a, cl_va, sizeof(*cl));
    cl->tt = ROME2_LUA_TFUNCTION; cl->isC = 0u; cl->nupvalues = 1u;
    cl->env_va = t_va; cl->f_or_p_va = pt_va;

    assert(rome2_l75_symbexec(&a, pt_va, 1, 0u) == code[0]);

    stk_va = base + cur; cur += 64u;
    ci_base = base + cur; cur += 4u * (uint32_t)sizeof(rome2_lua_callinfo_32);
    ci1 = ci_base + (uint32_t)sizeof(rome2_lua_callinfo_32);
    rome2_lua_tvalue_32 *stk = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(&a, stk_va, 64u);
    stk[0].tt = ROME2_LUA_TFUNCTION; stk[0].value_u32 = cl_va;
    stk[1].tt = ROME2_LUA_TNUMBER; stk[1].value_u32 = f32_bits(55.0f);

    rome2_lua_callinfo_32 *c1 = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(&a, ci1, sizeof(*c1));
    c1->func_va = stk_va;
    c1->base_va = stk_va + 8u;
    c1->top_va = stk_va + 24u;
    L->base_ci_va = ci_base;
    L->ci_va = ci1;
    L->savedpc_va = code_va + 4u;
    L->top_va = stk_va + 16u;

    assert(rome2_l75_lua_getstack(&a, l_va, 0, &ar) == 1 && ar.i_ci == 1);
    assert(rome2_l75_aux_getinfo(&a, l_va, "Slnu", &ar, cl_va, ci1) == 1);
    assert(ar.currentline == 11 && ar.nups == 1 && ar.linedefined == 10);
    assert(strcmp(ar.short_src, "lua/test.lua") == 0);
    assert(rome2_l75_lua_getlocal(&a, l_va, &ar, 1) == ts_foo + sizeof(rome2_lua_tstring_hdr_32));
    assert(L->top_va == stk_va + 24u);

    {
        uint32_t nm = 0u;
        uint32_t what_va = rome2_l75_getobjname(&a, l_va, ci1, 0u, &nm);
        assert(what_va == ROME2_LUA_VA_STR_LOCAL);
        assert(strcmp(rome2_l75_cstr_at(&a, nm), "foo") == 0);
    }

    assert(rome2_l75_luaD_rawrunprotected(&a, l_va, rawrun_cb, 0u) == 2);

    {
        rome2_lua_upval_32 *uv = (rome2_lua_upval_32 *)rome2_l75_mut_ptr(&a, uv_va, sizeof(*uv));
        uv->v_va = uv_va + 0x0cu;
        uv->u_value.tt = ROME2_LUA_TSTRING;
        uv->u_value.value_u32 = ts_foo;
        rome2_l75_luaC_linkupval(&a, l_va, uv_va);
        rome2_l75_traverseclosure(&a, g_va, cl_va);
        assert(rome2_l75_luaT_gettmbyobj(&a, l_va, &kquery, 3) == ROME2_LUA_VA_NILOBJECT);
        assert(rome2_l75_get_compTM(&a, l_va, mt_va, mt_va, 3u) != 0u);
    }
}

int main(void) {
    test_luaO_and_state_basics();
    test_table_str_and_gc();
    return 0;
}
