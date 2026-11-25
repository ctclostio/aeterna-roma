#include "startup_advice_script_bridge_ops.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

enum {
    T_BASE = 0x53000000u,
    T_OWNER_A = T_BASE + 0x40u,
    T_OWNER_B = T_BASE + 0x60u,
    T_OWNER_C = T_BASE + 0x80u,
    T_OWNER_D = T_BASE + 0xa0u,
    T_EVENT = T_BASE + 0xc0u,
    T_COMPONENT = T_BASE + 0xe0u,
    T_DETAIL = T_BASE + 0x100u, /* five 0x50-byte detail records */
    T_HEAP = T_BASE + 0x400u,
    T_FN_PACKAGE_LOADER_1 = 0x7aaa0001u,
    T_FN_PACKAGE_LOADER_2 = 0x7aaa0002u,
    T_FN_HANDLER_TRUE = 0x7eed0001u,
    T_FN_HANDLER_RAISE = 0x7eed0002u,
    T_FN_HANDLER_FALSE = 0x7eed0003u,
    T_ADVICE_A = 0x6d000001u,
    T_ADVICE_B = 0x6d000002u,
    T_ADVICE_C = 0x6d000003u,
    T_ADVICE_D = 0x6d000004u,
    T_ADVICE_E = 0x6d000005u,
    T_ADVICE_F = 0x6d000006u,
    T_MGR = 0x6d0000ffu
};

static uint8_t g_buf[0x80000];
static rome2_l79_bridge_ctx *g_bctx;

static uint32_t g_last_cfn;
static uint32_t g_threads_created;
static uint32_t g_last_thread;
static uint32_t g_log_count;
static char g_log[4096];

static uint32_t g_handler_calls;
static uint32_t g_handler_box;
static uint32_t g_handler_payload;
static uint32_t g_handler_component;
static int32_t g_handler_component_type;
static int32_t g_handler_filled;
static char g_handler_string[64];

static uint32_t g_component_va;
static uint8_t g_event_enabled;
static uint8_t g_event_visible;

static char g_trace[256];
static uint32_t g_detail_of[8];

static void trace(const char *tag, uint32_t advice_va) {
    char item[32];
    (void)snprintf(item, sizeof(item), "%s%u;", tag, (unsigned)(advice_va & 0xffu));
    (void)strncat_s(g_trace, sizeof(g_trace), item, _TRUNCATE);
}

static uint32_t read_u32(const rome2_l75_arena *a, uint32_t va) {
    const uint32_t *p = (const uint32_t *)rome2_l75_const_ptr(a, va, 4u);
    assert(p != NULL);
    return *p;
}

static void push_number(rome2_l75_arena *a, uint32_t l_va, float value) {
    rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(a, l_va, sizeof(*L));
    rome2_lua_tvalue_32 *top = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(a, L->top_va, sizeof(*top));
    memcpy(&top->value_u32, &value, sizeof(value));
    top->tt = ROME2_LUA_TNUMBER;
    L->top_va += 8u;
}

/* Calls the function at the stack top and returns the C address the VM dispatched. */
static uint32_t called_address(rome2_l77_ctx *lua, uint32_t l_va) {
    assert(rome2_l76_lua_type(lua->arena, l_va, -1) == ROME2_LUA_TFUNCTION);
    g_last_cfn = 0u;
    rome2_l78_lua_call(lua, l_va, 0, 0);
    return g_last_cfn;
}

static uint32_t global_fn_address(rome2_l77_ctx *lua, uint32_t l_va, const char *name) {
    rome2_l78_lua_getfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, name);
    return called_address(lua, l_va);
}

static uint32_t field_fn_address(rome2_l77_ctx *lua, uint32_t l_va, const char *table, const char *name) {
    uint32_t va;
    rome2_l78_lua_getfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, table);
    assert(rome2_l76_lua_type(lua->arena, l_va, -1) == ROME2_LUA_TTABLE);
    rome2_l78_lua_getfield(lua, l_va, -1, name);
    va = called_address(lua, l_va);
    rome2_l76_lua_settop(lua->arena, l_va, -2);
    return va;
}

static int32_t global_type(rome2_l77_ctx *lua, uint32_t l_va, const char *name) {
    int32_t t;
    rome2_l78_lua_getfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, name);
    t = rome2_l76_lua_type(lua->arena, l_va, -1);
    rome2_l76_lua_settop(lua->arena, l_va, -2);
    return t;
}

static void expect_weak_mode(rome2_l77_ctx *lua, uint32_t l_va, const char *table, const char *mode) {
    const char *s;
    rome2_l78_lua_getfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, table);
    assert(rome2_l76_lua_getmetatable(lua->arena, l_va, -1) != 0);
    rome2_l78_lua_getfield(lua, l_va, -1, "__mode");
    s = rome2_l78_lua_tolstring(lua, l_va, -1, NULL);
    assert(s != NULL && strcmp(s, mode) == 0);
    rome2_l76_lua_settop(lua->arena, l_va, -4);
}

static int32_t mock_c_call(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t cfn_va) {
    rome2_l75_arena *a = ctx->arena;
    g_last_cfn = cfn_va;
    switch (cfn_va) {
        case 0x116d6af0u: /* luaopen_package: package.loaders = { f1, f2 } */
            rome2_l78_lua_createtable(ctx, l_va, 0, 1);
            rome2_l78_lua_createtable(ctx, l_va, 2, 0);
            rome2_l78_lua_pushcclosure(ctx, l_va, T_FN_PACKAGE_LOADER_1, 0);
            rome2_l78_lua_rawseti(ctx, l_va, -2, 1);
            rome2_l78_lua_pushcclosure(ctx, l_va, T_FN_PACKAGE_LOADER_2, 0);
            rome2_l78_lua_rawseti(ctx, l_va, -2, 2);
            rome2_l78_lua_setfield(ctx, l_va, -2, "loaders");
            rome2_l78_lua_setfield(ctx, l_va, ROME2_LUA_GLOBALSINDEX, "package");
            return 0;
        case 0x116d3ea0u: /* luaopen_string */
            rome2_l78_lua_createtable(ctx, l_va, 0, 4);
            rome2_l78_lua_setfield(ctx, l_va, ROME2_LUA_GLOBALSINDEX, "string");
            return 0;
        case ROME2_L79_VA_TRACEBACK:
            return rome2_l79_lua_error_traceback_handler(g_bctx, l_va);
        case T_FN_HANDLER_TRUE: {
            const char *s;
            ++g_handler_calls;
            g_handler_box = rome2_l76_lua_touserdata(a, l_va, 1);
            g_handler_payload = read_u32(a, g_handler_box);
            rome2_l78_lua_getfield(ctx, l_va, 1, "string");
            s = rome2_l78_lua_tolstring(ctx, l_va, -1, NULL);
            (void)snprintf(g_handler_string, sizeof(g_handler_string), "%s", s != NULL ? s : "(nil)");
            rome2_l78_lua_getfield(ctx, l_va, 1, "component");
            g_handler_component_type = rome2_l76_lua_type(a, l_va, -1);
            g_handler_component = (g_handler_component_type == ROME2_LUA_TUSERDATA)
                ? read_u32(a, rome2_l76_lua_touserdata(a, l_va, -1))
                : 0u;
            rome2_l78_lua_getfield(ctx, l_va, 1, "filled");
            g_handler_filled = rome2_l76_lua_toboolean(a, l_va, -1);
            rome2_l76_lua_pushboolean(a, l_va, 1);
            return 1;
        }
        case T_FN_HANDLER_RAISE:
            (void)rome2_l78_luaL_error(ctx, l_va, "script-boom");
            return 0;
        case T_FN_HANDLER_FALSE:
            ++g_handler_calls;
            rome2_l76_lua_pushboolean(a, l_va, 0);
            return 1;
        default:
            return 0;
    }
}

static const char *hook_owner_name(rome2_l79_bridge_ctx *bctx, uint32_t owner_va) {
    (void)bctx;
    return (owner_va == T_OWNER_A) ? "campaign_ui" : "other";
}

static void hook_thread_created(rome2_l79_bridge_ctx *bctx, uint32_t owner_va, uint32_t l_va) {
    (void)bctx;
    (void)owner_va;
    ++g_threads_created;
    g_last_thread = l_va;
}

static void hook_log(rome2_l79_bridge_ctx *bctx, const char *text) {
    (void)bctx;
    ++g_log_count;
    (void)strncat_s(g_log, sizeof(g_log), text, _TRUNCATE);
}

static const char *hook_event_name(rome2_l79_bridge_ctx *bctx, uint32_t event_va) {
    switch (read_u32(bctx->lua->arena, event_va)) {
        case ROME2_L79_VA_ADVICE_ISSUED_EVENT_VTBL: return "AdviceIssued";
        case ROME2_L79_VA_ADVICE_ACTIVE_EVENT_VTBL: return "AdviceSuperseded";
        default: return "PanelOpened";
    }
}

static uint8_t hook_event_enabled(rome2_l79_bridge_ctx *bctx, uint32_t event_va) {
    (void)bctx;
    (void)event_va;
    return g_event_enabled;
}

static uint8_t hook_event_visible(rome2_l79_bridge_ctx *bctx, uint32_t event_va) {
    (void)bctx;
    (void)event_va;
    return g_event_visible;
}

static const char *hook_event_string(rome2_l79_bridge_ctx *bctx, uint32_t event_va) {
    (void)bctx;
    (void)event_va;
    return "advice.key";
}

static uint32_t hook_event_component(rome2_l79_bridge_ctx *bctx, uint32_t event_va) {
    (void)bctx;
    (void)event_va;
    return g_component_va;
}

static void hook_event_fill(rome2_l79_bridge_ctx *bctx, uint32_t event_va, uint32_t l_va) {
    (void)event_va;
    rome2_l76_lua_pushboolean(bctx->lua->arena, l_va, 1);
    rome2_l78_lua_setfield(bctx->lua, l_va, -2, "filled");
}

static void hook_activate(rome2_l79_bridge_ctx *bctx, uint32_t advice_va) {
    (void)bctx;
    trace("act", advice_va);
}

static void hook_dismiss(rome2_l79_bridge_ctx *bctx, uint32_t advice_va, uint32_t arg) {
    (void)bctx;
    assert(arg == 0u);
    trace("dis", advice_va);
}

static uint32_t hook_detail(rome2_l79_bridge_ctx *bctx, uint32_t advice_va) {
    (void)bctx;
    return g_detail_of[advice_va & 7u];
}

static void hook_mgr(rome2_l79_bridge_ctx *bctx, uint32_t mgr_va, uint32_t advice_va) {
    (void)bctx;
    assert(mgr_va == T_MGR);
    trace("mgr", advice_va);
}

static void reset_fixture(rome2_l75_arena *arena, rome2_l77_ctx *lua, rome2_l79_bridge_ctx *bctx) {
    memset(g_buf, 0, sizeof(g_buf));
    rome2_l75_arena_init(arena, T_BASE, g_buf, sizeof(g_buf));
    rome2_l77_ctx_init(lua, arena, T_HEAP, T_BASE + (uint32_t)sizeof(g_buf));
    lua->c_call = mock_c_call;
    rome2_l79_bridge_ctx_init(bctx, lua);
    bctx->owner_name = hook_owner_name;
    bctx->owner_thread_created = hook_thread_created;
    bctx->log_sink = hook_log;
    bctx->event_name = hook_event_name;
    bctx->event_enabled = hook_event_enabled;
    bctx->event_lua_visible = hook_event_visible;
    bctx->event_string = hook_event_string;
    bctx->event_component = hook_event_component;
    bctx->event_fill_context = hook_event_fill;
    bctx->advice_activate = hook_activate;
    bctx->advice_dismiss = hook_dismiss;
    bctx->advice_detail = hook_detail;
    bctx->mgr_advice_started = hook_mgr;
    g_bctx = bctx;
    g_threads_created = 0u;
    g_last_thread = 0u;
    g_log_count = 0u;
    g_log[0] = '\0';
    g_handler_calls = 0u;
    g_component_va = 0u;
    g_event_enabled = 1u;
    g_event_visible = 1u;
    g_trace[0] = '\0';
    memset(g_detail_of, 0, sizeof(g_detail_of));
}

static rome2_lua_script_owner_prefix24_32 *owner_at(rome2_l75_arena *a, uint32_t va) {
    return (rome2_lua_script_owner_prefix24_32 *)rome2_l75_mut_ptr(a, va, 0x18u);
}

static const rome2_lua_script_wrapper24_32 *wrapper_at(rome2_l75_arena *a, uint32_t va) {
    return (const rome2_lua_script_wrapper24_32 *)rome2_l75_const_ptr(a, va, 0x18u);
}

static const rome2_lua_wrapper_ring20_32 *node_at(rome2_l75_arena *a, uint32_t va) {
    return (const rome2_lua_wrapper_ring20_32 *)rome2_l75_const_ptr(a, va, 0x14u);
}

/* 0x112ada40, 0x112addc0, 0x112adf80, 0x112ae010, 0x112ae710 */
static void test_states_wrappers_and_ring(void) {
    rome2_l75_arena arena;
    rome2_l77_ctx lua;
    rome2_l79_bridge_ctx bctx;
    const rome2_lua_script_wrapper24_32 *wa;
    const rome2_lua_wrapper_ring20_32 *na;
    const rome2_lua_wrapper_ring20_32 *nb;
    uint32_t wrap_a, wrap_b, wrap_c, thread_a, own_a, node_a, node_b, saved_cursor;
    const char *s;

    reset_fixture(&arena, &lua, &bctx);
    assert(bctx.ring_tail_va == ROME2_L79_VA_RING_HEAD_SLOT && bctx.ring_head_va == 0u);

    /* owner with the +0x14 flag set builds its own state and threads off it */
    owner_at(&arena, T_OWNER_A)->creates_master_state = 1u;
    wrap_a = rome2_l79_get_or_init_script_wrapper(&bctx, T_OWNER_A);
    assert(wrap_a != 0u && owner_at(&arena, T_OWNER_A)->wrapper_va == wrap_a);
    wa = wrapper_at(&arena, wrap_a);
    thread_a = wa->lua_state_va;
    assert(wa->is_valid == 1u && wa->owner_ctx_va == T_OWNER_A && wa->owns_master_state == 1u);
    assert(wa->reserved10 == 0u && wa->reserved14 == 0u);
    assert(g_threads_created == 1u && g_last_thread == thread_a);
    assert(rome2_l79_get_or_init_script_wrapper(&bctx, T_OWNER_A) == wrap_a);
    assert(g_threads_created == 1u);
    assert(rome2_l79_get_script_lua_state(&bctx, T_OWNER_A) == thread_a);

    node_a = bctx.ring_head_va;
    na = node_at(&arena, node_a);
    own_a = na->parent_lua_state_va;
    assert(bctx.ring_tail_va == node_a);
    assert(na->next_va == 0u && na->prev_va == ROME2_L79_VA_RING_HEAD_SLOT);
    assert(na->wrapper_va == wrap_a && na->registry_ref >= 1);
    /* the process-wide state at 0x12031f0c is created too, but is not this wrapper's parent */
    assert(bctx.master_state_va != 0u && own_a != bctx.master_state_va && own_a != thread_a);
    assert(rome2_l76_lua_gettop(&arena, own_a) == 0 && rome2_l76_lua_gettop(&arena, thread_a) == 0);

    /* 0x112ada40 contents */
    assert(global_fn_address(&lua, own_a, "dofile") == ROME2_L79_VA_DOFILE);
    assert(global_fn_address(&lua, own_a, "loadfile") == ROME2_L79_VA_LOADFILE);
    assert(global_fn_address(&lua, own_a, "CliExecute") == ROME2_L79_VA_CLI_EXECUTE);
    assert(field_fn_address(&lua, own_a, "string", "sub") == ROME2_L79_VA_STRING_SUB);
    assert(field_fn_address(&lua, own_a, "string", "find") == ROME2_L79_VA_STRING_FIND);
    assert(field_fn_address(&lua, own_a, "string", "length") == ROME2_L79_VA_STRING_LENGTH);
    assert(field_fn_address(&lua, own_a, "vfs", "exists") == ROME2_L79_VA_VFS_EXISTS);
    expect_weak_mode(&lua, own_a, "lookup", "k");
    expect_weak_mode(&lua, own_a, "udata_lookup", "v");
    rome2_l78_lua_getfield(&lua, own_a, ROME2_LUA_GLOBALSINDEX, "decoda_name");
    s = rome2_l78_lua_tolstring(&lua, own_a, -1, NULL);
    assert(s != NULL && strcmp(s, "Parent State") == 0);
    rome2_l76_lua_settop(&arena, own_a, 0);

    rome2_l78_lua_getfield(&lua, own_a, ROME2_LUA_GLOBALSINDEX, "defined");
    rome2_l78_lua_getfield(&lua, own_a, -1, "final_release");
    assert(rome2_l76_lua_type(&arena, own_a, -1) == ROME2_LUA_TBOOLEAN);
    assert(rome2_l76_lua_toboolean(&arena, own_a, -1) == 1);
    rome2_l78_lua_getfield(&lua, own_a, -2, "kostas");
    assert(rome2_l76_lua_type(&arena, own_a, -1) == ROME2_LUA_TBOOLEAN);
    assert(rome2_l76_lua_toboolean(&arena, own_a, -1) == 0);
    rome2_l78_lua_getfield(&lua, own_a, -3, "tom_s");
    assert(rome2_l76_lua_type(&arena, own_a, -1) == ROME2_LUA_TBOOLEAN);
    rome2_l76_lua_settop(&arena, own_a, 0);
    assert(global_type(&lua, own_a, "events") == ROME2_LUA_TNIL);

    /* package.loaders: existing entries move up one slot, 0x112ae680 takes slot 1 */
    rome2_l78_lua_getfield(&lua, own_a, ROME2_LUA_GLOBALSINDEX, "package");
    rome2_l78_lua_getfield(&lua, own_a, -1, "loaders");
    assert(rome2_l78_lua_objlen(&lua, own_a, -1) == 3u);
    rome2_l76_lua_rawgeti(&arena, own_a, -1, 1);
    assert(called_address(&lua, own_a) == ROME2_L79_VA_PACKAGE_LOADER);
    rome2_l76_lua_rawgeti(&arena, own_a, -1, 2);
    assert(called_address(&lua, own_a) == T_FN_PACKAGE_LOADER_1);
    rome2_l76_lua_rawgeti(&arena, own_a, -1, 3);
    assert(called_address(&lua, own_a) == T_FN_PACKAGE_LOADER_2);
    rome2_l76_lua_settop(&arena, own_a, 0);

    /* RequireRegister and system belong to the 0x12031f0c state only */
    assert(global_type(&lua, own_a, "RequireRegister") == ROME2_LUA_TNIL);
    assert(global_type(&lua, own_a, "system") == ROME2_LUA_TNIL);
    assert(global_fn_address(&lua, bctx.master_state_va, "RequireRegister") ==
           ROME2_L79_VA_REQUIRE_REGISTER);
    assert(field_fn_address(&lua, bctx.master_state_va, "system", "ClearRequiredFiles") ==
           ROME2_L79_VA_CLEAR_REQUIRED_FILES);

    /* thread environment inherits the parent globals; "out" is thread-local */
    assert(global_type(&lua, thread_a, "defined") == ROME2_LUA_TTABLE);
    assert(global_type(&lua, own_a, "out") == ROME2_LUA_TNIL);
    assert(field_fn_address(&lua, thread_a, "out", "shane") == ROME2_L79_VA_OUT_PRINT_STUB);
    assert(field_fn_address(&lua, thread_a, "out", "design") == ROME2_L79_VA_OUT_PRINT_STUB);
    assert(global_type(&lua, thread_a, "shane") == ROME2_LUA_TNIL);

    /* 0x112ae010 */
    assert(rome2_l79_lookup_lua_wrapper(&bctx, thread_a) == wrap_a);
    assert(rome2_l79_lookup_lua_wrapper(&bctx, own_a) == 0u);
    assert(rome2_l76_lua_gettop(&arena, thread_a) == 0 && rome2_l76_lua_gettop(&arena, own_a) == 0);

    /* owner with a parent wrapper threads off that wrapper's state */
    owner_at(&arena, T_OWNER_B)->parent_wrapper_va = wrap_a;
    wrap_b = rome2_l79_get_or_init_script_wrapper(&bctx, T_OWNER_B);
    assert(wrap_b != 0u && wrapper_at(&arena, wrap_b)->owns_master_state == 0u);
    assert(wrapper_at(&arena, wrap_b)->is_valid == 1u);
    node_b = bctx.ring_head_va;
    nb = node_at(&arena, node_b);
    assert(node_b != node_a && bctx.ring_tail_va == node_a);
    assert(nb->next_va == node_a && nb->prev_va == ROME2_L79_VA_RING_HEAD_SLOT);
    assert(node_at(&arena, node_a)->prev_va == node_b);
    assert(nb->parent_lua_state_va == thread_a && nb->wrapper_va == wrap_b);
    assert(rome2_l79_lookup_lua_wrapper(&bctx, wrapper_at(&arena, wrap_b)->lua_state_va) == wrap_b);

    /* owner with neither flag nor parent threads off the 0x12031f0c state */
    wrap_c = rome2_l79_get_or_init_script_wrapper(&bctx, T_OWNER_C);
    assert(wrap_c != 0u);
    assert(node_at(&arena, bctx.ring_head_va)->parent_lua_state_va == bctx.master_state_va);
    assert(node_at(&arena, bctx.ring_head_va)->next_va == node_b);
    assert(g_threads_created == 3u);

    /* failed 0x18-byte allocation clears the owner slot and returns NULL */
    saved_cursor = lua.heap_cursor;
    lua.heap_cursor = lua.heap_end;
    owner_at(&arena, T_OWNER_D)->wrapper_va = 0u;
    assert(rome2_l79_get_or_init_script_wrapper(&bctx, T_OWNER_D) == 0u);
    assert(owner_at(&arena, T_OWNER_D)->wrapper_va == 0u);
    assert(rome2_l79_get_script_lua_state(&bctx, T_OWNER_D) == 0u);
    lua.heap_cursor = saved_cursor;
}

/* 0x112af430, 0x112afa70, 0x112c6d90 */
static void test_value_and_upvalue_formatting(void) {
    rome2_l75_arena arena;
    rome2_l77_ctx lua;
    rome2_l79_bridge_ctx bctx;
    uint32_t l_va;
    char out[160];
    const char *s;

    reset_fixture(&arena, &lua, &bctx);
    l_va = rome2_l79_get_script_lua_state(&bctx, T_OWNER_C);
    assert(l_va != 0u);

    (void)snprintf(out, sizeof(out), "x=");
    rome2_l78_lua_pushstring(&lua, l_va, "cohort");
    rome2_l79_append_lua_typed_value(&bctx, out, sizeof(out), l_va);
    assert(strcmp(out, "x=string: cohort") == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);

    out[0] = '\0';
    rome2_l76_lua_pushboolean(&arena, l_va, 1);
    rome2_l79_append_lua_typed_value(&bctx, out, sizeof(out), l_va);
    rome2_l76_lua_pushboolean(&arena, l_va, 0);
    rome2_l79_append_lua_typed_value(&bctx, out, sizeof(out), l_va);
    rome2_l76_lua_pushnil(&arena, l_va);
    rome2_l79_append_lua_typed_value(&bctx, out, sizeof(out), l_va);
    assert(strcmp(out, "boolean: trueboolean: falsenil: nil") == 0);

    /* numbers print as the truncated unsigned integer */
    out[0] = '\0';
    push_number(&arena, l_va, 42.75f);
    rome2_l79_append_lua_typed_value(&bctx, out, sizeof(out), l_va);
    assert(strcmp(out, "number: 42") == 0);

    /* every other type contributes only its name */
    out[0] = '\0';
    rome2_l76_lua_pushlightuserdata(&arena, l_va, 0x1234u);
    rome2_l79_append_lua_typed_value(&bctx, out, sizeof(out), l_va);
    rome2_l78_lua_createtable(&lua, l_va, 0, 0);
    rome2_l79_append_lua_typed_value(&bctx, out, sizeof(out), l_va);
    assert(strcmp(out, "userdata: table: ") == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);

    /* C-closure upvalues have empty names */
    out[0] = '\0';
    rome2_l78_lua_pushstring(&lua, l_va, "upval_text");
    rome2_l76_lua_pushboolean(&arena, l_va, 1);
    rome2_l78_lua_pushcclosure(&lua, l_va, T_FN_HANDLER_TRUE, 2);
    rome2_l79_append_lua_upvalues(&bctx, l_va, out, sizeof(out));
    assert(strcmp(out, "-->  string: upval_text\n-->  boolean: true\n") == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 1);
    rome2_l76_lua_settop(&arena, l_va, 0);

    out[0] = '\0';
    rome2_l78_lua_pushstring(&lua, l_va, "not a function");
    rome2_l79_append_lua_upvalues(&bctx, l_va, out, sizeof(out));
    assert(out[0] == '\0' && rome2_l76_lua_gettop(&arena, l_va) == 1);
    rome2_l76_lua_settop(&arena, l_va, 0);

    /* 0x112af430: first use builds the metatable, later uses share it */
    (void)rome2_l78_lua_newuserdata(&lua, l_va, 4u);
    rome2_l79_set_pointer_metatable(&bctx, l_va, "Pointer<EVENT>");
    (void)rome2_l78_lua_newuserdata(&lua, l_va, 4u);
    rome2_l79_set_pointer_metatable(&bctx, l_va, "Pointer<EVENT>");
    assert(rome2_l76_lua_gettop(&arena, l_va) == 2);
    assert(rome2_l76_lua_getmetatable(&arena, l_va, 1) != 0);
    assert(rome2_l76_lua_getmetatable(&arena, l_va, 2) != 0);
    assert(rome2_l76_index2adr(&arena, l_va, 3) != 0u);
    assert(read_u32(&arena, rome2_l76_index2adr(&arena, l_va, 3)) ==
           read_u32(&arena, rome2_l76_index2adr(&arena, l_va, 4)));
    rome2_l78_lua_getfield(&lua, l_va, 3, "type");
    s = rome2_l78_lua_tolstring(&lua, l_va, -1, NULL);
    assert(s != NULL && strcmp(s, "Pointer<EVENT>") == 0);
    rome2_l78_lua_getfield(&lua, l_va, 3, "__tostring");
    assert(called_address(&lua, l_va) == ROME2_L79_VA_USERDATA_TOSTRING);
    rome2_l78_lua_getfield(&lua, l_va, 3, "__eq");
    assert(called_address(&lua, l_va) == ROME2_L79_VA_USERDATA_EQ);
    rome2_l76_lua_settop(&arena, l_va, 0);
}

/* 0x112ad700, 0x112be4c0, 0x112dbc80 */
static void test_protected_call_and_traceback(void) {
    rome2_l75_arena arena;
    rome2_l77_ctx lua;
    rome2_l79_bridge_ctx bctx;
    uint32_t wrap, l_va;

    reset_fixture(&arena, &lua, &bctx);
    owner_at(&arena, T_OWNER_A)->creates_master_state = 1u;
    wrap = rome2_l79_get_or_init_script_wrapper(&bctx, T_OWNER_A);
    l_va = wrapper_at(&arena, wrap)->lua_state_va;
    (void)snprintf(bctx.script_label, sizeof(bctx.script_label), "ui/advice.lua");

    /* non-function callee: logged, callee and arguments dropped, nothing pushed */
    rome2_l76_lua_pushboolean(&arena, l_va, 1);
    rome2_l76_lua_pushnil(&arena, l_va);
    rome2_l79_wrapper_pcall(&bctx, wrap, 1, 1);
    assert(g_log_count == 1u);
    assert(strcmp(g_log, "Lua Error: [campaign_ui], ui/advice.lua\n"
                         "Trying to retrieve type function, found type boolean\n") == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);

    /* successful call leaves exactly the requested result */
    g_log[0] = '\0';
    rome2_l78_lua_pushcclosure(&lua, l_va, T_FN_HANDLER_FALSE, 0);
    rome2_l76_lua_pushnil(&arena, l_va);
    rome2_l79_wrapper_pcall(&bctx, wrap, 1, 1);
    assert(g_log_count == 1u && rome2_l76_lua_gettop(&arena, l_va) == 1);
    assert(rome2_l76_lua_type(&arena, l_va, -1) == ROME2_LUA_TBOOLEAN);
    rome2_l76_lua_settop(&arena, l_va, 0);

    /* raising callee: the handler logs the frame and returns no value, so the error slot is nil */
    rome2_l78_lua_pushcclosure(&lua, l_va, T_FN_HANDLER_RAISE, 0);
    rome2_l76_lua_pushlightuserdata(&arena, l_va, 0x1234u);
    rome2_l79_wrapper_pcall(&bctx, wrap, 1, 1);
    assert(g_log_count == 5u);
    assert(strcmp(g_log, "Lua Error: [campaign_ui], ui/advice.lua\nscript-boom\n"
                         "1. Function (C):():-1\n"
                         "> Local Variables\n--> (*temporary) userdata: \n\n"
                         "> Upvalues\n\n") == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 1);
    assert(rome2_l76_lua_type(&arena, l_va, -1) == ROME2_LUA_TNIL);
    rome2_l76_lua_settop(&arena, l_va, 0);

    /* a state with no lookup entry logs nothing and still consumes the message */
    g_log[0] = '\0';
    rome2_l78_lua_pushstring(&lua, bctx.master_state_va, "orphan");
    assert(rome2_l79_lua_error_traceback_handler(&bctx, bctx.master_state_va) == 0);
    assert(g_log_count == 5u && rome2_l76_lua_gettop(&arena, bctx.master_state_va) == 0);

    /* non-string error object */
    rome2_l76_lua_pushboolean(&arena, l_va, 1);
    assert(rome2_l79_lua_error_traceback_handler(&bctx, l_va) == 0);
    assert(strcmp(g_log, "Lua Error: [campaign_ui], ui/advice.lua\n(error with no message)\n") == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);
}

static void install_handlers(rome2_l77_ctx *lua, uint32_t l_va, const char *event, const uint32_t *fns, int32_t n) {
    int32_t i;
    rome2_l78_lua_getfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "events");
    if (rome2_l76_lua_type(lua->arena, l_va, -1) != ROME2_LUA_TTABLE) {
        rome2_l76_lua_settop(lua->arena, l_va, -2);
        rome2_l78_lua_createtable(lua, l_va, 0, 2);
        rome2_l76_lua_pushvalue(lua->arena, l_va, -1);
        rome2_l78_lua_setfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "events");
    }
    rome2_l78_lua_createtable(lua, l_va, n, 0);
    for (i = 0; i < n; ++i) {
        rome2_l78_lua_pushcclosure(lua, l_va, fns[i], 0);
        rome2_l78_lua_rawseti(lua, l_va, -2, i + 1);
    }
    rome2_l78_lua_setfield(lua, l_va, -2, event);
    rome2_l76_lua_settop(lua->arena, l_va, -2);
}

/* 0x10ca32d0, 0x10cb8880 */
static void test_event_dispatch(void) {
    static const uint32_t k_three[3] = { T_FN_HANDLER_TRUE, T_FN_HANDLER_RAISE, T_FN_HANDLER_FALSE };
    rome2_l75_arena arena;
    rome2_l77_ctx lua;
    rome2_l79_bridge_ctx bctx;
    uint32_t l_va, first_box;

    reset_fixture(&arena, &lua, &bctx);
    owner_at(&arena, T_OWNER_A)->creates_master_state = 1u;
    l_va = rome2_l79_get_script_lua_state(&bctx, T_OWNER_A);

    /* no events table, then no list for this event name */
    assert(rome2_l79_dispatch_lua_event(&bctx, T_OWNER_A, T_EVENT) == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);
    install_handlers(&lua, l_va, "SomethingElse", k_three, 1);
    assert(rome2_l79_dispatch_lua_event(&bctx, T_OWNER_A, T_EVENT) == 0);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0 && g_handler_calls == 0u);

    /* only handlers returning boolean true are counted; a raising handler is logged */
    install_handlers(&lua, l_va, "PanelOpened", k_three, 3);
    g_component_va = T_COMPONENT;
    assert(rome2_l79_dispatch_lua_event(&bctx, T_OWNER_A, T_EVENT) == 1);
    assert(g_handler_calls == 2u && g_log_count == 4u);
    assert(strstr(g_log, "Lua Error: [campaign_ui], \nscript-boom\n") == g_log);
    assert(g_handler_payload == T_EVENT && g_handler_filled == 1);
    assert(strcmp(g_handler_string, "advice.key") == 0);
    assert(g_handler_component_type == ROME2_LUA_TUSERDATA && g_handler_component == T_COMPONENT);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);
    first_box = g_handler_box;

    /* the boxed pointer is reused from udata_lookup; a NULL component becomes nil */
    g_component_va = 0u;
    assert(rome2_l79_dispatch_lua_event(&bctx, T_OWNER_A, T_EVENT) == 1);
    assert(g_handler_box == first_box && g_handler_component_type == ROME2_LUA_TNIL);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);

    /* 0x10cb8880 gates: event +0x10, script-context stack top, event +0xbc */
    g_handler_calls = 0u;
    rome2_l79_dispatch_event_if_lua_enabled(&bctx, T_EVENT);
    assert(g_handler_calls == 0u);
    bctx.script_ctx_depth = 1u;
    rome2_l79_dispatch_event_if_lua_enabled(&bctx, T_EVENT);
    assert(g_handler_calls == 0u);
    bctx.script_ctx_stack[0] = T_OWNER_A;
    g_event_enabled = 0u;
    rome2_l79_dispatch_event_if_lua_enabled(&bctx, T_EVENT);
    g_event_enabled = 1u;
    g_event_visible = 0u;
    rome2_l79_dispatch_event_if_lua_enabled(&bctx, T_EVENT);
    assert(g_handler_calls == 0u);
    g_event_visible = 1u;
    rome2_l79_dispatch_event_if_lua_enabled(&bctx, T_EVENT);
    assert(g_handler_calls == 2u && rome2_l76_lua_gettop(&arena, l_va) == 0);
}

static void set_detail(rome2_l75_arena *a, uint32_t advice_va, uint32_t slot, int32_t priority) {
    uint32_t detail_va = T_DETAIL + slot * 0x50u;
    int32_t *p = (int32_t *)rome2_l75_mut_ptr(a, detail_va + 0x4cu, 4u);
    assert(p != NULL);
    *p = priority;
    g_detail_of[advice_va & 7u] = detail_va;
}

/* 0x10cb6520 */
static void test_advice_priority_trigger(void) {
    static const uint32_t k_true[1] = { T_FN_HANDLER_TRUE };
    rome2_l75_arena arena;
    rome2_l77_ctx lua;
    rome2_l79_bridge_ctx bctx;
    uint32_t l_va;

    reset_fixture(&arena, &lua, &bctx);
    owner_at(&arena, T_OWNER_A)->creates_master_state = 1u;
    l_va = rome2_l79_get_script_lua_state(&bctx, T_OWNER_A);
    install_handlers(&lua, l_va, "AdviceIssued", k_true, 1);
    install_handlers(&lua, l_va, "AdviceSuperseded", k_true, 1);
    bctx.script_ctx_stack[0] = T_OWNER_A;
    bctx.script_ctx_depth = 1u;

    set_detail(&arena, T_ADVICE_A, 0u, 20);
    set_detail(&arena, T_ADVICE_C, 1u, 5);
    set_detail(&arena, T_ADVICE_D, 2u, 5);
    set_detail(&arena, T_ADVICE_E, 3u, 1);
    bctx.advice_queue[0] = T_ADVICE_A;
    bctx.advice_queue[1] = T_ADVICE_B; /* no detail record: never preferred */
    bctx.advice_queue[2] = T_ADVICE_C;
    bctx.advice_queue[3] = T_ADVICE_D;
    bctx.advice_queue_count = 4u;

    /* no manager at 0x11f83cd4: nothing happens */
    rome2_l79_trigger_highest_priority_advice(&bctx);
    assert(bctx.advice_queue_count == 4u && g_trace[0] == '\0');

    /* first strictly lowest priority wins; every other entry is dismissed in queue order */
    bctx.advice_mgr_va = T_MGR;
    rome2_l79_trigger_highest_priority_advice(&bctx);
    assert(strcmp(g_trace, "dis1;dis2;dis4;act3;mgr3;") == 0);
    assert(bctx.active_advice_va == T_ADVICE_C && bctx.advice_queue_count == 0u);
    assert(bctx.history_count == 1u && bctx.history_capacity == 1u);
    assert(read_u32(&arena, bctx.history_va) == T_ADVICE_C);
    /* the issued event carries the winner's detail record */
    assert(g_handler_calls == 1u);
    assert(read_u32(&arena, g_handler_payload) == ROME2_L79_VA_ADVICE_ISSUED_EVENT_VTBL);
    assert(read_u32(&arena, g_handler_payload + 0x10u) == g_detail_of[T_ADVICE_C & 7u]);
    assert(rome2_l76_lua_gettop(&arena, l_va) == 0);

    /* empty queue with an active advice: only the active-advice event is raised */
    g_trace[0] = '\0';
    rome2_l79_trigger_highest_priority_advice(&bctx);
    assert(g_handler_calls == 2u && g_trace[0] == '\0' && bctx.history_count == 1u);
    assert(read_u32(&arena, g_handler_payload) == ROME2_L79_VA_ADVICE_ACTIVE_EVENT_VTBL);
    assert(read_u32(&arena, g_handler_payload + 0x10u) == g_detail_of[T_ADVICE_C & 7u]);

    /* history doubles: 1 -> 2 -> 4, earlier entries carried over */
    bctx.advice_queue[0] = T_ADVICE_E;
    bctx.advice_queue_count = 1u;
    rome2_l79_trigger_highest_priority_advice(&bctx);
    assert(strcmp(g_trace, "act5;mgr5;") == 0 && g_handler_calls == 4u);
    assert(bctx.active_advice_va == T_ADVICE_E);
    assert(bctx.history_count == 2u && bctx.history_capacity == 2u);
    assert(read_u32(&arena, bctx.history_va) == T_ADVICE_C);
    assert(read_u32(&arena, bctx.history_va + 4u) == T_ADVICE_E);

    /* no entry has a detail record: the first is taken and no issued event is raised */
    g_trace[0] = '\0';
    g_event_enabled = 0u;
    bctx.advice_queue[0] = T_ADVICE_B;
    bctx.advice_queue[1] = T_ADVICE_F;
    bctx.advice_queue_count = 2u;
    rome2_l79_trigger_highest_priority_advice(&bctx);
    assert(strcmp(g_trace, "dis6;act2;mgr2;") == 0 && g_handler_calls == 4u);
    assert(bctx.history_count == 3u && bctx.history_capacity == 4u);
    assert(read_u32(&arena, bctx.history_va + 8u) == T_ADVICE_B);
    assert(read_u32(&arena, bctx.history_va + 4u) == T_ADVICE_E);
}

int main(void) {
    test_states_wrappers_and_ring();
    test_value_and_upvalue_formatting();
    test_protected_call_and_traceback();
    test_event_dispatch();
    test_advice_priority_trigger();
    return 0;
}
