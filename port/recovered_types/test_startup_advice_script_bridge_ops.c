#include "startup_advice_script_bridge_ops.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t g_l79_buf[65536];
static uint32_t g_l79_handler_calls = 0u;
static uint32_t g_l79_last_event_va = 0u;
static uint32_t g_l79_last_comp_va = 0u;
static uint32_t g_l79_wrapper_inits = 0u;

static void on_wrap_init(rome2_l79_bridge_ctx *bctx, uint32_t owner_ctx_va, uint32_t l_va) {
    (void)bctx;
    (void)owner_ctx_va;
    if (l_va != 0u) {
        ++g_l79_wrapper_inits;
    }
}

static int32_t mock_l79_c_handler(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t cfn_va) {
    if (cfn_va == 0x112be4c0u) {
        return 1;
    }
    if (cfn_va == 0xfeed0001u) {
        const uint32_t *ev = (const uint32_t *)rome2_l75_const_ptr(
            ctx->arena, rome2_l76_lua_touserdata(ctx->arena, l_va, 1), 4u);
        const uint32_t *cp = (const uint32_t *)rome2_l75_const_ptr(
            ctx->arena, rome2_l76_lua_touserdata(ctx->arena, l_va, 2), 4u);
        g_l79_last_event_va = (ev != NULL) ? *ev : 0u;
        g_l79_last_comp_va = (cp != NULL) ? *cp : 0u;
        ++g_l79_handler_calls;
        return 0;
    }
    if (cfn_va == 0xfeed0002u) {
        rome2_l78_luaL_error(ctx, l_va, "script-boom");
        return 0;
    }
    return 0;
}

static void test_l79_lua_wrapper_and_diagnostics(void) {
    rome2_l75_arena arena;
    rome2_l77_ctx lua;
    rome2_l79_bridge_ctx bctx;
    uint32_t base = 0x53000000u;
    uint32_t owner_va = base + 0x40u;
    uint32_t wrap_va, l_va, raw_l;
    char fmt[128];

    g_l79_wrapper_inits = 0u;
    memset(g_l79_buf, 0, sizeof(g_l79_buf));
    rome2_l75_arena_init(&arena, base, g_l79_buf, sizeof(g_l79_buf));
    rome2_l77_ctx_init(&lua, &arena, base + 0x200u, base + (uint32_t)sizeof(g_l79_buf));
    lua.c_call = mock_l79_c_handler;
    rome2_l79_bridge_ctx_init(&bctx, &lua);
    bctx.on_wrapper_init = on_wrap_init;

    wrap_va = rome2_l79_get_or_init_lua_script_context(&bctx, owner_va, 0u, 1u);
    assert(wrap_va != 0u);
    assert(g_l79_wrapper_inits == 1u);
    assert(bctx.ring_head_va != 0u && bctx.master_state_va != 0u);

    raw_l = rome2_l79_get_current_lua_state_raw(&bctx, owner_va, 0u, 0u);
    l_va = raw_l;
    assert(l_va != 0u);
    assert(rome2_l79_lookup_lua_wrapper_owner(&bctx, l_va) == wrap_va);

    /* Format typed values and upvalues */
    rome2_l78_lua_pushstring(&lua, l_va, "cohort");
    rome2_l79_format_lua_typed_value(&bctx, fmt, sizeof(fmt), l_va);
    assert(strcmp(fmt, "cohort") == 0);
    rome2_l76_lua_settop(&arena, l_va, 0);

    rome2_l78_lua_pushstring(&lua, l_va, "upval_text");
    rome2_l78_lua_pushcclosure(&lua, l_va, 0xfeed0001u, 1);
    fmt[0] = '\0';
    rome2_l79_format_lua_upvalues(&bctx, l_va, fmt, sizeof(fmt));
    assert(strstr(fmt, "upval_text") != NULL);
    rome2_l76_lua_settop(&arena, l_va, 0);

    /* Type mismatch & traceback logging */
    rome2_l76_lua_pushboolean(&arena, l_va, 1);
    assert(rome2_l79_lua_state_pcall_or_err(&bctx, wrap_va, 0, 0) == ROME2_LUA_ERRRUN);
    assert(bctx.pcall_errors == 1u && bctx.traceback_calls >= 1u);
    assert(strstr(bctx.last_error_msg, "Trying to retrieve type function, found type boolean") != NULL);

    /* Throwing pcall routes through lua_error_traceback_handler */
    rome2_l78_lua_pushcclosure(&lua, l_va, 0xfeed0002u, 0);
    assert(rome2_l79_lua_state_pcall_or_err(&bctx, wrap_va, 0, 0) == ROME2_LUA_ERRRUN);
    assert(bctx.pcall_errors == 2u);
    assert(strstr(bctx.last_error_msg, "script-boom") != NULL);
}

static void test_l79_advice_priority_and_dispatch(void) {
    rome2_l75_arena arena;
    rome2_l77_ctx lua;
    rome2_l79_bridge_ctx bctx;
    uint32_t base = 0x54000000u;
    uint32_t owner_va = base + 0x40u;
    uint32_t wrap_va, l_va;
    rome2_l79_advice_item low_item;
    rome2_l79_advice_item high_item;

    g_l79_handler_calls = 0u;
    g_l79_last_event_va = 0u;
    g_l79_last_comp_va = 0u;
    memset(g_l79_buf, 0, sizeof(g_l79_buf));
    rome2_l75_arena_init(&arena, base, g_l79_buf, sizeof(g_l79_buf));
    rome2_l77_ctx_init(&lua, &arena, base + 0x200u, base + (uint32_t)sizeof(g_l79_buf));
    lua.c_call = mock_l79_c_handler;
    rome2_l79_bridge_ctx_init(&bctx, &lua);

    wrap_va = rome2_l79_get_or_init_lua_script_context(&bctx, owner_va, 0u, 1u);
    l_va = rome2_l79_get_current_lua_state_raw(&bctx, owner_va, 0u, 0u);
    assert(wrap_va != 0u && l_va != 0u);

    /* Register events.AdviceTriggered[1] = 0xfeed0001u on thread state _G */
    rome2_l78_lua_createtable(&lua, l_va, 0, 1);
    rome2_l78_lua_createtable(&lua, l_va, 1, 0);
    rome2_l78_lua_pushcclosure(&lua, l_va, 0xfeed0001u, 0);
    rome2_l78_lua_rawseti(&lua, l_va, -2, 1);
    rome2_l78_lua_setfield(bctx.lua, l_va, -2, "AdviceTriggered");
    rome2_l78_lua_setfield(bctx.lua, l_va, ROME2_LUA_GLOBALSINDEX, "events");

    memset(&low_item, 0, sizeof(low_item));
    low_item.obj_va = 0xaaaa0001u;
    low_item.comp_va = 0xbbbb0001u;
    low_item.priority = 20;
    low_item.has_detail = 1u;
    low_item.should_dispatch = 1u;
    low_item.is_lua_eligible = 1u;
    (void)snprintf(low_item.event_name, sizeof(low_item.event_name), "AdviceTriggered");

    memset(&high_item, 0, sizeof(high_item));
    high_item.obj_va = 0xaaaa0002u;
    high_item.comp_va = 0xbbbb0002u;
    high_item.priority = 5;
    high_item.has_detail = 1u;
    high_item.should_dispatch = 1u;
    high_item.is_lua_eligible = 1u;
    (void)snprintf(high_item.event_name, sizeof(high_item.event_name), "AdviceTriggered");

    bctx.advice_mgr_active = 1u;
    bctx.lua_enabled_stack[0] = 1u;
    bctx.lua_enabled_depth = 1u;
    bctx.advice_queue[0] = &low_item;
    bctx.advice_queue[1] = &high_item;
    bctx.advice_queue_count = 2u;

    rome2_l79_dispatch_advice_if_lua_enabled(&bctx, owner_va, &high_item);
    assert(g_l79_handler_calls == 1u);
    assert(g_l79_last_event_va == 0xaaaa0002u && g_l79_last_comp_va == 0xbbbb0002u);

    rome2_l79_trigger_highest_priority_advice_thread(&bctx, owner_va);
    assert(bctx.active_advice_va == 0xaaaa0002u);
    assert(high_item.active == 1u);
    assert(bctx.activate_calls == 1u && bctx.dismiss_calls == 1u && bctx.notify_calls == 1u);
    assert(bctx.triggered_count == 1u && bctx.triggered_history[0] == 0xaaaa0002u);
}

int main(void) {
    test_l79_lua_wrapper_and_diagnostics();
    test_l79_advice_priority_and_dispatch();
    return 0;
}
