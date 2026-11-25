#ifndef ROME2_STARTUP_ADVICE_SCRIPT_BRIDGE_OPS_H
#define ROME2_STARTUP_ADVICE_SCRIPT_BRIDGE_OPS_H

#include "lua_auxlib_state_ops.h"

#include <stddef.h>
#include <stdint.h>

enum rome2_l79_cap {
    ROME2_L79_MAX_ADVICE_ITEMS = 16,
    ROME2_L79_MAX_ENABLED_STACK = 8,
    ROME2_L79_ERR_CAP = 512
};

typedef struct rome2_l79_advice_item {
    uint32_t obj_va;
    uint32_t comp_va;
    int32_t priority;
    uint8_t has_detail;
    uint8_t should_dispatch;
    uint8_t is_lua_eligible;
    uint8_t active;
    char event_name[64];
} rome2_l79_advice_item;

typedef struct rome2_l79_bridge_ctx {
    rome2_l77_ctx *lua;
    uint32_t master_state_va;      /* 0x12031f0c */
    uint32_t ring_head_va;         /* 0x119e1090 */
    uint32_t ring_tail_va;         /* 0x119e108c */
    uint8_t advice_mgr_active;     /* 0x11f83cd4 */
    uint32_t active_advice_va;     /* 0x11f83ce0 */
    rome2_l79_advice_item *advice_queue[ROME2_L79_MAX_ADVICE_ITEMS];
    size_t advice_queue_count;     /* 0x1196fc24 */
    uint32_t triggered_history[ROME2_L79_MAX_ADVICE_ITEMS];
    size_t triggered_count;        /* 0x1196fc18 */
    uint8_t lua_enabled_stack[ROME2_L79_MAX_ENABLED_STACK];
    size_t lua_enabled_depth;      /* 0x1196fc08 */

    void (*on_wrapper_init)(struct rome2_l79_bridge_ctx *bctx, uint32_t owner_ctx_va, uint32_t l_va);
    void (*on_advice_activate)(struct rome2_l79_bridge_ctx *bctx, rome2_l79_advice_item *item);
    void (*on_advice_dismiss)(struct rome2_l79_bridge_ctx *bctx, rome2_l79_advice_item *item);
    void (*on_advice_notify)(struct rome2_l79_bridge_ctx *bctx, rome2_l79_advice_item *item);
    void (*on_error_log)(struct rome2_l79_bridge_ctx *bctx, const char *msg);

    char last_error_msg[ROME2_L79_ERR_CAP];
    uint32_t traceback_calls;
    uint32_t pcall_errors;
    uint32_t dismiss_calls;
    uint32_t activate_calls;
    uint32_t notify_calls;
} rome2_l79_bridge_ctx;

void rome2_l79_bridge_ctx_init(rome2_l79_bridge_ctx *bctx, rome2_l77_ctx *lua);

/* Lua wrapper / script bridge (0x112ad700..0x112dbc80) */
uint32_t rome2_l79_create_empire_lua_master_state(rome2_l79_bridge_ctx *bctx);
void rome2_l79_init_empire_lua_thread_wrapper(
    rome2_l79_bridge_ctx *bctx,
    uint32_t wrapper_va,
    uint32_t parent_state_va);
uint32_t rome2_l79_get_or_init_lua_script_context(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va,
    uint32_t parent_wrapper_va,
    uint8_t create_master);
uint32_t rome2_l79_lookup_lua_wrapper_owner(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va);
uint32_t rome2_l79_get_current_lua_state_raw(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va,
    uint32_t parent_wrapper_va,
    uint8_t create_master);
void rome2_l79_register_lua_pointer_metatable(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    const char *tname);
void rome2_l79_format_lua_typed_value(
    rome2_l79_bridge_ctx *bctx,
    char *out,
    size_t out_cap,
    uint32_t l_va);
void rome2_l79_format_lua_upvalues(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    char *out,
    size_t out_cap);
int32_t rome2_l79_lua_error_traceback_handler(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va);
void rome2_l79_report_lua_type_mismatch(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    int32_t expected_type,
    int32_t found_type);
int32_t rome2_l79_lua_state_pcall_or_err(
    rome2_l79_bridge_ctx *bctx,
    uint32_t wrapper_va,
    int32_t nargs,
    int32_t nresults);

/* Advice dispatch bridge (0x10ca32d0, 0x10cb6520, 0x10cb8880) */
int32_t rome2_l79_dispatch_advice_lua_events(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va,
    const rome2_l79_advice_item *advice_obj);
void rome2_l79_dispatch_advice_if_lua_enabled(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va,
    const rome2_l79_advice_item *advice_obj);
void rome2_l79_trigger_highest_priority_advice_thread(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va);

#endif
