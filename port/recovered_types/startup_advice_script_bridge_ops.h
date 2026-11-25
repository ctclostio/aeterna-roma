#ifndef ROME2_STARTUP_ADVICE_SCRIPT_BRIDGE_OPS_H
#define ROME2_STARTUP_ADVICE_SCRIPT_BRIDGE_OPS_H

#include "lua_auxlib_state_ops.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Layer 79: Empire Lua script bridge and advice dispatch
 * (0x10ca32d0, 0x10cb6520, 0x10cb8880, 0x112ad700..0x112dbc80).
 *
 * Guest objects live in the Layer 75 arena. Virtual slots, the log sink at
 * [0x11fb5b30] and Lua C functions reached by address are injected callbacks.
 * Process globals the bodies read or write are fields of the bridge context,
 * each tagged with its original address.
 */

enum rome2_l79_cap {
    ROME2_L79_MAX_ADVICE_ITEMS = 16,
    ROME2_L79_MAX_SCRIPT_CTX_STACK = 8,
    ROME2_L79_TEXT_CAP = 512,
    ROME2_L79_LABEL_CAP = 64
};

enum rome2_l79_va {
    ROME2_L79_VA_LUA_ALLOC = 0x10102c60u,
    ROME2_L79_VA_OUT_PRINT_STUB = 0x100dbc00u,
    ROME2_L79_VA_CLI_EXECUTE = 0x112ad9b0u,
    ROME2_L79_VA_CLEAR_REQUIRED_FILES = 0x112ad850u,
    ROME2_L79_VA_DOFILE = 0x112ae070u,
    ROME2_L79_VA_LOADFILE = 0x112ae0e0u,
    ROME2_L79_VA_REQUIRE_REGISTER = 0x112ae1d0u,
    ROME2_L79_VA_PACKAGE_LOADER = 0x112ae680u,
    ROME2_L79_VA_USERDATA_EQ = 0x112ae770u,
    ROME2_L79_VA_USERDATA_TOSTRING = 0x112ae7b0u,
    ROME2_L79_VA_STRING_FIND = 0x112af560u,
    ROME2_L79_VA_STRING_LENGTH = 0x112af6a0u,
    ROME2_L79_VA_STRING_SUB = 0x112af720u,
    ROME2_L79_VA_VFS_EXISTS = 0x112af9e0u,
    ROME2_L79_VA_TRACEBACK = 0x112be4c0u,
    ROME2_L79_VA_ADVICE_ISSUED_EVENT_VTBL = 0x117df6fcu,
    ROME2_L79_VA_ADVICE_ACTIVE_EVENT_VTBL = 0x117df87cu,
    ROME2_L79_VA_RING_HEAD_SLOT = 0x119e1090u
};

typedef struct rome2_l79_bridge_ctx rome2_l79_bridge_ctx;

struct rome2_l79_bridge_ctx {
    rome2_l77_ctx *lua;

    uint32_t master_state_va;      /* 0x12031f0c */
    uint32_t ring_head_va;         /* 0x119e1090 */
    uint32_t ring_tail_va;         /* 0x119e108c, image value 0x119e1090 */
    uint32_t script_ctx_stack[ROME2_L79_MAX_SCRIPT_CTX_STACK]; /* [0x1196fc0c] */
    uint32_t script_ctx_depth;     /* 0x1196fc08 */
    uint32_t advice_mgr_va;        /* 0x11f83cd4 */
    uint32_t active_advice_va;     /* 0x11f83ce0 */
    uint32_t advice_queue[ROME2_L79_MAX_ADVICE_ITEMS];         /* [0x1196fc28] */
    uint32_t advice_queue_count;   /* 0x1196fc24 */
    uint32_t history_capacity;     /* 0x1196fc14 */
    uint32_t history_count;        /* 0x1196fc18 */
    uint32_t history_va;           /* 0x1196fc1c */
    char script_label[ROME2_L79_LABEL_CAP];                    /* 0x12031b00 */

    /* script-context object: vtable +0x04, +0x10 */
    const char *(*owner_name)(rome2_l79_bridge_ctx *bctx, uint32_t owner_va);
    void (*owner_thread_created)(rome2_l79_bridge_ctx *bctx, uint32_t owner_va, uint32_t l_va);
    /* [0x11fb5b30] */
    void (*log_sink)(rome2_l79_bridge_ctx *bctx, const char *text);
    /* event object: vtable +0x08, +0x10, +0x1c, +0x20, +0xb4, +0xbc */
    const char *(*event_name)(rome2_l79_bridge_ctx *bctx, uint32_t event_va);
    uint8_t (*event_enabled)(rome2_l79_bridge_ctx *bctx, uint32_t event_va);
    const char *(*event_string)(rome2_l79_bridge_ctx *bctx, uint32_t event_va);
    uint32_t (*event_component)(rome2_l79_bridge_ctx *bctx, uint32_t event_va);
    void (*event_fill_context)(rome2_l79_bridge_ctx *bctx, uint32_t event_va, uint32_t l_va);
    uint8_t (*event_lua_visible)(rome2_l79_bridge_ctx *bctx, uint32_t event_va);
    /* advice object: vtable +0x24, +0x2c, +0x38 */
    void (*advice_activate)(rome2_l79_bridge_ctx *bctx, uint32_t advice_va);
    void (*advice_dismiss)(rome2_l79_bridge_ctx *bctx, uint32_t advice_va, uint32_t arg);
    uint32_t (*advice_detail)(rome2_l79_bridge_ctx *bctx, uint32_t advice_va);
    /* advice manager: vtable +0x00 */
    void (*mgr_advice_started)(rome2_l79_bridge_ctx *bctx, uint32_t mgr_va, uint32_t advice_va);
};

void rome2_l79_bridge_ctx_init(rome2_l79_bridge_ctx *bctx, rome2_l77_ctx *lua);

/* 0x112ada40, 0x112addc0, 0x112adf80, 0x112ae010, 0x112ae710 */
uint32_t rome2_l79_create_empire_lua_state(rome2_l79_bridge_ctx *bctx);
void rome2_l79_init_lua_thread_wrapper(
    rome2_l79_bridge_ctx *bctx,
    uint32_t wrapper_va,
    uint32_t parent_wrapper_va);
uint32_t rome2_l79_get_or_init_script_wrapper(rome2_l79_bridge_ctx *bctx, uint32_t owner_va);
uint32_t rome2_l79_lookup_lua_wrapper(rome2_l79_bridge_ctx *bctx, uint32_t l_va);
uint32_t rome2_l79_get_script_lua_state(rome2_l79_bridge_ctx *bctx, uint32_t owner_va);

/* 0x112af430, 0x112afa70, 0x112c6d90 */
void rome2_l79_set_pointer_metatable(rome2_l79_bridge_ctx *bctx, uint32_t l_va, const char *tname);
void rome2_l79_append_lua_typed_value(
    rome2_l79_bridge_ctx *bctx,
    char *out,
    size_t out_cap,
    uint32_t l_va);
void rome2_l79_append_lua_upvalues(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    char *out,
    size_t out_cap);

/* 0x112be4c0, 0x112dbc80, 0x112ad700 */
int32_t rome2_l79_lua_error_traceback_handler(rome2_l79_bridge_ctx *bctx, uint32_t l_va);
void rome2_l79_report_lua_type_mismatch(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    int32_t expected_type,
    int32_t found_type);
void rome2_l79_wrapper_pcall(
    rome2_l79_bridge_ctx *bctx,
    uint32_t wrapper_va,
    int32_t nargs,
    int32_t nresults);

/* 0x10ca32d0, 0x10cb8880, 0x10cb6520 */
int32_t rome2_l79_dispatch_lua_event(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_va,
    uint32_t event_va);
void rome2_l79_dispatch_event_if_lua_enabled(rome2_l79_bridge_ctx *bctx, uint32_t event_va);
void rome2_l79_trigger_highest_priority_advice(rome2_l79_bridge_ctx *bctx);

#endif
