#ifndef ROME2_LUA_VM_GC_TABLE_OPS_H
#define ROME2_LUA_VM_GC_TABLE_OPS_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "lua_core_leaf_ops.h"
#include "lua_stack_api_ops.h"

/*
 * Layer 77 Partition 9 recovery:
 * 54 Lua 5.1.4 mutual-recursion VM/GC/table/call/string core SCC routines
 * including 6,580B luaV_execute (0x10f462b0..0x10f4e0d0).
 *
 * Native adaptations: bounded bump/free reallocators and injected C-closure,
 * hook, panic, and error-throw callbacks replace native x86 longjmp/exit
 * and host-pointer slots inside guest32 Lua state.
 */

enum {
    ROME2_LUA_OK = 0,
    ROME2_LUA_YIELD = 1,
    ROME2_LUA_ERRRUN = 2,
    ROME2_LUA_ERRSYNTAX = 3,
    ROME2_LUA_ERRMEM = 4,
    ROME2_LUA_ERRERR = 5
};

typedef struct rome2_l77_ctx {
    rome2_l75_arena *arena;
    uint32_t heap_cursor;
    uint32_t heap_end;
    int32_t last_thrown_err;
    int32_t panic_calls;
    int32_t fatal_exit_calls;
    uint32_t last_panic_l_va;
    int32_t (*c_call)(struct rome2_l77_ctx *ctx, uint32_t l_va, uint32_t cfn_va);
    void (*hook_fn)(struct rome2_l77_ctx *ctx, uint32_t l_va, uint32_t hook_va, const rome2_lua_debug_32 *ar);
    void (*panic_fn)(struct rome2_l77_ctx *ctx, uint32_t l_va);
    void (*throw_fn)(struct rome2_l77_ctx *ctx, uint32_t l_va, int32_t errcode);
} rome2_l77_ctx;

void rome2_l77_ctx_init(
    rome2_l77_ctx *ctx,
    rome2_l75_arena *arena,
    uint32_t heap_start_va,
    uint32_t heap_end_va);

/* 0x10f4e080, 0x10f4e0d0, 0x10f467e0 */
uint32_t rome2_l77_luaM_realloc(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    uint32_t block_va,
    uint32_t osize,
    uint32_t nsize);
uint32_t rome2_l77_luaM_toobig(rome2_l77_ctx *ctx, uint32_t l_va);
uint32_t rome2_l77_luaZ_openspace(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t mbuf_va, uint32_t n);

/* 0x10f4a500, 0x10f4a7c0, 0x10f4a750_shared */
uint32_t rome2_l77_luaS_newlstr(rome2_l77_ctx *ctx, uint32_t l_va, const char *str, size_t len);
void rome2_l77_luaS_resize(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t newsize);

/* 0x10f4ab20, 0x10f4a8a0, 0x10f4ace0, 0x10f4ad20, 0x10f4ade0, 0x10f4ae30, 0x10f4af50, 0x10f4b040, 0x10f4b240, 0x10f4b3c0, 0x10f4b430 */
uint32_t rome2_l77_luaH_new(rome2_l77_ctx *ctx, uint32_t l_va, int32_t narray, int32_t lnhash);
void rome2_l77_luaH_free(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va);
void rome2_l77_luaH_resizearray(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t nasize);
uint32_t rome2_l77_luaH_set(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, const rome2_lua_tvalue_32 *key);
uint32_t rome2_l77_luaH_setnum(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t key);
uint32_t rome2_l77_luaH_setstr(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, uint32_t ts_va);
uint32_t rome2_l77_newkey(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, const rome2_lua_tvalue_32 *key);
void rome2_l77_rehash(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, const rome2_lua_tvalue_32 *ek);
void rome2_l77_resize(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t nasize, int32_t nhsize);
void rome2_l77_setarrayvector(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t size);
void rome2_l77_setnodevector(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t size);

/* 0x10f48a80, 0x10f48b10, 0x10f48ba0, 0x10f48bd0, 0x10f48c60, 0x10f48d20 */
void rome2_l77_luaF_close(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t level_va);
uint32_t rome2_l77_luaF_findupval(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t level_va);
void rome2_l77_luaF_freeclosure(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t cl_va);
void rome2_l77_luaF_freeproto(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t pt_va);
void rome2_l77_luaF_freeupval(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t uv_va);
uint32_t rome2_l77_luaF_newLclosure(rome2_l77_ctx *ctx, uint32_t l_va, int32_t nelems, uint32_t env_va);

/* 0x10f48e60, 0x10f48f20, 0x10f49630, 0x10f499a0, 0x10f49be0, 0x10f4a0a0 */
void rome2_l77_GCTM(rome2_l77_ctx *ctx, uint32_t l_va);
void rome2_l77_atomic(rome2_l77_ctx *ctx, uint32_t l_va);
int32_t rome2_l77_singlestep(rome2_l77_ctx *ctx, uint32_t l_va);
void rome2_l77_propagateall(rome2_l77_ctx *ctx, uint32_t g_va);
int32_t rome2_l77_propagatemark(rome2_l77_ctx *ctx, uint32_t g_va);
uint32_t rome2_l77_sweeplist(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t p_head_va, uint32_t count);

/* 0x10f469d0, 0x10f47df0, 0x10f47e40, 0x10f47ed0, 0x10f47fc0, 0x10f480c0, 0x10f48190, 0x10f48680, 0x10f48700, 0x10f487e0, 0x10f48850, 0x10f48980 */
void rome2_l77_luaE_freethread(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t l1_va);
uint32_t rome2_l77_growCI(rome2_l77_ctx *ctx, uint32_t l_va);
void rome2_l77_luaD_call(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t func_va, int32_t nresults);
void rome2_l77_luaD_callhook(rome2_l77_ctx *ctx, uint32_t l_va, int32_t event, int32_t line);
void rome2_l77_luaD_growstack(rome2_l77_ctx *ctx, uint32_t l_va, int32_t n);
int32_t rome2_l77_luaD_poscall(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t first_res_va);
int32_t rome2_l77_luaD_precall(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t func_va, int32_t nresults);
void rome2_l77_luaD_reallocCI(rome2_l77_ctx *ctx, uint32_t l_va, int32_t newsize);
void rome2_l77_luaD_reallocstack(rome2_l77_ctx *ctx, uint32_t l_va, int32_t newsize);
void rome2_l77_luaD_seterrorobj(rome2_l77_ctx *ctx, uint32_t l_va, int32_t errcode, uint32_t oldtop_va);
void rome2_l77_luaD_throw(rome2_l77_ctx *ctx, uint32_t l_va, int32_t errcode);
void rome2_l77_resetstack(rome2_l77_ctx *ctx, uint32_t l_va, int32_t status);

/* 0x10f462b0, 0x10f462d0, 0x10f472c0, 0x10f47310, 0x10f473c0, 0x10f47410, 0x10f47520 */
uint32_t rome2_l77_luaO_pushvfstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, va_list ap);
uint32_t rome2_l77_luaO_pushfstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, ...);
void rome2_l77_luaG_aritherror(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t p1_va, uint32_t p2_va);
void rome2_l77_luaG_concaterror(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t p1_va, uint32_t p2_va);
int32_t rome2_l77_luaG_ordererror(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t p1_va, uint32_t p2_va);
void rome2_l77_luaG_runerror(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, ...);
void rome2_l77_luaG_typeerror(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t o_va, const char *op);

/* 0x10f4b9d0, 0x10f4bc30, 0x10f4bcc0, 0x10f4be50, 0x10f4c0f0, 0x10f4db60, 0x10f4dcb0 */
void rome2_l77_arith(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    uint32_t ra_va,
    const rome2_lua_tvalue_32 *rb,
    const rome2_lua_tvalue_32 *rc,
    uint32_t event);
void rome2_l77_callTMres(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    uint32_t res_va,
    const rome2_lua_tvalue_32 *f,
    const rome2_lua_tvalue_32 *p1,
    const rome2_lua_tvalue_32 *p2);
int32_t rome2_l77_call_orderTM(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const rome2_lua_tvalue_32 *p1,
    const rome2_lua_tvalue_32 *p2,
    int32_t event);
void rome2_l77_luaV_concat(rome2_l77_ctx *ctx, uint32_t l_va, int32_t total, int32_t last);
void rome2_l77_luaV_execute(rome2_l77_ctx *ctx, uint32_t l_va, int32_t nexeccalls);
void rome2_l77_luaV_gettable(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const rome2_lua_tvalue_32 *t,
    const rome2_lua_tvalue_32 *key,
    uint32_t val_va);
void rome2_l77_luaV_settable(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const rome2_lua_tvalue_32 *t,
    const rome2_lua_tvalue_32 *key,
    const rome2_lua_tvalue_32 *val);

#endif
