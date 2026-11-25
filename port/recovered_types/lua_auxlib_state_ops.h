#ifndef ROME2_LUA_AUXLIB_STATE_OPS_H
#define ROME2_LUA_AUXLIB_STATE_OPS_H

#include "lua_vm_gc_table_ops.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

enum rome2_lua_aux_const_32 {
    ROME2_LUA_MULTRET = -1,
    ROME2_LUA_REFNIL = -1,
    ROME2_LUA_NOREF = -2
};

typedef struct rome2_l78_reg {
    const char *name;
    uint32_t func_va;
} rome2_l78_reg;

typedef void (*rome2_l78_pfunc)(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t ud_va);

/* Public C API (0x10f43cd0..0x10f44d70) */
void rome2_l78_lua_call(rome2_l77_ctx *ctx, uint32_t l_va, int32_t nargs, int32_t nresults);
void rome2_l78_lua_concat(rome2_l77_ctx *ctx, uint32_t l_va, int32_t n);
void rome2_l78_lua_createtable(rome2_l77_ctx *ctx, uint32_t l_va, int32_t narray, int32_t nrec);
int32_t rome2_l78_lua_error(rome2_l77_ctx *ctx, uint32_t l_va);
void rome2_l78_lua_getfield(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx, const char *k);
void rome2_l78_lua_gettable(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx);
uint32_t rome2_l78_lua_newthread(rome2_l77_ctx *ctx, uint32_t l_va);
uint32_t rome2_l78_lua_newuserdata(rome2_l77_ctx *ctx, uint32_t l_va, size_t size);
size_t rome2_l78_lua_objlen(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx);
int32_t rome2_l78_lua_pcall(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    int32_t nargs,
    int32_t nresults,
    int32_t errfunc);
void rome2_l78_lua_pushcclosure(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t fn_va, int32_t n);
const char *rome2_l78_lua_pushvfstring(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const char *fmt,
    va_list argp);
const char *rome2_l78_lua_pushfstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, ...);
void rome2_l78_lua_pushlstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *s, size_t len);
void rome2_l78_lua_pushstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *s);
void rome2_l78_lua_rawseti(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx, int32_t n);
void rome2_l78_lua_setfield(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx, const char *k);
void rome2_l78_lua_settable(rome2_l77_ctx *ctx, uint32_t l_va, int32_t idx);
const char *rome2_l78_lua_tolstring(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    int32_t idx,
    size_t *len_out);

/* Auxlib (0x10f45680..0x10f45ed0) */
int32_t rome2_l78_luaL_error(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, ...);
const char *rome2_l78_luaL_findtable(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    int32_t idx,
    const char *fname,
    int32_t szhint);
int32_t rome2_l78_luaL_newmetatable(rome2_l77_ctx *ctx, uint32_t l_va, const char *tname);
int32_t rome2_l78_luaL_ref(rome2_l77_ctx *ctx, uint32_t l_va, int32_t t);
void rome2_l78_luaL_register(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const char *libname,
    const rome2_l78_reg *regs);

/* State, GC, Debug, VM & luaL_openlibs (0x10f468c0..0x116cfa80) */
void rome2_l78_close_state(rome2_l77_ctx *ctx, uint32_t l_va);
uint32_t rome2_l78_luaE_newthread(rome2_l77_ctx *ctx, uint32_t l_va);
uint32_t rome2_l78_lua_newstate(rome2_l77_ctx *ctx, uint32_t frealloc_va, uint32_t ud_va);
void rome2_l78_stack_init(rome2_l77_ctx *ctx, uint32_t l1_va, uint32_t l_va);
void rome2_l78_luaG_errormsg(rome2_l77_ctx *ctx, uint32_t l_va);
int32_t rome2_l78_lua_getinfo(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const char *what,
    rome2_lua_debug_32 *ar);
int32_t rome2_l78_luaD_pcall(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    rome2_l78_pfunc func,
    uint32_t ud_va,
    int32_t old_top,
    int32_t ef);
uint32_t rome2_l78_luaF_newCclosure(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    int32_t nelems,
    uint32_t e_va);
void rome2_l78_luaC_freeall(rome2_l77_ctx *ctx, uint32_t l_va);
uint32_t rome2_l78_luaS_newudata(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    size_t s,
    uint32_t e_va);
int32_t rome2_l78_luaV_tostring(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    uint32_t obj_va);
void rome2_l78_luaL_openlibs(rome2_l77_ctx *ctx, uint32_t l_va);

#endif
