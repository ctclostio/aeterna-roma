#ifndef ROME2_LUA_STACK_API_OPS_H
#define ROME2_LUA_STACK_API_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "lua_core_leaf_ops.h"

/*
 * Layer 76 Partition 9 recovery:
 * 24 Lua 5.1.4 C API stack/push/to/raw/env/metatable functions
 * (0x10f43c00..0x10f44f10) plus 2 Lua binding string helpers
 * (0x112a5480, 0x112c0df0).
 */

enum {
    ROME2_LUA_REGISTRYINDEX = -10000,
    ROME2_LUA_ENVIRONINDEX = -10001,
    ROME2_LUA_GLOBALSINDEX = -10002
};

/* 0x10f43c00, 0x10f44040, 0x10f440c0, 0x10f440d0, 0x10f44160, 0x10f44250 */
uint32_t rome2_l76_index2adr(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
int32_t rome2_l76_lua_getmetatable(rome2_l75_arena *a, uint32_t l_va, int32_t objindex);
int32_t rome2_l76_lua_gettop(const rome2_l75_arena *a, uint32_t l_va);
uint32_t rome2_l76_lua_getupvalue(rome2_l75_arena *a, uint32_t l_va, int32_t funcindex, int32_t n);
void rome2_l76_lua_insert(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
int32_t rome2_l76_lua_isuserdata(rome2_l75_arena *a, uint32_t l_va, int32_t idx);

/* 0x10f444e0, 0x10f445f0, 0x10f44650, 0x10f44720, 0x10f447c0, 0x10f447f0 */
void rome2_l76_lua_pushboolean(rome2_l75_arena *a, uint32_t l_va, int32_t b);
void rome2_l76_lua_pushlightuserdata(rome2_l75_arena *a, uint32_t l_va, uint32_t ptr_va);
void rome2_l76_lua_pushnil(rome2_l75_arena *a, uint32_t l_va);
void rome2_l76_lua_pushvalue(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
void rome2_l76_lua_rawget(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
void rome2_l76_lua_rawgeti(rome2_l75_arena *a, uint32_t l_va, int32_t idx, int32_t n);

/* 0x10f44900, 0x10f449f0, 0x10f44ad0, 0x10f44bb0 */
void rome2_l76_lua_remove(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
int32_t rome2_l76_lua_setfenv(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
int32_t rome2_l76_lua_setmetatable(rome2_l75_arena *a, uint32_t l_va, int32_t objindex);
void rome2_l76_lua_settop(rome2_l75_arena *a, uint32_t l_va, int32_t idx);

/* 0x10f44cd0, 0x10f44d30, 0x10f44df0, 0x10f44ec0, 0x10f44ef0, 0x10f44f10 */
int32_t rome2_l76_lua_toboolean(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
int32_t rome2_l76_lua_tointeger(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
float rome2_l76_lua_tonumber(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
uint32_t rome2_l76_lua_touserdata(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
int32_t rome2_l76_lua_type(rome2_l75_arena *a, uint32_t l_va, int32_t idx);
const char *rome2_l76_lua_typename(int32_t t);

/* 0x112a5480, 0x112c0df0 */
char *rome2_l76_lua_format_3args(
    char *out,
    size_t cap,
    const char *fmt,
    const char *s1,
    const char *s2,
    const char *s3);
char *rome2_l76_lua_pointer_type_name(char *out, size_t cap, const char *full_type);

#endif
