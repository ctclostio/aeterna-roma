#ifndef ROME2_LUA_CORE_LEAF_OPS_H
#define ROME2_LUA_CORE_LEAF_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

/*
 * Layer 75 Partition 9 recovery:
 * 39 Lua 5.1.4 core leaf helpers across debug/introspection, bytecode symbexec,
 * table/TValue lookup, GC marking/weak-clearing, and string comparison
 * (0x10f43cb0..0x10f4df10).
 *
 * Native adaptations: guest32 Lua objects reside inside a bounded byte arena
 * (rome2_l75_arena) indexed by 32-bit virtual addresses; raw PE static RO
 * string/sentinel addresses (nilobject, dummynode, debug tag strings) resolve
 * deterministically without native pointer truncation.
 */

enum {
    ROME2_LUA_TNIL = 0,
    ROME2_LUA_TBOOLEAN = 1,
    ROME2_LUA_TLIGHTUSERDATA = 2,
    ROME2_LUA_TNUMBER = 3,
    ROME2_LUA_TSTRING = 4,
    ROME2_LUA_TTABLE = 5,
    ROME2_LUA_TFUNCTION = 6,
    ROME2_LUA_TUSERDATA = 7,
    ROME2_LUA_TTHREAD = 8,
    ROME2_LUA_TPROTO = 9,
    ROME2_LUA_TUPVAL = 10,
    ROME2_LUA_TDEADKEY = 11
};

enum {
    ROME2_LUA_VA_EMPTY = 0x1173dad0u,
    ROME2_LUA_VA_STR_C = 0x11741d48u,
    ROME2_LUA_VA_STR_MAIN = 0x11745314u,
    ROME2_LUA_VA_STR_GLOBAL = 0x11756080u,
    ROME2_LUA_VA_STR_TAIL = 0x1177d404u,
    ROME2_LUA_VA_STR_QMARK = 0x11846b10u,
    ROME2_LUA_VA_STR_METHOD = 0x11846b2cu,
    ROME2_LUA_VA_NILOBJECT = 0x11846c28u,
    ROME2_LUA_VA_STR_TEMP = 0x11846d5cu,
    ROME2_LUA_VA_STR_EQC = 0x11846d6cu,
    ROME2_LUA_VA_STR_LUA = 0x11846d74u,
    ROME2_LUA_VA_STR_TAILCALL = 0x11846d78u,
    ROME2_LUA_VA_STR_LOCAL = 0x11846d88u,
    ROME2_LUA_VA_STR_FIELD = 0x11846d90u,
    ROME2_LUA_VA_STR_UPVALUE = 0x11846d98u,
    ROME2_LUA_VA_DUMMYNODE = 0x11846ee0u
};

typedef struct rome2_l75_arena {
    uint32_t base_va;
    uint8_t *bytes;
    uint32_t size;
    const rome2_lua_tvalue_32 *ro_nil;
    const rome2_lua_node_32 *ro_dummy;
} rome2_l75_arena;

void rome2_l75_arena_init(rome2_l75_arena *a, uint32_t base_va, uint8_t *bytes, uint32_t size);
void *rome2_l75_mut_ptr(const rome2_l75_arena *a, uint32_t va, uint32_t bytes);
const void *rome2_l75_const_ptr(const rome2_l75_arena *a, uint32_t va, uint32_t bytes);
const char *rome2_l75_cstr_at(const rome2_l75_arena *a, uint32_t va);

/* 0x10f43cb0, 0x10f460e0, 0x10f46230, 0x10f46280, 0x10f46610, 0x10f46670 */
void rome2_l75_luaA_pushobject(rome2_l75_arena *a, uint32_t l_va, const rome2_lua_tvalue_32 *o);
void rome2_l75_luaO_chunkid(char *out, const char *source, size_t bufflen);
uint32_t rome2_l75_luaO_fb2int(uint32_t x);
int32_t rome2_l75_luaO_log2(uint32_t x);
int32_t rome2_l75_luaO_rawequalObj(const rome2_lua_tvalue_32 *t1, const rome2_lua_tvalue_32 *t2);
int32_t rome2_l75_luaO_str2d(const char *s, float *out_num);

/* 0x10f46c40, 0x10f46d50, 0x10f46fc0, 0x10f47020, 0x10f47070, 0x10f470c0, 0x10f47140, 0x10f47290 */
void rome2_l75_preinit_state(rome2_l75_arena *a, uint32_t l_va, uint32_t g_va);
int32_t rome2_l75_aux_getinfo(
    rome2_l75_arena *a,
    uint32_t l_va,
    const char *what,
    rome2_lua_debug_32 *ar,
    uint32_t f_cl_va,
    uint32_t ci_va);
int32_t rome2_l75_checkArgMode(const rome2_lua_proto_32 *pt, uint32_t r, int32_t mode);
int32_t rome2_l75_currentline(rome2_l75_arena *a, uint32_t l_va, uint32_t ci_va);
int32_t rome2_l75_currentpc(rome2_l75_arena *a, uint32_t l_va, uint32_t ci_va);
uint32_t rome2_l75_findlocal(rome2_l75_arena *a, uint32_t l_va, uint32_t ci_va, int32_t n);
uint32_t rome2_l75_getobjname(
    rome2_l75_arena *a,
    uint32_t l_va,
    uint32_t ci_va,
    uint32_t stackpos,
    uint32_t *out_name_va);
uint32_t rome2_l75_kname(const rome2_l75_arena *a, const rome2_lua_proto_32 *pt, uint32_t c);

/* 0x10f47720, 0x10f47770, 0x10f47870, 0x10f48620, 0x10f48c90 */
uint32_t rome2_l75_lua_getlocal(
    rome2_l75_arena *a,
    uint32_t l_va,
    const rome2_lua_debug_32 *ar,
    int32_t n);
int32_t rome2_l75_lua_getstack(
    const rome2_l75_arena *a,
    uint32_t l_va,
    int32_t level,
    rome2_lua_debug_32 *ar);
uint32_t rome2_l75_symbexec(
    const rome2_l75_arena *a,
    uint32_t pt_va,
    int32_t lastpc,
    uint32_t reg);
int32_t rome2_l75_luaD_rawrunprotected(
    rome2_l75_arena *a,
    uint32_t l_va,
    void (*fn)(rome2_l75_arena *a, uint32_t l_va, uint32_t ud_va, int32_t *status_slot),
    uint32_t ud_va);
uint32_t rome2_l75_luaF_getlocalname(
    const rome2_l75_arena *a,
    uint32_t f_proto_va,
    int32_t local_number,
    int32_t pc);

/* 0x10f490a0, 0x10f491a0, 0x10f491c0, 0x10f494e0, 0x10f49510, 0x10f49830, 0x10f49920, 0x10f49e60, 0x10f4a1e0, 0x10f4a340 */
void rome2_l75_cleartable(rome2_l75_arena *a, uint32_t table_va);
void rome2_l75_luaC_barrierback(rome2_l75_arena *a, uint32_t l_va, uint32_t table_va);
void rome2_l75_luaC_barrierf(rome2_l75_arena *a, uint32_t l_va, uint32_t o_va, uint32_t v_va);
void rome2_l75_luaC_link(rome2_l75_arena *a, uint32_t l_va, uint32_t o_va, uint8_t tt);
void rome2_l75_luaC_linkupval(rome2_l75_arena *a, uint32_t l_va, uint32_t uv_va);
void rome2_l75_marktmu_mt(rome2_l75_arena *a, uint32_t g_va);
void rome2_l75_markroot(rome2_l75_arena *a, uint32_t l_va);
void rome2_l75_reallymarkobject(rome2_l75_arena *a, uint32_t g_va, uint32_t o_va);
void rome2_l75_traverseclosure(rome2_l75_arena *a, uint32_t g_va, uint32_t cl_va);
int32_t rome2_l75_traversetable(rome2_l75_arena *a, uint32_t g_va, uint32_t table_va);

/* 0x10f4a900, 0x10f4a980, 0x10f4aa60, 0x10f4aae0, 0x10f4aea0 */
uint32_t rome2_l75_luaH_get(const rome2_l75_arena *a, uint32_t t_va, const rome2_lua_tvalue_32 *key);
uint32_t rome2_l75_luaH_getn(const rome2_l75_arena *a, uint32_t t_va);
uint32_t rome2_l75_luaH_getnum(const rome2_l75_arena *a, uint32_t t_va, int32_t key);
uint32_t rome2_l75_luaH_getstr(const rome2_l75_arena *a, uint32_t t_va, uint32_t key_ts_va);
uint32_t rome2_l75_mainposition(const rome2_l75_arena *a, uint32_t t_va, const rome2_lua_tvalue_32 *key);

/* 0x10f4bd40, 0x10f4bdd0, 0x10f4de20, 0x10f4dee0, 0x10f4df10 */
uint32_t rome2_l75_get_compTM(
    rome2_l75_arena *a,
    uint32_t l_va,
    uint32_t mt1_va,
    uint32_t mt2_va,
    uint32_t event);
int32_t rome2_l75_l_strcmp(
    const rome2_l75_arena *a,
    uint32_t ls_va,
    uint32_t rs_va);
const rome2_lua_tvalue_32 *rome2_l75_luaV_tonumber(
    const rome2_l75_arena *a,
    const rome2_lua_tvalue_32 *obj,
    rome2_lua_tvalue_32 *n);
uint32_t rome2_l75_luaT_gettm(
    rome2_l75_arena *a,
    uint32_t events_va,
    uint32_t event,
    uint32_t ename_va);
uint32_t rome2_l75_luaT_gettmbyobj(
    const rome2_l75_arena *a,
    uint32_t l_va,
    const rome2_lua_tvalue_32 *o,
    int32_t event);

#endif
