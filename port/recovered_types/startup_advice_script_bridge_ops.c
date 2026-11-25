#include "startup_advice_script_bridge_ops.h"

#include "vfs_fs_engine_crt_ops.h"

#include <stdio.h>
#include <string.h>

/*
 * __FUNCSIG__ literals the two operator<< instantiations hand to the
 * Pointer<%s> formatter at 0x112c0df0 (static locals 0x11f929a8, 0x11bccc10).
 */
static const char k_l79_event_funcsig[] =
    "class UTILITYDLL::LUA::State &__thiscall UTILITYDLL::LUA::State::operator <<"
    "<const class EMPIREUTILITY::EVENT>(const class UTILITYDLL::LUA::Pointer"
    "<class EMPIREUTILITY::EVENT const > &)";
static const char k_l79_component_funcsig[] =
    "class UTILITYDLL::LUA::State &__thiscall UTILITYDLL::LUA::State::operator <<"
    "<class TWUI::Component>(const class UTILITYDLL::LUA::Pointer"
    "<class TWUI::Component> &)";

static uint32_t l79_alloc_zero(rome2_l77_ctx *ctx, uint32_t bytes) {
    uint32_t aligned;
    uint32_t va;
    void *p;
    if (ctx == NULL || ctx->arena == NULL || bytes == 0u) {
        return 0u;
    }
    aligned = (bytes + 7u) & ~7u;
    if (ctx->heap_cursor > ctx->heap_end || aligned > ctx->heap_end - ctx->heap_cursor) {
        return 0u;
    }
    va = ctx->heap_cursor;
    p = rome2_l75_mut_ptr(ctx->arena, va, aligned);
    if (p == NULL) {
        return 0u;
    }
    memset(p, 0, aligned);
    ctx->heap_cursor += aligned;
    return va;
}

static void l79_append(char *dst, size_t cap, const char *src) {
    size_t cur;
    size_t add;
    if (dst == NULL || cap == 0u || src == NULL) {
        return;
    }
    cur = strnlen(dst, cap - 1u);
    add = strnlen(src, cap - 1u - cur);
    memcpy(dst + cur, src, add);
    dst[cur + add] = '\0';
}

static void l79_log(rome2_l79_bridge_ctx *bctx, const char *text) {
    if (bctx->log_sink != NULL) {
        bctx->log_sink(bctx, text);
    }
}

static uint32_t l79_wrapper_state(const rome2_l79_bridge_ctx *bctx, uint32_t wrapper_va) {
    const rome2_lua_script_wrapper24_32 *wrap = (const rome2_lua_script_wrapper24_32 *)
        rome2_l75_const_ptr(bctx->lua->arena, wrapper_va, sizeof(*wrap));
    return (wrap != NULL) ? wrap->lua_state_va : 0u;
}

/*
 * Pointer push the original inlines twice in 0x10ca32d0: reuse the userdata
 * cached in _G.udata_lookup[ptr], or box the pointer in a 4-byte userdata,
 * give it the per-type metatable and cache it.
 */
static void l79_push_cached_pointer(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    uint32_t ptr_va,
    const char *funcsig) {
    rome2_l75_arena *a = bctx->lua->arena;
    int32_t lookup_idx;
    rome2_l78_lua_getfield(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX, "udata_lookup");
    lookup_idx = rome2_l76_lua_gettop(a, l_va);
    rome2_l76_lua_pushlightuserdata(a, l_va, ptr_va);
    rome2_l78_lua_gettable(bctx->lua, l_va, -2);
    if (rome2_l76_lua_type(a, l_va, -1) == ROME2_LUA_TNIL) {
        char tname[128];
        uint32_t box_va;
        uint32_t *box;
        rome2_l76_lua_settop(a, l_va, -2);
        box_va = rome2_l78_lua_newuserdata(bctx->lua, l_va, 4u);
        box = (uint32_t *)rome2_l75_mut_ptr(a, box_va, 4u);
        if (box != NULL) {
            *box = ptr_va;
        }
        (void)rome2_l76_lua_pointer_type_name(tname, sizeof(tname), funcsig);
        rome2_l79_set_pointer_metatable(bctx, l_va, tname);
        rome2_l76_lua_pushlightuserdata(a, l_va, ptr_va);
        rome2_l76_lua_pushvalue(a, l_va, -2);
        rome2_l78_lua_settable(bctx->lua, l_va, -4);
    }
    rome2_l76_lua_remove(a, l_va, lookup_idx);
}

/* 20-byte event 0x10cb6520 builds in its own frame; the model gives it a guest address. */
static uint32_t l79_make_frame_event(rome2_l79_bridge_ctx *bctx, uint32_t vptr_va, uint32_t payload_va) {
    uint32_t ev_va = l79_alloc_zero(bctx->lua, (uint32_t)sizeof(rome2_advice_lua_event20_32));
    rome2_advice_lua_event20_32 *ev = (rome2_advice_lua_event20_32 *)
        rome2_l75_mut_ptr(bctx->lua->arena, ev_va, sizeof(*ev));
    if (ev == NULL) {
        return 0u;
    }
    ev->vptr_va = vptr_va;
    ev->payload_va = payload_va;
    return ev_va;
}

void rome2_l79_bridge_ctx_init(rome2_l79_bridge_ctx *bctx, rome2_l77_ctx *lua) {
    if (bctx == NULL) {
        return;
    }
    memset(bctx, 0, sizeof(*bctx));
    bctx->lua = lua;
    bctx->ring_tail_va = ROME2_L79_VA_RING_HEAD_SLOT;
}

/* 0x112ada40 */
uint32_t rome2_l79_create_empire_lua_state(rome2_l79_bridge_ctx *bctx) {
    static const struct {
        const char *name;
        int32_t value;
    } k_defined[9] = {
        { "final_release", 1 }, { "intel", 0 }, { "debug", 0 }, { "demo", 0 }, { "demo2", 0 },
        { "tom", 0 }, { "shane", 0 }, { "dylan", 0 }, { "tom_s", 0 }
    };
    rome2_l77_ctx *lua;
    rome2_l75_arena *a;
    uint32_t l_va;
    int32_t i;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0u;
    }
    lua = bctx->lua;
    a = lua->arena;
    l_va = rome2_l78_lua_newstate(lua, ROME2_L79_VA_LUA_ALLOC, 0u);
    if (l_va == 0u) {
        return 0u; /* the original passes the NULL state on */
    }
    rome2_l78_luaL_openlibs(lua, l_va);

    rome2_l78_lua_pushstring(lua, l_va, "lookup");
    rome2_l78_lua_createtable(lua, l_va, 0, 0);
    rome2_l78_lua_createtable(lua, l_va, 0, 1);
    rome2_l78_lua_pushstring(lua, l_va, "__mode");
    rome2_l78_lua_pushstring(lua, l_va, "k");
    rome2_l78_lua_settable(lua, l_va, -3);
    (void)rome2_l76_lua_setmetatable(a, l_va, -2);
    rome2_l78_lua_settable(lua, l_va, ROME2_LUA_GLOBALSINDEX);

    rome2_l78_lua_pushstring(lua, l_va, "udata_lookup");
    rome2_l78_lua_createtable(lua, l_va, 0, 0);
    rome2_l78_lua_createtable(lua, l_va, 0, 1);
    rome2_l78_lua_pushstring(lua, l_va, "__mode");
    rome2_l78_lua_pushstring(lua, l_va, "v");
    rome2_l78_lua_settable(lua, l_va, -3);
    (void)rome2_l76_lua_setmetatable(a, l_va, -2);
    rome2_l78_lua_settable(lua, l_va, ROME2_LUA_GLOBALSINDEX);

    rome2_l78_lua_pushstring(lua, l_va, "defined");
    rome2_l78_lua_createtable(lua, l_va, 0, 0);
    for (i = 0; i < 9; ++i) {
        rome2_l78_lua_pushstring(lua, l_va, k_defined[i].name);
        rome2_l76_lua_pushboolean(a, l_va, k_defined[i].value);
        rome2_l78_lua_settable(lua, l_va, -3);
    }
    rome2_l76_lua_pushboolean(a, l_va, 0);
    rome2_l78_lua_setfield(lua, l_va, -2, "kostas");
    rome2_l78_lua_settable(lua, l_va, ROME2_LUA_GLOBALSINDEX);

    rome2_l78_lua_pushcclosure(lua, l_va, ROME2_L79_VA_DOFILE, 0);
    rome2_l78_lua_setfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "dofile");
    rome2_l78_lua_pushcclosure(lua, l_va, ROME2_L79_VA_LOADFILE, 0);
    rome2_l78_lua_setfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "loadfile");

    /*
     * The original indexes package.loaders and string unconditionally and
     * raises a Lua error when the openers have not installed them; the model
     * skips the block instead.
     */
    rome2_l78_lua_getfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "package");
    if (rome2_l76_lua_type(a, l_va, -1) == ROME2_LUA_TTABLE) {
        rome2_l78_lua_getfield(lua, l_va, -1, "loaders");
        if (rome2_l76_lua_type(a, l_va, -1) == ROME2_LUA_TTABLE) {
            for (i = (int32_t)rome2_l78_lua_objlen(lua, l_va, -1); i > 0; --i) {
                rome2_l76_lua_rawgeti(a, l_va, -1, i);
                rome2_l78_lua_rawseti(lua, l_va, -2, i + 1);
            }
            rome2_l78_lua_pushcclosure(lua, l_va, ROME2_L79_VA_PACKAGE_LOADER, 0);
            rome2_l78_lua_rawseti(lua, l_va, -2, 1);
        }
        rome2_l76_lua_settop(a, l_va, -3);
    } else {
        rome2_l76_lua_settop(a, l_va, -2);
    }

    rome2_l78_lua_getfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "string");
    if (rome2_l76_lua_type(a, l_va, -1) == ROME2_LUA_TTABLE) {
        rome2_l78_lua_pushcclosure(lua, l_va, ROME2_L79_VA_STRING_SUB, 0);
        rome2_l78_lua_setfield(lua, l_va, -2, "sub");
        rome2_l78_lua_pushcclosure(lua, l_va, ROME2_L79_VA_STRING_FIND, 0);
        rome2_l78_lua_setfield(lua, l_va, -2, "find");
        rome2_l78_lua_pushcclosure(lua, l_va, ROME2_L79_VA_STRING_LENGTH, 0);
        rome2_l78_lua_setfield(lua, l_va, -2, "length");
    }
    rome2_l76_lua_settop(a, l_va, -2);

    rome2_l78_lua_createtable(lua, l_va, 0, 0);
    rome2_l78_lua_pushcclosure(lua, l_va, ROME2_L79_VA_VFS_EXISTS, 0);
    rome2_l78_lua_setfield(lua, l_va, -2, "exists");
    rome2_l78_lua_setfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "vfs");

    rome2_l78_lua_pushstring(lua, l_va, "Parent State");
    rome2_l78_lua_setfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "decoda_name");
    rome2_l78_lua_pushcclosure(lua, l_va, ROME2_L79_VA_CLI_EXECUTE, 0);
    rome2_l78_lua_setfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "CliExecute");
    return l_va;
}

/* 0x112addc0 */
void rome2_l79_init_lua_thread_wrapper(
    rome2_l79_bridge_ctx *bctx,
    uint32_t wrapper_va,
    uint32_t parent_wrapper_va) {
    /* luaL_Reg table at 0x11896760: seven names sharing the stub 0x100dbc00. */
    static const rome2_l78_reg k_out_lib[] = {
        { "shane",   ROME2_L79_VA_OUT_PRINT_STUB },
        { "dylan",   ROME2_L79_VA_OUT_PRINT_STUB },
        { "tom",     ROME2_L79_VA_OUT_PRINT_STUB },
        { "kostas",  ROME2_L79_VA_OUT_PRINT_STUB },
        { "ting",    ROME2_L79_VA_OUT_PRINT_STUB },
        { "scott_b", ROME2_L79_VA_OUT_PRINT_STUB },
        { "design",  ROME2_L79_VA_OUT_PRINT_STUB },
        { NULL, 0u }
    };
    rome2_l77_ctx *lua;
    rome2_l75_arena *a;
    rome2_lua_script_wrapper24_32 *wrap;
    rome2_lua_wrapper_ring20_32 *node;
    uint32_t parent_l;
    uint32_t child_l;
    uint32_t node_va;
    int32_t ref;
    if (bctx == NULL || bctx->lua == NULL) {
        return;
    }
    lua = bctx->lua;
    a = lua->arena;
    if (bctx->master_state_va == 0u) {
        uint32_t m = rome2_l79_create_empire_lua_state(bctx);
        bctx->master_state_va = m;
        if (m == 0u) {
            return; /* the original continues with the NULL state */
        }
        rome2_l78_lua_pushcclosure(lua, m, ROME2_L79_VA_REQUIRE_REGISTER, 0);
        rome2_l78_lua_setfield(lua, m, ROME2_LUA_GLOBALSINDEX, "RequireRegister");
        rome2_l78_lua_createtable(lua, m, 0, 0);
        rome2_l78_lua_pushcclosure(lua, m, ROME2_L79_VA_CLEAR_REQUIRED_FILES, 0);
        rome2_l78_lua_setfield(lua, m, -2, "ClearRequiredFiles");
        rome2_l78_lua_setfield(lua, m, ROME2_LUA_GLOBALSINDEX, "system");
    }
    parent_l = bctx->master_state_va;
    if (parent_wrapper_va != 0u) {
        parent_l = l79_wrapper_state(bctx, parent_wrapper_va);
    }
    wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(a, wrapper_va, sizeof(*wrap));
    if (wrap == NULL || parent_l == 0u) {
        return; /* outside the bounded domain; the original faults */
    }
    child_l = rome2_l78_lua_newthread(lua, parent_l);
    wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(a, wrapper_va, sizeof(*wrap));
    wrap->lua_state_va = child_l;

    /* thread environment: fresh table whose metatable __index is the parent globals */
    rome2_l78_lua_createtable(lua, parent_l, 0, 0);
    rome2_l78_lua_createtable(lua, parent_l, 0, 1);
    rome2_l76_lua_pushvalue(a, parent_l, ROME2_LUA_GLOBALSINDEX);
    rome2_l78_lua_setfield(lua, parent_l, -2, "__index");
    (void)rome2_l76_lua_setmetatable(a, parent_l, -2);
    (void)rome2_l76_lua_setfenv(a, parent_l, -2);

    /* lookup[thread] = wrapper */
    rome2_l78_lua_pushstring(lua, parent_l, "lookup");
    rome2_l78_lua_gettable(lua, parent_l, ROME2_LUA_GLOBALSINDEX);
    rome2_l76_lua_pushlightuserdata(a, parent_l, child_l);
    rome2_l76_lua_pushlightuserdata(a, parent_l, wrapper_va);
    rome2_l78_lua_settable(lua, parent_l, -3);
    rome2_l76_lua_settop(a, parent_l, -2);

    ref = rome2_l78_luaL_ref(lua, parent_l, ROME2_LUA_REGISTRYINDEX);

    node_va = l79_alloc_zero(lua, (uint32_t)sizeof(*node));
    node = (rome2_lua_wrapper_ring20_32 *)rome2_l75_mut_ptr(a, node_va, sizeof(*node));
    if (node == NULL) {
        return; /* the original does not test this allocation */
    }
    node->wrapper_va = wrapper_va;
    node->parent_lua_state_va = parent_l;
    node->registry_ref = ref;
    if (bctx->ring_tail_va != ROME2_L79_VA_RING_HEAD_SLOT) {
        rome2_lua_wrapper_ring20_32 *head = (rome2_lua_wrapper_ring20_32 *)
            rome2_l75_mut_ptr(a, bctx->ring_head_va, sizeof(*head));
        if (head != NULL) {
            head->prev_va = node_va;
        }
    } else {
        bctx->ring_tail_va = node_va;
    }
    node->next_va = bctx->ring_head_va;
    node->prev_va = ROME2_L79_VA_RING_HEAD_SLOT;
    bctx->ring_head_va = node_va;

    rome2_l78_lua_createtable(lua, child_l, 0, 0);
    rome2_l78_luaL_register(lua, child_l, NULL, k_out_lib);
    rome2_l78_lua_setfield(lua, child_l, ROME2_LUA_GLOBALSINDEX, "out");

    wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(a, wrapper_va, sizeof(*wrap));
    if (bctx->owner_thread_created != NULL) {
        bctx->owner_thread_created(bctx, wrap->owner_ctx_va, child_l);
    }
}

/* 0x112adf80 */
uint32_t rome2_l79_get_or_init_script_wrapper(rome2_l79_bridge_ctx *bctx, uint32_t owner_va) {
    rome2_l75_arena *a;
    rome2_lua_script_owner_prefix24_32 *owner;
    rome2_lua_script_wrapper24_32 *wrap;
    uint32_t wrapper_va;
    uint32_t parent_va;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0u;
    }
    a = bctx->lua->arena;
    owner = (rome2_lua_script_owner_prefix24_32 *)rome2_l75_mut_ptr(a, owner_va, sizeof(*owner));
    if (owner == NULL) {
        return 0u;
    }
    if (owner->wrapper_va != 0u) {
        return owner->wrapper_va;
    }
    wrapper_va = l79_alloc_zero(bctx->lua, (uint32_t)sizeof(*wrap));
    wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(a, wrapper_va, sizeof(*wrap));
    if (wrap == NULL) {
        owner->wrapper_va = 0u;
        return 0u;
    }
    wrap->owner_ctx_va = owner_va;
    wrap->reserved10 = 0u;
    wrap->reserved14 = 0u;
    if (owner->creates_master_state == 0u) {
        wrap->owns_master_state = 0u;
        parent_va = owner->parent_wrapper_va;
    } else {
        uint32_t own_state;
        wrap->owns_master_state = 1u;
        own_state = rome2_l79_create_empire_lua_state(bctx);
        wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(a, wrapper_va, sizeof(*wrap));
        wrap->lua_state_va = own_state;
        parent_va = wrapper_va;
    }
    rome2_l79_init_lua_thread_wrapper(bctx, wrapper_va, parent_va);
    wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(a, wrapper_va, sizeof(*wrap));
    wrap->is_valid = (wrap->lua_state_va != 0u) ? 1u : 0u;
    owner = (rome2_lua_script_owner_prefix24_32 *)rome2_l75_mut_ptr(a, owner_va, sizeof(*owner));
    owner->wrapper_va = wrapper_va;
    return wrapper_va;
}

/* 0x112ae010 */
uint32_t rome2_l79_lookup_lua_wrapper(rome2_l79_bridge_ctx *bctx, uint32_t l_va) {
    rome2_l75_arena *a;
    uint32_t wrapper_va = 0u;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0u;
    }
    a = bctx->lua->arena;
    rome2_l78_lua_pushstring(bctx->lua, l_va, "lookup");
    rome2_l78_lua_gettable(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX);
    rome2_l76_lua_pushlightuserdata(a, l_va, l_va);
    rome2_l78_lua_gettable(bctx->lua, l_va, -2);
    if (rome2_l76_lua_isuserdata(a, l_va, -1) != 0) {
        wrapper_va = rome2_l76_lua_touserdata(a, l_va, -1);
    }
    rome2_l76_lua_settop(a, l_va, -3);
    return wrapper_va;
}

/* 0x112ae710: the original dereferences the wrapper without a NULL test. */
uint32_t rome2_l79_get_script_lua_state(rome2_l79_bridge_ctx *bctx, uint32_t owner_va) {
    uint32_t wrapper_va = rome2_l79_get_or_init_script_wrapper(bctx, owner_va);
    return (wrapper_va != 0u) ? l79_wrapper_state(bctx, wrapper_va) : 0u;
}

/* 0x112af430 */
void rome2_l79_set_pointer_metatable(rome2_l79_bridge_ctx *bctx, uint32_t l_va, const char *tname) {
    if (bctx == NULL || bctx->lua == NULL || tname == NULL) {
        return;
    }
    if (rome2_l78_luaL_newmetatable(bctx->lua, l_va, tname) == 1) {
        rome2_l78_lua_pushstring(bctx->lua, l_va, tname);
        rome2_l78_lua_setfield(bctx->lua, l_va, -2, "type");
        rome2_l78_lua_pushcclosure(bctx->lua, l_va, ROME2_L79_VA_USERDATA_TOSTRING, 0);
        rome2_l78_lua_setfield(bctx->lua, l_va, -2, "__tostring");
        rome2_l78_lua_pushcclosure(bctx->lua, l_va, ROME2_L79_VA_USERDATA_EQ, 0);
        rome2_l78_lua_setfield(bctx->lua, l_va, -2, "__eq");
    }
    (void)rome2_l76_lua_setmetatable(bctx->lua->arena, l_va, -2);
}

/* 0x112afa70: appends "<typename>: <value>" for the stack top and pops it. */
void rome2_l79_append_lua_typed_value(
    rome2_l79_bridge_ctx *bctx,
    char *out,
    size_t out_cap,
    uint32_t l_va) {
    rome2_l75_arena *a;
    const char *text = NULL;
    char num[16];
    if (bctx == NULL || bctx->lua == NULL || out == NULL || out_cap == 0u) {
        return;
    }
    a = bctx->lua->arena;
    l79_append(out, out_cap, rome2_l76_lua_typename(rome2_l76_lua_type(a, l_va, -1)));
    l79_append(out, out_cap, ": ");
    switch (rome2_l76_lua_type(a, l_va, -1)) {
        case ROME2_LUA_TNIL:
            text = "nil";
            break;
        case ROME2_LUA_TBOOLEAN:
            text = (rome2_l76_lua_toboolean(a, l_va, -1) == 1) ? "true" : "false";
            break;
        case ROME2_LUA_TNUMBER:
            /* float -> u32 through 0x11683b10, then unsigned decimal through 0x101002b0 */
            (void)snprintf(
                num, sizeof(num), "%u",
                (unsigned)rome2_vfs_crt_ftoui3(rome2_l76_lua_tonumber(a, l_va, -1)));
            text = num;
            break;
        case ROME2_LUA_TSTRING:
            text = rome2_l78_lua_tolstring(bctx->lua, l_va, -1, NULL);
            break;
        default:
            break;
    }
    l79_append(out, out_cap, text);
    rome2_l76_lua_settop(a, l_va, -2);
}

/* 0x112c6d90: one "--> name type: value\n" line per upvalue of the function at the top. */
void rome2_l79_append_lua_upvalues(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    char *out,
    size_t out_cap) {
    rome2_l75_arena *a;
    int32_t func_idx;
    int32_t n;
    uint32_t name_va;
    if (bctx == NULL || bctx->lua == NULL || out == NULL || out_cap == 0u) {
        return;
    }
    a = bctx->lua->arena;
    func_idx = rome2_l76_lua_gettop(a, l_va);
    if (rome2_l76_lua_type(a, l_va, func_idx) != ROME2_LUA_TFUNCTION) {
        return;
    }
    name_va = rome2_l76_lua_getupvalue(a, l_va, func_idx, 1);
    n = 2;
    while (name_va != 0u) {
        l79_append(out, out_cap, "--> ");
        l79_append(out, out_cap, rome2_l75_cstr_at(a, name_va));
        l79_append(out, out_cap, " ");
        rome2_l79_append_lua_typed_value(bctx, out, out_cap, l_va);
        l79_append(out, out_cap, "\n");
        name_va = rome2_l76_lua_getupvalue(a, l_va, func_idx, n);
        ++n;
    }
}

/* 0x112be4c0: pcall message handler; pops the message, logs a traceback, returns no values. */
int32_t rome2_l79_lua_error_traceback_handler(rome2_l79_bridge_ctx *bctx, uint32_t l_va) {
    rome2_l75_arena *a;
    const rome2_lua_script_wrapper24_32 *wrap;
    const char *msg;
    const char *owner_name = NULL;
    char message[ROME2_L79_TEXT_CAP];
    char text[ROME2_L79_TEXT_CAP];
    char locals[ROME2_L79_TEXT_CAP];
    char upvalues[ROME2_L79_TEXT_CAP];
    rome2_lua_debug_32 ar;
    uint32_t wrapper_va;
    int32_t level;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0;
    }
    a = bctx->lua->arena;
    msg = rome2_l78_lua_tolstring(bctx->lua, l_va, -1, NULL);
    (void)snprintf(message, sizeof(message), "%s", msg != NULL ? msg : "(error with no message)");
    rome2_l76_lua_settop(a, l_va, -2);
    wrapper_va = rome2_l79_lookup_lua_wrapper(bctx, l_va);
    if (wrapper_va == 0u) {
        return 0;
    }
    wrap = (const rome2_lua_script_wrapper24_32 *)rome2_l75_const_ptr(a, wrapper_va, sizeof(*wrap));
    if (wrap != NULL && bctx->owner_name != NULL) {
        owner_name = bctx->owner_name(bctx, wrap->owner_ctx_va);
    }
    bctx->script_label[ROME2_L79_LABEL_CAP - 1] = '\0';
    (void)rome2_l76_lua_format_3args(
        text, sizeof(text), "Lua Error: [%s], %s\n%s\n", owner_name, bctx->script_label, message);
    l79_log(bctx, text);

    memset(&ar, 0, sizeof(ar));
    level = 2;
    while (rome2_l75_lua_getstack(a, l_va, level - 1, &ar) == 1) {
        uint32_t name_va;
        int32_t n = 2;
        locals[0] = '\0';
        upvalues[0] = '\0';
        name_va = rome2_l75_lua_getlocal(a, l_va, &ar, 1);
        while (name_va != 0u) {
            l79_append(locals, sizeof(locals), "--> ");
            l79_append(locals, sizeof(locals), rome2_l75_cstr_at(a, name_va));
            l79_append(locals, sizeof(locals), " ");
            rome2_l79_append_lua_typed_value(bctx, locals, sizeof(locals), l_va);
            l79_append(locals, sizeof(locals), "\n");
            name_va = rome2_l75_lua_getlocal(a, l_va, &ar, n);
            ++n;
        }
        /* "f" leaves the frame's function on the stack; the original never pops it */
        if (rome2_l78_lua_getinfo(bctx->lua, l_va, "Slnfu", &ar) == 1) {
            const char *what = (ar.what_va != 0u) ? rome2_l75_cstr_at(a, ar.what_va) : "";
            const char *name = (ar.name_va != 0u) ? rome2_l75_cstr_at(a, ar.name_va) : "";
            rome2_l79_append_lua_upvalues(bctx, l_va, upvalues, sizeof(upvalues));
            (void)snprintf(
                text, sizeof(text), "%d. Function (%s):(%s):%d\n",
                level - 1, what != NULL ? what : "", name != NULL ? name : "", ar.linedefined);
            l79_log(bctx, text);
            (void)snprintf(text, sizeof(text), "> Local Variables\n%s\n", locals);
            l79_log(bctx, text);
            (void)snprintf(text, sizeof(text), "> Upvalues\n%s\n", upvalues);
            l79_log(bctx, text);
        }
        ++level;
    }
    return 0;
}

/* 0x112dbc80: the formatted text is itself handed to lua_pushfstring as the format. */
void rome2_l79_report_lua_type_mismatch(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    int32_t expected_type,
    int32_t found_type) {
    char text[128];
    if (bctx == NULL || bctx->lua == NULL) {
        return;
    }
    (void)snprintf(
        text, sizeof(text), "Trying to retrieve type %s, found type %s",
        rome2_l76_lua_typename(expected_type), rome2_l76_lua_typename(found_type));
    (void)rome2_l78_lua_pushfstring(bctx->lua, l_va, text);
    (void)rome2_l79_lua_error_traceback_handler(bctx, l_va);
}

/* 0x112ad700: __thiscall on the wrapper; the handler sits at stack index 1 for the call. */
void rome2_l79_wrapper_pcall(
    rome2_l79_bridge_ctx *bctx,
    uint32_t wrapper_va,
    int32_t nargs,
    int32_t nresults) {
    rome2_l75_arena *a;
    uint32_t l_va;
    if (bctx == NULL || bctx->lua == NULL) {
        return;
    }
    a = bctx->lua->arena;
    l_va = l79_wrapper_state(bctx, wrapper_va);
    if (l_va == 0u) {
        return;
    }
    rome2_l78_lua_pushcclosure(bctx->lua, l_va, ROME2_L79_VA_TRACEBACK, 0);
    rome2_l76_lua_insert(a, l_va, 1);
    if (rome2_l76_lua_type(a, l_va, ~nargs) == ROME2_LUA_TFUNCTION) {
        (void)rome2_l78_lua_pcall(bctx->lua, l_va, nargs, nresults, 1);
        rome2_l76_lua_remove(a, l_va, 1);
        return;
    }
    rome2_l79_report_lua_type_mismatch(
        bctx, l_va, ROME2_LUA_TFUNCTION, rome2_l76_lua_type(a, l_va, ~nargs));
    rome2_l76_lua_settop(a, l_va, -2 - nargs);
    rome2_l76_lua_remove(a, l_va, 1);
}

/* 0x10ca32d0: __thiscall on the script context; returns how many handlers returned true. */
int32_t rome2_l79_dispatch_lua_event(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_va,
    uint32_t event_va) {
    rome2_l77_ctx *lua;
    rome2_l75_arena *a;
    uint32_t l_va;
    const char *key;
    int32_t count = 0;
    int32_t n;
    int32_t i;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0;
    }
    lua = bctx->lua;
    a = lua->arena;
    l_va = rome2_l79_get_script_lua_state(bctx, owner_va);
    if (l_va == 0u) {
        return 0;
    }
    rome2_l78_lua_getfield(lua, l_va, ROME2_LUA_GLOBALSINDEX, "events");
    if (rome2_l76_lua_type(a, l_va, -1) == ROME2_LUA_TNIL) {
        rome2_l76_lua_settop(a, l_va, -2);
        return 0;
    }
    key = (bctx->event_name != NULL) ? bctx->event_name(bctx, event_va) : NULL;
    rome2_l78_lua_getfield(lua, l_va, -1, key != NULL ? key : "");
    if (rome2_l76_lua_type(a, l_va, -1) != ROME2_LUA_TNIL) {
        n = (int32_t)rome2_l78_lua_objlen(lua, l_va, -1);
        for (i = 1; i <= n; ++i) {
            uint32_t w_l;
            uint32_t comp_va;
            const char *text;
            rome2_l76_lua_rawgeti(a, l_va, -1, i);
            w_l = l79_wrapper_state(bctx, rome2_l79_get_or_init_script_wrapper(bctx, owner_va));
            l79_push_cached_pointer(bctx, w_l, event_va, k_l79_event_funcsig);
            (void)rome2_l76_lua_getmetatable(a, l_va, -1);
            rome2_l78_lua_createtable(lua, l_va, 0, 0);
            if (bctx->event_fill_context != NULL) {
                bctx->event_fill_context(bctx, event_va, l_va);
            }
            rome2_l78_lua_pushstring(lua, l_va, "component");
            comp_va = (bctx->event_component != NULL) ? bctx->event_component(bctx, event_va) : 0u;
            w_l = l79_wrapper_state(bctx, rome2_l79_get_or_init_script_wrapper(bctx, owner_va));
            if (comp_va == 0u) {
                rome2_l76_lua_pushnil(a, w_l);
            } else {
                l79_push_cached_pointer(bctx, w_l, comp_va, k_l79_component_funcsig);
            }
            rome2_l78_lua_settable(lua, l_va, -3);
            rome2_l78_lua_pushstring(lua, l_va, "string");
            text = (bctx->event_string != NULL) ? bctx->event_string(bctx, event_va) : NULL;
            rome2_l78_lua_pushstring(lua, l_va, text != NULL ? text : "");
            rome2_l78_lua_settable(lua, l_va, -3);
            rome2_l78_lua_setfield(lua, l_va, -2, "__index");
            (void)rome2_l76_lua_setmetatable(a, l_va, -2);
            rome2_l79_wrapper_pcall(
                bctx, rome2_l79_get_or_init_script_wrapper(bctx, owner_va), 1, 1);
            if (rome2_l76_lua_type(a, l_va, -1) == ROME2_LUA_TBOOLEAN &&
                rome2_l76_lua_toboolean(a, l_va, -1) > 0) {
                ++count;
            }
            rome2_l76_lua_settop(a, l_va, -2);
        }
    }
    rome2_l76_lua_settop(a, l_va, -3);
    return count;
}

/* 0x10cb8880 */
void rome2_l79_dispatch_event_if_lua_enabled(rome2_l79_bridge_ctx *bctx, uint32_t event_va) {
    uint32_t owner_va;
    if (bctx == NULL || bctx->event_enabled == NULL || bctx->event_enabled(bctx, event_va) == 0u) {
        return;
    }
    if (bctx->script_ctx_depth == 0u || bctx->script_ctx_depth > ROME2_L79_MAX_SCRIPT_CTX_STACK) {
        return;
    }
    owner_va = bctx->script_ctx_stack[bctx->script_ctx_depth - 1u];
    if (owner_va == 0u) {
        return;
    }
    if (bctx->event_lua_visible == NULL || bctx->event_lua_visible(bctx, event_va) == 0u) {
        return;
    }
    (void)rome2_l79_dispatch_lua_event(bctx, owner_va, event_va);
}

static uint32_t l79_advice_detail(rome2_l79_bridge_ctx *bctx, uint32_t advice_va) {
    return (bctx->advice_detail != NULL) ? bctx->advice_detail(bctx, advice_va) : 0u;
}

/* detail +0x4c */
static int32_t l79_detail_priority(const rome2_l79_bridge_ctx *bctx, uint32_t detail_va) {
    const int32_t *p = (const int32_t *)rome2_l75_const_ptr(bctx->lua->arena, detail_va + 0x4cu, 4u);
    return (p != NULL) ? *p : 0xff;
}

/* push_back on the {capacity, count, data} vector at 0x1196fc14 */
static void l79_history_push(rome2_l79_bridge_ctx *bctx, uint32_t advice_va) {
    rome2_l75_arena *a = bctx->lua->arena;
    uint32_t *slot;
    if (bctx->history_count >= bctx->history_capacity) {
        uint32_t old_va = bctx->history_va;
        uint32_t new_cap = (bctx->history_capacity == 0u) ? 1u : bctx->history_capacity * 2u;
        uint32_t new_va;
        if (new_cap > 0x1000u) {
            return; /* outside the bounded domain */
        }
        new_va = l79_alloc_zero(bctx->lua, new_cap * 4u);
        if (new_va == 0u) {
            return; /* the original does not test this allocation */
        }
        if (bctx->history_count != 0u) {
            const void *src = rome2_l75_const_ptr(a, old_va, bctx->history_count * 4u);
            void *dst = rome2_l75_mut_ptr(a, new_va, bctx->history_count * 4u);
            if (src != NULL && dst != NULL) {
                memcpy(dst, src, (size_t)bctx->history_count * 4u);
            }
        }
        bctx->history_capacity = new_cap;
        bctx->history_va = new_va; /* the original frees the old block through 0x100fcc50 */
    }
    slot = (uint32_t *)rome2_l75_mut_ptr(a, bctx->history_va + bctx->history_count * 4u, 4u);
    if (slot != NULL) {
        *slot = advice_va;
    }
    ++bctx->history_count;
}

/* 0x10cb6520 */
void rome2_l79_trigger_highest_priority_advice(rome2_l79_bridge_ctx *bctx) {
    uint32_t winner_va;
    uint32_t detail_va;
    uint32_t i;
    uint32_t win = 0u;
    int32_t best = 0xff;
    if (bctx == NULL || bctx->lua == NULL || bctx->advice_mgr_va == 0u) {
        return;
    }
    if (bctx->active_advice_va != 0u) {
        uint32_t ev_va = l79_make_frame_event(
            bctx, ROME2_L79_VA_ADVICE_ACTIVE_EVENT_VTBL,
            l79_advice_detail(bctx, bctx->active_advice_va));
        rome2_l79_dispatch_event_if_lua_enabled(bctx, ev_va);
    }
    if (bctx->advice_queue_count == 0u || bctx->advice_queue_count > ROME2_L79_MAX_ADVICE_ITEMS) {
        return; /* the original reads past an empty queue; its caller tests the count */
    }
    for (i = 0u; i < bctx->advice_queue_count; ++i) {
        /* the original repeats the +0x38 getter for each use */
        if (l79_advice_detail(bctx, bctx->advice_queue[i]) != 0u &&
            l79_detail_priority(bctx, l79_advice_detail(bctx, bctx->advice_queue[i])) < best) {
            best = l79_detail_priority(bctx, l79_advice_detail(bctx, bctx->advice_queue[i]));
            win = i;
        }
    }
    winner_va = bctx->advice_queue[win];
    for (i = win + 1u; i < bctx->advice_queue_count; ++i) {
        bctx->advice_queue[i - 1u] = bctx->advice_queue[i];
    }
    while (--bctx->advice_queue_count != 0u) {
        if (bctx->advice_dismiss != NULL) {
            bctx->advice_dismiss(bctx, bctx->advice_queue[0], 0u);
        }
        for (i = 1u; i < bctx->advice_queue_count; ++i) {
            bctx->advice_queue[i - 1u] = bctx->advice_queue[i];
        }
    }
    if (bctx->advice_activate != NULL) {
        bctx->advice_activate(bctx, winner_va);
    }
    detail_va = l79_advice_detail(bctx, winner_va);
    bctx->active_advice_va = winner_va;
    if (bctx->mgr_advice_started != NULL) {
        bctx->mgr_advice_started(bctx, bctx->advice_mgr_va, winner_va);
    }
    l79_history_push(bctx, winner_va);
    if (detail_va != 0u) {
        /* same gate as 0x10cb8880 with the +0x10 slot devirtualized to 0x100d6900 (always 1) */
        uint32_t ev_va = l79_make_frame_event(bctx, ROME2_L79_VA_ADVICE_ISSUED_EVENT_VTBL, detail_va);
        if (bctx->script_ctx_depth != 0u && bctx->script_ctx_depth <= ROME2_L79_MAX_SCRIPT_CTX_STACK) {
            uint32_t owner_va = bctx->script_ctx_stack[bctx->script_ctx_depth - 1u];
            if (owner_va != 0u && bctx->event_lua_visible != NULL &&
                bctx->event_lua_visible(bctx, ev_va) != 0u) {
                (void)rome2_l79_dispatch_lua_event(bctx, owner_va, ev_va);
            }
        }
    }
}
