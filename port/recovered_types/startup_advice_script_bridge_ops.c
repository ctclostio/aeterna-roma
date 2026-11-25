#include "startup_advice_script_bridge_ops.h"

#include <stdio.h>
#include <string.h>

static uint32_t l79_alloc_zero(rome2_l77_ctx *ctx, uint32_t bytes) {
    uint32_t aligned;
    uint32_t va;
    void *p;
    if (ctx == NULL || ctx->arena == NULL || bytes == 0u) {
        return 0u;
    }
    aligned = (bytes + 7u) & ~7u;
    if (ctx->heap_cursor + aligned > ctx->heap_end) {
        return 0u;
    }
    va = ctx->heap_cursor;
    ctx->heap_cursor += aligned;
    p = rome2_l75_mut_ptr(ctx->arena, va, aligned);
    if (p != NULL) {
        memset(p, 0, aligned);
    }
    return va;
}

static void l79_append_str(char *dst, size_t cap, const char *src) {
    size_t cur;
    size_t add;
    if (dst == NULL || cap == 0u || src == NULL) {
        return;
    }
    cur = strnlen(dst, cap - 1u);
    if (cur >= cap - 1u) {
        return;
    }
    add = strnlen(src, cap - 1u - cur);
    memcpy(dst + cur, src, add);
    dst[cur + add] = '\0';
}

static uint32_t l79_push_ptr_userdata(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    uint32_t ptr_val_va,
    const char *tname) {
    uint32_t payload_va;
    uint32_t *slot;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0u;
    }
    payload_va = rome2_l78_lua_newuserdata(bctx->lua, l_va, 4u);
    if (payload_va == 0u) {
        return 0u;
    }
    slot = (uint32_t *)rome2_l75_mut_ptr(bctx->lua->arena, payload_va, 4u);
    if (slot != NULL) {
        *slot = ptr_val_va;
    }
    rome2_l79_register_lua_pointer_metatable(bctx, l_va, tname);
    return payload_va;
}

void rome2_l79_bridge_ctx_init(rome2_l79_bridge_ctx *bctx, rome2_l77_ctx *lua) {
    if (bctx == NULL) {
        return;
    }
    memset(bctx, 0, sizeof(*bctx));
    bctx->lua = lua;
}

/* 0x112ada40 */
uint32_t rome2_l79_create_empire_lua_master_state(rome2_l79_bridge_ctx *bctx) {
    static const char *const k_tm_names[17] = {
        "__index", "__newindex", "__gc", "__mode", "__eq",
        "__add", "__sub", "__mul", "__div", "__mod", "__pow", "__unm",
        "__len", "__lt", "__le", "__concat", "__call"
    };
    uint32_t l_va;
    const rome2_lua_state_32 *L;
    rome2_lua_global_state_32 *g;
    int32_t ti;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0u;
    }
    l_va = rome2_l78_lua_newstate(bctx->lua, 0x100fcc80u, 0u);
    if (l_va == 0u) {
        return 0u;
    }
    L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(bctx->lua->arena, l_va, sizeof(*L));
    g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(bctx->lua->arena, L->l_g_va, sizeof(*g))
        : NULL;
    if (g != NULL && g->tmname_va[0] == 0u) {
        for (ti = 0; ti < 17; ++ti) {
            uint32_t ts_va = rome2_l77_luaS_newlstr(
                bctx->lua, l_va, k_tm_names[ti], strlen(k_tm_names[ti]));
            rome2_lua_tstring_hdr_32 *ts = (ts_va != 0u)
                ? (rome2_lua_tstring_hdr_32 *)rome2_l75_mut_ptr(bctx->lua->arena, ts_va, sizeof(*ts))
                : NULL;
            if (ts != NULL) {
                ts->marked |= 0x20u;
            }
            g = (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(
                bctx->lua->arena, L->l_g_va, sizeof(*g));
            if (g != NULL) {
                g->tmname_va[ti] = ts_va;
            }
        }
    }
    rome2_l78_luaopen_string(bctx->lua, l_va);

    /* Create weak "lookup" table in _G */
    rome2_l78_lua_createtable(bctx->lua, l_va, 0, 0);
    rome2_l78_lua_createtable(bctx->lua, l_va, 0, 1);
    rome2_l78_lua_pushstring(bctx->lua, l_va, "kv");
    rome2_l78_lua_setfield(bctx->lua, l_va, -2, "__mode");
    (void)rome2_l76_lua_setmetatable(bctx->lua->arena, l_va, -2);
    rome2_l78_lua_setfield(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX, "lookup");

    /* Create weak "udata_lookup" table in _G */
    rome2_l78_lua_createtable(bctx->lua, l_va, 0, 0);
    rome2_l78_lua_createtable(bctx->lua, l_va, 0, 1);
    rome2_l78_lua_pushstring(bctx->lua, l_va, "v");
    rome2_l78_lua_setfield(bctx->lua, l_va, -2, "__mode");
    (void)rome2_l76_lua_setmetatable(bctx->lua->arena, l_va, -2);
    rome2_l78_lua_setfield(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX, "udata_lookup");

    /* Set default events table in _G */
    rome2_l78_lua_createtable(bctx->lua, l_va, 0, 0);
    rome2_l78_lua_setfield(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX, "events");

    /* Optional RequireRegister and system.ClearRequiredFiles hooks */
    rome2_l78_lua_pushcclosure(bctx->lua, l_va, 0x112ae1d0u, 0);
    rome2_l78_lua_setfield(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX, "RequireRegister");
    rome2_l78_lua_createtable(bctx->lua, l_va, 0, 0);
    rome2_l78_lua_pushcclosure(bctx->lua, l_va, 0x112ad850u, 0);
    rome2_l78_lua_setfield(bctx->lua, l_va, -2, "ClearRequiredFiles");
    rome2_l78_lua_setfield(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX, "system");

    bctx->master_state_va = l_va;
    return l_va;
}

/* 0x112addc0 */
void rome2_l79_init_empire_lua_thread_wrapper(
    rome2_l79_bridge_ctx *bctx,
    uint32_t wrapper_va,
    uint32_t parent_state_va) {
    rome2_lua_script_wrapper24_32 *wrap;
    uint32_t parent_l;
    uint32_t child_l;
    int32_t reg_ref;
    uint32_t node_va;
    rome2_lua_wrapper_ring20_32 *node;
    static const rome2_l78_reg shane_lib[] = {
        { NULL, 0u }
    };
    if (bctx == NULL || bctx->lua == NULL) {
        return;
    }
    if (bctx->master_state_va == 0u) {
        (void)rome2_l79_create_empire_lua_master_state(bctx);
    }
    parent_l = (parent_state_va != 0u) ? parent_state_va : bctx->master_state_va;
    if (parent_l == 0u) {
        return;
    }
    child_l = rome2_l78_lua_newthread(bctx->lua, parent_l);
    wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(
        bctx->lua->arena, wrapper_va, sizeof(*wrap));
    if (wrap == NULL || child_l == 0u) {
        return;
    }
    wrap->lua_state_va = child_l;

    /* New environment table inheriting _G via __index */
    rome2_l78_lua_createtable(bctx->lua, parent_l, 0, 0);
    rome2_l78_lua_createtable(bctx->lua, parent_l, 0, 1);
    rome2_l76_lua_pushvalue(bctx->lua->arena, parent_l, ROME2_LUA_GLOBALSINDEX);
    rome2_l78_lua_setfield(bctx->lua, parent_l, -2, "__index");
    (void)rome2_l76_lua_setmetatable(bctx->lua->arena, parent_l, -2);
    (void)rome2_l76_lua_setfenv(bctx->lua->arena, parent_l, -2);

    /* lookup[child_l] = wrapper_va */
    rome2_l78_lua_getfield(bctx->lua, parent_l, ROME2_LUA_GLOBALSINDEX, "lookup");
    if (rome2_l76_lua_type(bctx->lua->arena, parent_l, -1) == ROME2_LUA_TTABLE) {
        rome2_l76_lua_pushlightuserdata(bctx->lua->arena, parent_l, child_l);
        rome2_l76_lua_pushlightuserdata(bctx->lua->arena, parent_l, wrapper_va);
        rome2_l78_lua_settable(bctx->lua, parent_l, -3);
    }
    rome2_l76_lua_settop(bctx->lua->arena, parent_l, -2);

    reg_ref = rome2_l78_luaL_ref(bctx->lua, parent_l, ROME2_LUA_REGISTRYINDEX);
    node_va = l79_alloc_zero(bctx->lua, (uint32_t)sizeof(rome2_lua_wrapper_ring20_32));
    node = (rome2_lua_wrapper_ring20_32 *)rome2_l75_mut_ptr(
        bctx->lua->arena, node_va, sizeof(*node));
    if (node != NULL) {
        node->wrapper_va = wrapper_va;
        node->parent_lua_state_va = parent_l;
        node->registry_ref = reg_ref;
        node->next_va = bctx->ring_head_va;
        node->prev_va = 0u;
        if (bctx->ring_head_va != 0u) {
            rome2_lua_wrapper_ring20_32 *old_head = (rome2_lua_wrapper_ring20_32 *)rome2_l75_mut_ptr(
                bctx->lua->arena, bctx->ring_head_va, sizeof(*old_head));
            if (old_head != NULL) {
                old_head->prev_va = node_va;
            }
        } else {
            bctx->ring_tail_va = node_va;
        }
        bctx->ring_head_va = node_va;
    }

    rome2_l78_lua_createtable(bctx->lua, child_l, 0, 0);
    rome2_l78_luaL_register(bctx->lua, child_l, NULL, shane_lib);
    rome2_l78_lua_setfield(bctx->lua, child_l, ROME2_LUA_GLOBALSINDEX, "shane");

    if (bctx->on_wrapper_init != NULL) {
        bctx->on_wrapper_init(bctx, wrap->owner_ctx_va, child_l);
    }
}

/* 0x112adf80 */
uint32_t rome2_l79_get_or_init_lua_script_context(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va,
    uint32_t parent_wrapper_va,
    uint8_t create_master) {
    uint32_t *owner_slot;
    uint32_t wrap_va;
    rome2_lua_script_wrapper24_32 *wrap;
    uint32_t parent_state_va = 0u;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0u;
    }
    owner_slot = (uint32_t *)rome2_l75_mut_ptr(bctx->lua->arena, owner_ctx_va, 4u);
    if (owner_slot != NULL && *owner_slot != 0u) {
        return *owner_slot;
    }
    wrap_va = l79_alloc_zero(bctx->lua, (uint32_t)sizeof(rome2_lua_script_wrapper24_32));
    wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(
        bctx->lua->arena, wrap_va, sizeof(*wrap));
    if (wrap == NULL) {
        return 0u;
    }
    wrap->owner_ctx_va = owner_ctx_va;
    wrap->owns_master_state = (create_master != 0u) ? 1u : 0u;
    if (create_master != 0u) {
        parent_state_va = rome2_l79_create_empire_lua_master_state(bctx);
        wrap->lua_state_va = parent_state_va;
    } else if (parent_wrapper_va != 0u) {
        const rome2_lua_script_wrapper24_32 *pw = (const rome2_lua_script_wrapper24_32 *)rome2_l75_const_ptr(
            bctx->lua->arena, parent_wrapper_va, sizeof(*pw));
        if (pw != NULL) {
            parent_state_va = pw->lua_state_va;
        }
    }
    rome2_l79_init_empire_lua_thread_wrapper(bctx, wrap_va, parent_state_va);
    wrap = (rome2_lua_script_wrapper24_32 *)rome2_l75_mut_ptr(
        bctx->lua->arena, wrap_va, sizeof(*wrap));
    if (wrap != NULL) {
        wrap->is_valid = (wrap->lua_state_va != 0u) ? 1u : 0u;
    }
    owner_slot = (uint32_t *)rome2_l75_mut_ptr(bctx->lua->arena, owner_ctx_va, 4u);
    if (owner_slot != NULL) {
        *owner_slot = wrap_va;
    }
    return wrap_va;
}

/* 0x112ae010 */
uint32_t rome2_l79_lookup_lua_wrapper_owner(rome2_l79_bridge_ctx *bctx, uint32_t l_va) {
    uint32_t owner_va = 0u;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0u;
    }
    rome2_l78_lua_getfield(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX, "lookup");
    if (rome2_l76_lua_type(bctx->lua->arena, l_va, -1) == ROME2_LUA_TTABLE) {
        rome2_l76_lua_pushlightuserdata(bctx->lua->arena, l_va, l_va);
        rome2_l78_lua_gettable(bctx->lua, l_va, -2);
        if (rome2_l76_lua_isuserdata(bctx->lua->arena, l_va, -1) != 0) {
            owner_va = rome2_l76_lua_touserdata(bctx->lua->arena, l_va, -1);
        }
        rome2_l76_lua_settop(bctx->lua->arena, l_va, -3);
        return owner_va;
    }
    rome2_l76_lua_settop(bctx->lua->arena, l_va, -2);
    return 0u;
}

/* 0x112ae710 */
uint32_t rome2_l79_get_current_lua_state_raw(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va,
    uint32_t parent_wrapper_va,
    uint8_t create_master) {
    uint32_t wrap_va = rome2_l79_get_or_init_lua_script_context(
        bctx, owner_ctx_va, parent_wrapper_va, create_master);
    const rome2_lua_script_wrapper24_32 *wrap = (wrap_va != 0u && bctx != NULL && bctx->lua != NULL)
        ? (const rome2_lua_script_wrapper24_32 *)rome2_l75_const_ptr(
            bctx->lua->arena, wrap_va, sizeof(*wrap))
        : NULL;
    return (wrap != NULL) ? wrap->lua_state_va : 0u;
}

/* 0x112af430 */
void rome2_l79_register_lua_pointer_metatable(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    const char *tname) {
    if (bctx == NULL || bctx->lua == NULL || tname == NULL) {
        return;
    }
    if (rome2_l78_luaL_newmetatable(bctx->lua, l_va, tname) == 1) {
        rome2_l78_lua_pushstring(bctx->lua, l_va, tname);
        rome2_l78_lua_setfield(bctx->lua, l_va, -2, "type");
        rome2_l78_lua_pushcclosure(bctx->lua, l_va, 0x112ae7b0u, 0);
        rome2_l78_lua_setfield(bctx->lua, l_va, -2, "__tostring");
        rome2_l78_lua_pushcclosure(bctx->lua, l_va, 0x112ae770u, 0);
        rome2_l78_lua_setfield(bctx->lua, l_va, -2, "__eq");
    }
    (void)rome2_l76_lua_setmetatable(bctx->lua->arena, l_va, -2);
}

/* 0x112afa70 */
void rome2_l79_format_lua_typed_value(
    rome2_l79_bridge_ctx *bctx,
    char *out,
    size_t out_cap,
    uint32_t l_va) {
    int32_t t;
    char buf[128];
    if (out == NULL || out_cap == 0u) {
        return;
    }
    out[0] = '\0';
    if (bctx == NULL || bctx->lua == NULL) {
        return;
    }
    t = rome2_l76_lua_type(bctx->lua->arena, l_va, -1);
    switch (t) {
        case ROME2_LUA_TNIL:
            l79_append_str(out, out_cap, "nil");
            break;
        case ROME2_LUA_TBOOLEAN:
            l79_append_str(
                out,
                out_cap,
                rome2_l76_lua_toboolean(bctx->lua->arena, l_va, -1) != 0 ? "true" : "false");
            break;
        case ROME2_LUA_TNUMBER: {
            float num = rome2_l76_lua_tonumber(bctx->lua->arena, l_va, -1);
            (void)snprintf(buf, sizeof(buf), "%.14g", (double)num);
            l79_append_str(out, out_cap, buf);
            break;
        }
        case ROME2_LUA_TSTRING: {
            const char *s = rome2_l78_lua_tolstring(bctx->lua, l_va, -1, NULL);
            l79_append_str(out, out_cap, s != NULL ? s : "");
            break;
        }
        case ROME2_LUA_TLIGHTUSERDATA:
        case ROME2_LUA_TUSERDATA: {
            uint32_t ud = rome2_l76_lua_touserdata(bctx->lua->arena, l_va, -1);
            if (rome2_l76_lua_getmetatable(bctx->lua->arena, l_va, -1) != 0) {
                const char *tstr;
                rome2_l78_lua_getfield(bctx->lua, l_va, -1, "type");
                tstr = rome2_l78_lua_tolstring(bctx->lua, l_va, -1, NULL);
                (void)snprintf(
                    buf, sizeof(buf), "%s@0x%08x", tstr != NULL ? tstr : "userdata", ud);
                rome2_l76_lua_settop(bctx->lua->arena, l_va, -3);
            } else {
                (void)snprintf(buf, sizeof(buf), "userdata@0x%08x", ud);
            }
            l79_append_str(out, out_cap, buf);
            break;
        }
        default: {
            const char *tn = rome2_l76_lua_typename(t);
            l79_append_str(out, out_cap, tn != NULL ? tn : "unknown");
            break;
        }
    }
}

/* 0x112c6d90 */
void rome2_l79_format_lua_upvalues(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    char *out,
    size_t out_cap) {
    int32_t idx = 1;
    uint32_t name_va;
    if (bctx == NULL || bctx->lua == NULL || out == NULL || out_cap == 0u) {
        return;
    }
    while ((name_va = rome2_l76_lua_getupvalue(bctx->lua->arena, l_va, -1, idx)) != 0u) {
        const char *name = rome2_l75_cstr_at(bctx->lua->arena, name_va);
        char val_buf[128];
        char line[192];
        rome2_l79_format_lua_typed_value(bctx, val_buf, sizeof(val_buf), l_va);
        rome2_l76_lua_settop(bctx->lua->arena, l_va, -2);
        (void)snprintf(
            line, sizeof(line), "\n  upvalue %s = %s", name != NULL ? name : "?", val_buf);
        l79_append_str(out, out_cap, line);
        ++idx;
    }
}

/* 0x112be4c0 */
int32_t rome2_l79_lua_error_traceback_handler(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va) {
    const char *err = NULL;
    char msg[ROME2_L79_ERR_CAP];
    rome2_lua_debug_32 ar;
    int32_t level = 1;
    if (bctx == NULL || bctx->lua == NULL) {
        return 0;
    }
    ++bctx->traceback_calls;
    msg[0] = '\0';
    err = rome2_l78_lua_tolstring(bctx->lua, l_va, -1, NULL);
    l79_append_str(msg, sizeof(msg), err != NULL ? err : "(non-string error)");
    memset(&ar, 0, sizeof(ar));
    while (level <= 8 && rome2_l75_lua_getstack(bctx->lua->arena, l_va, level, &ar) != 0) {
        char frame_buf[160];
        if (rome2_l78_lua_getinfo(bctx->lua, l_va, "Slnf", &ar) != 0) {
            const char *name = rome2_l75_cstr_at(bctx->lua->arena, ar.name_va);
            (void)snprintf(
                frame_buf,
                sizeof(frame_buf),
                "\n  [%d] %s:%d (%s)",
                level,
                ar.short_src,
                ar.currentline,
                name != NULL ? name : "?");
            l79_append_str(msg, sizeof(msg), frame_buf);
            rome2_l79_format_lua_upvalues(bctx, l_va, msg, sizeof(msg));
            rome2_l76_lua_settop(bctx->lua->arena, l_va, -2);
        }
        ++level;
        memset(&ar, 0, sizeof(ar));
    }
    memcpy(bctx->last_error_msg, msg, sizeof(msg));
    if (bctx->on_error_log != NULL) {
        bctx->on_error_log(bctx, bctx->last_error_msg);
    }
    rome2_l78_lua_pushstring(bctx->lua, l_va, bctx->last_error_msg);
    return 1;
}

/* 0x112dbc80 */
void rome2_l79_report_lua_type_mismatch(
    rome2_l79_bridge_ctx *bctx,
    uint32_t l_va,
    int32_t expected_type,
    int32_t found_type) {
    const char *exp_name = rome2_l76_lua_typename(expected_type);
    const char *fnd_name = rome2_l76_lua_typename(found_type);
    char buf[256];
    if (bctx == NULL || bctx->lua == NULL) {
        return;
    }
    (void)snprintf(
        buf,
        sizeof(buf),
        "Trying to retrieve type %s, found type %s",
        exp_name != NULL ? exp_name : "unknown",
        fnd_name != NULL ? fnd_name : "unknown");
    rome2_l78_lua_pushstring(bctx->lua, l_va, buf);
    (void)rome2_l79_lua_error_traceback_handler(bctx, l_va);
}

/* 0x112ad700 */
int32_t rome2_l79_lua_state_pcall_or_err(
    rome2_l79_bridge_ctx *bctx,
    uint32_t wrapper_va,
    int32_t nargs,
    int32_t nresults) {
    const rome2_lua_script_wrapper24_32 *wrap;
    uint32_t l_va;
    int32_t fn_idx;
    int32_t errfunc_idx;
    int32_t found_t;
    int32_t status;
    if (bctx == NULL || bctx->lua == NULL || nargs < 0) {
        return ROME2_LUA_ERRRUN;
    }
    wrap = (const rome2_lua_script_wrapper24_32 *)rome2_l75_const_ptr(
        bctx->lua->arena, wrapper_va, sizeof(*wrap));
    if (wrap == NULL || wrap->lua_state_va == 0u) {
        return ROME2_LUA_ERRRUN;
    }
    l_va = wrap->lua_state_va;
    fn_idx = rome2_l76_lua_gettop(bctx->lua->arena, l_va) - nargs;
    if (fn_idx < 1) {
        return ROME2_LUA_ERRRUN;
    }
    found_t = rome2_l76_lua_type(bctx->lua->arena, l_va, fn_idx);
    if (found_t != ROME2_LUA_TFUNCTION) {
        ++bctx->pcall_errors;
        rome2_l79_report_lua_type_mismatch(bctx, l_va, ROME2_LUA_TFUNCTION, found_t);
        rome2_l76_lua_settop(bctx->lua->arena, l_va, fn_idx - 1);
        return ROME2_LUA_ERRRUN;
    }
    errfunc_idx = fn_idx;
    rome2_l78_lua_pushcclosure(bctx->lua, l_va, 0x112be4c0u, 0);
    rome2_l76_lua_insert(bctx->lua->arena, l_va, errfunc_idx);
    status = rome2_l78_lua_pcall(bctx->lua, l_va, nargs, nresults, errfunc_idx);
    if (status != ROME2_LUA_OK) {
        ++bctx->pcall_errors;
        (void)rome2_l79_lua_error_traceback_handler(bctx, l_va);
    }
    rome2_l76_lua_remove(bctx->lua->arena, l_va, errfunc_idx);
    return status;
}

/* 0x10ca32d0 */
int32_t rome2_l79_dispatch_advice_lua_events(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va,
    const rome2_l79_advice_item *advice_obj) {
    uint32_t wrap_va;
    const rome2_lua_script_wrapper24_32 *wrap;
    uint32_t l_va;
    int32_t dispatched = 0;
    int32_t tbl_len;
    int32_t i;
    if (bctx == NULL || bctx->lua == NULL || advice_obj == NULL || advice_obj->event_name[0] == '\0') {
        return 0;
    }
    wrap_va = rome2_l79_get_or_init_lua_script_context(bctx, owner_ctx_va, 0u, 0u);
    wrap = (wrap_va != 0u)
        ? (const rome2_lua_script_wrapper24_32 *)rome2_l75_const_ptr(
            bctx->lua->arena, wrap_va, sizeof(*wrap))
        : NULL;
    if (wrap == NULL || wrap->lua_state_va == 0u || wrap->is_valid == 0u) {
        return 0;
    }
    l_va = wrap->lua_state_va;
    rome2_l78_lua_getfield(bctx->lua, l_va, ROME2_LUA_GLOBALSINDEX, "events");
    if (rome2_l76_lua_type(bctx->lua->arena, l_va, -1) != ROME2_LUA_TTABLE) {
        rome2_l76_lua_settop(bctx->lua->arena, l_va, -2);
        return 0;
    }
    rome2_l78_lua_getfield(bctx->lua, l_va, -1, advice_obj->event_name);
    if (rome2_l76_lua_type(bctx->lua->arena, l_va, -1) != ROME2_LUA_TTABLE) {
        rome2_l76_lua_settop(bctx->lua->arena, l_va, -3);
        return 0;
    }
    tbl_len = (int32_t)rome2_l78_lua_objlen(bctx->lua, l_va, -1);
    for (i = 1; i <= tbl_len; ++i) {
        rome2_l76_lua_rawgeti(bctx->lua->arena, l_va, -1, i);
        if (rome2_l76_lua_type(bctx->lua->arena, l_va, -1) == ROME2_LUA_TFUNCTION) {
            (void)l79_push_ptr_userdata(bctx, l_va, advice_obj->obj_va, "EMPIREUTILITY::EVENT");
            (void)l79_push_ptr_userdata(bctx, l_va, advice_obj->comp_va, "TWUI::Component");
            if (rome2_l79_lua_state_pcall_or_err(bctx, wrap_va, 2, 0) == ROME2_LUA_OK) {
                ++dispatched;
            }
        } else {
            rome2_l76_lua_settop(bctx->lua->arena, l_va, -2);
        }
    }
    rome2_l76_lua_settop(bctx->lua->arena, l_va, -3);
    return dispatched;
}

/* 0x10cb8880 */
void rome2_l79_dispatch_advice_if_lua_enabled(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va,
    const rome2_l79_advice_item *advice_obj) {
    if (bctx == NULL || advice_obj == NULL) {
        return;
    }
    if (advice_obj->is_lua_eligible == 0u || advice_obj->should_dispatch == 0u) {
        return;
    }
    if (bctx->lua_enabled_depth == 0u ||
        bctx->lua_enabled_stack[bctx->lua_enabled_depth - 1u] == 0u) {
        return;
    }
    (void)rome2_l79_dispatch_advice_lua_events(bctx, owner_ctx_va, advice_obj);
}

/* 0x10cb6520 */
void rome2_l79_trigger_highest_priority_advice_thread(
    rome2_l79_bridge_ctx *bctx,
    uint32_t owner_ctx_va) {
    size_t i;
    int32_t best_prio = 0xff;
    size_t best_idx = 0u;
    rome2_l79_advice_item *winner;
    if (bctx == NULL || bctx->advice_mgr_active == 0u || bctx->advice_queue_count == 0u) {
        return;
    }
    if (bctx->active_advice_va != 0u) {
        for (i = 0u; i < bctx->advice_queue_count; ++i) {
            rome2_l79_advice_item *cur = bctx->advice_queue[i];
            if (cur != NULL && cur->obj_va == bctx->active_advice_va) {
                rome2_l79_dispatch_advice_if_lua_enabled(bctx, owner_ctx_va, cur);
                break;
            }
        }
    }
    for (i = 0u; i < bctx->advice_queue_count; ++i) {
        rome2_l79_advice_item *cur = bctx->advice_queue[i];
        if (cur != NULL && cur->has_detail != 0u && cur->priority < best_prio) {
            best_prio = cur->priority;
            best_idx = i;
        }
    }
    winner = bctx->advice_queue[best_idx];
    for (i = best_idx + 1u; i < bctx->advice_queue_count; ++i) {
        bctx->advice_queue[i - 1u] = bctx->advice_queue[i];
    }
    --bctx->advice_queue_count;

    while (bctx->advice_queue_count > 0u) {
        rome2_l79_advice_item *loser = bctx->advice_queue[0];
        for (i = 1u; i < bctx->advice_queue_count; ++i) {
            bctx->advice_queue[i - 1u] = bctx->advice_queue[i];
        }
        --bctx->advice_queue_count;
        if (loser != NULL) {
            ++bctx->dismiss_calls;
            if (bctx->on_advice_dismiss != NULL) {
                bctx->on_advice_dismiss(bctx, loser);
            }
        }
    }

    if (winner != NULL) {
        winner->active = 1u;
        bctx->active_advice_va = winner->obj_va;
        ++bctx->activate_calls;
        if (bctx->on_advice_activate != NULL) {
            bctx->on_advice_activate(bctx, winner);
        }
        ++bctx->notify_calls;
        if (bctx->on_advice_notify != NULL) {
            bctx->on_advice_notify(bctx, winner);
        }
        if (bctx->triggered_count < ROME2_L79_MAX_ADVICE_ITEMS) {
            bctx->triggered_history[bctx->triggered_count++] = winner->obj_va;
        }
    }
}
