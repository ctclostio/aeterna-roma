#include "lua_vm_gc_table_ops.h"
#include "startup_crt_strtod_setjmp_ops.h"

#include <stdio.h>
#include <string.h>

static float l77_u2f(uint32_t u) {
    float f = 0.0f;
    memcpy(&f, &u, sizeof(f));
    return f;
}

static uint32_t l77_f2u(float f) {
    uint32_t u = 0u;
    memcpy(&u, &f, sizeof(u));
    return u;
}

static void l77_check_gc(rome2_l77_ctx *ctx, uint32_t l_va) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    const rome2_lua_global_state_32 *g = (L != NULL)
        ? (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    if (g != NULL && g->totalbytes >= g->gc_threshold && g->gc_threshold != 0u) {
        rome2_l77_singlestep(ctx, l_va);
    }
}

void rome2_l77_ctx_init(
    rome2_l77_ctx *ctx,
    rome2_l75_arena *arena,
    uint32_t heap_start_va,
    uint32_t heap_end_va) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->arena = arena;
    ctx->heap_cursor = (heap_start_va + 7u) & ~7u;
    ctx->heap_end = heap_end_va;
}

/* 0x10f4e080 */
uint32_t rome2_l77_luaM_realloc(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    uint32_t block_va,
    uint32_t osize,
    uint32_t nsize) {
    const rome2_lua_state_32 *L;
    rome2_lua_global_state_32 *g;
    uint32_t new_va = 0u;
    if (ctx == NULL || ctx->arena == NULL) {
        return 0u;
    }
    L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L));
    g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    if (nsize > 0u) {
        uint32_t align = (ctx->heap_cursor + 7u) & ~7u;
        if (align > ctx->heap_end || nsize > (ctx->heap_end - align)) {
            rome2_l77_luaD_throw(ctx, l_va, ROME2_LUA_ERRMEM);
            return 0u;
        }
        new_va = align;
        ctx->heap_cursor = align + ((nsize + 7u) & ~7u);
        {
            void *dst = rome2_l75_mut_ptr(ctx->arena, new_va, nsize);
            if (dst != NULL) {
                memset(dst, 0, nsize);
                if (block_va != 0u && osize > 0u) {
                    uint32_t copy_n = (osize < nsize) ? osize : nsize;
                    const void *src = rome2_l75_const_ptr(ctx->arena, block_va, copy_n);
                    if (src != NULL) {
                        memcpy(dst, src, copy_n);
                    }
                }
            }
        }
    }
    if (g != NULL) {
        g->totalbytes = (uint32_t)((int32_t)g->totalbytes + (int32_t)(nsize - osize));
    }
    return new_va;
}

/* 0x10f4e0d0 */
uint32_t rome2_l77_luaM_toobig(rome2_l77_ctx *ctx, uint32_t l_va) {
    rome2_l77_luaG_runerror(ctx, l_va, "memory allocation error: block too big");
    return 0u;
}

/* 0x10f467e0 */
uint32_t rome2_l77_luaZ_openspace(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t mbuf_va, uint32_t n) {
    uint32_t *hdr;
    uint32_t cur_ptr;
    uint32_t cur_sz;
    uint32_t target;
    if (ctx == NULL) {
        return 0u;
    }
    hdr = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, mbuf_va, 12u);
    if (hdr == NULL) {
        return 0u;
    }
    cur_ptr = hdr[0];
    cur_sz = hdr[2];
    if (n <= cur_sz) {
        return cur_ptr;
    }
    target = (n < 32u) ? 32u : n;
    if (target + 1u < 0xfffffffeu) {
        cur_ptr = rome2_l77_luaM_realloc(ctx, l_va, cur_ptr, cur_sz, target);
    } else {
        cur_ptr = rome2_l77_luaM_toobig(ctx, l_va);
    }
    hdr[0] = cur_ptr;
    hdr[2] = target;
    return cur_ptr;
}

static uint32_t l77_hash_str(const char *str, size_t len) {
    uint32_t h = (uint32_t)len;
    size_t step = (len >> 5) + 1u;
    size_t l1;
    for (l1 = len; l1 >= step; l1 -= step) {
        h ^= (h << 5) + (h >> 2) + (uint32_t)(uint8_t)str[l1 - 1u];
    }
    return h;
}

/* 0x10f4a7c0 */
void rome2_l77_luaS_resize(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t newsize) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    uint32_t newhash_va;
    uint32_t i;
    if (g == NULL || g->gcstate == 2u) {
        return;
    }
    newhash_va = (newsize + 1u < 0x40000000u)
        ? rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, newsize * 4u)
        : rome2_l77_luaM_toobig(ctx, l_va);
    if (newhash_va == 0u) {
        return;
    }
    for (i = 0u; i < (uint32_t)g->strt_size; ++i) {
        const uint32_t *bucket = (const uint32_t *)rome2_l75_const_ptr(
            ctx->arena, g->strt_hash_va + i * 4u, 4u);
        uint32_t p = (bucket != NULL) ? *bucket : 0u;
        while (p != 0u) {
            rome2_lua_tstring_hdr_32 *ts = (rome2_lua_tstring_hdr_32 *)rome2_l75_mut_ptr(
                ctx->arena, p, sizeof(*ts));
            uint32_t nxt;
            uint32_t h;
            uint32_t *dst;
            if (ts == NULL) {
                break;
            }
            nxt = ts->next_va;
            h = ts->hash & (newsize - 1u);
            dst = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, newhash_va + h * 4u, 4u);
            if (dst != NULL) {
                ts->next_va = *dst;
                *dst = p;
            }
            p = nxt;
        }
    }
    rome2_l77_luaM_realloc(ctx, l_va, g->strt_hash_va, (uint32_t)g->strt_size * 4u, 0u);
    g->strt_hash_va = newhash_va;
    g->strt_size = (int32_t)newsize;
}

/* 0x10f4a500 */
uint32_t rome2_l77_luaS_newlstr(rome2_l77_ctx *ctx, uint32_t l_va, const char *str, size_t len) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    uint32_t h;
    uint32_t bucket_va;
    uint32_t p;
    uint32_t ts_va;
    rome2_lua_tstring_hdr_32 *ts;
    if (g == NULL || str == NULL) {
        return 0u;
    }
    h = l77_hash_str(str, len);
    if (g->strt_size > 0 && g->strt_hash_va != 0u) {
        bucket_va = g->strt_hash_va + ((uint32_t)(g->strt_size - 1) & h) * 4u;
        {
            const uint32_t *bp = (const uint32_t *)rome2_l75_const_ptr(ctx->arena, bucket_va, 4u);
            p = (bp != NULL) ? *bp : 0u;
        }
        while (p != 0u) {
            rome2_lua_tstring_hdr_32 *cur = (rome2_lua_tstring_hdr_32 *)rome2_l75_mut_ptr(
                ctx->arena, p, sizeof(*cur));
            const char *txt;
            if (cur == NULL) {
                break;
            }
            if (cur->len == (uint32_t)len) {
                txt = (const char *)rome2_l75_const_ptr(
                    ctx->arena, p + (uint32_t)sizeof(*cur), (uint32_t)len);
                if (txt != NULL && (len == 0u || memcmp(str, txt, len) == 0)) {
                    if (((uint8_t)(g->currentwhite ^ 3u) & (cur->marked ^ 3u) & 3u) != 0u) {
                        cur->marked ^= 3u;
                    }
                    return p;
                }
            }
            p = cur->next_va;
        }
    }
    if (len + 1u > 0xffffffedu) {
        rome2_l77_luaM_toobig(ctx, l_va);
        return 0u;
    }
    ts_va = rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, (uint32_t)(len + sizeof(*ts) + 1u));
    ts = (rome2_lua_tstring_hdr_32 *)rome2_l75_mut_ptr(
        ctx->arena, ts_va, (uint32_t)(len + sizeof(*ts) + 1u));
    if (ts == NULL) {
        return 0u;
    }
    ts->len = (uint32_t)len;
    ts->hash = h;
    ts->marked = g->currentwhite & 3u;
    ts->tt = ROME2_LUA_TSTRING;
    ts->reserved = 0u;
    if (len > 0u) {
        memcpy((uint8_t *)ts + sizeof(*ts), str, len);
    }
    ((uint8_t *)ts)[sizeof(*ts) + len] = 0u;
    if (g->strt_size > 0 && g->strt_hash_va != 0u) {
        uint32_t *bp = (uint32_t *)rome2_l75_mut_ptr(
            ctx->arena, g->strt_hash_va + ((uint32_t)(g->strt_size - 1) & h) * 4u, 4u);
        if (bp != NULL) {
            ts->next_va = *bp;
            *bp = ts_va;
        }
    }
    ++g->strt_nuse;
    if (g->strt_nuse > g->strt_size && g->strt_size < 0x3fffffff) {
        rome2_l77_luaS_resize(ctx, l_va, (uint32_t)(g->strt_size * 2));
    }
    return ts_va;
}

/* 0x10f4b3c0 */
void rome2_l77_setarrayvector(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t size) {
    rome2_lua_table_32 *t = (ctx != NULL)
        ? (rome2_lua_table_32 *)rome2_l75_mut_ptr(ctx->arena, t_va, sizeof(*t))
        : NULL;
    uint32_t arr_va;
    int32_t i;
    if (t == NULL) {
        return;
    }
    arr_va = ((uint32_t)(size + 1) < 0x20000000u)
        ? rome2_l77_luaM_realloc(ctx, l_va, t->array_va, (uint32_t)t->sizearray * 8u, (uint32_t)size * 8u)
        : rome2_l77_luaM_toobig(ctx, l_va);
    t->array_va = arr_va;
    for (i = t->sizearray; i < size; ++i) {
        rome2_lua_tvalue_32 *slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
            ctx->arena, arr_va + (uint32_t)i * 8u, sizeof(*slot));
        if (slot != NULL) {
            slot->tt = ROME2_LUA_TNIL;
        }
    }
    t->sizearray = size;
}

/* 0x10f4b430 */
void rome2_l77_setnodevector(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t size) {
    rome2_lua_table_32 *t = (ctx != NULL)
        ? (rome2_lua_table_32 *)rome2_l75_mut_ptr(ctx->arena, t_va, sizeof(*t))
        : NULL;
    int32_t lsize;
    uint32_t nsize;
    uint32_t n_va;
    if (t == NULL) {
        return;
    }
    if (size == 0) {
        t->lsizenode = 0u;
        t->node_va = ROME2_LUA_VA_DUMMYNODE;
        t->lastfree_va = ROME2_LUA_VA_DUMMYNODE;
        return;
    }
    lsize = rome2_l75_luaO_log2((uint32_t)(size - 1)) + 1;
    if (lsize > 26) {
        rome2_l77_luaG_runerror(ctx, l_va, "table overflow");
        return;
    }
    nsize = 1u << ((uint32_t)lsize & 0x1fu);
    n_va = (nsize + 1u < 0xccccccdu)
        ? rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, nsize * (uint32_t)sizeof(rome2_lua_node_32))
        : rome2_l77_luaM_toobig(ctx, l_va);
    t->node_va = n_va;
    t->lsizenode = (uint8_t)lsize;
    t->lastfree_va = n_va + nsize * (uint32_t)sizeof(rome2_lua_node_32);
}

/* 0x10f4ab20 */
uint32_t rome2_l77_luaH_new(rome2_l77_ctx *ctx, uint32_t l_va, int32_t narray, int32_t lnhash) {
    uint32_t t_va = rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, sizeof(rome2_lua_table_32));
    rome2_lua_table_32 *t = (rome2_lua_table_32 *)rome2_l75_mut_ptr(ctx->arena, t_va, sizeof(*t));
    if (t == NULL) {
        return 0u;
    }
    rome2_l75_luaC_link(ctx->arena, l_va, t_va, ROME2_LUA_TTABLE);
    t->metatable_va = 0u;
    t->flags = 0xffu;
    t->lsizenode = 0u;
    t->array_va = 0u;
    t->sizearray = 0;
    t->node_va = ROME2_LUA_VA_DUMMYNODE;
    t->lastfree_va = ROME2_LUA_VA_DUMMYNODE;
    rome2_l77_setarrayvector(ctx, l_va, t_va, narray);
    rome2_l77_setnodevector(ctx, l_va, t_va, lnhash);
    return t_va;
}

/* 0x10f4a8a0 */
void rome2_l77_luaH_free(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va) {
    const rome2_lua_table_32 *t = (ctx != NULL)
        ? (const rome2_lua_table_32 *)rome2_l75_const_ptr(ctx->arena, t_va, sizeof(*t))
        : NULL;
    if (t == NULL) {
        return;
    }
    if (t->node_va != ROME2_LUA_VA_DUMMYNODE) {
        uint32_t nsz = (1u << (t->lsizenode & 0x1fu)) * (uint32_t)sizeof(rome2_lua_node_32);
        rome2_l77_luaM_realloc(ctx, l_va, t->node_va, nsz, 0u);
    }
    rome2_l77_luaM_realloc(ctx, l_va, t->array_va, (uint32_t)t->sizearray * 8u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, t_va, sizeof(*t), 0u);
}

/* 0x10f4b240 */
void rome2_l77_resize(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t nasize, int32_t nhsize) {
    rome2_lua_table_32 *t = (ctx != NULL)
        ? (rome2_lua_table_32 *)rome2_l75_mut_ptr(ctx->arena, t_va, sizeof(*t))
        : NULL;
    int32_t oldasize;
    uint32_t oldhsize;
    uint32_t nold_va;
    int32_t i;
    if (t == NULL) {
        return;
    }
    oldasize = t->sizearray;
    oldhsize = 1u << (t->lsizenode & 0x1fu);
    nold_va = t->node_va;
    if (nasize > oldasize) {
        rome2_l77_setarrayvector(ctx, l_va, t_va, nasize);
    }
    rome2_l77_setnodevector(ctx, l_va, t_va, nhsize);
    if (nasize < oldasize) {
        t->sizearray = nasize;
        for (i = nasize; i < oldasize; ++i) {
            const rome2_lua_tvalue_32 *av = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, t->array_va + (uint32_t)i * 8u, sizeof(*av));
            if (av != NULL && av->tt != ROME2_LUA_TNIL) {
                uint32_t slot_va = rome2_l77_luaH_setnum(ctx, l_va, t_va, i + 1);
                rome2_lua_tvalue_32 *slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, slot_va, sizeof(*slot));
                if (slot != NULL) {
                    *slot = *av;
                }
            }
        }
        t->array_va = ((uint32_t)(nasize + 1) < 0x20000000u)
            ? rome2_l77_luaM_realloc(ctx, l_va, t->array_va, (uint32_t)oldasize * 8u, (uint32_t)nasize * 8u)
            : rome2_l77_luaM_toobig(ctx, l_va);
    }
    if (nold_va != ROME2_LUA_VA_DUMMYNODE) {
        uint32_t idx;
        for (idx = oldhsize; idx-- > 0u;) {
            const rome2_lua_node_32 *old = (const rome2_lua_node_32 *)rome2_l75_const_ptr(
                ctx->arena, nold_va + idx * (uint32_t)sizeof(*old), sizeof(*old));
            if (old != NULL && old->i_val.tt != ROME2_LUA_TNIL) {
                uint32_t slot_va = rome2_l77_luaH_set(ctx, l_va, t_va, &old->i_key);
                rome2_lua_tvalue_32 *slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, slot_va, sizeof(*slot));
                if (slot != NULL) {
                    *slot = old->i_val;
                }
            }
        }
        rome2_l77_luaM_realloc(ctx, l_va, nold_va, oldhsize * (uint32_t)sizeof(rome2_lua_node_32), 0u);
    }
}

/* 0x10f4ace0 */
void rome2_l77_luaH_resizearray(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t nasize) {
    const rome2_lua_table_32 *t = (ctx != NULL)
        ? (const rome2_lua_table_32 *)rome2_l75_const_ptr(ctx->arena, t_va, sizeof(*t))
        : NULL;
    int32_t nsize = (t == NULL || t->node_va == ROME2_LUA_VA_DUMMYNODE)
        ? 0
        : (int32_t)(1u << (t->lsizenode & 0x1fu));
    rome2_l77_resize(ctx, l_va, t_va, nasize, nsize);
}

/* 0x10f4b040 */
void rome2_l77_rehash(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, const rome2_lua_tvalue_32 *ek) {
    const rome2_lua_table_32 *t = (ctx != NULL)
        ? (const rome2_lua_table_32 *)rome2_l75_const_ptr(ctx->arena, t_va, sizeof(*t))
        : NULL;
    int32_t nums[27];
    int32_t totaluse = 0;
    int32_t na = 0;
    int32_t ause = 0;
    int32_t lg = 0;
    int32_t ttlg = 1;
    int32_t au = 1;
    uint32_t sizenode;
    int32_t n = 0;
    int32_t i;
    if (t == NULL) {
        return;
    }
    memset(nums, 0, sizeof(nums));
    while (lg < 27 && au <= t->sizearray) {
        int32_t lim = ttlg;
        int32_t lc = 0;
        if (lim > t->sizearray) {
            lim = t->sizearray;
        }
        for (; au <= lim; ++au) {
            const rome2_lua_tvalue_32 *av = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, t->array_va + (uint32_t)(au - 1) * 8u, sizeof(*av));
            if (av != NULL && av->tt != ROME2_LUA_TNIL) {
                ++lc;
            }
        }
        nums[lg] += lc;
        totaluse += lc;
        ause += lc;
        ttlg *= 2;
        ++lg;
    }
    sizenode = 1u << (t->lsizenode & 0x1fu);
    for (i = (int32_t)sizenode; i-- > 0;) {
        const rome2_lua_node_32 *nd = (const rome2_lua_node_32 *)rome2_l75_const_ptr(
            ctx->arena, t->node_va + (uint32_t)i * (uint32_t)sizeof(*nd), sizeof(*nd));
        if (nd != NULL && nd->i_val.tt != ROME2_LUA_TNIL) {
            if (nd->i_key.tt == ROME2_LUA_TNUMBER) {
                float fn = l77_u2f(nd->i_key.value_u32);
                int32_t k = (int32_t)fn;
                if ((float)k == fn && (uint32_t)(k - 1) < 0x4000000u) {
                    nums[rome2_l75_luaO_log2((uint32_t)(k - 1)) + 1] += 1;
                    ++ause;
                }
            }
            ++totaluse;
            ++n;
        }
    }
    if (ek != NULL && ek->tt == ROME2_LUA_TNUMBER) {
        float fn = l77_u2f(ek->value_u32);
        int32_t k = (int32_t)fn;
        if ((float)k == fn && (uint32_t)(k - 1) < 0x4000000u) {
            nums[rome2_l75_luaO_log2((uint32_t)(k - 1)) + 1] += 1;
            ++ause;
        }
    }
    ++totaluse;
    {
        int32_t sum = 0;
        int32_t p2 = 1;
        int32_t k = 0;
        for (i = 0; i < 27 && p2 / 2 < totaluse; ++i, p2 *= 2) {
            if (nums[i] > 0) {
                sum += nums[i];
                if (sum > p2 / 2) {
                    na = p2;
                    k = sum;
                }
            }
            if (sum == totaluse) {
                break;
            }
        }
        rome2_l77_resize(ctx, l_va, t_va, na, (n + ause + 1) - k);
    }
}

/* 0x10f4af50 */
uint32_t rome2_l77_newkey(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, const rome2_lua_tvalue_32 *key) {
    rome2_lua_table_32 *t = (ctx != NULL)
        ? (rome2_lua_table_32 *)rome2_l75_mut_ptr(ctx->arena, t_va, sizeof(*t))
        : NULL;
    uint32_t mp_va;
    rome2_lua_node_32 *mp;
    if (t == NULL || key == NULL) {
        return ROME2_LUA_VA_NILOBJECT;
    }
    mp_va = rome2_l75_mainposition(ctx->arena, t_va, key);
    if (mp_va == ROME2_LUA_VA_DUMMYNODE) {
        rome2_l77_rehash(ctx, l_va, t_va, key);
        return rome2_l77_luaH_set(ctx, l_va, t_va, key);
    }
    mp = (rome2_lua_node_32 *)rome2_l75_mut_ptr(ctx->arena, mp_va, sizeof(*mp));
    if (mp == NULL) {
        return ROME2_LUA_VA_NILOBJECT;
    }
    if (mp->i_val.tt != ROME2_LUA_TNIL) {
        uint32_t f_va = 0u;
        while (t->lastfree_va > t->node_va) {
            t->lastfree_va -= (uint32_t)sizeof(rome2_lua_node_32);
            {
                const rome2_lua_node_32 *cand = (const rome2_lua_node_32 *)rome2_l75_const_ptr(
                    ctx->arena, t->lastfree_va, sizeof(*cand));
                if (cand != NULL && cand->i_key.tt == ROME2_LUA_TNIL) {
                    f_va = t->lastfree_va;
                    break;
                }
            }
        }
        if (f_va == 0u) {
            rome2_l77_rehash(ctx, l_va, t_va, key);
            return rome2_l77_luaH_set(ctx, l_va, t_va, key);
        }
        {
            uint32_t othern_va = rome2_l75_mainposition(ctx->arena, t_va, &mp->i_key);
            rome2_lua_node_32 *othern = (rome2_lua_node_32 *)rome2_l75_mut_ptr(
                ctx->arena, othern_va, sizeof(*othern));
            rome2_lua_node_32 *f = (rome2_lua_node_32 *)rome2_l75_mut_ptr(ctx->arena, f_va, sizeof(*f));
            if (othern != NULL && f != NULL) {
                if (othern_va != mp_va) {
                    while (othern->next_va != mp_va && othern->next_va != 0u) {
                        othern_va = othern->next_va;
                        othern = (rome2_lua_node_32 *)rome2_l75_mut_ptr(
                            ctx->arena, othern_va, sizeof(*othern));
                        if (othern == NULL) {
                            break;
                        }
                    }
                    if (othern != NULL) {
                        othern->next_va = f_va;
                    }
                    *f = *mp;
                    mp->next_va = 0u;
                    mp->i_val.tt = ROME2_LUA_TNIL;
                } else {
                    f->next_va = mp->next_va;
                    mp->next_va = f_va;
                    mp_va = f_va;
                    mp = f;
                }
            }
        }
    }
    mp->i_key = *key;
    if (key->tt > 3) {
        const uint8_t *kh = (const uint8_t *)rome2_l75_const_ptr(ctx->arena, key->value_u32, 6u);
        if (kh != NULL && (kh[5] & 3u) != 0u && (t->marked & 4u) != 0u) {
            rome2_l75_luaC_barrierback(ctx->arena, l_va, t_va);
        }
    }
    return mp_va;
}

/* 0x10f4ad20 */
uint32_t rome2_l77_luaH_set(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, const rome2_lua_tvalue_32 *key) {
    rome2_lua_table_32 *t = (ctx != NULL)
        ? (rome2_lua_table_32 *)rome2_l75_mut_ptr(ctx->arena, t_va, sizeof(*t))
        : NULL;
    uint32_t p = rome2_l75_luaH_get(ctx != NULL ? ctx->arena : NULL, t_va, key);
    if (t != NULL) {
        t->flags = 0u;
    }
    if (p != ROME2_LUA_VA_NILOBJECT) {
        return p;
    }
    if (key == NULL || key->tt == ROME2_LUA_TNIL) {
        rome2_l77_luaG_runerror(ctx, l_va, "table index is nil");
        return ROME2_LUA_VA_NILOBJECT;
    }
    return rome2_l77_newkey(ctx, l_va, t_va, key);
}

/* 0x10f4ade0 */
uint32_t rome2_l77_luaH_setnum(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, int32_t key) {
    uint32_t p = rome2_l75_luaH_getnum(ctx != NULL ? ctx->arena : NULL, t_va, key);
    if (p != ROME2_LUA_VA_NILOBJECT) {
        return p;
    }
    {
        rome2_lua_tvalue_32 k;
        k.value_u32 = l77_f2u((float)key);
        k.tt = ROME2_LUA_TNUMBER;
        return rome2_l77_newkey(ctx, l_va, t_va, &k);
    }
}

/* 0x10f4ae30 */
uint32_t rome2_l77_luaH_setstr(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t t_va, uint32_t ts_va) {
    uint32_t p = rome2_l75_luaH_getstr(ctx != NULL ? ctx->arena : NULL, t_va, ts_va);
    if (p != ROME2_LUA_VA_NILOBJECT) {
        return p;
    }
    {
        rome2_lua_tvalue_32 k;
        k.value_u32 = ts_va;
        k.tt = ROME2_LUA_TSTRING;
        return rome2_l77_newkey(ctx, l_va, t_va, &k);
    }
}

/* 0x10f48c60 */
void rome2_l77_luaF_freeupval(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t uv_va) {
    const rome2_lua_upval_32 *uv = (ctx != NULL)
        ? (const rome2_lua_upval_32 *)rome2_l75_const_ptr(ctx->arena, uv_va, sizeof(*uv))
        : NULL;
    if (uv == NULL) {
        return;
    }
    if (uv->v_va != uv_va + 0x0cu) {
        uint32_t prev_va = uv->u_value.value_u32;
        uint32_t next_va = (uint32_t)uv->u_value.tt;
        if (next_va != 0u) {
            uint32_t *p = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, next_va + 0x0cu, 4u);
            if (p != NULL) {
                *p = prev_va;
            }
        }
        if (prev_va != 0u) {
            uint32_t *n = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, prev_va + 0x10u, 4u);
            if (n != NULL) {
                *n = next_va;
            }
        }
    }
    rome2_l77_luaM_realloc(ctx, l_va, uv_va, sizeof(*uv), 0u);
}

/* 0x10f48a80 */
void rome2_l77_luaF_close(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t level_va) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    const rome2_lua_global_state_32 *g = (L != NULL)
        ? (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    if (L == NULL || g == NULL) {
        return;
    }
    while (L->openupval_va != 0u) {
        uint32_t uv_va = L->openupval_va;
        rome2_lua_upval_32 *uv = (rome2_lua_upval_32 *)rome2_l75_mut_ptr(
            ctx->arena, uv_va, sizeof(*uv));
        if (uv == NULL || uv->v_va < level_va) {
            break;
        }
        L->openupval_va = uv->next_va;
        if (((uint8_t)(g->currentwhite ^ 3u) & uv->marked & 3u) != 0u) {
            rome2_l77_luaF_freeupval(ctx, l_va, uv_va);
        } else {
            const rome2_lua_tvalue_32 *live = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, uv->v_va, sizeof(*live));
            uint32_t prev_va = uv->u_value.value_u32;
            uint32_t next_va = (uint32_t)uv->u_value.tt;
            if (next_va != 0u) {
                uint32_t *p = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, next_va + 0x0cu, 4u);
                if (p != NULL) {
                    *p = prev_va;
                }
            }
            if (prev_va != 0u) {
                uint32_t *n = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, prev_va + 0x10u, 4u);
                if (n != NULL) {
                    *n = next_va;
                }
            }
            if (live != NULL) {
                uv->u_value = *live;
            }
            uv->v_va = uv_va + 0x0cu;
            rome2_l75_luaC_linkupval(ctx->arena, l_va, uv_va);
        }
    }
}

/* 0x10f48b10 */
uint32_t rome2_l77_luaF_findupval(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t level_va) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    uint32_t prev_link_va;
    uint32_t cur_va;
    uint32_t uv_va;
    rome2_lua_upval_32 *uv;
    if (L == NULL || g == NULL) {
        return 0u;
    }
    prev_link_va = l_va + 0x54u;
    cur_va = L->openupval_va;
    while (cur_va != 0u) {
        rome2_lua_upval_32 *p = (rome2_lua_upval_32 *)rome2_l75_mut_ptr(ctx->arena, cur_va, sizeof(*p));
        if (p == NULL || p->v_va < level_va) {
            break;
        }
        if (p->v_va == level_va) {
            if (((uint8_t)(g->currentwhite ^ 3u) & p->marked & 3u) != 0u) {
                p->marked ^= 3u;
            }
            return cur_va;
        }
        prev_link_va = cur_va;
        cur_va = p->next_va;
    }
    uv_va = rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, sizeof(*uv));
    uv = (rome2_lua_upval_32 *)rome2_l75_mut_ptr(ctx->arena, uv_va, sizeof(*uv));
    if (uv == NULL) {
        return 0u;
    }
    uv->tt = ROME2_LUA_TUPVAL;
    uv->marked = g->currentwhite & 3u;
    uv->v_va = level_va;
    {
        uint32_t *pp = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, prev_link_va, 4u);
        if (pp != NULL) {
            uv->next_va = *pp;
            *pp = uv_va;
        }
    }
    {
        uint32_t head_va = L->l_g_va + 0x68u;
        uint32_t head_next_va;
        memcpy(&head_next_va, g->uvhead_pad + 0x10u, 4u);
        if (head_next_va == 0u) {
            head_next_va = head_va;
        }
        uv->u_value.value_u32 = head_va;
        uv->u_value.tt = (int32_t)head_next_va;
        {
            uint32_t *hn_prev = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, head_next_va + 0x0cu, 4u);
            if (hn_prev != NULL) {
                *hn_prev = uv_va;
            }
        }
        memcpy(g->uvhead_pad + 0x10u, &uv_va, 4u);
    }
    return uv_va;
}

/* 0x10f48ba0 */
void rome2_l77_luaF_freeclosure(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t cl_va) {
    const rome2_lua_closure_hdr_32 *cl = (ctx != NULL)
        ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(ctx->arena, cl_va, sizeof(*cl))
        : NULL;
    uint32_t sz;
    if (cl == NULL) {
        return;
    }
    sz = (uint32_t)(cl->isC ? 8u : 4u) * (uint32_t)cl->nupvalues + (uint32_t)sizeof(*cl);
    rome2_l77_luaM_realloc(ctx, l_va, cl_va, sz, 0u);
}

/* 0x10f48bd0 */
void rome2_l77_luaF_freeproto(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t pt_va) {
    const rome2_lua_proto_32 *pt = (ctx != NULL)
        ? (const rome2_lua_proto_32 *)rome2_l75_const_ptr(ctx->arena, pt_va, sizeof(*pt))
        : NULL;
    if (pt == NULL) {
        return;
    }
    rome2_l77_luaM_realloc(ctx, l_va, pt->code_va, (uint32_t)pt->sizecode * 4u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, pt->p_va, (uint32_t)pt->sizep * 4u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, pt->k_va, (uint32_t)pt->sizek * 8u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, pt->lineinfo_va, (uint32_t)pt->sizelineinfo * 4u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, pt->locvars_va, (uint32_t)pt->sizelocvars * 12u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, pt->upvalues_va, (uint32_t)pt->sizeupvalues * 4u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, pt_va, sizeof(*pt), 0u);
}

/* 0x10f48d20 */
uint32_t rome2_l77_luaF_newLclosure(rome2_l77_ctx *ctx, uint32_t l_va, int32_t nelems, uint32_t env_va) {
    uint32_t sz = (uint32_t)sizeof(rome2_lua_closure_hdr_32) + (uint32_t)nelems * 4u;
    uint32_t cl_va = rome2_l77_luaM_realloc(ctx, l_va, 0u, 0u, sz);
    rome2_lua_closure_hdr_32 *cl = (rome2_lua_closure_hdr_32 *)rome2_l75_mut_ptr(ctx->arena, cl_va, sz);
    if (cl == NULL) {
        return 0u;
    }
    rome2_l75_luaC_link(ctx->arena, l_va, cl_va, ROME2_LUA_TFUNCTION);
    cl->isC = 0u;
    cl->env_va = env_va;
    cl->nupvalues = (uint8_t)nelems;
    return cl_va;
}

/* 0x10f469d0 */
void rome2_l77_luaE_freethread(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t l1_va) {
    const rome2_lua_state_32 *L1 = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l1_va, sizeof(*L1))
        : NULL;
    if (L1 == NULL) {
        return;
    }
    rome2_l77_luaF_close(ctx, l1_va, L1->stack_va);
    rome2_l77_luaM_realloc(ctx, l_va, L1->base_ci_va, (uint32_t)L1->size_ci * 0x18u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, L1->stack_va, (uint32_t)L1->stacksize * 8u, 0u);
    rome2_l77_luaM_realloc(ctx, l_va, l1_va, 100u, 0u);
}

/* 0x10f4a0a0 */
uint32_t rome2_l77_sweeplist(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t p_head_va, uint32_t count) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    uint32_t p_va = p_head_va;
    if (g == NULL) {
        return p_va;
    }
    while (count-- > 0u) {
        uint32_t *pp = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, p_va, 4u);
        uint32_t curr_va;
        uint8_t *curr;
        if (pp == NULL || *pp == 0u) {
            break;
        }
        curr_va = *pp;
        curr = (uint8_t *)rome2_l75_mut_ptr(ctx->arena, curr_va, 6u);
        if (curr == NULL) {
            break;
        }
        if (curr[4] == ROME2_LUA_TTHREAD) {
            rome2_l77_sweeplist(ctx, l_va, curr_va + 0x54u, 0xfffffffdu);
        }
        if (((uint8_t)(g->currentwhite ^ 3u) & (curr[5] ^ 3u) & 3u) != 0u) {
            curr[5] = (uint8_t)((g->currentwhite & 3u) | (curr[5] & 0xf8u));
            p_va = curr_va;
        } else {
            uint32_t nxt = 0u;
            memcpy(&nxt, curr, 4u);
            *pp = nxt;
            if (curr_va == g->rootgc_va) {
                g->rootgc_va = nxt;
            }
            switch (curr[4]) {
                case ROME2_LUA_TSTRING: {
                    const rome2_lua_tstring_hdr_32 *ts = (const rome2_lua_tstring_hdr_32 *)curr;
                    --g->strt_nuse;
                    rome2_l77_luaM_realloc(ctx, l_va, curr_va, ts->len + 0x11u, 0u);
                    break;
                }
                case ROME2_LUA_TTABLE:
                    rome2_l77_luaH_free(ctx, l_va, curr_va);
                    break;
                case ROME2_LUA_TFUNCTION:
                    rome2_l77_luaF_freeclosure(ctx, l_va, curr_va);
                    break;
                case ROME2_LUA_TUSERDATA: {
                    const rome2_lua_userdata_hdr_32 *u = (const rome2_lua_userdata_hdr_32 *)curr;
                    rome2_l77_luaM_realloc(ctx, l_va, curr_va, u->len + 0x18u, 0u);
                    break;
                }
                case ROME2_LUA_TTHREAD:
                    rome2_l77_luaE_freethread(ctx, l_va, curr_va);
                    break;
                case ROME2_LUA_TPROTO:
                    rome2_l77_luaF_freeproto(ctx, l_va, curr_va);
                    break;
                case ROME2_LUA_TUPVAL:
                    rome2_l77_luaF_freeupval(ctx, l_va, curr_va);
                    break;
                default:
                    break;
            }
        }
    }
    return p_va;
}

/* 0x10f49be0 */
int32_t rome2_l77_propagatemark(rome2_l77_ctx *ctx, uint32_t g_va) {
    rome2_lua_global_state_32 *g = (ctx != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, g_va, sizeof(*g))
        : NULL;
    uint32_t o_va;
    uint8_t *o;
    if (g == NULL || g->gray_va == 0u) {
        return 0;
    }
    o_va = g->gray_va;
    o = (uint8_t *)rome2_l75_mut_ptr(ctx->arena, o_va, 6u);
    if (o == NULL) {
        return 0;
    }
    o[5] |= 4u;
    switch (o[4]) {
        case ROME2_LUA_TTABLE: {
            rome2_lua_table_32 *h = (rome2_lua_table_32 *)rome2_l75_mut_ptr(ctx->arena, o_va, sizeof(*h));
            if (h == NULL) {
                return 0;
            }
            g->gray_va = h->gclist_va;
            if (rome2_l75_traversetable(ctx->arena, g_va, o_va) != 0) {
                h->marked &= 0xfbu;
            }
            return h->sizearray * 8 + 0x20 + (1 << (h->lsizenode & 0x1f)) * 0x14;
        }
        case ROME2_LUA_TFUNCTION: {
            const rome2_lua_closure_hdr_32 *cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(
                ctx->arena, o_va, sizeof(*cl));
            if (cl == NULL) {
                return 0;
            }
            g->gray_va = cl->gclist_va;
            rome2_l75_traverseclosure(ctx->arena, g_va, o_va);
            return (int32_t)(((cl->isC != 0u) ? 8u : 4u) * (uint32_t)cl->nupvalues + 0x14u);
        }
        case ROME2_LUA_TTHREAD: {
            rome2_lua_state_32 *th = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, o_va, sizeof(*th));
            if (th == NULL) {
                return 0;
            }
            g->gray_va = th->gclist_va;
            th->gclist_va = g->grayagain_va;
            g->grayagain_va = o_va;
            th->marked &= 0xfbu;
            if (th->l_gt.tt > 3) {
                const uint8_t *gt = (const uint8_t *)rome2_l75_const_ptr(ctx->arena, th->l_gt.value_u32, 6u);
                if (gt != NULL && (gt[5] & 3u) != 0u) {
                    rome2_l75_reallymarkobject(ctx->arena, g_va, th->l_gt.value_u32);
                }
            }
            return (th->size_ci * 3 + th->stacksize) * 8 + 100;
        }
        case ROME2_LUA_TPROTO: {
            const rome2_lua_proto_32 *f = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(
                ctx->arena, o_va, sizeof(*f));
            int32_t i;
            if (f == NULL) {
                return 0;
            }
            g->gray_va = f->gclist_va;
            for (i = 0; i < f->sizek; ++i) {
                const rome2_lua_tvalue_32 *kv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, f->k_va + (uint32_t)i * 8u, sizeof(*kv));
                if (kv != NULL && kv->tt > 3) {
                    const uint8_t *kh = (const uint8_t *)rome2_l75_const_ptr(ctx->arena, kv->value_u32, 6u);
                    if (kh != NULL && (kh[5] & 3u) != 0u) {
                        rome2_l75_reallymarkobject(ctx->arena, g_va, kv->value_u32);
                    }
                }
            }
            for (i = 0; i < f->sizep; ++i) {
                const uint32_t *pp = (const uint32_t *)rome2_l75_const_ptr(
                    ctx->arena, f->p_va + (uint32_t)i * 4u, 4u);
                if (pp != NULL && *pp != 0u) {
                    const uint8_t *ph = (const uint8_t *)rome2_l75_const_ptr(ctx->arena, *pp, 6u);
                    if (ph != NULL && (ph[5] & 3u) != 0u) {
                        rome2_l75_reallymarkobject(ctx->arena, g_va, *pp);
                    }
                }
            }
            return (f->sizelocvars * 3 + f->sizek * 2 + f->sizecode + f->sizelineinfo + f->sizep + f->sizeupvalues) * 4 + 0x4c;
        }
        default:
            return 0;
    }
}

/* 0x10f499a0 */
void rome2_l77_propagateall(rome2_l77_ctx *ctx, uint32_t g_va) {
    const rome2_lua_global_state_32 *g = (ctx != NULL)
        ? (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(ctx->arena, g_va, sizeof(*g))
        : NULL;
    uint32_t guard = 0u;
    while (g != NULL && g->gray_va != 0u && guard++ < 4096u) {
        rome2_l77_propagatemark(ctx, g_va);
    }
}

/* 0x10f48e60 */
void rome2_l77_GCTM(rome2_l77_ctx *ctx, uint32_t l_va) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    uint32_t tmudata_va;
    uint32_t u_va;
    uint32_t *tmudata_next;
    uint32_t *u_next;
    rome2_lua_userdata_hdr_32 *u;
    if (L == NULL || g == NULL || g->tmudata_va == 0u) {
        return;
    }
    tmudata_va = g->tmudata_va;
    tmudata_next = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, tmudata_va, 4u);
    if (tmudata_next == NULL) {
        return;
    }
    u_va = *tmudata_next;
    u = (rome2_lua_userdata_hdr_32 *)rome2_l75_mut_ptr(ctx->arena, u_va, sizeof(*u));
    u_next = (uint32_t *)u;
    if (u == NULL) {
        return;
    }
    if (u_va == tmudata_va) {
        g->tmudata_va = 0u;
    } else {
        *tmudata_next = *u_next;
    }
    {
        uint32_t *mt_next = (uint32_t *)rome2_l75_mut_ptr(ctx->arena, g->mainthread_va, 4u);
        if (mt_next != NULL) {
            *u_next = *mt_next;
            *mt_next = u_va;
        }
    }
    u->marked = (uint8_t)((g->currentwhite & 3u) | (u->marked & 0xf8u));
    if (u->metatable_va != 0u) {
        const rome2_lua_table_32 *mtt = (const rome2_lua_table_32 *)rome2_l75_const_ptr(
            ctx->arena, u->metatable_va, sizeof(*mtt));
        if (mtt != NULL && (mtt->flags & 4u) == 0u) {
            uint32_t tm_va = rome2_l75_luaT_gettm(ctx->arena, u->metatable_va, 2u, g->tmname_va[2]);
            const rome2_lua_tvalue_32 *tm = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, tm_va, sizeof(*tm));
            if (tm != NULL && tm->tt == ROME2_LUA_TFUNCTION) {
                rome2_lua_state_32 *Lm = (rome2_lua_state_32 *)rome2_l75_mut_ptr(
                    ctx->arena, l_va, sizeof(*Lm));
                uint32_t old_thresh = g->gc_threshold;
                uint8_t oldah = Lm->allowhook;
                uint32_t call_base = Lm->top_va;
                rome2_lua_tvalue_32 *s0 = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, call_base, 16u);
                if (s0 != NULL) {
                    s0[0] = *tm;
                    s0[1].value_u32 = u_va;
                    s0[1].tt = ROME2_LUA_TUSERDATA;
                    Lm->allowhook = 0u;
                    g->gc_threshold = g->totalbytes * 2u;
                    Lm->top_va = call_base + 16u;
                    rome2_l77_luaD_call(ctx, l_va, call_base, 0);
                    Lm->allowhook = oldah;
                    g->gc_threshold = old_thresh;
                }
            }
        }
    }
}

/* 0x10f48f20 */
void rome2_l77_atomic(rome2_l77_ctx *ctx, uint32_t l_va) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    uint32_t g_va;
    if (L == NULL || g == NULL) {
        return;
    }
    g_va = L->l_g_va;
    rome2_l77_propagateall(ctx, g_va);
    g->gray_va = g->weak_va;
    g->weak_va = 0u;
    {
        const uint8_t *lh = (const uint8_t *)rome2_l75_const_ptr(ctx->arena, l_va, 6u);
        if (lh != NULL && (lh[5] & 3u) != 0u) {
            rome2_l75_reallymarkobject(ctx->arena, g_va, l_va);
        }
    }
    rome2_l75_marktmu_mt(ctx->arena, g_va);
    rome2_l77_propagateall(ctx, g_va);
    g->gray_va = g->grayagain_va;
    g->grayagain_va = 0u;
    rome2_l77_propagateall(ctx, g_va);
    if (g->weak_va != 0u) {
        rome2_l75_cleartable(ctx->arena, g->weak_va);
    }
    g->currentwhite ^= 3u;
    g->sweepgc_va = g_va + 0x1cu;
    g->sweepstrgc = 0;
    g->gcstate = 2u;
    g->estimate = g->totalbytes;
}

/* 0x10f49630 */
int32_t rome2_l77_singlestep(rome2_l77_ctx *ctx, uint32_t l_va) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_global_state_32 *g = (L != NULL)
        ? (rome2_lua_global_state_32 *)rome2_l75_mut_ptr(ctx->arena, L->l_g_va, sizeof(*g))
        : NULL;
    if (L == NULL || g == NULL) {
        return 0;
    }
    switch (g->gcstate) {
        case 0u:
            rome2_l75_markroot(ctx->arena, l_va);
            return 0;
        case 1u:
            if (g->gray_va != 0u) {
                return rome2_l77_propagatemark(ctx, L->l_g_va);
            }
            rome2_l77_atomic(ctx, l_va);
            return 0;
        case 2u: {
            if (g->sweepstrgc < g->strt_size) {
                rome2_l77_sweeplist(ctx, l_va, g->strt_hash_va + (uint32_t)g->sweepstrgc * 4u, 0xfffffffdu);
                ++g->sweepstrgc;
                if (g->sweepstrgc >= g->strt_size) {
                    g->gcstate = 3u;
                }
            } else {
                g->gcstate = 3u;
            }
            return 10;
        }
        case 3u: {
            uint32_t next_p = rome2_l77_sweeplist(ctx, l_va, g->sweepgc_va, 40u);
            const uint32_t *pp = (const uint32_t *)rome2_l75_const_ptr(ctx->arena, next_p, 4u);
            g->sweepgc_va = next_p;
            if (pp == NULL || *pp == 0u) {
                g->gcstate = 4u;
            }
            return 400;
        }
        case 4u:
            if (g->tmudata_va != 0u) {
                rome2_l77_GCTM(ctx, l_va);
                return 100;
            }
            g->gcstate = 0u;
            return 0;
        default:
            return 0;
    }
}

/* 0x10f48680 */
void rome2_l77_luaD_reallocCI(rome2_l77_ctx *ctx, uint32_t l_va, int32_t newsize) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t oldci;
    uint32_t newci;
    if (L == NULL) {
        return;
    }
    oldci = L->base_ci_va;
    newci = ((uint32_t)(newsize + 1) < 0xaaaaaab)
        ? rome2_l77_luaM_realloc(ctx, l_va, oldci, (uint32_t)L->size_ci * 0x18u, (uint32_t)newsize * 0x18u)
        : rome2_l77_luaM_toobig(ctx, l_va);
    L->size_ci = newsize;
    L->base_ci_va = newci;
    L->ci_va = newci + (L->ci_va - oldci);
    L->end_ci_va = newci + (uint32_t)(newsize - 1) * 0x18u;
}

/* 0x10f47df0 */
uint32_t rome2_l77_growCI(rome2_l77_ctx *ctx, uint32_t l_va) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    if (L == NULL) {
        return 0u;
    }
    if (L->size_ci > 20000) {
        rome2_l77_luaD_throw(ctx, l_va, ROME2_LUA_ERRERR);
        return 0u;
    }
    rome2_l77_luaD_reallocCI(ctx, l_va, L->size_ci * 2);
    if (L->size_ci > 20000) {
        rome2_l77_luaG_runerror(ctx, l_va, "stack overflow");
    }
    L->ci_va += 0x18u;
    return L->ci_va;
}

/* 0x10f48700 */
void rome2_l77_luaD_reallocstack(rome2_l77_ctx *ctx, uint32_t l_va, int32_t newsize) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t oldstk;
    uint32_t newstk;
    uint32_t uv_va;
    uint32_t ci_va;
    if (L == NULL) {
        return;
    }
    oldstk = L->stack_va;
    newstk = ((uint32_t)(newsize + 7) < 0x20000000u)
        ? rome2_l77_luaM_realloc(ctx, l_va, oldstk, (uint32_t)L->stacksize * 8u, (uint32_t)(newsize + 6) * 8u)
        : rome2_l77_luaM_toobig(ctx, l_va);
    L->stack_va = newstk;
    L->stacksize = newsize + 6;
    L->stack_last_va = newstk + (uint32_t)newsize * 8u;
    L->top_va = newstk + (L->top_va - oldstk);
    for (uv_va = L->openupval_va; uv_va != 0u;) {
        rome2_lua_upval_32 *uv = (rome2_lua_upval_32 *)rome2_l75_mut_ptr(
            ctx->arena, uv_va, sizeof(*uv));
        if (uv == NULL) {
            break;
        }
        uv->v_va = newstk + (uv->v_va - oldstk);
        uv_va = uv->next_va;
    }
    for (ci_va = L->base_ci_va; ci_va <= L->ci_va; ci_va += 0x18u) {
        rome2_lua_callinfo_32 *ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(
            ctx->arena, ci_va, sizeof(*ci));
        if (ci == NULL) {
            break;
        }
        ci->top_va = newstk + (ci->top_va - oldstk);
        ci->base_va = newstk + (ci->base_va - oldstk);
        ci->func_va = newstk + (ci->func_va - oldstk);
    }
    L->base_va = newstk + (L->base_va - oldstk);
}

/* 0x10f47fc0 */
void rome2_l77_luaD_growstack(rome2_l77_ctx *ctx, uint32_t l_va, int32_t n) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    if (L == NULL) {
        return;
    }
    if (n <= L->stacksize) {
        rome2_l77_luaD_reallocstack(ctx, l_va, L->stacksize * 2);
    } else {
        rome2_l77_luaD_reallocstack(ctx, l_va, L->stacksize + n);
    }
}

/* 0x10f487e0 */
void rome2_l77_luaD_seterrorobj(rome2_l77_ctx *ctx, uint32_t l_va, int32_t errcode, uint32_t oldtop_va) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_tvalue_32 *oldtop = (L != NULL)
        ? (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, oldtop_va, sizeof(*oldtop))
        : NULL;
    if (L == NULL || oldtop == NULL) {
        return;
    }
    switch (errcode) {
        case ROME2_LUA_ERRMEM:
            oldtop->value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, "not enough memory", 17u);
            oldtop->tt = ROME2_LUA_TSTRING;
            break;
        case ROME2_LUA_ERRERR:
            oldtop->value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, "error in error handling", 23u);
            oldtop->tt = ROME2_LUA_TSTRING;
            break;
        case ROME2_LUA_ERRRUN:
        case ROME2_LUA_ERRSYNTAX: {
            const rome2_lua_tvalue_32 *top = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, L->top_va - 8u, sizeof(*top));
            if (top != NULL) {
                *oldtop = *top;
            }
            break;
        }
        default:
            break;
    }
    L->top_va = oldtop_va + 8u;
}

/* 0x10f48980 */
void rome2_l77_resetstack(rome2_l77_ctx *ctx, uint32_t l_va, int32_t status) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    const rome2_lua_callinfo_32 *base_ci;
    if (L == NULL) {
        return;
    }
    L->ci_va = L->base_ci_va;
    base_ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
        ctx->arena, L->base_ci_va, sizeof(*base_ci));
    if (base_ci != NULL) {
        L->base_va = base_ci->base_va;
        rome2_l77_luaF_close(ctx, l_va, base_ci->base_va);
        rome2_l77_luaD_seterrorobj(ctx, l_va, status, base_ci->base_va);
    }
    L->nCcalls = 0u;
    L->allowhook = 1u;
    if (L->size_ci > 20000) {
        if ((int32_t)((L->ci_va - L->base_ci_va) / 0x18u) + 1 < 20000) {
            rome2_l77_luaD_reallocCI(ctx, l_va, 20000);
        }
    }
    L->errfunc = 0;
    L->error_jmp_va = 0u;
}

/* 0x10f48850 */
void rome2_l77_luaD_throw(rome2_l77_ctx *ctx, uint32_t l_va, int32_t errcode) {
    rome2_lua_state_32 *L;
    const rome2_lua_global_state_32 *g;
    if (ctx == NULL) {
        return;
    }
    ctx->last_thrown_err = errcode;
    L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L));
    if (L != NULL && L->error_jmp_va != 0u) {
        if (ctx->throw_fn != NULL) {
            ctx->throw_fn(ctx, l_va, errcode);
        }
        return;
    }
    if (L != NULL) {
        L->status = (uint8_t)errcode;
        g = (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(
            ctx->arena, L->l_g_va, sizeof(*g));
        if (g != NULL && g->panic_va != 0u) {
            rome2_l77_resetstack(ctx, l_va, errcode);
            ++ctx->panic_calls;
            ctx->last_panic_l_va = l_va;
            if (ctx->panic_fn != NULL) {
                ctx->panic_fn(ctx, l_va);
            }
        }
    }
    ++ctx->fatal_exit_calls;
}

/* 0x10f47ed0 */
void rome2_l77_luaD_callhook(rome2_l77_ctx *ctx, uint32_t l_va, int32_t event, int32_t line) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    rome2_lua_callinfo_32 *ci;
    uint32_t top_off;
    uint32_t citop_off;
    rome2_lua_debug_32 ar;
    if (L == NULL || L->hook_va == 0u || L->allowhook == 0u) {
        return;
    }
    ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(ctx->arena, L->ci_va, sizeof(*ci));
    if (ci == NULL) {
        return;
    }
    top_off = L->top_va - L->stack_va;
    citop_off = ci->top_va - L->stack_va;
    memset(&ar, 0, sizeof(ar));
    ar.event = event;
    ar.currentline = line;
    ar.i_ci = (event == 4) ? 0 : (int32_t)((L->ci_va - L->base_ci_va) / 0x18u);
    if ((int32_t)(L->stack_last_va - L->top_va) < 0xa1) {
        rome2_l77_luaD_growstack(ctx, l_va, 20);
        ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(ctx->arena, L->ci_va, sizeof(*ci));
    }
    if (ci != NULL) {
        ci->top_va = L->top_va + 0xa0u;
    }
    L->allowhook = 0u;
    if (ctx->hook_fn != NULL) {
        ctx->hook_fn(ctx, l_va, L->hook_va, &ar);
    }
    L->allowhook = 1u;
    ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(ctx->arena, L->ci_va, sizeof(*ci));
    if (ci != NULL) {
        ci->top_va = L->stack_va + citop_off;
    }
    L->top_va = L->stack_va + top_off;
}

/* 0x10f480c0 */
int32_t rome2_l77_luaD_poscall(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t first_res_va) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t res_off;
    const rome2_lua_callinfo_32 *ci;
    int32_t wanted;
    uint32_t res_va;
    int32_t i;
    if (L == NULL) {
        return 0;
    }
    res_off = first_res_va - L->stack_va;
    if ((L->hookmask & 2u) != 0u) {
        rome2_l77_luaD_callhook(ctx, l_va, 1, -1);
    }
    first_res_va = L->stack_va + res_off;
    ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(ctx->arena, L->ci_va, sizeof(*ci));
    if (ci == NULL) {
        return 0;
    }
    res_va = ci->func_va;
    wanted = ci->nresults;
    L->ci_va -= 0x18u;
    {
        const rome2_lua_callinfo_32 *prev_ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
            ctx->arena, L->ci_va, sizeof(*prev_ci));
        if (prev_ci != NULL) {
            L->base_va = prev_ci->base_va;
            L->savedpc_va = prev_ci->savedpc_va;
        }
    }
    i = wanted;
    while (i != 0 && first_res_va < L->top_va) {
        rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, res_va, sizeof(*dst));
        const rome2_lua_tvalue_32 *src = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, first_res_va, sizeof(*src));
        if (dst != NULL && src != NULL) {
            *dst = *src;
        }
        res_va += 8u;
        first_res_va += 8u;
        --i;
    }
    while (i-- > 0) {
        rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, res_va, sizeof(*dst));
        if (dst != NULL) {
            dst->tt = ROME2_LUA_TNIL;
        }
        res_va += 8u;
    }
    L->top_va = res_va;
    return wanted + 1;
}

/* 0x10f48190 */
int32_t rome2_l77_luaD_precall(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t func_va, int32_t nresults) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    const rome2_lua_tvalue_32 *fn;
    const rome2_lua_closure_hdr_32 *cl;
    uint32_t ci_va;
    rome2_lua_callinfo_32 *ci;
    if (L == NULL) {
        return 0;
    }
    fn = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, func_va, sizeof(*fn));
    if (fn == NULL) {
        return 0;
    }
    if (fn->tt != ROME2_LUA_TFUNCTION) {
        uint32_t tm_va = rome2_l75_luaT_gettmbyobj(ctx->arena, l_va, fn, 16);
        const rome2_lua_tvalue_32 *tm = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, tm_va, sizeof(*tm));
        uint32_t fn_off = func_va - L->stack_va;
        if (tm == NULL || tm->tt != ROME2_LUA_TFUNCTION) {
            rome2_l77_luaG_typeerror(ctx, l_va, func_va, "call");
            return 0;
        }
        {
            uint32_t p;
            for (p = L->top_va; p > func_va; p -= 8u) {
                rome2_lua_tvalue_32 *d = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, p, sizeof(*d));
                const rome2_lua_tvalue_32 *s = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, p - 8u, sizeof(*s));
                if (d != NULL && s != NULL) {
                    *d = *s;
                }
            }
            if ((int32_t)(L->stack_last_va - L->top_va) < 9) {
                rome2_l77_luaD_growstack(ctx, l_va, 1);
            }
            L->top_va += 8u;
            func_va = L->stack_va + fn_off;
            {
                rome2_lua_tvalue_32 *d = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, func_va, sizeof(*d));
                if (d != NULL) {
                    *d = *tm;
                }
            }
        }
        fn = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, func_va, sizeof(*fn));
    }
    cl = (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(ctx->arena, fn->value_u32, sizeof(*cl));
    if (cl == NULL) {
        return 0;
    }
    {
        rome2_lua_callinfo_32 *cur_ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(
            ctx->arena, L->ci_va, sizeof(*cur_ci));
        if (cur_ci != NULL) {
            cur_ci->savedpc_va = L->savedpc_va;
        }
    }
    if (cl->isC != 0u) {
        uint32_t fn_off = func_va - L->stack_va;
        if ((int32_t)(L->stack_last_va - L->top_va) < 0xa1) {
            rome2_l77_luaD_growstack(ctx, l_va, 20);
            func_va = L->stack_va + fn_off;
        }
        ci_va = (L->ci_va == L->end_ci_va) ? rome2_l77_growCI(ctx, l_va) : (L->ci_va += 0x18u);
        ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(ctx->arena, ci_va, sizeof(*ci));
        if (ci != NULL) {
            ci->func_va = func_va;
            ci->base_va = func_va + 8u;
            ci->top_va = L->top_va + 0xa0u;
            ci->nresults = nresults;
            L->base_va = ci->base_va;
        }
        if ((L->hookmask & 1u) != 0u) {
            rome2_l77_luaD_callhook(ctx, l_va, 0, -1);
        }
        {
            int32_t n = (ctx->c_call != NULL) ? ctx->c_call(ctx, l_va, cl->f_or_p_va) : 0;
            if (n >= 0) {
                rome2_l77_luaD_poscall(ctx, l_va, L->top_va - (uint32_t)n * 8u);
                return 1;
            }
            return 2;
        }
    }
    {
        const rome2_lua_proto_32 *p = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(
            ctx->arena, cl->f_or_p_va, sizeof(*p));
        uint32_t fn_off = func_va - L->stack_va;
        uint32_t base_va;
        if (p == NULL) {
            return 0;
        }
        if ((int32_t)(L->stack_last_va - L->top_va) <= (int32_t)p->maxstacksize) {
            rome2_l77_luaD_growstack(ctx, l_va, (int32_t)p->maxstacksize);
            func_va = L->stack_va + fn_off;
        }
        if (p->is_vararg == 0u) {
            base_va = func_va + 8u;
            if (L->top_va > base_va + (uint32_t)p->numparams * 8u) {
                L->top_va = base_va + (uint32_t)p->numparams * 8u;
            }
        } else {
            int32_t actual = (int32_t)((L->top_va - func_va) >> 3) - 1;
            int32_t fixed = (int32_t)p->numparams;
            int32_t i;
            while (actual < fixed) {
                rome2_lua_tvalue_32 *s = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, L->top_va, sizeof(*s));
                if (s != NULL) {
                    s->tt = ROME2_LUA_TNIL;
                }
                L->top_va += 8u;
                ++actual;
            }
            base_va = L->top_va;
            for (i = 0; i < fixed; ++i) {
                rome2_lua_tvalue_32 *src = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, L->stack_va + fn_off + 8u + (uint32_t)i * 8u, sizeof(*src));
                rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, L->top_va, sizeof(*dst));
                if (src != NULL && dst != NULL) {
                    *dst = *src;
                    src->tt = ROME2_LUA_TNIL;
                }
                L->top_va += 8u;
            }
        }
        ci_va = (L->ci_va == L->end_ci_va) ? rome2_l77_growCI(ctx, l_va) : (L->ci_va += 0x18u);
        ci = (rome2_lua_callinfo_32 *)rome2_l75_mut_ptr(ctx->arena, ci_va, sizeof(*ci));
        if (ci != NULL) {
            ci->func_va = L->stack_va + fn_off;
            ci->base_va = base_va;
            L->base_va = base_va;
            ci->top_va = base_va + (uint32_t)p->maxstacksize * 8u;
            L->savedpc_va = p->code_va;
            ci->tailcalls = 0;
            ci->nresults = nresults;
            while (L->top_va < ci->top_va) {
                rome2_lua_tvalue_32 *s = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, L->top_va, sizeof(*s));
                if (s != NULL) {
                    s->tt = ROME2_LUA_TNIL;
                }
                L->top_va += 8u;
            }
            L->top_va = ci->top_va;
        }
    }
    return 0;
}

/* 0x10f47e40 */
void rome2_l77_luaD_call(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t func_va, int32_t nresults) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    if (L == NULL) {
        return;
    }
    ++L->nCcalls;
    if (L->nCcalls >= 200u) {
        if (L->nCcalls == 200u) {
            rome2_l77_luaG_runerror(ctx, l_va, "C stack overflow");
        } else if (L->nCcalls > 0xe0u) {
            rome2_l77_luaD_throw(ctx, l_va, ROME2_LUA_ERRERR);
            return;
        }
    }
    if (rome2_l77_luaD_precall(ctx, l_va, func_va, nresults) == 0) {
        rome2_l77_luaV_execute(ctx, l_va, 1);
    }
    --L->nCcalls;
    l77_check_gc(ctx, l_va);
}

/* 0x10f462d0 */
uint32_t rome2_l77_luaO_pushvfstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, va_list ap) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    int32_t n = 1;
    const char *p = fmt;
    const char *e;
    if (L == NULL || fmt == NULL) {
        return 0u;
    }
    {
        uint32_t emp_va = rome2_l77_luaS_newlstr(ctx, l_va, "", 0u);
        rome2_lua_tvalue_32 tv = { emp_va, ROME2_LUA_TSTRING };
        rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
    }
    while ((e = strchr(p, '%')) != NULL) {
        if (e > p) {
            uint32_t seg = rome2_l77_luaS_newlstr(ctx, l_va, p, (size_t)(e - p));
            rome2_lua_tvalue_32 tv = { seg, ROME2_LUA_TSTRING };
            rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
            ++n;
        }
        switch (e[1]) {
            case 's': {
                const char *s = va_arg(ap, const char *);
                uint32_t sv;
                rome2_lua_tvalue_32 tv;
                if (s == NULL) {
                    s = "(null)";
                }
                sv = rome2_l77_luaS_newlstr(ctx, l_va, s, strlen(s));
                tv.value_u32 = sv;
                tv.tt = ROME2_LUA_TSTRING;
                rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
                break;
            }
            case 'c': {
                char c = (char)va_arg(ap, int);
                uint32_t sv = rome2_l77_luaS_newlstr(ctx, l_va, &c, 1u);
                rome2_lua_tvalue_32 tv = { sv, ROME2_LUA_TSTRING };
                rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
                break;
            }
            case 'd': {
                int32_t d = va_arg(ap, int32_t);
                rome2_lua_tvalue_32 tv = { l77_f2u((float)d), ROME2_LUA_TNUMBER };
                rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
                break;
            }
            case 'f': {
                double df = va_arg(ap, double);
                rome2_lua_tvalue_32 tv = { l77_f2u((float)df), ROME2_LUA_TNUMBER };
                rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
                break;
            }
            case 'p': {
                char pbuf[24];
                const void *ptr = va_arg(ap, const void *);
                uint32_t sv;
                rome2_lua_tvalue_32 tv;
                (void)snprintf(pbuf, sizeof(pbuf), "%p", ptr);
                sv = rome2_l77_luaS_newlstr(ctx, l_va, pbuf, strlen(pbuf));
                tv.value_u32 = sv;
                tv.tt = ROME2_LUA_TSTRING;
                rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
                break;
            }
            case '%': {
                uint32_t sv = rome2_l77_luaS_newlstr(ctx, l_va, "%", 1u);
                rome2_lua_tvalue_32 tv = { sv, ROME2_LUA_TSTRING };
                rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
                break;
            }
            default: {
                char buf[4];
                uint32_t sv;
                rome2_lua_tvalue_32 tv;
                buf[0] = '%';
                buf[1] = e[1];
                buf[2] = '\0';
                sv = rome2_l77_luaS_newlstr(ctx, l_va, buf, strlen(buf));
                tv.value_u32 = sv;
                tv.tt = ROME2_LUA_TSTRING;
                rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
                break;
            }
        }
        ++n;
        if (e[1] == '\0') {
            p = e + 1;
            break;
        }
        p = e + 2;
    }
    if (*p != '\0') {
        uint32_t sv = rome2_l77_luaS_newlstr(ctx, l_va, p, strlen(p));
        rome2_lua_tvalue_32 tv = { sv, ROME2_LUA_TSTRING };
        rome2_l75_luaA_pushobject(ctx->arena, l_va, &tv);
        ++n;
    }
    {
        int32_t last = (int32_t)((L->top_va - L->base_va) >> 3) - 1;
        if (n > 1) {
            rome2_l77_luaV_concat(ctx, l_va, n, last);
            L->top_va -= (uint32_t)(n - 1) * 8u;
        }
    }
    {
        const rome2_lua_tvalue_32 *res = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, L->top_va - 8u, sizeof(*res));
        return (res != NULL) ? (res->value_u32 + (uint32_t)sizeof(rome2_lua_tstring_hdr_32)) : 0u;
    }
}

/* 0x10f462b0 */
uint32_t rome2_l77_luaO_pushfstring(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, ...) {
    va_list ap;
    uint32_t res;
    va_start(ap, fmt);
    res = rome2_l77_luaO_pushvfstring(ctx, l_va, fmt, ap);
    va_end(ap);
    return res;
}

/* 0x10f47410 */
void rome2_l77_luaG_runerror(rome2_l77_ctx *ctx, uint32_t l_va, const char *fmt, ...) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    va_list ap;
    uint32_t msg_va;
    if (L == NULL || fmt == NULL) {
        return;
    }
    va_start(ap, fmt);
    msg_va = rome2_l77_luaO_pushvfstring(ctx, l_va, fmt, ap);
    va_end(ap);
    {
        const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
            ctx->arena, L->ci_va, sizeof(*ci));
        const rome2_lua_tvalue_32 *fn = (ci != NULL)
            ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, ci->func_va, sizeof(*fn))
            : NULL;
        const rome2_lua_closure_hdr_32 *cl = (fn != NULL && fn->tt == ROME2_LUA_TFUNCTION)
            ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(ctx->arena, fn->value_u32, sizeof(*cl))
            : NULL;
        if (cl != NULL && cl->isC == 0u) {
            const rome2_lua_proto_32 *pt = (const rome2_lua_proto_32 *)rome2_l75_const_ptr(
                ctx->arena, cl->f_or_p_va, sizeof(*pt));
            int32_t line = rome2_l75_currentline(ctx->arena, l_va, L->ci_va);
            const char *src = (pt != NULL)
                ? rome2_l75_cstr_at(ctx->arena, pt->source_va + (uint32_t)sizeof(rome2_lua_tstring_hdr_32))
                : NULL;
            const char *msg = rome2_l75_cstr_at(ctx->arena, msg_va);
            char buff[256];
            rome2_l75_luaO_chunkid(buff, src != NULL ? src : "", 0xffu);
            rome2_l77_luaO_pushfstring(ctx, l_va, "%s:%d: %s", buff, line, msg != NULL ? msg : "");
        }
    }
    if (L->errfunc != 0) {
        const rome2_lua_tvalue_32 *errf = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, L->stack_va + (uint32_t)L->errfunc, sizeof(*errf));
        rome2_lua_tvalue_32 *top = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
            ctx->arena, L->top_va - 8u, 16u);
        if (errf == NULL || errf->tt != ROME2_LUA_TFUNCTION) {
            rome2_l77_luaD_throw(ctx, l_va, ROME2_LUA_ERRERR);
            return;
        }
        if (top != NULL) {
            top[1] = top[0];
            top[0] = *errf;
            L->top_va += 8u;
            rome2_l77_luaD_call(ctx, l_va, L->top_va - 16u, 1);
        }
    }
    rome2_l77_luaD_throw(ctx, l_va, ROME2_LUA_ERRRUN);
}

/* 0x10f47520 */
void rome2_l77_luaG_typeerror(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t o_va, const char *op) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    const rome2_lua_tvalue_32 *o = (L != NULL)
        ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, o_va, sizeof(*o))
        : NULL;
    const char *t;
    const rome2_lua_callinfo_32 *ci;
    if (L == NULL || o == NULL) {
        return;
    }
    t = rome2_l76_lua_typename(o->tt);
    ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(ctx->arena, L->ci_va, sizeof(*ci));
    if (ci != NULL && o_va >= ci->base_va && o_va < ci->top_va) {
        uint32_t name_va = 0u;
        uint32_t nw = rome2_l75_getobjname(
            ctx->arena, l_va, L->ci_va, (o_va - L->base_va) >> 3, &name_va);
        if (nw != 0u) {
            rome2_l77_luaG_runerror(
                ctx, l_va, "attempt to %s %s '%s' (a %s value)",
                op, rome2_l75_cstr_at(ctx->arena, nw),
                rome2_l75_cstr_at(ctx->arena, name_va), t);
            return;
        }
    }
    rome2_l77_luaG_runerror(ctx, l_va, "attempt to %s a %s value", op, t);
}

/* 0x10f472c0 */
void rome2_l77_luaG_aritherror(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t p1_va, uint32_t p2_va) {
    rome2_lua_tvalue_32 tmp;
    const rome2_lua_tvalue_32 *p1 = (ctx != NULL)
        ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, p1_va, sizeof(*p1))
        : NULL;
    uint32_t bad = (p1 != NULL && rome2_l75_luaV_tonumber(ctx->arena, p1, &tmp) == NULL) ? p1_va : p2_va;
    rome2_l77_luaG_typeerror(ctx, l_va, bad, "perform arithmetic on");
}

/* 0x10f47310 */
void rome2_l77_luaG_concaterror(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t p1_va, uint32_t p2_va) {
    const rome2_lua_tvalue_32 *p1 = (ctx != NULL)
        ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, p1_va, sizeof(*p1))
        : NULL;
    uint32_t bad = (p1 != NULL && p1->tt != ROME2_LUA_TSTRING) ? p1_va : p2_va;
    rome2_l77_luaG_typeerror(ctx, l_va, bad, "concatenate");
}

/* 0x10f473c0 */
int32_t rome2_l77_luaG_ordererror(rome2_l77_ctx *ctx, uint32_t l_va, uint32_t p1_va, uint32_t p2_va) {
    const rome2_lua_tvalue_32 *p1 = (ctx != NULL)
        ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, p1_va, sizeof(*p1))
        : NULL;
    const rome2_lua_tvalue_32 *p2 = (ctx != NULL)
        ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, p2_va, sizeof(*p2))
        : NULL;
    const char *t1 = (p1 != NULL) ? rome2_l76_lua_typename(p1->tt) : "nil";
    const char *t2 = (p2 != NULL) ? rome2_l76_lua_typename(p2->tt) : "nil";
    if (t1[2] == t2[2]) {
        rome2_l77_luaG_runerror(ctx, l_va, "attempt to compare two %s values", t1);
    } else {
        rome2_l77_luaG_runerror(ctx, l_va, "attempt to compare %s with %s", t1, t2);
    }
    return 0;
}

/* 0x10f4bc30 */
void rome2_l77_callTMres(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    uint32_t res_va,
    const rome2_lua_tvalue_32 *f,
    const rome2_lua_tvalue_32 *p1,
    const rome2_lua_tvalue_32 *p2) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t res_off;
    uint32_t fn_slot;
    rome2_lua_tvalue_32 *s;
    if (L == NULL || f == NULL || p1 == NULL || p2 == NULL) {
        return;
    }
    res_off = res_va - L->stack_va;
    if ((int32_t)(L->stack_last_va - L->top_va) < 25) {
        rome2_l77_luaD_growstack(ctx, l_va, 3);
    }
    fn_slot = L->top_va;
    s = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, fn_slot, 24u);
    if (s != NULL) {
        s[0] = *f;
        s[1] = *p1;
        s[2] = *p2;
        L->top_va = fn_slot + 24u;
        rome2_l77_luaD_call(ctx, l_va, fn_slot, 1);
    }
    L->top_va -= 8u;
    {
        const rome2_lua_tvalue_32 *r = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, L->top_va, sizeof(*r));
        rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
            ctx->arena, L->stack_va + res_off, sizeof(*dst));
        if (r != NULL && dst != NULL) {
            *dst = *r;
        }
    }
}

/* 0x10f4bcc0 */
int32_t rome2_l77_call_orderTM(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const rome2_lua_tvalue_32 *p1,
    const rome2_lua_tvalue_32 *p2,
    int32_t event) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t tm1_va = rome2_l75_luaT_gettmbyobj(ctx != NULL ? ctx->arena : NULL, l_va, p1, event);
    const rome2_lua_tvalue_32 *tm1 = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
        ctx != NULL ? ctx->arena : NULL, tm1_va, sizeof(*tm1));
    uint32_t tm2_va;
    const rome2_lua_tvalue_32 *tm2;
    if (L == NULL || tm1 == NULL || tm1->tt == ROME2_LUA_TNIL) {
        return -1;
    }
    tm2_va = rome2_l75_luaT_gettmbyobj(ctx->arena, l_va, p2, event);
    tm2 = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, tm2_va, sizeof(*tm2));
    if (!rome2_l75_luaO_rawequalObj(tm1, tm2)) {
        return -1;
    }
    rome2_l77_callTMres(ctx, l_va, L->top_va, tm1, p1, p2);
    return (rome2_l76_lua_toboolean(ctx->arena, l_va, (int32_t)((L->top_va - L->base_va) >> 3) + 1) != 0) ? 1 : 0;
}

/* 0x10f4b9d0 */
void rome2_l77_arith(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    uint32_t ra_va,
    const rome2_lua_tvalue_32 *rb,
    const rome2_lua_tvalue_32 *rc,
    uint32_t event) {
    rome2_lua_tvalue_32 tb;
    rome2_lua_tvalue_32 tc;
    const rome2_lua_tvalue_32 *b = rome2_l75_luaV_tonumber(ctx->arena, rb, &tb);
    const rome2_lua_tvalue_32 *c = rome2_l75_luaV_tonumber(ctx->arena, rc, &tc);
    rome2_lua_tvalue_32 *ra = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, ra_va, sizeof(*ra));
    if (b != NULL && c != NULL && ra != NULL) {
        float nb = l77_u2f(b->value_u32);
        float nc = l77_u2f(c->value_u32);
        float out = 0.0f;
        switch (event) {
            case 5u: out = nb + nc; break;
            case 6u: out = nb - nc; break;
            case 7u: out = nb * nc; break;
            case 8u: out = nb / nc; break;
            case 9u: {
                double d = (double)nb / (double)nc;
                double fl = (d >= 0.0 || d == (double)(int64_t)d) ? (double)(int64_t)d : (double)((int64_t)d - 1);
                out = (float)((double)nb - fl * (double)nc);
                break;
            }
            case 10u: out = (float)rome2_l74_pow((double)nb, (double)nc); break;
            case 11u: out = -nb; break;
            default: break;
        }
        ra->value_u32 = l77_f2u(out);
        ra->tt = ROME2_LUA_TNUMBER;
        return;
    }
    {
        uint32_t tm_va = rome2_l75_luaT_gettmbyobj(ctx->arena, l_va, rb, (int32_t)event);
        const rome2_lua_tvalue_32 *tm = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
            ctx->arena, tm_va, sizeof(*tm));
        if (tm == NULL || tm->tt == ROME2_LUA_TNIL) {
            tm_va = rome2_l75_luaT_gettmbyobj(ctx->arena, l_va, rc, (int32_t)event);
            tm = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, tm_va, sizeof(*tm));
        }
        if (tm != NULL && tm->tt == ROME2_LUA_TFUNCTION) {
            rome2_l77_callTMres(ctx, l_va, ra_va, tm, rb, rc);
        }
    }
}

/* 0x10f4be50 */
void rome2_l77_luaV_concat(rome2_l77_ctx *ctx, uint32_t l_va, int32_t total, int32_t last) {
    const rome2_lua_state_32 *L = (ctx != NULL)
        ? (const rome2_lua_state_32 *)rome2_l75_const_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    if (L == NULL) {
        return;
    }
    while (total >= 2) {
        uint32_t top_va = L->base_va + (uint32_t)last * 8u;
        rome2_lua_tvalue_32 *right = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, top_va, 8u);
        rome2_lua_tvalue_32 *left = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, top_va - 8u, 8u);
        int32_t n = 2;
        if (right == NULL || left == NULL) {
            return;
        }
        if (right->tt == ROME2_LUA_TNUMBER) {
            char nb[32];
            (void)snprintf(nb, sizeof(nb), "%.14g", (double)l77_u2f(right->value_u32));
            right->value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, nb, strlen(nb));
            right->tt = ROME2_LUA_TSTRING;
        }
        if (left->tt == ROME2_LUA_TNUMBER) {
            char nb[32];
            (void)snprintf(nb, sizeof(nb), "%.14g", (double)l77_u2f(left->value_u32));
            left->value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, nb, strlen(nb));
            left->tt = ROME2_LUA_TSTRING;
        }
        if (left->tt != ROME2_LUA_TSTRING || right->tt != ROME2_LUA_TSTRING) {
            uint32_t tm_va = rome2_l75_luaT_gettmbyobj(ctx->arena, l_va, left, 15);
            const rome2_lua_tvalue_32 *tm = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, tm_va, sizeof(*tm));
            if (tm == NULL || tm->tt == ROME2_LUA_TNIL) {
                tm_va = rome2_l75_luaT_gettmbyobj(ctx->arena, l_va, right, 15);
                tm = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, tm_va, sizeof(*tm));
            }
            if (tm != NULL && tm->tt == ROME2_LUA_TFUNCTION) {
                rome2_l77_callTMres(ctx, l_va, top_va - 8u, tm, left, right);
            } else {
                rome2_l77_luaG_concaterror(ctx, l_va, top_va - 8u, top_va);
            }
        } else {
            const rome2_lua_tstring_hdr_32 *rh = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
                ctx->arena, right->value_u32, sizeof(*rh));
            uint32_t tl = (rh != NULL) ? rh->len : 0u;
            if (tl > 0u) {
                int32_t i;
                for (n = 1; n < total; ++n) {
                    rome2_lua_tvalue_32 *s = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                        ctx->arena, top_va - (uint32_t)n * 8u, 8u);
                    if (s == NULL) {
                        break;
                    }
                    if (s->tt == ROME2_LUA_TNUMBER) {
                        char nb[32];
                        (void)snprintf(nb, sizeof(nb), "%.14g", (double)l77_u2f(s->value_u32));
                        s->value_u32 = rome2_l77_luaS_newlstr(ctx, l_va, nb, strlen(nb));
                        s->tt = ROME2_LUA_TSTRING;
                    } else if (s->tt != ROME2_LUA_TSTRING) {
                        break;
                    }
                    {
                        const rome2_lua_tstring_hdr_32 *sh = (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
                            ctx->arena, s->value_u32, sizeof(*sh));
                        uint32_t sl = (sh != NULL) ? sh->len : 0u;
                        if (sl >= (~0u - tl - 2u)) {
                            rome2_l77_luaG_runerror(ctx, l_va, "string length overflow");
                            return;
                        }
                        tl += sl;
                    }
                }
                {
                    uint32_t buf_va = rome2_l77_luaZ_openspace(ctx, l_va, L->l_g_va + 0x34u, tl);
                    uint8_t *dst = (uint8_t *)rome2_l75_mut_ptr(ctx->arena, buf_va, tl);
                    uint32_t pos = 0u;
                    if (dst != NULL) {
                        for (i = n; i > 0; --i) {
                            const rome2_lua_tvalue_32 *sv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                                ctx->arena, top_va - (uint32_t)(i - 1) * 8u, 8u);
                            const rome2_lua_tstring_hdr_32 *sh = (sv != NULL)
                                ? (const rome2_lua_tstring_hdr_32 *)rome2_l75_const_ptr(
                                    ctx->arena, sv->value_u32, sizeof(*sh))
                                : NULL;
                            if (sh != NULL && sh->len > 0u) {
                                const void *src = rome2_l75_const_ptr(
                                    ctx->arena, sv->value_u32 + (uint32_t)sizeof(*sh), sh->len);
                                if (src != NULL) {
                                    memcpy(dst + pos, src, sh->len);
                                }
                                pos += sh->len;
                            }
                        }
                        {
                            uint32_t out_ts = rome2_l77_luaS_newlstr(ctx, l_va, (const char *)dst, tl);
                            rome2_lua_tvalue_32 *res_slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                                ctx->arena, top_va - (uint32_t)(n - 1) * 8u, 8u);
                            if (res_slot != NULL) {
                                res_slot->value_u32 = out_ts;
                                res_slot->tt = ROME2_LUA_TSTRING;
                            }
                        }
                    }
                }
            }
        }
        total -= (n - 1);
        last -= (n - 1);
    }
}

/* 0x10f4db60 */
void rome2_l77_luaV_gettable(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const rome2_lua_tvalue_32 *t,
    const rome2_lua_tvalue_32 *key,
    uint32_t val_va) {
    rome2_lua_tvalue_32 cur;
    int32_t loop;
    if (ctx == NULL || t == NULL || key == NULL) {
        return;
    }
    cur = *t;
    for (loop = 0; loop < 100; ++loop) {
        uint32_t tm_va = 0u;
        if (cur.tt == ROME2_LUA_TTABLE) {
            const rome2_lua_table_32 *tbl = (const rome2_lua_table_32 *)rome2_l75_const_ptr(
                ctx->arena, cur.value_u32, sizeof(*tbl));
            uint32_t v_va = rome2_l75_luaH_get(ctx->arena, cur.value_u32, key);
            const rome2_lua_tvalue_32 *v = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, v_va, sizeof(*v));
            const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(
                ctx->arena, l_va, sizeof(*L));
            const rome2_lua_global_state_32 *g = (L != NULL)
                ? (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(ctx->arena, L->l_g_va, sizeof(*g))
                : NULL;
            if ((v != NULL && v->tt != ROME2_LUA_TNIL) || tbl == NULL || tbl->metatable_va == 0u ||
                g == NULL || (tm_va = rome2_l75_luaT_gettm(ctx->arena, tbl->metatable_va, 0u, g->tmname_va[0])) == 0u) {
                rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                    ctx->arena, val_va, sizeof(*dst));
                if (dst != NULL && v != NULL) {
                    *dst = *v;
                }
                return;
            }
        } else {
            tm_va = rome2_l75_luaT_gettmbyobj(ctx->arena, l_va, &cur, 0);
        }
        {
            const rome2_lua_tvalue_32 *tm = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, tm_va, sizeof(*tm));
            if (tm == NULL || tm->tt == ROME2_LUA_TNIL) {
                return;
            }
            if (tm->tt == ROME2_LUA_TFUNCTION) {
                rome2_l77_callTMres(ctx, l_va, val_va, tm, &cur, key);
                return;
            }
            cur = *tm;
        }
    }
    rome2_l77_luaG_runerror(ctx, l_va, "loop in gettable");
}

/* 0x10f4dcb0 */
void rome2_l77_luaV_settable(
    rome2_l77_ctx *ctx,
    uint32_t l_va,
    const rome2_lua_tvalue_32 *t,
    const rome2_lua_tvalue_32 *key,
    const rome2_lua_tvalue_32 *val) {
    rome2_lua_tvalue_32 cur;
    int32_t loop;
    if (ctx == NULL || t == NULL || key == NULL || val == NULL) {
        return;
    }
    cur = *t;
    for (loop = 0; loop < 100; ++loop) {
        uint32_t tm_va = 0u;
        if (cur.tt == ROME2_LUA_TTABLE) {
            const rome2_lua_table_32 *tbl = (const rome2_lua_table_32 *)rome2_l75_const_ptr(
                ctx->arena, cur.value_u32, sizeof(*tbl));
            uint32_t old_va = rome2_l77_luaH_set(ctx, l_va, cur.value_u32, key);
            rome2_lua_tvalue_32 *old = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                ctx->arena, old_va, sizeof(*old));
            const rome2_lua_state_32 *L = (const rome2_lua_state_32 *)rome2_l75_const_ptr(
                ctx->arena, l_va, sizeof(*L));
            const rome2_lua_global_state_32 *g = (L != NULL)
                ? (const rome2_lua_global_state_32 *)rome2_l75_const_ptr(ctx->arena, L->l_g_va, sizeof(*g))
                : NULL;
            if ((old != NULL && old->tt != ROME2_LUA_TNIL) || tbl == NULL || tbl->metatable_va == 0u ||
                g == NULL || (tm_va = rome2_l75_luaT_gettm(ctx->arena, tbl->metatable_va, 1u, g->tmname_va[1])) == 0u) {
                if (old != NULL) {
                    *old = *val;
                }
                if (val->tt > 3) {
                    const uint8_t *vh = (const uint8_t *)rome2_l75_const_ptr(ctx->arena, val->value_u32, 6u);
                    if (vh != NULL && (vh[5] & 3u) != 0u && tbl != NULL && (tbl->marked & 4u) != 0u) {
                        rome2_l75_luaC_barrierback(ctx->arena, l_va, cur.value_u32);
                    }
                }
                return;
            }
        } else {
            tm_va = rome2_l75_luaT_gettmbyobj(ctx->arena, l_va, &cur, 1);
        }
        {
            const rome2_lua_tvalue_32 *tm = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                ctx->arena, tm_va, sizeof(*tm));
            if (tm == NULL || tm->tt == ROME2_LUA_TNIL) {
                return;
            }
            if (tm->tt == ROME2_LUA_TFUNCTION) {
                rome2_lua_state_32 *L = (rome2_lua_state_32 *)rome2_l75_mut_ptr(
                    ctx->arena, l_va, sizeof(*L));
                if (L != NULL) {
                    rome2_lua_tvalue_32 *s = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                        ctx->arena, L->top_va, 32u);
                    if (s != NULL) {
                        uint32_t fn_va = L->top_va;
                        s[0] = *tm;
                        s[1] = cur;
                        s[2] = *key;
                        s[3] = *val;
                        L->top_va += 32u;
                        rome2_l77_luaD_call(ctx, l_va, fn_va, 0);
                    }
                }
                return;
            }
            cur = *tm;
        }
    }
    rome2_l77_luaG_runerror(ctx, l_va, "loop in settable");
}

static const rome2_lua_tvalue_32 *rkb_or_rkc(
    const rome2_l75_arena *a,
    uint32_t base_va,
    uint32_t k_va,
    uint32_t idx) {
    uint32_t va = ((idx & 0x100u) != 0u)
        ? (k_va + (idx & 0xffu) * 8u)
        : (base_va + idx * 8u);
    return (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(a, va, sizeof(rome2_lua_tvalue_32));
}

/* 0x10f4c0f0 */
void rome2_l77_luaV_execute(rome2_l77_ctx *ctx, uint32_t l_va, int32_t nexeccalls) {
    rome2_lua_state_32 *L = (ctx != NULL)
        ? (rome2_lua_state_32 *)rome2_l75_mut_ptr(ctx->arena, l_va, sizeof(*L))
        : NULL;
    uint32_t steps = 0u;
    if (L == NULL || nexeccalls <= 0) {
        return;
    }
    while (nexeccalls > 0 && steps++ < 4096u) {
        const rome2_lua_callinfo_32 *ci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
            ctx->arena, L->ci_va, sizeof(*ci));
        const rome2_lua_tvalue_32 *fn = (ci != NULL)
            ? (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(ctx->arena, ci->func_va, sizeof(*fn))
            : NULL;
        const rome2_lua_closure_hdr_32 *cl = (fn != NULL)
            ? (const rome2_lua_closure_hdr_32 *)rome2_l75_const_ptr(ctx->arena, fn->value_u32, sizeof(*cl))
            : NULL;
        const rome2_lua_proto_32 *pt = (cl != NULL)
            ? (const rome2_lua_proto_32 *)rome2_l75_const_ptr(ctx->arena, cl->f_or_p_va, sizeof(*pt))
            : NULL;
        const uint32_t *ip = (const uint32_t *)rome2_l75_const_ptr(ctx->arena, L->savedpc_va, 4u);
        uint32_t inst;
        uint32_t op;
        uint32_t a;
        uint32_t b;
        uint32_t c;
        uint32_t bx;
        int32_t sbx;
        uint32_t ra_va;
        if (pt == NULL || ip == NULL) {
            return;
        }
        inst = *ip;
        L->savedpc_va += 4u;
        op = inst & 0x3fu;
        a = (inst >> 6) & 0xffu;
        b = inst >> 23;
        c = (inst >> 14) & 0x1ffu;
        bx = inst >> 14;
        sbx = (int32_t)bx - 0x1ffff;
        ra_va = L->base_va + a * 8u;
        switch (op) {
            case 0u: {
                rome2_lua_tvalue_32 *ra = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, ra_va, 8u);
                const rome2_lua_tvalue_32 *rb = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, L->base_va + b * 8u, 8u);
                if (ra != NULL && rb != NULL) {
                    *ra = *rb;
                }
                break;
            }
            case 1u: {
                rome2_lua_tvalue_32 *ra = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, ra_va, 8u);
                const rome2_lua_tvalue_32 *kv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, pt->k_va + bx * 8u, 8u);
                if (ra != NULL && kv != NULL) {
                    *ra = *kv;
                }
                break;
            }
            case 2u: {
                rome2_lua_tvalue_32 *ra = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, ra_va, 8u);
                if (ra != NULL) {
                    ra->value_u32 = (b != 0u) ? 1u : 0u;
                    ra->tt = ROME2_LUA_TBOOLEAN;
                }
                if (c != 0u) {
                    L->savedpc_va += 4u;
                }
                break;
            }
            case 3u: {
                uint32_t i;
                for (i = a; i <= b; ++i) {
                    rome2_lua_tvalue_32 *slot = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                        ctx->arena, L->base_va + i * 8u, 8u);
                    if (slot != NULL) {
                        slot->tt = ROME2_LUA_TNIL;
                    }
                }
                break;
            }
            case 5u: {
                const rome2_lua_tvalue_32 *kv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, pt->k_va + bx * 8u, 8u);
                rome2_lua_tvalue_32 env = { cl->env_va, ROME2_LUA_TTABLE };
                if (kv != NULL) {
                    rome2_l77_luaV_gettable(ctx, l_va, &env, kv, ra_va);
                }
                break;
            }
            case 7u: {
                const rome2_lua_tvalue_32 *kv = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, pt->k_va + bx * 8u, 8u);
                const rome2_lua_tvalue_32 *ra = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, ra_va, 8u);
                rome2_lua_tvalue_32 env = { cl->env_va, ROME2_LUA_TTABLE };
                if (kv != NULL && ra != NULL) {
                    rome2_l77_luaV_settable(ctx, l_va, &env, kv, ra);
                }
                break;
            }
            case 6u: {
                const rome2_lua_tvalue_32 *rb = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, L->base_va + b * 8u, 8u);
                const rome2_lua_tvalue_32 *rc = rkb_or_rkc(ctx->arena, L->base_va, pt->k_va, c);
                rome2_l77_luaV_gettable(ctx, l_va, rb, rc, ra_va);
                break;
            }
            case 9u: {
                const rome2_lua_tvalue_32 *ra = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, ra_va, 8u);
                const rome2_lua_tvalue_32 *rb = rkb_or_rkc(ctx->arena, L->base_va, pt->k_va, b);
                const rome2_lua_tvalue_32 *rc = rkb_or_rkc(ctx->arena, L->base_va, pt->k_va, c);
                rome2_l77_luaV_settable(ctx, l_va, ra, rb, rc);
                break;
            }
            case 10u: {
                rome2_lua_tvalue_32 *ra = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(ctx->arena, ra_va, 8u);
                uint32_t tbl_va = rome2_l77_luaH_new(
                    ctx, l_va, (int32_t)rome2_l75_luaO_fb2int(b), (int32_t)rome2_l75_luaO_fb2int(c));
                if (ra != NULL) {
                    ra->value_u32 = tbl_va;
                    ra->tt = ROME2_LUA_TTABLE;
                }
                break;
            }
            case 12u:
            case 13u:
            case 14u:
            case 15u:
            case 16u:
            case 17u: {
                const rome2_lua_tvalue_32 *rb = rkb_or_rkc(ctx->arena, L->base_va, pt->k_va, b);
                const rome2_lua_tvalue_32 *rc = rkb_or_rkc(ctx->arena, L->base_va, pt->k_va, c);
                rome2_l77_arith(ctx, l_va, ra_va, rb, rc, op - 7u);
                break;
            }
            case 18u: {
                const rome2_lua_tvalue_32 *rb = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                    ctx->arena, L->base_va + b * 8u, 8u);
                rome2_l77_arith(ctx, l_va, ra_va, rb, rb, 11u);
                break;
            }
            case 21u:
                rome2_l77_luaV_concat(ctx, l_va, (int32_t)(c - b + 1u), (int32_t)c);
                {
                    const rome2_lua_tvalue_32 *src = (const rome2_lua_tvalue_32 *)rome2_l75_const_ptr(
                        ctx->arena, L->base_va + b * 8u, 8u);
                    rome2_lua_tvalue_32 *dst = (rome2_lua_tvalue_32 *)rome2_l75_mut_ptr(
                        ctx->arena, ra_va, 8u);
                    if (src != NULL && dst != NULL) {
                        *dst = *src;
                    }
                }
                break;
            case 22u:
                L->savedpc_va = (uint32_t)((int32_t)L->savedpc_va + sbx * 4);
                break;
            case 28u: {
                int32_t nres = (int32_t)c - 1;
                if (b != 0u) {
                    L->top_va = ra_va + b * 8u;
                }
                if (rome2_l77_luaD_precall(ctx, l_va, ra_va, nres) == 0) {
                    ++nexeccalls;
                } else {
                    if (nres >= 0) {
                        const rome2_lua_callinfo_32 *nci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
                            ctx->arena, L->ci_va, sizeof(*nci));
                        if (nci != NULL) {
                            L->top_va = nci->top_va;
                        }
                    }
                }
                break;
            }
            case 30u: {
                if (b != 0u) {
                    L->top_va = ra_va + (b - 1u) * 8u;
                }
                if (L->openupval_va != 0u) {
                    rome2_l77_luaF_close(ctx, l_va, L->base_va);
                }
                rome2_l77_luaD_poscall(ctx, l_va, ra_va);
                --nexeccalls;
                if (nexeccalls > 0) {
                    const rome2_lua_callinfo_32 *nci = (const rome2_lua_callinfo_32 *)rome2_l75_const_ptr(
                        ctx->arena, L->ci_va, sizeof(*nci));
                    if (nci != NULL) {
                        L->top_va = nci->top_va;
                    }
                }
                break;
            }
            default:
                break;
        }
    }
}
