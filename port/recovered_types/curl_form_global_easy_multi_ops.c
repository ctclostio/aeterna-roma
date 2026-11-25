#include "curl_form_global_easy_multi_ops.h"

#include <string.h>

const rome2_l83_openssl_thunk_desc rome2_l83_openssl_thunks[ROME2_L83_OPENSSL_THUNK_COUNT] = {
    {0x11687680u, 0x1172f438u, 2604u, 0u},
    {0x116876e0u, 0x1172f460u, 3212u, 0u},
    {0x116876e6u, 0x1172f45cu, 298u, 0u},
    {0x1168778eu, 0x1172f3c8u, 224u, 0u},
    {0x11687794u, 0x1172f3ccu, 254u, 0u},
    {0x116c7f45u, 0x1172f5e8u, 74u, 1u},
    {0x116c7f93u, 0x1172f588u, 76u, 1u},
    {0x116c7fd5u, 0x1172f5b4u, 183u, 1u}
};

const rome2_l83_content_type_entry rome2_l83_content_types[6] = {
    {".gif", "image/gif"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".txt", "text/plain"},
    {".html", "text/html"},
    {".xml", "application/xml"}
};

/* {UserDefined dword index, value} written by 0x10f178c0 and by the copy inlined in 0x10f17b10. */
static const uint32_t l83_userdefined_defaults[][2] = {
    {0x1au, 0u}, {0x1bu, 0u}, {0x10u, 0u}, {0x25u, 0u}, {0x26u, 0u}, {0x27u, 0u}, {0x28u, 0u},
    {0x30u, 0xffffffffu}, {0x31u, 0xffffffffu}, {0x12u, 0xffffffffu}, {0x13u, 0xffffffffu},
    {0x0cu, 0xffffffffu}, {0x4au, 1u}, {0xbeu, 1u}, {0x81u, 1u}, {0x82u, 1u}, {0x83u, 0u},
    {0x66u, 1u}, {0x5du, 0x3cu}, {0x57u, 5u}, {0x03u, 0x438u}, {0x5cu, 0u}, {0x09u, 1u},
    {0x0au, 1u}, {0x71u, 1u}, {0x4eu, 1u}, {0x4fu, 2u}, {0x8eu, 0xffffffffu}, {0x5au, 1u},
    {0x91u, 0x1a4u}, {0x92u, 0x1edu}, {0xbbu, 0xffffffffu},
    {0xbcu, ROME2_CURL_REDIR_PROTOCOLS_DEFAULT}, {0xc0u, 0u}, {0xc1u, 0u}, {0xc2u, 0u},
    {0xc6u, 0u}, {0xc8u, 0x3cu}, {0xc7u, 0x3cu}
};

static uint32_t l83_rd32(const rome2_l82_curl_ctx *ctx, uint32_t va) {
    const void *p = rome2_l82_const_ptr(ctx, va, 4u);
    uint32_t v = 0u;
    if (p) {
        memcpy(&v, p, 4u);
    }
    return v;
}

static void l83_wr32(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t v) {
    void *p = rome2_l82_mut_ptr(ctx, va, 4u);
    if (p) {
        memcpy(p, &v, 4u);
    }
}

static void l83_zero(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t bytes) {
    void *p = rome2_l82_mut_ptr(ctx, va, bytes);
    if (p) {
        memset(p, 0, bytes);
    }
}

static void l83_copy(const rome2_l82_curl_ctx *ctx, uint32_t dst_va, uint32_t src_va, uint32_t bytes) {
    if (bytes == 0u) {
        return;
    }
    void *dst = rome2_l82_mut_ptr(ctx, dst_va, bytes);
    const void *src = rome2_l82_const_ptr(ctx, src_va, bytes);
    if (dst && src) {
        memmove(dst, src, bytes);
    }
}

/* NUL-terminated guest string, or NULL when it is not wholly inside the arena. */
static const char *l83_cstr(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t *len_out) {
    if (!ctx || !ctx->arena_bytes || va < ctx->arena_base_va) {
        return NULL;
    }
    uint32_t off = va - ctx->arena_base_va;
    if (off >= ctx->arena_size) {
        return NULL;
    }
    const char *s = (const char *)ctx->arena_bytes + off;
    const char *nul = (const char *)memchr(s, 0, ctx->arena_size - off);
    if (!nul) {
        return NULL;
    }
    if (len_out) {
        *len_out = (uint32_t)(nul - s);
    }
    return s;
}

static uint32_t l83_strdup(rome2_l82_curl_ctx *ctx, uint32_t src_va) {
    return rome2_l82_strdup_va(ctx, l83_cstr(ctx, src_va, NULL));
}

/* realloc through 0x119750d4; the caller supplies the size the image's heap would know. */
static uint32_t l83_realloc(rome2_l82_curl_ctx *ctx, uint32_t old_va, uint32_t old_size, uint32_t new_size) {
    if (old_va != 0u && new_size == 0u) {
        rome2_l82_curl_free(ctx, old_va);
        return 0u;
    }
    uint32_t new_va = rome2_l82_alloc(ctx, new_size);
    if (new_va == 0u) {
        return 0u;
    }
    if (old_va != 0u) {
        l83_copy(ctx, new_va, old_va, old_size < new_size ? old_size : new_size);
        rome2_l82_curl_free(ctx, old_va);
    }
    return new_va;
}

/* 0x100dbc00 (`XOR EAX, EAX; RET`): the folded Curl_resolver_global_init / _init / _getsock stubs. */
static int32_t l83_resolver_stub(rome2_l83_curl_state *g) {
    g->resolver_stub_calls++;
    return 0;
}

/* 0x100d6560 (`RET`): the folded Curl_resolver_global_cleanup / _cleanup stubs. */
static void l83_nop_stub(rome2_l83_curl_state *g) {
    g->nop_stub_calls++;
}

static uint32_t l83_getsock_cb(
    rome2_l83_curl_state *g,
    uint32_t fn_va,
    uint32_t conn_va,
    uint32_t *socks,
    int32_t numsocks) {
    return g->on_getsock ? g->on_getsock(g, fn_va, conn_va, socks, numsocks) : 0u;
}

static uint32_t l83_write_cb(
    rome2_l83_curl_state *g,
    uint32_t fn_va,
    uint32_t ptr_va,
    uint32_t len,
    uint32_t stream_va) {
    if (!g->on_write) {
        return len;
    }
    return g->on_write(g, fn_va, (const uint8_t *)rome2_l82_const_ptr(g->mem, ptr_va, len), 1u, len, stream_va);
}

void rome2_l83_state_init(rome2_l83_curl_state *g, rome2_l82_curl_ctx *mem) {
    if (!g) {
        return;
    }
    memset(g, 0, sizeof(*g));
    g->mem = mem;
    /* 0x119750cc..0x119750dc are file-initialised to the CRT defaults. */
    g->malloc_fn_va = ROME2_L83_CRT_MALLOC_VA;
    g->free_fn_va = ROME2_L83_CRT_FREE_VA;
    g->realloc_fn_va = ROME2_L83_CRT_REALLOC_VA;
    g->strdup_fn_va = ROME2_L83_CRT_STRDUP_VA;
    g->calloc_fn_va = ROME2_L83_CRT_CALLOC_VA;
}

/* 0x11687680, 0x116876e0, 0x116876e6, 0x1168778e, 0x11687794, 0x116c7f45, 0x116c7f93, 0x116c7fd5 */
int32_t rome2_l83_openssl_thunk(
    rome2_l83_curl_state *g,
    int32_t id,
    uint32_t a0,
    uint32_t a1,
    uint32_t a2) {
    if (!g || id < 0 || id >= ROME2_L83_OPENSSL_THUNK_COUNT || !g->on_openssl) {
        return 0;
    }
    return g->on_openssl(g, id, a0, a1, a2);
}

/* 0x10f2d380 */
int32_t rome2_l83_curl_ossl_init(rome2_l83_curl_state *g) {
    (void)rome2_l83_openssl_thunk(g, ROME2_L83_SSLEAY32_ORD_74, 0u, 0u, 0u);
    if (rome2_l83_openssl_thunk(g, ROME2_L83_SSLEAY32_ORD_183, 0u, 0u, 0u) == 0) {
        return 0;
    }
    (void)rome2_l83_openssl_thunk(g, ROME2_L83_LIBEAY32_ORD_3212, 0u, 0u, 0u);
    return 1;
}

/* 0x10f2d290 */
void rome2_l83_curl_ossl_cleanup(rome2_l83_curl_state *g) {
    (void)rome2_l83_openssl_thunk(g, ROME2_L83_LIBEAY32_ORD_298, 0u, 0u, 0u);
    (void)rome2_l83_openssl_thunk(g, ROME2_L83_LIBEAY32_ORD_2604, 0u, 0u, 0u);
    (void)rome2_l83_openssl_thunk(g, ROME2_L83_LIBEAY32_ORD_224, 0u, 0u, 0u);
    (void)rome2_l83_openssl_thunk(g, ROME2_L83_LIBEAY32_ORD_254, 0u, 0u, 0u);
}

/* 0x10f2d260: SSLEAY32 #76(conn->ssl[0].handle, &stack byte, 1); the buffer address is passed as 0. */
int32_t rome2_l83_curl_ossl_check_cxn(rome2_l83_curl_state *g, uint32_t conn_va) {
    if (!g) {
        return 0;
    }
    int32_t rc = rome2_l83_openssl_thunk(
        g,
        ROME2_L83_SSLEAY32_ORD_76,
        l83_rd32(g->mem, conn_va + ROME2_CURL_CONN_SSL0_HANDLE_OFF),
        0u,
        1u);
    if (rc > 0) {
        return 1;
    }
    return rc != 0 ? -1 : 0;
}

/* 0x10f15ca0: JMP 0x10f2d260 */
int32_t rome2_l83_curl_ssl_check_cxn(rome2_l83_curl_state *g, uint32_t conn_va) {
    return rome2_l83_curl_ossl_check_cxn(g, conn_va);
}

/* 0x10f162a0 */
int32_t rome2_l83_curl_ssl_init(rome2_l83_curl_state *g) {
    if (!g) {
        return 0;
    }
    if (g->ssl_initialized != 0u) {
        return 1;
    }
    g->ssl_initialized = 1u;
    return rome2_l83_curl_ossl_init(g);
}

/* 0x10f15cb0 */
void rome2_l83_curl_ssl_cleanup(rome2_l83_curl_state *g) {
    if (g && g->ssl_initialized != 0u) {
        rome2_l83_curl_ossl_cleanup(g);
        g->ssl_initialized = 0u;
    }
}

/* 0x10f12f30 */
void rome2_l83_curl_global_host_cache_dtor(rome2_l83_curl_state *g) {
    if (g && g->host_cache_initialized != 0u) {
        rome2_l83_curl_hash_clean(g->mem, g->hostname_cache_va);
        g->host_cache_initialized = 0u;
    }
}

/* 0x10f109e0 */
int32_t rome2_l83_curl_global_init(rome2_l83_curl_state *g, uint32_t flags) {
    if (!g) {
        return ROME2_CURLE_FAILED_INIT;
    }
    uint32_t was = g->initialized;
    g->initialized = was + 1u;
    if (was != 0u) {
        return ROME2_CURLE_OK;
    }
    g->malloc_fn_va = ROME2_L83_CRT_MALLOC_VA;
    g->free_fn_va = ROME2_L83_CRT_FREE_VA;
    g->realloc_fn_va = ROME2_L83_CRT_REALLOC_VA;
    g->strdup_fn_va = ROME2_L83_CRT_STRDUP_VA;
    g->calloc_fn_va = ROME2_L83_CRT_CALLOC_VA;
    if ((flags & ROME2_CURL_GLOBAL_SSL) != 0u && rome2_l83_curl_ssl_init(g) == 0) {
        return ROME2_CURLE_FAILED_INIT;
    }
    if ((flags & ROME2_CURL_GLOBAL_WIN32) != 0u) {
        uint16_t version = ROME2_CURL_WSA_VERSION;
        if (g->on_wsa_startup && g->on_wsa_startup(g, ROME2_CURL_WSA_VERSION, &version) != 0) {
            return ROME2_CURLE_FAILED_INIT;
        }
        if ((version & 0xffu) != 2u || (version >> 8) != 2u) {
            if (g->on_wsa_cleanup) {
                g->on_wsa_cleanup(g);
            }
            return ROME2_CURLE_FAILED_INIT;
        }
    }
    if (l83_resolver_stub(g) != 0) {
        return ROME2_CURLE_FAILED_INIT;
    }
    g->init_flags = flags;
    rome2_l83_curl_srand(g);
    return ROME2_CURLE_OK;
}

/* 0x10f10ab0 */
int32_t rome2_l83_curl_global_init_mem(
    rome2_l83_curl_state *g,
    uint32_t flags,
    uint32_t m_va,
    uint32_t f_va,
    uint32_t r_va,
    uint32_t s_va,
    uint32_t c_va) {
    if (!g || m_va == 0u || f_va == 0u || r_va == 0u || s_va == 0u || c_va == 0u) {
        return ROME2_CURLE_FAILED_INIT;
    }
    if (g->initialized != 0u) {
        return ROME2_CURLE_OK;
    }
    int32_t rc = rome2_l83_curl_global_init(g, flags);
    if (rc == ROME2_CURLE_OK) {
        g->malloc_fn_va = m_va;
        g->free_fn_va = f_va;
        g->strdup_fn_va = s_va;
        g->realloc_fn_va = r_va;
        g->calloc_fn_va = c_va;
    }
    return rc;
}

/* 0x10f10990 */
void rome2_l83_curl_global_cleanup(rome2_l83_curl_state *g) {
    if (!g || g->initialized == 0u) {
        return;
    }
    g->initialized--;
    if (g->initialized != 0u) {
        return;
    }
    rome2_l83_curl_global_host_cache_dtor(g);
    if ((g->init_flags & ROME2_CURL_GLOBAL_SSL) != 0u) {
        rome2_l83_curl_ssl_cleanup(g);
    }
    l83_nop_stub(g);
    if ((g->init_flags & ROME2_CURL_GLOBAL_WIN32) != 0u && g->on_wsa_cleanup) {
        g->on_wsa_cleanup(g);
    }
    g->init_flags = 0u;
}

/* 0x10f123e0 */
void rome2_l83_curl_hash_clean(rome2_l82_curl_ctx *ctx, uint32_t hash_va) {
    rome2_curl_hash_32 *h = (rome2_curl_hash_32 *)rome2_l82_mut_ptr(ctx, hash_va, (uint32_t)sizeof(*h));
    if (!h) {
        return;
    }
    for (int32_t i = 0; i < h->slots; ++i) {
        uint32_t slot_va = h->table_va + (uint32_t)i * 4u;
        if (!rome2_l82_const_ptr(ctx, slot_va, 4u)) {
            break;
        }
        rome2_l82_curl_llist_destroy(ctx, l83_rd32(ctx, slot_va), hash_va);
        l83_wr32(ctx, slot_va, 0u);
    }
    rome2_l82_curl_free(ctx, h->table_va);
    h->table_va = 0u;
    h->size = 0u;
    h->slots = 0;
}

/* 0x10f12660 */
uint32_t rome2_l83_curl_hash_pick(
    rome2_l83_curl_state *g,
    uint32_t hash_va,
    const void *key,
    uint32_t key_len) {
    if (!g || !g->on_hash_func || !g->on_hash_comp) {
        return 0u;
    }
    const rome2_l82_curl_ctx *ctx = g->mem;
    const rome2_curl_hash_32 *h =
        (const rome2_curl_hash_32 *)rome2_l82_const_ptr(ctx, hash_va, (uint32_t)sizeof(*h));
    if (!h) {
        return 0u;
    }
    uint32_t index = g->on_hash_func(g, h->hash_func_va, key, key_len, h->slots);
    uint32_t le_va = l83_rd32(ctx, l83_rd32(ctx, h->table_va + index * 4u));
    for (uint32_t guard = 0u; le_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_llist_element_32 *le =
            (const rome2_curl_llist_element_32 *)rome2_l82_const_ptr(ctx, le_va, (uint32_t)sizeof(*le));
        if (!le) {
            break;
        }
        const rome2_curl_hash_element_32 *he =
            (const rome2_curl_hash_element_32 *)rome2_l82_const_ptr(ctx, le->ptr_va, (uint32_t)sizeof(*he));
        if (!he) {
            break;
        }
        if (g->on_hash_comp(g, h->comp_func_va, he->key_va, he->key_len, key, key_len) != 0u) {
            return he->ptr_va;
        }
        le_va = le->next_va;
    }
    return 0u;
}

/* 0x10f21180 */
uint32_t rome2_l83_curl_llist_count(const rome2_l82_curl_ctx *ctx, uint32_t list_va) {
    return l83_rd32(ctx, list_va + (uint32_t)offsetof(rome2_curl_llist_32, size));
}

/* 0x10f213a0: always returns 1. The destructor call is skipped when the Layer 82 hook is unset. */
int32_t rome2_l83_curl_llist_remove(
    rome2_l82_curl_ctx *ctx,
    uint32_t list_va,
    uint32_t elem_va,
    uint32_t user_va) {
    if (elem_va == 0u) {
        return 1;
    }
    rome2_curl_llist_32 *list = (rome2_curl_llist_32 *)rome2_l82_mut_ptr(ctx, list_va, (uint32_t)sizeof(*list));
    rome2_curl_llist_element_32 *e =
        (rome2_curl_llist_element_32 *)rome2_l82_mut_ptr(ctx, elem_va, (uint32_t)sizeof(*e));
    if (!list || !e || list->size == 0u) {
        return 1;
    }
    if (elem_va == list->head_va) {
        list->head_va = e->next_va;
        if (e->next_va == 0u) {
            list->tail_va = 0u;
        } else {
            l83_wr32(ctx, e->next_va + 4u, 0u);
        }
    } else {
        l83_wr32(ctx, e->prev_va + 8u, e->next_va);
        if (e->next_va == 0u) {
            list->tail_va = e->prev_va;
        } else {
            l83_wr32(ctx, e->next_va + 4u, e->prev_va);
        }
    }
    if (ctx->on_llist_dtor) {
        ctx->on_llist_dtor(ctx, list->dtor_fn_va, user_va, e->ptr_va);
    }
    e->ptr_va = 0u;
    e->prev_va = 0u;
    e->next_va = 0u;
    rome2_l82_curl_free(ctx, elem_va);
    list->size--;
    return 1;
}

/* 0x10f21420: 32-bit wrapping (sec diff) * 1000 + (usec diff) / 1000, the division truncating toward zero. */
int32_t rome2_l83_curlx_tvdiff(rome2_curl_timeval_32 newer, rome2_curl_timeval_32 older) {
    int32_t usec = (int32_t)((uint32_t)newer.tv_usec - (uint32_t)older.tv_usec);
    uint32_t sec = (uint32_t)newer.tv_sec - (uint32_t)older.tv_sec;
    return (int32_t)(sec * 1000u + (uint32_t)(usec / 1000));
}

/* 0x10f214b0: EAX = GetTickCount() / 1000, EDX = (GetTickCount() % 1000) * 1000 */
rome2_curl_timeval_32 rome2_l83_curlx_tvnow(rome2_l83_curl_state *g) {
    rome2_curl_timeval_32 now;
    uint32_t ms = (g && g->on_get_tick_count) ? g->on_get_tick_count(g) : 0u;
    now.tv_sec = (int32_t)(ms / 1000u);
    now.tv_usec = (int32_t)((ms % 1000u) * 1000u);
    return now;
}

/* 0x116a886e: stdcall; calls the resolved precise API or tail-jumps to GetSystemTimeAsFileTime. */
void rome2_l83_crt_get_system_time_precise_as_file_time(rome2_l83_curl_state *g, uint64_t *filetime) {
    if (g && filetime && g->on_system_filetime) {
        *filetime = g->on_system_filetime(g, g->has_precise_filetime ? 1u : 0u);
    }
}

/* 0x1168c9e2 */
int32_t rome2_l83_crt_timespec_get(rome2_l83_curl_state *g, rome2_crt_timespec64 *ts, int32_t base) {
    if (!g) {
        return 0;
    }
    if (!ts) {
        if (g->mem) {
            g->mem->last_errno = 22; /* EINVAL */
        }
        g->invalid_parameter_calls++;
        return 0;
    }
    if (base != 1) {
        return 0;
    }
    uint64_t filetime = 0u;
    rome2_l83_crt_get_system_time_precise_as_file_time(g, &filetime);
    int64_t span = (int64_t)(filetime - ROME2_L83_FILETIME_UNIX_EPOCH);
    if (span >= ROME2_L83_FILETIME_SPAN_LIMIT) {
        return 0;
    }
    ts->tv_sec = span / 10000000;
    ts->tv_nsec = (int32_t)(span % 10000000) * 100;
    return 1;
}

/* 0x1168ca95 */
int64_t rome2_l83_crt_time64(rome2_l83_curl_state *g, int64_t *out) {
    rome2_crt_timespec64 ts = {0, 0};
    if (rome2_l83_crt_timespec_get(g, &ts, 1) != 1) {
        ts.tv_sec = -1;
    }
    if (out) {
        *out = ts.tv_sec;
    }
    return ts.tv_sec;
}

/* 0x10f1eda0: the seed after three folded `seed * 1103515245 + 12345` steps. */
void rome2_l83_curl_srand(rome2_l83_curl_state *g) {
    if (g) {
        uint32_t now = (uint32_t)(uint64_t)rome2_l83_crt_time64(g, NULL);
        g->randseed = now * ROME2_L83_RANDSEED_MUL + ROME2_L83_RANDSEED_ADD;
    }
}

/* 0x10f10330 */
void rome2_l83_curl_easy_init_handle_data(rome2_l82_curl_ctx *ctx, uint32_t data_va) {
    l83_zero(ctx, data_va + ROME2_CURL_EASY_REQ_OFF, ROME2_CURL_EASY_REQ_BYTES);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_REQ_MAXDOWNLOAD_OFF, 0xffffffffu);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_REQ_MAXDOWNLOAD_OFF + 4u, 0xffffffffu);
}

static void l83_apply_userdefined_defaults(const rome2_l82_curl_ctx *ctx, uint32_t set_va) {
    l83_wr32(ctx, set_va + 4u * 4u, ROME2_L83_CRT_IOB_BASE_VA + 1u * ROME2_L83_CRT_IOB_STRIDE); /* out: stdout */
    l83_wr32(ctx, set_va + 5u * 4u, ROME2_L83_CRT_IOB_BASE_VA);                                 /* in: stdin */
    l83_wr32(ctx, set_va, ROME2_L83_CRT_IOB_BASE_VA + 2u * ROME2_L83_CRT_IOB_STRIDE);           /* err: stderr */
    l83_wr32(ctx, set_va + 0x16u * 4u, ROME2_L83_CRT_FWRITE_VA);
    l83_wr32(ctx, set_va + 0x19u * 4u, ROME2_L83_CRT_FREAD_VA);
    for (size_t i = 0u; i < sizeof(l83_userdefined_defaults) / sizeof(l83_userdefined_defaults[0]); ++i) {
        l83_wr32(ctx, set_va + l83_userdefined_defaults[i][0] * 4u, l83_userdefined_defaults[i][1]);
    }
}

/* 0x10f178c0 */
int32_t rome2_l83_curl_init_userdefined(rome2_l82_curl_ctx *ctx, uint32_t set_va) {
    l83_apply_userdefined_defaults(ctx, set_va);
    return ROME2_CURLE_OK;
}

/* 0x10f17730 */
void rome2_l83_curl_freeset(rome2_l82_curl_ctx *ctx, uint32_t data_va) {
    for (uint32_t i = 0u; i < ROME2_CURL_EASY_SET_STR_COUNT; ++i) {
        uint32_t slot_va = data_va + ROME2_CURL_EASY_SET_STR_OFF + i * 4u;
        uint32_t str_va = l83_rd32(ctx, slot_va);
        if (str_va != 0u) {
            rome2_l82_curl_free(ctx, str_va);
            l83_wr32(ctx, slot_va, 0u);
        }
    }
    if (l83_rd32(ctx, data_va + ROME2_CURL_EASY_CHANGE_REFERER_ALLOC_OFF) != 0u) {
        uint32_t referer_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_CHANGE_REFERER_OFF);
        if (referer_va != 0u) {
            rome2_l82_curl_free(ctx, referer_va);
        }
        l83_wr32(ctx, data_va + ROME2_CURL_EASY_CHANGE_REFERER_ALLOC_OFF, 0u);
    }
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_CHANGE_REFERER_OFF, 0u);
}

/* 0x10f17b10. A missing model argument reports CURLE_BAD_FUNCTION_ARGUMENT. */
int32_t rome2_l83_curl_open(rome2_l83_curl_state *g, uint32_t *out_data_va) {
    if (!g || !g->mem || !out_data_va) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    rome2_l82_curl_ctx *ctx = g->mem;
    uint32_t data_va = rome2_l82_calloc(ctx, 1u, ROME2_CURL_EASY_BYTES);
    if (data_va == 0u) {
        return ROME2_CURLE_OUT_OF_MEMORY;
    }
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_MAGIC_OFF, ROME2_CURL_EASY_MAGIC);
    int32_t rc = l83_resolver_stub(g);
    if (rc != 0) {
        rome2_l82_curl_free(ctx, data_va);
        return rc;
    }
    uint32_t headerbuff_va = rome2_l82_alloc(ctx, ROME2_CURL_HEADERSIZE);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_HEADERBUFF_OFF, headerbuff_va);
    if (headerbuff_va == 0u) {
        l83_nop_stub(g);
        rome2_l83_curl_freeset(ctx, data_va);
        rome2_l82_curl_free(ctx, data_va);
        return ROME2_CURLE_OUT_OF_MEMORY;
    }
    rome2_l83_curl_easy_init_handle_data(ctx, data_va);
    l83_apply_userdefined_defaults(ctx, data_va + ROME2_CURL_EASY_SET_OFF);
    l83_wr32(
        ctx,
        data_va + ROME2_CURL_EASY_PROGRESS_FLAGS_OFF,
        l83_rd32(ctx, data_va + ROME2_CURL_EASY_PROGRESS_FLAGS_OFF) | ROME2_CURL_PGRS_HIDE);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_WILDCARD_STATE_OFF, 0u);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_WILDCARD_FILELIST_OFF, 0u);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_SET_WILDCARDMATCH_OFF, 0u);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_HEADERSIZE_OFF, ROME2_CURL_HEADERSIZE);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_LASTCONNECT_OFF, 0xffffffffu);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_CURRENT_SPEED_OFF, 0xffffffffu);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_CURRENT_SPEED_OFF + 4u, 0xffffffffu);
    *out_data_va = data_va;
    return ROME2_CURLE_OK;
}

/* 0x10f105a0 */
uint32_t rome2_l83_curl_easy_init(rome2_l83_curl_state *g) {
    if (!g) {
        return 0u;
    }
    if (g->initialized == 0u && rome2_l83_curl_global_init(g, ROME2_CURL_GLOBAL_ALL) != ROME2_CURLE_OK) {
        return 0u;
    }
    uint32_t data_va = 0u;
    if (rome2_l83_curl_open(g, &data_va) != ROME2_CURLE_OK) {
        return 0u;
    }
    return data_va;
}

/* 0x10f10820 */
void rome2_l83_curl_easy_reset(rome2_l82_curl_ctx *ctx, uint32_t data_va) {
    uint32_t pathbuffer_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_PATHBUFFER_OFF);
    if (pathbuffer_va != 0u) {
        rome2_l82_curl_free(ctx, pathbuffer_va);
        l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_PATHBUFFER_OFF, 0u);
    }
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_PATH_OFF, 0u);
    uint32_t proto_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_PROTO_OFF);
    if (proto_va != 0u) {
        rome2_l82_curl_free(ctx, proto_va);
        l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_PROTO_OFF, 0u);
    }
    rome2_l83_curl_freeset(ctx, data_va);
    l83_zero(ctx, data_va + ROME2_CURL_EASY_SET_OFF, ROME2_CURL_EASY_SET_BYTES);
    (void)rome2_l83_curl_init_userdefined(ctx, data_va + ROME2_CURL_EASY_SET_OFF);
    l83_zero(ctx, data_va + ROME2_CURL_EASY_PROGRESS_OFF, ROME2_CURL_EASY_PROGRESS_BYTES);
    l83_zero(ctx, data_va + ROME2_CURL_EASY_REQ_OFF, ROME2_CURL_EASY_REQ_BYTES);
    l83_wr32(
        ctx,
        data_va + ROME2_CURL_EASY_PROGRESS_FLAGS_OFF,
        l83_rd32(ctx, data_va + ROME2_CURL_EASY_PROGRESS_FLAGS_OFF) | ROME2_CURL_PGRS_HIDE);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_REQ_MAXDOWNLOAD_OFF, 0xffffffffu);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_REQ_MAXDOWNLOAD_OFF + 4u, 0xffffffffu);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_CURRENT_SPEED_OFF, 0xffffffffu);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_CURRENT_SPEED_OFF + 4u, 0xffffffffu);
}

/* 0x10f1d260 */
void rome2_l83_curl_failf(rome2_l83_curl_state *g, uint32_t data_va, const char *fmt, ...) {
    if (!g || !fmt) {
        return;
    }
    const rome2_l82_curl_ctx *ctx = g->mem;
    char *buf = (char *)rome2_l82_mut_ptr(ctx, data_va + ROME2_CURL_EASY_STATE_BUFFER_OFF, ROME2_CURL_MAX_WRITE_SIZE);
    if (!buf) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    (void)rome2_l82_curl_mvsnprintf(buf, ROME2_CURL_MAX_WRITE_SIZE, fmt, ap);
    va_end(ap);
    uint32_t errorbuffer_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_ERRORBUFFER_OFF);
    if (errorbuffer_va != 0u && l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_ERRORBUF_OFF) == 0u) {
        char *errorbuffer = (char *)rome2_l82_mut_ptr(ctx, errorbuffer_va, ROME2_CURL_ERROR_SIZE);
        if (errorbuffer) {
            (void)rome2_l82_curl_msnprintf(errorbuffer, ROME2_CURL_ERROR_SIZE, "%s", buf);
        }
        l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_ERRORBUF_OFF, 1u);
    }
    if (l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_VERBOSE_OFF) == 0u) {
        return;
    }
    const char *nul = (const char *)memchr(buf, 0, ROME2_CURL_MAX_WRITE_SIZE);
    uint32_t len = nul ? (uint32_t)(nul - buf) : (uint32_t)ROME2_CURL_MAX_WRITE_SIZE - 1u;
    if (len < (uint32_t)ROME2_CURL_MAX_WRITE_SIZE - 1u) {
        buf[len] = '\n';
        len++;
        buf[len] = '\0';
    }
    uint32_t fdebug_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_FDEBUG_OFF);
    if (fdebug_va != 0u) {
        if (g->on_debug) {
            g->on_debug(g, fdebug_va, data_va, 0, buf, len, l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_DEBUGDATA_OFF));
        }
        return;
    }
    if (g->on_write) {
        uint32_t err_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_ERR_OFF);
        (void)g->on_write(g, ROME2_L83_CRT_FWRITE_VA, (const uint8_t *)"* ", 2u, 1u, err_va); /* 0x1183fa10 */
        (void)g->on_write(g, ROME2_L83_CRT_FWRITE_VA, (const uint8_t *)buf, len, 1u, err_va);
    }
}

/* 0x10f1d8e0 */
int32_t rome2_l83_pausewrite(
    rome2_l82_curl_ctx *ctx,
    uint32_t data_va,
    uint32_t type,
    uint32_t ptr_va,
    uint32_t len) {
    uint32_t dup_va = rome2_l82_alloc(ctx, len);
    if (dup_va == 0u) {
        return ROME2_CURLE_OUT_OF_MEMORY;
    }
    l83_copy(ctx, dup_va, ptr_va, len);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITE_OFF, dup_va);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITESIZE_OFF, len);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITETYPE_OFF, type);
    l83_wr32(
        ctx,
        data_va + ROME2_CURL_EASY_REQ_KEEPON_OFF,
        l83_rd32(ctx, data_va + ROME2_CURL_EASY_REQ_KEEPON_OFF) | ROME2_CURL_KEEP_RECV_PAUSE);
    return ROME2_CURLE_OK;
}

/* 0x10f1d030 */
int32_t rome2_l83_curl_client_write(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t type,
    uint32_t ptr_va,
    uint32_t len) {
    if (!g || !g->mem) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    rome2_l82_curl_ctx *ctx = g->mem;
    uint32_t data_va = l83_rd32(ctx, conn_va + ROME2_CURL_CONN_DATA_OFF);
    if (len == 0u) {
        (void)l83_cstr(ctx, ptr_va, &len);
    }
    if ((l83_rd32(ctx, data_va + ROME2_CURL_EASY_REQ_KEEPON_OFF) & ROME2_CURL_KEEP_RECV_PAUSE) != 0u) {
        if (type != l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITETYPE_OFF)) {
            return ROME2_CURLE_RECV_ERROR;
        }
        uint32_t old_size = l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITESIZE_OFF);
        uint32_t new_size = old_size + len;
        uint32_t new_va = l83_realloc(
            ctx,
            l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITE_OFF),
            old_size,
            new_size);
        if (new_va == 0u) {
            return ROME2_CURLE_OUT_OF_MEMORY;
        }
        l83_copy(ctx, new_va + old_size, ptr_va, len);
        l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITESIZE_OFF, new_size);
        l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITE_OFF, new_va);
        return ROME2_CURLE_OK;
    }
    if ((type & ROME2_CURL_CLIENTWRITE_BODY) != 0u && len != 0u) {
        uint32_t wrote = l83_write_cb(
            g,
            l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_FWRITE_FUNC_OFF),
            ptr_va,
            len,
            l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_OUT_OFF));
        if (wrote == ROME2_CURL_WRITEFUNC_PAUSE) {
            return rome2_l83_pausewrite(ctx, data_va, type, ptr_va, len);
        }
        if (wrote != len) {
            rome2_l83_curl_failf(g, data_va, "Failed writing body (%zu != %zu)", (size_t)wrote, (size_t)len);
            return ROME2_CURLE_WRITE_ERROR;
        }
    }
    if ((type & ROME2_CURL_CLIENTWRITE_HEADER) != 0u) {
        uint32_t writeheader_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_WRITEHEADER_OFF);
        uint32_t fn_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_FWRITE_HEADER_OFF);
        if (fn_va == 0u) {
            if (writeheader_va == 0u) {
                return ROME2_CURLE_OK;
            }
            fn_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_SET_FWRITE_FUNC_OFF);
        }
        uint32_t wrote = l83_write_cb(g, fn_va, ptr_va, len, writeheader_va);
        if (wrote == ROME2_CURL_WRITEFUNC_PAUSE) {
            return rome2_l83_pausewrite(ctx, data_va, ROME2_CURL_CLIENTWRITE_HEADER, ptr_va, len);
        }
        if (wrote != len) {
            rome2_l83_curl_failf(g, data_va, "Failed writing header");
            return ROME2_CURLE_WRITE_ERROR;
        }
    }
    return ROME2_CURLE_OK;
}

/* 0x10f105e0 */
int32_t rome2_l83_curl_easy_pause(rome2_l83_curl_state *g, uint32_t data_va, uint32_t action) {
    if (!g || !g->mem) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    rome2_l82_curl_ctx *ctx = g->mem;
    uint32_t keepon = l83_rd32(ctx, data_va + ROME2_CURL_EASY_REQ_KEEPON_OFF);
    keepon &= ~(uint32_t)(ROME2_CURL_KEEP_RECV_PAUSE | ROME2_CURL_KEEP_SEND_PAUSE);
    keepon |= (((action & ROME2_CURLPAUSE_RECV) * 2u) | (action & ROME2_CURLPAUSE_SEND)) << 3;
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_REQ_KEEPON_OFF, keepon);
    if ((action & ROME2_CURLPAUSE_RECV) != 0u) {
        return ROME2_CURLE_OK;
    }
    uint32_t freewrite_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITE_OFF);
    if (freewrite_va == 0u) {
        return ROME2_CURLE_OK;
    }
    uint32_t temptype = l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITETYPE_OFF);
    l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITE_OFF, 0u);
    uint32_t tempwrite_va = freewrite_va;
    uint32_t tempsize = l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITESIZE_OFF);
    int32_t result;
    for (;;) {
        uint32_t chunklen = tempsize > ROME2_CURL_MAX_WRITE_SIZE ? (uint32_t)ROME2_CURL_MAX_WRITE_SIZE : tempsize;
        result = rome2_l83_curl_client_write(
            g,
            l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_CURRENT_CONN_OFF),
            temptype,
            tempwrite_va,
            chunklen);
        if (result != ROME2_CURLE_OK) {
            break;
        }
        uint32_t paused_va = l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITE_OFF);
        if (paused_va != 0u && tempsize - chunklen != 0u) {
            /* paused again with data left: keep everything from the current chunk on */
            uint32_t new_va = l83_realloc(
                ctx,
                paused_va,
                l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITESIZE_OFF),
                tempsize);
            if (new_va == 0u) {
                rome2_l82_curl_free(ctx, paused_va);
                l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITE_OFF, 0u);
                rome2_l82_curl_free(ctx, freewrite_va);
                return ROME2_CURLE_OUT_OF_MEMORY;
            }
            l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITE_OFF, new_va);
            l83_copy(ctx, new_va, tempwrite_va, tempsize);
            l83_wr32(ctx, data_va + ROME2_CURL_EASY_STATE_TEMPWRITESIZE_OFF, tempsize);
            break;
        }
        tempsize -= chunklen;
        tempwrite_va += chunklen;
        if (tempsize == 0u) {
            break;
        }
    }
    rome2_l82_curl_free(ctx, freewrite_va);
    return result;
}

/* 0x10f1d7e0 */
int32_t rome2_l83_curl_write(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t sockfd,
    uint32_t mem_va,
    uint32_t len,
    int32_t *written) {
    if (!g) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    const rome2_l82_curl_ctx *ctx = g->mem;
    uint32_t num = (sockfd == l83_rd32(ctx, conn_va + ROME2_CURL_CONN_SOCK_OFF + 4u)) ? 1u : 0u;
    int32_t curlcode = 0;
    int32_t bytes_written = -1;
    if (g->on_conn_send) {
        bytes_written = g->on_conn_send(
            g,
            l83_rd32(ctx, conn_va + ROME2_CURL_CONN_SEND_OFF + num * 4u),
            conn_va,
            num,
            mem_va,
            len,
            &curlcode);
    }
    if (written) {
        *written = bytes_written;
    }
    if (bytes_written >= 0) {
        return ROME2_CURLE_OK;
    }
    if (curlcode == 0) {
        return ROME2_CURLE_SEND_ERROR;
    }
    if (curlcode == ROME2_CURLE_AGAIN) {
        if (written) {
            *written = 0;
        }
        return ROME2_CURLE_OK;
    }
    return curlcode;
}

/* 0x10f1db90 */
uint32_t rome2_l83_curl_getconnectinfo(
    rome2_l83_curl_state *g,
    uint32_t data_va,
    uint32_t *conn_va) {
    if (!g) {
        return ROME2_CURL_SOCKET_BAD;
    }
    const rome2_l82_curl_ctx *ctx = g->mem;
    uint32_t lastconnect = l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_LASTCONNECT_OFF);
    if (lastconnect == 0xffffffffu) {
        return ROME2_CURL_SOCKET_BAD;
    }
    uint32_t connects_va = l83_rd32(ctx, l83_rd32(ctx, data_va + ROME2_CURL_EASY_STATE_CONNC_OFF));
    uint32_t c_va = l83_rd32(ctx, connects_va + lastconnect * 4u);
    if (c_va == 0u) {
        return ROME2_CURL_SOCKET_BAD;
    }
    if (conn_va) {
        *conn_va = c_va;
    }
    uint32_t sockfd = l83_rd32(ctx, c_va + ROME2_CURL_CONN_SOCK_OFF);
    int32_t alive;
    if (l83_rd32(ctx, c_va + ROME2_CURL_CONN_SSL0_USE_OFF) != 0u) {
        alive = rome2_l83_curl_ssl_check_cxn(g, c_va);
    } else {
        alive = g->on_recv_peek ? g->on_recv_peek(g, sockfd) : 0;
    }
    return alive != 0 ? sockfd : ROME2_CURL_SOCKET_BAD;
}

/* 0x10f10b30 */
int32_t rome2_l83_easy_connection(
    rome2_l83_curl_state *g,
    uint32_t data_va,
    uint32_t *sfd,
    uint32_t *conn_va) {
    if (!g || data_va == 0u) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (l83_rd32(g->mem, data_va + ROME2_CURL_EASY_SET_CONNECT_ONLY_OFF) == 0u) {
        rome2_l83_curl_failf(g, data_va, "CONNECT_ONLY is required!");
        return ROME2_CURLE_UNSUPPORTED_PROTOCOL;
    }
    uint32_t sockfd = rome2_l83_curl_getconnectinfo(g, data_va, conn_va);
    if (sfd) {
        *sfd = sockfd;
    }
    if (sockfd == ROME2_CURL_SOCKET_BAD) {
        rome2_l83_curl_failf(g, data_va, "Failed to get recent socket");
        return ROME2_CURLE_UNSUPPORTED_PROTOCOL;
    }
    return ROME2_CURLE_OK;
}

/* 0x10f108e0 */
int32_t rome2_l83_curl_easy_send(
    rome2_l83_curl_state *g,
    uint32_t data_va,
    uint32_t buffer_va,
    uint32_t buflen,
    int32_t *n) {
    uint32_t sfd = 0u;
    uint32_t c_va = 0u;
    int32_t ret = rome2_l83_easy_connection(g, data_va, &sfd, &c_va);
    if (ret != ROME2_CURLE_OK) {
        return ret;
    }
    int32_t n1 = 0;
    if (n) {
        *n = 0;
    }
    ret = rome2_l83_curl_write(g, c_va, sfd, buffer_va, buflen, &n1);
    if (n1 == -1) {
        return ROME2_CURLE_SEND_ERROR;
    }
    if (ret == ROME2_CURLE_OK && n1 == 0) {
        return ROME2_CURLE_AGAIN;
    }
    if (n) {
        *n = n1;
    }
    return ret;
}

/* 0x10f14670 */
uint32_t rome2_l83_curl_single_getsock(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t *socks,
    int32_t numsocks) {
    if (!g) {
        return 0u;
    }
    const rome2_l82_curl_ctx *ctx = g->mem;
    uint32_t data_va = l83_rd32(ctx, conn_va + ROME2_CURL_CONN_DATA_OFF);
    uint32_t perform_getsock_va = l83_rd32(
        ctx,
        l83_rd32(ctx, conn_va + ROME2_CURL_CONN_HANDLER_OFF) + ROME2_CURL_HANDLER_PERFORM_GETSOCK_OFF);
    if (perform_getsock_va != 0u) {
        return l83_getsock_cb(g, perform_getsock_va, conn_va, socks, numsocks);
    }
    if (numsocks < 2 || !socks) {
        return 0u;
    }
    uint32_t bitmap = 0u;
    uint32_t sockindex = 0u;
    uint32_t keepon = l83_rd32(ctx, data_va + ROME2_CURL_EASY_REQ_KEEPON_OFF);
    if ((keepon & 0x15u) == ROME2_CURL_KEEP_RECV) {
        socks[0] = l83_rd32(ctx, conn_va + ROME2_CURL_CONN_SOCKFD_OFF);
        bitmap |= 1u;
        keepon = l83_rd32(ctx, data_va + ROME2_CURL_EASY_REQ_KEEPON_OFF);
    }
    if ((keepon & 0x2au) == ROME2_CURL_KEEP_SEND) {
        uint32_t writesockfd = l83_rd32(ctx, conn_va + ROME2_CURL_CONN_WRITESOCKFD_OFF);
        uint32_t recv_bit = keepon & ROME2_CURL_KEEP_RECV;
        if (l83_rd32(ctx, conn_va + ROME2_CURL_CONN_SOCKFD_OFF) != writesockfd || recv_bit == 0u) {
            sockindex = recv_bit;
            socks[sockindex] = writesockfd;
        }
        bitmap |= 1u << (sockindex + 16u);
    }
    return bitmap;
}

/* 0x10f173f0: tail-jumps to handler->doing_getsock */
uint32_t rome2_l83_curl_doing_getsock(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t *socks,
    int32_t numsocks) {
    if (!g || conn_va == 0u) {
        return 0u;
    }
    uint32_t fn_va = l83_rd32(
        g->mem,
        l83_rd32(g->mem, conn_va + ROME2_CURL_CONN_HANDLER_OFF) + ROME2_CURL_HANDLER_DOING_GETSOCK_OFF);
    return fn_va != 0u ? l83_getsock_cb(g, fn_va, conn_va, socks, numsocks) : 0u;
}

/* 0x10f17f40: tail-jumps to handler->proto_getsock; the image does not test conn for NULL */
uint32_t rome2_l83_curl_protocol_getsock(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t *socks,
    int32_t numsocks) {
    if (!g) {
        return 0u;
    }
    uint32_t fn_va = l83_rd32(
        g->mem,
        l83_rd32(g->mem, conn_va + ROME2_CURL_CONN_HANDLER_OFF) + ROME2_CURL_HANDLER_PROTO_GETSOCK_OFF);
    return fn_va != 0u ? l83_getsock_cb(g, fn_va, conn_va, socks, numsocks) : 0u;
}

/* 0x10f232c0: states 2..14 first store the easy handle into the connection */
uint32_t rome2_l83_multi_getsock(
    rome2_l83_curl_state *g,
    uint32_t one_easy_va,
    uint32_t *socks,
    int32_t numsocks) {
    if (!g) {
        return 0u;
    }
    const rome2_l82_curl_ctx *ctx = g->mem;
    const rome2_curl_one_easy_prefix_32 *easy =
        (const rome2_curl_one_easy_prefix_32 *)rome2_l82_const_ptr(ctx, one_easy_va, (uint32_t)sizeof(*easy));
    if (!easy) {
        return 0u;
    }
    if (l83_rd32(ctx, easy->easy_handle_va + ROME2_CURL_EASY_STATE_PIPE_BROKE_OFF) != 0u ||
        easy->easy_conn_va == 0u) {
        return 0u;
    }
    uint32_t conn_va = easy->easy_conn_va;
    int32_t state = easy->state;
    if (state > 1 && state < 0xf) {
        l83_wr32(ctx, conn_va + ROME2_CURL_CONN_DATA_OFF, easy->easy_handle_va);
    }
    switch (state) {
    case 2:
        return (uint32_t)l83_resolver_stub(g);
    case 3:
    case 4:
        if (numsocks == 0 || !socks) {
            return 0u;
        }
        socks[0] = l83_rd32(ctx, conn_va + ROME2_CURL_CONN_SOCK_OFF);
        return l83_rd32(ctx, conn_va + ROME2_CURL_CONN_TUNNEL_STATE0_OFF) == 1u ? 1u : 0x10000u;
    case 5:
        return rome2_l83_curl_protocol_getsock(g, conn_va, socks, numsocks);
    case 7:
    case 8:
        return rome2_l83_curl_doing_getsock(g, conn_va, socks, numsocks);
    case 9: {
        uint32_t fn_va = l83_rd32(
            ctx,
            l83_rd32(ctx, conn_va + ROME2_CURL_CONN_HANDLER_OFF) + ROME2_CURL_HANDLER_DOMORE_GETSOCK_OFF);
        return fn_va != 0u ? l83_getsock_cb(g, fn_va, conn_va, socks, numsocks) : 0u;
    }
    case 10:
    case 11:
    case 12:
        return rome2_l83_curl_single_getsock(g, conn_va, socks, numsocks);
    default:
        return 0u;
    }
}

/* Winsock FD_SET: append unless present or the set already holds 64 sockets. */
static void l83_fd_set_add(const rome2_l82_curl_ctx *ctx, uint32_t set_va, uint32_t fd) {
    rome2_curl_fd_set_32 *set = (rome2_curl_fd_set_32 *)rome2_l82_mut_ptr(ctx, set_va, (uint32_t)sizeof(*set));
    if (!set) {
        return;
    }
    uint32_t count = set->fd_count;
    uint32_t i = 0u;
    while (i < count && i < ROME2_CURL_FD_SETSIZE && set->fd_array[i] != fd) {
        i++;
    }
    if (i == count && count < ROME2_CURL_FD_SETSIZE) {
        set->fd_array[i] = fd;
        set->fd_count = count + 1u;
    }
}

/* 0x10f228f0: the exception set is never touched. The image's sockbunch is uninitialised; the model zero-fills it. */
int32_t rome2_l83_curl_multi_fdset(
    rome2_l83_curl_state *g,
    uint32_t multi_va,
    uint32_t read_fd_set_va,
    uint32_t write_fd_set_va,
    uint32_t exc_fd_set_va,
    int32_t *max_fd) {
    (void)exc_fd_set_va;
    if (!g) {
        return ROME2_CURLM_BAD_HANDLE;
    }
    const rome2_l82_curl_ctx *ctx = g->mem;
    if (multi_va == 0u || l83_rd32(ctx, multi_va) != ROME2_CURL_MULTI_MAGIC) {
        return ROME2_CURLM_BAD_HANDLE;
    }
    int32_t this_max_fd = -1;
    uint32_t sentinel_va = multi_va + (uint32_t)offsetof(rome2_curl_multi_prefix_32, easy);
    uint32_t easy_va = l83_rd32(ctx, sentinel_va);
    for (uint32_t guard = 0u; easy_va != sentinel_va && guard < ROME2_L83_WALK_CAP; ++guard) {
        uint32_t sockbunch[ROME2_CURL_MAX_SOCKSPEREASYHANDLE] = {0u, 0u, 0u, 0u, 0u};
        uint32_t bitmap = rome2_l83_multi_getsock(g, easy_va, sockbunch, ROME2_CURL_MAX_SOCKSPEREASYHANDLE);
        for (uint32_t i = 0u; i < ROME2_CURL_MAX_SOCKSPEREASYHANDLE; ++i) {
            uint32_t s = ROME2_CURL_SOCKET_BAD;
            if ((bitmap & (1u << i)) != 0u) {
                l83_fd_set_add(ctx, read_fd_set_va, sockbunch[i]);
                s = sockbunch[i];
            }
            if ((bitmap & (1u << (i + 16u))) != 0u) {
                l83_fd_set_add(ctx, write_fd_set_va, sockbunch[i]);
                s = sockbunch[i];
            }
            if (s == ROME2_CURL_SOCKET_BAD) {
                break;
            }
            if ((int32_t)s > this_max_fd) {
                this_max_fd = (int32_t)s;
            }
        }
        easy_va = l83_rd32(ctx, easy_va);
    }
    if (max_fd) {
        *max_fd = this_max_fd;
    }
    return ROME2_CURLM_OK;
}

/* 0x10f22a40: returns the queued message payload pointer */
uint32_t rome2_l83_curl_multi_info_read(
    rome2_l82_curl_ctx *ctx,
    uint32_t multi_va,
    int32_t *msgs_in_queue) {
    if (msgs_in_queue) {
        *msgs_in_queue = 0;
    }
    if (multi_va == 0u || l83_rd32(ctx, multi_va) != ROME2_CURL_MULTI_MAGIC) {
        return 0u;
    }
    uint32_t msglist_va = l83_rd32(ctx, multi_va + (uint32_t)offsetof(rome2_curl_multi_prefix_32, msglist_va));
    if (rome2_l83_curl_llist_count(ctx, msglist_va) == 0u) {
        return 0u;
    }
    uint32_t e_va = l83_rd32(ctx, msglist_va);
    uint32_t msg_va = l83_rd32(ctx, e_va);
    (void)rome2_l83_curl_llist_remove(ctx, msglist_va, e_va, 0u);
    if (msgs_in_queue) {
        *msgs_in_queue = rome2_l82_curlx_uztosi(rome2_l83_curl_llist_count(ctx, msglist_va));
    }
    return msg_va;
}

/* 0x10f22ef0 */
int32_t rome2_l83_curl_multi_setopt(
    rome2_l82_curl_ctx *ctx,
    uint32_t multi_va,
    int32_t option,
    uint32_t value) {
    rome2_curl_multi_prefix_32 *multi =
        (rome2_curl_multi_prefix_32 *)rome2_l82_mut_ptr(ctx, multi_va, (uint32_t)sizeof(*multi));
    if (!multi || multi->magic != ROME2_CURL_MULTI_MAGIC) {
        return ROME2_CURLM_BAD_HANDLE;
    }
    switch (option) {
    case ROME2_CURLMOPT_TIMERDATA:
        multi->timer_userp_va = value;
        return ROME2_CURLM_OK;
    case ROME2_CURLMOPT_PIPELINING:
        multi->pipelining = value != 0u ? 1u : 0u;
        return ROME2_CURLM_OK;
    case ROME2_CURLMOPT_MAXCONNECTS:
        multi->maxconnects = value;
        return ROME2_CURLM_OK;
    case ROME2_CURLMOPT_SOCKETDATA:
        multi->socket_userp_va = value;
        return ROME2_CURLM_OK;
    case ROME2_CURLMOPT_SOCKETFUNCTION:
        multi->socket_cb_va = value;
        return ROME2_CURLM_OK;
    case ROME2_CURLMOPT_TIMERFUNCTION:
        multi->timer_cb_va = value;
        return ROME2_CURLM_OK;
    default:
        return ROME2_CURLM_UNKNOWN_OPTION;
    }
}

/* 0x10f22760: no handle check; the looked-up entry's +0x18 slot takes the pointer */
int32_t rome2_l83_curl_multi_assign(
    rome2_l83_curl_state *g,
    uint32_t multi_va,
    uint32_t sockfd,
    uint32_t hashp_va) {
    if (!g || sockfd == ROME2_CURL_SOCKET_BAD) {
        return ROME2_CURLM_BAD_SOCKET;
    }
    uint32_t there_va = rome2_l83_curl_hash_pick(
        g,
        l83_rd32(g->mem, multi_va + (uint32_t)offsetof(rome2_curl_multi_prefix_32, sockhash_va)),
        &sockfd,
        4u);
    if (there_va == 0u) {
        return ROME2_CURLM_BAD_SOCKET;
    }
    l83_wr32(g->mem, there_va + (uint32_t)offsetof(rome2_curl_sh_entry_prefix_32, socketp_va), hashp_va);
    return ROME2_CURLM_OK;
}

static rome2_curl_tree_prefix_32 *l83_tree(const rome2_l82_curl_ctx *ctx, uint32_t va) {
    return (rome2_curl_tree_prefix_32 *)rome2_l82_mut_ptr(ctx, va, (uint32_t)sizeof(rome2_curl_tree_prefix_32));
}

static int32_t l83_tree_compare(rome2_curl_timeval_32 i, const rome2_curl_tree_prefix_32 *node) {
    if (i.tv_sec < node->key_sec) {
        return -1;
    }
    if (i.tv_sec > node->key_sec) {
        return 1;
    }
    if (i.tv_usec < node->key_usec) {
        return -1;
    }
    return i.tv_usec > node->key_usec ? 1 : 0;
}

/* 0x10f3d820: top-down splay; returns the new root in EAX */
uint32_t rome2_l83_curl_splay(rome2_l82_curl_ctx *ctx, rome2_curl_timeval_32 i, uint32_t t_va) {
    rome2_curl_tree_prefix_32 *t = l83_tree(ctx, t_va);
    if (!t) {
        return t_va;
    }
    uint32_t n_smaller = 0u; /* N.smaller: head of the right (larger) tree */
    uint32_t n_larger = 0u;  /* N.larger: head of the left (smaller) tree */
    rome2_curl_tree_prefix_32 *l = NULL; /* NULL stands for &N */
    rome2_curl_tree_prefix_32 *r = NULL;
    for (uint32_t guard = 0u; guard < ROME2_L83_WALK_CAP; ++guard) {
        int32_t comp = l83_tree_compare(i, t);
        if (comp < 0) {
            rome2_curl_tree_prefix_32 *y = l83_tree(ctx, t->smaller_va);
            if (!y) {
                break;
            }
            if (l83_tree_compare(i, y) < 0) {
                uint32_t y_va = t->smaller_va; /* rotate smaller */
                t->smaller_va = y->larger_va;
                y->larger_va = t_va;
                t = y;
                t_va = y_va;
            }
            rome2_curl_tree_prefix_32 *next = l83_tree(ctx, t->smaller_va);
            if (!next) {
                break;
            }
            if (r) { /* link smaller */
                r->smaller_va = t_va;
            } else {
                n_smaller = t_va;
            }
            r = t;
            t_va = t->smaller_va;
            t = next;
        } else if (comp > 0) {
            rome2_curl_tree_prefix_32 *y = l83_tree(ctx, t->larger_va);
            if (!y) {
                break;
            }
            if (l83_tree_compare(i, y) > 0) {
                uint32_t y_va = t->larger_va; /* rotate larger */
                t->larger_va = y->smaller_va;
                y->smaller_va = t_va;
                t = y;
                t_va = y_va;
            }
            rome2_curl_tree_prefix_32 *next = l83_tree(ctx, t->larger_va);
            if (!next) {
                break;
            }
            if (l) { /* link larger */
                l->larger_va = t_va;
            } else {
                n_larger = t_va;
            }
            l = t;
            t_va = t->larger_va;
            t = next;
        } else {
            break;
        }
    }
    if (l) { /* assemble */
        l->larger_va = t->smaller_va;
    } else {
        n_larger = t->smaller_va;
    }
    if (r) {
        r->smaller_va = t->larger_va;
    } else {
        n_smaller = t->larger_va;
    }
    t->smaller_va = n_larger;
    t->larger_va = n_smaller;
    return t_va;
}

/* 0x10f24450 */
int32_t rome2_l83_multi_timeout(
    rome2_l83_curl_state *g,
    uint32_t multi_va,
    int32_t *timeout_ms) {
    if (!g || !timeout_ms) {
        return ROME2_CURLM_OK;
    }
    rome2_l82_curl_ctx *ctx = g->mem;
    rome2_curl_multi_prefix_32 *multi =
        (rome2_curl_multi_prefix_32 *)rome2_l82_mut_ptr(ctx, multi_va, (uint32_t)sizeof(*multi));
    if (!multi) {
        return ROME2_CURLM_OK;
    }
    if (multi->timetree_va == 0u) {
        *timeout_ms = -1;
        return ROME2_CURLM_OK;
    }
    rome2_curl_timeval_32 now = rome2_l83_curlx_tvnow(g);
    multi->timetree_va = rome2_l83_curl_splay(ctx, g->tv_zero, multi->timetree_va);
    const rome2_curl_tree_prefix_32 *root = l83_tree(ctx, multi->timetree_va);
    *timeout_ms = 0;
    if (root && l83_tree_compare(now, root) < 0) {
        rome2_curl_timeval_32 key;
        key.tv_sec = root->key_sec;
        key.tv_usec = root->key_usec;
        int32_t diff = rome2_l83_curlx_tvdiff(key, now);
        *timeout_ms = diff != 0 ? diff : 1;
    }
    return ROME2_CURLM_OK;
}

/* 0x10f23030: tail-jumps to 0x10f24450 for a live handle */
int32_t rome2_l83_curl_multi_timeout(
    rome2_l83_curl_state *g,
    uint32_t multi_va,
    int32_t *timeout_ms) {
    if (!g || multi_va == 0u || l83_rd32(g->mem, multi_va) != ROME2_CURL_MULTI_MAGIC) {
        return ROME2_CURLM_BAD_HANDLE;
    }
    return rome2_l83_multi_timeout(g, multi_va, timeout_ms);
}

/* 0x10f40670 */
uint32_t rome2_l83_form_memdup(rome2_l82_curl_ctx *ctx, uint32_t src_va, uint32_t len) {
    uint32_t add = 0u;
    if (len == 0u) {
        if (src_va == 0u) {
            return rome2_l82_strdup_va(ctx, ""); /* strdup(0x1173dad0) */
        }
        if (!l83_cstr(ctx, src_va, &len)) {
            return 0u;
        }
        add = 1u;
    }
    uint32_t dst_va = rome2_l82_alloc(ctx, len + add);
    if (dst_va == 0u) {
        return 0u;
    }
    l83_copy(ctx, dst_va, src_va, len);
    if (add != 0u) {
        uint8_t *terminator = (uint8_t *)rome2_l82_mut_ptr(ctx, dst_va + len, 1u);
        if (terminator) {
            *terminator = 0u;
        }
    }
    return dst_va;
}

static void l83_formfree(rome2_l82_curl_ctx *ctx, uint32_t form_va, uint32_t depth) {
    for (uint32_t guard = 0u; form_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_httppost_32 *form =
            (const rome2_curl_httppost_32 *)rome2_l82_const_ptr(ctx, form_va, (uint32_t)sizeof(*form));
        if (!form) {
            return;
        }
        uint32_t next_va = form->next_va;
        if (form->more_va != 0u && depth < 256u) {
            l83_formfree(ctx, form->more_va, depth + 1u);
        }
        if ((form->flags & ROME2_HTTPPOST_PTRNAME) == 0u && form->name_va != 0u) {
            rome2_l82_curl_free(ctx, form->name_va);
        }
        if ((form->flags & (ROME2_HTTPPOST_PTRCONTENTS | ROME2_HTTPPOST_BUFFER | ROME2_HTTPPOST_CALLBACK)) == 0u &&
            form->contents_va != 0u) {
            rome2_l82_curl_free(ctx, form->contents_va);
        }
        if (form->contenttype_va != 0u) {
            rome2_l82_curl_free(ctx, form->contenttype_va);
        }
        if (form->showfilename_va != 0u) {
            rome2_l82_curl_free(ctx, form->showfilename_va);
        }
        rome2_l82_curl_free(ctx, form_va);
        form_va = next_va;
    }
}

/* 0x10f40410: recurses through `more`; the model stops recursing 256 levels deep */
void rome2_l83_curl_formfree(rome2_l82_curl_ctx *ctx, uint32_t form_va) {
    l83_formfree(ctx, form_va, 0u);
}

static rome2_curl_forminfo_32 *l83_forminfo(const rome2_l82_curl_ctx *ctx, uint32_t va) {
    return (rome2_curl_forminfo_32 *)rome2_l82_mut_ptr(ctx, va, (uint32_t)sizeof(rome2_curl_forminfo_32));
}

/* Release every field a FormInfo chain owns, starting at form_va. */
static void l83_form_free_allocs(rome2_l82_curl_ctx *ctx, uint32_t form_va) {
    for (uint32_t guard = 0u; guard < ROME2_L83_WALK_CAP; ++guard) {
        rome2_curl_forminfo_32 *form = l83_forminfo(ctx, form_va);
        if (!form) {
            return;
        }
        if (form->name_alloc != 0u) {
            rome2_l82_curl_free(ctx, form->name_va);
            form->name_va = 0u;
            form->name_alloc = 0u;
        }
        if (form->value_alloc != 0u) {
            rome2_l82_curl_free(ctx, form->value_va);
            form->value_va = 0u;
            form->value_alloc = 0u;
        }
        if (form->contenttype_alloc != 0u) {
            rome2_l82_curl_free(ctx, form->contenttype_va);
            form->contenttype_va = 0u;
            form->contenttype_alloc = 0u;
        }
        if (form->showfilename_alloc != 0u) {
            rome2_l82_curl_free(ctx, form->showfilename_va);
            form->showfilename_va = 0u;
            form->showfilename_alloc = 0u;
        }
        form_va = form->more_va;
    }
}

/* Inlined ContentTypeForFilename: suffix match against the 0x118465b0 table. */
static const char *l83_content_type_for_filename(
    rome2_l82_curl_ctx *ctx,
    uint32_t filename_va,
    uint32_t prevtype_va) {
    const char *prevtype = l83_cstr(ctx, prevtype_va, NULL);
    const char *contenttype = prevtype ? prevtype : "application/octet-stream"; /* 0x1184664c */
    uint32_t filename_len = 0u;
    const char *filename = l83_cstr(ctx, filename_va, &filename_len);
    if (!filename) {
        return contenttype;
    }
    for (size_t i = 0u; i < sizeof(rome2_l83_content_types) / sizeof(rome2_l83_content_types[0]); ++i) {
        size_t extension_len = strlen(rome2_l83_content_types[i].extension);
        if (extension_len <= filename_len &&
            rome2_l82_curl_strequal(
                ctx,
                filename + filename_len - extension_len,
                rome2_l83_content_types[i].extension) != 0u) {
            return rome2_l83_content_types[i].type;
        }
    }
    return contenttype;
}

typedef struct l83_form_args {
    const uint32_t *args;
    uint32_t count;
    uint32_t pos;
    uint8_t exhausted;
} l83_form_args;

static uint32_t l83_form_arg(l83_form_args *va) {
    if (!va->args || va->pos >= va->count) {
        va->exhausted = 1u;
        return 0u;
    }
    return va->args[va->pos++];
}

/* A second CURLFORM_FILE / CURLFORM_CONTENTTYPE on a file part chains a new FormInfo behind the current one. */
static rome2_curl_forminfo_32 *l83_form_add_info(
    rome2_l82_curl_ctx *ctx,
    rome2_curl_forminfo_32 *parent,
    uint32_t dup_va,
    uint8_t is_contenttype) {
    uint32_t info_va = rome2_l82_calloc(ctx, 1u, (uint32_t)sizeof(rome2_curl_forminfo_32));
    rome2_curl_forminfo_32 *info = l83_forminfo(ctx, info_va);
    if (!info) {
        return NULL;
    }
    if (is_contenttype) {
        info->contenttype_va = dup_va;
        info->contenttype_alloc = 1u;
    } else {
        info->value_va = dup_va;
        info->value_alloc = 1u;
    }
    info->flags = ROME2_HTTPPOST_FILENAME;
    info->more_va = parent->more_va;
    parent->more_va = info_va;
    return info;
}

/* 0x10f3fb40 */
int32_t rome2_l83_form_add(
    rome2_l82_curl_ctx *ctx,
    uint32_t httppost_slot_va,
    uint32_t last_post_slot_va,
    const uint32_t *args,
    uint32_t arg_count) {
    uint32_t first_va = rome2_l82_calloc(ctx, 1u, (uint32_t)sizeof(rome2_curl_forminfo_32));
    rome2_curl_forminfo_32 *current = l83_forminfo(ctx, first_va);
    if (!current) {
        return ROME2_CURL_FORMADD_MEMORY;
    }
    l83_form_args va = {args, arg_count, 0u, 0u};
    int32_t rc = ROME2_CURL_FORMADD_OK;
    uint8_t array_state = 0u;
    uint32_t forms_va = 0u;
    uint32_t array_value = 0u;

    while (rc == ROME2_CURL_FORMADD_OK) {
        uint32_t option;
        if (array_state != 0u) {
            const uint32_t *pair = (const uint32_t *)rome2_l82_const_ptr(ctx, forms_va, 8u);
            if (!pair) {
                rc = ROME2_L83_FORMADD_ARGS_EXHAUSTED;
                break;
            }
            option = pair[0];
            array_value = pair[1];
            forms_va += 8u;
            if (option == ROME2_CURLFORM_END) {
                array_state = 0u;
                continue;
            }
        } else {
            option = l83_form_arg(&va);
            if (va.exhausted != 0u) {
                rc = ROME2_L83_FORMADD_ARGS_EXHAUSTED;
                break;
            }
            if (option == ROME2_CURLFORM_END) {
                break;
            }
        }
        uint32_t value;
        switch (option) {
        case ROME2_CURLFORM_COPYNAME:
        case ROME2_CURLFORM_PTRNAME:
            if (option == ROME2_CURLFORM_PTRNAME) {
                current->flags |= ROME2_HTTPPOST_PTRNAME;
            }
            if (current->name_va != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
                break;
            }
            value = array_state != 0u ? array_value : l83_form_arg(&va);
            if (value == 0u) {
                rc = ROME2_CURL_FORMADD_NULL;
            } else {
                current->name_va = value;
            }
            break;
        case ROME2_CURLFORM_NAMELENGTH:
            if (current->namelength != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
            } else {
                current->namelength = array_state != 0u ? array_value : l83_form_arg(&va);
            }
            break;
        case ROME2_CURLFORM_COPYCONTENTS:
        case ROME2_CURLFORM_PTRCONTENTS:
            if (option == ROME2_CURLFORM_PTRCONTENTS) {
                current->flags |= ROME2_HTTPPOST_PTRCONTENTS;
            }
            if (current->value_va != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
                break;
            }
            value = array_state != 0u ? array_value : l83_form_arg(&va);
            if (value == 0u) {
                rc = ROME2_CURL_FORMADD_NULL;
            } else {
                current->value_va = value;
            }
            break;
        case ROME2_CURLFORM_CONTENTSLENGTH:
            if (current->contentslength != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
            } else {
                current->contentslength = array_state != 0u ? array_value : l83_form_arg(&va);
            }
            break;
        case ROME2_CURLFORM_FILECONTENT:
            if (current->flags != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
                break;
            }
            value = array_state != 0u ? array_value : l83_form_arg(&va);
            if (value == 0u) {
                rc = ROME2_CURL_FORMADD_NULL;
                break;
            }
            current->value_va = l83_strdup(ctx, value);
            if (current->value_va == 0u) {
                rc = ROME2_CURL_FORMADD_MEMORY;
            } else {
                current->flags |= ROME2_HTTPPOST_READFILE;
                current->value_alloc = 1u;
            }
            break;
        case ROME2_CURLFORM_ARRAY:
            if (array_state != 0u) {
                rc = ROME2_CURL_FORMADD_ILLEGAL_ARRAY;
                break;
            }
            forms_va = l83_form_arg(&va);
            if (forms_va == 0u) {
                rc = ROME2_CURL_FORMADD_NULL;
            } else {
                array_state = 1u;
            }
            break;
        case ROME2_CURLFORM_FILE:
        case ROME2_CURLFORM_CONTENTTYPE: {
            uint8_t is_contenttype = option == ROME2_CURLFORM_CONTENTTYPE ? 1u : 0u;
            uint32_t *slot = is_contenttype ? &current->contenttype_va : &current->value_va;
            value = array_state != 0u ? array_value : l83_form_arg(&va);
            if (*slot == 0u) {
                if (value == 0u) {
                    rc = ROME2_CURL_FORMADD_NULL;
                    break;
                }
                *slot = l83_strdup(ctx, value);
                if (*slot == 0u) {
                    rc = ROME2_CURL_FORMADD_MEMORY;
                } else if (is_contenttype) {
                    current->contenttype_alloc = 1u;
                } else {
                    current->flags |= ROME2_HTTPPOST_FILENAME;
                    current->value_alloc = 1u;
                }
                break;
            }
            if ((current->flags & ROME2_HTTPPOST_FILENAME) == 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
                break;
            }
            if (value == 0u) {
                rc = ROME2_CURL_FORMADD_NULL;
                break;
            }
            uint32_t dup_va = l83_strdup(ctx, value);
            if (dup_va == 0u) {
                rc = ROME2_CURL_FORMADD_MEMORY;
                break;
            }
            rome2_curl_forminfo_32 *added = l83_form_add_info(ctx, current, dup_va, is_contenttype);
            if (!added) {
                rome2_l82_curl_free(ctx, dup_va);
                rc = ROME2_CURL_FORMADD_MEMORY;
            } else {
                current = added;
            }
            break;
        }
        case ROME2_CURLFORM_BUFFER:
        case ROME2_CURLFORM_FILENAME:
            value = array_state != 0u ? array_value : l83_form_arg(&va);
            if (current->showfilename_va != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
                break;
            }
            current->showfilename_va = l83_strdup(ctx, value);
            if (current->showfilename_va == 0u) {
                rc = ROME2_CURL_FORMADD_MEMORY;
            } else {
                current->showfilename_alloc = 1u;
            }
            break;
        case ROME2_CURLFORM_BUFFERPTR:
            current->flags |= ROME2_HTTPPOST_PTRBUFFER | ROME2_HTTPPOST_BUFFER;
            if (current->buffer_va != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
                break;
            }
            value = array_state != 0u ? array_value : l83_form_arg(&va);
            if (value == 0u) {
                rc = ROME2_CURL_FORMADD_NULL;
            } else {
                current->buffer_va = value;
                current->value_va = value;
            }
            break;
        case ROME2_CURLFORM_BUFFERLENGTH:
            if (current->bufferlength != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
            } else {
                current->bufferlength = array_state != 0u ? array_value : l83_form_arg(&va);
            }
            break;
        case ROME2_CURLFORM_CONTENTHEADER:
            value = array_state != 0u ? array_value : l83_form_arg(&va);
            if (current->contentheader_va != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
            } else {
                current->contentheader_va = value;
            }
            break;
        case ROME2_CURLFORM_STREAM:
            current->flags |= ROME2_HTTPPOST_CALLBACK;
            if (current->userp_va != 0u) {
                rc = ROME2_CURL_FORMADD_OPTION_TWICE;
                break;
            }
            value = array_state != 0u ? array_value : l83_form_arg(&va);
            if (value == 0u) {
                rc = ROME2_CURL_FORMADD_NULL;
            } else {
                current->userp_va = value;
                current->value_va = value;
            }
            break;
        default:
            rc = ROME2_CURL_FORMADD_UNKNOWN_OPTION;
            break;
        }
        if (va.exhausted != 0u) {
            rc = ROME2_L83_FORMADD_ARGS_EXHAUSTED;
        }
    }

    uint32_t form_va = first_va;
    if (rc != ROME2_CURL_FORMADD_OK) {
        l83_form_free_allocs(ctx, first_va);
        form_va = 0u;
    }
    uint32_t prev_post_va = 0u;
    uint32_t prevtype_va = 0u;
    for (uint32_t guard = 0u; form_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        rome2_curl_forminfo_32 *form = l83_forminfo(ctx, form_va);
        if (!form) {
            break;
        }
        uint32_t flags = form->flags;
        if (((form->name_va == 0u || form->value_va == 0u) && prev_post_va == 0u) ||
            (form->contentslength != 0u && (flags & ROME2_HTTPPOST_FILENAME) != 0u) ||
            (flags & 0x09u) == 0x09u ||
            (form->buffer_va == 0u && (flags & 0x30u) == 0x30u) ||
            (flags & 0x0au) == 0x0au) {
            rc = ROME2_CURL_FORMADD_INCOMPLETE;
            break;
        }
        if ((flags & (ROME2_HTTPPOST_FILENAME | ROME2_HTTPPOST_BUFFER)) != 0u && form->contenttype_va == 0u) {
            form->contenttype_va = rome2_l82_strdup_va(
                ctx,
                l83_content_type_for_filename(ctx, form->value_va, prevtype_va));
            if (form->contenttype_va == 0u) {
                rc = ROME2_CURL_FORMADD_MEMORY;
                break;
            }
            form->contenttype_alloc = 1u;
        }
        if ((flags & ROME2_HTTPPOST_PTRNAME) == 0u && form_va == first_va) {
            if (form->name_va != 0u) {
                form->name_va = rome2_l83_form_memdup(ctx, form->name_va, form->namelength);
            }
            if (form->name_va == 0u) {
                rc = ROME2_CURL_FORMADD_MEMORY;
                break;
            }
            form->name_alloc = 1u;
        }
        if ((flags & 0x6bu) == 0u) {
            form->value_va = rome2_l83_form_memdup(ctx, form->value_va, form->contentslength);
            if (form->value_va == 0u) {
                rc = ROME2_CURL_FORMADD_MEMORY;
                break;
            }
            form->value_alloc = 1u;
        }
        uint32_t post_va = rome2_l82_calloc(ctx, 1u, (uint32_t)sizeof(rome2_curl_httppost_32));
        rome2_curl_httppost_32 *post =
            (rome2_curl_httppost_32 *)rome2_l82_mut_ptr(ctx, post_va, (uint32_t)sizeof(*post));
        if (!post) {
            rc = ROME2_CURL_FORMADD_MEMORY;
            break;
        }
        uint32_t namelength = form->namelength;
        if (form->name_va == 0u) {
            namelength = 0u;
        } else if (namelength == 0u) {
            (void)l83_cstr(ctx, form->name_va, &namelength);
        }
        post->name_va = form->name_va;
        post->namelength = namelength;
        post->contents_va = form->value_va;
        post->contentslength = form->contentslength;
        post->buffer_va = form->buffer_va;
        post->bufferlength = form->bufferlength;
        post->contenttype_va = form->contenttype_va;
        post->contentheader_va = form->contentheader_va;
        post->showfilename_va = form->showfilename_va;
        post->userp_va = form->userp_va;
        post->flags = flags;
        if (prev_post_va == 0u) {
            uint32_t last_va = l83_rd32(ctx, last_post_slot_va);
            l83_wr32(ctx, last_va != 0u ? last_va : httppost_slot_va, post_va); /* (*last_post)->next or *httppost */
            l83_wr32(ctx, last_post_slot_va, post_va);
        } else {
            uint32_t prev_more_va = prev_post_va + (uint32_t)offsetof(rome2_curl_httppost_32, more_va);
            post->more_va = l83_rd32(ctx, prev_more_va);
            l83_wr32(ctx, prev_more_va, post_va);
        }
        if (form->contenttype_va != 0u) {
            prevtype_va = form->contenttype_va;
        }
        prev_post_va = post_va;
        form_va = form->more_va;
    }
    if (rc != ROME2_CURL_FORMADD_OK && form_va != 0u) {
        l83_form_free_allocs(ctx, form_va);
    }

    form_va = first_va;
    for (uint32_t guard = 0u; guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_forminfo_32 *form = l83_forminfo(ctx, form_va);
        if (!form) {
            break;
        }
        uint32_t more_va = form->more_va;
        rome2_l82_curl_free(ctx, form_va);
        form_va = more_va;
    }
    return rc;
}

/* 0x10f403f0: forwards the address of its first variadic argument as the va_list */
int32_t rome2_l83_curl_formadd(
    rome2_l82_curl_ctx *ctx,
    uint32_t httppost_slot_va,
    uint32_t last_post_slot_va,
    const uint32_t *args,
    uint32_t arg_count) {
    return rome2_l83_form_add(ctx, httppost_slot_va, last_post_slot_va, args, arg_count);
}
