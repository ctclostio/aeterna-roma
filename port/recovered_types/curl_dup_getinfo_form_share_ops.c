#include "curl_dup_getinfo_form_share_ops.h"

#include "startup_stdio_stream_ops.h"
#include "startup_sysinfo_vsprintf_ops.h"
#include "vfs_fs_engine_crt_strtox_ops.h"

#include <string.h>

const rome2_l83_openssl_thunk_desc rome2_l86_openssl_thunks[ROME2_L86_OPENSSL_THUNK_COUNT] = {
    {0x116c7f0fu, 0x1172f604u, 8u, 1u},
    {0x116c7f81u, 0x1172f57cu, 48u, 1u},
    {0x116c7fc9u, 0x1172f5acu, 96u, 1u},
    {0x116c7fcfu, 0x1172f5b0u, 86u, 1u}
};

/* connectdata string slots conn_free (inlined in 0x10f17fd0) releases and clears, in image order. */
static const uint16_t l86_conn_free_offsets[] = {
    0x104u, 0x108u, 0x10cu, 0x110u, 0x248u, 0x24cu, 0x254u, 0x250u, 0x26cu,
    0x258u, 0x25cu, 0x260u, 0x264u, 0x268u, 0x3e4u, 0x078u, 0x088u, 0x290u
};

/* Curl_getinfo CURLINFO_LONG arms that copy one SessionHandle dword: {info, offset}. */
static const uint32_t l86_getinfo_long[][2] = {
    {0x200002u, 0x86e4u}, {0x20000bu, 0x86f8u}, {0x20000cu, 0x86fcu}, {0x20000du, 0x025cu},
    {0x20000eu, 0x86f0u}, {0x200014u, 0x0154u}, {0x200016u, 0x86e8u}, {0x200017u, 0x8704u},
    {0x200018u, 0x8700u}, {0x200019u, 0x85c4u}, {0x20001au, 0x8708u}, {0x200023u, 0x86f4u},
    {0x200025u, 0x86b0u}, {0x200026u, 0x86b4u}, {0x200027u, 0x86b8u}, {0x200028u, 0x8744u},
    {0x20002au, 0x8778u}
};

/* Curl_getinfo CURLINFO_STRING arms that copy one SessionHandle pointer: {info, offset}. */
static const uint32_t l86_getinfo_string[][2] = {
    {0x100012u, 0x870cu}, {0x100015u, 0x02a4u}, {0x10001eu, 0x8670u}, {0x10001fu, 0x8710u},
    {0x100024u, 0x03fcu}
};

/* Curl_getinfo CURLINFO_DOUBLE arms that copy one stored double: {info, offset}. */
static const uint32_t l86_getinfo_double[][2] = {
    {0x300003u, 0x04b0u}, {0x300004u, 0x04c8u}, {0x300005u, 0x04d0u}, {0x300006u, 0x04e0u},
    {0x300011u, 0x04e8u}, {0x300013u, 0x04f0u}, {0x300021u, 0x04d8u}
};

/* Curl_getinfo CURLINFO_DOUBLE arms that convert a 64-bit count: {info, offset, required progress flag}. */
static const uint32_t l86_getinfo_off_t[][3] = {
    {0x300007u, 0x0490u, 0u}, {0x300008u, 0x0488u, 0u}, {0x300009u, 0x04b8u, 0u},
    {0x30000au, 0x04c0u, 0u}, {0x30000fu, 0x0478u, ROME2_L86_PGRS_DL_SIZE_KNOWN},
    {0x300010u, 0x0480u, ROME2_L86_PGRS_UL_SIZE_KNOWN}
};

static uint32_t l86_rd32(const rome2_l82_curl_ctx *ctx, uint32_t va) {
    const void *p = rome2_l82_const_ptr(ctx, va, 4u);
    uint32_t v = 0u;
    if (p) {
        memcpy(&v, p, 4u);
    }
    return v;
}

static void l86_wr32(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t v) {
    void *p = rome2_l82_mut_ptr(ctx, va, 4u);
    if (p) {
        memcpy(p, &v, 4u);
    }
}

static void l86_copy(const rome2_l82_curl_ctx *ctx, uint32_t dst_va, uint32_t src_va, uint32_t bytes) {
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
static char *l86_mstr(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t *len_out) {
    if (!ctx || !ctx->arena_bytes || va < ctx->arena_base_va) {
        return NULL;
    }
    uint32_t off = va - ctx->arena_base_va;
    if (off >= ctx->arena_size) {
        return NULL;
    }
    char *str = (char *)ctx->arena_bytes + off;
    const char *nul = (const char *)memchr(str, 0, ctx->arena_size - off);
    if (!nul) {
        return NULL;
    }
    if (len_out) {
        *len_out = (uint32_t)(nul - str);
    }
    return str;
}

static const char *l86_cstr(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t *len_out) {
    return l86_mstr(ctx, va, len_out);
}

static uint32_t l86_strdup(rome2_l82_curl_ctx *ctx, uint32_t src_va) {
    return rome2_l82_strdup_va(ctx, l86_cstr(ctx, src_va, NULL));
}

static void l86_free_if_set(rome2_l82_curl_ctx *ctx, uint32_t ptr_va) {
    if (ptr_va != 0u) {
        rome2_l82_curl_free(ctx, ptr_va);
    }
}

/* Curl_safefree on a pointer slot: free and clear when set. */
static void l86_safefree(rome2_l82_curl_ctx *ctx, uint32_t slot_va) {
    uint32_t ptr_va = l86_rd32(ctx, slot_va);
    if (ptr_va != 0u) {
        rome2_l82_curl_free(ctx, ptr_va);
        l86_wr32(ctx, slot_va, 0u);
    }
}

/* strstore: release the old string, then strdup the new one into the slot. */
static uint32_t l86_strstore(rome2_l82_curl_ctx *ctx, uint32_t *slot, const char *text) {
    if (*slot != 0u) {
        rome2_l82_curl_free(ctx, *slot);
    }
    *slot = rome2_l82_strdup_va(ctx, text);
    return *slot;
}

static uint32_t l86_text_len(const char *buf, uint32_t cap) {
    const char *nul = (const char *)memchr(buf, 0, cap);
    return nul ? (uint32_t)(nul - buf) : cap - 1u;
}

static uint8_t l86_isblank(char ch) {
    return (ch == ' ' || ch == '\t') ? 1u : 0u;
}

static rome2_l82_curl_ctx *l86_ctx(const rome2_l86_curl_state *s) {
    return (s && s->g) ? s->g->mem : NULL;
}

static rome2_curl_cookie_32 *l86_cookie(const rome2_l82_curl_ctx *ctx, uint32_t va) {
    return (rome2_curl_cookie_32 *)rome2_l82_mut_ptr(ctx, va, (uint32_t)sizeof(rome2_curl_cookie_32));
}

static rome2_curl_formdata_32 *l86_formdata(const rome2_l82_curl_ctx *ctx, uint32_t va) {
    return (rome2_curl_formdata_32 *)rome2_l82_mut_ptr(ctx, va, (uint32_t)sizeof(rome2_curl_formdata_32));
}

static uint32_t l86_fopen(rome2_l86_curl_state *s, const char *path, const char *mode) {
    return (s->on_fopen && path) ? s->on_fopen(s, path, mode) : 0u;
}

static void l86_fclose(rome2_l86_curl_state *s, uint32_t stream_va) {
    if (s->on_fclose) {
        (void)s->on_fclose(s, stream_va);
    }
}

void rome2_l86_state_init(rome2_l86_curl_state *s, rome2_l83_curl_state *g) {
    if (!s) {
        return;
    }
    memset(s, 0, sizeof(*s));
    s->g = g;
    s->stdin_va = ROME2_L83_CRT_IOB_BASE_VA;
}

/*
 * 0x11683da0: EDX:ECX as a signed 64-bit count to double. The low dword is
 * converted signed and corrected by [0x1190bb38 + sign * 8] (0.0 or 2^32),
 * then the signed high dword times [0x1190bb40] (2^32) is added.
 */
double rome2_l86_crt_ltod3(uint32_t lo, int32_t hi) {
    static const double low_fix[2] = {0.0, 4294967296.0};
    double high = (double)hi;
    double low = (double)(int32_t)lo;
    high *= 4294967296.0;
    low += low_fix[lo >> 31];
    low += high;
    return low;
}

/* 0x1168ebe6: fread_s(buffer, SIZE_MAX, element_size, count, stream) */
uint32_t rome2_l86_crt_fread(
    rome2_l86_curl_state *s,
    uint8_t *buffer,
    uint32_t element_size,
    uint32_t count,
    uint32_t stream_va) {
    if (!s || !s->on_fread_s) {
        return 0u;
    }
    return s->on_fread_s(s, buffer, 0xffffffffu, element_size, count, stream_va);
}

/* 0x1169ece3. A stream or read pointer outside the arena reads as end of file. */
int32_t rome2_l86_crt_fgetc_nolock(rome2_l86_curl_state *s, uint32_t stream_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return ROME2_L86_CRT_EOF;
    }
    if (stream_va == 0u) {
        ctx->last_errno = ROME2_L86_CRT_EINVAL;
        s->g->invalid_parameter_calls++;
        return ROME2_L86_CRT_EOF;
    }
    rome2_crt_stream_prefix_32 *stream =
        (rome2_crt_stream_prefix_32 *)rome2_l82_mut_ptr(ctx, stream_va, (uint32_t)sizeof(*stream));
    if (!stream) {
        return ROME2_L86_CRT_EOF;
    }
    stream->cnt = (int32_t)((uint32_t)stream->cnt - 1u);
    if (stream->cnt < 0) {
        return s->on_stream_refill ? s->on_stream_refill(s, stream_va) : ROME2_L86_CRT_EOF;
    }
    const uint8_t *p = (const uint8_t *)rome2_l82_const_ptr(ctx, stream->ptr_va, 1u);
    if (!p) {
        return ROME2_L86_CRT_EOF;
    }
    stream->ptr_va += 1u;
    return (int32_t)*p;
}

/* 0x1169ed1f: frame stub that tail-jumps to 0x1169ece3 */
int32_t rome2_l86_crt_fgetc_nolock_stub(rome2_l86_curl_state *s, uint32_t stream_va) {
    return rome2_l86_crt_fgetc_nolock(s, stream_va);
}

/* 0x1168eed4: the __finally funclet of 0x1168ee1c */
void rome2_l86_crt_fgets_unlock_funclet(rome2_l86_curl_state *s, uint32_t stream_va) {
    (void)stream_va;
    if (s) {
        s->unlock_file_calls++;
    }
}

/* 0x1168ee1c. A destination outside the arena ends the read with no result. */
uint32_t rome2_l86_crt_common_fgets(
    rome2_l86_curl_state *s,
    uint32_t buf_va,
    int32_t count,
    uint32_t stream_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return 0u;
    }
    if ((buf_va == 0u && count != 0) || count < 0 || stream_va == 0u) {
        ctx->last_errno = ROME2_L86_CRT_EINVAL;
        s->g->invalid_parameter_calls++;
        return 0u;
    }
    if (count == 0) {
        return 0u;
    }
    uint32_t result = 0u;
    s->lock_file_calls++;
    if ((s->on_stream_is_ansi ? s->on_stream_is_ansi(s, stream_va) : 1u) != 0u) {
        uint32_t p_va = buf_va;
        uint8_t store = 1u;
        for (int32_t i = 1; i != count; ++i) {
            int32_t ch = rome2_l86_crt_fgetc_nolock_stub(s, stream_va);
            if (ch == ROME2_L86_CRT_EOF) {
                store = (p_va != buf_va) ? 1u : 0u;
                break;
            }
            uint8_t *dst = (uint8_t *)rome2_l82_mut_ptr(ctx, p_va, 1u);
            if (!dst) {
                store = 0u;
                break;
            }
            *dst = (uint8_t)ch;
            p_va++;
            if ((uint8_t)ch == (uint8_t)'\n') {
                break;
            }
        }
        uint8_t *end = store != 0u ? (uint8_t *)rome2_l82_mut_ptr(ctx, p_va, 1u) : NULL;
        if (end) {
            *end = 0u;
            result = buf_va;
        }
    }
    rome2_l86_crt_fgets_unlock_funclet(s, stream_va);
    return result;
}

/* 0x1168eede: frame stub that tail-jumps to 0x1168ee1c */
uint32_t rome2_l86_crt_fgets(
    rome2_l86_curl_state *s,
    uint32_t buf_va,
    int32_t count,
    uint32_t stream_va) {
    return rome2_l86_crt_common_fgets(s, buf_va, count, stream_va);
}

/* 0x1169de5f: parse_integer<unsigned __int64> (0x1168dc34) over a C string source, signed */
int64_t rome2_l86_crt_strtoi64(
    rome2_l86_curl_state *s,
    const char *str,
    const char **endptr,
    int32_t radix) {
    int32_t parse_errno = 0;
    uint64_t value = rome2_vfs_crt_parse_uint64_cstr(str, endptr, radix, 1u, &parse_errno);
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (parse_errno != 0 && ctx) {
        ctx->last_errno = parse_errno;
    }
    return (int64_t)value;
}

/* 0x10f1ed80: one seed * 1103515245 + 12345 step, returning the seed rotated by 16 bits */
uint32_t rome2_l86_curl_rand(rome2_l83_curl_state *g) {
    if (!g) {
        return 0u;
    }
    uint32_t seed = g->randseed * ROME2_L86_RAND_MUL + ROME2_L86_RAND_ADD;
    g->randseed = seed;
    return (seed << 16) | (seed >> 16);
}

/* 0x10f20900 */
char *rome2_l86_curl_strtok_r(char *ptr, const char *sep, char **end) {
    if (!sep || !end) {
        return NULL;
    }
    if (!ptr) {
        ptr = *end;
    }
    if (!ptr) {
        return NULL;
    }
    while (*ptr != '\0' && strchr(sep, *ptr) != NULL) {
        ptr++;
    }
    if (*ptr == '\0') {
        return NULL;
    }
    *end = ptr + 1;
    while (**end != '\0' && strchr(sep, **end) == NULL) {
        (*end)++;
    }
    if (**end != '\0') {
        **end = '\0';
        (*end)++;
    }
    return ptr;
}

/* 0x10f20dd0: the first operand's a..z fold is the 26-entry table at 0x10f20ecc, the second's is 0x10f20f40 */
int32_t rome2_l86_curl_raw_nequal(const char *first, const char *second, uint32_t max) {
    if (!first || !second) {
        return 0;
    }
    while (*first != '\0' && *second != '\0') {
        if (max == 0u) {
            return 1;
        }
        char upper = (*first >= 'a' && *first <= 'z') ? (char)(*first - ('a' - 'A')) : *first;
        if (upper != rome2_l82_curl_raw_toupper(*second)) {
            break;
        }
        first++;
        max--;
        second++;
    }
    if (max == 0u) {
        return 1;
    }
    return rome2_l82_curl_raw_toupper(*first) == rome2_l82_curl_raw_toupper(*second) ? 1 : 0;
}

/* 0x10f21130 */
const void *rome2_l86_curl_memrchr(const void *s, int32_t c, uint32_t n) {
    const uint8_t *base = (const uint8_t *)s;
    if (!base || n == 0u) {
        return NULL;
    }
    for (uint32_t i = n; i != 0u; --i) {
        if (base[i - 1u] == (uint8_t)c) {
            return base + (i - 1u);
        }
    }
    return NULL;
}

/* 0x10f21150 */
uint32_t rome2_l86_curl_llist_alloc(rome2_l82_curl_ctx *ctx, uint32_t dtor_va) {
    uint32_t list_va = rome2_l82_alloc(ctx, (uint32_t)sizeof(rome2_curl_llist_32));
    rome2_curl_llist_32 *list =
        (rome2_curl_llist_32 *)rome2_l82_mut_ptr(ctx, list_va, (uint32_t)sizeof(*list));
    if (list_va == 0u || !list) {
        return 0u;
    }
    list->dtor_fn_va = dtor_va;
    list->size = 0u;
    list->head_va = 0u;
    list->tail_va = 0u;
    return list_va;
}

/* 0x10f122e0: a negative slot count whose table allocation succeeds returns the hash with no bucket lists */
uint32_t rome2_l86_curl_hash_alloc(
    rome2_l82_curl_ctx *ctx,
    int32_t slots,
    uint32_t hfunc_va,
    uint32_t comp_va,
    uint32_t dtor_va) {
    if (slots == 0 || hfunc_va == 0u || comp_va == 0u || dtor_va == 0u) {
        return 0u;
    }
    uint32_t h_va = rome2_l82_alloc(ctx, (uint32_t)sizeof(rome2_curl_hash_32));
    rome2_curl_hash_32 *h = (rome2_curl_hash_32 *)rome2_l82_mut_ptr(ctx, h_va, (uint32_t)sizeof(*h));
    if (h_va == 0u || !h) {
        return 0u;
    }
    h->dtor_va = dtor_va;
    h->hash_func_va = hfunc_va;
    h->comp_func_va = comp_va;
    h->size = 0u;
    h->slots = slots;
    h->table_va = rome2_l82_alloc(ctx, (uint32_t)slots * 4u);
    if (h->table_va == 0u) {
        h->slots = 0;
        rome2_l82_curl_free(ctx, h_va);
        return 0u;
    }
    for (int32_t i = 0; i < slots; ++i) {
        uint32_t list_va = rome2_l86_curl_llist_alloc(ctx, ROME2_L86_HASH_ELEMENT_DTOR_VA);
        l86_wr32(ctx, h->table_va + (uint32_t)i * 4u, list_va);
        if (list_va == 0u) {
            while (i != 0) {
                --i;
                uint32_t slot_va = h->table_va + (uint32_t)i * 4u;
                rome2_l82_curl_llist_destroy(ctx, l86_rd32(ctx, slot_va), 0u);
                l86_wr32(ctx, slot_va, 0u);
            }
            rome2_l82_curl_free(ctx, h->table_va);
            h->table_va = 0u;
            h->slots = 0;
            rome2_l82_curl_free(ctx, h_va);
            return 0u;
        }
    }
    return h_va;
}

/* 0x10f131e0 */
uint32_t rome2_l86_curl_mk_dnscache(rome2_l82_curl_ctx *ctx) {
    return rome2_l86_curl_hash_alloc(
        ctx,
        ROME2_L86_DNSCACHE_SLOTS,
        ROME2_L86_HASH_STR_VA,
        ROME2_L86_STR_KEY_COMPARE_VA,
        ROME2_L86_FREEDNSENTRY_VA);
}

/* 0x10f10b90 */
uint32_t rome2_l86_curl_slist_duplicate(rome2_l82_curl_ctx *ctx, uint32_t inlist_va) {
    uint32_t outlist_va = 0u;
    for (uint32_t guard = 0u; inlist_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_slist_32 *in =
            (const rome2_curl_slist_32 *)rome2_l82_const_ptr(ctx, inlist_va, (uint32_t)sizeof(*in));
        if (!in) {
            break;
        }
        uint32_t node_va = rome2_l82_alloc(ctx, (uint32_t)sizeof(rome2_curl_slist_32));
        rome2_curl_slist_32 *node =
            (rome2_curl_slist_32 *)rome2_l82_mut_ptr(ctx, node_va, (uint32_t)sizeof(*node));
        if (node_va == 0u || !node) {
            rome2_l82_curl_slist_free_all(ctx, outlist_va);
            return 0u;
        }
        uint32_t dup_va = l86_strdup(ctx, in->data_va);
        if (dup_va == 0u) {
            rome2_l82_curl_free(ctx, node_va);
            rome2_l82_curl_slist_free_all(ctx, outlist_va);
            return 0u;
        }
        node->next_va = 0u;
        node->data_va = dup_va;
        if (outlist_va != 0u) {
            uint32_t last_va = outlist_va;
            for (uint32_t walk = 0u; walk < ROME2_L83_WALK_CAP; ++walk) {
                uint32_t next_va = l86_rd32(ctx, last_va + 4u);
                if (next_va == 0u) {
                    break;
                }
                last_va = next_va;
            }
            l86_wr32(ctx, last_va + 4u, node_va);
        } else {
            outlist_va = node_va;
        }
        inlist_va = in->next_va;
    }
    return outlist_va;
}

/* 0x10f40780 */
uint32_t rome2_l86_strippath(rome2_l82_curl_ctx *ctx, uint32_t fullfile_va) {
    uint32_t dup_va = l86_strdup(ctx, fullfile_va);
    const char *dup = l86_cstr(ctx, dup_va, NULL);
    if (dup_va == 0u || !dup) {
        return 0u;
    }
    const char *slash = strrchr(dup, '/');
    const char *backslash = strrchr(dup, '\\');
    const char *base = dup;
    if (slash) {
        base = (backslash && backslash > slash ? backslash : slash) + 1;
    } else if (backslash) {
        base = backslash + 1;
    }
    uint32_t base_va = rome2_l82_strdup_va(ctx, base);
    rome2_l82_curl_free(ctx, dup_va);
    return base_va;
}

/* 0x116c7f0f, 0x116c7f81, 0x116c7fc9, 0x116c7fcf */
int32_t rome2_l86_openssl_thunk(rome2_l86_curl_state *s, int32_t id, uint32_t a0) {
    if (!s || id < 0 || id >= ROME2_L86_OPENSSL_THUNK_COUNT || !s->on_openssl) {
        return 0;
    }
    return s->on_openssl(s, id, a0);
}

/* 0x10f2d2b0: the handle is re-read from the record for the second and third import */
void rome2_l86_curl_ossl_close(rome2_l86_curl_state *s, uint32_t conn_va, int32_t sockindex) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    uint32_t ssl_va = conn_va + ((uint32_t)sockindex + 0xeu) * (uint32_t)sizeof(rome2_curl_ssl_connect_data_32);
    rome2_curl_ssl_connect_data_32 *ssl =
        (rome2_curl_ssl_connect_data_32 *)rome2_l82_mut_ptr(ctx, ssl_va, (uint32_t)sizeof(*ssl));
    if (!ssl) {
        return;
    }
    if (ssl->handle_va != 0u) {
        (void)rome2_l86_openssl_thunk(s, ROME2_L86_SSLEAY32_ORD_96, ssl->handle_va);
        (void)rome2_l86_openssl_thunk(s, ROME2_L86_SSLEAY32_ORD_86, ssl->handle_va);
        (void)rome2_l86_openssl_thunk(s, ROME2_L86_SSLEAY32_ORD_48, ssl->handle_va);
        ssl->handle_va = 0u;
    }
    if (ssl->ctx_va != 0u) {
        (void)rome2_l86_openssl_thunk(s, ROME2_L86_SSLEAY32_ORD_8, ssl->ctx_va);
        ssl->ctx_va = 0u;
    }
}

/* 0x10f15cd0: JMP 0x10f2d2b0 */
void rome2_l86_curl_ssl_close(rome2_l86_curl_state *s, uint32_t conn_va, int32_t sockindex) {
    rome2_l86_curl_ossl_close(s, conn_va, sockindex);
}

/* 0x10f16080: JMP 0x100dbc00, the folded `XOR EAX, EAX; RET` stub */
uint32_t rome2_l86_curl_ssl_engines_list(rome2_l86_curl_state *s, uint32_t data_va) {
    (void)data_va;
    if (s && s->g) {
        s->g->resolver_stub_calls++;
    }
    return 0u;
}

/* 0x10f15a00 */
void rome2_l86_curl_free_ssl_config(rome2_l82_curl_ctx *ctx, uint32_t sslc_va) {
    l86_safefree(ctx, sslc_va + (uint32_t)offsetof(rome2_curl_ssl_config_prefix_32, cafile_va));
    l86_safefree(ctx, sslc_va + (uint32_t)offsetof(rome2_curl_ssl_config_prefix_32, capath_va));
    l86_safefree(ctx, sslc_va + (uint32_t)offsetof(rome2_curl_ssl_config_prefix_32, cipher_list_va));
    l86_safefree(ctx, sslc_va + (uint32_t)offsetof(rome2_curl_ssl_config_prefix_32, egdsocket_va));
    l86_safefree(ctx, sslc_va + (uint32_t)offsetof(rome2_curl_ssl_config_prefix_32, random_file_va));
}

/* 0x10f214e0 */
void rome2_l86_curl_freeaddrinfo(rome2_l82_curl_ctx *ctx, uint32_t ai_va) {
    for (uint32_t guard = 0u; ai_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_addrinfo_32 *ai =
            (const rome2_curl_addrinfo_32 *)rome2_l82_const_ptr(ctx, ai_va, (uint32_t)sizeof(*ai));
        if (!ai) {
            return;
        }
        if (ai->addr_va != 0u) {
            rome2_l82_curl_free(ctx, ai->addr_va);
        }
        if (ai->canonname_va != 0u) {
            rome2_l82_curl_free(ctx, ai->canonname_va);
        }
        uint32_t next_va = ai->next_va;
        rome2_l82_curl_free(ctx, ai_va);
        ai_va = next_va;
    }
}

/* 0x10f249a0 */
int32_t rome2_l86_curl_thread_join(rome2_l86_curl_state *s, uint32_t hnd_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx || !rome2_l82_const_ptr(ctx, hnd_va, 4u)) {
        return 0;
    }
    uint32_t handle = l86_rd32(ctx, hnd_va);
    uint32_t waited = s->on_wait_for_single_object ? s->on_wait_for_single_object(s, handle, 0xffffffffu) : 0u;
    if (s->on_close_handle) {
        s->on_close_handle(s, l86_rd32(ctx, hnd_va));
    }
    l86_wr32(ctx, hnd_va, 0u);
    return waited == 0u ? 1 : 0;
}

/* 0x10f12bf0 */
void rome2_l86_destroy_thread_sync_data(rome2_l86_curl_state *s, uint32_t tsd_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    rome2_curl_thread_sync_data_32 *tsd =
        (rome2_curl_thread_sync_data_32 *)rome2_l82_mut_ptr(ctx, tsd_va, (uint32_t)sizeof(*tsd));
    if (!tsd) {
        return;
    }
    if (tsd->mtx_va != 0u) {
        if (s->on_delete_critical_section) {
            s->on_delete_critical_section(s, tsd->mtx_va);
        }
        rome2_l82_curl_free(ctx, tsd->mtx_va);
    }
    if (tsd->hostname_va != 0u) {
        rome2_l82_curl_free(ctx, tsd->hostname_va);
    }
    if (tsd->res_va != 0u) {
        rome2_l86_curl_freeaddrinfo(ctx, tsd->res_va);
    }
    memset(tsd, 0, sizeof(*tsd));
}

/* 0x10f127d0 */
void rome2_l86_curl_resolver_cancel(rome2_l86_curl_state *s, uint32_t conn_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx || !rome2_l82_const_ptr(ctx, conn_va + ROME2_L86_CONN_ASYNC_OS_SPECIFIC_OFF, 4u)) {
        return;
    }
    uint32_t hostname_va = l86_rd32(ctx, conn_va + ROME2_L86_CONN_ASYNC_HOSTNAME_OFF);
    if (hostname_va != 0u) {
        rome2_l82_curl_free(ctx, hostname_va);
    }
    uint32_t td_va = l86_rd32(ctx, conn_va + ROME2_L86_CONN_ASYNC_OS_SPECIFIC_OFF);
    if (td_va != 0u) {
        if (l86_rd32(ctx, td_va) != 0u) {
            (void)rome2_l86_curl_thread_join(s, td_va);
        }
        rome2_l86_destroy_thread_sync_data(
            s, td_va + (uint32_t)offsetof(rome2_curl_thread_data_prefix_32, tsd));
        rome2_l82_curl_free(ctx, l86_rd32(ctx, conn_va + ROME2_L86_CONN_ASYNC_OS_SPECIFIC_OFF));
    }
    l86_wr32(ctx, conn_va + ROME2_L86_CONN_ASYNC_OS_SPECIFIC_OFF, 0u);
    l86_wr32(ctx, conn_va + ROME2_L86_CONN_ASYNC_HOSTNAME_OFF, 0u);
}

/* 0x10f1d9a0: an accepted secondary socket clears its flag and bypasses the close callback */
int32_t rome2_l86_curl_closesocket(rome2_l86_curl_state *s, uint32_t conn_va, uint32_t sock) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return 0;
    }
    uint32_t fclosesocket_va = conn_va != 0u ? l86_rd32(ctx, conn_va + ROME2_L86_CONN_FCLOSESOCKET_OFF) : 0u;
    if (fclosesocket_va != 0u) {
        if (sock == l86_rd32(ctx, conn_va + ROME2_CURL_CONN_SOCK_OFF + 4u) &&
            l86_rd32(ctx, conn_va + ROME2_L86_CONN_SOCK_ACCEPTED1_OFF) != 0u) {
            l86_wr32(ctx, conn_va + ROME2_L86_CONN_SOCK_ACCEPTED1_OFF, 0u);
        } else {
            uint32_t clientp_va = l86_rd32(ctx, conn_va + ROME2_L86_CONN_CLOSESOCKET_CLIENT_OFF);
            return s->on_closesocket_cb ? s->on_closesocket_cb(s, fclosesocket_va, clientp_va, sock) : 0;
        }
    }
    return s->on_closesocket ? s->on_closesocket(s, sock) : 0;
}

/* 0x10f17aa0: the type selects the default size only; +8 keeps its calloc zero */
uint32_t rome2_l86_curl_mk_connc(rome2_l82_curl_ctx *ctx, int32_t type, int32_t amount) {
    int32_t default_amount = type == 0 ? ROME2_L86_CONNC_DEFAULT_SINGLE : ROME2_L86_CONNC_DEFAULT_MULTI;
    if (amount < 1) {
        amount = default_amount;
    }
    if (amount > ROME2_L86_CONNC_MAX) {
        amount = ROME2_L86_CONNC_MAX;
    }
    uint32_t c_va = rome2_l82_calloc(ctx, 1u, (uint32_t)sizeof(rome2_curl_conncache_32));
    rome2_curl_conncache_32 *c =
        (rome2_curl_conncache_32 *)rome2_l82_mut_ptr(ctx, c_va, (uint32_t)sizeof(*c));
    if (c_va == 0u || !c) {
        return 0u;
    }
    c->connects_va = rome2_l82_calloc(ctx, (uint32_t)amount, 4u);
    if (c->connects_va == 0u) {
        rome2_l82_curl_free(ctx, c_va);
        return 0u;
    }
    c->num = amount;
    return c_va;
}

/* conn_free, inlined in 0x10f17fd0 */
static void l86_conn_free(rome2_l86_curl_state *s, uint32_t conn_va) {
    rome2_l82_curl_ctx *ctx = s->g->mem;
    rome2_l86_curl_resolver_cancel(s, conn_va);
    rome2_l86_curl_ssl_close(s, conn_va, 0);
    rome2_l86_curl_ssl_close(s, conn_va, 1);
    uint32_t sock = l86_rd32(ctx, conn_va + ROME2_CURL_CONN_SOCK_OFF + 4u);
    if (sock != ROME2_CURL_SOCKET_BAD) {
        (void)rome2_l86_curl_closesocket(s, conn_va, sock);
    }
    sock = l86_rd32(ctx, conn_va + ROME2_CURL_CONN_SOCK_OFF);
    if (sock != ROME2_CURL_SOCKET_BAD) {
        (void)rome2_l86_curl_closesocket(s, conn_va, sock);
    }
    for (size_t i = 0u; i < sizeof(l86_conn_free_offsets) / sizeof(l86_conn_free_offsets[0]); ++i) {
        l86_safefree(ctx, conn_va + l86_conn_free_offsets[i]);
    }
    for (uint32_t i = 0u; i < 4u; ++i) {
        rome2_l82_curl_llist_destroy(ctx, l86_rd32(ctx, conn_va + ROME2_L86_CONN_PIPE_OFF + i * 4u), 0u);
    }
    for (uint32_t i = 0u; i < 4u; ++i) {
        l86_wr32(ctx, conn_va + ROME2_L86_CONN_PIPE_OFF + i * 4u, 0u);
    }
    l86_safefree(ctx, conn_va + ROME2_L86_CONN_LOCALDEV_OFF);
    rome2_l86_curl_free_ssl_config(ctx, conn_va + ROME2_L86_CONN_SSL_CONFIG_OFF);
    rome2_l82_curl_free(ctx, conn_va);
}

/* 0x10f17fd0. A connects table that leaves the arena ends the walk. */
void rome2_l86_curl_rm_connc(rome2_l86_curl_state *s, uint32_t c_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx || c_va == 0u) {
        return;
    }
    rome2_curl_conncache_32 *c =
        (rome2_curl_conncache_32 *)rome2_l82_mut_ptr(ctx, c_va, (uint32_t)sizeof(*c));
    if (!c) {
        return;
    }
    if (c->connects_va != 0u) {
        for (int32_t i = 0; i < c->num; ++i) {
            uint32_t slot_va = c->connects_va + (uint32_t)i * 4u;
            if (!rome2_l82_const_ptr(ctx, slot_va, 4u)) {
                break;
            }
            uint32_t conn_va = l86_rd32(ctx, slot_va);
            if (conn_va != 0u) {
                l86_conn_free(s, conn_va);
            }
            l86_wr32(ctx, slot_va, 0u);
        }
        rome2_l82_curl_free(ctx, c->connects_va);
        c->connects_va = 0u;
    }
    c->num = 0;
    rome2_l82_curl_free(ctx, c_va);
}

/* 0x10f176a0 */
int32_t rome2_l86_curl_dupset(rome2_l82_curl_ctx *ctx, uint32_t dst_va, uint32_t src_va) {
    l86_copy(ctx, dst_va + ROME2_CURL_EASY_SET_OFF, src_va + ROME2_CURL_EASY_SET_OFF, ROME2_L86_EASY_SET_DWORDS * 4u);
    void *strings = rome2_l82_mut_ptr(ctx, dst_va + ROME2_CURL_EASY_SET_STR_OFF, ROME2_L86_EASY_SET_STR_BYTES);
    if (strings) {
        memset(strings, 0, ROME2_L86_EASY_SET_STR_BYTES);
    }
    for (uint32_t i = 0u; i < ROME2_CURL_EASY_SET_STR_COUNT; ++i) {
        uint32_t dst_slot_va = dst_va + ROME2_CURL_EASY_SET_STR_OFF + i * 4u;
        uint32_t src_str_va = l86_rd32(ctx, src_va + ROME2_CURL_EASY_SET_STR_OFF + i * 4u);
        l86_safefree(ctx, dst_slot_va);
        if (src_str_va != 0u) {
            uint32_t dup_va = l86_strdup(ctx, src_str_va);
            if (dup_va == 0u) {
                return ROME2_CURLE_OUT_OF_MEMORY;
            }
            l86_wr32(ctx, dst_slot_va, dup_va);
        }
    }
    return ROME2_CURLE_OK;
}

/* 0x10f10380. The failure path leaves a cookie jar already attached to the copy unreleased, as the image does. */
uint32_t rome2_l86_curl_easy_duphandle(rome2_l86_curl_state *s, uint32_t incurl_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return 0u;
    }
    uint32_t out_va = rome2_l82_calloc(ctx, 1u, ROME2_CURL_EASY_BYTES);
    if (out_va == 0u) {
        return 0u;
    }
    uint32_t headerbuff_va = rome2_l82_alloc(ctx, ROME2_CURL_HEADERSIZE);
    l86_wr32(ctx, out_va + ROME2_CURL_EASY_STATE_HEADERBUFF_OFF, headerbuff_va);
    uint8_t ok = headerbuff_va != 0u ? 1u : 0u;
    if (ok != 0u) {
        l86_wr32(ctx, out_va + ROME2_CURL_EASY_STATE_HEADERSIZE_OFF, ROME2_CURL_HEADERSIZE);
        ok = rome2_l86_curl_dupset(ctx, out_va, incurl_va) == ROME2_CURLE_OK ? 1u : 0u;
    }
    if (ok != 0u) {
        l86_wr32(ctx, out_va + ROME2_CURL_EASY_STATE_CONNC_OFF, 0u);
        l86_wr32(ctx, out_va + ROME2_CURL_EASY_STATE_LASTCONNECT_OFF, 0xffffffffu);
        l86_wr32(
            ctx,
            out_va + ROME2_CURL_EASY_PROGRESS_FLAGS_OFF,
            l86_rd32(ctx, incurl_va + ROME2_CURL_EASY_PROGRESS_FLAGS_OFF));
        l86_wr32(
            ctx,
            out_va + ROME2_L86_EASY_PROGRESS_CALLBACK_OFF,
            l86_rd32(ctx, incurl_va + ROME2_L86_EASY_PROGRESS_CALLBACK_OFF));
        uint32_t cookies_va = l86_rd32(ctx, incurl_va + ROME2_L86_EASY_COOKIES_OFF);
        if (cookies_va != 0u) {
            uint32_t jar_va = rome2_l86_curl_cookie_init(
                s,
                incurl_va,
                l86_rd32(ctx, cookies_va + (uint32_t)offsetof(rome2_curl_cookie_info_32, filename_va)),
                l86_rd32(ctx, out_va + ROME2_L86_EASY_COOKIES_OFF),
                l86_rd32(ctx, incurl_va + ROME2_L86_EASY_SET_COOKIESESSION_OFF));
            l86_wr32(ctx, out_va + ROME2_L86_EASY_COOKIES_OFF, jar_va);
            ok = jar_va != 0u ? 1u : 0u;
        }
    }
    if (ok != 0u) {
        uint32_t cookielist_va = l86_rd32(ctx, incurl_va + ROME2_L86_EASY_CHANGE_COOKIELIST_OFF);
        if (cookielist_va != 0u) {
            uint32_t dup_va = rome2_l86_curl_slist_duplicate(ctx, cookielist_va);
            l86_wr32(ctx, out_va + ROME2_L86_EASY_CHANGE_COOKIELIST_OFF, dup_va);
            ok = dup_va != 0u ? 1u : 0u;
        }
    }
    if (ok != 0u) {
        uint32_t url_va = l86_rd32(ctx, incurl_va + ROME2_L86_EASY_CHANGE_URL_OFF);
        if (url_va != 0u) {
            uint32_t dup_va = l86_strdup(ctx, url_va);
            l86_wr32(ctx, out_va + ROME2_L86_EASY_CHANGE_URL_OFF, dup_va);
            ok = dup_va != 0u ? 1u : 0u;
            if (ok != 0u) {
                l86_wr32(ctx, out_va + ROME2_L86_EASY_CHANGE_URL_ALLOC_OFF, 1u);
            }
        }
    }
    if (ok != 0u) {
        uint32_t referer_va = l86_rd32(ctx, incurl_va + ROME2_CURL_EASY_CHANGE_REFERER_OFF);
        if (referer_va != 0u) {
            uint32_t dup_va = l86_strdup(ctx, referer_va);
            l86_wr32(ctx, out_va + ROME2_CURL_EASY_CHANGE_REFERER_OFF, dup_va);
            ok = dup_va != 0u ? 1u : 0u;
            if (ok != 0u) {
                l86_wr32(ctx, out_va + ROME2_CURL_EASY_CHANGE_REFERER_ALLOC_OFF, 1u);
            }
        }
    }
    if (ok != 0u) {
        /* 0x100dbc00(&out->state.resolver, in->state.resolver): the folded zero stub */
        s->g->resolver_stub_calls++;
        rome2_l83_curl_easy_init_handle_data(ctx, out_va);
        l86_wr32(ctx, out_va + ROME2_CURL_EASY_MAGIC_OFF, ROME2_CURL_EASY_MAGIC);
        return out_va;
    }
    uint32_t connc_va = l86_rd32(ctx, out_va + ROME2_CURL_EASY_STATE_CONNC_OFF);
    if (connc_va != 0u && l86_rd32(ctx, connc_va + (uint32_t)offsetof(rome2_curl_conncache_32, type)) == 0u) {
        rome2_l86_curl_rm_connc(s, connc_va);
        l86_wr32(ctx, out_va + ROME2_CURL_EASY_STATE_CONNC_OFF, 0u);
    }
    rome2_l82_curl_slist_free_all(ctx, l86_rd32(ctx, out_va + ROME2_L86_EASY_CHANGE_COOKIELIST_OFF));
    l86_wr32(ctx, out_va + ROME2_L86_EASY_CHANGE_COOKIELIST_OFF, 0u);
    l86_safefree(ctx, out_va + ROME2_CURL_EASY_STATE_HEADERBUFF_OFF);
    l86_safefree(ctx, out_va + ROME2_L86_EASY_CHANGE_URL_OFF);
    l86_safefree(ctx, out_va + ROME2_CURL_EASY_CHANGE_REFERER_OFF);
    rome2_l83_curl_freeset(ctx, out_va);
    rome2_l82_curl_free(ctx, out_va);
    return 0u;
}

/* 0x10f1d330 */
void rome2_l86_curl_infof(rome2_l86_curl_state *s, uint32_t data_va, const char *fmt, ...) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx || !fmt || data_va == 0u || l86_rd32(ctx, data_va + ROME2_CURL_EASY_SET_VERBOSE_OFF) == 0u) {
        return;
    }
    char print_buffer[ROME2_L86_INFOF_BUFFER_BYTES];
    print_buffer[0] = '\0';
    va_list ap;
    va_start(ap, fmt);
    (void)rome2_l82_curl_mvsnprintf(print_buffer, sizeof(print_buffer), fmt, ap);
    va_end(ap);
    uint32_t len = l86_text_len(print_buffer, (uint32_t)sizeof(print_buffer));
    rome2_l83_curl_state *g = s->g;
    uint32_t fdebug_va = l86_rd32(ctx, data_va + ROME2_CURL_EASY_SET_FDEBUG_OFF);
    if (fdebug_va != 0u) {
        if (g->on_debug) {
            g->on_debug(
                g, fdebug_va, data_va, 0, print_buffer, len, l86_rd32(ctx, data_va + ROME2_CURL_EASY_SET_DEBUGDATA_OFF));
        }
        return;
    }
    if (g->on_write) {
        uint32_t err_va = l86_rd32(ctx, data_va + ROME2_CURL_EASY_SET_ERR_OFF);
        (void)g->on_write(g, ROME2_L83_CRT_FWRITE_VA, (const uint8_t *)"* ", 2u, 1u, err_va); /* 0x1183fa10 */
        (void)g->on_write(g, ROME2_L83_CRT_FWRITE_VA, (const uint8_t *)print_buffer, len, 1u, err_va);
    }
}

/* 0x10f223b0 */
uint32_t rome2_l86_curl_multi_can_pipeline(const rome2_l82_curl_ctx *ctx, uint32_t multi_va) {
    return l86_rd32(ctx, multi_va + (uint32_t)offsetof(rome2_curl_multi_prefix_32, pipelining));
}

/*
 * 0x10f1d3f0. Pipelined reads are served from the master buffer (+0x290) while
 * unread bytes remain between read_pos (+0x294) and buf_len (+0x298).
 */
int32_t rome2_l86_curl_read(
    rome2_l86_curl_state *s,
    uint32_t conn_va,
    uint32_t sockfd,
    uint32_t buf_va,
    uint32_t sizerequested,
    int32_t *n) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx || !n) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    int32_t curlcode = ROME2_CURLE_RECV_ERROR;
    uint32_t data_va = l86_rd32(ctx, conn_va + ROME2_CURL_CONN_DATA_OFF);
    uint32_t multi_va = l86_rd32(ctx, data_va + ROME2_L86_EASY_MULTI_OFF);
    uint8_t pipelining = (multi_va != 0u && rome2_l86_curl_multi_can_pipeline(ctx, multi_va) != 0u) ? 1u : 0u;
    uint32_t num = sockfd == l86_rd32(ctx, conn_va + ROME2_CURL_CONN_SOCK_OFF + 4u) ? 1u : 0u;
    uint32_t master_va = l86_rd32(ctx, conn_va + ROME2_L86_CONN_MASTER_BUFFER_OFF);
    uint32_t target_va;
    uint32_t want;
    *n = 0;
    if (pipelining != 0u) {
        uint32_t read_pos = l86_rd32(ctx, conn_va + ROME2_L86_CONN_READ_POS_OFF);
        uint32_t bytestocopy = l86_rd32(ctx, conn_va + ROME2_L86_CONN_BUF_LEN_OFF) - read_pos;
        if (bytestocopy > sizerequested) {
            bytestocopy = sizerequested;
        }
        if (bytestocopy != 0u) {
            l86_copy(ctx, buf_va, master_va + read_pos, bytestocopy);
            l86_wr32(ctx, conn_va + ROME2_L86_CONN_READ_POS_OFF, read_pos + bytestocopy);
            l86_wr32(ctx, conn_va + ROME2_L86_CONN_STREAM_WAS_REWOUND_OFF, 0u);
            *n = (int32_t)bytestocopy;
            return ROME2_CURLE_OK;
        }
        want = sizerequested < (uint32_t)ROME2_CURL_MAX_WRITE_SIZE ? sizerequested : (uint32_t)ROME2_CURL_MAX_WRITE_SIZE;
        target_va = master_va;
    } else {
        uint32_t buffer_size = l86_rd32(ctx, data_va + ROME2_L86_EASY_SET_BUFFER_SIZE_OFF);
        uint32_t limit = buffer_size != 0u ? buffer_size : (uint32_t)ROME2_CURL_MAX_WRITE_SIZE;
        want = (int32_t)sizerequested < (int32_t)limit ? sizerequested : limit;
        target_va = buf_va;
    }
    int32_t nread = -1;
    if (s->on_conn_recv) {
        nread = s->on_conn_recv(
            s, l86_rd32(ctx, conn_va + ROME2_L86_CONN_RECV_OFF + num * 4u), conn_va, num, target_va, want, &curlcode);
    }
    if (nread < 0) {
        return curlcode;
    }
    if (pipelining != 0u) {
        l86_copy(ctx, buf_va, master_va, (uint32_t)nread);
        l86_wr32(ctx, conn_va + ROME2_L86_CONN_BUF_LEN_OFF, (uint32_t)nread);
        l86_wr32(ctx, conn_va + ROME2_L86_CONN_READ_POS_OFF, (uint32_t)nread);
    }
    *n += nread;
    return ROME2_CURLE_OK;
}

/* 0x10f107c0 */
int32_t rome2_l86_curl_easy_recv(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t buffer_va,
    uint32_t buflen,
    int32_t *n) {
    if (!s || !n) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    uint32_t sfd = 0u;
    uint32_t c_va = 0u;
    int32_t ret = rome2_l83_easy_connection(s->g, data_va, &sfd, &c_va);
    if (ret != ROME2_CURLE_OK) {
        return ret;
    }
    int32_t n1 = 0;
    *n = 0;
    ret = rome2_l86_curl_read(s, c_va, sfd, buffer_va, buflen, &n1);
    if (ret != ROME2_CURLE_OK) {
        return ret;
    }
    *n = n1;
    return ROME2_CURLE_OK;
}

/* 0x10f22aa0 */
uint32_t rome2_l86_curl_multi_init(rome2_l86_curl_state *s) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return 0u;
    }
    uint32_t multi_va = rome2_l82_calloc(ctx, 1u, ROME2_CURL_MULTI_BYTES);
    rome2_curl_multi_prefix_32 *multi =
        (rome2_curl_multi_prefix_32 *)rome2_l82_mut_ptr(ctx, multi_va, (uint32_t)sizeof(*multi));
    if (multi_va == 0u || !multi) {
        return 0u;
    }
    multi->magic = ROME2_CURL_MULTI_MAGIC;
    uint8_t ok = 0u;
    multi->hostcache_va = rome2_l86_curl_mk_dnscache(ctx);
    if (multi->hostcache_va != 0u) {
        multi->sockhash_va = rome2_l86_curl_hash_alloc(
            ctx, ROME2_L86_SOCKHASH_SLOTS, ROME2_L86_HASH_FD_VA, ROME2_L86_FD_KEY_COMPARE_VA, ROME2_L86_SH_FREEENTRY_VA);
        if (multi->sockhash_va != 0u) {
            multi->connc_va = rome2_l86_curl_mk_connc(ctx, 1, -1);
            if (multi->connc_va != 0u) {
                multi->msglist_va = rome2_l86_curl_llist_alloc(ctx, ROME2_L86_MSGLIST_DTOR_VA);
                ok = multi->msglist_va != 0u ? 1u : 0u;
            }
        }
    }
    if (ok != 0u) {
        uint32_t sentinel_va = multi_va + (uint32_t)offsetof(rome2_curl_multi_prefix_32, easy);
        multi->easy.prev_va = sentinel_va;
        multi->easy.next_va = sentinel_va;
        return multi_va;
    }
    rome2_l82_curl_hash_destroy(ctx, multi->sockhash_va);
    multi->sockhash_va = 0u;
    rome2_l82_curl_hash_destroy(ctx, multi->hostcache_va);
    multi->hostcache_va = 0u;
    rome2_l86_curl_rm_connc(s, multi->connc_va);
    multi->connc_va = 0u;
    rome2_l82_curl_free(ctx, multi_va);
    return 0u;
}

/* 0x10f1cad0. A result pointer outside the arena drops the store and still reports CURLE_OK. */
int32_t rome2_l86_curl_getinfo(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t info,
    uint32_t param_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx || data_va == 0u) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    uint32_t type = info & ROME2_CURLINFO_TYPEMASK;
    if ((type != ROME2_CURLINFO_STRING && type != ROME2_CURLINFO_LONG && type != ROME2_CURLINFO_DOUBLE &&
         type != ROME2_CURLINFO_SLIST) ||
        param_va == 0u) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (type == ROME2_CURLINFO_LONG) {
        if (info == ROME2_CURLINFO_LASTSOCKET) {
            l86_wr32(ctx, param_va, rome2_l83_curl_getconnectinfo(s->g, data_va, NULL));
            return ROME2_CURLE_OK;
        }
        for (size_t i = 0u; i < sizeof(l86_getinfo_long) / sizeof(l86_getinfo_long[0]); ++i) {
            if (l86_getinfo_long[i][0] == info) {
                l86_wr32(ctx, param_va, l86_rd32(ctx, data_va + l86_getinfo_long[i][1]));
                return ROME2_CURLE_OK;
            }
        }
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (type == ROME2_CURLINFO_STRING) {
        if (info == ROME2_CURLINFO_EFFECTIVE_URL) {
            /* a NULL change.url reports the image's empty string 0x1173dad0, an address outside the arena */
            uint32_t url_va = l86_rd32(ctx, data_va + ROME2_L86_EASY_CHANGE_URL_OFF);
            l86_wr32(ctx, param_va, url_va != 0u ? url_va : 0x1173dad0u);
            return ROME2_CURLE_OK;
        }
        if (info == ROME2_CURLINFO_PRIMARY_IP || info == ROME2_CURLINFO_LOCAL_IP) {
            l86_wr32(
                ctx,
                param_va,
                data_va + (info == ROME2_CURLINFO_PRIMARY_IP ? (uint32_t)ROME2_L86_EASY_INFO_PRIMARY_IP_OFF
                                                             : (uint32_t)ROME2_L86_EASY_INFO_LOCAL_IP_OFF));
            return ROME2_CURLE_OK;
        }
        for (size_t i = 0u; i < sizeof(l86_getinfo_string) / sizeof(l86_getinfo_string[0]); ++i) {
            if (l86_getinfo_string[i][0] == info) {
                l86_wr32(ctx, param_va, l86_rd32(ctx, data_va + l86_getinfo_string[i][1]));
                return ROME2_CURLE_OK;
            }
        }
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (type == ROME2_CURLINFO_DOUBLE) {
        for (size_t i = 0u; i < sizeof(l86_getinfo_double) / sizeof(l86_getinfo_double[0]); ++i) {
            if (l86_getinfo_double[i][0] == info) {
                l86_copy(ctx, param_va, data_va + l86_getinfo_double[i][1], 8u);
                return ROME2_CURLE_OK;
            }
        }
        for (size_t i = 0u; i < sizeof(l86_getinfo_off_t) / sizeof(l86_getinfo_off_t[0]); ++i) {
            if (l86_getinfo_off_t[i][0] == info) {
                double value = -1.0; /* 0x1183fa08 */
                uint32_t flag = l86_getinfo_off_t[i][2];
                if (flag == 0u || (l86_rd32(ctx, data_va + ROME2_CURL_EASY_PROGRESS_FLAGS_OFF) & flag) != 0u) {
                    value = rome2_l86_crt_ltod3(
                        l86_rd32(ctx, data_va + l86_getinfo_off_t[i][1]),
                        (int32_t)l86_rd32(ctx, data_va + l86_getinfo_off_t[i][1] + 4u));
                }
                void *out = rome2_l82_mut_ptr(ctx, param_va, 8u);
                if (out) {
                    memcpy(out, &value, 8u);
                }
                return ROME2_CURLE_OK;
            }
        }
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (info == ROME2_CURLINFO_SSL_ENGINES) {
        l86_wr32(ctx, param_va, rome2_l86_curl_ssl_engines_list(s, data_va));
        return ROME2_CURLE_OK;
    }
    if (info == ROME2_CURLINFO_COOKIELIST) {
        l86_wr32(ctx, param_va, rome2_l86_curl_cookie_list(s, data_va));
        return ROME2_CURLE_OK;
    }
    if (info == ROME2_CURLINFO_CERTINFO) {
        l86_wr32(ctx, param_va, data_va + ROME2_L86_EASY_INFO_CERTS_OFF);
        return ROME2_CURLE_OK;
    }
    return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
}

/* 0x10f10580: forwards the one variadic argument */
int32_t rome2_l86_curl_easy_getinfo(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t info,
    uint32_t param_va) {
    return rome2_l86_curl_getinfo(s, data_va, info, param_va);
}

/* 0x10f120c0 */
void rome2_l86_freecookie(rome2_l82_curl_ctx *ctx, uint32_t co_va) {
    const rome2_curl_cookie_32 *co = l86_cookie(ctx, co_va);
    if (!co) {
        return;
    }
    l86_free_if_set(ctx, co->expirestr_va);
    l86_free_if_set(ctx, co->domain_va);
    l86_free_if_set(ctx, co->path_va);
    l86_free_if_set(ctx, co->name_va);
    l86_free_if_set(ctx, co->value_va);
    l86_free_if_set(ctx, co->maxage_va);
    l86_free_if_set(ctx, co->version_va);
    rome2_l82_curl_free(ctx, co_va);
}

/*
 * sscanf(ptr, "%1023[^;\r\n =]=%4999[^;\r\n]", name, what) through the CRT
 * scan wrapper 0x10cbb440, restated for this one format (0x1183eaa8): the
 * number of fields stored, or -1 for an empty input.
 */
static int32_t l86_scan_cookie_pair(const char *ptr, char *name, char *what) {
    uint32_t n = 0u;
    if (*ptr == '\0') {
        return -1;
    }
    while (n < (uint32_t)ROME2_L86_COOKIE_NAME_BYTES - 1u && ptr[n] != '\0' && ptr[n] != ';' && ptr[n] != '\r' &&
           ptr[n] != '\n' && ptr[n] != ' ' && ptr[n] != '=') {
        name[n] = ptr[n];
        n++;
    }
    if (n == 0u) {
        return 0;
    }
    name[n] = '\0';
    ptr += n;
    if (*ptr != '=') {
        return 1;
    }
    ptr++;
    uint32_t m = 0u;
    while (m < (uint32_t)ROME2_L86_COOKIE_LINE_BYTES - 1u && ptr[m] != '\0' && ptr[m] != ';' && ptr[m] != '\r' &&
           ptr[m] != '\n') {
        what[m] = ptr[m];
        m++;
    }
    if (m == 0u) {
        return 1;
    }
    what[m] = '\0';
    return 2;
}

/* The Set-Cookie header arm of 0x10f10cd0; returns 0 for a bad cookie. */
static uint8_t l86_cookie_parse_header(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    rome2_curl_cookie_32 *co,
    const char *ptr,
    char *what,
    const char *domain,
    const char *path,
    int64_t now) {
    rome2_l82_curl_ctx *ctx = s->g->mem;
    char name[ROME2_L86_COOKIE_NAME_BYTES];
    uint8_t badcookie = 0u;
    const char *semiptr = strchr(ptr, ';');
    while (*ptr != '\0' && l86_isblank(*ptr) != 0u) {
        ptr++;
    }
    for (uint32_t guard = 0u; guard < ROME2_L83_WALK_CAP; ++guard) {
        what[0] = '\0';
        name[0] = '\0';
        if (l86_scan_cookie_pair(ptr, name, what) >= 1) {
            uint32_t len = l86_text_len(what, ROME2_L86_COOKIE_LINE_BYTES);
            const char *endofn = ptr + l86_text_len(name, (uint32_t)sizeof(name));
            while (*endofn != '\0' && l86_isblank(*endofn) != 0u) {
                endofn++;
            }
            char sep = *endofn;
            while (len != 0u && l86_isblank(what[len - 1u]) != 0u) {
                what[len - 1u] = '\0';
                len--;
            }
            const char *whatptr = what;
            while (*whatptr != '\0' && l86_isblank(*whatptr) != 0u) {
                whatptr++;
            }
            uint8_t pair = len != 0u ? 1u : 0u;
            if (len == 0u) {
                if (rome2_l82_curl_raw_equal("secure", name) != 0u) {
                    co->secure = 1u;
                } else if (rome2_l82_curl_raw_equal("httponly", name) != 0u) {
                    co->httponly = 1u;
                } else if (sep == '=') {
                    pair = 1u;
                }
            }
            if (pair != 0u) {
                if (rome2_l82_curl_raw_equal("path", name) != 0u) {
                    if (l86_strstore(ctx, &co->path_va, whatptr) == 0u) {
                        return 0u;
                    }
                } else if (rome2_l82_curl_raw_equal("domain", name) != 0u) {
                    const char *domptr = whatptr[0] == '.' ? whatptr + 1 : whatptr;
                    int32_t dotcount = 1;
                    for (const char *nextptr = strchr(domptr, '.'); nextptr; nextptr = strchr(domptr, '.')) {
                        if (domptr != nextptr) {
                            dotcount++;
                        }
                        domptr = nextptr + 1;
                    }
                    if (dotcount < 2) {
                        badcookie = 1u;
                        rome2_l86_curl_infof(s, data_va, "skipped cookie with illegal dotcount domain: %s\n", whatptr);
                    } else {
                        if (whatptr[0] == '.') {
                            whatptr++;
                        }
                        uint8_t tailmatch = 1u;
                        if (domain) {
                            size_t little = strlen(whatptr);
                            size_t big = strlen(domain);
                            tailmatch = (little <= big && rome2_l82_curl_raw_equal(whatptr, domain + (big - little)) != 0u)
                                            ? 1u
                                            : 0u;
                        }
                        if (tailmatch != 0u) {
                            const char *tailptr = whatptr[0] == '.' ? whatptr + 1 : whatptr;
                            if (l86_strstore(ctx, &co->domain_va, tailptr) == 0u) {
                                return 0u;
                            }
                            co->tailmatch = 1u;
                        } else {
                            badcookie = 1u;
                            rome2_l86_curl_infof(s, data_va, "skipped cookie with bad tailmatch domain: %s\n", whatptr);
                        }
                    }
                } else if (rome2_l82_curl_raw_equal("version", name) != 0u) {
                    if (l86_strstore(ctx, &co->version_va, whatptr) == 0u) {
                        return 0u;
                    }
                } else if (rome2_l82_curl_raw_equal("max-age", name) != 0u) {
                    if (l86_strstore(ctx, &co->maxage_va, whatptr) == 0u) {
                        return 0u;
                    }
                    const char *maxage = l86_cstr(ctx, co->maxage_va, NULL);
                    int32_t parse_errno = 0;
                    int32_t age = 0;
                    if (maxage) {
                        age = rome2_startup_crt_strtol_1169de89(maxage[0] == '"' ? maxage + 1 : maxage, NULL, 10, &parse_errno);
                        if (parse_errno != 0) {
                            ctx->last_errno = parse_errno;
                        }
                    }
                    int32_t expires = (int32_t)((uint32_t)age + (uint32_t)now);
                    co->expires_lo = (uint32_t)expires;
                    co->expires_hi = expires < 0 ? -1 : 0;
                } else if (rome2_l82_curl_raw_equal("expires", name) != 0u) {
                    if (l86_strstore(ctx, &co->expirestr_va, whatptr) == 0u) {
                        return 0u;
                    }
                    int64_t expires = rome2_l82_curl_getdate(what, &now);
                    if (expires == 0) {
                        expires = 1;
                    } else if (expires < 0) {
                        expires = 0;
                    }
                    co->expires_lo = (uint32_t)expires;
                    co->expires_hi = (int32_t)(expires >> 32);
                } else if (co->name_va == 0u) {
                    co->name_va = rome2_l82_strdup_va(ctx, name);
                    co->value_va = rome2_l82_strdup_va(ctx, whatptr);
                    if (co->name_va == 0u || co->value_va == 0u) {
                        return 0u;
                    }
                }
            }
        }
        if (!semiptr || *semiptr == '\0') {
            break;
        }
        ptr = semiptr + 1;
        while (*ptr != '\0' && l86_isblank(*ptr) != 0u) {
            ptr++;
        }
        semiptr = strchr(ptr, ';');
        if (!semiptr) {
            if (*ptr == '\0') {
                break;
            }
            semiptr = strchr(ptr, '\0');
        }
    }
    if (badcookie != 0u) {
        return 0u;
    }
    if (co->domain_va == 0u && domain) {
        co->domain_va = rome2_l82_strdup_va(ctx, domain);
        if (co->domain_va == 0u) {
            return 0u;
        }
    }
    if (co->path_va == 0u && path) {
        const char *queryp = strchr(path, '?');
        const char *endslash =
            queryp ? (const char *)rome2_l86_curl_memrchr(path, '/', (uint32_t)(queryp - path)) : strrchr(path, '/');
        if (endslash) {
            uint32_t pathlen = (uint32_t)(endslash - path) + 1u;
            co->path_va = rome2_l82_alloc(ctx, pathlen + 1u);
            char *copy = (char *)rome2_l82_mut_ptr(ctx, co->path_va, pathlen + 1u);
            if (co->path_va == 0u || !copy) {
                return 0u;
            }
            memcpy(copy, path, pathlen);
            copy[pathlen] = '\0';
        }
    }
    return 1u;
}

/* The Netscape cookie-file arm of 0x10f10cd0: tab-separated fields through the 7-entry table at 0x10f1164c. */
static uint8_t l86_cookie_parse_netscape(
    rome2_l86_curl_state *s,
    rome2_curl_cookie_32 *co,
    char *firstptr,
    char **tok_buf) {
    rome2_l82_curl_ctx *ctx = s->g->mem;
    uint8_t badcookie = 0u;
    int32_t fields = 0;
    for (char *ptr = firstptr; ptr && badcookie == 0u; ptr = rome2_l86_curl_strtok_r(NULL, "\t", tok_buf), fields++) {
        switch (fields) {
        case 0:
            if (ptr[0] == '.') {
                ptr++;
            }
            co->domain_va = rome2_l82_strdup_va(ctx, ptr);
            badcookie = co->domain_va == 0u ? 1u : 0u;
            break;
        case 1:
            co->tailmatch = rome2_l82_curl_raw_equal(ptr, "TRUE") != 0u ? 1u : 0u;
            break;
        case 2:
            if (strcmp("TRUE", ptr) != 0 && strcmp("FALSE", ptr) != 0) {
                co->path_va = rome2_l82_strdup_va(ctx, ptr);
                badcookie = co->path_va == 0u ? 1u : 0u;
                break;
            }
            /* a missing path column: the path is "/" and this field is the secure flag */
            co->path_va = rome2_l82_strdup_va(ctx, "/");
            badcookie = co->path_va == 0u ? 1u : 0u;
            fields = 3;
            co->secure = rome2_l82_curl_raw_equal(ptr, "TRUE") != 0u ? 1u : 0u;
            break;
        case 3:
            co->secure = rome2_l82_curl_raw_equal(ptr, "TRUE") != 0u ? 1u : 0u;
            break;
        case 4: {
            int64_t expires = rome2_l86_crt_strtoi64(s, ptr, NULL, 10);
            co->expires_lo = (uint32_t)expires;
            co->expires_hi = (int32_t)(expires >> 32);
            break;
        }
        case 5:
            co->name_va = rome2_l82_strdup_va(ctx, ptr);
            badcookie = co->name_va == 0u ? 1u : 0u;
            break;
        case 6:
            co->value_va = rome2_l82_strdup_va(ctx, ptr);
            badcookie = co->value_va == 0u ? 1u : 0u;
            break;
        default:
            break;
        }
    }
    if (fields == 6) {
        co->value_va = rome2_l82_strdup_va(ctx, "");
        if (co->value_va == 0u) {
            return 0u;
        }
        fields = 7;
    }
    return (badcookie == 0u && fields == 7) ? 1u : 0u;
}

/* Curl_raw_equal on two guest strings; an unreadable operand compares unequal. */
static uint8_t l86_raw_equal_va(const rome2_l82_curl_ctx *ctx, uint32_t first_va, uint32_t second_va) {
    const char *first = l86_cstr(ctx, first_va, NULL);
    const char *second = l86_cstr(ctx, second_va, NULL);
    return (first && second) ? rome2_l82_curl_raw_equal(first, second) : 0u;
}

/* The optional-string match Curl_cookie_add applies to domain and path: both absent, or both present and equal. */
static uint8_t l86_cookie_field_matches(const rome2_l82_curl_ctx *ctx, uint32_t old_va, uint32_t new_va) {
    if (old_va == 0u) {
        return new_va == 0u ? 1u : 0u;
    }
    return new_va != 0u ? l86_raw_equal_va(ctx, old_va, new_va) : 0u;
}

/*
 * 0x10f10cd0. An unreadable line or jar releases the new record and returns
 * NULL. A Netscape line is cut in place at its CR, LF and tab characters.
 */
uint32_t rome2_l86_curl_cookie_add(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t c_va,
    uint32_t httpheader,
    uint32_t lineptr_va,
    uint32_t domain_va,
    uint32_t path_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return 0u;
    }
    int64_t now = rome2_l83_crt_time64(s->g, NULL);
    uint32_t co_va = rome2_l82_calloc(ctx, 1u, (uint32_t)sizeof(rome2_curl_cookie_32));
    rome2_curl_cookie_32 *co = l86_cookie(ctx, co_va);
    if (co_va == 0u || !co) {
        return 0u;
    }
    char *lineptr = l86_mstr(ctx, lineptr_va, NULL);
    rome2_curl_cookie_info_32 *c =
        (rome2_curl_cookie_info_32 *)rome2_l82_mut_ptr(ctx, c_va, (uint32_t)sizeof(*c));
    if (!lineptr || !c) {
        rome2_l82_curl_free(ctx, co_va);
        return 0u;
    }
    if (httpheader != 0u) {
        uint32_t what_va = rome2_l82_alloc(ctx, ROME2_L86_COOKIE_LINE_BYTES);
        char *what = (char *)rome2_l82_mut_ptr(ctx, what_va, ROME2_L86_COOKIE_LINE_BYTES);
        if (what_va == 0u || !what) {
            rome2_l82_curl_free(ctx, co_va);
            return 0u;
        }
        uint8_t good = l86_cookie_parse_header(
            s,
            data_va,
            co,
            lineptr,
            what,
            domain_va != 0u ? l86_cstr(ctx, domain_va, NULL) : NULL,
            path_va != 0u ? l86_cstr(ctx, path_va, NULL) : NULL,
            now);
        rome2_l82_curl_free(ctx, what_va);
        if (good == 0u || co->name_va == 0u) {
            rome2_l86_freecookie(ctx, co_va);
            return 0u;
        }
    } else {
        char *tok_buf = NULL;
        if (rome2_startup_crt_strncmp_1168d030(lineptr, "#HttpOnly_", 10u) == 0) {
            lineptr += 10;
            co->httponly = 1u;
        }
        if (lineptr[0] == '#') {
            rome2_l82_curl_free(ctx, co_va);
            return 0u;
        }
        char *cut = strchr(lineptr, '\r');
        if (cut) {
            *cut = '\0';
        }
        cut = strchr(lineptr, '\n');
        if (cut) {
            *cut = '\0';
        }
        char *firstptr = rome2_l86_curl_strtok_r(lineptr, "\t", &tok_buf);
        if (!firstptr || strchr(firstptr, ':') != NULL) {
            rome2_l82_curl_free(ctx, co_va);
            return 0u;
        }
        if (l86_cookie_parse_netscape(s, co, firstptr, &tok_buf) == 0u) {
            rome2_l86_freecookie(ctx, co_va);
            return 0u;
        }
    }

    if (c->running == 0u && c->newsession != 0u && co->expires_lo == 0u && co->expires_hi == 0) {
        rome2_l86_freecookie(ctx, co_va);
        return 0u;
    }
    co->livecookie = c->running;

    uint32_t lastc_va = 0u;
    uint8_t replace_old = 0u;
    uint32_t clist_va = c->cookies_va;
    for (uint32_t guard = 0u; clist_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        rome2_curl_cookie_32 *clist = l86_cookie(ctx, clist_va);
        if (!clist) {
            break;
        }
        if (l86_raw_equal_va(ctx, clist->name_va, co->name_va) != 0u &&
            l86_cookie_field_matches(ctx, clist->domain_va, co->domain_va) != 0u &&
            l86_cookie_field_matches(ctx, clist->path_va, co->path_va) != 0u) {
            if (co->livecookie == 0u && clist->livecookie != 0u) {
                /* a cookie read from a file never replaces one set by a header */
                rome2_l86_freecookie(ctx, co_va);
                return 0u;
            }
            co->next_va = clist->next_va;
            rome2_l82_curl_free(ctx, clist->name_va);
            l86_free_if_set(ctx, clist->value_va);
            l86_free_if_set(ctx, clist->domain_va);
            l86_free_if_set(ctx, clist->path_va);
            l86_free_if_set(ctx, clist->expirestr_va);
            l86_free_if_set(ctx, clist->version_va);
            l86_free_if_set(ctx, clist->maxage_va);
            *clist = *co;
            rome2_l82_curl_free(ctx, co_va);
            co = clist;
            co_va = clist_va;
            lastc_va = clist_va;
            for (uint32_t walk = 0u; walk < ROME2_L83_WALK_CAP; ++walk) {
                uint32_t next_va = l86_rd32(ctx, lastc_va);
                if (next_va == 0u) {
                    break;
                }
                lastc_va = next_va;
            }
            replace_old = 1u;
            break;
        }
        lastc_va = clist_va;
        clist_va = clist->next_va;
    }

    if (c->running != 0u) {
        int64_t expires = (int64_t)(((uint64_t)(uint32_t)co->expires_hi << 32) | (uint64_t)co->expires_lo);
        rome2_l86_curl_infof(
            s,
            data_va,
            "%s cookie %s=\"%s\" for domain %s, path %s, expire %lld\n",
            replace_old != 0u ? "Replaced" : "Added",
            l86_cstr(ctx, co->name_va, NULL),
            l86_cstr(ctx, co->value_va, NULL),
            l86_cstr(ctx, co->domain_va, NULL),
            l86_cstr(ctx, co->path_va, NULL),
            expires);
    }
    if (replace_old == 0u) {
        if (lastc_va != 0u) {
            l86_wr32(ctx, lastc_va, co_va);
        } else {
            c->cookies_va = co_va;
        }
    }
    c->numcookies++;
    return co_va;
}

/* 0x10f11a80: a jar the caller did not pass is allocated with the file name (or "none") duplicated unchecked */
uint32_t rome2_l86_curl_cookie_init(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t file_va,
    uint32_t inc_va,
    uint32_t newsession) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return 0u;
    }
    const char *file = file_va != 0u ? l86_cstr(ctx, file_va, NULL) : NULL;
    uint32_t c_va = inc_va;
    uint8_t fromfile = 1u;
    if (c_va == 0u) {
        c_va = rome2_l82_calloc(ctx, 1u, (uint32_t)sizeof(rome2_curl_cookie_info_32));
        if (c_va == 0u) {
            return 0u;
        }
        l86_wr32(
            ctx,
            c_va + (uint32_t)offsetof(rome2_curl_cookie_info_32, filename_va),
            rome2_l82_strdup_va(ctx, file ? file : "none"));
    }
    rome2_curl_cookie_info_32 *c =
        (rome2_curl_cookie_info_32 *)rome2_l82_mut_ptr(ctx, c_va, (uint32_t)sizeof(*c));
    if (!c) {
        return 0u;
    }
    c->running = 0u;
    uint32_t fp_va = 0u;
    if (file) {
        if (rome2_l82_curl_strequal(ctx, file, "-") != 0u) {
            fp_va = s->stdin_va;
            fromfile = 0u;
        } else if (file[0] != '\0') {
            fp_va = l86_fopen(s, file, "r");
        }
    }
    c->newsession = newsession;
    if (fp_va != 0u) {
        uint32_t line_va = rome2_l82_alloc(ctx, ROME2_L86_COOKIE_LINE_BYTES);
        if (line_va != 0u) {
            for (uint32_t guard = 0u; guard < ROME2_L83_WALK_CAP; ++guard) {
                if (rome2_l86_crt_fgets(s, line_va, ROME2_L86_COOKIE_LINE_BYTES, fp_va) == 0u) {
                    break;
                }
                const char *line = l86_cstr(ctx, line_va, NULL);
                if (!line) {
                    break;
                }
                uint32_t headerline = rome2_l86_curl_raw_nequal("Set-Cookie:", line, 11u) != 0 ? 1u : 0u;
                uint32_t skip = headerline != 0u ? 11u : 0u;
                while (line[skip] != '\0' && l86_isblank(line[skip]) != 0u) {
                    skip++;
                }
                (void)rome2_l86_curl_cookie_add(s, data_va, c_va, headerline, line_va + skip, 0u, 0u);
            }
            rome2_l82_curl_free(ctx, line_va);
        }
        if (fromfile != 0u) {
            l86_fclose(s, fp_va);
        }
    }
    c->running = 1u;
    return c_va;
}

/* 0x10f11be0: one Netscape-format line per cookie; NULL for an empty jar or a failed allocation */
uint32_t rome2_l86_curl_cookie_list(rome2_l86_curl_state *s, uint32_t data_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return 0u;
    }
    uint32_t jar_va = l86_rd32(ctx, data_va + ROME2_L86_EASY_COOKIES_OFF);
    const rome2_curl_cookie_info_32 *jar =
        (const rome2_curl_cookie_info_32 *)rome2_l82_const_ptr(ctx, jar_va, (uint32_t)sizeof(*jar));
    if (jar_va == 0u || !jar || jar->numcookies == 0) {
        return 0u;
    }
    uint32_t list_va = 0u;
    uint32_t co_va = jar->cookies_va;
    for (uint32_t guard = 0u; co_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_cookie_32 *co = l86_cookie(ctx, co_va);
        if (!co) {
            break;
        }
        const char *domain = co->domain_va != 0u ? l86_cstr(ctx, co->domain_va, NULL) : NULL;
        int64_t expires = (int64_t)(((uint64_t)(uint32_t)co->expires_hi << 32) | (uint64_t)co->expires_lo);
        uint32_t line_va = rome2_l82_curl_maprintf(
            ctx,
            "%s%s%s\t%s\t%s\t%s\t%lld\t%s\t%s",
            co->httponly != 0u ? "#HttpOnly_" : "",
            (co->tailmatch != 0u && domain && domain[0] != '.') ? "." : "",
            domain ? domain : "unknown",
            co->tailmatch != 0u ? "TRUE" : "FALSE",
            co->path_va != 0u ? l86_cstr(ctx, co->path_va, NULL) : "/",
            co->secure != 0u ? "TRUE" : "FALSE",
            expires,
            l86_cstr(ctx, co->name_va, NULL),
            co->value_va != 0u ? l86_cstr(ctx, co->value_va, NULL) : "");
        if (line_va == 0u) {
            rome2_l82_curl_slist_free_all(ctx, list_va);
            return 0u;
        }
        uint32_t beg_va = rome2_l82_curl_slist_append(ctx, list_va, l86_cstr(ctx, line_va, NULL));
        rome2_l82_curl_free(ctx, line_va);
        if (beg_va == 0u) {
            rome2_l82_curl_slist_free_all(ctx, list_va);
            return 0u;
        }
        list_va = beg_va;
        co_va = co->next_va;
    }
    return list_va;
}

/*
 * 0x10f20af0. SHARE and UNSHARE update the specifier bit before the lock type
 * is range-checked, so an unknown type still flips its bit and returns
 * CURLSHE_BAD_OPTION.
 */
int32_t rome2_l86_curl_share_setopt(
    rome2_l86_curl_state *s,
    uint32_t share_va,
    int32_t option,
    uint32_t param) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    rome2_curl_share_32 *share =
        (rome2_curl_share_32 *)rome2_l82_mut_ptr(ctx, share_va, (uint32_t)sizeof(*share));
    if (!ctx || !share) {
        return ROME2_CURLSHE_INVALID;
    }
    if (share->dirty != 0u) {
        return ROME2_CURLSHE_IN_USE;
    }
    switch (option) {
    case ROME2_CURLSHOPT_SHARE:
        share->specifier |= 1u << (param & 31u);
        switch (param) {
        case ROME2_L86_CURL_LOCK_DATA_DNS:
            if (share->hostcache_va == 0u) {
                share->hostcache_va = rome2_l86_curl_mk_dnscache(ctx);
                if (share->hostcache_va == 0u) {
                    return ROME2_CURLSHE_NOMEM;
                }
            }
            return ROME2_CURLSHE_OK;
        case ROME2_L86_CURL_LOCK_DATA_COOKIE:
            if (share->cookies_va == 0u) {
                share->cookies_va = rome2_l86_curl_cookie_init(s, 0u, 0u, 0u, 1u);
                if (share->cookies_va == 0u) {
                    return ROME2_CURLSHE_NOMEM;
                }
            }
            return ROME2_CURLSHE_OK;
        case ROME2_L86_CURL_LOCK_DATA_SSL_SESSION:
            if (share->sslsession_va == 0u) {
                share->max_ssl_sessions = ROME2_L86_SSL_SESSIONS_DEFAULT;
                share->sslsession_va = rome2_l82_calloc(
                    ctx, ROME2_L86_SSL_SESSIONS_DEFAULT, (uint32_t)sizeof(rome2_curl_ssl_sessionid_32));
                share->sessionage = 0;
                if (share->sslsession_va == 0u) {
                    return ROME2_CURLSHE_NOMEM;
                }
            }
            return ROME2_CURLSHE_OK;
        case ROME2_L86_CURL_LOCK_DATA_CONNECT:
            return ROME2_CURLSHE_OK;
        default:
            return ROME2_CURLSHE_BAD_OPTION;
        }
    case ROME2_CURLSHOPT_UNSHARE:
        share->specifier &= ~(1u << (param & 31u));
        switch (param) {
        case ROME2_L86_CURL_LOCK_DATA_DNS:
            if (share->hostcache_va != 0u) {
                rome2_l82_curl_hash_destroy(ctx, share->hostcache_va);
                share->hostcache_va = 0u;
            }
            return ROME2_CURLSHE_OK;
        case ROME2_L86_CURL_LOCK_DATA_COOKIE:
            if (share->cookies_va != 0u) {
                rome2_l82_curl_cookie_cleanup(ctx, share->cookies_va);
                share->cookies_va = 0u;
            }
            return ROME2_CURLSHE_OK;
        case ROME2_L86_CURL_LOCK_DATA_SSL_SESSION:
            if (share->sslsession_va != 0u) {
                rome2_l82_curl_free(ctx, share->sslsession_va);
                share->sslsession_va = 0u;
            }
            return ROME2_CURLSHE_OK;
        case ROME2_L86_CURL_LOCK_DATA_CONNECT:
            return ROME2_CURLSHE_OK;
        default:
            return ROME2_CURLSHE_BAD_OPTION;
        }
    case ROME2_CURLSHOPT_LOCKFUNC:
        share->lockfunc_va = param;
        return ROME2_CURLSHE_OK;
    case ROME2_CURLSHOPT_UNLOCKFUNC:
        share->unlockfunc_va = param;
        return ROME2_CURLSHE_OK;
    case ROME2_CURLSHOPT_USERDATA:
        share->clientdata_va = param;
        return ROME2_CURLSHE_OK;
    default:
        return ROME2_CURLSHE_BAD_OPTION;
    }
}

/* Links a filled FormData node behind the chain tail and makes it the tail. */
static void l86_form_link(const rome2_l82_curl_ctx *ctx, uint32_t *formp_va, uint32_t node_va) {
    if (*formp_va != 0u) {
        l86_wr32(ctx, *formp_va, node_va);
    }
    *formp_va = node_va;
}

/*
 * AddFormData, inlined throughout 0x10f3f340. Data and content nodes copy
 * `length` bytes (strlen when zero) into a NUL-terminated buffer; callback and
 * file nodes keep the pointer and leave the node's length unwritten. A guest
 * source outside the arena fails as CURLE_OUT_OF_MEMORY.
 */
static int32_t l86_add_form_data(
    rome2_l82_curl_ctx *ctx,
    uint32_t *formp_va,
    int32_t type,
    uint32_t line_va,
    const uint8_t *line,
    uint32_t length,
    int64_t *size) {
    uint32_t node_va = rome2_l82_alloc(ctx, (uint32_t)sizeof(rome2_curl_formdata_32));
    rome2_curl_formdata_32 *node = l86_formdata(ctx, node_va);
    if (node_va == 0u || !node) {
        return ROME2_CURLE_OUT_OF_MEMORY;
    }
    node->next_va = 0u;
    if (type <= ROME2_CURL_FORM_CONTENT) {
        if (!line) {
            /* a guest source: an explicit length copies raw bytes, a zero length means strlen */
            if (length == 0u) {
                line = (const uint8_t *)l86_cstr(ctx, line_va, &length);
            } else {
                line = (const uint8_t *)rome2_l82_const_ptr(ctx, line_va, length);
            }
            if (!line) {
                rome2_l82_curl_free(ctx, node_va);
                return ROME2_CURLE_OUT_OF_MEMORY;
            }
        }
        node->line_va = rome2_l82_alloc(ctx, length + 1u);
        uint8_t *copy = (uint8_t *)rome2_l82_mut_ptr(ctx, node->line_va, length + 1u);
        if (node->line_va == 0u || !copy) {
            rome2_l82_curl_free(ctx, node_va);
            return ROME2_CURLE_OUT_OF_MEMORY;
        }
        memcpy(copy, line, length);
        node->length = length;
        copy[length] = 0u;
    } else {
        node->line_va = line_va;
    }
    node->type = type;
    l86_form_link(ctx, formp_va, node_va);
    *size = (int64_t)((uint64_t)*size + (uint64_t)length);
    return ROME2_CURLE_OK;
}

/* 0x10f3f060 */
int32_t rome2_l86_add_form_dataf(
    rome2_l82_curl_ctx *ctx,
    uint32_t *formp_va,
    int64_t *size,
    const char *fmt,
    ...) {
    if (!ctx || !formp_va || !fmt) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    char text[ROME2_L86_FORMDATAF_BYTES];
    text[0] = '\0';
    va_list ap;
    va_start(ap, fmt);
    (void)rome2_l82_curl_mvsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    int64_t unused = 0;
    return l86_add_form_data(
        ctx,
        formp_va,
        ROME2_CURL_FORM_DATA,
        0u,
        (const uint8_t *)text,
        l86_text_len(text, (uint32_t)sizeof(text)),
        size ? size : &unused);
}

/* 0x10f3f140: 28 dashes followed by 12 hex digits drawn through Curl_rand */
uint32_t rome2_l86_curl_form_boundary(rome2_l83_curl_state *g) {
    if (!g) {
        return 0u;
    }
    uint32_t boundary_va = rome2_l82_alloc(g->mem, ROME2_L86_FORM_BOUNDARY_BYTES);
    char *boundary = (char *)rome2_l82_mut_ptr(g->mem, boundary_va, ROME2_L86_FORM_BOUNDARY_BYTES);
    if (boundary_va == 0u || !boundary) {
        return 0u;
    }
    memcpy(boundary, ROME2_L86_FORM_BOUNDARY_DASHES, sizeof(ROME2_L86_FORM_BOUNDARY_DASHES));
    for (uint32_t i = (uint32_t)sizeof(ROME2_L86_FORM_BOUNDARY_DASHES) - 1u; i < ROME2_L86_FORM_BOUNDARY_BYTES - 1u; ++i) {
        boundary[i] = ROME2_L86_FORM_BOUNDARY_DIGITS[rome2_l86_curl_rand(g) & 0xfu];
    }
    boundary[ROME2_L86_FORM_BOUNDARY_BYTES - 1u] = '\0';
    return boundary_va;
}

/* 0x10f3f2d0: only data and content nodes own their line buffer */
void rome2_l86_curl_formclean(rome2_l82_curl_ctx *ctx, uint32_t *form_va) {
    if (!form_va || *form_va == 0u) {
        return;
    }
    uint32_t node_va = *form_va;
    for (uint32_t guard = 0u; node_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_formdata_32 *node = l86_formdata(ctx, node_va);
        if (!node) {
            break;
        }
        uint32_t next_va = node->next_va;
        if (node->type <= ROME2_CURL_FORM_CONTENT) {
            rome2_l82_curl_free(ctx, node->line_va);
        }
        rome2_l82_curl_free(ctx, node_va);
        node_va = next_va;
    }
    *form_va = 0u;
}

/* The file arm of 0x10f3f340: "-" reads stdin in 0x200-byte content nodes, any other name becomes one file node. */
static int32_t l86_form_add_file(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t contents_va,
    uint32_t *form_va,
    uint32_t *finalform_va,
    int64_t *size) {
    rome2_l82_curl_ctx *ctx = s->g->mem;
    const char *contents = l86_cstr(ctx, contents_va, NULL);
    uint32_t fileread_va = 0u;
    if (contents) {
        fileread_va = rome2_l82_curl_strequal(ctx, "-", contents) != 0u ? s->stdin_va : l86_fopen(s, contents, "rb");
    }
    if (fileread_va == 0u) {
        if (data_va != 0u) {
            rome2_l83_curl_failf(s->g, data_va, "couldn't open file \"%s\"", contents);
        }
        *finalform_va = 0u;
        return ROME2_L86_CURLE_READ_ERROR;
    }
    if (fileread_va != s->stdin_va) {
        l86_fclose(s, fileread_va);
        int64_t unused = 0;
        int32_t result = l86_add_form_data(ctx, form_va, ROME2_CURL_FORM_FILE, contents_va, NULL, 0u, &unused);
        if (result == ROME2_CURLE_OK && rome2_l82_curl_strequal(ctx, "-", contents) == 0u) {
            int64_t st_size = 0;
            if (s->on_stat64 && s->on_stat64(s, contents, &st_size) == 0) {
                *size = (int64_t)((uint64_t)*size + (uint64_t)st_size);
            }
        }
        return result;
    }
    uint8_t buffer[ROME2_L86_FORM_STDIN_CHUNK];
    for (uint32_t guard = 0u; guard < ROME2_L83_WALK_CAP; ++guard) {
        uint32_t nread = rome2_l86_crt_fread(s, buffer, 1u, ROME2_L86_FORM_STDIN_CHUNK, fileread_va);
        if (nread == 0u) {
            break;
        }
        if (nread > (uint32_t)ROME2_L86_FORM_STDIN_CHUNK) {
            nread = ROME2_L86_FORM_STDIN_CHUNK; /* a hook result above the request is clamped */
        }
        int32_t result = l86_add_form_data(ctx, form_va, ROME2_CURL_FORM_CONTENT, 0u, buffer, nread, size);
        if (result != ROME2_CURLE_OK) {
            return result;
        }
    }
    return ROME2_CURLE_OK;
}

/* One field of 0x10f3f340: its headers and contents, including every `more` file of a multi-file field. */
static int32_t l86_form_add_post(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t post_va,
    const char *boundary,
    uint32_t *fileboundary_va,
    uint32_t *form_va,
    uint32_t *finalform_va,
    int64_t *size) {
    rome2_l82_curl_ctx *ctx = s->g->mem;
    const rome2_curl_httppost_32 *post =
        (const rome2_curl_httppost_32 *)rome2_l82_const_ptr(ctx, post_va, (uint32_t)sizeof(*post));
    if (!post) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    int32_t result = ROME2_CURLE_OK;
    if (*size != 0) {
        result = rome2_l86_add_form_dataf(ctx, form_va, size, "\r\n");
    }
    if (result == ROME2_CURLE_OK) {
        result = rome2_l86_add_form_dataf(ctx, form_va, size, "--%s\r\n", boundary);
    }
    if (result == ROME2_CURLE_OK) {
        result = rome2_l86_add_form_dataf(ctx, form_va, size, "Content-Disposition: form-data; name=\"");
    }
    if (result == ROME2_CURLE_OK) {
        result = l86_add_form_data(ctx, form_va, ROME2_CURL_FORM_DATA, post->name_va, NULL, post->namelength, size);
    }
    if (result == ROME2_CURLE_OK) {
        result = rome2_l86_add_form_dataf(ctx, form_va, size, "\"");
    }
    if (result != ROME2_CURLE_OK) {
        return result;
    }
    if (post->more_va != 0u) {
        if (*fileboundary_va != 0u) {
            rome2_l82_curl_free(ctx, *fileboundary_va);
        }
        *fileboundary_va = rome2_l86_curl_form_boundary(s->g);
        if (*fileboundary_va == 0u) {
            return ROME2_CURLE_OUT_OF_MEMORY;
        }
        result = rome2_l86_add_form_dataf(
            ctx,
            form_va,
            size,
            "\r\nContent-Type: multipart/mixed, boundary=%s\r\n",
            l86_cstr(ctx, *fileboundary_va, NULL));
        if (result != ROME2_CURLE_OK) {
            return result;
        }
    }
    uint32_t file_va = post_va;
    for (uint32_t guard = 0u; file_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_httppost_32 *file =
            (const rome2_curl_httppost_32 *)rome2_l82_const_ptr(ctx, file_va, (uint32_t)sizeof(*file));
        if (!file) {
            return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
        }
        if (post->more_va != 0u) {
            uint32_t basename_va = 0u;
            if (file->showfilename_va == 0u) {
                basename_va = rome2_l86_strippath(ctx, file->contents_va);
                if (basename_va == 0u) {
                    return ROME2_CURLE_OUT_OF_MEMORY;
                }
            }
            result = rome2_l86_add_form_dataf(
                ctx,
                form_va,
                size,
                "\r\n--%s\r\nContent-Disposition: attachment; filename=\"%s\"",
                l86_cstr(ctx, *fileboundary_va, NULL),
                l86_cstr(ctx, file->showfilename_va != 0u ? file->showfilename_va : basename_va, NULL));
            if (basename_va != 0u) {
                rome2_l82_curl_free(ctx, basename_va);
            }
        } else if ((post->flags & (ROME2_HTTPPOST_FILENAME | ROME2_HTTPPOST_BUFFER | ROME2_HTTPPOST_CALLBACK)) != 0u &&
                   (post->showfilename_va != 0u || (post->flags & ROME2_HTTPPOST_FILENAME) != 0u)) {
            uint32_t basename_va = post->showfilename_va == 0u ? rome2_l86_strippath(ctx, post->contents_va) : 0u;
            result = rome2_l86_add_form_dataf(
                ctx,
                form_va,
                size,
                "; filename=\"%s\"",
                l86_cstr(ctx, post->showfilename_va != 0u ? post->showfilename_va : basename_va, NULL));
            if (basename_va != 0u) {
                rome2_l82_curl_free(ctx, basename_va);
            }
        }
        if (result == ROME2_CURLE_OK && file->contenttype_va != 0u) {
            result = rome2_l86_add_form_dataf(
                ctx, form_va, size, "\r\nContent-Type: %s", l86_cstr(ctx, file->contenttype_va, NULL));
        }
        uint32_t header_va = file->contentheader_va;
        for (uint32_t walk = 0u; result == ROME2_CURLE_OK && header_va != 0u && walk < ROME2_L83_WALK_CAP; ++walk) {
            const rome2_curl_slist_32 *header =
                (const rome2_curl_slist_32 *)rome2_l82_const_ptr(ctx, header_va, (uint32_t)sizeof(*header));
            if (!header) {
                break;
            }
            result = rome2_l86_add_form_dataf(ctx, form_va, size, "\r\n%s", l86_cstr(ctx, header->data_va, NULL));
            header_va = header->next_va;
        }
        if (result == ROME2_CURLE_OK) {
            result = rome2_l86_add_form_dataf(ctx, form_va, size, "\r\n\r\n");
        }
        if (result != ROME2_CURLE_OK) {
            return result;
        }
        if ((post->flags & (ROME2_HTTPPOST_FILENAME | ROME2_HTTPPOST_READFILE)) != 0u) {
            result = l86_form_add_file(s, data_va, file->contents_va, form_va, finalform_va, size);
        } else if ((post->flags & ROME2_HTTPPOST_BUFFER) != 0u) {
            result = l86_add_form_data(
                ctx, form_va, ROME2_CURL_FORM_CONTENT, post->buffer_va, NULL, post->bufferlength, size);
        } else if ((post->flags & ROME2_HTTPPOST_CALLBACK) != 0u) {
            result = l86_add_form_data(
                ctx, form_va, ROME2_CURL_FORM_CALLBACK, post->userp_va, NULL, post->contentslength, size);
        } else {
            result = l86_add_form_data(
                ctx, form_va, ROME2_CURL_FORM_CONTENT, post->contents_va, NULL, post->contentslength, size);
        }
        if (result != ROME2_CURLE_OK) {
            return result;
        }
        file_va = file->more_va;
    }
    if (post->more_va != 0u) {
        result = rome2_l86_add_form_dataf(
            ctx, form_va, size, "\r\n--%s--", l86_cstr(ctx, *fileboundary_va, NULL));
    }
    return result;
}

/*
 * 0x10f3f340. An unreadable post record ends the walk through the cleanup path
 * as CURLE_BAD_FUNCTION_ARGUMENT. The contents of every file of a field are
 * selected by the field's own flags; only the name, type and headers come from
 * the `more` record. The original stores the 64-bit size through its last
 * argument without a NULL test (0x10f3faa4, 0x10f3faaa); a NULL sizep is
 * skipped here.
 */
int32_t rome2_l86_curl_getformdata(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t *finalform_va,
    uint32_t post_va,
    uint32_t custom_content_type_va,
    int64_t *sizep) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx || !finalform_va) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    uint32_t form_va = 0u;
    uint32_t fileboundary_va = 0u;
    int64_t size = 0;
    *finalform_va = 0u;
    if (post_va == 0u) {
        return ROME2_CURLE_OK;
    }
    uint32_t boundary_va = rome2_l86_curl_form_boundary(s->g);
    const char *boundary = l86_cstr(ctx, boundary_va, NULL);
    if (boundary_va == 0u || !boundary) {
        return ROME2_CURLE_OUT_OF_MEMORY;
    }
    int32_t result = rome2_l86_add_form_dataf(
        ctx,
        &form_va,
        NULL,
        "%s; boundary=%s\r\n",
        custom_content_type_va != 0u ? l86_cstr(ctx, custom_content_type_va, NULL) : "Content-Type: multipart/form-data",
        boundary);
    if (result != ROME2_CURLE_OK) {
        rome2_l82_curl_free(ctx, boundary_va);
        return result;
    }
    uint32_t firstform_va = form_va;
    for (uint32_t guard = 0u; post_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        result = l86_form_add_post(s, data_va, post_va, boundary, &fileboundary_va, &form_va, finalform_va, &size);
        if (result != ROME2_CURLE_OK) {
            break;
        }
        post_va = l86_rd32(ctx, post_va + (uint32_t)offsetof(rome2_curl_httppost_32, next_va));
    }
    if (result == ROME2_CURLE_OK) {
        result = rome2_l86_add_form_dataf(ctx, &form_va, &size, "\r\n--%s--\r\n", boundary);
    }
    if (result != ROME2_CURLE_OK) {
        rome2_l86_curl_formclean(ctx, &firstform_va);
        if (fileboundary_va != 0u) {
            rome2_l82_curl_free(ctx, fileboundary_va);
        }
        rome2_l82_curl_free(ctx, boundary_va);
        return result;
    }
    if (sizep) {
        *sizep = size;
    }
    if (fileboundary_va != 0u) {
        rome2_l82_curl_free(ctx, fileboundary_va);
    }
    rome2_l82_curl_free(ctx, boundary_va);
    *finalform_va = firstform_va;
    return ROME2_CURLE_OK;
}

static uint32_t l86_formget_append(
    rome2_l86_curl_state *s,
    uint32_t fn_va,
    uint32_t arg_va,
    const uint8_t *buf,
    uint32_t len) {
    return s->on_formget_append ? s->on_formget_append(s, fn_va, arg_va, buf, len) : len;
}

/*
 * 0x10f404a0. A callback node offers the append callback zero bytes; a file
 * node is opened "rb" and streamed in 0x2000-byte reads. Every failure frees
 * the chain and returns -1.
 */
int32_t rome2_l86_curl_formget(
    rome2_l86_curl_state *s,
    uint32_t form_va,
    uint32_t arg_va,
    uint32_t append_fn_va) {
    rome2_l82_curl_ctx *ctx = l86_ctx(s);
    if (!ctx) {
        return ROME2_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    uint32_t data_va = 0u;
    int64_t size = 0;
    int32_t rc = rome2_l86_curl_getformdata(s, 0u, &data_va, form_va, 0u, &size);
    if (rc != ROME2_CURLE_OK) {
        return rc;
    }
    uint8_t buffer[ROME2_L86_FORMGET_CHUNK];
    uint32_t ptr_va = data_va;
    for (uint32_t guard = 0u; ptr_va != 0u && guard < ROME2_L83_WALK_CAP; ++guard) {
        const rome2_curl_formdata_32 *node = l86_formdata(ctx, ptr_va);
        if (!node) {
            break;
        }
        if (node->type == ROME2_CURL_FORM_FILE || node->type == ROME2_CURL_FORM_CALLBACK) {
            uint32_t fp_va = 0u;
            uint32_t nread = 0u;
            do {
                nread = 0u;
                if (node->type != ROME2_CURL_FORM_CALLBACK) {
                    if (fp_va == 0u) {
                        fp_va = l86_fopen(s, l86_cstr(ctx, node->line_va, NULL), "rb");
                        if (fp_va == 0u) {
                            rome2_l86_curl_formclean(ctx, &data_va);
                            return -1;
                        }
                    }
                    nread = rome2_l86_crt_fread(s, buffer, 1u, ROME2_L86_FORMGET_CHUNK, fp_va);
                    if (nread == 0u) {
                        l86_fclose(s, fp_va);
                        fp_va = 0u;
                    }
                }
                if (nread == 0xffffffffu || nread > (uint32_t)ROME2_L86_FORMGET_CHUNK ||
                    l86_formget_append(s, append_fn_va, arg_va, buffer, nread) != nread) {
                    if (fp_va != 0u) {
                        l86_fclose(s, fp_va);
                    }
                    rome2_l86_curl_formclean(ctx, &data_va);
                    return -1;
                }
            } while (nread != 0u);
        } else {
            const uint8_t *line = (const uint8_t *)rome2_l82_const_ptr(ctx, node->line_va, node->length);
            if (l86_formget_append(s, append_fn_va, arg_va, line, node->length) != node->length) {
                rome2_l86_curl_formclean(ctx, &data_va);
                return -1;
            }
        }
        ptr_va = node->next_va;
    }
    rome2_l86_curl_formclean(ctx, &data_va);
    return 0;
}
