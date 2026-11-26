#include "curl_util_printf_slist_share_ops.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t s_l82_arena[128u * 1024u];
static int s_l82_lock_calls = 0;
static int s_l82_unlock_calls = 0;
static int s_l82_llist_dtor_calls = 0;
static int s_l82_ssl_free_calls = 0;
static uint32_t s_l82_ssl_free_arg = 0u;

static void test_on_lock(
    rome2_l82_curl_ctx *ctx,
    uint32_t lockfunc_va,
    int32_t data,
    int32_t access,
    uint32_t userptr_va) {
    (void)ctx;
    (void)lockfunc_va;
    (void)data;
    (void)access;
    (void)userptr_va;
    s_l82_lock_calls++;
}

static void test_on_unlock(
    rome2_l82_curl_ctx *ctx,
    uint32_t unlockfunc_va,
    int32_t data,
    uint32_t userptr_va) {
    (void)ctx;
    (void)unlockfunc_va;
    (void)data;
    (void)userptr_va;
    s_l82_unlock_calls++;
}

static void test_on_llist_dtor(
    rome2_l82_curl_ctx *ctx,
    uint32_t dtor_fn_va,
    uint32_t user_va,
    uint32_t elem_ptr_va) {
    (void)dtor_fn_va;
    (void)user_va;
    s_l82_llist_dtor_calls++;
    rome2_l82_curl_free(ctx, elem_ptr_va);
}

static void test_on_ssl_free(rome2_l82_curl_ctx *ctx, uint32_t ssl_session_va) {
    (void)ctx;
    s_l82_ssl_free_arg = ssl_session_va;
    s_l82_ssl_free_calls++;
}

static const char *test_on_getenv(rome2_l82_curl_ctx *ctx, const char *name) {
    (void)ctx;
    if (name && strcmp(name, "ROME2_CURL_TEST") == 0) {
        return "http://localhost:8080";
    }
    return NULL;
}

static void setup_ctx(rome2_l82_curl_ctx *ctx) {
    memset(s_l82_arena, 0, sizeof(s_l82_arena));
    s_l82_lock_calls = 0;
    s_l82_unlock_calls = 0;
    s_l82_llist_dtor_calls = 0;
    s_l82_ssl_free_calls = 0;
    s_l82_ssl_free_arg = 0u;

    rome2_l82_ctx_init(ctx, s_l82_arena, 0x40000000u, (uint32_t)sizeof(s_l82_arena), 0x40001000u);
    ctx->on_share_lock = test_on_lock;
    ctx->on_share_unlock = test_on_unlock;
    ctx->on_llist_dtor = test_on_llist_dtor;
    ctx->on_ssl_session_free = test_on_ssl_free;
    ctx->on_getenv = test_on_getenv;
}

static void test_l82_slist_share_escape_and_date(void) {
    rome2_l82_curl_ctx ctx;
    setup_ctx(&ctx);

    /* slist append + free */
    uint32_t list_va = rome2_l82_curl_slist_append(&ctx, 0u, "Accept: application/json");
    assert(list_va != 0u);
    list_va = rome2_l82_curl_slist_append(&ctx, list_va, "User-Agent: Rome2");
    const rome2_curl_slist_32 *first = (const rome2_curl_slist_32 *)rome2_l82_const_ptr(
        &ctx, list_va, (uint32_t)sizeof(*first));
    assert(first != NULL && first->next_va != 0u);
    rome2_l82_curl_slist_free_all(&ctx, list_va);
    assert(ctx.free_count == 4u);

    /* Share + hash + llist + cookie + SSL session cleanup */
    uint32_t sh_va = rome2_l82_curl_share_init(&ctx);
    assert(sh_va != 0u);
    rome2_curl_share_32 *sh = (rome2_curl_share_32 *)rome2_l82_mut_ptr(
        &ctx, sh_va, (uint32_t)sizeof(*sh));
    assert(sh != NULL && sh->specifier == 2u);
    sh->lockfunc_va = 0x10f10001u;
    sh->unlockfunc_va = 0x10f10002u;

    /* Populate 1-bucket hash -> 1 llist -> 1 element */
    uint32_t hash_va = rome2_l82_calloc(&ctx, 1u, (uint32_t)sizeof(rome2_curl_hash_32));
    uint32_t buckets_va = rome2_l82_calloc(&ctx, 1u, 4u);
    uint32_t llist_va = rome2_l82_calloc(&ctx, 1u, (uint32_t)sizeof(rome2_curl_llist_32));
    uint32_t elem_va = rome2_l82_calloc(&ctx, 1u, (uint32_t)sizeof(rome2_curl_llist_element_32));
    uint32_t payload_va = rome2_l82_strdup_va(&ctx, "hostcache_entry");
    rome2_curl_hash_32 *h = (rome2_curl_hash_32 *)rome2_l82_mut_ptr(&ctx, hash_va, (uint32_t)sizeof(*h));
    uint32_t *bp = (uint32_t *)rome2_l82_mut_ptr(&ctx, buckets_va, 4u);
    rome2_curl_llist_32 *ll = (rome2_curl_llist_32 *)rome2_l82_mut_ptr(&ctx, llist_va, (uint32_t)sizeof(*ll));
    rome2_curl_llist_element_32 *el = (rome2_curl_llist_element_32 *)rome2_l82_mut_ptr(
        &ctx, elem_va, (uint32_t)sizeof(*el));
    assert(h && bp && ll && el);
    el->ptr_va = payload_va;
    ll->head_va = elem_va;
    ll->tail_va = elem_va;
    ll->dtor_fn_va = 0x10f10003u;
    ll->size = 1u;
    bp[0] = llist_va;
    h->table_va = buckets_va;
    h->slots = 1;
    h->size = 1u;
    sh->hostcache_va = hash_va;

    /* Populate cookie + ssl session array */
    uint32_t ci_va = rome2_l82_calloc(&ctx, 1u, (uint32_t)sizeof(rome2_curl_cookie_info_32));
    uint32_t co_va = rome2_l82_calloc(&ctx, 1u, (uint32_t)sizeof(rome2_curl_cookie_32));
    rome2_curl_cookie_info_32 *ci = (rome2_curl_cookie_info_32 *)rome2_l82_mut_ptr(
        &ctx, ci_va, (uint32_t)sizeof(*ci));
    rome2_curl_cookie_32 *co = (rome2_curl_cookie_32 *)rome2_l82_mut_ptr(
        &ctx, co_va, (uint32_t)sizeof(*co));
    assert(ci && co);
    co->name_va = rome2_l82_strdup_va(&ctx, "sid");
    co->value_va = rome2_l82_strdup_va(&ctx, "abc");
    ci->cookies_va = co_va;
    sh->cookies_va = ci_va;

    uint32_t ssl_arr_va = rome2_l82_calloc(&ctx, 1u, (uint32_t)sizeof(rome2_curl_ssl_sessionid_32));
    rome2_curl_ssl_sessionid_32 *ss = (rome2_curl_ssl_sessionid_32 *)rome2_l82_mut_ptr(
        &ctx, ssl_arr_va, (uint32_t)sizeof(*ss));
    assert(ss != NULL);
    ss->sessionid_va = 0x40000123u;
    ss->name_va = rome2_l82_strdup_va(&ctx, "ca.example");
    sh->sslsession_va = ssl_arr_va;
    sh->max_ssl_sessions = 1u;

    assert(rome2_l82_curl_share_cleanup(&ctx, sh_va) == ROME2_CURLSHE_OK);
    assert(s_l82_lock_calls == 1 && s_l82_unlock_calls == 1);
    assert(s_l82_llist_dtor_calls == 1 && s_l82_ssl_free_calls == 1);

    /* Escape, unescape, env, string equality, strerror, getdate */
    uint32_t esc_va = rome2_l82_curl_escape(&ctx, "a b/c~1", 0);
    const char *esc = (const char *)rome2_l82_const_ptr(&ctx, esc_va, 16u);
    assert(esc != NULL && strcmp(esc, "a%20b%2Fc~1") == 0);
    int32_t ulen = 0;
    uint32_t unesc_va = rome2_l82_curl_easy_unescape(&ctx, 0u, esc, 0, &ulen);
    const char *unesc = (const char *)rome2_l82_const_ptr(&ctx, unesc_va, 8u);
    assert(unesc != NULL && ulen == 7 && strcmp(unesc, "a b/c~1") == 0);
    rome2_l82_curl_free(&ctx, esc_va);
    rome2_l82_curl_free(&ctx, unesc_va);

    uint32_t env_va = rome2_l82_curl_getenv(&ctx, "ROME2_CURL_TEST");
    const char *env_s = (const char *)rome2_l82_const_ptr(&ctx, env_va, 16u);
    assert(env_s != NULL && strcmp(env_s, "http://localhost:8080") == 0);

    assert(rome2_l82_curl_strequal(&ctx, "Content-Type", "content-type") == 1u);
    assert(rome2_l82_curl_strnequal("HTTP/1.1", "http/2", 5u) == 1u);
    assert(strcmp(rome2_l82_curl_easy_strerror(28), "Timeout was reached") == 0);
    assert(strcmp(rome2_l82_curl_multi_strerror(-1), "Please call curl_multi_perform() soon") == 0);
    assert(strcmp(rome2_l82_curl_share_strerror(2), "Share currently in use") == 0);

    int64_t ts = rome2_l82_curl_getdate("Wed, 21 Oct 2015 07:28:00 GMT", NULL);
    assert(ts == 1445412480LL);
}

static void test_l82_mprintf_and_positional_args(void) {
    rome2_l82_curl_ctx ctx;
    setup_ctx(&ctx);

    char buf[128];
    int32_t n = rome2_l82_curl_msnprintf(buf, sizeof(buf), "%2$s=%1$04d%%", 7, "legion");
    assert(n == 12 && strcmp(buf, "legion=0007%") == 0);

    n = rome2_l82_curl_msprintf(buf, "%-5s|%u|%x", "TW", 42u, 0x2au);
    assert(n == 11 && strcmp(buf, "TW   |42|2a") == 0);

    uint32_t ap_va = rome2_l82_curl_maprintf(&ctx, "url=%s&port=%d", "rome2.local", 443);
    const char *ap_s = (const char *)rome2_l82_const_ptr(&ctx, ap_va, 24u);
    assert(ap_s != NULL && strcmp(ap_s, "url=rome2.local&port=443") == 0);
    rome2_l82_curl_free(&ctx, ap_va);

    /* Dynamic width & precision */
    n = rome2_l82_curl_msnprintf(buf, sizeof(buf), "[%*.*s]", 6, 3, "Centurion");
    assert(n == 8 && strcmp(buf, "[   Cen]") == 0);
}

static uint32_t session_dword(rome2_l82_curl_ctx *ctx, uint32_t record_va, uint32_t offset) {
    uint32_t value = 0u;
    const void *p = rome2_l82_const_ptr(ctx, record_va + offset, 4u);
    assert(p != NULL);
    memcpy(&value, p, sizeof(value));
    return value;
}

static void set_session_dword(rome2_l82_curl_ctx *ctx, uint32_t record_va, uint32_t offset, uint32_t value) {
    void *p = rome2_l82_mut_ptr(ctx, record_va + offset, 4u);
    assert(p != NULL);
    memcpy(p, &value, sizeof(value));
}

/*
 * 0x10f16310 by raw offset: the handle at +4 gates the body; it, the age at
 * +0xc, the five ssl_config strings at +0x28, +0x24, +0x3c, +0x38 and +0x34
 * and the name at +0 are released and cleared, and nothing else is written.
 */
static void test_l82_ssl_kill_session_offsets(void) {
    static const uint32_t cleared[] = {0x00u, 0x04u, 0x0cu, 0x24u, 0x28u, 0x34u, 0x38u, 0x3cu};
    rome2_l82_curl_ctx ctx;
    setup_ctx(&ctx);
    assert(sizeof(rome2_curl_ssl_sessionid_32) == 0x54u);
    uint32_t record_va = rome2_l82_calloc(&ctx, 1u, 0x54u);
    assert(record_va != 0u);
    for (uint32_t offset = 0u; offset < 0x54u; offset += 4u) {
        set_session_dword(&ctx, record_va, offset, 0x40000800u + offset);
    }

    /* no handle: nothing is released or cleared */
    set_session_dword(&ctx, record_va, 0x04u, 0u);
    uint32_t frees = ctx.free_count;
    rome2_l82_curl_ssl_kill_session(&ctx, record_va);
    assert(ctx.free_count == frees && s_l82_ssl_free_calls == 0);
    for (uint32_t offset = 0u; offset < 0x54u; offset += 4u) {
        assert(session_dword(&ctx, record_va, offset) == (offset == 0x04u ? 0u : 0x40000800u + offset));
    }

    set_session_dword(&ctx, record_va, 0x04u, 0x40000123u);
    rome2_l82_curl_ssl_kill_session(&ctx, record_va);
    assert(s_l82_ssl_free_calls == 1 && s_l82_ssl_free_arg == 0x40000123u);
    assert(ctx.free_count == frees + 6u); /* five strings and the name; the handle goes to SSL_SESSION_free */
    for (uint32_t offset = 0u; offset < 0x54u; offset += 4u) {
        uint32_t expected = 0x40000800u + offset;
        for (uint32_t i = 0u; i < sizeof(cleared) / sizeof(cleared[0]); ++i) {
            if (cleared[i] == offset) {
                expected = 0u;
            }
        }
        assert(session_dword(&ctx, record_va, offset) == expected);
    }

    /* a record with only a handle releases nothing through the allocator */
    set_session_dword(&ctx, record_va, 0x04u, 0x40000124u);
    set_session_dword(&ctx, record_va, 0x0cu, 9u);
    frees = ctx.free_count;
    rome2_l82_curl_ssl_kill_session(&ctx, record_va);
    assert(ctx.free_count == frees && s_l82_ssl_free_calls == 2 && s_l82_ssl_free_arg == 0x40000124u);
    assert(session_dword(&ctx, record_va, 0x04u) == 0u && session_dword(&ctx, record_va, 0x0cu) == 0u);
    rome2_l82_curl_ssl_kill_session(&ctx, 0u);
    assert(s_l82_ssl_free_calls == 2);
}

int main(void) {
    test_l82_slist_share_escape_and_date();
    test_l82_mprintf_and_positional_args();
    test_l82_ssl_kill_session_offsets();
    printf("curl_util_printf_slist_share_ops tests passed\n");
    return 0;
}
