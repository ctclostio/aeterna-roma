#include "curl_form_global_easy_multi_ops.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define L83_BASE 0x40000000u
#define L83_COUNT(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))
#define L83_LOG_CAP 24u
#define L83_USE_NMEMB 0xfffffffeu

static uint8_t s_arena[768u * 1024u];
static rome2_l82_curl_ctx s_ctx;
static rome2_l83_curl_state s_g;

static int32_t s_ossl_ids[L83_LOG_CAP];
static uint32_t s_ossl_a0[L83_LOG_CAP];
static uint32_t s_ossl_a2[L83_LOG_CAP];
static uint32_t s_ossl_count;
static int32_t s_ossl_result[ROME2_L83_OPENSSL_THUNK_COUNT];

static int32_t s_wsa_result;
static uint16_t s_wsa_version;
static uint16_t s_wsa_requested;
static uint32_t s_wsa_startup_calls;
static uint32_t s_wsa_cleanup_calls;

static uint32_t s_tick;
static uint64_t s_filetime;
static uint8_t s_filetime_precise_seen;

static int32_t s_recv_result;
static uint32_t s_recv_sockfd;

static int32_t s_send_result;
static int32_t s_send_code;
static uint32_t s_send_fn;
static uint32_t s_send_num;
static uint32_t s_send_mem;
static uint32_t s_send_len;

static uint32_t s_write_script[L83_LOG_CAP];
static uint32_t s_write_fn[L83_LOG_CAP];
static uint32_t s_write_size[L83_LOG_CAP];
static uint32_t s_write_nmemb[L83_LOG_CAP];
static uint32_t s_write_stream[L83_LOG_CAP];
static char s_write_text[L83_LOG_CAP][32];
static uint32_t s_write_count;

static uint32_t s_debug_calls;
static uint32_t s_debug_fn;
static uint32_t s_debug_data;
static int32_t s_debug_type;
static uint32_t s_debug_size;
static uint32_t s_debug_userp;
static char s_debug_last;

static uint32_t s_getsock_fn;
static uint32_t s_getsock_conn;
static int32_t s_getsock_numsocks;
static uint32_t s_getsock_calls;

static uint32_t s_dtor_calls;
static uint32_t s_dtor_fn;
static uint32_t s_dtor_user;
static uint32_t s_dtor_ptr;

static uint32_t rd32(uint32_t va) {
    const void *p = rome2_l82_const_ptr(&s_ctx, va, 4u);
    uint32_t v = 0u;
    assert(p != NULL);
    memcpy(&v, p, 4u);
    return v;
}

static void wr32(uint32_t va, uint32_t v) {
    void *p = rome2_l82_mut_ptr(&s_ctx, va, 4u);
    assert(p != NULL);
    memcpy(p, &v, 4u);
}

static const char *str_at(uint32_t va) {
    const char *s = (const char *)rome2_l82_const_ptr(&s_ctx, va, 1u);
    assert(s != NULL);
    return s;
}

static uint32_t put_str(const char *s) {
    uint32_t va = rome2_l82_strdup_va(&s_ctx, s);
    assert(va != 0u);
    return va;
}

static uint32_t zalloc(uint32_t bytes) {
    uint32_t va = rome2_l82_calloc(&s_ctx, 1u, bytes);
    assert(va != 0u);
    return va;
}

static uint32_t heap_used(void) {
    return s_ctx.heap_cursor - s_ctx.arena_base_va;
}

static int32_t on_openssl(rome2_l83_curl_state *g, int32_t id, uint32_t a0, uint32_t a1, uint32_t a2) {
    (void)g;
    (void)a1;
    assert(id >= 0 && id < ROME2_L83_OPENSSL_THUNK_COUNT);
    if (s_ossl_count < L83_LOG_CAP) {
        s_ossl_ids[s_ossl_count] = id;
        s_ossl_a0[s_ossl_count] = a0;
        s_ossl_a2[s_ossl_count] = a2;
    }
    s_ossl_count++;
    return s_ossl_result[id];
}

static int32_t on_wsa_startup(rome2_l83_curl_state *g, uint16_t version_requested, uint16_t *version_out) {
    (void)g;
    s_wsa_startup_calls++;
    s_wsa_requested = version_requested;
    *version_out = s_wsa_version;
    return s_wsa_result;
}

static void on_wsa_cleanup(rome2_l83_curl_state *g) {
    (void)g;
    s_wsa_cleanup_calls++;
}

static uint32_t on_get_tick_count(rome2_l83_curl_state *g) {
    (void)g;
    return s_tick;
}

static uint64_t on_system_filetime(rome2_l83_curl_state *g, uint8_t precise) {
    (void)g;
    s_filetime_precise_seen = precise;
    return s_filetime;
}

static int32_t on_recv_peek(rome2_l83_curl_state *g, uint32_t sockfd) {
    (void)g;
    s_recv_sockfd = sockfd;
    return s_recv_result;
}

static int32_t on_conn_send(
    rome2_l83_curl_state *g,
    uint32_t send_fn_va,
    uint32_t conn_va,
    uint32_t sockindex,
    uint32_t mem_va,
    uint32_t len,
    int32_t *curlcode) {
    (void)g;
    (void)conn_va;
    s_send_fn = send_fn_va;
    s_send_num = sockindex;
    s_send_mem = mem_va;
    s_send_len = len;
    *curlcode = s_send_code;
    return s_send_result;
}

static uint32_t on_write(
    rome2_l83_curl_state *g,
    uint32_t fn_va,
    const uint8_t *ptr,
    uint32_t size,
    uint32_t nmemb,
    uint32_t stream_va) {
    (void)g;
    uint32_t result = nmemb;
    if (s_write_count < L83_LOG_CAP) {
        uint32_t bytes = size * nmemb;
        uint32_t keep = bytes < 31u ? bytes : 31u;
        s_write_fn[s_write_count] = fn_va;
        s_write_size[s_write_count] = size;
        s_write_nmemb[s_write_count] = nmemb;
        s_write_stream[s_write_count] = stream_va;
        memset(s_write_text[s_write_count], 0, sizeof(s_write_text[s_write_count]));
        if (ptr && keep != 0u) {
            memcpy(s_write_text[s_write_count], ptr, keep);
        }
        if (s_write_script[s_write_count] != L83_USE_NMEMB) {
            result = s_write_script[s_write_count];
        }
    }
    s_write_count++;
    return result;
}

static void on_debug(
    rome2_l83_curl_state *g,
    uint32_t fn_va,
    uint32_t data_va,
    int32_t type,
    const char *text,
    uint32_t size,
    uint32_t userp_va) {
    (void)g;
    s_debug_calls++;
    s_debug_fn = fn_va;
    s_debug_data = data_va;
    s_debug_type = type;
    s_debug_size = size;
    s_debug_userp = userp_va;
    s_debug_last = size != 0u ? text[size - 1u] : '\0';
}

static uint32_t on_getsock(
    rome2_l83_curl_state *g,
    uint32_t fn_va,
    uint32_t conn_va,
    uint32_t *socks,
    int32_t numsocks) {
    (void)g;
    s_getsock_calls++;
    s_getsock_fn = fn_va;
    s_getsock_conn = conn_va;
    s_getsock_numsocks = numsocks;
    if (socks && numsocks > 0) {
        socks[0] = 0x51u;
    }
    return 0x77u;
}

static uint32_t on_hash_func(
    rome2_l83_curl_state *g,
    uint32_t fn_va,
    const void *key,
    uint32_t key_len,
    int32_t slots) {
    (void)g;
    uint32_t k = 0u;
    assert(fn_va == 0x7001u && key_len == 4u && slots > 0);
    memcpy(&k, key, 4u);
    return k % (uint32_t)slots;
}

static uint32_t on_hash_comp(
    rome2_l83_curl_state *g,
    uint32_t fn_va,
    uint32_t k1_va,
    uint32_t k1_len,
    const void *key,
    uint32_t key_len) {
    (void)g;
    assert(fn_va == 0x7002u);
    const void *k1 = rome2_l82_const_ptr(&s_ctx, k1_va, k1_len);
    return (k1 && k1_len == key_len && memcmp(k1, key, key_len) == 0) ? 1u : 0u;
}

static void on_llist_dtor(rome2_l82_curl_ctx *ctx, uint32_t dtor_fn_va, uint32_t user_va, uint32_t elem_ptr_va) {
    (void)ctx;
    s_dtor_calls++;
    s_dtor_fn = dtor_fn_va;
    s_dtor_user = user_va;
    s_dtor_ptr = elem_ptr_va;
}

static void reset_write_log(void) {
    s_write_count = 0u;
    for (uint32_t i = 0u; i < L83_LOG_CAP; ++i) {
        s_write_script[i] = L83_USE_NMEMB;
    }
}

static void setup(void) {
    memset(s_arena, 0, sizeof(s_arena));
    rome2_l82_ctx_init(&s_ctx, s_arena, L83_BASE, (uint32_t)sizeof(s_arena), L83_BASE + 0x100u);
    s_ctx.on_llist_dtor = on_llist_dtor;
    rome2_l83_state_init(&s_g, &s_ctx);
    s_g.on_openssl = on_openssl;
    s_g.on_wsa_startup = on_wsa_startup;
    s_g.on_wsa_cleanup = on_wsa_cleanup;
    s_g.on_get_tick_count = on_get_tick_count;
    s_g.on_system_filetime = on_system_filetime;
    s_g.on_recv_peek = on_recv_peek;
    s_g.on_conn_send = on_conn_send;
    s_g.on_write = on_write;
    s_g.on_debug = on_debug;
    s_g.on_getsock = on_getsock;
    s_g.on_hash_func = on_hash_func;
    s_g.on_hash_comp = on_hash_comp;

    s_ossl_count = 0u;
    for (uint32_t i = 0u; i < ROME2_L83_OPENSSL_THUNK_COUNT; ++i) {
        s_ossl_result[i] = 1;
    }
    s_wsa_result = 0;
    s_wsa_version = ROME2_CURL_WSA_VERSION;
    s_wsa_requested = 0u;
    s_wsa_startup_calls = 0u;
    s_wsa_cleanup_calls = 0u;
    s_tick = 0u;
    s_filetime = ROME2_L83_FILETIME_UNIX_EPOCH;
    s_filetime_precise_seen = 0xffu;
    s_recv_result = 0;
    s_recv_sockfd = 0u;
    s_send_result = 0;
    s_send_code = 0;
    s_send_fn = 0u;
    s_send_num = 0xffu;
    s_send_mem = 0u;
    s_send_len = 0u;
    reset_write_log();
    s_debug_calls = 0u;
    s_getsock_calls = 0u;
    s_getsock_fn = 0u;
    s_dtor_calls = 0u;
}

/* curl_llist with elements appended at the tail. */
static uint32_t make_llist(uint32_t dtor_fn_va) {
    uint32_t list_va = zalloc(0x10u);
    wr32(list_va + 8u, dtor_fn_va);
    return list_va;
}

static uint32_t llist_push(uint32_t list_va, uint32_t ptr_va) {
    uint32_t e_va = zalloc(0x0cu);
    uint32_t tail_va = rd32(list_va + 4u);
    wr32(e_va, ptr_va);
    wr32(e_va + 4u, tail_va);
    if (tail_va != 0u) {
        wr32(tail_va + 8u, e_va);
    } else {
        wr32(list_va, e_va);
    }
    wr32(list_va + 4u, e_va);
    wr32(list_va + 0x0cu, rd32(list_va + 0x0cu) + 1u);
    return e_va;
}

static uint32_t make_hash(int32_t slots) {
    uint32_t h_va = zalloc(0x18u);
    uint32_t table_va = zalloc((uint32_t)slots * 4u);
    for (int32_t i = 0; i < slots; ++i) {
        wr32(table_va + (uint32_t)i * 4u, make_llist(0x7003u));
    }
    wr32(h_va, table_va);
    wr32(h_va + 4u, 0x7001u);
    wr32(h_va + 8u, 0x7002u);
    wr32(h_va + 0x10u, (uint32_t)slots);
    return h_va;
}

/* Adds a socket-keyed entry and returns its 0x1c-byte payload. */
static uint32_t hash_add_socket(uint32_t h_va, uint32_t sockfd) {
    uint32_t key_va = zalloc(4u);
    uint32_t entry_va = zalloc(0x1cu);
    uint32_t he_va = zalloc(0x0cu);
    wr32(key_va, sockfd);
    wr32(he_va, entry_va);
    wr32(he_va + 4u, key_va);
    wr32(he_va + 8u, 4u);
    (void)llist_push(rd32(rd32(h_va) + (sockfd % rd32(h_va + 0x10u)) * 4u), he_va);
    wr32(h_va + 0x14u, rd32(h_va + 0x14u) + 1u);
    return entry_va;
}

static uint32_t make_conn(uint32_t data_va) {
    uint32_t conn_va = zalloc(0x4a8u);
    uint32_t handler_va = zalloc(0x40u);
    wr32(conn_va, data_va);
    wr32(conn_va + ROME2_CURL_CONN_HANDLER_OFF, handler_va);
    return conn_va;
}

static uint32_t open_easy(void) {
    uint32_t data_va = 0u;
    assert(rome2_l83_curl_open(&s_g, &data_va) == ROME2_CURLE_OK);
    assert(data_va != 0u);
    return data_va;
}

static void test_global_init_and_cleanup(void) {
    setup();
    s_filetime = ROME2_L83_FILETIME_UNIX_EPOCH + 1000000000ULL * 10000000ULL + 1234567ULL;
    assert(rome2_l83_curl_global_init(&s_g, ROME2_CURL_GLOBAL_ALL) == ROME2_CURLE_OK);
    assert(s_g.initialized == 1u && s_g.init_flags == 3u && s_g.ssl_initialized == 1u);
    assert(s_ossl_count == 3u);
    assert(s_ossl_ids[0] == ROME2_L83_SSLEAY32_ORD_74 && s_ossl_ids[1] == ROME2_L83_SSLEAY32_ORD_183);
    assert(s_ossl_ids[2] == ROME2_L83_LIBEAY32_ORD_3212);
    assert(s_wsa_startup_calls == 1u && s_wsa_requested == 0x0202u && s_wsa_cleanup_calls == 0u);
    assert(s_g.resolver_stub_calls == 1u && s_filetime_precise_seen == 0u);
    uint32_t seed = 1000000000u; /* three folded LCG steps */
    for (int i = 0; i < 3; ++i) {
        seed = seed * 1103515245u + 12345u;
    }
    assert(s_g.randseed == seed);

    /* nested init only counts */
    assert(rome2_l83_curl_global_init(&s_g, 0u) == ROME2_CURLE_OK);
    assert(s_g.initialized == 2u && s_g.init_flags == 3u && s_ossl_count == 3u && s_wsa_startup_calls == 1u);
    rome2_l83_curl_global_cleanup(&s_g);
    assert(s_g.initialized == 1u && s_ossl_count == 3u && s_wsa_cleanup_calls == 0u);

    uint32_t cache_va = make_hash(3);
    (void)hash_add_socket(cache_va, 4u);
    s_g.hostname_cache_va = cache_va;
    s_g.host_cache_initialized = 1u;
    rome2_l83_curl_global_cleanup(&s_g);
    assert(s_g.initialized == 0u && s_g.init_flags == 0u && s_g.ssl_initialized == 0u);
    assert(s_g.host_cache_initialized == 0u && rd32(cache_va) == 0u && rd32(cache_va + 0x10u) == 0u);
    assert(s_dtor_calls == 1u && s_dtor_user == cache_va);
    assert(s_ossl_count == 7u);
    assert(s_ossl_ids[3] == ROME2_L83_LIBEAY32_ORD_298 && s_ossl_ids[4] == ROME2_L83_LIBEAY32_ORD_2604);
    assert(s_ossl_ids[5] == ROME2_L83_LIBEAY32_ORD_224 && s_ossl_ids[6] == ROME2_L83_LIBEAY32_ORD_254);
    assert(s_ossl_a0[6] == 0u && s_wsa_cleanup_calls == 1u && s_g.nop_stub_calls == 1u);
    rome2_l83_curl_global_cleanup(&s_g);
    assert(s_g.initialized == 0u && s_ossl_count == 7u && s_g.nop_stub_calls == 1u);

    /* SSL bring-up failure leaves the count raised and the flag set */
    setup();
    s_ossl_result[ROME2_L83_SSLEAY32_ORD_183] = 0;
    assert(rome2_l83_curl_global_init(&s_g, ROME2_CURL_GLOBAL_SSL) == ROME2_CURLE_FAILED_INIT);
    assert(s_g.initialized == 1u && s_g.ssl_initialized == 1u && s_g.init_flags == 0u && s_ossl_count == 2u);
    assert(s_g.resolver_stub_calls == 0u);
    assert(rome2_l83_curl_global_init(&s_g, ROME2_CURL_GLOBAL_SSL) == ROME2_CURLE_OK && s_g.initialized == 2u);
    assert(rome2_l83_curl_ssl_init(&s_g) == 1 && s_ossl_count == 2u);

    setup();
    s_wsa_result = 10091;
    assert(rome2_l83_curl_global_init(&s_g, ROME2_CURL_GLOBAL_WIN32) == ROME2_CURLE_FAILED_INIT);
    assert(s_wsa_cleanup_calls == 0u && s_ossl_count == 0u);
    setup();
    s_wsa_version = 0x0101u;
    assert(rome2_l83_curl_global_init(&s_g, ROME2_CURL_GLOBAL_WIN32) == ROME2_CURLE_FAILED_INIT);
    assert(s_wsa_cleanup_calls == 1u && s_g.init_flags == 0u);
    setup();
    s_wsa_version = 0x0102u;
    assert(rome2_l83_curl_global_init(&s_g, ROME2_CURL_GLOBAL_WIN32) == ROME2_CURLE_FAILED_INIT);
    assert(s_wsa_cleanup_calls == 1u);

    /* allocator overrides */
    setup();
    assert(s_g.malloc_fn_va == 0x1168d0c3u && s_g.calloc_fn_va == 0x1169d9adu);
    assert(rome2_l83_curl_global_init_mem(&s_g, 0u, 0x501u, 0x502u, 0u, 0x504u, 0x505u) == ROME2_CURLE_FAILED_INIT);
    assert(s_g.initialized == 0u);
    assert(rome2_l83_curl_global_init_mem(&s_g, 0u, 0x501u, 0x502u, 0x503u, 0x504u, 0x505u) == ROME2_CURLE_OK);
    assert(s_g.initialized == 1u && s_g.malloc_fn_va == 0x501u && s_g.free_fn_va == 0x502u);
    assert(s_g.realloc_fn_va == 0x503u && s_g.strdup_fn_va == 0x504u && s_g.calloc_fn_va == 0x505u);
    assert(rome2_l83_curl_global_init_mem(&s_g, 0u, 0x601u, 0x602u, 0x603u, 0x604u, 0x605u) == ROME2_CURLE_OK);
    assert(s_g.initialized == 1u && s_g.malloc_fn_va == 0x501u);
    rome2_l83_curl_global_cleanup(&s_g);
    assert(rome2_l83_curl_global_init(&s_g, 0u) == ROME2_CURLE_OK);
    assert(s_g.malloc_fn_va == 0x1168d0c3u && s_g.free_fn_va == 0x1168d0a8u && s_g.realloc_fn_va == 0x1169d9a2u);
    assert(s_g.strdup_fn_va == 0x116b204du && s_g.calloc_fn_va == 0x1169d9adu);

    /* thunk table */
    assert(rome2_l83_openssl_thunks[ROME2_L83_SSLEAY32_ORD_76].thunk_va == 0x116c7f93u);
    assert(rome2_l83_openssl_thunks[ROME2_L83_SSLEAY32_ORD_76].iat_slot_va == 0x1172f588u);
    assert(rome2_l83_openssl_thunks[ROME2_L83_LIBEAY32_ORD_254].ordinal == 254u);
    assert(rome2_l83_openssl_thunk(&s_g, ROME2_L83_OPENSSL_THUNK_COUNT, 0u, 0u, 0u) == 0);
}

static void test_time_helpers(void) {
    setup();
    rome2_crt_timespec64 ts = {7, 7};
    assert(rome2_l83_crt_timespec_get(&s_g, NULL, 1) == 0);
    assert(s_ctx.last_errno == 22 && s_g.invalid_parameter_calls == 1u);
    assert(rome2_l83_crt_timespec_get(&s_g, &ts, 2) == 0 && ts.tv_sec == 7 && ts.tv_nsec == 7);

    s_filetime = ROME2_L83_FILETIME_UNIX_EPOCH + 15ULL * 10000000ULL + 1234567ULL;
    assert(rome2_l83_crt_timespec_get(&s_g, &ts, 1) == 1 && ts.tv_sec == 15 && ts.tv_nsec == 123456700);
    s_filetime = ROME2_L83_FILETIME_UNIX_EPOCH + (uint64_t)ROME2_L83_FILETIME_SPAN_LIMIT;
    assert(rome2_l83_crt_timespec_get(&s_g, &ts, 1) == 0 && ts.tv_sec == 15);
    s_filetime -= 1u;
    assert(rome2_l83_crt_timespec_get(&s_g, &ts, 1) == 1);
    assert(ts.tv_sec == 32536799999LL && ts.tv_nsec == 999999900);
    s_filetime = ROME2_L83_FILETIME_UNIX_EPOCH - 10000005ULL; /* before the epoch: signed division */
    assert(rome2_l83_crt_timespec_get(&s_g, &ts, 1) == 1 && ts.tv_sec == -1 && ts.tv_nsec == -500);

    int64_t out = 0;
    s_g.has_precise_filetime = 1u;
    s_filetime = ROME2_L83_FILETIME_UNIX_EPOCH + 42ULL * 10000000ULL;
    assert(rome2_l83_crt_time64(&s_g, &out) == 42 && out == 42 && s_filetime_precise_seen == 1u);
    assert(rome2_l83_crt_time64(&s_g, NULL) == 42);
    s_filetime = ROME2_L83_FILETIME_UNIX_EPOCH + (uint64_t)ROME2_L83_FILETIME_SPAN_LIMIT;
    assert(rome2_l83_crt_time64(&s_g, &out) == -1 && out == -1);
    rome2_l83_curl_srand(&s_g);
    assert(s_g.randseed == 0xffffffffu * ROME2_L83_RANDSEED_MUL + ROME2_L83_RANDSEED_ADD);

    uint64_t ft = 5u;
    s_g.on_system_filetime = NULL;
    rome2_l83_crt_get_system_time_precise_as_file_time(&s_g, &ft);
    assert(ft == 5u);

    s_tick = 123456789u;
    rome2_curl_timeval_32 now = rome2_l83_curlx_tvnow(&s_g);
    assert(now.tv_sec == 123456 && now.tv_usec == 789000);
    s_tick = 0xffffffffu;
    now = rome2_l83_curlx_tvnow(&s_g);
    assert(now.tv_sec == 4294967 && now.tv_usec == 295000);

    rome2_curl_timeval_32 a = {10, 500000};
    rome2_curl_timeval_32 b = {8, 250000};
    rome2_curl_timeval_32 c = {5, 100};
    rome2_curl_timeval_32 d = {5, 999900};
    assert(rome2_l83_curlx_tvdiff(a, b) == 2250 && rome2_l83_curlx_tvdiff(b, a) == -2250);
    assert(rome2_l83_curlx_tvdiff(c, d) == -999 && rome2_l83_curlx_tvdiff(d, c) == 999);
}

static void test_hash_and_llist(void) {
    setup();
    uint32_t h_va = make_hash(7);
    uint32_t entry5 = hash_add_socket(h_va, 5u);
    uint32_t entry12 = hash_add_socket(h_va, 12u); /* same bucket as 5 */
    uint32_t key = 5u;
    assert(rome2_l83_curl_hash_pick(&s_g, h_va, &key, 4u) == entry5);
    key = 12u;
    assert(rome2_l83_curl_hash_pick(&s_g, h_va, &key, 4u) == entry12);
    key = 19u;
    assert(rome2_l83_curl_hash_pick(&s_g, h_va, &key, 4u) == 0u);
    key = 6u;
    assert(rome2_l83_curl_hash_pick(&s_g, h_va, &key, 4u) == 0u);

    uint32_t multi_va = zalloc(0x78u);
    wr32(multi_va + 0x5cu, h_va);
    assert(rome2_l83_curl_multi_assign(&s_g, multi_va, 12u, 0xabcu) == ROME2_CURLM_OK);
    assert(rd32(entry12 + 0x18u) == 0xabcu && rd32(entry5 + 0x18u) == 0u);
    assert(rome2_l83_curl_multi_assign(&s_g, multi_va, ROME2_CURL_SOCKET_BAD, 1u) == ROME2_CURLM_BAD_SOCKET);
    assert(rome2_l83_curl_multi_assign(&s_g, multi_va, 77u, 1u) == ROME2_CURLM_BAD_SOCKET);

    uint32_t frees = s_ctx.free_count;
    rome2_l83_curl_hash_clean(&s_ctx, h_va);
    assert(rd32(h_va) == 0u && rd32(h_va + 0x10u) == 0u && rd32(h_va + 0x14u) == 0u);
    assert(s_dtor_calls == 2u && s_dtor_fn == 0x7003u && s_dtor_user == h_va);
    assert(s_ctx.free_count - frees == 10u); /* 7 lists, 2 elements, the table */

    s_dtor_calls = 0u;
    uint32_t list_va = make_llist(0x7003u);
    uint32_t a_va = llist_push(list_va, 0x11u);
    uint32_t b_va = llist_push(list_va, 0x22u);
    uint32_t c_va = llist_push(list_va, 0x33u);
    assert(rome2_l83_curl_llist_count(&s_ctx, list_va) == 3u);
    frees = s_ctx.free_count;
    assert(rome2_l83_curl_llist_remove(&s_ctx, list_va, b_va, 0x99u) == 1);
    assert(rd32(a_va + 8u) == c_va && rd32(c_va + 4u) == a_va && rd32(list_va + 0x0cu) == 2u);
    assert(s_dtor_calls == 1u && s_dtor_user == 0x99u && s_dtor_ptr == 0x22u);
    assert(rd32(b_va) == 0u && rd32(b_va + 4u) == 0u && rd32(b_va + 8u) == 0u && s_ctx.free_count - frees == 1u);
    assert(rome2_l83_curl_llist_remove(&s_ctx, list_va, c_va, 0u) == 1);
    assert(rd32(list_va + 4u) == a_va && rd32(a_va + 8u) == 0u && rd32(list_va) == a_va);
    assert(rome2_l83_curl_llist_remove(&s_ctx, list_va, a_va, 0u) == 1);
    assert(rd32(list_va) == 0u && rd32(list_va + 4u) == 0u && rome2_l83_curl_llist_count(&s_ctx, list_va) == 0u);
    assert(s_dtor_calls == 3u);
    assert(rome2_l83_curl_llist_remove(&s_ctx, list_va, a_va, 0u) == 1 && s_dtor_calls == 3u);
    assert(rome2_l83_curl_llist_remove(&s_ctx, list_va, 0u, 0u) == 1 && s_dtor_calls == 3u);

    uint32_t x_va = llist_push(list_va, 0x44u);
    uint32_t y_va = llist_push(list_va, 0x55u);
    assert(rome2_l83_curl_llist_remove(&s_ctx, list_va, x_va, 0u) == 1);
    assert(rd32(list_va) == y_va && rd32(y_va + 4u) == 0u && rd32(list_va + 4u) == y_va);
}

static void test_easy_open_and_reset(void) {
    setup();
    uint32_t data_va = rome2_l83_curl_easy_init(&s_g);
    assert(data_va != 0u && s_g.initialized == 1u && s_g.init_flags == 3u && s_g.resolver_stub_calls == 2u);
    assert(rd32(data_va + 0x8784u) == 0xc0dedbadu);
    uint32_t headerbuff_va = rd32(data_va + 0x58cu);
    assert(headerbuff_va != 0u && rd32(data_va + 0x590u) == 0x100u && rd32(data_va + 0x588u) == 0xffffffffu);
    assert(rd32(data_va + 0x28u) == 0xffffffffu && rd32(data_va + 0x2cu) == 0xffffffffu);
    assert(rd32(data_va + 0x8598u) == 0xffffffffu && rd32(data_va + 0x859cu) == 0xffffffffu);
    assert(rd32(data_va + 0x128u) == 0x119ebe18u + 0x70u); /* err: stderr */
    assert(rd32(data_va + 0x138u) == 0x119ebe18u + 0x38u); /* out: stdout */
    assert(rd32(data_va + 0x13cu) == 0x119ebe18u);         /* in: stdin */
    assert(rd32(data_va + 0x180u) == 0x11688039u && rd32(data_va + 0x18cu) == 0x1168ebe6u);
    assert(rd32(data_va + 0x134u) == 0x438u && rd32(data_va + 0x158u) == 0xffffffffu);
    assert(rd32(data_va + 0x170u) == 0xffffffffu && rd32(data_va + 0x174u) == 0xffffffffu);
    assert(rd32(data_va + 0x1e8u) == 0xffffffffu && rd32(data_va + 0x1ecu) == 0xffffffffu);
    assert(rd32(data_va + 0x14cu) == 1u && rd32(data_va + 0x150u) == 1u && rd32(data_va + 0x250u) == 1u);
    assert(rd32(data_va + 0x260u) == 1u && rd32(data_va + 0x264u) == 2u && rd32(data_va + 0x284u) == 5u);
    assert(rd32(data_va + 0x290u) == 1u && rd32(data_va + 0x29cu) == 0x3cu && rd32(data_va + 0x2c0u) == 1u);
    assert(rd32(data_va + 0x2ecu) == 1u && rd32(data_va + 0x32cu) == 1u && rd32(data_va + 0x330u) == 1u);
    assert(rd32(data_va + 0x360u) == 0xffffffffu && rd32(data_va + 0x36cu) == 0x1a4u);
    assert(rd32(data_va + 0x370u) == 0x1edu && rd32(data_va + 0x414u) == 0xffffffffu);
    assert(rd32(data_va + 0x418u) == 0xfffffbefu && rd32(data_va + 0x420u) == 1u);
    assert(rd32(data_va + 0x444u) == 0x3cu && rd32(data_va + 0x448u) == 0x3cu && rd32(data_va + 0x4a8u) == 0x10u);
    assert(rd32(data_va + 0x31cu) == 0u && rd32(data_va + 0x358u) == 0u && rd32(data_va + 0x85b0u) == 0u);

    /* dirty the handle, then reset */
    uint32_t str0 = put_str("http://rome2.local/");
    uint32_t str37 = put_str("agent");
    wr32(data_va + 0x378u, str0);
    wr32(data_va + 0x378u + 37u * 4u, str37);
    wr32(data_va + 0x458u, put_str("referer"));
    wr32(data_va + 0x45cu, 1u);
    wr32(data_va + 0x868cu, put_str("/path"));
    wr32(data_va + 0x8690u, 0x1234u);
    wr32(data_va + 0x86bcu, zalloc(8u));
    wr32(data_va + 0x31cu, 1u);
    wr32(data_va + 0x358u, 1u);
    wr32(data_va + 0x134u, 8080u);
    wr32(data_va + 0x470u, 0x55u);
    wr32(data_va + 0x574u, 0x66u);
    wr32(data_va + 0xf8u, 3u);
    wr32(data_va + 0x28u, 0u);
    wr32(data_va + 0x8598u, 0u);
    uint32_t frees = s_ctx.free_count;
    rome2_l83_curl_easy_reset(&s_ctx, data_va);
    assert(s_ctx.free_count - frees == 5u);
    assert(rd32(data_va + 0x378u) == 0u && rd32(data_va + 0x378u + 37u * 4u) == 0u);
    assert(rd32(data_va + 0x458u) == 0u && rd32(data_va + 0x45cu) == 0u);
    assert(rd32(data_va + 0x868cu) == 0u && rd32(data_va + 0x8690u) == 0u && rd32(data_va + 0x86bcu) == 0u);
    assert(rd32(data_va + 0x31cu) == 0u && rd32(data_va + 0x358u) == 0u && rd32(data_va + 0x134u) == 0x438u);
    assert(rd32(data_va + 0x470u) == 0u && rd32(data_va + 0x574u) == 0u && rd32(data_va + 0x4a8u) == 0x10u);
    assert(rd32(data_va + 0xf8u) == 0u && rd32(data_va + 0x28u) == 0xffffffffu);
    assert(rd32(data_va + 0x2cu) == 0xffffffffu && rd32(data_va + 0x8598u) == 0xffffffffu);
    assert(rd32(data_va + 0x58cu) == headerbuff_va && rd32(data_va + 0x8784u) == 0xc0dedbadu);

    /* a referer the handle does not own is dropped without a free */
    wr32(data_va + 0x458u, 0x4000beefu);
    frees = s_ctx.free_count;
    rome2_l83_curl_freeset(&s_ctx, data_va);
    assert(s_ctx.free_count == frees && rd32(data_va + 0x458u) == 0u);

    uint32_t set_va = zalloc(ROME2_CURL_EASY_SET_BYTES);
    assert(rome2_l83_curl_init_userdefined(&s_ctx, set_va) == ROME2_CURLE_OK);
    assert(rd32(set_va) == 0x119ebe18u + 0x70u && rd32(set_va + 0x10u) == 0x119ebe18u + 0x38u);
    assert(rd32(set_va + 0x0cu) == 0x438u && rd32(set_va + 0xbcu * 4u) == 0xfffffbefu);
    assert(rd32(set_va + 200u * 4u) == 0x3cu && rd32(set_va + 199u * 4u) == 0x3cu);

    uint32_t data2_va = zalloc(ROME2_CURL_EASY_BYTES);
    memset(rome2_l82_mut_ptr(&s_ctx, data2_va + 0x18u, 0x110u), 0xee, 0x110u);
    rome2_l83_curl_easy_init_handle_data(&s_ctx, data2_va);
    assert(rd32(data2_va + 0x18u) == 0u && rd32(data2_va + 0x124u) == 0u && rd32(data2_va + 0x28u) == 0xffffffffu);

    /* allocation failures */
    uint32_t out_va = 0x1111u;
    uint32_t full_size = s_ctx.arena_size;
    assert(rome2_l83_curl_open(&s_g, NULL) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT);
    s_ctx.arena_size = heap_used() + 0x100u;
    assert(rome2_l83_curl_open(&s_g, &out_va) == ROME2_CURLE_OUT_OF_MEMORY && out_va == 0x1111u);
    s_ctx.arena_size = heap_used() + ROME2_CURL_EASY_BYTES;
    frees = s_ctx.free_count;
    uint32_t nops = s_g.nop_stub_calls;
    assert(rome2_l83_curl_open(&s_g, &out_va) == ROME2_CURLE_OUT_OF_MEMORY && out_va == 0x1111u);
    assert(s_ctx.free_count - frees == 1u && s_g.nop_stub_calls - nops == 1u);
    s_ctx.arena_size = full_size;

    setup();
    s_ossl_result[ROME2_L83_SSLEAY32_ORD_183] = 0;
    assert(rome2_l83_curl_easy_init(&s_g) == 0u && s_g.initialized == 1u && s_ctx.alloc_count == 0u);
}

static void test_client_write_and_pause(void) {
    setup();
    uint32_t data_va = open_easy();
    uint32_t conn_va = make_conn(data_va);
    wr32(data_va + 0x86c0u, conn_va);
    uint32_t hello_va = put_str("hello");
    uint32_t world_va = put_str("world!");

    assert(rome2_l83_curl_client_write(&s_g, conn_va, 1u, hello_va, 5u) == ROME2_CURLE_OK);
    assert(s_write_count == 1u && s_write_fn[0] == 0x11688039u && s_write_stream[0] == 0x119ebe18u + 0x38u);
    assert(s_write_size[0] == 1u && s_write_nmemb[0] == 5u && strcmp(s_write_text[0], "hello") == 0);
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 1u, world_va, 0u) == ROME2_CURLE_OK);
    assert(s_write_count == 2u && s_write_nmemb[1] == 6u);

    /* headers: nothing without a header target, then the body callback, then the header callback */
    reset_write_log();
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 2u, hello_va, 5u) == ROME2_CURLE_OK && s_write_count == 0u);
    wr32(data_va + 0x140u, 0x9000u);
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 2u, hello_va, 5u) == ROME2_CURLE_OK);
    assert(s_write_count == 1u && s_write_fn[0] == 0x11688039u && s_write_stream[0] == 0x9000u);
    wr32(data_va + 0x184u, 0x8001u);
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 3u, hello_va, 5u) == ROME2_CURLE_OK);
    assert(s_write_count == 3u && s_write_fn[1] == 0x11688039u && s_write_stream[1] == 0x119ebe18u + 0x38u);
    assert(s_write_fn[2] == 0x8001u && s_write_stream[2] == 0x9000u);

    /* short writes format the failure text once into the error buffer */
    uint32_t errbuf_va = zalloc(0x100u);
    wr32(data_va + 0x130u, errbuf_va);
    reset_write_log();
    s_write_script[0] = 3u;
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 1u, hello_va, 5u) == ROME2_CURLE_WRITE_ERROR);
    assert(strcmp(str_at(data_va + 0x594u), "Failed writing body (3 != 5)") == 0);
    assert(strcmp(str_at(errbuf_va), "Failed writing body (3 != 5)") == 0 && rd32(data_va + 0x85c0u) == 1u);
    reset_write_log();
    s_write_script[0] = 0u;
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 2u, hello_va, 5u) == ROME2_CURLE_WRITE_ERROR);
    assert(strcmp(str_at(data_va + 0x594u), "Failed writing header") == 0);
    assert(strcmp(str_at(errbuf_va), "Failed writing body (3 != 5)") == 0);

    /* pause from the body callback, append while paused */
    reset_write_log();
    s_write_script[0] = ROME2_CURL_WRITEFUNC_PAUSE;
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 1u, hello_va, 5u) == ROME2_CURLE_OK);
    uint32_t temp_va = rd32(data_va + 0x85b0u);
    assert(temp_va != 0u && temp_va != hello_va && rd32(data_va + 0x85b4u) == 5u && rd32(data_va + 0x85b8u) == 1u);
    assert((rd32(data_va + 0xf8u) & 0x10u) != 0u && memcmp(str_at(temp_va), "hello", 5u) == 0);
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 2u, world_va, 6u) == ROME2_CURLE_RECV_ERROR);
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 1u, world_va, 6u) == ROME2_CURLE_OK);
    assert(s_write_count == 1u && rd32(data_va + 0x85b4u) == 11u);
    assert(memcmp(str_at(rd32(data_va + 0x85b0u)), "helloworld!", 11u) == 0);
    uint32_t full_size = s_ctx.arena_size;
    s_ctx.arena_size = heap_used();
    temp_va = rd32(data_va + 0x85b0u);
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 1u, world_va, 6u) == ROME2_CURLE_OUT_OF_MEMORY);
    assert(rd32(data_va + 0x85b0u) == temp_va && rd32(data_va + 0x85b4u) == 11u);
    s_ctx.arena_size = full_size;

    /* pausing again replays nothing; unpausing replays the saved bytes */
    reset_write_log();
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, ROME2_CURLPAUSE_RECV) == ROME2_CURLE_OK);
    assert(s_write_count == 0u && (rd32(data_va + 0xf8u) & 0x30u) == 0x10u);
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, ROME2_CURLPAUSE_RECV | ROME2_CURLPAUSE_SEND) == ROME2_CURLE_OK);
    assert((rd32(data_va + 0xf8u) & 0x30u) == 0x30u);
    uint32_t frees = s_ctx.free_count;
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, ROME2_CURLPAUSE_SEND) == ROME2_CURLE_OK);
    assert((rd32(data_va + 0xf8u) & 0x30u) == 0x20u && s_write_count == 1u && s_write_nmemb[0] == 11u);
    assert(strcmp(s_write_text[0], "helloworld!") == 0 && rd32(data_va + 0x85b0u) == 0u);
    assert(s_ctx.free_count - frees == 1u);
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, 0u) == ROME2_CURLE_OK);
    assert(rd32(data_va + 0xf8u) == 0u && s_write_count == 1u);

    /* replay in 0x4000-byte chunks */
    uint32_t big_va = zalloc(0x9000u);
    uint8_t *big = (uint8_t *)rome2_l82_mut_ptr(&s_ctx, big_va, 0x9000u);
    assert(big != NULL);
    for (uint32_t i = 0u; i < 0x9000u; ++i) {
        big[i] = (uint8_t)(i * 7u + (i >> 8));
    }
    uint32_t saved_va = rome2_l82_alloc(&s_ctx, 0x9000u);
    memcpy(rome2_l82_mut_ptr(&s_ctx, saved_va, 0x9000u), big, 0x9000u);
    wr32(data_va + 0x85b0u, saved_va);
    wr32(data_va + 0x85b4u, 0x9000u);
    wr32(data_va + 0x85b8u, 1u);
    wr32(data_va + 0xf8u, 0x10u);
    reset_write_log();
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, 0u) == ROME2_CURLE_OK);
    assert(s_write_count == 3u && s_write_nmemb[0] == 0x4000u && s_write_nmemb[1] == 0x4000u);
    assert(s_write_nmemb[2] == 0x1000u && rd32(data_va + 0x85b0u) == 0u);

    /* paused again in the second chunk: everything from that chunk on is kept */
    saved_va = rome2_l82_alloc(&s_ctx, 0x9000u);
    memcpy(rome2_l82_mut_ptr(&s_ctx, saved_va, 0x9000u), big, 0x9000u);
    wr32(data_va + 0x85b0u, saved_va);
    wr32(data_va + 0x85b4u, 0x9000u);
    wr32(data_va + 0xf8u, 0x10u);
    reset_write_log();
    s_write_script[1] = ROME2_CURL_WRITEFUNC_PAUSE;
    frees = s_ctx.free_count;
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, 0u) == ROME2_CURLE_OK);
    assert(s_write_count == 2u && rd32(data_va + 0x85b4u) == 0x5000u && (rd32(data_va + 0xf8u) & 0x10u) != 0u);
    temp_va = rd32(data_va + 0x85b0u);
    assert(temp_va != 0u && temp_va != saved_va);
    assert(memcmp(rome2_l82_const_ptr(&s_ctx, temp_va, 0x5000u), big + 0x4000u, 0x5000u) == 0);
    assert(s_ctx.free_count - frees == 2u); /* the realloc source and the replayed buffer */

    /* paused in the final chunk: only that chunk is kept */
    reset_write_log();
    s_write_script[1] = ROME2_CURL_WRITEFUNC_PAUSE;
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, 0u) == ROME2_CURLE_OK);
    assert(s_write_count == 2u && rd32(data_va + 0x85b4u) == 0x1000u);
    assert(memcmp(rome2_l82_const_ptr(&s_ctx, rd32(data_va + 0x85b0u), 0x1000u), big + 0x8000u, 0x1000u) == 0);

    /* a failing replay returns the write error and still releases the buffer */
    reset_write_log();
    s_write_script[0] = 1u;
    frees = s_ctx.free_count;
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, 0u) == ROME2_CURLE_WRITE_ERROR);
    assert(s_ctx.free_count - frees == 1u && rd32(data_va + 0x85b0u) == 0u);

    /* out of memory while re-pausing drops both buffers */
    saved_va = rome2_l82_alloc(&s_ctx, 0x9000u);
    wr32(data_va + 0x85b0u, saved_va);
    wr32(data_va + 0x85b4u, 0x9000u);
    wr32(data_va + 0xf8u, 0x10u);
    reset_write_log();
    s_write_script[1] = ROME2_CURL_WRITEFUNC_PAUSE;
    s_ctx.arena_size = heap_used() + 0x4000u + 0x10u;
    frees = s_ctx.free_count;
    assert(rome2_l83_curl_easy_pause(&s_g, data_va, 0u) == ROME2_CURLE_OUT_OF_MEMORY);
    assert(rd32(data_va + 0x85b0u) == 0u && s_ctx.free_count - frees == 2u);
    s_ctx.arena_size = heap_used();
    wr32(data_va + 0xf8u, 0u);
    reset_write_log();
    s_write_script[0] = ROME2_CURL_WRITEFUNC_PAUSE;
    assert(rome2_l83_curl_client_write(&s_g, conn_va, 1u, hello_va, 5u) == ROME2_CURLE_OUT_OF_MEMORY);
    assert(rd32(data_va + 0x85b0u) == 0u && rd32(data_va + 0xf8u) == 0u);
    s_ctx.arena_size = full_size;
}

static void test_failf_verbose_paths(void) {
    setup();
    uint32_t data_va = open_easy();
    char *long_text = (char *)rome2_l82_mut_ptr(&s_ctx, zalloc(0x4100u), 0x4100u);
    assert(long_text != NULL);

    rome2_l83_curl_failf(&s_g, data_va, "quiet %d", 1);
    assert(strcmp(str_at(data_va + 0x594u), "quiet 1") == 0 && s_write_count == 0u && s_debug_calls == 0u);
    assert(rd32(data_va + 0x85c0u) == 0u);

    wr32(data_va + 0x31cu, 1u);
    rome2_l83_curl_failf(&s_g, data_va, "code %d", 7);
    assert(strcmp(str_at(data_va + 0x594u), "code 7\n") == 0 && s_write_count == 2u);
    assert(s_write_fn[0] == 0x11688039u && s_write_size[0] == 2u && s_write_nmemb[0] == 1u);
    assert(strcmp(s_write_text[0], "* ") == 0 && s_write_stream[0] == 0x119ebe18u + 0x70u);
    assert(s_write_size[1] == 7u && s_write_nmemb[1] == 1u && strcmp(s_write_text[1], "code 7\n") == 0);

    wr32(data_va + 0x19cu, 0x8100u);
    wr32(data_va + 0x12cu, 0x8200u);
    rome2_l83_curl_failf(&s_g, data_va, "x");
    assert(s_write_count == 2u && s_debug_calls == 1u && s_debug_fn == 0x8100u && s_debug_data == data_va);
    assert(s_debug_type == 0 && s_debug_size == 2u && s_debug_userp == 0x8200u && s_debug_last == '\n');

    /* a full 0x3fff-character message gets no newline */
    memset(long_text, 'A', 0x40ffu);
    long_text[0x40ffu] = '\0';
    rome2_l83_curl_failf(&s_g, data_va, "%s", long_text);
    assert(s_debug_calls == 2u && s_debug_size == 0x3fffu && s_debug_last == 'A');
    assert(str_at(data_va + 0x594u)[0x3fffu] == '\0');
}

static void test_send_and_connectinfo(void) {
    setup();
    uint32_t data_va = open_easy();
    uint32_t buffer_va = put_str("payload");
    int32_t n = 99;
    uint32_t sfd = 0u;
    uint32_t c_va = 0u;

    assert(rome2_l83_easy_connection(&s_g, 0u, &sfd, &c_va) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT);
    assert(rome2_l83_curl_easy_send(&s_g, data_va, buffer_va, 7u, &n) == ROME2_CURLE_UNSUPPORTED_PROTOCOL);
    assert(n == 99 && strcmp(str_at(data_va + 0x594u), "CONNECT_ONLY is required!") == 0);
    wr32(data_va + 0x358u, 1u);
    assert(rome2_l83_curl_easy_send(&s_g, data_va, buffer_va, 7u, &n) == ROME2_CURLE_UNSUPPORTED_PROTOCOL);
    assert(n == 99 && strcmp(str_at(data_va + 0x594u), "Failed to get recent socket") == 0);

    uint32_t connc_va = zalloc(8u);
    uint32_t connects_va = zalloc(16u);
    uint32_t conn_va = make_conn(data_va);
    wr32(connc_va, connects_va);
    wr32(data_va + 0x57cu, connc_va);
    wr32(data_va + 0x588u, 2u);
    assert(rome2_l83_curl_getconnectinfo(&s_g, data_va, &c_va) == ROME2_CURL_SOCKET_BAD && c_va == 0u);
    wr32(connects_va + 8u, conn_va);
    wr32(conn_va + 0x130u, 55u);
    wr32(conn_va + 0x134u, 66u);
    wr32(conn_va + 0x148u, 0xa000u);
    wr32(conn_va + 0x14cu, 0xa001u);
    assert(rome2_l83_curl_getconnectinfo(&s_g, data_va, &c_va) == ROME2_CURL_SOCKET_BAD);
    assert(c_va == conn_va && s_recv_sockfd == 55u);
    s_recv_result = 1;
    assert(rome2_l83_curl_getconnectinfo(&s_g, data_va, NULL) == 55u);

    /* SSL connections ask SSLEAY32 #76 instead of recv */
    wr32(conn_va + 0x150u, 1u);
    wr32(conn_va + 0x15cu, 0xb000u);
    s_recv_sockfd = 0u;
    s_ossl_result[ROME2_L83_SSLEAY32_ORD_76] = 5;
    assert(rome2_l83_curl_getconnectinfo(&s_g, data_va, NULL) == 55u && s_recv_sockfd == 0u);
    assert(s_ossl_count == 1u && s_ossl_ids[0] == ROME2_L83_SSLEAY32_ORD_76);
    assert(s_ossl_a0[0] == 0xb000u && s_ossl_a2[0] == 1u);
    assert(rome2_l83_curl_ossl_check_cxn(&s_g, conn_va) == 1 && rome2_l83_curl_ssl_check_cxn(&s_g, conn_va) == 1);
    s_ossl_result[ROME2_L83_SSLEAY32_ORD_76] = 0;
    assert(rome2_l83_curl_ossl_check_cxn(&s_g, conn_va) == 0);
    assert(rome2_l83_curl_getconnectinfo(&s_g, data_va, NULL) == ROME2_CURL_SOCKET_BAD);
    s_ossl_result[ROME2_L83_SSLEAY32_ORD_76] = -3;
    assert(rome2_l83_curl_ossl_check_cxn(&s_g, conn_va) == -1);
    assert(rome2_l83_curl_getconnectinfo(&s_g, data_va, NULL) == 55u);

    s_send_result = 9;
    assert(rome2_l83_curl_easy_send(&s_g, data_va, buffer_va, 7u, &n) == ROME2_CURLE_OK && n == 9);
    assert(s_send_fn == 0xa000u && s_send_num == 0u && s_send_mem == buffer_va && s_send_len == 7u);
    s_send_result = 0;
    assert(rome2_l83_curl_easy_send(&s_g, data_va, buffer_va, 7u, &n) == ROME2_CURLE_AGAIN && n == 0);
    s_send_result = -1;
    s_send_code = 0;
    assert(rome2_l83_curl_easy_send(&s_g, data_va, buffer_va, 7u, &n) == ROME2_CURLE_SEND_ERROR);
    s_send_code = ROME2_CURLE_AGAIN;
    assert(rome2_l83_curl_easy_send(&s_g, data_va, buffer_va, 7u, &n) == ROME2_CURLE_AGAIN && n == 0);
    s_send_code = 0x1c;
    assert(rome2_l83_curl_easy_send(&s_g, data_va, buffer_va, 7u, &n) == ROME2_CURLE_SEND_ERROR);
    s_send_result = -5;
    assert(rome2_l83_curl_easy_send(&s_g, data_va, buffer_va, 7u, &n) == 0x1c && n == -5);

    int32_t written = 7;
    assert(rome2_l83_curl_write(&s_g, conn_va, 66u, buffer_va, 3u, &written) == 0x1c && written == -5);
    assert(s_send_fn == 0xa001u && s_send_num == 1u);
    s_send_code = ROME2_CURLE_AGAIN;
    assert(rome2_l83_curl_write(&s_g, conn_va, 55u, buffer_va, 3u, &written) == ROME2_CURLE_OK && written == 0);
    assert(s_send_num == 0u);
    s_g.on_conn_send = NULL;
    assert(rome2_l83_curl_write(&s_g, conn_va, 55u, buffer_va, 3u, &written) == ROME2_CURLE_SEND_ERROR);
    assert(written == -1);
}

static void test_getsock_family(void) {
    setup();
    uint32_t data_va = open_easy();
    uint32_t conn_va = make_conn(data_va);
    uint32_t handler_va = rd32(conn_va + 0x234u);
    uint32_t socks[5] = {0u, 0u, 0u, 0u, 0u};
    wr32(conn_va + 0x240u, 10u);
    wr32(conn_va + 0x244u, 11u);

    wr32(handler_va + 0x2cu, 0xc02cu);
    assert(rome2_l83_curl_single_getsock(&s_g, conn_va, socks, 5) == 0x77u);
    assert(s_getsock_fn == 0xc02cu && s_getsock_conn == conn_va && s_getsock_numsocks == 5 && socks[0] == 0x51u);
    wr32(handler_va + 0x2cu, 0u);
    wr32(data_va + 0xf8u, 3u);
    assert(rome2_l83_curl_single_getsock(&s_g, conn_va, socks, 1) == 0u);
    socks[0] = 0u;
    socks[1] = 0u;
    assert(rome2_l83_curl_single_getsock(&s_g, conn_va, socks, 2) == 0x20001u && socks[0] == 10u && socks[1] == 11u);
    wr32(data_va + 0xf8u, 1u);
    socks[0] = 0u;
    assert(rome2_l83_curl_single_getsock(&s_g, conn_va, socks, 2) == 1u && socks[0] == 10u);
    wr32(data_va + 0xf8u, 2u);
    assert(rome2_l83_curl_single_getsock(&s_g, conn_va, socks, 2) == 0x10000u && socks[0] == 11u);
    wr32(conn_va + 0x244u, 10u); /* one socket for both directions */
    wr32(data_va + 0xf8u, 3u);
    socks[0] = 0u;
    socks[1] = 0xeeu;
    assert(rome2_l83_curl_single_getsock(&s_g, conn_va, socks, 2) == 0x10001u && socks[0] == 10u && socks[1] == 0xeeu);
    wr32(data_va + 0xf8u, 0x11u);
    assert(rome2_l83_curl_single_getsock(&s_g, conn_va, socks, 2) == 0u);
    wr32(data_va + 0xf8u, 0x22u);
    assert(rome2_l83_curl_single_getsock(&s_g, conn_va, socks, 2) == 0u);
    wr32(conn_va + 0x244u, 11u);

    s_getsock_calls = 0u;
    assert(rome2_l83_curl_doing_getsock(&s_g, 0u, socks, 5) == 0u);
    assert(rome2_l83_curl_doing_getsock(&s_g, conn_va, socks, 5) == 0u);
    assert(rome2_l83_curl_protocol_getsock(&s_g, conn_va, socks, 5) == 0u && s_getsock_calls == 0u);
    wr32(handler_va + 0x24u, 0xc024u);
    wr32(handler_va + 0x20u, 0xc020u);
    assert(rome2_l83_curl_doing_getsock(&s_g, conn_va, socks, 5) == 0x77u && s_getsock_fn == 0xc024u);
    assert(rome2_l83_curl_protocol_getsock(&s_g, conn_va, socks, 5) == 0x77u && s_getsock_fn == 0xc020u);

    uint32_t easy_va = zalloc(0x14u);
    wr32(easy_va + 8u, data_va);
    wr32(easy_va + 0x0cu, conn_va);
    wr32(conn_va, 0u);
    wr32(easy_va + 0x10u, 1u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0u && rd32(conn_va) == 0u);
    wr32(easy_va + 0x10u, 15u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0u && rd32(conn_va) == 0u);
    wr32(easy_va + 0x10u, 14u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0u && rd32(conn_va) == data_va);
    wr32(conn_va, 0u);
    uint32_t stubs = s_g.resolver_stub_calls;
    wr32(easy_va + 0x10u, 2u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0u && rd32(conn_va) == data_va);
    assert(s_g.resolver_stub_calls - stubs == 1u);

    wr32(conn_va + 0x130u, 21u);
    wr32(easy_va + 0x10u, 3u);
    socks[0] = 0u;
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 0) == 0u && socks[0] == 0u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0x10000u && socks[0] == 21u);
    wr32(conn_va + 0x4a4u, 1u);
    wr32(easy_va + 0x10u, 4u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 1u);
    wr32(conn_va + 0x4a4u, 0u);

    wr32(easy_va + 0x10u, 5u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0x77u && s_getsock_fn == 0xc020u);
    wr32(easy_va + 0x10u, 7u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0x77u && s_getsock_fn == 0xc024u);
    wr32(easy_va + 0x10u, 8u);
    s_getsock_fn = 0u;
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0x77u && s_getsock_fn == 0xc024u);
    wr32(easy_va + 0x10u, 9u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0u);
    wr32(handler_va + 0x28u, 0xc028u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0x77u && s_getsock_fn == 0xc028u);
    wr32(easy_va + 0x10u, 6u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0u);
    wr32(data_va + 0xf8u, 1u);
    for (uint32_t state = 10u; state <= 12u; ++state) {
        wr32(easy_va + 0x10u, state);
        socks[0] = 0u;
        assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 1u && socks[0] == 10u);
    }
    wr32(data_va + 0x8680u, 1u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0u);
    wr32(data_va + 0x8680u, 0u);
    wr32(easy_va + 0x0cu, 0u);
    assert(rome2_l83_multi_getsock(&s_g, easy_va, socks, 5) == 0u);
}

static void test_multi_handle(void) {
    setup();
    uint32_t multi_va = zalloc(0x78u);
    uint32_t sentinel_va = multi_va + 4u;
    wr32(multi_va, ROME2_CURL_MULTI_MAGIC);
    wr32(sentinel_va, sentinel_va);
    uint32_t read_va = zalloc(0x104u);
    uint32_t write_va = zalloc(0x104u);
    uint32_t exc_va = zalloc(0x104u);
    int32_t max_fd = 5;
    wr32(exc_va, 99u);

    assert(rome2_l83_curl_multi_fdset(&s_g, 0u, read_va, write_va, exc_va, &max_fd) == ROME2_CURLM_BAD_HANDLE);
    assert(rome2_l83_curl_multi_fdset(&s_g, read_va, read_va, write_va, exc_va, &max_fd) == ROME2_CURLM_BAD_HANDLE);
    assert(max_fd == 5);
    assert(rome2_l83_curl_multi_fdset(&s_g, multi_va, read_va, write_va, exc_va, &max_fd) == ROME2_CURLM_OK);
    assert(max_fd == -1);

    /* easy 1 waits to connect on socket 7; easy 2 transfers on 10 (read) and 11 (write) */
    uint32_t data1_va = open_easy();
    uint32_t data2_va = open_easy();
    uint32_t conn1_va = make_conn(data1_va);
    uint32_t conn2_va = make_conn(data2_va);
    uint32_t easy1_va = zalloc(0x14u);
    uint32_t easy2_va = zalloc(0x14u);
    wr32(conn1_va + 0x130u, 7u);
    wr32(conn2_va + 0x240u, 10u);
    wr32(conn2_va + 0x244u, 11u);
    wr32(data2_va + 0xf8u, 3u);
    wr32(easy1_va + 8u, data1_va);
    wr32(easy1_va + 0x0cu, conn1_va);
    wr32(easy1_va + 0x10u, 3u);
    wr32(easy2_va + 8u, data2_va);
    wr32(easy2_va + 0x0cu, conn2_va);
    wr32(easy2_va + 0x10u, 11u);
    wr32(sentinel_va, easy1_va);
    wr32(easy1_va, easy2_va);
    wr32(easy2_va, sentinel_va);
    wr32(read_va, 1u);
    wr32(read_va + 4u, 10u); /* already present */
    assert(rome2_l83_curl_multi_fdset(&s_g, multi_va, read_va, write_va, exc_va, &max_fd) == ROME2_CURLM_OK);
    assert(max_fd == 11 && rd32(read_va) == 1u && rd32(read_va + 4u) == 10u);
    assert(rd32(write_va) == 2u && rd32(write_va + 4u) == 7u && rd32(write_va + 8u) == 11u);
    assert(rd32(exc_va) == 99u && rd32(exc_va + 4u) == 0u);
    wr32(write_va, 64u); /* a full set takes nothing more */
    wr32(write_va + 4u, 0u);
    wr32(write_va + 8u, 0u);
    assert(rome2_l83_curl_multi_fdset(&s_g, multi_va, read_va, write_va, exc_va, &max_fd) == ROME2_CURLM_OK);
    assert(rd32(write_va) == 64u && rd32(write_va + 4u) == 0u && rd32(write_va + 0x100u) == 0u);

    assert(rome2_l83_curl_multi_setopt(&s_ctx, read_va, ROME2_CURLMOPT_PIPELINING, 1u) == ROME2_CURLM_BAD_HANDLE);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, 0u, ROME2_CURLMOPT_PIPELINING, 1u) == ROME2_CURLM_BAD_HANDLE);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, ROME2_CURLMOPT_PIPELINING, 5u) == ROME2_CURLM_OK);
    assert(rd32(multi_va + 0x60u) == 1u);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, ROME2_CURLMOPT_PIPELINING, 0u) == ROME2_CURLM_OK);
    assert(rd32(multi_va + 0x60u) == 0u);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, ROME2_CURLMOPT_MAXCONNECTS, 12u) == ROME2_CURLM_OK);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, ROME2_CURLMOPT_SOCKETDATA, 0x1002u) == ROME2_CURLM_OK);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, ROME2_CURLMOPT_TIMERDATA, 0x1005u) == ROME2_CURLM_OK);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, ROME2_CURLMOPT_SOCKETFUNCTION, 0x2001u) == ROME2_CURLM_OK);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, ROME2_CURLMOPT_TIMERFUNCTION, 0x2004u) == ROME2_CURLM_OK);
    assert(rd32(multi_va + 0x68u) == 12u && rd32(multi_va + 0x50u) == 0x1002u && rd32(multi_va + 0x74u) == 0x1005u);
    assert(rd32(multi_va + 0x4cu) == 0x2001u && rd32(multi_va + 0x70u) == 0x2004u);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, 10003, 1u) == ROME2_CURLM_UNKNOWN_OPTION);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, 20002, 1u) == ROME2_CURLM_UNKNOWN_OPTION);
    assert(rome2_l83_curl_multi_setopt(&s_ctx, multi_va, 1, 1u) == ROME2_CURLM_UNKNOWN_OPTION);

    /* queued messages */
    uint32_t msglist_va = make_llist(0x7003u);
    (void)llist_push(msglist_va, 0xd100u);
    (void)llist_push(msglist_va, 0xd200u);
    wr32(multi_va + 0x48u, msglist_va);
    int32_t msgs = 99;
    assert(rome2_l83_curl_multi_info_read(&s_ctx, read_va, &msgs) == 0u && msgs == 0);
    assert(rome2_l83_curl_multi_info_read(&s_ctx, multi_va, &msgs) == 0xd100u && msgs == 1);
    assert(s_dtor_calls == 1u && s_dtor_user == 0u && s_dtor_ptr == 0xd100u);
    assert(rome2_l83_curl_multi_info_read(&s_ctx, multi_va, &msgs) == 0xd200u && msgs == 0);
    msgs = 99;
    assert(rome2_l83_curl_multi_info_read(&s_ctx, multi_va, &msgs) == 0u && msgs == 0 && s_dtor_calls == 2u);

    /* timeouts from the splay tree's smallest key */
    int32_t timeout_ms = 77;
    assert(rome2_l83_curl_multi_timeout(&s_g, read_va, &timeout_ms) == ROME2_CURLM_BAD_HANDLE && timeout_ms == 77);
    assert(rome2_l83_curl_multi_timeout(&s_g, multi_va, &timeout_ms) == ROME2_CURLM_OK && timeout_ms == -1);
    uint32_t n5_va = zalloc(0x18u);
    uint32_t n3_va = zalloc(0x18u);
    uint32_t n9_va = zalloc(0x18u);
    wr32(n5_va + 0x0cu, 5u);
    wr32(n3_va + 0x0cu, 3u);
    wr32(n3_va + 0x10u, 500000u);
    wr32(n9_va + 0x0cu, 9u);
    wr32(n5_va, n3_va);
    wr32(n5_va + 4u, n9_va);
    wr32(multi_va + 0x58u, n5_va);
    s_tick = 2000u;
    assert(rome2_l83_curl_multi_timeout(&s_g, multi_va, &timeout_ms) == ROME2_CURLM_OK && timeout_ms == 1500);
    assert(rd32(multi_va + 0x58u) == n3_va && rd32(n3_va) == 0u && rd32(n3_va + 4u) == n5_va);
    assert(rd32(n5_va) == 0u && rd32(n5_va + 4u) == n9_va);
    s_tick = 3500u;
    assert(rome2_l83_multi_timeout(&s_g, multi_va, &timeout_ms) == ROME2_CURLM_OK && timeout_ms == 0);
    s_tick = 4000u;
    assert(rome2_l83_multi_timeout(&s_g, multi_va, &timeout_ms) == ROME2_CURLM_OK && timeout_ms == 0);
    s_tick = 3499u;
    assert(rome2_l83_multi_timeout(&s_g, multi_va, &timeout_ms) == ROME2_CURLM_OK && timeout_ms == 1);
    wr32(n3_va + 0x10u, 500500u); /* later by under a millisecond still reports 1 */
    s_tick = 3500u;
    assert(rome2_l83_multi_timeout(&s_g, multi_va, &timeout_ms) == ROME2_CURLM_OK && timeout_ms == 1);
}

static uint32_t tree_node(int32_t sec, int32_t usec) {
    uint32_t va = zalloc(0x18u);
    wr32(va + 0x0cu, (uint32_t)sec);
    wr32(va + 0x10u, (uint32_t)usec);
    return va;
}

/* In-order walk checking the search-tree ordering; returns the node count. */
static uint32_t tree_check(uint32_t va, int64_t *last_key) {
    if (va == 0u) {
        return 0u;
    }
    uint32_t count = tree_check(rd32(va), last_key);
    int64_t key = (int64_t)(int32_t)rd32(va + 0x0cu) * 1000000 + (int32_t)rd32(va + 0x10u);
    assert(key > *last_key);
    *last_key = key;
    return count + 1u + tree_check(rd32(va + 4u), last_key);
}

static void test_splay(void) {
    setup();
    rome2_curl_timeval_32 key = {1, 0};
    assert(rome2_l83_curl_splay(&s_ctx, key, 0u) == 0u);

    /* keys 1..6 as a chain leaning on `smaller` */
    uint32_t nodes[7] = {0u, 0u, 0u, 0u, 0u, 0u, 0u};
    for (int32_t i = 1; i <= 6; ++i) {
        nodes[i] = tree_node(i, 0);
        wr32(nodes[i], nodes[i - 1]);
    }
    int64_t last = -1;
    uint32_t root_va = rome2_l83_curl_splay(&s_ctx, key, nodes[6]);
    assert(root_va == nodes[1] && rd32(root_va) == 0u && tree_check(root_va, &last) == 6u);
    key.tv_sec = 4;
    root_va = rome2_l83_curl_splay(&s_ctx, key, root_va);
    last = -1;
    assert(root_va == nodes[4] && tree_check(root_va, &last) == 6u);
    key.tv_sec = 99; /* beyond every key: the largest node surfaces */
    root_va = rome2_l83_curl_splay(&s_ctx, key, root_va);
    last = -1;
    assert(root_va == nodes[6] && rd32(root_va + 4u) == 0u && tree_check(root_va, &last) == 6u);
    key.tv_sec = 3;
    key.tv_usec = 500000; /* absent key: a neighbour surfaces */
    root_va = rome2_l83_curl_splay(&s_ctx, key, root_va);
    last = -1;
    assert((root_va == nodes[3] || root_va == nodes[4]) && tree_check(root_va, &last) == 6u);
    key.tv_sec = 0;
    key.tv_usec = 0;
    root_va = rome2_l83_curl_splay(&s_ctx, key, root_va);
    last = -1;
    assert(root_va == nodes[1] && tree_check(root_va, &last) == 6u);

    /* microseconds break ties */
    uint32_t a_va = tree_node(2, 100);
    uint32_t b_va = tree_node(2, 200);
    uint32_t c_va = tree_node(2, 300);
    wr32(a_va + 4u, b_va);
    wr32(b_va + 4u, c_va);
    key.tv_sec = 2;
    key.tv_usec = 300;
    root_va = rome2_l83_curl_splay(&s_ctx, key, a_va);
    last = -1;
    assert(root_va == c_va && tree_check(root_va, &last) == 3u);
    key.tv_usec = 200;
    root_va = rome2_l83_curl_splay(&s_ctx, key, root_va);
    assert(root_va == b_va && rd32(b_va) == a_va && rd32(b_va + 4u) == c_va);
}

static uint32_t s_httppost_slot;
static uint32_t s_last_post_slot;

static void form_setup(void) {
    setup();
    s_httppost_slot = zalloc(4u);
    s_last_post_slot = zalloc(4u);
}

static int32_t form_add(const uint32_t *args, uint32_t count) {
    return rome2_l83_curl_formadd(&s_ctx, s_httppost_slot, s_last_post_slot, args, count);
}

static void test_formadd_contents(void) {
    form_setup();
    uint32_t name_va = put_str("field");
    uint32_t value_va = put_str("value");
    uint32_t allocs = s_ctx.alloc_count;
    uint32_t frees = s_ctx.free_count;
    const uint32_t basic[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_COPYCONTENTS, value_va, ROME2_CURLFORM_END};
    assert(form_add(basic, L83_COUNT(basic)) == ROME2_CURL_FORMADD_OK);
    uint32_t post1_va = rd32(s_httppost_slot);
    assert(post1_va != 0u && rd32(s_last_post_slot) == post1_va && rd32(post1_va) == 0u);
    assert(rd32(post1_va + 4u) != name_va && strcmp(str_at(rd32(post1_va + 4u)), "field") == 0);
    assert(rd32(post1_va + 8u) == 5u && rd32(post1_va + 0x0cu) != value_va);
    assert(strcmp(str_at(rd32(post1_va + 0x0cu)), "value") == 0 && rd32(post1_va + 0x10u) == 0u);
    assert(rd32(post1_va + 0x1cu) == 0u && rd32(post1_va + 0x24u) == 0u && rd32(post1_va + 0x28u) == 0u);
    assert(s_ctx.alloc_count - allocs == 4u && s_ctx.free_count - frees == 1u);

    /* pointer options keep the caller's storage; the new part is appended through `next` */
    const uint32_t pointers[] = {
        ROME2_CURLFORM_PTRNAME, name_va, ROME2_CURLFORM_PTRCONTENTS, value_va,
        ROME2_CURLFORM_CONTENTSLENGTH, 3u, ROME2_CURLFORM_CONTENTHEADER, 0x4000f00du, ROME2_CURLFORM_END};
    assert(form_add(pointers, L83_COUNT(pointers)) == ROME2_CURL_FORMADD_OK);
    uint32_t post2_va = rd32(s_last_post_slot);
    assert(post2_va != post1_va && rd32(s_httppost_slot) == post1_va && rd32(post1_va) == post2_va);
    assert(rd32(post2_va + 4u) == name_va && rd32(post2_va + 8u) == 5u && rd32(post2_va + 0x0cu) == value_va);
    assert(rd32(post2_va + 0x10u) == 3u && rd32(post2_va + 0x20u) == 0x4000f00du && rd32(post2_va + 0x28u) == 0x0cu);

    /* an explicit name length copies exactly that many bytes */
    form_setup();
    name_va = put_str("abcdef");
    value_va = put_str("xyz");
    const uint32_t lengths[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_NAMELENGTH, 2u,
        ROME2_CURLFORM_COPYCONTENTS, value_va, ROME2_CURLFORM_CONTENTSLENGTH, 2u, ROME2_CURLFORM_END};
    assert(form_add(lengths, L83_COUNT(lengths)) == ROME2_CURL_FORMADD_OK);
    post1_va = rd32(s_httppost_slot);
    assert(rd32(post1_va + 8u) == 2u && memcmp(str_at(rd32(post1_va + 4u)), "ab", 2u) == 0);
    assert(rd32(post1_va + 0x10u) == 2u && memcmp(str_at(rd32(post1_va + 0x0cu)), "xy", 2u) == 0);

    /* the same options through CURLFORM_ARRAY, then more varargs */
    form_setup();
    name_va = put_str("arr");
    value_va = put_str("contents");
    uint32_t forms_va = zalloc(24u);
    wr32(forms_va, ROME2_CURLFORM_COPYNAME);
    wr32(forms_va + 4u, name_va);
    wr32(forms_va + 8u, ROME2_CURLFORM_COPYCONTENTS);
    wr32(forms_va + 12u, value_va);
    wr32(forms_va + 16u, ROME2_CURLFORM_END);
    const uint32_t array[] = {
        ROME2_CURLFORM_ARRAY, forms_va, ROME2_CURLFORM_CONTENTSLENGTH, 4u, ROME2_CURLFORM_END};
    assert(form_add(array, L83_COUNT(array)) == ROME2_CURL_FORMADD_OK);
    post1_va = rd32(s_httppost_slot);
    assert(strcmp(str_at(rd32(post1_va + 4u)), "arr") == 0 && rd32(post1_va + 0x10u) == 4u);
    assert(memcmp(str_at(rd32(post1_va + 0x0cu)), "cont", 4u) == 0);

    /* stream and file-content parts */
    form_setup();
    name_va = put_str("s");
    const uint32_t stream[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_STREAM, 0x4000e000u, ROME2_CURLFORM_END};
    assert(form_add(stream, L83_COUNT(stream)) == ROME2_CURL_FORMADD_OK);
    post1_va = rd32(s_httppost_slot);
    assert(rd32(post1_va + 0x28u) == 0x40u && rd32(post1_va + 0x30u) == 0x4000e000u);
    assert(rd32(post1_va + 0x0cu) == 0x4000e000u && rd32(post1_va + 0x1cu) == 0u);
    uint32_t path_va = put_str("C:/rome2/list.txt");
    const uint32_t filecontent[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_FILECONTENT, path_va, ROME2_CURLFORM_END};
    assert(form_add(filecontent, L83_COUNT(filecontent)) == ROME2_CURL_FORMADD_OK);
    post2_va = rd32(s_last_post_slot);
    assert(rd32(post2_va + 0x28u) == 0x02u && rd32(post2_va + 0x0cu) != path_va);
    assert(strcmp(str_at(rd32(post2_va + 0x0cu)), "C:/rome2/list.txt") == 0 && rd32(post2_va + 0x1cu) == 0u);
}

static void test_formadd_files(void) {
    form_setup();
    uint32_t name_va = put_str("pic");
    uint32_t f1_va = put_str("photo.JPG");
    uint32_t f2_va = put_str("notes.txt");
    uint32_t f3_va = put_str("blob.bin");
    const uint32_t files[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_FILE, f1_va, ROME2_CURLFORM_FILE, f2_va,
        ROME2_CURLFORM_FILE, f3_va, ROME2_CURLFORM_END};
    assert(form_add(files, L83_COUNT(files)) == ROME2_CURL_FORMADD_OK);
    uint32_t post1_va = rd32(s_httppost_slot);
    uint32_t post2_va = rd32(post1_va + 0x24u);
    uint32_t post3_va = rd32(post2_va + 0x24u);
    assert(post2_va != 0u && post3_va != 0u && rd32(post3_va + 0x24u) == 0u && rd32(post1_va) == 0u);
    assert(rd32(post1_va + 0x28u) == 1u && strcmp(str_at(rd32(post1_va + 0x0cu)), "photo.JPG") == 0);
    assert(strcmp(str_at(rd32(post1_va + 0x1cu)), "image/jpeg") == 0);
    assert(rd32(post2_va + 4u) == 0u && rd32(post2_va + 8u) == 0u);
    assert(strcmp(str_at(rd32(post2_va + 0x1cu)), "text/plain") == 0);
    /* an unknown extension inherits the previous part's type */
    assert(strcmp(str_at(rd32(post3_va + 0x0cu)), "blob.bin") == 0);
    assert(strcmp(str_at(rd32(post3_va + 0x1cu)), "text/plain") == 0);

    uint32_t frees = s_ctx.free_count;
    rome2_l83_curl_formfree(&s_ctx, post1_va);
    assert(s_ctx.free_count - frees == 10u);

    /* every table row, and the default */
    static const char *const names[] = {"y.gif", "x.jpeg", "index.HTML", ".xml", "a", "blob.bin"};
    static const char *const types[] = {
        "image/gif", "image/jpeg", "text/html", "application/xml",
        "application/octet-stream", "application/octet-stream"};
    for (uint32_t i = 0u; i < L83_COUNT(names); ++i) {
        form_setup();
        const uint32_t one[] = {
            ROME2_CURLFORM_COPYNAME, put_str("n"), ROME2_CURLFORM_FILE, put_str(names[i]), ROME2_CURLFORM_END};
        assert(form_add(one, L83_COUNT(one)) == ROME2_CURL_FORMADD_OK);
        assert(strcmp(str_at(rd32(rd32(s_httppost_slot) + 0x1cu)), types[i]) == 0);
    }
    assert(strcmp(rome2_l83_content_types[2].extension, ".jpeg") == 0);

    /* an explicit type is copied and inherited; a second type starts another part */
    form_setup();
    name_va = put_str("doc");
    f1_va = put_str("a.bin");
    f2_va = put_str("b.bin");
    uint32_t pdf_va = put_str("application/pdf");
    uint32_t zip_va = put_str("application/zip");
    const uint32_t typed[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_FILE, f1_va, ROME2_CURLFORM_CONTENTTYPE, pdf_va,
        ROME2_CURLFORM_FILE, f2_va, ROME2_CURLFORM_END};
    assert(form_add(typed, L83_COUNT(typed)) == ROME2_CURL_FORMADD_OK);
    post1_va = rd32(s_httppost_slot);
    post2_va = rd32(post1_va + 0x24u);
    assert(rd32(post1_va + 0x1cu) != pdf_va && strcmp(str_at(rd32(post1_va + 0x1cu)), "application/pdf") == 0);
    assert(strcmp(str_at(rd32(post2_va + 0x1cu)), "application/pdf") == 0);
    form_setup();
    name_va = put_str("doc");
    f1_va = put_str("a.bin");
    pdf_va = put_str("application/pdf");
    zip_va = put_str("application/zip");
    const uint32_t retyped[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_FILE, f1_va, ROME2_CURLFORM_CONTENTTYPE, pdf_va,
        ROME2_CURLFORM_CONTENTTYPE, zip_va, ROME2_CURLFORM_END};
    assert(form_add(retyped, L83_COUNT(retyped)) == ROME2_CURL_FORMADD_OK);
    post1_va = rd32(s_httppost_slot);
    post2_va = rd32(post1_va + 0x24u);
    assert(post2_va != 0u && rd32(post2_va + 0x0cu) == 0u && rd32(post2_va + 0x28u) == 1u);
    assert(strcmp(str_at(rd32(post2_va + 0x1cu)), "application/zip") == 0);

    /* buffer uploads: the type lookup reads the buffer pointer as the file name */
    form_setup();
    name_va = put_str("buf");
    uint32_t shown_va = put_str("shown.txt");
    uint32_t buffer_va = put_str("data.xml");
    const uint32_t buffer[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_BUFFER, shown_va, ROME2_CURLFORM_BUFFERPTR, buffer_va,
        ROME2_CURLFORM_BUFFERLENGTH, 8u, ROME2_CURLFORM_END};
    assert(form_add(buffer, L83_COUNT(buffer)) == ROME2_CURL_FORMADD_OK);
    post1_va = rd32(s_httppost_slot);
    assert(rd32(post1_va + 0x28u) == 0x30u && rd32(post1_va + 0x14u) == buffer_va && rd32(post1_va + 0x18u) == 8u);
    assert(rd32(post1_va + 0x0cu) == buffer_va && rd32(post1_va + 0x2cu) != shown_va);
    assert(strcmp(str_at(rd32(post1_va + 0x2cu)), "shown.txt") == 0);
    assert(strcmp(str_at(rd32(post1_va + 0x1cu)), "application/xml") == 0);
    frees = s_ctx.free_count;
    rome2_l83_curl_formfree(&s_ctx, post1_va);
    assert(s_ctx.free_count - frees == 4u); /* name, type, shown name, node: not the buffer */

    /* two top-level parts; pointer parts own only their node */
    form_setup();
    name_va = put_str("p");
    const uint32_t first[] = {
        ROME2_CURLFORM_PTRNAME, name_va, ROME2_CURLFORM_PTRCONTENTS, name_va, ROME2_CURLFORM_END};
    const uint32_t second[] = {
        ROME2_CURLFORM_COPYNAME, name_va, ROME2_CURLFORM_COPYCONTENTS, name_va, ROME2_CURLFORM_END};
    assert(form_add(first, L83_COUNT(first)) == ROME2_CURL_FORMADD_OK);
    assert(form_add(second, L83_COUNT(second)) == ROME2_CURL_FORMADD_OK);
    frees = s_ctx.free_count;
    rome2_l83_curl_formfree(&s_ctx, rd32(s_httppost_slot));
    assert(s_ctx.free_count - frees == 4u);
    rome2_l83_curl_formfree(&s_ctx, 0u);
    assert(s_ctx.free_count - frees == 4u);
}

static void test_formadd_errors_and_memdup(void) {
    form_setup();
    uint32_t a_va = put_str("a");
    uint32_t b_va = put_str("b");
    uint32_t f_va = put_str("f.txt");
    uint32_t forms_va = zalloc(16u);
    wr32(forms_va, ROME2_CURLFORM_ARRAY);
    wr32(forms_va + 4u, forms_va);

    const uint32_t twice[] = {ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_COPYNAME, b_va, ROME2_CURLFORM_END};
    const uint32_t null_name[] = {ROME2_CURLFORM_COPYNAME, 0u, ROME2_CURLFORM_END};
    const uint32_t null_array[] = {ROME2_CURLFORM_ARRAY, 0u, ROME2_CURLFORM_END};
    const uint32_t nested[] = {ROME2_CURLFORM_ARRAY, forms_va, ROME2_CURLFORM_END};
    const uint32_t unknown9[] = {9u, a_va, ROME2_CURLFORM_END};
    const uint32_t unknown18[] = {ROME2_CURLFORM_COPYNAME, a_va, 18u, ROME2_CURLFORM_END};
    const uint32_t unknown99[] = {99u};
    const uint32_t only_end[] = {ROME2_CURLFORM_END};
    const uint32_t no_contents[] = {ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_END};
    const uint32_t file_length[] = {
        ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_FILE, f_va, ROME2_CURLFORM_CONTENTSLENGTH, 4u,
        ROME2_CURLFORM_END};
    const uint32_t file_after_ptr[] = {
        ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_PTRCONTENTS, b_va, ROME2_CURLFORM_FILE, f_va,
        ROME2_CURLFORM_END};
    const uint32_t content_after_ptr[] = {
        ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_PTRCONTENTS, b_va, ROME2_CURLFORM_FILECONTENT, f_va,
        ROME2_CURLFORM_END};
    const uint32_t type_twice[] = {
        ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_COPYCONTENTS, b_va, ROME2_CURLFORM_CONTENTTYPE, a_va,
        ROME2_CURLFORM_CONTENTTYPE, b_va, ROME2_CURLFORM_END};
    const uint32_t null_buffer[] = {ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_BUFFERPTR, 0u, ROME2_CURLFORM_END};
    const uint32_t buffer_twice[] = {
        ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_BUFFERPTR, b_va, ROME2_CURLFORM_BUFFERPTR, b_va,
        ROME2_CURLFORM_END};
    const uint32_t header_twice[] = {
        ROME2_CURLFORM_CONTENTHEADER, 0u, ROME2_CURLFORM_CONTENTHEADER, a_va, ROME2_CURLFORM_CONTENTHEADER, b_va,
        ROME2_CURLFORM_END};
    const uint32_t shown_null[] = {ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_FILENAME, 0u, ROME2_CURLFORM_END};
    const uint32_t unterminated[] = {ROME2_CURLFORM_COPYNAME, a_va};
    const uint32_t missing_value[] = {ROME2_CURLFORM_COPYNAME};

    assert(form_add(twice, L83_COUNT(twice)) == ROME2_CURL_FORMADD_OPTION_TWICE);
    assert(form_add(null_name, L83_COUNT(null_name)) == ROME2_CURL_FORMADD_NULL);
    assert(form_add(null_array, L83_COUNT(null_array)) == ROME2_CURL_FORMADD_NULL);
    assert(form_add(nested, L83_COUNT(nested)) == ROME2_CURL_FORMADD_ILLEGAL_ARRAY);
    assert(form_add(unknown9, L83_COUNT(unknown9)) == ROME2_CURL_FORMADD_UNKNOWN_OPTION);
    assert(form_add(unknown18, L83_COUNT(unknown18)) == ROME2_CURL_FORMADD_UNKNOWN_OPTION);
    assert(form_add(unknown99, L83_COUNT(unknown99)) == ROME2_CURL_FORMADD_UNKNOWN_OPTION);
    assert(form_add(only_end, L83_COUNT(only_end)) == ROME2_CURL_FORMADD_INCOMPLETE);
    assert(form_add(no_contents, L83_COUNT(no_contents)) == ROME2_CURL_FORMADD_INCOMPLETE);
    assert(form_add(file_length, L83_COUNT(file_length)) == ROME2_CURL_FORMADD_INCOMPLETE);
    assert(form_add(file_after_ptr, L83_COUNT(file_after_ptr)) == ROME2_CURL_FORMADD_OPTION_TWICE);
    assert(form_add(content_after_ptr, L83_COUNT(content_after_ptr)) == ROME2_CURL_FORMADD_OPTION_TWICE);
    assert(form_add(type_twice, L83_COUNT(type_twice)) == ROME2_CURL_FORMADD_OPTION_TWICE);
    assert(form_add(null_buffer, L83_COUNT(null_buffer)) == ROME2_CURL_FORMADD_NULL);
    assert(form_add(buffer_twice, L83_COUNT(buffer_twice)) == ROME2_CURL_FORMADD_OPTION_TWICE);
    assert(form_add(header_twice, L83_COUNT(header_twice)) == ROME2_CURL_FORMADD_OPTION_TWICE);
    assert(form_add(shown_null, L83_COUNT(shown_null)) == ROME2_CURL_FORMADD_MEMORY);
    assert(form_add(unterminated, L83_COUNT(unterminated)) == ROME2_L83_FORMADD_ARGS_EXHAUSTED);
    assert(form_add(missing_value, L83_COUNT(missing_value)) == ROME2_L83_FORMADD_ARGS_EXHAUSTED);
    assert(form_add(NULL, 0u) == ROME2_L83_FORMADD_ARGS_EXHAUSTED);
    assert(rd32(s_httppost_slot) == 0u && rd32(s_last_post_slot) == 0u);

    /* every failure path releases what the parse allocated */
    uint32_t f2_va = put_str("g.txt");
    const uint32_t parse_error[] = {
        ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_FILE, f_va, ROME2_CURLFORM_FILE, f2_va,
        ROME2_CURLFORM_NAMELENGTH, 1u, ROME2_CURLFORM_NAMELENGTH, 2u, ROME2_CURLFORM_END};
    uint32_t allocs = s_ctx.alloc_count;
    uint32_t frees = s_ctx.free_count;
    assert(form_add(parse_error, L83_COUNT(parse_error)) == ROME2_CURL_FORMADD_OPTION_TWICE);
    assert(s_ctx.alloc_count - allocs == 4u && s_ctx.free_count - frees == 4u);
    allocs = s_ctx.alloc_count;
    frees = s_ctx.free_count;
    assert(form_add(file_length, L83_COUNT(file_length)) == ROME2_CURL_FORMADD_INCOMPLETE);
    assert(s_ctx.alloc_count - allocs == 2u && s_ctx.free_count - frees == 2u);

    uint32_t full_size = s_ctx.arena_size;
    s_ctx.arena_size = heap_used();
    assert(form_add(no_contents, L83_COUNT(no_contents)) == ROME2_CURL_FORMADD_MEMORY);
    s_ctx.arena_size = heap_used() + 0x40u; /* room for the scratch record only */
    const uint32_t simple[] = {ROME2_CURLFORM_COPYNAME, a_va, ROME2_CURLFORM_COPYCONTENTS, b_va, ROME2_CURLFORM_END};
    assert(form_add(simple, L83_COUNT(simple)) == ROME2_CURL_FORMADD_MEMORY);
    assert(rd32(s_httppost_slot) == 0u);
    s_ctx.arena_size = full_size;

    /* memdup */
    uint32_t src_va = put_str("abcdef");
    uint8_t *ahead = (uint8_t *)rome2_l82_mut_ptr(&s_ctx, s_ctx.heap_cursor, 32u);
    assert(ahead != NULL);
    memset(ahead, 0xee, 32u);
    uint32_t dup_va = rome2_l83_form_memdup(&s_ctx, src_va, 3u);
    assert(dup_va != 0u && memcmp(str_at(dup_va), "abc\xee", 4u) == 0);
    dup_va = rome2_l83_form_memdup(&s_ctx, src_va, 0u);
    assert(dup_va != 0u && memcmp(str_at(dup_va), "abcdef", 7u) == 0);
    dup_va = rome2_l83_form_memdup(&s_ctx, 0u, 0u);
    assert(dup_va != 0u && str_at(dup_va)[0] == '\0');
    assert(rome2_l83_form_memdup(&s_ctx, 0x10u, 0u) == 0u);
    s_ctx.arena_size = heap_used();
    assert(rome2_l83_form_memdup(&s_ctx, src_va, 3u) == 0u);
    s_ctx.arena_size = full_size;
}

int main(void) {
    test_global_init_and_cleanup();
    test_time_helpers();
    test_hash_and_llist();
    test_easy_open_and_reset();
    test_client_write_and_pause();
    test_failf_verbose_paths();
    test_send_and_connectinfo();
    test_getsock_family();
    test_multi_handle();
    test_splay();
    test_formadd_contents();
    test_formadd_files();
    test_formadd_errors_and_memdup();
    printf("curl_form_global_easy_multi_ops tests passed\n");
    return 0;
}
