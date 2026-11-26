#include "curl_dup_getinfo_form_share_ops.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define L86_BASE 0x40000000u
#define L86_LOG_CAP 32u
#define L86_STDERR_VA (0x119ebe18u + 0x70u)
/* Curl_FormBoundary output for the first three draws from a zero seed. */
#define L86_B1 "----------------------------0c45afddaa5c"
#define L86_B2 "----------------------------bef309cd0f9f"
#define L86_B3 "----------------------------0d4c4d2b683a"

static uint8_t s_arena[1024u * 1024u];
static rome2_l82_curl_ctx s_ctx;
static rome2_l83_curl_state s_g;
static rome2_l86_curl_state s_s;

static int32_t s_ossl_ids[L86_LOG_CAP];
static uint32_t s_ossl_a0[L86_LOG_CAP];
static uint32_t s_ossl_count;

static int32_t s_recv_result;
static int32_t s_recv_code;
static uint32_t s_recv_calls;
static uint32_t s_recv_fn;
static uint32_t s_recv_conn;
static uint32_t s_recv_num;
static uint32_t s_recv_buf;
static uint32_t s_recv_len;

static uint8_t s_close_is_cb[L86_LOG_CAP];
static uint32_t s_close_sock[L86_LOG_CAP];
static uint32_t s_close_count;
static uint32_t s_close_fn;
static uint32_t s_close_client;

static uint32_t s_dcs_calls;
static uint32_t s_dcs_va;
static uint32_t s_wait_calls;
static uint32_t s_wait_handle;
static uint32_t s_wait_ms;
static uint32_t s_wait_result;
static uint32_t s_closeh_calls;
static uint32_t s_closeh_handle;

static char s_append_text[4096];
static uint32_t s_append_len;
static uint32_t s_append_calls;
static uint32_t s_append_fn;
static uint32_t s_append_arg;
static uint32_t s_append_last_len;
static uint32_t s_append_fail_call;

static char s_fopen_path[L86_LOG_CAP][48];
static char s_fopen_mode[L86_LOG_CAP][4];
static uint32_t s_fopen_results[L86_LOG_CAP];
static uint32_t s_fopen_calls;
static uint32_t s_fclose_calls;
static uint32_t s_fclose_stream;

static uint32_t s_fread_script[L86_LOG_CAP];
static uint32_t s_fread_calls;
static uint32_t s_fread_buffer_size;
static uint32_t s_fread_elem;
static uint32_t s_fread_count;
static uint32_t s_fread_stream;

static int32_t s_stat_result;
static int64_t s_stat_size;
static uint32_t s_stat_calls;
static char s_stat_path[48];

static int32_t s_refill_result;
static uint32_t s_refill_calls;
static uint8_t s_ansi;

static uint32_t s_write_fn[L86_LOG_CAP];
static uint32_t s_write_size[L86_LOG_CAP];
static uint32_t s_write_nmemb[L86_LOG_CAP];
static uint32_t s_write_stream[L86_LOG_CAP];
static char s_write_text[L86_LOG_CAP][96];
static uint32_t s_write_count;

static uint32_t s_debug_calls;
static uint32_t s_debug_fn;
static uint32_t s_debug_data;
static int32_t s_debug_type;
static uint32_t s_debug_size;
static uint32_t s_debug_userp;
static char s_debug_text[128];

static uint64_t s_filetime;
static int32_t s_peek_result;

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

static double rd_f64(uint32_t va) {
    const void *p = rome2_l82_const_ptr(&s_ctx, va, 8u);
    double v = 0.0;
    assert(p != NULL);
    memcpy(&v, p, 8u);
    return v;
}

static void wr_f64(uint32_t va, double v) {
    void *p = rome2_l82_mut_ptr(&s_ctx, va, 8u);
    assert(p != NULL);
    memcpy(p, &v, 8u);
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

/* Leaves room for exactly `bytes` more arena bytes; returns the size to restore. */
static uint32_t limit_arena(uint32_t bytes) {
    uint32_t full = s_ctx.arena_size;
    s_ctx.arena_size = heap_used() + bytes;
    return full;
}

static void copy_text(char *dst, size_t cap, const char *src) {
    size_t len = strlen(src);
    assert(len < cap);
    memcpy(dst, src, len + 1u);
}

static int32_t on_openssl(rome2_l86_curl_state *s, int32_t id, uint32_t a0) {
    (void)s;
    assert(id >= 0 && id < ROME2_L86_OPENSSL_THUNK_COUNT);
    if (s_ossl_count < L86_LOG_CAP) {
        s_ossl_ids[s_ossl_count] = id;
        s_ossl_a0[s_ossl_count] = a0;
    }
    s_ossl_count++;
    return 0x600 + id;
}

static int32_t on_conn_recv(
    rome2_l86_curl_state *s,
    uint32_t recv_fn_va,
    uint32_t conn_va,
    uint32_t sockindex,
    uint32_t buf_va,
    uint32_t len,
    int32_t *curlcode) {
    (void)s;
    s_recv_calls++;
    s_recv_fn = recv_fn_va;
    s_recv_conn = conn_va;
    s_recv_num = sockindex;
    s_recv_buf = buf_va;
    s_recv_len = len;
    if (s_recv_result > 0) {
        void *dst = rome2_l82_mut_ptr(&s_ctx, buf_va, (uint32_t)s_recv_result);
        assert(dst != NULL);
        memset(dst, 'r', (size_t)s_recv_result);
    }
    if (s_recv_result < 0 && s_recv_code != 0) {
        *curlcode = s_recv_code;
    }
    return s_recv_result;
}

static int32_t on_closesocket_cb(rome2_l86_curl_state *s, uint32_t fn_va, uint32_t clientp_va, uint32_t sock) {
    (void)s;
    assert(s_close_count < L86_LOG_CAP);
    s_close_is_cb[s_close_count] = 1u;
    s_close_sock[s_close_count] = sock;
    s_close_count++;
    s_close_fn = fn_va;
    s_close_client = clientp_va;
    return 0x1234;
}

static int32_t on_closesocket(rome2_l86_curl_state *s, uint32_t sock) {
    (void)s;
    assert(s_close_count < L86_LOG_CAP);
    s_close_is_cb[s_close_count] = 0u;
    s_close_sock[s_close_count] = sock;
    s_close_count++;
    return 0x55;
}

static void on_delete_critical_section(rome2_l86_curl_state *s, uint32_t cs_va) {
    (void)s;
    s_dcs_calls++;
    s_dcs_va = cs_va;
}

static uint32_t on_wait_for_single_object(rome2_l86_curl_state *s, uint32_t handle, uint32_t ms) {
    (void)s;
    s_wait_calls++;
    s_wait_handle = handle;
    s_wait_ms = ms;
    return s_wait_result;
}

static void on_close_handle(rome2_l86_curl_state *s, uint32_t handle) {
    (void)s;
    s_closeh_calls++;
    s_closeh_handle = handle;
}

static uint32_t on_formget_append(
    rome2_l86_curl_state *s,
    uint32_t fn_va,
    uint32_t arg_va,
    const uint8_t *buf,
    uint32_t len) {
    (void)s;
    s_append_calls++;
    s_append_fn = fn_va;
    s_append_arg = arg_va;
    s_append_last_len = len;
    if (len != 0u) {
        assert(buf != NULL && s_append_len + len < sizeof(s_append_text));
        memcpy(s_append_text + s_append_len, buf, len);
        s_append_len += len;
        s_append_text[s_append_len] = '\0';
    }
    return s_append_calls == s_append_fail_call ? len + 1u : len;
}

static uint32_t on_fopen(rome2_l86_curl_state *s, const char *path, const char *mode) {
    (void)s;
    assert(s_fopen_calls < L86_LOG_CAP);
    copy_text(s_fopen_path[s_fopen_calls], sizeof(s_fopen_path[0]), path);
    copy_text(s_fopen_mode[s_fopen_calls], sizeof(s_fopen_mode[0]), mode);
    return s_fopen_results[s_fopen_calls++];
}

static int32_t on_fclose(rome2_l86_curl_state *s, uint32_t stream_va) {
    (void)s;
    s_fclose_calls++;
    s_fclose_stream = stream_va;
    return 0;
}

/* Returns the scripted count and fills that many bytes (capped at the request) with a per-call letter. */
static uint32_t on_fread_s(
    rome2_l86_curl_state *s,
    uint8_t *buffer,
    uint32_t buffer_size,
    uint32_t element_size,
    uint32_t count,
    uint32_t stream_va) {
    (void)s;
    assert(s_fread_calls < L86_LOG_CAP && buffer != NULL);
    uint32_t result = s_fread_script[s_fread_calls];
    s_fread_buffer_size = buffer_size;
    s_fread_elem = element_size;
    s_fread_count = count;
    s_fread_stream = stream_va;
    if (result != 0xffffffffu) {
        memset(buffer, 'a' + (int)s_fread_calls, result < count ? result : count);
    }
    s_fread_calls++;
    return result;
}

static int32_t on_stat64(rome2_l86_curl_state *s, const char *path, int64_t *st_size) {
    (void)s;
    copy_text(s_stat_path, sizeof(s_stat_path), path);
    s_stat_calls++;
    *st_size = s_stat_size;
    return s_stat_result;
}

static int32_t on_stream_refill(rome2_l86_curl_state *s, uint32_t stream_va) {
    (void)s;
    (void)stream_va;
    s_refill_calls++;
    return s_refill_result;
}

static uint8_t on_stream_is_ansi(rome2_l86_curl_state *s, uint32_t stream_va) {
    (void)s;
    (void)stream_va;
    return s_ansi;
}

static uint32_t on_write(
    rome2_l83_curl_state *g,
    uint32_t fn_va,
    const uint8_t *ptr,
    uint32_t size,
    uint32_t nmemb,
    uint32_t stream_va) {
    (void)g;
    if (s_write_count < L86_LOG_CAP) {
        uint32_t bytes = size * nmemb;
        uint32_t keep = bytes < 95u ? bytes : 95u;
        s_write_fn[s_write_count] = fn_va;
        s_write_size[s_write_count] = size;
        s_write_nmemb[s_write_count] = nmemb;
        s_write_stream[s_write_count] = stream_va;
        memset(s_write_text[s_write_count], 0, sizeof(s_write_text[s_write_count]));
        if (ptr && keep != 0u) {
            memcpy(s_write_text[s_write_count], ptr, keep);
        }
    }
    s_write_count++;
    return nmemb;
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
    uint32_t keep = size < 127u ? size : 127u;
    s_debug_calls++;
    s_debug_fn = fn_va;
    s_debug_data = data_va;
    s_debug_type = type;
    s_debug_size = size;
    s_debug_userp = userp_va;
    memcpy(s_debug_text, text, keep);
    s_debug_text[keep] = '\0';
}

static uint64_t on_system_filetime(rome2_l83_curl_state *g, uint8_t precise) {
    (void)g;
    (void)precise;
    return s_filetime;
}

static int32_t on_recv_peek(rome2_l83_curl_state *g, uint32_t sockfd) {
    (void)g;
    (void)sockfd;
    return s_peek_result;
}

static void on_llist_dtor(rome2_l82_curl_ctx *ctx, uint32_t dtor_fn_va, uint32_t user_va, uint32_t elem_ptr_va) {
    (void)ctx;
    s_dtor_calls++;
    s_dtor_fn = dtor_fn_va;
    s_dtor_user = user_va;
    s_dtor_ptr = elem_ptr_va;
}

static void set_now(uint32_t seconds) {
    s_filetime = ROME2_L83_FILETIME_UNIX_EPOCH + (uint64_t)seconds * 10000000ULL;
}

static void setup(void) {
    memset(s_arena, 0, sizeof(s_arena));
    rome2_l82_ctx_init(&s_ctx, s_arena, L86_BASE, (uint32_t)sizeof(s_arena), L86_BASE + 0x100u);
    s_ctx.on_llist_dtor = on_llist_dtor;
    rome2_l83_state_init(&s_g, &s_ctx);
    s_g.on_write = on_write;
    s_g.on_debug = on_debug;
    s_g.on_system_filetime = on_system_filetime;
    s_g.on_recv_peek = on_recv_peek;
    rome2_l86_state_init(&s_s, &s_g);
    s_s.on_openssl = on_openssl;
    s_s.on_conn_recv = on_conn_recv;
    s_s.on_closesocket_cb = on_closesocket_cb;
    s_s.on_closesocket = on_closesocket;
    s_s.on_delete_critical_section = on_delete_critical_section;
    s_s.on_wait_for_single_object = on_wait_for_single_object;
    s_s.on_close_handle = on_close_handle;
    s_s.on_formget_append = on_formget_append;
    s_s.on_fopen = on_fopen;
    s_s.on_fclose = on_fclose;
    s_s.on_fread_s = on_fread_s;
    s_s.on_stat64 = on_stat64;
    s_s.on_stream_refill = on_stream_refill;
    s_s.on_stream_is_ansi = on_stream_is_ansi;

    s_ossl_count = 0u;
    s_recv_result = 0;
    s_recv_code = 0;
    s_recv_calls = 0u;
    s_close_count = 0u;
    s_close_fn = 0u;
    s_close_client = 0u;
    s_dcs_calls = 0u;
    s_wait_calls = 0u;
    s_wait_result = 0u;
    s_closeh_calls = 0u;
    s_append_len = 0u;
    s_append_calls = 0u;
    s_append_fail_call = 0u;
    s_append_text[0] = '\0';
    s_fopen_calls = 0u;
    memset(s_fopen_results, 0, sizeof(s_fopen_results));
    s_fclose_calls = 0u;
    s_fclose_stream = 0u;
    s_fread_calls = 0u;
    memset(s_fread_script, 0, sizeof(s_fread_script));
    s_stat_result = -1;
    s_stat_size = 0;
    s_stat_calls = 0u;
    s_refill_result = ROME2_L86_CRT_EOF;
    s_refill_calls = 0u;
    s_ansi = 1u;
    s_write_count = 0u;
    s_debug_calls = 0u;
    s_debug_text[0] = '\0';
    s_peek_result = 0;
    s_dtor_calls = 0u;
    set_now(1000u);
}

static uint32_t open_easy(void) {
    uint32_t data_va = 0u;
    assert(rome2_l83_curl_open(&s_g, &data_va) == ROME2_CURLE_OK);
    assert(data_va != 0u);
    return data_va;
}

static uint32_t make_conn(uint32_t data_va) {
    uint32_t conn_va = zalloc(0x4a8u);
    wr32(conn_va, data_va);
    wr32(conn_va + 0x130u, 0xffffffffu);
    wr32(conn_va + 0x134u, 0xffffffffu);
    return conn_va;
}

/* A CRT FILE whose buffered bytes are `text`; reading past them reaches the refill hook. */
static uint32_t make_stream(const char *text) {
    uint32_t stream_va = zalloc(0x38u);
    wr32(stream_va, put_str(text));
    wr32(stream_va + 8u, (uint32_t)strlen(text));
    return stream_va;
}

static uint32_t make_slist(const char *const *items, uint32_t count) {
    uint32_t head_va = 0u;
    for (uint32_t i = 0u; i < count; ++i) {
        head_va = rome2_l82_curl_slist_append(&s_ctx, head_va, items[i]);
        assert(head_va != 0u);
    }
    return head_va;
}

static uint32_t make_jar(uint32_t running, uint32_t newsession) {
    uint32_t c_va = zalloc(0x14u);
    wr32(c_va + 8u, running);
    wr32(c_va + 0x10u, newsession);
    return c_va;
}

static uint32_t add_header(uint32_t data_va, uint32_t c_va, const char *line, const char *domain, const char *path) {
    return rome2_l86_curl_cookie_add(
        &s_s, data_va, c_va, 1u, put_str(line), domain ? put_str(domain) : 0u, path ? put_str(path) : 0u);
}

static uint32_t add_netscape(uint32_t c_va, const char *line) {
    return rome2_l86_curl_cookie_add(&s_s, 0u, c_va, 0u, put_str(line), 0u, 0u);
}

/* struct Cookie string field, or NULL when the slot is empty. */
static const char *cookie_str(uint32_t co_va, uint32_t off) {
    uint32_t va = rd32(co_va + off);
    return va != 0u ? str_at(va) : NULL;
}

static uint8_t cookie_str_is(uint32_t co_va, uint32_t off, const char *expected) {
    const char *actual = cookie_str(co_va, off);
    return (actual != NULL && strcmp(actual, expected) == 0) ? 1u : 0u;
}

static uint32_t make_post(const char *name, const char *contents, uint32_t flags) {
    uint32_t post_va = zalloc(0x34u);
    wr32(post_va + 4u, put_str(name));
    if (contents) {
        wr32(post_va + 0xcu, put_str(contents));
    }
    wr32(post_va + 0x28u, flags);
    return post_va;
}

/* Concatenates a FormData chain: data and content text, "<C>" for a callback node and "<F>" for a file node. */
static uint32_t chain_text(uint32_t form_va, char *out, uint32_t cap, uint32_t *nodes) {
    uint32_t used = 0u;
    uint32_t count = 0u;
    while (form_va != 0u) {
        int32_t type = (int32_t)rd32(form_va + 4u);
        if (type <= ROME2_CURL_FORM_CONTENT) {
            uint32_t len = rd32(form_va + 0xcu);
            const char *src = (const char *)rome2_l82_const_ptr(&s_ctx, rd32(form_va + 8u), len + 1u);
            assert(src != NULL && src[len] == '\0' && used + len < cap);
            memcpy(out + used, src, len);
            used += len;
        } else {
            assert(used + 3u < cap);
            memcpy(out + used, type == ROME2_CURL_FORM_CALLBACK ? "<C>" : "<F>", 3u);
            used += 3u;
        }
        count++;
        form_va = rd32(form_va);
    }
    out[used] = '\0';
    if (nodes) {
        *nodes = count;
    }
    return used;
}

static void test_crt_numeric(void) {
    setup();
    assert(rome2_l86_crt_ltod3(0u, 0) == 0.0);
    assert(rome2_l86_crt_ltod3(1u, 0) == 1.0);
    assert(rome2_l86_crt_ltod3(0x7fffffffu, 0) == 2147483647.0);
    /* a low dword with its top bit set is corrected by 2^32 */
    assert(rome2_l86_crt_ltod3(0x80000000u, 0) == 2147483648.0);
    assert(rome2_l86_crt_ltod3(0xffffffffu, 0) == 4294967295.0);
    assert(rome2_l86_crt_ltod3(0u, 1) == 4294967296.0);
    assert(rome2_l86_crt_ltod3(5u, 2) == 8589934597.0);
    assert(rome2_l86_crt_ltod3(0xffffffffu, -1) == -1.0);
    assert(rome2_l86_crt_ltod3(0u, -1) == -4294967296.0);
    assert(rome2_l86_crt_ltod3(0u, (int32_t)0x80000000u) == -9223372036854775808.0);

    const char *end = NULL;
    assert(rome2_l86_crt_strtoi64(&s_s, "1234567890123", &end, 10) == 1234567890123LL && *end == '\0');
    assert(rome2_l86_crt_strtoi64(&s_s, "  -42x", &end, 10) == -42 && *end == 'x');
    assert(rome2_l86_crt_strtoi64(&s_s, "0x1f", &end, 16) == 0x1f && *end == '\0');
    assert(rome2_l86_crt_strtoi64(&s_s, "abc", &end, 10) == 0 && *end == 'a');
    assert(s_ctx.last_errno == 0);
    assert(rome2_l86_crt_strtoi64(&s_s, "-999999999999999999999", NULL, 10) == INT64_MIN);
    assert(s_ctx.last_errno == 34);
}

static void test_crt_stream(void) {
    setup();
    uint8_t host[8];
    memset(host, 0, sizeof(host));

    /* fread forwards to fread_s with an unbounded buffer size */
    s_fread_script[0] = 3u;
    assert(rome2_l86_crt_fread(&s_s, host, 1u, 8u, 0x7700u) == 3u);
    assert(s_fread_buffer_size == 0xffffffffu && s_fread_elem == 1u && s_fread_count == 8u && s_fread_stream == 0x7700u);
    assert(memcmp(host, "aaa", 3u) == 0 && host[3] == 0u);
    s_s.on_fread_s = NULL;
    assert(rome2_l86_crt_fread(&s_s, host, 1u, 8u, 0x7700u) == 0u);

    /* _fgetc_nolock */
    assert(rome2_l86_crt_fgetc_nolock(&s_s, 0u) == -1);
    assert(s_ctx.last_errno == 22 && s_g.invalid_parameter_calls == 1u && s_refill_calls == 0u);
    uint32_t stream_va = make_stream("A\xff");
    uint32_t text_va = rd32(stream_va);
    assert(rome2_l86_crt_fgetc_nolock(&s_s, stream_va) == 'A');
    assert(rd32(stream_va) == text_va + 1u && rd32(stream_va + 8u) == 1u);
    assert(rome2_l86_crt_fgetc_nolock_stub(&s_s, stream_va) == 0xff); /* zero-extended, not EOF */
    assert(rd32(stream_va) == text_va + 2u && rd32(stream_va + 8u) == 0u && s_refill_calls == 0u);
    s_refill_result = 'Z';
    assert(rome2_l86_crt_fgetc_nolock(&s_s, stream_va) == 'Z');
    assert(s_refill_calls == 1u && rd32(stream_va + 8u) == 0xffffffffu && rd32(stream_va) == text_va + 2u);
    s_s.on_stream_refill = NULL;
    assert(rome2_l86_crt_fgetc_nolock(&s_s, stream_va) == -1);

    /* fgets argument validation */
    uint32_t buf_va = zalloc(16u);
    s_ctx.last_errno = 0;
    s_g.invalid_parameter_calls = 0u;
    assert(rome2_l86_crt_fgets(&s_s, 0u, 5, stream_va) == 0u && s_ctx.last_errno == 22);
    assert(rome2_l86_crt_fgets(&s_s, buf_va, -1, stream_va) == 0u);
    assert(rome2_l86_crt_fgets(&s_s, buf_va, 5, 0u) == 0u);
    assert(rome2_l86_crt_fgets(&s_s, 0u, 0, 0u) == 0u);
    assert(s_g.invalid_parameter_calls == 4u && s_s.lock_file_calls == 0u);
    s_ctx.last_errno = 0;
    assert(rome2_l86_crt_fgets(&s_s, 0u, 0, stream_va) == 0u);
    assert(rome2_l86_crt_common_fgets(&s_s, buf_va, 0, stream_va) == 0u);
    assert(s_ctx.last_errno == 0 && s_g.invalid_parameter_calls == 4u && s_s.lock_file_calls == 0u);

    /* line reads */
    stream_va = make_stream("ab\ncd");
    memset(rome2_l82_mut_ptr(&s_ctx, buf_va, 16u), 'x', 16u);
    assert(rome2_l86_crt_fgets(&s_s, buf_va, 10, stream_va) == buf_va);
    assert(strcmp(str_at(buf_va), "ab\n") == 0 && s_s.lock_file_calls == 1u && s_s.unlock_file_calls == 1u);
    assert(rome2_l86_crt_fgets(&s_s, buf_va, 10, stream_va) == buf_va && strcmp(str_at(buf_va), "cd") == 0);
    /* end of file before any character: no result and the buffer is left alone */
    assert(rome2_l86_crt_fgets(&s_s, buf_va, 10, stream_va) == 0u && strcmp(str_at(buf_va), "cd") == 0);
    assert(s_s.lock_file_calls == 3u && s_s.unlock_file_calls == 3u);

    /* the count bounds the line, and a count of one stores only the terminator */
    stream_va = make_stream("abcdef");
    assert(rome2_l86_crt_fgets(&s_s, buf_va, 3, stream_va) == buf_va && strcmp(str_at(buf_va), "ab") == 0);
    assert(rome2_l86_crt_fgets(&s_s, buf_va, 1, stream_va) == buf_va && str_at(buf_va)[0] == '\0');
    assert(rd32(stream_va + 8u) == 4u);

    /* a stream the ANSI check rejects is locked, unlocked and not read */
    s_ansi = 0u;
    assert(rome2_l86_crt_fgets(&s_s, buf_va, 5, stream_va) == 0u && rd32(stream_va + 8u) == 4u);
    assert(s_s.lock_file_calls == 6u && s_s.unlock_file_calls == 6u);
    rome2_l86_crt_fgets_unlock_funclet(&s_s, stream_va);
    assert(s_s.unlock_file_calls == 7u);
}

static void test_rand_and_strings(void) {
    setup();
    assert(rome2_l86_curl_rand(&s_g) == 0x30390000u && s_g.randseed == 0x00003039u);
    assert(rome2_l86_curl_rand(&s_g) == 0x167ed3dcu);
    assert(rome2_l86_curl_rand(&s_g) == 0x27dfa704u);
    s_g.randseed = 0x12345678u;
    assert(rome2_l86_curl_rand(&s_g) == 0x91510b71u);
    assert(rome2_l86_curl_rand(&s_g) == 0xbdb66f47u && s_g.randseed == 0x6f47bdb6u);
    assert(rome2_l86_curl_rand(NULL) == 0u);

    char line[] = "\t\ta\tbc,,d\t";
    char *save = NULL;
    char *tok = rome2_l86_curl_strtok_r(line, "\t,", &save);
    assert(tok == line + 2 && strcmp(tok, "a") == 0 && save == line + 4);
    tok = rome2_l86_curl_strtok_r(NULL, "\t,", &save);
    assert(tok == line + 4 && strcmp(tok, "bc") == 0);
    tok = rome2_l86_curl_strtok_r(NULL, "\t,", &save);
    assert(tok == line + 8 && strcmp(tok, "d") == 0 && *save == '\0');
    assert(rome2_l86_curl_strtok_r(NULL, "\t,", &save) == NULL);
    char only_sep[] = ",,";
    save = only_sep + 2;
    assert(rome2_l86_curl_strtok_r(only_sep, ",", &save) == NULL && save == only_sep + 2);
    char last[] = "end";
    tok = rome2_l86_curl_strtok_r(last, ",", &save);
    assert(tok == last && save == last + 3); /* no separator: the save pointer rests on the terminator */

    assert(rome2_l86_curl_raw_nequal("Set-Cookie:", "set-cookie: a=b", 11u) == 1);
    assert(rome2_l86_curl_raw_nequal("Set-Cookie:", "Set-Cookie", 11u) == 0);
    assert(rome2_l86_curl_raw_nequal("abc", "abd", 2u) == 1);
    assert(rome2_l86_curl_raw_nequal("abc", "abd", 3u) == 0);
    assert(rome2_l86_curl_raw_nequal("ab", "abc", 3u) == 0);
    assert(rome2_l86_curl_raw_nequal("abc", "ABC", 10u) == 1);
    assert(rome2_l86_curl_raw_nequal("", "", 5u) == 1);
    assert(rome2_l86_curl_raw_nequal("a", "b", 0u) == 1);
    assert(rome2_l86_curl_raw_nequal("{z", "[Z", 2u) == 0); /* only a..z folds */
    assert(rome2_l86_curl_raw_nequal("\xe9", "\xc9", 1u) == 0);

    const char *hay = "a/b/c";
    assert(rome2_l86_curl_memrchr(hay, '/', 5u) == hay + 3);
    assert(rome2_l86_curl_memrchr(hay, '/', 3u) == hay + 1);
    assert(rome2_l86_curl_memrchr(hay, '/', 1u) == NULL);
    assert(rome2_l86_curl_memrchr(hay, 'a', 1u) == hay);
    assert(rome2_l86_curl_memrchr(hay, '/', 0u) == NULL);
    assert(rome2_l86_curl_memrchr(hay, 'x', 5u) == NULL);
}

static void test_llist_hash_alloc(void) {
    setup();
    uint32_t list_va = rome2_l86_curl_llist_alloc(&s_ctx, 0x7003u);
    assert(list_va != 0u && rd32(list_va) == 0u && rd32(list_va + 4u) == 0u);
    assert(rd32(list_va + 8u) == 0x7003u && rd32(list_va + 0xcu) == 0u);

    uint32_t allocs = s_ctx.alloc_count;
    assert(rome2_l86_curl_hash_alloc(&s_ctx, 0, 1u, 2u, 3u) == 0u);
    assert(rome2_l86_curl_hash_alloc(&s_ctx, 3, 0u, 2u, 3u) == 0u);
    assert(rome2_l86_curl_hash_alloc(&s_ctx, 3, 1u, 0u, 3u) == 0u);
    assert(rome2_l86_curl_hash_alloc(&s_ctx, 3, 1u, 2u, 0u) == 0u);
    assert(s_ctx.alloc_count == allocs);

    uint32_t h_va = rome2_l86_curl_hash_alloc(&s_ctx, 3, 0x7001u, 0x7002u, 0x7004u);
    assert(h_va != 0u && rd32(h_va + 4u) == 0x7001u && rd32(h_va + 8u) == 0x7002u && rd32(h_va + 0xcu) == 0x7004u);
    assert(rd32(h_va + 0x10u) == 3u && rd32(h_va + 0x14u) == 0u && s_ctx.alloc_count == allocs + 5u);
    for (uint32_t i = 0u; i < 3u; ++i) {
        uint32_t bucket_va = rd32(rd32(h_va) + i * 4u);
        assert(bucket_va != 0u && rd32(bucket_va + 8u) == 0x10f12780u && rd32(bucket_va + 0xcu) == 0u);
    }

    uint32_t dns_va = rome2_l86_curl_mk_dnscache(&s_ctx);
    assert(dns_va != 0u && rd32(dns_va + 0x10u) == 7u);
    assert(rd32(dns_va + 4u) == 0x10f126c0u && rd32(dns_va + 8u) == 0x10f12710u && rd32(dns_va + 0xcu) == 0x10f13510u);

    /* out of memory at the list, the hash, the table and the second bucket */
    uint32_t full = limit_arena(0u);
    assert(rome2_l86_curl_llist_alloc(&s_ctx, 1u) == 0u);
    assert(rome2_l86_curl_hash_alloc(&s_ctx, 3, 1u, 2u, 3u) == 0u);
    s_ctx.arena_size = full;
    uint32_t frees = s_ctx.free_count;
    full = limit_arena(0x18u);
    assert(rome2_l86_curl_hash_alloc(&s_ctx, 3, 1u, 2u, 3u) == 0u && s_ctx.free_count == frees + 1u);
    s_ctx.arena_size = full;
    frees = s_ctx.free_count;
    full = limit_arena(0x18u + 0xcu + 0x10u);
    assert(rome2_l86_curl_hash_alloc(&s_ctx, 3, 1u, 2u, 3u) == 0u);
    assert(s_ctx.free_count == frees + 3u); /* the first bucket list, the table and the hash */
    s_ctx.arena_size = full;
}

static void test_slist_duplicate_and_strippath(void) {
    setup();
    static const char *const items[] = {"one", "two", "three"};
    assert(rome2_l86_curl_slist_duplicate(&s_ctx, 0u) == 0u);
    uint32_t in_va = make_slist(items, 3u);
    uint32_t out_va = rome2_l86_curl_slist_duplicate(&s_ctx, in_va);
    uint32_t a = in_va;
    uint32_t b = out_va;
    for (uint32_t i = 0u; i < 3u; ++i) {
        assert(a != 0u && b != 0u && a != b && rd32(a) != rd32(b));
        assert(strcmp(str_at(rd32(b)), items[i]) == 0);
        a = rd32(a + 4u);
        b = rd32(b + 4u);
    }
    assert(a == 0u && b == 0u);

    /* the second string cannot be duplicated: its node and the partial copy are released */
    uint32_t frees = s_ctx.free_count;
    uint32_t full = limit_arena(8u + 4u + 8u);
    assert(rome2_l86_curl_slist_duplicate(&s_ctx, in_va) == 0u && s_ctx.free_count == frees + 3u);
    s_ctx.arena_size = full;
    frees = s_ctx.free_count;
    full = limit_arena(8u + 4u);
    assert(rome2_l86_curl_slist_duplicate(&s_ctx, in_va) == 0u && s_ctx.free_count == frees + 2u);
    s_ctx.arena_size = full;

    assert(strcmp(str_at(rome2_l86_strippath(&s_ctx, put_str("/a/b/c.txt"))), "c.txt") == 0);
    assert(strcmp(str_at(rome2_l86_strippath(&s_ctx, put_str("C:\\dir\\f.bin"))), "f.bin") == 0);
    assert(strcmp(str_at(rome2_l86_strippath(&s_ctx, put_str("a/b\\c"))), "c") == 0);
    assert(strcmp(str_at(rome2_l86_strippath(&s_ctx, put_str("a\\b/c"))), "c") == 0);
    assert(strcmp(str_at(rome2_l86_strippath(&s_ctx, put_str("plain"))), "plain") == 0);
    assert(str_at(rome2_l86_strippath(&s_ctx, put_str("dir/")))[0] == '\0');
    uint32_t path_va = put_str("x/yz");
    frees = s_ctx.free_count;
    assert(rome2_l86_strippath(&s_ctx, path_va) != 0u && s_ctx.free_count == frees + 1u);
    full = limit_arena(0u);
    assert(rome2_l86_strippath(&s_ctx, path_va) == 0u && s_ctx.free_count == frees + 1u);
    s_ctx.arena_size = full;
    full = limit_arena(8u);
    assert(rome2_l86_strippath(&s_ctx, path_va) == 0u && s_ctx.free_count == frees + 2u);
    s_ctx.arena_size = full;
}

static void test_ssl_teardown(void) {
    setup();
    static const uint32_t expected[ROME2_L86_OPENSSL_THUNK_COUNT][3] = {
        {0x116c7f0fu, 0x1172f604u, 8u},
        {0x116c7f81u, 0x1172f57cu, 48u},
        {0x116c7fc9u, 0x1172f5acu, 96u},
        {0x116c7fcfu, 0x1172f5b0u, 86u}
    };
    for (int32_t id = 0; id < ROME2_L86_OPENSSL_THUNK_COUNT; ++id) {
        assert(rome2_l86_openssl_thunks[id].thunk_va == expected[id][0]);
        assert(rome2_l86_openssl_thunks[id].iat_slot_va == expected[id][1]);
        assert(rome2_l86_openssl_thunks[id].ordinal == expected[id][2] && rome2_l86_openssl_thunks[id].is_ssleay32 == 1u);
        assert(rome2_l86_openssl_thunk(&s_s, id, 0x100u + (uint32_t)id) == 0x600 + id);
        assert(s_ossl_ids[id] == id && s_ossl_a0[id] == 0x100u + (uint32_t)id);
    }
    assert(rome2_l86_openssl_thunk(&s_s, -1, 0u) == 0 && rome2_l86_openssl_thunk(&s_s, 4, 0u) == 0);
    assert(s_ossl_count == 4u);
    s_s.on_openssl = NULL;
    assert(rome2_l86_openssl_thunk(&s_s, ROME2_L86_SSLEAY32_ORD_8, 1u) == 0);
    s_s.on_openssl = on_openssl;

    /* ssl[0] is conn+0x150, ssl[1] is conn+0x168; the handle is at +0xc and the context at +8 */
    uint32_t conn_va = make_conn(0u);
    s_ossl_count = 0u;
    rome2_l86_curl_ossl_close(&s_s, conn_va, 0);
    assert(s_ossl_count == 0u);
    wr32(conn_va + 0x15cu, 0x9001u);
    wr32(conn_va + 0x158u, 0x9002u);
    wr32(conn_va + 0x170u, 0x9003u);
    rome2_l86_curl_ossl_close(&s_s, conn_va, 0);
    assert(s_ossl_count == 4u);
    assert(s_ossl_ids[0] == ROME2_L86_SSLEAY32_ORD_96 && s_ossl_a0[0] == 0x9001u);
    assert(s_ossl_ids[1] == ROME2_L86_SSLEAY32_ORD_86 && s_ossl_a0[1] == 0x9001u);
    assert(s_ossl_ids[2] == ROME2_L86_SSLEAY32_ORD_48 && s_ossl_a0[2] == 0x9001u);
    assert(s_ossl_ids[3] == ROME2_L86_SSLEAY32_ORD_8 && s_ossl_a0[3] == 0x9002u);
    assert(rd32(conn_va + 0x15cu) == 0u && rd32(conn_va + 0x158u) == 0u && rd32(conn_va + 0x170u) == 0x9003u);
    s_ossl_count = 0u;
    rome2_l86_curl_ssl_close(&s_s, conn_va, 1);
    assert(s_ossl_count == 1u && s_ossl_ids[0] == ROME2_L86_SSLEAY32_ORD_8 && s_ossl_a0[0] == 0x9003u);
    assert(rd32(conn_va + 0x170u) == 0u);

    assert(rome2_l86_curl_ssl_engines_list(&s_s, 0x1234u) == 0u && s_g.resolver_stub_calls == 1u);

    uint32_t sslc_va = zalloc(0x2cu);
    wr32(sslc_va + 0x10u, put_str("capath"));
    wr32(sslc_va + 0x14u, put_str("cafile"));
    wr32(sslc_va + 0x20u, put_str("random"));
    wr32(sslc_va + 0x28u, put_str("ciphers"));
    wr32(sslc_va + 0x18u, 0x4444u); /* not a string slot */
    uint32_t frees = s_ctx.free_count;
    rome2_l86_curl_free_ssl_config(&s_ctx, sslc_va);
    assert(s_ctx.free_count == frees + 4u && rd32(sslc_va + 0x18u) == 0x4444u);
    assert(rd32(sslc_va + 0x10u) == 0u && rd32(sslc_va + 0x14u) == 0u && rd32(sslc_va + 0x20u) == 0u);
    assert(rd32(sslc_va + 0x24u) == 0u && rd32(sslc_va + 0x28u) == 0u);
    rome2_l86_curl_free_ssl_config(&s_ctx, sslc_va);
    assert(s_ctx.free_count == frees + 4u);
}

static void test_resolver_teardown(void) {
    setup();
    uint32_t ai2_va = zalloc(0x20u);
    uint32_t ai1_va = zalloc(0x20u);
    wr32(ai1_va + 0x14u, put_str("canon"));
    wr32(ai1_va + 0x18u, zalloc(0x10u));
    wr32(ai1_va + 0x1cu, ai2_va);
    uint32_t frees = s_ctx.free_count;
    rome2_l86_curl_freeaddrinfo(&s_ctx, 0u);
    assert(s_ctx.free_count == frees);
    rome2_l86_curl_freeaddrinfo(&s_ctx, ai1_va);
    assert(s_ctx.free_count == frees + 4u);

    uint32_t hnd_va = zalloc(4u);
    wr32(hnd_va, 0x44u);
    assert(rome2_l86_curl_thread_join(&s_s, hnd_va) == 1);
    assert(s_wait_calls == 1u && s_wait_handle == 0x44u && s_wait_ms == 0xffffffffu);
    assert(s_closeh_calls == 1u && s_closeh_handle == 0x44u && rd32(hnd_va) == 0u);
    wr32(hnd_va, 0x45u);
    s_wait_result = 0x102u; /* any nonzero wait result reports failure */
    assert(rome2_l86_curl_thread_join(&s_s, hnd_va) == 0 && s_closeh_handle == 0x45u && rd32(hnd_va) == 0u);
    s_s.on_wait_for_single_object = NULL;
    s_s.on_close_handle = NULL;
    wr32(hnd_va, 0x46u);
    assert(rome2_l86_curl_thread_join(&s_s, hnd_va) == 1 && rd32(hnd_va) == 0u && s_closeh_calls == 2u);
    s_s.on_wait_for_single_object = on_wait_for_single_object;
    s_s.on_close_handle = on_close_handle;
    s_wait_result = 0u;

    uint32_t tsd_va = zalloc(0x38u);
    uint32_t mtx_va = zalloc(0x18u);
    for (uint32_t off = 0u; off < 0x38u; off += 4u) {
        wr32(tsd_va + off, 0xa5a5a5a5u);
    }
    wr32(tsd_va, mtx_va);
    wr32(tsd_va + 8u, put_str("host"));
    ai1_va = zalloc(0x20u);
    wr32(ai1_va + 0x18u, zalloc(0x10u));
    wr32(tsd_va + 0x14u, ai1_va);
    frees = s_ctx.free_count;
    rome2_l86_destroy_thread_sync_data(&s_s, tsd_va);
    assert(s_dcs_calls == 1u && s_dcs_va == mtx_va && s_ctx.free_count == frees + 4u);
    for (uint32_t off = 0u; off < 0x38u; off += 4u) {
        assert(rd32(tsd_va + off) == 0u);
    }
    rome2_l86_destroy_thread_sync_data(&s_s, tsd_va);
    assert(s_dcs_calls == 1u && s_ctx.free_count == frees + 4u);

    /* a running resolver thread is joined before its record is destroyed */
    uint32_t conn_va = make_conn(0u);
    uint32_t td_va = zalloc(0x44u);
    wr32(td_va, 0x77u);
    wr32(td_va + 0xcu + 8u, put_str("tsd-host"));
    wr32(conn_va + 0x3ccu, put_str("async-host"));
    wr32(conn_va + 0x3e0u, td_va);
    frees = s_ctx.free_count;
    s_wait_calls = 0u;
    rome2_l86_curl_resolver_cancel(&s_s, conn_va);
    assert(s_wait_calls == 1u && s_wait_handle == 0x77u && s_closeh_handle == 0x77u && rd32(td_va) == 0u);
    assert(s_ctx.free_count == frees + 3u && rd32(conn_va + 0x3ccu) == 0u && rd32(conn_va + 0x3e0u) == 0u);
    assert(rd32(td_va + 0xcu + 8u) == 0u);

    td_va = zalloc(0x44u);
    wr32(conn_va + 0x3e0u, td_va);
    frees = s_ctx.free_count;
    rome2_l86_curl_resolver_cancel(&s_s, conn_va);
    assert(s_wait_calls == 1u && s_ctx.free_count == frees + 1u && rd32(conn_va + 0x3e0u) == 0u);
    rome2_l86_curl_resolver_cancel(&s_s, conn_va);
    assert(s_wait_calls == 1u && s_ctx.free_count == frees + 1u);
}

static void test_closesocket_and_connc(void) {
    setup();
    uint32_t conn_va = make_conn(0u);
    assert(rome2_l86_curl_closesocket(&s_s, 0u, 7u) == 0x55);
    assert(rome2_l86_curl_closesocket(&s_s, conn_va, 8u) == 0x55);
    assert(s_close_count == 2u && s_close_is_cb[0] == 0u && s_close_sock[0] == 7u && s_close_sock[1] == 8u);

    wr32(conn_va + 0x28u, 0x8800u);
    wr32(conn_va + 0x2cu, 0x8801u);
    wr32(conn_va + 0x134u, 66u);
    assert(rome2_l86_curl_closesocket(&s_s, conn_va, 55u) == 0x1234);
    assert(s_close_count == 3u && s_close_is_cb[2] == 1u && s_close_sock[2] == 55u);
    assert(s_close_fn == 0x8800u && s_close_client == 0x8801u);
    /* the secondary socket goes to the callback unless it was accepted */
    assert(rome2_l86_curl_closesocket(&s_s, conn_va, 66u) == 0x1234 && s_close_is_cb[3] == 1u);
    wr32(conn_va + 0x13cu, 1u);
    assert(rome2_l86_curl_closesocket(&s_s, conn_va, 66u) == 0x55);
    assert(s_close_count == 5u && s_close_is_cb[4] == 0u && s_close_sock[4] == 66u && rd32(conn_va + 0x13cu) == 0u);
    wr32(conn_va + 0x13cu, 1u);
    assert(rome2_l86_curl_closesocket(&s_s, conn_va, 55u) == 0x1234 && rd32(conn_va + 0x13cu) == 1u);
    s_s.on_closesocket_cb = NULL;
    s_s.on_closesocket = NULL;
    assert(rome2_l86_curl_closesocket(&s_s, conn_va, 55u) == 0 && rome2_l86_curl_closesocket(&s_s, 0u, 1u) == 0);
    s_s.on_closesocket_cb = on_closesocket_cb;
    s_s.on_closesocket = on_closesocket;

    /* Curl_mk_connc: the type picks the default, the amount is clamped */
    uint32_t c_va = rome2_l86_curl_mk_connc(&s_ctx, 0, 0);
    assert(c_va != 0u && rd32(c_va + 4u) == 5u && rd32(c_va) != 0u && rd32(c_va + 8u) == 0u);
    c_va = rome2_l86_curl_mk_connc(&s_ctx, 1, -1);
    assert(c_va != 0u && rd32(c_va + 4u) == 10u);
    c_va = rome2_l86_curl_mk_connc(&s_ctx, 7, 3);
    assert(c_va != 0u && rd32(c_va + 4u) == 3u);
    for (uint32_t i = 0u; i < 3u; ++i) {
        assert(rd32(rd32(c_va) + i * 4u) == 0u);
    }
    uint32_t frees = s_ctx.free_count;
    assert(rome2_l86_curl_mk_connc(&s_ctx, 0, 0x20000000) == 0u && s_ctx.free_count == frees + 1u);
    uint32_t full = limit_arena(0u);
    assert(rome2_l86_curl_mk_connc(&s_ctx, 0, 1) == 0u && s_ctx.free_count == frees + 1u);
    s_ctx.arena_size = full;
    full = limit_arena(0xcu);
    assert(rome2_l86_curl_mk_connc(&s_ctx, 0, 1) == 0u && s_ctx.free_count == frees + 2u);
    s_ctx.arena_size = full;

    /* Curl_rm_connc releases every cached connection */
    uint32_t a_va = make_conn(0u);
    uint32_t b_va = make_conn(0u);
    uint32_t pipe_va = rome2_l86_curl_llist_alloc(&s_ctx, 0x7003u);
    uint32_t elem_va = zalloc(0xcu);
    wr32(elem_va, 0x5555u);
    wr32(pipe_va, elem_va);
    wr32(pipe_va + 4u, elem_va);
    wr32(pipe_va + 0xcu, 1u);
    wr32(a_va + 0x130u, 11u);
    wr32(a_va + 0x134u, 12u);
    wr32(a_va + 0x104u, put_str("user"));
    wr32(a_va + 0x26cu, put_str("cookiehost"));
    wr32(a_va + 0x290u, put_str("master"));
    wr32(a_va + 0x498u, put_str("localdev"));
    wr32(a_va + 0x180u + 0x14u, put_str("cafile"));
    wr32(a_va + 0x3ccu, put_str("async"));
    wr32(a_va + 0x15cu, 0x9001u);
    wr32(a_va + 0x170u, 0x9002u);
    wr32(a_va + 0x280u, pipe_va);
    wr32(rd32(c_va), a_va);
    wr32(rd32(c_va) + 8u, b_va);
    uint32_t connects_va = rd32(c_va);
    frees = s_ctx.free_count;
    s_close_count = 0u;
    s_ossl_count = 0u;
    rome2_l86_curl_rm_connc(&s_s, 0u);
    assert(s_ctx.free_count == frees);
    rome2_l86_curl_rm_connc(&s_s, c_va);
    assert(s_ossl_count == 4u && s_ossl_ids[0] == ROME2_L86_SSLEAY32_ORD_96 && s_ossl_a0[0] == 0x9001u);
    assert(s_ossl_ids[3] == ROME2_L86_SSLEAY32_ORD_8 && s_ossl_a0[3] == 0x9002u);
    assert(s_close_count == 2u && s_close_sock[0] == 12u && s_close_sock[1] == 11u);
    assert(s_dtor_calls == 1u && s_dtor_fn == 0x7003u && s_dtor_user == 0u && s_dtor_ptr == 0x5555u);
    /* A: six strings, the pipe element and list, the record; B: the record; then the table and the cache */
    assert(s_ctx.free_count == frees + 9u + 1u + 2u);
    assert(rd32(connects_va) == 0u && rd32(connects_va + 8u) == 0u);
    assert(rd32(c_va) == 0u && rd32(c_va + 4u) == 0u);
    assert(rd32(a_va + 0x104u) == 0u && rd32(a_va + 0x280u) == 0u && rd32(a_va + 0x498u) == 0u);

    c_va = zalloc(0xcu);
    wr32(c_va + 4u, 9u);
    frees = s_ctx.free_count;
    rome2_l86_curl_rm_connc(&s_s, c_va);
    assert(s_ctx.free_count == frees + 1u && rd32(c_va + 4u) == 0u);
}

static void test_dupset(void) {
    setup();
    uint32_t src_va = open_easy();
    uint32_t dst_va = zalloc(ROME2_CURL_EASY_BYTES);
    wr32(src_va + 0x378u, put_str("alpha"));
    wr32(src_va + 0x378u + 5u * 4u, put_str("beta"));
    wr32(src_va + 0x378u + 0x25u * 4u, put_str("omega"));
    wr32(src_va + 0x218u, 0x1234u);
    wr32(dst_va + 0x378u + 4u, 0x00dead00u); /* a stale slot is cleared, not freed */
    uint32_t frees = s_ctx.free_count;
    assert(rome2_l86_curl_dupset(&s_ctx, dst_va, src_va) == ROME2_CURLE_OK && s_ctx.free_count == frees);
    assert(memcmp(str_at(dst_va + 0x128u), str_at(src_va + 0x128u), 0x250u) == 0);
    assert(memcmp(str_at(dst_va + 0x410u), str_at(src_va + 0x410u), 0x40u) == 0);
    assert(rd32(dst_va + 0x128u) == L86_STDERR_VA && rd32(dst_va + 0x218u) == 0x1234u);
    for (uint32_t i = 0u; i < 0x26u; ++i) {
        uint32_t src_str = rd32(src_va + 0x378u + i * 4u);
        uint32_t dst_str = rd32(dst_va + 0x378u + i * 4u);
        if (src_str == 0u) {
            assert(dst_str == 0u);
        } else {
            assert(dst_str != 0u && dst_str != src_str && strcmp(str_at(dst_str), str_at(src_str)) == 0);
        }
    }
    assert(rd32(dst_va + 0x450u) == 0u); /* the copy stops at the end of the UserDefined block */

    uint32_t dst2_va = zalloc(ROME2_CURL_EASY_BYTES);
    uint32_t full = limit_arena(8u);
    assert(rome2_l86_curl_dupset(&s_ctx, dst2_va, src_va) == ROME2_CURLE_OUT_OF_MEMORY);
    s_ctx.arena_size = full;
    assert(rd32(dst2_va + 0x378u) != 0u && rd32(dst2_va + 0x378u + 5u * 4u) == 0u);
}

static void test_duphandle(void) {
    setup();
    static const char *const cookie_lines[] = {"Set-Cookie: a=b", "Set-Cookie: c=d"};
    uint32_t in_va = open_easy();

    /* a bare handle */
    uint32_t stubs = s_g.resolver_stub_calls;
    uint32_t out_va = rome2_l86_curl_easy_duphandle(&s_s, in_va);
    assert(out_va != 0u && out_va != in_va && rd32(out_va + 0x8784u) == 0xc0dedbadu);
    assert(rd32(out_va + 0x58cu) != 0u && rd32(out_va + 0x58cu) != rd32(in_va + 0x58cu) && rd32(out_va + 0x590u) == 0x100u);
    assert(rd32(out_va + 0x57cu) == 0u && rd32(out_va + 0x588u) == 0xffffffffu);
    assert(rd32(out_va + 0x468u) == 0u && rd32(out_va + 0x460u) == 0u);
    assert(rd32(out_va + 0x450u) == 0u && rd32(out_va + 0x454u) == 0u && rd32(out_va + 0x458u) == 0u);
    assert(rd32(out_va + 0x28u) == 0xffffffffu && rd32(out_va + 0x2cu) == 0xffffffffu);
    assert(s_g.resolver_stub_calls == stubs + 1u && s_fopen_calls == 0u);

    /* cookies, the pending cookie list, the URL and the referer are duplicated */
    uint32_t jar_va = rome2_l86_curl_cookie_init(&s_s, in_va, put_str("jar.txt"), 0u, 0u);
    assert(jar_va != 0u && s_fopen_calls == 1u);
    wr32(in_va + 0x468u, jar_va);
    wr32(in_va + 0x218u, 1u);
    wr32(in_va + 0x460u, make_slist(cookie_lines, 2u));
    wr32(in_va + 0x450u, put_str("http://example.com/"));
    wr32(in_va + 0x458u, put_str("http://referer/"));
    wr32(in_va + 0x4a8u, 0x60u);
    wr32(in_va + 0x4a0u, 1u);
    wr32(in_va + 0x378u, put_str("option"));
    s_fopen_results[1] = make_stream("example.com\tFALSE\t/\tFALSE\t5\tkept\t1\nexample.com\tFALSE\t/\tFALSE\t0\tsession\t2\n");
    out_va = rome2_l86_curl_easy_duphandle(&s_s, in_va);
    assert(out_va != 0u && rd32(out_va + 0x8784u) == 0xc0dedbadu);
    assert(rd32(out_va + 0x4a8u) == 0x60u && rd32(out_va + 0x4a0u) == 1u);
    assert(strcmp(str_at(rd32(out_va + 0x378u)), "option") == 0 && rd32(out_va + 0x378u) != rd32(in_va + 0x378u));
    uint32_t out_jar_va = rd32(out_va + 0x468u);
    assert(out_jar_va != 0u && out_jar_va != jar_va && s_fopen_calls == 2u);
    assert(strcmp(s_fopen_path[1], "jar.txt") == 0 && strcmp(s_fopen_mode[1], "r") == 0 && s_fclose_calls == 1u);
    assert(strcmp(str_at(rd32(out_jar_va + 4u)), "jar.txt") == 0 && rd32(out_jar_va + 4u) != rd32(jar_va + 4u));
    /* set.cookiesession travels as newsession, so the session cookie in the file is dropped */
    assert(rd32(out_jar_va + 8u) == 1u && rd32(out_jar_va + 0x10u) == 1u && rd32(out_jar_va + 0xcu) == 1u);
    assert(cookie_str_is(rd32(out_jar_va), 4u, "kept") == 1u);
    uint32_t list_va = rd32(out_va + 0x460u);
    assert(list_va != 0u && list_va != rd32(in_va + 0x460u));
    assert(strcmp(str_at(rd32(list_va)), "Set-Cookie: a=b") == 0);
    assert(strcmp(str_at(rd32(rd32(list_va + 4u))), "Set-Cookie: c=d") == 0 && rd32(rd32(list_va + 4u) + 4u) == 0u);
    assert(rd32(out_va + 0x450u) != rd32(in_va + 0x450u) && rd32(out_va + 0x454u) == 1u);
    assert(strcmp(str_at(rd32(out_va + 0x450u)), "http://example.com/") == 0);
    assert(rd32(out_va + 0x458u) != rd32(in_va + 0x458u) && rd32(out_va + 0x45cu) == 1u);
    assert(strcmp(str_at(rd32(out_va + 0x458u)), "http://referer/") == 0);

    /* failures: the handle, the header buffer, a set string, the URL and the referer */
    uint32_t plain_va = open_easy();
    uint32_t full = limit_arena(0u);
    assert(rome2_l86_curl_easy_duphandle(&s_s, plain_va) == 0u);
    s_ctx.arena_size = full;
    uint32_t frees = s_ctx.free_count;
    full = limit_arena(ROME2_CURL_EASY_BYTES);
    assert(rome2_l86_curl_easy_duphandle(&s_s, plain_va) == 0u && s_ctx.free_count == frees + 1u);
    s_ctx.arena_size = full;

    wr32(plain_va + 0x378u, put_str("first"));
    wr32(plain_va + 0x37cu, put_str("second"));
    frees = s_ctx.free_count;
    full = limit_arena(ROME2_CURL_EASY_BYTES + 0x100u + 8u);
    assert(rome2_l86_curl_easy_duphandle(&s_s, plain_va) == 0u);
    assert(s_ctx.free_count == frees + 3u); /* the header buffer, the one copied string and the handle */
    s_ctx.arena_size = full;

    wr32(plain_va + 0x378u, 0u);
    wr32(plain_va + 0x37cu, 0u);
    wr32(plain_va + 0x450u, put_str("url"));
    wr32(plain_va + 0x458u, put_str("ref"));
    frees = s_ctx.free_count;
    full = limit_arena(ROME2_CURL_EASY_BYTES + 0x100u);
    assert(rome2_l86_curl_easy_duphandle(&s_s, plain_va) == 0u && s_ctx.free_count == frees + 2u);
    s_ctx.arena_size = full;
    frees = s_ctx.free_count;
    full = limit_arena(ROME2_CURL_EASY_BYTES + 0x100u + 4u);
    assert(rome2_l86_curl_easy_duphandle(&s_s, plain_va) == 0u && s_ctx.free_count == frees + 3u);
    s_ctx.arena_size = full;

    /* a cookie list that cannot be duplicated */
    wr32(plain_va + 0x450u, 0u);
    wr32(plain_va + 0x458u, 0u);
    wr32(plain_va + 0x460u, make_slist(cookie_lines, 1u));
    frees = s_ctx.free_count;
    full = limit_arena(ROME2_CURL_EASY_BYTES + 0x100u + 8u);
    assert(rome2_l86_curl_easy_duphandle(&s_s, plain_va) == 0u && s_ctx.free_count == frees + 3u);
    s_ctx.arena_size = full;

    /* a cookie jar that cannot be allocated */
    wr32(plain_va + 0x460u, 0u);
    wr32(plain_va + 0x468u, jar_va);
    frees = s_ctx.free_count;
    full = limit_arena(ROME2_CURL_EASY_BYTES + 0x100u);
    assert(rome2_l86_curl_easy_duphandle(&s_s, plain_va) == 0u && s_ctx.free_count == frees + 2u);
    s_ctx.arena_size = full;
}

static void test_infof(void) {
    setup();
    uint32_t data_va = open_easy();
    rome2_l86_curl_infof(&s_s, 0u, "x");
    rome2_l86_curl_infof(&s_s, data_va, "quiet %d", 1);
    assert(s_write_count == 0u && s_debug_calls == 0u);

    wr32(data_va + 0x31cu, 1u);
    rome2_l86_curl_infof(&s_s, data_va, "code %d %s\n", 7, "ok");
    assert(s_write_count == 2u && s_write_fn[0] == 0x11688039u && s_write_fn[1] == 0x11688039u);
    assert(s_write_size[0] == 2u && s_write_nmemb[0] == 1u && strcmp(s_write_text[0], "* ") == 0);
    assert(s_write_size[1] == 10u && s_write_nmemb[1] == 1u && strcmp(s_write_text[1], "code 7 ok\n") == 0);
    assert(s_write_stream[0] == L86_STDERR_VA && s_write_stream[1] == L86_STDERR_VA);

    /* a NULL string argument prints as "(nil)", or as nothing under a precision below five */
    rome2_l86_curl_infof(&s_s, data_va, "[%s][%.3s][%.5s]", (const char *)NULL, (const char *)NULL, (const char *)NULL);
    assert(s_write_count == 4u && strcmp(s_write_text[3], "[(nil)][][(nil)]") == 0);

    wr32(data_va + 0x19cu, 0x8100u);
    wr32(data_va + 0x12cu, 0x8200u);
    rome2_l86_curl_infof(&s_s, data_va, "dbg %u", 5u);
    assert(s_write_count == 4u && s_debug_calls == 1u && s_debug_fn == 0x8100u && s_debug_data == data_va);
    assert(s_debug_type == 0 && s_debug_size == 5u && s_debug_userp == 0x8200u && strcmp(s_debug_text, "dbg 5") == 0);

    /* the 0x801-byte print buffer holds at most 0x800 characters */
    char *long_text = (char *)rome2_l82_mut_ptr(&s_ctx, zalloc(0x900u), 0x900u);
    assert(long_text != NULL);
    memset(long_text, 'A', 0x8ffu);
    long_text[0x8ffu] = '\0';
    rome2_l86_curl_infof(&s_s, data_va, "%s", long_text);
    assert(s_debug_calls == 2u && s_debug_size == 0x800u);

    s_g.on_debug = NULL;
    s_g.on_write = NULL;
    rome2_l86_curl_infof(&s_s, data_va, "unhooked");
    wr32(data_va + 0x19cu, 0u);
    rome2_l86_curl_infof(&s_s, data_va, "unhooked");
    assert(s_debug_calls == 2u && s_write_count == 4u);
}

static void test_read_and_recv(void) {
    setup();
    uint32_t data_va = open_easy();
    uint32_t conn_va = make_conn(data_va);
    uint32_t buf_va = zalloc(0x40u);
    int32_t n = 99;
    wr32(conn_va + 0x130u, 55u);
    wr32(conn_va + 0x134u, 66u);
    wr32(conn_va + 0x140u, 0xa000u);
    wr32(conn_va + 0x144u, 0xa001u);

    /* plain reads ask for min(requested, buffer_size or 0x4000) */
    s_recv_result = 5;
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 100u, &n) == ROME2_CURLE_OK && n == 5);
    assert(s_recv_fn == 0xa000u && s_recv_conn == conn_va && s_recv_num == 0u && s_recv_buf == buf_va && s_recv_len == 100u);
    assert(memcmp(str_at(buf_va), "rrrrr", 5u) == 0);
    assert(rome2_l86_curl_read(&s_s, conn_va, 66u, buf_va, 0x5000u, &n) == ROME2_CURLE_OK);
    assert(s_recv_fn == 0xa001u && s_recv_num == 1u && s_recv_len == 0x4000u);
    wr32(data_va + 0x2a0u, 0x200u);
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 0x300u, &n) == ROME2_CURLE_OK && s_recv_len == 0x200u);
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 0x200u, &n) == ROME2_CURLE_OK && s_recv_len == 0x200u);
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 0x1ffu, &n) == ROME2_CURLE_OK && s_recv_len == 0x1ffu);
    /* the size comparison is signed */
    s_recv_result = 0;
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 0x80000000u, &n) == ROME2_CURLE_OK && n == 0);
    assert(s_recv_len == 0x80000000u);

    /* a negative result returns the callback's code, or CURLE_RECV_ERROR when it sets none */
    s_recv_result = -1;
    s_recv_code = ROME2_CURLE_AGAIN;
    n = 99;
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 8u, &n) == ROME2_CURLE_AGAIN && n == 0);
    s_recv_code = 0;
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 8u, &n) == ROME2_CURLE_RECV_ERROR);
    s_s.on_conn_recv = NULL;
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 8u, &n) == ROME2_CURLE_RECV_ERROR && n == 0);
    s_s.on_conn_recv = on_conn_recv;

    /* pipelining serves unread master-buffer bytes first */
    uint32_t multi_va = zalloc(ROME2_CURL_MULTI_BYTES);
    uint32_t master_va = put_str("0123456789abcdef");
    wr32(data_va + 8u, multi_va);
    assert(rome2_l86_curl_multi_can_pipeline(&s_ctx, multi_va) == 0u);
    wr32(multi_va + 0x60u, 1u);
    assert(rome2_l86_curl_multi_can_pipeline(&s_ctx, multi_va) == 1u);
    wr32(conn_va + 0x290u, master_va);
    wr32(conn_va + 0x294u, 4u);
    wr32(conn_va + 0x298u, 10u);
    wr32(conn_va + 0x214u, 1u);
    s_recv_calls = 0u;
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 4u, &n) == ROME2_CURLE_OK && n == 4);
    assert(memcmp(str_at(buf_va), "4567", 4u) == 0 && rd32(conn_va + 0x294u) == 8u && rd32(conn_va + 0x214u) == 0u);
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 100u, &n) == ROME2_CURLE_OK && n == 2);
    assert(memcmp(str_at(buf_va), "89", 2u) == 0 && rd32(conn_va + 0x294u) == 10u && s_recv_calls == 0u);
    /* an empty master buffer is refilled from the socket and copied out */
    s_recv_result = 3;
    assert(rome2_l86_curl_read(&s_s, conn_va, 66u, buf_va, 0x5000u, &n) == ROME2_CURLE_OK && n == 3);
    assert(s_recv_calls == 1u && s_recv_buf == master_va && s_recv_len == 0x4000u && s_recv_num == 1u);
    assert(memcmp(str_at(buf_va), "rrr", 3u) == 0 && rd32(conn_va + 0x294u) == 3u && rd32(conn_va + 0x298u) == 3u);
    s_recv_result = 0;
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 9u, &n) == ROME2_CURLE_OK && n == 0);
    assert(s_recv_len == 9u && rd32(conn_va + 0x294u) == 0u && rd32(conn_va + 0x298u) == 0u);
    s_recv_result = -1;
    s_recv_code = ROME2_CURLE_AGAIN;
    assert(rome2_l86_curl_read(&s_s, conn_va, 55u, buf_va, 9u, &n) == ROME2_CURLE_AGAIN);
    wr32(data_va + 8u, 0u);

    /* curl_easy_recv */
    n = 99;
    assert(rome2_l86_curl_easy_recv(&s_s, 0u, buf_va, 8u, &n) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT && n == 99);
    assert(rome2_l86_curl_easy_recv(&s_s, data_va, buf_va, 8u, &n) == ROME2_CURLE_UNSUPPORTED_PROTOCOL && n == 99);
    assert(strcmp(str_at(data_va + 0x594u), "CONNECT_ONLY is required!") == 0);
    wr32(data_va + 0x358u, 1u);
    assert(rome2_l86_curl_easy_recv(&s_s, data_va, buf_va, 8u, &n) == ROME2_CURLE_UNSUPPORTED_PROTOCOL && n == 99);
    uint32_t connc_va = rome2_l86_curl_mk_connc(&s_ctx, 0, 4);
    wr32(rd32(connc_va) + 8u, conn_va);
    wr32(data_va + 0x57cu, connc_va);
    wr32(data_va + 0x588u, 2u);
    s_peek_result = 1;
    s_recv_result = 6;
    s_recv_calls = 0u;
    assert(rome2_l86_curl_easy_recv(&s_s, data_va, buf_va, 0x20u, &n) == ROME2_CURLE_OK && n == 6);
    assert(s_recv_calls == 1u && s_recv_conn == conn_va && s_recv_num == 0u && s_recv_buf == buf_va && s_recv_len == 0x20u);
    s_recv_result = -1;
    s_recv_code = ROME2_CURLE_AGAIN;
    n = 99;
    assert(rome2_l86_curl_easy_recv(&s_s, data_va, buf_va, 0x20u, &n) == ROME2_CURLE_AGAIN && n == 0);
}

static void test_multi_init(void) {
    setup();
    uint32_t multi_va = rome2_l86_curl_multi_init(&s_s);
    assert(multi_va != 0u && rd32(multi_va) == 0x000bab1eu);
    assert(rd32(multi_va + 4u) == multi_va + 4u && rd32(multi_va + 8u) == multi_va + 4u);
    uint32_t dns_va = rd32(multi_va + 0x54u);
    uint32_t sock_va = rd32(multi_va + 0x5cu);
    uint32_t connc_va = rd32(multi_va + 0x64u);
    uint32_t msg_va = rd32(multi_va + 0x48u);
    assert(dns_va != 0u && rd32(dns_va + 0x10u) == 7u && rd32(dns_va + 0xcu) == 0x10f13510u);
    assert(sock_va != 0u && rd32(sock_va + 0x10u) == 0x38fu);
    assert(rd32(sock_va + 4u) == 0x10f23070u && rd32(sock_va + 8u) == 0x10f23050u && rd32(sock_va + 0xcu) == 0x10f244f0u);
    assert(rd32(rd32(rd32(sock_va) + 0x38eu * 4u) + 8u) == 0x10f12780u);
    assert(connc_va != 0u && rd32(connc_va + 4u) == 10u);
    assert(msg_va != 0u && rd32(msg_va + 8u) == 0x100d6560u && rd32(msg_va + 0xcu) == 0u);
    for (uint32_t off = 0xcu; off < 0x80u; off += 4u) {
        if (off != 0x48u && off != 0x54u && off != 0x5cu && off != 0x64u) {
            assert(rd32(multi_va + off) == 0u);
        }
    }

    /* each failed stage releases what was built: sizes are the handle, DNS cache, socket hash and cache */
    const uint32_t multi_bytes = 0x80u;
    const uint32_t dns_bytes = 0x18u + 7u * 4u + 7u * 0x10u;
    const uint32_t sock_bytes = 0x18u + 0x38fu * 4u + 0x38fu * 0x10u;
    const uint32_t connc_bytes = 0xcu + 10u * 4u;
    uint32_t full = limit_arena(0u);
    assert(rome2_l86_curl_multi_init(&s_s) == 0u);
    s_ctx.arena_size = full;
    uint32_t frees = s_ctx.free_count;
    full = limit_arena(multi_bytes);
    assert(rome2_l86_curl_multi_init(&s_s) == 0u && s_ctx.free_count == frees + 1u);
    s_ctx.arena_size = full;
    frees = s_ctx.free_count;
    full = limit_arena(multi_bytes + dns_bytes + sock_bytes);
    assert(rome2_l86_curl_multi_init(&s_s) == 0u);
    assert(s_ctx.free_count == frees + (0x38fu + 2u) + (7u + 2u) + 1u);
    s_ctx.arena_size = full;
    frees = s_ctx.free_count;
    full = limit_arena(multi_bytes + dns_bytes + sock_bytes + connc_bytes);
    assert(rome2_l86_curl_multi_init(&s_s) == 0u);
    assert(s_ctx.free_count == frees + (0x38fu + 2u) + (7u + 2u) + 2u + 1u);
    s_ctx.arena_size = full;
}

static void test_getinfo(void) {
    setup();
    static const uint32_t longs[][2] = {
        {0x200002u, 0x86e4u}, {0x20000bu, 0x86f8u}, {0x20000cu, 0x86fcu}, {0x20000du, 0x025cu},
        {0x20000eu, 0x86f0u}, {0x200014u, 0x0154u}, {0x200016u, 0x86e8u}, {0x200017u, 0x8704u},
        {0x200018u, 0x8700u}, {0x200019u, 0x85c4u}, {0x20001au, 0x8708u}, {0x200023u, 0x86f4u},
        {0x200025u, 0x86b0u}, {0x200026u, 0x86b4u}, {0x200027u, 0x86b8u}, {0x200028u, 0x8744u},
        {0x20002au, 0x8778u}
    };
    static const uint32_t strings[][2] = {
        {0x100001u, 0x0450u}, {0x100012u, 0x870cu}, {0x100015u, 0x02a4u}, {0x10001eu, 0x8670u},
        {0x10001fu, 0x8710u}, {0x100024u, 0x03fcu}
    };
    static const uint32_t doubles[][2] = {
        {0x300003u, 0x04b0u}, {0x300004u, 0x04c8u}, {0x300005u, 0x04d0u}, {0x300006u, 0x04e0u},
        {0x300011u, 0x04e8u}, {0x300013u, 0x04f0u}, {0x300021u, 0x04d8u}
    };
    static const uint32_t counts[][2] = {
        {0x300007u, 0x0490u}, {0x300008u, 0x0488u}, {0x300009u, 0x04b8u}, {0x30000au, 0x04c0u}
    };
    static const uint32_t rejected[] = {
        0x200001u, 0x200003u, 0x20000au, 0x20001bu, 0x200029u, 0x20002bu, 0x100000u, 0x100002u, 0x100021u,
        0x10002au, 0x300002u, 0x30000bu, 0x300012u, 0x300022u, 0x40001au, 0x40001du, 0x400021u, 0x400023u,
        0x000001u, 0x500001u, 0xf00001u
    };
    uint32_t data_va = open_easy();
    uint32_t param_va = zalloc(8u);

    assert(rome2_l86_curl_getinfo(&s_s, 0u, 0x200002u, param_va) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x200002u, 0u) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x100001u, 0u) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x300003u, 0u) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x40001cu, 0u) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT);
    for (uint32_t i = 0u; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        wr32(param_va, 0x5a5a5a5au);
        assert(rome2_l86_curl_getinfo(&s_s, data_va, rejected[i], param_va) == ROME2_CURLE_BAD_FUNCTION_ARGUMENT);
        assert(rd32(param_va) == 0x5a5a5a5au);
    }

    for (uint32_t i = 0u; i < sizeof(longs) / sizeof(longs[0]); ++i) {
        wr32(data_va + longs[i][1], 0x1000u + i);
    }
    for (uint32_t i = 0u; i < sizeof(longs) / sizeof(longs[0]); ++i) {
        assert(rome2_l86_curl_easy_getinfo(&s_s, data_va, longs[i][0], param_va) == ROME2_CURLE_OK);
        assert(rd32(param_va) == 0x1000u + i);
    }
    /* CURLINFO_LASTSOCKET: no connection reports -1, a live one its socket */
    assert(rome2_l86_curl_getinfo(&s_s, data_va, ROME2_CURLINFO_LASTSOCKET, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) == 0xffffffffu);
    uint32_t conn_va = make_conn(data_va);
    uint32_t connc_va = rome2_l86_curl_mk_connc(&s_ctx, 0, 2);
    wr32(conn_va + 0x130u, 77u);
    wr32(rd32(connc_va), conn_va);
    wr32(data_va + 0x57cu, connc_va);
    wr32(data_va + 0x588u, 0u);
    s_peek_result = 1;
    assert(rome2_l86_curl_getinfo(&s_s, data_va, ROME2_CURLINFO_LASTSOCKET, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) == 77u);

    /* strings: a missing effective URL reports the image's empty string */
    assert(rome2_l86_curl_getinfo(&s_s, data_va, ROME2_CURLINFO_EFFECTIVE_URL, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) == 0x1173dad0u);
    for (uint32_t i = 0u; i < sizeof(strings) / sizeof(strings[0]); ++i) {
        wr32(data_va + strings[i][1], 0x2000u + i);
        assert(rome2_l86_curl_getinfo(&s_s, data_va, strings[i][0], param_va) == ROME2_CURLE_OK);
        assert(rd32(param_va) == 0x2000u + i);
    }
    assert(rome2_l86_curl_getinfo(&s_s, data_va, ROME2_CURLINFO_PRIMARY_IP, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) == data_va + 0x8714u);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, ROME2_CURLINFO_LOCAL_IP, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) == data_va + 0x8748u);

    /* doubles: stored values are copied, 64-bit counts are converted */
    for (uint32_t i = 0u; i < sizeof(doubles) / sizeof(doubles[0]); ++i) {
        wr_f64(data_va + doubles[i][1], 1.5 + (double)i);
        assert(rome2_l86_curl_getinfo(&s_s, data_va, doubles[i][0], param_va) == ROME2_CURLE_OK);
        assert(rd_f64(param_va) == 1.5 + (double)i);
    }
    for (uint32_t i = 0u; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        wr32(data_va + counts[i][1], 5u + i);
        wr32(data_va + counts[i][1] + 4u, 1u);
        assert(rome2_l86_curl_getinfo(&s_s, data_va, counts[i][0], param_va) == ROME2_CURLE_OK);
        assert(rd_f64(param_va) == 4294967301.0 + (double)i);
    }
    /* content lengths are -1 until the progress flags mark them known */
    wr32(data_va + 0x478u, 1234u);
    wr32(data_va + 0x480u, 0x80000000u);
    wr32(data_va + 0x4a8u, 0u);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x30000fu, param_va) == ROME2_CURLE_OK && rd_f64(param_va) == -1.0);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x300010u, param_va) == ROME2_CURLE_OK && rd_f64(param_va) == -1.0);
    wr32(data_va + 0x4a8u, 0x40u);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x30000fu, param_va) == ROME2_CURLE_OK && rd_f64(param_va) == 1234.0);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x300010u, param_va) == ROME2_CURLE_OK && rd_f64(param_va) == -1.0);
    wr32(data_va + 0x4a8u, 0x20u);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x30000fu, param_va) == ROME2_CURLE_OK && rd_f64(param_va) == -1.0);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, 0x300010u, param_va) == ROME2_CURLE_OK);
    assert(rd_f64(param_va) == 2147483648.0);

    /* slists */
    uint32_t stubs = s_g.resolver_stub_calls;
    wr32(param_va, 0x5a5a5a5au);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, ROME2_CURLINFO_SSL_ENGINES, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) == 0u && s_g.resolver_stub_calls == stubs + 1u);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, ROME2_CURLINFO_CERTINFO, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) == data_va + 0x877cu);
    wr32(param_va, 0x5a5a5a5au);
    assert(rome2_l86_curl_getinfo(&s_s, data_va, ROME2_CURLINFO_COOKIELIST, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) == 0u);
    uint32_t jar_va = make_jar(1u, 0u);
    assert(add_header(0u, jar_va, "k=v", NULL, NULL) != 0u);
    wr32(data_va + 0x468u, jar_va);
    assert(rome2_l86_curl_easy_getinfo(&s_s, data_va, ROME2_CURLINFO_COOKIELIST, param_va) == ROME2_CURLE_OK);
    assert(rd32(param_va) != 0u && strcmp(str_at(rd32(rd32(param_va))), "unknown\tFALSE\t/\tFALSE\t0\tk\tv") == 0);
}

static void test_cookie_header(void) {
    setup();
    uint32_t data_va = open_easy();
    uint32_t c_va = make_jar(1u, 0u);

    /* every attribute */
    uint32_t co_va = add_header(
        data_va, c_va, "  name=value; path=/p; domain=.example.com; secure; httponly; version=1", "www.example.com", NULL);
    assert(co_va != 0u && rd32(c_va) == co_va && rd32(c_va + 0xcu) == 1u && rd32(co_va) == 0u);
    assert(cookie_str_is(co_va, 4u, "name") == 1u && cookie_str_is(co_va, 8u, "value") == 1u);
    assert(cookie_str_is(co_va, 0xcu, "/p") == 1u && cookie_str_is(co_va, 0x10u, "example.com") == 1u);
    assert(cookie_str_is(co_va, 0x28u, "1") == 1u && rd32(co_va + 0x24u) == 1u);
    assert(rd32(co_va + 0x30u) == 1u && rd32(co_va + 0x38u) == 1u && rd32(co_va + 0x34u) == 1u);
    assert(rd32(co_va + 0x18u) == 0u && rd32(co_va + 0x1cu) == 0u && rd32(co_va + 0x20u) == 0u);

    /* the request host and path supply a missing domain and path */
    c_va = make_jar(1u, 0u);
    co_va = add_header(data_va, c_va, "a=b", "host.example.com", "/dir/page?x=/y");
    assert(co_va != 0u && cookie_str_is(co_va, 0x10u, "host.example.com") == 1u && rd32(co_va + 0x24u) == 0u);
    assert(cookie_str_is(co_va, 0xcu, "/dir/") == 1u);
    co_va = add_header(data_va, make_jar(1u, 0u), "a=b", NULL, "/a/b/c");
    assert(co_va != 0u && cookie_str_is(co_va, 0xcu, "/a/b/") == 1u && rd32(co_va + 0x10u) == 0u);
    co_va = add_header(data_va, make_jar(1u, 0u), "a=b", NULL, "nopath?q=/");
    assert(co_va != 0u && rd32(co_va + 0xcu) == 0u);

    /* blanks around a value are trimmed; a blank before '=' leaves the value empty */
    co_va = add_header(data_va, make_jar(1u, 0u), "n=  v w \t; x=", NULL, NULL);
    assert(co_va != 0u && cookie_str_is(co_va, 4u, "n") == 1u && cookie_str_is(co_va, 8u, "v w") == 1u);
    co_va = add_header(data_va, make_jar(1u, 0u), "n = v", NULL, NULL);
    assert(co_va != 0u && cookie_str_is(co_va, 4u, "n") == 1u && cookie_str_is(co_va, 8u, "") == 1u);
    co_va = add_header(data_va, make_jar(1u, 0u), "x=; secure=; HttpOnly=; other", NULL, NULL);
    assert(co_va != 0u && cookie_str_is(co_va, 4u, "x") == 1u && cookie_str_is(co_va, 8u, "") == 1u);
    assert(rd32(co_va + 0x30u) == 1u && rd32(co_va + 0x38u) == 1u);
    /* a repeated attribute keeps the last value and releases the first */
    uint32_t frees = s_ctx.free_count;
    co_va = add_header(data_va, make_jar(1u, 0u), "a=b; path=/one; path=/two", NULL, NULL);
    assert(co_va != 0u && cookie_str_is(co_va, 0xcu, "/two") == 1u && s_ctx.free_count == frees + 2u);

    /* max-age is added to the current time as a 32-bit value; expires goes through curl_getdate */
    co_va = add_header(data_va, make_jar(1u, 0u), "a=b; max-age=\"100\"", NULL, NULL);
    assert(co_va != 0u && rd32(co_va + 0x18u) == 1100u && rd32(co_va + 0x1cu) == 0u);
    assert(cookie_str_is(co_va, 0x2cu, "\"100\"") == 1u);
    co_va = add_header(data_va, make_jar(1u, 0u), "a=b; Max-Age=-2000", NULL, NULL);
    assert(co_va != 0u && rd32(co_va + 0x18u) == 0xfffffc18u && rd32(co_va + 0x1cu) == 0xffffffffu);
    co_va = add_header(data_va, make_jar(1u, 0u), "a=b; expires=Sun, 06 Nov 1994 08:49:37 GMT", NULL, NULL);
    assert(co_va != 0u && rd32(co_va + 0x18u) == 784111777u && rd32(co_va + 0x1cu) == 0u);
    assert(cookie_str_is(co_va, 0x20u, "Sun, 06 Nov 1994 08:49:37 GMT") == 1u);
    co_va = add_header(data_va, make_jar(1u, 0u), "a=b; expires=Thu, 01 Jan 1970 00:00:00 GMT", NULL, NULL);
    assert(co_va != 0u && rd32(co_va + 0x18u) == 1u && rd32(co_va + 0x1cu) == 0u);
    co_va = add_header(data_va, make_jar(1u, 0u), "a=b; expires=never", NULL, NULL);
    assert(co_va != 0u && rd32(co_va + 0x18u) == 0u && rd32(co_va + 0x1cu) == 0u);

    /* rejected lines release everything they allocated */
    c_va = make_jar(1u, 0u);
    wr32(data_va + 0x31cu, 1u);
    uint32_t used_frees = s_ctx.free_count;
    uint32_t used_allocs = s_ctx.alloc_count;
    assert(add_header(data_va, c_va, "a=b; domain=com", NULL, NULL) == 0u);
    assert(s_write_count == 2u && strcmp(s_write_text[1], "skipped cookie with illegal dotcount domain: com\n") == 0);
    assert(add_header(data_va, c_va, "a=b; domain=.other.org", "www.example.com", NULL) == 0u);
    assert(s_write_count == 4u);
    assert(strcmp(s_write_text[3], "skipped cookie with bad tailmatch domain: other.org\n") == 0);
    assert(add_header(data_va, c_va, "a=b; domain=a.long.example.com", "example.com", NULL) == 0u);
    assert(add_header(data_va, c_va, "; path=/", NULL, NULL) == 0u);
    assert(add_header(data_va, c_va, "", NULL, NULL) == 0u);
    assert(rd32(c_va) == 0u && rd32(c_va + 0xcu) == 0u);
    /* the seven line and host strings stay; every other allocation was released */
    assert(s_ctx.alloc_count - used_allocs - 7u == s_ctx.free_count - used_frees);
    wr32(data_va + 0x31cu, 0u);

    /* session cookies are dropped while a file is loaded with newsession set */
    c_va = make_jar(0u, 1u);
    assert(add_header(data_va, c_va, "a=b", NULL, NULL) == 0u && rd32(c_va + 0xcu) == 0u);
    co_va = add_header(data_va, c_va, "a=b; max-age=5", NULL, NULL);
    assert(co_va != 0u && rd32(co_va + 0x34u) == 0u && rd32(c_va + 0xcu) == 1u);

    /* out of memory at the record and at the value buffer */
    c_va = make_jar(1u, 0u);
    uint32_t line_va = put_str("a=b");
    uint32_t full = limit_arena(0u);
    assert(rome2_l86_curl_cookie_add(&s_s, data_va, c_va, 1u, line_va, 0u, 0u) == 0u);
    s_ctx.arena_size = full;
    frees = s_ctx.free_count;
    full = limit_arena(0x40u);
    assert(rome2_l86_curl_cookie_add(&s_s, data_va, c_va, 1u, line_va, 0u, 0u) == 0u);
    assert(s_ctx.free_count == frees + 1u);
    s_ctx.arena_size = full;
    /* the name is stored but the value cannot be: the cookie is discarded */
    frees = s_ctx.free_count;
    full = limit_arena(0x40u + 5000u + 4u);
    assert(rome2_l86_curl_cookie_add(&s_s, data_va, c_va, 1u, line_va, 0u, 0u) == 0u);
    assert(s_ctx.free_count == frees + 3u && rd32(c_va) == 0u);
    s_ctx.arena_size = full;

    /* freecookie releases the seven strings and the record */
    co_va = add_header(
        data_va, c_va, "a=b; path=/; domain=x.org; version=1; max-age=1; expires=never", NULL, NULL);
    assert(co_va != 0u);
    frees = s_ctx.free_count;
    rome2_l86_freecookie(&s_ctx, co_va);
    assert(s_ctx.free_count == frees + 8u);
    uint32_t bare_va = zalloc(0x40u);
    frees = s_ctx.free_count;
    rome2_l86_freecookie(&s_ctx, bare_va);
    assert(s_ctx.free_count == frees + 1u);
}

static void test_cookie_netscape(void) {
    setup();
    uint32_t c_va = make_jar(1u, 0u);
    uint32_t line_va = put_str(".example.com\tTRUE\t/\tFALSE\t1234567890\tname\tvalue\r\n");
    uint32_t co_va = rome2_l86_curl_cookie_add(&s_s, 0u, c_va, 0u, line_va, 0u, 0u);
    assert(co_va != 0u && rd32(c_va) == co_va && rd32(c_va + 0xcu) == 1u);
    assert(cookie_str_is(co_va, 0x10u, "example.com") == 1u && rd32(co_va + 0x24u) == 1u);
    assert(cookie_str_is(co_va, 0xcu, "/") == 1u && rd32(co_va + 0x30u) == 0u);
    assert(rd32(co_va + 0x18u) == 1234567890u && rd32(co_va + 0x1cu) == 0u);
    assert(cookie_str_is(co_va, 4u, "name") == 1u && cookie_str_is(co_va, 8u, "value") == 1u);
    assert(rd32(co_va + 0x38u) == 0u && rd32(co_va + 0x34u) == 1u);
    /* the caller's line was cut at its first tab */
    assert(strcmp(str_at(line_va), ".example.com") == 0);

    co_va = add_netscape(c_va, "#HttpOnly_host.org\tFALSE\t/only\tTRUE\t4294967296\tn\tv");
    assert(co_va != 0u && rd32(co_va + 0x38u) == 1u && cookie_str_is(co_va, 0x10u, "host.org") == 1u);
    assert(rd32(co_va + 0x24u) == 0u && rd32(co_va + 0x30u) == 1u);
    assert(rd32(co_va + 0x18u) == 0u && rd32(co_va + 0x1cu) == 1u);

    /* a boolean in the path column means the path was left out */
    co_va = add_netscape(c_va, "nopath.org\tFALSE\tTRUE\t7\tn\tv");
    assert(co_va != 0u && cookie_str_is(co_va, 0xcu, "/") == 1u && rd32(co_va + 0x30u) == 1u);
    assert(rd32(co_va + 0x18u) == 7u && cookie_str_is(co_va, 4u, "n") == 1u && cookie_str_is(co_va, 8u, "v") == 1u);
    co_va = add_netscape(c_va, "nopath2.org\tFALSE\tFALSE\t7\tn\tv");
    assert(co_va != 0u && cookie_str_is(co_va, 0xcu, "/") == 1u && rd32(co_va + 0x30u) == 0u);
    /* a missing value column is an empty value */
    co_va = add_netscape(c_va, "blank.org\tFALSE\t/\tFALSE\t5\tn");
    assert(co_va != 0u && cookie_str_is(co_va, 8u, "") == 1u);
    assert(rd32(c_va + 0xcu) == 5u);

    /* rejected lines */
    uint32_t frees = s_ctx.free_count;
    uint32_t allocs = s_ctx.alloc_count;
    assert(add_netscape(c_va, "# a comment") == 0u);
    assert(add_netscape(c_va, "#HttpOnly_#still a comment") == 0u);
    assert(add_netscape(c_va, "http://not-a-cookie\tx") == 0u);
    assert(add_netscape(c_va, "") == 0u);
    assert(add_netscape(c_va, "\r\n") == 0u);
    assert(add_netscape(c_va, "few.org\tFALSE\t/") == 0u);
    assert(add_netscape(c_va, "many.org\tFALSE\t/\tFALSE\t5\tn\tv\textra") == 0u);
    assert(rd32(c_va + 0xcu) == 5u);
    assert(s_ctx.alloc_count - allocs - 7u == s_ctx.free_count - frees); /* only the seven lines remain */

    /* a session cookie read from a file is dropped under newsession and kept otherwise */
    c_va = make_jar(0u, 1u);
    assert(add_netscape(c_va, "s.org\tFALSE\t/\tFALSE\t0\tn\tv") == 0u && rd32(c_va) == 0u);
    co_va = add_netscape(c_va, "s.org\tFALSE\t/\tFALSE\t9\tn\tv");
    assert(co_va != 0u && rd32(co_va + 0x34u) == 0u);
    c_va = make_jar(0u, 0u);
    assert(add_netscape(c_va, "s.org\tFALSE\t/\tFALSE\t0\tn\tv") != 0u);

    /* out of memory while a field is copied discards the cookie */
    c_va = make_jar(1u, 0u);
    line_va = put_str("oom.org\tFALSE\t/\tFALSE\t5\tn\tv");
    frees = s_ctx.free_count;
    uint32_t full = limit_arena(0x40u + 8u);
    assert(rome2_l86_curl_cookie_add(&s_s, 0u, c_va, 0u, line_va, 0u, 0u) == 0u);
    assert(s_ctx.free_count == frees + 2u && rd32(c_va) == 0u);
    s_ctx.arena_size = full;
}

static void test_cookie_replace(void) {
    setup();
    uint32_t data_va = open_easy();
    uint32_t c_va = make_jar(1u, 0u);
    wr32(data_va + 0x31cu, 1u);

    uint32_t first_va = add_header(data_va, c_va, "a=1; path=/x; domain=.ex.com", NULL, NULL);
    assert(first_va != 0u && s_write_count == 2u);
    assert(strcmp(s_write_text[1], "Added cookie a=\"1\" for domain ex.com, path /x, expire 0\n") == 0);

    /* the same name, domain and path, compared without case, replaces in place */
    uint32_t frees = s_ctx.free_count;
    uint32_t again_va = add_header(data_va, c_va, "A=2; path=/X; domain=ex.com; max-age=5", NULL, NULL);
    assert(again_va == first_va && rd32(c_va) == first_va && rd32(first_va) == 0u && rd32(c_va + 0xcu) == 2u);
    assert(cookie_str_is(first_va, 4u, "A") == 1u && cookie_str_is(first_va, 8u, "2") == 1u);
    assert(cookie_str_is(first_va, 0xcu, "/X") == 1u && rd32(first_va + 0x18u) == 1005u);
    assert(s_ctx.free_count == frees + 6u); /* four old strings, the new record and the value buffer */
    assert(s_write_count == 4u);
    assert(strcmp(s_write_text[3], "Replaced cookie A=\"2\" for domain ex.com, path /X, expire 1005\n") == 0);

    /* another path, another domain or no domain is a different cookie, appended at the tail */
    uint32_t second_va = add_header(data_va, c_va, "a=3; path=/y; domain=ex.com", NULL, NULL);
    assert(second_va != 0u && second_va != first_va && rd32(first_va) == second_va && rd32(second_va) == 0u);
    uint32_t third_va = add_header(data_va, c_va, "a=4; path=/x; domain=other.com", NULL, NULL);
    assert(third_va != 0u && rd32(second_va) == third_va);
    uint32_t fourth_va = add_header(data_va, c_va, "a=5", NULL, NULL);
    assert(fourth_va != 0u && rd32(third_va) == fourth_va && rd32(c_va + 0xcu) == 5u);
    assert(strcmp(s_write_text[9], "Added cookie a=\"5\" for domain (nil), path (nil), expire 0\n") == 0);
    /* one with neither domain nor path matches only its like */
    assert(add_header(data_va, c_va, "a=6", NULL, NULL) == fourth_va && cookie_str_is(fourth_va, 8u, "6") == 1u);
    assert(add_header(data_va, c_va, "a=7; path=/x", NULL, NULL) != fourth_va);
    /* replacing the head leaves the rest of the list linked */
    assert(add_header(data_va, c_va, "a=8; path=/x; domain=ex.com", NULL, NULL) == first_va);
    assert(rd32(first_va) == second_va && rd32(second_va) == third_va && rd32(c_va + 0xcu) == 8u);

    /* a cookie read from a file never replaces a live one, but a live one replaces a file cookie */
    wr32(c_va + 8u, 0u);
    assert(add_netscape(c_va, "ex.com\tTRUE\t/x\tFALSE\t99\ta\tfile") == 0u);
    assert(cookie_str_is(first_va, 8u, "8") == 1u && rd32(c_va + 0xcu) == 8u);
    uint32_t file_va = add_netscape(c_va, "file.org\tTRUE\t/\tFALSE\t99\tf\told");
    assert(file_va != 0u && rd32(file_va + 0x34u) == 0u && rd32(c_va + 0xcu) == 9u);
    wr32(c_va + 8u, 1u);
    assert(add_netscape(c_va, "file.org\tTRUE\t/\tFALSE\t100\tf\tnew") == file_va);
    assert(cookie_str_is(file_va, 8u, "new") == 1u && rd32(file_va + 0x34u) == 1u && rd32(file_va + 0x18u) == 100u);
}

static void test_cookie_init_and_list(void) {
    setup();
    uint32_t data_va = open_easy();

    /* no file: a fresh jar named "none" */
    uint32_t c_va = rome2_l86_curl_cookie_init(&s_s, data_va, 0u, 0u, 1u);
    assert(c_va != 0u && strcmp(str_at(rd32(c_va + 4u)), "none") == 0);
    assert(rd32(c_va) == 0u && rd32(c_va + 8u) == 1u && rd32(c_va + 0xcu) == 0u && rd32(c_va + 0x10u) == 1u);
    assert(s_fopen_calls == 0u);
    /* an existing jar is reused and keeps its name */
    wr32(c_va + 8u, 0u);
    assert(rome2_l86_curl_cookie_init(&s_s, data_va, put_str(""), c_va, 0u) == c_va);
    assert(strcmp(str_at(rd32(c_va + 4u)), "none") == 0 && rd32(c_va + 8u) == 1u && rd32(c_va + 0x10u) == 0u);
    assert(s_fopen_calls == 0u);
    /* a file that cannot be opened leaves the jar empty */
    c_va = rome2_l86_curl_cookie_init(&s_s, data_va, put_str("missing.txt"), 0u, 0u);
    assert(c_va != 0u && s_fopen_calls == 1u && strcmp(s_fopen_path[0], "missing.txt") == 0);
    assert(strcmp(s_fopen_mode[0], "r") == 0 && strcmp(str_at(rd32(c_va + 4u)), "missing.txt") == 0);
    assert(rd32(c_va) == 0u && rd32(c_va + 8u) == 1u && s_fclose_calls == 0u && s_s.lock_file_calls == 0u);

    /* Netscape lines, a Set-Cookie header line, a comment and a blank line */
    static const char file_text[] =
        "# Netscape HTTP Cookie File\n"
        ".example.com\tTRUE\t/\tFALSE\t2000000000\tsid\tabc\n"
        "Set-Cookie: \thdr=1; domain=example.com; path=/h\n"
        "\n"
        "#HttpOnly_host.example.com\tFALSE\t/only\tTRUE\t0\tsess\tx";
    uint32_t stream_va = make_stream(file_text);
    s_fopen_results[1] = stream_va;
    c_va = rome2_l86_curl_cookie_init(&s_s, data_va, put_str("cookies.txt"), 0u, 0u);
    assert(c_va != 0u && s_fopen_calls == 2u && strcmp(s_fopen_path[1], "cookies.txt") == 0);
    assert(s_fclose_calls == 1u && s_fclose_stream == stream_va);
    assert(s_s.lock_file_calls == 6u && s_s.unlock_file_calls == 6u);
    assert(rd32(c_va + 8u) == 1u && rd32(c_va + 0xcu) == 3u);
    uint32_t sid_va = rd32(c_va);
    uint32_t hdr_va = rd32(sid_va);
    uint32_t sess_va = rd32(hdr_va);
    assert(sess_va != 0u && rd32(sess_va) == 0u);
    assert(cookie_str_is(sid_va, 4u, "sid") == 1u && rd32(sid_va + 0x18u) == 2000000000u && rd32(sid_va + 0x34u) == 0u);
    assert(cookie_str_is(hdr_va, 4u, "hdr") == 1u && cookie_str_is(hdr_va, 0xcu, "/h") == 1u);
    assert(cookie_str_is(hdr_va, 0x10u, "example.com") == 1u && rd32(hdr_va + 0x34u) == 0u);
    assert(cookie_str_is(sess_va, 4u, "sess") == 1u && rd32(sess_va + 0x38u) == 1u);

    /* Curl_cookie_list writes one Netscape line per cookie */
    wr32(data_va + 0x468u, c_va);
    uint32_t list_va = rome2_l86_curl_cookie_list(&s_s, data_va);
    assert(list_va != 0u);
    assert(strcmp(str_at(rd32(list_va)), ".example.com\tTRUE\t/\tFALSE\t2000000000\tsid\tabc") == 0);
    list_va = rd32(list_va + 4u);
    assert(strcmp(str_at(rd32(list_va)), ".example.com\tTRUE\t/h\tFALSE\t0\thdr\t1") == 0);
    list_va = rd32(list_va + 4u);
    assert(strcmp(str_at(rd32(list_va)), "#HttpOnly_host.example.com\tFALSE\t/only\tTRUE\t0\tsess\tx") == 0);
    assert(rd32(list_va + 4u) == 0u);
    /* a 64-bit expiry and a stored leading dot */
    wr32(sid_va + 0x1cu, 1u);
    wr32(sid_va + 0x18u, 2u);
    wr32(rd32(sid_va + 0x10u), 0x6178652eu); /* ".exa": the tail-match dot is not doubled */
    list_va = rome2_l86_curl_cookie_list(&s_s, data_va);
    assert(list_va != 0u && strcmp(str_at(rd32(list_va)), ".exaple.com\tTRUE\t/\tFALSE\t4294967298\tsid\tabc") == 0);

    /* the list fails as a whole when memory runs out */
    uint32_t frees = s_ctx.free_count;
    uint32_t full = limit_arena(0x80u);
    assert(rome2_l86_curl_cookie_list(&s_s, data_va) == 0u && s_ctx.free_count > frees);
    s_ctx.arena_size = full;
    /* no jar, an empty jar, and a count with no records */
    wr32(data_va + 0x468u, 0u);
    assert(rome2_l86_curl_cookie_list(&s_s, data_va) == 0u);
    uint32_t empty_va = make_jar(1u, 0u);
    wr32(data_va + 0x468u, empty_va);
    assert(rome2_l86_curl_cookie_list(&s_s, data_va) == 0u);
    wr32(empty_va + 0xcu, 2u);
    assert(rome2_l86_curl_cookie_list(&s_s, data_va) == 0u);

    /* newsession drops the two session cookies; "-" reads stdin and leaves it open */
    s_s.stdin_va = make_stream(file_text);
    uint32_t closes = s_fclose_calls;
    uint32_t opens = s_fopen_calls;
    c_va = rome2_l86_curl_cookie_init(&s_s, data_va, put_str("-"), 0u, 1u);
    assert(c_va != 0u && rd32(c_va + 0xcu) == 1u && cookie_str_is(rd32(c_va), 4u, "sid") == 1u);
    assert(s_fclose_calls == closes && s_fopen_calls == opens && rd32(c_va + 0x10u) == 1u);

    /* out of memory: no jar at all; with a jar but no line buffer the file is still closed */
    uint32_t file_va = put_str("cookies.txt");
    full = limit_arena(0u);
    assert(rome2_l86_curl_cookie_init(&s_s, data_va, file_va, 0u, 0u) == 0u);
    s_ctx.arena_size = full;
    s_fopen_results[s_fopen_calls] = make_stream(file_text);
    uint32_t locks = s_s.lock_file_calls;
    closes = s_fclose_calls;
    full = limit_arena(0x14u + 0xcu);
    c_va = rome2_l86_curl_cookie_init(&s_s, data_va, file_va, 0u, 0u);
    s_ctx.arena_size = full;
    assert(c_va != 0u && rd32(c_va + 8u) == 1u && rd32(c_va) == 0u);
    assert(s_s.lock_file_calls == locks && s_fclose_calls == closes + 1u);
    /* the unchecked file-name copy may fail and leave the name NULL */
    full = limit_arena(0x14u);
    c_va = rome2_l86_curl_cookie_init(&s_s, data_va, 0u, 0u, 0u);
    s_ctx.arena_size = full;
    assert(c_va != 0u && rd32(c_va + 4u) == 0u && rd32(c_va + 8u) == 1u);
}

static void test_share_setopt(void) {
    setup();
    uint32_t share_va = rome2_l82_curl_share_init(&s_ctx);
    assert(share_va != 0u && rd32(share_va) == 2u);

    /* a share in use rejects every option */
    wr32(share_va + 4u, 1u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 3u) == ROME2_CURLSHE_IN_USE);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, 0, 0u) == ROME2_CURLSHE_IN_USE && rd32(share_va) == 2u);
    wr32(share_va + 4u, 0u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, 0, 0u) == ROME2_CURLSHE_BAD_OPTION);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, 6, 0u) == ROME2_CURLSHE_BAD_OPTION);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, -1, 0u) == ROME2_CURLSHE_BAD_OPTION && rd32(share_va) == 2u);

    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 3u) == ROME2_CURLSHE_OK);
    uint32_t dns_va = rd32(share_va + 0x14u);
    assert(rd32(share_va) == 0xau && dns_va != 0u && rd32(dns_va + 0x10u) == 7u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 3u) == ROME2_CURLSHE_OK);
    assert(rd32(share_va + 0x14u) == dns_va);

    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 2u) == ROME2_CURLSHE_OK);
    uint32_t jar_va = rd32(share_va + 0x18u);
    assert(rd32(share_va) == 0xeu && jar_va != 0u && strcmp(str_at(rd32(jar_va + 4u)), "none") == 0);
    assert(rd32(jar_va + 8u) == 1u && rd32(jar_va + 0x10u) == 1u);

    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 4u) == ROME2_CURLSHE_OK);
    uint32_t sessions_va = rd32(share_va + 0x1cu);
    assert(rd32(share_va) == 0x1eu && sessions_va != 0u && rd32(share_va + 0x20u) == 8u && rd32(share_va + 0x24u) == 0u);
    assert(rome2_l82_const_ptr(&s_ctx, sessions_va, 8u * 0x54u) != NULL && rd32(sessions_va + 8u * 0x54u - 4u) == 0u);
    wr32(share_va + 0x24u, 9u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 4u) == ROME2_CURLSHE_OK);
    assert(rd32(share_va + 0x1cu) == sessions_va && rd32(share_va + 0x24u) == 9u);

    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 5u) == ROME2_CURLSHE_OK);
    assert(rd32(share_va) == 0x3eu);
    /* an unknown data type is rejected after its specifier bit was already changed */
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 6u) == ROME2_CURLSHE_BAD_OPTION);
    assert(rd32(share_va) == 0x7eu);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_UNSHARE, 1u) == ROME2_CURLSHE_BAD_OPTION);
    assert(rd32(share_va) == 0x7cu);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 32u) == ROME2_CURLSHE_BAD_OPTION);
    assert(rd32(share_va) == 0x7du); /* the bit index wraps at 32 */

    uint32_t frees = s_ctx.free_count;
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_UNSHARE, 3u) == ROME2_CURLSHE_OK);
    assert(rd32(share_va + 0x14u) == 0u && rd32(share_va) == 0x75u && s_ctx.free_count == frees + 9u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_UNSHARE, 2u) == ROME2_CURLSHE_OK);
    assert(rd32(share_va + 0x18u) == 0u && rd32(share_va) == 0x71u && s_ctx.free_count == frees + 11u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_UNSHARE, 4u) == ROME2_CURLSHE_OK);
    assert(rd32(share_va + 0x1cu) == 0u && rd32(share_va) == 0x61u && s_ctx.free_count == frees + 12u);
    assert(rd32(share_va + 0x20u) == 8u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_UNSHARE, 5u) == ROME2_CURLSHE_OK);
    /* unsharing what is not shared changes nothing else */
    for (uint32_t type = 2u; type <= 5u; ++type) {
        assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_UNSHARE, type) == ROME2_CURLSHE_OK);
    }
    assert(rd32(share_va) == 0x41u && s_ctx.free_count == frees + 12u);

    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_LOCKFUNC, 0x8001u) == ROME2_CURLSHE_OK);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_UNLOCKFUNC, 0x8002u) == ROME2_CURLSHE_OK);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_USERDATA, 0x8003u) == ROME2_CURLSHE_OK);
    assert(rd32(share_va + 8u) == 0x8001u && rd32(share_va + 0xcu) == 0x8002u && rd32(share_va + 0x10u) == 0x8003u);

    /* out of memory still leaves the specifier bit set */
    wr32(share_va, 0u);
    uint32_t full = limit_arena(0u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 3u) == ROME2_CURLSHE_NOMEM);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 2u) == ROME2_CURLSHE_NOMEM);
    wr32(share_va + 0x20u, 0u);
    wr32(share_va + 0x24u, 7u);
    assert(rome2_l86_curl_share_setopt(&s_s, share_va, ROME2_CURLSHOPT_SHARE, 4u) == ROME2_CURLSHE_NOMEM);
    s_ctx.arena_size = full;
    assert(rd32(share_va) == 0x1cu && rd32(share_va + 0x14u) == 0u && rd32(share_va + 0x18u) == 0u);
    assert(rd32(share_va + 0x1cu) == 0u && rd32(share_va + 0x20u) == 8u && rd32(share_va + 0x24u) == 0u);
}

static void test_form_primitives(void) {
    setup();
    char text[512];
    uint32_t nodes = 0u;
    uint32_t form_va = 0u;
    int64_t size = 0;

    assert(rome2_l86_add_form_dataf(&s_ctx, &form_va, &size, "--%s\r\n", "bound") == ROME2_CURLE_OK);
    uint32_t first_va = form_va;
    assert(first_va != 0u && rd32(first_va) == 0u && rd32(first_va + 4u) == 0u && rd32(first_va + 0xcu) == 9u);
    assert(strcmp(str_at(rd32(first_va + 8u)), "--bound\r\n") == 0 && size == 9);
    assert(rome2_l86_add_form_dataf(&s_ctx, &form_va, NULL, "n=%d", 42) == ROME2_CURLE_OK);
    assert(form_va != first_va && rd32(first_va) == form_va && size == 9);
    assert(rome2_l86_add_form_dataf(&s_ctx, &form_va, &size, "[%s]", (const char *)NULL) == ROME2_CURLE_OK);
    assert(chain_text(first_va, text, sizeof(text), &nodes) == 20u && nodes == 3u && size == 16);
    assert(strcmp(text, "--bound\r\nn=42[(nil)]") == 0);

    /* the 0x1000-byte buffer bounds one node at 0xfff characters */
    char *long_text = (char *)rome2_l82_mut_ptr(&s_ctx, zalloc(0x1100u), 0x1100u);
    assert(long_text != NULL);
    memset(long_text, 'B', 0x10ffu);
    long_text[0x10ffu] = '\0';
    assert(rome2_l86_add_form_dataf(&s_ctx, &form_va, &size, "%s", long_text) == ROME2_CURLE_OK);
    assert(rd32(form_va + 0xcu) == 0xfffu && size == 16 + 0xfff);

    /* out of memory at the node, then at its text */
    uint32_t tail_va = form_va;
    uint32_t full = limit_arena(0u);
    assert(rome2_l86_add_form_dataf(&s_ctx, &form_va, &size, "x") == ROME2_CURLE_OUT_OF_MEMORY);
    s_ctx.arena_size = full;
    uint32_t frees = s_ctx.free_count;
    full = limit_arena(0x10u);
    assert(rome2_l86_add_form_dataf(&s_ctx, &form_va, &size, "x") == ROME2_CURLE_OUT_OF_MEMORY);
    s_ctx.arena_size = full;
    assert(s_ctx.free_count == frees + 1u && form_va == tail_va && rd32(tail_va) == 0u && size == 16 + 0xfff);

    /* Curl_formclean frees the text only of data and content nodes */
    uint32_t file_va = zalloc(0x10u);
    uint32_t cb_va = zalloc(0x10u);
    wr32(file_va + 4u, 3u);
    wr32(file_va + 8u, put_str("kept-name"));
    wr32(cb_va + 4u, 2u);
    wr32(cb_va + 8u, 0x7777u);
    wr32(tail_va, file_va);
    wr32(file_va, cb_va);
    frees = s_ctx.free_count;
    rome2_l86_curl_formclean(&s_ctx, &first_va);
    assert(first_va == 0u && s_ctx.free_count == frees + 4u * 2u + 2u);
    rome2_l86_curl_formclean(&s_ctx, &first_va);
    rome2_l86_curl_formclean(&s_ctx, NULL);
    assert(s_ctx.free_count == frees + 10u);

    /* Curl_FormBoundary: 28 dashes and 12 hex digits, one Curl_rand draw each */
    uint32_t boundary_va = rome2_l86_curl_form_boundary(&s_g);
    assert(boundary_va != 0u && strcmp(str_at(boundary_va), L86_B1) == 0 && strlen(L86_B1) == 40u);
    assert(strcmp(str_at(rome2_l86_curl_form_boundary(&s_g)), L86_B2) == 0);
    assert(strcmp(str_at(rome2_l86_curl_form_boundary(&s_g)), L86_B3) == 0);
    uint32_t seed = s_g.randseed;
    full = limit_arena(0x28u);
    assert(rome2_l86_curl_form_boundary(&s_g) == 0u && s_g.randseed == seed);
    s_ctx.arena_size = full;
    assert(rome2_l86_curl_form_boundary(NULL) == 0u);
}

#define L86_HEAD "Content-Type: multipart/form-data; boundary=" L86_B1 "\r\n"
#define L86_DISP "--" L86_B1 "\r\nContent-Disposition: form-data; name=\""
#define L86_TAIL "\r\n--" L86_B1 "--\r\n"

static void test_getformdata_fields(void) {
    setup();
    char text[1024];
    uint32_t nodes = 0u;
    uint32_t form_va = 0x1234u;
    int64_t size = -1;

    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, 0u, 0u, &size) == ROME2_CURLE_OK);
    assert(form_va == 0u && size == -1 && s_g.randseed == 0u);

    /* one plain field */
    uint32_t post_va = make_post("field", "value", 0u);
    uint32_t frees = s_ctx.free_count;
    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, post_va, 0u, &size) == ROME2_CURLE_OK);
    static const char one_field[] = L86_HEAD L86_DISP "field\"\r\n\r\nvalue" L86_TAIL;
    assert(chain_text(form_va, text, sizeof(text), &nodes) == sizeof(one_field) - 1u && strcmp(text, one_field) == 0);
    assert(nodes == 8u && size == (int64_t)(sizeof(one_field) - 1u - strlen(L86_HEAD)));
    assert(s_ctx.free_count == frees + 1u); /* the boundary */
    /* the contents node is the only content-typed one */
    uint32_t node_va = form_va;
    for (uint32_t i = 0u; i < 6u; ++i) {
        assert(rd32(node_va + 4u) == 0u);
        node_va = rd32(node_va);
    }
    assert(rd32(node_va + 4u) == 1u && strcmp(str_at(rd32(node_va + 8u)), "value") == 0);
    assert(rd32(node_va + 8u) != rd32(post_va + 0xcu));

    /* a custom content type, two fields, and explicit name and contents lengths */
    s_g.randseed = 0u;
    uint32_t second_va = make_post("abcdef", "bin", 0u);
    wr32(second_va + 8u, 3u);
    wr32(second_va + 0xcu, put_str("xy\tz!"));
    wr32(second_va + 0x10u, 4u);
    wr32(post_va, second_va);
    assert(
        rome2_l86_curl_getformdata(&s_s, 0u, &form_va, post_va, put_str("Content-Type: multipart/related"), &size) ==
        ROME2_CURLE_OK);
    static const char two_head[] = "Content-Type: multipart/related; boundary=" L86_B1 "\r\n";
    static const char two_body[] =
        L86_DISP "field\"\r\n\r\nvalue\r\n" L86_DISP "abc\"\r\n\r\nxy\tz" L86_TAIL;
    assert(chain_text(form_va, text, sizeof(text), &nodes) == sizeof(two_head) - 1u + sizeof(two_body) - 1u);
    assert(strncmp(text, two_head, sizeof(two_head) - 1u) == 0 && strcmp(text + sizeof(two_head) - 1u, two_body) == 0);
    assert(nodes == 15u && size == (int64_t)(sizeof(two_body) - 1u));
    wr32(post_va, 0u);

    /* a buffer field with a shown file name, a content type and extra headers */
    static const char *const headers[] = {"X-A: 1", "X-B: 2"};
    s_g.randseed = 0u;
    uint32_t buffer_va = make_post("up", "ignored", ROME2_HTTPPOST_BUFFER);
    wr32(buffer_va + 0x14u, put_str("BUFFERDATA"));
    wr32(buffer_va + 0x18u, 6u);
    wr32(buffer_va + 0x1cu, put_str("application/octet-stream"));
    wr32(buffer_va + 0x20u, make_slist(headers, 2u));
    wr32(buffer_va + 0x2cu, put_str("x.bin"));
    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, buffer_va, 0u, &size) == ROME2_CURLE_OK);
    static const char buffer_field[] =
        L86_HEAD L86_DISP "up\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream"
        "\r\nX-A: 1\r\nX-B: 2\r\n\r\nBUFFER" L86_TAIL;
    assert(chain_text(form_va, text, sizeof(text), &nodes) == sizeof(buffer_field) - 1u);
    assert(strcmp(text, buffer_field) == 0 && nodes == 12u);
    /* without a shown name a buffer field gets no filename parameter */
    s_g.randseed = 0u;
    wr32(buffer_va + 0x2cu, 0u);
    wr32(buffer_va + 0x1cu, 0u);
    wr32(buffer_va + 0x20u, 0u);
    wr32(buffer_va + 0x18u, 0u); /* a zero buffer length means strlen */
    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, buffer_va, 0u, &size) == ROME2_CURLE_OK);
    (void)chain_text(form_va, text, sizeof(text), &nodes);
    assert(strcmp(text, L86_HEAD L86_DISP "up\"\r\n\r\nBUFFERDATA" L86_TAIL) == 0 && nodes == 8u);

    /* a callback field keeps the user pointer and counts contentslength */
    s_g.randseed = 0u;
    uint32_t callback_va = make_post("cb", NULL, ROME2_HTTPPOST_CALLBACK);
    wr32(callback_va + 0x10u, 1000u);
    wr32(callback_va + 0x2cu, put_str("stream.dat"));
    wr32(callback_va + 0x30u, 0x7777u);
    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, callback_va, 0u, &size) == ROME2_CURLE_OK);
    static const char callback_field[] = L86_HEAD L86_DISP "cb\"; filename=\"stream.dat\"\r\n\r\n<C>" L86_TAIL;
    assert(chain_text(form_va, text, sizeof(text), &nodes) == sizeof(callback_field) - 1u);
    assert(strcmp(text, callback_field) == 0 && nodes == 9u);
    assert(size == (int64_t)(sizeof(callback_field) - 1u - 3u - strlen(L86_HEAD)) + 1000);
    node_va = form_va;
    for (uint32_t i = 0u; i < 7u; ++i) {
        node_va = rd32(node_va);
    }
    assert(rd32(node_va + 4u) == 2u && rd32(node_va + 8u) == 0x7777u);

    /* out of memory: the boundary, the header node, and a node in the middle of the chain */
    uint32_t full = limit_arena(0u);
    form_va = 0x1234u;
    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, post_va, 0u, &size) == ROME2_CURLE_OUT_OF_MEMORY);
    assert(form_va == 0u);
    s_ctx.arena_size = full;
    frees = s_ctx.free_count;
    full = limit_arena(0x2cu);
    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, post_va, 0u, &size) == ROME2_CURLE_OUT_OF_MEMORY);
    s_ctx.arena_size = full;
    assert(s_ctx.free_count == frees + 1u && form_va == 0u);
    frees = s_ctx.free_count;
    uint32_t allocs = s_ctx.alloc_count;
    full = limit_arena(0x2cu + 0x100u); /* room for the header node and three of the seven that follow */
    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, post_va, 0u, &size) == ROME2_CURLE_OUT_OF_MEMORY);
    s_ctx.arena_size = full;
    assert(form_va == 0u && s_ctx.alloc_count - allocs == s_ctx.free_count - frees);
}

static void test_getformdata_files(void) {
    setup();
    char text[1024];
    uint32_t nodes = 0u;
    uint32_t form_va = 0u;
    int64_t size = 0;
    uint32_t data_va = open_easy();

    /* a named file is opened to prove it exists, closed, and recorded by name with its stat size */
    uint32_t file_va = make_post("doc", "/tmp/dir/up.txt", ROME2_HTTPPOST_FILENAME);
    s_fopen_results[0] = 0x6600u;
    s_stat_result = 0;
    s_stat_size = 0x100000005LL;
    assert(rome2_l86_curl_getformdata(&s_s, data_va, &form_va, file_va, 0u, &size) == ROME2_CURLE_OK);
    static const char file_field[] = L86_HEAD L86_DISP "doc\"; filename=\"up.txt\"\r\n\r\n<F>" L86_TAIL;
    assert(chain_text(form_va, text, sizeof(text), &nodes) == sizeof(file_field) - 1u && strcmp(text, file_field) == 0);
    assert(nodes == 9u && s_fopen_calls == 1u && strcmp(s_fopen_path[0], "/tmp/dir/up.txt") == 0);
    assert(strcmp(s_fopen_mode[0], "rb") == 0 && s_fclose_calls == 1u && s_fclose_stream == 0x6600u);
    assert(s_stat_calls == 1u && strcmp(s_stat_path, "/tmp/dir/up.txt") == 0);
    assert(size == (int64_t)(sizeof(file_field) - 1u - 3u - strlen(L86_HEAD)) + 0x100000005LL);
    uint32_t node_va = form_va;
    for (uint32_t i = 0u; i < 7u; ++i) {
        node_va = rd32(node_va);
    }
    assert(rd32(node_va + 4u) == 3u && rd32(node_va + 8u) == rd32(file_va + 0xcu));

    /* a failed stat adds nothing; a shown name replaces the stripped path */
    s_g.randseed = 0u;
    s_fopen_results[1] = 0x6600u;
    s_stat_result = -1;
    wr32(file_va + 0x2cu, put_str("shown.txt"));
    assert(rome2_l86_curl_getformdata(&s_s, data_va, &form_va, file_va, 0u, &size) == ROME2_CURLE_OK);
    static const char shown_field[] = L86_HEAD L86_DISP "doc\"; filename=\"shown.txt\"\r\n\r\n<F>" L86_TAIL;
    (void)chain_text(form_va, text, sizeof(text), &nodes);
    assert(strcmp(text, shown_field) == 0 && s_stat_calls == 2u);
    assert(size == (int64_t)(sizeof(shown_field) - 1u - 3u - strlen(L86_HEAD)));
    wr32(file_va + 0x2cu, 0u);

    /* a file that cannot be opened: CURLE_READ_ERROR, a failf message, and the chain released */
    s_g.randseed = 0u;
    uint32_t frees = s_ctx.free_count;
    uint32_t allocs = s_ctx.alloc_count;
    form_va = 0x1234u;
    assert(rome2_l86_curl_getformdata(&s_s, data_va, &form_va, file_va, 0u, &size) == ROME2_L86_CURLE_READ_ERROR);
    assert(form_va == 0u && s_fopen_calls == 3u && s_fclose_calls == 2u);
    assert(strcmp(str_at(data_va + 0x594u), "couldn't open file \"/tmp/dir/up.txt\"") == 0);
    assert(s_ctx.alloc_count - allocs == s_ctx.free_count - frees);
    wr32(data_va + 0x594u, 0u);
    assert(rome2_l86_curl_getformdata(&s_s, 0u, &form_va, file_va, 0u, &size) == ROME2_L86_CURLE_READ_ERROR);
    assert(rd32(data_va + 0x594u) == 0u);

    /* "-" reads stdin in 0x200-byte pieces and never closes it */
    s_g.randseed = 0u;
    uint32_t stdin_va = make_post("in", "-", ROME2_HTTPPOST_READFILE);
    s_fread_script[0] = 0x200u;
    s_fread_script[1] = 5u;
    s_fread_script[2] = 0u;
    uint32_t opens = s_fopen_calls;
    uint32_t closes = s_fclose_calls;
    assert(rome2_l86_curl_getformdata(&s_s, data_va, &form_va, stdin_va, 0u, &size) == ROME2_CURLE_OK);
    assert(s_fread_calls == 3u && s_fread_elem == 1u && s_fread_count == 0x200u && s_fread_stream == 0x119ebe18u);
    assert(s_fopen_calls == opens && s_fclose_calls == closes);
    node_va = form_va;
    for (uint32_t i = 0u; i < 6u; ++i) {
        node_va = rd32(node_va);
    }
    assert(rd32(node_va + 4u) == 1u && rd32(node_va + 0xcu) == 0x200u && str_at(rd32(node_va + 8u))[0x1ffu] == 'a');
    node_va = rd32(node_va);
    assert(rd32(node_va + 4u) == 1u && rd32(node_va + 0xcu) == 5u && strcmp(str_at(rd32(node_va + 8u)), "bbbbb") == 0);
    static const char stdin_frame[] = L86_DISP "in\"\r\n\r\n" L86_TAIL;
    assert(size == (int64_t)(sizeof(stdin_frame) - 1u) + 0x205);

    /* several files under one field name: a nested multipart/mixed part with its own boundary */
    s_g.randseed = 0u;
    uint32_t multi_va = make_post("files", "/a/one.txt", ROME2_HTTPPOST_FILENAME);
    uint32_t more_va = make_post("unused", "C:\\b\\two.bin", ROME2_HTTPPOST_FILENAME);
    wr32(multi_va + 0x24u, more_va);
    wr32(multi_va + 0x1cu, put_str("text/plain"));
    wr32(more_va + 0x2cu, put_str("second.bin"));
    s_fopen_results[s_fopen_calls] = 0x6601u;
    s_fopen_results[s_fopen_calls + 1u] = 0x6602u;
    assert(rome2_l86_curl_getformdata(&s_s, data_va, &form_va, multi_va, 0u, &size) == ROME2_CURLE_OK);
    static const char multi_field[] =
        L86_HEAD L86_DISP "files\"\r\nContent-Type: multipart/mixed, boundary=" L86_B2 "\r\n"
        "\r\n--" L86_B2 "\r\nContent-Disposition: attachment; filename=\"one.txt\"\r\nContent-Type: text/plain\r\n\r\n<F>"
        "\r\n--" L86_B2 "\r\nContent-Disposition: attachment; filename=\"second.bin\"\r\n\r\n<F>"
        "\r\n--" L86_B2 "--" L86_TAIL;
    assert(chain_text(form_va, text, sizeof(text), &nodes) == sizeof(multi_field) - 1u);
    assert(strcmp(text, multi_field) == 0 && nodes == 15u);
    assert(strcmp(s_fopen_path[s_fopen_calls - 2u], "/a/one.txt") == 0);
    assert(strcmp(s_fopen_path[s_fopen_calls - 1u], "C:\\b\\two.bin") == 0);

    /* the second file cannot be opened: everything built so far is released */
    s_g.randseed = 0u;
    s_fopen_results[s_fopen_calls] = 0x6601u;
    frees = s_ctx.free_count;
    allocs = s_ctx.alloc_count;
    assert(rome2_l86_curl_getformdata(&s_s, data_va, &form_va, multi_va, 0u, &size) == ROME2_L86_CURLE_READ_ERROR);
    assert(form_va == 0u && s_ctx.alloc_count - allocs == s_ctx.free_count - frees);
    assert(strcmp(str_at(data_va + 0x594u), "couldn't open file \"C:\\b\\two.bin\"") == 0);
}

static void test_formget(void) {
    setup();
    /* no posts: nothing to append */
    assert(rome2_l86_curl_formget(&s_s, 0u, 0x9000u, 0x9100u) == 0 && s_append_calls == 0u);

    uint32_t post_va = make_post("field", "value", 0u);
    uint32_t frees = s_ctx.free_count;
    uint32_t allocs = s_ctx.alloc_count;
    assert(rome2_l86_curl_formget(&s_s, post_va, 0x9000u, 0x9100u) == 0);
    assert(s_append_calls == 8u && s_append_fn == 0x9100u && s_append_arg == 0x9000u);
    assert(strcmp(s_append_text, L86_HEAD L86_DISP "field\"\r\n\r\nvalue" L86_TAIL) == 0);
    assert(s_ctx.alloc_count - allocs == s_ctx.free_count - frees); /* the chain is always released */

    /* a short append stops the walk */
    s_g.randseed = 0u;
    s_append_calls = 0u;
    s_append_len = 0u;
    s_append_fail_call = 3u;
    frees = s_ctx.free_count;
    allocs = s_ctx.alloc_count;
    assert(rome2_l86_curl_formget(&s_s, post_va, 0x9000u, 0x9100u) == -1 && s_append_calls == 3u);
    assert(s_ctx.alloc_count - allocs == s_ctx.free_count - frees);
    s_append_fail_call = 0u;

    /* a file node is reopened and streamed in 0x2000-byte reads, ending with a zero-length append */
    s_g.randseed = 0u;
    s_append_calls = 0u;
    s_append_len = 0u;
    uint32_t file_va = make_post("doc", "/tmp/up.txt", ROME2_HTTPPOST_FILENAME);
    s_fopen_results[0] = 0x6600u;
    s_fopen_results[1] = 0x6601u;
    s_fread_script[0] = 4u;
    s_fread_script[1] = 2u;
    s_fread_script[2] = 0u;
    assert(rome2_l86_curl_formget(&s_s, file_va, 0x9000u, 0x9100u) == 0);
    assert(s_fopen_calls == 2u && strcmp(s_fopen_path[1], "/tmp/up.txt") == 0 && strcmp(s_fopen_mode[1], "rb") == 0);
    assert(s_fread_calls == 3u && s_fread_count == 0x2000u && s_fread_elem == 1u && s_fread_stream == 0x6601u);
    assert(s_fclose_calls == 2u && s_fclose_stream == 0x6601u && s_append_calls == 7u + 3u + 1u);
    assert(strcmp(s_append_text, L86_HEAD L86_DISP "doc\"; filename=\"up.txt\"\r\n\r\naaaabb" L86_TAIL) == 0);

    /* the second open fails */
    s_g.randseed = 0u;
    s_fopen_results[2] = 0x6600u;
    assert(rome2_l86_curl_formget(&s_s, file_va, 0x9000u, 0x9100u) == -1);
    assert(s_fopen_calls == 4u && s_fclose_calls == 3u);
    /* fread failure and an oversized read both close the file and fail */
    s_g.randseed = 0u;
    s_fopen_results[4] = 0x6600u;
    s_fopen_results[5] = 0x6601u;
    s_fread_script[3] = 0xffffffffu;
    assert(rome2_l86_curl_formget(&s_s, file_va, 0x9000u, 0x9100u) == -1);
    assert(s_fread_calls == 4u && s_fclose_calls == 5u && s_fclose_stream == 0x6601u);
    s_g.randseed = 0u;
    s_fopen_results[6] = 0x6600u;
    s_fopen_results[7] = 0x6601u;
    s_fread_script[4] = 0x2001u;
    assert(rome2_l86_curl_formget(&s_s, file_va, 0x9000u, 0x9100u) == -1);
    assert(s_fread_calls == 5u && s_fclose_calls == 7u);
    /* a full 0x2000-byte read is accepted */
    s_g.randseed = 0u;
    s_fopen_results[8] = 0x6600u;
    s_fopen_results[9] = 0x6601u;
    s_fread_script[5] = 0x2000u;
    s_fread_script[6] = 0u;
    s_append_calls = 0u;
    s_append_len = 0u;
    s_s.on_formget_append = NULL; /* unset: every append is accepted in full */
    assert(rome2_l86_curl_formget(&s_s, file_va, 0x9000u, 0x9100u) == 0 && s_fread_calls == 7u);
    s_s.on_formget_append = on_formget_append;

    /* a callback node offers one zero-length append, which must return zero */
    s_g.randseed = 0u;
    uint32_t callback_va = make_post("cb", NULL, ROME2_HTTPPOST_CALLBACK);
    wr32(callback_va + 0x30u, 0x7777u);
    s_append_calls = 0u;
    s_append_len = 0u;
    uint32_t reads = s_fread_calls;
    uint32_t opens = s_fopen_calls;
    assert(rome2_l86_curl_formget(&s_s, callback_va, 0x9000u, 0x9100u) == 0);
    assert(s_append_calls == 6u + 1u + 1u && s_fread_calls == reads && s_fopen_calls == opens);
    assert(strcmp(s_append_text, L86_HEAD L86_DISP "cb\"\r\n\r\n" L86_TAIL) == 0);
    s_g.randseed = 0u;
    s_append_calls = 0u;
    s_append_fail_call = 7u;
    assert(rome2_l86_curl_formget(&s_s, callback_va, 0x9000u, 0x9100u) == -1 && s_append_last_len == 0u);
    s_append_fail_call = 0u;

    /* a chain that cannot be built returns Curl_getformdata's code */
    s_append_calls = 0u;
    assert(rome2_l86_curl_formget(&s_s, file_va, 0x9000u, 0x9100u) == ROME2_L86_CURLE_READ_ERROR);
    assert(s_append_calls == 0u);
}

int main(void) {
    test_crt_numeric();
    test_crt_stream();
    test_rand_and_strings();
    test_llist_hash_alloc();
    test_slist_duplicate_and_strippath();
    test_ssl_teardown();
    test_resolver_teardown();
    test_closesocket_and_connc();
    test_dupset();
    test_duphandle();
    test_infof();
    test_read_and_recv();
    test_multi_init();
    test_getinfo();
    test_cookie_header();
    test_cookie_netscape();
    test_cookie_replace();
    test_cookie_init_and_list();
    test_share_setopt();
    test_form_primitives();
    test_getformdata_fields();
    test_getformdata_files();
    test_formget();
    printf("curl_dup_getinfo_form_share_ops tests passed\n");
    return 0;
}
