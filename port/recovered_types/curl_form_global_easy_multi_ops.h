#ifndef ROME2_CURL_FORM_GLOBAL_EASY_MULTI_OPS_H
#define ROME2_CURL_FORM_GLOBAL_EASY_MULTI_OPS_H

#include "curl_util_printf_slist_share_ops.h"
#include "guest32_layouts.h"

#include <stdarg.h>
#include <stdint.h>

/*
 * Layer 83: statically linked libcurl global/easy/multi/formpost routines, the
 * OpenSSL import thunks they reach and the CRT time helpers behind Curl_srand
 * (57 functions, 0x10f10330..0x116c7fd5).
 *
 * Guest objects live in the Layer 82 bump arena and are addressed by guest VA.
 * Field names follow the libcurl source shape the bodies match; they are
 * inference, only the offsets and widths are evidenced.
 *
 * Bounded deviations shared by every routine here:
 *  - a guest pointer outside the arena makes the routine stop early where the
 *    image would fault;
 *  - the allocator globals 0x119750cc..0x119750dc are recorded but every
 *    allocation is served by the Layer 82 bump arena;
 *  - imports, callback pointers and CRT stream I/O are dispatched to the hooks
 *    below, each documented with the result used when the hook is unset;
 *  - list and tree walks stop after ROME2_L83_WALK_CAP nodes.
 */

#define ROME2_CURL_EASY_MAGIC 0xc0dedbadu
#define ROME2_CURL_MULTI_MAGIC 0x000bab1eu
#define ROME2_CURL_WRITEFUNC_PAUSE 0x10000001u
#define ROME2_CURL_SOCKET_BAD 0xffffffffu
#define ROME2_CURL_REDIR_PROTOCOLS_DEFAULT 0xfffffbefu
#define ROME2_L83_RANDSEED_MUL 0x807dbcb5u
#define ROME2_L83_RANDSEED_ADD 0xa70427dfu
#define ROME2_L83_FILETIME_UNIX_EPOCH 0x019db1ded53e8000ULL
#define ROME2_L83_FILETIME_SPAN_LIMIT 0x0483f078dd478000LL

enum rome2_l83_const {
    ROME2_L83_WALK_CAP = 4096,
    ROME2_L83_FORMADD_ARGS_EXHAUSTED = -1, /* model-only: argument list ended before CURLFORM_END */
    ROME2_CURL_MAX_WRITE_SIZE = 0x4000,
    ROME2_CURL_ERROR_SIZE = 0x100,
    ROME2_CURL_HEADERSIZE = 0x100,
    ROME2_CURL_FD_SETSIZE = 64,
    ROME2_CURL_MAX_SOCKSPEREASYHANDLE = 5,
    ROME2_CURL_GLOBAL_SSL = 1,
    ROME2_CURL_GLOBAL_WIN32 = 2,
    ROME2_CURL_GLOBAL_ALL = 3,
    ROME2_CURL_WSA_VERSION = 0x0202,
    ROME2_CURLPAUSE_RECV = 1,
    ROME2_CURLPAUSE_SEND = 4,
    ROME2_CURL_KEEP_RECV = 0x01,
    ROME2_CURL_KEEP_SEND = 0x02,
    ROME2_CURL_KEEP_RECV_PAUSE = 0x10,
    ROME2_CURL_KEEP_SEND_PAUSE = 0x20,
    ROME2_CURL_CLIENTWRITE_BODY = 1,
    ROME2_CURL_CLIENTWRITE_HEADER = 2,
    ROME2_CURL_PGRS_HIDE = 0x10
};

enum rome2_l83_curlcode {
    ROME2_CURLE_OK = 0,
    ROME2_CURLE_UNSUPPORTED_PROTOCOL = 1,
    ROME2_CURLE_FAILED_INIT = 2,
    ROME2_CURLE_WRITE_ERROR = 0x17,
    ROME2_CURLE_OUT_OF_MEMORY = 0x1b,
    ROME2_CURLE_BAD_FUNCTION_ARGUMENT = 0x2b,
    ROME2_CURLE_SEND_ERROR = 0x37,
    ROME2_CURLE_RECV_ERROR = 0x38,
    ROME2_CURLE_AGAIN = 0x51
};

enum rome2_l83_curlmcode {
    ROME2_CURLM_OK = 0,
    ROME2_CURLM_BAD_HANDLE = 1,
    ROME2_CURLM_BAD_SOCKET = 5,
    ROME2_CURLM_UNKNOWN_OPTION = 6
};

enum rome2_curl_formadd_code {
    ROME2_CURL_FORMADD_OK = 0,
    ROME2_CURL_FORMADD_MEMORY = 1,
    ROME2_CURL_FORMADD_OPTION_TWICE = 2,
    ROME2_CURL_FORMADD_NULL = 3,
    ROME2_CURL_FORMADD_UNKNOWN_OPTION = 4,
    ROME2_CURL_FORMADD_INCOMPLETE = 5,
    ROME2_CURL_FORMADD_ILLEGAL_ARRAY = 6
};

enum rome2_curlform_option {
    ROME2_CURLFORM_COPYNAME = 1,
    ROME2_CURLFORM_PTRNAME = 2,
    ROME2_CURLFORM_NAMELENGTH = 3,
    ROME2_CURLFORM_COPYCONTENTS = 4,
    ROME2_CURLFORM_PTRCONTENTS = 5,
    ROME2_CURLFORM_CONTENTSLENGTH = 6,
    ROME2_CURLFORM_FILECONTENT = 7,
    ROME2_CURLFORM_ARRAY = 8,
    ROME2_CURLFORM_FILE = 10,
    ROME2_CURLFORM_BUFFER = 11,
    ROME2_CURLFORM_BUFFERPTR = 12,
    ROME2_CURLFORM_BUFFERLENGTH = 13,
    ROME2_CURLFORM_CONTENTTYPE = 14,
    ROME2_CURLFORM_CONTENTHEADER = 15,
    ROME2_CURLFORM_FILENAME = 16,
    ROME2_CURLFORM_END = 17,
    ROME2_CURLFORM_STREAM = 19
};

/* curl_httppost / FormInfo flag bits (FormInfo +0x20, curl_httppost +0x28). */
enum rome2_curl_httppost_flag {
    ROME2_HTTPPOST_FILENAME = 0x01,
    ROME2_HTTPPOST_READFILE = 0x02,
    ROME2_HTTPPOST_PTRNAME = 0x04,
    ROME2_HTTPPOST_PTRCONTENTS = 0x08,
    ROME2_HTTPPOST_BUFFER = 0x10,
    ROME2_HTTPPOST_PTRBUFFER = 0x20,
    ROME2_HTTPPOST_CALLBACK = 0x40
};

enum rome2_curlm_option {
    ROME2_CURLMOPT_PIPELINING = 3,
    ROME2_CURLMOPT_MAXCONNECTS = 6,
    ROME2_CURLMOPT_SOCKETDATA = 10002,
    ROME2_CURLMOPT_TIMERDATA = 10005,
    ROME2_CURLMOPT_SOCKETFUNCTION = 20001,
    ROME2_CURLMOPT_TIMERFUNCTION = 20004
};

/* SessionHandle (calloc(1, 0x8788) in 0x10f17b10) offsets touched by this layer. */
enum rome2_curl_easy_off {
    ROME2_CURL_EASY_REQ_OFF = 0x18,
    ROME2_CURL_EASY_REQ_BYTES = 0x110,
    ROME2_CURL_EASY_REQ_MAXDOWNLOAD_OFF = 0x28, /* 64-bit, -1 */
    ROME2_CURL_EASY_REQ_KEEPON_OFF = 0xf8,
    ROME2_CURL_EASY_SET_OFF = 0x128,
    ROME2_CURL_EASY_SET_BYTES = 0x328,
    ROME2_CURL_EASY_SET_ERR_OFF = 0x128,
    ROME2_CURL_EASY_SET_DEBUGDATA_OFF = 0x12c,
    ROME2_CURL_EASY_SET_ERRORBUFFER_OFF = 0x130,
    ROME2_CURL_EASY_SET_OUT_OFF = 0x138,
    ROME2_CURL_EASY_SET_IN_OFF = 0x13c,
    ROME2_CURL_EASY_SET_WRITEHEADER_OFF = 0x140,
    ROME2_CURL_EASY_SET_FWRITE_FUNC_OFF = 0x180,
    ROME2_CURL_EASY_SET_FWRITE_HEADER_OFF = 0x184,
    ROME2_CURL_EASY_SET_FREAD_FUNC_OFF = 0x18c,
    ROME2_CURL_EASY_SET_FDEBUG_OFF = 0x19c,
    ROME2_CURL_EASY_SET_VERBOSE_OFF = 0x31c,
    ROME2_CURL_EASY_SET_CONNECT_ONLY_OFF = 0x358,
    ROME2_CURL_EASY_SET_STR_OFF = 0x378,
    ROME2_CURL_EASY_SET_STR_COUNT = 0x26,
    ROME2_CURL_EASY_SET_WILDCARDMATCH_OFF = 0x434,
    ROME2_CURL_EASY_CHANGE_REFERER_OFF = 0x458,
    ROME2_CURL_EASY_CHANGE_REFERER_ALLOC_OFF = 0x45c,
    ROME2_CURL_EASY_PROGRESS_OFF = 0x470,
    ROME2_CURL_EASY_PROGRESS_BYTES = 0x108,
    ROME2_CURL_EASY_PROGRESS_FLAGS_OFF = 0x4a8,
    ROME2_CURL_EASY_STATE_CONNC_OFF = 0x57c,
    ROME2_CURL_EASY_STATE_LASTCONNECT_OFF = 0x588,
    ROME2_CURL_EASY_STATE_HEADERBUFF_OFF = 0x58c,
    ROME2_CURL_EASY_STATE_HEADERSIZE_OFF = 0x590,
    ROME2_CURL_EASY_STATE_BUFFER_OFF = 0x594, /* 0x4000 bytes formatted by Curl_failf */
    ROME2_CURL_EASY_STATE_CURRENT_SPEED_OFF = 0x8598, /* 64-bit, -1 */
    ROME2_CURL_EASY_STATE_TEMPWRITE_OFF = 0x85b0,
    ROME2_CURL_EASY_STATE_TEMPWRITESIZE_OFF = 0x85b4,
    ROME2_CURL_EASY_STATE_TEMPWRITETYPE_OFF = 0x85b8,
    ROME2_CURL_EASY_STATE_ERRORBUF_OFF = 0x85c0,
    ROME2_CURL_EASY_STATE_RESOLVER_OFF = 0x8648,
    ROME2_CURL_EASY_STATE_PIPE_BROKE_OFF = 0x8680,
    ROME2_CURL_EASY_STATE_PATHBUFFER_OFF = 0x868c,
    ROME2_CURL_EASY_STATE_PATH_OFF = 0x8690,
    ROME2_CURL_EASY_STATE_PROTO_OFF = 0x86bc,
    ROME2_CURL_EASY_STATE_CURRENT_CONN_OFF = 0x86c0,
    ROME2_CURL_EASY_WILDCARD_STATE_OFF = 0x86c8,
    ROME2_CURL_EASY_WILDCARD_FILELIST_OFF = 0x86d4,
    ROME2_CURL_EASY_MAGIC_OFF = 0x8784,
    ROME2_CURL_EASY_BYTES = 0x8788
};

/* connectdata and Curl_handler offsets touched by this layer. */
enum rome2_curl_conn_off {
    ROME2_CURL_CONN_DATA_OFF = 0x000,
    ROME2_CURL_CONN_SOCK_OFF = 0x130,         /* sock[2] */
    ROME2_CURL_CONN_SEND_OFF = 0x148,         /* send[2] */
    ROME2_CURL_CONN_SSL0_USE_OFF = 0x150,
    ROME2_CURL_CONN_SSL0_HANDLE_OFF = 0x15c,
    ROME2_CURL_CONN_HANDLER_OFF = 0x234,
    ROME2_CURL_CONN_SOCKFD_OFF = 0x240,
    ROME2_CURL_CONN_WRITESOCKFD_OFF = 0x244,
    ROME2_CURL_CONN_TUNNEL_STATE0_OFF = 0x4a4,
    ROME2_CURL_HANDLER_PROTO_GETSOCK_OFF = 0x20,
    ROME2_CURL_HANDLER_DOING_GETSOCK_OFF = 0x24,
    ROME2_CURL_HANDLER_DOMORE_GETSOCK_OFF = 0x28,
    ROME2_CURL_HANDLER_PERFORM_GETSOCK_OFF = 0x2c
};

/* Image addresses this layer stores as data. */
enum rome2_l83_image_va {
    ROME2_L83_CRT_MALLOC_VA = 0x1168d0c3,
    ROME2_L83_CRT_FREE_VA = 0x1168d0a8,
    ROME2_L83_CRT_REALLOC_VA = 0x1169d9a2,
    ROME2_L83_CRT_STRDUP_VA = 0x116b204d,
    ROME2_L83_CRT_CALLOC_VA = 0x1169d9ad,
    ROME2_L83_CRT_FWRITE_VA = 0x11688039,
    ROME2_L83_CRT_FREAD_VA = 0x1168ebe6,
    ROME2_L83_CRT_IOB_BASE_VA = 0x119ebe18, /* __acrt_iob_func(n) = base + n * 0x38 */
    ROME2_L83_CRT_IOB_STRIDE = 0x38,
    ROME2_L83_CONTENT_TYPE_TABLE_VA = 0x118465b0
};

/* The eight by-ordinal OpenSSL import thunks (JMP dword ptr [slot]). */
enum rome2_l83_openssl_thunk_id {
    ROME2_L83_LIBEAY32_ORD_2604 = 0, /* 0x11687680 -> [0x1172f438] */
    ROME2_L83_LIBEAY32_ORD_3212 = 1, /* 0x116876e0 -> [0x1172f460] */
    ROME2_L83_LIBEAY32_ORD_298 = 2,  /* 0x116876e6 -> [0x1172f45c] */
    ROME2_L83_LIBEAY32_ORD_224 = 3,  /* 0x1168778e -> [0x1172f3c8] */
    ROME2_L83_LIBEAY32_ORD_254 = 4,  /* 0x11687794 -> [0x1172f3cc] */
    ROME2_L83_SSLEAY32_ORD_74 = 5,   /* 0x116c7f45 -> [0x1172f5e8] */
    ROME2_L83_SSLEAY32_ORD_76 = 6,   /* 0x116c7f93 -> [0x1172f588] */
    ROME2_L83_SSLEAY32_ORD_183 = 7,  /* 0x116c7fd5 -> [0x1172f5b4] */
    ROME2_L83_OPENSSL_THUNK_COUNT = 8
};

typedef struct rome2_l83_openssl_thunk_desc {
    uint32_t thunk_va;
    uint32_t iat_slot_va;
    uint16_t ordinal;
    uint8_t is_ssleay32; /* 0: LIBEAY32.dll, 1: SSLEAY32.dll */
} rome2_l83_openssl_thunk_desc;

extern const rome2_l83_openssl_thunk_desc rome2_l83_openssl_thunks[ROME2_L83_OPENSSL_THUNK_COUNT];

typedef struct rome2_l83_content_type_entry {
    const char *extension;
    const char *type;
} rome2_l83_content_type_entry;

/* 0x118465b0: six 0xc-byte {char ext[8]; const char *type} rows scanned by FormAdd. */
extern const rome2_l83_content_type_entry rome2_l83_content_types[6];

typedef struct rome2_crt_timespec64 {
    int64_t tv_sec;
    int32_t tv_nsec;
} rome2_crt_timespec64;

typedef struct rome2_l83_curl_state {
    rome2_l82_curl_ctx *mem;

    uint32_t initialized;            /* 0x11fb5948 */
    uint32_t init_flags;             /* 0x11fb594c */
    uint32_t hostname_cache_va;      /* arena stand-in for the curl_hash at 0x11fb5950 */
    uint32_t host_cache_initialized; /* 0x11fb5968 */
    uint32_t ssl_initialized;        /* 0x11fb596c */
    uint32_t randseed;               /* 0x11fb5970 */
    rome2_curl_timeval_32 tv_zero;   /* 0x11fb5974: zero-filled splay key */
    uint32_t malloc_fn_va;           /* 0x119750cc */
    uint32_t free_fn_va;             /* 0x119750d0 */
    uint32_t realloc_fn_va;          /* 0x119750d4 */
    uint32_t strdup_fn_va;           /* 0x119750d8 */
    uint32_t calloc_fn_va;           /* 0x119750dc */

    uint8_t has_precise_filetime;    /* try_get_function(GetSystemTimePreciseAsFileTime) != NULL */
    uint32_t invalid_parameter_calls;
    uint32_t resolver_stub_calls;    /* 0x100dbc00: XOR EAX, EAX; RET */
    uint32_t nop_stub_calls;         /* 0x100d6560: RET */

    /* By-ordinal OpenSSL import behind thunk `id`; unset: returns 0. */
    int32_t (*on_openssl)(
        struct rome2_l83_curl_state *g,
        int32_t id,
        uint32_t a0,
        uint32_t a1,
        uint32_t a2);
    /* WS2_32 WSAStartup [0x1172f84c]; unset: returns 0 and reports the requested version. */
    int32_t (*on_wsa_startup)(
        struct rome2_l83_curl_state *g,
        uint16_t version_requested,
        uint16_t *version_out);
    /* WS2_32 WSACleanup [0x1172f850]; unset: no effect. */
    void (*on_wsa_cleanup)(struct rome2_l83_curl_state *g);
    /* KERNEL32 GetTickCount [0x1172f234]; unset: returns 0. */
    uint32_t (*on_get_tick_count)(struct rome2_l83_curl_state *g);
    /* GetSystemTimePreciseAsFileTime (precise != 0) or GetSystemTimeAsFileTime; unset: FILETIME 0. */
    uint64_t (*on_system_filetime)(struct rome2_l83_curl_state *g, uint8_t precise);
    /* WS2_32 recv(s, buf, 1, MSG_PEEK) [0x1172f830]; unset: returns 0. */
    int32_t (*on_recv_peek)(struct rome2_l83_curl_state *g, uint32_t sockfd);
    /* conn->send[sockindex]; unset: returns -1 leaving *curlcode untouched. */
    int32_t (*on_conn_send)(
        struct rome2_l83_curl_state *g,
        uint32_t send_fn_va,
        uint32_t conn_va,
        uint32_t sockindex,
        uint32_t mem_va,
        uint32_t len,
        int32_t *curlcode);
    /* size_t fn(ptr, size, nmemb, stream) write callbacks and CRT fwrite; unset: returns nmemb. */
    uint32_t (*on_write)(
        struct rome2_l83_curl_state *g,
        uint32_t fn_va,
        const uint8_t *ptr,
        uint32_t size,
        uint32_t nmemb,
        uint32_t stream_va);
    /* set.fdebug(data, type, text, size, userp); unset: no effect. */
    void (*on_debug)(
        struct rome2_l83_curl_state *g,
        uint32_t fn_va,
        uint32_t data_va,
        int32_t type,
        const char *text,
        uint32_t size,
        uint32_t userp_va);
    /* Curl_handler getsock callbacks; unset: returns 0. */
    uint32_t (*on_getsock)(
        struct rome2_l83_curl_state *g,
        uint32_t fn_va,
        uint32_t conn_va,
        uint32_t *socks,
        int32_t numsocks);
    /* curl_hash hash_func(key, key_len, slots); unset: Curl_hash_pick finds nothing. */
    uint32_t (*on_hash_func)(
        struct rome2_l83_curl_state *g,
        uint32_t fn_va,
        const void *key,
        uint32_t key_len,
        int32_t slots);
    /* curl_hash comp_func(k1, k1_len, key, key_len); unset: never matches. */
    uint32_t (*on_hash_comp)(
        struct rome2_l83_curl_state *g,
        uint32_t fn_va,
        uint32_t k1_va,
        uint32_t k1_len,
        const void *key,
        uint32_t key_len);
} rome2_l83_curl_state;

void rome2_l83_state_init(rome2_l83_curl_state *g, rome2_l82_curl_ctx *mem);

/* Global and SSL bring-up (0x10f10990, 0x10f109e0, 0x10f10ab0, 0x10f12f30, 0x10f15ca0, 0x10f15cb0, 0x10f162a0, 0x10f2d260, 0x10f2d290, 0x10f2d380, eight thunks) */
int32_t rome2_l83_curl_global_init(rome2_l83_curl_state *g, uint32_t flags);
int32_t rome2_l83_curl_global_init_mem(
    rome2_l83_curl_state *g,
    uint32_t flags,
    uint32_t m_va,
    uint32_t f_va,
    uint32_t r_va,
    uint32_t s_va,
    uint32_t c_va);
void rome2_l83_curl_global_cleanup(rome2_l83_curl_state *g);
void rome2_l83_curl_global_host_cache_dtor(rome2_l83_curl_state *g);
int32_t rome2_l83_curl_ssl_init(rome2_l83_curl_state *g);
void rome2_l83_curl_ssl_cleanup(rome2_l83_curl_state *g);
int32_t rome2_l83_curl_ossl_init(rome2_l83_curl_state *g);
void rome2_l83_curl_ossl_cleanup(rome2_l83_curl_state *g);
int32_t rome2_l83_curl_ossl_check_cxn(rome2_l83_curl_state *g, uint32_t conn_va);
int32_t rome2_l83_curl_ssl_check_cxn(rome2_l83_curl_state *g, uint32_t conn_va);
int32_t rome2_l83_openssl_thunk(
    rome2_l83_curl_state *g,
    int32_t id,
    uint32_t a0,
    uint32_t a1,
    uint32_t a2);

/* Hash, llist, time and seed helpers (0x10f123e0, 0x10f12660, 0x10f1eda0, 0x10f21180, 0x10f213a0, 0x10f21420, 0x10f214b0, 0x1168c9e2, 0x1168ca95, 0x116a886e) */
void rome2_l83_curl_hash_clean(rome2_l82_curl_ctx *ctx, uint32_t hash_va);
uint32_t rome2_l83_curl_hash_pick(
    rome2_l83_curl_state *g,
    uint32_t hash_va,
    const void *key,
    uint32_t key_len);
uint32_t rome2_l83_curl_llist_count(const rome2_l82_curl_ctx *ctx, uint32_t list_va);
int32_t rome2_l83_curl_llist_remove(
    rome2_l82_curl_ctx *ctx,
    uint32_t list_va,
    uint32_t elem_va,
    uint32_t user_va);
int32_t rome2_l83_curlx_tvdiff(rome2_curl_timeval_32 newer, rome2_curl_timeval_32 older);
rome2_curl_timeval_32 rome2_l83_curlx_tvnow(rome2_l83_curl_state *g);
void rome2_l83_curl_srand(rome2_l83_curl_state *g);
int32_t rome2_l83_crt_timespec_get(rome2_l83_curl_state *g, rome2_crt_timespec64 *ts, int32_t base);
int64_t rome2_l83_crt_time64(rome2_l83_curl_state *g, int64_t *out);
void rome2_l83_crt_get_system_time_precise_as_file_time(rome2_l83_curl_state *g, uint64_t *filetime);

/* Easy handle lifecycle and transfer I/O (0x10f10330, 0x10f105a0, 0x10f105e0, 0x10f10820, 0x10f108e0, 0x10f10b30, 0x10f14670, 0x10f173f0, 0x10f17730, 0x10f178c0, 0x10f17b10, 0x10f17f40, 0x10f1d030, 0x10f1d260, 0x10f1d7e0, 0x10f1d8e0, 0x10f1db90) */
void rome2_l83_curl_easy_init_handle_data(rome2_l82_curl_ctx *ctx, uint32_t data_va);
uint32_t rome2_l83_curl_easy_init(rome2_l83_curl_state *g);
int32_t rome2_l83_curl_easy_pause(rome2_l83_curl_state *g, uint32_t data_va, uint32_t action);
void rome2_l83_curl_easy_reset(rome2_l82_curl_ctx *ctx, uint32_t data_va);
int32_t rome2_l83_curl_easy_send(
    rome2_l83_curl_state *g,
    uint32_t data_va,
    uint32_t buffer_va,
    uint32_t buflen,
    int32_t *n);
int32_t rome2_l83_easy_connection(
    rome2_l83_curl_state *g,
    uint32_t data_va,
    uint32_t *sfd,
    uint32_t *conn_va);
uint32_t rome2_l83_curl_single_getsock(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t *socks,
    int32_t numsocks);
uint32_t rome2_l83_curl_doing_getsock(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t *socks,
    int32_t numsocks);
uint32_t rome2_l83_curl_protocol_getsock(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t *socks,
    int32_t numsocks);
void rome2_l83_curl_freeset(rome2_l82_curl_ctx *ctx, uint32_t data_va);
int32_t rome2_l83_curl_init_userdefined(rome2_l82_curl_ctx *ctx, uint32_t set_va);
int32_t rome2_l83_curl_open(rome2_l83_curl_state *g, uint32_t *out_data_va);
int32_t rome2_l83_curl_client_write(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t type,
    uint32_t ptr_va,
    uint32_t len);
void rome2_l83_curl_failf(rome2_l83_curl_state *g, uint32_t data_va, const char *fmt, ...);
int32_t rome2_l83_curl_write(
    rome2_l83_curl_state *g,
    uint32_t conn_va,
    uint32_t sockfd,
    uint32_t mem_va,
    uint32_t len,
    int32_t *written);
int32_t rome2_l83_pausewrite(
    rome2_l82_curl_ctx *ctx,
    uint32_t data_va,
    uint32_t type,
    uint32_t ptr_va,
    uint32_t len);
uint32_t rome2_l83_curl_getconnectinfo(
    rome2_l83_curl_state *g,
    uint32_t data_va,
    uint32_t *conn_va);

/* Multi handle and splay tree (0x10f22760, 0x10f228f0, 0x10f22a40, 0x10f22ef0, 0x10f23030, 0x10f232c0, 0x10f24450, 0x10f3d820) */
int32_t rome2_l83_curl_multi_assign(
    rome2_l83_curl_state *g,
    uint32_t multi_va,
    uint32_t sockfd,
    uint32_t hashp_va);
int32_t rome2_l83_curl_multi_fdset(
    rome2_l83_curl_state *g,
    uint32_t multi_va,
    uint32_t read_fd_set_va,
    uint32_t write_fd_set_va,
    uint32_t exc_fd_set_va,
    int32_t *max_fd);
uint32_t rome2_l83_curl_multi_info_read(
    rome2_l82_curl_ctx *ctx,
    uint32_t multi_va,
    int32_t *msgs_in_queue);
int32_t rome2_l83_curl_multi_setopt(
    rome2_l82_curl_ctx *ctx,
    uint32_t multi_va,
    int32_t option,
    uint32_t value);
int32_t rome2_l83_curl_multi_timeout(
    rome2_l83_curl_state *g,
    uint32_t multi_va,
    int32_t *timeout_ms);
uint32_t rome2_l83_multi_getsock(
    rome2_l83_curl_state *g,
    uint32_t one_easy_va,
    uint32_t *socks,
    int32_t numsocks);
int32_t rome2_l83_multi_timeout(
    rome2_l83_curl_state *g,
    uint32_t multi_va,
    int32_t *timeout_ms);
uint32_t rome2_l83_curl_splay(rome2_l82_curl_ctx *ctx, rome2_curl_timeval_32 i, uint32_t t_va);

/*
 * Formpost (0x10f3fb40, 0x10f403f0, 0x10f40410, 0x10f40670).
 * `args` holds the guest dwords the image reads through its va_list.
 */
int32_t rome2_l83_form_add(
    rome2_l82_curl_ctx *ctx,
    uint32_t httppost_slot_va,
    uint32_t last_post_slot_va,
    const uint32_t *args,
    uint32_t arg_count);
int32_t rome2_l83_curl_formadd(
    rome2_l82_curl_ctx *ctx,
    uint32_t httppost_slot_va,
    uint32_t last_post_slot_va,
    const uint32_t *args,
    uint32_t arg_count);
void rome2_l83_curl_formfree(rome2_l82_curl_ctx *ctx, uint32_t form_va);
uint32_t rome2_l83_form_memdup(rome2_l82_curl_ctx *ctx, uint32_t src_va, uint32_t len);

#endif
