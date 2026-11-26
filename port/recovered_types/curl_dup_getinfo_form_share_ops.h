#ifndef ROME2_CURL_DUP_GETINFO_FORM_SHARE_OPS_H
#define ROME2_CURL_DUP_GETINFO_FORM_SHARE_OPS_H

#include "curl_form_global_easy_multi_ops.h"
#include "guest32_layouts.h"

#include <stdarg.h>
#include <stdint.h>

/*
 * Layer 86: statically linked libcurl handle duplication, getinfo, recv,
 * cookie jar, connection cache, formpost chain, share and multi-init routines,
 * the SSLEAY32 import thunks they reach and the CRT fgets/fread/strtoi64
 * helpers behind them (51 functions, 0x10f10380..0x116c7fcf).
 *
 * Guest objects live in the Layer 82 bump arena and are addressed by guest VA;
 * the Layer 83 state supplies the allocator globals, the random seed and the
 * OpenSSL, write and debug hooks. Field names follow the libcurl source shape
 * the bodies match; they are inference, only the offsets and widths are
 * evidenced.
 *
 * Bounded deviations shared by every routine here:
 *  - a guest pointer outside the arena makes the routine stop early or skip
 *    the access where the image would fault;
 *  - every allocation is served by the Layer 82 bump arena, so an allocation
 *    fails only when the arena is exhausted and a free only counts;
 *  - imports, callback pointers and CRT stream I/O are dispatched to the hooks
 *    below, each documented with the result used when the hook is unset;
 *  - list walks stop after ROME2_L83_WALK_CAP nodes.
 */

#define ROME2_CURL_MULTI_BYTES 0x80u
#define ROME2_L86_RAND_MUL 0x41c64e6du
#define ROME2_L86_RAND_ADD 0x00003039u
#define ROME2_L86_FORM_BOUNDARY_DASHES "----------------------------" /* 0x118467a0 */
#define ROME2_L86_FORM_BOUNDARY_DIGITS "0123456789abcdef"             /* 0x118465f8 */

enum rome2_l86_const {
    ROME2_L86_COOKIE_LINE_BYTES = 5000,     /* malloc(5000) line and value buffers */
    ROME2_L86_COOKIE_NAME_BYTES = 0x400,    /* stack name buffer of Curl_cookie_add */
    ROME2_L86_INFOF_BUFFER_BYTES = 0x801,   /* Curl_infof print buffer */
    ROME2_L86_FORMDATAF_BYTES = 0x1000,     /* AddFormDataf print buffer */
    ROME2_L86_FORM_STDIN_CHUNK = 0x200,     /* Curl_getformdata stdin read size */
    ROME2_L86_FORMGET_CHUNK = 0x2000,       /* curl_formget file read size */
    ROME2_L86_FORM_BOUNDARY_BYTES = 0x29,   /* 28 dashes, 12 hex digits and a NUL */
    ROME2_L86_DNSCACHE_SLOTS = 7,
    ROME2_L86_SOCKHASH_SLOTS = 0x38f,
    ROME2_L86_SSL_SESSIONS_DEFAULT = 8,
    ROME2_L86_CONNC_DEFAULT_SINGLE = 5,
    ROME2_L86_CONNC_DEFAULT_MULTI = 10,
    ROME2_L86_CONNC_MAX = 0x1fffffff,
    ROME2_L86_CRT_EINVAL = 22,
    ROME2_L86_CRT_EOF = -1
};

enum rome2_l86_curlcode {
    ROME2_L86_CURLE_READ_ERROR = 0x1a
};

/* FormData.type values stored by AddFormDataf and Curl_getformdata. */
enum rome2_curl_formtype {
    ROME2_CURL_FORM_DATA = 0,
    ROME2_CURL_FORM_CONTENT = 1,
    ROME2_CURL_FORM_CALLBACK = 2,
    ROME2_CURL_FORM_FILE = 3
};

enum rome2_curlshopt {
    ROME2_CURLSHOPT_SHARE = 1,
    ROME2_CURLSHOPT_UNSHARE = 2,
    ROME2_CURLSHOPT_LOCKFUNC = 3,
    ROME2_CURLSHOPT_UNLOCKFUNC = 4,
    ROME2_CURLSHOPT_USERDATA = 5
};

enum rome2_l86_curl_lock_data {
    ROME2_L86_CURL_LOCK_DATA_COOKIE = 2,
    ROME2_L86_CURL_LOCK_DATA_DNS = 3,
    ROME2_L86_CURL_LOCK_DATA_SSL_SESSION = 4,
    ROME2_L86_CURL_LOCK_DATA_CONNECT = 5
};

/* CURLINFO type mask and the options Curl_getinfo (0x10f1cad0) answers outside its copy tables. */
enum rome2_curlinfo {
    ROME2_CURLINFO_TYPEMASK = 0xf00000,
    ROME2_CURLINFO_STRING = 0x100000,
    ROME2_CURLINFO_LONG = 0x200000,
    ROME2_CURLINFO_DOUBLE = 0x300000,
    ROME2_CURLINFO_SLIST = 0x400000,
    ROME2_CURLINFO_EFFECTIVE_URL = 0x100001,
    ROME2_CURLINFO_PRIMARY_IP = 0x100020,
    ROME2_CURLINFO_LOCAL_IP = 0x100029,
    ROME2_CURLINFO_LASTSOCKET = 0x20001d,
    ROME2_CURLINFO_SSL_ENGINES = 0x40001b,
    ROME2_CURLINFO_COOKIELIST = 0x40001c,
    ROME2_CURLINFO_CERTINFO = 0x400022
};

/* SessionHandle offsets touched by this layer beyond the Layer 83 set. */
enum rome2_l86_easy_off {
    ROME2_L86_EASY_MULTI_OFF = 0x008,
    ROME2_L86_EASY_SET_COOKIESESSION_OFF = 0x218,
    ROME2_L86_EASY_SET_BUFFER_SIZE_OFF = 0x2a0,
    ROME2_L86_EASY_SET_DWORDS = 0xca,               /* UserDefined copied by Curl_dupset */
    ROME2_L86_EASY_SET_STR_BYTES = 0x98,            /* the 38 set.str slots */
    ROME2_L86_EASY_CHANGE_URL_OFF = 0x450,
    ROME2_L86_EASY_CHANGE_URL_ALLOC_OFF = 0x454,
    ROME2_L86_EASY_CHANGE_COOKIELIST_OFF = 0x460,
    ROME2_L86_EASY_COOKIES_OFF = 0x468,
    ROME2_L86_EASY_PROGRESS_CALLBACK_OFF = 0x4a0,
    ROME2_L86_EASY_INFO_PRIMARY_IP_OFF = 0x8714,
    ROME2_L86_EASY_INFO_LOCAL_IP_OFF = 0x8748,
    ROME2_L86_EASY_INFO_CERTS_OFF = 0x877c
};

/* Progress.flags bits Curl_getinfo tests at SessionHandle +0x4a8. */
enum rome2_l86_pgrs_flag {
    ROME2_L86_PGRS_UL_SIZE_KNOWN = 0x20,
    ROME2_L86_PGRS_DL_SIZE_KNOWN = 0x40
};

/* connectdata offsets touched by this layer beyond the Layer 83 set. */
enum rome2_l86_conn_off {
    ROME2_L86_CONN_FCLOSESOCKET_OFF = 0x028,
    ROME2_L86_CONN_CLOSESOCKET_CLIENT_OFF = 0x02c,
    ROME2_L86_CONN_SOCK_ACCEPTED1_OFF = 0x13c,
    ROME2_L86_CONN_RECV_OFF = 0x140,                /* recv[2] */
    ROME2_L86_CONN_SSL_OFF = 0x150,                 /* ssl[2], 0x18 bytes each */
    ROME2_L86_CONN_SSL_CONFIG_OFF = 0x180,
    ROME2_L86_CONN_STREAM_WAS_REWOUND_OFF = 0x214,
    ROME2_L86_CONN_PIPE_OFF = 0x280,                /* send, recv, pend and done pipe llists */
    ROME2_L86_CONN_MASTER_BUFFER_OFF = 0x290,
    ROME2_L86_CONN_READ_POS_OFF = 0x294,
    ROME2_L86_CONN_BUF_LEN_OFF = 0x298,
    ROME2_L86_CONN_ASYNC_HOSTNAME_OFF = 0x3cc,
    ROME2_L86_CONN_ASYNC_OS_SPECIFIC_OFF = 0x3e0,
    ROME2_L86_CONN_LOCALDEV_OFF = 0x498
};

/* Image addresses this layer stores as data. */
enum rome2_l86_image_va {
    ROME2_L86_HASH_ELEMENT_DTOR_VA = 0x10f12780,   /* bucket llist destructor */
    ROME2_L86_HASH_STR_VA = 0x10f126c0,            /* DNS cache hash callback */
    ROME2_L86_STR_KEY_COMPARE_VA = 0x10f12710,     /* DNS cache compare callback */
    ROME2_L86_FREEDNSENTRY_VA = 0x10f13510,        /* DNS cache element destructor */
    ROME2_L86_HASH_FD_VA = 0x10f23070,             /* socket hash callback */
    ROME2_L86_FD_KEY_COMPARE_VA = 0x10f23050,      /* socket hash compare callback */
    ROME2_L86_SH_FREEENTRY_VA = 0x10f244f0,        /* socket hash element destructor (the curl_free body) */
    ROME2_L86_MSGLIST_DTOR_VA = 0x100d6560         /* message list destructor (the folded RET stub) */
};

/* The four by-ordinal SSLEAY32 import thunks (JMP dword ptr [slot]) Curl_ossl_close calls. */
enum rome2_l86_openssl_thunk_id {
    ROME2_L86_SSLEAY32_ORD_8 = 0,  /* 0x116c7f0f -> [0x1172f604] */
    ROME2_L86_SSLEAY32_ORD_48 = 1, /* 0x116c7f81 -> [0x1172f57c] */
    ROME2_L86_SSLEAY32_ORD_96 = 2, /* 0x116c7fc9 -> [0x1172f5ac] */
    ROME2_L86_SSLEAY32_ORD_86 = 3, /* 0x116c7fcf -> [0x1172f5b0] */
    ROME2_L86_OPENSSL_THUNK_COUNT = 4
};

/* thunk_va, iat_slot_va, ordinal, is_ssleay32 */
extern const rome2_l83_openssl_thunk_desc rome2_l86_openssl_thunks[ROME2_L86_OPENSSL_THUNK_COUNT];

typedef struct rome2_l86_curl_state {
    rome2_l83_curl_state *g;

    uint32_t stdin_va;          /* __acrt_iob_func(0): 0x119ebe18 in the image */
    uint32_t lock_file_calls;   /* __lock_file 0x11699f8f */
    uint32_t unlock_file_calls; /* __unlock_file 0x11699fa3 */

    /* By-ordinal SSLEAY32 import behind thunk `id`; unset: returns 0. */
    int32_t (*on_openssl)(struct rome2_l86_curl_state *s, int32_t id, uint32_t a0);
    /* conn->recv[sockindex]; unset: returns -1 leaving *curlcode untouched. */
    int32_t (*on_conn_recv)(
        struct rome2_l86_curl_state *s,
        uint32_t recv_fn_va,
        uint32_t conn_va,
        uint32_t sockindex,
        uint32_t buf_va,
        uint32_t len,
        int32_t *curlcode);
    /* conn->fclosesocket(closesocket_client, sock); unset: returns 0. */
    int32_t (*on_closesocket_cb)(
        struct rome2_l86_curl_state *s,
        uint32_t fn_va,
        uint32_t clientp_va,
        uint32_t sock);
    /* WS2_32 closesocket [0x1172f880]; unset: returns 0. */
    int32_t (*on_closesocket)(struct rome2_l86_curl_state *s, uint32_t sock);
    /* KERNEL32 DeleteCriticalSection [0x1172f1fc]; unset: no effect. */
    void (*on_delete_critical_section)(struct rome2_l86_curl_state *s, uint32_t cs_va);
    /* KERNEL32 WaitForSingleObject(handle, INFINITE) [0x1172f20c]; unset: returns 0 (WAIT_OBJECT_0). */
    uint32_t (*on_wait_for_single_object)(struct rome2_l86_curl_state *s, uint32_t handle, uint32_t ms);
    /* KERNEL32 CloseHandle [0x1172f178]; unset: no effect. */
    void (*on_close_handle)(struct rome2_l86_curl_state *s, uint32_t handle);
    /* curl_formget append(arg, buf, len); unset: returns len. */
    uint32_t (*on_formget_append)(
        struct rome2_l86_curl_state *s,
        uint32_t fn_va,
        uint32_t arg_va,
        const uint8_t *buf,
        uint32_t len);
    /* CRT fopen 0x1168e9a2; returns the guest FILE address; unset: returns 0. */
    uint32_t (*on_fopen)(struct rome2_l86_curl_state *s, const char *path, const char *mode);
    /* CRT fclose 0x1168ed98; unset: returns 0. */
    int32_t (*on_fclose)(struct rome2_l86_curl_state *s, uint32_t stream_va);
    /* CRT fread_s 0x1168ec03; unset: returns 0. */
    uint32_t (*on_fread_s)(
        struct rome2_l86_curl_state *s,
        uint8_t *buffer,
        uint32_t buffer_size,
        uint32_t element_size,
        uint32_t count,
        uint32_t stream_va);
    /* CRT _stat64 0x11699af7 reduced to the st_size it reports; unset: returns -1. */
    int32_t (*on_stat64)(struct rome2_l86_curl_state *s, const char *path, int64_t *st_size);
    /* CRT refill-and-read 0x116ab534 behind _fgetc_nolock; unset: returns -1 (EOF). */
    int32_t (*on_stream_refill)(struct rome2_l86_curl_state *s, uint32_t stream_va);
    /* CRT ANSI-stream check 0x1168b8a6; unset: returns 1. */
    uint8_t (*on_stream_is_ansi)(struct rome2_l86_curl_state *s, uint32_t stream_va);
} rome2_l86_curl_state;

void rome2_l86_state_init(rome2_l86_curl_state *s, rome2_l83_curl_state *g);

/* CRT helpers (0x11683da0, 0x1168ebe6, 0x1168ee1c, 0x1168eed4, 0x1168eede, 0x1169de5f, 0x1169ece3, 0x1169ed1f) */
double rome2_l86_crt_ltod3(uint32_t lo, int32_t hi);
uint32_t rome2_l86_crt_fread(
    rome2_l86_curl_state *s,
    uint8_t *buffer,
    uint32_t element_size,
    uint32_t count,
    uint32_t stream_va);
uint32_t rome2_l86_crt_common_fgets(
    rome2_l86_curl_state *s,
    uint32_t buf_va,
    int32_t count,
    uint32_t stream_va);
void rome2_l86_crt_fgets_unlock_funclet(rome2_l86_curl_state *s, uint32_t stream_va);
uint32_t rome2_l86_crt_fgets(
    rome2_l86_curl_state *s,
    uint32_t buf_va,
    int32_t count,
    uint32_t stream_va);
int64_t rome2_l86_crt_strtoi64(
    rome2_l86_curl_state *s,
    const char *str,
    const char **endptr,
    int32_t radix);
int32_t rome2_l86_crt_fgetc_nolock(rome2_l86_curl_state *s, uint32_t stream_va);
int32_t rome2_l86_crt_fgetc_nolock_stub(rome2_l86_curl_state *s, uint32_t stream_va);

/* String, random, list and hash helpers (0x10f1ed80, 0x10f20900, 0x10f20dd0, 0x10f21130, 0x10f21150, 0x10f122e0, 0x10f131e0, 0x10f10b90, 0x10f40780) */
uint32_t rome2_l86_curl_rand(rome2_l83_curl_state *g);
char *rome2_l86_curl_strtok_r(char *ptr, const char *sep, char **end);
int32_t rome2_l86_curl_raw_nequal(const char *first, const char *second, uint32_t max);
const void *rome2_l86_curl_memrchr(const void *s, int32_t c, uint32_t n);
uint32_t rome2_l86_curl_llist_alloc(rome2_l82_curl_ctx *ctx, uint32_t dtor_va);
uint32_t rome2_l86_curl_hash_alloc(
    rome2_l82_curl_ctx *ctx,
    int32_t slots,
    uint32_t hfunc_va,
    uint32_t comp_va,
    uint32_t dtor_va);
uint32_t rome2_l86_curl_mk_dnscache(rome2_l82_curl_ctx *ctx);
uint32_t rome2_l86_curl_slist_duplicate(rome2_l82_curl_ctx *ctx, uint32_t inlist_va);
uint32_t rome2_l86_strippath(rome2_l82_curl_ctx *ctx, uint32_t fullfile_va);

/* Connection teardown and cache (0x10f127d0, 0x10f12bf0, 0x10f15a00, 0x10f15cd0, 0x10f16080, 0x10f17aa0, 0x10f17fd0, 0x10f1d9a0, 0x10f214e0, 0x10f249a0, 0x10f2d2b0, four thunks) */
int32_t rome2_l86_openssl_thunk(rome2_l86_curl_state *s, int32_t id, uint32_t a0);
void rome2_l86_curl_ossl_close(rome2_l86_curl_state *s, uint32_t conn_va, int32_t sockindex);
void rome2_l86_curl_ssl_close(rome2_l86_curl_state *s, uint32_t conn_va, int32_t sockindex);
uint32_t rome2_l86_curl_ssl_engines_list(rome2_l86_curl_state *s, uint32_t data_va);
void rome2_l86_curl_free_ssl_config(rome2_l82_curl_ctx *ctx, uint32_t sslc_va);
void rome2_l86_curl_freeaddrinfo(rome2_l82_curl_ctx *ctx, uint32_t ai_va);
int32_t rome2_l86_curl_thread_join(rome2_l86_curl_state *s, uint32_t hnd_va);
void rome2_l86_destroy_thread_sync_data(rome2_l86_curl_state *s, uint32_t tsd_va);
void rome2_l86_curl_resolver_cancel(rome2_l86_curl_state *s, uint32_t conn_va);
int32_t rome2_l86_curl_closesocket(rome2_l86_curl_state *s, uint32_t conn_va, uint32_t sock);
uint32_t rome2_l86_curl_mk_connc(rome2_l82_curl_ctx *ctx, int32_t type, int32_t amount);
void rome2_l86_curl_rm_connc(rome2_l86_curl_state *s, uint32_t c_va);

/* Easy handle duplication, info and receive (0x10f10380, 0x10f10580, 0x10f107c0, 0x10f176a0, 0x10f1cad0, 0x10f1d330, 0x10f1d3f0, 0x10f223b0, 0x10f22aa0) */
int32_t rome2_l86_curl_dupset(rome2_l82_curl_ctx *ctx, uint32_t dst_va, uint32_t src_va);
uint32_t rome2_l86_curl_easy_duphandle(rome2_l86_curl_state *s, uint32_t incurl_va);
int32_t rome2_l86_curl_getinfo(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t info,
    uint32_t param_va);
int32_t rome2_l86_curl_easy_getinfo(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t info,
    uint32_t param_va);
void rome2_l86_curl_infof(rome2_l86_curl_state *s, uint32_t data_va, const char *fmt, ...);
uint32_t rome2_l86_curl_multi_can_pipeline(const rome2_l82_curl_ctx *ctx, uint32_t multi_va);
int32_t rome2_l86_curl_read(
    rome2_l86_curl_state *s,
    uint32_t conn_va,
    uint32_t sockfd,
    uint32_t buf_va,
    uint32_t sizerequested,
    int32_t *n);
int32_t rome2_l86_curl_easy_recv(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t buffer_va,
    uint32_t buflen,
    int32_t *n);
uint32_t rome2_l86_curl_multi_init(rome2_l86_curl_state *s);

/* Cookie jar (0x10f10cd0, 0x10f11a80, 0x10f11be0, 0x10f120c0) and share options (0x10f20af0) */
void rome2_l86_freecookie(rome2_l82_curl_ctx *ctx, uint32_t co_va);
uint32_t rome2_l86_curl_cookie_add(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t c_va,
    uint32_t httpheader,
    uint32_t lineptr_va,
    uint32_t domain_va,
    uint32_t path_va);
uint32_t rome2_l86_curl_cookie_init(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t file_va,
    uint32_t inc_va,
    uint32_t newsession);
uint32_t rome2_l86_curl_cookie_list(rome2_l86_curl_state *s, uint32_t data_va);
int32_t rome2_l86_curl_share_setopt(
    rome2_l86_curl_state *s,
    uint32_t share_va,
    int32_t option,
    uint32_t param);

/*
 * Formpost chain (0x10f3f060, 0x10f3f140, 0x10f3f2d0, 0x10f3f340, 0x10f404a0).
 * The chain tail, chain head and running size are stack slots in the image and
 * host variables here; format arguments are host values.
 */
int32_t rome2_l86_add_form_dataf(
    rome2_l82_curl_ctx *ctx,
    uint32_t *formp_va,
    int64_t *size,
    const char *fmt,
    ...);
uint32_t rome2_l86_curl_form_boundary(rome2_l83_curl_state *g);
void rome2_l86_curl_formclean(rome2_l82_curl_ctx *ctx, uint32_t *form_va);
int32_t rome2_l86_curl_getformdata(
    rome2_l86_curl_state *s,
    uint32_t data_va,
    uint32_t *finalform_va,
    uint32_t post_va,
    uint32_t custom_content_type_va,
    int64_t *sizep);
int32_t rome2_l86_curl_formget(
    rome2_l86_curl_state *s,
    uint32_t form_va,
    uint32_t arg_va,
    uint32_t append_fn_va);

#endif
