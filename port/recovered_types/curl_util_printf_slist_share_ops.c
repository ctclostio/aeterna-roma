#include "curl_util_printf_slist_share_ops.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

void rome2_l82_ctx_init(
    rome2_l82_curl_ctx *ctx,
    uint8_t *arena_bytes,
    uint32_t base_va,
    uint32_t arena_size,
    uint32_t heap_start_va) {
    if (!ctx) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->arena_bytes = arena_bytes;
    ctx->arena_base_va = base_va;
    ctx->arena_size = arena_size;
    ctx->heap_cursor = (heap_start_va >= base_va) ? heap_start_va : base_va;
}

void *rome2_l82_mut_ptr(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t bytes) {
    if (!ctx || !ctx->arena_bytes || va < ctx->arena_base_va) {
        return NULL;
    }
    uint64_t off = (uint64_t)(va - ctx->arena_base_va);
    if (off + (uint64_t)bytes > (uint64_t)ctx->arena_size) {
        return NULL;
    }
    return ctx->arena_bytes + off;
}

const void *rome2_l82_const_ptr(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t bytes) {
    return rome2_l82_mut_ptr(ctx, va, bytes);
}

uint32_t rome2_l82_alloc(rome2_l82_curl_ctx *ctx, uint32_t size) {
    if (!ctx || !ctx->arena_bytes) {
        return 0u;
    }
    uint32_t aligned = (size == 0u) ? 4u : ((size + 3u) & ~3u);
    uint64_t off = (uint64_t)(ctx->heap_cursor - ctx->arena_base_va);
    if (off + (uint64_t)aligned > (uint64_t)ctx->arena_size) {
        return 0u;
    }
    uint32_t va = ctx->heap_cursor;
    ctx->heap_cursor += aligned;
    ctx->alloc_count++;
    return va;
}

uint32_t rome2_l82_calloc(rome2_l82_curl_ctx *ctx, uint32_t nmemb, uint32_t size) {
    uint64_t total = (uint64_t)nmemb * (uint64_t)size;
    if (total > 0x7fffffffULL) {
        return 0u;
    }
    uint32_t va = rome2_l82_alloc(ctx, (uint32_t)total);
    if (va == 0u) {
        return 0u;
    }
    uint32_t nbytes = (total == 0u) ? 4u : (uint32_t)total;
    void *p = rome2_l82_mut_ptr(ctx, va, nbytes);
    if (p) {
        memset(p, 0, nbytes);
    }
    return va;
}

uint32_t rome2_l82_strdup_va(rome2_l82_curl_ctx *ctx, const char *s) {
    if (!ctx || !s) {
        return 0u;
    }
    size_t n = strlen(s) + 1u;
    if (n > 0x7ffffffeu) {
        return 0u;
    }
    uint32_t va = rome2_l82_alloc(ctx, (uint32_t)n);
    if (va == 0u) {
        return 0u;
    }
    void *dst = rome2_l82_mut_ptr(ctx, va, (uint32_t)n);
    if (dst) {
        memcpy(dst, s, n);
    }
    return va;
}

/* 0x10f244f0 */
void rome2_l82_curl_free(rome2_l82_curl_ctx *ctx, uint32_t ptr_va) {
    if (ctx && ptr_va != 0u) {
        ctx->free_count++;
    }
}

/* 0x10f10c20 */
uint32_t rome2_l82_curl_slist_append(rome2_l82_curl_ctx *ctx, uint32_t list_va, const char *data) {
    if (!ctx || !data) {
        return 0u;
    }
    uint32_t node_va = rome2_l82_alloc(ctx, (uint32_t)sizeof(rome2_curl_slist_32));
    if (node_va == 0u) {
        return 0u;
    }
    uint32_t dup_va = rome2_l82_strdup_va(ctx, data);
    if (dup_va == 0u) {
        rome2_l82_curl_free(ctx, node_va);
        return 0u;
    }
    rome2_curl_slist_32 *node = (rome2_curl_slist_32 *)rome2_l82_mut_ptr(
        ctx, node_va, (uint32_t)sizeof(*node));
    if (!node) {
        return 0u;
    }
    node->data_va = dup_va;
    node->next_va = 0u;
    if (list_va == 0u) {
        return node_va;
    }
    uint32_t cur_va = list_va;
    uint32_t guard = 0u;
    while (cur_va != 0u && guard < 4096u) {
        guard++;
        rome2_curl_slist_32 *cur = (rome2_curl_slist_32 *)rome2_l82_mut_ptr(
            ctx, cur_va, (uint32_t)sizeof(*cur));
        if (!cur) {
            return list_va;
        }
        if (cur->next_va == 0u) {
            cur->next_va = node_va;
            break;
        }
        cur_va = cur->next_va;
    }
    return list_va;
}

/* 0x10f10c90 */
void rome2_l82_curl_slist_free_all(rome2_l82_curl_ctx *ctx, uint32_t list_va) {
    uint32_t cur_va = list_va;
    uint32_t guard = 0u;
    while (ctx && cur_va != 0u && guard < 4096u) {
        guard++;
        rome2_curl_slist_32 *cur = (rome2_curl_slist_32 *)rome2_l82_mut_ptr(
            ctx, cur_va, (uint32_t)sizeof(*cur));
        if (!cur) {
            break;
        }
        uint32_t next_va = cur->next_va;
        if (cur->data_va != 0u) {
            rome2_l82_curl_free(ctx, cur->data_va);
            cur->data_va = 0u;
        }
        rome2_l82_curl_free(ctx, cur_va);
        cur_va = next_va;
    }
}

/* 0x10f11670 */
void rome2_l82_curl_cookie_cleanup(rome2_l82_curl_ctx *ctx, uint32_t c_va) {
    if (!ctx || c_va == 0u) {
        return;
    }
    rome2_curl_cookie_info_32 *ci = (rome2_curl_cookie_info_32 *)rome2_l82_mut_ptr(
        ctx, c_va, (uint32_t)sizeof(*ci));
    if (!ci) {
        return;
    }
    if (ci->filename_va != 0u) {
        rome2_l82_curl_free(ctx, ci->filename_va);
    }
    uint32_t co_va = ci->cookies_va;
    uint32_t guard = 0u;
    while (co_va != 0u && guard < 4096u) {
        guard++;
        rome2_curl_cookie_32 *co = (rome2_curl_cookie_32 *)rome2_l82_mut_ptr(
            ctx, co_va, (uint32_t)sizeof(*co));
        if (!co) {
            break;
        }
        uint32_t next_va = co->next_va;
        rome2_l82_curl_free(ctx, co->spath_va);
        rome2_l82_curl_free(ctx, co->domain_va);
        rome2_l82_curl_free(ctx, co->path_va);
        rome2_l82_curl_free(ctx, co->name_va);
        rome2_l82_curl_free(ctx, co->value_va);
        rome2_l82_curl_free(ctx, co->maxage_va);
        rome2_l82_curl_free(ctx, co->version_va);
        rome2_l82_curl_free(ctx, co_va);
        co_va = next_va;
    }
    rome2_l82_curl_free(ctx, c_va);
}

/* 0x10f21190 */
void rome2_l82_curl_llist_destroy(rome2_l82_curl_ctx *ctx, uint32_t list_va, uint32_t user_va) {
    if (!ctx || list_va == 0u) {
        return;
    }
    rome2_curl_llist_32 *list = (rome2_curl_llist_32 *)rome2_l82_mut_ptr(
        ctx, list_va, (uint32_t)sizeof(*list));
    if (!list) {
        return;
    }
    uint32_t guard = 0u;
    while (list->size > 0u && guard < 4096u) {
        guard++;
        uint32_t elem_va = list->tail_va;
        if (elem_va == 0u) {
            break;
        }
        rome2_curl_llist_element_32 *elem = (rome2_curl_llist_element_32 *)rome2_l82_mut_ptr(
            ctx, elem_va, (uint32_t)sizeof(*elem));
        if (!elem) {
            break;
        }
        uint32_t next_va = elem->next_va;
        uint32_t prev_va = elem->prev_va;
        uint32_t payload_va = elem->ptr_va;
        if (elem_va == list->head_va) {
            list->head_va = next_va;
            if (next_va == 0u) {
                list->tail_va = 0u;
            } else {
                rome2_curl_llist_element_32 *nxt = (rome2_curl_llist_element_32 *)rome2_l82_mut_ptr(
                    ctx, next_va, (uint32_t)sizeof(*nxt));
                if (nxt) {
                    nxt->prev_va = 0u;
                }
            }
        } else {
            rome2_curl_llist_element_32 *prv = (rome2_curl_llist_element_32 *)rome2_l82_mut_ptr(
                ctx, prev_va, (uint32_t)sizeof(*prv));
            if (prv) {
                prv->next_va = next_va;
            }
            if (next_va == 0u) {
                list->tail_va = prev_va;
            } else {
                rome2_curl_llist_element_32 *nxt = (rome2_curl_llist_element_32 *)rome2_l82_mut_ptr(
                    ctx, next_va, (uint32_t)sizeof(*nxt));
                if (nxt) {
                    nxt->prev_va = prev_va;
                }
            }
        }
        if (ctx->on_llist_dtor && list->dtor_fn_va != 0u) {
            ctx->on_llist_dtor(ctx, list->dtor_fn_va, user_va, payload_va);
        }
        elem->ptr_va = 0u;
        elem->prev_va = 0u;
        elem->next_va = 0u;
        rome2_l82_curl_free(ctx, elem_va);
        list->size--;
    }
    rome2_l82_curl_free(ctx, list_va);
}

/* 0x10f12500 */
void rome2_l82_curl_hash_destroy(rome2_l82_curl_ctx *ctx, uint32_t hash_va) {
    if (!ctx || hash_va == 0u) {
        return;
    }
    rome2_curl_hash_32 *h = (rome2_curl_hash_32 *)rome2_l82_mut_ptr(
        ctx, hash_va, (uint32_t)sizeof(*h));
    if (!h) {
        return;
    }
    if (h->table_va != 0u && h->slots > 0) {
        uint32_t nslots = (uint32_t)h->slots;
        uint32_t *buckets = (uint32_t *)rome2_l82_mut_ptr(ctx, h->table_va, nslots * 4u);
        for (uint32_t i = 0u; buckets && i < nslots; ++i) {
            if (buckets[i] != 0u) {
                rome2_l82_curl_llist_destroy(ctx, buckets[i], hash_va);
                buckets[i] = 0u;
            }
        }
        rome2_l82_curl_free(ctx, h->table_va);
    }
    h->table_va = 0u;
    h->size = 0u;
    h->slots = 0;
    rome2_l82_curl_free(ctx, hash_va);
}

/* 0x116c7f4b */
void rome2_l82_imp_ssl_session_free(rome2_l82_curl_ctx *ctx, uint32_t ssl_session_va) {
    if (!ctx || ssl_session_va == 0u) {
        return;
    }
    ctx->ssl_session_free_calls++;
    if (ctx->on_ssl_session_free) {
        ctx->on_ssl_session_free(ctx, ssl_session_va);
    }
}

/* 0x10f2d4f0 */
void rome2_l82_thunk_ssl_session_free(rome2_l82_curl_ctx *ctx, uint32_t ssl_session_va) {
    rome2_l82_imp_ssl_session_free(ctx, ssl_session_va);
}

/* 0x10f16310 */
void rome2_l82_curl_ssl_kill_session(rome2_l82_curl_ctx *ctx, uint32_t session_entry_va) {
    if (!ctx || session_entry_va == 0u) {
        return;
    }
    rome2_curl_ssl_sessionid_32 *s = (rome2_curl_ssl_sessionid_32 *)rome2_l82_mut_ptr(
        ctx, session_entry_va, (uint32_t)sizeof(*s));
    if (!s || s->sessionid_va == 0u) {
        return;
    }
    rome2_l82_thunk_ssl_session_free(ctx, s->sessionid_va);
    s->sessionid_va = 0u;
    s->idsize = 0u;
    rome2_l82_curl_free(ctx, s->cafile_va);
    s->cafile_va = 0u;
    rome2_l82_curl_free(ctx, s->capath_va);
    s->capath_va = 0u;
    rome2_l82_curl_free(ctx, s->random_file_va);
    s->random_file_va = 0u;
    rome2_l82_curl_free(ctx, s->egdsocket_va);
    s->egdsocket_va = 0u;
    rome2_l82_curl_free(ctx, s->cipher_list_va);
    s->cipher_list_va = 0u;
    rome2_l82_curl_free(ctx, s->name_va);
    s->name_va = 0u;
}

/* 0x10f20ad0 */
uint32_t rome2_l82_curl_share_init(rome2_l82_curl_ctx *ctx) {
    uint32_t share_va = rome2_l82_calloc(ctx, 1u, (uint32_t)sizeof(rome2_curl_share_32));
    if (share_va == 0u) {
        return 0u;
    }
    rome2_curl_share_32 *sh = (rome2_curl_share_32 *)rome2_l82_mut_ptr(
        ctx, share_va, (uint32_t)sizeof(*sh));
    if (sh) {
        sh->specifier |= 2u;
    }
    return share_va;
}

/* 0x10f20a00 */
int32_t rome2_l82_curl_share_cleanup(rome2_l82_curl_ctx *ctx, uint32_t share_va) {
    if (!ctx || share_va == 0u) {
        return ROME2_CURLSHE_INVALID;
    }
    rome2_curl_share_32 *sh = (rome2_curl_share_32 *)rome2_l82_mut_ptr(
        ctx, share_va, (uint32_t)sizeof(*sh));
    if (!sh) {
        return ROME2_CURLSHE_INVALID;
    }
    if (ctx->on_share_lock && sh->lockfunc_va != 0u) {
        ctx->on_share_lock(
            ctx, sh->lockfunc_va, ROME2_CURL_LOCK_DATA_SHARE,
            ROME2_CURL_LOCK_ACCESS_SINGLE, sh->clientdata_va);
    }
    if (sh->dirty != 0u) {
        if (ctx->on_share_unlock && sh->unlockfunc_va != 0u) {
            ctx->on_share_unlock(
                ctx, sh->unlockfunc_va, ROME2_CURL_LOCK_DATA_SHARE, sh->clientdata_va);
        }
        return ROME2_CURLSHE_IN_USE;
    }
    if (sh->hostcache_va != 0u) {
        rome2_l82_curl_hash_destroy(ctx, sh->hostcache_va);
        sh->hostcache_va = 0u;
    }
    if (sh->cookies_va != 0u) {
        rome2_l82_curl_cookie_cleanup(ctx, sh->cookies_va);
    }
    if (sh->sslsession_va != 0u) {
        for (uint32_t i = 0u; i < sh->max_ssl_sessions; ++i) {
            uint32_t entry_va = sh->sslsession_va +
                                (i * (uint32_t)sizeof(rome2_curl_ssl_sessionid_32));
            rome2_l82_curl_ssl_kill_session(ctx, entry_va);
        }
        rome2_l82_curl_free(ctx, sh->sslsession_va);
    }
    if (ctx->on_share_unlock && sh->unlockfunc_va != 0u) {
        ctx->on_share_unlock(
            ctx, sh->unlockfunc_va, ROME2_CURL_LOCK_DATA_SHARE, sh->clientdata_va);
    }
    rome2_l82_curl_free(ctx, share_va);
    return ROME2_CURLSHE_OK;
}

/* 0x10f21aa0 */
const char *rome2_l82_curl_easy_strerror(int32_t code) {
    switch (code) {
    case 0: return "No error";
    case 1: return "Unsupported protocol";
    case 2: return "Failed initialization";
    case 3: return "URL using bad/illegal format or missing URL";
    case 4: return "A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision.";
    case 5: return "Couldn't resolve proxy name";
    case 6: return "Couldn't resolve host name";
    case 7: return "Couldn't connect to server";
    case 8: return "FTP: weird server reply";
    case 9: return "Access denied to remote resource";
    case 10: return "FTP: The server failed to connect to data port";
    case 11: return "FTP: unknown PASS reply";
    case 12: return "FTP: Accepting server connect has timed out";
    case 13: return "FTP: unknown PASV reply";
    case 14: return "FTP: unknown 227 response format";
    case 15: return "FTP: can't figure out the host in the PASV response";
    case 17: return "FTP: couldn't set file type";
    case 18: return "Transferred a partial file";
    case 19: return "FTP: couldn't retrieve (RETR failed) the specified file";
    case 21: return "Quote command returned error";
    case 22: return "HTTP response code said error";
    case 23: return "Failed writing received data to disk/application";
    case 25: return "Upload failed (at start/before it took off)";
    case 26: return "Failed to open/read local data from file/application";
    case 27: return "Out of memory";
    case 28: return "Timeout was reached";
    case 30: return "FTP: command PORT failed";
    case 31: return "FTP: command REST failed";
    case 33: return "Requested range was not delivered by the server";
    case 34: return "Internal problem setting up the POST";
    case 35: return "SSL connect error";
    case 36: return "Couldn't resume download";
    case 37: return "Couldn't read a file:// file";
    case 38: return "LDAP: cannot bind";
    case 39: return "LDAP: search failed";
    case 41: return "A required function in the library was not found";
    case 42: return "Operation was aborted by an application callback";
    case 43: return "A libcurl function was given a bad argument";
    case 45: return "Failed binding local connection end";
    case 47: return "Number of redirects hit maximum amount";
    case 48: return "An unknown option was passed in to libcurl";
    case 49: return "Malformed telnet option";
    case 51: return "SSL peer certificate or SSH remote key was not OK";
    case 52: return "Server returned nothing (no headers, no data)";
    case 53: return "SSL crypto engine not found";
    case 54: return "Can not set SSL crypto engine as default";
    case 55: return "Failed sending data to the peer";
    case 56: return "Failure when receiving data from the peer";
    case 58: return "Problem with the local SSL certificate";
    case 59: return "Couldn't use specified SSL cipher";
    case 60: return "Peer certificate cannot be authenticated with given CA certificates";
    case 61: return "Unrecognized or bad HTTP Content or Transfer-Encoding";
    case 62: return "Invalid LDAP URL";
    case 63: return "Maximum file size exceeded";
    case 64: return "Requested SSL level failed";
    case 65: return "Send failed since rewinding of the data stream failed";
    case 66: return "Failed to initialise SSL crypto engine";
    case 67: return "Login denied";
    case 68: return "TFTP: File Not Found";
    case 69: return "TFTP: Access Violation";
    case 70: return "Disk full or allocation exceeded";
    case 71: return "TFTP: Illegal operation";
    case 72: return "TFTP: Unknown transfer ID";
    case 73: return "Remote file already exists";
    case 74: return "TFTP: No such user";
    case 75: return "Conversion failed";
    case 76: return "Caller must register CURLOPT_CONV_ callback options";
    case 77: return "Problem with the SSL CA cert (path? access rights?)";
    case 78: return "Remote file not found";
    case 79: return "Error in the SSH layer";
    case 80: return "Failed to shut down the SSL connection";
    case 81: return "Socket not ready for send/recv";
    case 82: return "Failed to load CRL file (path? access rights?, format?)";
    case 83: return "Issuer check against peer certificate failed";
    case 84: return "FTP: The server did not accept the PRET command.";
    case 85: return "RTSP CSeq mismatch or invalid CSeq";
    case 86: return "RTSP session error";
    case 87: return "Unable to parse FTP file list";
    case 88: return "Chunk callback failed";
    default: return "Unknown error";
    }
}

/* 0x10f21e00 */
const char *rome2_l82_curl_multi_strerror(int32_t code) {
    switch (code) {
    case -1: return "Please call curl_multi_perform() soon";
    case 0: return "No error";
    case 1: return "Invalid multi handle";
    case 2: return "Invalid easy handle";
    case 3: return "Out of memory";
    case 4: return "Internal error";
    case 5: return "Invalid socket argument";
    case 6: return "Unknown option";
    default: return "Unknown error";
    }
}

/* 0x10f21e70 */
const char *rome2_l82_curl_share_strerror(int32_t code) {
    switch (code) {
    case 0: return "No error";
    case 1: return "Unknown share option";
    case 2: return "Share currently in use";
    case 3: return "Invalid share handle";
    case 4: return "Out of memory";
    case 5: return "Feature not enabled in this library";
    default: return "CURLSHcode unknown";
    }
}

/* 0x1169df5b..0x1169e3b2 */
int32_t rome2_l82_crt_isalnum_l(int32_t ch) {
    return isalnum((unsigned char)ch) ? 1 : 0;
}

int32_t rome2_l82_crt_isalpha_l(int32_t ch) {
    return isalpha((unsigned char)ch) ? 1 : 0;
}

int32_t rome2_l82_crt_isdigit_l(int32_t ch) {
    return isdigit((unsigned char)ch) ? 1 : 0;
}

int32_t rome2_l82_crt_isxdigit_l(int32_t ch) {
    return isxdigit((unsigned char)ch) ? 1 : 0;
}

int32_t rome2_l82_crt_isalnum(int32_t ch) {
    return rome2_l82_crt_isalnum_l(ch);
}

int32_t rome2_l82_crt_isalpha(int32_t ch) {
    return rome2_l82_crt_isalpha_l(ch);
}

int32_t rome2_l82_crt_isdigit(int32_t ch) {
    return rome2_l82_crt_isdigit_l(ch);
}

int32_t rome2_l82_crt_isxdigit(int32_t ch) {
    return rome2_l82_crt_isxdigit_l(ch);
}

/* 0x116d74e3 */
int32_t rome2_l82_ascii_stricmp(const char *s1, const char *s2) {
    if (!s1 || !s2) {
        return 0x7fffffff;
    }
    uint32_t u1 = 0u;
    uint32_t u2 = 0u;
    do {
        u1 = (uint32_t)(uint8_t)*s1++;
        if (u1 - 0x41u < 0x1au) {
            u1 += 0x20u;
        }
        u2 = (uint32_t)(uint8_t)*s2++;
        if (u2 - 0x41u < 0x1au) {
            u2 += 0x20u;
        }
    } while (u1 == u2 && u1 != 0u);
    return (int32_t)u1 - (int32_t)u2;
}

/* 0x116d7565 */
int32_t rome2_l82_stricmp_l(rome2_l82_curl_ctx *ctx, const char *s1, const char *s2) {
    if (!s1 || !s2) {
        if (ctx) {
            ctx->last_errno = EINVAL;
        }
        return 0x7fffffff;
    }
    return rome2_l82_ascii_stricmp(s1, s2);
}

/* 0x116d751c */
int32_t rome2_l82_stricmp(rome2_l82_curl_ctx *ctx, const char *s1, const char *s2) {
    if (ctx && ctx->use_locale_stricmp) {
        return rome2_l82_stricmp_l(ctx, s1, s2);
    }
    if (!s1 || !s2) {
        if (ctx) {
            ctx->last_errno = EINVAL;
        }
        return 0x7fffffff;
    }
    return rome2_l82_ascii_stricmp(s1, s2);
}

/* 0x10f1ee30 */
uint8_t rome2_l82_curl_strequal(rome2_l82_curl_ctx *ctx, const char *s1, const char *s2) {
    return rome2_l82_stricmp(ctx, s1, s2) == 0 ? 1u : 0u;
}

/* 0x10f1ee50 */
uint8_t rome2_l82_curl_strnequal(const char *s1, const char *s2, size_t maxcount) {
    if (!s1 || !s2) {
        return (s1 == s2) ? 1u : 0u;
    }
    for (size_t i = 0u; i < maxcount; ++i) {
        uint8_t a = (uint8_t)s1[i];
        uint8_t b = (uint8_t)s2[i];
        if (a - 'A' < 26u) {
            a = (uint8_t)(a + 0x20u);
        }
        if (b - 'A' < 26u) {
            b = (uint8_t)(b + 0x20u);
        }
        if (a != b) {
            return 0u;
        }
        if (a == 0u) {
            break;
        }
    }
    return 1u;
}

/* 0x10f20f40 */
char rome2_l82_curl_raw_toupper(char in) {
    if (in >= 'a' && in <= 'z') {
        return (char)(in - ('a' - 'A'));
    }
    return in;
}

/* 0x10f20c90 */
uint8_t rome2_l82_curl_raw_equal(const char *first, const char *second) {
    if (!first || !second) {
        return 0u;
    }
    while (*first != '\0' && *second != '\0') {
        if (rome2_l82_curl_raw_toupper(*first) != rome2_l82_curl_raw_toupper(*second)) {
            break;
        }
        first++;
        second++;
    }
    return rome2_l82_curl_raw_toupper(*first) == rome2_l82_curl_raw_toupper(*second) ? 1u : 0u;
}

/* 0x10f3bf70 */
int32_t rome2_l82_curlx_uztosi(uint32_t u) {
    return (int32_t)(u & 0x7fffffffu);
}

/* 0x10f3bf90 */
uint8_t rome2_l82_identity_u8(uint8_t v) {
    return v;
}

/* 0x1169e98f */
void rome2_l82_crt_unlock_env_nop(void) {
}

/* 0x1169e919 */
const char *rome2_l82_common_getenv(rome2_l82_curl_ctx *ctx, const char *name) {
    if (!name || strlen(name) >= 0x7fffu) {
        if (ctx) {
            ctx->last_errno = EINVAL;
        }
        return NULL;
    }
    const char *val = NULL;
    if (ctx && ctx->on_getenv) {
        val = ctx->on_getenv(ctx, name);
    }
    rome2_l82_crt_unlock_env_nop();
    return val;
}

/* 0x1169eccd */
const char *rome2_l82_getenv_thunk(rome2_l82_curl_ctx *ctx, const char *name) {
    return rome2_l82_common_getenv(ctx, name);
}

/* 0x10f3ae20 */
uint32_t rome2_l82_curl_getenv(rome2_l82_curl_ctx *ctx, const char *name) {
    if (!ctx || !name) {
        return 0u;
    }
    const char *env = rome2_l82_getenv_thunk(ctx, name);
    if (!env || env[0] == '\0') {
        return 0u;
    }
    return rome2_l82_strdup_va(ctx, env);
}

static uint8_t l82_is_unreserved(uint8_t ch) {
    if ((ch >= '0' && ch <= '9') ||
        (ch >= 'A' && ch <= 'Z') ||
        (ch >= 'a' && ch <= 'z')) {
        return 1u;
    }
    return (ch == '-' || ch == '.' || ch == '_' || ch == '~') ? 1u : 0u;
}

/* 0x10f3af80 */
uint32_t rome2_l82_curl_easy_escape(
    rome2_l82_curl_ctx *ctx,
    uint32_t handle_va,
    const char *string,
    int32_t inlength) {
    (void)handle_va;
    if (!ctx || !string) {
        return 0u;
    }
    size_t slen = (inlength == 0) ? strlen(string) : (size_t)inlength;
    if (slen > 0x1fffffffu) {
        return 0u;
    }
    /* Worst case: every char becomes %XX (3 bytes per char + 1 NUL). */
    size_t max_bytes = slen * 3u + 1u;
    uint32_t out_va = rome2_l82_alloc(ctx, (uint32_t)max_bytes);
    if (out_va == 0u) {
        return 0u;
    }
    char *out = (char *)rome2_l82_mut_ptr(ctx, out_va, (uint32_t)max_bytes);
    if (!out) {
        return 0u;
    }
    static const char hex[] = "0123456789ABCDEF";
    size_t pos = 0u;
    for (size_t i = 0u; i < slen; ++i) {
        uint8_t ch = (uint8_t)string[i];
        if (l82_is_unreserved(ch)) {
            out[pos++] = (char)ch;
        } else {
            out[pos++] = '%';
            out[pos++] = hex[(ch >> 4u) & 0xfu];
            out[pos++] = hex[ch & 0xfu];
        }
    }
    out[pos] = '\0';
    return out_va;
}

/* 0x10f3b1b0 */
uint32_t rome2_l82_curl_escape(rome2_l82_curl_ctx *ctx, const char *string, int32_t inlength) {
    return rome2_l82_curl_easy_escape(ctx, 0u, string, inlength);
}

static int32_t l82_hex_val(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* 0x10f3b0c0 */
uint32_t rome2_l82_curl_easy_unescape(
    rome2_l82_curl_ctx *ctx,
    uint32_t handle_va,
    const char *string,
    int32_t inlength,
    int32_t *outlength) {
    (void)handle_va;
    if (!ctx || !string) {
        return 0u;
    }
    size_t slen = (inlength == 0) ? strlen(string) : (size_t)inlength;
    uint32_t out_va = rome2_l82_alloc(ctx, (uint32_t)(slen + 1u));
    if (out_va == 0u) {
        return 0u;
    }
    char *out = (char *)rome2_l82_mut_ptr(ctx, out_va, (uint32_t)(slen + 1u));
    if (!out) {
        return 0u;
    }
    size_t i = 0u;
    size_t o = 0u;
    while (i < slen) {
        uint8_t ch = (uint8_t)string[i];
        if (ch == '%' && (i + 2u) < slen &&
            rome2_l82_crt_isxdigit((uint8_t)string[i + 1u]) &&
            rome2_l82_crt_isxdigit((uint8_t)string[i + 2u])) {
            int32_t hi = l82_hex_val(string[i + 1u]);
            int32_t lo = l82_hex_val(string[i + 2u]);
            if (hi >= 0 && lo >= 0) {
                ch = rome2_l82_identity_u8((uint8_t)((hi << 4) | lo));
                i += 2u;
            }
        }
        out[o++] = (char)ch;
        i++;
    }
    out[o] = '\0';
    if (outlength) {
        *outlength = rome2_l82_curlx_uztosi((uint32_t)o);
    }
    return out_va;
}

/* 0x10f3b1d0 */
uint32_t rome2_l82_curl_unescape(rome2_l82_curl_ctx *ctx, const char *string, int32_t inlength) {
    return rome2_l82_curl_easy_unescape(ctx, 0u, string, inlength, NULL);
}

static int32_t l82_lookup_month(const char *tok) {
    static const char *const months[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    for (int32_t i = 0; i < 12; ++i) {
        if (rome2_l82_curl_raw_equal(tok, months[i])) {
            return i;
        }
    }
    return -1;
}

static int64_t l82_days_from_civil(int32_t y, int32_t m, int32_t d) {
    /* Howard Hinnant civil-from-days inverse for UTC epoch 1970-01-01. */
    y -= (m <= 2) ? 1 : 0;
    int32_t era = (y >= 0 ? y : y - 399) / 400;
    int32_t yoe = y - era * 400;
    int32_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

/* 0x10f1eee0 */
int32_t rome2_l82_curl_parsedate(const char *date, int64_t *output) {
    if (!date || !output) {
        return ROME2_CURL_PARSEDATE_FAIL;
    }
    int32_t year = -1;
    int32_t mon = -1;
    int32_t mday = -1;
    int32_t hour = -1;
    int32_t min = -1;
    int32_t sec = -1;
    int32_t tzoff = 0;
    uint8_t seen_tz = 0u;
    const char *p = date;

    while (*p != '\0') {
        while (*p != '\0' && !rome2_l82_crt_isalnum((uint8_t)*p) && *p != '+' && *p != '-') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        if ((p[0] == '+' || p[0] == '-') && rome2_l82_crt_isdigit((uint8_t)p[1]) && !seen_tz) {
            int sign = (p[0] == '-') ? -1 : 1;
            char *endp = NULL;
            long val = strtol(p + 1, &endp, 10);
            if (endp != p + 1) {
                tzoff = sign * ((int32_t)(val / 100) * 3600 + (int32_t)(val % 100) * 60);
                seen_tz = 1u;
                p = endp;
                continue;
            }
        }
        if (rome2_l82_crt_isdigit((uint8_t)*p)) {
            char *endp = NULL;
            long num = strtol(p, &endp, 10);
            if (*endp == ':' && hour == -1) {
                hour = (int32_t)num;
                p = endp + 1;
                min = (int32_t)strtol(p, &endp, 10);
                if (*endp == ':') {
                    p = endp + 1;
                    sec = (int32_t)strtol(p, &endp, 10);
                } else {
                    sec = 0;
                }
                p = endp;
            } else if (*endp == '-' && year == -1 && num > 31) {
                year = (int32_t)num;
                p = endp + 1;
                mon = (int32_t)strtol(p, &endp, 10) - 1;
                if (*endp == '-') {
                    p = endp + 1;
                    mday = (int32_t)strtol(p, &endp, 10);
                }
                p = endp;
            } else {
                if (num > 31 && year == -1) {
                    year = (int32_t)num;
                } else if (mday == -1 && num >= 1 && num <= 31) {
                    mday = (int32_t)num;
                } else if (year == -1) {
                    year = (int32_t)num;
                    if (year < 70) {
                        year += 2000;
                    } else if (year < 100) {
                        year += 1900;
                    }
                }
                p = endp;
            }
        } else if (rome2_l82_crt_isalpha((uint8_t)*p)) {
            char tok[32];
            size_t len = 0u;
            while (len + 1u < sizeof(tok) && rome2_l82_crt_isalpha((uint8_t)*p)) {
                tok[len++] = *p++;
            }
            tok[len] = '\0';
            while (rome2_l82_crt_isalpha((uint8_t)*p)) {
                p++;
            }
            int32_t m = l82_lookup_month(tok);
            if (m >= 0 && mon == -1) {
                mon = m;
            } else if (rome2_l82_curl_raw_equal(tok, "GMT") || rome2_l82_curl_raw_equal(tok, "UTC")) {
                seen_tz = 1u;
                tzoff = 0;
            }
        } else {
            p++;
        }
    }
    if (year < 1970 || mon < 0 || mon > 11 || mday < 1 || mday > 31 ||
        hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 60) {
        return ROME2_CURL_PARSEDATE_FAIL;
    }
    int64_t days = l82_days_from_civil(year, mon + 1, mday);
    int64_t secs = days * 86400 + (int64_t)hour * 3600 + (int64_t)min * 60 + (int64_t)sec - (int64_t)tzoff;
    *output = secs;
    return ROME2_CURL_PARSEDATE_OK;
}

/* 0x10f1eeb0 */
int64_t rome2_l82_curl_getdate(const char *p, const int64_t *unused) {
    (void)unused;
    int64_t t = 0;
    int32_t rc = rome2_l82_curl_parsedate(p, &t);
    if (rc < 3 && rc >= 0) {
        return t;
    }
    return -1;
}

/* 0x10f1f840 */
int32_t rome2_l82_dprintf_dollar_string(const char *input, const char **endptr) {
    if (!input || !endptr) {
        return 0;
    }
    int32_t number = 0;
    const char *p = input;
    while (rome2_l82_crt_isdigit((uint8_t)*p)) {
        number = number * 10 + (*p - '0');
        p++;
    }
    if (number != 0 && *p == '$') {
        *endptr = p + 1;
        return number;
    }
    return 0;
}

enum l82_fmt_type {
    L82_FMT_NONE = 0,
    L82_FMT_INT,
    L82_FMT_UINT,
    L82_FMT_PTR,
    L82_FMT_CHAR,
    L82_FMT_STR,
    L82_FMT_DOUBLE
};

typedef struct l82_fmt_spec {
    enum l82_fmt_type type;
    uint8_t is_long_long;
    uint8_t left_align;
    uint8_t plus_sign;
    uint8_t space_sign;
    uint8_t zero_pad;
    uint8_t has_prec;
    char conv;
    int32_t width;
    int32_t prec;
    int32_t num;
    int32_t width_num;
    int32_t prec_num;
} l82_fmt_spec;

typedef union l82_fmt_val {
    int64_t i64;
    uint64_t u64;
    double dbl;
    const void *ptr;
} l82_fmt_val;

static int32_t l82_emit_str(rome2_l82_emit_fn stream, void *user, const char *s, size_t len, int32_t *out_count) {
    for (size_t i = 0u; i < len; ++i) {
        if (stream((uint8_t)s[i], user) == -1) {
            return -1;
        }
        (*out_count)++;
    }
    return 0;
}

static int32_t l82_emit_repeat(rome2_l82_emit_fn stream, void *user, char ch, int32_t count, int32_t *out_count) {
    for (int32_t i = 0; i < count; ++i) {
        if (stream((uint8_t)ch, user) == -1) {
            return -1;
        }
        (*out_count)++;
    }
    return 0;
}

static void l82_parse_spec(const char *start, const char **after_out, l82_fmt_spec *sp, int32_t *auto_idx) {
    memset(sp, 0, sizeof(*sp));
    sp->width = -1;
    sp->prec = -1;
    const char *p = start;

    const char *endp = NULL;
    int32_t pos = rome2_l82_dprintf_dollar_string(p, &endp);
    if (pos > 0) {
        sp->num = pos;
        p = endp;
    }
    for (;;) {
        if (*p == '-') sp->left_align = 1u;
        else if (*p == '+') sp->plus_sign = 1u;
        else if (*p == ' ') sp->space_sign = 1u;
        else if (*p == '0') sp->zero_pad = 1u;
        else if (*p == '#' || *p == '\'') { /* accepted flag */ }
        else break;
        p++;
    }
    if (*p == '*') {
        p++;
        int32_t wpos = rome2_l82_dprintf_dollar_string(p, &endp);
        if (wpos > 0) {
            sp->width_num = wpos;
            p = endp;
        } else {
            sp->width_num = ++(*auto_idx);
        }
    } else if (rome2_l82_crt_isdigit((uint8_t)*p)) {
        int32_t w = 0;
        while (rome2_l82_crt_isdigit((uint8_t)*p)) {
            w = w * 10 + (*p - '0');
            p++;
        }
        sp->width = w;
    }
    if (*p == '.') {
        p++;
        sp->has_prec = 1u;
        if (*p == '*') {
            p++;
            int32_t ppos = rome2_l82_dprintf_dollar_string(p, &endp);
            if (ppos > 0) {
                sp->prec_num = ppos;
                p = endp;
            } else {
                sp->prec_num = ++(*auto_idx);
            }
        } else {
            int32_t pr = 0;
            while (rome2_l82_crt_isdigit((uint8_t)*p)) {
                pr = pr * 10 + (*p - '0');
                p++;
            }
            sp->prec = pr;
        }
    }
    if (*p == 'l') {
        p++;
        if (*p == 'l') {
            sp->is_long_long = 1u;
            p++;
        }
    } else if (*p == 'z') {
        if (sizeof(size_t) == 8u) {
            sp->is_long_long = 1u;
        }
        p++;
    } else if (*p == 'h') {
        p++;
        if (*p == 'h') {
            p++;
        }
    } else if (*p == 'I' && p[1] == '6' && p[2] == '4') {
        sp->is_long_long = 1u;
        p += 3;
    }
    sp->conv = *p;
    if (*p != '\0') {
        p++;
    }
    if (sp->num == 0 && sp->conv != '%' && sp->conv != '\0') {
        sp->num = ++(*auto_idx);
    }
    switch (sp->conv) {
    case 'd':
    case 'i':
        sp->type = L82_FMT_INT;
        break;
    case 'u':
    case 'o':
    case 'x':
    case 'X':
        sp->type = L82_FMT_UINT;
        break;
    case 'p':
        sp->type = L82_FMT_PTR;
        break;
    case 'c':
        sp->type = L82_FMT_CHAR;
        break;
    case 's':
        sp->type = L82_FMT_STR;
        break;
    case 'f':
    case 'e':
    case 'E':
    case 'g':
    case 'G':
        sp->type = L82_FMT_DOUBLE;
        break;
    default:
        sp->type = L82_FMT_NONE;
        break;
    }
    *after_out = p;
}

static int32_t l82_format_uint_buf(uint64_t val, uint32_t base, uint8_t upper, char *out, size_t cap) {
    static const char low[] = "0123456789abcdef";
    static const char up[] = "0123456789ABCDEF";
    const char *digits = upper ? up : low;
    char tmp[64];
    size_t len = 0u;
    if (val == 0u) {
        tmp[len++] = '0';
    } else {
        while (val != 0u && len < sizeof(tmp)) {
            tmp[len++] = digits[val % base];
            val /= base;
        }
    }
    if (len >= cap) {
        len = cap - 1u;
    }
    for (size_t i = 0u; i < len; ++i) {
        out[i] = tmp[len - 1u - i];
    }
    out[len] = '\0';
    return (int32_t)len;
}

/* 0x10f1ff20 & 0x10f1f890 (dprintf_formatf + dprintf_Pass1) */
int32_t rome2_l82_dprintf_formatf(void *user, rome2_l82_emit_fn stream, const char *fmt, va_list ap) {
    if (!stream || !fmt) {
        return -1;
    }
    enum { MAX_ARGS = 32 };
    l82_fmt_spec arg_specs[MAX_ARGS + 1];
    l82_fmt_val arg_vals[MAX_ARGS + 1];
    memset(arg_specs, 0, sizeof(arg_specs));
    memset(arg_vals, 0, sizeof(arg_vals));

    int32_t max_arg = 0;
    int32_t auto_idx = 0;
    const char *scan = fmt;
    while (*scan != '\0') {
        if (*scan != '%') {
            scan++;
            continue;
        }
        scan++;
        if (*scan == '%') {
            scan++;
            continue;
        }
        l82_fmt_spec sp;
        l82_parse_spec(scan, &scan, &sp, &auto_idx);
        if (sp.width_num > 0 && sp.width_num <= MAX_ARGS) {
            arg_specs[sp.width_num].type = L82_FMT_INT;
            if (sp.width_num > max_arg) max_arg = sp.width_num;
        }
        if (sp.prec_num > 0 && sp.prec_num <= MAX_ARGS) {
            arg_specs[sp.prec_num].type = L82_FMT_INT;
            if (sp.prec_num > max_arg) max_arg = sp.prec_num;
        }
        if (sp.num > 0 && sp.num <= MAX_ARGS) {
            arg_specs[sp.num].type = sp.type;
            arg_specs[sp.num].is_long_long = sp.is_long_long;
            if (sp.num > max_arg) max_arg = sp.num;
        }
    }

    va_list ap_copy;
    va_copy(ap_copy, ap);
    for (int32_t idx = 1; idx <= max_arg; ++idx) {
        switch (arg_specs[idx].type) {
        case L82_FMT_INT:
        case L82_FMT_CHAR:
            if (arg_specs[idx].is_long_long) {
                arg_vals[idx].i64 = va_arg(ap_copy, int64_t);
            } else {
                arg_vals[idx].i64 = (int64_t)va_arg(ap_copy, int32_t);
            }
            break;
        case L82_FMT_UINT:
            if (arg_specs[idx].is_long_long) {
                arg_vals[idx].u64 = va_arg(ap_copy, uint64_t);
            } else {
                arg_vals[idx].u64 = (uint64_t)va_arg(ap_copy, uint32_t);
            }
            break;
        case L82_FMT_PTR:
        case L82_FMT_STR:
            arg_vals[idx].ptr = va_arg(ap_copy, const void *);
            break;
        case L82_FMT_DOUBLE:
            arg_vals[idx].dbl = va_arg(ap_copy, double);
            break;
        default:
            break;
        }
    }
    va_end(ap_copy);

    int32_t out_count = 0;
    auto_idx = 0;
    const char *p = fmt;
    while (*p != '\0') {
        if (*p != '%') {
            if (stream((uint8_t)*p++, user) == -1) return -1;
            out_count++;
            continue;
        }
        p++;
        if (*p == '%') {
            if (stream('%', user) == -1) return -1;
            out_count++;
            p++;
            continue;
        }
        l82_fmt_spec sp;
        l82_parse_spec(p, &p, &sp, &auto_idx);
        int32_t width = (sp.width_num > 0 && sp.width_num <= MAX_ARGS) ? (int32_t)arg_vals[sp.width_num].i64 : sp.width;
        if (width < 0 && sp.width_num > 0) {
            sp.left_align = 1u;
            width = -width;
        }
        int32_t prec = (sp.prec_num > 0 && sp.prec_num <= MAX_ARGS) ? (int32_t)arg_vals[sp.prec_num].i64 : sp.prec;
        if (sp.num <= 0 || sp.num > MAX_ARGS) {
            continue;
        }

        char numbuf[128];
        if (sp.conv == 's') {
            const char *s = (const char *)arg_vals[sp.num].ptr;
            if (!s) s = "(null)";
            size_t len = strlen(s);
            if (sp.has_prec && prec >= 0 && (size_t)prec < len) {
                len = (size_t)prec;
            }
            int32_t pad = (width > (int32_t)len) ? (width - (int32_t)len) : 0;
            if (!sp.left_align && l82_emit_repeat(stream, user, ' ', pad, &out_count) == -1) return -1;
            if (l82_emit_str(stream, user, s, len, &out_count) == -1) return -1;
            if (sp.left_align && l82_emit_repeat(stream, user, ' ', pad, &out_count) == -1) return -1;
        } else if (sp.conv == 'c') {
            char ch = (char)arg_vals[sp.num].i64;
            int32_t pad = (width > 1) ? (width - 1) : 0;
            if (!sp.left_align && l82_emit_repeat(stream, user, ' ', pad, &out_count) == -1) return -1;
            if (stream((uint8_t)ch, user) == -1) return -1;
            out_count++;
            if (sp.left_align && l82_emit_repeat(stream, user, ' ', pad, &out_count) == -1) return -1;
        } else if (sp.type == L82_FMT_INT || sp.type == L82_FMT_UINT || sp.type == L82_FMT_PTR) {
            char sign_ch = '\0';
            uint64_t uval = 0u;
            uint32_t base = 10u;
            uint8_t upper = 0u;
            const char *prefix = "";
            if (sp.type == L82_FMT_INT) {
                int64_t v = arg_vals[sp.num].i64;
                if (v < 0) {
                    sign_ch = '-';
                    uval = (uint64_t)(-(v + 1)) + 1u;
                } else {
                    uval = (uint64_t)v;
                    if (sp.plus_sign) sign_ch = '+';
                    else if (sp.space_sign) sign_ch = ' ';
                }
            } else if (sp.type == L82_FMT_PTR) {
                uval = (uint64_t)(uintptr_t)arg_vals[sp.num].ptr;
                base = 16u;
                prefix = "0x";
            } else {
                uval = arg_vals[sp.num].u64;
                if (sp.conv == 'o') base = 8u;
                else if (sp.conv == 'x') base = 16u;
                else if (sp.conv == 'X') { base = 16u; upper = 1u; }
            }
            int32_t dlen = l82_format_uint_buf(uval, base, upper, numbuf, sizeof(numbuf));
            if (sp.has_prec && prec == 0 && uval == 0u) {
                dlen = 0;
            }
            int32_t zprec = (sp.has_prec && prec > dlen) ? (prec - dlen) : 0;
            int32_t plen = (sign_ch != '\0' ? 1 : 0) + (int32_t)strlen(prefix) + zprec + dlen;
            int32_t pad = (width > plen) ? (width - plen) : 0;
            if (!sp.left_align && (!sp.zero_pad || sp.has_prec)) {
                if (l82_emit_repeat(stream, user, ' ', pad, &out_count) == -1) return -1;
            }
            if (sign_ch != '\0') {
                if (stream((uint8_t)sign_ch, user) == -1) return -1;
                out_count++;
            }
            if (prefix[0] != '\0' && l82_emit_str(stream, user, prefix, strlen(prefix), &out_count) == -1) return -1;
            if (!sp.left_align && sp.zero_pad && !sp.has_prec) {
                if (l82_emit_repeat(stream, user, '0', pad, &out_count) == -1) return -1;
            }
            if (l82_emit_repeat(stream, user, '0', zprec, &out_count) == -1) return -1;
            if (l82_emit_str(stream, user, numbuf, (size_t)dlen, &out_count) == -1) return -1;
            if (sp.left_align && l82_emit_repeat(stream, user, ' ', pad, &out_count) == -1) return -1;
        } else if (sp.type == L82_FMT_DOUBLE) {
            int n = snprintf(numbuf, sizeof(numbuf), "%.6f", arg_vals[sp.num].dbl);
            size_t len = (n > 0) ? (size_t)n : 0u;
            if (len >= sizeof(numbuf)) len = sizeof(numbuf) - 1u;
            if (l82_emit_str(stream, user, numbuf, len, &out_count) == -1) return -1;
        }
    }
    return out_count;
}

typedef struct l82_snp_buf {
    char *buffer;
    size_t length;
    size_t max;
} l82_snp_buf;

typedef struct l82_alloc_buf {
    rome2_l82_curl_ctx *ctx;
    uint32_t va;
    size_t len;
    size_t cap;
    uint8_t fail;
} l82_alloc_buf;

static int32_t l82_add_to_buffer(int32_t outp, void *user) {
    l82_snp_buf *b = (l82_snp_buf *)user;
    if (b && b->max > 0u) {
        b->buffer[b->length++] = (char)outp;
        b->max--;
    }
    return outp;
}

static int32_t l82_store_char(int32_t outp, void *user) {
    char **p = (char **)user;
    if (p && *p) {
        **p = (char)outp;
        (*p)++;
    }
    return outp;
}

static int32_t l82_alloc_add_char(int32_t outp, void *user) {
    l82_alloc_buf *b = (l82_alloc_buf *)user;
    if (!b || b->fail) {
        return -1;
    }
    if (b->len + 2u > b->cap) {
        size_t new_cap = (b->cap == 0u) ? 32u : (b->cap * 2u);
        uint32_t new_va = rome2_l82_alloc(b->ctx, (uint32_t)new_cap);
        if (new_va == 0u) {
            b->fail = 1u;
            return -1;
        }
        char *dst = (char *)rome2_l82_mut_ptr(b->ctx, new_va, (uint32_t)new_cap);
        if (!dst) {
            b->fail = 1u;
            return -1;
        }
        if (b->va != 0u && b->len > 0u) {
            const char *old = (const char *)rome2_l82_const_ptr(b->ctx, b->va, (uint32_t)b->len);
            if (old) {
                memcpy(dst, old, b->len);
            }
            rome2_l82_curl_free(b->ctx, b->va);
        }
        b->va = new_va;
        b->cap = new_cap;
    }
    char *dst = (char *)rome2_l82_mut_ptr(b->ctx, b->va, (uint32_t)(b->len + 1u));
    if (!dst) {
        b->fail = 1u;
        return -1;
    }
    dst[b->len++] = (char)outp;
    return outp;
}

static int32_t l82_fputc_stream(int32_t outp, void *user) {
    FILE *f = (FILE *)user;
    return f ? fputc(outp, f) : -1;
}

/* 0x10f1f7b0 */
int32_t rome2_l82_curl_mvsnprintf(char *buffer, size_t maxlength, const char *fmt, va_list ap) {
    l82_snp_buf info;
    info.buffer = buffer;
    info.length = 0u;
    info.max = maxlength;
    if (info.max > 0u) {
        info.max--;
    }
    int32_t ret = rome2_l82_dprintf_formatf(&info, l82_add_to_buffer, fmt, ap);
    if (buffer && maxlength > 0u) {
        info.buffer[info.length] = '\0';
    }
    return ret;
}

/* 0x10f1f680 */
int32_t rome2_l82_curl_msnprintf(char *buffer, size_t maxlength, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int32_t ret = rome2_l82_curl_mvsnprintf(buffer, maxlength, fmt, ap);
    va_end(ap);
    return ret;
}

/* 0x10f1f810 */
int32_t rome2_l82_curl_mvsprintf(char *buffer, const char *fmt, va_list ap) {
    char *p = buffer;
    int32_t ret = rome2_l82_dprintf_formatf(&p, l82_store_char, fmt, ap);
    if (p) {
        *p = '\0';
    }
    return ret;
}

/* 0x10f1f6a0 */
int32_t rome2_l82_curl_msprintf(char *buffer, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int32_t ret = rome2_l82_curl_mvsprintf(buffer, fmt, ap);
    va_end(ap);
    return ret;
}

/* 0x10f1f6d0 */
uint32_t rome2_l82_curl_mvaprintf(rome2_l82_curl_ctx *ctx, const char *fmt, va_list ap) {
    if (!ctx || !fmt) {
        return 0u;
    }
    l82_alloc_buf info;
    memset(&info, 0, sizeof(info));
    info.ctx = ctx;
    int32_t ret = rome2_l82_dprintf_formatf(&info, l82_alloc_add_char, fmt, ap);
    if (ret != -1 && info.fail == 0u) {
        if (info.cap > 0u) {
            char *dst = (char *)rome2_l82_mut_ptr(ctx, info.va, (uint32_t)(info.len + 1u));
            if (dst) {
                dst[info.len] = '\0';
            }
            return info.va;
        }
        return rome2_l82_strdup_va(ctx, "");
    }
    if (info.va != 0u) {
        rome2_l82_curl_free(ctx, info.va);
    }
    return 0u;
}

/* 0x10f1f5a0 */
uint32_t rome2_l82_curl_maprintf(rome2_l82_curl_ctx *ctx, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    uint32_t va = rome2_l82_curl_mvaprintf(ctx, fmt, ap);
    va_end(ap);
    return va;
}

/* 0x10f1f760 */
int32_t rome2_l82_curl_mvfprintf(FILE *wheretoprint, const char *fmt, va_list ap) {
    return rome2_l82_dprintf_formatf(wheretoprint, l82_fputc_stream, fmt, ap);
}

/* 0x10f1f630 */
int32_t rome2_l82_curl_mfprintf(FILE *wheretoprint, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int32_t ret = rome2_l82_curl_mvfprintf(wheretoprint, fmt, ap);
    va_end(ap);
    return ret;
}

/* 0x10f1f780 */
int32_t rome2_l82_curl_mvprintf(const char *fmt, va_list ap) {
    return rome2_l82_curl_mvfprintf(stdout, fmt, ap);
}

/* 0x10f1f650 */
int32_t rome2_l82_curl_mprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int32_t ret = rome2_l82_curl_mvprintf(fmt, ap);
    va_end(ap);
    return ret;
}
