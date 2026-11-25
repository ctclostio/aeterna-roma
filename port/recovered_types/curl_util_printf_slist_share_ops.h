#ifndef ROME2_CURL_UTIL_PRINTF_SLIST_SHARE_OPS_H
#define ROME2_CURL_UTIL_PRINTF_SLIST_SHARE_OPS_H

#include "guest32_layouts.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum rome2_curl_parsedate_status {
    ROME2_CURL_PARSEDATE_OK = 0,
    ROME2_CURL_PARSEDATE_FUTURE = 1,
    ROME2_CURL_PARSEDATE_LATER = 2,
    ROME2_CURL_PARSEDATE_FAIL = -1
};

enum rome2_curlsh_code {
    ROME2_CURLSHE_OK = 0,
    ROME2_CURLSHE_BAD_OPTION = 1,
    ROME2_CURLSHE_IN_USE = 2,
    ROME2_CURLSHE_INVALID = 3,
    ROME2_CURLSHE_NOMEM = 4,
    ROME2_CURLSHE_NOT_BUILT_IN = 5
};

enum rome2_curl_lock_data {
    ROME2_CURL_LOCK_DATA_SHARE = 1,
    ROME2_CURL_LOCK_ACCESS_SINGLE = 2
};

typedef struct rome2_l82_curl_ctx {
    uint8_t *arena_bytes;
    uint32_t arena_base_va;
    uint32_t arena_size;
    uint32_t heap_cursor;
    uint32_t alloc_count;
    uint32_t free_count;
    uint32_t ssl_session_free_calls;
    int32_t last_errno;
    uint8_t use_locale_stricmp;

    void (*on_share_lock)(
        struct rome2_l82_curl_ctx *ctx,
        uint32_t lockfunc_va,
        int32_t data,
        int32_t access,
        uint32_t userptr_va);
    void (*on_share_unlock)(
        struct rome2_l82_curl_ctx *ctx,
        uint32_t unlockfunc_va,
        int32_t data,
        uint32_t userptr_va);
    void (*on_llist_dtor)(
        struct rome2_l82_curl_ctx *ctx,
        uint32_t dtor_fn_va,
        uint32_t user_va,
        uint32_t elem_ptr_va);
    void (*on_ssl_session_free)(
        struct rome2_l82_curl_ctx *ctx,
        uint32_t ssl_session_va);
    const char *(*on_getenv)(
        struct rome2_l82_curl_ctx *ctx,
        const char *name);
} rome2_l82_curl_ctx;

void rome2_l82_ctx_init(
    rome2_l82_curl_ctx *ctx,
    uint8_t *arena_bytes,
    uint32_t base_va,
    uint32_t arena_size,
    uint32_t heap_start_va);
void *rome2_l82_mut_ptr(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t bytes);
const void *rome2_l82_const_ptr(const rome2_l82_curl_ctx *ctx, uint32_t va, uint32_t bytes);
uint32_t rome2_l82_alloc(rome2_l82_curl_ctx *ctx, uint32_t size);
uint32_t rome2_l82_calloc(rome2_l82_curl_ctx *ctx, uint32_t nmemb, uint32_t size);
uint32_t rome2_l82_strdup_va(rome2_l82_curl_ctx *ctx, const char *s);
void rome2_l82_curl_free(rome2_l82_curl_ctx *ctx, uint32_t ptr_va); /* 0x10f244f0 */

/* slist, llist, hash, cookie, ssl_session, share (0x10f10c20, 0x10f10c90, 0x10f11670, 0x10f12500, 0x10f16310, 0x10f20a00, 0x10f20ad0, 0x10f21190, 0x10f2d4f0, 0x116c7f4b) */
uint32_t rome2_l82_curl_slist_append(rome2_l82_curl_ctx *ctx, uint32_t list_va, const char *data);
void rome2_l82_curl_slist_free_all(rome2_l82_curl_ctx *ctx, uint32_t list_va);
void rome2_l82_curl_cookie_cleanup(rome2_l82_curl_ctx *ctx, uint32_t c_va);
void rome2_l82_curl_llist_destroy(rome2_l82_curl_ctx *ctx, uint32_t list_va, uint32_t user_va);
void rome2_l82_curl_hash_destroy(rome2_l82_curl_ctx *ctx, uint32_t hash_va);
void rome2_l82_imp_ssl_session_free(rome2_l82_curl_ctx *ctx, uint32_t ssl_session_va);
void rome2_l82_thunk_ssl_session_free(rome2_l82_curl_ctx *ctx, uint32_t ssl_session_va);
void rome2_l82_curl_ssl_kill_session(rome2_l82_curl_ctx *ctx, uint32_t session_entry_va);
uint32_t rome2_l82_curl_share_init(rome2_l82_curl_ctx *ctx);
int32_t rome2_l82_curl_share_cleanup(rome2_l82_curl_ctx *ctx, uint32_t share_va);

/* Error tables (0x10f21aa0, 0x10f21e00, 0x10f21e70) */
const char *rome2_l82_curl_easy_strerror(int32_t code);
const char *rome2_l82_curl_multi_strerror(int32_t code);
const char *rome2_l82_curl_share_strerror(int32_t code);

/* Character classification & string helpers (0x10f1ee30, 0x10f1ee50, 0x10f20c90, 0x10f20f40, 0x1169df5b..0x1169e3b2, 0x116d74e3..0x116d7565) */
int32_t rome2_l82_crt_isalnum_l(int32_t ch);
int32_t rome2_l82_crt_isalpha_l(int32_t ch);
int32_t rome2_l82_crt_isdigit_l(int32_t ch);
int32_t rome2_l82_crt_isxdigit_l(int32_t ch);
int32_t rome2_l82_crt_isalnum(int32_t ch);
int32_t rome2_l82_crt_isalpha(int32_t ch);
int32_t rome2_l82_crt_isdigit(int32_t ch);
int32_t rome2_l82_crt_isxdigit(int32_t ch);
int32_t rome2_l82_ascii_stricmp(const char *s1, const char *s2);
int32_t rome2_l82_stricmp_l(rome2_l82_curl_ctx *ctx, const char *s1, const char *s2);
int32_t rome2_l82_stricmp(rome2_l82_curl_ctx *ctx, const char *s1, const char *s2);
uint8_t rome2_l82_curl_strequal(rome2_l82_curl_ctx *ctx, const char *s1, const char *s2);
uint8_t rome2_l82_curl_strnequal(const char *s1, const char *s2, size_t maxcount);
uint8_t rome2_l82_curl_raw_equal(const char *first, const char *second);
char rome2_l82_curl_raw_toupper(char in);

/* Escape / Unescape / Env / Date (0x10f1eeb0, 0x10f1eee0, 0x10f3ae20, 0x10f3af80, 0x10f3b0c0, 0x10f3b1b0, 0x10f3b1d0, 0x10f3bf70, 0x10f3bf90, 0x1169e919, 0x1169e98f, 0x1169eccd) */
int32_t rome2_l82_curlx_uztosi(uint32_t u);
uint8_t rome2_l82_identity_u8(uint8_t v);
void rome2_l82_crt_unlock_env_nop(void);
const char *rome2_l82_common_getenv(rome2_l82_curl_ctx *ctx, const char *name);
const char *rome2_l82_getenv_thunk(rome2_l82_curl_ctx *ctx, const char *name);
uint32_t rome2_l82_curl_getenv(rome2_l82_curl_ctx *ctx, const char *name);
uint32_t rome2_l82_curl_easy_escape(
    rome2_l82_curl_ctx *ctx,
    uint32_t handle_va,
    const char *string,
    int32_t inlength);
uint32_t rome2_l82_curl_escape(rome2_l82_curl_ctx *ctx, const char *string, int32_t inlength);
uint32_t rome2_l82_curl_easy_unescape(
    rome2_l82_curl_ctx *ctx,
    uint32_t handle_va,
    const char *string,
    int32_t inlength,
    int32_t *outlength);
uint32_t rome2_l82_curl_unescape(rome2_l82_curl_ctx *ctx, const char *string, int32_t inlength);
int32_t rome2_l82_curl_parsedate(const char *date, int64_t *output);
int64_t rome2_l82_curl_getdate(const char *p, const int64_t *unused);

/* mprintf formatter family (0x10f1f5a0..0x10f1ff20) */
int32_t rome2_l82_dprintf_dollar_string(const char *input, const char **endptr);
typedef int32_t (*rome2_l82_emit_fn)(int32_t ch, void *user);
int32_t rome2_l82_dprintf_formatf(void *user, rome2_l82_emit_fn stream, const char *fmt, va_list ap);
int32_t rome2_l82_curl_mvsnprintf(char *buffer, size_t maxlength, const char *fmt, va_list ap);
int32_t rome2_l82_curl_msnprintf(char *buffer, size_t maxlength, const char *fmt, ...);
int32_t rome2_l82_curl_mvsprintf(char *buffer, const char *fmt, va_list ap);
int32_t rome2_l82_curl_msprintf(char *buffer, const char *fmt, ...);
uint32_t rome2_l82_curl_mvaprintf(rome2_l82_curl_ctx *ctx, const char *fmt, va_list ap);
uint32_t rome2_l82_curl_maprintf(rome2_l82_curl_ctx *ctx, const char *fmt, ...);
int32_t rome2_l82_curl_mvfprintf(FILE *wheretoprint, const char *fmt, va_list ap);
int32_t rome2_l82_curl_mfprintf(FILE *wheretoprint, const char *fmt, ...);
int32_t rome2_l82_curl_mvprintf(const char *fmt, va_list ap);
int32_t rome2_l82_curl_mprintf(const char *fmt, ...);

#endif
