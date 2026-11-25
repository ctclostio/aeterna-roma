#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "startup_prefs_seh_tail_ops.h"

typedef struct test_prefs_ctx {
    uint8_t open_fail;
    int32_t open_errno;
    uint8_t write_fail;
    uint8_t stream_good;
    int32_t close_rc;
    uint32_t open_calls;
    uint32_t write_calls;
    uint32_t log_calls;
    uint8_t written[4096];
    size_t written_len;
} test_prefs_ctx;

static uint8_t mock_open_prefs(void *user, const uint16_t *path_hint, uint8_t append, int32_t *out_errno) {
    test_prefs_ctx *ctx = (test_prefs_ctx *)user;
    (void)path_hint;
    (void)append;
    ctx->open_calls++;
    if (ctx->open_fail) {
        *out_errno = ctx->open_errno;
        return 0u;
    }
    *out_errno = 0;
    return 1u;
}

static uint8_t mock_write_prefs(void *user, const uint8_t *bytes, size_t len, size_t *out_written) {
    test_prefs_ctx *ctx = (test_prefs_ctx *)user;
    ctx->write_calls++;
    if (ctx->write_fail) {
        *out_written = len / 2u;
        return 0u;
    }
    if (len <= sizeof(ctx->written)) {
        memcpy(ctx->written, bytes, len);
        ctx->written_len = len;
    }
    *out_written = len;
    return 1u;
}

static uint8_t mock_stream_good(void *user) {
    return ((test_prefs_ctx *)user)->stream_good;
}

static int32_t mock_close_prefs(void *user) {
    return ((test_prefs_ctx *)user)->close_rc;
}

static void mock_log_line(void *user, const char *line) {
    (void)line;
    ((test_prefs_ctx *)user)->log_calls++;
}

static void format_int_val(void *user, rome2_l72_wstream *stream) {
    const char *val = (const char *)user;
    rome2_l72_wostream_insert_cstr(stream, val);
}

typedef struct test_unwind_log {
    uint32_t notify_codes[8];
    uint32_t notify_handlers[8];
    uint32_t notify_count;
    uint32_t call_handlers[8];
    uint32_t call_cookies[8];
    uint32_t call_count;
    uint32_t global_frame;
    uint32_t global_ip;
    uint32_t global_count;
    uint32_t dtor_va;
    uint32_t dtor_calls;
} test_unwind_log;

static void mock_nlg_notify(void *user, const rome2_startup_nlg_dest16_32 *dest) {
    test_unwind_log *log = (test_unwind_log *)user;
    assert(dest->sig_00 == ROME2_L72_NLG_SIG);
    if (log->notify_count < 8u) {
        log->notify_codes[log->notify_count] = dest->code_08;
        log->notify_handlers[log->notify_count] = dest->eax_04;
        log->notify_count++;
    }
}

static void mock_nlg_call(void *user, uint32_t funclet_va, uint32_t cookie) {
    test_unwind_log *log = (test_unwind_log *)user;
    if (log->call_count < 8u) {
        log->call_handlers[log->call_count] = funclet_va;
        log->call_cookies[log->call_count] = cookie;
        log->call_count++;
    }
}

static void mock_rtl_unwind(void *user, uint32_t target_frame_va, uint32_t target_ip_va) {
    test_unwind_log *log = (test_unwind_log *)user;
    log->global_frame = target_frame_va;
    log->global_ip = target_ip_va;
    log->global_count++;
}

static void mock_dtor_call(void *user, uint32_t dtor_va) {
    test_unwind_log *log = (test_unwind_log *)user;
    log->dtor_va = dtor_va;
    log->dtor_calls++;
}

static void build_synthetic_pe(uint8_t *buf, size_t size, uint32_t sec1_chars, uint32_t sec2_chars) {
    memset(buf, 0, size);
    buf[0] = 'M';
    buf[1] = 'Z';
    buf[0x3c] = 0x80;
    /* PE\0\0 at 0x80 */
    buf[0x80] = 'P';
    buf[0x81] = 'E';
    /* 2 sections */
    buf[0x86] = 2;
    /* OptionalHeader size = 0xe0 */
    buf[0x94] = 0xe0;
    /* PE32 magic 0x010b at 0x98 */
    buf[0x98] = 0x0b;
    buf[0x99] = 0x01;
    /* Section 1 (.text) at 0x80 + 0x18 + 0xe0 = 0x178: VirtualSize=0x1000, VirtualAddress=0x1000 */
    memcpy(buf + 0x178, ".text\0\0\0", 8);
    buf[0x178 + 0x08] = 0x00;
    buf[0x178 + 0x09] = 0x10;
    buf[0x178 + 0x0c] = 0x00;
    buf[0x178 + 0x0d] = 0x10;
    buf[0x178 + 0x24] = (uint8_t)(sec1_chars & 0xffu);
    buf[0x178 + 0x25] = (uint8_t)((sec1_chars >> 8) & 0xffu);
    buf[0x178 + 0x26] = (uint8_t)((sec1_chars >> 16) & 0xffu);
    buf[0x178 + 0x27] = (uint8_t)((sec1_chars >> 24) & 0xffu);
    /* Section 2 (.rdata) at 0x1a0: VirtualSize=0x1000, VirtualAddress=0x2000 */
    memcpy(buf + 0x1a0, ".rdata\0\0", 8);
    buf[0x1a0 + 0x08] = 0x00;
    buf[0x1a0 + 0x09] = 0x10;
    buf[0x1a0 + 0x0c] = 0x00;
    buf[0x1a0 + 0x0d] = 0x20;
    buf[0x1a0 + 0x24] = (uint8_t)(sec2_chars & 0xffu);
    buf[0x1a0 + 0x25] = (uint8_t)((sec2_chars >> 8) & 0xffu);
    buf[0x1a0 + 0x26] = (uint8_t)((sec2_chars >> 16) & 0xffu);
    buf[0x1a0 + 0x27] = (uint8_t)((sec2_chars >> 24) & 0xffu);
}

int main(void) {
    uint16_t wbuf[256];
    rome2_l72_wstream stream;
    test_prefs_ctx pctx;
    rome2_l72_prefs_env penv;
    rome2_l72_pref_item items[2];
    rome2_startup_crt_file_box8_32 fbox;
    uint8_t exc = 0u;
    uint32_t matherr = 0u;
    uint8_t pe[1024];
    rome2_startup_pe_sec_hdr40_32 sec;
    rome2_startup_seh_scope12_32 scopes[3];
    rome2_startup_eh3_reg16_32 reg;
    rome2_l72_eh3_env ehenv;
    test_unwind_log ulog;
    rome2_l72_unwind_env uenv;
    uint32_t checks = 0u;

    /* 1. wostream_insert_cstr width/fill/badbit */
    memset(&stream, 0, sizeof(stream));
    stream.buf = wbuf;
    stream.capacity = 256u;
    stream.width = 5u;
    stream.fill = (uint16_t)'_';
    stream.rdstate = 0u;
    stream.rdbuf_present = 1u;
    stream.sentry_ok = 1u;
    rome2_l72_wostream_insert_cstr(&stream, "abc");
    assert(stream.len == 5u && stream.width == 0u && stream.rdstate == 0u);
    assert(wbuf[0] == 'a' && wbuf[2] == 'c' && wbuf[3] == '_' && wbuf[4] == '_');
    rome2_l72_stream_set_badbit(&stream);
    assert(stream.rdstate == 2u);
    checks += 2u;

    /* 2. pref_write_line quoted vs unquoted + write_preferences */
    memset(&stream, 0, sizeof(stream));
    stream.buf = wbuf;
    stream.capacity = 256u;
    stream.fill = (uint16_t)' ';
    stream.rdbuf_present = 1u;
    stream.sentry_ok = 1u;
    items[0].name = "x_res";
    items[0].group = "gfx";
    items[0].desc = "width";
    items[0].quote = 0u;
    items[0].format_value = format_int_val;
    items[0].user = (void *)"1920";
    items[1].name = "lang";
    items[1].group = "ui";
    items[1].desc = "locale";
    items[1].quote = 1u;
    items[1].format_value = format_int_val;
    items[1].user = (void *)"en";
    memset(&pctx, 0, sizeof(pctx));
    pctx.stream_good = 1u;
    memset(&penv, 0, sizeof(penv));
    penv.user = &pctx;
    penv.open_prefs_file = mock_open_prefs;
    penv.write_prefs_bytes = mock_write_prefs;
    penv.stream_good = mock_stream_good;
    penv.close_prefs_file = mock_close_prefs;
    penv.log_line = mock_log_line;
    assert(rome2_l72_write_preferences(&penv, items, 2u, &stream, NULL) == 0);
    assert(pctx.open_calls == 1u && pctx.write_calls == 1u && pctx.log_calls == 0u);
    assert(pctx.written_len == stream.len * 2u);
    checks += 3u;

    /* open fail records errno & logs */
    pctx.open_fail = 1u;
    pctx.open_errno = 13;
    assert(rome2_l72_open_write_wstr(&penv, NULL, 0u, &fbox) == 0u && fbox.err_04 == 13 && fbox.file_00 == 0u);
    stream.len = 0u;
    assert(rome2_l72_write_preferences(&penv, items, 1u, &stream, NULL) == 13 && pctx.log_calls == 1u);
    pctx.open_fail = 0u;
    pctx.write_fail = 1u;
    stream.len = 0u;
    assert(rome2_l72_write_preferences(&penv, items, 1u, &stream, NULL) == 0x26);
    checks += 3u;

    /* 3. ___ascii_strnicmp */
    assert(rome2_l72_ascii_strnicmp("AbC", "aBc", 3u) == 0);
    assert(rome2_l72_ascii_strnicmp("AbC", "aBd", 3u) == -1);
    assert(rome2_l72_ascii_strnicmp("AbE", "aBd", 3u) == 1);
    assert(rome2_l72_ascii_strnicmp("AbZ", "aBa", 2u) == 0);
    assert(rome2_l72_ascii_strnicmp("x", "y", 0u) == 0);
    checks += 5u;

    /* 4. x87 cw restore, math_exit, log10 */
    assert(rome2_l72_fpu_cw_restore_needed(0x027fu) == 0u);
    assert(rome2_l72_fpu_cw_restore_needed(0x037fu) == 1u);
    assert(rome2_l72_math_exit(0x027fu, 0x0020u, &exc) == 0u && exc == 0u);
    assert(rome2_l72_math_exit(0x037fu, 0x0020u, &exc) == 0u && exc == 8u);
    assert(rome2_l72_math_exit(0x037fu, 0x0000u, &exc) == 1u && exc == 0u);
    assert(fabs(rome2_l72_log10(1000.0, &matherr) - 3.0) < 1e-12 && matherr == 0u);
    assert(isinf(rome2_l72_log10(0.0, &matherr)) && matherr == 8u);
    assert(isnan(rome2_l72_log10(-1.0, &matherr)) && matherr == 9u);
    checks += 8u;

    /* 5. PE section lookup, IsNonwritableInCurrentImage, ValidateScopeTableHandlers, ValidateEH3RN */
    build_synthetic_pe(pe, sizeof(pe), ROME2_L72_PE_SCN_MEM_EXECUTE, 0u);
    assert(rome2_l72_validate_image_base(pe, sizeof(pe)) == 1u);
    assert(rome2_l72_find_pe_section(pe, sizeof(pe), 0x1050u, &sec) != NULL &&
           sec.virtual_address_0c == 0x1000u);
    assert(rome2_l72_is_nonwritable_in_image(pe, sizeof(pe), 0x10000000u, 0x10002010u) == 1u);
    /* writable .rdata rejects */
    build_synthetic_pe(pe, sizeof(pe), ROME2_L72_PE_SCN_MEM_EXECUTE, ROME2_L72_PE_SCN_MEM_WRITE);
    assert(rome2_l72_is_nonwritable_in_image(pe, sizeof(pe), 0x10000000u, 0x10002010u) == 0u);
    checks += 4u;

    build_synthetic_pe(pe, sizeof(pe), ROME2_L72_PE_SCN_MEM_EXECUTE, 0u);
    scopes[0].enclosing_level_00 = -1;
    scopes[0].filter_04 = 0u;
    scopes[0].handler_08 = 0x10001100u;
    scopes[1].enclosing_level_00 = 0;
    scopes[1].filter_04 = 0x10001200u;
    scopes[1].handler_08 = 0x10001220u;
    scopes[2].enclosing_level_00 = 1;
    scopes[2].filter_04 = 0u;
    scopes[2].handler_08 = 0x10001300u;
    assert(rome2_l72_validate_scope_table_handlers(pe, sizeof(pe), 0x10000000u, scopes, 3u, 2u) == 1u);
    scopes[2].handler_08 = 0x10002100u; /* non-executable .rdata */
    assert(rome2_l72_validate_scope_table_handlers(pe, sizeof(pe), 0x10000000u, scopes, 3u, 2u) == 0u);
    scopes[2].handler_08 = 0x10001300u;

    reg.next_00 = 0xffffffffu;
    reg.handler_04 = 0x10001050u;
    reg.scope_table_08 = 0x10002000u;
    reg.try_level_0c = 2u;
    memset(&ehenv, 0, sizeof(ehenv));
    ehenv.image = pe;
    ehenv.image_size = sizeof(pe);
    ehenv.image_base_va = 0x10000000u;
    ehenv.reg_va = 0x0019f000u;
    ehenv.stack_low_va = 0x00190000u;
    ehenv.stack_high_va = 0x00200000u;
    ehenv.saved_ebp_va = 0x0019ef80u;
    ehenv.handler_rva = 0x1050u;
    ehenv.reg = &reg;
    ehenv.scopes = scopes;
    ehenv.scope_count = 3u;
    ehenv.region_writable_page = 1u;
    assert(rome2_l72_validate_eh3_rn(&ehenv) == 1);
    reg.scope_table_08 = 0x10002002u; /* misaligned */
    assert(rome2_l72_validate_eh3_rn(&ehenv) == 0);
    reg.scope_table_08 = 0x10002000u;
    checks += 4u;

    /* 6. local_unwind2, global_unwind2, CallDestructExceptionObject, seh_restore_chain */
    memset(&ulog, 0, sizeof(ulog));
    memset(&uenv, 0, sizeof(uenv));
    uenv.user = &ulog;
    uenv.nlg_notify = mock_nlg_notify;
    uenv.nlg_call = mock_nlg_call;
    uenv.rtl_unwind = mock_rtl_unwind;
    assert(rome2_l72_local_unwind2(&uenv, scopes, 3u, 2u, 0u, 0x0019ef80u, 0xdeadbeefu) == 0u);
    /* scope 2 has filter=0 -> invoked; scope 1 has filter!=0 -> skipped */
    assert(ulog.notify_count == 1u && ulog.notify_handlers[0] == 0x10001300u && ulog.notify_codes[0] == 0x101u);
    assert(ulog.call_count == 1u && ulog.call_handlers[0] == 0x10001300u && ulog.call_cookies[0] == 0xdeadbeefu);
    rome2_l72_global_unwind2(&uenv, 0x0019ff00u);
    assert(ulog.global_count == 1u && ulog.global_frame == 0x0019ff00u && ulog.global_ip == 0x116c0a09u);
    assert(rome2_l72_call_destruct_exception_object(
               pe, sizeof(pe), 0x10000000u, ROME2_L72_CPP_EH_CODE, 0x10001400u, 0x10002040u, mock_dtor_call, &ulog) == 1u);
    assert(ulog.dtor_calls == 1u && ulog.dtor_va == 0x10001400u);
    assert(rome2_l72_seh_restore_chain(0x0019ffe0u) == 0x0019ffe0u);
    checks += 6u;

    (void)checks;
    return 0;
}
