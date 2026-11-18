#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_crt_fls_ops.h"

#define TEST_ASSERT(cond)                                                          \
    do {                                                                           \
        if (!(cond)) {                                                             \
            fprintf(stderr, "FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            return 1;                                                              \
        }                                                                          \
        ++g_checks;                                                                \
    } while (0)

typedef struct mock_wput_ctx {
    uint16_t buf[32];
    size_t count;
    int32_t fail_after;
} mock_wput_ctx;

static uint8_t mock_wput(uint16_t wch, void *ctx, int32_t *out_errno) {
    mock_wput_ctx *c = (mock_wput_ctx *)ctx;
    if (c->fail_after >= 0 && (int32_t)c->count >= c->fail_after) {
        if (out_errno) {
            *out_errno = 42;
        }
        return 0u;
    }
    c->buf[c->count++] = wch;
    return 1u;
}

typedef struct mock_stream_ctx {
    uint8_t bytes[64];
    size_t len;
    uint8_t seek_ok;
    uint8_t write_ok;
} mock_stream_ctx;

static uint8_t mock_seek0(rome2_vfs_crt_stdio_stream56_32 *stream, void *ctx) {
    (void)stream;
    mock_stream_ctx *c = (mock_stream_ctx *)ctx;
    return c->seek_ok;
}

static uint8_t mock_write_byte(rome2_vfs_crt_stdio_stream56_32 *stream, uint32_t unit, void *ctx) {
    (void)stream;
    mock_stream_ctx *c = (mock_stream_ctx *)ctx;
    if (!c->write_ok || c->len >= sizeof(c->bytes)) {
        return 0u;
    }
    c->bytes[c->len++] = (uint8_t)(unit & 0xffu);
    return 1u;
}

static uint8_t mock_write_word(rome2_vfs_crt_stdio_stream56_32 *stream, uint32_t unit, void *ctx) {
    (void)stream;
    mock_stream_ctx *c = (mock_stream_ctx *)ctx;
    if (!c->write_ok || c->len + 2u > sizeof(c->bytes)) {
        return 0u;
    }
    c->bytes[c->len++] = (uint8_t)(unit & 0xffu);
    c->bytes[c->len++] = (uint8_t)((unit >> 8) & 0xffu);
    return 1u;
}

typedef struct mock_api_ctx {
    uint32_t seen_slot;
    char seen_name[32];
    uint32_t first_mod;
    uint32_t first_ver;
    uint32_t second_mod;
} mock_api_ctx;

static uint32_t mock_resolve_api(
    uint32_t table_slot,
    const char *api_name,
    const rome2_vfs_crt_api_mod_desc8_32 *begin_desc,
    const rome2_vfs_crt_api_mod_desc8_32 *end_desc,
    void *ctx) {
    mock_api_ctx *c = (mock_api_ctx *)ctx;
    c->seen_slot = table_slot;
    strncpy_s(c->seen_name, sizeof(c->seen_name), api_name, _TRUNCATE);
    c->first_mod = begin_desc->module_id_00;
    c->first_ver = begin_desc->min_version_04;
    c->second_mod = end_desc->module_id_00;
    return 0x12345678u;
}

typedef struct mock_con_ctx {
    uint16_t name[16];
    uint32_t closed_handle;
    int32_t close_calls;
} mock_con_ctx;

static uint32_t mock_open_con(const uint16_t *device_name, void *ctx) {
    mock_con_ctx *c = (mock_con_ctx *)ctx;
    for (size_t i = 0u; i < 8u; ++i) {
        c->name[i] = device_name[i];
    }
    return 0x44u;
}

static uint8_t mock_close_con(uint32_t handle, void *ctx) {
    mock_con_ctx *c = (mock_con_ctx *)ctx;
    c->closed_handle = handle;
    ++c->close_calls;
    return 1u;
}

int main(void) {
    int g_checks = 0;

    /* 1. New guest32 layouts (`sizeof` & field offsets) */
    TEST_ASSERT(sizeof(rome2_vfs_crt_stdio_stream56_32) == 0x38u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_stdio_stream56_32, base_04) == 0x04u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_stdio_stream56_32, cnt_08) == 0x08u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_stdio_stream56_32, flags_0c) == 0x0cu);
    TEST_ASSERT(sizeof(rome2_vfs_crt_api_mod_desc8_32) == 0x08u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_seh4_scope16_32) == 0x10u);

    /* 2. __aullshr (0x116847e0) & __alldvrm (0x116d7120) */
    TEST_ASSERT(rome2_vfs_crt_aullshr(0x8000000000000000ULL, 63u) == 1ULL);
    TEST_ASSERT(rome2_vfs_crt_aullshr(0xffffffffffffffffULL, 64u) == 0ULL);
    TEST_ASSERT(rome2_vfs_crt_aullshr(0x123456789abcdef0ULL, 36u) == 0x01234567ULL);

    int64_t q = 0, r = 0;
    TEST_ASSERT(rome2_vfs_crt_alldvrm(-1000000000007LL, 1000000000LL, &q, &r) == 1u);
    TEST_ASSERT(q == -1000LL && r == -7LL);
    TEST_ASSERT(rome2_vfs_crt_alldvrm(1000000000007LL, -1000000000LL, &q, &r) == 1u);
    TEST_ASSERT(q == -1000LL && r == 7LL);
    TEST_ASSERT(rome2_vfs_crt_alldvrm(42LL, 0LL, &q, &r) == 0u);

    /* 3. to_integer_size switch (0x1168aeb3) */
    TEST_ASSERT(rome2_vfs_crt_to_integer_size(0u) == 4u);
    TEST_ASSERT(rome2_vfs_crt_to_integer_size(1u) == 1u);
    TEST_ASSERT(rome2_vfs_crt_to_integer_size(2u) == 2u);
    TEST_ASSERT(rome2_vfs_crt_to_integer_size(4u) == 8u);
    TEST_ASSERT(rome2_vfs_crt_to_integer_size(5u) == 8u);
    TEST_ASSERT(rome2_vfs_crt_to_integer_size(8u) == 0u);
    TEST_ASSERT(rome2_vfs_crt_to_integer_size(11u) == 8u);
    TEST_ASSERT(rome2_vfs_crt_to_integer_size(12u) == 0u);

    /* 4. write_string<wchar_t> (0x1168bcc3) */
    rome2_vfs_crt_stdio_stream56_32 s_fast;
    memset(&s_fast, 0, sizeof(s_fast));
    s_fast.flags_0c = 0x1000u; /* _IOSTRG, base_04 == 0 */
    int32_t written = 3;
    int32_t err = 0;
    const uint16_t wstr[4] = { 'A', 'B', 'C', 0u };
    rome2_vfs_crt_wstream_write_string(&s_fast, wstr, 3, &written, NULL, NULL, &err);
    TEST_ASSERT(written == 6 && err == 0);

    rome2_vfs_crt_stdio_stream56_32 s_real;
    memset(&s_real, 0, sizeof(s_real));
    mock_wput_ctx wp = { { 0 }, 0u, 1 };
    written = 0;
    rome2_vfs_crt_wstream_write_string(&s_real, wstr, 3, &written, mock_wput, &wp, &err);
    TEST_ASSERT(written == -1 && err == 42 && wp.count == 1u && wp.buf[0] == 'A');

    /* 5. parse_integer<uint32> (0x1168d407) */
    size_t end_off = 99u;
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_parse_uint32("  -0x2aZ", &end_off, 0, 1u, &err) == (uint32_t)(-42));
    TEST_ASSERT(end_off == 7u && err == 0);
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_parse_uint32("2147483648", &end_off, 10, 1u, &err) == 0x7fffffffu);
    TEST_ASSERT(err == 34);
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_parse_uint32("0x100000000", &end_off, 0, 0u, &err) == 0xffffffffu);
    TEST_ASSERT(err == 34);
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_parse_uint32("xyz", &end_off, 10, 0u, &err) == 0u && end_off == 0u && err == 0);
    TEST_ASSERT(rome2_vfs_crt_parse_uint32("10", &end_off, 99, 0u, &err) == 0u && err == 22);

    /* 6. process_conversion_specifier switch (0x11695ee2) */
    rome2_vfs_crt_scanf_input116_32 scan_in;
    memset(&scan_in, 0, sizeof(scan_in));
    rome2_vfs_crt_scanf_conv_action act;
    scan_in.fmt_18.conv_idx_28 = 6u; /* base 16 unsigned */
    TEST_ASSERT(rome2_vfs_crt_scanf_dispatch_conversion(&scan_in, &act) == 1u);
    TEST_ASSERT(act.kind == 4u && act.base == 16u && act.is_signed == 0u);
    scan_in.fmt_18.conv_idx_28 = 8u; /* scanset */
    TEST_ASSERT(rome2_vfs_crt_scanf_dispatch_conversion(&scan_in, &act) == 1u && act.kind == 3u);
    scan_in.fmt_18.conv_idx_28 = 10u;
    TEST_ASSERT(rome2_vfs_crt_scanf_dispatch_conversion(&scan_in, &act) == 0u && act.valid == 0u);

    /* 7. _getenv_s (0x1169ecd8) */
    const rome2_vfs_crt_env_kv env_tbl[2] = {
        { "PATH", "C:\\Rome2" },
        { "LANG", "en_US" },
    };
    char env_buf[16];
    size_t env_need = 0u;
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_getenv_s(&env_need, env_buf, sizeof(env_buf), "path", env_tbl, 2u, &err) == 0);
    TEST_ASSERT(env_need == 9u && strcmp(env_buf, "C:\\Rome2") == 0);
    TEST_ASSERT(rome2_vfs_crt_getenv_s(&env_need, env_buf, 4u, "PATH", env_tbl, 2u, &err) == 34 && env_need == 9u && err == 34);
    TEST_ASSERT(rome2_vfs_crt_getenv_s(&env_need, env_buf, sizeof(env_buf), "MISSING", env_tbl, 2u, &err) == 0 && env_need == 0u);

    /* 8. _flsbuf (0x116a5864) & _flswbuf (0x116a586f) */
    rome2_vfs_crt_stdio_stream56_32 st_out;
    memset(&st_out, 0, sizeof(st_out));
    st_out.flags_0c = 0x05u; /* _IOREAD | _IORW */
    mock_stream_ctx sc = { { 0 }, 0u, 1u, 1u };
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_flsbuf('R', &st_out, 0u, mock_seek0, mock_write_byte, &sc, &err) == 'R');
    TEST_ASSERT((st_out.flags_0c & 0x03u) == 0x02u && st_out.bufsiz_14 == 4096 && sc.len == 1u && sc.bytes[0] == 'R');
    TEST_ASSERT(rome2_vfs_crt_flswbuf(0x03b1u, &st_out, 0u, mock_seek0, mock_write_word, &sc, &err) == 0x03b1u);
    TEST_ASSERT(sc.len == 3u && sc.bytes[1] == 0xb1u && sc.bytes[2] == 0x03u);

    rome2_vfs_crt_stdio_stream56_32 st_bad;
    memset(&st_bad, 0, sizeof(st_bad));
    st_bad.flags_0c = 0x1002u; /* _IOWRITE | _IOSTRG */
    TEST_ASSERT(rome2_vfs_crt_flsbuf('X', &st_bad, 0u, mock_seek0, mock_write_byte, &sc, &err) == -1);
    TEST_ASSERT(err == 34 && (st_bad.flags_0c & 0x10u) != 0u);

    /* 9. __wctomb_s_l (0x116a5b4b) */
    uint8_t mb_out[4] = { 0 };
    int32_t conv = -1;
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_wctomb_s_l(&conv, mb_out, sizeof(mb_out), 0x20acu, 65001u, 0u, &err) == 0);
    TEST_ASSERT(conv == 3 && mb_out[0] == 0xe2u && mb_out[1] == 0x82u && mb_out[2] == 0xacu);
    TEST_ASSERT(rome2_vfs_crt_wctomb_s_l(&conv, NULL, 4u, 0x0041u, 0u, 1u, &err) == 0 && conv == 0);
    TEST_ASSERT(rome2_vfs_crt_wctomb_s_l(&conv, mb_out, sizeof(mb_out), 0x03a9u, 0u, 1u, &err) == 42 && err == 42);

    /* 10. fp_format_e_internal (0x116a613a) & fp_format_f_internal (0x116a630d) */
    char fbuf[32];
    strcpy_s(fbuf, sizeof(fbuf), "125");
    rome2_vfs_crt_strflt12_32 sflt = { ' ', 12, 0u };
    TEST_ASSERT(rome2_vfs_crt_fp_format_e_internal(fbuf, sizeof(fbuf), 3, 1u, 2u, &sflt, "125", 1u, '.', &err) == 0);
    TEST_ASSERT(strcmp(fbuf, "1.25E+11") == 0);
    strcpy_s(fbuf, sizeof(fbuf), " 125");
    TEST_ASSERT(rome2_vfs_crt_fp_format_e_internal(fbuf, sizeof(fbuf), 2, 0u, 3u, &sflt, "125", 0u, '.', &err) == 0);
    TEST_ASSERT(strcmp(fbuf, "1.25e+011") == 0);

    rome2_vfs_crt_strflt12_32 sflt_f = { '-', -1, 0u };
    strcpy_s(fbuf, sizeof(fbuf), "-45");
    TEST_ASSERT(rome2_vfs_crt_fp_format_f_internal(fbuf, sizeof(fbuf), 3, &sflt_f, 0u, '.', &err) == 0);
    TEST_ASSERT(strcmp(fbuf, "-0.045") == 0);

    /* 11. try_get_LCMapStringEx (0x116a83bd) & LocaleNameToLCID (0x116a8a8d) */
    mock_api_ctx apic;
    memset(&apic, 0, sizeof(apic));
    TEST_ASSERT(rome2_vfs_crt_try_get_lcmapstring_ex(mock_resolve_api, &apic) == 0x12345678u);
    TEST_ASSERT(apic.seen_slot == 0x14u && strcmp(apic.seen_name, "LCMapStringEx") == 0);
    TEST_ASSERT(apic.first_mod == 3u && apic.first_ver == 16u && apic.second_mod == 4u);

    const uint16_t loc_en[6] = { 'e', 'n', '-', 'U', 'S', 0u };
    TEST_ASSERT(rome2_vfs_crt_locale_name_to_lcid(loc_en, 0u, 0u, 0u, 0u) == 0x0409u);
    TEST_ASSERT(rome2_vfs_crt_locale_name_to_lcid(loc_en, 0u, 1u, 0x0407u, 0x0409u) == 0x0407u);

    /* 12. return_illegal_sequence (0x116b149d) & GetStringTypeW (0x116b8215) */
    rome2_vfs_crt_mbstate8_32 mbst = { 0x1234u, 3u, 1u };
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_return_illegal_sequence(&mbst, &err) == 0xffffffffu);
    TEST_ASSERT(err == 42 && mbst.wchar_00 == 0u && mbst.byte_04 == 0u && mbst.state_06 == 0u);

    const uint16_t ctype_in[4] = { 'A', '9', ' ', '!' };
    uint16_t ctype_out[4] = { 0 };
    TEST_ASSERT(rome2_vfs_crt_get_string_type_w(1u, ctype_in, 4, ctype_out) == 1u);
    TEST_ASSERT((ctype_out[0] & 0x0181u) == 0x0181u); /* UPPER | ALPHA | XDIGIT */
    TEST_ASSERT((ctype_out[1] & 0x0084u) == 0x0084u); /* DIGIT | XDIGIT */
    TEST_ASSERT((ctype_out[2] & 0x0048u) == 0x0048u); /* BLANK | SPACE */
    TEST_ASSERT((ctype_out[3] & 0x0010u) == 0x0010u); /* PUNCT */

    /* 13. Console init (0x116bd4d3), terminate (0x116bd511), and strrchr (0x116bf330) */
    mock_con_ctx con;
    memset(&con, 0, sizeof(con));
    uint32_t chnd = 0xfffffffeu;
    rome2_vfs_crt_console_output_init(&chnd, mock_open_con, &con);
    TEST_ASSERT(chnd == 0x44u && con.name[0] == 'C' && con.name[6] == '$');
    TEST_ASSERT(rome2_vfs_crt_console_output_terminate(0xfffffffeu, mock_close_con, &con) == 0u && con.close_calls == 0);
    TEST_ASSERT(rome2_vfs_crt_console_output_terminate(0xffffffffu, mock_close_con, &con) == 0u && con.close_calls == 0);
    TEST_ASSERT(rome2_vfs_crt_console_output_terminate(chnd, mock_close_con, &con) == 1u && con.closed_handle == 0x44u && con.close_calls == 1);

    const char *hay = "alpha/beta/gamma";
    const char *hit = rome2_vfs_crt_strrchr(hay, 32u, '/', 1u);
    TEST_ASSERT(hit == hay + 10);
    TEST_ASSERT(rome2_vfs_crt_strrchr(hay, 32u, '\0', 0u) == hay + strlen(hay));
    TEST_ASSERT(rome2_vfs_crt_strrchr(hay, 32u, 'z', 5u) == NULL);

    printf("test_vfs_fs_engine_crt_fls_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
