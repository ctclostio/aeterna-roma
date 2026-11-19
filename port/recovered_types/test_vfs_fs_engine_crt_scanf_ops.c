#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_crt_scanf_ops.h"

#define TEST_ASSERT(cond)                                                          \
    do {                                                                           \
        if (!(cond)) {                                                             \
            fprintf(stderr, "FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            return 1;                                                              \
        }                                                                          \
        ++g_checks;                                                                \
    } while (0)

typedef struct mock_io_ctx {
    uint8_t disk[64];
    size_t len;
    int64_t seek_offset;
    int32_t seek_origin;
    uint32_t unlock_arg;
    uint32_t api_slot;
    char api_name[32];
    uint32_t mod_id;
} mock_io_ctx;

static int64_t mock_lseek64(int32_t fh, int64_t off, int32_t origin, void *ctx) {
    (void)fh;
    mock_io_ctx *c = (mock_io_ctx *)ctx;
    c->seek_offset = off;
    c->seek_origin = origin;
    return (origin == 2) ? (int64_t)c->len : off;
}

static int32_t mock_write_lowio(int32_t fh, const void *buf, uint32_t byte_count, void *ctx) {
    (void)fh;
    mock_io_ctx *c = (mock_io_ctx *)ctx;
    if (c->len + byte_count > sizeof(c->disk)) {
        return -1;
    }
    memcpy(c->disk + c->len, buf, byte_count);
    c->len += byte_count;
    return (int32_t)byte_count;
}

static void mock_unlock(uint32_t lock_idx, void *ctx) {
    mock_io_ctx *c = (mock_io_ctx *)ctx;
    c->unlock_arg = lock_idx;
}

static uint32_t mock_resolve_lcid_api(
    uint32_t table_slot,
    const char *api_name,
    const rome2_vfs_crt_api_mod_desc8_32 *begin_desc,
    const rome2_vfs_crt_api_mod_desc8_32 *end_marker,
    void *ctx) {
    (void)end_marker;
    mock_io_ctx *c = (mock_io_ctx *)ctx;
    c->api_slot = table_slot;
    strncpy_s(c->api_name, sizeof(c->api_name), api_name, _TRUNCATE);
    c->mod_id = begin_desc->module_id_00;
    return 0x55aa1122u;
}

int main(void) {
    int g_checks = 0;

    /* 1. New + corrected guest32 layouts */
    TEST_ASSERT(sizeof(rome2_vfs_crt_stdio_stream56_32) == 0x38u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_stdio_stream56_32, charbuf_14) == 0x14u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_stdio_stream56_32, bufsiz_18) == 0x18u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_input_char_source32_32) == 0x20u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_input_char_source32_32, read_count_lo_10) == 0x10u);
    TEST_ASSERT(offsetof(rome2_vfs_crt_input_char_source32_32, succeeded_ptr_18) == 0x18u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_lcid_name_entry8_32) == 0x08u);
    TEST_ASSERT(sizeof(rome2_vfs_crt_locale_index_entry8_32) == 0x08u);

    /* 2. make_input_char_source (0x1168f338) & parse_uint64_adapter (0x11691750) */
    rome2_vfs_crt_input_char_source32_32 cs;
    TEST_ASSERT(rome2_vfs_crt_make_input_char_source(&cs, 0x10002000u, 0x0000000100000010ULL, 0x20003000u) == &cs);
    TEST_ASSERT(cs.adapter_ptr_00 == 0x10002000u && cs.width_lo_08 == 0x10u && cs.width_hi_0c == 1u && cs.succeeded_ptr_18 == 0x20003000u);

    size_t used = 0u;
    uint8_t ok = 0u;
    int32_t err = 0;
    uint64_t u64 = rome2_vfs_crt_parse_uint64_adapter("  -0x123456789abcZ", 32u, &used, 0, 1u, &ok, &err);
    TEST_ASSERT(ok == 1u && err == 0 && used == 17u && u64 == (uint64_t)(-0x123456789abcLL));

    u64 = rome2_vfs_crt_parse_uint64_adapter("99999999999999999999", 32u, &used, 10, 0u, &ok, &err);
    TEST_ASSERT(ok == 1u && err == 34 && u64 == UINT64_MAX);
    err = 0;
    u64 = rome2_vfs_crt_parse_uint64_adapter("9223372036854775808", 32u, &used, 10, 1u, &ok, &err);
    TEST_ASSERT(ok == 1u && err == 34 && u64 == 0x7fffffffffffffffULL);

    /* 3. scanf length (0x11695bf3), write_integer (0x116974ef), process_integer_specifier (0x116960bc) */
    rome2_vfs_crt_scanf_input116_32 in_st;
    memset(&in_st, 0, sizeof(in_st));
    in_st.fmt_18.conv_idx_28 = 2u;   /* int */
    in_st.fmt_18.length_idx_20 = 4u; /* ll -> 8 bytes */
    TEST_ASSERT(rome2_vfs_crt_scanf_format_length(&in_st.fmt_18) == 8u);
    in_st.fmt_18.conv_idx_28 = 7u;   /* float */
    in_st.fmt_18.length_idx_20 = 3u; /* l -> 8 bytes double */
    TEST_ASSERT(rome2_vfs_crt_scanf_format_length(&in_st.fmt_18) == 8u);
    in_st.fmt_18.conv_idx_28 = 1u;   /* string */
    in_st.fmt_18.is_wide_24 = 1u;    /* %ls -> 2 bytes */
    TEST_ASSERT(rome2_vfs_crt_scanf_format_length(&in_st.fmt_18) == 2u);

    in_st.fmt_18.conv_idx_28 = 2u;
    in_st.fmt_18.length_idx_20 = 2u; /* h -> 2 bytes */
    uint16_t short_out = 0u;
    size_t cur = 0u;
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_scanf_process_integer_specifier(&in_st, "  -321xy", &cur, 16u, 10, 1u, &short_out, &err) == 1u);
    TEST_ASSERT(cur == 6u && (int16_t)short_out == -321 && err == 0);
    TEST_ASSERT(rome2_vfs_crt_scanf_write_integer(&in_st.fmt_18, NULL, 5u, &err) == 0u && err == 22);

    /* 4. process_string_narrow (0x116923d9), wide (0x11692817), specifier (0x116963d4) */
    in_st.fmt_18.conv_idx_28 = 1u;
    in_st.fmt_18.is_wide_24 = 0u;
    in_st.fmt_18.width_18 = 4u;
    char sbuf[16] = { 0 };
    cur = 0u;
    TEST_ASSERT(rome2_vfs_crt_scanf_process_string_specifier(&in_st, "  hello world", &cur, 32u, 1u, sbuf, sizeof(sbuf), &err) == 1u);
    TEST_ASSERT(strcmp(sbuf, "hell") == 0 && cur == 6u);

    in_st.fmt_18.is_wide_24 = 1u;
    in_st.fmt_18.width_18 = 0u;
    in_st.fmt_18.conv_idx_28 = 8u; /* scanset */
    in_st.fmt_18.scanset_words_2c[(uint8_t)'a' >> 5] |= 1u << ((uint8_t)'a' & 31u);
    in_st.fmt_18.scanset_words_2c[(uint8_t)'b' >> 5] |= 1u << ((uint8_t)'b' & 31u);
    uint16_t wbuf[16] = { 0 };
    cur = 0u;
    TEST_ASSERT(rome2_vfs_crt_scanf_process_string_specifier(&in_st, "abba123", &cur, 16u, 8u, wbuf, 16u, &err) == 1u);
    TEST_ASSERT(wbuf[0] == 'a' && wbuf[3] == 'a' && wbuf[4] == 0u && cur == 4u);

    /* 5. _lseeki64 forward (0x1169e7db), getenv_nolock (0x1169e998), SEH unlock (0x1169eadf), getenv_s_nolock (0x1169eb47) */
    mock_io_ctx io;
    memset(&io, 0, sizeof(io));
    TEST_ASSERT(rome2_vfs_crt_lseeki64_forward(3, 512LL, 1, mock_lseek64, &io) == 512LL);
    TEST_ASSERT(io.seek_offset == 512LL && io.seek_origin == 1);

    const char *env_arr[2] = { "ROME2_HOME=X:\\game", "EMPTY=" };
    TEST_ASSERT(strcmp(rome2_vfs_crt_common_getenv_nolock("rome2_home", env_arr, 2u), "X:\\game") == 0);
    rome2_vfs_crt_getenv_seh_unlock(mock_unlock, &io);
    TEST_ASSERT(io.unlock_arg == 0x0bu);

    char gbuf[16] = { 0 };
    size_t greq = 0u;
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_common_getenv_s_nolock(&greq, gbuf, sizeof(gbuf), "ROME2_HOME", env_arr, 2u, &err) == 0);
    TEST_ASSERT(greq == 8u && strcmp(gbuf, "X:\\game") == 0);
    TEST_ASSERT(rome2_vfs_crt_common_getenv_s_nolock(&greq, gbuf, 4u, "ROME2_HOME", env_arr, 2u, &err) == 34 && err == 34);

    /* 6. write_buffer_nolock<char|wchar_t> (0x116a5645/0x116a5711), EOF check (0x116a57df), fp_shift (0x116a6534) */
    rome2_vfs_crt_stdio_stream56_32 fs;
    memset(&fs, 0, sizeof(fs));
    uint32_t cflush = 10u;
    rome2_vfs_crt_stdio_allocate_buffer_nolock(&fs, 0u, 0x119ec014u, &cflush);
    TEST_ASSERT(cflush == 11u && (fs.flags_0c & 0x400u) != 0u && fs.base_04 == 0x119ec014u && fs.bufsiz_18 == 2);

    rome2_vfs_crt_stdio_allocate_buffer_nolock(&fs, 0x20001000u, 0u, &cflush);
    TEST_ASSERT(cflush == 12u && (fs.flags_0c & 0x40u) != 0u && fs.base_04 == 0x20001000u && fs.bufsiz_18 == 4096);

    uint8_t sbuf_io[64] = { 'A', 'B' };
    size_t io_pos = 2u;
    fs.file_10 = 3;
    TEST_ASSERT(rome2_vfs_crt_write_buffer_nolock_char('C', &fs, sbuf_io, sizeof(sbuf_io), &io_pos, 1u, mock_lseek64, mock_write_lowio, &io) == 1u);
    TEST_ASSERT(io.len == 2u && io.disk[0] == 'A' && io.disk[1] == 'B' && sbuf_io[0] == 'C' && io_pos == 1u);
    TEST_ASSERT(rome2_vfs_crt_write_buffer_nolock_wchar(0x03b2u, &fs, sbuf_io, sizeof(sbuf_io), &io_pos, 0u, mock_lseek64, mock_write_lowio, &io) == 1u);
    TEST_ASSERT(io.len == 3u && io.disk[2] == 'C' && sbuf_io[0] == 0xb2u && sbuf_io[1] == 0x03u);

    TEST_ASSERT(rome2_vfs_crt_is_at_eof_for_write_transition(&fs, 1u, 1u, 100LL, 1u, 100LL) == 1u);
    TEST_ASSERT(rome2_vfs_crt_is_at_eof_for_write_transition(&fs, 1u, 1u, 50LL, 1u, 100LL) == 0u);
    fs.flags_0c |= 0x08u; /* _IOEOF */
    TEST_ASSERT(rome2_vfs_crt_is_at_eof_for_write_transition(&fs, 0u, 0u, 0LL, 0u, 100LL) == 1u);

    char shbuf[16] = "123";
    rome2_vfs_crt_fp_shift_bytes_right(shbuf, sizeof(shbuf), 0u, 1u);
    TEST_ASSERT(strcmp(shbuf, "1123") == 0);

    /* 7. try_get_LocaleNameToLCID (0x116a83d7), __c32rtomb_utf8 (0x116b14bc), downlevel tables (0x116b80ef/0x116b81e9) */
    TEST_ASSERT(rome2_vfs_crt_try_get_locale_name_to_lcid(mock_resolve_lcid_api, &io) == 0x55aa1122u);
    TEST_ASSERT(io.api_slot == 0x16u && strcmp(io.api_name, "LocaleNameToLCID") == 0 && io.mod_id == 3u);

    rome2_vfs_crt_mbstate8_32 mb = { 7u, 2u, 1u };
    uint8_t u8[4] = { 0u, 0u, 0u, 0u };
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(u8, sizeof(u8), 'A', &mb, &err) == 1u && u8[0] == 'A');
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(u8, sizeof(u8), 0x20acu, &mb, &err) == 3u && u8[0] == 0xe2u && u8[1] == 0x82u && u8[2] == 0xacu);
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(u8, sizeof(u8), 0x1f600u, &mb, &err) == 4u && u8[0] == 0xf0u && u8[1] == 0x9fu && u8[2] == 0x98u && u8[3] == 0x80u);
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(u8, sizeof(u8), 0xd800u, &mb, &err) == 0xffffffffu && err == 42);
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(u8, sizeof(u8), 0xdc00u, &mb, &err) == 0xffffffffu && err == 42);
    err = 0;
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(u8, sizeof(u8), 0x110000u, &mb, &err) == 0xffffffffu && err == 42);

    static const uint16_t k_de[6] = { 'd', 'e', '-', 'D', 'E', 0u };
    static const uint16_t k_en[6] = { 'e', 'n', '-', 'U', 'S', 0u };
    static const uint16_t k_fr[6] = { 'f', 'r', '-', 'F', 'R', 0u };
    const rome2_vfs_crt_locale_entry_pair tbl[3] = {
        { k_de, 0, 0x0407u },
        { k_en, 1, 0x0409u },
        { k_fr, 2, 0x040cu },
    };
    const uint32_t lcids[3] = { 0x0407u, 0x0409u, 0x040cu };
    const uint16_t q_en[6] = { 'E', 'N', '-', 'u', 's', 0u };
    TEST_ASSERT(rome2_vfs_crt_downlevel_locale_index(q_en, tbl, 3u) == 1);
    TEST_ASSERT(rome2_vfs_crt_downlevel_locale_name_to_lcid(q_en, tbl, lcids, 3u) == 0x0409u);
    TEST_ASSERT(rome2_vfs_crt_downlevel_locale_name_to_lcid(k_de, tbl, lcids, 3u) == 0x0407u);
    TEST_ASSERT(rome2_vfs_crt_downlevel_locale_name_to_lcid(k_fr, tbl, lcids, 3u) == 0x040cu);
    TEST_ASSERT(rome2_vfs_crt_downlevel_locale_name_to_lcid(k_en, tbl, lcids, 3u) == 0x0409u);

    /* 8. Additional edge-case & error-path checks */
    const uint16_t k_missing[6] = { 'z', 'z', '-', 'Z', 'Z', 0u };
    TEST_ASSERT(rome2_vfs_crt_downlevel_locale_index(k_missing, tbl, 3u) == -1);
    TEST_ASSERT(rome2_vfs_crt_downlevel_locale_name_to_lcid(k_missing, tbl, lcids, 3u) == 0u);
    TEST_ASSERT(rome2_vfs_crt_downlevel_locale_name_to_lcid(NULL, tbl, lcids, 3u) == 0u);

    mb.state_06 = 9u;
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(NULL, 0u, 0x0041u, &mb, &err) == 1u);
    TEST_ASSERT(mb.state_06 == 0u);
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(u8, sizeof(u8), 0u, &mb, &err) == 1u);
    TEST_ASSERT(u8[0] == 0u);
    TEST_ASSERT(rome2_vfs_crt_c32rtomb_utf8(u8, 1u, 0x03a9u, &mb, &err) == 0xffffffffu);
    TEST_ASSERT(err == 34);

    err = 0;
    TEST_ASSERT(rome2_vfs_crt_parse_uint64_adapter("0", 1u, &used, 99, 0u, &ok, &err) == 0ULL);
    TEST_ASSERT(ok == 0u && err == 22);
    TEST_ASSERT(rome2_vfs_crt_common_getenv_nolock("NO_SUCH_VAR", env_arr, 2u) == NULL);
    TEST_ASSERT(rome2_vfs_crt_common_getenv_s_nolock(&greq, NULL, 8u, "ROME2_HOME", env_arr, 2u, &err) == 22);
    TEST_ASSERT(rome2_vfs_crt_common_getenv_s_nolock(&greq, gbuf, sizeof(gbuf), "EMPTY", env_arr, 2u, &err) == 0);
    TEST_ASSERT(greq == 1u && gbuf[0] == '\0');

    in_st.fmt_18.conv_idx_28 = 99u;
    TEST_ASSERT(rome2_vfs_crt_scanf_format_length(&in_st.fmt_18) == 0u);
    in_st.fmt_18.conv_idx_28 = 0u; /* %c single byte */
    in_st.fmt_18.is_wide_24 = 0u;
    TEST_ASSERT(rome2_vfs_crt_scanf_format_length(&in_st.fmt_18) == 1u);
    in_st.fmt_18.conv_idx_28 = 2u;
    in_st.fmt_18.suppress_16 = 1u;
    cur = 0u;
    TEST_ASSERT(rome2_vfs_crt_scanf_process_integer_specifier(&in_st, "777", &cur, 8u, 10, 0u, NULL, &err) == 1u);
    TEST_ASSERT(cur == 3u);

    uint8_t byte_out = 0u;
    in_st.fmt_18.suppress_16 = 0u;
    in_st.fmt_18.length_idx_20 = 1u; /* hh -> 1 byte */
    TEST_ASSERT(rome2_vfs_crt_scanf_write_integer(&in_st.fmt_18, &byte_out, 0x1234ULL, &err) == 1u);
    TEST_ASSERT(byte_out == 0x34u);

    printf("test_vfs_fs_engine_crt_scanf_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
