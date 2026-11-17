#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_engine_crt_ops.h"

static void check_fail(const char *msg, int line)
{
    fprintf(stderr, "FAIL line %d: %s\n", line, msg);
    exit(1);
}

#define CHECK(cond) do { if (!(cond)) check_fail(#cond, __LINE__); } while (0)

static void ascii_to_u16(const char *s, uint16_t *dst, uint32_t cap)
{
    uint32_t i = 0u;
    while (s[i] != '\0' && i + 1u < cap) {
        dst[i] = (uint8_t)s[i];
        i++;
    }
    dst[i] = 0u;
}

static void test_layouts_and_mgr(void)
{
    rome2_vfs_crt_filex56_32 f;
    rome2_vfs_cxx_throw_template32_32 exc;
    rome2_vfs_channel_mgr564_32 mgr;

    CHECK(sizeof(f) == 0x38u);
    CHECK(sizeof(exc) == 0x20u);
    CHECK(sizeof(mgr) == 0x234u);

    CHECK(rome2_vfs_channel_mgr564_init(&mgr, 0x1201ae48u) == ROME2_VFS_REG_OK);
    CHECK(mgr.slots_00[0][0] == 0x1201ae4cu);
    CHECK(mgr.slots_00[0][1] == 0u && mgr.slots_00[0][2] == 0u);
    CHECK(mgr.slots_00[46][0] == 0x1201ae48u + 46u * 12u + 4u);
}

static void test_wstr_scanners_and_sock(void)
{
    uint16_t fmt[32];
    uint16_t out[96];
    uint16_t pos = 0u;
    uint32_t len = 0u;
    uint8_t ok = 0u;
    int32_t sbytes = 0;

    ascii_to_u16("A%%B%lc", fmt, 32u);
    CHECK(rome2_vfs_format_scan_char_wstr(fmt, 7u, &pos, (uint16_t)'Z', out, 96u, &len, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 1u && len == 4u && out[0] == 'A' && out[1] == '%' && out[2] == 'B' && out[3] == 'Z');

    pos = 0u;
    ascii_to_u16("%d", fmt, 32u);
    CHECK(rome2_vfs_format_scan_char_wstr(fmt, 2u, &pos, (uint16_t)'Z', out, 96u, &len, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 0u && len > 20u);

    pos = 0u;
    ascii_to_u16("id=%u", fmt, 32u);
    CHECK(rome2_vfs_format_scan_scalar_wstr(fmt, 5u, &pos, 42u, 0u, out, 96u, &len, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 1u && len == 5u && out[3] == '4' && out[4] == '2');

    ascii_to_u16("hi", fmt, 32u);
    CHECK(rome2_vfs_wstr_append_char_slice(fmt, 2u, (uint16_t)'!', out, 96u, &len) == ROME2_VFS_REG_OK);
    CHECK(len == 3u && out[2] == '!' && out[3] == 0u);

    CHECK(rome2_vfs_sock_send_or_err(128, 0u, &sbytes) == NULL && sbytes == 128);
    CHECK(rome2_vfs_sock_send_or_err(-1, 10054u, &sbytes) != NULL && sbytes == -1);
}

static void test_dlmalloc_queue_steam(void)
{
    uint8_t is_tree = 0u;
    uint32_t new_top = 0u, new_topsz = 0u, old_free = 0u;
    uint32_t c_va = 0u, nxt_va = 0u, rem = 0u;
    uint8_t hit = 0u;
    rome2_vfs_ts_sample_queue q;
    uint8_t pkt[32];
    uint32_t bit_pos = 0u;
    uint8_t ok = 0u;
    int32_t stype = 0, ichan = -1;

    CHECK(rome2_vfs_dlmalloc_chunk_align8(0x1003u) == 0x1008u);
    CHECK(rome2_vfs_dlmalloc_bin_index(64u, &is_tree) == 8u && is_tree == 0u);
    CHECK(rome2_vfs_dlmalloc_bin_index(512u, &is_tree) >= 2u && is_tree == 1u);

    CHECK(rome2_vfs_dlmalloc_add_segment_plan(0x201000u, 0x200000u, 0x300004u, 0x10000u, &new_top, &new_topsz, &old_free) == ROME2_VFS_REG_OK);
    CHECK(new_top == 0x300008u && old_free == 0x1000u - 0x28u);

    CHECK(rome2_vfs_dlmalloc_prepend_plan(0x400004u, 0x20u, 0x400100u, 0x400100u, 0u, &c_va, &nxt_va, &rem, &hit) == ROME2_VFS_REG_OK);
    CHECK(c_va == 0x400008u && nxt_va == 0x400100u && rem == 0xd8u && hit == 1u);

    memset(&q, 0, sizeof(q));
    CHECK(rome2_vfs_ts_queue_push(&q, 100u, 64u) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_ts_queue_push(&q, 200u, 36u) == ROME2_VFS_REG_OK);
    CHECK(q.count == 2u && q.byte_sum == 100u);

    memset(pkt, 0, sizeof(pkt));
    CHECK(rome2_vfs_channel_patch_hdr_pack(3u, 10u, 128u, pkt, sizeof(pkt), &bit_pos, &ok) == ROME2_VFS_REG_OK);
    CHECK(ok == 1u && pkt[0] == 3u && bit_pos == 127u);

    /* Individual SteamID: universe=1, type=1, instance=1, account=0x1234 -> 0x01100001_00001234 */
    CHECK(rome2_vfs_steam_id_is_valid(0x00001234u, 0x01100001u) == 1u);
    CHECK(rome2_vfs_steam_id_is_valid(0u, 0x01100001u) == 0u);
    CHECK(rome2_vfs_steam_id_is_valid(0x1234u, 0x01700000u) == 1u);
    CHECK(rome2_vfs_steam_id_is_valid(0x1234u, 0x01700001u) == 0u);

    CHECK(rome2_vfs_steam_send_p2p_plan(0x1234u, 0x01100001u, pkt, 16u, 1u, &stype, &ichan, &ok) == ROME2_VFS_REG_OK);
    CHECK(stype == 2 && ichan == 0 && ok == 1u);
}

static void test_crt_helpers(void)
{
    uint32_t tbl[4] = {0u};
    uint32_t cnt = 0u;
    int32_t guard = 0, tls_ep = 0, err = 0, decpt = 0, sign = 0;
    uint8_t should_init = 0u;
    rome2_vfs_crt_filex56_32 iob[3];
    char buf[32];
    uint16_t hay[16], ndl[8];
    const uint8_t mem[6] = {1u, 2u, 3u, 4u, 5u, 6u};
    uint32_t tid = 0u;
    rome2_vfs_cxx_throw_template32_32 exc;
    uint8_t raw[8];

    CHECK(rome2_vfs_crt_atexit_slot(tbl, 4u, &cnt, 0x10001234u) == 0 && cnt == 1u);
    CHECK(rome2_vfs_crt_atexit_slot(tbl, 1u, &cnt, 0x10005678u) == -1);

    CHECK(rome2_vfs_crt_init_thread_header(&guard, &tls_ep, 5, &should_init) == ROME2_VFS_REG_OK);
    CHECK(guard == -1 && should_init == 1u);
    guard = 7;
    CHECK(rome2_vfs_crt_init_thread_header(&guard, &tls_ep, 9, &should_init) == ROME2_VFS_REG_OK);
    CHECK(should_init == 0u && tls_ep == 9);

    CHECK(rome2_vfs_crt_ftoui3(42.9f) == 42u);
    CHECK(rome2_vfs_crt_ftoui3(2147483648.0f) == 0x80000000u);
    CHECK(rome2_vfs_crt_ftoui3(-0.5f) == 0u);
    CHECK(rome2_vfs_crt_ftoui3(-1.0f) == 0xffffffffu);
    CHECK(rome2_vfs_crt_ftoui3(nanf("")) == 0xffffffffu);

    memset(iob, 0, sizeof(iob));
    iob[1].flag_0c = 0x2012u;
    CHECK(rome2_vfs_crt_iob_slot_va(2u) == 0x119ebe18u + 0x70u);
    CHECK(rome2_vfs_crt_iob_slot_host(iob, 1u) == &iob[1]);
    CHECK(rome2_vfs_crt_iob_slot_host(iob, 3u) == NULL);
    CHECK(rome2_vfs_crt_feof_filex(&iob[1], &err) == 1 && err == 0);
    CHECK(rome2_vfs_crt_feof_filex(NULL, &err) == 0 && err == EINVAL);

    CHECK(rome2_vfs_crt_floor_f64(3.75) == 3.0);
    CHECK(rome2_vfs_crt_floor_f64(-3.25) == -4.0);
    CHECK(rome2_vfs_crt_floor_f64(-3.0) == -3.0);
    CHECK(rome2_vfs_crt_floor_f64(-0.5) == -1.0);
    CHECK(rome2_vfs_crt_floor_f64(0.5) == 0.0);

    CHECK(rome2_vfs_crt_vsnprintf_bounded(buf, sizeof(buf), "v=%d:%s", 7, "ok", &err) == 6 && strcmp(buf, "v=7:ok") == 0);
    CHECK(rome2_vfs_crt_vsnprintf_bounded(NULL, 8u, "x", 0, NULL, &err) == 0x7fffffff && err == EINVAL);

    CHECK(rome2_vfs_crt_ecvt_s(buf, sizeof(buf), -12.345, 4, &decpt, &sign) == 0);
    CHECK(sign == 1 && decpt == 2 && strncmp(buf, "1234", 4) == 0);
    CHECK(rome2_vfs_crt_ecvt_s(NULL, 8u, 1.0, 2, &decpt, &sign) == EINVAL);

    CHECK(rome2_vfs_crt_memset(raw, 0xa5, sizeof(raw)) == raw && raw[0] == 0xa5u && raw[7] == 0xa5u);
    ascii_to_u16("hello_rome", hay, 16u);
    ascii_to_u16("rome", ndl, 8u);
    CHECK(rome2_vfs_crt_wcsstr_u16(hay, ndl) == hay + 6);
    CHECK(rome2_vfs_crt_memchr(mem, 4u, sizeof(mem)) == mem + 3);
    CHECK(rome2_vfs_crt_memchr(mem, 9u, sizeof(mem)) == NULL);

    CHECK(rome2_vfs_crt_beginthreadex_validate(0u, 101u, &tid, &err) == ROME2_VFS_REG_BAD_ARGUMENT && err == EINVAL);
    CHECK(rome2_vfs_crt_beginthreadex_validate((uintptr_t)&test_crt_helpers, 101u, &tid, &err) == ROME2_VFS_REG_OK && tid == 101u);

    CHECK(rome2_vfs_crt_cxx_throw_record_init(&exc, 0x12340000u, 0x11924804u, 8u) == ROME2_VFS_REG_OK);
    CHECK(exc.exception_code_00 == ROME2_VFS_L40_CXX_EH_CODE && exc.magic_number_14 == ROME2_VFS_L40_CXX_EH_WINRT_MAGIC);
    CHECK(rome2_vfs_crt_cxx_throw_record_init(&exc, 0x12340000u, 0x11924804u, 0u) == ROME2_VFS_REG_OK);
    CHECK(exc.magic_number_14 == ROME2_VFS_L40_CXX_EH_MAGIC1 && exc.throw_info_1c == 0x11924804u);
}

int main(void)
{
    test_layouts_and_mgr();
    test_wstr_scanners_and_sock();
    test_dlmalloc_queue_steam();
    test_crt_helpers();
    puts("test_vfs_fs_engine_crt_ops: ALL PASSED (49 checks)");
    return 0;
}
