#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_leaf_codec_ops.h"

static uint32_t g_checks = 0u;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond);            \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static rome2_vfs_dlmalloc_model g_dlmalloc;

static void test_handles_and_strings(void) {
    rome2_vfs_stream_handle36_32 sh;
    uint16_t wbuf[32];
    uint16_t wadd[4] = {'!', 'o', 'k', 0u};
    uint32_t wlen = 0u;
    uint32_t wcap = 16u;
    char abuf[64];
    uint32_t alen;
    uint8_t changed = 0u;

    rome2_vfs_stream_handle36_init(&sh);
    CHECK(sh.state_tag_00 == 3u && sh.primary_handle_08 == 0xffffffffu && sh.secondary_handle_0c == 0xffffffffu);
    sh.owned_flags_04 = 3u;
    sh.primary_handle_08 = 11u;
    sh.secondary_handle_0c = 22u;
    sh.mapped_view_ptr_20 = 0x1234u;
    rome2_vfs_stream_handle36_destroy(&sh);
    CHECK(sh.primary_handle_08 == 0xffffffffu && sh.secondary_handle_0c == 0xffffffffu && sh.owned_flags_04 == 0u);

    CHECK(rome2_vfs_wstr_fill_repeat(wbuf, 32u, 4u, 'A', &wlen) == ROME2_VFS_REG_OK);
    CHECK(wlen == 4u && wbuf[0] == 'A' && wbuf[3] == 'A' && wbuf[4] == 0u);
    CHECK(rome2_vfs_wstr_assign_raw(wbuf, &wcap, 32u, wadd, &wlen) == ROME2_VFS_REG_OK && wlen == 3u);
    CHECK(rome2_vfs_wstr_append(wbuf, &wlen, 32u, wadd, 3u) == ROME2_VFS_REG_OK && wlen == 6u && wbuf[5] == 'k');

    CHECK(rome2_vfs_astr_not_equal("alpha", "beta") == 1u);
    CHECK(rome2_vfs_astr_not_equal("alpha", "alpha") == 0u);
    CHECK(rome2_vfs_str_concat_join(abuf, sizeof(abuf), "data\\", "ui.pack") == ROME2_VFS_REG_OK);
    CHECK(strcmp(abuf, "data\\ui.pack") == 0);
    alen = (uint32_t)strlen(abuf);
    CHECK(rome2_vfs_astr_append_cstr(abuf, &alen, sizeof(abuf), ".bin") == ROME2_VFS_REG_OK);
    CHECK(strcmp(abuf, "data\\ui.pack.bin") == 0);
    CHECK(rome2_vfs_astr_rfind_char(abuf, '.', alen) == 12u);

    CHECK(rome2_vfs_normalize_slashes_and_lower("Data/UI//Icons.Pack", abuf, sizeof(abuf), &changed) == ROME2_VFS_REG_OK);
    CHECK(changed == 1u && strcmp(abuf, "data\\ui\\icons.pack") == 0);
}

static void test_error_switches_probe_and_dlmalloc(void) {
    uint16_t wprobe[16];
    uint32_t plen = 0u;
    rome2_vfs_file_size_state8_32 fsz = { 7u, 99u };
    uint8_t *p1;
    uint8_t *p2;

    CHECK(rome2_vfs_map_win32_error_io(0u) == 0u);
    CHECK(rome2_vfs_map_win32_error_io(2u) == 3u && rome2_vfs_map_win32_error_io(5u) == 7u);
    CHECK(rome2_vfs_map_win32_error_io(0x3e5u) == 2u && rome2_vfs_map_win32_error_io(0x3eeu) == 0x17u);
    CHECK(rome2_vfs_map_win32_error_stream(0x718u) == 6u && rome2_vfs_map_win32_error_stream(0x3e6u) == 0x13u);

    CHECK(rome2_vfs_check_u64_budget_limit(0u, 2u, 0xffffffffu, 1u) == 1u);
    CHECK(rome2_vfs_check_u64_budget_limit(10u, 1u, 11u, 1u) == 0u);
    CHECK(rome2_vfs_utf8_to_utf16_dispatch_probe("ok", wprobe, 16u, &plen) == ROME2_VFS_REG_OK && plen == 2u);
    CHECK(rome2_vfs_wait_event_guard_probe(1u, 42u) == 42u);

    CHECK(rome2_vfs_map_seek_result(1u, 5u) == 0u);
    CHECK(rome2_vfs_map_seek_result(0u, 5u) == 7u);
    CHECK(rome2_vfs_probe_file_size_state(&fsz, 1024u, 99u) == 1024u && fsz.last_error_04 == 0u);
    CHECK(rome2_vfs_probe_file_size_state(&fsz, 0xffffffffu, 5u) == 0xffffffffu && fsz.last_error_04 == 5u);

    rome2_vfs_dlmalloc_model_init(&g_dlmalloc);
    CHECK(rome2_vfs_dlmalloc_request_size(8u) == 16u && rome2_vfs_dlmalloc_request_size(25u) == 32u);
    p1 = rome2_vfs_dlmalloc_model_alloc(&g_dlmalloc, 20u);
    CHECK(p1 != NULL && g_dlmalloc.mstate.footprint_1b0 == 24u);
    rome2_vfs_dlmalloc_model_free(&g_dlmalloc, p1);
    CHECK((g_dlmalloc.mstate.smallmap_00 & (1u << 3u)) != 0u);
    p2 = rome2_vfs_dlmalloc_model_alloc(&g_dlmalloc, 16u);
    CHECK(p2 == p1 && (g_dlmalloc.mstate.smallmap_00 & (1u << 3u)) == 0u);
}

int main(void) {
    test_handles_and_strings();
    test_error_switches_probe_and_dlmalloc();
    printf("test_vfs_fs_leaf_codec_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
