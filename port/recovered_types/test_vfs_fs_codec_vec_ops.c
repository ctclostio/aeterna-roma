#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs_fs_codec_vec_ops.h"

static uint32_t g_checks = 0u;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond);            \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static void test_wstr_fmt_and_sys(void) {
    uint16_t fill_buf[8];
    uint16_t joined[16];
    uint16_t wlhs[3] = { 'h', 'i', 0u };
    uint16_t wrhs[3] = { 't', 'w', 0u };
    uint32_t jlen = 0u;
    uint32_t idx = 0u;
    char scan_out[32] = "";
    uint32_t scan_len = 0u;
    rome2_vfs_mem_status_ex64_32 mstat;
    uint16_t pct_in[5] = { '%', 's', '%', 'd', 0u };
    uint16_t pct_out[8];
    char nbuf[32];

    rome2_vfs_fill_u16_range(fill_buf, 4u, 0x0058u);
    CHECK(fill_buf[0] == 0x0058u && fill_buf[3] == 0x0058u);
    CHECK(rome2_vfs_wstr_concat_join(joined, 16u, &jlen, wlhs, 2u, wrhs, 2u) == ROME2_VFS_REG_OK && jlen == 4u);
    CHECK(rome2_vfs_wstr_push_back(joined, &jlen, 16u, '!') == ROME2_VFS_REG_OK && jlen == 5u && joined[4] == '!');

    CHECK(rome2_vfs_cstr_offset_char("pack", 2u) == 'c' && rome2_vfs_cstr_offset_char("pack", 9u) == '\0');
    CHECK(rome2_vfs_cstr_back_or_nul("pack") == 'k' && rome2_vfs_cstr_back_or_nul("") == '\0');

    CHECK(rome2_vfs_scan_fmt_token_ascii("100%% ok%d", &idx, scan_out, &scan_len, sizeof(scan_out)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(scan_out, "100% ok") == 0 && idx == 8u);

    CHECK(rome2_vfs_map_thread_priority(0u) == -15 && rome2_vfs_map_thread_priority(6u) == 15);
    rome2_vfs_mem_status_ex64_init(&mstat);
    CHECK(mstat.dw_length_00 == 0x40u);
    CHECK(rome2_vfs_sanitize_debug_pct_wstr(pct_in, pct_out, 8u) == ROME2_VFS_REG_OK);
    CHECK(pct_out[0] == '&' && pct_out[2] == '&');

    CHECK(rome2_vfs_format_u32_ascii(0u, nbuf, sizeof(nbuf)) == ROME2_VFS_REG_OK && strcmp(nbuf, "0") == 0);
    CHECK(rome2_vfs_format_f32_ascii(1.5f, 6u, 0u, nbuf, sizeof(nbuf)) == ROME2_VFS_REG_OK && strcmp(nbuf, "1.5") == 0);
}

static void test_path_hash_tuple_and_math_fmt(void) {
    uint32_t buckets = 0u;
    const char *items[3] = { "\\data\\", "\\working_data\\", "\\mods\\" };
    char out_path[128];
    uint8_t changed = 0u;
    const char *cur = " \t\n\rboot.pack";
    rome2_vfs_tuple36_vec tvec;
    char fmt_buf[128];

    CHECK(rome2_vfs_hash_next_power2_buckets(9u, &buckets) == ROME2_VFS_REG_OK && buckets == 16u);
    CHECK(rome2_vfs_hash_next_power2_buckets(ROME2_VFS_L35_HASH_BUCKET_LIMIT + 1u, &buckets) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(rome2_vfs_cstr_ends_with("data\\boot.pack", ".pack") == 1u);
    CHECK(rome2_vfs_cstr_ends_with("boot", ".pack") == 0u);
    CHECK(rome2_vfs_search_list_find_idx(items, 3u, "\\working_data\\") == 1);
    CHECK(rome2_vfs_search_list_find_idx(items, 3u, "missing") == -1);

    CHECK(rome2_vfs_normalize_all_dots("a\\b\\..\\c\\.\\d.pack", out_path, sizeof(out_path), &changed) == ROME2_VFS_REG_OK);
    CHECK(changed == 1u && strcmp(out_path, "a\\c\\d.pack") == 0);
    CHECK(rome2_vfs_skip_ascii_ws(&cur) == 1u && strcmp(cur, "boot.pack") == 0);

    memset(&tvec, 0, sizeof(tvec));
    CHECK(rome2_vfs_tuple36_push_back(&tvec, "ui", "root", "pack") == ROME2_VFS_REG_OK);
    CHECK(tvec.count == 1u && strcmp(tvec.entries[0].b, "root") == 0);

    CHECK(rome2_vfs_format_euler_ascii(3.0f, 2.0f, 1.0f, fmt_buf, sizeof(fmt_buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(fmt_buf, "euler(1,2,3)") == 0);
    CHECK(rome2_vfs_format_vec3_ascii(1.0f, 2.5f, 3.0f, fmt_buf, sizeof(fmt_buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(fmt_buf, "vector(1,2.5,3)") == 0);
    CHECK(rome2_vfs_format_vec4i_ascii(1, 2, 3, 4, fmt_buf, sizeof(fmt_buf)) == ROME2_VFS_REG_OK);
    CHECK(strcmp(fmt_buf, "vector(1,2,3,4)") == 0);
}

int main(void) {
    test_wstr_fmt_and_sys();
    test_path_hash_tuple_and_math_fmt();
    printf("test_vfs_fs_codec_vec_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
