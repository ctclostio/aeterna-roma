#include <stdio.h>
#include <string.h>

#include "vfs_fs_dlmalloc_stream_ops.h"

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
            return 1; \
        } \
        ++checks; \
    } while (0)

int main(void) {
    int checks = 0;

    /* 1. Layout invariants verified via _Static_assert in guest32_layouts.h */
    CHECK(sizeof(rome2_vfs_dlmalloc_mparams28_32) == 0x1c);
    CHECK(sizeof(rome2_vfs_bucket_slot12_32) == 0x0c);
    CHECK(sizeof(rome2_vfs_wstreambuf_iter8_32) == 0x08);

    /* 2. 0x10123640..0x101246f0 dlmalloc mparams, tree index, backoff & sys_trim */
    rome2_vfs_dlmalloc_mparams28_32 mp = {0};
    mp.spinlock_00 = 1u;
    CHECK(rome2_vfs_dlmalloc_init_mparams(&mp, 4096u, 65536u, 0x12345678u) == ROME2_VFS_REG_OK);
    CHECK(mp.page_size_08 == 4096u && mp.granularity_0c == 65536u && mp.spinlock_00 == 0u);
    CHECK(mp.mmap_threshold_10 == 0x40000u && mp.trim_threshold_14 == 0x200000u && mp.default_mflags_18 == 7u);
    CHECK(mp.magic_04 == (((0x12345678u ^ 0x55555550u) & 0xfffffff8u) | 8u));
    CHECK(rome2_vfs_dlmalloc_init_mparams(&mp, 3000u, 65536u, 1u) == ROME2_VFS_REG_BAD_ARGUMENT);
    CHECK(rome2_vfs_dlmalloc_tree_idx(256u) == 0u);
    CHECK(rome2_vfs_dlmalloc_tree_idx(384u) == 1u);
    CHECK(rome2_vfs_dlmalloc_tree_idx(1u << 25u) == 31u);
    CHECK(rome2_vfs_dlmalloc_tree_step_shift(0u) == 25u);
    CHECK(rome2_vfs_dlmalloc_tree_step_shift(31u) == 0u);
    CHECK(rome2_vfs_dlmalloc_spin_should_sleep(0x8u) == 1u);
    CHECK(rome2_vfs_dlmalloc_spin_should_sleep(0x2710u) == 0u);
    uint32_t trim_extra = 0u;
    CHECK(rome2_vfs_dlmalloc_sys_trim_calc(0x30000u, 0u, 0x10000u, &trim_extra) == 1u);
    CHECK(trim_extra == 0x20000u);
    CHECK(rome2_vfs_dlmalloc_sys_trim_calc(0x28u, 0u, 0x10000u, &trim_extra) == 0u);

    /* 3. 0x100d1790, 0x100f3150, 0x100f6f30, 0x100ffbb0 */
    uint16_t fmt_idx = 0u;
    uint32_t out_len = 0u;
    uint8_t hit_spec = 0u;
    char fmt_out[64] = {0};
    CHECK(rome2_vfs_scan_lfmt_token_ascii("hp%%=%llu", &fmt_idx, fmt_out, &out_len, sizeof(fmt_out), &hit_spec) == ROME2_VFS_REG_OK);
    CHECK(strcmp(fmt_out, "hp%=") == 0 && fmt_idx == 8u && hit_spec == 1u);

    char pb[8] = "ab";
    uint32_t pblen = 2u;
    CHECK(rome2_vfs_cstr_push_back(pb, &pblen, sizeof(pb), 'c') == ROME2_VFS_REG_OK);
    CHECK(strcmp(pb, "abc") == 0 && pblen == 3u);

    rome2_vfs_stream_handle36_32 sh = {0};
    sh.state_tag_00 = 1u;
    sh.owned_flags_04 = 3u;
    sh.primary_handle_08 = 0x1111u;
    sh.secondary_handle_0c = 0x2222u;
    sh.state_words_10[0] = 128u;
    sh.state_words_10[1] = 64u;
    sh.byte_flag_1c = 1u;
    sh.mapped_view_ptr_20 = 0x3333u;
    rome2_vfs_stream_handle36_close(&sh);
    CHECK(sh.state_tag_00 == 3u && sh.owned_flags_04 == 0u && sh.primary_handle_08 == 0xffffffffu &&
          sh.secondary_handle_0c == 0xffffffffu && sh.byte_flag_1c == 0u && sh.state_words_10[0] == 0u);

    const uint16_t hw[] = {L'a', L'/', L'b', L'/', L'c'};
    CHECK(rome2_vfs_wstr_find_wchar(hw, 5u, L'/', 0u) == 1);
    CHECK(rome2_vfs_wstr_find_wchar(hw, 5u, L'/', 2u) == 3);
    CHECK(rome2_vfs_wstr_find_wchar(hw, 5u, L'z', 0u) == -1);

    /* 4. 0x100db960, 0x100e10c0, 0x100e3950, 0x113682d0 */
    const uint16_t k_w[] = {L'A', L'B'};
    CHECK(rome2_vfs_hash_wstr_xor(k_w, 2u) == (0xf73a51c9u ^ ((uint32_t)L'B') ^ (((uint32_t)L'A') << 8u)));
    CHECK(rome2_vfs_hash_cstr_pairsum("ACBD") == ((uint32_t)('A' + 'B') | (((uint32_t)('C' + 'D')) << 16u)));
    CHECK(rome2_vfs_handle_table_bucket(0x4a545ee0u, 8u) == (13u % 8u));

    rome2_vfs_bucket_slot12_32 bslot = {0x123u, 0x456u, 0x789u};
    rome2_vfs_bucket12_reset_empty(&bslot, 0x2000u);
    CHECK(bslot.begin_00 == 0x2004u && bslot.end_or_self_04 == 0u && bslot.tail_ptr_08 == 0u);

    /* 5. 0x11346d60 & 0x11348d50 wide stream pad + num_get _Getifld */
    uint16_t wpad[16] = {0};
    uint32_t wpad_len = 0u;
    CHECK(rome2_vfs_wstr_pad_write(wpad, 16u, &wpad_len, L'7', 4u, L'0') == ROME2_VFS_REG_OK);
    CHECK(wpad_len == 4u && wpad[0] == L'7' && wpad[1] == L'0' && wpad[3] == L'0' && wpad[4] == 0u);

    const uint16_t hex_in[] = {L'-', L'0', L'x', L'0', L'A', L'f', L'Z'};
    char ifld[32] = {0};
    int32_t parsed_base = 0;
    CHECK(rome2_vfs_wstreambuf_get_ifld(hex_in, 7u, 8u, ifld, sizeof(ifld), &parsed_base) == ROME2_VFS_REG_OK);
    CHECK(strcmp(ifld, "-Af") == 0 && parsed_base == 16);

    const uint16_t zero_in[] = {L'0', L'0', L'0'};
    CHECK(rome2_vfs_wstreambuf_get_ifld(zero_in, 3u, 0u, ifld, sizeof(ifld), &parsed_base) == ROME2_VFS_REG_OK);
    CHECK(strcmp(ifld, "0") == 0 && parsed_base == 10);

    printf("test_vfs_fs_dlmalloc_stream_ops: ALL PASSED (%d checks)\n", checks);
    return 0;
}
