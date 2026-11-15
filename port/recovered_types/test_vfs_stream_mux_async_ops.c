#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs_stream_completion_ops.h"
#include "vfs_stream_mux_async_ops.h"

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "CHECK FAILED (%s:%d): %s\n",                    \
                    __FILE__, __LINE__, #cond);                              \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static void write_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xffu);
    dst[1] = (uint8_t)((value >> 8) & 0xffu);
    dst[2] = (uint8_t)((value >> 16) & 0xffu);
    dst[3] = (uint8_t)((value >> 24) & 0xffu);
}

static int test_dual_slot_view_lifecycle_and_prefetch(void)
{
    rome2_vfs_dual_slot_view32 view;
    uint32_t released = 99u;
    uint32_t new_refs = 99u;
    int has_task = -1;
    int has_refs = -1;
    int is_miss = -1;
    int toggled = -1;
    int prefetched = -1;
    uint8_t guest_mem_buf[256];
    const rome2_guest_read_view gview = {
        .host_base = guest_mem_buf,
        .guest_base = 0x20000000u,
        .byte_count = sizeof(guest_mem_buf),
    };
    int ready = -1;
    uint32_t remaining = 0u;

    memset(guest_mem_buf, 0, sizeof(guest_mem_buf));

    CHECK(sizeof(rome2_vfs_dual_slot_entry32) == 0x10u);
    CHECK(sizeof(rome2_vfs_dual_slot_view32) == 0x54u);

    CHECK(rome2_vfs_dual_slot_view_init(&view, 0x1001u, 0x1002u, 700u, 0x22u, 0x33u, 0u, 1u) ==
          ROME2_VFS_REG_BAD_ARGUMENT);
    CHECK(rome2_vfs_dual_slot_view_init(&view, 0x1001u, 0x1002u, 700u, 0x22u, 0x33u, 256u, 1u) ==
          ROME2_VFS_REG_OK);
    CHECK(view.vtable == ROME2_VFS_DUAL_SLOT_VIEW_VTABLE32);
    CHECK(view.active_slot_idx_50 == 0u);
    CHECK(view.active_ref_count_24 == 0u);

    CHECK(rome2_vfs_dual_slot_view_has_active_task(&view, &has_task) == ROME2_VFS_REG_OK);
    CHECK(has_task == 0);
    CHECK(rome2_vfs_dual_slot_view_has_active_refs(&view, &has_refs) == ROME2_VFS_REG_OK);
    CHECK(has_refs == 0);
    CHECK(rome2_vfs_dual_slot_view_is_window_cache_miss(&view, 0u, &is_miss) == ROME2_VFS_REG_OK);
    CHECK(is_miss == 1);

    /* Initial miss at offset 0 toggles slot 0->1: loads slot 1 [0, 256), prefetches slot 0 [256, 256). */
    CHECK(rome2_vfs_dual_slot_view_map_and_prefetch(&view, 512u, 0u, 0x20000020u, &toggled, &prefetched) ==
          ROME2_VFS_REG_OK);
    CHECK(toggled == 1 && prefetched == 1);
    CHECK(view.active_ref_count_24 == 1u);
    CHECK(view.active_slot_idx_50 == 1u);
    CHECK(view.slot1_38.task_ptr_00 == 0x20000020u);
    CHECK(view.slot1_38.window_off_08 == 0u && view.slot1_38.window_len_04 == 256u);
    CHECK(view.slot0_28.task_ptr_00 == 0x20000021u);
    CHECK(view.slot0_28.window_off_08 == 256u && view.slot0_28.window_len_04 == 256u);

    /* Active slot 1 hit at offset 100. */
    CHECK(rome2_vfs_dual_slot_view_is_window_cache_miss(&view, 100u, &is_miss) == ROME2_VFS_REG_OK);
    CHECK(is_miss == 0);
    CHECK(rome2_vfs_dual_slot_view_map_and_prefetch(&view, 64u, 100u, 0x20000040u, &toggled, &prefetched) ==
          ROME2_VFS_REG_OK);
    CHECK(toggled == 0 && prefetched == 0);
    CHECK(view.active_ref_count_24 == 2u);
    CHECK(view.slot1_rel_off_4c == 100u);

    /* Guest memory layout for active slot 1 task at 0x20000020 -> task_bytes=256, inner=0x20000080 -> ready=1. */
    write_u32_le(guest_mem_buf + 0x20u, 256u);
    write_u32_le(guest_mem_buf + 0x2cu, 0x20000080u);
    guest_mem_buf[0x8cu] = 0u;
    CHECK(rome2_vfs_dual_slot_view_is_active_task_ready(&view, &gview, &ready) == ROME2_VFS_REG_OK);
    CHECK(ready == 0);
    guest_mem_buf[0x8cu] = 1u;
    CHECK(rome2_vfs_dual_slot_view_is_active_task_ready(&view, &gview, &ready) == ROME2_VFS_REG_OK);
    CHECK(ready == 1);
    CHECK(rome2_vfs_dual_slot_view_active_remaining_bytes(&view, &gview, &remaining) == ROME2_VFS_REG_OK);
    CHECK(remaining == 156u);

    /* Prefetched slot 0 hit at offset 300 toggles back to slot 0 and prefetches [512, 188) into slot 1. */
    CHECK(rome2_vfs_dual_slot_view_is_window_cache_miss(&view, 300u, &is_miss) == ROME2_VFS_REG_OK);
    CHECK(is_miss == 0);
    CHECK(rome2_vfs_dual_slot_view_map_and_prefetch(&view, 64u, 300u, 0x20000050u, &toggled, &prefetched) ==
          ROME2_VFS_REG_OK);
    CHECK(toggled == 1 && prefetched == 1);
    CHECK(view.active_slot_idx_50 == 0u);
    CHECK(view.slot0_rel_off_48 == 44u);
    CHECK(view.slot1_38.window_off_08 == 512u && view.slot1_38.window_len_04 == 188u);

    /* Cache miss beyond prefetched windows at offset 600 (already in slot 1 [512, 700), so check 750!). */
    CHECK(rome2_vfs_dual_slot_view_is_window_cache_miss(&view, 750u, &is_miss) == ROME2_VFS_REG_OK);
    CHECK(is_miss == 1);

    /* Release refs down to 0 -> detaches both slot tasks and resets rel offsets. */
    CHECK(rome2_vfs_dual_slot_view_release_ref(&view, &new_refs, &released) == ROME2_VFS_REG_OK);
    CHECK(new_refs == 2u && released == 0u);
    CHECK(rome2_vfs_dual_slot_view_release_ref(&view, &new_refs, &released) == ROME2_VFS_REG_OK);
    CHECK(new_refs == 1u && released == 0u);
    CHECK(rome2_vfs_dual_slot_view_release_ref(&view, &new_refs, &released) == ROME2_VFS_REG_OK);
    CHECK(new_refs == 0u && released == 2u);
    CHECK(view.slot0_28.task_ptr_00 == 0u && view.slot1_38.task_ptr_00 == 0u);
    CHECK(view.slot0_rel_off_48 == 0u && view.slot1_rel_off_4c == 0u);
    CHECK(rome2_vfs_dual_slot_view_release_ref(&view, &new_refs, &released) == ROME2_VFS_REG_RANGE_ERROR);

    /* Destroy after assigning a dummy task resets vtable to 0x11849278. */
    view.slot0_28.task_ptr_00 = 0x20000020u;
    CHECK(rome2_vfs_dual_slot_view_destroy(&view, &released) == ROME2_VFS_REG_OK);
    CHECK(released == 1u);
    CHECK(view.vtable == ROME2_VFS_BACKING_VIEW_BASE_VTABLE32);
    return 0;
}

static int test_cipher_mem_view_and_delegate_adapter(void)
{
    rome2_vfs_cipher_mem_view32 cview;
    uint32_t out_refs = 0u;
    uint32_t out_ptr = 0u;
    uint8_t valid = 0u;
    uint8_t ready = 1u;
    uint8_t cipher_buf[16];
    uint8_t expected_buf[16];
    uint32_t key = 0u;
    size_t processed = 0u;
    size_t i;

    rome2_vfs_stream_delegate_adapter32 adapter;
    uint8_t gmem[128];
    const rome2_guest_read_view gview = {
        .host_base = gmem,
        .guest_base = 0x30000000u,
        .byte_count = sizeof(gmem),
    };
    uint32_t out_obj = 0xffffffffu;
    uint32_t out_hr = 0u;
    uint32_t thunk_target = 0u;

    CHECK(sizeof(rome2_vfs_cipher_mem_view32) == 0x20u);
    CHECK(sizeof(rome2_vfs_stream_delegate_adapter32) == 0x14u);

    CHECK(rome2_vfs_cipher_mem_view_init(&cview, 0x1111u, 1u) == ROME2_VFS_REG_OK);
    CHECK(cview.vtable == ROME2_VFS_CIPHER_MEM_VIEW_VTABLE32);
    CHECK(rome2_vfs_cipher_mem_view_is_valid(&cview, &valid) == ROME2_VFS_REG_OK && valid == 1u);
    CHECK(rome2_vfs_cipher_mem_view_is_ready(&cview, &ready) == ROME2_VFS_REG_OK && ready == 0u);
    CHECK(rome2_vfs_cipher_mem_view_get_buffer(&cview, &out_ptr) == ROME2_VFS_REG_RANGE_ERROR);

    CHECK(rome2_vfs_cipher_mem_view_inc_ref(&cview) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_cipher_mem_view_dec_ref(&cview, &out_refs) == ROME2_VFS_REG_OK && out_refs == 0u);
    CHECK(rome2_vfs_cipher_mem_view_dec_ref(&cview, &out_refs) == ROME2_VFS_REG_OK && out_refs == 0u);

    for (i = 0u; i < sizeof(cipher_buf); ++i) {
        cipher_buf[i] = (uint8_t)(0xa0u + i);
        expected_buf[i] = cipher_buf[i];
    }
    CHECK(rome2_vfs_stream_xor_deobfuscate_blocks32(
        expected_buf, sizeof(expected_buf), expected_buf, &key, &processed) == ROME2_VFS_REG_OK);
    CHECK(rome2_vfs_cipher_mem_view_install_buffer(
        &cview, 0x40001000u, cipher_buf, sizeof(cipher_buf)) == ROME2_VFS_REG_OK);
    CHECK(memcmp(cipher_buf, expected_buf, sizeof(cipher_buf)) == 0);
    CHECK(cview.ready_flag_11 == 1u && cview.valid_flag_10 == 1u);
    CHECK(rome2_vfs_cipher_mem_view_get_buffer(&cview, &out_ptr) == ROME2_VFS_REG_OK &&
          out_ptr == 0x40001000u);

    /* Null install clears valid_flag_10 without overwriting buffer_ptr_14. */
    CHECK(rome2_vfs_cipher_mem_view_install_buffer(&cview, 0u, NULL, 0u) == ROME2_VFS_REG_OK);
    CHECK(cview.valid_flag_10 == 0u && cview.ready_flag_11 == 1u && cview.buffer_ptr_14 == 0x40001000u);

    /* Delegating stream adapter 0x11897c90 + 0x1173db9c + QueryInterface + 10 thunks. */
    CHECK(rome2_vfs_stream_delegate_adapter_init_base(&adapter) == ROME2_VFS_REG_OK);
    CHECK(adapter.vtable == ROME2_VFS_STREAM_ADAPTER_BASE_VTABLE32);
    CHECK(rome2_vfs_stream_delegate_adapter_init(&adapter, 0x30000010u, 8u, 15u, 0x30000060u) ==
          ROME2_VFS_REG_OK);
    CHECK(adapter.vtable == ROME2_VFS_STREAM_DELEGATE_VTABLE32);
    CHECK(rome2_vfs_stream_delegate_adapter_query_interface(&out_obj, &out_hr) == ROME2_VFS_REG_OK);
    CHECK(out_obj == 0u && out_hr == ROME2_VFS_E_NOINTERFACE32);

    memset(gmem, 0, sizeof(gmem));
    write_u32_le(gmem + 0x10u, 0x30000020u); /* inner_stream->vtable */
    for (i = 0x10u; i <= 0x34u; i += 4u) {
        write_u32_le(gmem + 0x20u + i, (uint32_t)(0x12000000u + i));
        CHECK(rome2_vfs_stream_delegate_adapter_resolve_thunk_target(
            &adapter, &gview, (uint32_t)i, &thunk_target) == ROME2_VFS_REG_OK);
        CHECK(thunk_target == (uint32_t)(0x12000000u + i));
    }
    CHECK(rome2_vfs_stream_delegate_adapter_resolve_thunk_target(
        &adapter, &gview, 0x0cu, &thunk_target) == ROME2_VFS_REG_BAD_ARGUMENT);
    CHECK(rome2_vfs_stream_delegate_adapter_resolve_thunk_target(
        &adapter, &gview, 0x38u, &thunk_target) == ROME2_VFS_REG_BAD_ARGUMENT);

    CHECK(rome2_vfs_stream_delegate_adapter_destroy(&adapter) == ROME2_VFS_REG_OK);
    CHECK(adapter.vtable == ROME2_VFS_STREAM_ADAPTER_BASE_VTABLE32);
    CHECK(adapter.wide_path_len_08 == 0u && adapter.wide_path_buf_10 == 0u);
    return 0;
}

static int test_stat_and_ascii_widening(void)
{
    rome2_vfs_file_stat32 st = {0};
    int matched = -1;
    uint16_t wide[32];
    size_t written = 0u;
    const uint8_t path[] = "data/rome.pack";
    size_t i;

    CHECK(sizeof(rome2_vfs_file_stat32) == 0x10u);

    CHECK(rome2_vfs_file_stat32_from_mode_and_meta(&st, 0x0000u, 0x1122334455667788ULL, 123u, &matched) ==
          ROME2_VFS_REG_OK);
    CHECK(matched == 0);

    CHECK(rome2_vfs_file_stat32_from_mode_and_meta(&st, 0x8180u, 0x1122334455667788ULL, 4096u, &matched) ==
          ROME2_VFS_REG_OK);
    CHECK(matched == 1);
    CHECK(st.mtime_lo_00 == 0x55667788u && st.mtime_hi_04 == 0x11223344u && st.file_size_08 == 4096u);
    CHECK(st.is_readable_0c == 1u && st.is_writable_0d == 1u && st.is_dir_0e == 0u);

    CHECK(rome2_vfs_file_stat32_from_mode_and_meta(&st, 0x4100u, 1u, 0u, &matched) ==
          ROME2_VFS_REG_OK);
    CHECK(matched == 1 && st.is_readable_0c == 1u && st.is_writable_0d == 0u && st.is_dir_0e == 1u);

    CHECK(rome2_vfs_widen_ascii_to_utf16(path, wide, sizeof(path) - 1u, &written) ==
          ROME2_VFS_REG_RANGE_ERROR);
    CHECK(rome2_vfs_widen_ascii_to_utf16(path, wide, 32u, &written) == ROME2_VFS_REG_OK);
    CHECK(written == sizeof(path) - 1u);
    for (i = 0u; i < sizeof(path); ++i) {
        CHECK(wide[i] == (uint16_t)path[i]);
    }
    return 0;
}

int main(void)
{
    if (test_dual_slot_view_lifecycle_and_prefetch() != 0) {
        return 1;
    }
    if (test_cipher_mem_view_and_delegate_adapter() != 0) {
        return 1;
    }
    if (test_stat_and_ascii_widening() != 0) {
        return 1;
    }
    printf("vfs_stream_mux_async_ops_tests: 3 suites passed (0 failures)\n");
    return 0;
}
