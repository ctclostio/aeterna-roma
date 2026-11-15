#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs_substream_loose_ops.h"

typedef struct mock_handle_ctx {
    uint32_t last_closed_handle;
    int close_rc;
    int close_calls;
} mock_handle_ctx;

static int mock_close_handle(void *ctx, uint32_t handle)
{
    mock_handle_ctx *m = (mock_handle_ctx *)ctx;
    m->last_closed_handle = handle;
    m->close_calls += 1;
    return m->close_rc;
}

static void write_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xffu);
    dst[1] = (uint8_t)((value >> 8) & 0xffu);
    dst[2] = (uint8_t)((value >> 16) & 0xffu);
    dst[3] = (uint8_t)((value >> 24) & 0xffu);
}

int main(void)
{
    int checks = 0;
    mock_handle_ctx mctx = {0};
    rome2_vfs_win32_handle_ops hops = {
        .ctx = &mctx,
        .close_handle = mock_close_handle,
    };

    /* 1-2: 0x100f6fd0 CloseHandle boolean normalization + arg rejection */
    {
        int closed_ok = -1;
        mctx.close_rc = 1;
        assert(rome2_vfs_close_handle_bool_6fd0(&hops, 0x1234u, &closed_ok) == ROME2_VFS_REG_OK);
        assert(closed_ok == 1);
        assert(mctx.last_closed_handle == 0x1234u);
        assert(mctx.close_calls == 1);
        checks += 1;

        mctx.close_rc = 2; /* non-1 truthy value still maps to 0 per cmp eax, 1 */
        assert(rome2_vfs_close_handle_bool_6fd0(&hops, 0x5678u, &closed_ok) == ROME2_VFS_REG_OK);
        assert(closed_ok == 0);
        closed_ok = 99;
        assert(rome2_vfs_close_handle_bool_6fd0(NULL, 1u, &closed_ok) == ROME2_VFS_REG_BAD_ARGUMENT);
        assert(closed_ok == 99);
        checks += 1;
    }

    /* 3-4: 0x10104cc0 CreateFileA flags & 0x1011fda0 stat20 zeroing */
    {
        uint32_t acc = 0u, share = 0u, disp = 0u, attrs = 0u;
        assert(rome2_vfs_create_file_flags_4cc0(0u, &acc, &share, &disp, &attrs) == ROME2_VFS_REG_OK);
        assert(acc == 0x80000000u && share == 3u && disp == 3u && attrs == 0x08000001u);
        assert(rome2_vfs_create_file_flags_4cc0(1u, &acc, &share, &disp, &attrs) == ROME2_VFS_REG_OK);
        assert(attrs == 0x68000001u);
        assert(rome2_vfs_create_file_flags_4cc0(1u, &acc, &share, NULL, &attrs) == ROME2_VFS_REG_BAD_ARGUMENT);
        checks += 1;

        rome2_vfs_file_stat20_32 st20 = {
            .file_size_low_00 = 11u,
            .file_size_high_04 = 22u,
            .mtime_low_08 = 33u,
            .mtime_high_0c = 44u,
            .attr_flags_10 = 0x7fu,
            .pad_11 = {0xaau, 0xbbu, 0xccu},
        };
        assert(rome2_vfs_file_stat20_zero_fda0(&st20) == ROME2_VFS_REG_OK);
        assert(st20.file_size_low_00 == 0u && st20.file_size_high_04 == 0u);
        assert(st20.mtime_low_08 == 0u && st20.mtime_high_0c == 0u && st20.attr_flags_10 == 0u);
        assert(st20.pad_11[0] == 0xaau && st20.pad_11[1] == 0xbbu && st20.pad_11[2] == 0xccu);
        assert(rome2_vfs_file_stat20_zero_fda0(NULL) == ROME2_VFS_REG_BAD_ARGUMENT);
        checks += 1;
    }

    /* 5-7: 0x112b43d0 aligned-16 vs fallback memcpy + overlap rejection + zero-byte copy */
    {
        uint8_t src[32];
        uint8_t dst[32];
        uint8_t overlap[32];
        int aligned16 = -1;
        size_t i;

        for (i = 0u; i < sizeof(src); ++i) {
            src[i] = (uint8_t)(i + 1u);
            dst[i] = 0u;
            overlap[i] = (uint8_t)(0x80u + i);
        }
        assert(rome2_vfs_aligned16_or_memcpy_43d0(0x1000u, 0x2000u, dst, src, 32u, &aligned16) == ROME2_VFS_REG_OK);
        assert(aligned16 == 1 && memcmp(dst, src, 32u) == 0);
        checks += 1;

        memset(dst, 0, sizeof(dst));
        assert(rome2_vfs_aligned16_or_memcpy_43d0(0x1004u, 0x2000u, dst, src, 16u, &aligned16) == ROME2_VFS_REG_OK);
        assert(aligned16 == 0 && memcmp(dst, src, 16u) == 0);
        checks += 1;

        aligned16 = 5;
        assert(rome2_vfs_aligned16_or_memcpy_43d0(0x1000u, 0x2000u, overlap + 4, overlap, 16u, &aligned16) == ROME2_VFS_REG_RANGE_ERROR);
        assert(aligned16 == 5);
        assert(rome2_vfs_aligned16_or_memcpy_43d0(0x1000u, 0x2000u, dst, src, 0u, &aligned16) == ROME2_VFS_REG_OK);
        assert(aligned16 == 1);
        assert(rome2_vfs_aligned16_or_memcpy_43d0(0x1000u, 0x2000u, NULL, src, 16u, &aligned16) == ROME2_VFS_REG_BAD_ARGUMENT);
        checks += 1;
    }

    /* 8-9: 0x10115df0 std::exception::what & 0x112d0d20 loose-entry window clamp */
    {
        rome2_vfs_bad_alloc_exc8_32 exc = {0};
        uint32_t what = 0u;
        assert(rome2_vfs_bad_alloc_init_1c50(&exc) == ROME2_VFS_REG_OK);
        assert(rome2_vfs_std_exception_what_5df0(&exc, &what) == ROME2_VFS_REG_OK);
        assert(what == ROME2_VFS_BAD_ALLOC_WHAT32);
        exc.what_str_04 = 0u;
        assert(rome2_vfs_std_exception_what_5df0(&exc, &what) == ROME2_VFS_REG_OK);
        assert(what == ROME2_VFS_STD_EXCEPTION_UNKNOWN32);
        checks += 1;

        rome2_vfs_loose_file_entry32 entry = {
            .vtable_00 = ROME2_VFS_LOOSE_VTABLE_7710_VTABLE32,
            .file_handle_0c = 0x111u,
            .aux_handle_10 = 0x222u,
            .file_size_14 = 100u,
            .backing_view_1c = 0x3000u,
        };
        uint32_t clamped = 777u, out_off = 888u;
        assert(rome2_vfs_loose_entry_clamp_window_0d20(&entry, 40u, 20u, &clamped, &out_off) == ROME2_VFS_REG_OK);
        assert(clamped == 40u && out_off == 20u);
        assert(rome2_vfs_loose_entry_clamp_window_0d20(&entry, 50u, 80u, &clamped, &out_off) == ROME2_VFS_REG_OK);
        assert(clamped == 20u && out_off == 80u);
        assert(rome2_vfs_loose_entry_clamp_window_0d20(&entry, 0u, 70u, &clamped, &out_off) == ROME2_VFS_REG_OK);
        assert(clamped == 30u && out_off == 70u);
        clamped = 999u;
        assert(rome2_vfs_loose_entry_clamp_window_0d20(&entry, 10u, 101u, &clamped, &out_off) == ROME2_VFS_REG_RANGE_ERROR);
        assert(clamped == 999u);
        checks += 1;
    }

    /* 10-11: 0x112daa40 loose-entry handle teardown */
    {
        rome2_vfs_loose_file_entry32 entry = {
            .vtable_00 = ROME2_VFS_LOOSE_VTABLE_7710_VTABLE32,
            .file_handle_0c = 0x901u,
            .aux_handle_10 = 0x902u,
            .file_size_14 = 64u,
            .backing_view_1c = 0x4444u,
        };
        int closed_ok = -1;
        mctx.close_rc = 1;
        assert(rome2_vfs_loose_entry_teardown_handles_aa40(&hops, &entry, &closed_ok) == ROME2_VFS_REG_OK);
        assert(closed_ok == 1);
        assert(mctx.last_closed_handle == 0x901u);
        assert(entry.backing_view_1c == 0u);
        assert(entry.file_handle_0c == ROME2_VFS_INVALID_HANDLE32);
        assert(entry.aux_handle_10 == ROME2_VFS_INVALID_HANDLE32);
        checks += 1;

        assert(rome2_vfs_loose_entry_teardown_handles_aa40(&hops, NULL, &closed_ok) == ROME2_VFS_REG_BAD_ARGUMENT);
        checks += 1;
    }

    /* 12-15: Vtable matchers 0x11897710 (20), 0x11897760 (12), 0x11897c24 (8) + 0x112c9520 bit6 */
    {
        uint8_t mem[1024];
        rome2_guest_read_view view;
        static const uint32_t s7710[20] = {
            0x112acf40u, 0x112d3270u, 0x10a34b40u, 0x10171400u,
            0x101d9800u, 0x112c8b90u, 0x100d6900u, 0x112d0bf0u,
            0x112d0d20u, 0x112daa40u, 0x101d97f0u, 0x112baeb0u,
            0x112d9880u, 0x100d6560u, 0x112d0bb0u, 0x112c0db0u,
            0x112dd2e0u, 0x112d3270u, 0x112bffe0u, 0x100dbc00u
        };
        static const uint32_t s7760[12] = {
            0x112ace20u, 0x112d3270u, 0x112d3270u, 0x101d9800u,
            0x101a0430u, 0x10abbf90u, 0x112c9520u, 0x100e22c0u,
            0x100f3d00u, 0x100dbc00u, 0x100dbc00u, 0x112c8c80u
        };
        static const uint32_t s7c24[8] = {
            0x112ad6a0u, 0x112c8c40u, 0x112d98c0u, 0x112c0cf0u,
            0x112dc1a0u, 0x112d3290u, 0x112d5690u, 0x112d57d0u
        };
        size_t i;
        rome2_vfs_loose_vtable_7710_20slot32 vt7710 = {0};
        rome2_vfs_pack_wrap_vtable_7760_12slot32 vt7760 = {0};
        rome2_vfs_substream_vtable_7c24_8slot32 vt7c24 = {0};
        int matches = 0;

        memset(mem, 0, sizeof(mem));
        for (i = 0u; i < 20u; ++i) {
            write_u32_le(mem + i * 4u, s7710[i]);
        }
        for (i = 0u; i < 12u; ++i) {
            write_u32_le(mem + 0x80u + i * 4u, s7760[i]);
        }
        for (i = 0u; i < 8u; ++i) {
            write_u32_le(mem + 0xc0u + i * 4u, s7c24[i]);
        }
        /* Wrapper objects at +0x100 (null +0x18), +0x140 (bit6=1), +0x180 (bit6=0) */
        write_u32_le(mem + 0x100u + 0x18u, 0u);
        write_u32_le(mem + 0x140u + 0x18u, 0x100001c0u);
        write_u32_le(mem + 0x1c0u + 0x00u, 0x100001d0u);
        write_u32_le(mem + 0x1d0u + 0x1cu, 0x00000040u);
        write_u32_le(mem + 0x180u + 0x18u, 0x100001e0u);
        write_u32_le(mem + 0x1e0u + 0x00u, 0x100001f0u);
        write_u32_le(mem + 0x1f0u + 0x1cu, 0x0000003fu);

        view = (rome2_guest_read_view){ mem, 0x10000000u, sizeof(mem) };

        assert(rome2_vfs_loose_vtable_7710_matches(&view, (rome2_guest_addr32){0x10000000u}, &vt7710, &matches) == ROME2_VFS_REG_OK);
        assert(matches == 1 && vt7710.slot_00 == 0x112acf40u && vt7710.slot_48 == 0x112bffe0u);
        assert(rome2_vfs_loose_vtable_7710_matches(&view, (rome2_guest_addr32){0x10000004u}, &vt7710, &matches) == ROME2_VFS_REG_OK);
        assert(matches == 0);
        checks += 1;

        assert(rome2_vfs_pack_wrap_vtable_7760_matches(&view, (rome2_guest_addr32){0x10000080u}, &vt7760, &matches) == ROME2_VFS_REG_OK);
        assert(matches == 1 && vt7760.slot_00 == 0x112ace20u && vt7760.slot_2c == 0x112c8c80u);
        assert(rome2_vfs_substream_vtable_7c24_matches(&view, (rome2_guest_addr32){0x100000c0u}, &vt7c24, &matches) == ROME2_VFS_REG_OK);
        assert(matches == 1 && vt7c24.slot_00 == 0x112ad6a0u && vt7c24.slot_18 == 0x112d5690u);
        assert(rome2_vfs_substream_vtable_7c24_matches(&view, (rome2_guest_addr32){0x100003f0u}, &vt7c24, &matches) == ROME2_VFS_REG_RANGE_ERROR);
        checks += 1;

        uint8_t bit = 9u;
        assert(rome2_vfs_pack_wrap_flag_bit6_9520(&view, (rome2_guest_addr32){0x10000100u}, &bit) == ROME2_VFS_REG_OK);
        assert(bit == 1u);
        assert(rome2_vfs_pack_wrap_flag_bit6_9520(&view, (rome2_guest_addr32){0x10000140u}, &bit) == ROME2_VFS_REG_OK);
        assert(bit == 1u);
        assert(rome2_vfs_pack_wrap_flag_bit6_9520(&view, (rome2_guest_addr32){0x10000180u}, &bit) == ROME2_VFS_REG_OK);
        assert(bit == 0u);
        bit = 77u;
        assert(rome2_vfs_pack_wrap_flag_bit6_9520(&view, (rome2_guest_addr32){0x100003f0u}, &bit) == ROME2_VFS_REG_RANGE_ERROR);
        assert(bit == 77u);
        checks += 2;
    }

    /* 16-22: 0x11897c24 substream can_read, refresh_eof, advance_0cf0, and rewind_c1a0 */
    {
        rome2_vfs_buffered_substream40_32 sub = {
            .vtable_00 = 0x11897c24u,
            .window_base_04 = 0x2000u,
            .window_size_08 = 100u,
            .window_offset_0c = 10u,
            .stream_pos_10 = 110u,
            .parent_entry_14 = 0x5000u,
            .initial_pos_or_cursor_1c = 100u,
            .eof_flag_24 = 0u,
            .error_flag_25 = 0u,
        };
        int can_read = -1;
        int remapped = -1;

        assert(rome2_vfs_substream_can_read_8c40(&sub, 1, &can_read) == ROME2_VFS_REG_OK);
        assert(can_read == 1);
        assert(rome2_vfs_substream_can_read_8c40(&sub, 0, &can_read) == ROME2_VFS_REG_OK);
        assert(can_read == 0);
        sub.eof_flag_24 = 1u;
        assert(rome2_vfs_substream_can_read_8c40(&sub, 1, &can_read) == ROME2_VFS_REG_OK);
        assert(can_read == 0);
        sub.eof_flag_24 = 0u;
        sub.error_flag_25 = 1u;
        assert(rome2_vfs_substream_can_read_8c40(&sub, 1, &can_read) == ROME2_VFS_REG_OK);
        assert(can_read == 0);
        sub.error_flag_25 = 0u;
        checks += 1;

        assert(rome2_vfs_substream_refresh_eof_57d0(&sub, 111u) == ROME2_VFS_REG_OK);
        assert(sub.eof_flag_24 == 0u);
        assert(rome2_vfs_substream_refresh_eof_57d0(&sub, 110u) == ROME2_VFS_REG_OK);
        assert(sub.eof_flag_24 == 1u);
        sub.eof_flag_24 = 0u;
        checks += 1;

        /* In-window advance: 10 + 50 < 100 */
        assert(rome2_vfs_substream_advance_0cf0(&sub, 50u, 0x3000u, 80u, &remapped) == ROME2_VFS_REG_OK);
        assert(remapped == 0 && sub.window_offset_0c == 60u && sub.stream_pos_10 == 160u && sub.window_base_04 == 0x2000u);
        checks += 1;

        /* Cross-window advance: 60 + 40 >= 100 -> remap */
        assert(rome2_vfs_substream_advance_0cf0(&sub, 40u, 0x3000u, 80u, &remapped) == ROME2_VFS_REG_OK);
        assert(remapped == 1 && sub.window_offset_0c == 0u && sub.stream_pos_10 == 200u &&
               sub.window_base_04 == 0x3000u && sub.window_size_08 == 80u);
        checks += 1;

        /* Overflow rejection preserves substream */
        assert(rome2_vfs_substream_advance_0cf0(&sub, UINT32_MAX, 0x4000u, 10u, &remapped) == ROME2_VFS_REG_RANGE_ERROR);
        assert(sub.stream_pos_10 == 200u);
        /* Zero-delta advance resets to initial_pos_or_cursor_1c */
        assert(rome2_vfs_substream_advance_0cf0(&sub, 0u, 0x5000u, 64u, &remapped) == ROME2_VFS_REG_OK);
        assert(remapped == 1 && sub.stream_pos_10 == 100u && sub.window_base_04 == 0x5000u &&
               sub.window_size_08 == 64u && sub.window_offset_0c == 0u);
        checks += 1;

        /* In-window rewind vs cross-window rewind + underflow */
        sub.window_offset_0c = 25u;
        sub.stream_pos_10 = 125u;
        assert(rome2_vfs_substream_rewind_c1a0(&sub, 10u, 0x6000u, 50u, &remapped) == ROME2_VFS_REG_OK);
        assert(remapped == 0 && sub.window_offset_0c == 15u && sub.stream_pos_10 == 115u && sub.window_base_04 == 0x5000u);
        checks += 1;

        assert(rome2_vfs_substream_rewind_c1a0(&sub, 20u, 0x6000u, 50u, &remapped) == ROME2_VFS_REG_OK);
        assert(remapped == 1 && sub.window_offset_0c == 0u && sub.stream_pos_10 == 95u &&
               sub.window_base_04 == 0x6000u && sub.window_size_08 == 50u);
        assert(rome2_vfs_substream_rewind_c1a0(&sub, 96u, 0x7000u, 50u, &remapped) == ROME2_VFS_REG_RANGE_ERROR);
        assert(sub.stream_pos_10 == 95u);
        assert(rome2_vfs_substream_rewind_c1a0(&sub, 0u, 0x7000u, 32u, &remapped) == ROME2_VFS_REG_OK);
        assert(remapped == 1 && sub.stream_pos_10 == 100u && sub.window_base_04 == 0x7000u);
        checks += 1;
    }

    assert(checks == 22);
    printf("vfs_substream_loose_ops_tests: %d checks passed (0 failures)\n", checks);
    return 0;
}
