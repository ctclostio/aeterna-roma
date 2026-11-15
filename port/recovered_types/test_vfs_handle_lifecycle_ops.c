#include <stdio.h>
#include <string.h>

#include "vfs_handle_lifecycle_ops.h"

typedef struct mock_win32_ctx {
    uint32_t next_sem_handle;
    uint32_t next_file_handle;
    uint32_t file_size_lo;
    uint32_t file_size_hi;
    uint32_t next_map_handle;
    uint32_t last_error;
    int close_return_ok;
    uint32_t closed_handles[8];
    size_t closed_count;
} mock_win32_ctx;

static uint32_t mock_create_sem_a(void *ctx, int32_t init_cnt, int32_t max_cnt, const char *name)
{
    mock_win32_ctx *m = (mock_win32_ctx *)ctx;
    (void)init_cnt;
    (void)max_cnt;
    (void)name;
    return m->next_sem_handle;
}

static uint32_t mock_create_file_a(void *ctx, const char *path)
{
    mock_win32_ctx *m = (mock_win32_ctx *)ctx;
    (void)path;
    return m->next_file_handle;
}

static uint32_t mock_get_file_size(void *ctx, uint32_t fh, uint32_t *out_hi)
{
    mock_win32_ctx *m = (mock_win32_ctx *)ctx;
    (void)fh;
    *out_hi = m->file_size_hi;
    return m->file_size_lo;
}

static uint32_t mock_create_mapping_w(void *ctx, uint32_t fh, uint32_t hi, uint32_t lo)
{
    mock_win32_ctx *m = (mock_win32_ctx *)ctx;
    (void)fh;
    (void)hi;
    (void)lo;
    return m->next_map_handle;
}

static int mock_close_handle(void *ctx, uint32_t h)
{
    mock_win32_ctx *m = (mock_win32_ctx *)ctx;
    if (m->closed_count < 8u) {
        m->closed_handles[m->closed_count++] = h;
    }
    return m->close_return_ok;
}

static uint32_t mock_get_last_error(void *ctx)
{
    return ((mock_win32_ctx *)ctx)->last_error;
}

static uint32_t mock_map_error(void *ctx, uint32_t raw_err)
{
    (void)ctx;
    if (raw_err == 2u) {
        return 7u;
    }
    return 0u;
}

static rome2_vfs_win32_handle_ops make_ops(mock_win32_ctx *ctx, int use_mapper)
{
    rome2_vfs_win32_handle_ops ops;
    ops.ctx = ctx;
    ops.create_semaphore_a = mock_create_sem_a;
    ops.create_file_read_a = mock_create_file_a;
    ops.get_file_size = mock_get_file_size;
    ops.create_file_mapping_w = mock_create_mapping_w;
    ops.close_handle = mock_close_handle;
    ops.get_last_error = mock_get_last_error;
    ops.map_win32_error = use_mapper ? mock_map_error : NULL;
    return ops;
}

static void put_u32_le(uint8_t *dst, uint32_t val)
{
    dst[0] = (uint8_t)(val & 0xffu);
    dst[1] = (uint8_t)((val >> 8u) & 0xffu);
    dst[2] = (uint8_t)((val >> 16u) & 0xffu);
    dst[3] = (uint8_t)((val >> 24u) & 0xffu);
}

static rome2_guest_read_view make_view(const uint8_t *buf, size_t len, uint32_t base)
{
    rome2_guest_read_view v;
    v.host_base = buf;
    v.guest_base = base;
    v.byte_count = len;
    return v;
}

static int test_semaphore_and_handle_box(void)
{
    mock_win32_ctx ctx;
    rome2_vfs_win32_handle_ops ops;
    rome2_vfs_win32_handle_box8_32 box;
    uint32_t sem = 0u;
    uint32_t close_err = 0u;
    int closed = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.next_sem_handle = 0x1111u;
    ctx.last_error = 0u;
    ctx.close_return_ok = 1;
    ops = make_ops(&ctx, 0);

    /* Check 1: 0x100f12c0 fresh semaphore retains handle */
    if (rome2_vfs_semaphore_handle_init_12c0(&ops, 0, 0x7fffffff, NULL, &sem) != ROME2_VFS_REG_OK ||
        sem != 0x1111u || ctx.closed_count != 0u) {
        return 1;
    }

    /* Check 2: 0x100f12c0 ERROR_ALREADY_EXISTS (0xb7) closes handle & stores 0 */
    ctx.next_sem_handle = 0x2222u;
    ctx.last_error = ROME2_VFS_ERR_ALREADY_EXISTS32;
    if (rome2_vfs_semaphore_handle_init_12c0(&ops, 0, 1, "dup", &sem) != ROME2_VFS_REG_OK ||
        sem != 0u || ctx.closed_count != 1u || ctx.closed_handles[0] != 0x2222u) {
        return 2;
    }

    /* Check 3: 0x100f2230 skips 0, closes non-zero without clearing cell */
    ctx.closed_count = 0u;
    sem = 0u;
    if (rome2_vfs_semaphore_handle_close_2230(&ops, &sem, &closed) != ROME2_VFS_REG_OK ||
        closed != 0 || ctx.closed_count != 0u) {
        return 3;
    }
    sem = 0x3333u;
    if (rome2_vfs_semaphore_handle_close_2230(&ops, &sem, &closed) != ROME2_VFS_REG_OK ||
        closed != 1 || sem != 0x3333u || ctx.closed_count != 1u || ctx.closed_handles[0] != 0x3333u) {
        return 4;
    }

    /* Check 5: 0x100f1080 init + 0x100f2170 failed CloseHandle captures GetLastError and resets */
    if (rome2_vfs_win32_handle_box_init_1080(&box) != ROME2_VFS_REG_OK ||
        box.handle_00 != ROME2_VFS_INVALID_HANDLE32 || box.last_status_04 != 6u) {
        return 5;
    }
    box.handle_00 = 0x4444u;
    box.last_status_04 = 0u;
    ctx.close_return_ok = 0;
    ctx.last_error = 6u;
    ctx.closed_count = 0u;
    if (rome2_vfs_win32_handle_box_close_2170(&ops, &box, &close_err) != ROME2_VFS_REG_OK ||
        close_err != 6u || box.handle_00 != ROME2_VFS_INVALID_HANDLE32 ||
        box.last_status_04 != 6u || ctx.closed_count != 1u) {
        return 6;
    }

    /* Check 7: NULL checks */
    if (rome2_vfs_win32_handle_box_init_1080(NULL) != ROME2_VFS_REG_BAD_ARGUMENT) {
        return 7;
    }
    return 0;
}

static int test_open_file_mapping_and_bad_alloc(void)
{
    mock_win32_ctx ctx;
    rome2_vfs_win32_handle_ops ops;
    rome2_vfs_open_file_mapping16_32 fm;
    rome2_vfs_bad_alloc_exc8_32 exc;
    uint64_t fsize = 0ULL;

    memset(&ctx, 0, sizeof(ctx));
    ctx.close_return_ok = 1;
    ops = make_ops(&ctx, 1);

    /* Check 8: 0x100f1a30 clears flags and handles to -1 while preserving last_error_00 */
    fm.last_error_00 = 0xdeadbeefu;
    fm.open_flags_04 = 3u;
    fm.file_handle_08 = 10u;
    fm.mapping_handle_0c = 20u;
    if (rome2_vfs_open_file_mapping_init_1a30(&fm) != ROME2_VFS_REG_OK ||
        fm.last_error_00 != 0xdeadbeefu || fm.open_flags_04 != 0u ||
        fm.file_handle_08 != ROME2_VFS_INVALID_HANDLE32 ||
        fm.mapping_handle_0c != ROME2_VFS_INVALID_HANDLE32) {
        return 8;
    }

    /* Check 9: 0x100f2350 closes mapping first, then file handle, only when flag bits set */
    fm.open_flags_04 = 3u;
    fm.file_handle_08 = 0x100u;
    fm.mapping_handle_0c = 0x200u;
    ctx.closed_count = 0u;
    if (rome2_vfs_open_file_mapping_close_2350(&ops, &fm) != ROME2_VFS_REG_OK ||
        ctx.closed_count != 2u || ctx.closed_handles[0] != 0x200u || ctx.closed_handles[1] != 0x100u ||
        fm.open_flags_04 != 0u || fm.file_handle_08 != ROME2_VFS_INVALID_HANDLE32 ||
        fm.mapping_handle_0c != ROME2_VFS_INVALID_HANDLE32) {
        return 9;
    }

    /* Check 10: 0x10104b60 + 0x100fcb00 success path returns 64-bit size and sets bits 1|2 */
    ctx.next_file_handle = 0x555u;
    ctx.file_size_hi = 0x00000001u;
    ctx.file_size_lo = 0x00002000u;
    ctx.next_map_handle = 0x666u;
    if (rome2_vfs_open_file_mapping_open_4b60(&ops, &fm, "data.pack", &fsize) != ROME2_VFS_REG_OK ||
        fsize != 0x0000000100002000ULL || fm.open_flags_04 != 3u ||
        fm.file_handle_08 != 0x555u || fm.mapping_handle_0c != 0x666u || fm.last_error_00 != 0u) {
        return 10;
    }

    /* Check 11: 0x10104b60 CreateFileA failure closes prior handles, sets mapped fallback 3 */
    ctx.closed_count = 0u;
    ctx.next_file_handle = ROME2_VFS_INVALID_HANDLE32;
    ctx.last_error = 999u; /* mock_map_error returns 0 -> fallback 3 */
    fsize = 123ULL;
    if (rome2_vfs_open_file_mapping_open_4b60(&ops, &fm, "missing.pack", &fsize) != ROME2_VFS_REG_OK ||
        fsize != 0ULL || ctx.closed_count != 2u ||
        fm.open_flags_04 != 0u || fm.last_error_00 != 3u) {
        return 11;
    }

    /* Check 12: 0x100fcb00 CreateFileMappingW failure records mapped error & leaves bit 2 clear */
    fm.open_flags_04 = ROME2_VFS_OPEN_FLAG_FILE;
    fm.file_handle_08 = 0x777u;
    fm.mapping_handle_0c = ROME2_VFS_INVALID_HANDLE32;
    ctx.file_size_hi = 0u;
    ctx.file_size_lo = 0x400u;
    ctx.next_map_handle = 0u;
    ctx.last_error = 2u; /* mock_map_error -> 7 */
    fsize = 999ULL;
    if (rome2_vfs_open_file_mapping_map_cb00(&ops, &fm, &fsize) != ROME2_VFS_REG_OK ||
        fsize != 0ULL || fm.last_error_00 != 7u ||
        fm.open_flags_04 != ROME2_VFS_OPEN_FLAG_FILE || fm.mapping_handle_0c != 0u) {
        return 12;
    }

    /* Check 13: 0x100f1c50 std::bad_alloc initialization */
    memset(&exc, 0, sizeof(exc));
    if (rome2_vfs_bad_alloc_init_1c50(&exc) != ROME2_VFS_REG_OK ||
        exc.vtable_00 != ROME2_VFS_BAD_ALLOC_VTABLE32 ||
        exc.what_str_04 != ROME2_VFS_BAD_ALLOC_WHAT32) {
        return 13;
    }
    return 0;
}

static int test_vtables_and_substream(void)
{
    static const uint32_t vt_7be0[17] = {
        0x112acf80u, 0x112d3270u, 0x112d3270u, 0x100dbc00u,
        0x100dbc00u, 0x100d6770u, 0x100d6900u, 0x112d0c80u,
        0x100f3d00u, 0x112daae0u, 0x100dbc00u, 0x100dbc00u,
        0x100d6770u, 0x100d6560u, 0x100d6770u, 0x100d6770u,
        0x100dbc00u
    };
    static const uint32_t vt_7c44[8] = {
        0x112ad6d0u, 0x112c8c60u, 0x100d6900u, 0x112c0d90u,
        0x112dc250u, 0x112d32b0u, 0x101e48d0u, 0x100d6560u
    };
    uint8_t mem[0x80];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x70000000u);
    rome2_vfs_pack_vtable_7be0_17slot32 out_7be0;
    rome2_vfs_pack_vtable_7c44_8slot32 out_7c44;
    rome2_guest_addr32 addr;
    uint32_t ref_cnt = 2u;
    uint32_t cursor = 10u;
    int matches = 0;
    int deleted = 99;
    int can_read = 99;
    size_t i;

    /* Check 14-15: 0x11897be0 decode & match + mismatch + OOB preserve */
    memset(mem, 0, sizeof(mem));
    for (i = 0u; i < 17u; ++i) {
        put_u32_le(mem + i * 4u, vt_7be0[i]);
    }
    addr.value = 0x70000000u;
    if (rome2_vfs_pack_vtable_7be0_matches(&view, addr, &out_7be0, &matches) != ROME2_VFS_REG_OK ||
        matches != 1 || out_7be0.slot_024_daae0 != 0x112daae0u) {
        return 14;
    }
    put_u32_le(mem + 9u * 4u, 0xdeadbeefu);
    if (rome2_vfs_pack_vtable_7be0_matches(&view, addr, &out_7be0, &matches) != ROME2_VFS_REG_OK ||
        matches != 0) {
        return 15;
    }

    /* Check 16: 0x112daae0 refcount decrement & zero underflow guard */
    if (rome2_vfs_pack_ref_release_aae0(&ref_cnt, &deleted) != ROME2_VFS_REG_OK ||
        ref_cnt != 1u || deleted != 0) {
        return 16;
    }
    if (rome2_vfs_pack_ref_release_aae0(&ref_cnt, &deleted) != ROME2_VFS_REG_OK ||
        ref_cnt != 0u || deleted != 1) {
        return 17;
    }
    deleted = 77;
    if (rome2_vfs_pack_ref_release_aae0(&ref_cnt, &deleted) != ROME2_VFS_REG_INVALID_STATE ||
        ref_cnt != 0u || deleted != 77) {
        return 18;
    }

    /* Check 19: 0x11897c44 8-slot decode & match + OOB preserve */
    for (i = 0u; i < 8u; ++i) {
        put_u32_le(mem + i * 4u, vt_7c44[i]);
    }
    if (rome2_vfs_pack_vtable_7c44_matches(&view, addr, &out_7c44, &matches) != ROME2_VFS_REG_OK ||
        matches != 1 || out_7c44.slot_014_d32b0 != 0x112d32b0u) {
        return 19;
    }
    addr.value = 0x70000070u; /* only 0x10B remaining -> RANGE_ERROR preserves outputs */
    out_7c44.slot_000_ad6d0 = 0x12345678u;
    matches = 99;
    if (rome2_vfs_pack_vtable_7c44_matches(&view, addr, &out_7c44, &matches) != ROME2_VFS_REG_RANGE_ERROR ||
        out_7c44.slot_000_ad6d0 != 0x12345678u || matches != 99) {
        return 19;
    }

    /* Check 20: 0x112c8c60 substream can_read predicate */
    memset(mem, 0, sizeof(mem));
    addr.value = 0x70000000u;
    put_u32_le(mem + 0x14u, 0x55555555u);
    put_u32_le(mem + 0x1cu, 0x10u);
    put_u32_le(mem + 0x20u, 0x20u);
    if (rome2_vfs_pack_substream_can_read_8c60(&view, addr, &can_read) != ROME2_VFS_REG_OK ||
        can_read != 1) {
        return 20;
    }
    put_u32_le(mem + 0x1cu, 0x20u);
    if (rome2_vfs_pack_substream_can_read_8c60(&view, addr, &can_read) != ROME2_VFS_REG_OK ||
        can_read != 0) {
        return 20;
    }

    /* Check 21: 0x112c0d90 advance & 0x112dc250 rewind with overflow/underflow checks */
    if (rome2_vfs_pack_substream_advance_0d90(&cursor, 5u) != ROME2_VFS_REG_OK || cursor != 15u ||
        rome2_vfs_pack_substream_rewind_c250(&cursor, 6u) != ROME2_VFS_REG_OK || cursor != 9u ||
        rome2_vfs_pack_substream_advance_0d90(&cursor, UINT32_MAX) != ROME2_VFS_REG_RANGE_ERROR ||
        cursor != 9u ||
        rome2_vfs_pack_substream_rewind_c250(&cursor, 20u) != ROME2_VFS_REG_RANGE_ERROR ||
        cursor != 9u ||
        rome2_vfs_pack_substream_advance_0d90(&cursor, 0u) != ROME2_VFS_REG_OK || cursor != 0u) {
        return 21;
    }
    return 0;
}

int main(void)
{
    int rc;

    rc = test_semaphore_and_handle_box();
    if (rc != 0) {
        fprintf(stderr, "FAIL check %d\n", rc);
        return rc;
    }
    rc = test_open_file_mapping_and_bad_alloc();
    if (rc != 0) {
        fprintf(stderr, "FAIL check %d\n", rc);
        return rc;
    }
    rc = test_vtables_and_substream();
    if (rc != 0) {
        fprintf(stderr, "FAIL check %d\n", rc);
        return rc;
    }
    printf("vfs_handle_lifecycle_ops_tests: 21 checks passed (0 failures)\n");
    return 0;
}
