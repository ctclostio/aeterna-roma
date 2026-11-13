#include "vfs_pool_slab.h"

#include <stdio.h>
#include <string.h>

static int g_checks = 0;
static int g_failures = 0;

static void check(int cond, const char *name) {
    ++g_checks;
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        ++g_failures;
    }
}

static void put_u32_le(uint8_t *buf, size_t offset, uint32_t val) {
    buf[offset + 0u] = (uint8_t)(val & 0xffu);
    buf[offset + 1u] = (uint8_t)((val >> 8) & 0xffu);
    buf[offset + 2u] = (uint8_t)((val >> 16) & 0xffu);
    buf[offset + 3u] = (uint8_t)((val >> 24) & 0xffu);
}

static void test_pool_header_and_slab_descriptor(void) {
    uint8_t mem[32];
    rome2_guest_read_view view = {mem, 0x119344f4u, sizeof(mem)};
    rome2_vfs_freelist_pool_header32 hdr;
    rome2_vfs_slab_descriptor32 desc;
    rome2_guest_addr32 addr_ok = {0x119344f4u};
    rome2_guest_addr32 addr_next = {0x11934500u};
    rome2_guest_addr32 addr_oob = {0x11934510u};

    memset(mem, 0, sizeof(mem));
    put_u32_le(mem, 0x00u, 0x20001000u);
    put_u32_le(mem, 0x04u, 0x20002000u);
    put_u32_le(mem, 0x08u, 4u);
    put_u32_le(mem, 0x0cu, 0x30001000u);
    put_u32_le(mem, 0x10u, 0x30002000u);

    memset(&hdr, 0xaa, sizeof(hdr));
    check(rome2_vfs_decode_freelist_pool_header32(&view, addr_ok, &hdr) ==
              ROME2_VFS_REG_OK,
          "decode pool 0 header");
    check(hdr.freelist_head == 0x20001000u, "pool freelist_head");
    check(hdr.slab_chain_head == 0x20002000u, "pool slab_chain_head");
    check(hdr.reserved_008 == 4u, "pool reserved_008");

    check(rome2_vfs_decode_freelist_pool_header32(&view, addr_oob, &hdr) ==
              ROME2_VFS_REG_RANGE_ERROR,
          "pool decode OOB fails closed");
    check(hdr.freelist_head == 0x20001000u, "pool output preserved on OOB");

    memset(&desc, 0, sizeof(desc));
    check(rome2_vfs_decode_slab_descriptor32(&view, addr_next, &desc) ==
              ROME2_VFS_REG_OK,
          "decode slab descriptor");
    check(desc.node_array == 0x30001000u && desc.next_slab == 0x30002000u,
          "slab descriptor fields");

    check(rome2_vfs_decode_freelist_pool_header32(NULL, addr_ok, &hdr) ==
              ROME2_VFS_REG_BAD_ARGUMENT,
          "pool null view");
    check(rome2_vfs_decode_slab_descriptor32(&view, (rome2_guest_addr32){0u},
                                             &desc) ==
              ROME2_VFS_REG_BAD_ARGUMENT,
          "slab desc null address");
}

static void test_stride28_slab_build_and_verify(void) {
    uint8_t slab_buf[5u * ROME2_VFS_SLAB_NODE_STRIDE];
    rome2_guest_read_view view = {slab_buf, 0x20000000u, sizeof(slab_buf)};
    uint32_t bytes = 999u;
    rome2_guest_addr32 last_next = {0xdeadbeefu};

    check(rome2_vfs_stride28_slab_byte_size(5u, &bytes) == ROME2_VFS_REG_OK,
          "stride28 size ok");
    check(bytes == 140u, "5 * 28 = 140");
    check(rome2_vfs_stride28_slab_byte_size(0x10000000u, &bytes) ==
              ROME2_VFS_REG_RANGE_ERROR,
          "stride28 overflow rejected");
    check(bytes == 140u, "stride28 size preserved on overflow");

    check(rome2_vfs_init_stride28_slab(slab_buf, sizeof(slab_buf),
                                       (rome2_guest_addr32){0x20000000u}, 5u) ==
              ROME2_VFS_REG_OK,
          "init stride28 slab");
    check(rome2_vfs_verify_stride28_slab_chain(
              &view, (rome2_guest_addr32){0x20000000u}, 5u, &last_next) ==
              ROME2_VFS_REG_OK,
          "verify stride28 chain");
    check(last_next.value == 0u, "tail next == 0");

    /* Corrupt link 2 -> should fail with INVALID_STATE and preserve last_next */
    last_next.value = 0x12345678u;
    put_u32_le(slab_buf, 2u * ROME2_VFS_SLAB_NODE_STRIDE, 0x20000000u);
    check(rome2_vfs_verify_stride28_slab_chain(
              &view, (rome2_guest_addr32){0x20000000u}, 5u, &last_next) ==
              ROME2_VFS_REG_INVALID_STATE,
          "corrupt stride28 link rejected");
    check(last_next.value == 0x12345678u, "last_next preserved on error");

    /* Capacity too small & guest wraparound checks */
    check(rome2_vfs_init_stride28_slab(slab_buf, 139u,
                                       (rome2_guest_addr32){0x20000000u}, 5u) ==
              ROME2_VFS_REG_RANGE_ERROR,
          "slab capacity too small");
    check(rome2_vfs_init_stride28_slab(slab_buf, sizeof(slab_buf),
                                       (rome2_guest_addr32){0xffffffa0u}, 5u) ==
              ROME2_VFS_REG_RANGE_ERROR,
          "slab guest wraparound rejected");
    check(rome2_vfs_init_stride28_slab(NULL, 0u,
                                       (rome2_guest_addr32){0x20000000u}, 0u) ==
              ROME2_VFS_REG_OK,
          "zero-count slab init no-op");
}

static void test_archive_disposer_and_base_vtable(void) {
    uint8_t disp_mem[0x18];
    uint8_t vt_mem[ROME2_VFS_BASE_VTABLE_SLOT_COUNT * 4u];
    rome2_guest_read_view disp_view = {disp_mem, 0x30001000u, sizeof(disp_mem)};
    rome2_guest_read_view vt_view = {
        vt_mem, ROME2_VFS_PACK_ENTRY_BASE_VTABLE32, sizeof(vt_mem)};
    rome2_vfs_archive_name_disposer32 disp;
    uint32_t concrete[ROME2_VFS_BASE_CONCRETE_SLOTS];

    memset(disp_mem, 0, sizeof(disp_mem));
    put_u32_le(disp_mem, 0x00u, ROME2_VFS_ARCHIVE_DISPOSER_VT32);
    put_u32_le(disp_mem, 0x0cu, 0x1189a444u);
    put_u32_le(disp_mem, 0x10u, 0x30002020u);
    put_u32_le(disp_mem, 0x14u, 7u);

    memset(&disp, 0, sizeof(disp));
    check(rome2_vfs_decode_archive_disposer32(
              &disp_view, (rome2_guest_addr32){0x30001000u}, &disp) ==
              ROME2_VFS_REG_OK,
          "decode archive disposer");
    check(disp.vtable == ROME2_VFS_ARCHIVE_DISPOSER_VT32, "disposer vtable");
    check(disp.owned_node == 0x30002020u && disp.tail_014 == 7u,
          "disposer owned_node & tail");

    put_u32_le(disp_mem, 0x00u, 0x1189a444u);
    check(rome2_vfs_decode_archive_disposer32(
              &disp_view, (rome2_guest_addr32){0x30001000u}, &disp) ==
              ROME2_VFS_REG_INVALID_STATE,
          "disposer wrong vtable rejected");
    check(disp.vtable == ROME2_VFS_ARCHIVE_DISPOSER_VT32,
          "disposer preserved on wrong vtable");

    for (uint32_t i = 0u; i < ROME2_VFS_BASE_PURECALL_PREFIX; ++i) {
        put_u32_le(vt_mem, (size_t)i * 4u, ROME2_VFS_PURECALL32);
    }
    put_u32_le(vt_mem, 11u * 4u, 0x10fa1340u);
    put_u32_le(vt_mem, 12u * 4u, 0x10f9f6e0u);
    put_u32_le(vt_mem, 13u * 4u, 0x10f9faa0u);
    put_u32_le(vt_mem, 14u * 4u, 0x10f9fae0u);

    memset(concrete, 0, sizeof(concrete));
    check(rome2_vfs_decode_pack_entry_base_vtable32(
              &vt_view,
              (rome2_guest_addr32){ROME2_VFS_PACK_ENTRY_BASE_VTABLE32},
              concrete) == ROME2_VFS_REG_OK,
          "decode pack_entry base vtable");
    check(concrete[0] == 0x10fa1340u && concrete[3] == 0x10f9fae0u,
          "base vtable concrete tail");

    put_u32_le(vt_mem, 3u * 4u, 0x10128c50u);
    check(rome2_vfs_decode_pack_entry_base_vtable32(
              &vt_view,
              (rome2_guest_addr32){ROME2_VFS_PACK_ENTRY_BASE_VTABLE32},
              concrete) == ROME2_VFS_REG_INVALID_STATE,
          "base vtable requires 11 purecall prefix");
    check(concrete[0] == 0x10fa1340u, "base vtable concrete preserved");
}

static void test_mutex_global_map_and_setting_flags(void) {
    uint8_t box_mem[sizeof(rome2_vfs_mutex_box32)];
    uint8_t map_mem[sizeof(rome2_vfs_global_map32)];
    rome2_guest_read_view box_view = {
        box_mem, ROME2_VFS_MUTEX_BOX_ADDR32, sizeof(box_mem)};
    rome2_guest_read_view map_view = {
        map_mem, ROME2_VFS_GLOBAL_MAP_ADDR32, sizeof(map_mem)};
    rome2_vfs_mutex_box32 box;
    rome2_vfs_global_map32 map;
    uint32_t bucket_bytes = 0u;
    uint32_t next_flags = 0u;

    memset(box_mem, 0, sizeof(box_mem));
    put_u32_le(box_mem, 0x00u, 0x1189a000u);
    put_u32_le(box_mem, 0x04u, 0x40001000u);
    put_u32_le(box_mem, 0x08u, 0xffffffffu);
    put_u32_le(box_mem, 0x0cu, 0u);
    put_u32_le(box_mem, 0x18u, 4000u);

    memset(&box, 0, sizeof(box));
    check(rome2_vfs_decode_mutex_box32(
              &box_view, (rome2_guest_addr32){ROME2_VFS_MUTEX_BOX_ADDR32},
              &box) == ROME2_VFS_REG_OK,
          "decode mutex box");
    check(box.cs_lock_count == -1 && box.cs_spin_count == 4000u,
          "mutex box fields");

    memset(map_mem, 0, sizeof(map_mem));
    put_u32_le(map_mem, 0x00u, 0x50001000u);
    put_u32_le(map_mem, 0x04u, 8u);
    put_u32_le(map_mem, 0x08u, 11u); /* length_units = 11 ("Removed_key") */
    put_u32_le(map_mem, 0x0cu, 16u); /* capacity_units = 16 */
    put_u32_le(map_mem, 0x10u, 0x50002000u);
    put_u32_le(map_mem, 0x14u, 10u); /* length_units = 10 ("Unused_key") */
    put_u32_le(map_mem, 0x18u, 16u); /* capacity_units = 16 */
    put_u32_le(map_mem, 0x1cu, 0x50003000u);

    memset(&map, 0, sizeof(map));
    check(rome2_vfs_decode_global_map32(
              &map_view, (rome2_guest_addr32){ROME2_VFS_GLOBAL_MAP_ADDR32},
              &map, &bucket_bytes) == ROME2_VFS_REG_OK,
          "decode global map");
    check(map.bucket_count == 8u && bucket_bytes == 0x80u, "map 8 * 16 = 0x80");
    check(map.removed_key.length_units == 11 && map.unused_key.length_units == 10,
          "map sentinel key lengths");

    put_u32_le(map_mem, 0x04u, 0x10000000u);
    check(rome2_vfs_decode_global_map32(
              &map_view, (rome2_guest_addr32){ROME2_VFS_GLOBAL_MAP_ADDR32},
              &map, &bucket_bytes) == ROME2_VFS_REG_RANGE_ERROR,
          "map bucket overflow rejected");
    check(bucket_bytes == 0x80u, "bucket_bytes preserved on error");

    /* 0x11346530 flag transitions */
    check(rome2_vfs_setting_flags_compute32(0x03u, 0x1234u, 0u, 1u,
                                            &next_flags) == ROME2_VFS_REG_OK,
          "flags early return on effective == 1");
    check(next_flags == 0x03u, "flags unchanged when effective == 1");

    check(rome2_vfs_setting_flags_compute32(0x02u, 0u, 0x10u, 2u,
                                            &next_flags) == ROME2_VFS_REG_OK,
          "flags merge zero vb_ptr sets bit3");
    check(next_flags == 0x0au, "(0x02 | 0x02 | 0x08) & 0x0f == 0x0a");

    check(rome2_vfs_setting_flags_compute32(0x01u, 0x2000u, 0x14u, 1u,
                                            &next_flags) == ROME2_VFS_REG_OK,
          "flags bit2 bypasses resolved_status");
    check(next_flags == 0x05u, "(0x01 | 0x14) & 0x0f == 0x05");

    check(rome2_vfs_setting_flags_compute32(0u, 0u, 0u, 0u, NULL) ==
              ROME2_VFS_REG_BAD_ARGUMENT,
          "flags null output");
}

int main(void) {
    test_pool_header_and_slab_descriptor();
    test_stride28_slab_build_and_verify();
    test_archive_disposer_and_base_vtable();
    test_mutex_global_map_and_setting_flags();
    printf("vfs_pool_slab_tests: %d checks passed (%d failures)\n",
           g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
