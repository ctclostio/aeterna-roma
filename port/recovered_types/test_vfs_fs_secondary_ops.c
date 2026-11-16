#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs_fs_secondary_ops.h"
#include "vfs_stream_completion_ops.h"

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "CHECK FAILED (%s:%d): %s\n",                    \
                    __FILE__, __LINE__, #cond);                              \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static int test_base_fs_and_singleton_layouts(void)
{
    rome2_vfs_base_fs_obj32 base_obj;
    rome2_vfs_u64_pair32 u64_pair;
    rome2_vfs_entry_info32 info;
    rome2_vfs_pack_wrap_singleton28_32 wrap;
    int should_free = -1;
    uint32_t end_addr = 0u;

    CHECK(sizeof(rome2_vfs_base_fs_obj32) == 0x08u);
    CHECK(sizeof(rome2_vfs_base_fs_vtable_30slot32) == 0x78u);
    CHECK(sizeof(rome2_vfs_fs_secondary_vtable_13slot32) == 0x34u);
    CHECK(sizeof(rome2_vfs_sp_ctrl_block32) == 0x10u);
    CHECK(sizeof(rome2_vfs_sp_ctrl_vtable_4slot32) == 0x10u);
    CHECK(sizeof(rome2_vfs_sp_pair32) == 0x08u);
    CHECK(sizeof(rome2_vfs_entry_info32) == 0x20u);
    CHECK(sizeof(rome2_vfs_pack_wrap_singleton28_32) == 0x1cu);
    CHECK(sizeof(rome2_vfs_fs_secondary_hdr32) == 0x20u);

    memset(&base_obj, 0, sizeof(base_obj));
    CHECK(rome2_vfs_base_fs_init_static(&base_obj) == ROME2_VFS_REG_OK);
    CHECK(base_obj.primary_vptr_00 == ROME2_VFS_BASE_FS_PRIMARY_VTABLE32);
    CHECK(base_obj.secondary_vptr_04 == ROME2_VFS_BASE_FS_SECONDARY_VTABLE32);

    base_obj.primary_vptr_00 = 0x11111111u;
    base_obj.secondary_vptr_04 = 0x22222222u;
    CHECK(rome2_vfs_base_fs_deleting_dtor(&base_obj, 0u, &should_free) == ROME2_VFS_REG_OK);
    CHECK(should_free == 0);
    CHECK(base_obj.primary_vptr_00 == ROME2_VFS_BASE_FS_PRIMARY_VTABLE32);
    CHECK(rome2_vfs_base_fs_deleting_dtor(&base_obj, 1u, &should_free) == ROME2_VFS_REG_OK);
    CHECK(should_free == 1);

    u64_pair.low_00 = 0x1234u;
    u64_pair.high_04 = 0x5678u;
    CHECK(rome2_vfs_base_fs_default_pair_zero(&u64_pair) == ROME2_VFS_REG_OK);
    CHECK(u64_pair.low_00 == 0u && u64_pair.high_04 == 0u);

    memset(&info, 0x5a, sizeof(info));
    CHECK(rome2_vfs_base_fs_default_entry_info(&info, 0x1173dad0u) == ROME2_VFS_REG_OK);
    CHECK(info.size_lo_00 == 0xffffffffu && info.size_hi_04 == 0xffffffffu);
    CHECK(info.name_str_08 == 0x1173dad0u);
    CHECK(info.pad_0c == 0x5a5a5a5au);
    CHECK(info.zero_10 == 0u && info.zero_14 == 0u && info.zero_18 == 0u && info.flag_1c == 0u);

    CHECK(rome2_vfs_vec12_end_ptr(0x20001000u, 5u, &end_addr) == ROME2_VFS_REG_OK);
    CHECK(end_addr == 0x2000103cu);
    CHECK(rome2_vfs_vec12_end_ptr(0xfffffff0u, 3u, &end_addr) == ROME2_VFS_REG_RANGE_ERROR);

    memset(&wrap, 0xff, sizeof(wrap));
    CHECK(rome2_vfs_pack_wrap_singleton_init(&wrap, 0x118979c8u) == ROME2_VFS_REG_OK);
    CHECK(wrap.vtable_00 == ROME2_VFS_PACK_WRAP_SINGLETON_VTABLE32);
    CHECK(wrap.name_str_04 == 0x118979c8u);
    CHECK(wrap.zero_08 == 0u && wrap.zero_0c == 0u && wrap.zero_10 == 0u &&
          wrap.zero_14 == 0u && wrap.zero_18 == 0u);
    CHECK(rome2_vfs_pack_wrap_singleton_atexit_reset(&wrap) == ROME2_VFS_REG_OK);
    CHECK(wrap.vtable_00 == ROME2_VFS_DTOR_BASE_VTABLE32);

    return 0;
}

static int test_shared_ptr_ctrl_block_lifecycle(void)
{
    rome2_vfs_sp_ctrl_block32 ctrl;
    rome2_vfs_sp_pair32 sp1;
    rome2_vfs_sp_pair32 sp2;
    int destroy_payload = -1;
    int delete_ctrl = -1;

    CHECK(rome2_vfs_sp_ctrl_init(&ctrl, 0x30001000u, 0x30002000u, &sp1) == ROME2_VFS_REG_OK);
    CHECK(ctrl.vtable_00 == ROME2_VFS_SP_CTRL_VTABLE32);
    CHECK(ctrl.uses_04 == 1u && ctrl.weaks_08 == 1u);
    CHECK(sp1.ptr_00 == 0x30002000u && sp1.rep_04 == 0x30001000u);

    CHECK(rome2_vfs_sp_pair_assign_retain(&ctrl, 0x30001000u, 0x30002000u, &sp2) == ROME2_VFS_REG_OK);
    CHECK(ctrl.uses_04 == 2u);
    CHECK(sp2.ptr_00 == 0x30002000u && sp2.rep_04 == 0x30001000u);

    CHECK(rome2_vfs_sp_ctrl_release_strong(&ctrl, &destroy_payload, &delete_ctrl) == ROME2_VFS_REG_OK);
    CHECK(ctrl.uses_04 == 1u && ctrl.weaks_08 == 1u);
    CHECK(destroy_payload == 0 && delete_ctrl == 0);

    CHECK(rome2_vfs_sp_ctrl_release_strong(&ctrl, &destroy_payload, &delete_ctrl) == ROME2_VFS_REG_OK);
    CHECK(ctrl.uses_04 == 0u && ctrl.weaks_08 == 0u && ctrl.payload_ptr_0c == 0u);
    CHECK(destroy_payload == 1 && delete_ctrl == 1);

    CHECK(rome2_vfs_sp_ctrl_release_strong(&ctrl, &destroy_payload, &delete_ctrl) ==
          ROME2_VFS_REG_INVALID_STATE);
    return 0;
}

static int test_secondary_handle_read_quota_and_unlink(void)
{
    rome2_vfs_handle_domain dom = ROME2_VFS_HANDLE_INVALID;
    uint32_t idx = 99u;
    const uint8_t src[8] = { 'R', 'O', 'M', 'E', '2', 'V', 'F', 'S' };
    uint8_t dst[8];
    uint32_t bytes_read = 99u;
    int succeeded = -1;
    uint32_t used_items = 1u;
    uint32_t used_bytes = 100u;
    int updated = -1;
    uint8_t cached_gate = 0u;
    int gate_init = 0;
    int ready = -1;
    rome2_vfs_dlink_node32 nodes[3];
    int32_t head = 0;
    int removed = -1;

    CHECK(rome2_vfs_sec_classify_handle(2u, 4u, 3u, ROME2_VFS_HANDLE_SENTINEL_BOUND32, &dom, &idx) ==
          ROME2_VFS_REG_OK);
    CHECK(dom == ROME2_VFS_HANDLE_PACK && idx == 2u);

    CHECK(rome2_vfs_sec_classify_handle(0x80000000u, 4u, 3u, ROME2_VFS_HANDLE_SENTINEL_BOUND32, &dom, &idx) ==
          ROME2_VFS_REG_OK);
    CHECK(dom == ROME2_VFS_HANDLE_INVALID);

    CHECK(rome2_vfs_sec_classify_handle(0x80000001u, 4u, 3u, ROME2_VFS_HANDLE_SENTINEL_BOUND32, &dom, &idx) ==
          ROME2_VFS_REG_OK);
    CHECK(dom == ROME2_VFS_HANDLE_LOOSE && idx == 0u);

    CHECK(rome2_vfs_sec_classify_handle(0x80000003u, 4u, 3u, ROME2_VFS_HANDLE_SENTINEL_BOUND32, &dom, &idx) ==
          ROME2_VFS_REG_OK);
    CHECK(dom == ROME2_VFS_HANDLE_LOOSE && idx == 2u);

    CHECK(rome2_vfs_sec_classify_handle(0xffffffffu, 4u, 3u, ROME2_VFS_HANDLE_SENTINEL_BOUND32, &dom, &idx) ==
          ROME2_VFS_REG_OK);
    CHECK(dom == ROME2_VFS_HANDLE_INVALID);

    /* Unmounted read returns 0 cleanly without copying. */
    memset(dst, 0, sizeof(dst));
    CHECK(rome2_vfs_sec_read_whole_file_dispatch(0u, 1u, 1u, src, sizeof(src), dst, sizeof(dst),
                                               &bytes_read, &succeeded) == ROME2_VFS_REG_OK);
    CHECK(succeeded == 0 && bytes_read == 0u && dst[0] == 0u);

    /* Mounted encrypted read copies then XOR-deciphers with key=0 sequence. */
    CHECK(rome2_vfs_sec_read_whole_file_dispatch(1u, 1u, ROME2_VFS_STREAM_FLAG_ENCRYPTED32,
                                               src, sizeof(src), dst, sizeof(dst),
                                               &bytes_read, &succeeded) == ROME2_VFS_REG_OK);
    CHECK(succeeded == 1 && bytes_read == sizeof(src));
    CHECK(memcmp(dst, src, sizeof(src)) != 0);
    {
        uint32_t key = 0u;
        size_t processed = 0u;
        CHECK(rome2_vfs_stream_xor_deobfuscate_blocks32(
                  dst, sizeof(dst), dst, &key, &processed) == ROME2_VFS_REG_OK);
        CHECK(processed == sizeof(dst));
        CHECK(memcmp(dst, src, sizeof(src)) == 0);
    }

    CHECK(rome2_vfs_sec_apply_quota_update(1u, 1u, 1u, 50u, 3u, 200u,
                                         &used_items, &used_bytes, &updated) == ROME2_VFS_REG_OK);
    CHECK(updated == 1 && used_items == 2u && used_bytes == 150u);
    CHECK(rome2_vfs_sec_apply_quota_update(1u, 1u, 1u, 60u, 3u, 200u,
                                         &used_items, &used_bytes, &updated) == ROME2_VFS_REG_OK);
    CHECK(updated == 0 && used_items == 2u && used_bytes == 150u);

    CHECK(rome2_vfs_sec_gate_and_mounted_ready(1u, 1u, 1u, &cached_gate, &gate_init, &ready) ==
          ROME2_VFS_REG_OK);
    CHECK(ready == 1 && cached_gate == 1u && gate_init == 1);

    nodes[0] = (rome2_vfs_dlink_node32){ -1, 1, 10u, 1u, 0u };
    nodes[1] = (rome2_vfs_dlink_node32){ 0, 2, 20u, 1u, 0u };
    nodes[2] = (rome2_vfs_dlink_node32){ 1, -1, 30u, 1u, 0u };
    CHECK(rome2_vfs_sec_unlink_list_node(ready, nodes, 3u, &head, 20u, &removed) == ROME2_VFS_REG_OK);
    CHECK(removed == 1 && head == 0 && nodes[0].next_idx == 2 && nodes[2].prev_idx == 0 &&
          nodes[1].active == 0u && nodes[1].freed == 1u);
    CHECK(rome2_vfs_sec_unlink_list_node(ready, nodes, 3u, &head, 10u, &removed) == ROME2_VFS_REG_OK);
    CHECK(removed == 1 && head == 2 && nodes[2].prev_idx == -1 && nodes[0].freed == 1u);
    CHECK(rome2_vfs_sec_unlink_list_node(ready, nodes, 3u, &head, 99u, &removed) == ROME2_VFS_REG_OK);
    CHECK(removed == 0);

    return 0;
}

int main(void)
{
    if (test_base_fs_and_singleton_layouts() != 0) {
        return 1;
    }
    if (test_shared_ptr_ctrl_block_lifecycle() != 0) {
        return 1;
    }
    if (test_secondary_handle_read_quota_and_unlink() != 0) {
        return 1;
    }
    puts("test_vfs_fs_secondary_ops: ALL PASSED");
    return 0;
}
