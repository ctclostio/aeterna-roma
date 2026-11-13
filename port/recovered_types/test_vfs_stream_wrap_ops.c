#include <stdio.h>
#include <string.h>

#include "vfs_stream_wrap_ops.h"

static void put_u32_le(uint8_t *dst, uint32_t value) {
    dst[0] = (uint8_t)(value & 0xffu);
    dst[1] = (uint8_t)((value >> 8u) & 0xffu);
    dst[2] = (uint8_t)((value >> 16u) & 0xffu);
    dst[3] = (uint8_t)((value >> 24u) & 0xffu);
}

static rome2_guest_read_view make_view(const uint8_t *buf, size_t len, uint32_t base) {
    rome2_guest_read_view v;
    v.host_base = buf;
    v.guest_base = base;
    v.byte_count = len;
    return v;
}

static int test_wrap_a_slots_and_release(void) {
    uint8_t mem[0x100];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x20000000u);
    rome2_vfs_stream_wrap_a32 wa;
    uint32_t rem = 777u;
    int flag = 99;
    rome2_data_address32 hdl = 0xdeadbeefu;
    rome2_vfs_stream_wrap_a_slot1c_plan32 plan;

    memset(mem, 0, sizeof(mem));
    memset(&wa, 0, sizeof(wa));
    wa.vtable = 0x118977ecu;
    wa.zero_020 = 11u;
    wa.zero_024 = 22u;
    wa.flag_028 = 1u;
    wa.zero_02c = 2u;
    wa.zero_030 = 0x20000020u;

    /* 0x112c8b80 has_handle & 0x112d9860 is_open & 0x112badf0 plan_slot1c */
    put_u32_le(mem + 0x20u + 0x0cu, 0x20000060u); /* handle_box.sentinel_or_state */
    put_u32_le(mem + 0x60u + 0x00u, 0x11899990u); /* state.vtable */
    mem[0x60u + 0x0cu] = 0u;                      /* open/ready */

    if (rome2_vfs_stream_wrap_a_has_handle32(&wa, &flag) != ROME2_VFS_REG_OK || flag != 1) {
        return 1;
    }
    if (rome2_vfs_stream_wrap_a_is_open32(&view, &wa, &flag) != ROME2_VFS_REG_OK || flag != 1) {
        return 2;
    }
    memset(&plan, 0, sizeof(plan));
    if (rome2_vfs_stream_wrap_a_plan_slot1c32(&view, &wa, &plan) != ROME2_VFS_REG_OK ||
        plan.has_state != 1 || plan.needs_sync_call != 1 ||
        plan.state_addr != 0x20000060u || plan.tail_slot_008_vtable_offset != 0x08u) {
        return 3;
    }

    /* Closed state (eof_or_closed_00c == 1) -> is_open=0, plan skips sync call. */
    mem[0x60u + 0x0cu] = 1u;
    if (rome2_vfs_stream_wrap_a_is_open32(&view, &wa, &flag) != ROME2_VFS_REG_OK || flag != 0) {
        return 4;
    }
    if (rome2_vfs_stream_wrap_a_plan_slot1c32(&view, &wa, &plan) != ROME2_VFS_REG_OK ||
        plan.has_state != 1 || plan.needs_sync_call != 0) {
        return 5;
    }

    /* Release ref 2 -> 1 keeps handle & zero_020..flag_028 intact. */
    if (rome2_vfs_stream_wrap_a_release_ref32(&wa, &rem, &flag, &hdl) != ROME2_VFS_REG_OK ||
        rem != 1u || flag != 0 || hdl != 0u || wa.zero_030 != 0x20000020u || wa.zero_020 != 11u) {
        return 6;
    }
    /* Release ref 1 -> 0 zeroes fields & captures handle. */
    if (rome2_vfs_stream_wrap_a_release_ref32(&wa, &rem, &flag, &hdl) != ROME2_VFS_REG_OK ||
        rem != 0u || flag != 1 || hdl != 0x20000020u ||
        wa.zero_030 != 0u || wa.zero_020 != 0u || wa.zero_024 != 0u || wa.flag_028 != 0u) {
        return 7;
    }
    /* Further release fails INVALID_STATE and preserves outputs. */
    rem = 55u;
    flag = 3;
    hdl = 0x1234u;
    if (rome2_vfs_stream_wrap_a_release_ref32(&wa, &rem, &flag, &hdl) != ROME2_VFS_REG_INVALID_STATE ||
        rem != 55u || flag != 3 || hdl != 0x1234u) {
        return 8;
    }
    if (rome2_vfs_stream_wrap_a_has_handle32(&wa, &flag) != ROME2_VFS_REG_OK || flag != 0) {
        return 9;
    }
    if (rome2_vfs_stream_wrap_a_is_open32(NULL, &wa, &flag) != ROME2_VFS_REG_OK || flag != 0) {
        return 10;
    }
    if (rome2_vfs_stream_wrap_a_plan_slot1c32(NULL, &wa, &plan) != ROME2_VFS_REG_OK ||
        plan.has_state != 0 || plan.state_addr != 0u) {
        return 11;
    }
    /* Null output preservation */
    if (rome2_vfs_stream_wrap_a_has_handle32(NULL, &flag) != ROME2_VFS_REG_BAD_ARGUMENT) {
        return 12;
    }
    return 0;
}

static int test_wrap_b_slots_and_release(void) {
    uint8_t mem[0x80];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x30000000u);
    rome2_vfs_stream_wrap_b32 wb;
    rome2_vfs_stream_view_box32 box;
    uint32_t rem = 0u;
    int flag = 0;
    rome2_data_address32 vbox = 0u;

    memset(mem, 0, sizeof(mem));
    memset(&wb, 0, sizeof(wb));
    wb.vtable = 0x11897790u;
    wb.tag_00c = 0x100u;
    wb.zero_020[0] = 0x30000010u; /* view_box ptr */
    wb.zero_020[1] = 0x100u;      /* cursor/bound */
    wb.zero_020[2] = 0u;          /* override == 0 -> uses tag_00c */
    wb.flag_030 = 1u;
    wb.flag_034 = 1u;
    wb.zero_038 = 1u;

    put_u32_le(mem + 0x10u + 0x00u, 0x40000000u);
    put_u32_le(mem + 0x10u + 0x04u, 0x40000080u);

    if (rome2_vfs_stream_wrap_b_has_view32(&wb, &flag) != ROME2_VFS_REG_OK || flag != 1) {
        return 21;
    }
    if (rome2_vfs_stream_wrap_b_is_at_bound32(&wb, &flag) != ROME2_VFS_REG_OK || flag != 1) {
        return 22;
    }
    wb.zero_020[2] = 0x80u; /* non-zero override mismatch with 0x100u */
    if (rome2_vfs_stream_wrap_b_is_at_bound32(&wb, &flag) != ROME2_VFS_REG_OK || flag != 0) {
        return 23;
    }
    wb.zero_020[1] = 0x80u;
    if (rome2_vfs_stream_wrap_b_is_at_bound32(&wb, &flag) != ROME2_VFS_REG_OK || flag != 1) {
        return 24;
    }
    memset(&box, 0, sizeof(box));
    if (rome2_vfs_stream_wrap_b_read_view_box32(&view, &wb, &box) != ROME2_VFS_REG_OK ||
        box.mapped_view_base != 0x40000000u || box.data_ptr != 0x40000080u) {
        return 25;
    }

    if (rome2_vfs_stream_wrap_b_release_ref32(&wb, &rem, &flag, &vbox) != ROME2_VFS_REG_OK ||
        rem != 0u || flag != 1 || vbox != 0x30000010u ||
        wb.zero_020[0] != 0u || wb.zero_020[1] != 0u || wb.zero_020[2] != 0u ||
        wb.flag_030 != 0u || wb.flag_034 != 0u) {
        return 26;
    }
    if (rome2_vfs_stream_wrap_b_has_view32(&wb, &flag) != ROME2_VFS_REG_OK || flag != 0) {
        return 27;
    }
    /* OOB / NULL box read preserves output struct. */
    box.mapped_view_base = 0xaaaaaaaaU;
    box.data_ptr = 0xbbbbbbbbU;
    if (rome2_vfs_stream_wrap_b_read_view_box32(&view, &wb, &box) != ROME2_VFS_REG_INVALID_STATE ||
        box.mapped_view_base != 0xaaaaaaaaU || box.data_ptr != 0xbbbbbbbbU) {
        return 28;
    }
    return 0;
}

static int test_rb_rotations_and_extremes(void) {
    /*
     * Index 0 = sentinel (is_nil = 1)
     * Build tree:
     *        1 (root)
     *       / \
     *      2   3
     *         / \
     *        4   5
     */
    rome2_vfs_rb_sentinel_node32 nodes[6];
    uint32_t idx = 999u;

    memset(nodes, 0, sizeof(nodes));
    nodes[0].is_nil = 1u;
    nodes[0].parent = 1u;
    nodes[0].left = 2u;
    nodes[0].right = 5u;

    nodes[1].left = 2u;  nodes[1].parent = 0u; nodes[1].right = 3u;
    nodes[2].left = 0u;  nodes[2].parent = 1u; nodes[2].right = 0u;
    nodes[3].left = 4u;  nodes[3].parent = 1u; nodes[3].right = 5u;
    nodes[4].left = 0u;  nodes[4].parent = 3u; nodes[4].right = 0u;
    nodes[5].left = 0u;  nodes[5].parent = 3u; nodes[5].right = 0u;

    if (rome2_vfs_rb_find_extreme_index(nodes, 6u, 1u, 0, &idx) != ROME2_VFS_REG_OK || idx != 2u) {
        return 41;
    }
    if (rome2_vfs_rb_find_extreme_index(nodes, 6u, 1u, 1, &idx) != ROME2_VFS_REG_OK || idx != 5u) {
        return 42;
    }

    /* Left rotate at root 1 -> new root is 3; left(3)=1, right(1)=4; min=2, max=5. */
    if (rome2_vfs_rb_rotate_and_refresh_extremes(nodes, 6u, 0u, 1u, 1) != ROME2_VFS_REG_OK ||
        nodes[0].parent != 3u || nodes[3].left != 1u || nodes[1].parent != 3u ||
        nodes[1].right != 4u || nodes[4].parent != 1u ||
        nodes[0].left != 2u || nodes[0].right != 5u) {
        return 43;
    }

    /* Right rotate back at new root 3 -> restores root 1; right(1)=3, left(3)=4. */
    if (rome2_vfs_rb_rotate_and_refresh_extremes(nodes, 6u, 0u, 3u, 0) != ROME2_VFS_REG_OK ||
        nodes[0].parent != 1u || nodes[1].right != 3u || nodes[3].parent != 1u ||
        nodes[3].left != 4u || nodes[4].parent != 3u ||
        nodes[0].left != 2u || nodes[0].right != 5u) {
        return 44;
    }

    /* Cycle detection in walk returns STEP_LIMIT and preserves *out_extreme_idx. */
    nodes[2].left = 2u;
    idx = 12345u;
    if (rome2_vfs_rb_find_extreme_index(nodes, 6u, 1u, 0, &idx) != ROME2_VFS_REG_STEP_LIMIT ||
        idx != 12345u) {
        return 45;
    }
    return 0;
}

int main(void) {
    int rc;
    rc = test_wrap_a_slots_and_release();
    if (rc != 0) {
        fprintf(stderr, "test_wrap_a_slots_and_release failed: %d\n", rc);
        return rc;
    }
    rc = test_wrap_b_slots_and_release();
    if (rc != 0) {
        fprintf(stderr, "test_wrap_b_slots_and_release failed: %d\n", rc);
        return rc;
    }
    rc = test_rb_rotations_and_extremes();
    if (rc != 0) {
        fprintf(stderr, "test_rb_rotations_and_extremes failed: %d\n", rc);
        return rc;
    }
    printf("vfs_stream_wrap_ops_tests: 18 checks passed (0 failures)\n");
    return 0;
}
