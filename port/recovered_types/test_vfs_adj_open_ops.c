#include <stdio.h>
#include <string.h>

#include "vfs_adj_open_ops.h"

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

static int test_adj_hash_and_vec_plan(void) {
    uint8_t mem[0x40];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x10000000u);
    rome2_guest_addr32 addr;
    rome2_vfs_adj_hash_node32 node;
    rome2_vfs_u32_ptr_vec32 vec;
    uint32_t next_cnt = 999u;
    uint32_t sz = 999u;
    uint32_t cap = 999u;
    int grow = 99;

    /* Check 1-2: 0x112a2910 ceiling */
    if (rome2_vfs_adj_hash_can_allocate32(0x071c71c6u, &next_cnt) != ROME2_VFS_REG_OK ||
        next_cnt != 0x071c71c7u) {
        return 1;
    }
    next_cnt = 42u;
    if (rome2_vfs_adj_hash_can_allocate32(0x071c71c7u, &next_cnt) != ROME2_VFS_REG_RANGE_ERROR ||
        next_cnt != 42u) {
        return 2;
    }

    /* Check 3-4: 36B node decode + error preservation */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x00u, 0x20001000u);
    put_u32_le(mem + 0x04u, 0x20001020u);
    put_u32_le(mem + 0x08u, 0x61626364u);
    put_u32_le(mem + 0x14u, 0x30000000u);
    put_u32_le(mem + 0x18u, 5u);
    put_u32_le(mem + 0x1cu, 0x30000100u);
    put_u32_le(mem + 0x20u, 7u);
    addr.value = 0x10000000u;
    memset(&node, 0, sizeof(node));
    if (rome2_vfs_decode_adj_hash_node32(&view, addr, &node) != ROME2_VFS_REG_OK ||
        node.next != 0x20001000u || node.prev != 0x20001020u ||
        node.key_name[0] != 0x61626364u || node.sub_tree_a.sentinel != 0x30000000u ||
        node.sub_tree_a.size != 5u || node.sub_tree_b.size != 7u) {
        return 3;
    }
    addr.value = 0x10000030u; /* truncated inside 36B node */
    if (rome2_vfs_decode_adj_hash_node32(&view, addr, &node) != ROME2_VFS_REG_RANGE_ERROR ||
        node.next != 0x20001000u || node.sub_tree_b.size != 7u) {
        return 4;
    }

    /* Check 5-8: 0x112d8c50 12B ptr vec push_back planner */
    vec.first = 0x40000000u;
    vec.last = 0x40000008u; /* 2 elems */
    vec.end = 0x40000010u;  /* 4 cap -> no grow */
    if (rome2_vfs_u32_vec_plan_push32(&vec, &sz, &cap, &grow) != ROME2_VFS_REG_OK ||
        sz != 2u || cap != 4u || grow != 0) {
        return 5;
    }
    vec.last = 0x40000010u; /* 4 elems, full -> 1.5x = 6 */
    if (rome2_vfs_u32_vec_plan_push32(&vec, &sz, &cap, &grow) != ROME2_VFS_REG_OK ||
        sz != 4u || cap != 6u || grow != 1) {
        return 6;
    }
    vec.first = 0x40000000u;
    vec.last = 0x40000004u; /* cap 1 -> half_cap=0 -> clamps to size+1 = 2 */
    vec.end = 0x40000004u;
    if (rome2_vfs_u32_vec_plan_push32(&vec, &sz, &cap, &grow) != ROME2_VFS_REG_OK ||
        sz != 1u || cap != 2u || grow != 1) {
        return 7;
    }
    /* Overflow ceiling 0x3fffffff * 4 = 0xfffffffc preserves outputs */
    vec.first = 0u;
    vec.last = 0xfffffffcu;
    vec.end = 0xfffffffcu;
    sz = 11u;
    cap = 22u;
    grow = -1;
    if (rome2_vfs_u32_vec_plan_push32(&vec, &sz, &cap, &grow) != ROME2_VFS_REG_RANGE_ERROR ||
        sz != 11u || cap != 22u || grow != -1) {
        return 8;
    }
    return 0;
}

static int test_wait_reentry_chain_and_dtors(void) {
    rome2_vfs_stream_state_prefix32 st;
    rome2_vfs_flag_chain_node32 nodes[4];
    int should_wait = 99;
    uint32_t leaves = 99u;
    uint32_t reenters = 99u;
    uint32_t next_ref = 99u;
    uint32_t free_bytes = 99u;
    size_t cleared = 99u;

    /* Check 9-11: 0x112c0c60 recursive mutex unwind/restore plan */
    memset(&st, 0, sizeof(st));
    st.eof_or_closed_00c = 0u;
    if (rome2_vfs_state_wait_plan32(&st, 3u, &should_wait, &leaves, &reenters) != ROME2_VFS_REG_OK ||
        should_wait != 1 || leaves != 4u || reenters != 3u) {
        return 11;
    }
    st.eof_or_closed_00c = 1u;
    if (rome2_vfs_state_wait_plan32(&st, 3u, &should_wait, &leaves, &reenters) != ROME2_VFS_REG_OK ||
        should_wait != 0 || leaves != 0u || reenters != 0u) {
        return 12;
    }
    st.eof_or_closed_00c = 0u;
    should_wait = 5;
    leaves = 6u;
    reenters = 7u;
    if (rome2_vfs_state_wait_plan32(&st, UINT32_MAX, &should_wait, &leaves, &reenters) != ROME2_VFS_REG_RANGE_ERROR ||
        should_wait != 5 || leaves != 6u || reenters != 7u) {
        return 13;
    }

    /* Check 14-16: 0x112d8d30 / 0x112d8e20 slice reentry validation */
    if (rome2_vfs_stream_wrap_check_open_reentry32(0u, 1u, 2u, 3u, 4u, 0, &next_ref) != ROME2_VFS_REG_OK ||
        next_ref != 1u) {
        return 14;
    }
    next_ref = 88u;
    if (rome2_vfs_stream_wrap_check_open_reentry32(1u, 10u, 20u, 10u, 99u, 0, &next_ref) != ROME2_VFS_REG_INVALID_STATE ||
        next_ref != 88u) {
        return 15;
    }
    if (rome2_vfs_stream_wrap_check_open_reentry32(2u, 10u, 20u, 10u, 99u, 1, &next_ref) != ROME2_VFS_REG_OK ||
        next_ref != 3u) {
        return 16;
    }

    /* Check 17-19: 0x112cd4c0 recursive chain clear & cycle protection */
    memset(nodes, 0, sizeof(nodes));
    nodes[0].next = 1u; nodes[0].flag_004 = 1u;
    nodes[1].next = 2u; nodes[1].flag_004 = 1u;
    nodes[2].next = UINT32_MAX; nodes[2].flag_004 = 1u;
    nodes[3].next = UINT32_MAX; nodes[3].flag_004 = 1u;
    if (rome2_vfs_clear_flag_chain_bounded(nodes, 4u, 0u, &cleared) != ROME2_VFS_REG_OK ||
        cleared != 3u || nodes[0].flag_004 != 0u || nodes[1].flag_004 != 0u ||
        nodes[2].flag_004 != 0u || nodes[3].flag_004 != 1u) {
        return 17;
    }
    nodes[0].flag_004 = 1u;
    nodes[1].next = 0u; /* cycle 0 <-> 1 must not mutate nodes */
    cleared = 77u;
    if (rome2_vfs_clear_flag_chain_bounded(nodes, 4u, 0u, &cleared) != ROME2_VFS_REG_STEP_LIMIT ||
        cleared != 77u || nodes[0].flag_004 != 1u) {
        return 18;
    }

    /* Check 19-22: 0x112acd50 / 0x112acd70 / 0x112accd0 ref-block free sizes */
    if (rome2_vfs_ref_block_delete_size32(ROME2_VFS_REF_BLOCK_A_VTABLE32, 1u, &free_bytes) != ROME2_VFS_REG_OK ||
        free_bytes != 0x50u) {
        return 19;
    }
    if (rome2_vfs_ref_block_delete_size32(ROME2_VFS_REF_BLOCK_B_VTABLE32, 1u, &free_bytes) != ROME2_VFS_REG_OK ||
        free_bytes != 0x18u) {
        return 20;
    }
    if (rome2_vfs_ref_block_delete_size32(ROME2_VFS_REF_BLOCK_C_VTABLE32, 0u, &free_bytes) != ROME2_VFS_REG_OK ||
        free_bytes != 0u) {
        return 21;
    }
    free_bytes = 0xdeadbeefu;
    if (rome2_vfs_ref_block_delete_size32(0x11000000u, 1u, &free_bytes) != ROME2_VFS_REG_INVALID_STATE ||
        free_bytes != 0xdeadbeefu) {
        return 22;
    }
    return 0;
}

int main(void) {
    int rc = test_adj_hash_and_vec_plan();
    if (rc != 0) {
        fprintf(stderr, "test_adj_hash_and_vec_plan failed: %d\n", rc);
        return rc;
    }
    rc = test_wait_reentry_chain_and_dtors();
    if (rc != 0) {
        fprintf(stderr, "test_wait_reentry_chain_and_dtors failed: %d\n", rc);
        return rc;
    }
    printf("vfs_adj_open_ops_tests: 20 checks passed (0 failures)\n");
    return 0;
}
