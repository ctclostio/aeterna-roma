#include <stdio.h>
#include <string.h>

#include "vfs_state_telemetry_ops.h"

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

static int test_decode_state_ref_block(void) {
    uint8_t mem[0x40];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x20000000u);
    rome2_guest_addr32 addr;
    rome2_vfs_state_ref_block28_32 blk;

    /* Check 1: valid 0x1189a474 / 0x118977bc and 0x118977e0 decode */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x00u, ROME2_VFS_REF_BLOCK1C_A474_VTABLE32);
    put_u32_le(mem + 0x04u, 3u);
    put_u32_le(mem + 0x08u, 1u);
    put_u32_le(mem + 0x0cu, ROME2_VFS_INNER_STATE_77BC_VTABLE32);
    put_u32_le(mem + 0x10u, 0x30001000u);
    put_u32_le(mem + 0x14u, 0x00024000u);
    mem[0x18u] = 1u;
    mem[0x19u] = 0u;
    mem[0x1au] = 0x5au;
    mem[0x1bu] = 0xa5u;
    addr.value = 0x20000000u;
    memset(&blk, 0, sizeof(blk));
    if (rome2_vfs_decode_state_ref_block28_32(&view, addr, &blk) != ROME2_VFS_STATE_TELEMETRY_OK ||
        blk.vtable != ROME2_VFS_REF_BLOCK1C_A474_VTABLE32 ||
        blk.use_count != 3u || blk.weak_count != 1u ||
        blk.inner_vtable != ROME2_VFS_INNER_STATE_77BC_VTABLE32 ||
        blk.view_box_ptr_010 != 0x30001000u || blk.size_014 != 0x00024000u ||
        blk.eof_or_closed_018 != 1u || blk.closed_019 != 0u ||
        blk.unobserved_01a[0] != 0x5au || blk.unobserved_01a[1] != 0xa5u) {
        return 1;
    }

    put_u32_le(mem + 0x0cu, ROME2_VFS_INNER_STATE_77E0_VTABLE32);
    if (rome2_vfs_decode_state_ref_block28_32(&view, addr, &blk) != ROME2_VFS_STATE_TELEMETRY_OK ||
        blk.inner_vtable != ROME2_VFS_INNER_STATE_77E0_VTABLE32) {
        return 1;
    }

    /* Check 2: bad outer/inner vtable preserves *out_block */
    put_u32_le(mem + 0x00u, 0xdeadbeefu);
    if (rome2_vfs_decode_state_ref_block28_32(&view, addr, &blk) != ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE ||
        blk.inner_vtable != ROME2_VFS_INNER_STATE_77E0_VTABLE32) {
        return 2;
    }
    put_u32_le(mem + 0x00u, ROME2_VFS_REF_BLOCK1C_A474_VTABLE32);
    put_u32_le(mem + 0x0cu, ROME2_VFS_INNER_STATE_77D4_VTABLE32);
    if (rome2_vfs_decode_state_ref_block28_32(&view, addr, &blk) != ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE ||
        blk.inner_vtable != ROME2_VFS_INNER_STATE_77E0_VTABLE32) {
        return 2;
    }

    /* Check 3: null arg and truncated view preserve *out_block */
    if (rome2_vfs_decode_state_ref_block28_32(NULL, addr, &blk) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT ||
        rome2_vfs_decode_state_ref_block28_32(&view, addr, NULL) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT) {
        return 3;
    }
    addr.value = 0x20000030u;
    if (rome2_vfs_decode_state_ref_block28_32(&view, addr, &blk) != ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL ||
        blk.use_count != 3u) {
        return 3;
    }
    return 0;
}

static int test_decode_listener_and_sys_info(void) {
    uint8_t mem[0x50];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x30000000u);
    rome2_guest_read_view tiny = make_view(mem, 12u, 0x30000000u);
    rome2_guest_addr32 addr;
    rome2_vfs_state_inner_listener28_32 st;
    rome2_vfs_sys_info32 info;

    /* Check 4: valid 0x118977c8 and 0x118977bc listener decode */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x00u, ROME2_VFS_INNER_STATE_77C8_VTABLE32);
    put_u32_le(mem + 0x04u, 0x40001000u);
    put_u32_le(mem + 0x08u, 0x12345u);
    mem[0x0cu] = 0u;
    mem[0x0du] = 1u;
    mem[0x0eu] = 2u;
    mem[0x0fu] = 3u;
    put_u32_le(mem + 0x10u, 0x40002000u);
    put_u32_le(mem + 0x14u, 0x40002010u);
    put_u32_le(mem + 0x18u, 0x99u);
    addr.value = 0x30000000u;
    memset(&st, 0, sizeof(st));
    if (rome2_vfs_decode_state_inner_listener28_32(&view, addr, &st) != ROME2_VFS_STATE_TELEMETRY_OK ||
        st.vtable != ROME2_VFS_INNER_STATE_77C8_VTABLE32 ||
        st.view_box_ptr_004 != 0x40001000u ||
        st.size_008 != 0x12345u ||
        st.closed_00d != 1u ||
        st.listener_head_010 != 0x40002000u ||
        st.listener_sentinel_014 != 0x40002010u ||
        st.unobserved_018 != 0x99u) {
        return 4;
    }

    put_u32_le(mem + 0x00u, ROME2_VFS_INNER_STATE_77BC_VTABLE32);
    if (rome2_vfs_decode_state_inner_listener28_32(&view, addr, &st) != ROME2_VFS_STATE_TELEMETRY_OK ||
        st.vtable != ROME2_VFS_INNER_STATE_77BC_VTABLE32) {
        return 4;
    }

    /* Check 5: bad vtable, null arg, short view preserve *out_state */
    put_u32_le(mem + 0x00u, ROME2_VFS_INNER_STATE_77E0_VTABLE32);
    if (rome2_vfs_decode_state_inner_listener28_32(&view, addr, &st) != ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE ||
        st.vtable != ROME2_VFS_INNER_STATE_77BC_VTABLE32 ||
        rome2_vfs_decode_state_inner_listener28_32(NULL, addr, &st) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT ||
        rome2_vfs_decode_state_inner_listener28_32(&tiny, addr, &st) != ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL ||
        st.size_008 != 0x12345u) {
        return 5;
    }

    /* Check 6: valid 36B SYSTEM_INFO decode */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x00u, 9u);
    put_u32_le(mem + 0x04u, 4096u);
    put_u32_le(mem + 0x18u, 8u); /* nNumberOfProcessors inside unobserved_008[4] */
    put_u32_le(mem + 0x1cu, 65536u);
    put_u32_le(mem + 0x20u, 0x06000001u);
    memset(&info, 0, sizeof(info));
    if (rome2_vfs_decode_sys_info32(&view, addr, &info) != ROME2_VFS_STATE_TELEMETRY_OK ||
        info.oem_id_000 != 9u || info.page_size_004 != 4096u ||
        info.unobserved_008[4] != 8u || info.allocation_granularity_01c != 65536u ||
        info.unobserved_020 != 0x06000001u) {
        return 6;
    }

    /* Check 7: zero / non-power-of-two granularity and short buffer preserve *out_info */
    put_u32_le(mem + 0x04u, 4097u);
    if (rome2_vfs_decode_sys_info32(&view, addr, &info) != ROME2_VFS_STATE_TELEMETRY_BAD_GRANULARITY ||
        info.page_size_004 != 4096u) {
        return 7;
    }
    put_u32_le(mem + 0x04u, 4096u);
    put_u32_le(mem + 0x1cu, 0u);
    if (rome2_vfs_decode_sys_info32(&view, addr, &info) != ROME2_VFS_STATE_TELEMETRY_BAD_GRANULARITY ||
        info.allocation_granularity_01c != 65536u ||
        rome2_vfs_decode_sys_info32(&tiny, addr, &info) != ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL) {
        return 7;
    }
    return 0;
}

static int test_dtor_plan_and_poll(void) {
    uint32_t free_bytes = 999u;
    rome2_vfs_state_d97f0_plan plan;
    int needs_spin = -1;
    uint32_t result_ptr = 999u;

    /* Check 8: inner dtor sizes with delete flag */
    if (rome2_vfs_state_inner_deleting_dtor_size32(ROME2_VFS_INNER_DTOR_112ACD90, 1u, &free_bytes) != ROME2_VFS_STATE_TELEMETRY_OK ||
        free_bytes != 0x10u ||
        rome2_vfs_state_inner_deleting_dtor_size32(ROME2_VFS_INNER_DTOR_112ACFE0, 3u, &free_bytes) != ROME2_VFS_STATE_TELEMETRY_OK ||
        free_bytes != 0x1cu ||
        rome2_vfs_state_inner_deleting_dtor_size32(ROME2_VFS_INNER_DTOR_112AD140, 1u, &free_bytes) != ROME2_VFS_STATE_TELEMETRY_OK ||
        free_bytes != 0x20u ||
        rome2_vfs_state_inner_deleting_dtor_size32(ROME2_VFS_INNER_DTOR_112AD140, 2u, &free_bytes) != ROME2_VFS_STATE_TELEMETRY_OK ||
        free_bytes != 0u) {
        return 8;
    }

    /* Check 9: unknown dtor VA and null ptr preserve *out_free_bytes */
    free_bytes = 77u;
    if (rome2_vfs_state_inner_deleting_dtor_size32(0x112ad000u, 1u, &free_bytes) != ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE ||
        free_bytes != 77u ||
        rome2_vfs_state_inner_deleting_dtor_size32(ROME2_VFS_INNER_DTOR_112ACD90, 1u, NULL) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT) {
        return 9;
    }

    /* Check 10: d97f0 uncompressed plan */
    memset(&plan, 0, sizeof(plan));
    if (rome2_vfs_state_d97f0_plan_complete32(0u, 0u, 0u, 0x50000000u, 0x1200u, &plan) != ROME2_VFS_STATE_TELEMETRY_OK ||
        plan.already_closed != 0 || plan.compressed != 0 ||
        plan.completion_target_va != ROME2_VFS_COMPLETE_UNCOMPRESSED_FN32 ||
        plan.src_addr != 0x50000000u || plan.src_end != 0x50001200u ||
        plan.size_bytes != 0x1200u || plan.next_eof_00c != 1u) {
        return 10;
    }

    /* Check 11: d97f0 compressed plan */
    if (rome2_vfs_state_d97f0_plan_complete32(0u, 0u, 0x05u, 0x50001000u, 0x800u, &plan) != ROME2_VFS_STATE_TELEMETRY_OK ||
        plan.already_closed != 0 || plan.compressed != 1 ||
        plan.completion_target_va != ROME2_VFS_COMPLETE_COMPRESSED_FN32 ||
        plan.src_end != 0x50001800u || plan.next_eof_00c != 1u) {
        return 11;
    }

    /* Check 12: d97f0 closed state skips dispatch */
    if (rome2_vfs_state_d97f0_plan_complete32(1u, 1u, 1u, 0x50001000u, 0x800u, &plan) != ROME2_VFS_STATE_TELEMETRY_OK ||
        plan.already_closed != 1 || plan.compressed != 1 ||
        plan.completion_target_va != 0u || plan.src_addr != 0u || plan.src_end != 0u ||
        plan.size_bytes != 0u || plan.next_eof_00c != 1u) {
        return 12;
    }

    /* Check 13: d97f0 32-bit overflow preserves *out_plan */
    if (rome2_vfs_state_d97f0_plan_complete32(0u, 0u, 0u, 0xfffffc00u, 0x500u, &plan) != ROME2_VFS_STATE_TELEMETRY_ARITHMETIC_OVERFLOW ||
        plan.already_closed != 1 ||
        rome2_vfs_state_d97f0_plan_complete32(0u, 0u, 0u, 0u, 0u, NULL) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT) {
        return 13;
    }

    /* Check 14: 0x112baf00 poll helper */
    if (rome2_vfs_state_baf00_poll_extra32(0u, 0u, 0x12345678u, &needs_spin, &result_ptr) != ROME2_VFS_STATE_TELEMETRY_OK ||
        needs_spin != 1 || result_ptr != 0x12345678u ||
        rome2_vfs_state_baf00_poll_extra32(1u, 0u, 0x12345678u, &needs_spin, &result_ptr) != ROME2_VFS_STATE_TELEMETRY_OK ||
        needs_spin != 0 || result_ptr != 0x12345678u ||
        rome2_vfs_state_baf00_poll_extra32(1u, 1u, 0x12345678u, &needs_spin, &result_ptr) != ROME2_VFS_STATE_TELEMETRY_OK ||
        needs_spin != 0 || result_ptr != 0u ||
        rome2_vfs_state_baf00_poll_extra32(0u, 0u, 0u, NULL, &result_ptr) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT ||
        rome2_vfs_state_baf00_poll_extra32(0u, 0u, 0u, &needs_spin, NULL) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT) {
        return 14;
    }
    return 0;
}

static int test_prefetch_and_telemetry_ids(void) {
    uint8_t pages[8192];
    uint8_t cancel = 0u;
    uint32_t acc = 0u;
    size_t steps = 99u;
    uint32_t free_ids[2] = {0u, 0u};
    size_t free_count = 0u;
    uint32_t next_id = 1u;
    uint32_t out_id = 0u;
    uint32_t max_id = UINT32_MAX;
    uint32_t active = 0u;
    uint32_t high = 2u;

    /* Check 15: stride-4096 LE accumulator + modulo 2^32 wrap */
    memset(pages, 0, sizeof(pages));
    put_u32_le(pages + 0u, 0x11223344u);
    put_u32_le(pages + 4096u, 0x01020304u);
    if (rome2_vfs_prefetch_pages_cancellable_sum32(pages, sizeof(pages), 5000u, 4096u, 0xffffffffu, &cancel, &acc, &steps) != ROME2_VFS_STATE_TELEMETRY_OK ||
        steps != 2u || acc != 0x12243647u) {
        return 15;
    }

    /* Check 16: zero-length prefetch succeeds without touching buf */
    if (rome2_vfs_prefetch_pages_cancellable_sum32(NULL, 0u, 0u, 4096u, 0xabcdef01u, NULL, &acc, &steps) != ROME2_VFS_STATE_TELEMETRY_OK ||
        steps != 0u || acc != 0xabcdef01u) {
        return 16;
    }

    /* Check 17: cancel flag, invalid stride, and short tail bounds preserve outputs */
    cancel = 1u;
    acc = 777u;
    steps = 88u;
    if (rome2_vfs_prefetch_pages_cancellable_sum32(pages, sizeof(pages), 5000u, 4096u, 0x10u, &cancel, &acc, &steps) != ROME2_VFS_STATE_TELEMETRY_OK ||
        steps != 0u || acc != 0x10u) {
        return 17;
    }
    cancel = 0u;
    if (rome2_vfs_prefetch_pages_cancellable_sum32(pages, sizeof(pages), 5000u, 3000u, 1u, &cancel, &acc, &steps) != ROME2_VFS_STATE_TELEMETRY_BAD_GRANULARITY ||
        acc != 0x10u ||
        rome2_vfs_prefetch_pages_cancellable_sum32(pages, 4098u, 4098u, 4096u, 1u, &cancel, &acc, &steps) != ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL ||
        acc != 0x10u || steps != 0u) {
        return 17;
    }

    /* Check 18-19: telemetry acquire ID LIFO + next_id + overflow/null guards */
    if (rome2_vfs_telemetry_acquire_id32(free_ids, &free_count, &next_id, &out_id) != ROME2_VFS_STATE_TELEMETRY_OK ||
        out_id != 1u || next_id != 2u ||
        rome2_vfs_telemetry_release_id32(free_ids, &free_count, 2u, 1u) != ROME2_VFS_STATE_TELEMETRY_OK ||
        free_count != 1u ||
        rome2_vfs_telemetry_acquire_id32(free_ids, &free_count, &next_id, &out_id) != ROME2_VFS_STATE_TELEMETRY_OK ||
        out_id != 1u || free_count != 0u || next_id != 2u ||
        rome2_vfs_telemetry_acquire_id32(NULL, &free_count, &next_id, &out_id) != ROME2_VFS_STATE_TELEMETRY_OK ||
        out_id != 2u || next_id != 3u) {
        return 18;
    }
    if (rome2_vfs_telemetry_acquire_id32(free_ids, &free_count, &max_id, &out_id) != ROME2_VFS_STATE_TELEMETRY_ARITHMETIC_OVERFLOW ||
        max_id != UINT32_MAX) {
        return 18;
    }
    free_count = 1u;
    if (rome2_vfs_telemetry_acquire_id32(NULL, &free_count, &next_id, &out_id) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT ||
        free_count != 1u ||
        rome2_vfs_telemetry_acquire_id32(free_ids, NULL, &next_id, &out_id) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT) {
        return 19;
    }

    /* Check 20: release stack capacity guard */
    free_count = 1u;
    if (rome2_vfs_telemetry_release_id32(free_ids, &free_count, 2u, 9u) != ROME2_VFS_STATE_TELEMETRY_OK ||
        free_count != 2u || free_ids[1] != 9u ||
        rome2_vfs_telemetry_release_id32(free_ids, &free_count, 2u, 10u) != ROME2_VFS_STATE_TELEMETRY_CAPACITY_EXCEEDED ||
        free_count != 2u ||
        rome2_vfs_telemetry_release_id32(NULL, &free_count, 2u, 10u) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT) {
        return 20;
    }

    /* Check 21: async view high-water mark */
    if (rome2_vfs_async_view_high_water32(&active, &high) != ROME2_VFS_STATE_TELEMETRY_OK ||
        active != 1u || high != 2u ||
        rome2_vfs_async_view_high_water32(&active, &high) != ROME2_VFS_STATE_TELEMETRY_OK ||
        active != 2u || high != 2u ||
        rome2_vfs_async_view_high_water32(&active, &high) != ROME2_VFS_STATE_TELEMETRY_OK ||
        active != 3u || high != 3u ||
        rome2_vfs_async_view_high_water32(&max_id, &high) != ROME2_VFS_STATE_TELEMETRY_ARITHMETIC_OVERFLOW ||
        max_id != UINT32_MAX ||
        rome2_vfs_async_view_high_water32(NULL, &high) != ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT) {
        return 21;
    }
    return 0;
}

int main(void) {
    int rc;

    rc = test_decode_state_ref_block();
    if (rc != 0) {
        fprintf(stderr, "test_decode_state_ref_block failed: %d\n", rc);
        return rc;
    }
    rc = test_decode_listener_and_sys_info();
    if (rc != 0) {
        fprintf(stderr, "test_decode_listener_and_sys_info failed: %d\n", rc);
        return rc;
    }
    rc = test_dtor_plan_and_poll();
    if (rc != 0) {
        fprintf(stderr, "test_dtor_plan_and_poll failed: %d\n", rc);
        return rc;
    }
    rc = test_prefetch_and_telemetry_ids();
    if (rc != 0) {
        fprintf(stderr, "test_prefetch_and_telemetry_ids failed: %d\n", rc);
        return rc;
    }
    printf("vfs_state_telemetry_ops_tests: 21 checks passed (0 failures)\n");
    return 0;
}
