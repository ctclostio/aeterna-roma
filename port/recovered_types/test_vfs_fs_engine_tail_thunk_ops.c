#include <stdio.h>
#include <string.h>

#include "vfs_fs_engine_tail_thunk_ops.h"

static unsigned int g_checks = 0u;

#define CHECK(cond)                                                               \
    do {                                                                          \
        if (!(cond)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
            return 1;                                                             \
        }                                                                         \
        g_checks++;                                                               \
    } while (0)

typedef struct test_free_log {
    uint32_t calls;
    uint32_t last_ptr;
} test_free_log;

static void record_free_cb(uint32_t ptr_va, void *ctx) {
    test_free_log *log = (test_free_log *)ctx;
    log->calls += 1u;
    log->last_ptr = ptr_va;
}

static int test_free_thunk_and_wstr_cmp(void) {
    test_free_log flog = { 0u, 0u };
    const uint16_t hello[] = { 'a', 'b', 'c' };
    const uint16_t abc0[] = { 'a', 'b', 'c', 0u };
    const uint16_t abcd0[] = { 'a', 'b', 'c', 'd', 0u };
    const uint16_t a0c0[] = { 'a', 0u, 'c', 0u };
    const uint16_t empty0[] = { 0u };
    const uint16_t custom_sent[] = { 'a', 'b', '!', 0u };

    CHECK(rome2_vfs_tail_free_thunk_100d12c0(0x20001000u, record_free_cb, &flog) == 1u);
    CHECK(flog.calls == 1u && flog.last_ptr == 0x20001000u);
    CHECK(rome2_vfs_tail_free_thunk_100d12c0(0u, record_free_cb, &flog) == 1u);
    CHECK(flog.calls == 2u && flog.last_ptr == 0u);
    CHECK(rome2_vfs_tail_free_thunk_100d12c0(0x1234u, NULL, NULL) == 0u);

    CHECK(rome2_vfs_utf16_str_ne_cstr_100f2a70(hello, 3u, abc0, 8u, 0u) == 0u);
    CHECK(rome2_vfs_utf16_str_ne_cstr_100f2a70(hello, 3u, abcd0, 8u, 0u) == 1u);
    CHECK(rome2_vfs_utf16_str_ne_cstr_100f2a70(a0c0, 3u, a0c0, 8u, 0u) == 1u);
    CHECK(rome2_vfs_utf16_str_ne_cstr_100f2a70(NULL, 0u, empty0, 4u, 0u) == 0u);
    CHECK(rome2_vfs_utf16_str_ne_cstr_100f2a70(hello, 2u, custom_sent, 8u, (uint16_t)'!') == 0u);
    CHECK(rome2_vfs_utf16_str_ne_cstr_100f2a70(hello, 3u, NULL, 4u, 0u) == 1u);
    CHECK(rome2_vfs_utf16_str_ne_cstr_100f2a70(hello, 3u, abc0, 3u, 0u) == 1u);
    return 0;
}

static int test_vec12_push_and_signed_bits(void) {
    rome2_vfs_elem12_vec12_32 vec = { 0u, 0u, 0u };
    rome2_vfs_elem12_push_plan plan;
    uint8_t buf[16];
    uint32_t bit_cur = 0u;
    uint32_t bits_written = 99u;

    CHECK(rome2_vfs_elem12_vec_push_plan_1011fc50(&vec, 0x30001000u, 0u, &plan) == ROME2_VFS_REG_INVALID_STATE);
    CHECK(vec.cap_08 == 0u && vec.count_04 == 0u);
    CHECK(rome2_vfs_elem12_vec_push_plan_1011fc50(&vec, 0x30001000u, 1u, &plan) == ROME2_VFS_REG_OK);
    CHECK(plan.did_grow == 1u && plan.new_cap == 8u && plan.alloc_bytes == 96u);
    CHECK(plan.old_data_va == 0u && plan.move_count == 0u && plan.append_dst_va == 0x30001000u);
    CHECK(vec.count_04 == 1u && vec.cap_08 == 8u);

    CHECK(rome2_vfs_elem12_vec_push_plan_1011fc50(&vec, 0u, 1u, &plan) == ROME2_VFS_REG_OK);
    CHECK(plan.did_grow == 0u && plan.append_dst_va == 0x3000100cu && vec.count_04 == 2u);

    vec.count_04 = 8u;
    CHECK(rome2_vfs_elem12_vec_push_plan_1011fc50(&vec, 0x30002000u, 1u, &plan) == ROME2_VFS_REG_OK);
    CHECK(plan.did_grow == 1u && plan.new_cap == 16u && plan.alloc_bytes == 192u);
    CHECK(plan.old_data_va == 0x30001000u && plan.move_count == 8u && plan.append_dst_va == 0x30002060u);

    vec.cap_08 = 0x10000000u;
    vec.count_04 = 0x10000000u;
    CHECK(rome2_vfs_elem12_vec_push_plan_1011fc50(&vec, 0x40000000u, 1u, &plan) == ROME2_VFS_REG_RANGE_ERROR);

    memset(buf, 0, sizeof(buf));
    CHECK(rome2_vfs_write_signed_ranged_bits_10f71f70(buf, sizeof(buf), &bit_cur, -11, -10, 10, &bits_written) == ROME2_VFS_REG_OK);
    CHECK(bits_written == 0u && bit_cur == 0u);
    CHECK(rome2_vfs_write_signed_ranged_bits_10f71f70(buf, sizeof(buf), &bit_cur, 11, -10, 10, &bits_written) == ROME2_VFS_REG_OK);
    CHECK(bits_written == 0u && bit_cur == 0u);
    CHECK(rome2_vfs_write_signed_ranged_bits_10f71f70(buf, sizeof(buf), &bit_cur, 0, -10, 10, &bits_written) == ROME2_VFS_REG_OK);
    CHECK(bits_written == 5u && bit_cur == 5u);
    return 0;
}

static int test_channel_dtors(void) {
    rome2_vfs_l57_channel_graph g;
    rome2_vfs_l57_derived_channel_state dstate;

    memset(&g, 0, sizeof(g));
    g.channel_count = 3u;
    for (uint32_t i = 0u; i < 3u; ++i) {
        g.channels[i].head_idx = ROME2_VFS_L57_INVALID_INDEX;
        g.channels[i].tail_idx = ROME2_VFS_L57_INVALID_INDEX;
    }
    /* Channel 0: [peer=1, peer=1 (dup), peer=2]; Channel 1: [peer=0]; Channel 2: empty */
    g.node_count = 4u;
    g.channels[0].head_idx = 0u;
    g.channels[0].tail_idx = 2u;
    g.nodes[0] = (rome2_vfs_l57_peer_node){ ROME2_VFS_L57_INVALID_INDEX, 1u, 1u, 1u };
    g.nodes[1] = (rome2_vfs_l57_peer_node){ 0u, 2u, 1u, 1u };
    g.nodes[2] = (rome2_vfs_l57_peer_node){ 1u, ROME2_VFS_L57_INVALID_INDEX, 2u, 1u };

    g.channels[1].head_idx = 3u;
    g.channels[1].tail_idx = 3u;
    g.nodes[3] = (rome2_vfs_l57_peer_node){ ROME2_VFS_L57_INVALID_INDEX, ROME2_VFS_L57_INVALID_INDEX, 0u, 1u };

    memset(&dstate, 0, sizeof(dstate));
    dstate.aux_owner_ptr_4048 = 0x50001000u;
    dstate.aux_owner_link_04 = 0x1111u;
    dstate.queue_406c_len = 3u;
    dstate.queue_4054_len = 5u;
    dstate.active_24 = 1u;
    dstate.sock_fd_10 = 42u;

    CHECK(rome2_vfs_channel_derived_dtor_10f69830(&g, 0u, &dstate) == ROME2_VFS_REG_OK);
    CHECK(g.channels[0].vtable_va == ROME2_VFS_L57_CH_BASE_VTABLE_VA);
    CHECK(g.channels[0].head_idx == ROME2_VFS_L57_INVALID_INDEX);
    CHECK(g.channels[1].head_idx == ROME2_VFS_L57_INVALID_INDEX);
    CHECK(g.freed_node_count == 4u);
    CHECK(dstate.did_reset_slots == 1u && dstate.aux_owner_ptr_4048 == 0u && dstate.aux_owner_link_04 == 0u);
    CHECK(dstate.queue_nodes_freed == 8u && dstate.did_close_socket == 1u && dstate.closed_sock_fd == 42u);

    /* Inactive derived channel should not close socket even if fd != -1 */
    memset(&dstate, 0, sizeof(dstate));
    dstate.active_24 = 0u;
    dstate.sock_fd_10 = 99u;
    CHECK(rome2_vfs_channel_derived_dtor_10f69830(&g, 2u, &dstate) == ROME2_VFS_REG_OK);
    CHECK(dstate.did_close_socket == 0u && dstate.sock_fd_10 == 99u);
    return 0;
}

static int test_hash_pack_and_folder_dtors(void) {
    rome2_vfs_l57_hash_dtor_stats hstats;
    rome2_vfs_l57_pack_entry_slot pslots[3] = {
        { 0u, 0u },
        { 1u, 101u },
        { 2u, 102u },
    };
    rome2_vfs_l57_pack_map_dtor_stats pstats;
    rome2_vfs_l57_folder_node_model nodes[3];
    rome2_vfs_l57_folder_dtor_stats fstats;

    memset(nodes, 0, sizeof(nodes));
    for (uint32_t i = 0u; i < 3u; ++i) {
        nodes[i].subdirs_empty_key[0] = 'e';
        nodes[i].subdirs_empty_len = 1u;
        nodes[i].subdirs_deleted_key[0] = 'd';
        nodes[i].subdirs_deleted_len = 1u;
        nodes[i].files_empty_key[0] = 'e';
        nodes[i].files_empty_len = 1u;
        nodes[i].files_deleted_key[0] = 'd';
        nodes[i].files_deleted_len = 1u;
    }

    nodes[0].raw.subdirs_map_20.data_00 = 0x60001000u;
    nodes[0].raw.subdirs_map_20.cap_04 = 5u;
    nodes[0].raw.files_map_44.data_00 = 0x60002000u;
    nodes[0].raw.files_map_44.cap_04 = 2u;
    nodes[0].raw.aux_buf_70 = 0x60003000u;
    nodes[0].raw.tuples_base_74 = 0x60004000u;
    nodes[0].raw.tuples_count_78 = 3u;
    nodes[0].subdir_slot_count = 5u;
    /* Slot 0: empty sentinel */
    nodes[0].subdirs[0].key[0] = 'e';
    nodes[0].subdirs[0].key_len = 1u;
    nodes[0].subdirs[0].has_vec = 1u;
    nodes[0].subdirs[0].child_count = 1u;
    nodes[0].subdirs[0].child_indices[0] = 99u;
    /* Slot 1: unused_key skipped even if has_vec */
    memcpy(nodes[0].subdirs[1].key, (const uint16_t[]){ 'u','n','u','s','e','d','_','k','e','y' }, 20u);
    nodes[0].subdirs[1].key_len = 10u;
    nodes[0].subdirs[1].has_vec = 1u;
    nodes[0].subdirs[1].child_count = 1u;
    nodes[0].subdirs[1].child_indices[0] = 99u;
    /* Slot 2: removed_key skipped */
    memcpy(nodes[0].subdirs[2].key, (const uint16_t[]){ 'r','e','m','o','v','e','d','_','k','e','y' }, 22u);
    nodes[0].subdirs[2].key_len = 11u;
    nodes[0].subdirs[2].has_vec = 1u;
    /* Slot 3: valid child dir -> node 1 & NULL slot */
    nodes[0].subdirs[3].key[0] = 'd';
    nodes[0].subdirs[3].key[1] = 'a';
    nodes[0].subdirs[3].key_len = 2u;
    nodes[0].subdirs[3].has_vec = 1u;
    nodes[0].subdirs[3].child_count = 2u;
    nodes[0].subdirs[3].child_indices[0] = 1u;
    nodes[0].subdirs[3].child_indices[1] = ROME2_VFS_L57_INVALID_INDEX;
    /* Slot 4: valid leaf -> node 2 */
    nodes[0].subdirs[4].key[0] = 'x';
    nodes[0].subdirs[4].key_len = 1u;
    nodes[0].subdirs[4].has_vec = 1u;
    nodes[0].subdirs[4].child_count = 1u;
    nodes[0].subdirs[4].child_indices[0] = 2u;

    nodes[0].files_slot_count = 2u;
    nodes[0].files[0].key[0] = 'e';
    nodes[0].files[0].key_len = 1u;
    nodes[0].files[0].val0_live = 1u;
    nodes[0].files[1].key[0] = 'f';
    nodes[0].files[1].key_len = 1u;
    nodes[0].files[1].val0_live = 1u;
    nodes[0].files[1].val1_live = 1u;
    nodes[0].files[1].val2_live = 1u;

    CHECK(rome2_vfs_hash48_table_dtor_112ab150(
              &nodes[1].raw.files_map_44, nodes[0].files, 2u,
              nodes[0].files_empty_key, 1u, nodes[0].files_deleted_key, 1u, &hstats) == ROME2_VFS_REG_OK);
    CHECK(hstats.keys_destroyed == 2u && hstats.values_destroyed == 3u && hstats.sentinels_destroyed == 2u);

    CHECK(rome2_vfs_pack_entry_map_dtor_112ab6b0(0u, pslots, 3u, &pstats) == ROME2_VFS_REG_OK);
    CHECK(pstats.virtual_dtor_calls == 2u && pstats.pool_freelist_pushes == 2u);
    CHECK(pstats.path_str_destroyed == 1u && pstats.array_teardown_called == 1u);

    CHECK(rome2_vfs_folder_node_dtor_112ab8b0(nodes, 3u, 0u, &fstats) == ROME2_VFS_REG_OK);
    CHECK(fstats.nodes_destroyed == 3u && fstats.child_nodes_freed80 == 2u);
    CHECK(fstats.child_vec_arrays_freed == 2u && fstats.child_vec_headers_freed12 == 2u);
    CHECK(fstats.tuple_arrays_torndown == 1u && fstats.aux_buffers_freed == 1u);
    CHECK(fstats.files_tables_torndown == 3u && fstats.subdirs_tables_torndown == 3u);

    /* Cycle detection fail-closed check */
    nodes[1].subdir_slot_count = 1u;
    nodes[1].subdirs[0].key[0] = 'c';
    nodes[1].subdirs[0].key_len = 1u;
    nodes[1].subdirs[0].has_vec = 1u;
    nodes[1].subdirs[0].child_count = 1u;
    nodes[1].subdirs[0].child_indices[0] = 0u;
    CHECK(rome2_vfs_folder_node_dtor_112ab8b0(nodes, 3u, 0u, &fstats) == ROME2_VFS_REG_RANGE_ERROR);
    return 0;
}

static int test_crt_alloca_state_size_malloc_and_iat(void) {
    uint32_t aligned = 0u;
    uint32_t pages = 0u;
    uint32_t target = 0u;
    rome2_vfs_crt_wprintf_state64_32 st;
    uint32_t off = 0u;
    int32_t err = 0;
    uint8_t inv = 0u;
    uint8_t deleg = 0u;
    const uint16_t u_h[] = { 'h' };
    const uint16_t u_l[] = { 'l' };
    const uint16_t u_32[] = { '3', '2' };
    const uint16_t u_64[] = { '6', '4' };
    const uint16_t u_d[] = { 'd' };
    uint32_t malloc_bytes = 0u;
    rome2_vfs_iat_thunk_desc idesc;
    rome2_vfs_ws2_mock_socket sock;
    uint8_t io_buf[8];
    uint32_t arg = 1u;

    target = rome2_vfs_crt_alloca_probe_16_11684240(0x0019ff08u, 0x100u, &aligned, &pages);
    CHECK(aligned == 0x108u && (target & 0x0fu) == 0u && target == (0x0019ff08u - 0x108u));
    (void)rome2_vfs_crt_alloca_probe_16_11684240(0x0019ff08u, 0xfffffffcu, &aligned, &pages);
    CHECK(aligned == 0xffffffffu);

    memset(&st, 0, sizeof(st));
    st.cur_ch_32 = (uint16_t)'F';
    CHECK(rome2_vfs_crt_wprintf_state_case_size_1168a23e(&st, NULL, 0u, &off, &err, &inv, &deleg) == 1u);
    CHECK(st.fsm_state_1c == 7u && deleg == 1u && inv == 0u);

    st.cur_ch_32 = (uint16_t)'N';
    CHECK(rome2_vfs_crt_wprintf_state_case_size_1168a23e(&st, NULL, 0u, &off, &err, &inv, &deleg) == 0u);
    CHECK(st.fsm_state_1c == 8u && err == ROME2_VFS_L57_EINVAL_MSVC && inv == 1u);

    memset(&st, 0, sizeof(st));
    st.cur_ch_32 = (uint16_t)'h';
    CHECK(rome2_vfs_crt_wprintf_state_case_size_1168a23e(&st, u_h, 1u, &off, &err, &inv, &deleg) == 1u);
    CHECK(st.length_mod_2c == 1u && off == 1u && st.fmt_ptr_10 == 2u);
    /* Duplicate length modifier fails EINVAL */
    CHECK(rome2_vfs_crt_wprintf_state_case_size_1168a23e(&st, u_l, 1u, &off, &err, &inv, &deleg) == 0u);
    CHECK(err == ROME2_VFS_L57_EINVAL_MSVC && inv == 1u);

    st.length_mod_2c = 0u; st.cur_ch_32 = (uint16_t)'I'; off = 0u;
    CHECK(rome2_vfs_crt_wprintf_state_case_size_1168a23e(&st, u_32, 2u, &off, &err, &inv, &deleg) == 1u);
    CHECK(st.length_mod_2c == 10u && off == 2u);
    st.length_mod_2c = 0u; st.cur_ch_32 = (uint16_t)'I'; off = 0u;
    CHECK(rome2_vfs_crt_wprintf_state_case_size_1168a23e(&st, u_64, 2u, &off, &err, &inv, &deleg) == 1u);
    CHECK(st.length_mod_2c == 11u && off == 2u);
    st.length_mod_2c = 0u; st.cur_ch_32 = (uint16_t)'I'; off = 0u;
    CHECK(rome2_vfs_crt_wprintf_state_case_size_1168a23e(&st, u_d, 1u, &off, &err, &inv, &deleg) == 1u);
    CHECK(st.length_mod_2c == 9u && off == 0u);

    err = 0;
    CHECK(rome2_vfs_crt_malloc_thunk_1168d0c3(0u, &malloc_bytes, &err) == 1u && malloc_bytes == 1u && err == 0);
    CHECK(rome2_vfs_crt_malloc_thunk_1168d0c3(0xffffffe1u, &malloc_bytes, &err) == 0u && err == 12);

    CHECK(rome2_vfs_iat_thunk_describe(0x100f3880u, &idesc) == 1u && idesc.iat_slot_va == 0x1172f1d8u);
    CHECK(rome2_vfs_iat_thunk_describe(0x116c80d7u, &idesc) == 1u && idesc.iat_slot_va == 0x1172f820u && idesc.stack_bytes == 4u);
    CHECK(rome2_vfs_iat_thunk_describe(0xdeadbeefu, &idesc) == 0u);
    CHECK(rome2_vfs_win32_get_last_error_100f3880(5u) == 5u);
    CHECK(rome2_vfs_win32_get_tick_count_100f3890(12345u) == 12345u);
    CHECK(rome2_vfs_ws2_htons_116c80d7(0x1234u) == 0x3412u);

    CHECK(rome2_vfs_ws2_socket_116c810d(&sock, 2, 1, 6, 77u) == 77u);
    CHECK(rome2_vfs_ws2_ioctlsocket_116c80d1(&sock, 0x8004667eu, &arg) == 0 && sock.nonblocking == 1u);
    CHECK(rome2_vfs_ws2_recv_116c80ef(&sock, io_buf, 4u, 0u) == -1 && rome2_vfs_ws2_get_last_error_116c8125(&sock) == ROME2_VFS_L38_WSAEWOULDBLOCK);
    CHECK(rome2_vfs_ws2_send_116c80fb(&sock, (const uint8_t *)"ping", 4u, 0u) == 4 && sock.tx_len == 4u);
    memcpy(sock.rx_buf, "ok", 2u);
    sock.rx_len = 2u;
    CHECK(rome2_vfs_ws2_recv_116c80ef(&sock, io_buf, 4u, 0u) == 2 && memcmp(io_buf, "ok", 2u) == 0);
    CHECK(rome2_vfs_ws2_closesocket_116c80c5(&sock) == 0 && sock.open == 0u);
    return 0;
}

int main(void) {
    if (test_free_thunk_and_wstr_cmp() != 0 ||
        test_vec12_push_and_signed_bits() != 0 ||
        test_channel_dtors() != 0 ||
        test_hash_pack_and_folder_dtors() != 0 ||
        test_crt_alloca_state_size_malloc_and_iat() != 0) {
        return 1;
    }
    printf("test_vfs_fs_engine_tail_thunk_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
