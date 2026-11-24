#include "startup_remote_socket_net_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks = 0;
#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAILED at line %d: %s\n", __LINE__, #cond); \
        return 1; \
    } \
    g_checks++; \
} while (0)

int main(void) {
    /* 1. Layer 69 guest32 layout checks */
    rome2_startup_remote_socket_entry24_32 se24;
    rome2_startup_assert_dlg_hdr24_32 dh24;
    rome2_startup_fx_name_bucket20_32 fb20;
    CHECK(sizeof(se24) == 24u && sizeof(dh24) == 24u && sizeof(fb20) == 20u);

    /* 2. WS2_32 IAT thunks (ntohs / accept) & byte buffer / UTF-16 helpers */
    CHECK(rome2_l69_ws2_ntohs(0x3412u) == 0x1234u);
    memset(&se24, 0, sizeof(se24));
    se24.peer_words_04[0] = (0x3930u << 16u); /* htons(12345) = 0x3930 */
    se24.peer_words_04[1] = 0x7f000001u;
    uint32_t ip = 0u, port = 0u;
    rome2_l69_remote_endpoint_get(&se24, &ip, &port);
    CHECK(ip == 0x7f000001u && port == 12345u);

    rome2_l69_byte_buf bbuf = {NULL, 0u, 0u};
    const uint16_t u_ab[3] = {'A', 'B', 0};
    CHECK(rome2_l69_append_utf16_bytes(&bbuf, u_ab, 4u) == 4);
    CHECK(rome2_l69_buf_find_byte(&bbuf, 'B', 0u) == 2);
    CHECK(rome2_l69_buf_find_byte(&bbuf, 'Z', 0u) == -1);
    free(bbuf.data);

    uint16_t wout[32];
    CHECK(rome2_l69_wide_printf_format_value('X', 0x2au, wout, 32u) == 1);
    CHECK(wout[0] == '2' && wout[1] == 'A' && wout[2] == 0u);
    const uint16_t fmt[5] = {'a', '%', 'X', 'b', 0};
    uint16_t idx = 0u, spec = 0u;
    CHECK(rome2_l69_wide_format_spec_step(fmt, 4u, &idx, &spec) == 1 && spec == 'X' && idx == 3u);

    /* 3. Rolling hash + open-addressed FxName map + assert dialog */
    uint32_t slot = 99u;
    rome2_startup_fx_name_bucket20_32 htab[8];
    memset(htab, 0, sizeof(htab));
    CHECK(rome2_l69_fx_name_open_hash_insert(htab, 8u, "card32", 77u, &slot) == 1);
    CHECK(slot < 8u && htab[slot].value_10 == 77u);
    uint32_t slot2 = 99u;
    CHECK(rome2_l69_fx_name_open_hash_insert(htab, 8u, "card32", 88u, &slot2) == 1 && slot2 == slot && htab[slot].value_10 == 88u);

    /* 4. Remote socket poll -> direct_jmp_short -> remote assert dispatch + cleanup */
    rome2_l69_remote_socket_env *env = (rome2_l69_remote_socket_env *)calloc(
        1u, sizeof(rome2_l69_remote_socket_env));
    CHECK(env != NULL);
    static const uint8_t pkt_stream[] = {
        13u, 0u, 0u, 0u,
        'A', 's', 's', 'e', 'r', 't', '(', '9', '9', '9', ')', '\0', '\0'
    };
    env->accept_fd_next = 10u;
    env->peer_ip_be = 0x0a000001u;
    env->peer_port_be = 0x3930u;
    env->rx_stream = pkt_stream;
    env->rx_len = sizeof(pkt_stream);
    CHECK(rome2_l69_remote_socket_poll_and_dispatch(env) == 1);
    CHECK(env->socket_count == 1u && env->assert_count == 1u);
    CHECK(strstr(env->eh_log_msg, "REMOTE ASSERT from (name: Assert)") != NULL);
    CHECK(rome2_l69_assert_dialog_box_call(env, "Title", "Msg") == 1 && env->dlg_invoked == 1 && env->dlg_alt_mode == 1);

    /* 0x2800 packet overflow guard + WSAEWOULDBLOCK error paths */
    static const uint8_t big_hdr[4] = {0x00u, 0x28u, 0x00u, 0x00u};
    env->rx_stream = big_hdr;
    env->rx_len = sizeof(big_hdr);
    env->rx_pos = 0u;
    CHECK(rome2_l69_remote_socket_poll_and_dispatch(env) == 0 && env->packet_too_large_throws == 1);

    env->accept_fd_next = ROME2_L69_INVALID_SOCKET;
    env->last_wsa_error = 10054;
    CHECK(rome2_l69_remote_socket_accept(env) == ROME2_L69_INVALID_SOCKET && env->accept_throws == 1);

    rome2_l69_remote_socket_array_destroy(env, env->sockets, env->socket_count);
    CHECK(env->closed_socket_count == 2);
    free(env->asserts);
    free(env);

    printf("test_startup_remote_socket_net_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
