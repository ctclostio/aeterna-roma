#ifndef ROME2_STARTUP_REMOTE_SOCKET_NET_OPS_H
#define ROME2_STARTUP_REMOTE_SOCKET_NET_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_video_device_cfg_ops.h"

/*
 * Layer 69 Partition 8 recovery:
 * 23 remote-assert socket / WS2_32 IAT thunk / assert DLGTEMPLATEW /
 * wide format & radix conversion / FxName rolling-hash map functions (0x100eeb50..0x116c80e9).
 */

#define ROME2_L69_INVALID_SOCKET 0xffffffffu
#define ROME2_L69_WSAEWOULDBLOCK 0x2733
#define ROME2_L69_MAX_REMOTE_PACKET 0x2800u

typedef struct rome2_l69_assert_entry12 {
    uint32_t code;
    uint32_t ip_addr;
    uint32_t tag;
} rome2_l69_assert_entry12;

typedef struct rome2_l69_byte_buf {
    uint8_t *data;
    uint32_t len;
    uint32_t cap;
} rome2_l69_byte_buf;

typedef struct rome2_l69_remote_socket_env {
    uint32_t accept_fd_next;
    int32_t last_wsa_error;
    int accept_throws;
    int recv_throws;
    int packet_too_large_throws;
    int closed_socket_count;
    const uint8_t *rx_stream;
    size_t rx_len;
    size_t rx_pos;
    uint32_t peer_ip_be;
    uint16_t peer_port_be;
    rome2_startup_remote_socket_entry24_32 *sockets;
    uint32_t socket_count;
    uint32_t socket_cap;
    rome2_l69_assert_entry12 *asserts;
    uint32_t assert_count;
    uint32_t assert_cap;
    char remote_assert_banner[160];
    int dlg_alt_mode;
    int dlg_invoked;
    char eh_log_msg[128];
} rome2_l69_remote_socket_env;

/* 0x116c80e9 (WS2_32!ntohs IAT thunk) & 0x10100e20 */
uint16_t rome2_l69_ws2_ntohs(uint16_t netshort);
void rome2_l69_remote_endpoint_get(
    const rome2_startup_remote_socket_entry24_32 *entry, uint32_t *out_ip, uint32_t *out_port);

/* 0x116c80b9 (WS2_32!accept IAT thunk) & 0x100f3b40 */
uint32_t rome2_l69_ws2_accept(rome2_l69_remote_socket_env *env);
uint32_t rome2_l69_remote_socket_accept(rome2_l69_remote_socket_env *env);

/* 0x10113510 */
int rome2_l69_remote_socket_recv(rome2_l69_remote_socket_env *env, uint8_t *dst, int len);

/* 0x10cba480 / 0x10cbae00 / 0x10924df0 */
void rome2_l69_remote_socket_array_destroy(
    rome2_l69_remote_socket_env *env, rome2_startup_remote_socket_entry24_32 *arr, uint32_t count);
int rome2_l69_remote_socket_push_back(
    rome2_l69_remote_socket_env *env, rome2_startup_remote_socket_entry24_32 *elem);
int rome2_l69_assert_entry_push_back(
    rome2_l69_remote_socket_env *env, const rome2_l69_assert_entry12 *elem);

/* 0x100ffa10 / 0x10106230 / 0x10115e10 */
int rome2_l69_buf_find_byte(const rome2_l69_byte_buf *buf, uint8_t ch, uint32_t start);
int rome2_l69_byte_buf_grow(rome2_l69_byte_buf *buf, const uint8_t *seed, uint32_t add_len);
int rome2_l69_append_utf16_bytes(rome2_l69_byte_buf *buf, const uint16_t *src, uint32_t hint);

/* 0x100f1bf0 / 0x10100700 / 0x100f5630 / 0x100eeb50 */
size_t rome2_l69_wstr_assign_raw_len(
    uint16_t *dst, size_t dst_cap, const uint16_t *src, size_t wchar_count);
size_t rome2_l69_u32_format_radix_wstr(
    uint32_t val, uint32_t radix, const uint16_t *digits, uint16_t *out_w, size_t out_cap);
int rome2_l69_wide_printf_format_value(
    uint16_t spec, uint32_t val, uint16_t *out_w, size_t out_cap);
int rome2_l69_wide_format_spec_step(
    const uint16_t *fmt, size_t fmt_len, uint16_t *idx, uint16_t *out_spec);

/* 0x10cba4c0 / 0x10c93c00 / 0x100f6220 / 0x10101e30 */
int rome2_l69_parse_remote_assert_packet(
    const char *pkt, char *out_name, size_t name_cap, uint32_t *out_ip);
void rome2_l69_assert_eh_forward_log(
    rome2_l69_remote_socket_env *env, const char *name, uint32_t ip);
int rome2_l69_assert_dialog_show(
    rome2_l69_remote_socket_env *env, const char *title, const char *msg, uint8_t alt,
    rome2_startup_assert_dlg_hdr24_32 *out_hdr);
int rome2_l69_assert_dialog_box_call(
    rome2_l69_remote_socket_env *env, const char *title, const char *msg);

/* 0x11370160 / 0x10cbaf70 */
uint32_t rome2_l69_fx_name_rolling_hash(const uint8_t *data, size_t len);
int rome2_l69_fx_name_open_hash_insert(
    rome2_startup_fx_name_bucket20_32 *buckets, uint32_t bucket_count,
    const char *key, uint32_t value, uint32_t *out_slot);

/* 0x10cba590 -> direct_jmp_short -> 0x10cba7a0 */
int rome2_l69_remote_assert_dispatch_cont(
    rome2_l69_remote_socket_env *env, const char *pkt, uint32_t ip, uint16_t port);
int rome2_l69_remote_socket_poll_and_dispatch(rome2_l69_remote_socket_env *env);

#endif
