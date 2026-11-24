#include "startup_remote_socket_net_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint16_t rome2_l69_ws2_ntohs(uint16_t netshort) {
    return (uint16_t)(((netshort & 0xffu) << 8u) | ((netshort >> 8u) & 0xffu));
}

void rome2_l69_remote_endpoint_get(
    const rome2_startup_remote_socket_entry24_32 *entry, uint32_t *out_ip, uint32_t *out_port) {
    if (entry == NULL) {
        return;
    }
    if (out_ip != NULL) {
        *out_ip = entry->peer_words_04[1];
    }
    if (out_port != NULL) {
        *out_port = (uint32_t)rome2_l69_ws2_ntohs((uint16_t)(entry->peer_words_04[0] >> 16u));
    }
}

uint32_t rome2_l69_ws2_accept(rome2_l69_remote_socket_env *env) {
    if (env == NULL || env->accept_fd_next == 0u || env->accept_fd_next == ROME2_L69_INVALID_SOCKET) {
        return ROME2_L69_INVALID_SOCKET;
    }
    return env->accept_fd_next++;
}

uint32_t rome2_l69_remote_socket_accept(rome2_l69_remote_socket_env *env) {
    uint32_t s = rome2_l69_ws2_accept(env);
    if (env == NULL) {
        return ROME2_L69_INVALID_SOCKET;
    }
    if (s == ROME2_L69_INVALID_SOCKET && env->last_wsa_error != ROME2_L69_WSAEWOULDBLOCK) {
        env->accept_throws++;
    }
    return s;
}

int rome2_l69_remote_socket_recv(rome2_l69_remote_socket_env *env, uint8_t *dst, int len) {
    int total = 0;

    if (env == NULL || dst == NULL || len <= 0) {
        return 0;
    }
    while (total < len) {
        if (env->rx_stream == NULL || env->rx_pos >= env->rx_len) {
            if (env->last_wsa_error != 0 && env->last_wsa_error != ROME2_L69_WSAEWOULDBLOCK) {
                env->recv_throws++;
            }
            return total;
        }
        size_t avail = env->rx_len - env->rx_pos;
        size_t chunk = ((size_t)(len - total) < avail) ? (size_t)(len - total) : avail;
        memcpy(dst + total, env->rx_stream + env->rx_pos, chunk);
        env->rx_pos += chunk;
        total += (int)chunk;
    }
    return total;
}

void rome2_l69_remote_socket_array_destroy(
    rome2_l69_remote_socket_env *env, rome2_startup_remote_socket_entry24_32 *arr, uint32_t count) {
    uint32_t i;

    if (arr == NULL) {
        return;
    }
    for (i = 0u; i < count; ++i) {
        if (arr[i].active_14 != 0u && arr[i].sock_fd_00 != ROME2_L69_INVALID_SOCKET) {
            if (env != NULL) {
                env->closed_socket_count++;
            }
            arr[i].sock_fd_00 = ROME2_L69_INVALID_SOCKET;
            arr[i].active_14 = 0u;
        }
    }
    free(arr);
}

int rome2_l69_remote_socket_push_back(
    rome2_l69_remote_socket_env *env, rome2_startup_remote_socket_entry24_32 *elem) {
    if (env == NULL || elem == NULL) {
        return 0;
    }
    if (env->socket_count >= env->socket_cap) {
        uint32_t ncap = (env->socket_cap == 0u) ? 2u : env->socket_cap * 2u;
        rome2_startup_remote_socket_entry24_32 *grown =
            (rome2_startup_remote_socket_entry24_32 *)calloc(
                ncap, sizeof(rome2_startup_remote_socket_entry24_32));
        if (grown == NULL) {
            return 0;
        }
        if (env->sockets != NULL && env->socket_count > 0u) {
            memcpy(grown, env->sockets, (size_t)env->socket_count * sizeof(*grown));
        }
        free(env->sockets);
        env->sockets = grown;
        env->socket_cap = ncap;
    }
    env->sockets[env->socket_count] = *elem;
    env->sockets[env->socket_count].active_14 = 1u;
    elem->active_14 = 0u;
    env->socket_count++;
    return 1;
}

int rome2_l69_assert_entry_push_back(
    rome2_l69_remote_socket_env *env, const rome2_l69_assert_entry12 *elem) {
    if (env == NULL || elem == NULL) {
        return 0;
    }
    if (env->assert_count >= env->assert_cap) {
        uint32_t ncap = (env->assert_cap == 0u) ? 2u : env->assert_cap * 2u;
        rome2_l69_assert_entry12 *grown = (rome2_l69_assert_entry12 *)calloc(
            ncap, sizeof(rome2_l69_assert_entry12));
        if (grown == NULL) {
            return 0;
        }
        if (env->asserts != NULL && env->assert_count > 0u) {
            memcpy(grown, env->asserts, (size_t)env->assert_count * sizeof(*grown));
        }
        free(env->asserts);
        env->asserts = grown;
        env->assert_cap = ncap;
    }
    env->asserts[env->assert_count++] = *elem;
    return 1;
}

int rome2_l69_buf_find_byte(const rome2_l69_byte_buf *buf, uint8_t ch, uint32_t start) {
    uint32_t off;
    const void *found;

    if (buf == NULL || buf->data == NULL) {
        return -1;
    }
    off = (start > buf->len) ? buf->len : start;
    found = memchr(buf->data + off, ch, (size_t)(buf->len - off));
    return (found != NULL) ? (int)((const uint8_t *)found - buf->data) : -1;
}

int rome2_l69_byte_buf_grow(rome2_l69_byte_buf *buf, const uint8_t *seed, uint32_t add_len) {
    uint32_t needed;
    (void)seed;

    if (buf == NULL) {
        return 0;
    }
    if (add_len > UINT32_MAX - buf->len) {
        return 0;
    }
    needed = buf->len + add_len;
    if (needed > buf->cap) {
        uint8_t *grown = (uint8_t *)calloc(needed + 8u, 1u);
        if (grown == NULL) {
            return 0;
        }
        if (buf->data != NULL && buf->len > 0u) {
            memcpy(grown, buf->data, buf->len);
        }
        free(buf->data);
        buf->data = grown;
        buf->cap = needed;
    }
    return 1;
}

int rome2_l69_append_utf16_bytes(rome2_l69_byte_buf *buf, const uint16_t *src, uint32_t hint) {
    size_t i = 0u;
    if (buf == NULL || src == NULL) {
        return 0;
    }
    if (hint > buf->len && rome2_l69_byte_buf_grow(buf, NULL, hint - buf->len) == 0) {
        return 0;
    }
    while (src[i] != 0u) {
        if (rome2_l69_byte_buf_grow(buf, NULL, 2u) == 0) {
            return 0;
        }
        buf->data[buf->len++] = (uint8_t)(src[i] & 0xffu);
        buf->data[buf->len++] = (uint8_t)((src[i] >> 8u) & 0xffu);
        i++;
    }
    return (int)buf->len;
}

size_t rome2_l69_wstr_assign_raw_len(
    uint16_t *dst, size_t dst_cap, const uint16_t *src, size_t wchar_count) {
    size_t n;
    if (dst == NULL || dst_cap == 0u) {
        return 0u;
    }
    n = (src != NULL && wchar_count < dst_cap) ? wchar_count : (dst_cap - 1u);
    if (src != NULL && n > 0u) {
        memcpy(dst, src, n * sizeof(uint16_t));
    }
    dst[n] = 0u;
    return n;
}

size_t rome2_l69_u32_format_radix_wstr(
    uint32_t val, uint32_t radix, const uint16_t *digits, uint16_t *out_w, size_t out_cap) {
    uint16_t rev[34];
    size_t pos = 0u;
    size_t i;

    if (out_w == NULL || out_cap == 0u || digits == NULL || radix < 2u) {
        return 0u;
    }
    if (val == 0u) {
        return rome2_l69_wstr_assign_raw_len(out_w, out_cap, digits, 1u);
    }
    while (val != 0u && pos < 33u) {
        rev[pos++] = digits[val % radix];
        val /= radix;
    }
    for (i = 0u; i < pos && i + 1u < out_cap; ++i) {
        out_w[i] = rev[pos - 1u - i];
    }
    out_w[i] = 0u;
    return i;
}

int rome2_l69_wide_printf_format_value(
    uint16_t spec, uint32_t val, uint16_t *out_w, size_t out_cap) {
    static const uint16_t hex_upper[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',0};
    static const uint16_t hex_lower[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',0};

    if (spec == 'X') {
        (void)rome2_l69_u32_format_radix_wstr(val, 16u, hex_upper, out_w, out_cap);
        return 1;
    }
    if (spec == 'x' || spec == 'u' || spec == 'd') {
        uint32_t radix = (spec == 'x') ? 16u : 10u;
        (void)rome2_l69_u32_format_radix_wstr(val, radix, hex_lower, out_w, out_cap);
        return 1;
    }
    return 0;
}

int rome2_l69_wide_format_spec_step(
    const uint16_t *fmt, size_t fmt_len, uint16_t *idx, uint16_t *out_spec) {
    if (fmt == NULL || idx == NULL || out_spec == NULL) {
        return 0;
    }
    while ((size_t)(*idx) < fmt_len) {
        uint16_t ch = fmt[*idx];
        if (ch == '%') {
            (*idx)++;
            if ((size_t)(*idx) < fmt_len) {
                *out_spec = fmt[*idx];
                (*idx)++;
                return 1;
            }
            return 0;
        }
        (*idx)++;
    }
    return 0;
}

int rome2_l69_parse_remote_assert_packet(
    const char *pkt, char *out_name, size_t name_cap, uint32_t *out_ip) {
    const char *sep;
    size_t nlen;
    unsigned long ip_val = 0ul;

    if (pkt == NULL || out_name == NULL || name_cap == 0u || out_ip == NULL) {
        return 0;
    }
    sep = strchr(pkt, '(');
    if (sep == NULL) {
        return 0;
    }
    nlen = (size_t)(sep - pkt);
    if (nlen >= name_cap) {
        nlen = name_cap - 1u;
    }
    memcpy(out_name, pkt, nlen);
    out_name[nlen] = '\0';
    if (sscanf_s(sep + 1, "%lu", &ip_val) != 1) {
        return 0;
    }
    *out_ip = (uint32_t)ip_val;
    return 1;
}

void rome2_l69_assert_eh_forward_log(
    rome2_l69_remote_socket_env *env, const char *name, uint32_t ip) {
    if (env != NULL) {
        snprintf(
            env->eh_log_msg, sizeof(env->eh_log_msg),
            "REMOTE ASSERT from (name: %s) (IP %x)", name ? name : "", ip);
    }
}

int rome2_l69_assert_dialog_show(
    rome2_l69_remote_socket_env *env, const char *title, const char *msg, uint8_t alt,
    rome2_startup_assert_dlg_hdr24_32 *out_hdr) {
    (void)title;
    (void)msg;
    if (env == NULL || out_hdr == NULL) {
        return 0;
    }
    memset(out_hdr, 0, sizeof(*out_hdr));
    out_hdr->style_00 = 0x0082ffffu;
    out_hdr->cdit_08 = (alt != 0u) ? 6u : 1u;
    env->dlg_alt_mode = (alt != 0u) ? 1 : 0;
    env->dlg_invoked++;
    return 1;
}

int rome2_l69_assert_dialog_box_call(
    rome2_l69_remote_socket_env *env, const char *title, const char *msg) {
    rome2_startup_assert_dlg_hdr24_32 hdr;
    return rome2_l69_assert_dialog_show(env, title, msg, 1u, &hdr);
}

uint32_t rome2_l69_fx_name_rolling_hash(const uint8_t *data, size_t len) {
    uint32_t h = 0u;
    size_t i = 0u;

    if (data == NULL) {
        return 0u;
    }
    while (i < len) {
        uint32_t word = 0u;
        size_t take = ((len - i) >= 4u) ? 4u : (len - i);
        size_t k;
        for (k = 0u; k < take; ++k) {
            word |= ((uint32_t)data[i + k]) << (8u * k);
        }
        uint32_t rot = (((word & 0xffu) ^ (h & 0xffu)) + 0x0du) & 0x1fu;
        uint32_t mix = (rot == 0u) ? h : ((h >> rot) | (h << (32u - rot)));
        h = mix ^ word;
        i += take;
    }
    return h;
}

int rome2_l69_fx_name_open_hash_insert(
    rome2_startup_fx_name_bucket20_32 *buckets, uint32_t bucket_count,
    const char *key, uint32_t value, uint32_t *out_slot) {
    uint32_t h;
    uint32_t idx;
    uint32_t probe;

    if (buckets == NULL || bucket_count == 0u || key == NULL) {
        return 0;
    }
    h = rome2_l69_fx_name_rolling_hash((const uint8_t *)key, strlen(key));
    idx = h % bucket_count;
    for (probe = 0u; probe < bucket_count; ++probe) {
        uint32_t slot = (idx + probe) % bucket_count;
        if (buckets[slot].hash_0c == 0u && buckets[slot].value_10 == 0u) {
            buckets[slot].hash_0c = h;
            buckets[slot].value_10 = value;
            if (out_slot != NULL) {
                *out_slot = slot;
            }
            return 1;
        }
        if (buckets[slot].hash_0c == h) {
            buckets[slot].value_10 = value;
            if (out_slot != NULL) {
                *out_slot = slot;
            }
            return 1;
        }
    }
    return 0;
}

int rome2_l69_remote_assert_dispatch_cont(
    rome2_l69_remote_socket_env *env, const char *pkt, uint32_t ip, uint16_t port) {
    char name[64];
    uint32_t parsed_ip = ip;
    (void)port;

    if (env == NULL || pkt == NULL) {
        return 0;
    }
    memset(name, 0, sizeof(name));
    (void)rome2_l69_parse_remote_assert_packet(pkt, name, sizeof(name), &parsed_ip);
    rome2_l69_assert_eh_forward_log(env, name[0] ? name : pkt, parsed_ip);
    return 1;
}

int rome2_l69_remote_socket_poll_and_dispatch(rome2_l69_remote_socket_env *env) {
    uint8_t hdr4[4];
    uint32_t pkt_len;
    char pkt_buf[256];
    uint32_t s;
    uint32_t ip = 0u;
    uint32_t port = 0u;
    rome2_startup_remote_socket_entry24_32 sock_rec;

    if (env == NULL) {
        return 0;
    }
    s = rome2_l69_remote_socket_accept(env);
    if (s != ROME2_L69_INVALID_SOCKET) {
        memset(&sock_rec, 0, sizeof(sock_rec));
        sock_rec.sock_fd_00 = s;
        sock_rec.peer_words_04[0] = ((uint32_t)env->peer_port_be) << 16u;
        sock_rec.peer_words_04[1] = env->peer_ip_be;
        rome2_l69_remote_endpoint_get(&sock_rec, &ip, &port);
        (void)rome2_l69_remote_socket_push_back(env, &sock_rec);
        rome2_l69_assert_entry12 ae = {s, ip, port};
        (void)rome2_l69_assert_entry_push_back(env, &ae);
    }
    if (rome2_l69_remote_socket_recv(env, hdr4, 4) < 4) {
        return rome2_l69_remote_assert_dispatch_cont(env, "", env->peer_ip_be, (uint16_t)port);
    }
    pkt_len = ((uint32_t)hdr4[0]) | (((uint32_t)hdr4[1]) << 8u) |
              (((uint32_t)hdr4[2]) << 16u) | (((uint32_t)hdr4[3]) << 24u);
    if (4u + pkt_len > ROME2_L69_MAX_REMOTE_PACKET) {
        env->packet_too_large_throws++;
        return 0;
    }
    memset(pkt_buf, 0, sizeof(pkt_buf));
    if (pkt_len > 0u && pkt_len < sizeof(pkt_buf)) {
        (void)rome2_l69_remote_socket_recv(env, (uint8_t *)pkt_buf, (int)pkt_len);
    }
    return rome2_l69_remote_assert_dispatch_cont(env, pkt_buf, ip, (uint16_t)port);
}
