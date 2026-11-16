#ifndef ROME2_VFS_FS_ENGINE_CODEC_OPS_H
#define ROME2_VFS_FS_ENGINE_CODEC_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_channel_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L38_SENTINEL_CTX_VA 0x119f3078u
#define ROME2_VFS_L38_WSTRBUF_BASE_VT_VA 0x1173dadcu
#define ROME2_VFS_L38_WSAEWOULDBLOCK 0x2733u

typedef struct rome2_vfs_fmt_spec {
    uint16_t width;
    uint16_t precision;
    uint16_t sign_ch;
    uint16_t zero_pad_ch;
    uint16_t last_ch;
    uint8_t is_minus;
} rome2_vfs_fmt_spec;

typedef struct rome2_vfs_msegment_span {
    uint32_t base_va;
    uint32_t size;
} rome2_vfs_msegment_span;

/* `0x100d26e0`, `0x113490a0`, `0x11349180`, `0x1134a060`: basic_stringbuf<wchar_t> core ops. */
uint32_t rome2_vfs_wstringbuf_state_from_openmode(uint32_t openmode);

rome2_vfs_reg_status rome2_vfs_wstringbuf60_init_slots(
    rome2_vfs_wstringbuf60_32 *sb,
    uint32_t self_va,
    uint32_t vftable_va);

rome2_vfs_reg_status rome2_vfs_wstringbuf60_init_buf(
    rome2_vfs_wstringbuf60_32 *sb,
    uint16_t *dst_buf,
    uint32_t dst_cap,
    uint32_t dst_guest_va,
    const uint16_t *src,
    uint32_t count,
    uint32_t str_state);

rome2_vfs_reg_status rome2_vfs_wstringbuf60_tidy(
    rome2_vfs_wstringbuf60_32 *sb,
    uint8_t *out_should_free,
    uint32_t *out_free_va);

/* `0x100de0d0`: pinned zero-fill context accessor returning 0x119f3078. */
uint32_t rome2_vfs_sentinel_ctx_va(void);

/* `0x100f2af0` & `0x100f2b00`: unchecked / bounds-checked UTF-16 element accessors. */
const uint16_t *rome2_vfs_wstr_ptr_at_unchecked(const uint16_t *buf, uint32_t idx);
uint16_t rome2_vfs_wstr_char_at_checked(const uint16_t *buf, uint32_t len, uint32_t idx);

/* `0x101056d0`, `0x10105850`, `0x100de340`, `0x100f5860`: printf specifier & float format ops. */
rome2_vfs_reg_status rome2_vfs_parse_fmt_spec_ascii(
    const char *str,
    uint32_t len,
    uint16_t *inout_idx,
    rome2_vfs_fmt_spec *out_spec);

rome2_vfs_reg_status rome2_vfs_parse_fmt_spec_wstr(
    const uint16_t *wstr,
    uint32_t len,
    uint16_t *inout_idx,
    rome2_vfs_fmt_spec *out_spec);

rome2_vfs_reg_status rome2_vfs_scan_lfmt_spec_ascii(
    const char *fmt,
    uint32_t fmt_len,
    uint16_t *inout_idx,
    char *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap,
    rome2_vfs_fmt_spec *out_spec,
    uint8_t *out_hit_spec);

rome2_vfs_reg_status rome2_vfs_format_float32_wstr(
    float val,
    uint16_t spec_ch,
    uint16_t prec,
    uint16_t prefix_ch,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok);

/* `0x10114f00`, `0x10114f60`, `0x10fd7df0`, `0x10fe4780`: endpoint/FIONBIO/probe/Steam ops. */
rome2_vfs_reg_status rome2_vfs_sock_endpoint12_set_ipv4(
    rome2_vfs_sock_endpoint12_32 *ep,
    uint32_t ipv4_addr_dword,
    uint16_t host_port);

rome2_vfs_reg_status rome2_vfs_sock_toggle_fionbio(
    int32_t ioctl_ret,
    uint8_t blocking_flag,
    uint32_t *out_argp);

uint8_t rome2_vfs_channel_slot_probe_ready(
    uint8_t steam_ready,
    int32_t peek_ret,
    uint32_t wsa_last_error);

rome2_vfs_reg_status rome2_vfs_steam_p2p_close_pack(
    uint32_t steam_id_lo,
    uint32_t steam_id_hi,
    uint32_t out_pair[2]);

/* `0x1011fcf0`, `0x101236f0`, `0x10123dd0`, `0x101e3c50`, `0x10f5f5c0`, `0x10fd6850`. */
rome2_vfs_reg_status rome2_vfs_freelist4_link_links(
    uint32_t base_va,
    uint32_t count,
    uint32_t *out_links,
    uint32_t links_cap);

rome2_vfs_reg_status rome2_vfs_dlmalloc_init_top(
    rome2_vfs_dlmalloc_mstate448_32 *ms,
    uint32_t tbase_va,
    uint32_t tsize,
    uint32_t trim_threshold,
    uint32_t *out_aligned_top_va,
    uint32_t *out_aligned_size,
    uint32_t *out_chunk_head,
    uint32_t *out_fencepost_head);

uint32_t rome2_vfs_dlmalloc_find_segment_idx(
    const rome2_vfs_msegment_span *segs,
    uint32_t seg_count,
    uint32_t addr_va);

rome2_vfs_reg_status rome2_vfs_intrusive_list_clear_range(
    const uint32_t *payload_vas,
    const uint32_t *node_vas,
    uint32_t count,
    uint32_t self_va,
    uint32_t *out_freed_vas,
    uint32_t freed_cap,
    uint32_t *out_freed_count,
    uint32_t *out_head_after);

rome2_vfs_reg_status rome2_vfs_channel_queue24_init(
    rome2_vfs_channel_queue24_32 *q,
    uint32_t self_va,
    uint32_t owner_arg);

rome2_vfs_reg_status rome2_vfs_channel_adapter_register(
    uint32_t *list_slots,
    uint32_t *inout_count,
    uint32_t cap,
    uint32_t adapter_va,
    uint8_t *out_inserted);

/* `0x1055bff0`, `0x10f71eb0`, `0x10f78290`, `0x10f80f40`: stream/bit-range/slot ops. */
rome2_vfs_reg_status rome2_vfs_stream_read_bytes_or_overflow(
    const uint8_t *buf,
    uint32_t cap,
    uint32_t *inout_cursor,
    uint32_t *inout_avail,
    uint8_t *dst,
    uint32_t size,
    uint8_t *out_need_fallback,
    uint8_t *out_hit_end);

uint8_t rome2_vfs_bitrev8(uint8_t v);

rome2_vfs_reg_status rome2_vfs_write_ranged_bits(
    uint8_t *buf,
    uint32_t byte_cap,
    uint32_t *inout_bit_cursor,
    uint32_t value,
    uint32_t min_val,
    uint32_t max_val,
    uint32_t *out_bits_written);

rome2_vfs_reg_status rome2_vfs_channel_slot_reset_flags(
    uint32_t *sub_dwords20,
    uint8_t *sub_bytes20,
    uint32_t *state_40a8,
    uint32_t *aux_40ac,
    uint8_t clear_aux);

uint32_t rome2_vfs_channel_find_active_slot(
    const rome2_vfs_channel_slot_hdr24_32 *slots,
    const uint32_t *states,
    uint32_t count,
    const rome2_vfs_channel_slot_hdr24_32 *key);

#ifdef __cplusplus
}
#endif

#endif
