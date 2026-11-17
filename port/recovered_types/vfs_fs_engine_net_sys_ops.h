#ifndef ROME2_VFS_FS_ENGINE_NET_SYS_OPS_H
#define ROME2_VFS_FS_ENGINE_NET_SYS_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_codec_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L39_SSE_ZERO_TLS_VA 0x119f3b04u
#define ROME2_VFS_L39_CHANNEL_MGR_VA 0x1201ae48u
#define ROME2_VFS_L39_MS_VC_THREADNAME_EXC 0x406d1388u
#define ROME2_VFS_L39_MAX_TCP_FRAME_BYTES 0x4000u
#define ROME2_VFS_L39_MAX_BCAST_PATCH_BYTES 0x2000u

/* `0x100e7ff0` & `0x10fddba0`: TLS-guarded static zero-vector & manager singleton helpers. */
uint32_t rome2_vfs_sse_zero_tls_va(void);

rome2_vfs_reg_status rome2_vfs_sse_zero_init16(
    int32_t *inout_guard,
    uint8_t out_vec16[16],
    int32_t tls_epoch,
    uint8_t *out_initialized);

uint32_t rome2_vfs_channel_mgr_singleton_va(
    int32_t *inout_guard,
    int32_t tls_epoch,
    uint8_t *out_constructed);

/* `0x100f38b0`: MSVC thread-name SEH descriptor (0x406d1388). */
rome2_vfs_reg_status rome2_vfs_threadname_info16_fill(
    rome2_vfs_threadname_info16_32 *info,
    uint32_t sz_name_va,
    uint32_t thread_id);

/* `0x100efa10`, `0x100f2f60`, `0x100f3f70`, `0x100f4240`, `0x10104e10`, `0x10115640`, `0x10c93ed0`. */
rome2_vfs_reg_status rome2_vfs_wstr_prepend_char(
    uint16_t prefix_ch,
    const uint16_t *src,
    uint32_t src_len,
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_wstr_pad_aligned(
    const uint16_t *src,
    uint32_t src_len,
    uint16_t min_width,
    uint8_t left_align,
    uint16_t pad_ch,
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_wstr_substr_slice(
    const uint16_t *src,
    uint32_t src_len,
    uint32_t pos,
    uint32_t count,
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_format_scalar_type_error(
    char spec_ch,
    const char *type_name,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_format_int32_card32(
    uint32_t val,
    char spec_ch,
    uint8_t is_signed,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok);

/* `0x100feef0`: Winsock / host lookup diagnostic message mapping. */
const char *rome2_vfs_winsock_err_str(uint32_t slot_idx, uint32_t wsa_err);

/* `0x10123e40`: dlmalloc sys_alloc alignment & footprint/mmap dispatch planning. */
rome2_vfs_reg_status rome2_vfs_dlmalloc_sys_alloc_plan(
    const rome2_vfs_dlmalloc_mstate448_32 *ms,
    uint32_t nb,
    uint32_t granularity,
    uint32_t mmap_threshold,
    uint32_t *out_alloc_sz,
    uint8_t *out_use_mmap);

/* `0x10f74830` & `0x10f79f60`: MSB span width & byte-stream MSB-first bit-block copier. */
uint32_t rome2_vfs_msb_width_u32(uint32_t val);

rome2_vfs_reg_status rome2_vfs_bitcopy_msb(
    uint8_t *dst,
    uint32_t dst_byte_cap,
    uint32_t *inout_dst_bit,
    const uint8_t *src,
    uint32_t src_byte_cap,
    uint32_t *inout_src_bit,
    uint32_t bit_count,
    uint32_t *out_copied);

/* `0x10fa5d10`: bounded ring sequence ack & bitmap dequeue helper. */
rome2_vfs_reg_status rome2_vfs_seq_ack_ring_pop(
    rome2_vfs_seq_ack_ring36_32 *ring,
    uint8_t *bitmap,
    uint32_t bitmap_len,
    uint32_t *ack_out_arr,
    uint32_t ack_cap,
    int32_t seq_val,
    uint8_t *out_acked,
    uint8_t *out_freed_external);

/* `0x10fb2fb0`, `0x10fd6d80..0x10fd9500`, `0x10fdf080..0x10fe47b0`: channel lifecycle/transport. */
rome2_vfs_reg_status rome2_vfs_channel_hdr24_reset(rome2_vfs_channel_slot_hdr24_32 *hdr);
rome2_vfs_reg_status rome2_vfs_channel_meta36_reset(rome2_vfs_channel_slot_meta36_32 *meta);

rome2_vfs_reg_status rome2_vfs_channel_slot_meta_move(
    rome2_vfs_channel_slot_meta36_32 *dst_meta,
    rome2_vfs_channel_slot_hdr24_32 *dst_hdr,
    const rome2_vfs_channel_slot_meta36_32 *src_meta,
    rome2_vfs_channel_slot_hdr24_32 *src_hdr,
    uint8_t *out_closed_prev_sock);

uint8_t rome2_vfs_channel_hdr24_endpoint_matches(
    const rome2_vfs_channel_slot_hdr24_32 *a,
    const rome2_vfs_channel_slot_hdr24_32 *b,
    uint8_t steam_id_valid);

uint8_t rome2_vfs_steam_p2p_state_ready(
    uint8_t ctx_nonnull,
    uint8_t id_valid,
    uint8_t session_state_ok);

rome2_vfs_reg_status rome2_vfs_channel_frame_send_plan(
    uint32_t payload_len,
    uint8_t steam_ready,
    uint8_t tcp_ready,
    uint8_t reliable,
    uint8_t *out_route,
    uint8_t out_framed_hdr2[2],
    uint32_t *out_wire_bytes);

rome2_vfs_reg_status rome2_vfs_channel_broadcast_validate(
    uint32_t sender_ch,
    uint32_t target_ch,
    uint32_t target_state,
    uint8_t slot_ready,
    uint32_t ack_seq_delta_bytes,
    uint8_t *out_ok);

#ifdef __cplusplus
}
#endif

#endif
