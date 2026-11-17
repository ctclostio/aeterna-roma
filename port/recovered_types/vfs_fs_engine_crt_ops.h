#ifndef ROME2_VFS_FS_ENGINE_CRT_OPS_H
#define ROME2_VFS_FS_ENGINE_CRT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_net_sys_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L40_IOB_BASE_VA 0x119ebe18u
#define ROME2_VFS_L40_IOB_STRIDE_BYTES 0x38u
#define ROME2_VFS_L40_CXX_EH_CODE 0xe06d7363u
#define ROME2_VFS_L40_CXX_EH_MAGIC1 0x19930520u
#define ROME2_VFS_L40_CXX_EH_WINRT_MAGIC 0x01994000u
#define ROME2_VFS_L40_TIME_QUEUE_DEFAULT_CAP 16u

/* `0x100ee990` & `0x100eee00`: UTF-16 %c and scalar token format scanners. */
rome2_vfs_reg_status rome2_vfs_format_scan_char_wstr(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint16_t *inout_pos,
    uint16_t ch_val,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok);

rome2_vfs_reg_status rome2_vfs_format_scan_scalar_wstr(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint16_t *inout_pos,
    uint32_t val,
    uint8_t is_signed,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok);

/* `0x100ef980`: UTF-16 bounded delimiter/suffix lookup-or-fallback builder. */
rome2_vfs_reg_status rome2_vfs_wstr_append_char_slice(
    const uint16_t *src,
    uint32_t src_len,
    uint16_t ch,
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len);

/* `0x10114740`: socket send byte count or Winsock error diagnostic message (`0x100feef0` sl=3). */
const char *rome2_vfs_sock_send_or_err(
    int32_t send_ret,
    uint32_t wsa_err,
    int32_t *out_bytes);

/* `0x10122e50` & `0x10123730`: dlmalloc add_segment / prepend_alloc alignment & bin classification. */
uint32_t rome2_vfs_dlmalloc_chunk_align8(uint32_t addr);
uint32_t rome2_vfs_dlmalloc_bin_index(uint32_t sz, uint8_t *out_is_tree);

rome2_vfs_reg_status rome2_vfs_dlmalloc_add_segment_plan(
    uint32_t old_seg_end,
    uint32_t old_top_va,
    uint32_t new_tbase,
    uint32_t new_tsize,
    uint32_t *out_new_top_va,
    uint32_t *out_new_topsize,
    uint32_t *out_old_top_free_size);

rome2_vfs_reg_status rome2_vfs_dlmalloc_prepend_plan(
    uint32_t old_base,
    uint32_t nb,
    uint32_t prev_base,
    uint32_t top_va,
    uint32_t dv_va,
    uint32_t *out_chunk_va,
    uint32_t *out_next_va,
    uint32_t *out_rem_size,
    uint8_t *out_hit_mode);

/* `0x10f7c1a0`: timestamped sample queue push tracking total count & cumulative bytes. */
typedef struct rome2_vfs_ts_sample_queue {
    uint32_t timestamps[ROME2_VFS_L40_TIME_QUEUE_DEFAULT_CAP];
    uint32_t sizes[ROME2_VFS_L40_TIME_QUEUE_DEFAULT_CAP];
    uint32_t count;
    uint32_t byte_sum;
} rome2_vfs_ts_sample_queue;

rome2_vfs_reg_status rome2_vfs_ts_queue_push(
    rome2_vfs_ts_sample_queue *q,
    uint32_t timestamp_ms,
    uint32_t byte_len);

/* `0x10fa7230`: reliable patch control packet header encoder. */
rome2_vfs_reg_status rome2_vfs_channel_patch_hdr_pack(
    uint8_t sender_ch,
    uint32_t base_seq,
    uint32_t patch_bytes,
    uint8_t *dst,
    uint32_t dst_cap,
    uint32_t *inout_bit_pos,
    uint8_t *out_ok);

/* `0x10fdad30`: 47-slot x 12B channel manager singleton layout initializer. */
rome2_vfs_reg_status rome2_vfs_channel_mgr564_init(
    rome2_vfs_channel_mgr564_32 *mgr,
    uint32_t mgr_va);

/* `0x10fdebc0` & `0x10fe4980`: 64-bit SteamID validator & ISteamNetworking::SendP2PPacket plan. */
uint8_t rome2_vfs_steam_id_is_valid(uint32_t id_lo, uint32_t id_hi);

rome2_vfs_reg_status rome2_vfs_steam_send_p2p_plan(
    uint32_t id_lo,
    uint32_t id_hi,
    const void *pub_data,
    uint32_t cub_data,
    uint8_t reliable,
    int32_t *out_send_type,
    int32_t *out_channel,
    uint8_t *out_ready);

/* `0x116838ea`..`0x116bec60`: bounded C17 reconstructions for 15 CRT runtime helpers. */
int32_t rome2_vfs_crt_atexit_slot(
    uint32_t *table,
    uint32_t cap,
    uint32_t *inout_count,
    uint32_t fn_va);

rome2_vfs_reg_status rome2_vfs_crt_init_thread_header(
    int32_t *inout_guard,
    int32_t *inout_tls_epoch,
    int32_t global_epoch,
    uint8_t *out_should_init);

uint32_t rome2_vfs_crt_ftoui3(float val);

int32_t rome2_vfs_crt_feof_filex(
    const rome2_vfs_crt_filex56_32 *stream,
    int32_t *out_errno);

uint32_t rome2_vfs_crt_iob_slot_va(uint32_t idx);

const rome2_vfs_crt_filex56_32 *rome2_vfs_crt_iob_slot_host(
    const rome2_vfs_crt_filex56_32 iob[3],
    uint32_t idx);

double rome2_vfs_crt_floor_f64(double x);

int32_t rome2_vfs_crt_vsnprintf_bounded(
    char *dst,
    size_t cap,
    const char *fmt,
    int32_t val_i,
    const char *val_s,
    int32_t *out_errno);

int32_t rome2_vfs_crt_ecvt_s(
    char *buf,
    size_t cap,
    double val,
    int32_t ndigit,
    int32_t *out_decpt,
    int32_t *out_sign);

void *rome2_vfs_crt_memset(void *dst, int byte_val, size_t len);
const uint16_t *rome2_vfs_crt_wcsstr_u16(const uint16_t *haystack, const uint16_t *needle);
const void *rome2_vfs_crt_memchr(const void *buf, uint8_t ch, size_t len);

rome2_vfs_reg_status rome2_vfs_crt_beginthreadex_validate(
    uintptr_t start_addr,
    uint32_t synthetic_tid,
    uint32_t *out_tid,
    int32_t *out_errno);

rome2_vfs_reg_status rome2_vfs_crt_cxx_throw_record_init(
    rome2_vfs_cxx_throw_template32_32 *rec,
    uint32_t exception_obj_va,
    uint32_t throw_info_va,
    uint8_t throw_info_flags);

#ifdef __cplusplus
}
#endif

#endif
