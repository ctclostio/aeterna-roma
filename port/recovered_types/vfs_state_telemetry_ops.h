#ifndef ROME2_RECOVERED_VFS_STATE_TELEMETRY_OPS_H
#define ROME2_RECOVERED_VFS_STATE_TELEMETRY_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"

/* Layer 23 recovered vtable identities, inner dtor addresses, and bounds. */
#define ROME2_VFS_INNER_STATE_77BC_VTABLE32    0x118977bcu /* 0x10B inner state */
#define ROME2_VFS_INNER_STATE_77C8_VTABLE32    0x118977c8u /* 0x1cB listener inner state */
#define ROME2_VFS_INNER_STATE_77D4_VTABLE32    0x118977d4u /* 0x20B inner state */
#define ROME2_VFS_INNER_STATE_77E0_VTABLE32    0x118977e0u /* 0x10B async inner state */
#define ROME2_VFS_REF_BLOCK20_A464_VTABLE32    0x1189a464u /* 0x20B open-stream ref block */
#define ROME2_VFS_REF_BLOCK1C_A474_VTABLE32    0x1189a474u /* 0x1cB async-view ref block */

#define ROME2_VFS_INNER_DTOR_112ACD90          0x112acd90u /* 0x10B deleting dtor */
#define ROME2_VFS_INNER_DTOR_112ACFE0          0x112acfe0u /* 0x1cB deleting dtor */
#define ROME2_VFS_INNER_DTOR_112AD140          0x112ad140u /* 0x20B deleting dtor */

#define ROME2_VFS_COMPLETE_UNCOMPRESSED_FN32   0x100fa6d0u
#define ROME2_VFS_COMPLETE_COMPRESSED_FN32     0x100fcfd0u

typedef enum rome2_vfs_state_telemetry_status {
    ROME2_VFS_STATE_TELEMETRY_OK = 0,
    ROME2_VFS_STATE_TELEMETRY_NULL_ARGUMENT = 1,
    ROME2_VFS_STATE_TELEMETRY_BUFFER_TOO_SMALL = 2,
    ROME2_VFS_STATE_TELEMETRY_BAD_VTABLE = 3,
    ROME2_VFS_STATE_TELEMETRY_BAD_GRANULARITY = 4,
    ROME2_VFS_STATE_TELEMETRY_ARITHMETIC_OVERFLOW = 5,
    ROME2_VFS_STATE_TELEMETRY_CAPACITY_EXCEEDED = 6
} rome2_vfs_state_telemetry_status;

typedef struct rome2_vfs_state_d97f0_plan {
    int already_closed;
    int compressed;
    uint32_t completion_target_va;
    uint32_t src_addr;
    uint32_t src_end;
    uint32_t size_bytes;
    uint8_t next_eof_00c;
} rome2_vfs_state_d97f0_plan;

/* Decode 28-byte (0x1cB) `rome2_vfs_state_ref_block28_32` (`0x112d91c0`)
 * from `view` without mutating `*out_block` on failure. */
rome2_vfs_state_telemetry_status rome2_vfs_decode_state_ref_block28_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_state_ref_block28_32 *out_block);

/* Decode 28-byte (0x1cB) `rome2_vfs_state_inner_listener28_32` (`0x112acfe0`)
 * from `view` without mutating `*out_state` on failure. */
rome2_vfs_state_telemetry_status rome2_vfs_decode_state_inner_listener28_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_state_inner_listener28_32 *out_state);

/* Decode 36-byte (0x24B) `rome2_vfs_sys_info32` (`0x10115730` at `0x11af40e0`),
 * validating positive power-of-two `page_size_004` and
 * `allocation_granularity_01c`. Preserves `*out_info` on failure. */
rome2_vfs_state_telemetry_status rome2_vfs_decode_sys_info32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_sys_info32 *out_info);

/* Return guest byte allocation size passed to `0x116835d7` when `delete_flag`
 * bit 0 is set (`0x112acd90` -> 0x10B, `0x112acfe0` -> 0x1cB, `0x112ad140` -> 0x20B),
 * or `0` when `(delete_flag & 1U) == 0`. Preserves `*out_free_bytes` on error. */
rome2_vfs_state_telemetry_status rome2_vfs_state_inner_deleting_dtor_size32(
    uint32_t dtor_va,
    uint32_t delete_flag,
    uint32_t *out_free_bytes);

/* Model `0x112d97f0`: validates `closed_00d`, `flags_014 & 1U` (compressed
 * `0x100fcfd0` vs uncompressed `0x100fa6d0`), and `data_ptr + size_bytes`
 * 32-bit wrap before returning `*out_plan`. Preserves `*out_plan` on error. */
rome2_vfs_state_telemetry_status rome2_vfs_state_d97f0_plan_complete32(
    uint8_t eof_or_closed_00c,
    uint8_t closed_00d,
    uint32_t flags_014,
    uint32_t data_ptr,
    uint32_t size_bytes,
    rome2_vfs_state_d97f0_plan *out_plan);

/* Model `0x112baf00`: evaluates `{eof_or_closed_00c, closed_00d, extra_deref_010}`,
 * reporting `*out_needs_spin = 1` when both flags are 0, `*out_result_ptr = 0`
 * if closed, and `*out_result_ptr = extra_deref_010` otherwise. Preserves
 * caller outputs on NULL pointers. */
rome2_vfs_state_telemetry_status rome2_vfs_state_baf00_poll_extra32(
    uint8_t eof_or_closed_00c,
    uint8_t closed_00d,
    uint32_t extra_deref_010,
    int *out_needs_spin,
    uint32_t *out_result_ptr);

/* Model `0x10115940` / `0x112d9640`: reads 32-bit LE words spaced by power-of-two
 * `page_stride` up to `len_bytes` while `cancel_flag == 0`, accumulating into
 * `initial_acc` modulo 2^32. Preserves `*out_acc` and `*out_steps` on error. */
rome2_vfs_state_telemetry_status rome2_vfs_prefetch_pages_cancellable_sum32(
    const uint8_t *buf,
    size_t buf_len,
    uint32_t len_bytes,
    uint32_t page_stride,
    uint32_t initial_acc,
    const uint8_t *cancel_flag,
    uint32_t *out_acc,
    size_t *out_steps);

/* Model `0x112e1780` / `0x112e1960` ID allocation: pops from free_ids stack if
 * `*free_count > 0`, else consumes `*next_id` with overflow guard. Preserves
 * all caller state on error. */
rome2_vfs_state_telemetry_status rome2_vfs_telemetry_acquire_id32(
    uint32_t *free_ids,
    size_t *free_count,
    uint32_t *next_id,
    uint32_t *out_id);

/* Model `0x112e17e0` / `0x112e19b0` ID release: pushes `released_id` onto
 * bounded `free_ids` stack (`stack_cap` ceiling) or rejects with
 * `CAPACITY_EXCEEDED` without mutating `*free_count`. */
rome2_vfs_state_telemetry_status rome2_vfs_telemetry_release_id32(
    uint32_t *free_ids,
    size_t *free_count,
    size_t stack_cap,
    uint32_t released_id);

/* Model `0x112d91c0` active/high-water update (`[0x12031ac0]`, `[0x12031ac4]`):
 * increments `*active_count` with overflow check and updates `*high_water`. */
rome2_vfs_state_telemetry_status rome2_vfs_async_view_high_water32(
    uint32_t *active_count,
    uint32_t *high_water);

#endif
