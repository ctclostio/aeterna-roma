#ifndef ROME2_RECOVERED_VFS_PACK_STREAM_H
#define ROME2_RECOVERED_VFS_PACK_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "vfs_pack_entry.h"

/* Result of aligned allocation geometry modeled from 0x10102f50:
 * allocates request_bytes + 4 + effective_align, aligns (raw + 4 +
 * effective_align) down modulo effective_align, and reserves aligned_addr - 4
 * for storing the underlying raw allocation address. */
typedef struct rome2_vfs_aligned_alloc_plan {
    uint32_t effective_align;
    uint32_t alloc_bytes;
    uint64_t aligned_addr;
    uint64_t backptr_slot_addr;
} rome2_vfs_aligned_alloc_plan;

/* Clamped byte-slice output produced by vtable 0x118976c0 slots +0x1c
 * (0x112d0c90 locked) and +0x20 (0x112d0d80 unlocked) before dispatching to
 * stream_state->vtable[+0x04/+0x08]. */
typedef struct rome2_vfs_entry_slice_clamp32 {
    uint32_t clamped_len;
    uint32_t relative_offset;
    uint32_t entry_byte_size;
    uint64_t entry_pack_offset;
    uint64_t slice_pack_offset;
    rome2_data_address32 stream_state;
} rome2_vfs_entry_slice_clamp32;

/* Snapshot of 0x118976c0 entry accessor state:
 *   +0x0c (0x10171400): entry_meta ([ECX+0x18])
 *   +0x10 (0x10101a40): byte_size ([ECX+0x08])
 *   +0x28 (0x10269610): stream_state ([ECX+0x20])
 *   +0x34 (0x112d2900): winner_notified ([ECX+0x24])
 *   +0x14/+0x38/+0x3c: non-null stream_state gating. */
typedef struct rome2_vfs_pack_entry_stream_info32 {
    uint32_t entry_meta;
    uint32_t byte_size;
    rome2_data_address32 stream_state;
    rome2_vtable_address32 stream_vtable;
    bool has_stream_state;
    uint8_t winner_notified;
} rome2_vfs_pack_entry_stream_info32;

/* Checked adaptation of 0x10102f50 aligned buffer geometry: enforces
 * effective_align = max(4, requested_align), prevents 32-bit allocation-size
 * wraparound, and aligns any caller-supplied raw_base upward within the
 * allocation span with back-pointer slot at aligned_addr - 4. Preserves
 * *out_plan on every non-OK return. */
rome2_vfs_reg_status rome2_vfs_plan_aligned_alloc(
    uint32_t requested_bytes, uint32_t requested_align, uint64_t raw_base,
    rome2_vfs_aligned_alloc_plan *out_plan);

/* Checked adaptation of the shared range-clamping logic in 0x118976c0 slots
 * +0x1c (0x112d0c90) and +0x20 (0x112d0d80): validates vtable == 0x118976c0,
 * rejects req_offset > entry.byte_size without 32-bit wraparound, sets
 * clamped_len = (req_len != 0) ? min(byte_size - req_offset, req_len) :
 * (byte_size - req_offset), and checks 64-bit pack offset addition. Preserves
 * *output on every non-OK status. */
rome2_vfs_reg_status rome2_vfs_entry_clamp_slice32(
    const rome2_guest_read_view *entries, rome2_guest_addr32 entry_addr,
    uint32_t req_len, uint32_t req_offset,
    rome2_vfs_entry_slice_clamp32 *output);

/* Checked adaptation of vtable 0x118976c0 slot +0x18 (0x112c9540): validates
 * entry vtable == 0x118976c0, reads carrier = entry+0x1c, pack_props =
 * *carrier, and extracts (*pack_props + 0x1c >> 6) & 1. Rejects null carrier or
 * pack_props with INVALID_STATE and preserves *out_has_meta on failure. */
rome2_vfs_reg_status rome2_vfs_entry_has_per_entry_meta32(
    const rome2_guest_read_view *entries, rome2_guest_addr32 entry_addr,
    const rome2_guest_read_view *carriers,
    const rome2_guest_read_view *pack_props_view,
    bool *out_has_meta);

/* Reads entry accessor metadata (+0x08/+0x18/+0x20/+0x24) and, when
 * stream_state != 0, validates its leading 32-bit vtable word over streams_view.
 * Preserves *output on every non-OK return. */
rome2_vfs_reg_status rome2_vfs_entry_read_stream_info32(
    const rome2_guest_read_view *entries, rome2_guest_addr32 entry_addr,
    const rome2_guest_read_view *streams_view,
    rome2_vfs_pack_entry_stream_info32 *output);

#endif
