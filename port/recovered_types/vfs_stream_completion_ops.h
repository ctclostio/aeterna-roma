#ifndef ROME2_RECOVERED_VFS_STREAM_COMPLETION_OPS_H
#define ROME2_RECOVERED_VFS_STREAM_COMPLETION_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 24 recovered vtable, stream XOR, and allocator tag constants. */
#define ROME2_VFS_REF_BLOCK_E_VTABLE32       0x1189a454u /* 0x38B (0x112b2f40 / 0x112accd0) */
#define ROME2_VFS_REF_BLOCK_A_VTABLE32       0x1189a414u /* 0x28B (0x1090b600 +0x08) */
#define ROME2_VFS_STREAM_XOR_MULT64          0x8feb2a6740a6920eULL /* 0x100fcfd0 LCG multiplier */
#define ROME2_VFS_TAGGED_ALLOC_FILL_BYTE     0xcau       /* [0x11934484] fill byte in 0x100fcc80 */

/*
 * Deobfuscate 8-byte blocks in host buffers matching `0x100fcfd0`: computes
 * `(uint64_t)(~key) * 0x8feb2a6740a6920eULL`, XORs the low 32 bits into dst[0]
 * and high 32 bits into dst[4], and advances `key += 8`. Trailing `< 8` bytes
 * are excluded via `(byte_len & 7u)` alignment; preserves outputs on error.
 */
rome2_vfs_reg_status rome2_vfs_stream_xor_deobfuscate_blocks32(
    const uint8_t *src_bytes,
    size_t byte_len,
    uint8_t *dst_bytes,
    uint32_t *inout_key,
    size_t *out_bytes_processed);

/*
 * Cancellable page-chunked copy matching `0x100fa6d0`: checks `*cancel_flag_addr`
 * before copying `page_size` chunks from `src_addr` in `view` and any trailing
 * bytes if still uncancelled. Validates guest span up front on uncancelled copy
 * and preserves outputs on error.
 */
rome2_vfs_reg_status rome2_vfs_stream_page_copy_cancellable32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 src_addr,
    uint32_t byte_count,
    uint32_t page_size,
    rome2_guest_addr32 cancel_flag_addr,
    uint8_t *dst_buf,
    uint32_t *out_copied_bytes,
    int *out_cancelled);

/*
 * Unsigned 64-bit multiplication helper matching x86 CRT `__allmul` at
 * `0x11684200`. Preserves outputs on error.
 */
rome2_vfs_reg_status rome2_vfs_crt_allmul32(
    uint32_t a_lo,
    uint32_t a_hi,
    uint32_t b_lo,
    uint32_t b_hi,
    uint32_t *out_lo,
    uint32_t *out_hi);

/*
 * Unsigned 64-bit division helper matching x86 CRT `__aulldiv` at `0x11684270`:
 * rejects zero divisor with `BAD_ARGUMENT` while preserving caller outputs.
 */
rome2_vfs_reg_status rome2_vfs_crt_aulldiv32(
    uint32_t dvd_lo,
    uint32_t dvd_hi,
    uint32_t dvs_lo,
    uint32_t dvs_hi,
    uint32_t *out_lo,
    uint32_t *out_hi);

/*
 * Initialize `rome2_vfs_open_cache_entry16_32` matching `0x100f19f0`: clears
 * `zero_004` and resolves `-1` sentinel args against `resolved_lo`/`resolved_hi`.
 */
rome2_vfs_reg_status rome2_vfs_open_cache_entry_init32(
    rome2_vfs_open_cache_entry16_32 *entry,
    uint32_t token_lo_arg,
    uint32_t token_hi_arg,
    uint32_t resolved_lo,
    uint32_t resolved_hi);

/*
 * Read `{token_lo_008, token_hi_00c}` from `entry_addr` matching `0x100ff8c0`
 * (and `0x112c0090` via `[[pack_entry + 0x1c]] + 0x08`).
 */
rome2_vfs_reg_status rome2_vfs_open_cache_entry_read_pair32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 entry_addr,
    uint32_t *out_token_lo,
    uint32_t *out_token_hi);

/*
 * Read `{token_lo, token_hi}` via `[[pack_entry + 0x1c]] + 0x08` matching
 * pack-entry vtable `0x118976c0` slot `+0x48` (`0x112c0090`).
 */
rome2_vfs_reg_status rome2_vfs_pack_read_backing_pair32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 pack_entry_addr,
    uint32_t *out_token_lo,
    uint32_t *out_token_hi);

/*
 * Extract bits 4 and 5 of `[[[pack_entry + 0x1c]] + 0x1c]` as `0..3` matching
 * pack-entry vtable `0x118976c0` slot `+0x4c` (`0x112c0c40`).
 */
rome2_vfs_reg_status rome2_vfs_pack_extract_archive_flags_4_5_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 pack_entry_addr,
    uint32_t *out_flags);

/*
 * Evaluate `[stream_obj + 0x38] != 0 && expected_u64 != *(uint64_t*)(stream_obj + 0x28)`
 * matching `0x11897790` slot `+0x28` (`0x112b3190`).
 */
rome2_vfs_reg_status rome2_vfs_stream_state_u64_ne_28_38_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 stream_obj_addr,
    uint64_t expected_u64,
    int *out_result);

/*
 * Evaluate `[stream_obj + 0x2c] != 0 && expected_u64 != *(uint64_t*)(stream_obj + 0x20)`
 * matching `0x118977ec` slot `+0x28` (`0x112b30b0`).
 */
rome2_vfs_reg_status rome2_vfs_stream_state_u64_ne_20_2c_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 stream_obj_addr,
    uint64_t expected_u64,
    int *out_result);

/*
 * Decode one 56-byte (`0x38`B) `rome2_vfs_async_worker_ref_block56_32`
 * (`0x1189a454`) constructed by `0x112b2f40` without mutating `*out_block`.
 */
rome2_vfs_reg_status rome2_vfs_decode_async_worker_ref_block56_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_async_worker_ref_block56_32 *out_block);

/*
 * Decode one 44-byte (`0x2c`B) 11-slot `rome2_vfs_stream_vtable_11slot32`
 * (`0x11897790` or `0x118977ec`) without mutating `*out_vt`.
 */
rome2_vfs_reg_status rome2_vfs_decode_stream_vtable_11slot32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_stream_vtable_11slot32 *out_vt);

/*
 * Decode one 80-byte (`0x50`B) 20-slot `rome2_vfs_pack_vtable_76c0_full32`
 * (`0x118976c0`) without mutating `*out_vt`.
 */
rome2_vfs_reg_status rome2_vfs_decode_pack_vtable_76c0_full32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_pack_vtable_76c0_full32 *out_vt);

#endif
