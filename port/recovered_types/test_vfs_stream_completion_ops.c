#include <stdio.h>
#include <string.h>

#include "vfs_stream_completion_ops.h"

static void put_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xffu);
    dst[1] = (uint8_t)((value >> 8u) & 0xffu);
    dst[2] = (uint8_t)((value >> 16u) & 0xffu);
    dst[3] = (uint8_t)((value >> 24u) & 0xffu);
}

static uint32_t get_u32_le(const uint8_t *src)
{
    return (uint32_t)src[0] |
           ((uint32_t)src[1] << 8u) |
           ((uint32_t)src[2] << 16u) |
           ((uint32_t)src[3] << 24u);
}

static rome2_guest_read_view make_view(const uint8_t *buf, size_t len, uint32_t base)
{
    rome2_guest_read_view v;
    v.host_base = buf;
    v.guest_base = base;
    v.byte_count = len;
    return v;
}

static int test_xor_and_page_copy(void)
{
    uint8_t src[19];
    uint8_t dst[19];
    uint8_t mem[0x40];
    uint8_t copy_out[20];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x40000000u);
    rome2_guest_addr32 src_addr;
    rome2_guest_addr32 cancel_addr;
    uint32_t key = 0u;
    size_t processed = 999u;
    uint32_t copied = 999u;
    int cancelled = 99;
    size_t i;

    for (i = 0u; i < sizeof(src); ++i) {
        src[i] = (uint8_t)(0x10u + i);
        dst[i] = 0xaau;
    }

    /* Check 1: 19B processes 16B (2 blocks), leaves tail untouched, updates key=16 */
    if (rome2_vfs_stream_xor_deobfuscate_blocks32(src, sizeof(src), dst, &key, &processed) != ROME2_VFS_REG_OK ||
        processed != 16u || key != 16u ||
        get_u32_le(dst) != (get_u32_le(src) ^ 0xbf596df2u) ||
        get_u32_le(dst + 4u) != (get_u32_le(src + 4u) ^ 0xb0bb67a6u) ||
        dst[16] != 0xaau) {
        return 1;
    }

    /* Check 2: Round-trip deobfuscation with NULL key starts at seed=0, matches dst[0..15] */
    if (rome2_vfs_stream_xor_deobfuscate_blocks32(dst, 16u, dst, NULL, &processed) != ROME2_VFS_REG_OK ||
        processed != 16u || memcmp(dst, src, 16u) != 0) {
        return 2;
    }

    /* Check 3: Error preserves outputs */
    key = 123u;
    processed = 777u;
    if (rome2_vfs_stream_xor_deobfuscate_blocks32(NULL, 8u, dst, &key, &processed) != ROME2_VFS_REG_BAD_ARGUMENT ||
        key != 123u || processed != 777u) {
        return 3;
    }

    /* Check 4: 0x100fa6d0 page-chunked copy with trailing remainder */
    for (i = 0u; i < 18u; ++i) {
        mem[i] = (uint8_t)(0x30u + i);
    }
    mem[0x30] = 0u; /* cancel flag = 0 */
    src_addr.value = 0x40000000u;
    cancel_addr.value = 0x40000030u;
    memset(copy_out, 0, sizeof(copy_out));
    if (rome2_vfs_stream_page_copy_cancellable32(&view, src_addr, 18u, 8u, cancel_addr,
                                                 copy_out, &copied, &cancelled) != ROME2_VFS_REG_OK ||
        copied != 18u || cancelled != 0 || memcmp(copy_out, mem, 18u) != 0) {
        return 4;
    }

    /* Check 5: Cancelled at entry copies 0 bytes and reports cancelled=1 */
    mem[0x30] = 1u;
    copied = 55u;
    cancelled = 0;
    if (rome2_vfs_stream_page_copy_cancellable32(&view, src_addr, 18u, 8u, cancel_addr,
                                                 copy_out, &copied, &cancelled) != ROME2_VFS_REG_OK ||
        copied != 0u || cancelled != 1) {
        return 5;
    }

    /* Check 6: Zero page_size and OOB span preserve caller outputs */
    mem[0x30] = 0u;
    copied = 44u;
    cancelled = 77;
    if (rome2_vfs_stream_page_copy_cancellable32(&view, src_addr, 18u, 0u, cancel_addr,
                                                 copy_out, &copied, &cancelled) != ROME2_VFS_REG_BAD_ARGUMENT ||
        copied != 44u || cancelled != 77) {
        return 6;
    }
    if (rome2_vfs_stream_page_copy_cancellable32(&view, src_addr, 0x80u, 8u, cancel_addr,
                                                 copy_out, &copied, &cancelled) != ROME2_VFS_REG_RANGE_ERROR ||
        copied != 44u || cancelled != 77) {
        return 7;
    }
    return 0;
}

static int test_crt_math_and_cache(void)
{
    uint8_t mem[0x60];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x50000000u);
    rome2_vfs_open_cache_entry16_32 entry;
    rome2_guest_addr32 addr;
    uint32_t out_lo = 999u, out_hi = 999u;
    uint32_t flags = 999u;

    /* Check 8: 0x11684200 __allmul fast path & cross-term full 64-bit path */
    if (rome2_vfs_crt_allmul32(0x10001u, 0u, 0x20003u, 0u, &out_lo, &out_hi) != ROME2_VFS_REG_OK ||
        out_lo != 0x00050003u || out_hi != 2u) {
        return 8;
    }
    if (rome2_vfs_crt_allmul32(0x80000001u, 1u, 3u, 2u, &out_lo, &out_hi) != ROME2_VFS_REG_OK ||
        out_lo != 0x80000003u || out_hi != 6u) {
        return 9;
    }

    /* Check 10-11: 0x11684270 __aulldiv fast path, wide divisor shift path, zero reject */
    if (rome2_vfs_crt_aulldiv32(0x00000004u, 0x00000005u, 2u, 0u, &out_lo, &out_hi) != ROME2_VFS_REG_OK ||
        out_lo != 0x80000002u || out_hi != 2u) {
        return 10;
    }
    if (rome2_vfs_crt_aulldiv32(0x00000000u, 0x00000006u, 0x80000000u, 1u, &out_lo, &out_hi) != ROME2_VFS_REG_OK ||
        out_lo != 4u || out_hi != 0u) {
        return 11;
    }
    out_lo = 11u;
    out_hi = 22u;
    if (rome2_vfs_crt_aulldiv32(10u, 0u, 0u, 0u, &out_lo, &out_hi) != ROME2_VFS_REG_BAD_ARGUMENT ||
        out_lo != 11u || out_hi != 22u) {
        return 12;
    }

    /* Check 13: 0x100f19f0 init clears zero_004 & substitutes -1 sentinel args */
    entry.unobserved_000 = 0x11223344u;
    entry.zero_004 = 0xffffffffu;
    if (rome2_vfs_open_cache_entry_init32(&entry, UINT32_MAX, 0x77u, 0xaaaabbbbu, 0xccccddddu) != ROME2_VFS_REG_OK ||
        entry.zero_004 != 0u || entry.token_lo_008 != 0xaaaabbbbu || entry.token_hi_00c != 0x77u) {
        return 13;
    }
    if (rome2_vfs_open_cache_entry_init32(&entry, 0x12u, UINT32_MAX, 0x99u, 0xeeeeffffu) != ROME2_VFS_REG_OK ||
        entry.token_lo_008 != 0x12u || entry.token_hi_00c != 0xeeeeffffu) {
        return 14;
    }

    /* Check 15-16: 0x112c0090 / 0x100ff8c0 backing pair & 0x112c0c40 bits 4/5 extractor */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x1cu, 0x50000030u); /* pack_entry + 0x1c -> carrier */
    put_u32_le(mem + 0x30u, 0x50000038u); /* carrier + 0x00 -> inner/props */
    put_u32_le(mem + 0x48u, 0x13579bdfu); /* inner + 0x08 + 0x08 = inner + 0x10 = token_lo */
    put_u32_le(mem + 0x4cu, 0x2468ace0u); /* inner + 0x08 + 0x0c = inner + 0x14 = token_hi */
    put_u32_le(mem + 0x54u, 0x00000030u); /* inner + 0x1c = flags with bits 4 & 5 */
    addr.value = 0x50000000u;
    if (rome2_vfs_pack_read_backing_pair32(&view, addr, &out_lo, &out_hi) != ROME2_VFS_REG_OK ||
        out_lo != 0x13579bdfu || out_hi != 0x2468ace0u) {
        return 15;
    }
    if (rome2_vfs_pack_extract_archive_flags_4_5_32(&view, addr, &flags) != ROME2_VFS_REG_OK ||
        flags != 3u) {
        return 16;
    }
    put_u32_le(mem + 0x54u, 0x00000010u); /* bit 4 only */
    if (rome2_vfs_pack_extract_archive_flags_4_5_32(&view, addr, &flags) != ROME2_VFS_REG_OK ||
        flags != 1u) {
        return 17;
    }
    return 0;
}

static int test_stream_predicates_and_decodes(void)
{
    uint8_t mem[0x60];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x60000000u);
    rome2_vfs_async_worker_ref_block56_32 worker_blk;
    rome2_vfs_stream_vtable_11slot32 vt11;
    rome2_vfs_pack_vtable_76c0_full32 vt20;
    rome2_guest_addr32 addr;
    int ne_res = 99;
    size_t i;

    /* Check 18-19: 0x112b3190 (+0x28/+0x38) and 0x112b30b0 (+0x20/+0x2c) predicates */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x20u, 0xabcdef01u);
    put_u32_le(mem + 0x24u, 0x12345678u);
    put_u32_le(mem + 0x28u, 0x87654321u);
    put_u32_le(mem + 0x2cu, 0x00000001u); /* active_02c = 1 for 112b30b0; also hi for 112b3190 */
    put_u32_le(mem + 0x38u, 0x00000001u); /* active_038 = 1 for 112b3190 */
    addr.value = 0x60000000u;
    if (rome2_vfs_stream_state_u64_ne_28_38_32(&view, addr, 0x0000000187654321ULL, &ne_res) != ROME2_VFS_REG_OK ||
        ne_res != 0) {
        return 18;
    }
    if (rome2_vfs_stream_state_u64_ne_20_2c_32(&view, addr, 0x12345678abcdef00ULL, &ne_res) != ROME2_VFS_REG_OK ||
        ne_res != 1) {
        return 19;
    }
    put_u32_le(mem + 0x38u, 0u);
    if (rome2_vfs_stream_state_u64_ne_28_38_32(&view, addr, 0ULL, &ne_res) != ROME2_VFS_REG_OK ||
        ne_res != 0) {
        return 19;
    }

    /* Check 20: 56B async worker ref-block decode + 44B stream vtable decode */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x00u, ROME2_VFS_REF_BLOCK_E_VTABLE32);
    put_u32_le(mem + 0x04u, 2u);
    put_u32_le(mem + 0x08u, 1u);
    put_u32_le(mem + 0x0cu, 0x60000010u);
    put_u32_le(mem + 0x34u, 0x000001a4u);
    if (rome2_vfs_decode_async_worker_ref_block56_32(&view, addr, &worker_blk) != ROME2_VFS_REG_OK ||
        worker_blk.vtable != ROME2_VFS_REF_BLOCK_E_VTABLE32 ||
        worker_blk.queue_head_00c != 0x60000010u || worker_blk.semaphore_034 != 0x1a4u) {
        return 20;
    }

    for (i = 0u; i < 20u; ++i) {
        put_u32_le(mem + i * 4u, 0x11200000u + (uint32_t)(i * 0x10u));
    }
    if (rome2_vfs_decode_stream_vtable_11slot32(&view, addr, &vt11) != ROME2_VFS_REG_OK ||
        vt11.state_u64_ne_028 != 0x112000a0u) {
        return 21;
    }
    if (rome2_vfs_decode_pack_vtable_76c0_full32(&view, addr, &vt20) != ROME2_VFS_REG_OK ||
        vt20.slot_04c_c0c40 != 0x11200130u) {
        return 21;
    }
    vt20.slot_000_ad1b0 = 0xdeadbeefu;
    addr.value = 0x60000040u; /* only 0x20B available -> RANGE_ERROR preserves vt20 */
    if (rome2_vfs_decode_pack_vtable_76c0_full32(&view, addr, &vt20) != ROME2_VFS_REG_RANGE_ERROR ||
        vt20.slot_000_ad1b0 != 0xdeadbeefu) {
        return 21;
    }
    return 0;
}

int main(void)
{
    int rc;

    rc = test_xor_and_page_copy();
    if (rc != 0) {
        fprintf(stderr, "FAIL check %d\n", rc);
        return rc;
    }
    rc = test_crt_math_and_cache();
    if (rc != 0) {
        fprintf(stderr, "FAIL check %d\n", rc);
        return rc;
    }
    rc = test_stream_predicates_and_decodes();
    if (rc != 0) {
        fprintf(stderr, "FAIL check %d\n", rc);
        return rc;
    }
    printf("vfs_stream_completion_ops_tests: 21 checks passed (0 failures)\n");
    return 0;
}
