#include <stdio.h>
#include <string.h>

#include "vfs_view_map_ops.h"

static void put_u32_le(uint8_t *dst, uint32_t value) {
    dst[0] = (uint8_t)(value & 0xffu);
    dst[1] = (uint8_t)((value >> 8u) & 0xffu);
    dst[2] = (uint8_t)((value >> 16u) & 0xffu);
    dst[3] = (uint8_t)((value >> 24u) & 0xffu);
}

static rome2_guest_read_view make_view(const uint8_t *buf, size_t len, uint32_t base) {
    rome2_guest_read_view v;
    v.host_base = buf;
    v.guest_base = base;
    v.byte_count = len;
    return v;
}

static int test_alloc_and_rebind(void) {
    uint8_t mem[0x40];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x20000000u);
    uint32_t raw_bytes = 999u;
    int aligned32 = 99;
    rome2_vfs_u32_ptr_vec32 old_v;
    rome2_vfs_u32_ptr_vec32 new_v;
    rome2_guest_addr32 new_first;
    rome2_guest_addr32 free_addr;
    uint32_t free_bytes = 999u;
    int needs_free = 99;

    /* Check 1-4: 0x101d9910 aligned-32 alloc planner */
    if (rome2_vfs_plan_u32_aligned_alloc32(0u, &raw_bytes, &aligned32) != ROME2_VFS_REG_OK ||
        raw_bytes != 0u || aligned32 != 0) {
        return 1;
    }
    if (rome2_vfs_plan_u32_aligned_alloc32(0x3ffu, &raw_bytes, &aligned32) != ROME2_VFS_REG_OK ||
        raw_bytes != 0xffcu || aligned32 != 0) {
        return 2;
    }
    if (rome2_vfs_plan_u32_aligned_alloc32(0x400u, &raw_bytes, &aligned32) != ROME2_VFS_REG_OK ||
        raw_bytes != 0x1023u || aligned32 != 1) {
        return 3;
    }
    raw_bytes = 77u;
    aligned32 = 77;
    if (rome2_vfs_plan_u32_aligned_alloc32(0x40000000u, &raw_bytes, &aligned32) != ROME2_VFS_REG_RANGE_ERROR ||
        raw_bytes != 77u || aligned32 != 77) {
        return 4;
    }

    /* Check 5-7: 0x112afb90 aligned >= 0x1000 header check & invalid gap rejection */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x1cu, 0x20000008u); /* raw base at first - 4 */
    old_v.first = 0x20000020u;
    old_v.last = 0x20000420u;
    old_v.end = 0x20001020u; /* span = 0x1000 */
    new_first.value = 0x30000000u;
    if (rome2_vfs_u32_vec_plan_rebind32(&view, &old_v, new_first, 3u, 8u, &needs_free,
                                        &free_addr, &free_bytes, &new_v) != ROME2_VFS_REG_OK ||
        needs_free != 1 || free_addr.value != 0x20000008u || free_bytes != 0x1023u ||
        new_v.first != 0x30000000u || new_v.last != 0x3000000cu || new_v.end != 0x30000020u) {
        return 5;
    }
    put_u32_le(mem + 0x1cu, 0x1fffffd0u); /* delta > 0x1f -> INVALID_STATE */
    if (rome2_vfs_u32_vec_plan_rebind32(&view, &old_v, new_first, 1u, 2u, &needs_free,
                                        &free_addr, &free_bytes, &new_v) != ROME2_VFS_REG_INVALID_STATE ||
        free_addr.value != 0x20000008u || new_v.last != 0x3000000cu) {
        return 6;
    }
    old_v.first = 0x20000000u;
    old_v.end = 0x20000200u; /* < 0x1000 direct free */
    if (rome2_vfs_u32_vec_plan_rebind32(NULL, &old_v, new_first, 0u, 4u, &needs_free,
                                        &free_addr, &free_bytes, &new_v) != ROME2_VFS_REG_OK ||
        needs_free != 1 || free_addr.value != 0x20000000u || free_bytes != 0x200u) {
        return 7;
    }
    return 0;
}

static int test_view_map_and_decodes(void) {
    uint8_t mem[0x80];
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x50000000u);
    rome2_vfs_state_ref_block32 sblk;
    rome2_vfs_pack_telemetry_mgr32 tmgr;
    rome2_guest_addr32 addr;
    uint32_t lo = 999u, hi = 999u, sub = 999u, mlen = 999u, plen = 999u;

    /* Check 8-9: 0x10102f90 granularity window alignment + overflow preservation */
    if (rome2_vfs_plan_view_map_window32(0x100012345ULL, 0x4000u, 0x10000u,
                                         &lo, &hi, &sub, &mlen, &plen) != ROME2_VFS_REG_OK ||
        hi != 1u || lo != 0x00010000u || sub != 0x2345u ||
        mlen != 0x6345u || plen != 0x10000u) {
        return 8;
    }
    if (rome2_vfs_plan_view_map_window32(0x0001ffffULL, 0xffff0000u, 0x10000u,
                                         &lo, &hi, &sub, &mlen, &plen) != ROME2_VFS_REG_RANGE_ERROR ||
        lo != 0x00010000u || plen != 0x10000u) {
        return 9;
    }

    /* Check 10-11: 44B 0x1189a444 state_ref_block decode & OOB preservation */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x00u, ROME2_VFS_REF_BLOCK_D_VTABLE32);
    put_u32_le(mem + 0x04u, 1u);
    put_u32_le(mem + 0x08u, 1u);
    put_u32_le(mem + 0x0cu, 0x118977d4u);
    put_u32_le(mem + 0x10u, 0x1234u);
    put_u32_le(mem + 0x14u, 0x60001000u);
    mem[0x18u] = 1u;
    mem[0x19u] = 0u;
    put_u32_le(mem + 0x1cu, 0x60002000u);
    mem[0x28u] = 1u;
    addr.value = 0x50000000u;
    memset(&sblk, 0, sizeof(sblk));
    if (rome2_vfs_decode_state_ref_block32(&view, addr, &sblk) != ROME2_VFS_REG_OK ||
        sblk.vtable != ROME2_VFS_REF_BLOCK_D_VTABLE32 || sblk.inner_vtable != 0x118977d4u ||
        sblk.view_box_ptr != 0x60001000u || sblk.eof_or_closed_018 != 1u ||
        sblk.handle_ptr != 0x60002000u || sblk.flag_028 != 1u) {
        return 10;
    }
    addr.value = 0x50000070u; /* truncated inside 0x2c */
    if (rome2_vfs_decode_state_ref_block32(&view, addr, &sblk) != ROME2_VFS_REG_RANGE_ERROR ||
        sblk.state_word_010 != 0x1234u) {
        return 11;
    }

    /* Check 12-13: 108B telemetry singleton 0x118976a4 decode & OOB preservation */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x00u, ROME2_VFS_TELEMETRY_MGR_VTABLE32);
    mem[0x0au] = 1u;
    put_u32_le(mem + 0x0cu, 4321u);
    put_u32_le(mem + 0x44u, ROME2_VFS_TELEMETRY_BUCKETS);
    put_u32_le(mem + 0x48u, ROME2_VFS_TELEMETRY_BUCKETS);
    put_u32_le(mem + 0x4cu, 0x70000000u);
    addr.value = 0x50000000u;
    memset(&tmgr, 0, sizeof(tmgr));
    if (rome2_vfs_decode_pack_telemetry_mgr32(&view, addr, &tmgr) != ROME2_VFS_REG_OK ||
        tmgr.vtable != ROME2_VFS_TELEMETRY_MGR_VTABLE32 || tmgr.flag_00a != 1u ||
        tmgr.process_id != 4321u || tmgr.bucket_cap_044 != 997u ||
        tmgr.buckets_04c != 0x70000000u) {
        return 12;
    }
    addr.value = 0x50000030u; /* truncated inside 0x6c */
    if (rome2_vfs_decode_pack_telemetry_mgr32(&view, addr, &tmgr) != ROME2_VFS_REG_RANGE_ERROR ||
        tmgr.process_id != 4321u) {
        return 13;
    }
    return 0;
}

static int test_string_prefetch_slot18_and_dtors(void) {
    uint8_t mem[0x60];
    uint8_t pages[5] = { 10u, 20u, 30u, 40u, 50u };
    rome2_guest_read_view view = make_view(mem, sizeof(mem), 0x80000000u);
    rome2_guest_addr32 entry;
    int found = 99;
    uint32_t acc = 999u;
    uint8_t bit = 99u;
    uint32_t free_bytes = 999u;
    rome2_vtable_address32 reset_vt = 999u;

    /* Check 14-16: 0x10e13a60 bounded ASCII substring predicate */
    if (rome2_vfs_ascii_contains_bounded("data\\units.pack", 32u, "units", 16u, &found) != ROME2_VFS_REG_OK ||
        found != 1) {
        return 14;
    }
    if (rome2_vfs_ascii_contains_bounded("", 4u, "", 4u, &found) != ROME2_VFS_REG_OK ||
        found != 0) { /* matches 10e13a67 early zero check on *haystack */
        return 15;
    }
    if (rome2_vfs_ascii_contains_bounded("abc", 2u, "a", 4u, &found) != ROME2_VFS_REG_RANGE_ERROR ||
        found != 0) {
        return 16;
    }

    /* Check 17: 0x10115900 page-stride accumulator + zero-stride rejection */
    if (rome2_vfs_prefetch_pages_sum32(pages, 5u, 2u, 100u, &acc) != ROME2_VFS_REG_OK ||
        acc != (100u + 10u + 30u + 50u)) {
        return 17;
    }
    if (rome2_vfs_prefetch_pages_sum32(pages, 5u, 0u, 1u, &acc) != ROME2_VFS_REG_BAD_ARGUMENT ||
        acc != 190u) {
        return 18;
    }

    /* Check 19: 0x112c9540 pack_entry_vtable_76c0 slot +0x18 */
    memset(mem, 0, sizeof(mem));
    put_u32_le(mem + 0x00u + 0x1cu, 0x80000028u); /* entry->carrier */
    put_u32_le(mem + 0x28u, 0x80000030u);         /* carrier->inner */
    put_u32_le(mem + 0x30u + 0x1cu, 0x40u);       /* bit 6 set */
    entry.value = 0x80000000u;
    if (rome2_vfs_pack_entry_read_archive_bit6_32(&view, entry, &bit) != ROME2_VFS_REG_OK ||
        bit != 1u) {
        return 19;
    }
    put_u32_le(mem + 0x28u, 0u); /* null inner preserves output */
    if (rome2_vfs_pack_entry_read_archive_bit6_32(&view, entry, &bit) != ROME2_VFS_REG_INVALID_STATE ||
        bit != 1u) {
        return 20;
    }

    /* Check 21: 7 scalar deleting dtors + unknown preservation */
    if (rome2_vfs_deleting_dtor_size32(ROME2_VFS_DTOR_112ACCF0, 1u, &free_bytes, &reset_vt) != ROME2_VFS_REG_OK ||
        free_bytes != 0x20u || reset_vt != 0u ||
        rome2_vfs_deleting_dtor_size32(ROME2_VFS_DTOR_112ACD10, 1u, &free_bytes, &reset_vt) != ROME2_VFS_REG_OK ||
        free_bytes != 0x1cu ||
        rome2_vfs_deleting_dtor_size32(ROME2_VFS_DTOR_112ACD30, 1u, &free_bytes, &reset_vt) != ROME2_VFS_REG_OK ||
        free_bytes != 0x2cu ||
        rome2_vfs_deleting_dtor_size32(ROME2_VFS_DTOR_112AD1B0, 1u, &free_bytes, &reset_vt) != ROME2_VFS_REG_OK ||
        free_bytes != 0x28u || reset_vt != ROME2_VFS_PACK_ENTRY_BASE_VTABLE32 ||
        rome2_vfs_deleting_dtor_size32(ROME2_VFS_DTOR_112AD1B0, 0u, &free_bytes, &reset_vt) != ROME2_VFS_REG_OK ||
        free_bytes != 0u || reset_vt != ROME2_VFS_PACK_ENTRY_BASE_VTABLE32 ||
        rome2_vfs_deleting_dtor_size32(0xdeadbeefu, 1u, &free_bytes, &reset_vt) != ROME2_VFS_REG_INVALID_STATE ||
        free_bytes != 0u || reset_vt != ROME2_VFS_PACK_ENTRY_BASE_VTABLE32) {
        return 21;
    }
    return 0;
}

int main(void) {
    int rc;

    rc = test_alloc_and_rebind();
    if (rc != 0) {
        fprintf(stderr, "vfs_view_map_ops_tests: failed check %d\n", rc);
        return 1;
    }
    rc = test_view_map_and_decodes();
    if (rc != 0) {
        fprintf(stderr, "vfs_view_map_ops_tests: failed check %d\n", rc);
        return 1;
    }
    rc = test_string_prefetch_slot18_and_dtors();
    if (rc != 0) {
        fprintf(stderr, "vfs_view_map_ops_tests: failed check %d\n", rc);
        return 1;
    }
    printf("vfs_view_map_ops_tests: 21 checks passed (0 failures)\n");
    return 0;
}
