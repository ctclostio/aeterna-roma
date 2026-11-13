#include "vfs_pack_stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static void put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void init_entry(uint8_t *buf, uint32_t byte_size, uint32_t off_lo,
    uint32_t off_hi, uint32_t meta, uint32_t carrier, uint32_t stream_state,
    uint8_t notified)
{
    memset(buf, 0, sizeof(rome2_vfs_pack_entry_layout32));
    put32(buf + 0x00u, ROME2_VFS_PACK_ENTRY_VTABLE32);
    put32(buf + 0x04u, 0x1234u);
    put32(buf + 0x08u, byte_size);
    put32(buf + 0x10u, off_lo);
    put32(buf + 0x14u, off_hi);
    put32(buf + 0x18u, meta);
    put32(buf + 0x1cu, carrier);
    put32(buf + 0x20u, stream_state);
    buf[0x24u] = notified;
}

static void test_aligned_alloc_plan(void)
{
    rome2_vfs_aligned_alloc_plan plan;
    rome2_vfs_aligned_alloc_plan saved;
    uint32_t residue;

    memset(&plan, 0x33, sizeof(plan));
    /* requested_align < 4 clamps up to 4 (0x10102f5a..0x10102f63). */
    for (residue = 0u; residue < 16u; ++residue) {
        uint64_t raw = UINT64_C(0x10000000) + residue;
        CHECK(rome2_vfs_plan_aligned_alloc(64u, 16u, raw, &plan) == ROME2_VFS_REG_OK);
        CHECK(plan.effective_align == 16u);
        CHECK(plan.alloc_bytes == 84u);
        CHECK((plan.aligned_addr % 16u) == 0u);
        CHECK(plan.backptr_slot_addr == plan.aligned_addr - 4u);
        CHECK(plan.backptr_slot_addr >= raw);
        CHECK(plan.aligned_addr + 64u <= raw + plan.alloc_bytes);
    }

    CHECK(rome2_vfs_plan_aligned_alloc(32u, 1u, 0x20000003u, &plan) == ROME2_VFS_REG_OK);
    CHECK(plan.effective_align == 4u);
    CHECK(plan.alloc_bytes == 40u);
    CHECK((plan.aligned_addr % 4u) == 0u);
    CHECK(plan.backptr_slot_addr == plan.aligned_addr - 4u);
    CHECK(plan.backptr_slot_addr >= 0x20000003u);

    saved = plan;
    CHECK(rome2_vfs_plan_aligned_alloc(UINT32_MAX - 8u, 16u, 0x1000u, &plan) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(memcmp(&plan, &saved, sizeof(plan)) == 0);
    CHECK(rome2_vfs_plan_aligned_alloc(16u, 16u, 0u, &plan) == ROME2_VFS_REG_BAD_ARGUMENT);
    CHECK(memcmp(&plan, &saved, sizeof(plan)) == 0);
    CHECK(rome2_vfs_plan_aligned_alloc(16u, 16u, UINT64_MAX - 2u, &plan) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(memcmp(&plan, &saved, sizeof(plan)) == 0);
}

static void test_slice_clamp_and_meta(void)
{
    uint8_t entry_buf[sizeof(rome2_vfs_pack_entry_layout32)];
    uint8_t carrier_buf[0x20];
    uint8_t props_buf[sizeof(rome2_vfs_pack_props_prefix32)];
    uint8_t stream_buf[16];
    rome2_guest_read_view entry_view = { entry_buf, 0x40000000u, sizeof(entry_buf) };
    rome2_guest_read_view carrier_view = { carrier_buf, 0x41000000u, sizeof(carrier_buf) };
    rome2_guest_read_view props_view = { props_buf, 0x42000000u, sizeof(props_buf) };
    rome2_guest_read_view stream_view = { stream_buf, 0x43000000u, sizeof(stream_buf) };
    rome2_vfs_entry_slice_clamp32 clamp;
    rome2_vfs_entry_slice_clamp32 saved_clamp;
    bool has_meta = false;
    rome2_vfs_pack_entry_stream_info32 sinfo;
    rome2_vfs_pack_entry_stream_info32 saved_sinfo;

    init_entry(entry_buf, 1000u, 0x00002000u, 0x00000001u, 0x777u,
        0x41000000u, 0x43000000u, 1u);
    memset(carrier_buf, 0, sizeof(carrier_buf));
    put32(carrier_buf + 0x00u, 0x42000000u);
    memset(props_buf, 0, sizeof(props_buf));
    put32(props_buf + 0x1cu, 0x43u);
    memset(stream_buf, 0, sizeof(stream_buf));
    put32(stream_buf + 0x00u, 0x1189abcdU);

    memset(&clamp, 0x55, sizeof(clamp));
    /* Case 1: req_len < avail (clamped to req_len). */
    CHECK(rome2_vfs_entry_clamp_slice32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, 200u, 300u, &clamp) == ROME2_VFS_REG_OK);
    CHECK(clamp.clamped_len == 200u);
    CHECK(clamp.relative_offset == 300u);
    CHECK(clamp.entry_byte_size == 1000u);
    CHECK(clamp.entry_pack_offset == UINT64_C(0x0000000100002000));
    CHECK(clamp.slice_pack_offset == UINT64_C(0x000000010000212c));
    CHECK(clamp.stream_state == 0x43000000u);

    /* Case 2: req_len == 0 -> reads remaining tail [req_offset .. byte_size). */
    CHECK(rome2_vfs_entry_clamp_slice32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, 0u, 250u, &clamp) == ROME2_VFS_REG_OK);
    CHECK(clamp.clamped_len == 750u);

    /* Case 3: req_len > avail -> clamps down to avail. */
    CHECK(rome2_vfs_entry_clamp_slice32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, 500u, 900u, &clamp) == ROME2_VFS_REG_OK);
    CHECK(clamp.clamped_len == 100u);

    /* Case 4: req_offset > byte_size fails closed without changing *output. */
    saved_clamp = clamp;
    CHECK(rome2_vfs_entry_clamp_slice32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, 10u, 1001u, &clamp) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(memcmp(&clamp, &saved_clamp, sizeof(clamp)) == 0);

    /* Slot +0x18 (0x112c9540): flags bit 6 check via entry -> carrier -> pack_props. */
    CHECK(rome2_vfs_entry_has_per_entry_meta32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, &carrier_view, &props_view,
              &has_meta) == ROME2_VFS_REG_OK);
    CHECK(has_meta);
    put32(props_buf + 0x1cu, 0x03u);
    CHECK(rome2_vfs_entry_has_per_entry_meta32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, &carrier_view, &props_view,
              &has_meta) == ROME2_VFS_REG_OK);
    CHECK(!has_meta);

    has_meta = true;
    put32(carrier_buf + 0x00u, 0u);
    CHECK(rome2_vfs_entry_has_per_entry_meta32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, &carrier_view, &props_view,
              &has_meta) == ROME2_VFS_REG_INVALID_STATE);
    CHECK(has_meta);

    /* Accessor / stream state snapshot. */
    memset(&sinfo, 0, sizeof(sinfo));
    CHECK(rome2_vfs_entry_read_stream_info32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, &stream_view, &sinfo) == ROME2_VFS_REG_OK);
    CHECK(sinfo.entry_meta == 0x777u);
    CHECK(sinfo.byte_size == 1000u);
    CHECK(sinfo.has_stream_state);
    CHECK(sinfo.stream_state == 0x43000000u);
    CHECK(sinfo.stream_vtable == 0x1189abcdU);
    CHECK(sinfo.winner_notified == 1u);

    saved_sinfo = sinfo;
    put32(stream_buf + 0x00u, 0u);
    CHECK(rome2_vfs_entry_read_stream_info32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, &stream_view, &sinfo) == ROME2_VFS_REG_INVALID_STATE);
    CHECK(memcmp(&sinfo, &saved_sinfo, sizeof(sinfo)) == 0);

    put32(entry_buf + 0x20u, 0u);
    CHECK(rome2_vfs_entry_read_stream_info32(&entry_view,
              (rome2_guest_addr32){ 0x40000000u }, NULL, &sinfo) == ROME2_VFS_REG_OK);
    CHECK(!sinfo.has_stream_state);
    CHECK(sinfo.stream_vtable == 0u);
}

int main(void)
{
    test_aligned_alloc_plan();
    test_slice_clamp_and_meta();
    printf("vfs_pack_stream_tests: %zu checks passed\n", checks);
    return 0;
}
