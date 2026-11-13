#include "vfs_pack_entry.h"

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

static void test_pack_index_decoder(void)
{
    uint8_t buf[64];
    uint64_t data_offset;
    rome2_vfs_pack_index_record32 rec;
    size_t pos;

    /* Record 1: flags without bit 6 (4-byte size only), leading 0x00 padding,
     * followed by NUL-terminated path; Record 2: bit 6 set (size + meta). */
    memset(buf, 0xaa, sizeof(buf));
    pos = 0u;
    put32(buf + pos, 128u);
    pos += 4u;
    buf[pos++] = 0u;
    buf[pos++] = 0u;
    memcpy(buf + pos, "data/a.txt", 11u);
    pos += 11u;

    size_t rec2_start = pos;
    put32(buf + pos, 64u);
    pos += 4u;
    put32(buf + pos, 0x12345678u);
    pos += 4u;
    memcpy(buf + pos, "db/t", 5u);
    pos += 5u;

    data_offset = 0x100u;
    memset(&rec, 0x55, sizeof(rec));
    CHECK(rome2_vfs_decode_pack_index_record(buf, pos, 0u, 0x03u, 0x99u, 64u,
              &data_offset, &rec) == ROME2_VFS_REG_OK);
    CHECK(rec.byte_size == 128u);
    CHECK(rec.entry_meta == 0x99u);
    CHECK(rec.data_offset == 0x100u);
    CHECK(rec.path_offset == 6u);
    CHECK(rec.path_length == 10u);
    CHECK(memcmp(buf + rec.path_offset, "data/a.txt", rec.path_length) == 0);
    CHECK(rec.next_cursor == rec2_start);
    CHECK(data_offset == 0x180u);

    CHECK(rome2_vfs_decode_pack_index_record(buf, pos, rec.next_cursor, 0x43u, 0x99u, 64u,
              &data_offset, &rec) == ROME2_VFS_REG_OK);
    CHECK(rec.byte_size == 64u);
    CHECK(rec.entry_meta == 0x12345678u);
    CHECK(rec.data_offset == 0x180u);
    CHECK(rec.path_length == 4u);
    CHECK(memcmp(buf + rec.path_offset, "db/t", rec.path_length) == 0);
    CHECK(rec.next_cursor == pos);
    CHECK(data_offset == 0x1c0u);

    /* Non-OK error paths must preserve *io_data_offset and *out_record. */
    rome2_vfs_pack_index_record32 sentinel = rec;
    uint64_t saved_offset = UINT64_MAX - 10u;
    uint8_t bad_overflow[16];
    put32(bad_overflow, 20u);
    memcpy(bad_overflow + 4u, "x", 2u);
    CHECK(rome2_vfs_decode_pack_index_record(bad_overflow, 6u, 0u, 0u, 0u, 16u,
              &saved_offset, &rec) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(saved_offset == UINT64_MAX - 10u);
    CHECK(memcmp(&rec, &sentinel, sizeof(rec)) == 0);

    uint8_t no_nul[12];
    put32(no_nul, 4u);
    memcpy(no_nul + 4u, "abcd", 4u);
    CHECK(rome2_vfs_decode_pack_index_record(no_nul, 8u, 0u, 0u, 0u, 16u,
              &saved_offset, &rec) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(memcmp(&rec, &sentinel, sizeof(rec)) == 0);

    CHECK(rome2_vfs_decode_pack_index_record(buf, pos, 0u, 0u, 0u, 4u,
              &saved_offset, &rec) == ROME2_VFS_REG_STEP_LIMIT);
    CHECK(memcmp(&rec, &sentinel, sizeof(rec)) == 0);

    uint8_t only_zeroes[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    CHECK(rome2_vfs_decode_pack_index_record(only_zeroes, 8u, 0u, 0u, 0u, 16u,
              &saved_offset, &rec) == ROME2_VFS_REG_RANGE_ERROR);

    CHECK(rome2_vfs_decode_pack_index_record(NULL, 8u, 0u, 0u, 0u, 16u,
              &saved_offset, &rec) == ROME2_VFS_REG_BAD_ARGUMENT);
}

static void test_pack_props_and_entry_vtable(void)
{
    uint8_t props_buf[sizeof(rome2_vfs_pack_props_prefix32)];
    rome2_guest_read_view props_view = { props_buf, 0x30000000u, sizeof(props_buf) };
    rome2_vfs_pack_props_prefix_info32 pinfo;

    memset(props_buf, 0, sizeof(props_buf));
    put32(props_buf + 0x00u, 0x111u);
    put32(props_buf + 0x04u, 0u);
    put32(props_buf + 0x1cu, 0x43u);
    put32(props_buf + 0x24u, 0x5000u);
    put32(props_buf + 0x28u, 12u);
    put32(props_buf + 0x2cu, 512u);
    put32(props_buf + 0x30u, 0x777u);
    put32(props_buf + 0x34u, 8u);
    put32(props_buf + 0x38u, 16u);
    put32(props_buf + 0x3cu, 0x31000000u);
    props_buf[0x40u] = 1u;

    memset(&pinfo, 0xcc, sizeof(pinfo));
    CHECK(rome2_vfs_pack_props_read_prefix32(&props_view,
              (rome2_guest_addr32){ 0x30000000u }, &pinfo) == ROME2_VFS_REG_OK);
    CHECK(pinfo.file_handle == 0x111u);
    CHECK(pinfo.last_error == 0u);
    CHECK(pinfo.open_ok);
    CHECK(pinfo.low_nibble_01c == 3u);
    CHECK(pinfo.has_per_entry_meta);
    CHECK(pinfo.header_base == 0x5000u);
    CHECK(pinfo.entry_count == 12u);
    CHECK(pinfo.index_bytes == 512u);
    CHECK(pinfo.default_entry_meta == 0x777u);
    CHECK(pinfo.pack_path_len == 8u);
    CHECK(pinfo.pack_path_cap == 16u);
    CHECK(pinfo.pack_path_ptr == 0x31000000u);
    CHECK(pinfo.flag_040 == 1u);

    rome2_vfs_pack_props_prefix_info32 saved_pinfo = pinfo;
    CHECK(rome2_vfs_pack_props_read_prefix32(&props_view,
              (rome2_guest_addr32){ 0x30000004u }, &pinfo) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(memcmp(&pinfo, &saved_pinfo, sizeof(pinfo)) == 0);

    /* Pack entry 0x28 object + winner notification (+0x34 = 0x112d2900). */
    uint8_t entry_buf[sizeof(rome2_vfs_pack_entry_layout32)];
    rome2_guest_read_view entry_rview = { entry_buf, 0x40000000u, sizeof(entry_buf) };
    rome2_vfs_guest_write_view32 entry_wview = { entry_buf, 0x40000000u, sizeof(entry_buf) };
    rome2_vfs_pack_entry_info32 einfo;

    memset(entry_buf, 0xee, sizeof(entry_buf));
    put32(entry_buf + 0x00u, ROME2_VFS_PACK_ENTRY_VTABLE32);
    put32(entry_buf + 0x04u, 0x4242u);
    put32(entry_buf + 0x08u, 4096u);
    put32(entry_buf + 0x10u, 0x00001000u);
    put32(entry_buf + 0x14u, 0x00000002u);
    put32(entry_buf + 0x18u, 0x99u);
    put32(entry_buf + 0x1cu, 0x41000000u);
    put32(entry_buf + 0x20u, 0u);
    entry_buf[0x24u] = 0u;

    CHECK(rome2_vfs_entry_read32(&entry_rview, (rome2_guest_addr32){ 0x40000000u },
              &einfo) == ROME2_VFS_REG_OK);
    CHECK(einfo.vtable == ROME2_VFS_PACK_ENTRY_VTABLE32);
    CHECK(einfo.name_id == 0x4242u);
    CHECK(einfo.byte_size == 4096u);
    CHECK(einfo.data_offset == UINT64_C(0x0000000200001000));
    CHECK(einfo.entry_meta == 0x99u);
    CHECK(einfo.carrier == 0x41000000u);
    CHECK(einfo.unobserved_020 == 0u);
    CHECK(einfo.winner_notified == 0u);

    CHECK(rome2_vfs_entry_notify_winner32(&entry_wview,
              (rome2_guest_addr32){ 0x40000000u }) == ROME2_VFS_REG_OK);
    CHECK(entry_buf[0x24u] == 1u);

    CHECK(rome2_vfs_entry_read32(&entry_rview, (rome2_guest_addr32){ 0x40000000u },
              &einfo) == ROME2_VFS_REG_OK);
    CHECK(einfo.winner_notified == 1u);

    /* Wrong vtable fails closed on both read and notify without clobbering. */
    entry_buf[0x24u] = 0u;
    put32(entry_buf + 0x00u, 0xdeadbeefu);
    rome2_vfs_pack_entry_info32 saved_einfo = einfo;
    CHECK(rome2_vfs_entry_read32(&entry_rview, (rome2_guest_addr32){ 0x40000000u },
              &einfo) == ROME2_VFS_REG_INVALID_STATE);
    CHECK(memcmp(&einfo, &saved_einfo, sizeof(einfo)) == 0);
    CHECK(rome2_vfs_entry_notify_winner32(&entry_wview,
              (rome2_guest_addr32){ 0x40000000u }) == ROME2_VFS_REG_INVALID_STATE);
    CHECK(entry_buf[0x24u] == 0u);

    /* Truncated view fails closed. */
    rome2_guest_read_view short_rview = { entry_buf, 0x40000000u, 0x20u };
    rome2_vfs_guest_write_view32 short_wview = { entry_buf, 0x40000000u, 0x20u };
    CHECK(rome2_vfs_entry_read32(&short_rview, (rome2_guest_addr32){ 0x40000000u },
              &einfo) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(rome2_vfs_entry_notify_winner32(&short_wview,
              (rome2_guest_addr32){ 0x40000000u }) == ROME2_VFS_REG_RANGE_ERROR);
}

int main(void)
{
    test_pack_index_decoder();
    test_pack_props_and_entry_vtable();
    printf("vfs_pack_entry_tests: %zu checks passed\n", checks);
    return 0;
}
