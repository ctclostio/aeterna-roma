#include "vfs_archive_mount_step.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static void put32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}

static void write_string8(unsigned char *p, uint32_t len, uint32_t cap, uint32_t data_addr)
{
    put32(p + 0u, len);
    put32(p + 4u, cap);
    put32(p + 8u, data_addr);
}

static void write_open_slot(unsigned char *p, uint32_t len, uint32_t data_addr,
    uint32_t w0, uint32_t w1)
{
    write_string8(p + 0x00u, len, len + 1u, data_addr);
    put32(p + 0x0cu, w0);
    put32(p + 0x10u, w1);
}

static void write_edge_node(unsigned char *p, uint32_t left, uint32_t parent,
    uint32_t right, uint8_t color, uint8_t is_nil, uint32_t len, uint32_t data_addr)
{
    memset(p, 0xaa, 0x1cu);
    put32(p + 0x00u, left);
    put32(p + 0x04u, parent);
    put32(p + 0x08u, right);
    p[0x0cu] = color;
    p[0x0du] = is_nil;
    p[0x0eu] = 0u;
    p[0x0fu] = 0u;
    write_string8(p + 0x10u, len, len + 1u, data_addr);
}

static void write_graph_node(unsigned char *p, uint32_t next, uint32_t prev,
    uint32_t len, uint32_t data_addr, uint32_t tree_head, uint32_t dep_count)
{
    memset(p, 0xdd, 0x24u);
    put32(p + 0x00u, next);
    put32(p + 0x04u, prev);
    write_string8(p + 0x08u, len, len + 1u, data_addr);
    put32(p + 0x1cu, tree_head);
    put32(p + 0x20u, dep_count);
}

static void test_path_helpers(void)
{
    size_t off = 999u, len = 888u, pref = 777u;
    bool has_dir = false;
    const char *p1 = "C:\\games\\rome2\\data\\patch.pack";
    const char *p2 = "boot.pack";
    const char *p3 = "dir\\";
    const char *e1 = "ui\\units\\hero.png";
    const char *e2 = "\\root_file.txt";
    const char *e3 = "plain.lua";

    CHECK(rome2_vfs_archive_leaf_name(p1, strlen(p1), 64u, &off, &len) == ROME2_VFS_REG_OK);
    CHECK(off == 20u);
    CHECK(len == 10u);
    CHECK(memcmp(p1 + off, "patch.pack", len) == 0);

    CHECK(rome2_vfs_archive_leaf_name(p2, strlen(p2), 64u, &off, &len) == ROME2_VFS_REG_OK);
    CHECK(off == 0u && len == 9u);

    CHECK(rome2_vfs_archive_leaf_name(p3, strlen(p3), 64u, &off, &len) == ROME2_VFS_REG_OK);
    CHECK(off == 4u && len == 0u);

    CHECK(rome2_vfs_archive_leaf_name("", 0u, 64u, &off, &len) == ROME2_VFS_REG_OK);
    CHECK(off == 0u && len == 0u);

    off = 123u;
    len = 456u;
    CHECK(rome2_vfs_archive_leaf_name(p1, strlen(p1), 10u, &off, &len) == ROME2_VFS_REG_STEP_LIMIT);
    CHECK(off == 123u && len == 456u);
    CHECK(rome2_vfs_archive_leaf_name(NULL, 1u, 10u, &off, &len) == ROME2_VFS_REG_BAD_ARGUMENT);
    CHECK(off == 123u && len == 456u);

    CHECK(rome2_vfs_entry_dir_prefix(e1, strlen(e1), 64u, &pref, &has_dir) == ROME2_VFS_REG_OK);
    CHECK(has_dir && pref == 8u);
    CHECK(memcmp(e1, "ui\\units", pref) == 0);

    CHECK(rome2_vfs_entry_dir_prefix(e2, strlen(e2), 64u, &pref, &has_dir) == ROME2_VFS_REG_OK);
    CHECK(has_dir && pref == 0u);

    CHECK(rome2_vfs_entry_dir_prefix(e3, strlen(e3), 64u, &pref, &has_dir) == ROME2_VFS_REG_OK);
    CHECK(!has_dir && pref == 0u);

    pref = 55u;
    has_dir = true;
    CHECK(rome2_vfs_entry_dir_prefix(e1, strlen(e1), 5u, &pref, &has_dir) == ROME2_VFS_REG_STEP_LIMIT);
    CHECK(pref == 55u && has_dir);
    CHECK(rome2_vfs_entry_dir_prefix(NULL, 1u, 5u, &pref, &has_dir) == ROME2_VFS_REG_BAD_ARGUMENT);
    CHECK(pref == 55u && has_dir);
}

static void test_pack_props_gate(void)
{
    unsigned char cand_buf[0x24];
    unsigned char props_buf[0x20];
    rome2_guest_read_view cand_view = { cand_buf, 0x30000000u, sizeof(cand_buf) };
    rome2_guest_read_view props_view = { props_buf, 0x30010000u, sizeof(props_buf) };
    rome2_guest_addr32 cand_addr = { 0x30000000u };
    rome2_vfs_pack_props_gate32 gate;

    memset(cand_buf, 0, sizeof(cand_buf));
    memset(props_buf, 0, sizeof(props_buf));
    put32(cand_buf + 0x00u, 0x30010000u);
    props_buf[0x1cu] = 0x53u;

    CHECK(rome2_vfs_carrier_pack_props_gate32(&cand_view,
        cand_addr, &props_view, &gate) == ROME2_VFS_REG_OK);
    CHECK(gate.pack_props_addr == 0x30010000u);
    CHECK(gate.low_nibble_01c == 3u);
    CHECK(gate.is_type3 && !gate.is_type4);

    props_buf[0x1cu] = 0xa4u;
    CHECK(rome2_vfs_carrier_pack_props_gate32(&cand_view,
        cand_addr, &props_view, &gate) == ROME2_VFS_REG_OK);
    CHECK(gate.low_nibble_01c == 4u);
    CHECK(!gate.is_type3 && gate.is_type4);

    props_buf[0x1cu] = 0x22u;
    CHECK(rome2_vfs_carrier_pack_props_gate32(&cand_view,
        cand_addr, &props_view, &gate) == ROME2_VFS_REG_OK);
    CHECK(gate.low_nibble_01c == 2u);
    CHECK(!gate.is_type3 && !gate.is_type4);

    gate.low_nibble_01c = 9u;
    props_view.byte_count = 0x1cu;
    CHECK(rome2_vfs_carrier_pack_props_gate32(&cand_view,
        cand_addr, &props_view, &gate) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(gate.low_nibble_01c == 9u);

    put32(cand_buf + 0x00u, 0u);
    CHECK(rome2_vfs_carrier_pack_props_gate32(&cand_view,
        cand_addr, &props_view, &gate) == ROME2_VFS_REG_INVALID_STATE);
    CHECK(gate.low_nibble_01c == 9u);
}

static void test_carrier_name_table_scan(void)
{
    unsigned char cand_buf[0x20];
    unsigned char slots_buf[8 * 8];
    rome2_guest_read_view cand_view = { cand_buf, 0x31000000u, sizeof(cand_buf) };
    rome2_guest_read_view slots_view = { slots_buf, 0x31010000u, sizeof(slots_buf) };
    rome2_guest_addr32 cand_addr = { 0x31000000u };
    rome2_vfs_carrier_slot_match32 match;
    uint32_t i;

    memset(cand_buf, 0, sizeof(cand_buf));
    put32(cand_buf + 0x04u, 0x31010000u);
    put32(cand_buf + 0x08u, 8u);
    put32(cand_buf + 0x0cu, 0xffffffffu);

    for (i = 0u; i < 8u; ++i) {
        put32(slots_buf + i * 8u + 0u, 0xffffffffu);
        put32(slots_buf + i * 8u + 4u, 0u);
    }
    put32(slots_buf + 2u * 8u + 0u, 0x1001u);
    put32(slots_buf + 2u * 8u + 4u, 0x41000200u);
    put32(slots_buf + 6u * 8u + 0u, 0x1002u);
    put32(slots_buf + 6u * 8u + 4u, 0x41000600u);

    CHECK(rome2_vfs_carrier_next_nonempty_slot32(&cand_view,
        cand_addr, &slots_view, 0u, 16u, &match) == ROME2_VFS_REG_OK);
    CHECK(match.slot_index == 2u && match.slot_address.value == 0x31010010u &&
          match.name_id == 0x1001u && match.entry_ptr == 0x41000200u);

    CHECK(rome2_vfs_carrier_next_nonempty_slot32(&cand_view,
        cand_addr, &slots_view, match.slot_index + 1u, 16u, &match) == ROME2_VFS_REG_OK);
    CHECK(match.slot_index == 6u && match.slot_address.value == 0x31010030u &&
          match.name_id == 0x1002u && match.entry_ptr == 0x41000600u);

    match.slot_index = 77u;
    CHECK(rome2_vfs_carrier_next_nonempty_slot32(&cand_view,
        cand_addr, &slots_view, 7u, 16u, &match) == ROME2_VFS_REG_NOT_FOUND);
    CHECK(match.slot_index == 77u);

    CHECK(rome2_vfs_carrier_next_nonempty_slot32(&cand_view,
        cand_addr, &slots_view, 0u, 4u, &match) == ROME2_VFS_REG_STEP_LIMIT);
    CHECK(match.slot_index == 77u);

    put32(cand_buf + 0x04u, 0u);
    CHECK(rome2_vfs_carrier_next_nonempty_slot32(&cand_view,
        cand_addr, &slots_view, 0u, 16u, &match) == ROME2_VFS_REG_INVALID_STATE);
    CHECK(match.slot_index == 77u);
}

static void test_collect_pending_deps(void)
{
    /* Graph: mod.pack -> patch.pack -> base.pack; sound.pack is independent. */
    unsigned char map_buf[0x20];
    unsigned char nodes_buf[4 * 0x24];
    unsigned char buckets_buf[8 * 8];
    unsigned char edges_buf[4 * 0x1c];
    unsigned char open_table_buf[0x14];
    unsigned char desc_buf[5 * 0x14 + 0x10];
    unsigned char payload_buf[0x80];
    rome2_guest_read_view map_view = { map_buf, 0x32000000u, sizeof(map_buf) };
    rome2_guest_read_view nodes_view = { nodes_buf, 0x32010000u, sizeof(nodes_buf) };
    rome2_guest_read_view buckets_view = { buckets_buf, 0x32020000u, sizeof(buckets_buf) };
    rome2_guest_read_view edges_view = { edges_buf, 0x32030000u, sizeof(edges_buf) };
    rome2_guest_read_view open_tbl_view = { open_table_buf, 0x32040000u, sizeof(open_table_buf) };
    rome2_guest_read_view desc_view = { desc_buf, 0x32050000u, sizeof(desc_buf) };
    rome2_guest_read_view pay_view = { payload_buf, 0x32060000u, sizeof(payload_buf) };
    rome2_guest_addr32 map_addr = { 0x32000000u };
    rome2_guest_addr32 open_tbl_addr = { 0x32040000u };
    rome2_guest_addr32 pack_str_addr = { 0x32050000u + 5u * 0x14u };
    rome2_vfs_dep_limits limits = { 16u, 32u, 16u, 32u, 64u };
    rome2_vfs_open_pack_match32 deps[4];
    size_t count = 99u;

    const char *s_mod = "mod.pack";
    const char *s_patch = "patch.pack";
    const char *s_base = "base.pack";
    const char *s_sound = "sound.pack";
    const uint32_t a_mod = 0x32060000u;
    const uint32_t a_patch = 0x32060010u;
    const uint32_t a_base = 0x32060020u;
    const uint32_t a_sound = 0x32060030u;
    const uint32_t n_list = 0x32010000u;
    const uint32_t n_mod = 0x32010024u;
    const uint32_t n_patch = 0x32010048u;
    const uint32_t n_base = 0x3201006cu;
    const uint32_t e_mod_head = 0x32030000u;
    const uint32_t e_mod_node = 0x3203001cu;
    const uint32_t e_pat_head = 0x32030038u;
    const uint32_t e_pat_node = 0x32030054u;
    uint32_t b_idx;

    memset(payload_buf, 0, sizeof(payload_buf));
    memcpy(payload_buf + 0x00u, s_mod, strlen(s_mod) + 1u);
    memcpy(payload_buf + 0x10u, s_patch, strlen(s_patch) + 1u);
    memcpy(payload_buf + 0x20u, s_base, strlen(s_base) + 1u);
    memcpy(payload_buf + 0x30u, s_sound, strlen(s_sound) + 1u);

    /* Open-pack slots at 0x32050000..+0x64 (5 slots): empty, patch, sound, base, mod. */
    memset(desc_buf, 0, sizeof(desc_buf));
    write_open_slot(desc_buf + 0 * 0x14u, 0u, 0u, 0u, 0u);
    write_open_slot(desc_buf + 1 * 0x14u, (uint32_t)strlen(s_patch), a_patch, 0x1111u, 1u);
    write_open_slot(desc_buf + 2 * 0x14u, (uint32_t)strlen(s_sound), a_sound, 0x2222u, 2u);
    write_open_slot(desc_buf + 3 * 0x14u, (uint32_t)strlen(s_base), a_base, 0x3333u, 3u);
    write_open_slot(desc_buf + 4 * 0x14u, (uint32_t)strlen(s_mod), a_mod, 0x4444u, 4u);
    write_string8(desc_buf + 5 * 0x14u, (uint32_t)strlen(s_mod), 16u, a_mod);

    put32(open_table_buf + 0x00u, 0x32050000u);
    put32(open_table_buf + 0x04u, 5u);
    write_string8(open_table_buf + 0x08u, 0u, 0u, 0u);

    /* Hashmap list & buckets (mask 7) */
    memset(buckets_buf, 0, sizeof(buckets_buf));
    for (b_idx = 0u; b_idx < 8u; ++b_idx) {
        put32(buckets_buf + b_idx * 8u + 0u, n_list);
        put32(buckets_buf + b_idx * 8u + 4u, n_list);
    }
    write_graph_node(nodes_buf + 0x00u, n_mod, n_base, 0u, 0u, 0u, 0u);
    write_graph_node(nodes_buf + 0x24u, n_patch, n_list, (uint32_t)strlen(s_mod), a_mod, e_mod_head, 1u);
    write_graph_node(nodes_buf + 0x48u, n_base, n_mod, (uint32_t)strlen(s_patch), a_patch, e_pat_head, 1u);
    write_graph_node(nodes_buf + 0x6cu, n_list, n_patch, (uint32_t)strlen(s_base), a_base, 0u, 0u);

    /* Map all buckets across [n_mod .. n_base] in the hash-map list span. */
    for (b_idx = 0u; b_idx < 8u; ++b_idx) {
        put32(buckets_buf + b_idx * 8u + 0u, n_mod);
        put32(buckets_buf + b_idx * 8u + 4u, n_base);
    }

    memset(map_buf, 0, sizeof(map_buf));
    put32(map_buf + 0x04u, n_list);
    put32(map_buf + 0x08u, 3u);
    put32(map_buf + 0x0cu, 0x32020000u);
    put32(map_buf + 0x10u, 0x32020040u);
    put32(map_buf + 0x14u, 0x32020040u);
    put32(map_buf + 0x18u, 7u);
    put32(map_buf + 0x1cu, 8u);

    write_edge_node(edges_buf + 0 * 0x1cu, e_mod_node, e_mod_head, e_mod_node, 1u, 1u, 0u, 0u);
    write_edge_node(edges_buf + 1 * 0x1cu, e_mod_head, e_mod_head, e_mod_head, 0u, 0u, (uint32_t)strlen(s_patch), a_patch);
    write_edge_node(edges_buf + 2 * 0x1cu, e_pat_node, e_pat_head, e_pat_node, 1u, 1u, 0u, 0u);
    write_edge_node(edges_buf + 3 * 0x1cu, e_pat_head, e_pat_head, e_pat_head, 0u, 0u, (uint32_t)strlen(s_base), a_base);

    CHECK(rome2_vfs_collect_pending_deps32(&map_view, map_addr,
        &nodes_view, &buckets_view, &edges_view, &open_tbl_view,
        open_tbl_addr, &desc_view, &pay_view,
        pack_str_addr, &limits, 16u, deps, 4u, &count) == ROME2_VFS_REG_OK);
    CHECK(count == 2u);
    CHECK(deps[0].slot_index == 1u && deps[0].payload_address.value == 0x32050014u + 0x0cu);
    CHECK(deps[1].slot_index == 3u && deps[1].payload_address.value == 0x3205003cu + 0x0cu);

    /* Non-OK overflow must leave deps and count completely untouched. */
    deps[0].slot_index = 0xdeadbeefu;
    count = 0xcafebabeu;
    CHECK(rome2_vfs_collect_pending_deps32(&map_view, map_addr,
        &nodes_view, &buckets_view, &edges_view, &open_tbl_view,
        open_tbl_addr, &desc_view, &pay_view,
        pack_str_addr, &limits, 16u, deps, 1u, &count) == ROME2_VFS_REG_RANGE_ERROR);
    CHECK(deps[0].slot_index == 0xdeadbeefu);
    CHECK(count == 0xcafebabeu);

    /* Limit on open buckets stops before inspecting slots. */
    CHECK(rome2_vfs_collect_pending_deps32(&map_view, map_addr,
        &nodes_view, &buckets_view, &edges_view, &open_tbl_view,
        open_tbl_addr, &desc_view, &pay_view,
        pack_str_addr, &limits, 4u, deps, 4u, &count) == ROME2_VFS_REG_STEP_LIMIT);
    CHECK(count == 0xcafebabeu);

    /* Recursive dependency registration exit-code gate: only 0 and 1 continue. */
    CHECK(rome2_vfs_dep_status_acceptable(0u));
    CHECK(rome2_vfs_dep_status_acceptable(1u));
    CHECK(!rome2_vfs_dep_status_acceptable(2u));
    CHECK(!rome2_vfs_dep_status_acceptable(3u));
    CHECK(!rome2_vfs_dep_status_acceptable(8u));
}

int main(void)
{
    test_path_helpers();
    test_pack_props_gate();
    test_carrier_name_table_scan();
    test_collect_pending_deps();
    printf("vfs_archive_mount_step checks: %zu\n", checks);
    return 0;
}
