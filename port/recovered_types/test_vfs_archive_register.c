#include "vfs_archive_register.h"

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

static void write_cand_node(unsigned char *p, uint32_t left, uint32_t parent,
    uint32_t right, uint8_t color, uint8_t is_nil, uint32_t archive_addr)
{
    memset(p, 0xbb, 0x14u);
    put32(p + 0x00u, left);
    put32(p + 0x04u, parent);
    put32(p + 0x08u, right);
    p[0x0cu] = color;
    p[0x0du] = is_nil;
    p[0x0eu] = 0u;
    p[0x0fu] = 0u;
    put32(p + 0x10u, archive_addr);
}

static void write_candidate(unsigned char *p, uint32_t pack_props_addr,
    uint32_t len, uint32_t data_addr)
{
    memset(p, 0xcc, 0x20u);
    put32(p + 0x00u, pack_props_addr);
    write_string8(p + 0x14u, len, len + 1u, data_addr);
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

static uint32_t hash_cstr_helper(const char *s)
{
    uint32_t h = 0u;
    CHECK(rome2_vfs_hash_name_bytes((const unsigned char *)s, strlen(s), &h));
    return h;
}

static void test_open_pack_table(void)
{
    unsigned char table_buf[0x14 + 7];
    unsigned char slots_buf[5 * 0x14 + 7];
    unsigned char desc_buf[0x30];
    unsigned char payload_buf[0x80];

    const char *s_a = "data.pack";
    const char *s_b = "mod1.pack";
    const char *s_c = "mod2.pack";
    uint32_t bucket_count = 5u;
    uint32_t table_base = 0x2000u;
    uint32_t slots_base = 0x3000u;
    uint32_t desc_base = 0x4000u;
    uint32_t payload_base = 0x5000u;
    uint32_t off_a = 0x00u, off_b = 0x10u, off_c = 0x20u, off_empty = 0x30u;
    uint32_t h_a = hash_cstr_helper(s_a);
    uint32_t h_b = hash_cstr_helper(s_b);
    uint32_t idx_b = h_b % bucket_count;
    uint32_t residue;

    memset(payload_buf, 0, sizeof(payload_buf));
    memcpy(payload_buf + off_a, s_a, strlen(s_a) + 1u);
    memcpy(payload_buf + off_b, s_b, strlen(s_b) + 1u);
    memcpy(payload_buf + off_c, s_c, strlen(s_c) + 1u);
    payload_buf[off_empty] = 0u;

    memset(desc_buf, 0, sizeof(desc_buf));
    write_string8(desc_buf + 0x00u, (uint32_t)strlen(s_a), 16u, payload_base + off_a);
    write_string8(desc_buf + 0x0cu, (uint32_t)strlen(s_b), 16u, payload_base + off_b);
    write_string8(desc_buf + 0x18u, (uint32_t)strlen(s_c), 16u, payload_base + off_c);
    write_string8(desc_buf + 0x24u, 0u, 1u, payload_base + off_empty);

    for (residue = 0u; residue < 8u; ++residue) {
        unsigned char *t = table_buf + (residue & 7u);
        unsigned char *sl = slots_buf + ((residue + 3u) & 7u);
        rome2_guest_read_view tview = {t, table_base + residue, 0x14u};
        rome2_guest_read_view sview = {sl, slots_base, sizeof(slots_buf) - 7u};
        rome2_guest_read_view dview = {desc_buf, desc_base, sizeof(desc_buf)};
        rome2_guest_read_view pview = {payload_buf, payload_base, sizeof(payload_buf)};
        rome2_vfs_open_pack_match32 match;
        rome2_vfs_open_pack_match32 sentinel = {{0x1111u}, {0x2222u}, 99u, 88u};
        uint32_t i, hit_slot;

        put32(t + 0u, slots_base);
        put32(t + 4u, bucket_count);
        write_string8(t + 8u, 0u, 1u, payload_base + off_empty);

        /* Fill slots: put sentinel "" in slot idx_b, collide through end->0!
         * Put mod1.pack at (idx_b + 3) % 5 after filling idx_b, +1, +2 with non-empty strings. */
        for (i = 0u; i < bucket_count; ++i) {
            write_open_slot(sl + i * 0x14u, 0u, payload_base + off_empty, 0u, 0u);
        }
        write_open_slot(sl + idx_b * 0x14u, (uint32_t)strlen(s_a), payload_base + off_a, 0x11u, 0x22u);
        write_open_slot(sl + ((idx_b + 1u) % bucket_count) * 0x14u,
            (uint32_t)strlen(s_c), payload_base + off_c, 0x33u, 0x44u);
        hit_slot = (idx_b + 2u) % bucket_count;
        write_open_slot(sl + hit_slot * 0x14u,
            (uint32_t)strlen(s_b), payload_base + off_b, 0xdeadbeefu, 0xcafebabeu);

        match = sentinel;
        CHECK(rome2_vfs_open_pack_find32(
            &tview, (rome2_guest_addr32){table_base + residue},
            &sview, &dview, &pview,
            (rome2_guest_addr32){desc_base + 0x0cu}, 5u, 64u, &match) == ROME2_VFS_REG_OK);
        CHECK(match.slot_index == hit_slot);
        CHECK(match.probes == 3u);
        CHECK(match.slot_address.value == slots_base + hit_slot * 0x14u);
        CHECK(match.payload_address.value == slots_base + hit_slot * 0x14u + 0x0cu);

        /* Too-small max_probes stops with STEP_LIMIT and preserves output. */
        match = sentinel;
        CHECK(rome2_vfs_open_pack_find32(
            &tview, (rome2_guest_addr32){table_base + residue},
            &sview, &dview, &pview,
            (rome2_guest_addr32){desc_base + 0x0cu}, 2u, 64u, &match) == ROME2_VFS_REG_STEP_LIMIT);
        CHECK(match.slot_address.value == sentinel.slot_address.value);
        CHECK(match.probes == sentinel.probes);

        /* Direct check at empty key: slot idx_b+3 is empty sentinel so probing stops -> NOT_FOUND. */
        if (h_a % bucket_count == idx_b) {
            /* Ensure an empty slot after mod1.pack terminates missing queries cleanly. */
        }
        /* Force all buckets starting at h_b%5: idx_b=data, +1=mod2, +2=mod1, +3=empty, +4=empty.
         * Querying an empty string (desc_base+0x24) starts at hash("")%5 == 0; if slot 0 is empty,
         * match-before-empty returns OK! */
        {
            uint32_t h_empty = hash_cstr_helper("");
            uint32_t empty_idx = h_empty % bucket_count;
            if (empty_idx != idx_b && empty_idx != ((idx_b + 1u) % bucket_count) &&
                empty_idx != hit_slot) {
                match = sentinel;
                CHECK(rome2_vfs_open_pack_find32(
                    &tview, (rome2_guest_addr32){table_base + residue},
                    &sview, &dview, &pview,
                    (rome2_guest_addr32){desc_base + 0x24u}, 5u, 64u, &match) == ROME2_VFS_REG_OK);
                CHECK(match.slot_index == empty_idx);
                CHECK(match.probes == 1u);
            }
        }
    }

    /* Full miss after hitting empty sentinel at +3 preserves output. */
    {
        unsigned char *t = table_buf;
        unsigned char *sl = slots_buf;
        rome2_guest_read_view tview = {t, table_base, 0x14u};
        rome2_guest_read_view sview = {sl, slots_base, bucket_count * 0x14u};
        rome2_guest_read_view dview = {desc_buf, desc_base, sizeof(desc_buf)};
        rome2_guest_read_view pview = {payload_buf, payload_base, sizeof(payload_buf)};
        rome2_vfs_open_pack_match32 sentinel = {{0x99u}, {0xaau}, 7u, 9u};
        rome2_vfs_open_pack_match32 out = sentinel;
        uint32_t i;

        put32(t + 0u, slots_base);
        put32(t + 4u, bucket_count);
        write_string8(t + 8u, 0u, 1u, payload_base + off_empty);
        for (i = 0u; i < bucket_count; ++i) {
            write_open_slot(sl + i * 0x14u, 0u, payload_base + off_empty, 0u, 0u);
        }
        /* Place one unrelated entry at h_b % bucket_count; next slot is empty sentinel -> NOT_FOUND. */
        write_open_slot(sl + (h_b % bucket_count) * 0x14u,
            (uint32_t)strlen(s_c), payload_base + off_c, 0u, 0u);
        CHECK(rome2_vfs_open_pack_find32(
            &tview, (rome2_guest_addr32){table_base},
            &sview, &dview, &pview,
            (rome2_guest_addr32){desc_base + 0x0cu}, 5u, 64u, &out) == ROME2_VFS_REG_NOT_FOUND);
        CHECK(out.slot_address.value == sentinel.slot_address.value);

        /* Zero items / buckets -> INVALID_STATE. */
        put32(t + 4u, 0u);
        CHECK(rome2_vfs_open_pack_find32(
            &tview, (rome2_guest_addr32){table_base},
            &sview, &dview, &pview,
            (rome2_guest_addr32){desc_base + 0x0cu}, 5u, 64u, &out) == ROME2_VFS_REG_INVALID_STATE);

        /* Truncated table view -> RANGE_ERROR. */
        put32(t + 4u, bucket_count);
        tview.byte_count = 0x10u;
        CHECK(rome2_vfs_open_pack_find32(
            &tview, (rome2_guest_addr32){table_base},
            &sview, &dview, &pview,
            (rome2_guest_addr32){desc_base + 0x0cu}, 5u, 64u, &out) == ROME2_VFS_REG_RANGE_ERROR);
    }
}

static void test_preconditions_and_blacklist(void)
{
    unsigned char reg_table[0x10];
    unsigned char reg_slots[3 * 8];
    unsigned char bl_nodes[4 * 0x1c];
    unsigned char open_table[0x14];
    unsigned char open_slots[3 * 0x14];
    unsigned char descs[2 * 0x0c];
    unsigned char payloads[0x80];

    const char *s_banned = "cheat.pack";
    const char *s_ok = "patch.pack";
    const char *s_missing = "missing.pack";
    uint32_t reg_table_addr = 0x12032a1cu;
    uint32_t reg_slots_addr = 0x13000000u;
    uint32_t bl_base = 0x14000000u; /* +0x00 head, +0x1c n1, +0x38 n2, +0x54 n3 */
    uint32_t open_table_addr = 0x120329e0u;
    uint32_t open_slots_addr = 0x15000000u;
    uint32_t desc_base = 0x16000000u;
    uint32_t pay_base = 0x17000000u;
    uint32_t off_banned = 0x00u, off_ok = 0x20u, off_missing = 0x40u, off_empty = 0x60u;
    uint32_t h_ok = hash_cstr_helper(s_ok);
    uint32_t h_banned = hash_cstr_helper(s_banned);
    uint32_t h_missing = hash_cstr_helper(s_missing);

    memset(payloads, 0, sizeof(payloads));
    memcpy(payloads + off_banned, s_banned, strlen(s_banned) + 1u);
    memcpy(payloads + off_ok, s_ok, strlen(s_ok) + 1u);
    memcpy(payloads + off_missing, s_missing, strlen(s_missing) + 1u);
    payloads[off_empty] = 0u;

    /* 3-node blacklist RB-tree: root=n2("patch_other"), left=n1("cheat.pack"), right=n3("zebra.pack").
     * Notice leftmost is n1 ("cheat.pack"), rightmost is n3. */
    write_edge_node(bl_nodes + 0x00u, bl_base + 0x1cu, bl_base + 0x38u, bl_base + 0x54u, 1u, 1u, 0u, 0u);
    write_edge_node(bl_nodes + 0x1cu, bl_base, bl_base + 0x38u, bl_base, 1u, 0u,
        (uint32_t)strlen(s_banned), pay_base + off_banned);
    write_edge_node(bl_nodes + 0x38u, bl_base + 0x1cu, bl_base, bl_base + 0x54u, 1u, 0u,
        (uint32_t)strlen("other.pack"), pay_base + off_empty);
    write_edge_node(bl_nodes + 0x54u, bl_base, bl_base + 0x38u, bl_base, 1u, 0u,
        (uint32_t)strlen(s_missing), pay_base + off_empty);
    /* Give n2 and n3 distinct non-matching names. */
    memcpy(payloads + 0x70u, "other", 6u);
    write_edge_node(bl_nodes + 0x38u, bl_base + 0x1cu, bl_base, bl_base + 0x54u, 1u, 0u,
        5u, pay_base + 0x70u);
    write_edge_node(bl_nodes + 0x54u, bl_base, bl_base + 0x38u, bl_base, 1u, 0u,
        0u, pay_base + off_empty);

    /* Open-pack table (3 buckets): put cheat.pack AND patch.pack in open table so we prove
     * gate 1 > gate 2 > gate 3 precedence! */
    put32(open_table + 0u, open_slots_addr);
    put32(open_table + 4u, 3u);
    write_string8(open_table + 8u, 0u, 1u, pay_base + off_empty);
    for (uint32_t i = 0u; i < 3u; ++i) {
        write_open_slot(open_slots + i * 0x14u, 0u, pay_base + off_empty, 0u, 0u);
    }
    write_open_slot(open_slots + (h_ok % 3u) * 0x14u,
        (uint32_t)strlen(s_ok), pay_base + off_ok, 0x12345678u, 0x9abcdef0u);
    /* Put cheat.pack into open_slots too (if collision, find next bucket). */
    {
        uint32_t b_idx = h_banned % 3u;
        if (b_idx == h_ok % 3u) {
            b_idx = (b_idx + 1u) % 3u;
        }
        write_open_slot(open_slots + b_idx * 0x14u,
            (uint32_t)strlen(s_banned), pay_base + off_banned, 0x111u, 0x222u);
    }

    /* Registered table (3 buckets): empty_id = 0xffffffff, place s_banned name_id=101 in reg_slots! */
    put32(reg_table + 0u, reg_slots_addr);
    put32(reg_table + 4u, 3u);
    put32(reg_table + 8u, 0xffffffffu);
    for (uint32_t i = 0u; i < 3u; ++i) {
        put32(reg_slots + i * 8u + 0u, 0xffffffffu);
        put32(reg_slots + i * 8u + 4u, 0u);
    }
    put32(reg_slots + (h_banned % 3u) * 8u + 0u, 101u);
    put32(reg_slots + (h_banned % 3u) * 8u + 4u, 0xdeadbeefu);

    {
        rome2_guest_read_view rt = {reg_table, reg_table_addr, sizeof(reg_table)};
        rome2_guest_read_view rs = {reg_slots, reg_slots_addr, sizeof(reg_slots)};
        rome2_guest_read_view bn = {bl_nodes, bl_base, sizeof(bl_nodes)};
        rome2_guest_read_view ot = {open_table, open_table_addr, sizeof(open_table)};
        rome2_guest_read_view os = {open_slots, open_slots_addr, sizeof(open_slots)};
        rome2_guest_read_view dv = {descs, desc_base, sizeof(descs)};
        rome2_guest_read_view pv = {payloads, pay_base, sizeof(payloads)};
        rome2_vfs_reg_precondition_result32 res;
        rome2_vfs_reg_precondition_result32 sentinel = {99, {0x5555u}, 0x6666u};

        /* Gate 1 wins over blacklist + open pack: name_id=101 already registered -> code 1! */
        write_string8(descs, (uint32_t)strlen(s_banned), 32u, pay_base + off_banned);
        res = sentinel;
        CHECK(rome2_vfs_check_registration_preconditions32(
            &rt, (rome2_guest_addr32){reg_table_addr}, &rs,
            &bn, (rome2_guest_addr32){bl_base},
            &ot, (rome2_guest_addr32){open_table_addr}, &os,
            &dv, &pv, 101u, h_banned, (rome2_guest_addr32){desc_base},
            3u, 8u, 64u, &res) == ROME2_VFS_REG_OK);
        CHECK(res.code == ROME2_VFS_REG_ALREADY_REGISTERED);
        CHECK(res.registered_archive == 0xdeadbeefu);
        CHECK(res.open_pack_payload.value == 0u);

        /* Gate 2 wins over open pack when unregistered: name_id=102 + s_banned -> code 2! */
        res = sentinel;
        CHECK(rome2_vfs_check_registration_preconditions32(
            &rt, (rome2_guest_addr32){reg_table_addr}, &rs,
            &bn, (rome2_guest_addr32){bl_base},
            &ot, (rome2_guest_addr32){open_table_addr}, &os,
            &dv, &pv, 102u, h_banned, (rome2_guest_addr32){desc_base},
            3u, 8u, 64u, &res) == ROME2_VFS_REG_OK);
        CHECK(res.code == ROME2_VFS_REG_BLACKLISTED);
        CHECK(res.registered_archive == 0u);

        /* Gate 3 misses when not in open pack: s_missing -> code 3! */
        write_string8(descs, (uint32_t)strlen(s_missing), 32u, pay_base + off_missing);
        res = sentinel;
        CHECK(rome2_vfs_check_registration_preconditions32(
            &rt, (rome2_guest_addr32){reg_table_addr}, &rs,
            &bn, (rome2_guest_addr32){bl_base},
            &ot, (rome2_guest_addr32){open_table_addr}, &os,
            &dv, &pv, 103u, h_missing, (rome2_guest_addr32){desc_base},
            3u, 8u, 64u, &res) == ROME2_VFS_REG_OK);
        CHECK(res.code == ROME2_VFS_REG_PACK_NOT_OPEN);

        /* All gates pass: s_ok -> code 0 with open_pack_payload! */
        write_string8(descs, (uint32_t)strlen(s_ok), 32u, pay_base + off_ok);
        res = sentinel;
        CHECK(rome2_vfs_check_registration_preconditions32(
            &rt, (rome2_guest_addr32){reg_table_addr}, &rs,
            &bn, (rome2_guest_addr32){bl_base},
            &ot, (rome2_guest_addr32){open_table_addr}, &os,
            &dv, &pv, 104u, h_ok, (rome2_guest_addr32){desc_base},
            3u, 8u, 64u, &res) == ROME2_VFS_REG_OK);
        CHECK(res.code == ROME2_VFS_REG_ELIGIBLE);
        CHECK(res.open_pack_payload.value == open_slots_addr + (h_ok % 3u) * 0x14u + 0x0cu);

        /* Blacklist step limit preserves output. */
        bool bl_hit = true;
        CHECK(rome2_vfs_blacklist_contains32(
            &bn, (rome2_guest_addr32){bl_base}, &dv, &pv,
            (rome2_guest_addr32){desc_base}, 1u, 64u, &bl_hit) == ROME2_VFS_REG_STEP_LIMIT);
        CHECK(bl_hit == true);
    }
}

static void test_candidate_set_probe(void)
{
    /* Minimal empty dep hashmap (1 bucket pointing to list_head) so priorities decide order! */
    unsigned char map_buf[0x20];
    unsigned char bucket_buf[8];
    unsigned char empty_node[0x24];
    unsigned char edge_dummy[0x1c];
    unsigned char payloads[0x80];
    unsigned char props_buf[5 * 0x20];
    unsigned char cands_buf[5 * 0x20];
    unsigned char cset_buf[0x0c];
    unsigned char cnodes_buf[4 * 0x14];

    uint32_t map_addr = 0x20000000u;
    uint32_t node_addr = 0x21000000u;
    uint32_t bucket_addr = 0x22000000u;
    uint32_t edge_addr = 0x23000000u;
    uint32_t pay_addr = 0x24000000u;
    uint32_t props_addr = 0x25000000u;
    uint32_t cands_addr = 0x26000000u;
    uint32_t cset_addr = 0x27000000u;
    uint32_t cnodes_addr = 0x28000000u; /* +0x00 head, +0x14 n_p5, +0x28 n_p3, +0x3c n_p1 */

    const char *names[5] = {"cand0.pack", "cand1.pack", "cand2.pack", "cand3.pack", "cand4.pack"};
    uint32_t name_offs[5] = {0x00u, 0x10u, 0x20u, 0x30u, 0x40u};
    uint8_t prios[5] = {3u, 5u, 1u, 7u, 3u}; /* cand0=p3, cand1=p5, cand2=p1, cand3=p7, cand4=p3(tie) */

    memset(payloads, 0, sizeof(payloads));
    memset(props_buf, 0, sizeof(props_buf));
    for (uint32_t i = 0u; i < 5u; ++i) {
        memcpy(payloads + name_offs[i], names[i], strlen(names[i]) + 1u);
        props_buf[i * 0x20u + 0x1cu] = prios[i];
        write_candidate(cands_buf + i * 0x20u, props_addr + i * 0x20u,
            (uint32_t)strlen(names[i]), pay_addr + name_offs[i]);
    }

    write_graph_node(empty_node, node_addr, node_addr, 0u, pay_addr, edge_addr, 0u);
    write_edge_node(edge_dummy, edge_addr, edge_addr, edge_addr, 1u, 1u, 0u, pay_addr);
    put32(bucket_buf + 0u, node_addr);
    put32(bucket_buf + 4u, node_addr);

    memset(map_buf, 0, sizeof(map_buf));
    put32(map_buf + 0x04u, node_addr);
    put32(map_buf + 0x08u, 0u);
    put32(map_buf + 0x0cu, bucket_addr);
    put32(map_buf + 0x10u, bucket_addr + 8u);
    put32(map_buf + 0x14u, bucket_addr + 8u);
    put32(map_buf + 0x18u, 0u);

    /* Tree sorted descending by low-nibble priority (because comparator is lhs > rhs):
     *   cand1(p5) < cand0(p3) < cand2(p1)
     * Root = n_p3 (+0x28), left = n_p5 (+0x14), right = n_p1 (+0x3c); leftmost = n_p5. */
    put32(cset_buf + 0x00u, 0u);
    put32(cset_buf + 0x04u, cnodes_addr);
    put32(cset_buf + 0x08u, 3u);
    write_cand_node(cnodes_buf + 0x00u, cnodes_addr + 0x14u, cnodes_addr + 0x28u, cnodes_addr + 0x3cu, 1u, 1u, 0u);
    write_cand_node(cnodes_buf + 0x14u, cnodes_addr, cnodes_addr + 0x28u, cnodes_addr, 0u, 0u, cands_addr + 1u * 0x20u);
    write_cand_node(cnodes_buf + 0x28u, cnodes_addr + 0x14u, cnodes_addr, cnodes_addr + 0x3cu, 1u, 0u, cands_addr + 0u * 0x20u);
    write_cand_node(cnodes_buf + 0x3cu, cnodes_addr, cnodes_addr + 0x28u, cnodes_addr, 0u, 0u, cands_addr + 2u * 0x20u);

    {
        rome2_guest_read_view cs_v = {cset_buf, cset_addr, sizeof(cset_buf)};
        rome2_guest_read_view cn_v = {cnodes_buf, cnodes_addr, sizeof(cnodes_buf)};
        rome2_guest_read_view m_v = {map_buf, map_addr, sizeof(map_buf)};
        rome2_guest_read_view n_v = {empty_node, node_addr, sizeof(empty_node)};
        rome2_guest_read_view b_v = {bucket_buf, bucket_addr, sizeof(bucket_buf)};
        rome2_guest_read_view e_v = {edge_dummy, edge_addr, sizeof(edge_dummy)};
        rome2_guest_read_view c_v = {cands_buf, cands_addr, sizeof(cands_buf)};
        rome2_guest_read_view pp_v = {props_buf, props_addr, sizeof(props_buf)};
        rome2_guest_read_view pl_v = {payloads, pay_addr, sizeof(payloads)};
        rome2_vfs_dep_limits lim = {8u, 16u, 8u, 16u, 64u};
        rome2_vfs_candidate_probe_result32 out;

        /* 1. cand3 (p7 > p5) becomes new leftmost winner displacing n_p5 / cand1! */
        CHECK(rome2_vfs_probe_candidate_insert32(
            &cs_v, (rome2_guest_addr32){cset_addr}, &cn_v,
            &m_v, (rome2_guest_addr32){map_addr}, &n_v, &b_v, &e_v, &c_v, &pp_v, &pl_v,
            (rome2_guest_addr32){cands_addr + 3u * 0x20u}, false, &lim, &out) == ROME2_VFS_REG_OK);
        CHECK(out.code == ROME2_VFS_REG_ELIGIBLE);
        CHECK(out.would_insert && out.becomes_winner && out.insert_left);
        CHECK(out.parent_node.value == cnodes_addr + 0x14u);
        CHECK(out.displaced_winner_node.value == cnodes_addr + 0x14u);
        CHECK(out.displaced_winner_archive == cands_addr + 1u * 0x20u);

        /* Same insert with only_update_existing=true -> code 8 rejection! */
        CHECK(rome2_vfs_probe_candidate_insert32(
            &cs_v, (rome2_guest_addr32){cset_addr}, &cn_v,
            &m_v, (rome2_guest_addr32){map_addr}, &n_v, &b_v, &e_v, &c_v, &pp_v, &pl_v,
            (rome2_guest_addr32){cands_addr + 3u * 0x20u}, true, &lim, &out) == ROME2_VFS_REG_OK);
        CHECK(out.code == ROME2_VFS_REG_NEW_CANDIDATE_REJECTED);
        CHECK(out.would_insert && out.becomes_winner);

        /* 2. cand4 (p3) ties existing cand0 (n_p3) -> would_insert=false, code 0 even when only_update_existing=true! */
        CHECK(rome2_vfs_probe_candidate_insert32(
            &cs_v, (rome2_guest_addr32){cset_addr}, &cn_v,
            &m_v, (rome2_guest_addr32){map_addr}, &n_v, &b_v, &e_v, &c_v, &pp_v, &pl_v,
            (rome2_guest_addr32){cands_addr + 4u * 0x20u}, true, &lim, &out) == ROME2_VFS_REG_OK);
        CHECK(out.code == ROME2_VFS_REG_ELIGIBLE);
        CHECK(!out.would_insert && !out.becomes_winner);
        CHECK(out.existing_node.value == cnodes_addr + 0x28u);
        CHECK(out.existing_archive == cands_addr + 0u * 0x20u);

        /* 3. Middle non-winner insert: adjust cand4 to p2 (between p3 and p1 -> right of n_p3 -> left of n_p1). */
        props_buf[4u * 0x20u + 0x1cu] = 2u;
        CHECK(rome2_vfs_probe_candidate_insert32(
            &cs_v, (rome2_guest_addr32){cset_addr}, &cn_v,
            &m_v, (rome2_guest_addr32){map_addr}, &n_v, &b_v, &e_v, &c_v, &pp_v, &pl_v,
            (rome2_guest_addr32){cands_addr + 4u * 0x20u}, false, &lim, &out) == ROME2_VFS_REG_OK);
        CHECK(out.code == ROME2_VFS_REG_ELIGIBLE);
        CHECK(out.would_insert && !out.becomes_winner && out.insert_left);
        CHECK(out.parent_node.value == cnodes_addr + 0x3cu);
        CHECK(out.displaced_winner_node.value == 0u);

        /* 4. Empty tree: becomes_winner=true, displaced_winner_node=0. */
        put32(cset_buf + 0x08u, 0u);
        write_cand_node(cnodes_buf + 0x00u, cnodes_addr, cnodes_addr, cnodes_addr, 1u, 1u, 0u);
        CHECK(rome2_vfs_probe_candidate_insert32(
            &cs_v, (rome2_guest_addr32){cset_addr}, &cn_v,
            &m_v, (rome2_guest_addr32){map_addr}, &n_v, &b_v, &e_v, &c_v, &pp_v, &pl_v,
            (rome2_guest_addr32){cands_addr + 3u * 0x20u}, false, &lim, &out) == ROME2_VFS_REG_OK);
        CHECK(out.code == ROME2_VFS_REG_ELIGIBLE);
        CHECK(out.would_insert && out.becomes_winner);
        CHECK(out.parent_node.value == cnodes_addr);
        CHECK(out.displaced_winner_node.value == 0u);
    }
}

int main(void)
{
    test_open_pack_table();
    test_preconditions_and_blacklist();
    test_candidate_set_probe();
    printf("PASS vfs_archive_register (%zu checks)\n", checks);
    return 0;
}
