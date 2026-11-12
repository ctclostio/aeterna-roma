#include "vfs_archive_tree.h"
#include "vfs_name_assign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static const rome2_vfs_archive_tree_match32 sentinel_match = {
    {0xabcdef01u}, 0x13579bdfu, 0x2468ace0u, 0x11223344u, 0x55667788u, {0x99aabbccu}, 0xdeadbeefu
};

static void put32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}

static void match_unchanged(const rome2_vfs_archive_tree_match32 *out)
{
    CHECK(out->node_address.value == sentinel_match.node_address.value &&
        out->key_name == sentinel_match.key_name &&
        out->candidate_set == sentinel_match.candidate_set &&
        out->winner_node == sentinel_match.winner_node &&
        out->archive == sentinel_match.archive &&
        out->archive_table.value == sentinel_match.archive_table.value &&
        out->steps == sentinel_match.steps);
}

static void test_comparator_semantics(void)
{
    unsigned char desc_buf[64], pay_buf[64];
    rome2_guest_read_view descriptors, payloads, empty_view;
    bool less = false;
    uint32_t lhs_addr = 0x20000000u, rhs_addr = 0x20000018u;
    uint32_t lhs_pay = 0x30000000u, rhs_pay = 0x30000010u;
    uint32_t b0, b1;

    memset(desc_buf, 0xa5, sizeof desc_buf);
    memset(pay_buf, 0x5a, sizeof pay_buf);
    descriptors.host_base = desc_buf;
    descriptors.guest_base = lhs_addr;
    descriptors.byte_count = sizeof desc_buf;
    payloads.host_base = pay_buf;
    payloads.guest_base = lhs_pay;
    payloads.byte_count = sizeof pay_buf;
    empty_view.host_base = desc_buf;
    empty_view.guest_base = lhs_addr;
    empty_view.byte_count = 0u;

    /* FUN_101206f0 zero-identity rules: lhs==0 is always true (even when rhs==0),
     * rhs==0 with lhs!=0 is always false, and neither touches guest memory. */
    less = false;
    CHECK(rome2_vfs_compare_name_less32(&empty_view, &empty_view, 0u, 0u, 0u, &less) == ROME2_VFS_TREE_OK);
    CHECK(less);
    less = false;
    CHECK(rome2_vfs_compare_name_less32(&empty_view, &empty_view, 0u, rhs_addr, 0u, &less) == ROME2_VFS_TREE_OK);
    CHECK(less);
    less = true;
    CHECK(rome2_vfs_compare_name_less32(&empty_view, &empty_view, lhs_addr, 0u, 0u, &less) == ROME2_VFS_TREE_OK);
    CHECK(!less);

    /* Zero-length descriptors do not dereference payload addresses or read +4 capacity. */
    put32(desc_buf + 0u, 0u);
    put32(desc_buf + 4u, 0xffffffffu);
    put32(desc_buf + 8u, 0xdeadbeefu);
    put32(desc_buf + 24u, 0u);
    put32(desc_buf + 28u, 0x80000000u);
    put32(desc_buf + 32u, 0xfeedfaceu);
    less = true;
    CHECK(rome2_vfs_compare_name_less32(&descriptors, &empty_view, lhs_addr, rhs_addr, 0u, &less) == ROME2_VFS_TREE_OK);
    CHECK(!less);
    put32(desc_buf + 24u, 3u);
    less = false;
    CHECK(rome2_vfs_compare_name_less32(&descriptors, &empty_view, lhs_addr, rhs_addr, 0u, &less) == ROME2_VFS_TREE_OK);
    CHECK(less);

    /* Exhaustive 256x256 signed-byte comparisons at differing position 1 after shared byte 0. */
    put32(desc_buf + 0u, 2u);
    put32(desc_buf + 8u, lhs_pay);
    put32(desc_buf + 24u, 2u);
    put32(desc_buf + 32u, rhs_pay);
    pay_buf[0] = 0x41u;
    pay_buf[16] = 0x41u;
    for (b0 = 0u; b0 < 256u; ++b0) {
        for (b1 = 0u; b1 < 256u; ++b1) {
            const bool expected = (int8_t)(uint8_t)b0 < (int8_t)(uint8_t)b1;
            pay_buf[1] = (unsigned char)b0;
            pay_buf[17] = (unsigned char)b1;
            less = !expected;
            CHECK(rome2_vfs_compare_name_less32(&descriptors, &payloads, lhs_addr, rhs_addr, 2u, &less) == ROME2_VFS_TREE_OK);
            CHECK(less == expected);
        }
    }

    /* Prefix tie-breaks and max_bytes step limits. */
    memcpy(pay_buf, "rome2_pack", 10u);
    memcpy(pay_buf + 16u, "rome2_pack_extra", 16u);
    put32(desc_buf + 0u, 10u);
    put32(desc_buf + 24u, 16u);
    less = false;
    CHECK(rome2_vfs_compare_name_less32(&descriptors, &payloads, lhs_addr, rhs_addr, 10u, &less) == ROME2_VFS_TREE_OK);
    CHECK(less);
    less = true;
    CHECK(rome2_vfs_compare_name_less32(&descriptors, &payloads, rhs_addr, lhs_addr, 10u, &less) == ROME2_VFS_TREE_OK);
    CHECK(!less);
    less = true;
    CHECK(rome2_vfs_compare_name_less32(&descriptors, &payloads, lhs_addr, rhs_addr, 9u, &less) == ROME2_VFS_TREE_STEP_LIMIT);
    CHECK(less);
}

typedef struct tree_fixture {
    unsigned char header_buf[64];
    unsigned char node_buf[512];
    unsigned char desc_buf[512];
    unsigned char pay_buf[512];
    unsigned char set_buf[512];
    unsigned char cand_buf[512];
    rome2_guest_read_view headers, tree_nodes, descriptors, payloads, candidate_sets, candidate_nodes;
    rome2_guest_addr32 header;
    size_t h_off, n_off, d_off, p_off, s_off, c_off;
    uint32_t head_addr;
} tree_fixture;

static uint32_t add_string(tree_fixture *f, uint32_t index, const char *text, uint32_t len)
{
    const uint32_t desc_addr = f->descriptors.guest_base + index * 12u;
    const uint32_t pay_addr = f->payloads.guest_base + index * 16u;
    unsigned char *d = f->desc_buf + f->d_off + index * 12u;
    unsigned char *p = f->pay_buf + f->p_off + index * 16u;
    put32(d + 0u, len);
    put32(d + 4u, 0x77777777u);
    put32(d + 8u, pay_addr);
    if (len != 0u) {
        memcpy(p, text, len);
    }
    return desc_addr;
}

static uint32_t node_addr(const tree_fixture *f, uint32_t slot)
{
    return f->tree_nodes.guest_base + slot * 24u;
}

static void write_tree_node(tree_fixture *f, uint32_t slot, uint32_t left,
    uint32_t parent, uint32_t right, uint8_t color, uint8_t is_nil,
    uint32_t key, uint32_t value)
{
    unsigned char *n = f->node_buf + f->n_off + slot * 24u;
    put32(n + 0u, left);
    put32(n + 4u, parent);
    put32(n + 8u, right);
    n[12] = color;
    n[13] = is_nil;
    n[14] = 0u;
    n[15] = 0u;
    put32(n + 16u, key);
    put32(n + 20u, value);
}

static uint32_t write_candidate_winner(tree_fixture *f, uint32_t index, uint32_t archive_addr)
{
    const uint32_t set_addr = f->candidate_sets.guest_base + index * 12u;
    const uint32_t head_slot = index * 2u;
    const uint32_t win_slot = index * 2u + 1u;
    const uint32_t set_head = f->candidate_nodes.guest_base + head_slot * 20u;
    const uint32_t win_addr = f->candidate_nodes.guest_base + win_slot * 20u;
    unsigned char *s = f->set_buf + f->s_off + index * 12u;
    unsigned char *ch = f->cand_buf + f->c_off + head_slot * 20u;
    unsigned char *cw = f->cand_buf + f->c_off + win_slot * 20u;

    put32(s + 0u, 0x112e1500u);
    put32(s + 4u, set_head);
    put32(s + 8u, 1u);

    put32(ch + 0u, win_addr);
    put32(ch + 4u, win_addr);
    put32(ch + 8u, win_addr);
    ch[12] = 1u;
    ch[13] = 1u;
    put32(ch + 16u, 0u);

    put32(cw + 0u, set_head);
    put32(cw + 4u, set_head);
    put32(cw + 8u, set_head);
    cw[12] = 1u;
    cw[13] = 0u;
    put32(cw + 16u, archive_addr);
    return set_addr;
}

static uint32_t build_balanced_bst(tree_fixture *f, const uint32_t *keys,
    const uint32_t *sets, uint32_t lo, uint32_t hi, uint32_t parent)
{
    uint32_t mid, my_addr, left_addr, right_addr;
    if (lo > hi) {
        return f->head_addr;
    }
    mid = lo + (hi - lo) / 2u;
    my_addr = node_addr(f, mid + 1u);
    left_addr = mid > lo ? build_balanced_bst(f, keys, sets, lo, mid - 1u, my_addr) : f->head_addr;
    right_addr = mid < hi ? build_balanced_bst(f, keys, sets, mid + 1u, hi, my_addr) : f->head_addr;
    write_tree_node(f, mid + 1u, left_addr, parent, right_addr, 0u, 0u, keys[mid], sets[mid]);
    return my_addr;
}

static void init_tree_fixture(tree_fixture *f, size_t align, uint32_t count,
    uint32_t *present_keys, uint32_t *query_keys)
{
    static const char *const present_literals[7] = {
        "b.pack", "d.pack", "f.pack", "h.pack", "j.pack", "l.pack", "n.pack"
    };
    static const char *const miss_literals[8] = {
        "a.pack", "c.pack", "e.pack", "g.pack", "i.pack", "k.pack", "m.pack", "o.pack"
    };
    uint32_t sets[7];
    uint32_t i, root_addr;

    memset(f, 0xa5, sizeof *f);
    f->h_off = align & 7u;
    f->n_off = (align + 1u) & 7u;
    f->d_off = (align + 2u) & 7u;
    f->p_off = (align + 3u) & 7u;
    f->s_off = (align + 4u) & 7u;
    f->c_off = (align + 5u) & 7u;

    f->header.value = 0x12032950u + (uint32_t)f->h_off;
    f->headers.host_base = f->header_buf + f->h_off;
    f->headers.guest_base = f->header.value;
    f->headers.byte_count = 8u;

    f->tree_nodes.host_base = f->node_buf + f->n_off;
    f->tree_nodes.guest_base = 0x21000000u + (uint32_t)f->n_off;
    f->tree_nodes.byte_count = (uint64_t)(count + 2u) * 24u;

    f->descriptors.host_base = f->desc_buf + f->d_off;
    f->descriptors.guest_base = 0x22000000u + (uint32_t)f->d_off;
    f->descriptors.byte_count = 16u * 12u;

    f->payloads.host_base = f->pay_buf + f->p_off;
    f->payloads.guest_base = 0x23000000u + (uint32_t)f->p_off;
    f->payloads.byte_count = 16u * 16u;

    f->candidate_sets.host_base = f->set_buf + f->s_off;
    f->candidate_sets.guest_base = 0x24000000u + (uint32_t)f->s_off;
    f->candidate_sets.byte_count = 8u * 12u;

    f->candidate_nodes.host_base = f->cand_buf + f->c_off;
    f->candidate_nodes.guest_base = 0x25000000u + (uint32_t)f->c_off;
    f->candidate_nodes.byte_count = 16u * 20u;

    f->head_addr = node_addr(f, 0u);
    for (i = 0u; i < count; ++i) {
        present_keys[i] = add_string(f, i, present_literals[i], 6u);
        sets[i] = write_candidate_winner(f, i, 0x31000000u + i * 0x100u);
    }
    for (i = 0u; i <= count; ++i) {
        query_keys[i] = add_string(f, 8u + i, miss_literals[i], 6u);
    }
    root_addr = count == 0u ? f->head_addr : build_balanced_bst(f, present_keys, sets, 0u, count - 1u, f->head_addr);
    write_tree_node(f, 0u, count == 0u ? f->head_addr : node_addr(f, 1u),
        root_addr, count == 0u ? f->head_addr : node_addr(f, count), 1u, 1u, 0u, 0u);
    put32(f->header_buf + f->h_off + 0u, f->head_addr);
    put32(f->header_buf + f->h_off + 4u, count);
}

static void test_exhaustive_bst_search(void)
{
    size_t align;
    uint32_t count, i;
    for (align = 0u; align < 8u; ++align) {
        for (count = 0u; count <= 7u; ++count) {
            tree_fixture f;
            uint32_t present[7], misses[8];
            rome2_vfs_archive_tree_match32 out;

            init_tree_fixture(&f, align, count, present, misses);

            /* Every present key matches both with and without archive-table resolution. */
            for (i = 0u; i < count; ++i) {
                const uint32_t expected_archive = 0x31000000u + i * 0x100u;
                out = sentinel_match;
                CHECK(rome2_vfs_search_archive_tree32(
                    &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
                    NULL, NULL, present[i], 8u, 16u, false, &out) == ROME2_VFS_TREE_OK);
                CHECK(out.node_address.value == node_addr(&f, i + 1u));
                CHECK(out.key_name == present[i]);
                CHECK(out.candidate_set == f.candidate_sets.guest_base + i * 12u);
                CHECK(out.winner_node == 0u && out.archive == 0u && out.archive_table.value == 0u);
                CHECK(out.steps >= 1u && out.steps <= count);

                out = sentinel_match;
                CHECK(rome2_vfs_search_archive_tree32(
                    &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
                    &f.candidate_sets, &f.candidate_nodes, present[i], 8u, 16u, true, &out) == ROME2_VFS_TREE_OK);
                CHECK(out.node_address.value == node_addr(&f, i + 1u));
                CHECK(out.key_name == present[i]);
                CHECK(out.archive == expected_archive);
                CHECK(out.archive_table.value == expected_archive + 4u);
            }

            /* Every miss key (before min, between keys, after max) and query_name==0 fails cleanly. */
            for (i = 0u; i <= count; ++i) {
                out = sentinel_match;
                CHECK(rome2_vfs_search_archive_tree32(
                    &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
                    &f.candidate_sets, &f.candidate_nodes, misses[i], 8u, 16u, true, &out) == ROME2_VFS_TREE_NOT_FOUND);
                match_unchanged(&out);
            }
            out = sentinel_match;
            CHECK(rome2_vfs_search_archive_tree32(
                &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
                &f.candidate_sets, &f.candidate_nodes, 0u, 8u, 16u, true, &out) == ROME2_VFS_TREE_NOT_FOUND);
            match_unchanged(&out);
        }
    }

    /* Even if a node in the tree has key==0, query_name==0 still fails the post-loop
     * FUN_101206f0(query, candidate.key) check because compare(0, 0) returns true. */
    {
        tree_fixture f;
        uint32_t present[7], misses[8];
        rome2_vfs_archive_tree_match32 out = sentinel_match;
        init_tree_fixture(&f, 0u, 1u, present, misses);
        write_tree_node(&f, 1u, f.head_addr, f.head_addr, f.head_addr, 1u, 0u, 0u,
            f.candidate_sets.guest_base);
        CHECK(rome2_vfs_search_archive_tree32(
            &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
            &f.candidate_sets, &f.candidate_nodes, 0u, 4u, 16u, true, &out) == ROME2_VFS_TREE_NOT_FOUND);
        match_unchanged(&out);
    }

    /* Duplicate keys select the lower-bound (left-subtree) node. */
    {
        tree_fixture f;
        uint32_t present[7], misses[8];
        rome2_vfs_archive_tree_match32 out = sentinel_match;
        init_tree_fixture(&f, 2u, 3u, present, misses);
        /* Root slot 2 and left child slot 1 share key present[1]; lower-bound goes left to slot 1. */
        write_tree_node(&f, 2u, node_addr(&f, 1u), f.head_addr, node_addr(&f, 3u),
            1u, 0u, present[1], f.candidate_sets.guest_base + 12u);
        write_tree_node(&f, 1u, f.head_addr, node_addr(&f, 2u), f.head_addr,
            0u, 0u, present[1], f.candidate_sets.guest_base + 0u);
        CHECK(rome2_vfs_search_archive_tree32(
            &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
            &f.candidate_sets, &f.candidate_nodes, present[1], 4u, 16u, true, &out) == ROME2_VFS_TREE_OK);
        CHECK(out.node_address.value == node_addr(&f, 1u));
        CHECK(out.archive == 0x31000000u);
    }
}

static void test_limits_and_invalid_trees(void)
{
    tree_fixture f;
    uint32_t present[7], misses[8];
    rome2_vfs_archive_tree_match32 out = sentinel_match;
    rome2_guest_addr32 zero_addr = {0u};

    init_tree_fixture(&f, 1u, 7u, present, misses);

    /* Argument validation. */
    CHECK(rome2_vfs_search_archive_tree32(
        NULL, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 8u, 16u, true, &out) == ROME2_VFS_TREE_BAD_ARGUMENT);
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, zero_addr, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 8u, 16u, true, &out) == ROME2_VFS_TREE_BAD_ARGUMENT);
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 0u, 16u, true, &out) == ROME2_VFS_TREE_BAD_ARGUMENT);
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        NULL, &f.candidate_nodes, present[0], 8u, 16u, true, &out) == ROME2_VFS_TREE_BAD_ARGUMENT);
    match_unchanged(&out);

    /* Step limit and name-byte budget limit. */
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 2u, 16u, true, &out) == ROME2_VFS_TREE_STEP_LIMIT);
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 8u, 5u, true, &out) == ROME2_VFS_TREE_STEP_LIMIT);
    match_unchanged(&out);

    /* Self-loop cycle hits STEP_LIMIT cleanly. */
    init_tree_fixture(&f, 1u, 1u, present, misses);
    write_tree_node(&f, 1u, node_addr(&f, 1u), f.head_addr, node_addr(&f, 1u),
        0u, 0u, present[0], f.candidate_sets.guest_base);
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 5u, 16u, true, &out) == ROME2_VFS_TREE_STEP_LIMIT);
    match_unchanged(&out);

    /* Non-nil head or zero head/node pointers return INVALID_TREE. */
    init_tree_fixture(&f, 1u, 1u, present, misses);
    f.node_buf[f.n_off + 13u] = 0u;
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 4u, 16u, true, &out) == ROME2_VFS_TREE_INVALID_TREE);
    put32(f.header_buf + f.h_off, 0u);
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 4u, 16u, true, &out) == ROME2_VFS_TREE_INVALID_TREE);
    match_unchanged(&out);

    /* Empty candidate set (set_head->left == set_head) and archive+4 overflow. */
    init_tree_fixture(&f, 1u, 1u, present, misses);
    put32(f.cand_buf + f.c_off + 0u, f.candidate_nodes.guest_base);
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 4u, 16u, true, &out) == ROME2_VFS_TREE_INVALID_TREE);
    init_tree_fixture(&f, 1u, 1u, present, misses);
    put32(f.cand_buf + f.c_off + 20u + 16u, 0xfffffffdu);
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[0], 4u, 16u, true, &out) == ROME2_VFS_TREE_RANGE_ERROR);
    match_unchanged(&out);
}

static void test_end_to_end_winning_archive_probe(void)
{
    tree_fixture f;
    uint32_t present[7], misses[8];
    unsigned char arch_desc_buf[24], slot_buf[64];
    rome2_guest_read_view arch_descriptors, arch_slots;
    rome2_vfs_name_write_view32 write_slots;
    rome2_vfs_archive_tree_match32 tree_match = sentinel_match;
    rome2_vfs_name_assignment32 assigned;
    rome2_vfs_name_match32 probed;
    uint32_t hash = 0u, i;
    const uint32_t empty_marker = 0xeeeeeeeeu;
    const uint32_t expected_entry = 0x44556677u;

    init_tree_fixture(&f, 0u, 3u, present, misses);
    CHECK(rome2_vfs_hash_name_bytes((const unsigned char *)"d.pack", 6u, &hash));
    CHECK(rome2_vfs_search_archive_tree32(
        &f.headers, f.header, &f.tree_nodes, &f.descriptors, &f.payloads,
        &f.candidate_sets, &f.candidate_nodes, present[1], 8u, 16u, true, &tree_match) == ROME2_VFS_TREE_OK);
    CHECK(tree_match.archive == 0x31000100u);
    CHECK(tree_match.archive_table.value == 0x31000104u);

    /* Populate the winning archive's local name table at archive + 4 and probe it. */
    arch_descriptors.host_base = arch_desc_buf;
    arch_descriptors.guest_base = tree_match.archive_table.value;
    arch_descriptors.byte_count = 12u;
    write_slots.host_base = slot_buf;
    write_slots.guest_base = 0x32000000u;
    write_slots.byte_count = 4u * 8u;
    arch_slots.host_base = slot_buf;
    arch_slots.guest_base = write_slots.guest_base;
    arch_slots.byte_count = write_slots.byte_count;

    put32(arch_desc_buf + 0u, write_slots.guest_base);
    put32(arch_desc_buf + 4u, 4u);
    put32(arch_desc_buf + 8u, empty_marker);
    for (i = 0u; i < 4u; ++i) {
        put32(slot_buf + i * 8u, empty_marker);
        put32(slot_buf + i * 8u + 4u, 0u);
    }

    CHECK(rome2_vfs_assign_name32(
        &arch_descriptors, tree_match.archive_table, &write_slots,
        present[1], hash, expected_entry, 4u, &assigned) == ROME2_VFS_NAME_OK);
    CHECK(!assigned.matched_key);
    CHECK(rome2_vfs_probe_name32(
        &arch_descriptors, tree_match.archive_table, &arch_slots,
        present[1], hash, 4u, &probed) == ROME2_VFS_NAME_OK);
    CHECK(probed.value == expected_entry);
    CHECK(probed.value_address.value == assigned.value_address.value);
}

int main(void)
{
    test_comparator_semantics();
    test_exhaustive_bst_search();
    test_limits_and_invalid_trees();
    test_end_to_end_winning_archive_probe();
    printf("VFS archive tree: %zu checks; comparator, lower-bound search, and winning-archive table resolution verified.\n", checks);
    return 0;
}
