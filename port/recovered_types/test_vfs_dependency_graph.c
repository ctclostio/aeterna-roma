#include "vfs_dependency_graph.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static const rome2_vfs_dep_hashmap_match32 sentinel_match = {
    0xabcdef01u, 0x13579bdfu, 0x2468ace0u, 0xdeadbeefu
};

static void put32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}

static void match_unchanged(const rome2_vfs_dep_hashmap_match32 *out)
{
    CHECK(out->node == sentinel_match.node &&
        out->list_head == sentinel_match.list_head &&
        out->bucket_index == sentinel_match.bucket_index &&
        out->chain_steps == sentinel_match.chain_steps);
}

static uint32_t hash_cstr_helper(const char *s)
{
    uint32_t h = 0u;
    CHECK(rome2_vfs_hash_name_bytes((const unsigned char *)s, strlen(s), &h));
    return h;
}

static void write_string8(unsigned char *desc_ptr, uint32_t len, uint32_t cap, uint32_t data_addr)
{
    put32(desc_ptr + 0u, len);
    put32(desc_ptr + 4u, cap);
    put32(desc_ptr + 8u, data_addr);
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
    memset(p, 0xbb, 0x24u);
    put32(p + 0x00u, next);
    put32(p + 0x04u, prev);
    write_string8(p + 0x08u, len, len + 1u, data_addr);
    put32(p + 0x14u, 0u);
    put32(p + 0x18u, 0u);
    put32(p + 0x1cu, tree_head);
    put32(p + 0x20u, dep_count);
}

static void test_string8_equals(void)
{
    unsigned char desc[64], pay[64];
    rome2_guest_read_view dv, pv, empty_v;
    bool eq = false;
    rome2_guest_addr32 lhs = {0x20000000u}, rhs = {0x20000010u};

    memset(desc, 0xa5, sizeof desc);
    memset(pay, 0x5a, sizeof pay);
    dv.host_base = desc;
    dv.guest_base = lhs.value;
    dv.byte_count = sizeof desc;
    pv.host_base = pay;
    pv.guest_base = 0x30000000u;
    pv.byte_count = sizeof pay;
    empty_v.host_base = desc;
    empty_v.guest_base = lhs.value;
    empty_v.byte_count = 0u;

    /* Different lengths short-circuit without touching +8 or payloads. */
    write_string8(desc + 0u, 3u, 0xffffffffu, 0xdeadbeefu);
    write_string8(desc + 16u, 4u, 0x80000000u, 0xfeedfaceu);
    eq = true;
    CHECK(rome2_vfs_string8_equals32(&dv, lhs, &dv, rhs, &empty_v, 0u, &eq) == ROME2_VFS_DEP_OK);
    CHECK(!eq);

    /* Zero lengths return true without touching +8 or payloads. */
    write_string8(desc + 16u, 0u, 0u, 0xfeedfaceu);
    write_string8(desc + 0u, 0u, 0u, 0xdeadbeefu);
    eq = false;
    CHECK(rome2_vfs_string8_equals32(&dv, lhs, &dv, rhs, &empty_v, 0u, &eq) == ROME2_VFS_DEP_OK);
    CHECK(eq);

    /* Non-zero byte comparison including high bytes >= 0x80. */
    memcpy(pay + 0u, "rome\xff", 5u);
    memcpy(pay + 16u, "rome\xff", 5u);
    memcpy(pay + 32u, "rome\x01", 5u);
    write_string8(desc + 0u, 5u, 8u, 0x30000000u);
    write_string8(desc + 16u, 5u, 8u, 0x30000010u);
    eq = false;
    CHECK(rome2_vfs_string8_equals32(&dv, lhs, &dv, rhs, &pv, 5u, &eq) == ROME2_VFS_DEP_OK);
    CHECK(eq);

    write_string8(desc + 16u, 5u, 8u, 0x30000020u);
    eq = true;
    CHECK(rome2_vfs_string8_equals32(&dv, lhs, &dv, rhs, &pv, 5u, &eq) == ROME2_VFS_DEP_OK);
    CHECK(!eq);

    /* max_bytes limit and error preservation. */
    eq = true;
    CHECK(rome2_vfs_string8_equals32(&dv, lhs, &dv, rhs, &pv, 4u, &eq) == ROME2_VFS_DEP_STEP_LIMIT);
    CHECK(eq);
    write_string8(desc + 16u, 5u, 8u, 0u);
    eq = false;
    CHECK(rome2_vfs_string8_equals32(&dv, lhs, &dv, rhs, &pv, 5u, &eq) == ROME2_VFS_DEP_RANGE_ERROR);
    CHECK(!eq);
    CHECK(rome2_vfs_string8_equals32(NULL, lhs, &dv, rhs, &pv, 5u, &eq) == ROME2_VFS_DEP_BAD_ARGUMENT);
    CHECK(rome2_vfs_string8_equals32(&dv, (rome2_guest_addr32){0u}, &dv, rhs, &pv, 5u, &eq) == ROME2_VFS_DEP_BAD_ARGUMENT);
}

static void test_edge_tree_inorder(void)
{
    /* Build unbalanced 7-node BST plus sentinel_head at offset 0. */
    unsigned char buf[8 * 0x1cu];
    rome2_guest_read_view view;
    uint32_t base = 0x40000000u;
    /* Tree shape (sorted 1..7):
     *         4
     *        / \
     *       2   6
     *      / \ / \
     *     1  3 5  7 (with extra zig-zag test: move 3 under 1.right, 5 under 7.left)
     * Let's test zig-zag: root=4; 4.L=1; 1.R=2; 2.R=3; 4.R=7; 7.L=5; 5.R=6.
     */
    const uint32_t nil_addr = base;
    uint32_t addr[8];
    uint32_t cur, steps = 0u;
    int expected;
    int i;

    for (i = 0; i < 8; ++i) {
        addr[i] = base + (uint32_t)i * 0x1cu;
    }
    view.host_base = buf;
    view.guest_base = base;
    view.byte_count = sizeof buf;

    /* Sentinel: left=min(1), parent=root(4), right=max(7), is_nil=1 */
    write_edge_node(buf + 0u, addr[1], addr[4], addr[7], 1u, 1u, 0u, 0u);
    write_edge_node(buf + 1u * 0x1cu, nil_addr, addr[4], addr[2], 0u, 0u, 0u, 0u);
    write_edge_node(buf + 2u * 0x1cu, nil_addr, addr[1], addr[3], 1u, 0u, 0u, 0u);
    write_edge_node(buf + 3u * 0x1cu, nil_addr, addr[2], nil_addr, 0u, 0u, 0u, 0u);
    write_edge_node(buf + 4u * 0x1cu, addr[1], nil_addr, addr[7], 1u, 0u, 0u, 0u);
    write_edge_node(buf + 5u * 0x1cu, nil_addr, addr[7], addr[6], 0u, 0u, 0u, 0u);
    write_edge_node(buf + 6u * 0x1cu, nil_addr, addr[5], nil_addr, 1u, 0u, 0u, 0u);
    write_edge_node(buf + 7u * 0x1cu, addr[5], addr[4], nil_addr, 0u, 0u, 0u, 0u);

    cur = addr[1];
    for (expected = 1; expected <= 7; ++expected) {
        rome2_guest_addr32 next = {0u};
        CHECK(cur == addr[expected]);
        CHECK(rome2_vfs_dep_edge_next32(&view, (rome2_guest_addr32){cur}, 8u, &next, &steps) == ROME2_VFS_DEP_OK);
        cur = next.value;
    }
    CHECK(cur == nil_addr);

    /* Incrementing sentinel_head must reject as INVALID_GRAPH and preserve output. */
    {
        rome2_guest_addr32 next = {0x99887766u};
        CHECK(rome2_vfs_dep_edge_next32(&view, (rome2_guest_addr32){nil_addr}, 8u, &next, &steps) == ROME2_VFS_DEP_INVALID_GRAPH);
        CHECK(next.value == 0x99887766u);
    }

    /* Bounded upward parent walk (3 -> 2 -> 1 -> 4 needs 3 hops) hits STEP_LIMIT at budget 2. */
    {
        rome2_guest_addr32 next = {0x12345678u};
        CHECK(rome2_vfs_dep_edge_next32(&view, (rome2_guest_addr32){addr[3]}, 2u, &next, &steps) == ROME2_VFS_DEP_STEP_LIMIT);
        CHECK(next.value == 0x12345678u);
    }

    /* Cyclic downward-left chain (6.right = 7, 7.left = 7) also hits STEP_LIMIT. */
    put32(buf + 6u * 0x1cu + 8u, addr[7]);
    put32(buf + 7u * 0x1cu + 0u, addr[7]);
    {
        rome2_guest_addr32 next = {0x87654321u};
        CHECK(rome2_vfs_dep_edge_next32(&view, (rome2_guest_addr32){addr[6]}, 4u, &next, &steps) == ROME2_VFS_DEP_STEP_LIMIT);
        CHECK(next.value == 0x87654321u);
    }
}

/* Toy guest arena packing hashmap header, buckets, nodes, edges, candidates, pack_props, payloads. */
typedef struct test_arena {
    unsigned char map_buf[0x20];
    unsigned char bucket_buf[8 * 8];
    unsigned char node_buf[16 * 0x24];
    unsigned char edge_buf[32 * 0x1c];
    unsigned char cand_buf[8 * 0x20];
    unsigned char props_buf[8 * 0x20];
    unsigned char pay_buf[512];
    rome2_guest_read_view maps, buckets, nodes, edges, cands, props, pays;
    uint32_t next_pay;
} test_arena;

static void arena_init(test_arena *a)
{
    uint32_t head = 0x51000000u;
    uint32_t i;
    memset(a, 0, sizeof *a);
    a->maps.host_base = a->map_buf;     a->maps.guest_base = 0x50000000u;    a->maps.byte_count = sizeof a->map_buf;
    a->nodes.host_base = a->node_buf;   a->nodes.guest_base = 0x51000000u;   a->nodes.byte_count = sizeof a->node_buf;
    a->buckets.host_base = a->bucket_buf; a->buckets.guest_base = 0x52000000u; a->buckets.byte_count = sizeof a->bucket_buf;
    a->edges.host_base = a->edge_buf;   a->edges.guest_base = 0x53000000u;   a->edges.byte_count = sizeof a->edge_buf;
    a->cands.host_base = a->cand_buf;   a->cands.guest_base = 0x54000000u;   a->cands.byte_count = sizeof a->cand_buf;
    a->props.host_base = a->props_buf;  a->props.guest_base = 0x55000000u;  a->props.byte_count = sizeof a->props_buf;
    a->pays.host_base = a->pay_buf;     a->pays.guest_base = 0x56000000u;    a->pays.byte_count = sizeof a->pay_buf;

    put32(a->map_buf + 0x00u, 0x3f800000u);
    put32(a->map_buf + 0x04u, head);
    put32(a->map_buf + 0x08u, 0u);
    put32(a->map_buf + 0x0cu, 0x52000000u);
    put32(a->map_buf + 0x10u, 0x52000040u);
    put32(a->map_buf + 0x14u, 0x52000040u);
    put32(a->map_buf + 0x18u, 7u);
    put32(a->map_buf + 0x1cu, 8u);

    for (i = 0u; i < 8u; ++i) {
        put32(a->bucket_buf + i * 8u + 0u, head);
        put32(a->bucket_buf + i * 8u + 4u, head);
    }
    /* List head sentinel node at slot 0. */
    write_graph_node(a->node_buf, head, head, 0u, 0u, 0u, 0u);
}

static uint32_t arena_add_str(test_arena *a, const char *s)
{
    uint32_t len = (uint32_t)strlen(s);
    uint32_t addr = (uint32_t)(a->pays.guest_base + a->next_pay);
    CHECK(a->next_pay + len + 1u <= sizeof a->pay_buf);
    memcpy(a->pay_buf + a->next_pay, s, len + 1u);
    a->next_pay += len + 1u;
    return addr;
}

static void test_hashmap_collision_and_last_stop(void)
{
    test_arena a;
    uint32_t s_a, s_b, s_c, s_d;
    uint32_t b_idx;
    uint32_t n1 = 0x51000024u, n2 = 0x51000048u, n3 = 0x5100006cu, n4 = 0x51000090u;
    unsigned char qbuf[32];
    rome2_guest_read_view qv;
    rome2_vfs_dep_hashmap_match32 out = sentinel_match;
    uint32_t qhash;
    uint32_t other_b;

    arena_init(&a);
    s_a = arena_add_str(&a, "alpha.pack");
    s_b = arena_add_str(&a, "beta.pack");
    s_c = arena_add_str(&a, "gamma.pack");
    s_d = arena_add_str(&a, "delta.pack");

    qhash = hash_cstr_helper("beta.pack");
    b_idx = qhash & 7u;
    /* Chain n1(alpha) -> n2(beta) -> n3(gamma) as bucket[b_idx], with n4(delta)
     * in another bucket right after n3 in the linked list! */
    other_b = (hash_cstr_helper("delta.pack") & 7u);
    write_graph_node(a.node_buf + 1u * 0x24u, n2, 0x51000000u, 10u, s_a, 0u, 0u);
    write_graph_node(a.node_buf + 2u * 0x24u, n3, n1, 9u, s_b, 0u, 0u);
    write_graph_node(a.node_buf + 3u * 0x24u, n4, n2, 10u, s_c, 0u, 0u);
    write_graph_node(a.node_buf + 4u * 0x24u, 0x51000000u, n3, 10u, s_d, 0u, 0u);

    put32(a.bucket_buf + b_idx * 8u + 0u, n1);
    put32(a.bucket_buf + b_idx * 8u + 4u, n3);
    if (other_b != b_idx) {
        put32(a.bucket_buf + other_b * 8u + 0u, n4);
        put32(a.bucket_buf + other_b * 8u + 4u, n4);
    }

    qv.host_base = qbuf;
    qv.guest_base = 0x57000000u;
    qv.byte_count = sizeof qbuf;
    write_string8(qbuf, 9u, 16u, s_b);

    CHECK(rome2_vfs_dep_hashmap_find32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &qv, &a.pays, (rome2_guest_addr32){0x57000000u},
        8u, 32u, &out) == ROME2_VFS_DEP_OK);
    CHECK(out.node == n2);
    CHECK(out.bucket_index == b_idx);
    CHECK(out.chain_steps == 2u);

    /* Querying delta (chained right after n3's `next`) when placed artificially
     * in bucket b_idx would only fail if delta hashed to b_idx; force query to
     * hash to b_idx while having string "delta.pack" -> wait: let's test stopping
     * at last=n2! Set bucket[b_idx].last = n2; querying gamma MUST NOT see n3! */
    put32(a.bucket_buf + b_idx * 8u + 4u, n2);
    {
        uint32_t c_hash = hash_cstr_helper("gamma.pack");
        uint32_t c_idx = c_hash & 7u;
        put32(a.bucket_buf + c_idx * 8u + 0u, n1);
        put32(a.bucket_buf + c_idx * 8u + 4u, n2);
        write_string8(qbuf, 10u, 16u, s_c);
        out = sentinel_match;
        CHECK(rome2_vfs_dep_hashmap_find32(&a.maps, (rome2_guest_addr32){0x50000000u},
            &a.nodes, &a.buckets, &qv, &a.pays, (rome2_guest_addr32){0x57000000u},
            8u, 32u, &out) == ROME2_VFS_DEP_NOT_FOUND);
        match_unchanged(&out);
    }

    /* Chain budget exhaustion preserves output. */
    put32(a.bucket_buf + b_idx * 8u + 4u, n3);
    write_string8(qbuf, 9u, 16u, s_b);
    out = sentinel_match;
    CHECK(rome2_vfs_dep_hashmap_find32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &qv, &a.pays, (rome2_guest_addr32){0x57000000u},
        1u, 32u, &out) == ROME2_VFS_DEP_STEP_LIMIT);
    match_unchanged(&out);

    /* Unterminated query string triggers STEP_LIMIT. */
    {
        uint32_t nonnul = (uint32_t)(a.pays.guest_base + a.next_pay);
        memset(a.pay_buf + a.next_pay, 'x', 8u);
        write_string8(qbuf, 8u, 8u, nonnul);
        out = sentinel_match;
        CHECK(rome2_vfs_dep_hashmap_find32(&a.maps, (rome2_guest_addr32){0x50000000u},
            &a.nodes, &a.buckets, &qv, &a.pays, (rome2_guest_addr32){0x57000000u},
            8u, 4u, &out) == ROME2_VFS_DEP_STEP_LIMIT);
        match_unchanged(&out);
    }
}

typedef struct dag_node_spec {
    const char *name;
    const char *deps[2];
    uint32_t dep_count;
} dag_node_spec;

static uint32_t read32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void populate_graph(test_arena *a, const dag_node_spec *specs, uint32_t count)
{
    uint32_t head = 0x51000000u;
    uint32_t edge_cursor = 0u;
    uint32_t i;
    arena_init(a);

    for (i = 0u; i < count; ++i) {
        uint32_t str_addr = arena_add_str(a, specs[i].name);
        uint32_t len = (uint32_t)strlen(specs[i].name);
        uint32_t node_addr = 0x51000000u + (i + 1u) * 0x24u;
        uint32_t tree_head = 0x53000000u + edge_cursor * 0x1cu;
        uint32_t b_idx = hash_cstr_helper(specs[i].name) & 7u;
        uint32_t old_first = read32(a->bucket_buf + b_idx * 8u);
        uint32_t old_last = read32(a->bucket_buf + b_idx * 8u + 4u);
        uint32_t d;

        /* Prepend to list head if empty, or insert at bucket head by updating
         * global list link sequentially carefully: simpler is chaining only within
         * the same bucket when testing collision! Here put each node right after
         * previous list_head or extend existing bucket. */
        if (old_first == head) {
            uint32_t cur_head_next = read32(a->node_buf + 0u);
            write_graph_node(a->node_buf + (i + 1u) * 0x24u, cur_head_next, head,
                len, str_addr, tree_head, specs[i].dep_count);
            put32(a->node_buf + 0u, node_addr);
            put32(a->bucket_buf + b_idx * 8u + 0u, node_addr);
            put32(a->bucket_buf + b_idx * 8u + 4u, node_addr);
        } else {
            uint32_t after_last = read32(a->node_buf + (old_last - 0x51000000u));
            write_graph_node(a->node_buf + (i + 1u) * 0x24u, after_last, old_last,
                len, str_addr, tree_head, specs[i].dep_count);
            put32(a->node_buf + (old_last - 0x51000000u), node_addr);
            put32(a->bucket_buf + b_idx * 8u + 4u, node_addr);
        }

        /* Build sentinel + 0, 1, or 2 edge RB-tree nodes cleanly. */
        ++edge_cursor;
        if (specs[i].dep_count == 0u) {
            write_edge_node(a->edge_buf + (tree_head - 0x53000000u),
                tree_head, tree_head, tree_head, 1u, 1u, 0u, 0u);
        } else if (specs[i].dep_count == 1u) {
            uint32_t e0 = 0x53000000u + edge_cursor * 0x1cu;
            uint32_t d0 = arena_add_str(a, specs[i].deps[0]);
            ++edge_cursor;
            write_edge_node(a->edge_buf + (tree_head - 0x53000000u),
                e0, e0, e0, 1u, 1u, 0u, 0u);
            write_edge_node(a->edge_buf + (e0 - 0x53000000u),
                tree_head, tree_head, tree_head, 1u, 0u,
                (uint32_t)strlen(specs[i].deps[0]), d0);
        } else {
            uint32_t e0 = 0x53000000u + edge_cursor * 0x1cu;
            uint32_t e1 = 0x53000000u + (edge_cursor + 1u) * 0x1cu;
            uint32_t d0 = arena_add_str(a, specs[i].deps[0]);
            uint32_t d1 = arena_add_str(a, specs[i].deps[1]);
            edge_cursor += 2u;
            write_edge_node(a->edge_buf + (tree_head - 0x53000000u),
                e0, e0, e1, 1u, 1u, 0u, 0u);
            write_edge_node(a->edge_buf + (e0 - 0x53000000u),
                tree_head, tree_head, e1, 1u, 0u,
                (uint32_t)strlen(specs[i].deps[0]), d0);
            write_edge_node(a->edge_buf + (e1 - 0x53000000u),
                tree_head, e0, tree_head, 0u, 0u,
                (uint32_t)strlen(specs[i].deps[1]), d1);
        }
        (void)d;
    }
}

static void test_reachability_and_cycles(void)
{
    /* Graph:
     *   mod_top.pack -> {dlc1.pack, mod_mid.pack}
     *   mod_mid.pack -> {base.pack}
     *   dlc1.pack    -> {base.pack}
     *   base.pack    -> {}
     *   orphan.pack  -> {}
     *   cyc_a.pack   -> {cyc_b.pack}
     *   cyc_b.pack   -> {cyc_a.pack}
     */
    static const dag_node_spec specs[] = {
        {"mod_top.pack", {"dlc1.pack", "mod_mid.pack"}, 2u},
        {"mod_mid.pack", {"base.pack", NULL}, 1u},
        {"dlc1.pack", {"base.pack", NULL}, 1u},
        {"base.pack", {NULL, NULL}, 0u},
        {"orphan.pack", {NULL, NULL}, 0u},
        {"cyc_a.pack", {"cyc_b.pack", NULL}, 1u},
        {"cyc_b.pack", {"cyc_a.pack", NULL}, 1u}
    };
    test_arena a;
    unsigned char qbuf[7 * 12u];
    rome2_guest_read_view qv;
    uint32_t i;
    rome2_vfs_dep_limits lim = {16u, 16u, 8u, 64u, 64u};
    bool r = false;

    populate_graph(&a, specs, 7u);
    qv.host_base = qbuf;
    qv.guest_base = 0x57000000u;
    qv.byte_count = sizeof qbuf;
    for (i = 0u; i < 7u; ++i) {
        uint32_t s = arena_add_str(&a, specs[i].name);
        write_string8(qbuf + i * 12u, (uint32_t)strlen(specs[i].name), 16u, s);
    }

    /* Transitive reachability: mod_top -> base (depth 1). */
    r = false;
    CHECK(rome2_vfs_dep_reachable32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &qv, &a.pays,
        (rome2_guest_addr32){0x57000000u + 0u * 12u},
        (rome2_guest_addr32){0x57000000u + 3u * 12u},
        &lim, &r) == ROME2_VFS_DEP_OK);
    CHECK(r);

    /* Reverse direction is unreachable. */
    r = true;
    CHECK(rome2_vfs_dep_reachable32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &qv, &a.pays,
        (rome2_guest_addr32){0x57000000u + 3u * 12u},
        (rome2_guest_addr32){0x57000000u + 0u * 12u},
        &lim, &r) == ROME2_VFS_DEP_OK);
    CHECK(!r);

    /* Same name returns false immediately (even for cycles). */
    r = true;
    CHECK(rome2_vfs_dep_reachable32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &qv, &a.pays,
        (rome2_guest_addr32){0x57000000u + 5u * 12u},
        (rome2_guest_addr32){0x57000000u + 5u * 12u},
        &lim, &r) == ROME2_VFS_DEP_OK);
    CHECK(!r);

    /* Disconnected node orphan vs mod_top. */
    r = true;
    CHECK(rome2_vfs_dep_reachable32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &qv, &a.pays,
        (rome2_guest_addr32){0x57000000u + 0u * 12u},
        (rome2_guest_addr32){0x57000000u + 4u * 12u},
        &lim, &r) == ROME2_VFS_DEP_OK);
    CHECK(!r);

    /* Cycle containment: cyc_a -> cyc_b -> cyc_a searching for orphan fails closed with STEP_LIMIT. */
    r = true;
    CHECK(rome2_vfs_dep_reachable32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &qv, &a.pays,
        (rome2_guest_addr32){0x57000000u + 5u * 12u},
        (rome2_guest_addr32){0x57000000u + 4u * 12u},
        &lim, &r) == ROME2_VFS_DEP_STEP_LIMIT);
    CHECK(r);
}

static void test_comparator_0x112e1500(void)
{
    static const dag_node_spec specs[] = {
        {"mod_top.pack", {"base.pack", NULL}, 1u},
        {"base.pack", {NULL, NULL}, 0u},
        {"peer.pack", {NULL, NULL}, 0u}
    };
    test_arena a;
    rome2_vfs_dep_limits lim = {16u, 16u, 4u, 32u, 64u};
    rome2_guest_read_view empty_props;
    bool less = false;
    uint32_t i;

    populate_graph(&a, specs, 3u);
    for (i = 0u; i < 3u; ++i) {
        uint32_t s = arena_add_str(&a, specs[i].name);
        uint32_t cand_off = i * 0x20u;
        put32(a.cand_buf + cand_off + 0x00u, 0x55000000u + i * 0x20u);
        write_string8(a.cand_buf + cand_off + 0x14u, (uint32_t)strlen(specs[i].name), 16u, s);
    }
    empty_props.host_base = a.props_buf;
    empty_props.guest_base = 0x55000000u;
    empty_props.byte_count = 0u;

    /* Dependency dominance: mod_top depends on base -> base < mod_top is true,
     * and pack_props is NOT touched! */
    less = false;
    CHECK(rome2_vfs_compare_archive_candidates32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &a.cands, &empty_props, &a.pays,
        (rome2_guest_addr32){0x54000020u}, (rome2_guest_addr32){0x54000000u},
        &lim, &less) == ROME2_VFS_DEP_OK);
    CHECK(less);

    less = true;
    CHECK(rome2_vfs_compare_archive_candidates32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &a.cands, &empty_props, &a.pays,
        (rome2_guest_addr32){0x54000000u}, (rome2_guest_addr32){0x54000020u},
        &lim, &less) == ROME2_VFS_DEP_OK);
    CHECK(!less);

    /* Unrelated candidates tie-break on (*(*cand))[0x1c] & 0x0f > rhs & 0x0f,
     * ignoring upper nibble noise! Set base=0x52 (nibble 2), peer=0xf1 (nibble 1). */
    a.props_buf[1u * 0x20u + 0x1cu] = 0x52u;
    a.props_buf[2u * 0x20u + 0x1cu] = 0xf1u;
    less = false;
    CHECK(rome2_vfs_compare_archive_candidates32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &a.cands, &a.props, &a.pays,
        (rome2_guest_addr32){0x54000020u}, (rome2_guest_addr32){0x54000040u},
        &lim, &less) == ROME2_VFS_DEP_OK);
    CHECK(less);

    less = true;
    CHECK(rome2_vfs_compare_archive_candidates32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &a.cands, &a.props, &a.pays,
        (rome2_guest_addr32){0x54000040u}, (rome2_guest_addr32){0x54000020u},
        &lim, &less) == ROME2_VFS_DEP_OK);
    CHECK(!less);

    /* Equal low nibbles are asymmetric (strict weak ordering -> false). */
    a.props_buf[2u * 0x20u + 0x1cu] = 0xe2u;
    less = true;
    CHECK(rome2_vfs_compare_archive_candidates32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &a.cands, &a.props, &a.pays,
        (rome2_guest_addr32){0x54000020u}, (rome2_guest_addr32){0x54000040u},
        &lim, &less) == ROME2_VFS_DEP_OK);
    CHECK(!less);

    /* Unmapped pack_props returns RANGE_ERROR preserving output. */
    less = true;
    CHECK(rome2_vfs_compare_archive_candidates32(&a.maps, (rome2_guest_addr32){0x50000000u},
        &a.nodes, &a.buckets, &a.edges, &a.cands, &empty_props, &a.pays,
        (rome2_guest_addr32){0x54000020u}, (rome2_guest_addr32){0x54000040u},
        &lim, &less) == ROME2_VFS_DEP_RANGE_ERROR);
    CHECK(less);
}

static void test_alignment_and_bounds(void)
{
    unsigned char raw[48];
    uint32_t align;
    for (align = 0u; align < 8u; ++align) {
        rome2_guest_read_view dv, pv;
        bool eq = false;
        dv.host_base = raw + align;
        dv.guest_base = 0x60000000u + align;
        dv.byte_count = 32u;
        pv.host_base = raw + 32u + align;
        pv.guest_base = 0x61000000u + align;
        pv.byte_count = 4u;
        memcpy(raw + 32u + align, "ab", 2u);
        write_string8(raw + align + 0u, 2u, 4u, 0x61000000u + align);
        write_string8(raw + align + 12u, 2u, 4u, 0x61000000u + align);
        CHECK(rome2_vfs_string8_equals32(&dv, (rome2_guest_addr32){0x60000000u + align},
            &dv, (rome2_guest_addr32){0x60000000u + align + 12u}, &pv, 8u, &eq) == ROME2_VFS_DEP_OK);
        CHECK(eq);
    }
}

int main(void)
{
    test_string8_equals();
    test_edge_tree_inorder();
    test_hashmap_collision_and_last_stop();
    test_reachability_and_cycles();
    test_comparator_0x112e1500();
    test_alignment_and_bounds();
    printf("vfs_dependency_graph: %zu checks passed\n", checks);
    return 0;
}
