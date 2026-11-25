#include "facefx_name_avl_table_ops.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define L81_ARENA_BASE 0x30000000u
#define L81_LOG_MANAGER_VA 0x30000200u
#define L81_LISTENER_VA 0x30000400u
#define L81_CLASS_TABLE_VA 0x30000500u
#define L81_SCRATCH_VA 0x30000600u
#define L81_SCRATCH2_VA 0x30000700u
#define L81_HEAP_START 0x30001000u
#define L81_LOG_CAPACITY 64u
#define L81_FREE_CAPACITY 128u

typedef struct l81_log_line {
    int32_t level;
    uint32_t tab_level;
    char text[160];
} l81_log_line;

typedef struct l81_free_record {
    uint32_t va;
    uint32_t bytes;
} l81_free_record;

typedef struct l81_fixture {
    rome2_l80_fx_ctx fx;
    rome2_l81_fx_name_ctx names;
    rome2_fx_log_manager_32 *manager;
} l81_fixture;

static uint8_t s_arena[512u * 1024u];
static l81_log_line s_log[L81_LOG_CAPACITY];
static uint32_t s_log_count;
static l81_free_record s_frees[L81_FREE_CAPACITY];
static uint32_t s_free_count;

/* Records each message with the tab level in force when the entry was flushed. */
static void test_on_log(rome2_l80_fx_ctx *ctx, uint32_t listener_va, const char *msg, int32_t level) {
    const rome2_fx_log_manager_32 *manager = (const rome2_fx_log_manager_32 *)rome2_l80_const_ptr(
        ctx, ctx->log_manager_singleton_va, (uint32_t)sizeof(*manager));
    assert(listener_va == L81_LISTENER_VA);
    assert(manager != NULL && msg != NULL);
    if (s_log_count < L81_LOG_CAPACITY) {
        l81_log_line *line = &s_log[s_log_count];
        line->level = level;
        line->tab_level = manager->tab_level;
        while (*msg == ' ') {
            ++msg; /* tab indentation */
        }
        (void)snprintf(line->text, sizeof(line->text), "%s", msg);
    }
    ++s_log_count;
}

static void test_on_free(rome2_l80_fx_ctx *ctx, uint32_t ptr_va, uint32_t bytes) {
    (void)ctx;
    if (s_free_count < L81_FREE_CAPACITY) {
        s_frees[s_free_count].va = ptr_va;
        s_frees[s_free_count].bytes = bytes;
    }
    ++s_free_count;
}

static void expect_log(uint32_t index, int32_t level, uint32_t tab_level, const char *text) {
    assert(index < s_log_count && index < L81_LOG_CAPACITY);
    assert(s_log[index].level == level);
    assert(s_log[index].tab_level == tab_level);
    assert(strcmp(s_log[index].text, text) == 0);
}

static void expect_free(uint32_t index, uint32_t va, uint32_t bytes) {
    assert(index < s_free_count && index < L81_FREE_CAPACITY);
    assert(s_frees[index].va == va);
    assert(s_frees[index].bytes == bytes);
}

static void fixture_init(l81_fixture *f, int with_class_table) {
    memset(s_arena, 0, sizeof(s_arena));
    memset(s_log, 0, sizeof(s_log));
    memset(s_frees, 0, sizeof(s_frees));
    s_log_count = 0u;
    s_free_count = 0u;

    rome2_l80_ctx_init(&f->fx, s_arena, L81_ARENA_BASE, (uint32_t)sizeof(s_arena), L81_HEAP_START);
    f->fx.on_log_message = test_on_log;
    f->fx.custom_free = test_on_free;
    (void)rome2_l80_log_manager_ctor(&f->fx, L81_LOG_MANAGER_VA);
    f->fx.log_manager_singleton_va = L81_LOG_MANAGER_VA;
    f->manager = (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(
        &f->fx, L81_LOG_MANAGER_VA, (uint32_t)sizeof(*f->manager));
    assert(f->manager != NULL);
    rome2_l80_log_manager_set_max_level(f->manager, 6);
    rome2_l80_fx_log_add_listener(&f->manager->log, L81_LISTENER_VA);

    rome2_l81_ctx_init(&f->names, &f->fx);
    if (with_class_table != 0) {
        f->names.class_table_va = L81_CLASS_TABLE_VA; /* zeroed {items, capacity, count} */
    }
}

static const rome2_fx_avl_string_node_32 *node_at(l81_fixture *f, uint32_t va) {
    const rome2_fx_avl_string_node_32 *node = (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
        &f->fx, va, (uint32_t)sizeof(*node));
    assert(node != NULL);
    return node;
}

static const rome2_fx_avl_bucket_32 *tree_at(l81_fixture *f, uint32_t va) {
    const rome2_fx_avl_bucket_32 *tree = (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(
        &f->fx, va, (uint32_t)sizeof(*tree));
    assert(tree != NULL);
    return tree;
}

static rome2_fx_name_entry_32 *entry_at(l81_fixture *f, uint32_t va) {
    rome2_fx_name_entry_32 *entry = (rome2_fx_name_entry_32 *)rome2_l80_mut_ptr(
        &f->fx, va, (uint32_t)sizeof(*entry));
    assert(entry != NULL);
    return entry;
}

static rome2_fx_class_32 *class_at(l81_fixture *f, uint32_t va) {
    rome2_fx_class_32 *desc = (rome2_fx_class_32 *)rome2_l80_mut_ptr(&f->fx, va, (uint32_t)sizeof(*desc));
    assert(desc != NULL);
    return desc;
}

static const char *key_of(l81_fixture *f, uint32_t node_va) {
    const char *key = rome2_l81_fx_string_cstr(&f->names, node_va + 4u);
    assert(key != NULL);
    return key;
}

/* Checks parent links and the height / balance fields; returns the subtree height. */
static int32_t check_subtree(l81_fixture *f, uint32_t node_va, uint32_t parent_va, uint32_t *count) {
    const rome2_fx_avl_string_node_32 *node;
    int32_t left_height;
    int32_t right_height;
    if (node_va == 0u) {
        return 0;
    }
    node = node_at(f, node_va);
    assert(node->vtable_va == ROME2_FX_VTABLE_AVL_STRING_NODE);
    assert(node->parent_va == parent_va);
    left_height = check_subtree(f, node->left_va, node_va, count);
    right_height = check_subtree(f, node->right_va, node_va, count);
    assert(node->height == (left_height > right_height ? left_height : right_height) + 1);
    assert(node->balance == right_height - left_height);
    assert(node->balance >= -1 && node->balance <= 1);
    ++*count;
    return node->height;
}

static void collect_in_order(l81_fixture *f, uint32_t node_va, char *out, size_t capacity) {
    const rome2_fx_avl_string_node_32 *node;
    size_t used;
    if (node_va == 0u) {
        return;
    }
    node = node_at(f, node_va);
    collect_in_order(f, node->left_va, out, capacity);
    used = strlen(out);
    (void)snprintf(out + used, capacity - used, "%s,", key_of(f, node_va));
    collect_in_order(f, node->right_va, out, capacity);
}

static void expect_tree(l81_fixture *f, uint32_t tree_va, uint32_t count, const char *root_key, const char *order) {
    const rome2_fx_avl_bucket_32 *tree = tree_at(f, tree_va);
    char seen[128] = "";
    uint32_t walked = 0u;
    (void)check_subtree(f, tree->root_va, 0u, &walked);
    assert(walked == count && tree->node_count == count);
    assert(strcmp(key_of(f, tree->root_va), root_key) == 0);
    collect_in_order(f, tree->root_va, seen, sizeof(seen));
    assert(strcmp(seen, order) == 0);
}

static void test_fx_string(void) {
    l81_fixture f;
    rome2_fx_string_32 *text;
    const char *bytes;
    uint32_t self_va = L81_SCRATCH_VA;
    fixture_init(&f, 0);
    text = (rome2_fx_string_32 *)rome2_l80_mut_ptr(&f.fx, self_va, (uint32_t)sizeof(*text));
    assert(text != NULL);

    /* capacity is length + 1 and stays inline while it is below 0x11 */
    assert(rome2_l81_fx_string_ctor_slice(&f.names, self_va, "hello", -1) == self_va);
    assert(text->data_va == self_va && text->capacity == 6u && text->length == 5u);
    assert(memcmp(text->inline_buf, "hello", 6u) == 0);
    assert(rome2_l81_fx_string_ctor_slice(&f.names, self_va, "hello world", 5) == self_va);
    assert(text->data_va == self_va && text->capacity == 6u && text->length == 5u);
    assert(memcmp(text->inline_buf, "hello", 6u) == 0);

    assert(rome2_l81_fx_string_equals_cstr(&f.names, self_va, "hello") == 1u);
    assert(rome2_l81_fx_string_equals_cstr(&f.names, self_va, "hellp") == 0u);
    assert(rome2_l81_fx_string_equals_cstr(&f.names, self_va, "hell") == 0u);
    assert(rome2_l81_fx_string_equals_cstr(&f.names, self_va, NULL) == 0u);
    assert(rome2_l81_fx_string_not_equals_cstr(&f.names, self_va, "hello") == 0u);
    assert(rome2_l81_fx_string_not_equals_cstr(&f.names, self_va, "hellp") == 1u);
    assert(rome2_l81_fx_string_not_equals_cstr(&f.names, self_va, "hell") == 1u);
    assert(rome2_l81_fx_string_not_equals_cstr(&f.names, self_va, NULL) == 1u);

    assert(rome2_l81_fx_string_ctor_slice(&f.names, self_va, "fifteen_chars_x", -1) == self_va);
    assert(text->data_va == self_va && text->capacity == 16u && text->length == 15u);
    assert(f.fx.alloc_calls == 0u);
    assert(rome2_l81_fx_string_ctor_slice(&f.names, self_va, "sixteen_chars_xy", -1) == self_va);
    assert(text->data_va >= L81_HEAP_START && text->capacity == 17u && text->length == 16u);
    assert(f.fx.alloc_calls == 1u);
    bytes = rome2_l81_fx_string_cstr(&f.names, self_va);
    assert(bytes != NULL && strcmp(bytes, "sixteen_chars_xy") == 0);

    /* no source, or a zero length, leaves the empty state: inline pointer, capacity 0 */
    assert(rome2_l81_fx_string_ctor_slice(&f.names, self_va, NULL, -1) == self_va);
    assert(text->data_va == self_va && text->capacity == 0u && text->length == 0u);
    assert(rome2_l81_fx_string_ctor_slice(&f.names, self_va, "ignored", 0) == self_va);
    assert(text->data_va == self_va && text->capacity == 0u && text->length == 0u);

    /* c_str() on an unset data pointer rebinds the inline buffer */
    text->data_va = 0u;
    text->capacity = 7u;
    text->length = 3u;
    text->inline_buf[0] = 'q';
    bytes = rome2_l81_fx_string_cstr(&f.names, self_va);
    assert(bytes == text->inline_buf && bytes[0] == '\0');
    assert(text->data_va == self_va && text->capacity == 0x10u && text->length == 0u);
}

static void test_avl_tree(void) {
    static const char *const keys[7] = {"aa", "bb", "cc", "dd", "ee", "ff", "gg"};
    static const char long_key[] = "sixteen_chars_xy";
    l81_fixture f;
    rome2_l81_avl_iter it;
    const rome2_fx_avl_string_node_32 *node;
    const rome2_fx_avl_bucket_32 *tree;
    uint32_t tree_va = L81_SCRATCH_VA;
    uint32_t node_va;
    uint32_t key_va;
    uint32_t i;
    fixture_init(&f, 0);

    /* 0x10eddc90 */
    assert(rome2_l81_avl_string_node_ctor(&f.names, L81_SCRATCH2_VA, 0x1234u, "xyz", 3u, 0x7777u) ==
           L81_SCRATCH2_VA);
    node = node_at(&f, L81_SCRATCH2_VA);
    assert(node->vtable_va == ROME2_FX_VTABLE_AVL_STRING_NODE);
    assert(node->key.data_va == L81_SCRATCH2_VA + 4u && node->key.capacity == 4u && node->key.length == 3u);
    assert(memcmp(node->key.inline_buf, "xyz", 4u) == 0);
    assert(node->value_va == 0x7777u && node->height == 0 && node->parent_va == 0x1234u);
    assert(node->left_va == 0u && node->right_va == 0u && node->balance == 0);
    assert(rome2_l81_avl_string_node_ctor(&f.names, L81_SCRATCH2_VA, 0u, "", 0u, 1u) == L81_SCRATCH2_VA);
    assert(node->key.data_va == L81_SCRATCH2_VA + 4u && node->key.capacity == 0u && node->key.length == 0u);

    assert(rome2_l81_avl_bucket_ctor(&f.names, tree_va) == tree_va);
    tree = tree_at(&f, tree_va);
    assert(tree->vtable_va == ROME2_FX_VTABLE_AVL_BUCKET && tree->root_va == 0u && tree->node_count == 0u);
    assert(rome2_l81_avl_find(&f.names, tree_va, &it, "aa") == &it);
    assert(it.tree_va == tree_va && it.node_va == 0u);

    /* ascending inserts force a left rotation at every other step */
    for (i = 0u; i < 7u; ++i) {
        uint32_t walked = 0u;
        assert(rome2_l81_avl_insert(&f.names, tree_va, &it, keys[i], 0x100u + i) == &it);
        assert(it.tree_va == tree_va && it.node_va != 0u);
        assert(node_at(&f, it.node_va)->value_va == 0x100u + i);
        (void)check_subtree(&f, tree->root_va, 0u, &walked);
        assert(walked == i + 1u && tree->node_count == i + 1u);
    }
    expect_tree(&f, tree_va, 7u, "dd", "aa,bb,cc,dd,ee,ff,gg,");
    assert(f.fx.alloc_calls == 7u && s_free_count == 0u);

    /* a key already present yields {tree, NULL}: no allocation, no count change */
    assert(rome2_l81_avl_insert(&f.names, tree_va, &it, "cc", 0x999u) == &it);
    assert(it.tree_va == tree_va && it.node_va == 0u);
    assert(f.fx.alloc_calls == 7u && tree->node_count == 7u);

    assert(rome2_l81_avl_find(&f.names, tree_va, &it, "ee") == &it);
    assert(it.tree_va == tree_va && node_at(&f, it.node_va)->value_va == 0x104u);
    (void)rome2_l81_avl_find(&f.names, tree_va, &it, "zz");
    assert(it.tree_va == tree_va && it.node_va == 0u);
    assert(rome2_l81_avl_remove_key(&f.names, tree_va, "zz") == 0u);

    /* removal relinks nodes: the in-order successor takes the place of a two-child node */
    node_va = tree->root_va;
    (void)rome2_l81_avl_find(&f.names, tree_va, &it, "ee");
    assert(rome2_l81_avl_remove_key(&f.names, tree_va, "dd") == 1u);
    assert(tree->root_va == it.node_va);
    expect_tree(&f, tree_va, 6u, "ee", "aa,bb,cc,ee,ff,gg,");
    assert(s_free_count == 1u);
    expect_free(0u, node_va, 0x38u);

    /* right child without a left subtree moves up directly */
    (void)rome2_l81_avl_find(&f.names, tree_va, &it, "ff");
    assert(rome2_l81_avl_remove_key(&f.names, tree_va, "ee") == 1u);
    assert(tree->root_va == it.node_va);
    expect_tree(&f, tree_va, 5u, "ff", "aa,bb,cc,ff,gg,");

    /* no right child: the left link is spliced in, and the retrace rotates right at the root */
    assert(rome2_l81_avl_remove_key(&f.names, tree_va, "gg") == 1u);
    expect_tree(&f, tree_va, 4u, "bb", "aa,bb,cc,ff,");
    assert(s_free_count == 3u);

    /* left-right case: rotate the left child left, then the node right */
    (void)rome2_l81_avl_insert(&f.names, tree_va, &it, "dd", 0x200u);
    expect_tree(&f, tree_va, 5u, "bb", "aa,bb,cc,dd,ff,");
    assert(node_at(&f, tree->root_va)->right_va == it.node_va);

    /* a key of 16 bytes or more: node, stack temporary, key buffer; the temporary is freed */
    assert(f.fx.alloc_calls == 8u);
    (void)rome2_l81_avl_insert(&f.names, tree_va, &it, long_key, 0x300u);
    assert(f.fx.alloc_calls == 11u && s_free_count == 4u);
    node_va = it.node_va;
    node = node_at(&f, node_va);
    key_va = node->key.data_va;
    assert(key_va != node_va + 4u && node->key.capacity == 17u && node->key.length == 16u);
    assert(s_frees[3].bytes == 17u && s_frees[3].va != key_va);
    assert(strcmp(key_of(&f, node_va), long_key) == 0);
    assert(rome2_l81_avl_remove_key(&f.names, tree_va, long_key) == 1u);
    assert(s_free_count == 6u);
    expect_free(4u, key_va, 17u);
    expect_free(5u, node_va, 0x38u);
    expect_tree(&f, tree_va, 5u, "dd", "aa,bb,cc,dd,ff,"); /* the long key's insert rotated the root left */

    /* 0x10ede150 */
    rome2_l81_avl_bucket_dtor(&f.names, tree_va);
    assert(tree->vtable_va == ROME2_FX_VTABLE_AVL_TREE_BASE && tree->root_va == 0u && tree->node_count == 0u);
    assert(s_free_count == 11u);

    /* right-left case */
    (void)rome2_l81_avl_bucket_ctor(&f.names, tree_va);
    (void)rome2_l81_avl_insert(&f.names, tree_va, &it, "aa", 1u);
    (void)rome2_l81_avl_insert(&f.names, tree_va, &it, "cc", 2u);
    (void)rome2_l81_avl_insert(&f.names, tree_va, &it, "bb", 3u);
    expect_tree(&f, tree_va, 3u, "bb", "aa,bb,cc,");
    assert(tree->root_va == it.node_va);
    rome2_l81_avl_bucket_dtor(&f.names, tree_va);

    /* 0x10ee19c0 / 0x10ee1a20 called directly on the root link */
    (void)rome2_l81_avl_bucket_ctor(&f.names, tree_va);
    (void)rome2_l81_avl_insert(&f.names, tree_va, &it, "m", 1u);
    node_va = it.node_va;
    (void)rome2_l81_avl_insert(&f.names, tree_va, &it, "t", 2u);
    rome2_l81_avl_rotate_left(&f.names, tree_va, tree_va + 4u);
    assert(tree->root_va == it.node_va);
    node = node_at(&f, it.node_va);
    assert(node->parent_va == 0u && node->left_va == node_va && node->right_va == 0u);
    assert(node->height == 2 && node->balance == -1);
    node = node_at(&f, node_va);
    assert(node->parent_va == it.node_va && node->left_va == 0u && node->right_va == 0u);
    assert(node->height == 1 && node->balance == 0);
    rome2_l81_avl_rotate_right(&f.names, tree_va, tree_va + 4u);
    expect_tree(&f, tree_va, 2u, "m", "m,t,");
    assert(node->right_va == it.node_va && node->balance == 1);
    rome2_l81_avl_bucket_dtor(&f.names, tree_va);
}

static void expect_iter(
    const rome2_l81_name_iter *iter,
    uint32_t table_va,
    int32_t bucket_index,
    uint32_t node_va) {
    uint32_t bucket_va = table_va + 0x14u + (bucket_index < 0 ? 0u : (uint32_t)bucket_index * 0xcu);
    assert(iter->table_va == table_va && iter->bucket_count == 0x1000u);
    assert(iter->bucket_index == bucket_index && iter->bucket_va == bucket_va);
    assert(iter->node_va == node_va);
}

static void test_name_table(void) {
    static const char high_byte[] = {'\xff', '\0'};
    l81_fixture f;
    rome2_l81_name_iter iter;
    rome2_l81_name_iter walk;
    const rome2_fx_name_table_header_32 *header;
    uint32_t table_va;
    uint32_t node_a;
    uint32_t node_ab;
    uint32_t node_ba;
    uint32_t node_c;
    uint32_t i;
    fixture_init(&f, 0);

    /* seed 0x1505, h * 33 + sign-extended byte; "ab", "bA" and "c " share one hash */
    assert(rome2_l81_djb2_hash("") == 0x1505u);
    assert(rome2_l81_djb2_hash(NULL) == 0x1505u);
    assert(rome2_l81_djb2_hash("a") == 0x2b606u);
    assert(rome2_l81_djb2_hash(high_byte) == 0x2b5a4u);
    assert(rome2_l81_djb2_hash("ab") == 0x597728u);
    assert(rome2_l81_djb2_hash("bA") == 0x597728u);
    assert(rome2_l81_djb2_hash("c ") == 0x597728u);

    table_va = rome2_l80_fx_allocate(&f.fx, ROME2_FX_NAME_TABLE_BYTES);
    assert(table_va != 0u);
    for (i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        (void)rome2_l81_avl_bucket_ctor(&f.names, table_va + 0x14u + i * 0xcu);
    }
    header = (const rome2_fx_name_table_header_32 *)rome2_l80_const_ptr(
        &f.fx, table_va, (uint32_t)sizeof(*header));
    assert(header != NULL);

    assert(rome2_l81_name_table_find(&f.names, table_va, &iter, "ab") == &iter);
    expect_iter(&iter, table_va, -1, 0u);
    assert(header->probe_hits == 0u);

    assert(rome2_l81_name_table_insert(&f.names, table_va, &iter, "ab", 0x7001u) == &iter);
    node_ab = iter.node_va;
    assert(node_ab != 0u);
    expect_iter(&iter, table_va, 0x728, node_ab);
    assert(header->unique_count == 1u && header->total_added == 1u && header->hash_collisions == 0u);

    /* an insert into a bucket that already has a root counts as a collision */
    (void)rome2_l81_name_table_insert(&f.names, table_va, &iter, "bA", 0x7002u);
    node_ba = iter.node_va;
    (void)rome2_l81_name_table_insert(&f.names, table_va, &iter, "c ", 0x7003u);
    node_c = iter.node_va;
    expect_iter(&iter, table_va, 0x728, node_c);
    assert(header->unique_count == 3u && header->total_added == 3u && header->hash_collisions == 2u);
    expect_tree(&f, table_va + 0x14u + 0x728u * 0xcu, 3u, "bA", "ab,bA,c ,");

    /* a rejected insert and a successful find both bump header +0x10 */
    (void)rome2_l81_name_table_insert(&f.names, table_va, &iter, "ab", 0x7fffu);
    expect_iter(&iter, table_va, -1, 0u);
    assert(header->unique_count == 3u && header->total_added == 3u && header->probe_hits == 1u);
    assert(node_at(&f, node_ab)->value_va == 0x7001u);
    (void)rome2_l81_name_table_find(&f.names, table_va, &iter, "bA");
    expect_iter(&iter, table_va, 0x728, node_ba);
    assert(header->probe_hits == 2u);

    (void)rome2_l81_name_table_insert(&f.names, table_va, &iter, "a", 0x7004u);
    node_a = iter.node_va;
    expect_iter(&iter, table_va, 0x606, node_a);
    assert(header->unique_count == 4u && header->hash_collisions == 2u);

    /* 0x10edea00 from the end value: buckets in index order, keys in order inside a bucket */
    walk.table_va = table_va;
    walk.bucket_count = 0x1000u;
    walk.bucket_index = -1;
    walk.bucket_va = table_va + 0x14u;
    walk.node_va = 0u;
    rome2_l81_name_iter_advance(&f.names, &walk);
    expect_iter(&walk, table_va, 0x606, node_a);
    rome2_l81_name_iter_advance(&f.names, &walk);
    expect_iter(&walk, table_va, 0x728, node_ab);
    rome2_l81_name_iter_advance(&f.names, &walk);
    expect_iter(&walk, table_va, 0x728, node_ba);
    rome2_l81_name_iter_advance(&f.names, &walk);
    expect_iter(&walk, table_va, 0x728, node_c);
    rome2_l81_name_iter_advance(&f.names, &walk);
    expect_iter(&walk, table_va, -1, 0u);
    /* a bucket position without a node resumes at that bucket's leftmost node */
    walk.bucket_index = 0x728;
    walk.bucket_va = table_va + 0x14u + 0x728u * 0xcu;
    rome2_l81_name_iter_advance(&f.names, &walk);
    expect_iter(&walk, table_va, 0x728, node_ab);

    assert(rome2_l81_name_table_remove(&f.names, table_va, "bA") == 1u);
    assert(header->unique_count == 3u && header->total_removed == 1u);
    assert(rome2_l81_name_table_remove(&f.names, table_va, "bA") == 0u);
    assert(header->unique_count == 3u && header->total_removed == 1u && header->total_added == 4u);
    expect_tree(&f, table_va + 0x14u + 0x728u * 0xcu, 2u, "c ", "ab,c ,");

    /* 0x10eddfd0 */
    rome2_l81_name_table_dtor(&f.names, table_va);
    assert(header->unique_count == 0u && header->total_added == 0u && header->total_removed == 0u);
    assert(header->hash_collisions == 0u && header->probe_hits == 0u);
    for (i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        const rome2_fx_avl_bucket_32 *bucket = tree_at(&f, table_va + 0x14u + i * 0xcu);
        assert(bucket->vtable_va == ROME2_FX_VTABLE_AVL_TREE_BASE);
        assert(bucket->root_va == 0u && bucket->node_count == 0u);
    }
    assert(s_free_count == 4u);
}

static void test_fx_name_lifecycle(void) {
    static const char high_name[] = {'\xe9', 't', '\0'};
    static char long_name[0x201];
    l81_fixture f;
    rome2_l81_name_stats stats;
    rome2_l81_name_iter iter;
    rome2_fx_name_32 def_name;
    rome2_fx_name_32 a_name;
    rome2_fx_name_32 b_name;
    rome2_fx_name_32 c_name;
    rome2_fx_name_32 high;
    rome2_fx_name_32 full;
    rome2_fx_name_32 unbound;
    const uint32_t *class_table;
    const uint32_t *class_items;
    const rome2_fx_class_32 *desc;
    const rome2_fx_string_32 *text;
    uint32_t null_entry;
    uint32_t a_entry;
    uint32_t zeta_entry;
    uint32_t table_va;
    uint32_t allocs;
    uint32_t frees;
    fixture_init(&f, 1);

    rome2_l81_fx_name_startup(&f.names);
    assert(s_log_count == 4u);
    expect_log(0u, 5, 0u, "Starting up name manager...");
    expect_log(1u, 6, 1u, "FX_ALLOW_SPACES_IN_NAMES is 1.");
    expect_log(2u, 6, 1u, "FX_MAX_NAME_LENGTH is 512.");
    expect_log(3u, 5, 0u, "Name manager startup complete.");
    assert(f.manager->tab_level == 0u);
    table_va = f.names.name_table_va;
    assert(table_va != 0u);

    /* the three class descriptors register in construction order; the array doubles 1, 2, 4 */
    class_table = (const uint32_t *)rome2_l80_const_ptr(&f.fx, L81_CLASS_TABLE_VA, 12u);
    assert(class_table != NULL && class_table[1] == 4u && class_table[2] == 3u);
    class_items = (const uint32_t *)rome2_l80_const_ptr(&f.fx, class_table[0], 16u);
    assert(class_items != NULL);
    assert(class_items[0] == f.names.fx_object_class_va && class_items[0] != 0u);
    assert(class_items[1] == f.names.fx_ref_object_class_va && class_items[1] != 0u);
    assert(class_items[2] == f.names.fx_name_entry_class_va && class_items[2] != 0u);
    desc = class_at(&f, f.names.fx_object_class_va);
    assert(desc->current_version == 0u && desc->base_class_va == 0u && desc->num_children == 1u);
    assert(desc->size == 4u && desc->construct_fn_va == 0x10ef31f0u);
    desc = class_at(&f, f.names.fx_ref_object_class_va);
    assert(desc->base_class_va == f.names.fx_object_class_va && desc->num_children == 1u);
    assert(desc->size == 8u && desc->construct_fn_va == 0x10f06b80u);
    desc = class_at(&f, f.names.fx_name_entry_class_va);
    assert(desc->base_class_va == f.names.fx_ref_object_class_va && desc->num_children == 0u);
    assert(desc->size == 0xcu && desc->construct_fn_va == 0x10edef10u);
    assert(s_free_count == 2u && s_frees[0].bytes == 4u && s_frees[1].bytes == 8u);

    /* six names: three class names, then "", "Default" and "NewActor" */
    memset(&stats, 0xa5, sizeof(stats));
    rome2_l81_fx_name_get_stats(&f.names, &stats);
    assert(stats.num_names == 6u && stats.num_added == 6u && stats.num_collisions == 0u);
    assert(stats.num_probes == 3u); /* each class constructor looks its own name up once more */
    assert(stats.bucket_count == 0x1000u && stats.non_empty_buckets == 6u);
    assert(stats.min_bucket_len == 0u && stats.max_bucket_len == 1u && stats.avg_bucket_len == 0u);
    assert(stats.mem_bytes == 0xc000u + 45u + 6u * 0x59u);

    /* NullName is the empty name, and its entry points at the key inside its tree node */
    null_entry = f.names.null_name.entry_va;
    assert(null_entry != 0u && f.names.default_name.entry_va != 0u && f.names.new_actor_name.entry_va != 0u);
    (void)rome2_l81_name_table_find(&f.names, table_va, &iter, "");
    assert(iter.bucket_index == 0x505 && iter.node_va != 0u);
    assert(node_at(&f, iter.node_va)->value_va == null_entry);
    assert(entry_at(&f, null_entry)->vtable_va == ROME2_FX_VTABLE_NAME_ENTRY);
    assert(entry_at(&f, null_entry)->ref_count == 1);
    assert(entry_at(&f, null_entry)->fx_string_va == iter.node_va + 4u);
    assert(strcmp(rome2_l81_fx_name_get_cstr(&f.names, &f.names.default_name), "Default") == 0);
    assert(strcmp(rome2_l81_fx_name_get_cstr(&f.names, &f.names.new_actor_name), "NewActor") == 0);
    assert(rome2_l81_fx_name_exists(&f.names, "Default") == 1u);
    assert(rome2_l81_fx_name_exists(&f.names, "FxNameEntry") == 1u);
    assert(rome2_l81_fx_name_exists(&f.names, "NullName") == 0u);

    assert(rome2_l81_fx_name_ctor_default(&f.names, &def_name) == &def_name);
    assert(def_name.entry_va == null_entry && entry_at(&f, null_entry)->ref_count == 2);
    assert(rome2_l81_fx_name_eq_cstr(&f.names, &def_name, "") == 1u);
    assert(rome2_l81_fx_name_ne_cstr(&f.names, &def_name, "") == 0u);

    /* 0x10edf360: bucket order, with the singular / plural reference suffix */
    s_log_count = 0u;
    rome2_l81_fx_name_dump_to_log(&f.names);
    assert(s_log_count == 7u);
    expect_log(0u, 4, 0u, "Name table [6 names]:");
    expect_log(1u, 4, 1u, "[0]: NewActor (1 reference)");
    expect_log(2u, 4, 1u, "[1]: FxObject (1 reference)");
    expect_log(3u, 4, 1u, "[2]:  (2 references)");
    expect_log(4u, 4, 1u, "[3]: FxNameEntry (1 reference)");
    expect_log(5u, 4, 1u, "[4]: FxRefObject (1 reference)");
    expect_log(6u, 4, 1u, "[5]: Default (1 reference)");
    assert(f.manager->tab_level == 0u);
    s_log_count = 0u;
    rome2_l80_log_manager_set_max_level(f.manager, 3);
    rome2_l81_fx_name_dump_to_log(&f.names);
    assert(s_log_count == 0u && f.manager->tab_level == 0u);
    rome2_l80_log_manager_set_max_level(f.manager, 6);

    /* '|' and '"' are rewritten; an 18-byte name costs entry, node, temporary and key buffer */
    allocs = f.fx.alloc_calls;
    frees = s_free_count;
    assert(rome2_l81_fx_name_ctor_cstr(&f.names, &a_name, "Rome|Legate\"Alpha\"") == &a_name);
    assert(f.fx.alloc_calls == allocs + 4u && s_free_count == frees + 1u);
    assert(strcmp(rome2_l81_fx_name_get_cstr(&f.names, &a_name), "Rome_Legate'Alpha'") == 0);
    a_entry = a_name.entry_va;
    assert(entry_at(&f, a_entry)->ref_count == 1);
    assert(entry_at(&f, a_entry)->vtable_va == ROME2_FX_VTABLE_NAME_ENTRY);
    (void)rome2_l81_name_table_find(&f.names, table_va, &iter, "Rome_Legate'Alpha'");
    assert(iter.bucket_index == 0x19d && node_at(&f, iter.node_va)->value_va == a_entry);
    assert(rome2_l81_fx_name_get_string_va(&f.names, &a_name) == iter.node_va + 4u);
    text = (const rome2_fx_string_32 *)rome2_l80_const_ptr(&f.fx, iter.node_va + 4u, (uint32_t)sizeof(*text));
    assert(text != NULL && text->data_va != iter.node_va + 4u);
    assert(text->capacity == 19u && text->length == 18u);

    /* the already rewritten spelling finds the same entry and allocates nothing */
    allocs = f.fx.alloc_calls;
    assert(rome2_l81_fx_name_ctor_cstr(&f.names, &b_name, "Rome_Legate'Alpha'") == &b_name);
    assert(b_name.entry_va == a_entry && entry_at(&f, a_entry)->ref_count == 2);
    assert(f.fx.alloc_calls == allocs);
    assert(rome2_l81_fx_name_exists(&f.names, "Rome|Legate\"Alpha\"") == 0u); /* Exists does not rewrite */

    assert(rome2_l81_fx_name_eq_name(&f.names, &a_name, &b_name) == 1u);
    assert(rome2_l81_fx_name_ne_name(&f.names, &a_name, &b_name) == 0u);
    assert(rome2_l81_fx_name_eq_name(&f.names, &a_name, &def_name) == 0u);
    assert(rome2_l81_fx_name_ne_name(&f.names, &a_name, &def_name) == 1u);
    assert(rome2_l81_fx_name_eq_cstr(&f.names, &a_name, "Rome_Legate'Alpha'") == 1u);
    assert(rome2_l81_fx_name_eq_cstr(&f.names, &a_name, NULL) == 0u);
    assert(rome2_l81_fx_name_ne_cstr(&f.names, &a_name, "Rome") == 1u);
    assert(rome2_l81_fx_name_ne_cstr(&f.names, &a_name, NULL) == 1u);

    /* an FxName with no entry is bound to NullName on first use, without taking a reference */
    unbound.entry_va = 0u;
    assert(rome2_l81_fx_name_eq_name(&f.names, &unbound, &def_name) == 1u);
    assert(unbound.entry_va == null_entry && entry_at(&f, null_entry)->ref_count == 2);
    unbound.entry_va = 0u;
    assert(strcmp(rome2_l81_fx_name_get_cstr(&f.names, &unbound), "") == 0);
    assert(unbound.entry_va == null_entry);
    unbound.entry_va = 0u;
    assert(rome2_l81_fx_name_lt(&f.names, &unbound, &a_name) == 1u);
    assert(unbound.entry_va == null_entry && entry_at(&f, null_entry)->ref_count == 2);

    /* copy, SetName, both assignments */
    assert(rome2_l81_fx_name_ctor_copy(&f.names, &c_name, &a_name) == &c_name);
    assert(c_name.entry_va == a_entry && entry_at(&f, a_entry)->ref_count == 3);
    rome2_l81_fx_name_set_name(&f.names, &c_name, "Zeta");
    zeta_entry = c_name.entry_va;
    assert(zeta_entry != a_entry && entry_at(&f, a_entry)->ref_count == 2);
    assert(entry_at(&f, zeta_entry)->ref_count == 1);
    assert(rome2_l81_fx_name_lt(&f.names, &a_name, &c_name) == 1u);
    assert(rome2_l81_fx_name_gt(&f.names, &a_name, &c_name) == 0u);
    assert(rome2_l81_fx_name_gt(&f.names, &c_name, &a_name) == 1u);
    assert(rome2_l81_fx_name_lt(&f.names, &c_name, &c_name) == 0u);
    assert(rome2_l81_fx_name_gt(&f.names, &c_name, &c_name) == 0u);

    /* ordering compares unsigned bytes */
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &high, high_name);
    assert(rome2_l81_fx_name_gt(&f.names, &high, &c_name) == 1u);
    assert(rome2_l81_fx_name_lt(&f.names, &c_name, &high) == 1u);
    rome2_l81_fx_name_dtor(&f.names, &high);
    assert(high.entry_va == 0u && rome2_l81_fx_name_exists(&f.names, high_name) == 0u);

    /* assigning away the last reference unregisters "Zeta": inline key, so node then entry */
    frees = s_free_count;
    assert(rome2_l81_fx_name_assign_copy(&f.names, &c_name, &a_name) == &c_name);
    assert(c_name.entry_va == a_entry && entry_at(&f, a_entry)->ref_count == 3);
    assert(rome2_l81_fx_name_exists(&f.names, "Zeta") == 0u);
    assert(s_free_count == frees + 2u);
    assert(s_frees[frees].bytes == 0x38u);
    expect_free(frees + 1u, zeta_entry, 0xcu);
    assert(rome2_l81_fx_name_assign_copy(&f.names, &c_name, &c_name) == &c_name);
    assert(entry_at(&f, a_entry)->ref_count == 3);
    assert(rome2_l81_fx_name_assign_cstr(&f.names, &c_name, "Zeta") == &c_name);
    assert(c_name.entry_va != a_entry && entry_at(&f, a_entry)->ref_count == 2);
    assert(rome2_l81_fx_name_eq_cstr(&f.names, &c_name, "Zeta") == 1u);
    assert(s_log_count == 0u);

    /* 0x200 bytes with no terminator in range collapse to the empty name; 0x1ff are kept */
    memset(long_name, 'x', 0x200u);
    long_name[0x200] = '\0';
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &full, long_name);
    assert(full.entry_va == null_entry && entry_at(&f, null_entry)->ref_count == 3);
    long_name[0x1ff] = '\0';
    rome2_l81_fx_name_set_name(&f.names, &full, long_name);
    assert(full.entry_va != null_entry && entry_at(&f, null_entry)->ref_count == 2);
    assert(strlen(rome2_l81_fx_name_get_cstr(&f.names, &full)) == 0x1ffu);
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &high, NULL);
    assert(high.entry_va == null_entry && entry_at(&f, null_entry)->ref_count == 3);
    rome2_l81_fx_name_safe_remove_ref(&f.names, &high);
    assert(high.entry_va == null_entry && entry_at(&f, null_entry)->ref_count == 2);
    high.entry_va = 0u;
    rome2_l81_fx_name_safe_remove_ref(&f.names, &high);
    assert(entry_at(&f, null_entry)->ref_count == 2);

    /* releases: the pointer is cleared only by the release that drops the last reference */
    rome2_l81_fx_name_dtor(&f.names, &b_name);
    assert(b_name.entry_va == a_entry && entry_at(&f, a_entry)->ref_count == 1);
    assert(rome2_l81_fx_name_exists(&f.names, "Rome_Legate'Alpha'") == 1u);
    (void)rome2_l81_name_table_find(&f.names, table_va, &iter, "Rome_Legate'Alpha'");
    text = (const rome2_fx_string_32 *)rome2_l80_const_ptr(&f.fx, iter.node_va + 4u, (uint32_t)sizeof(*text));
    assert(text != NULL);
    frees = s_free_count;
    rome2_l81_fx_name_dtor(&f.names, &a_name);
    assert(a_name.entry_va == 0u);
    assert(rome2_l81_fx_name_exists(&f.names, "Rome_Legate'Alpha'") == 0u);
    assert(s_free_count == frees + 3u);
    assert(s_frees[frees].bytes == 19u);
    expect_free(frees + 1u, iter.node_va, 0x38u);
    expect_free(frees + 2u, a_entry, 0xcu); /* size read from the FxNameEntry class descriptor */

    /* 0x10ee0890: every remaining name goes, whatever still refers to it */
    rome2_l81_fx_name_get_stats(&f.names, &stats);
    assert(stats.num_names == 8u); /* six startup names, "Zeta" and the 0x1ff-byte name */
    s_log_count = 0u;
    frees = s_free_count;
    rome2_l81_fx_name_shutdown(&f.names);
    assert(s_log_count == 2u);
    expect_log(0u, 5, 0u, "Shutting down name manager...");
    expect_log(1u, 5, 0u, "Name manager shutdown complete.");
    assert(f.manager->tab_level == 0u);
    assert(f.names.name_table_va == 0u && f.names.null_name.entry_va == 0u);
    assert(f.names.default_name.entry_va == 0u && f.names.new_actor_name.entry_va == 0u);
    assert(s_free_count == frees + 8u * 2u + 1u + 1u);
    expect_free(s_free_count - 1u, table_va, 0xc014u);

    /* with the table gone the destructor leaves everything alone */
    frees = s_free_count;
    rome2_l81_fx_name_dtor(&f.names, &c_name);
    rome2_l81_fx_name_dtor(&f.names, &def_name);
    assert(c_name.entry_va != 0u && def_name.entry_va == null_entry && s_free_count == frees);
}

static void test_fx_name_before_startup(void) {
    l81_fixture f;
    rome2_fx_name_32 early;
    rome2_fx_name_32 other;
    const rome2_fx_class_32 *desc;
    uint32_t class_va;
    fixture_init(&f, 0);

    assert(rome2_l81_fx_name_ctor_cstr(&f.names, &early, "Early") == &early);
    assert(early.entry_va == 0u);
    assert(rome2_l81_fx_name_ctor_copy(&f.names, &other, &early) == &other);
    assert(other.entry_va == 0u);
    assert(rome2_l81_fx_name_assign_copy(&f.names, &other, &early) == &other);
    assert(rome2_l81_fx_name_assign_cstr(&f.names, &other, "Late") == &other);
    assert(s_log_count == 4u);
    expect_log(0u, 1, 0u, "Attempt to create name Early before FxName::Startup() called!");
    expect_log(1u, 1, 0u, "Attempt to copy construct name before FxName::Startup() called!");
    expect_log(2u, 1, 0u, "Attempt to assign to name before FxName::Startup() called!");
    expect_log(3u, 1, 0u, "Attempt to assign to name with other = Late before FxName::Startup() called!");
    rome2_l81_fx_name_dtor(&f.names, &other);
    rome2_l81_fx_name_dtor(&f.names, &early);
    assert(rome2_l81_fx_name_ctor_default(&f.names, &other) == &other && other.entry_va == 0u);

    /* FxClass before FxClass::Startup(): the fields are still written */
    s_log_count = 0u;
    class_va = rome2_l81_fx_object_static_class_init(&f.names);
    assert(class_va != 0u && s_log_count == 4u);
    expect_log(0u, 1, 0u, "Attempt to create name FxObject before FxName::Startup() called!");
    expect_log(1u, 2, 0u, "Attempt to create FxClass before FxClass::Startup() called!");
    expect_log(2u, 1, 0u, "Attempt to create name FxObject before FxName::Startup() called!");
    expect_log(3u, 2, 0u, "Attempt to find class description before FxClass::Startup() called!");
    desc = class_at(&f, class_va);
    assert(desc->name.entry_va == 0u && desc->size == 4u && desc->num_children == 0u);
    assert(desc->construct_fn_va == 0x10ef31f0u);

    /* each message is gated on the manager's maximum level */
    s_log_count = 0u;
    rome2_l80_log_manager_set_max_level(f.manager, 1);
    (void)rome2_l81_fx_object_static_class_init(&f.names);
    assert(s_log_count == 2u);
    rome2_l80_log_manager_set_max_level(f.manager, 0);
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &early, "Early");
    assert(s_log_count == 2u);
    rome2_l80_log_manager_set_max_level(f.manager, 4);
    rome2_l81_fx_name_startup(&f.names);
    assert(f.names.name_table_va != 0u && f.manager->tab_level == 0u);
    assert(s_log_count == 2u + 6u); /* the two level 2 warnings from each of three class constructors */
}

static void test_client_event(void) {
    l81_fixture f;
    rome2_fx_name_32 group;
    rome2_fx_name_32 anim;
    rome2_fx_name_32 payload;
    rome2_fx_name_32 other;
    rome2_fx_client_event_32 ev1;
    rome2_fx_client_event_32 ev2;
    rome2_fx_client_event_32 ev3;
    fixture_init(&f, 1);
    rome2_l81_fx_name_startup(&f.names);
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &group, "Speech");
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &anim, "Centurion_Rally");
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &payload, "event_tag");
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &other, "Other");

    /* 0x10ed7d70 stores its second FxName at +0x00 and its first at +0x04 */
    memset(&ev1, 0, sizeof(ev1));
    assert(rome2_l81_fx_client_event_ctor_full(
               &f.names, &ev1, &anim, &group, 0.25f, 1.0f, 0.125f, 0.5f, 1.5f, 1u, 42u, &payload) == &ev1);
    assert(ev1.animation_group_name.entry_va == group.entry_va);
    assert(ev1.animation_name.entry_va == anim.entry_va);
    assert(ev1.custom_payload.entry_va == payload.entry_va);
    assert(ev1.start_time_offset == 0.25f && ev1.magnitude_scale == 1.0f);
    assert(ev1.blend_in_time == 0.125f && ev1.blend_out_time == 0.5f && ev1.duration_scale == 1.5f);
    assert(ev1.should_persist_values == 1u && ev1.event_id == 42u);
    assert(entry_at(&f, group.entry_va)->ref_count == 2);
    assert(entry_at(&f, anim.entry_va)->ref_count == 2);
    assert(entry_at(&f, payload.entry_va)->ref_count == 2);

    memset(&ev2, 0, sizeof(ev2));
    assert(rome2_l81_fx_client_event_ctor_copy(&f.names, &ev2, &ev1) == &ev2);
    assert(memcmp(&ev2, &ev1, sizeof(ev1)) == 0);
    assert(entry_at(&f, group.entry_va)->ref_count == 3);
    assert(entry_at(&f, payload.entry_va)->ref_count == 3);

    memset(&ev3, 0, sizeof(ev3));
    (void)rome2_l81_fx_client_event_ctor_full(
        &f.names, &ev3, &other, &other, 0.0f, 0.5f, 0.0f, 0.0f, 1.0f, 0u, 7u, &other);
    assert(entry_at(&f, other.entry_va)->ref_count == 4);
    assert(rome2_l81_fx_client_event_assign(&f.names, &ev3, &ev2) == &ev3);
    assert(memcmp(&ev3, &ev1, sizeof(ev1)) == 0);
    assert(entry_at(&f, other.entry_va)->ref_count == 1);
    assert(entry_at(&f, group.entry_va)->ref_count == 4);
    assert(entry_at(&f, anim.entry_va)->ref_count == 4);
    assert(entry_at(&f, payload.entry_va)->ref_count == 4);

    rome2_l81_fx_client_event_dtor(&f.names, &ev3);
    rome2_l81_fx_client_event_dtor(&f.names, &ev2);
    rome2_l81_fx_client_event_dtor(&f.names, &ev1);
    assert(entry_at(&f, group.entry_va)->ref_count == 1);
    assert(entry_at(&f, anim.entry_va)->ref_count == 1);
    assert(entry_at(&f, payload.entry_va)->ref_count == 1);
    assert(rome2_l81_fx_name_exists(&f.names, "Centurion_Rally") == 1u);
}

static void test_fx_class_registry(void) {
    l81_fixture f;
    const uint32_t *class_table;
    const uint32_t *class_items;
    uint32_t *words;
    rome2_fx_class_32 *desc;
    uint32_t old_items_va;
    uint32_t dup_va;
    uint32_t fifth_va;
    uint32_t object_va;
    uint32_t frees;
    fixture_init(&f, 1);
    rome2_l81_fx_name_startup(&f.names);
    class_table = (const uint32_t *)rome2_l80_const_ptr(&f.fx, L81_CLASS_TABLE_VA, 12u);
    assert(class_table != NULL && class_table[1] == 4u && class_table[2] == 3u);

    /* a second class under a registered name is reported and still appended */
    s_log_count = 0u;
    dup_va = rome2_l80_fx_allocate(&f.fx, (uint32_t)sizeof(rome2_fx_class_32));
    assert(rome2_l81_fx_class_ctor(
               &f.names, dup_va, "FxObject", 3u, f.names.fx_object_class_va, 0x20u, 0x10203040u) == dup_va);
    assert(s_log_count == 1u);
    expect_log(0u, 2, 0u, "Attempt to create duplicate FxClass!");
    desc = class_at(&f, dup_va);
    assert(desc->name.entry_va == class_at(&f, f.names.fx_object_class_va)->name.entry_va);
    assert(entry_at(&f, desc->name.entry_va)->ref_count == 2);
    assert(desc->current_version == 3u && desc->base_class_va == f.names.fx_object_class_va);
    assert(desc->num_children == 0u && desc->size == 0x20u && desc->construct_fn_va == 0x10203040u);
    assert(class_at(&f, f.names.fx_object_class_va)->num_children == 2u);
    assert(class_table[1] == 4u && class_table[2] == 4u);
    class_items = (const uint32_t *)rome2_l80_const_ptr(&f.fx, class_table[0], 16u);
    assert(class_items != NULL && class_items[3] == dup_va);

    /* a full array doubles; the search binds a nameless class to NullName as it passes */
    class_at(&f, f.names.fx_object_class_va)->name.entry_va = 0u;
    old_items_va = class_table[0];
    frees = s_free_count;
    s_log_count = 0u;
    fifth_va = rome2_l80_fx_allocate(&f.fx, (uint32_t)sizeof(rome2_fx_class_32));
    assert(rome2_l81_fx_class_ctor(&f.names, fifth_va, "Fifth", 1u, 0u, 0x30u, 0u) == fifth_va);
    assert(s_log_count == 0u);
    assert(class_at(&f, f.names.fx_object_class_va)->name.entry_va == f.names.null_name.entry_va);
    assert(class_table[0] != old_items_va && class_table[1] == 8u && class_table[2] == 5u);
    assert(s_free_count == frees + 1u);
    expect_free(frees, old_items_va, 16u);
    class_items = (const uint32_t *)rome2_l80_const_ptr(&f.fx, class_table[0], 32u);
    assert(class_items != NULL && class_items[0] == f.names.fx_object_class_va);
    assert(class_items[3] == dup_va && class_items[4] == fifth_va);

    /* 0x10ef3160 / 0x10f06ad0 */
    object_va = rome2_l80_fx_allocate(&f.fx, 8u);
    words = (uint32_t *)rome2_l80_mut_ptr(&f.fx, object_va, 8u);
    assert(words != NULL);
    assert(rome2_l81_fx_object_helper_bind(&f.names, object_va) == object_va);
    assert(words[0] == ROME2_FX_VTABLE_OBJECT_HELPER);
    words[1] = 0x55u;
    assert(rome2_l81_fx_ref_object_ctor(&f.names, object_va) == object_va);
    assert(words[0] == ROME2_FX_VTABLE_REF_OBJECT && words[1] == 0u);
}

int main(void) {
    test_fx_string();
    test_avl_tree();
    test_name_table();
    test_fx_name_lifecycle();
    test_fx_name_before_startup();
    test_client_event();
    test_fx_class_registry();
    printf("facefx_name_avl_table_ops tests passed\n");
    return 0;
}
