#include "facefx_name_avl_table_ops.h"

#include <string.h>

/*
 * Virtual slots the recovered bodies call that are not themselves in the
 * recovered set are adapted here as static helpers from the canonical
 * decompilation; they carry no contract pin:
 *   tree  0x1183b9c0  +0x04 -> 0x10edeee0 clear
 *                     +0x10 -> 0x10ee1590 unlink node and retrace
 *                     +0x14 -> 0x10ee0ed0 height / balance
 *   node  0x1183b99c  +0x08 -> 0x10edede0 deleting destructor (body 0x10ede030)
 *   entry 0x1183b970  +0x00 -> 0x10edf760 class descriptor
 *                     +0x08 -> 0x10edeea0 destructor
 * Guards marked "bounded" return where the original faults or spins.
 */

enum {
    L81_TREE_ROOT_OFFSET = 0x04,
    L81_NODE_KEY_OFFSET = 0x04,
    L81_NODE_LEFT_OFFSET = 0x2c,
    L81_NODE_RIGHT_OFFSET = 0x30,
    L81_BUCKET_BYTES = 0x0c,
    L81_NODE_STATS_BYTES = 0x59,
    L81_WALK_LIMIT = 0x100000,
    L81_DELETE_DEPTH_LIMIT = 64
};

static rome2_fx_avl_string_node_32 *l81_node(const rome2_l81_fx_name_ctx *ctx, uint32_t va) {
    if (va == 0u) {
        return NULL;
    }
    return (rome2_fx_avl_string_node_32 *)rome2_l80_mut_ptr(
        ctx->fx, va, (uint32_t)sizeof(rome2_fx_avl_string_node_32));
}

static rome2_fx_avl_bucket_32 *l81_tree(const rome2_l81_fx_name_ctx *ctx, uint32_t va) {
    if (va == 0u) {
        return NULL;
    }
    return (rome2_fx_avl_bucket_32 *)rome2_l80_mut_ptr(
        ctx->fx, va, (uint32_t)sizeof(rome2_fx_avl_bucket_32));
}

static rome2_fx_string_32 *l81_string(const rome2_l81_fx_name_ctx *ctx, uint32_t va) {
    if (va == 0u) {
        return NULL;
    }
    return (rome2_fx_string_32 *)rome2_l80_mut_ptr(ctx->fx, va, (uint32_t)sizeof(rome2_fx_string_32));
}

static rome2_fx_name_entry_32 *l81_entry(const rome2_l81_fx_name_ctx *ctx, uint32_t va) {
    if (va == 0u) {
        return NULL;
    }
    return (rome2_fx_name_entry_32 *)rome2_l80_mut_ptr(
        ctx->fx, va, (uint32_t)sizeof(rome2_fx_name_entry_32));
}

static rome2_fx_class_32 *l81_class(const rome2_l81_fx_name_ctx *ctx, uint32_t va) {
    if (va == 0u) {
        return NULL;
    }
    return (rome2_fx_class_32 *)rome2_l80_mut_ptr(ctx->fx, va, (uint32_t)sizeof(rome2_fx_class_32));
}

static uint32_t *l81_u32(const rome2_l81_fx_name_ctx *ctx, uint32_t va) {
    if (va == 0u) {
        return NULL;
    }
    return (uint32_t *)rome2_l80_mut_ptr(ctx->fx, va, 4u);
}

static rome2_fx_name_table_header_32 *l81_header(const rome2_l81_fx_name_ctx *ctx, uint32_t table_va) {
    if (ctx == NULL || ctx->fx == NULL || table_va == 0u) {
        return NULL;
    }
    /* the whole 0xc014-byte table must be addressable */
    return (rome2_fx_name_table_header_32 *)rome2_l80_mut_ptr(ctx->fx, table_va, ROME2_FX_NAME_TABLE_BYTES);
}

static uint32_t l81_bucket_va(uint32_t table_va, uint32_t index) {
    return table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES + index * L81_BUCKET_BYTES;
}

/* ---- logging: every message is gated on FxLogManager +0x84 >= level ---- */

static rome2_fx_log_manager_32 *l81_log_manager(const rome2_l81_fx_name_ctx *ctx) {
    if (ctx->fx->log_manager_singleton_va == 0u) {
        return NULL; /* bounded */
    }
    return (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(
        ctx->fx, ctx->fx->log_manager_singleton_va, (uint32_t)sizeof(rome2_fx_log_manager_32));
}

static rome2_fx_log_stream_32 *l81_log_open(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_log_entry_32 *entry,
    int32_t level) {
    const rome2_fx_log_manager_32 *mgr = l81_log_manager(ctx);
    if (mgr == NULL || mgr->max_log_level < level) {
        return NULL;
    }
    (void)rome2_l80_log_entry_create(entry, ctx->fx->log_manager_singleton_va + 4u, level);
    return rome2_l80_log_entry_get_stream(entry, mgr->tab_level);
}

static void l81_log_line(rome2_l81_fx_name_ctx *ctx, int32_t level, const char *text) {
    rome2_fx_log_entry_32 entry;
    rome2_fx_log_stream_32 *stream = l81_log_open(ctx, &entry, level);
    if (stream != NULL) {
        (void)rome2_l80_log_stream_push_cstr(stream, text);
        rome2_l80_log_entry_dtor(ctx->fx, &entry);
    }
}

static void l81_log_name_line(
    rome2_l81_fx_name_ctx *ctx,
    const char *prefix,
    const char *name,
    const char *suffix) {
    rome2_fx_log_entry_32 entry;
    rome2_fx_log_stream_32 *stream = l81_log_open(ctx, &entry, 1);
    if (stream != NULL) {
        (void)rome2_l80_log_stream_push_cstr(stream, prefix);
        (void)rome2_l80_log_stream_push_cstr(stream, name != NULL ? name : "");
        (void)rome2_l80_log_stream_push_cstr(stream, suffix);
        rome2_l80_log_entry_dtor(ctx->fx, &entry);
    }
}

static void l81_log_value_line(
    rome2_l81_fx_name_ctx *ctx,
    int32_t level,
    const char *prefix,
    int32_t value,
    const char *suffix) {
    rome2_fx_log_entry_32 entry;
    rome2_fx_log_stream_32 *stream = l81_log_open(ctx, &entry, level);
    if (stream != NULL) {
        (void)rome2_l80_log_stream_push_cstr(stream, prefix);
        (void)rome2_l80_log_stream_push_int(stream, value);
        (void)rome2_l80_log_stream_push_cstr(stream, suffix);
        rome2_l80_log_entry_dtor(ctx->fx, &entry);
    }
}

static void l81_tab(rome2_l81_fx_name_ctx *ctx, int32_t delta) {
    rome2_fx_log_manager_32 *mgr = l81_log_manager(ctx);
    if (mgr != NULL) {
        rome2_l80_log_manager_set_tab_level(mgr, (uint32_t)((int32_t)mgr->tab_level + delta));
    }
}

void rome2_l81_ctx_init(rome2_l81_fx_name_ctx *ctx, rome2_l80_fx_ctx *fx_ctx) {
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->fx = fx_ctx;
    }
}

/* ---- FxString ---- */

/* 0x10411670: the body builds a temporary and swaps it in; the resulting state is written directly. */
uint32_t rome2_l81_fx_string_ctor_slice(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *src,
    int32_t len) {
    rome2_fx_string_32 *self;
    uint32_t count;
    uint32_t capacity;
    uint32_t data_va;
    char *data;
    if (ctx == NULL || ctx->fx == NULL) {
        return 0u;
    }
    self = l81_string(ctx, self_va);
    if (self == NULL) {
        return 0u;
    }
    self->data_va = self_va;
    self->capacity = 0u;
    self->length = 0u;
    if (src == NULL || len < -1) {
        return self_va;
    }
    count = (len == -1) ? (uint32_t)strlen(src) : (uint32_t)len;
    if (count == 0u) {
        return self_va;
    }
    capacity = count + 1u;
    data_va = self_va;
    if (capacity > ROME2_FX_STRING_INLINE_BYTES) {
        data_va = rome2_l80_fx_allocate(ctx->fx, capacity);
    }
    data = (data_va == 0u) ? NULL : (char *)rome2_l80_mut_ptr(ctx->fx, data_va, capacity);
    if (data == NULL) {
        return self_va; /* bounded: the original copies through a failed allocation */
    }
    memcpy(data, src, count);
    data[count] = '\0';
    self->data_va = data_va;
    self->capacity = capacity;
    self->length = count;
    return self_va;
}

/* Inlined c_str(): an unset data pointer is rebound to the inline buffer, then data[length] = 0. */
const char *rome2_l81_fx_string_cstr(rome2_l81_fx_name_ctx *ctx, uint32_t self_va) {
    rome2_fx_string_32 *self;
    char *data;
    if (ctx == NULL || ctx->fx == NULL) {
        return NULL;
    }
    self = l81_string(ctx, self_va);
    if (self == NULL) {
        return NULL;
    }
    if (self->data_va == 0u) {
        self->data_va = self_va;
        self->capacity = ROME2_FX_STRING_INLINE_BYTES;
        self->length = 0u; /* FxFree(NULL, old capacity) follows and does nothing */
    }
    data = (char *)rome2_l80_mut_ptr(ctx->fx, self->data_va, self->length + 1u);
    if (data == NULL) {
        return NULL; /* bounded */
    }
    data[self->length] = '\0';
    return data;
}

/* 0x10eddab0 */
uint8_t rome2_l81_fx_string_equals_cstr(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *rhs) {
    const rome2_fx_string_32 *self;
    const char *data;
    uint32_t count;
    if (ctx == NULL || ctx->fx == NULL || rhs == NULL) {
        return 0u;
    }
    self = l81_string(ctx, self_va);
    if (self == NULL || self->length != strlen(rhs)) {
        return 0u;
    }
    count = self->length;
    data = rome2_l81_fx_string_cstr(ctx, self_va);
    return (uint8_t)(data != NULL && strncmp(data, rhs, count) == 0);
}

/* 0x10eddb40 */
uint8_t rome2_l81_fx_string_not_equals_cstr(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *rhs) {
    const rome2_fx_string_32 *self;
    const char *data;
    uint32_t count;
    if (ctx == NULL || ctx->fx == NULL || rhs == NULL) {
        return 1u;
    }
    self = l81_string(ctx, self_va);
    if (self == NULL || self->length != strlen(rhs)) {
        return 1u;
    }
    count = self->length;
    data = rome2_l81_fx_string_cstr(ctx, self_va);
    return (uint8_t)(data == NULL || strncmp(data, rhs, count) != 0);
}

/* ---- unrecovered tree and node slots ---- */

/* tree slot +0x14 (0x10ee0ed0) */
static void l81_update_metrics(const rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
    const rome2_fx_avl_string_node_32 *child;
    int32_t left_height = 0;
    int32_t right_height = 0;
    if (node == NULL) {
        return;
    }
    child = l81_node(ctx, node->left_va);
    if (child != NULL) {
        left_height = child->height;
    }
    child = l81_node(ctx, node->right_va);
    if (child != NULL) {
        right_height = child->height;
    }
    node->height = (left_height < right_height ? right_height : left_height) + 1;
    node->balance = (int16_t)((int16_t)right_height - (int16_t)left_height);
}

/* node slot +0x08 (0x10edede0 over 0x10ede030): children, key buffer, then the 0x38-byte block */
static void l81_delete_subtree(rome2_l81_fx_name_ctx *ctx, uint32_t node_va, uint32_t depth) {
    rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
    if (node == NULL || depth > L81_DELETE_DEPTH_LIMIT) {
        return; /* bounded */
    }
    node->vtable_va = ROME2_FX_VTABLE_AVL_NODE_BASE;
    l81_delete_subtree(ctx, node->left_va, depth + 1u);
    l81_delete_subtree(ctx, node->right_va, depth + 1u);
    if (node->key.data_va != node_va + L81_NODE_KEY_OFFSET) {
        rome2_l80_fx_free(ctx->fx, node->key.data_va, node->key.capacity);
    }
    node->key.data_va = 0u;
    node->key.length = 0u;
    node->key.capacity = 0u;
    node->vtable_va = ROME2_FX_VTABLE_OBJECT_HELPER;
    rome2_l80_fx_free(ctx->fx, node_va, (uint32_t)sizeof(*node));
}

/* tree slot +0x04 (0x10edeee0) */
static void l81_tree_clear(rome2_l81_fx_name_ctx *ctx, uint32_t tree_va) {
    rome2_fx_avl_bucket_32 *tree = l81_tree(ctx, tree_va);
    if (tree == NULL) {
        return;
    }
    if (tree->root_va != 0u) {
        l81_delete_subtree(ctx, tree->root_va, 0u);
    }
    tree->node_count = 0u;
    tree->root_va = 0u;
}

static uint32_t l81_leftmost(const rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    uint32_t steps = 0u;
    while (node_va != 0u && steps++ < L81_WALK_LIMIT) {
        const rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
        if (node == NULL || node->left_va == 0u) {
            break;
        }
        node_va = node->left_va;
    }
    return node_va;
}

/* In-order successor step inlined in 0x10edea00 and 0x10edf860. */
static uint32_t l81_successor(const rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    const rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
    uint32_t parent_va;
    uint32_t steps = 0u;
    if (node == NULL) {
        return 0u;
    }
    if (node->right_va != 0u) {
        return l81_leftmost(ctx, node->right_va);
    }
    parent_va = node->parent_va;
    while (parent_va != 0u && steps++ < L81_WALK_LIMIT) {
        const rome2_fx_avl_string_node_32 *parent = l81_node(ctx, parent_va);
        if (parent == NULL) {
            return 0u;
        }
        if (parent->right_va != node_va) {
            break;
        }
        node_va = parent_va;
        parent_va = parent->parent_va;
    }
    return parent_va;
}

/* ---- AVL string tree ---- */

/* 0x10eddc90: the key arrives as an FxString; its data pointer and length are passed here. */
uint32_t rome2_l81_avl_string_node_ctor(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    uint32_t parent_va,
    const char *key,
    uint32_t key_len,
    uint32_t value_va) {
    rome2_fx_avl_string_node_32 *node;
    uint32_t capacity;
    uint32_t data_va;
    char *data;
    if (ctx == NULL || ctx->fx == NULL || (key == NULL && key_len != 0u)) {
        return 0u;
    }
    node = l81_node(ctx, self_va);
    if (node == NULL) {
        return 0u;
    }
    node->vtable_va = ROME2_FX_VTABLE_AVL_NODE_BASE;
    capacity = (key_len != 0u) ? key_len + 1u : 0u;
    data_va = self_va + L81_NODE_KEY_OFFSET;
    if (capacity > ROME2_FX_STRING_INLINE_BYTES) {
        data_va = rome2_l80_fx_allocate(ctx->fx, capacity);
    }
    data = (data_va == 0u) ? NULL : (char *)rome2_l80_mut_ptr(ctx->fx, data_va, key_len + 1u);
    if (data == NULL) {
        return 0u; /* bounded: the original copies through a failed allocation */
    }
    node->key.data_va = data_va;
    node->key.capacity = capacity;
    node->key.length = key_len;
    if (key_len != 0u) {
        memcpy(data, key, key_len);
        data[key_len] = '\0';
    }
    node->value_va = value_va;
    node->parent_va = parent_va;
    node->balance = 0;
    node->height = 0;
    node->right_va = 0u;
    node->left_va = 0u;
    node->vtable_va = ROME2_FX_VTABLE_AVL_STRING_NODE;
    return self_va;
}

/* 0x10eddfb0 */
uint32_t rome2_l81_avl_bucket_ctor(rome2_l81_fx_name_ctx *ctx, uint32_t tree_va) {
    rome2_fx_avl_bucket_32 *tree;
    if (ctx == NULL || ctx->fx == NULL) {
        return 0u;
    }
    tree = l81_tree(ctx, tree_va);
    if (tree == NULL) {
        return 0u;
    }
    tree->root_va = 0u;
    tree->node_count = 0u;
    tree->vtable_va = ROME2_FX_VTABLE_AVL_BUCKET;
    return tree_va;
}

/* 0x10ede150 */
void rome2_l81_avl_bucket_dtor(rome2_l81_fx_name_ctx *ctx, uint32_t tree_va) {
    rome2_fx_avl_bucket_32 *tree;
    if (ctx == NULL || ctx->fx == NULL) {
        return;
    }
    tree = l81_tree(ctx, tree_va);
    if (tree == NULL) {
        return;
    }
    tree->vtable_va = ROME2_FX_VTABLE_AVL_TREE_BASE;
    if (tree->root_va != 0u) {
        l81_delete_subtree(ctx, tree->root_va, 0u);
    }
    tree->node_count = 0u;
    tree->root_va = 0u;
}

/* Shared body of 0x10ee19c0 (toward = left link) and 0x10ee1a20 (toward = right link). */
static void l81_rotate(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t slot_va,
    uint32_t away_offset,
    uint32_t toward_offset) {
    uint32_t *slot = l81_u32(ctx, slot_va);
    uint32_t node_va;
    uint32_t pivot_va;
    uint32_t parent_va;
    uint32_t moved_va;
    rome2_fx_avl_string_node_32 *node;
    rome2_fx_avl_string_node_32 *pivot;
    uint32_t *node_away;
    uint32_t *pivot_toward;
    uint32_t *pivot_away;
    if (slot == NULL) {
        return;
    }
    node_va = *slot;
    node = l81_node(ctx, node_va);
    node_away = l81_u32(ctx, node_va + away_offset);
    if (node == NULL || node_away == NULL) {
        return; /* bounded */
    }
    pivot_va = *node_away;
    pivot = l81_node(ctx, pivot_va);
    pivot_toward = l81_u32(ctx, pivot_va + toward_offset);
    pivot_away = l81_u32(ctx, pivot_va + away_offset);
    if (pivot == NULL || pivot_toward == NULL || pivot_away == NULL) {
        return; /* bounded: the original requires the child it rotates up */
    }
    parent_va = node->parent_va;
    *slot = pivot_va;
    moved_va = *pivot_toward;
    *node_away = moved_va;
    if (moved_va != 0u) {
        rome2_fx_avl_string_node_32 *moved = l81_node(ctx, moved_va);
        if (moved != NULL) {
            moved->parent_va = node_va;
        }
    }
    *pivot_toward = node_va;
    pivot->parent_va = parent_va;
    node->parent_va = pivot_va;
    l81_update_metrics(ctx, pivot->left_va);
    l81_update_metrics(ctx, pivot->right_va);
    l81_update_metrics(ctx, pivot_va);
}

/* 0x10ee19c0 */
void rome2_l81_avl_rotate_left(rome2_l81_fx_name_ctx *ctx, uint32_t tree_va, uint32_t slot_va) {
    (void)tree_va; /* only its metrics slot is used */
    if (ctx != NULL && ctx->fx != NULL) {
        l81_rotate(ctx, slot_va, L81_NODE_RIGHT_OFFSET, L81_NODE_LEFT_OFFSET);
    }
}

/* 0x10ee1a20 */
void rome2_l81_avl_rotate_right(rome2_l81_fx_name_ctx *ctx, uint32_t tree_va, uint32_t slot_va) {
    (void)tree_va;
    if (ctx != NULL && ctx->fx != NULL) {
        l81_rotate(ctx, slot_va, L81_NODE_LEFT_OFFSET, L81_NODE_RIGHT_OFFSET);
    }
}

/* The retrace loop inlined in 0x10edfc40 and repeated in the unlink slot 0x10ee1590. */
static void l81_retrace(rome2_l81_fx_name_ctx *ctx, uint32_t tree_va, uint32_t start_va) {
    uint32_t node_va = start_va;
    uint32_t steps = 0u;
    while (node_va != 0u && steps++ < L81_WALK_LIMIT) {
        const rome2_fx_avl_string_node_32 *node;
        const rome2_fx_avl_string_node_32 *top;
        const rome2_fx_avl_string_node_32 *child;
        uint32_t slot_va = tree_va + L81_TREE_ROOT_OFFSET;
        const uint32_t *slot;
        l81_update_metrics(ctx, node_va);
        node = l81_node(ctx, node_va);
        if (node == NULL) {
            return;
        }
        if (node->parent_va != 0u) {
            const rome2_fx_avl_string_node_32 *parent = l81_node(ctx, node->parent_va);
            if (parent == NULL) {
                return;
            }
            slot_va = node->parent_va +
                      (parent->left_va != node_va ? L81_NODE_RIGHT_OFFSET : L81_NODE_LEFT_OFFSET);
        }
        slot = l81_u32(ctx, slot_va);
        if (slot == NULL) {
            return;
        }
        top = l81_node(ctx, *slot);
        if (top == NULL) {
            return;
        }
        if (top->balance > 1 && top->right_va != 0u) {
            child = l81_node(ctx, top->right_va);
            if (child != NULL && child->balance < 0) {
                rome2_l81_avl_rotate_right(ctx, tree_va, *slot + L81_NODE_RIGHT_OFFSET);
            }
            rome2_l81_avl_rotate_left(ctx, tree_va, slot_va);
        }
        top = l81_node(ctx, *slot);
        if (top == NULL) {
            return;
        }
        if (top->balance < -1 && top->left_va != 0u) {
            child = l81_node(ctx, top->left_va);
            if (child != NULL && child->balance >= 1) {
                rome2_l81_avl_rotate_left(ctx, tree_va, *slot + L81_NODE_LEFT_OFFSET);
            }
            rome2_l81_avl_rotate_right(ctx, tree_va, slot_va);
        }
        node_va = node->parent_va;
    }
}

/* tree slot +0x10 (0x10ee1590): relink around the node, delete it, retrace from the lowest changed parent */
static void l81_tree_unlink(rome2_l81_fx_name_ctx *ctx, uint32_t tree_va, uint32_t node_va) {
    rome2_fx_avl_bucket_32 *tree = l81_tree(ctx, tree_va);
    rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
    rome2_fx_avl_string_node_32 *parent;
    rome2_fx_avl_string_node_32 *left;
    rome2_fx_avl_string_node_32 *right;
    uint32_t *parent_link;
    uint32_t parent_va;
    uint32_t start_va;
    if (tree == NULL || node == NULL) {
        return;
    }
    parent_va = node->parent_va;
    parent = l81_node(ctx, parent_va);
    left = l81_node(ctx, node->left_va);
    right = l81_node(ctx, node->right_va);
    parent_link = &tree->root_va;
    if (parent != NULL) {
        parent_link = (parent->left_va == node_va) ? &parent->left_va : &parent->right_va;
    }
    if (right == NULL) {
        *parent_link = node->left_va;
        if (left != NULL) {
            left->parent_va = parent_va;
        }
        start_va = parent_va;
    } else if (right->left_va == 0u) {
        *parent_link = node->right_va;
        right->parent_va = parent_va;
        right->left_va = node->left_va;
        if (left != NULL) {
            left->parent_va = node->right_va;
        }
        start_va = node->right_va;
    } else {
        uint32_t successor_va = l81_leftmost(ctx, right->left_va);
        rome2_fx_avl_string_node_32 *successor = l81_node(ctx, successor_va);
        rome2_fx_avl_string_node_32 *successor_parent;
        rome2_fx_avl_string_node_32 *moved;
        if (successor == NULL) {
            return;
        }
        start_va = successor->parent_va;
        successor_parent = l81_node(ctx, start_va);
        if (successor_parent == NULL) {
            return;
        }
        *parent_link = successor_va;
        successor->parent_va = parent_va;
        successor_parent->left_va = successor->right_va;
        moved = l81_node(ctx, successor->right_va);
        if (moved != NULL) {
            moved->parent_va = start_va;
        }
        successor->right_va = node->right_va;
        moved = l81_node(ctx, successor->right_va);
        if (moved != NULL) {
            moved->parent_va = successor_va;
        }
        successor->left_va = node->left_va;
        if (left != NULL) {
            left->parent_va = successor_va;
        }
    }
    node->parent_va = 0u;
    node->left_va = 0u;
    node->right_va = 0u;
    l81_delete_subtree(ctx, node_va, 0u);
    tree->node_count--;
    l81_retrace(ctx, tree_va, start_va);
}

/* 0x10edfb00 */
rome2_l81_avl_iter *rome2_l81_avl_find(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t tree_va,
    rome2_l81_avl_iter *out,
    const char *key) {
    const rome2_fx_avl_bucket_32 *tree;
    uint32_t node_va;
    uint32_t steps = 0u;
    if (out == NULL) {
        return NULL;
    }
    out->tree_va = tree_va;
    out->node_va = 0u;
    if (ctx == NULL || ctx->fx == NULL || key == NULL) {
        return out;
    }
    tree = l81_tree(ctx, tree_va);
    if (tree == NULL) {
        return out;
    }
    node_va = tree->root_va;
    while (node_va != 0u && steps++ < L81_WALK_LIMIT) {
        const char *node_key = rome2_l81_fx_string_cstr(ctx, node_va + L81_NODE_KEY_OFFSET);
        const rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
        int order;
        if (node_key == NULL || node == NULL) {
            return out;
        }
        order = strcmp(key, node_key);
        if (order == 0) {
            out->node_va = node_va;
            return out;
        }
        node_va = (order < 0) ? node->left_va : node->right_va;
    }
    return out;
}

/* 0x10edfc40: a duplicate key returns {tree, NULL} and inserts nothing. */
rome2_l81_avl_iter *rome2_l81_avl_insert(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t tree_va,
    rome2_l81_avl_iter *out,
    const char *key,
    uint32_t value_va) {
    rome2_fx_avl_bucket_32 *tree;
    uint32_t node_va;
    uint32_t parent_va = 0u;
    uint32_t link_offset = L81_NODE_LEFT_OFFSET;
    uint32_t *slot;
    uint32_t block_va;
    uint32_t new_va = 0u;
    uint32_t steps = 0u;
    if (out == NULL) {
        return NULL;
    }
    out->tree_va = tree_va;
    out->node_va = 0u;
    if (ctx == NULL || ctx->fx == NULL || key == NULL) {
        return out;
    }
    tree = l81_tree(ctx, tree_va);
    if (tree == NULL) {
        return out;
    }
    node_va = tree->root_va;
    while (node_va != 0u) {
        const char *node_key = rome2_l81_fx_string_cstr(ctx, node_va + L81_NODE_KEY_OFFSET);
        const rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
        int order;
        if (node_key == NULL || node == NULL || steps++ >= L81_WALK_LIMIT) {
            return out; /* bounded */
        }
        order = strcmp(key, node_key);
        if (order == 0) {
            return out;
        }
        link_offset = (order < 0) ? L81_NODE_LEFT_OFFSET : L81_NODE_RIGHT_OFFSET;
        parent_va = node_va;
        node_va = (order < 0) ? node->left_va : node->right_va;
    }
    slot = l81_u32(ctx, parent_va != 0u ? parent_va + link_offset : tree_va + L81_TREE_ROOT_OFFSET);
    if (slot == NULL) {
        return out;
    }
    block_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_avl_string_node_32));
    if (block_va != 0u) {
        /*
         * 0x10411670 first builds the key as a stack FxString. Keys of 16 bytes or
         * more give that temporary a heap buffer, freed once the node has its copy.
         */
        uint32_t key_len = (uint32_t)strlen(key);
        uint32_t temp_va = 0u;
        if (key_len + 1u > ROME2_FX_STRING_INLINE_BYTES) {
            temp_va = rome2_l80_fx_allocate(ctx->fx, key_len + 1u);
        }
        new_va = rome2_l81_avl_string_node_ctor(ctx, block_va, parent_va, key, key_len, value_va);
        if (new_va == 0u) {
            rome2_l80_fx_free(ctx->fx, block_va, (uint32_t)sizeof(rome2_fx_avl_string_node_32)); /* bounded */
        }
        *slot = new_va;
        rome2_l80_fx_free(ctx->fx, temp_va, key_len + 1u);
    } else {
        *slot = 0u;
    }
    tree->node_count++; /* also when the allocation failed */
    l81_retrace(ctx, tree_va, new_va);
    out->node_va = new_va;
    return out;
}

/* 0x10edff50: the walk; the unlink itself is tree slot +0x10. */
uint8_t rome2_l81_avl_remove_key(rome2_l81_fx_name_ctx *ctx, uint32_t tree_va, const char *key) {
    const rome2_fx_avl_bucket_32 *tree;
    uint32_t node_va;
    uint32_t steps = 0u;
    if (ctx == NULL || ctx->fx == NULL || key == NULL) {
        return 0u;
    }
    tree = l81_tree(ctx, tree_va);
    if (tree == NULL) {
        return 0u;
    }
    node_va = tree->root_va;
    while (node_va != 0u && steps++ < L81_WALK_LIMIT) {
        const char *node_key = rome2_l81_fx_string_cstr(ctx, node_va + L81_NODE_KEY_OFFSET);
        const rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
        int order;
        if (node_key == NULL || node == NULL) {
            return 0u;
        }
        order = strcmp(key, node_key);
        if (order == 0) {
            l81_tree_unlink(ctx, tree_va, node_va);
            return 1u;
        }
        node_va = (order < 0) ? node->left_va : node->right_va;
    }
    return 0u;
}

/* ---- name table ---- */

/* The hash inlined in 0x10edf5f0, 0x10edf9f0 and 0x10ee0140: seed 0x1505, h * 33 + sign-extended byte. */
uint32_t rome2_l81_djb2_hash(const char *s) {
    uint32_t hash = 0x1505u;
    if (s != NULL) {
        for (; *s != '\0'; ++s) {
            hash = hash * 0x21u + (uint32_t)(int32_t)(signed char)*s;
        }
    }
    return hash;
}

static void l81_iter_set_end(rome2_l81_name_iter *iter) {
    iter->bucket_index = -1;
    iter->bucket_va = iter->table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES;
    iter->node_va = 0u;
}

/* 0x10eddfd0 */
void rome2_l81_name_table_dtor(rome2_l81_fx_name_ctx *ctx, uint32_t table_va) {
    rome2_fx_name_table_header_32 *header = l81_header(ctx, table_va);
    uint32_t i;
    if (header == NULL) {
        return;
    }
    for (i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        l81_tree_clear(ctx, l81_bucket_va(table_va, i));
    }
    memset(header, 0, sizeof(*header));
    for (i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        rome2_l81_avl_bucket_dtor(ctx, l81_bucket_va(table_va, i));
    }
}

/* 0x10edf5f0: a hit bumps header +0x10. */
rome2_l81_name_iter *rome2_l81_name_table_find(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t table_va,
    rome2_l81_name_iter *out,
    const char *key) {
    rome2_fx_name_table_header_32 *header = l81_header(ctx, table_va);
    rome2_l81_avl_iter found;
    uint32_t index;
    if (out == NULL) {
        return NULL;
    }
    out->table_va = table_va;
    out->bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    l81_iter_set_end(out);
    if (header == NULL || key == NULL) {
        return out; /* bounded */
    }
    index = rome2_l81_djb2_hash(key) & 0xfffu;
    (void)rome2_l81_avl_find(ctx, l81_bucket_va(table_va, index), &found, key);
    if (found.tree_va != 0u && found.node_va != 0u) {
        header->probe_hits++;
        out->bucket_index = (int32_t)index;
        out->bucket_va = found.tree_va;
        out->node_va = found.node_va;
    }
    return out;
}

/* 0x10edf9f0: a rejected insert also bumps header +0x10. */
rome2_l81_name_iter *rome2_l81_name_table_insert(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t table_va,
    rome2_l81_name_iter *out,
    const char *key,
    uint32_t entry_va) {
    rome2_fx_name_table_header_32 *header = l81_header(ctx, table_va);
    const rome2_fx_avl_bucket_32 *bucket;
    rome2_l81_avl_iter inserted;
    uint32_t index;
    uint32_t root_before;
    if (out == NULL) {
        return NULL;
    }
    out->table_va = table_va;
    out->bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    l81_iter_set_end(out);
    if (header == NULL || key == NULL) {
        return out; /* bounded */
    }
    index = rome2_l81_djb2_hash(key) & 0xfffu;
    bucket = l81_tree(ctx, l81_bucket_va(table_va, index));
    if (bucket == NULL) {
        return out;
    }
    root_before = bucket->root_va;
    (void)rome2_l81_avl_insert(ctx, l81_bucket_va(table_va, index), &inserted, key, entry_va);
    if (inserted.tree_va != 0u && inserted.node_va != 0u) {
        if (root_before != 0u) {
            header->hash_collisions++;
        }
        header->unique_count++;
        header->total_added++;
        out->bucket_index = (int32_t)index;
        out->bucket_va = inserted.tree_va;
        out->node_va = inserted.node_va;
    } else {
        header->probe_hits++;
    }
    return out;
}

/* 0x10ee0140 */
uint8_t rome2_l81_name_table_remove(rome2_l81_fx_name_ctx *ctx, uint32_t table_va, const char *key) {
    rome2_fx_name_table_header_32 *header = l81_header(ctx, table_va);
    uint32_t index;
    if (header == NULL || key == NULL) {
        return 0u; /* bounded */
    }
    index = rome2_l81_djb2_hash(key) & 0xfffu;
    if (rome2_l81_avl_remove_key(ctx, l81_bucket_va(table_va, index), key) != 0u) {
        header->unique_count--;
        header->total_removed++;
        return 1u;
    }
    return 0u;
}

/* First bucket at or after `from` whose node count is non-zero, else `fallback`. */
static uint32_t l81_next_used_bucket(
    const rome2_l81_fx_name_ctx *ctx,
    const rome2_l81_name_iter *iter,
    uint32_t from,
    uint32_t fallback) {
    uint32_t i;
    for (i = from; i < iter->bucket_count && i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        const rome2_fx_avl_bucket_32 *bucket = l81_tree(ctx, l81_bucket_va(iter->table_va, i));
        if (bucket != NULL && bucket->node_count != 0u) {
            return i;
        }
    }
    return fallback;
}

static void l81_iter_enter_bucket(
    const rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_iter *iter,
    uint32_t index) {
    const rome2_fx_avl_bucket_32 *bucket = l81_tree(ctx, l81_bucket_va(iter->table_va, index));
    iter->bucket_index = (int32_t)index;
    iter->bucket_va = l81_bucket_va(iter->table_va, index);
    iter->node_va = (bucket != NULL) ? l81_leftmost(ctx, bucket->root_va) : 0u;
}

/* 0x10edea00 */
void rome2_l81_name_iter_advance(rome2_l81_fx_name_ctx *ctx, rome2_l81_name_iter *iter) {
    uint32_t next_va;
    if (iter == NULL || l81_header(ctx, iter->table_va) == NULL) {
        return; /* bounded */
    }
    if (iter->bucket_index == -1) {
        l81_iter_enter_bucket(ctx, iter, l81_next_used_bucket(ctx, iter, 0u, 0u));
        if (iter->node_va == 0u) {
            l81_iter_set_end(iter);
        }
        return;
    }
    if (iter->node_va == 0u) {
        const rome2_fx_avl_bucket_32 *bucket = l81_tree(ctx, iter->bucket_va);
        next_va = (bucket != NULL) ? l81_leftmost(ctx, bucket->root_va) : 0u;
    } else {
        next_va = l81_successor(ctx, iter->node_va);
    }
    iter->node_va = next_va;
    if (iter->bucket_va == 0u || next_va == 0u) {
        uint32_t index = (uint32_t)iter->bucket_index;
        uint32_t found = l81_next_used_bucket(ctx, iter, index + 1u, index);
        if (found == index) {
            l81_iter_set_end(iter);
            return;
        }
        l81_iter_enter_bucket(ctx, iter, found);
    }
}

static uint8_t l81_iter_is_end(const rome2_l81_name_iter *iter) {
    return (uint8_t)(iter->bucket_index == -1 &&
                     iter->bucket_va == iter->table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES &&
                     iter->node_va == 0u);
}

/* ---- FxNameEntry slots and the release sequence ---- */

/* entry slot +0x00 (0x10edf760); 0x10ee0b20 carries the same body inline. */
static uint32_t l81_name_entry_class(rome2_l81_fx_name_ctx *ctx) {
    if (ctx->fx_name_entry_class_va == 0u) {
        uint32_t block_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_class_32));
        if (block_va != 0u) {
            if (ctx->fx_ref_object_class_va == 0u) {
                ctx->fx_ref_object_class_va = rome2_l81_fx_ref_object_static_class_init(ctx);
            }
            ctx->fx_name_entry_class_va = rome2_l81_fx_class_ctor(
                ctx,
                block_va,
                "FxNameEntry",
                0u,
                ctx->fx_ref_object_class_va,
                (uint32_t)sizeof(rome2_fx_name_entry_32),
                ROME2_L81_VA_FX_NAME_ENTRY_CONSTRUCT);
        }
    }
    return ctx->fx_name_entry_class_va;
}

/* entry slot +0x08 (0x10edeea0) without the free */
static void l81_entry_destruct(rome2_fx_name_entry_32 *entry) {
    entry->vtable_va = ROME2_FX_VTABLE_OBJECT_HELPER; /* through 0x1183b970 and 0x1183de70 */
}

/*
 * The sequence inlined in 0x10ede090, 0x10ede180, 0x10ede2b0, 0x10ee07c0 and
 * 0x10ee1a80: the last reference unregisters the name, then the entry is
 * destroyed and freed with the size its class descriptor reports.
 */
static void l81_release_entry(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    uint32_t entry_va = self->entry_va;
    rome2_fx_name_entry_32 *entry = l81_entry(ctx, entry_va);
    int32_t refs;
    if (entry == NULL) {
        return;
    }
    refs = entry->ref_count;
    if (refs == 1) {
        const char *key = rome2_l81_fx_string_cstr(ctx, entry->fx_string_va);
        if (key != NULL) {
            (void)rome2_l81_name_table_remove(ctx, ctx->name_table_va, key);
        }
        self->entry_va = 0u;
        refs = entry->ref_count;
    }
    entry->ref_count = refs - 1;
    if (refs - 1 == 0) {
        const rome2_fx_class_32 *desc = l81_class(ctx, l81_name_entry_class(ctx));
        uint32_t size = (desc != NULL) ? desc->size : (uint32_t)sizeof(*entry); /* bounded */
        l81_entry_destruct(entry);
        rome2_l80_fx_free(ctx->fx, entry_va, size);
    }
}

/* The lazy NullName bind the const accessors inline; it takes no reference. */
static rome2_fx_name_entry_32 *l81_bound_entry(const rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    if (self->entry_va == 0u) {
        self->entry_va = ctx->null_name.entry_va;
    }
    return l81_entry(ctx, self->entry_va);
}

static void l81_add_ref(const rome2_l81_fx_name_ctx *ctx, uint32_t entry_va) {
    rome2_fx_name_entry_32 *entry = l81_entry(ctx, entry_va);
    if (entry != NULL) {
        entry->ref_count++;
    }
}

/* ---- FxName statics ---- */

/* 0x10ee0b20 */
void rome2_l81_fx_name_startup(rome2_l81_fx_name_ctx *ctx) {
    if (ctx == NULL || ctx->fx == NULL) {
        return;
    }
    l81_log_line(ctx, 5, "Starting up name manager...");
    l81_tab(ctx, 1);
    l81_log_value_line(ctx, 6, "FX_ALLOW_SPACES_IN_NAMES is ", 1, ".");
    l81_log_value_line(ctx, 6, "FX_MAX_NAME_LENGTH is ", (int32_t)ROME2_FX_NAME_MAX_LEN, ".");
    if (ctx->name_table_va == 0u) {
        uint32_t table_va = rome2_l80_fx_allocate(ctx->fx, ROME2_FX_NAME_TABLE_BYTES);
        uint8_t *bytes = (table_va == 0u)
            ? NULL
            : (uint8_t *)rome2_l80_mut_ptr(ctx->fx, table_va, ROME2_FX_NAME_TABLE_BYTES);
        if (bytes != NULL) { /* bounded: the original writes through a failed allocation */
            uint32_t i;
            ctx->name_table_va = table_va;
            memset(bytes, 0, ROME2_FX_NAME_TABLE_BYTES);
            for (i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
                (void)rome2_l81_avl_bucket_ctor(ctx, l81_bucket_va(table_va, i));
            }
            (void)l81_name_entry_class(ctx);
            (void)rome2_l81_fx_name_assign_cstr(ctx, &ctx->null_name, "");
            (void)rome2_l81_fx_name_assign_cstr(ctx, &ctx->default_name, "Default");
            (void)rome2_l81_fx_name_assign_cstr(ctx, &ctx->new_actor_name, "NewActor");
        }
    }
    l81_tab(ctx, -1);
    l81_log_line(ctx, 5, "Name manager startup complete.");
}

/* 0x10ee0890: every remaining name is unregistered and its entry deleted, whatever its reference count. */
void rome2_l81_fx_name_shutdown(rome2_l81_fx_name_ctx *ctx) {
    rome2_fx_name_table_header_32 *header;
    uint32_t table_va;
    uint32_t steps = 0u;
    uint32_t i;
    rome2_l81_name_iter scan;
    if (ctx == NULL || ctx->fx == NULL) {
        return;
    }
    table_va = ctx->name_table_va;
    header = l81_header(ctx, table_va);
    if (header == NULL) {
        return; /* bounded: the original reads through a NULL table */
    }
    l81_log_line(ctx, 5, "Shutting down name manager...");
    l81_tab(ctx, 1);
    scan.table_va = table_va;
    scan.bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    l81_iter_set_end(&scan);
    while (header->unique_count != 0u && steps++ < L81_WALK_LIMIT) {
        const rome2_fx_avl_string_node_32 *node;
        const char *key;
        uint32_t entry_va;
        l81_iter_enter_bucket(ctx, &scan, l81_next_used_bucket(ctx, &scan, 0u, 0u));
        node = l81_node(ctx, scan.node_va);
        key = rome2_l81_fx_string_cstr(ctx, scan.node_va + L81_NODE_KEY_OFFSET);
        if (node == NULL || key == NULL) {
            break; /* bounded: the original spins when the count and the buckets disagree */
        }
        entry_va = node->value_va;
        (void)rome2_l81_name_table_remove(ctx, table_va, key);
        if (entry_va != 0u) {
            rome2_fx_name_entry_32 *entry = l81_entry(ctx, entry_va);
            if (entry != NULL) {
                l81_entry_destruct(entry);
                rome2_l80_fx_free(ctx->fx, entry_va, (uint32_t)sizeof(*entry));
            }
        }
    }
    for (i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        l81_tree_clear(ctx, l81_bucket_va(table_va, i));
    }
    memset(header, 0, sizeof(*header));
    rome2_l81_name_table_dtor(ctx, table_va);
    rome2_l80_fx_free(ctx->fx, table_va, ROME2_FX_NAME_TABLE_BYTES);
    ctx->name_table_va = 0u;
    ctx->null_name.entry_va = 0u;
    ctx->default_name.entry_va = 0u;
    ctx->new_actor_name.entry_va = 0u;
    l81_tab(ctx, -1);
    l81_log_line(ctx, 5, "Name manager shutdown complete.");
}

/* 0x10edf360 */
void rome2_l81_fx_name_dump_to_log(rome2_l81_fx_name_ctx *ctx) {
    const rome2_fx_name_table_header_32 *header;
    rome2_l81_name_iter iter;
    int32_t line = 0;
    uint32_t steps = 0u;
    if (ctx == NULL || ctx->fx == NULL) {
        return;
    }
    header = l81_header(ctx, ctx->name_table_va);
    if (header == NULL) {
        return; /* bounded */
    }
    l81_log_value_line(ctx, 4, "Name table [", (int32_t)header->unique_count, " names]:");
    l81_tab(ctx, 1);
    iter.table_va = ctx->name_table_va;
    iter.bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    l81_iter_set_end(&iter);
    rome2_l81_name_iter_advance(ctx, &iter); /* the inlined begin() */
    while (l81_iter_is_end(&iter) == 0u && steps++ < L81_WALK_LIMIT) {
        const rome2_fx_avl_string_node_32 *node = l81_node(ctx, iter.node_va);
        const rome2_fx_name_entry_32 *entry = (node != NULL) ? l81_entry(ctx, node->value_va) : NULL;
        rome2_fx_log_entry_32 log_entry;
        rome2_fx_log_stream_32 *stream;
        uint32_t refs;
        if (entry == NULL) {
            break; /* bounded */
        }
        refs = (uint32_t)entry->ref_count;
        stream = l81_log_open(ctx, &log_entry, 4);
        if (stream != NULL) {
            const char *text = rome2_l81_fx_string_cstr(ctx, entry->fx_string_va);
            (void)rome2_l80_log_stream_push_cstr(stream, "[");
            (void)rome2_l80_log_stream_push_int(stream, line++);
            (void)rome2_l80_log_stream_push_cstr(stream, "]: ");
            (void)rome2_l80_log_stream_push_cstr(stream, text != NULL ? text : "");
            (void)rome2_l80_log_stream_push_cstr(stream, " (");
            (void)rome2_l80_log_stream_push_int(stream, (int32_t)refs);
            (void)rome2_l80_log_stream_push_cstr(stream, refs < 2u ? " reference)" : " references)");
            rome2_l80_log_entry_dtor(ctx->fx, &log_entry);
        }
        rome2_l81_name_iter_advance(ctx, &iter);
    }
    l81_tab(ctx, -1);
}

/* 0x10edf860 */
void rome2_l81_fx_name_get_stats(rome2_l81_fx_name_ctx *ctx, rome2_l81_name_stats *out_stats) {
    const rome2_fx_name_table_header_32 *header;
    uint32_t i;
    if (ctx == NULL || ctx->fx == NULL || out_stats == NULL) {
        return;
    }
    header = l81_header(ctx, ctx->name_table_va);
    if (header == NULL) {
        return; /* bounded */
    }
    out_stats->num_names = header->unique_count;
    out_stats->num_collisions = header->hash_collisions;
    out_stats->num_added = header->total_added;
    out_stats->num_probes = header->probe_hits;
    out_stats->bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    out_stats->non_empty_buckets = 0u;
    out_stats->mem_bytes = 0xc000u;
    out_stats->min_bucket_len = 0xffffffffu;
    out_stats->max_bucket_len = 0u;
    out_stats->avg_bucket_len = 0u;
    for (i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        const rome2_fx_avl_bucket_32 *bucket = l81_tree(ctx, l81_bucket_va(ctx->name_table_va, i));
        uint32_t node_va;
        uint32_t steps = 0u;
        if (bucket == NULL) {
            return;
        }
        if (bucket->root_va != 0u) {
            out_stats->non_empty_buckets++;
        }
        for (node_va = l81_leftmost(ctx, bucket->root_va);
             node_va != 0u && steps++ < L81_WALK_LIMIT;
             node_va = l81_successor(ctx, node_va)) {
            const rome2_fx_avl_string_node_32 *node = l81_node(ctx, node_va);
            if (node == NULL) {
                break;
            }
            out_stats->mem_bytes += node->key.length + L81_NODE_STATS_BYTES;
        }
        out_stats->avg_bucket_len += bucket->node_count;
        if (out_stats->max_bucket_len < bucket->node_count) {
            out_stats->max_bucket_len = bucket->node_count;
        }
        if (bucket->node_count < out_stats->min_bucket_len) {
            out_stats->min_bucket_len = bucket->node_count;
        }
    }
    out_stats->avg_bucket_len >>= 12;
}

/* 0x10edf5b0: the name is looked up as given, without the sanitizing pass. */
uint8_t rome2_l81_fx_name_exists(rome2_l81_fx_name_ctx *ctx, const char *name) {
    rome2_l81_name_iter iter;
    if (ctx == NULL || ctx->fx == NULL) {
        return 0u;
    }
    (void)rome2_l81_name_table_find(ctx, ctx->name_table_va, &iter, name);
    return (uint8_t)(iter.table_va != 0u && iter.bucket_index != -1 && iter.bucket_va != 0u &&
                     iter.node_va != 0u);
}

/* ---- FxName members ---- */

/* 0x10eddf90 */
rome2_fx_name_32 *rome2_l81_fx_name_ctor_default(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return self;
    }
    self->entry_va = ctx->null_name.entry_va;
    l81_add_ref(ctx, self->entry_va);
    return self;
}

/* 0x10eddef0 */
rome2_fx_name_32 *rome2_l81_fx_name_ctor_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *name) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return self;
    }
    self->entry_va = 0u;
    if (ctx->name_table_va == 0u) {
        l81_log_name_line(ctx, "Attempt to create name ", name, " before FxName::Startup() called!");
    }
    rome2_l81_fx_name_add_to_table(ctx, self, name);
    return self;
}

/* 0x10edde70 */
rome2_fx_name_32 *rome2_l81_fx_name_ctor_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL || other == NULL) {
        return self;
    }
    self->entry_va = other->entry_va;
    if (ctx->name_table_va == 0u) {
        l81_log_line(ctx, 1, "Attempt to copy construct name before FxName::Startup() called!");
    }
    l81_add_ref(ctx, self->entry_va);
    return self;
}

/* 0x10ede090: nothing happens once the table is gone. */
void rome2_l81_fx_name_dtor(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL || ctx->name_table_va == 0u) {
        return;
    }
    l81_release_entry(ctx, self);
}

/* 0x10ee1a80 */
void rome2_l81_fx_name_safe_remove_ref(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return;
    }
    l81_release_entry(ctx, self);
}

/* 0x10ee0d90 */
void rome2_l81_fx_name_add_to_table(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *raw_name) {
    char name[ROME2_FX_NAME_MAX_LEN];
    uint32_t used = 0u;
    uint32_t terminator = 0u;
    rome2_l81_name_iter iter;
    const rome2_fx_avl_string_node_32 *node;
    rome2_fx_name_entry_32 *entry;
    uint32_t entry_va;
    if (ctx == NULL || ctx->fx == NULL || self == NULL || l81_header(ctx, ctx->name_table_va) == NULL) {
        return; /* bounded: the original searches through a NULL table */
    }
    if (raw_name != NULL) {
        /* a name that fills all 0x200 bytes without a terminator becomes the empty name */
        do {
            char ch = raw_name[used];
            terminator = used;
            if (ch == '\0') {
                break;
            }
            if (ch == '|') {
                ch = '_';
            } else if (ch == '"') {
                ch = '\'';
            }
            name[used] = ch;
            ++used;
            terminator = 0u;
        } while (used < ROME2_FX_NAME_MAX_LEN);
    }
    name[terminator] = '\0';

    (void)rome2_l81_name_table_find(ctx, ctx->name_table_va, &iter, name);
    node = l81_node(ctx, iter.node_va);
    if (iter.bucket_index != -1 && node != NULL) {
        self->entry_va = node->value_va;
        l81_add_ref(ctx, self->entry_va);
        return;
    }
    entry_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(*entry));
    entry = l81_entry(ctx, entry_va);
    if (entry == NULL) {
        return; /* bounded: the original inserts and dereferences the failed allocation */
    }
    (void)rome2_l81_fx_ref_object_ctor(ctx, entry_va);
    entry->vtable_va = ROME2_FX_VTABLE_NAME_ENTRY;
    entry->fx_string_va = 0u;
    (void)rome2_l81_name_table_insert(ctx, ctx->name_table_va, &iter, name, entry_va);
    node = l81_node(ctx, iter.node_va);
    if (iter.bucket_index != -1 && node != NULL) {
        /* the entry does not own a string: it points at the key held by its tree node */
        entry_va = node->value_va;
        entry = l81_entry(ctx, entry_va);
        if (entry == NULL) {
            return;
        }
        entry->fx_string_va = iter.node_va + L81_NODE_KEY_OFFSET;
    }
    self->entry_va = entry_va;
    entry->ref_count++;
}

/* 0x10ee07c0 */
void rome2_l81_fx_name_set_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *raw_name) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return;
    }
    l81_release_entry(ctx, self);
    rome2_l81_fx_name_add_to_table(ctx, self, raw_name);
}

/* 0x10ede180 */
rome2_fx_name_32 *rome2_l81_fx_name_assign_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL || other == NULL) {
        return self;
    }
    if (ctx->name_table_va == 0u) {
        l81_log_line(ctx, 1, "Attempt to assign to name before FxName::Startup() called!");
    }
    if (self != other) {
        l81_release_entry(ctx, self);
        self->entry_va = other->entry_va;
        l81_add_ref(ctx, self->entry_va);
    }
    return self;
}

/* 0x10ede2b0: operator=(const char *) */
rome2_fx_name_32 *rome2_l81_fx_name_assign_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *raw_name) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return self;
    }
    if (ctx->name_table_va == 0u) {
        l81_log_name_line(
            ctx, "Attempt to assign to name with other = ", raw_name, " before FxName::Startup() called!");
    }
    l81_release_entry(ctx, self);
    rome2_l81_fx_name_add_to_table(ctx, self, raw_name);
    return self;
}

/* 0x10ed5dd0 */
uint8_t rome2_l81_fx_name_eq_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other) {
    if (ctx == NULL || self == NULL || other == NULL) {
        return 0u;
    }
    if (self->entry_va == 0u) {
        self->entry_va = ctx->null_name.entry_va;
    }
    return (uint8_t)(self->entry_va == other->entry_va);
}

/* 0x10ed60d0 */
uint8_t rome2_l81_fx_name_ne_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other) {
    if (ctx == NULL || self == NULL || other == NULL) {
        return 1u;
    }
    if (self->entry_va == 0u) {
        self->entry_va = ctx->null_name.entry_va;
    }
    return (uint8_t)(self->entry_va != other->entry_va);
}

/* 0x10ede9c0 */
uint8_t rome2_l81_fx_name_eq_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *rhs) {
    const rome2_fx_name_entry_32 *entry;
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return 0u;
    }
    entry = l81_bound_entry(ctx, self);
    return (entry != NULL) ? rome2_l81_fx_string_equals_cstr(ctx, entry->fx_string_va, rhs) : 0u;
}

/* 0x10ede9e0 */
uint8_t rome2_l81_fx_name_ne_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *rhs) {
    const rome2_fx_name_entry_32 *entry;
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return 1u;
    }
    entry = l81_bound_entry(ctx, self);
    return (entry != NULL) ? rome2_l81_fx_string_not_equals_cstr(ctx, entry->fx_string_va, rhs) : 1u;
}

/* Shared body of 0x10edeb90 and 0x10edecb0: strcmp(self, other) over unsigned bytes. */
static int l81_name_compare(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self, rome2_fx_name_32 *other) {
    const rome2_fx_name_entry_32 *other_entry = l81_bound_entry(ctx, other);
    const rome2_fx_name_entry_32 *self_entry = l81_bound_entry(ctx, self);
    const char *other_text;
    const char *self_text;
    if (other_entry == NULL || self_entry == NULL) {
        return 0; /* bounded */
    }
    other_text = rome2_l81_fx_string_cstr(ctx, other_entry->fx_string_va);
    self_text = rome2_l81_fx_string_cstr(ctx, self_entry->fx_string_va);
    if (other_text == NULL || self_text == NULL) {
        return 0; /* bounded */
    }
    return strcmp(self_text, other_text);
}

/* 0x10edeb90 */
uint8_t rome2_l81_fx_name_lt(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    rome2_fx_name_32 *other) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL || other == NULL) {
        return 0u;
    }
    return (uint8_t)(l81_name_compare(ctx, self, other) < 0);
}

/* 0x10edecb0 */
uint8_t rome2_l81_fx_name_gt(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    rome2_fx_name_32 *other) {
    if (ctx == NULL || ctx->fx == NULL || self == NULL || other == NULL) {
        return 0u;
    }
    return (uint8_t)(l81_name_compare(ctx, self, other) > 0);
}

/* 0x10edf6e0 */
const char *rome2_l81_fx_name_get_cstr(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    const rome2_fx_name_entry_32 *entry;
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return NULL;
    }
    entry = l81_bound_entry(ctx, self);
    return (entry != NULL) ? rome2_l81_fx_string_cstr(ctx, entry->fx_string_va) : NULL;
}

/* 0x10edf740 */
uint32_t rome2_l81_fx_name_get_string_va(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    const rome2_fx_name_entry_32 *entry;
    if (ctx == NULL || ctx->fx == NULL || self == NULL) {
        return 0u;
    }
    entry = l81_bound_entry(ctx, self);
    return (entry != NULL) ? entry->fx_string_va : 0u;
}

/* ---- FxClientEvent ---- */

/* 0x10ed7d70: +0x00 is copied from the second FxName argument and +0x04 from the first. */
rome2_fx_client_event_32 *rome2_l81_fx_client_event_ctor_full(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_name_32 *name_arg1,
    const rome2_fx_name_32 *name_arg2,
    float start_time_offset,
    float magnitude_scale,
    float blend_in_time,
    float blend_out_time,
    float duration_scale,
    uint8_t should_persist_values,
    uint32_t event_id,
    const rome2_fx_name_32 *custom_payload) {
    if (ctx == NULL || self == NULL || name_arg1 == NULL || name_arg2 == NULL || custom_payload == NULL) {
        return self;
    }
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->animation_group_name, name_arg2);
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->animation_name, name_arg1);
    self->start_time_offset = start_time_offset;
    self->magnitude_scale = magnitude_scale;
    self->blend_in_time = blend_in_time;
    self->blend_out_time = blend_out_time;
    self->should_persist_values = should_persist_values;
    self->duration_scale = duration_scale;
    self->event_id = event_id;
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->custom_payload, custom_payload);
    return self;
}

static void l81_client_event_copy_scalars(
    rome2_fx_client_event_32 *self,
    const rome2_fx_client_event_32 *other) {
    self->start_time_offset = other->start_time_offset;
    self->magnitude_scale = other->magnitude_scale;
    self->blend_in_time = other->blend_in_time;
    self->blend_out_time = other->blend_out_time;
    self->duration_scale = other->duration_scale;
    self->should_persist_values = other->should_persist_values;
    self->event_id = other->event_id;
}

/* 0x10ed56a0 */
rome2_fx_client_event_32 *rome2_l81_fx_client_event_ctor_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_client_event_32 *other) {
    if (ctx == NULL || self == NULL || other == NULL) {
        return self;
    }
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->animation_group_name, &other->animation_group_name);
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->animation_name, &other->animation_name);
    l81_client_event_copy_scalars(self, other);
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->custom_payload, &other->custom_payload);
    return self;
}

/* 0x10ed5840 */
rome2_fx_client_event_32 *rome2_l81_fx_client_event_assign(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_client_event_32 *other) {
    if (ctx == NULL || self == NULL || other == NULL) {
        return self;
    }
    (void)rome2_l81_fx_name_assign_copy(ctx, &self->animation_group_name, &other->animation_group_name);
    (void)rome2_l81_fx_name_assign_copy(ctx, &self->animation_name, &other->animation_name);
    l81_client_event_copy_scalars(self, other);
    (void)rome2_l81_fx_name_assign_copy(ctx, &self->custom_payload, &other->custom_payload);
    return self;
}

/* 0x10ed57f0 */
void rome2_l81_fx_client_event_dtor(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self) {
    if (ctx == NULL || self == NULL) {
        return;
    }
    rome2_l81_fx_name_dtor(ctx, &self->custom_payload);
    rome2_l81_fx_name_dtor(ctx, &self->animation_name);
    rome2_l81_fx_name_dtor(ctx, &self->animation_group_name);
}

/* ---- FxClass, FxObject, FxRefObject ---- */

/* 0x10ef3160 */
uint32_t rome2_l81_fx_object_helper_bind(rome2_l81_fx_name_ctx *ctx, uint32_t self_va) {
    uint32_t *vtable_slot;
    if (ctx == NULL || ctx->fx == NULL) {
        return 0u;
    }
    vtable_slot = l81_u32(ctx, self_va);
    if (vtable_slot == NULL) {
        return 0u;
    }
    *vtable_slot = ROME2_FX_VTABLE_OBJECT_HELPER;
    return self_va;
}

/* 0x10f06ad0 */
uint32_t rome2_l81_fx_ref_object_ctor(rome2_l81_fx_name_ctx *ctx, uint32_t self_va) {
    uint32_t *words;
    if (ctx == NULL || ctx->fx == NULL || self_va == 0u) {
        return 0u;
    }
    words = (uint32_t *)rome2_l80_mut_ptr(ctx->fx, self_va, 8u);
    if (words == NULL || rome2_l81_fx_object_helper_bind(ctx, self_va) == 0u) {
        return 0u;
    }
    words[0] = ROME2_FX_VTABLE_REF_OBJECT;
    words[1] = 0u;
    return self_va;
}

/* 0x10ef2a10 */
uint32_t rome2_l81_fx_class_ctor(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *name,
    uint16_t version,
    uint32_t base_class_va,
    uint32_t size,
    uint32_t ctor_fn_va) {
    rome2_fx_class_32 *self;
    rome2_fx_class_array_32 *table;
    rome2_fx_name_32 probe;
    uint32_t duplicate_va = 0u;
    if (ctx == NULL || ctx->fx == NULL) {
        return 0u;
    }
    self = l81_class(ctx, self_va);
    if (self == NULL) {
        return 0u;
    }
    (void)rome2_l81_fx_name_ctor_cstr(ctx, &self->name, name);
    self->current_version = version;
    self->base_class_va = base_class_va;
    self->size = size;
    self->num_children = 0u;
    self->construct_fn_va = ctor_fn_va;
    table = (ctx->class_table_va == 0u)
        ? NULL
        : (rome2_fx_class_array_32 *)rome2_l80_mut_ptr(ctx->fx, ctx->class_table_va, (uint32_t)sizeof(*table));
    if (table == NULL) {
        l81_log_line(ctx, 2, "Attempt to create FxClass before FxClass::Startup() called!");
    }
    (void)rome2_l81_fx_name_ctor_cstr(ctx, &probe, name);
    if (table == NULL) {
        l81_log_line(ctx, 2, "Attempt to find class description before FxClass::Startup() called!");
    } else {
        uint32_t i;
        for (i = 0u; i < table->count; ++i) {
            const uint32_t *item = l81_u32(ctx, table->items_va + i * 4u);
            rome2_fx_class_32 *other = (item != NULL) ? l81_class(ctx, *item) : NULL;
            if (other == NULL) {
                break; /* bounded */
            }
            if (other->name.entry_va == 0u) {
                other->name.entry_va = ctx->null_name.entry_va;
            }
            if (other->name.entry_va == probe.entry_va) {
                duplicate_va = *item;
                break;
            }
        }
    }
    rome2_l81_fx_name_dtor(ctx, &probe);
    if (duplicate_va != 0u) {
        l81_log_line(ctx, 2, "Attempt to create duplicate FxClass!");
    }
    if (base_class_va != 0u) {
        rome2_fx_class_32 *base = l81_class(ctx, base_class_va);
        if (base != NULL) {
            base->num_children++;
        }
    }
    if (table == NULL) {
        return self_va; /* bounded: the original appends through the NULL table */
    }
    if (table->count < table->capacity) {
        uint32_t *item = l81_u32(ctx, table->items_va + table->count * 4u);
        if (item != NULL) {
            *item = self_va;
            table->count++;
        }
    } else {
        uint32_t new_capacity = (table->capacity == 0u) ? 1u : table->capacity * 2u;
        uint32_t new_items_va = rome2_l80_fx_allocate(ctx->fx, new_capacity * 4u);
        uint32_t *new_items = (new_items_va == 0u)
            ? NULL
            : (uint32_t *)rome2_l80_mut_ptr(ctx->fx, new_items_va, new_capacity * 4u);
        const uint32_t *old_items = (table->count == 0u)
            ? NULL
            : (const uint32_t *)rome2_l80_const_ptr(ctx->fx, table->items_va, table->count * 4u);
        uint32_t old_items_va = table->items_va;
        uint32_t old_capacity = table->capacity;
        if (new_items == NULL || (table->count != 0u && old_items == NULL) || table->count >= new_capacity) {
            return self_va; /* bounded: the original copies through a failed allocation */
        }
        if (old_items != NULL) {
            memcpy(new_items, old_items, (size_t)table->count * 4u);
        }
        new_items[table->count] = self_va;
        table->items_va = new_items_va;
        table->count++;
        table->capacity = new_capacity;
        rome2_l80_fx_free(ctx->fx, old_items_va, old_capacity * 4u);
    }
    return self_va;
}

/* 0x10ef31c0 */
uint32_t rome2_l81_fx_object_static_class_init(rome2_l81_fx_name_ctx *ctx) {
    uint32_t block_va;
    if (ctx == NULL || ctx->fx == NULL) {
        return 0u;
    }
    block_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_class_32));
    if (block_va == 0u) {
        return 0u;
    }
    return rome2_l81_fx_class_ctor(ctx, block_va, "FxObject", 0u, 0u, 4u, ROME2_L81_VA_FX_OBJECT_CONSTRUCT);
}

/* 0x10f06b40 */
uint32_t rome2_l81_fx_ref_object_static_class_init(rome2_l81_fx_name_ctx *ctx) {
    uint32_t block_va;
    if (ctx == NULL || ctx->fx == NULL) {
        return 0u;
    }
    block_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_class_32));
    if (block_va == 0u) {
        return 0u;
    }
    if (ctx->fx_object_class_va == 0u) {
        ctx->fx_object_class_va = rome2_l81_fx_object_static_class_init(ctx);
    }
    return rome2_l81_fx_class_ctor(
        ctx, block_va, "FxRefObject", 0u, ctx->fx_object_class_va, 8u, ROME2_L81_VA_FX_REF_OBJECT_CONSTRUCT);
}
