#include "facefx_name_avl_table_ops.h"

#include <string.h>

static const uint32_t ROME2_L81_NULL_NAME_ENTRY_TAG = 0xdead0001u;
static const uint32_t ROME2_L81_MAX_AVL_NODES_WALK = 8192u;

static void l81_log_msg(rome2_l81_fx_name_ctx *ctx, int32_t req_level, const char *msg) {
    if (!ctx || !ctx->fx || ctx->fx->log_manager_singleton_va == 0u || !msg) {
        return;
    }
    const rome2_fx_log_manager_32 *mgr =
        (const rome2_fx_log_manager_32 *)rome2_l80_const_ptr(
            ctx->fx, ctx->fx->log_manager_singleton_va, (uint32_t)sizeof(*mgr));
    if (!mgr || mgr->max_log_level <= req_level) {
        return;
    }
    rome2_fx_log_entry_32 entry;
    rome2_l80_log_entry_create(&entry, ctx->fx->log_manager_singleton_va + 4u, req_level);
    rome2_fx_log_stream_32 *stream = rome2_l80_log_entry_get_stream(&entry, mgr->tab_level);
    rome2_l80_log_stream_push_cstr(stream, msg);
    rome2_l80_log_entry_dtor(ctx->fx, &entry);
}

static uint32_t l81_bucket_va(const rome2_l81_fx_name_ctx *ctx, uint32_t idx) {
    return ctx->name_table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES +
           (idx * (uint32_t)sizeof(rome2_fx_avl_bucket_32));
}

static int32_t l81_max_i32(int32_t a, int32_t b) {
    return a > b ? a : b;
}

static uint32_t l81_node_ptr(const rome2_l81_fx_name_ctx *ctx, uint32_t va, rome2_fx_avl_string_node_32 **out) {
    if (!ctx || !ctx->fx || va == 0u) {
        *out = NULL;
        return 0u;
    }
    *out = (rome2_fx_avl_string_node_32 *)rome2_l80_mut_ptr(
        ctx->fx, va, (uint32_t)sizeof(rome2_fx_avl_string_node_32));
    return *out != NULL ? 1u : 0u;
}

static const char *l81_node_key_cstr(const rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    const rome2_fx_avl_string_node_32 *node =
        (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
            ctx->fx, node_va, (uint32_t)sizeof(*node));
    if (!node) {
        return "";
    }
    if (node->key.length == 0u) {
        return "";
    }
    if (node->key.data_va == 0u) {
        return node->key.inline_buf;
    }
    if (node->key.data_va == node_va + 4u) {
        return node->key.inline_buf;
    }
    const char *heap_s = (const char *)rome2_l80_const_ptr(
        ctx->fx, node->key.data_va, node->key.length + 1u);
    return heap_s ? heap_s : "";
}

static int16_t l81_node_height(const rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    if (node_va == 0u) {
        return 0;
    }
    const rome2_fx_avl_string_node_32 *node =
        (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
            ctx->fx, node_va, (uint32_t)sizeof(*node));
    return node ? node->height : 0;
}

static void l81_node_recompute_metrics(rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    rome2_fx_avl_string_node_32 *node = NULL;
    if (!l81_node_ptr(ctx, node_va, &node)) {
        return;
    }
    int16_t lh = l81_node_height(ctx, node->left_va);
    int16_t rh = l81_node_height(ctx, node->right_va);
    node->height = (int16_t)(1 + l81_max_i32((int32_t)lh, (int32_t)rh));
    node->balance = (int16_t)(rh - lh);
}

static void l81_free_avl_node(rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    rome2_fx_avl_string_node_32 *node = NULL;
    if (!l81_node_ptr(ctx, node_va, &node)) {
        return;
    }
    uint32_t key_str_va = node_va + 4u;
    rome2_l81_fx_string_dtor(ctx, key_str_va);
    rome2_l80_fx_free(ctx->fx, node_va, (uint32_t)sizeof(rome2_fx_avl_string_node_32));
}

static void l81_free_avl_subtree(rome2_l81_fx_name_ctx *ctx, uint32_t root_va) {
    if (root_va == 0u) {
        return;
    }
    /* Iterative post-order clear via parent link to keep stack shallow under /analyze. */
    uint32_t cur = root_va;
    uint32_t steps = 0u;
    while (cur != 0u && steps < ROME2_L81_MAX_AVL_NODES_WALK) {
        steps++;
        rome2_fx_avl_string_node_32 *node = NULL;
        if (!l81_node_ptr(ctx, cur, &node)) {
            break;
        }
        if (node->left_va != 0u) {
            cur = node->left_va;
            continue;
        }
        if (node->right_va != 0u) {
            cur = node->right_va;
            continue;
        }
        uint32_t parent_va = node->parent_va;
        if (parent_va != 0u) {
            rome2_fx_avl_string_node_32 *parent = NULL;
            if (l81_node_ptr(ctx, parent_va, &parent)) {
                if (parent->left_va == cur) {
                    parent->left_va = 0u;
                } else if (parent->right_va == cur) {
                    parent->right_va = 0u;
                }
            }
        }
        l81_free_avl_node(ctx, cur);
        if (cur == root_va) {
            break;
        }
        cur = parent_va;
    }
}

static uint32_t l81_leftmost_node(const rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    uint32_t cur = node_va;
    uint32_t guard = 0u;
    while (cur != 0u && guard < 128u) {
        guard++;
        const rome2_fx_avl_string_node_32 *n =
            (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                ctx->fx, cur, (uint32_t)sizeof(*n));
        if (!n || n->left_va == 0u) {
            break;
        }
        cur = n->left_va;
    }
    return cur;
}

static uint32_t l81_avl_next_inorder(const rome2_l81_fx_name_ctx *ctx, uint32_t node_va) {
    const rome2_fx_avl_string_node_32 *cur =
        (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
            ctx->fx, node_va, (uint32_t)sizeof(*cur));
    if (!cur) {
        return 0u;
    }
    if (cur->right_va != 0u) {
        return l81_leftmost_node(ctx, cur->right_va);
    }
    uint32_t child = node_va;
    uint32_t parent_va = cur->parent_va;
    uint32_t guard = 0u;
    while (parent_va != 0u && guard < 128u) {
        guard++;
        const rome2_fx_avl_string_node_32 *p =
            (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                ctx->fx, parent_va, (uint32_t)sizeof(*p));
        if (!p) {
            return 0u;
        }
        if (p->right_va != child) {
            return parent_va;
        }
        child = parent_va;
        parent_va = p->parent_va;
    }
    return 0u;
}

static void l81_set_child_slot(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    uint32_t parent_va,
    uint32_t is_right,
    uint32_t new_child_va) {
    if (parent_va == 0u) {
        rome2_fx_avl_bucket_32 *b = (rome2_fx_avl_bucket_32 *)rome2_l80_mut_ptr(
            ctx->fx, bucket_va, (uint32_t)sizeof(*b));
        if (b) {
            b->root_va = new_child_va;
        }
        return;
    }
    rome2_fx_avl_string_node_32 *parent = NULL;
    if (l81_node_ptr(ctx, parent_va, &parent)) {
        if (is_right) {
            parent->right_va = new_child_va;
        } else {
            parent->left_va = new_child_va;
        }
    }
}

static uint32_t l81_get_child_slot(
    const rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    uint32_t parent_va,
    uint32_t is_right) {
    if (parent_va == 0u) {
        const rome2_fx_avl_bucket_32 *b = (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(
            ctx->fx, bucket_va, (uint32_t)sizeof(*b));
        return b ? b->root_va : 0u;
    }
    const rome2_fx_avl_string_node_32 *parent =
        (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
            ctx->fx, parent_va, (uint32_t)sizeof(*parent));
    if (!parent) {
        return 0u;
    }
    return is_right ? parent->right_va : parent->left_va;
}

static void l81_rebalance_upward(rome2_l81_fx_name_ctx *ctx, uint32_t bucket_va, uint32_t start_va) {
    uint32_t cur_va = start_va;
    uint32_t guard = 0u;
    while (cur_va != 0u && guard < 128u) {
        guard++;
        rome2_fx_avl_string_node_32 *cur = NULL;
        if (!l81_node_ptr(ctx, cur_va, &cur)) {
            break;
        }
        uint32_t parent_va = cur->parent_va;
        uint32_t is_right = 0u;
        if (parent_va != 0u) {
            const rome2_fx_avl_string_node_32 *p =
                (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                    ctx->fx, parent_va, (uint32_t)sizeof(*p));
            if (p && p->right_va == cur_va) {
                is_right = 1u;
            }
        }
        l81_node_recompute_metrics(ctx, cur_va);
        int16_t bal = cur->balance;
        if (bal > 1) {
            const rome2_fx_avl_string_node_32 *r =
                (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                    ctx->fx, cur->right_va, (uint32_t)sizeof(*r));
            if (r && r->balance < 0) {
                rome2_l81_avl_rotate_right(ctx, bucket_va, cur_va, 1u);
            }
            rome2_l81_avl_rotate_left(ctx, bucket_va, parent_va, is_right);
        } else if (bal < -1) {
            const rome2_fx_avl_string_node_32 *l =
                (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                    ctx->fx, cur->left_va, (uint32_t)sizeof(*l));
            if (l && l->balance > 0) {
                rome2_l81_avl_rotate_left(ctx, bucket_va, cur_va, 0u);
            }
            rome2_l81_avl_rotate_right(ctx, bucket_va, parent_va, is_right);
        }
        cur_va = parent_va;
    }
}

static rome2_fx_name_32 *l81_lazy_bind_null(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *name) {
    if (name && name->entry_va == 0u && ctx && ctx->null_name_entry_va != 0u) {
        name->entry_va = ctx->null_name_entry_va;
    }
    return name;
}

void rome2_l81_ctx_init(rome2_l81_fx_name_ctx *ctx, rome2_l80_fx_ctx *fx_ctx) {
    if (!ctx) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->fx = fx_ctx;
}

/* 0x10411670: FxString::FxString(const char*, int len) */
uint32_t rome2_l81_fx_string_ctor_slice(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *src,
    int32_t len) {
    if (!ctx || !ctx->fx) {
        return 0u;
    }
    rome2_fx_string_32 *s = (rome2_fx_string_32 *)rome2_l80_mut_ptr(
        ctx->fx, self_va, (uint32_t)sizeof(*s));
    if (!s) {
        return 0u;
    }
    memset(s->inline_buf, 0, sizeof(s->inline_buf));
    s->data_va = self_va;
    s->capacity = 0x10u;
    s->length = 0u;
    if (!src) {
        return self_va;
    }
    uint32_t slice_len = 0u;
    if (len < 0) {
        slice_len = (uint32_t)strlen(src);
    } else {
        slice_len = (uint32_t)len;
    }
    if (slice_len == 0u) {
        return self_va;
    }
    uint32_t need = slice_len + 1u;
    if (need <= 0x10u) {
        memcpy(s->inline_buf, src, slice_len);
        s->inline_buf[slice_len] = '\0';
        s->data_va = self_va;
        s->capacity = 0x10u;
        s->length = slice_len;
        return self_va;
    }
    uint32_t buf_va = rome2_l80_fx_allocate(ctx->fx, need);
    if (buf_va == 0u) {
        return 0u;
    }
    char *dst = (char *)rome2_l80_mut_ptr(ctx->fx, buf_va, need);
    if (!dst) {
        rome2_l80_fx_free(ctx->fx, buf_va, need);
        return 0u;
    }
    memcpy(dst, src, slice_len);
    dst[slice_len] = '\0';
    s->data_va = buf_va;
    s->capacity = need;
    s->length = slice_len;
    return self_va;
}

const char *rome2_l81_fx_string_cstr(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    uint8_t mut_materialize) {
    if (!ctx || !ctx->fx || self_va == 0u) {
        return "";
    }
    rome2_fx_string_32 *s = (rome2_fx_string_32 *)rome2_l80_mut_ptr(
        ctx->fx, self_va, (uint32_t)sizeof(*s));
    if (!s) {
        return "";
    }
    if (s->data_va == 0u && mut_materialize) {
        s->data_va = self_va;
        s->capacity = 0x10u;
        s->length = 0u;
        s->inline_buf[0] = '\0';
    }
    if (s->length == 0u || s->data_va == 0u) {
        return "";
    }
    if (s->data_va == self_va) {
        s->inline_buf[s->length < 16u ? s->length : 15u] = '\0';
        return s->inline_buf;
    }
    char *heap_s = (char *)rome2_l80_mut_ptr(ctx->fx, s->data_va, s->length + 1u);
    if (!heap_s) {
        return "";
    }
    heap_s[s->length] = '\0';
    return heap_s;
}

void rome2_l81_fx_string_dtor(rome2_l81_fx_name_ctx *ctx, uint32_t self_va) {
    if (!ctx || !ctx->fx || self_va == 0u) {
        return;
    }
    rome2_fx_string_32 *s = (rome2_fx_string_32 *)rome2_l80_mut_ptr(
        ctx->fx, self_va, (uint32_t)sizeof(*s));
    if (!s) {
        return;
    }
    if (s->data_va != 0u && s->data_va != self_va) {
        rome2_l80_fx_free(ctx->fx, s->data_va, s->capacity);
    }
    s->data_va = self_va;
    s->capacity = 0x10u;
    s->length = 0u;
    s->inline_buf[0] = '\0';
}

/* 0x10eddab0 */
uint8_t rome2_l81_fx_string_equals_cstr(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *rhs) {
    if (!ctx || !ctx->fx || self_va == 0u || !rhs) {
        return 0u;
    }
    const rome2_fx_string_32 *s = (const rome2_fx_string_32 *)rome2_l80_const_ptr(
        ctx->fx, self_va, (uint32_t)sizeof(*s));
    if (!s) {
        return 0u;
    }
    size_t rhs_len = strlen(rhs);
    if ((size_t)s->length != rhs_len) {
        return 0u;
    }
    const char *lhs = rome2_l81_fx_string_cstr(ctx, self_va, 1u);
    return memcmp(lhs, rhs, rhs_len) == 0 ? 1u : 0u;
}

/* 0x10eddb40 */
uint8_t rome2_l81_fx_string_not_equals_cstr(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *rhs) {
    return rome2_l81_fx_string_equals_cstr(ctx, self_va, rhs) ? 0u : 1u;
}

/* 0x10eddc90 */
uint32_t rome2_l81_avl_string_node_ctor(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    uint32_t parent_va,
    uint32_t key_str_va,
    uint32_t value_va) {
    rome2_fx_avl_string_node_32 *node = NULL;
    if (!l81_node_ptr(ctx, self_va, &node)) {
        return 0u;
    }
    const char *key_cstr = rome2_l81_fx_string_cstr(ctx, key_str_va, 0u);
    const rome2_fx_string_32 *src_str = (const rome2_fx_string_32 *)rome2_l80_const_ptr(
        ctx->fx, key_str_va, (uint32_t)sizeof(*src_str));
    int32_t key_len = src_str ? (int32_t)src_str->length : (int32_t)strlen(key_cstr);
    memset(node, 0, sizeof(*node));
    node->vtable_va = ROME2_FX_VTABLE_AVL_STRING_NODE;
    (void)rome2_l81_fx_string_ctor_slice(ctx, self_va + 4u, key_cstr, key_len);
    node->value_va = value_va;
    node->parent_va = parent_va;
    node->balance = 0;
    node->height = 1;
    return self_va;
}

/* 0x10eddfb0 */
uint32_t rome2_l81_avl_bucket_ctor(rome2_l81_fx_name_ctx *ctx, uint32_t bucket_va) {
    if (!ctx || !ctx->fx || bucket_va == 0u) {
        return 0u;
    }
    rome2_fx_avl_bucket_32 *b = (rome2_fx_avl_bucket_32 *)rome2_l80_mut_ptr(
        ctx->fx, bucket_va, (uint32_t)sizeof(*b));
    if (!b) {
        return 0u;
    }
    b->vtable_va = ROME2_FX_VTABLE_AVL_BUCKET;
    b->root_va = 0u;
    b->node_count = 0u;
    return bucket_va;
}

/* 0x10ede150 */
void rome2_l81_avl_bucket_dtor(rome2_l81_fx_name_ctx *ctx, uint32_t bucket_va) {
    if (!ctx || !ctx->fx || bucket_va == 0u) {
        return;
    }
    rome2_fx_avl_bucket_32 *b = (rome2_fx_avl_bucket_32 *)rome2_l80_mut_ptr(
        ctx->fx, bucket_va, (uint32_t)sizeof(*b));
    if (!b) {
        return;
    }
    l81_free_avl_subtree(ctx, b->root_va);
    b->root_va = 0u;
    b->node_count = 0u;
}

/* 0x10ee19c0 */
void rome2_l81_avl_rotate_left(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    uint32_t parent_slot_node_va,
    uint32_t is_right_child) {
    uint32_t pivot_va = l81_get_child_slot(ctx, bucket_va, parent_slot_node_va, is_right_child);
    rome2_fx_avl_string_node_32 *pivot = NULL;
    if (!l81_node_ptr(ctx, pivot_va, &pivot) || pivot->right_va == 0u) {
        return;
    }
    uint32_t rhs_va = pivot->right_va;
    rome2_fx_avl_string_node_32 *rhs = NULL;
    if (!l81_node_ptr(ctx, rhs_va, &rhs)) {
        return;
    }
    uint32_t rhs_left_va = rhs->left_va;
    pivot->right_va = rhs_left_va;
    if (rhs_left_va != 0u) {
        rome2_fx_avl_string_node_32 *rl = NULL;
        if (l81_node_ptr(ctx, rhs_left_va, &rl)) {
            rl->parent_va = pivot_va;
        }
    }
    rhs->parent_va = pivot->parent_va;
    rhs->left_va = pivot_va;
    pivot->parent_va = rhs_va;
    l81_set_child_slot(ctx, bucket_va, parent_slot_node_va, is_right_child, rhs_va);
    l81_node_recompute_metrics(ctx, pivot_va);
    l81_node_recompute_metrics(ctx, rhs_va);
}

/* 0x10ee1a20 */
void rome2_l81_avl_rotate_right(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    uint32_t parent_slot_node_va,
    uint32_t is_right_child) {
    uint32_t pivot_va = l81_get_child_slot(ctx, bucket_va, parent_slot_node_va, is_right_child);
    rome2_fx_avl_string_node_32 *pivot = NULL;
    if (!l81_node_ptr(ctx, pivot_va, &pivot) || pivot->left_va == 0u) {
        return;
    }
    uint32_t lhs_va = pivot->left_va;
    rome2_fx_avl_string_node_32 *lhs = NULL;
    if (!l81_node_ptr(ctx, lhs_va, &lhs)) {
        return;
    }
    uint32_t lhs_right_va = lhs->right_va;
    pivot->left_va = lhs_right_va;
    if (lhs_right_va != 0u) {
        rome2_fx_avl_string_node_32 *lr = NULL;
        if (l81_node_ptr(ctx, lhs_right_va, &lr)) {
            lr->parent_va = pivot_va;
        }
    }
    lhs->parent_va = pivot->parent_va;
    lhs->right_va = pivot_va;
    pivot->parent_va = lhs_va;
    l81_set_child_slot(ctx, bucket_va, parent_slot_node_va, is_right_child, lhs_va);
    l81_node_recompute_metrics(ctx, pivot_va);
    l81_node_recompute_metrics(ctx, lhs_va);
}

/* 0x10edfb00 */
uint32_t rome2_l81_avl_find(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    const char *key) {
    if (!ctx || !ctx->fx || bucket_va == 0u || !key) {
        return 0u;
    }
    const rome2_fx_avl_bucket_32 *b = (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(
        ctx->fx, bucket_va, (uint32_t)sizeof(*b));
    if (!b) {
        return 0u;
    }
    uint32_t cur = b->root_va;
    uint32_t guard = 0u;
    while (cur != 0u && guard < ROME2_L81_MAX_AVL_NODES_WALK) {
        guard++;
        const rome2_fx_avl_string_node_32 *node =
            (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                ctx->fx, cur, (uint32_t)sizeof(*node));
        if (!node) {
            return 0u;
        }
        const char *node_key = l81_node_key_cstr(ctx, cur);
        int cmp = strcmp(key, node_key);
        if (cmp == 0) {
            return cur;
        }
        cur = (cmp < 0) ? node->left_va : node->right_va;
    }
    return 0u;
}

/* 0x10edfc40 */
uint32_t rome2_l81_avl_insert(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    const char *key,
    uint32_t value_va,
    uint8_t *inserted_out) {
    if (inserted_out) {
        *inserted_out = 0u;
    }
    if (!ctx || !ctx->fx || bucket_va == 0u || !key) {
        return 0u;
    }
    rome2_fx_avl_bucket_32 *b = (rome2_fx_avl_bucket_32 *)rome2_l80_mut_ptr(
        ctx->fx, bucket_va, (uint32_t)sizeof(*b));
    if (!b) {
        return 0u;
    }
    uint32_t cur_va = b->root_va;
    uint32_t parent_va = 0u;
    uint32_t is_right = 0u;
    uint32_t guard = 0u;
    while (cur_va != 0u && guard < ROME2_L81_MAX_AVL_NODES_WALK) {
        guard++;
        const rome2_fx_avl_string_node_32 *cur =
            (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                ctx->fx, cur_va, (uint32_t)sizeof(*cur));
        if (!cur) {
            return 0u;
        }
        const char *cur_key = l81_node_key_cstr(ctx, cur_va);
        int cmp = strcmp(key, cur_key);
        if (cmp == 0) {
            return cur_va;
        }
        parent_va = cur_va;
        if (cmp < 0) {
            is_right = 0u;
            cur_va = cur->left_va;
        } else {
            is_right = 1u;
            cur_va = cur->right_va;
        }
    }
    uint32_t tmp_str_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_string_32));
    if (tmp_str_va == 0u) {
        return 0u;
    }
    if (rome2_l81_fx_string_ctor_slice(ctx, tmp_str_va, key, -1) == 0u) {
        rome2_l80_fx_free(ctx->fx, tmp_str_va, (uint32_t)sizeof(rome2_fx_string_32));
        return 0u;
    }
    uint32_t new_node_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_avl_string_node_32));
    if (new_node_va == 0u) {
        rome2_l81_fx_string_dtor(ctx, tmp_str_va);
        rome2_l80_fx_free(ctx->fx, tmp_str_va, (uint32_t)sizeof(rome2_fx_string_32));
        return 0u;
    }
    (void)rome2_l81_avl_string_node_ctor(ctx, new_node_va, parent_va, tmp_str_va, value_va);
    rome2_l81_fx_string_dtor(ctx, tmp_str_va);
    rome2_l80_fx_free(ctx->fx, tmp_str_va, (uint32_t)sizeof(rome2_fx_string_32));

    l81_set_child_slot(ctx, bucket_va, parent_va, is_right, new_node_va);
    b->node_count++;
    if (inserted_out) {
        *inserted_out = 1u;
    }
    l81_rebalance_upward(ctx, bucket_va, parent_va);
    return new_node_va;
}

/* 0x10edff50 */
uint8_t rome2_l81_avl_remove_key(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    const char *key) {
    uint32_t target_va = rome2_l81_avl_find(ctx, bucket_va, key);
    if (target_va == 0u) {
        return 0u;
    }
    rome2_fx_avl_bucket_32 *b = (rome2_fx_avl_bucket_32 *)rome2_l80_mut_ptr(
        ctx->fx, bucket_va, (uint32_t)sizeof(*b));
    rome2_fx_avl_string_node_32 *target = NULL;
    if (!b || !l81_node_ptr(ctx, target_va, &target)) {
        return 0u;
    }
    uint32_t remove_va = target_va;
    if (target->left_va != 0u && target->right_va != 0u) {
        remove_va = l81_leftmost_node(ctx, target->right_va);
        rome2_fx_avl_string_node_32 *succ = NULL;
        if (!l81_node_ptr(ctx, remove_va, &succ)) {
            return 0u;
        }
        /* Swap key+value payload from successor into target before unlinking successor leaf/half-leaf. */
        rome2_fx_string_32 saved_key = target->key;
        uint32_t saved_val = target->value_va;
        target->value_va = succ->value_va;
        succ->value_va = saved_val;
        const char *succ_key = l81_node_key_cstr(ctx, remove_va);
        rome2_l81_fx_string_dtor(ctx, target_va + 4u);
        (void)rome2_l81_fx_string_ctor_slice(ctx, target_va + 4u, succ_key, -1);
        (void)saved_key;
    }
    rome2_fx_avl_string_node_32 *rem = NULL;
    if (!l81_node_ptr(ctx, remove_va, &rem)) {
        return 0u;
    }
    uint32_t child_va = (rem->left_va != 0u) ? rem->left_va : rem->right_va;
    uint32_t parent_va = rem->parent_va;
    uint32_t is_right = 0u;
    if (parent_va != 0u) {
        const rome2_fx_avl_string_node_32 *p =
            (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                ctx->fx, parent_va, (uint32_t)sizeof(*p));
        if (p && p->right_va == remove_va) {
            is_right = 1u;
        }
    }
    if (child_va != 0u) {
        rome2_fx_avl_string_node_32 *child = NULL;
        if (l81_node_ptr(ctx, child_va, &child)) {
            child->parent_va = parent_va;
        }
    }
    l81_set_child_slot(ctx, bucket_va, parent_va, is_right, child_va);
    l81_free_avl_node(ctx, remove_va);
    if (b->node_count > 0u) {
        b->node_count--;
    }
    l81_rebalance_upward(ctx, bucket_va, parent_va);
    return 1u;
}

/* DJB2 hash (signed char accumulation as observed at 0x10edf5f0 & 0x10edf9f0) */
uint32_t rome2_l81_djb2_hash(const char *s) {
    uint32_t h = 0x1505u;
    if (!s) {
        return h;
    }
    for (size_t i = 0; s[i] != '\0'; ++i) {
        int32_t ch = (int32_t)(signed char)s[i];
        h = (uint32_t)((int32_t)(h * 0x21u) + ch);
    }
    return h;
}

/* 0x10eddfd0 */
void rome2_l81_name_table_dtor(rome2_l81_fx_name_ctx *ctx, uint32_t table_va) {
    if (!ctx || !ctx->fx || table_va == 0u) {
        return;
    }
    for (uint32_t i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        uint32_t bva = table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES +
                       (i * (uint32_t)sizeof(rome2_fx_avl_bucket_32));
        rome2_l81_avl_bucket_dtor(ctx, bva);
    }
    rome2_fx_name_table_header_32 *hdr = (rome2_fx_name_table_header_32 *)rome2_l80_mut_ptr(
        ctx->fx, table_va, (uint32_t)sizeof(*hdr));
    if (hdr) {
        memset(hdr, 0, sizeof(*hdr));
    }
}

/* 0x10edf5f0 */
rome2_l81_name_iter *rome2_l81_name_table_find(
    rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_iter *out_iter,
    const char *key) {
    if (!out_iter) {
        return NULL;
    }
    memset(out_iter, 0, sizeof(*out_iter));
    out_iter->bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    out_iter->bucket_index = -1;
    if (!ctx || !ctx->fx || ctx->name_table_va == 0u || !key) {
        return out_iter;
    }
    out_iter->table_va = ctx->name_table_va;
    uint32_t idx = rome2_l81_djb2_hash(key) & 0xfffu;
    uint32_t bva = l81_bucket_va(ctx, idx);
    uint32_t node_va = rome2_l81_avl_find(ctx, bva, key);
    if (node_va != 0u) {
        rome2_fx_name_table_header_32 *hdr = (rome2_fx_name_table_header_32 *)rome2_l80_mut_ptr(
            ctx->fx, ctx->name_table_va, (uint32_t)sizeof(*hdr));
        if (hdr) {
            hdr->probe_hits++;
        }
        out_iter->bucket_index = (int32_t)idx;
        out_iter->bucket_va = bva;
        out_iter->node_va = node_va;
    } else {
        out_iter->bucket_va = ctx->name_table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES;
    }
    return out_iter;
}

/* 0x10edf9f0 */
rome2_l81_name_iter *rome2_l81_name_table_insert(
    rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_iter *out_iter,
    const char *key,
    uint32_t entry_va) {
    if (!out_iter) {
        return NULL;
    }
    memset(out_iter, 0, sizeof(*out_iter));
    out_iter->bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    out_iter->bucket_index = -1;
    if (!ctx || !ctx->fx || ctx->name_table_va == 0u || !key) {
        return out_iter;
    }
    uint32_t idx = rome2_l81_djb2_hash(key) & 0xfffu;
    uint32_t bva = l81_bucket_va(ctx, idx);
    const rome2_fx_avl_bucket_32 *b_before =
        (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(
            ctx->fx, bva, (uint32_t)sizeof(*b_before));
    uint32_t was_non_empty = (b_before && b_before->root_va != 0u) ? 1u : 0u;
    uint8_t inserted = 0u;
    uint32_t node_va = rome2_l81_avl_insert(ctx, bva, key, entry_va, &inserted);
    rome2_fx_name_table_header_32 *hdr = (rome2_fx_name_table_header_32 *)rome2_l80_mut_ptr(
        ctx->fx, ctx->name_table_va, (uint32_t)sizeof(*hdr));
    if (hdr && inserted) {
        if (was_non_empty) {
            hdr->hash_collisions++;
        }
        hdr->unique_count++;
        hdr->total_added++;
    }
    out_iter->table_va = ctx->name_table_va;
    if (node_va != 0u) {
        out_iter->bucket_index = (int32_t)idx;
        out_iter->bucket_va = bva;
        out_iter->node_va = node_va;
    } else {
        out_iter->bucket_va = ctx->name_table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES;
    }
    return out_iter;
}

/* 0x10ee0140 */
uint8_t rome2_l81_name_table_remove(rome2_l81_fx_name_ctx *ctx, const char *key) {
    if (!ctx || !ctx->fx || ctx->name_table_va == 0u || !key) {
        return 0u;
    }
    uint32_t idx = rome2_l81_djb2_hash(key) & 0xfffu;
    uint32_t bva = l81_bucket_va(ctx, idx);
    uint8_t removed = rome2_l81_avl_remove_key(ctx, bva, key);
    if (removed) {
        rome2_fx_name_table_header_32 *hdr = (rome2_fx_name_table_header_32 *)rome2_l80_mut_ptr(
            ctx->fx, ctx->name_table_va, (uint32_t)sizeof(*hdr));
        if (hdr) {
            if (hdr->unique_count > 0u) {
                hdr->unique_count--;
            }
            hdr->total_removed++;
        }
    }
    return removed;
}

/* 0x10edea00 */
rome2_l81_name_iter *rome2_l81_name_iter_advance(
    rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_iter *iter) {
    if (!ctx || !ctx->fx || !iter || iter->table_va == 0u) {
        return iter;
    }
    if (iter->bucket_index == -1) {
        for (uint32_t i = 0u; i < iter->bucket_count; ++i) {
            uint32_t bva = iter->table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES +
                           (i * (uint32_t)sizeof(rome2_fx_avl_bucket_32));
            const rome2_fx_avl_bucket_32 *b =
                (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(
                    ctx->fx, bva, (uint32_t)sizeof(*b));
            if (b && b->root_va != 0u) {
                iter->bucket_index = (int32_t)i;
                iter->bucket_va = bva;
                iter->node_va = l81_leftmost_node(ctx, b->root_va);
                return iter;
            }
        }
        iter->bucket_index = 0;
        iter->node_va = 0u;
        return iter;
    }
    if (iter->node_va != 0u) {
        uint32_t next_va = l81_avl_next_inorder(ctx, iter->node_va);
        if (next_va != 0u) {
            iter->node_va = next_va;
            return iter;
        }
    }
    for (uint32_t i = (uint32_t)(iter->bucket_index + 1); i < iter->bucket_count; ++i) {
        uint32_t bva = iter->table_va + ROME2_FX_NAME_TABLE_HEADER_BYTES +
                       (i * (uint32_t)sizeof(rome2_fx_avl_bucket_32));
        const rome2_fx_avl_bucket_32 *b =
            (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(
                ctx->fx, bva, (uint32_t)sizeof(*b));
        if (b && b->root_va != 0u) {
            iter->bucket_index = (int32_t)i;
            iter->bucket_va = bva;
            iter->node_va = l81_leftmost_node(ctx, b->root_va);
            return iter;
        }
    }
    iter->bucket_index = -1;
    iter->node_va = 0u;
    return iter;
}

static uint32_t l81_alloc_fx_name_entry(rome2_l81_fx_name_ctx *ctx, const char *sanitized_name) {
    uint32_t entry_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_name_entry_32));
    uint32_t str_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_string_32));
    if (entry_va == 0u || str_va == 0u) {
        if (entry_va != 0u) {
            rome2_l80_fx_free(ctx->fx, entry_va, (uint32_t)sizeof(rome2_fx_name_entry_32));
        }
        if (str_va != 0u) {
            rome2_l80_fx_free(ctx->fx, str_va, (uint32_t)sizeof(rome2_fx_string_32));
        }
        return 0u;
    }
    if (rome2_l81_fx_string_ctor_slice(ctx, str_va, sanitized_name, -1) == 0u) {
        rome2_l80_fx_free(ctx->fx, str_va, (uint32_t)sizeof(rome2_fx_string_32));
        rome2_l80_fx_free(ctx->fx, entry_va, (uint32_t)sizeof(rome2_fx_name_entry_32));
        return 0u;
    }
    rome2_fx_name_entry_32 *entry = (rome2_fx_name_entry_32 *)rome2_l80_mut_ptr(
        ctx->fx, entry_va, (uint32_t)sizeof(*entry));
    if (!entry) {
        return 0u;
    }
    entry->vtable_va = ROME2_FX_VTABLE_NAME_ENTRY;
    entry->ref_count = 1;
    entry->fx_string_va = str_va;
    return entry_va;
}

static void l81_free_fx_name_entry(rome2_l81_fx_name_ctx *ctx, uint32_t entry_va) {
    const rome2_fx_name_entry_32 *entry = (const rome2_fx_name_entry_32 *)rome2_l80_const_ptr(
        ctx->fx, entry_va, (uint32_t)sizeof(*entry));
    if (!entry) {
        return;
    }
    if (entry->fx_string_va != 0u) {
        rome2_l81_fx_string_dtor(ctx, entry->fx_string_va);
        rome2_l80_fx_free(ctx->fx, entry->fx_string_va, (uint32_t)sizeof(rome2_fx_string_32));
    }
    rome2_l80_fx_free(ctx->fx, entry_va, (uint32_t)sizeof(rome2_fx_name_entry_32));
}

/* 0x10ee0b20 */
void rome2_l81_fx_name_startup(rome2_l81_fx_name_ctx *ctx) {
    if (!ctx || !ctx->fx) {
        return;
    }
    l81_log_msg(ctx, 4, "Starting up name manager...");
    if (ctx->fx->log_manager_singleton_va != 0u) {
        rome2_fx_log_manager_32 *mgr = (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(
            ctx->fx, ctx->fx->log_manager_singleton_va, (uint32_t)sizeof(*mgr));
        if (mgr) {
            mgr->tab_level++;
        }
    }
    l81_log_msg(ctx, 5, "FX_ALLOW_SPACES_IN_NAMES is 1.");
    l81_log_msg(ctx, 5, "FX_MAX_NAME_LENGTH is 512.");

    if (ctx->name_table_va == 0u) {
        uint32_t table_va = rome2_l80_fx_allocate(ctx->fx, ROME2_FX_NAME_TABLE_BYTES);
        if (table_va == 0u) {
            return;
        }
        ctx->name_table_va = table_va;
        rome2_fx_name_table_header_32 *hdr = (rome2_fx_name_table_header_32 *)rome2_l80_mut_ptr(
            ctx->fx, table_va, (uint32_t)sizeof(*hdr));
        if (hdr) {
            memset(hdr, 0, sizeof(*hdr));
        }
        for (uint32_t i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
            (void)rome2_l81_avl_bucket_ctor(ctx, l81_bucket_va(ctx, i));
        }
    }
    if (ctx->null_name_entry_va == 0u) {
        uint32_t null_entry = l81_alloc_fx_name_entry(ctx, "NullName");
        if (null_entry != 0u) {
            ctx->null_name_entry_va = null_entry;
            rome2_l81_name_iter it;
            (void)rome2_l81_name_table_insert(ctx, &it, "NullName", null_entry);
            ctx->fx_name_entry_class_va = ROME2_L81_NULL_NAME_ENTRY_TAG;
        }
    }
}

/* 0x10edf360 */
void rome2_l81_fx_name_dump_to_log(rome2_l81_fx_name_ctx *ctx) {
    if (!ctx || !ctx->fx || ctx->name_table_va == 0u) {
        return;
    }
    l81_log_msg(ctx, 4, "FxName::DumpNameTableToLog():");
    rome2_l81_name_iter it;
    memset(&it, 0, sizeof(it));
    it.table_va = ctx->name_table_va;
    it.bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    it.bucket_index = -1;
    (void)rome2_l81_name_iter_advance(ctx, &it);
    while (it.node_va != 0u) {
        const rome2_fx_avl_string_node_32 *n =
            (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                ctx->fx, it.node_va, (uint32_t)sizeof(*n));
        if (n) {
            const char *k = l81_node_key_cstr(ctx, it.node_va);
            l81_log_msg(ctx, 4, k);
        }
        (void)rome2_l81_name_iter_advance(ctx, &it);
    }
}

/* 0x10ee0890 */
void rome2_l81_fx_name_shutdown(rome2_l81_fx_name_ctx *ctx) {
    if (!ctx || !ctx->fx) {
        return;
    }
    l81_log_msg(ctx, 4, "Shutting down name manager...");
    if (ctx->name_table_va != 0u) {
        rome2_l81_name_iter it;
        memset(&it, 0, sizeof(it));
        it.table_va = ctx->name_table_va;
        it.bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
        it.bucket_index = -1;
        (void)rome2_l81_name_iter_advance(ctx, &it);
        while (it.node_va != 0u) {
            const rome2_fx_avl_string_node_32 *n =
                (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                    ctx->fx, it.node_va, (uint32_t)sizeof(*n));
            uint32_t entry_va = n ? n->value_va : 0u;
            (void)rome2_l81_name_iter_advance(ctx, &it);
            if (entry_va != 0u && entry_va != ctx->null_name_entry_va) {
                l81_free_fx_name_entry(ctx, entry_va);
            }
        }
        if (ctx->null_name_entry_va != 0u) {
            l81_free_fx_name_entry(ctx, ctx->null_name_entry_va);
            ctx->null_name_entry_va = 0u;
        }
        rome2_l81_name_table_dtor(ctx, ctx->name_table_va);
        rome2_l80_fx_free(ctx->fx, ctx->name_table_va, ROME2_FX_NAME_TABLE_BYTES);
        ctx->name_table_va = 0u;
    }
}

/* 0x10edf860 */
void rome2_l81_fx_name_get_stats(
    rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_stats *out_stats) {
    if (!out_stats) {
        return;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    if (!ctx || !ctx->fx || ctx->name_table_va == 0u) {
        return;
    }
    const rome2_fx_name_table_header_32 *hdr =
        (const rome2_fx_name_table_header_32 *)rome2_l80_const_ptr(
            ctx->fx, ctx->name_table_va, (uint32_t)sizeof(*hdr));
    if (!hdr) {
        return;
    }
    out_stats->num_names = hdr->unique_count;
    out_stats->num_collisions = hdr->hash_collisions;
    out_stats->num_added = hdr->total_added;
    out_stats->num_probes = hdr->probe_hits;
    out_stats->bucket_count = ROME2_FX_NAME_BUCKET_COUNT;
    out_stats->min_bucket_len = 0xffffffffu;

    uint32_t total_mem = 0xc000u;
    uint32_t sum_buckets = 0u;
    for (uint32_t i = 0u; i < ROME2_FX_NAME_BUCKET_COUNT; ++i) {
        uint32_t bva = l81_bucket_va(ctx, i);
        const rome2_fx_avl_bucket_32 *b =
            (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(
                ctx->fx, bva, (uint32_t)sizeof(*b));
        uint32_t cnt = b ? b->node_count : 0u;
        if (b && b->root_va != 0u) {
            out_stats->non_empty_buckets++;
            uint32_t node_va = l81_leftmost_node(ctx, b->root_va);
            while (node_va != 0u) {
                const rome2_fx_avl_string_node_32 *n =
                    (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                        ctx->fx, node_va, (uint32_t)sizeof(*n));
                if (!n) {
                    break;
                }
                total_mem += n->key.length + 0x59u;
                node_va = l81_avl_next_inorder(ctx, node_va);
            }
        }
        sum_buckets += cnt;
        if (cnt > out_stats->max_bucket_len) {
            out_stats->max_bucket_len = cnt;
        }
        if (cnt < out_stats->min_bucket_len) {
            out_stats->min_bucket_len = cnt;
        }
    }
    out_stats->avg_bucket_len = sum_buckets >> 12u;
    out_stats->mem_bytes = total_mem;
}

/* 0x10edf5b0 */
uint8_t rome2_l81_fx_name_exists(rome2_l81_fx_name_ctx *ctx, const char *name) {
    if (!ctx || !ctx->fx || ctx->name_table_va == 0u || !name) {
        return 0u;
    }
    rome2_l81_name_iter it;
    (void)rome2_l81_name_table_find(ctx, &it, name);
    return it.node_va != 0u ? 1u : 0u;
}

/* 0x10eddf90 */
rome2_fx_name_32 *rome2_l81_fx_name_ctor_default(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self) {
    if (!self) {
        return NULL;
    }
    self->entry_va = 0u;
    if (ctx && ctx->null_name_entry_va != 0u) {
        self->entry_va = ctx->null_name_entry_va;
        rome2_fx_name_entry_32 *entry = (rome2_fx_name_entry_32 *)rome2_l80_mut_ptr(
            ctx->fx, self->entry_va, (uint32_t)sizeof(*entry));
        if (entry) {
            entry->ref_count++;
        }
    }
    return self;
}

/* 0x10eddef0 */
rome2_fx_name_32 *rome2_l81_fx_name_ctor_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *name) {
    if (!self) {
        return NULL;
    }
    self->entry_va = 0u;
    rome2_l81_fx_name_add_to_table(ctx, self, name);
    return self;
}

/* 0x10edde70 */
rome2_fx_name_32 *rome2_l81_fx_name_ctor_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other) {
    if (!self) {
        return NULL;
    }
    uint32_t src_va = other ? other->entry_va : 0u;
    if (src_va == 0u && ctx) {
        src_va = ctx->null_name_entry_va;
    }
    self->entry_va = src_va;
    if (ctx && ctx->fx && src_va != 0u) {
        rome2_fx_name_entry_32 *entry = (rome2_fx_name_entry_32 *)rome2_l80_mut_ptr(
            ctx->fx, src_va, (uint32_t)sizeof(*entry));
        if (entry) {
            entry->ref_count++;
        }
    }
    return self;
}

/* 0x10ee1a80 */
void rome2_l81_fx_name_safe_remove_ref(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    if (!ctx || !ctx->fx || !self || self->entry_va == 0u) {
        return;
    }
    uint32_t entry_va = self->entry_va;
    rome2_fx_name_entry_32 *entry = (rome2_fx_name_entry_32 *)rome2_l80_mut_ptr(
        ctx->fx, entry_va, (uint32_t)sizeof(*entry));
    if (!entry) {
        return;
    }
    if (entry->ref_count == 1) {
        const char *key = rome2_l81_fx_string_cstr(ctx, entry->fx_string_va, 1u);
        (void)rome2_l81_name_table_remove(ctx, key);
        self->entry_va = 0u;
    }
    entry->ref_count--;
    if (entry->ref_count == 0) {
        l81_free_fx_name_entry(ctx, entry_va);
        self->entry_va = 0u;
    }
}

/* 0x10ede090 */
void rome2_l81_fx_name_dtor(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    if (!ctx || ctx->name_table_va == 0u || !self) {
        return;
    }
    rome2_l81_fx_name_safe_remove_ref(ctx, self);
}

/* 0x10ee0d90 */
void rome2_l81_fx_name_add_to_table(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *raw_name) {
    if (!ctx || !ctx->fx || !self) {
        return;
    }
    char sanitized[ROME2_FX_NAME_MAX_LEN];
    size_t len = 0u;
    if (raw_name) {
        while (len + 1u < ROME2_FX_NAME_MAX_LEN && raw_name[len] != '\0') {
            char ch = raw_name[len];
            if (ch == '|') {
                ch = '_';
            } else if (ch == '"') {
                ch = '\'';
            }
            sanitized[len] = ch;
            len++;
        }
        if (raw_name[len] != '\0' && len + 1u >= ROME2_FX_NAME_MAX_LEN) {
            /* Binary truncates / falls back to empty when >= 0x200 chars without NUL. */
            len = 0u;
        }
    }
    sanitized[len] = '\0';

    rome2_l81_name_iter found;
    (void)rome2_l81_name_table_find(ctx, &found, sanitized);
    if (found.node_va != 0u) {
        const rome2_fx_avl_string_node_32 *n =
            (const rome2_fx_avl_string_node_32 *)rome2_l80_const_ptr(
                ctx->fx, found.node_va, (uint32_t)sizeof(*n));
        if (n && n->value_va != 0u) {
            self->entry_va = n->value_va;
            rome2_fx_name_entry_32 *entry = (rome2_fx_name_entry_32 *)rome2_l80_mut_ptr(
                ctx->fx, self->entry_va, (uint32_t)sizeof(*entry));
            if (entry) {
                entry->ref_count++;
            }
            return;
        }
    }
    uint32_t entry_va = l81_alloc_fx_name_entry(ctx, sanitized);
    if (entry_va == 0u) {
        return;
    }
    rome2_l81_name_iter inserted;
    (void)rome2_l81_name_table_insert(ctx, &inserted, sanitized, entry_va);
    self->entry_va = entry_va;
}

/* 0x10ee07c0 */
void rome2_l81_fx_name_set_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *raw_name) {
    if (!self) {
        return;
    }
    rome2_l81_fx_name_safe_remove_ref(ctx, self);
    self->entry_va = 0u;
    rome2_l81_fx_name_add_to_table(ctx, self, raw_name);
}

/* 0x10ede180 */
rome2_fx_name_32 *rome2_l81_fx_name_assign_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other) {
    if (!self || !other) {
        return self;
    }
    uint32_t rhs_va = other->entry_va;
    if (rhs_va == 0u && ctx) {
        rhs_va = ctx->null_name_entry_va;
    }
    if (self->entry_va == rhs_va) {
        return self;
    }
    if (ctx && ctx->fx && rhs_va != 0u) {
        rome2_fx_name_entry_32 *rhs_entry = (rome2_fx_name_entry_32 *)rome2_l80_mut_ptr(
            ctx->fx, rhs_va, (uint32_t)sizeof(*rhs_entry));
        if (rhs_entry) {
            rhs_entry->ref_count++;
        }
    }
    rome2_l81_fx_name_safe_remove_ref(ctx, self);
    self->entry_va = rhs_va;
    return self;
}

/* 0x10ede2b0 */
rome2_fx_name_32 *rome2_l81_fx_name_assign_move(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    rome2_fx_name_32 *other) {
    return rome2_l81_fx_name_assign_copy(ctx, self, other);
}

/* 0x10ed5dd0 */
uint8_t rome2_l81_fx_name_eq_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other) {
    if (!self || !other) {
        return 0u;
    }
    l81_lazy_bind_null(ctx, self);
    uint32_t rhs_va = other->entry_va;
    if (rhs_va == 0u && ctx) {
        rhs_va = ctx->null_name_entry_va;
    }
    return self->entry_va == rhs_va ? 1u : 0u;
}

/* 0x10ed60d0 */
uint8_t rome2_l81_fx_name_ne_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other) {
    return rome2_l81_fx_name_eq_name(ctx, self, other) ? 0u : 1u;
}

/* 0x10edf6e0 */
const char *rome2_l81_fx_name_get_cstr(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    if (!ctx || !ctx->fx || !self) {
        return "";
    }
    l81_lazy_bind_null(ctx, self);
    const rome2_fx_name_entry_32 *entry = (const rome2_fx_name_entry_32 *)rome2_l80_const_ptr(
        ctx->fx, self->entry_va, (uint32_t)sizeof(*entry));
    if (!entry) {
        return "";
    }
    return rome2_l81_fx_string_cstr(ctx, entry->fx_string_va, 1u);
}

/* 0x10edf740 */
uint32_t rome2_l81_fx_name_get_string_va(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self) {
    if (!ctx || !ctx->fx || !self) {
        return 0u;
    }
    l81_lazy_bind_null(ctx, self);
    const rome2_fx_name_entry_32 *entry = (const rome2_fx_name_entry_32 *)rome2_l80_const_ptr(
        ctx->fx, self->entry_va, (uint32_t)sizeof(*entry));
    return entry ? entry->fx_string_va : 0u;
}

/* 0x10ede9c0 */
uint8_t rome2_l81_fx_name_eq_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *rhs) {
    uint32_t s_va = rome2_l81_fx_name_get_string_va(ctx, self);
    return rome2_l81_fx_string_equals_cstr(ctx, s_va, rhs);
}

/* 0x10ede9e0 */
uint8_t rome2_l81_fx_name_ne_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *rhs) {
    uint32_t s_va = rome2_l81_fx_name_get_string_va(ctx, self);
    return rome2_l81_fx_string_not_equals_cstr(ctx, s_va, rhs);
}

/* 0x10edeb90 */
uint8_t rome2_l81_fx_name_lt(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    rome2_fx_name_32 *other) {
    const char *a = rome2_l81_fx_name_get_cstr(ctx, self);
    const char *b = rome2_l81_fx_name_get_cstr(ctx, other);
    return strcmp(a, b) < 0 ? 1u : 0u;
}

/* 0x10edecb0 */
uint8_t rome2_l81_fx_name_gt(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    rome2_fx_name_32 *other) {
    const char *a = rome2_l81_fx_name_get_cstr(ctx, self);
    const char *b = rome2_l81_fx_name_get_cstr(ctx, other);
    return strcmp(a, b) > 0 ? 1u : 0u;
}

/* 0x10ed7d70 */
rome2_fx_client_event_32 *rome2_l81_fx_client_event_ctor_full(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_name_32 *group_name,
    const rome2_fx_name_32 *anim_name,
    float start_time_offset,
    float magnitude_scale,
    float blend_in_time,
    float blend_out_time,
    float duration_scale,
    uint8_t should_persist_values,
    uint32_t event_id,
    const rome2_fx_name_32 *custom_payload) {
    if (!self) {
        return NULL;
    }
    memset(self, 0, sizeof(*self));
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->animation_group_name, group_name);
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->animation_name, anim_name);
    self->start_time_offset = start_time_offset;
    self->magnitude_scale = magnitude_scale;
    self->blend_in_time = blend_in_time;
    self->blend_out_time = blend_out_time;
    self->duration_scale = duration_scale;
    self->should_persist_values = should_persist_values;
    self->event_id = event_id;
    (void)rome2_l81_fx_name_ctor_copy(ctx, &self->custom_payload, custom_payload);
    return self;
}

/* 0x10ed56a0 */
rome2_fx_client_event_32 *rome2_l81_fx_client_event_ctor_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_client_event_32 *other) {
    if (!self || !other) {
        return self;
    }
    return rome2_l81_fx_client_event_ctor_full(
        ctx,
        self,
        &other->animation_group_name,
        &other->animation_name,
        other->start_time_offset,
        other->magnitude_scale,
        other->blend_in_time,
        other->blend_out_time,
        other->duration_scale,
        other->should_persist_values,
        other->event_id,
        &other->custom_payload);
}

/* 0x10ed5840 */
rome2_fx_client_event_32 *rome2_l81_fx_client_event_assign(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_client_event_32 *other) {
    if (!self || !other || self == other) {
        return self;
    }
    (void)rome2_l81_fx_name_assign_copy(ctx, &self->animation_group_name, &other->animation_group_name);
    (void)rome2_l81_fx_name_assign_copy(ctx, &self->animation_name, &other->animation_name);
    self->start_time_offset = other->start_time_offset;
    self->magnitude_scale = other->magnitude_scale;
    self->blend_in_time = other->blend_in_time;
    self->blend_out_time = other->blend_out_time;
    self->duration_scale = other->duration_scale;
    self->should_persist_values = other->should_persist_values;
    self->event_id = other->event_id;
    (void)rome2_l81_fx_name_assign_copy(ctx, &self->custom_payload, &other->custom_payload);
    return self;
}

/* 0x10ed57f0 (tail-jumps to 0x10ede090 on group_name after custom_payload & anim_name) */
void rome2_l81_fx_client_event_dtor(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self) {
    if (!self) {
        return;
    }
    rome2_l81_fx_name_dtor(ctx, &self->custom_payload);
    rome2_l81_fx_name_dtor(ctx, &self->animation_name);
    rome2_l81_fx_name_dtor(ctx, &self->animation_group_name);
}

/* 0x10ef3160 */
uint32_t rome2_l81_fx_object_helper_bind(uint32_t *vtable_slot, uint32_t self_va) {
    if (vtable_slot) {
        *vtable_slot = ROME2_FX_VTABLE_OBJECT_HELPER;
    }
    return self_va;
}

/* 0x10f06ad0 */
uint32_t rome2_l81_fx_ref_object_ctor(rome2_l81_fx_name_ctx *ctx, uint32_t self_va) {
    if (!ctx || !ctx->fx || self_va == 0u) {
        return 0u;
    }
    uint32_t *words = (uint32_t *)rome2_l80_mut_ptr(ctx->fx, self_va, 8u);
    if (!words) {
        return 0u;
    }
    (void)rome2_l81_fx_object_helper_bind(&words[0], self_va);
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
    if (!ctx || !ctx->fx || self_va == 0u || !name) {
        return 0u;
    }
    rome2_fx_class_32 *cls = (rome2_fx_class_32 *)rome2_l80_mut_ptr(
        ctx->fx, self_va, (uint32_t)sizeof(*cls));
    if (!cls) {
        return 0u;
    }
    memset(cls, 0, sizeof(*cls));
    (void)rome2_l81_fx_name_ctor_cstr(ctx, &cls->name, name);
    cls->current_version = version;
    cls->base_class_va = base_class_va;
    cls->num_children = 0u;
    cls->size = size;
    cls->construct_fn_va = ctor_fn_va;

    if (ctx->class_desc_array_va == 0u) {
        l81_log_msg(ctx, 1, "Attempt to create FxClass before FxClass::Startup() called!");
        ctx->class_desc_array_va = rome2_l80_fx_allocate(
            ctx->fx, (uint32_t)sizeof(rome2_fx_class_array_32));
        rome2_fx_class_array_32 *arr_init = (rome2_fx_class_array_32 *)rome2_l80_mut_ptr(
            ctx->fx, ctx->class_desc_array_va, (uint32_t)sizeof(*arr_init));
        if (arr_init) {
            memset(arr_init, 0, sizeof(*arr_init));
        }
    }

    rome2_fx_name_32 probe;
    (void)rome2_l81_fx_name_ctor_cstr(ctx, &probe, name);
    uint8_t dup = 0u;
    rome2_fx_class_array_32 *arr = (rome2_fx_class_array_32 *)rome2_l80_mut_ptr(
        ctx->fx, ctx->class_desc_array_va, (uint32_t)sizeof(*arr));
    if (arr && arr->items_va != 0u && arr->count > 0u) {
        uint32_t *ptrs = (uint32_t *)rome2_l80_mut_ptr(ctx->fx, arr->items_va, arr->count * 4u);
        for (uint32_t i = 0u; ptrs && i < arr->count; ++i) {
            rome2_fx_class_32 *existing = (rome2_fx_class_32 *)rome2_l80_mut_ptr(
                ctx->fx, ptrs[i], (uint32_t)sizeof(*existing));
            if (existing && rome2_l81_fx_name_eq_name(ctx, &existing->name, &probe)) {
                dup = 1u;
                break;
            }
        }
    }
    rome2_l81_fx_name_dtor(ctx, &probe);
    if (dup) {
        l81_log_msg(ctx, 1, "Attempt to create duplicate FxClass!");
    }

    if (base_class_va != 0u) {
        rome2_fx_class_32 *base = (rome2_fx_class_32 *)rome2_l80_mut_ptr(
            ctx->fx, base_class_va, (uint32_t)sizeof(*base));
        if (base) {
            base->num_children++;
        }
    }
    if (arr) {
        if (arr->count >= arr->capacity) {
            uint32_t new_cap = (arr->capacity == 0u) ? 1u : arr->capacity * 2u;
            uint32_t new_va = rome2_l80_fx_allocate(ctx->fx, new_cap * 4u);
            if (new_va != 0u) {
                uint32_t *new_ptrs = (uint32_t *)rome2_l80_mut_ptr(ctx->fx, new_va, new_cap * 4u);
                if (new_ptrs) {
                    if (arr->items_va != 0u && arr->count > 0u) {
                        const uint32_t *old_ptrs = (const uint32_t *)rome2_l80_const_ptr(
                            ctx->fx, arr->items_va, arr->count * 4u);
                        if (old_ptrs) {
                            memcpy(new_ptrs, old_ptrs, arr->count * 4u);
                        }
                        rome2_l80_fx_free(ctx->fx, arr->items_va, arr->capacity * 4u);
                    }
                    arr->items_va = new_va;
                    arr->capacity = new_cap;
                }
            }
        }
        if (arr->items_va != 0u && arr->count < arr->capacity) {
            uint32_t *ptrs = (uint32_t *)rome2_l80_mut_ptr(
                ctx->fx, arr->items_va, (arr->count + 1u) * 4u);
            if (ptrs) {
                ptrs[arr->count] = self_va;
                arr->count++;
            }
        }
    }
    return self_va;
}

/* 0x10ef31c0 */
uint32_t rome2_l81_fx_object_static_class_init(rome2_l81_fx_name_ctx *ctx) {
    if (!ctx || !ctx->fx) {
        return 0u;
    }
    uint32_t cls_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_class_32));
    if (cls_va == 0u) {
        return 0u;
    }
    return rome2_l81_fx_class_ctor(ctx, cls_va, "FxObject", 0u, 0u, 4u, 0x10ef31f0u);
}

/* 0x10f06b40 */
uint32_t rome2_l81_fx_ref_object_static_class_init(rome2_l81_fx_name_ctx *ctx) {
    if (!ctx || !ctx->fx) {
        return 0u;
    }
    uint32_t cls_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_class_32));
    if (cls_va == 0u) {
        return 0u;
    }
    if (ctx->fx_object_class_va == 0u) {
        ctx->fx_object_class_va = rome2_l81_fx_object_static_class_init(ctx);
    }
    return rome2_l81_fx_class_ctor(
        ctx, cls_va, "FxRefObject", 0u, ctx->fx_object_class_va, 8u, 0x10f06b80u);
}
