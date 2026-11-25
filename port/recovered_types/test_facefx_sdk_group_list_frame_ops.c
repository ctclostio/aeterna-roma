#include "facefx_sdk_group_list_frame_ops.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

/* Guest objects are placed at fixed arena addresses; every offset below is the one the image uses. */
#define L85_ARENA_BASE 0x30000000u
#define L85_LOG_MANAGER_VA 0x30000200u
#define L85_CLASS_TABLE_VA 0x30000300u
#define L85_LISTENER_VA 0x30000400u
#define L85_NAMES_VA 0x30000500u
#define L85_ANIM_VA 0x30001000u
#define L85_CURVES_VA 0x30001200u
#define L85_COMPRESSED_VA 0x30001300u
#define L85_GROUP_VA 0x30001400u
#define L85_NODES_VA 0x30001500u
#define L85_SUB_GROUP_VA 0x30001700u
#define L85_SET_VA 0x30001800u
#define L85_INSTANCE_VA 0x30001a00u
#define L85_MANAGER_VA 0x30001c00u
#define L85_EVENTS_VA 0x30001d00u
#define L85_FLAGS_VA 0x30002000u
#define L85_LINKED_VA 0x30002100u
#define L85_FUNCTOR_A_VA 0x30002200u
#define L85_FUNCTOR_B_VA 0x30002210u
#define L85_FUNCTOR_SOURCE_VA 0x30002220u
#define L85_FUNCTOR_NEW_VA 0x30002230u
#define L85_CLASSES_VA 0x30002400u
#define L85_BONES_VA 0x30003000u
#define L85_LINKS_VA 0x30003200u
#define L85_REFERENCE_VA 0x30003400u
#define L85_OUTPUT_VA 0x30003600u
#define L85_VALUES_VA 0x30003800u
#define L85_BITSET_VA 0x30003900u
#define L85_WORDS_VA 0x30003a00u
#define L85_HANDLE_VA 0x30003b00u
#define L85_POOL_VA 0x30003c00u
#define L85_STRINGS_VA 0x30004000u
#define L85_ACTOR_VA 0x30010000u
#define L85_HEAP_START 0x30040000u
#define L85_UNMAPPED_VA 0x50000000u

/* Objects that are only compared or handed to hooks, never read. */
#define L85_OBJECT_A 0x60000100u
#define L85_OBJECT_B 0x60000200u
#define L85_OBJECT_C 0x60000300u
#define L85_IMPL_AUDIO 0x60001000u
#define L85_IMPL_CUSTOM 0x60002000u
#define L85_IMPL_SOURCE 0x60003000u
#define L85_IMPL_CLONE 0x60004000u
#define L85_INSTANCE_A 0x70000000u
#define L85_INSTANCE_B 0x7000abcdu
#define L85_UNWRITTEN 0xa5a5a5a5u

#define L85_LOG_CAPACITY 24u
#define L85_CALL_CAPACITY 32u

typedef enum l85_call_kind {
    CALL_NEW,
    CALL_DELETE,
    CALL_FUNCTOR_DESTROY,
    CALL_FUNCTOR_CLONE,
    CALL_CLASS_DESC,
    CALL_DESTROY,
    CALL_TREE_CLEAR,
    CALL_TREE_INSERT,
    CALL_TREE_REMOVE,
    CALL_FREE
} l85_call_kind;

typedef struct l85_call {
    l85_call_kind kind;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} l85_call;

typedef struct l85_log_line {
    int32_t level;
    uint32_t tab_level;
    char text[160];
} l85_log_line;

typedef struct l85_fixture {
    rome2_l80_fx_ctx fx;
    rome2_l81_fx_name_ctx names;
    rome2_l84_fx_event_ctx events;
    rome2_l85_fx_sdk_ctx sdk;
    rome2_fx_log_manager_32 *manager;
} l85_fixture;

static uint8_t s_arena[512u * 1024u];
static l85_log_line s_log[L85_LOG_CAPACITY];
static uint32_t s_log_count;
static l85_call s_calls[L85_CALL_CAPACITY];
static uint32_t s_call_count;
static uint32_t s_new_result;
static uint32_t s_clone_result;
static uint32_t s_class_desc_result;
static rome2_fx_tree_iterator_32 s_insert_result;
static int32_t s_level_after_log;     /* when not negative, the log hook lowers the manager's level to it ... */
static uint32_t s_level_after_count;  /* ... once this many messages have been seen */
static const rome2_l80_fx_ctx *s_fx;

static void record(l85_call_kind kind, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    if (s_call_count < L85_CALL_CAPACITY) {
        l85_call *call = &s_calls[s_call_count];
        call->kind = kind;
        call->a = a;
        call->b = b;
        call->c = c;
        call->d = d;
    }
    ++s_call_count;
}

static void expect_call(uint32_t index, l85_call_kind kind, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    assert(index < s_call_count && index < L85_CALL_CAPACITY);
    assert(s_calls[index].kind == kind);
    assert(s_calls[index].a == a);
    assert(s_calls[index].b == b);
    assert(s_calls[index].c == c);
    assert(s_calls[index].d == d);
}

static void expect_log(uint32_t index, int32_t level, uint32_t tab_level, const char *text) {
    assert(index < s_log_count && index < L85_LOG_CAPACITY);
    assert(s_log[index].level == level);
    assert(s_log[index].tab_level == tab_level);
    assert(strcmp(s_log[index].text, text) == 0);
}

static void *at(uint32_t va, uint32_t bytes) {
    void *p = rome2_l80_mut_ptr(s_fx, va, bytes);
    assert(p != NULL);
    return p;
}

static void put_u32(uint32_t va, uint32_t value) {
    memcpy(at(va, 4u), &value, sizeof(value));
}

static uint32_t get_u32(uint32_t va) {
    uint32_t value;
    memcpy(&value, at(va, 4u), sizeof(value));
    return value;
}

static void put_f32(uint32_t va, float value) {
    memcpy(at(va, 4u), &value, sizeof(value));
}

static float get_f32(uint32_t va) {
    float value;
    memcpy(&value, at(va, 4u), sizeof(value));
    return value;
}

static float f32_of(uint32_t bits) {
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static void put_u8(uint32_t va, uint8_t value) {
    *(uint8_t *)at(va, 1u) = value;
}

static uint8_t get_u8(uint32_t va) {
    return *(const uint8_t *)at(va, 1u);
}

/* Records each message with the tab level in force when the entry was flushed, indentation stripped. */
static void test_on_log(rome2_l80_fx_ctx *ctx, uint32_t listener_va, const char *msg, int32_t level) {
    rome2_fx_log_manager_32 *manager = (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(
        ctx, ctx->log_manager_singleton_va, (uint32_t)sizeof(*manager));
    assert(listener_va == L85_LISTENER_VA && manager != NULL && msg != NULL);
    if (s_log_count < L85_LOG_CAPACITY) {
        l85_log_line *line = &s_log[s_log_count];
        line->level = level;
        line->tab_level = manager->tab_level;
        while (*msg == ' ') {
            ++msg;
        }
        (void)snprintf(line->text, sizeof(line->text), "%s", msg);
    }
    ++s_log_count;
    if (s_level_after_log >= 0 && s_log_count == s_level_after_count) {
        manager->max_log_level = s_level_after_log;
    }
}

static void test_on_free(rome2_l80_fx_ctx *ctx, uint32_t ptr_va, uint32_t bytes) {
    (void)ctx;
    record(CALL_FREE, ptr_va, bytes, 0u, 0u);
}

static uint32_t failing_alloc(rome2_l80_fx_ctx *ctx, uint32_t bytes) {
    (void)ctx;
    (void)bytes;
    return 0u;
}

static uint32_t hook_new(rome2_l84_fx_event_ctx *ctx, uint32_t bytes) {
    (void)ctx;
    record(CALL_NEW, bytes, 0u, 0u, 0u);
    return s_new_result;
}

static void hook_delete(rome2_l84_fx_event_ctx *ctx, uint32_t ptr_va, uint32_t bytes) {
    (void)ctx;
    record(CALL_DELETE, ptr_va, bytes, 0u, 0u);
}

static void hook_functor_destroy(rome2_l84_fx_event_ctx *ctx, uint32_t impl_va, uint32_t flags) {
    (void)ctx;
    record(CALL_FUNCTOR_DESTROY, impl_va, flags, 0u, 0u);
}

static uint32_t hook_functor_clone(rome2_l84_fx_event_ctx *ctx, uint32_t impl_va) {
    (void)ctx;
    record(CALL_FUNCTOR_CLONE, impl_va, 0u, 0u, 0u);
    return s_clone_result;
}

static uint32_t hook_class_desc(rome2_l85_fx_sdk_ctx *ctx, uint32_t object_va) {
    (void)ctx;
    record(CALL_CLASS_DESC, object_va, 0u, 0u, 0u);
    return s_class_desc_result;
}

static void hook_destroy(rome2_l85_fx_sdk_ctx *ctx, uint32_t object_va, uint32_t flags) {
    (void)ctx;
    record(CALL_DESTROY, object_va, flags, 0u, 0u);
}

static void hook_tree_clear(rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va) {
    (void)ctx;
    record(CALL_TREE_CLEAR, tree_va, 0u, 0u, 0u);
}

static void hook_tree_insert(
    rome2_l85_fx_sdk_ctx *ctx,
    uint32_t tree_va,
    rome2_fx_tree_iterator_32 *result,
    uint32_t root_slot_va,
    uint32_t key_va,
    uint32_t value_va) {
    (void)ctx;
    assert(result != NULL && result->tree_va == 0u && result->node_va == 0u);
    record(CALL_TREE_INSERT, tree_va, root_slot_va, key_va, value_va);
    *result = s_insert_result;
}

static void hook_tree_remove(rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va, uint32_t node_va) {
    (void)ctx;
    record(CALL_TREE_REMOVE, tree_va, node_va, 0u, 0u);
}

static void reset_records(void) {
    memset(s_log, 0, sizeof(s_log));
    memset(s_calls, 0, sizeof(s_calls));
    s_log_count = 0u;
    s_call_count = 0u;
}

/* with_name_table runs FxName::Startup over a zeroed class table, as the SDK does before any class is described. */
static void fixture_init(l85_fixture *f, int with_name_table) {
    memset(s_arena, 0, sizeof(s_arena));
    s_new_result = 0u;
    s_clone_result = 0u;
    s_class_desc_result = 0u;
    s_insert_result.tree_va = 0u;
    s_insert_result.node_va = 0u;
    s_level_after_log = -1;
    s_level_after_count = 0u;

    rome2_l80_ctx_init(&f->fx, s_arena, L85_ARENA_BASE, (uint32_t)sizeof(s_arena), L85_HEAP_START);
    s_fx = &f->fx;
    f->fx.on_log_message = test_on_log;
    f->fx.custom_free = test_on_free;
    (void)rome2_l80_log_manager_ctor(&f->fx, L85_LOG_MANAGER_VA);
    f->fx.log_manager_singleton_va = L85_LOG_MANAGER_VA;
    f->manager = (rome2_fx_log_manager_32 *)at(L85_LOG_MANAGER_VA, (uint32_t)sizeof(*f->manager));
    rome2_l80_log_manager_set_max_level(f->manager, 6);
    rome2_l80_fx_log_add_listener(&f->manager->log, L85_LISTENER_VA);

    rome2_l81_ctx_init(&f->names, &f->fx);
    if (with_name_table != 0) {
        f->names.class_table_va = L85_CLASS_TABLE_VA;
        rome2_l81_fx_name_startup(&f->names);
        assert(f->names.name_table_va != 0u && f->names.null_name.entry_va != 0u);
    }

    rome2_l84_event_ctx_init(&f->events, &f->fx);
    f->events.operator_new = hook_new;
    f->events.operator_delete = hook_delete;
    f->events.functor_impl_destroy = hook_functor_destroy;
    f->events.functor_impl_clone = hook_functor_clone;

    rome2_l85_ctx_init(&f->sdk, &f->fx, &f->names);
    f->sdk.object_get_class_desc = hook_class_desc;
    f->sdk.object_destroy = hook_destroy;
    f->sdk.tree_clear = hook_tree_clear;
    f->sdk.tree_insert = hook_tree_insert;
    f->sdk.tree_remove = hook_tree_remove;
    reset_records();
}

/*
 * A hand-built FxName entry: {vtable, reference count, FxString pointer} with
 * the FxString 0x10 bytes further on, its text inline. Returns the entry.
 */
static uint32_t fake_name(uint32_t index, const char *text) {
    uint32_t entry_va = L85_NAMES_VA + index * 0x30u;
    uint32_t string_va = entry_va + 0x10u;
    uint32_t length = (uint32_t)strlen(text);
    rome2_fx_string_32 *string = (rome2_fx_string_32 *)at(string_va, (uint32_t)sizeof(*string));
    assert(length < sizeof(string->inline_buf));
    put_u32(entry_va, ROME2_FX_VTABLE_NAME_ENTRY);
    put_u32(entry_va + 4u, 1u);
    put_u32(entry_va + 8u, string_va);
    memset(string, 0, sizeof(*string));
    memcpy(string->inline_buf, text, length);
    string->data_va = string_va;
    string->capacity = length + 1u;
    string->length = length;
    return entry_va;
}

static const rome2_fx_class_32 *class_at(uint32_t va) {
    return (const rome2_fx_class_32 *)at(va, (uint32_t)sizeof(rome2_fx_class_32));
}

static const char *class_name(l85_fixture *f, uint32_t class_va) {
    rome2_fx_name_32 *name = (rome2_fx_name_32 *)at(class_va, 4u);
    const char *text = rome2_l81_fx_name_get_cstr(&f->names, name);
    assert(text != NULL);
    return text;
}

static void test_class_queries(void) {
    l85_fixture f;
    uint32_t base_va = L85_CLASSES_VA;
    uint32_t middle_va = L85_CLASSES_VA + 0x20u;
    uint32_t leaf_va = L85_CLASSES_VA + 0x40u;
    uint32_t other_va = L85_CLASSES_VA + 0x60u;
    fixture_init(&f, 0);

    /* 0x1033c6a0: descriptors are equal when they are the same object */
    assert(rome2_l85_fx_class_equals(leaf_va, leaf_va) == 1u);
    assert(rome2_l85_fx_class_equals(leaf_va, middle_va) == 0u);
    assert(rome2_l85_fx_class_equals(0u, 0u) == 1u);

    /* 0x10ef2e80: leaf -> middle -> base through the pointer at +8 */
    put_u32(leaf_va + 8u, middle_va);
    put_u32(middle_va + 8u, base_va);
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, leaf_va, leaf_va) == 1u);
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, leaf_va, middle_va) == 1u);
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, leaf_va, base_va) == 1u);
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, base_va, leaf_va) == 0u);
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, leaf_va, other_va) == 0u);
    /* TEST ECX, ECX first: a NULL descriptor is no kind of anything, NULL included */
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, 0u, 0u) == 0u);
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, leaf_va, 0u) == 0u);
    /* bounded: a base outside the arena, and a base chain that loops */
    put_u32(base_va + 8u, L85_UNMAPPED_VA);
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, leaf_va, other_va) == 0u);
    put_u32(base_va + 8u, leaf_va);
    assert(rome2_l85_fx_class_is_kind_of(&f.fx, leaf_va, other_va) == 0u);
    assert(rome2_l85_fx_class_is_kind_of(NULL, leaf_va, leaf_va) == 0u);
    put_u32(base_va + 8u, 0u);

    /* 0x10ed78b0: the object's own class, from vtable slot +0, must be the argument itself */
    s_class_desc_result = leaf_va;
    assert(rome2_l85_fx_object_is_a(&f.sdk, L85_OBJECT_A, leaf_va) == 1u);
    assert(rome2_l85_fx_object_is_a(&f.sdk, L85_OBJECT_A, middle_va) == 0u);
    /* 0x10ed7950: any class on the base chain will do */
    assert(rome2_l85_fx_object_is_kind_of(&f.sdk, L85_OBJECT_A, base_va) == 1u);
    assert(rome2_l85_fx_object_is_kind_of(&f.sdk, L85_OBJECT_A, other_va) == 0u);
    assert(s_call_count == 4u);
    expect_call(0u, CALL_CLASS_DESC, L85_OBJECT_A, 0u, 0u, 0u);
    expect_call(3u, CALL_CLASS_DESC, L85_OBJECT_A, 0u, 0u, 0u);

    /* a NULL class answers 0 from both, even against a NULL argument */
    s_class_desc_result = 0u;
    assert(rome2_l85_fx_object_is_a(&f.sdk, L85_OBJECT_A, 0u) == 0u);
    assert(rome2_l85_fx_object_is_kind_of(&f.sdk, L85_OBJECT_A, 0u) == 0u);
    f.sdk.object_get_class_desc = NULL;
    assert(rome2_l85_fx_object_is_a(&f.sdk, L85_OBJECT_A, leaf_va) == 0u);
    assert(rome2_l85_fx_object_is_kind_of(&f.sdk, L85_OBJECT_A, leaf_va) == 0u);
    assert(rome2_l85_fx_object_is_a(NULL, L85_OBJECT_A, leaf_va) == 0u);
    assert(rome2_l85_fx_object_is_kind_of(NULL, L85_OBJECT_A, leaf_va) == 0u);
}

static void test_named_object_and_class_descriptors(void) {
    static const struct {
        uint32_t (*init)(rome2_l85_fx_sdk_ctx *ctx);
        const char *name;
        uint16_t version;
        uint32_t size;
        uint32_t construct_va;
    } classes[5] = {
        {rome2_l85_fx_anim_static_class_init, "FxAnim", 10u, 0xf8u, 0x10ed6440u},
        {rome2_l85_fx_anim_group_static_class_init, "FxAnimGroup", 1u, 0x20u, 0x10ed6460u},
        {rome2_l85_fx_anim_set_static_class_init, "FxAnimSet", 1u, 0x38u, 0x10ed6480u},
        {rome2_l85_fx_actor_static_class_init, "FxActor", 5u, 0x6118u, 0x10ed6420u},
        {rome2_l85_fx_actor_instance_static_class_init, "FxActorInstance", 0u, 0x11cu, 0x100dbc00u},
    };
    l85_fixture f;
    const rome2_fx_name_entry_32 *null_entry;
    const rome2_fx_class_32 *named;
    const rome2_fx_class_32 *described;
    const uint32_t *table;
    uint32_t object_class_va;
    uint32_t named_va;
    uint32_t first_va;
    uint32_t registered;
    int32_t null_refs;
    uint32_t i;
    fixture_init(&f, 1);
    null_entry = (const rome2_fx_name_entry_32 *)at(f.names.null_name.entry_va, (uint32_t)sizeof(*null_entry));
    null_refs = null_entry->ref_count;

    /* 0x10ef3260: the FxNamedObject vtable over whatever was there, and one more reference to NullName */
    memset(at(L85_GROUP_VA, 0x20u), 0xa5, 0x20u);
    assert(rome2_l85_fx_named_object_ctor(&f.sdk, L85_GROUP_VA) == L85_GROUP_VA);
    assert(get_u32(L85_GROUP_VA) == 0x1183ce30u);
    assert(get_u32(L85_GROUP_VA + 4u) == f.names.null_name.entry_va);
    assert(get_u32(L85_GROUP_VA + 8u) == L85_UNWRITTEN);
    assert(null_entry->ref_count == null_refs + 1 && s_log_count == 0u);

    /* 0x10ee49f0: the group vtable, the name, and two empty trees sharing one tree vtable */
    memset(at(L85_GROUP_VA, 0x24u), 0xa5, 0x24u);
    assert(rome2_l85_anim_group_ctor(&f.sdk, L85_GROUP_VA) == L85_GROUP_VA);
    assert(get_u32(L85_GROUP_VA) == 0x1183bf8cu);
    assert(get_u32(L85_GROUP_VA + 4u) == f.names.null_name.entry_va);
    assert(get_u32(L85_GROUP_VA + 0x08u) == 0x1183bf74u && get_u32(L85_GROUP_VA + 0x14u) == 0x1183bf74u);
    assert(get_u32(L85_GROUP_VA + 0x0cu) == 0u && get_u32(L85_GROUP_VA + 0x10u) == 0u);
    assert(get_u32(L85_GROUP_VA + 0x18u) == 0u && get_u32(L85_GROUP_VA + 0x1cu) == 0u);
    assert(get_u32(L85_GROUP_VA + 0x20u) == L85_UNWRITTEN);
    assert(null_entry->ref_count == null_refs + 2);
    assert(rome2_l85_anim_group_ctor(&f.sdk, L85_UNMAPPED_VA) == 0u);
    assert(rome2_l85_fx_named_object_ctor(&f.sdk, L85_UNMAPPED_VA) == 0u);

    /* startup registered its own descriptors; FxObject is among them and FxNamedObject is not yet described */
    table = (const uint32_t *)at(L85_CLASS_TABLE_VA, 12u);
    registered = table[2];
    object_class_va = f.names.fx_object_class_va;
    assert(object_class_va != 0u && f.sdk.fx_named_object_class_va == 0u);

    /*
     * 0x10ee2ad0: the FxAnim block is allocated before the missing base is described, so with a bump
     * allocator it has the lower address. The base registers first, though.
     */
    first_va = rome2_l85_fx_anim_static_class_init(&f.sdk);
    named_va = f.sdk.fx_named_object_class_va;
    assert(first_va != 0u && named_va != 0u && first_va < named_va);
    assert(table[2] == registered + 2u);
    assert(get_u32(table[0] + registered * 4u) == named_va);
    assert(get_u32(table[0] + (registered + 1u) * 4u) == first_va);

    /* 0x10ef3310: FxClass("FxNamedObject", 0, FxObject, 8, 0x10ef3350) */
    named = class_at(named_va);
    assert(strcmp(class_name(&f, named_va), "FxNamedObject") == 0);
    assert(named->current_version == 0u && named->base_class_va == object_class_va);
    assert(named->size == 8u && named->construct_fn_va == 0x10ef3350u && named->num_children == 1u);

    for (i = 0u; i < 5u; ++i) {
        uint32_t class_va = (i == 0u) ? first_va : classes[i].init(&f.sdk);
        described = class_at(class_va);
        assert(class_va != 0u && strcmp(class_name(&f, class_va), classes[i].name) == 0);
        assert(described->current_version == classes[i].version);
        assert(described->base_class_va == named_va && described->num_children == 0u);
        assert(described->size == classes[i].size && described->construct_fn_va == classes[i].construct_va);
        /* the cached base is reused: one more descriptor, one more child */
        assert(f.sdk.fx_named_object_class_va == named_va && named->num_children == i + 1u);
        assert(table[2] == registered + 2u + i);
        assert(rome2_l85_fx_class_is_kind_of(&f.fx, class_va, object_class_va) == 1u);
    }
    assert(s_log_count == 0u);

    /* an FxNamedObject descriptor of its own, with FxObject described on demand through 0x11fadba4 */
    f.names.fx_object_class_va = 0u;
    named_va = rome2_l85_fx_named_object_static_class_init(&f.sdk);
    assert(named_va != 0u && f.names.fx_object_class_va != 0u && f.names.fx_object_class_va != object_class_va);
    assert(class_at(named_va)->base_class_va == f.names.fx_object_class_va);
    assert(strcmp(class_name(&f, f.names.fx_object_class_va), "FxObject") == 0);
    /* the name already has a descriptor: the constructor reports it at level 2 and registers anyway */
    assert(s_log_count == 2u);
    expect_log(0u, 2, 0u, "Attempt to create duplicate FxClass!");

    /* a failed FxAllocate answers 0 before the base is looked at */
    f.fx.custom_alloc = failing_alloc;
    f.sdk.fx_named_object_class_va = 0u;
    registered = table[2];
    assert(rome2_l85_fx_named_object_static_class_init(&f.sdk) == 0u);
    for (i = 0u; i < 5u; ++i) {
        assert(classes[i].init(&f.sdk) == 0u);
    }
    assert(f.sdk.fx_named_object_class_va == 0u && table[2] == registered);
    assert(rome2_l85_fx_anim_static_class_init(NULL) == 0u);
    assert(rome2_l85_fx_named_object_static_class_init(NULL) == 0u);
}

static void put_string(uint32_t va, const char *text, uint32_t block_va) {
    rome2_fx_string_32 *string = (rome2_fx_string_32 *)at(va, (uint32_t)sizeof(*string));
    uint32_t length = (uint32_t)strlen(text);
    memset(string->inline_buf, '#', sizeof(string->inline_buf));
    if (block_va != 0u) {
        memcpy(at(block_va, length + 1u), text, (size_t)length + 1u);
        string->data_va = block_va;
    } else {
        assert(length < sizeof(string->inline_buf));
        memcpy(string->inline_buf, text, length);
        string->data_va = va;
    }
    string->capacity = (length != 0u) ? length + 1u : 0u;
    string->length = length;
}

static void test_fx_string_assign(void) {
    static const char long_text[] = "Centurion_Rally_Loud"; /* 20 characters */
    static const char edge_text[] = "0123456789abcdef";     /* 16 characters */
    l85_fixture f;
    const rome2_fx_string_32 *target;
    uint32_t target_va = L85_STRINGS_VA;
    uint32_t source_va = L85_STRINGS_VA + 0x40u;
    uint32_t block_va = L85_STRINGS_VA + 0x100u;
    uint32_t old_block_va = L85_STRINGS_VA + 0x200u;
    uint32_t allocated_va;
    fixture_init(&f, 0);
    target = (const rome2_fx_string_32 *)at(target_va, (uint32_t)sizeof(*target));

    /* short over inline: exactly five bytes move, the old sixth stays, and nothing is allocated or freed */
    put_string(target_va, "Maximus", 0u);
    put_string(source_va, "Rally", 0u);
    assert(rome2_l85_fx_string_assign(&f.fx, target_va, source_va) == target_va);
    assert(memcmp(target->inline_buf, "Rallyus#", 8u) == 0);
    assert(target->data_va == target_va && target->capacity == 6u && target->length == 5u);
    assert(f.fx.alloc_calls == 0u && s_call_count == 0u);

    /* empty over inline: capacity and length 0, every inline byte as it was */
    put_string(source_va, "", 0u);
    assert(rome2_l85_fx_string_assign(&f.fx, target_va, source_va) == target_va);
    assert(memcmp(target->inline_buf, "Rallyus#", 8u) == 0);
    assert(target->data_va == target_va && target->capacity == 0u && target->length == 0u);

    /* fifteen characters still fit inline (capacity 16); sixteen take FxAllocate(17) and a terminator */
    put_string(source_va, "0123456789abcde", 0u);
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, source_va);
    assert(target->data_va == target_va && target->capacity == 16u && target->length == 15u);
    assert(memcmp(target->inline_buf, "0123456789abcde#", 16u) == 0 && f.fx.alloc_calls == 0u);
    put_string(source_va, edge_text, block_va);
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, source_va);
    allocated_va = target->data_va;
    assert(allocated_va == L85_HEAP_START && f.fx.alloc_calls == 1u);
    assert(target->capacity == 17u && target->length == 16u);
    assert(memcmp(at(allocated_va, 17u), edge_text, 17u) == 0);
    assert(memcmp(target->inline_buf, "0123456789abcde#", 16u) == 0 && s_call_count == 0u);

    /* long over a block: the new block replaces the old one, which is released with its old capacity */
    put_string(source_va, long_text, block_va);
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, source_va);
    assert(target->data_va != allocated_va && target->capacity == 21u && target->length == 20u);
    assert(memcmp(at(target->data_va, 21u), long_text, 21u) == 0);
    assert(s_call_count == 1u);
    expect_call(0u, CALL_FREE, allocated_va, 17u, 0u, 0u);

    /* short over a block: the text moves inline and the block goes */
    put_string(target_va, long_text, old_block_va);
    put_string(source_va, "Ave", 0u);
    reset_records();
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, source_va);
    assert(target->data_va == target_va && target->capacity == 4u && target->length == 3u);
    assert(memcmp(target->inline_buf, "Ave#", 4u) == 0);
    assert(s_call_count == 1u);
    expect_call(0u, CALL_FREE, old_block_va, 21u, 0u, 0u);

    /* empty over a block frees it as well */
    put_string(target_va, long_text, old_block_va);
    put_string(source_va, "", 0u);
    reset_records();
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, source_va);
    assert(target->data_va == target_va && target->capacity == 0u && target->length == 0u);
    expect_call(0u, CALL_FREE, old_block_va, 21u, 0u, 0u);

    /* self-assignment of a long string copies it to a fresh block before the old one is released */
    put_string(target_va, long_text, old_block_va);
    reset_records();
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, target_va);
    assert(target->data_va != old_block_va && memcmp(at(target->data_va, 21u), long_text, 21u) == 0);
    expect_call(0u, CALL_FREE, old_block_va, 21u, 0u, 0u);

    /* 0x10ee47e0 / 0x10ee47f0: the same assignment on the strings at FxAnim +0xd0 and +0xb4 */
    put_string(L85_ANIM_VA + 0xd0u, "", 0u);
    put_string(L85_ANIM_VA + 0xb4u, "", 0u);
    put_string(source_va, "voice.wav", 0u);
    assert(rome2_l85_anim_set_audio_asset_name(&f.fx, L85_ANIM_VA, source_va) == L85_ANIM_VA + 0xd0u);
    assert(memcmp(at(L85_ANIM_VA + 0xd0u, 9u), "voice.wav", 9u) == 0 && get_u32(L85_ANIM_VA + 0xe8u) == 9u);
    assert(get_u32(L85_ANIM_VA + 0xccu) == 0u);
    put_string(source_va, "audio/", 0u);
    assert(rome2_l85_anim_set_audio_asset_path(&f.fx, L85_ANIM_VA, source_va) == L85_ANIM_VA + 0xb4u);
    assert(memcmp(at(L85_ANIM_VA + 0xb4u, 6u), "audio/", 6u) == 0 && get_u32(L85_ANIM_VA + 0xccu) == 6u);
    assert(get_u32(L85_ANIM_VA + 0xe8u) == 9u);

    /* bounded: unreadable source text, a failed allocation and an unmapped operand leave the target alone */
    put_string(target_va, "Maximus", 0u);
    put_string(source_va, "Rally", 0u);
    put_u32(source_va + 0x10u, L85_UNMAPPED_VA);
    assert(rome2_l85_fx_string_assign(&f.fx, target_va, source_va) == target_va);
    put_string(source_va, long_text, block_va);
    f.fx.custom_alloc = failing_alloc;
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, source_va);
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, L85_UNMAPPED_VA);
    put_u32(source_va + 0x18u, 0xffffffffu);
    (void)rome2_l85_fx_string_assign(&f.fx, target_va, source_va);
    assert(memcmp(target->inline_buf, "Maximus", 7u) == 0 && target->length == 7u && target->capacity == 8u);
    assert(rome2_l85_fx_string_assign(&f.fx, L85_UNMAPPED_VA, source_va) == L85_UNMAPPED_VA);
    assert(rome2_l85_fx_string_assign(NULL, target_va, source_va) == target_va);
}

static void test_name_stats_dump(void) {
    l85_fixture f;
    rome2_l81_name_stats stats;
    rome2_fx_name_32 extra[3];
    char expected[9][64];
    uint32_t i;
    fixture_init(&f, 1);
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &extra[0], "Centurion_Rally");
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &extra[1], "Legate");
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &extra[2], "Legate");
    memset(&stats, 0, sizeof(stats));
    rome2_l81_fx_name_get_stats(&f.names, &stats);
    assert(stats.num_names >= 5u && stats.bucket_count == 0x1000u && stats.non_empty_buckets != 0u);
    (void)snprintf(expected[0], sizeof(expected[0]), "%d unique names", (int)stats.num_names);
    (void)snprintf(expected[1], sizeof(expected[1]), "%d peak collisions", (int)stats.num_collisions);
    (void)snprintf(expected[2], sizeof(expected[2]), "%d peak unique names", (int)stats.num_added);
    (void)snprintf(expected[3], sizeof(expected[3]), "%d peak probes", (int)stats.num_probes);
    /* the sixth GetNameStats result (bins in use) is printed ahead of the fifth (the bin total) */
    (void)snprintf(expected[4], sizeof(expected[4]), "%d used / 4096 total hash bins", (int)stats.non_empty_buckets);
    (void)snprintf(expected[5], sizeof(expected[5]), "minimum bin size: %d", (int)stats.min_bucket_len);
    (void)snprintf(expected[6], sizeof(expected[6]), "maximum bin size: %d", (int)stats.max_bucket_len);
    (void)snprintf(expected[7], sizeof(expected[7]), "average bin size: %d", (int)stats.avg_bucket_len);
    (void)snprintf(expected[8], sizeof(expected[8]), "%d bytes used", (int)stats.mem_bytes);

    /* level 4: the heading at the current tab level, nine entries one level in, tab level restored */
    rome2_l80_log_manager_set_max_level(f.manager, 4);
    f.manager->tab_level = 2u;
    reset_records();
    rome2_l85_fx_name_dump_stats_to_log(&f.names);
    assert(s_log_count == 10u && f.manager->tab_level == 2u);
    expect_log(0u, 4, 2u, "Name table stats:");
    for (i = 0u; i < 9u; ++i) {
        expect_log(i + 1u, 4, 3u, expected[i]);
    }

    /* JL at 0x10edef53 and 0x10edf035: below level 4 nothing is logged, and the tab level still goes up and back */
    rome2_l80_log_manager_set_max_level(f.manager, 3);
    reset_records();
    rome2_l85_fx_name_dump_stats_to_log(&f.names);
    assert(s_log_count == 0u && f.manager->tab_level == 2u);

    /* the level is tested before every entry: lowered after the fourth message, the remaining six are skipped */
    rome2_l80_log_manager_set_max_level(f.manager, 4);
    s_level_after_log = 3;
    s_level_after_count = 4u;
    rome2_l85_fx_name_dump_stats_to_log(&f.names);
    assert(s_log_count == 4u && f.manager->tab_level == 2u);
    expect_log(3u, 4, 3u, expected[2]);
    s_level_after_log = -1;

    /* bounded: no log manager, no context */
    f.fx.log_manager_singleton_va = 0u;
    rome2_l85_fx_name_dump_stats_to_log(&f.names);
    rome2_l85_fx_name_dump_stats_to_log(NULL);
    assert(s_log_count == 4u);
}

static void test_resource_manager(void) {
    l85_fixture f;
    uint32_t self_va = L85_STRINGS_VA;
    uint32_t state_va = L85_HEAP_START;
    uint32_t i;
    fixture_init(&f, 0);
    memset(at(self_va, 12u), 0xa5, 12u);
    memset(at(state_va, 0x18u), 0xa5, 0x18u);

    /* 0x10eda380: singleton, vtable, then a 0x14-byte record with 17 bytes cleared */
    assert(rome2_l85_resource_manager_ctor(&f.fx, self_va) == self_va);
    assert(f.fx.resource_manager_singleton_va == self_va);
    assert(get_u32(self_va) == 0x1183a798u && get_u32(self_va + 4u) == state_va);
    assert(get_u32(self_va + 8u) == L85_UNWRITTEN && f.fx.alloc_calls == 1u);
    for (i = 0u; i < 0x11u; ++i) {
        assert(get_u8(state_va + i) == 0u);
    }
    assert(get_u8(state_va + 0x11u) == 0xa5u && get_u8(state_va + 0x13u) == 0xa5u);
    assert(get_u32(state_va + 0x14u) == L85_UNWRITTEN);

    /* 0x10edd130: only the byte at +0x10 of that record */
    rome2_l85_resource_manager_set_automatic_garbage_collection(&f.fx, self_va, 1u);
    assert(get_u8(state_va + 0x10u) == 1u && get_u32(state_va + 0x0cu) == 0u && get_u8(state_va + 0x11u) == 0xa5u);
    rome2_l85_resource_manager_set_automatic_garbage_collection(&f.fx, self_va, 0u);
    assert(get_u8(state_va + 0x10u) == 0u);

    /* a failed FxAllocate still leaves a registered, vtabled manager with a NULL record */
    f.fx.custom_alloc = failing_alloc;
    f.fx.resource_manager_singleton_va = 0u;
    memset(at(self_va, 12u), 0xa5, 12u);
    assert(rome2_l85_resource_manager_ctor(&f.fx, self_va) == self_va);
    assert(f.fx.resource_manager_singleton_va == self_va);
    assert(get_u32(self_va) == 0x1183a798u && get_u32(self_va + 4u) == 0u);

    /* bounded: the singleton is stored before the first write to the object */
    assert(rome2_l85_resource_manager_ctor(&f.fx, L85_UNMAPPED_VA) == L85_UNMAPPED_VA);
    assert(f.fx.resource_manager_singleton_va == L85_UNMAPPED_VA);
    rome2_l85_resource_manager_set_automatic_garbage_collection(&f.fx, L85_UNMAPPED_VA, 1u);
    rome2_l85_resource_manager_set_automatic_garbage_collection(NULL, self_va, 1u);
    assert(rome2_l85_resource_manager_ctor(NULL, self_va) == self_va);
}

static void put_event(uint32_t slot, float min, float max, float offset, float scale, float time_88) {
    uint32_t va = L85_EVENTS_VA + slot * 0xacu;
    memset(at(va, 0xacu), 0xa5, 0xacu);
    put_u32(va + 0x0cu, 0u);
    put_f32(va + 0x10u, min);
    put_f32(va + 0x14u, max);
    put_f32(va + 0x18u, offset);
    put_f32(va + 0x24u, scale);
    put_f32(va + 0x84u, 100.0f);
    put_f32(va + 0x88u, time_88);
}

static void test_event_time_range_and_frame_work(void) {
    l85_fixture f;
    uint32_t e0 = L85_EVENTS_VA;
    uint32_t e1 = L85_EVENTS_VA + 0xacu;
    uint32_t e2 = L85_EVENTS_VA + 0x158u;
    fixture_init(&f, 0);

    /* 0x10f09320: bounds = range * scale + offset; the offset is kept at +0x18 and nothing else moves */
    put_event(0u, 1.0f, 3.0f, 9.0f, 2.0f, 0.0f);
    rome2_l85_event_set_time_range(&f.fx, e0, 0.5f);
    assert(get_f32(e0 + 0x18u) == 0.5f && get_f32(e0 + 0x50u) == 2.5f && get_f32(e0 + 0x54u) == 6.5f);
    assert(get_f32(e0 + 0x10u) == 1.0f && get_f32(e0 + 0x14u) == 3.0f && get_f32(e0 + 0x24u) == 2.0f);
    assert(get_u32(e0 + 0x4cu) == L85_UNWRITTEN && get_u32(e0 + 0x58u) == L85_UNWRITTEN);
    /* a negative scale reverses the bounds, and they are stored ascending */
    put_event(0u, 1.0f, 3.0f, 9.0f, -2.0f, 0.0f);
    rome2_l85_event_set_time_range(&f.fx, e0, 10.0f);
    assert(get_f32(e0 + 0x50u) == 4.0f && get_f32(e0 + 0x54u) == 8.0f);
    /* JBE at 0x10f0935f: with a negative scale but bounds already ascending or equal, no swap */
    put_event(0u, 3.0f, 1.0f, 9.0f, -2.0f, 0.0f);
    rome2_l85_event_set_time_range(&f.fx, e0, 10.0f);
    assert(get_f32(e0 + 0x50u) == 4.0f && get_f32(e0 + 0x54u) == 8.0f);
    put_event(0u, 2.0f, 2.0f, 9.0f, -1.0f, 0.0f);
    rome2_l85_event_set_time_range(&f.fx, e0, 0.0f);
    assert(get_f32(e0 + 0x50u) == -2.0f && get_f32(e0 + 0x54u) == -2.0f);
    /* JBE at 0x10f0935a: a positive, zero or NaN scale never swaps, whatever the order */
    put_event(0u, 3.0f, 1.0f, 9.0f, 2.0f, 0.0f);
    rome2_l85_event_set_time_range(&f.fx, e0, 0.0f);
    assert(get_f32(e0 + 0x50u) == 6.0f && get_f32(e0 + 0x54u) == 2.0f);
    put_event(0u, 3.0f, 1.0f, 9.0f, 0.0f, 0.0f);
    rome2_l85_event_set_time_range(&f.fx, e0, 4.0f);
    assert(get_f32(e0 + 0x50u) == 4.0f && get_f32(e0 + 0x54u) == 4.0f);
    put_event(0u, 3.0f, 1.0f, 9.0f, f32_of(0x7fc00000u), 0.0f);
    rome2_l85_event_set_time_range(&f.fx, e0, 4.0f);
    assert(isnan(get_f32(e0 + 0x50u)) && isnan(get_f32(e0 + 0x54u)) && get_f32(e0 + 0x18u) == 4.0f);
    rome2_l85_event_set_time_range(&f.fx, L85_UNMAPPED_VA, 1.0f);
    rome2_l85_event_set_time_range(NULL, e0, 1.0f);

    /* 0x10ed8710: three slots; the bound is the count at +0x24, not the one at +0x18 */
    put_u32(L85_MANAGER_VA + 0x10u, L85_EVENTS_VA);
    put_u32(L85_MANAGER_VA + 0x18u, 0u);
    put_u32(L85_MANAGER_VA + 0x1cu, L85_FLAGS_VA);
    put_u32(L85_MANAGER_VA + 0x24u, 3u);
    put_f32(L85_LINKED_VA + 0x24u, 0.25f);

    /* slot 0 is not flagged: untouched although it holds the sentinel and would report work */
    put_event(0u, 1.0f, 3.0f, -50.0f, 2.0f, ROME2_FX_INVALID_TIME);
    /* slot 1 is flagged and unstarted, with a linked object */
    put_event(1u, 1.0f, 3.0f, 0.5f, 2.0f, ROME2_FX_INVALID_TIME);
    put_u32(e1 + 0x0cu, L85_LINKED_VA);
    /* slot 2 is flagged and already started: only its time_84 is compared */
    put_event(2u, 1.0f, 3.0f, 7.0f, 2.0f, 5.0f);
    put_u8(L85_FLAGS_VA, 0u);
    put_u8(L85_FLAGS_VA + 1u, 1u);
    put_u8(L85_FLAGS_VA + 2u, 0x80u);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 2.0f) == 0u);
    assert(get_f32(e0 + 0x88u) == ROME2_FX_INVALID_TIME && get_f32(e0 + 0x84u) == 100.0f);
    assert(get_u32(e0 + 0x90u) == L85_UNWRITTEN && get_f32(e0 + 0x18u) == -50.0f);
    /* started: +0x90 latches the offset, +0x84 = offset + time, +0x88 = that less the linked +0x24 */
    assert(get_f32(e1 + 0x90u) == 0.5f && get_f32(e1 + 0x84u) == 2.5f && get_f32(e1 + 0x88u) == 2.25f);
    /* ... and the range is rebuilt with offset 0, which replaces +0x18 */
    assert(get_f32(e1 + 0x18u) == 0.0f && get_f32(e1 + 0x50u) == 2.0f && get_f32(e1 + 0x54u) == 6.0f);
    assert(get_u32(e1 + 0x8cu) == L85_UNWRITTEN && get_u32(e1 + 0x94u) == L85_UNWRITTEN);
    assert(get_f32(e2 + 0x88u) == 5.0f && get_f32(e2 + 0x84u) == 100.0f && get_f32(e2 + 0x18u) == 7.0f);
    assert(get_u32(e2 + 0x90u) == L85_UNWRITTEN && get_u32(e2 + 0x50u) == L85_UNWRITTEN);

    /* CMOVNC: work is reported from time >= time_84 on, and stays reported for the later slots */
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 2.4f) == 0u);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 2.5f) == 1u);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 100.0f) == 1u);
    assert(get_f32(e1 + 0x84u) == 2.5f && get_f32(e1 + 0x18u) == 0.0f);
    /* an unordered compare never reports work */
    put_f32(e1 + 0x84u, f32_of(0x7fc00000u));
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 50.0f) == 0u);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, f32_of(0x7fc00000u)) == 0u);

    /* without a linked object +0x88 is a copy of +0x84; a non-positive offset is due at once */
    put_event(1u, 1.0f, 3.0f, -1.0f, 2.0f, ROME2_FX_INVALID_TIME);
    put_u8(L85_FLAGS_VA + 2u, 0u);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 4.0f) == 1u);
    assert(get_f32(e1 + 0x84u) == 3.0f && get_f32(e1 + 0x88u) == 3.0f && get_f32(e1 + 0x90u) == -1.0f);

    /* the count at +0x24 bounds the scan */
    put_event(1u, 1.0f, 3.0f, -1.0f, 2.0f, ROME2_FX_INVALID_TIME);
    put_u32(L85_MANAGER_VA + 0x24u, 1u);
    put_u32(L85_MANAGER_VA + 0x18u, 3u);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 4.0f) == 0u);
    assert(get_f32(e1 + 0x88u) == ROME2_FX_INVALID_TIME);

    /* bounded: unmapped flags, events, linked object or manager */
    put_u32(L85_MANAGER_VA + 0x24u, 3u);
    put_u32(e1 + 0x0cu, L85_UNMAPPED_VA);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 4.0f) == 0u);
    put_u32(L85_MANAGER_VA + 0x10u, L85_UNMAPPED_VA);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 4.0f) == 0u);
    put_u32(L85_MANAGER_VA + 0x1cu, L85_UNMAPPED_VA);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_MANAGER_VA, 4.0f) == 0u);
    assert(rome2_l85_event_manager_has_work_this_frame(&f.fx, L85_UNMAPPED_VA, 4.0f) == 0u);
    assert(rome2_l85_event_manager_has_work_this_frame(NULL, L85_MANAGER_VA, 4.0f) == 0u);
}

static void test_custom_event_callback_and_shutdown(void) {
    l85_fixture f;
    fixture_init(&f, 0);
    put_u32(L85_FUNCTOR_SOURCE_VA, L85_IMPL_SOURCE);
    put_u32(L85_FUNCTOR_NEW_VA, L85_UNWRITTEN);

    /* 0x10ed9af0, nothing installed: a failed operator new(4) stores NULL and never reads the argument */
    f.events.custom_event_callback_va = L85_UNWRITTEN;
    f.events.custom_event_callback_va = 0u;
    rome2_l85_event_manager_set_custom_event_callback(&f.events, L85_UNMAPPED_VA);
    assert(f.events.custom_event_callback_va == 0u && s_call_count == 1u);
    expect_call(0u, CALL_NEW, 4u, 0u, 0u, 0u);

    /* the new functor receives the clone made through the source implementation's slot +4 */
    s_new_result = L85_FUNCTOR_NEW_VA;
    s_clone_result = L85_IMPL_CLONE;
    reset_records();
    rome2_l85_event_manager_set_custom_event_callback(&f.events, L85_FUNCTOR_SOURCE_VA);
    assert(f.events.custom_event_callback_va == L85_FUNCTOR_NEW_VA && get_u32(L85_FUNCTOR_NEW_VA) == L85_IMPL_CLONE);
    assert(s_call_count == 2u && f.events.audio_callback_va == 0u);
    expect_call(0u, CALL_NEW, 4u, 0u, 0u, 0u);
    expect_call(1u, CALL_FUNCTOR_CLONE, L85_IMPL_SOURCE, 0u, 0u, 0u);

    /* installed: the clone is swapped in and the previous implementation destroyed with flag 1; no allocation */
    s_clone_result = L85_IMPL_CUSTOM;
    reset_records();
    rome2_l85_event_manager_set_custom_event_callback(&f.events, L85_FUNCTOR_SOURCE_VA);
    assert(f.events.custom_event_callback_va == L85_FUNCTOR_NEW_VA && get_u32(L85_FUNCTOR_NEW_VA) == L85_IMPL_CUSTOM);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_FUNCTOR_CLONE, L85_IMPL_SOURCE, 0u, 0u, 0u);
    expect_call(1u, CALL_FUNCTOR_DESTROY, L85_IMPL_CLONE, 1u, 0u, 0u);

    /* an empty source functor installs NULL without a clone call; a NULL previous implementation is not destroyed */
    put_u32(L85_FUNCTOR_SOURCE_VA, 0u);
    reset_records();
    rome2_l85_event_manager_set_custom_event_callback(&f.events, L85_FUNCTOR_SOURCE_VA);
    assert(get_u32(L85_FUNCTOR_NEW_VA) == 0u && s_call_count == 1u);
    expect_call(0u, CALL_FUNCTOR_DESTROY, L85_IMPL_CUSTOM, 1u, 0u, 0u);
    reset_records();
    rome2_l85_event_manager_set_custom_event_callback(&f.events, L85_FUNCTOR_SOURCE_VA);
    assert(get_u32(L85_FUNCTOR_NEW_VA) == 0u && s_call_count == 0u);
    /* nothing installed and an empty source: the new functor holds NULL */
    f.events.custom_event_callback_va = 0u;
    put_u32(L85_FUNCTOR_NEW_VA, L85_UNWRITTEN);
    rome2_l85_event_manager_set_custom_event_callback(&f.events, L85_FUNCTOR_SOURCE_VA);
    assert(f.events.custom_event_callback_va == L85_FUNCTOR_NEW_VA && get_u32(L85_FUNCTOR_NEW_VA) == 0u);
    assert(s_call_count == 1u);
    /* bounded: an unmapped source with a functor installed changes nothing */
    put_u32(L85_FUNCTOR_NEW_VA, L85_IMPL_CUSTOM);
    reset_records();
    rome2_l85_event_manager_set_custom_event_callback(&f.events, L85_UNMAPPED_VA);
    assert(get_u32(L85_FUNCTOR_NEW_VA) == L85_IMPL_CUSTOM && s_call_count == 0u);
    rome2_l85_event_manager_set_custom_event_callback(NULL, L85_FUNCTOR_SOURCE_VA);

    /* 0x10ed9b60: the audio functor first, then the custom-event one; each destroyed, released as 4 bytes, cleared */
    put_u32(L85_FUNCTOR_A_VA, L85_IMPL_AUDIO);
    put_u32(L85_FUNCTOR_B_VA, L85_IMPL_CUSTOM);
    f.events.audio_callback_va = L85_FUNCTOR_A_VA;
    f.events.custom_event_callback_va = L85_FUNCTOR_B_VA;
    rome2_l85_event_manager_shutdown(&f.events);
    assert(f.events.audio_callback_va == 0u && f.events.custom_event_callback_va == 0u && s_call_count == 4u);
    expect_call(0u, CALL_FUNCTOR_DESTROY, L85_IMPL_AUDIO, 1u, 0u, 0u);
    expect_call(1u, CALL_DELETE, L85_FUNCTOR_A_VA, 4u, 0u, 0u);
    expect_call(2u, CALL_FUNCTOR_DESTROY, L85_IMPL_CUSTOM, 1u, 0u, 0u);
    expect_call(3u, CALL_DELETE, L85_FUNCTOR_B_VA, 4u, 0u, 0u);
    assert(get_u32(L85_FUNCTOR_A_VA) == L85_IMPL_AUDIO && get_u32(L85_FUNCTOR_B_VA) == L85_IMPL_CUSTOM);

    /* nothing installed: nothing happens; an empty functor is released without a destructor call */
    reset_records();
    rome2_l85_event_manager_shutdown(&f.events);
    assert(s_call_count == 0u);
    put_u32(L85_FUNCTOR_B_VA, 0u);
    f.events.custom_event_callback_va = L85_FUNCTOR_B_VA;
    rome2_l85_event_manager_shutdown(&f.events);
    assert(f.events.custom_event_callback_va == 0u && s_call_count == 1u);
    expect_call(0u, CALL_DELETE, L85_FUNCTOR_B_VA, 4u, 0u, 0u);
    /* bounded: an unmapped audio functor stops the body before the custom-event half */
    f.events.audio_callback_va = L85_UNMAPPED_VA;
    f.events.custom_event_callback_va = L85_FUNCTOR_B_VA;
    reset_records();
    rome2_l85_event_manager_shutdown(&f.events);
    assert(f.events.custom_event_callback_va == L85_FUNCTOR_B_VA && s_call_count == 0u);
    rome2_l85_event_manager_shutdown(NULL);
}

static void test_anim_records_and_frame_rate(void) {
    l85_fixture f;
    char expected[160];
    uint32_t null_entry;
    uint32_t alpha;
    uint32_t bravo;
    uint32_t absent;
    uint32_t arg_va = L85_STRINGS_VA;
    uint32_t i;
    fixture_init(&f, 0);
    null_entry = fake_name(0u, "");
    alpha = fake_name(1u, "Alpha");
    bravo = fake_name(2u, "Centurion_Rally");
    absent = fake_name(3u, "Absent");
    f.names.null_name.entry_va = null_entry;

    /* 0x10ee3810: records of 0x28 bytes at [+0x0c], name at record +4, count at +0x14 */
    put_u32(L85_ANIM_VA + 0x0cu, L85_CURVES_VA);
    put_u32(L85_ANIM_VA + 0x14u, 3u);
    put_u32(L85_CURVES_VA + 0x04u, alpha);
    put_u32(L85_CURVES_VA + 0x2cu, 0u);
    put_u32(L85_CURVES_VA + 0x54u, bravo);
    put_u32(L85_CURVES_VA + 0x7cu, absent); /* a fourth record, past the count */
    put_u32(arg_va, bravo);
    assert(rome2_l85_anim_find_anim_curve(&f.sdk, L85_ANIM_VA, arg_va) == 2u);
    /* the unnamed record in front was bound to FxName::NullName on the way */
    assert(get_u32(L85_CURVES_VA + 0x2cu) == null_entry);
    put_u32(arg_va, null_entry);
    assert(rome2_l85_anim_find_anim_curve(&f.sdk, L85_ANIM_VA, arg_va) == 1u);
    put_u32(arg_va, absent);
    assert(rome2_l85_anim_find_anim_curve(&f.sdk, L85_ANIM_VA, arg_va) == 0xffffffffu);
    /* the argument's own NULL entry is compared as it is, and is not bound */
    put_u32(arg_va, 0u);
    assert(rome2_l85_anim_find_anim_curve(&f.sdk, L85_ANIM_VA, arg_va) == 0xffffffffu && get_u32(arg_va) == 0u);
    put_u32(L85_ANIM_VA + 0x14u, 0u);
    put_u32(arg_va, alpha);
    assert(rome2_l85_anim_find_anim_curve(&f.sdk, L85_ANIM_VA, arg_va) == 0xffffffffu);

    /* 0x10ee39d0: records of 0x18 bytes at [+0x18], count at +0x20 */
    put_u32(L85_ANIM_VA + 0x18u, L85_COMPRESSED_VA);
    put_u32(L85_ANIM_VA + 0x20u, 3u);
    put_u32(L85_COMPRESSED_VA + 0x04u, bravo);
    put_u32(L85_COMPRESSED_VA + 0x1cu, 0u);
    put_u32(L85_COMPRESSED_VA + 0x34u, alpha);
    assert(rome2_l85_anim_find_compressed_anim_curve(&f.sdk, L85_ANIM_VA, arg_va) == 2u);
    assert(get_u32(L85_COMPRESSED_VA + 0x1cu) == null_entry);
    put_u32(arg_va, absent);
    assert(rome2_l85_anim_find_compressed_anim_curve(&f.sdk, L85_ANIM_VA, arg_va) == 0xffffffffu);

    /* 0x10ed65a0 -> 0x10efd5c0: bone records of 0x40 bytes at FxActor [+0x14], name at record +8, count at +0x1c */
    put_u32(L85_ACTOR_VA + 0x14u, L85_BONES_VA);
    put_u32(L85_ACTOR_VA + 0x1cu, 3u);
    put_u32(L85_BONES_VA + 0x08u, 0u);
    put_u32(L85_BONES_VA + 0x48u, alpha);
    put_u32(L85_BONES_VA + 0x88u, bravo);
    put_u32(L85_BONES_VA + 0x04u, bravo); /* +4 is not the name */
    put_u32(arg_va, bravo);
    assert(rome2_l85_actor_find_bone(&f.sdk, L85_ACTOR_VA, arg_va) == 2u);
    assert(rome2_l85_bone_table_find_bone(&f.sdk, L85_ACTOR_VA + 0x0cu, arg_va) == 2u);
    assert(get_u32(L85_BONES_VA + 0x08u) == null_entry);
    put_u32(arg_va, absent);
    assert(rome2_l85_actor_find_bone(&f.sdk, L85_ACTOR_VA, arg_va) == 0xffffffffu);
    /* bounded: an unmapped record array or argument */
    put_u32(L85_ACTOR_VA + 0x14u, L85_UNMAPPED_VA);
    assert(rome2_l85_actor_find_bone(&f.sdk, L85_ACTOR_VA, arg_va) == 0xffffffffu);
    assert(rome2_l85_anim_find_compressed_anim_curve(&f.sdk, L85_ANIM_VA, L85_UNMAPPED_VA) == 0xffffffffu);
    assert(rome2_l85_anim_find_anim_curve(NULL, L85_ANIM_VA, arg_va) == 0xffffffffu);

    /* 0x10ee47d0 */
    put_u32(L85_ANIM_VA + 0xe8u, L85_UNWRITTEN);
    put_u32(L85_ANIM_VA + 0xf0u, L85_UNWRITTEN);
    rome2_l85_anim_set_audio_asset_index(&f.fx, L85_ANIM_VA, 0x12345678u);
    assert(get_u32(L85_ANIM_VA + 0xecu) == 0x12345678u);
    assert(get_u32(L85_ANIM_VA + 0xe8u) == L85_UNWRITTEN && get_u32(L85_ANIM_VA + 0xf0u) == L85_UNWRITTEN);
    rome2_l85_anim_set_audio_asset_index(&f.fx, L85_UNMAPPED_VA, 1u);
    rome2_l85_anim_set_audio_asset_index(NULL, L85_ANIM_VA, 1u);

    /* 0x10ee37e0: the object at +0xb0 goes through its slot +8 with flag 1; NULL answers 0 without a call */
    put_u32(L85_ANIM_VA + 0xb0u, L85_OBJECT_A);
    assert(rome2_l85_anim_destroy_editor_only_data(&f.sdk, L85_ANIM_VA) == 1u);
    assert(get_u32(L85_ANIM_VA + 0xb0u) == 0u && s_call_count == 1u);
    expect_call(0u, CALL_DESTROY, L85_OBJECT_A, 1u, 0u, 0u);
    assert(rome2_l85_anim_destroy_editor_only_data(&f.sdk, L85_ANIM_VA) == 0u && s_call_count == 1u);
    assert(rome2_l85_anim_destroy_editor_only_data(NULL, L85_ANIM_VA) == 0u);

    /* 0x10ee4840: 24.0f and 120.0f are both accepted */
    put_u32(L85_ANIM_VA + 0x04u, bravo);
    put_f32(L85_ANIM_VA + 0xf4u, 30.0f);
    assert(rome2_l85_anim_set_frame_rate(&f.sdk, L85_ANIM_VA, 24.0f) == 1u && get_f32(L85_ANIM_VA + 0xf4u) == 24.0f);
    assert(rome2_l85_anim_set_frame_rate(&f.sdk, L85_ANIM_VA, 120.0f) == 1u && get_f32(L85_ANIM_VA + 0xf4u) == 120.0f);
    assert(rome2_l85_anim_set_frame_rate(&f.sdk, L85_ANIM_VA, 60.0f) == 1u && s_log_count == 0u);
    /* the first singles outside the range, and a NaN, are refused with a level-2 entry naming the animation */
    {
        static const uint32_t refused[4] = {0x41bfffffu, 0x42f00001u, 0x7fc00000u, 0x80000000u};
        for (i = 0u; i < 4u; ++i) {
            float rate = f32_of(refused[i]);
            assert(rome2_l85_anim_set_frame_rate(&f.sdk, L85_ANIM_VA, rate) == 0u);
            assert(get_f32(L85_ANIM_VA + 0xf4u) == 60.0f && s_log_count == i + 1u);
            if (i < 2u) {
                (void)snprintf(
                    expected, sizeof(expected),
                    "An attempt to set an invalid frame rate of %f on animation \"Centurion_Rally\" was ignored",
                    (double)rate);
                expect_log(i, 2, 0u, expected);
            }
        }
        expect_log(0u, 2, 0u,
                   "An attempt to set an invalid frame rate of 23.999998 on animation \"Centurion_Rally\" was ignored");
    }
    /* JL at 0x10ee4886: below level 2 the refusal is silent */
    rome2_l80_log_manager_set_max_level(f.manager, 1);
    assert(rome2_l85_anim_set_frame_rate(&f.sdk, L85_ANIM_VA, 0.0f) == 0u && s_log_count == 4u);
    assert(rome2_l85_anim_set_frame_rate(NULL, L85_ANIM_VA, 30.0f) == 0u);
}

/* A tree node: {+4 key, +8 value, +0x10 parent, +0x14 left, +0x18 right}; the other two dwords stay marked. */
static uint32_t put_node(uint32_t index, uint32_t key, uint32_t value, uint32_t parent, uint32_t left, uint32_t right) {
    uint32_t va = L85_NODES_VA + index * 0x20u;
    put_u32(va, L85_UNWRITTEN);
    put_u32(va + 0x04u, key);
    put_u32(va + 0x08u, value);
    put_u32(va + 0x0cu, L85_UNWRITTEN);
    put_u32(va + 0x10u, parent);
    put_u32(va + 0x14u, left);
    put_u32(va + 0x18u, right);
    return va;
}

#define NODE(index) (L85_NODES_VA + (index) * 0x20u)

/*
 * Bravo at the root, Alpha on its left, Delta on its right, Charlie as
 * Delta's left child: in key order Alpha, Bravo, Charlie, Delta.
 */
static void put_tree(uint32_t tree_va, const uint32_t keys[4], const uint32_t values[4]) {
    put_u32(tree_va + 4u, put_node(1u, keys[1], values[1], 0u, NODE(0u), NODE(3u)));
    (void)put_node(0u, keys[0], values[0], NODE(1u), 0u, 0u);
    (void)put_node(3u, keys[3], values[3], NODE(1u), NODE(2u), 0u);
    (void)put_node(2u, keys[2], values[2], NODE(3u), 0u, 0u);
}

static void test_anim_group_iterators_and_clear(void) {
    static const uint32_t no_keys[4] = {0u, 0u, 0u, 0u};
    static const uint32_t anims[4] = {L85_OBJECT_A, L85_OBJECT_B, 0u, L85_OBJECT_C};
    l85_fixture f;
    rome2_fx_tree_iterator_32 it;
    uint32_t anim_tree = L85_GROUP_VA + 0x08u;
    uint32_t group_tree = L85_GROUP_VA + 0x14u;
    uint32_t sub_node;
    uint32_t sub_anim_node;
    fixture_init(&f, 0);

    /* empty trees: Begin and ReverseBegin are {tree, 0}, the same as End */
    it.tree_va = L85_UNWRITTEN;
    it.node_va = L85_UNWRITTEN;
    assert(rome2_l85_anim_group_begin_animations(&f.fx, L85_GROUP_VA, &it) == &it);
    assert(it.tree_va == anim_tree && it.node_va == 0u);
    assert(rome2_l85_anim_group_reverse_begin_sub_groups(&f.fx, L85_GROUP_VA, &it) == &it);
    assert(it.tree_va == group_tree && it.node_va == 0u);

    /* 0x10ee5450 / 0x10ee58c0: the leftmost and the rightmost node of the tree at +8 */
    put_tree(anim_tree, no_keys, anims);
    assert(rome2_l85_anim_group_begin_animations(&f.fx, L85_GROUP_VA, &it) == &it);
    assert(it.tree_va == anim_tree && it.node_va == NODE(0u));
    assert(rome2_l85_anim_group_reverse_begin_animations(&f.fx, L85_GROUP_VA, &it) == &it);
    assert(it.tree_va == anim_tree && it.node_va == NODE(3u));
    /* 0x10ee55e0 / 0x10ee5600: End and ReverseEnd are {tree, 0} without reading the group */
    assert(rome2_l85_anim_group_end_animations(L85_GROUP_VA, &it) == &it);
    assert(it.tree_va == anim_tree && it.node_va == 0u);
    assert(rome2_l85_anim_group_end_sub_groups(L85_UNMAPPED_VA, &it) == &it);
    assert(it.tree_va == L85_UNMAPPED_VA + 0x14u && it.node_va == 0u);
    /* 0x10ee5490 / 0x10ee5900: the same over the tree at +0x14 */
    put_u32(anim_tree + 4u, 0u);
    put_u32(group_tree + 4u, NODE(1u));
    assert(rome2_l85_anim_group_begin_sub_groups(&f.fx, L85_GROUP_VA, &it) == &it);
    assert(it.tree_va == group_tree && it.node_va == NODE(0u));
    assert(rome2_l85_anim_group_reverse_begin_sub_groups(&f.fx, L85_GROUP_VA, &it) == &it);
    assert(it.tree_va == group_tree && it.node_va == NODE(3u));
    assert(rome2_l85_anim_group_begin_animations(&f.fx, L85_GROUP_VA, &it) == &it && it.node_va == 0u);
    /* bounded: an unmapped group or node leaves the iterator alone; a left chain that loops is cut off */
    it.node_va = L85_UNWRITTEN;
    (void)rome2_l85_anim_group_begin_sub_groups(&f.fx, L85_UNMAPPED_VA, &it);
    put_u32(NODE(0u) + 0x14u, L85_UNMAPPED_VA);
    (void)rome2_l85_anim_group_begin_sub_groups(&f.fx, L85_GROUP_VA, &it);
    put_u32(NODE(0u) + 0x14u, NODE(1u));
    (void)rome2_l85_anim_group_begin_sub_groups(&f.fx, L85_GROUP_VA, &it);
    assert(it.node_va == L85_UNWRITTEN);
    assert(rome2_l85_anim_group_begin_animations(&f.fx, L85_GROUP_VA, NULL) == NULL);
    assert(rome2_l85_anim_group_end_animations(L85_GROUP_VA, NULL) == NULL);
    assert(rome2_l85_anim_group_end_sub_groups(L85_GROUP_VA, NULL) == NULL);

    /*
     * 0x10ee54d0: four animation nodes (one already empty), and one sub-group
     * node whose group holds one animation of its own.
     */
    put_tree(anim_tree, no_keys, anims);
    sub_node = put_node(4u, 0u, L85_SUB_GROUP_VA, 0u, 0u, 0u);
    put_u32(group_tree + 4u, sub_node);
    sub_anim_node = put_node(5u, 0u, 0x60000400u, 0u, 0u, 0u);
    put_u32(L85_SUB_GROUP_VA + 0x0cu, sub_anim_node);
    put_u32(L85_SUB_GROUP_VA + 0x18u, 0u);
    rome2_l85_anim_group_clear(&f.sdk, L85_GROUP_VA);
    assert(s_call_count == 9u);
    /* animations in key order, each through slot +8 with flag 1; the empty node is skipped */
    expect_call(0u, CALL_DESTROY, L85_OBJECT_A, 1u, 0u, 0u);
    expect_call(1u, CALL_DESTROY, L85_OBJECT_B, 1u, 0u, 0u);
    expect_call(2u, CALL_DESTROY, L85_OBJECT_C, 1u, 0u, 0u);
    expect_call(3u, CALL_TREE_CLEAR, anim_tree, 0u, 0u, 0u);
    /* the sub-group is cleared by the same body before it is destroyed */
    expect_call(4u, CALL_DESTROY, 0x60000400u, 1u, 0u, 0u);
    expect_call(5u, CALL_TREE_CLEAR, L85_SUB_GROUP_VA + 0x08u, 0u, 0u, 0u);
    expect_call(6u, CALL_TREE_CLEAR, L85_SUB_GROUP_VA + 0x14u, 0u, 0u, 0u);
    expect_call(7u, CALL_DESTROY, L85_SUB_GROUP_VA, 1u, 0u, 0u);
    /* the body's last act is the tail jump into slot +4 of the sub-group tree */
    expect_call(8u, CALL_TREE_CLEAR, group_tree, 0u, 0u, 0u);
    assert(get_u32(NODE(0u) + 8u) == 0u && get_u32(NODE(1u) + 8u) == 0u && get_u32(NODE(3u) + 8u) == 0u);
    assert(get_u32(sub_node + 8u) == 0u && get_u32(sub_anim_node + 8u) == 0u);
    /* only the value is written: keys, links and the two unknown dwords are as they were */
    assert(get_u32(NODE(1u)) == L85_UNWRITTEN && get_u32(NODE(1u) + 0x0cu) == L85_UNWRITTEN);
    assert(get_u32(NODE(1u) + 0x14u) == NODE(0u) && get_u32(NODE(1u) + 0x18u) == NODE(3u));
    assert(get_u32(anim_tree + 4u) == NODE(1u) && get_u32(group_tree + 4u) == sub_node);

    /* an empty group still empties both trees, in order; without hooks the values are simply zeroed */
    put_u32(anim_tree + 4u, 0u);
    put_u32(group_tree + 4u, 0u);
    reset_records();
    rome2_l85_anim_group_clear(&f.sdk, L85_GROUP_VA);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_TREE_CLEAR, anim_tree, 0u, 0u, 0u);
    expect_call(1u, CALL_TREE_CLEAR, group_tree, 0u, 0u, 0u);
    put_tree(anim_tree, no_keys, anims);
    f.sdk.object_destroy = NULL;
    f.sdk.tree_clear = NULL;
    rome2_l85_anim_group_clear(&f.sdk, L85_GROUP_VA);
    assert(get_u32(NODE(0u) + 8u) == 0u && get_u32(NODE(3u) + 8u) == 0u && s_call_count == 2u);

    /* bounded: a sub-group node without a group, a group that contains itself, an unmapped group */
    f.sdk.object_destroy = hook_destroy;
    f.sdk.tree_clear = hook_tree_clear;
    put_u32(anim_tree + 4u, 0u);
    put_u32(group_tree + 4u, put_node(4u, 0u, 0u, 0u, 0u, 0u));
    reset_records();
    rome2_l85_anim_group_clear(&f.sdk, L85_GROUP_VA);
    assert(s_call_count == 1u);
    /* each nested pass empties both trees; the value is re-read after the nested call, so one destroy in all */
    put_u32(sub_node + 8u, L85_GROUP_VA);
    reset_records();
    rome2_l85_anim_group_clear(&f.sdk, L85_GROUP_VA);
    assert(s_call_count == 2u * (uint32_t)ROME2_L85_CLEAR_DEPTH_LIMIT + 1u);
    assert(get_u32(sub_node + 8u) == 0u);
    reset_records();
    rome2_l85_anim_group_clear(&f.sdk, L85_UNMAPPED_VA);
    rome2_l85_anim_group_clear(NULL, L85_GROUP_VA);
    assert(s_call_count == 0u);
}

static void test_anim_group_find_remove_add(void) {
    static const uint32_t values[4] = {L85_OBJECT_A, L85_OBJECT_B, L85_OBJECT_C, 0x60000400u};
    l85_fixture f;
    uint32_t keys[4];
    uint32_t null_entry;
    uint32_t echo;
    uint32_t aardvark;
    uint32_t charlie_twin;
    uint32_t anim_tree = L85_GROUP_VA + 0x08u;
    uint32_t group_tree = L85_GROUP_VA + 0x14u;
    uint32_t arg_va = L85_STRINGS_VA;
    uint32_t i;
    fixture_init(&f, 0);
    null_entry = fake_name(0u, "");
    keys[0] = fake_name(1u, "Alpha");
    keys[1] = fake_name(2u, "Bravo");
    keys[2] = fake_name(3u, "Charlie");
    keys[3] = fake_name(4u, "Delta");
    echo = fake_name(5u, "Echo");
    aardvark = fake_name(6u, "Aardvark");
    charlie_twin = fake_name(7u, "Charlie"); /* same text, another entry */
    f.names.null_name.entry_va = null_entry;
    put_tree(anim_tree, keys, values);
    put_u32(group_tree + 4u, 0u);

    /* 0x10ee6050: every key is found by its entry, left and right of the root */
    for (i = 0u; i < 4u; ++i) {
        put_u32(arg_va, keys[i]);
        assert(rome2_l85_anim_group_find_anim(&f.sdk, L85_GROUP_VA, arg_va) == values[i]);
    }
    /* misses fall off the left and the right edge */
    put_u32(arg_va, aardvark);
    assert(rome2_l85_anim_group_find_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    put_u32(arg_va, echo);
    assert(rome2_l85_anim_group_find_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    /* equal text under another entry is not a match: the search goes right from Charlie and ends */
    put_u32(arg_va, charlie_twin);
    assert(rome2_l85_anim_group_find_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    /* ... and it finds a node placed there */
    put_u32(NODE(2u) + 0x18u, put_node(6u, charlie_twin, 0x60000500u, NODE(2u), 0u, 0u));
    assert(rome2_l85_anim_group_find_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0x60000500u);
    put_u32(NODE(2u) + 0x18u, 0u);
    /* a NULL entry in the argument is bound to FxName::NullName, whose empty text sorts before everything */
    put_u32(arg_va, 0u);
    assert(rome2_l85_anim_group_find_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0u && get_u32(arg_va) == null_entry);
    /* 0x10ee63f0 searches the other tree; an empty tree never reads the argument */
    put_u32(arg_va, keys[2]);
    assert(rome2_l85_anim_group_find_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    assert(rome2_l85_anim_group_find_sub_group(&f.sdk, L85_GROUP_VA, L85_UNMAPPED_VA) == 0u);
    put_u32(anim_tree + 4u, 0u);
    put_u32(group_tree + 4u, NODE(1u));
    assert(rome2_l85_anim_group_find_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == L85_OBJECT_C);
    assert(rome2_l85_anim_group_find_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    assert(s_call_count == 0u);

    /* 0x10ee5810: the value is returned and the tree's slot +0x10 receives the node */
    assert(rome2_l85_anim_group_remove_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == L85_OBJECT_C);
    assert(s_call_count == 1u);
    expect_call(0u, CALL_TREE_REMOVE, group_tree, NODE(2u), 0u, 0u);
    /* a miss still calls the slot, with a NULL node */
    put_u32(arg_va, echo);
    assert(rome2_l85_anim_group_remove_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    expect_call(1u, CALL_TREE_REMOVE, group_tree, 0u, 0u, 0u);
    /* 0x10ee5760 over an empty tree: the same NULL-node call, and the argument is not read */
    assert(rome2_l85_anim_group_remove_anim(&f.sdk, L85_GROUP_VA, L85_UNMAPPED_VA) == 0u);
    expect_call(2u, CALL_TREE_REMOVE, anim_tree, 0u, 0u, 0u);
    put_u32(group_tree + 4u, 0u);
    put_u32(anim_tree + 4u, NODE(1u));
    put_u32(arg_va, keys[3]);
    assert(rome2_l85_anim_group_remove_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0x60000400u);
    expect_call(3u, CALL_TREE_REMOVE, anim_tree, NODE(3u), 0u, 0u);

    /* 0x10ee5700: remove, then the removed animation's slot +8 with flag 1 */
    reset_records();
    put_u32(arg_va, keys[0]);
    assert(rome2_l85_anim_group_remove_and_destroy_anim(&f.sdk, L85_GROUP_VA, arg_va) == 1u);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_TREE_REMOVE, anim_tree, NODE(0u), 0u, 0u);
    expect_call(1u, CALL_DESTROY, L85_OBJECT_A, 1u, 0u, 0u);
    put_u32(arg_va, echo);
    assert(rome2_l85_anim_group_remove_and_destroy_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    assert(s_call_count == 3u);
    /* a node holding a NULL value is unlinked but reported as not removed */
    put_u32(NODE(1u) + 8u, 0u);
    put_u32(arg_va, keys[1]);
    assert(rome2_l85_anim_group_remove_and_destroy_anim(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    expect_call(3u, CALL_TREE_REMOVE, anim_tree, NODE(1u), 0u, 0u);
    assert(s_call_count == 4u);
    /* 0x10ee5730: the same over the sub-group tree */
    put_u32(anim_tree + 4u, 0u);
    put_u32(group_tree + 4u, NODE(1u));
    put_u32(arg_va, keys[2]);
    reset_records();
    assert(rome2_l85_anim_group_remove_and_destroy_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == 1u);
    expect_call(0u, CALL_TREE_REMOVE, group_tree, NODE(2u), 0u, 0u);
    expect_call(1u, CALL_DESTROY, L85_OBJECT_C, 1u, 0u, 0u);
    put_u32(arg_va, echo);
    assert(rome2_l85_anim_group_remove_and_destroy_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    assert(s_call_count == 3u);

    /* bounded: an unmapped node or argument, a key with no entry behind it, and a right chain that loops */
    put_u32(NODE(3u) + 0x14u, L85_UNMAPPED_VA);
    put_u32(arg_va, keys[2]);
    reset_records();
    assert(rome2_l85_anim_group_remove_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    assert(rome2_l85_anim_group_find_sub_group(&f.sdk, L85_GROUP_VA, L85_UNMAPPED_VA) == 0u);
    put_u32(NODE(3u) + 0x14u, NODE(2u));
    put_u32(NODE(1u) + 4u, L85_UNMAPPED_VA);
    assert(rome2_l85_anim_group_find_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    put_u32(NODE(1u) + 4u, keys[1]);
    put_u32(NODE(3u) + 0x18u, NODE(1u));
    put_u32(arg_va, echo);
    assert(rome2_l85_anim_group_find_sub_group(&f.sdk, L85_GROUP_VA, arg_va) == 0u);
    assert(rome2_l85_anim_group_find_anim(NULL, L85_GROUP_VA, arg_va) == 0u);
    assert(rome2_l85_anim_group_remove_anim(NULL, L85_GROUP_VA, arg_va) == 0u);
    assert(s_call_count == 0u);

    /* 0x10ee5c60: slot +0xc gets the tree, its root slot, the animation's name at +4 and the animation */
    s_insert_result.tree_va = anim_tree;
    s_insert_result.node_va = NODE(0u);
    assert(rome2_l85_anim_group_add_anim(&f.sdk, L85_GROUP_VA, L85_ANIM_VA) == 1u);
    expect_call(0u, CALL_TREE_INSERT, anim_tree, L85_GROUP_VA + 0x0cu, L85_ANIM_VA + 4u, L85_ANIM_VA);
    /* 0x10ee5cb0: the tree at +0x14 and its root slot at +0x18 */
    assert(rome2_l85_anim_group_add_sub_group(&f.sdk, L85_GROUP_VA, L85_SUB_GROUP_VA) == 1u);
    expect_call(1u, CALL_TREE_INSERT, group_tree, L85_GROUP_VA + 0x18u, L85_SUB_GROUP_VA + 4u, L85_SUB_GROUP_VA);
    /* both dwords of the returned iterator must be non-zero */
    s_insert_result.node_va = 0u;
    assert(rome2_l85_anim_group_add_anim(&f.sdk, L85_GROUP_VA, L85_ANIM_VA) == 0u);
    s_insert_result.tree_va = 0u;
    s_insert_result.node_va = NODE(0u);
    assert(rome2_l85_anim_group_add_sub_group(&f.sdk, L85_GROUP_VA, L85_SUB_GROUP_VA) == 0u);
    assert(s_call_count == 4u);
    /* a NULL object answers 0 without a call; so does an unset hook */
    s_insert_result.tree_va = anim_tree;
    assert(rome2_l85_anim_group_add_anim(&f.sdk, L85_GROUP_VA, 0u) == 0u);
    assert(rome2_l85_anim_group_add_sub_group(&f.sdk, L85_GROUP_VA, 0u) == 0u);
    assert(s_call_count == 4u);
    f.sdk.tree_insert = NULL;
    assert(rome2_l85_anim_group_add_anim(&f.sdk, L85_GROUP_VA, L85_ANIM_VA) == 0u);
    assert(rome2_l85_anim_group_add_anim(NULL, L85_GROUP_VA, L85_ANIM_VA) == 0u);
}

static void expect_node(uint32_t va, uint32_t item, uint32_t next, uint32_t prev) {
    assert(get_u32(va) == item && get_u32(va + 4u) == next && get_u32(va + 8u) == prev);
}

static void test_reference_list(void) {
    l85_fixture f;
    uint32_t list_va = L85_SET_VA + 0x30u;
    uint32_t head_va = L85_HEAP_START;
    uint32_t first_va = L85_HEAP_START + 0x10u; /* the host arena rounds each 0xc-byte node up to 8 */
    uint32_t second_va = L85_HEAP_START + 0x20u;
    uint32_t found;
    uint32_t wanted;
    fixture_init(&f, 0);
    memset(at(L85_HEAP_START, 0x30u), 0xa5, 0x30u);

    /* 0x10ee75b0 on a list without a sentinel: one is allocated and linked to itself, its item left alone */
    wanted = L85_OBJECT_A;
    found = L85_UNWRITTEN;
    assert(rome2_l85_fx_list_find(&f.fx, list_va, &found, &wanted) == &found);
    assert(found == head_va && get_u32(list_va) == head_va && get_u32(list_va + 4u) == 0u);
    expect_node(head_va, L85_UNWRITTEN, head_va, head_va);
    assert(f.fx.alloc_calls == 1u);

    /* 0x10ee7460: appended ahead of the sentinel, count up */
    rome2_l85_anim_set_add_reference(&f.sdk, L85_SET_VA, L85_OBJECT_A);
    expect_node(first_va, L85_OBJECT_A, head_va, head_va);
    expect_node(head_va, L85_UNWRITTEN, first_va, first_va);
    assert(get_u32(list_va + 4u) == 1u && f.fx.alloc_calls == 2u);
    rome2_l85_anim_set_add_reference(&f.sdk, L85_SET_VA, L85_OBJECT_B);
    expect_node(second_va, L85_OBJECT_B, head_va, first_va);
    expect_node(first_va, L85_OBJECT_A, second_va, head_va);
    expect_node(head_va, L85_UNWRITTEN, first_va, second_va);
    assert(get_u32(list_va + 4u) == 2u && s_log_count == 0u);

    /* Find stops on the node that holds the value, or on the sentinel */
    wanted = L85_OBJECT_B;
    assert(*rome2_l85_fx_list_find(&f.fx, list_va, &found, &wanted) == second_va);
    wanted = L85_OBJECT_C;
    assert(*rome2_l85_fx_list_find(&f.fx, list_va, &found, &wanted) == head_va);
    /* the sentinel's item is not compared */
    wanted = L85_UNWRITTEN;
    assert(*rome2_l85_fx_list_find(&f.fx, list_va, &found, &wanted) == head_va);

    /* a duplicate is reported at level 2 and not added */
    rome2_l85_anim_set_add_reference(&f.sdk, L85_SET_VA, L85_OBJECT_A);
    assert(get_u32(list_va + 4u) == 2u && f.fx.alloc_calls == 3u && s_log_count == 1u);
    expect_log(0u, 2, 0u, "FxAnimSet::AddReference: duplicate reference detected");
    rome2_l80_log_manager_set_max_level(f.manager, 1);
    rome2_l85_anim_set_add_reference(&f.sdk, L85_SET_VA, L85_OBJECT_B);
    assert(get_u32(list_va + 4u) == 2u && s_log_count == 1u);
    rome2_l80_log_manager_set_max_level(f.manager, 6);

    /* 0x10ee7670: a reference that is not there is reported at level 2 and nothing is removed */
    rome2_l85_anim_set_remove_reference(&f.sdk, L85_SET_VA, L85_OBJECT_C);
    assert(get_u32(list_va + 4u) == 2u && s_log_count == 2u && s_call_count == 0u);
    expect_log(1u, 2, 0u, "FxAnimSet::RemoveReference: invalid reference detected");
    /* a present one is unlinked, its 0xc bytes released and the count lowered */
    rome2_l85_anim_set_remove_reference(&f.sdk, L85_SET_VA, L85_OBJECT_A);
    expect_node(head_va, L85_UNWRITTEN, second_va, second_va);
    expect_node(second_va, L85_OBJECT_B, head_va, head_va);
    assert(get_u32(list_va + 4u) == 1u && s_call_count == 1u && s_log_count == 2u);
    expect_call(0u, CALL_FREE, first_va, 0x0cu, 0u, 0u);
    rome2_l85_anim_set_remove_reference(&f.sdk, L85_SET_VA, L85_OBJECT_B);
    expect_node(head_va, L85_UNWRITTEN, head_va, head_va);
    assert(get_u32(list_va + 4u) == 0u && get_u32(list_va) == head_va);
    expect_call(1u, CALL_FREE, second_va, 0x0cu, 0u, 0u);
    /* removing from a list that never had a sentinel creates one and reports the miss */
    put_u32(list_va, 0u);
    rome2_l85_anim_set_remove_reference(&f.sdk, L85_SET_VA, L85_OBJECT_B);
    assert(get_u32(list_va) != 0u && get_u32(list_va) != head_va && s_log_count == 3u);

    /* 0x10ee7850: one byte at +8, also FxActor::SetShouldClientRelink */
    put_u32(L85_SET_VA + 8u, L85_UNWRITTEN);
    rome2_l85_anim_set_set_is_published(&f.fx, L85_SET_VA, 1u);
    assert(get_u32(L85_SET_VA + 8u) == 0xa5a5a501u);
    rome2_l85_anim_set_set_is_published(&f.fx, L85_SET_VA, 0u);
    assert(get_u32(L85_SET_VA + 8u) == 0xa5a5a500u);

    /* bounded: a failed allocation, an unmapped list, a node chain that leaves the arena */
    put_u32(list_va, 0u);
    put_u32(list_va + 4u, 0u);
    f.fx.custom_alloc = failing_alloc;
    found = L85_UNWRITTEN;
    assert(rome2_l85_fx_list_find(&f.fx, list_va, &found, &wanted) == &found && found == L85_UNWRITTEN);
    rome2_l85_anim_set_add_reference(&f.sdk, L85_SET_VA, L85_OBJECT_A);
    rome2_l85_anim_set_remove_reference(&f.sdk, L85_SET_VA, L85_OBJECT_A);
    assert(get_u32(list_va) == 0u && get_u32(list_va + 4u) == 0u);
    put_u32(list_va, head_va);
    put_u32(head_va + 4u, L85_UNMAPPED_VA);
    assert(rome2_l85_fx_list_find(&f.fx, list_va, &found, &wanted) == &found && found == L85_UNWRITTEN);
    rome2_l85_anim_set_add_reference(&f.sdk, L85_SET_VA, L85_OBJECT_A);
    assert(get_u32(list_va + 4u) == 0u);
    rome2_l85_anim_set_add_reference(&f.sdk, L85_UNMAPPED_VA, L85_OBJECT_A);
    rome2_l85_anim_set_remove_reference(NULL, L85_SET_VA, L85_OBJECT_A);
    rome2_l85_anim_set_add_reference(NULL, L85_SET_VA, L85_OBJECT_A);
    assert(rome2_l85_fx_list_find(NULL, list_va, &found, &wanted) == &found);
    rome2_l85_anim_set_set_is_published(NULL, L85_SET_VA, 1u);
}

static void test_actor_instances(void) {
    l85_fixture f;
    rome2_fx_name_32 legate;
    rome2_fx_name_32 tribune;
    const rome2_fx_name_entry_32 *legate_entry;
    const rome2_fx_name_entry_32 *tribune_entry;
    uint32_t list_va = L85_ACTOR_VA + 0x60e8u;
    uint32_t head_va;
    uint32_t first_va;
    uint32_t second_va;
    uint32_t found;
    int32_t legate_refs;
    int32_t tribune_refs;
    fixture_init(&f, 1);
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &legate, "Legate");
    (void)rome2_l81_fx_name_ctor_cstr(&f.names, &tribune, "Tribune");
    put_u32(L85_ACTOR_VA + 4u, legate.entry_va);
    reset_records();

    /* 0x10ee9060 / 0x10ee9050 */
    assert(rome2_l85_actor_get_instances(L85_ACTOR_VA) == list_va);
    assert(rome2_l85_actor_get_instance_count(&f.fx, L85_ACTOR_VA) == 0u);

    /* 0x10ee8a70: the first instance creates the sentinel; the level-4 entry prints the pointer as %08X */
    rome2_l85_actor_add_instance(&f.sdk, L85_ACTOR_VA, L85_INSTANCE_A);
    head_va = get_u32(list_va);
    first_va = get_u32(head_va + 4u);
    assert(head_va != 0u && first_va == head_va + 0x10u);
    expect_node(first_va, L85_INSTANCE_A, head_va, head_va);
    assert(get_u32(head_va + 8u) == first_va && rome2_l85_actor_get_instance_count(&f.fx, L85_ACTOR_VA) == 1u);
    assert(s_log_count == 1u);
    expect_log(0u, 4, 0u, "Added instance 70000000 to the actor named \"Legate\" [1 instances].");
    rome2_l85_actor_add_instance(&f.sdk, L85_ACTOR_VA, L85_INSTANCE_B);
    second_va = get_u32(first_va + 4u);
    expect_node(second_va, L85_INSTANCE_B, head_va, first_va);
    assert(get_u32(head_va + 8u) == second_va && get_u32(list_va + 4u) == 2u);
    expect_log(1u, 4, 0u, "Added instance 7000ABCD to the actor named \"Legate\" [2 instances].");
    /* the mounted-set list in front of it is a different list */
    assert(get_u32(L85_ACTOR_VA + 0x60e0u) == 0u && get_u32(L85_ACTOR_VA + 0x60e4u) == 0u);

    /* a duplicate is reported at level 3 and not added */
    rome2_l85_actor_add_instance(&f.sdk, L85_ACTOR_VA, L85_INSTANCE_A);
    assert(get_u32(list_va + 4u) == 2u && s_log_count == 3u);
    expect_log(2u, 3, 0u, "Attempt to add duplicate actor instance!");

    /* 0x10eea950: a hit stores the node through the iterator; a miss leaves it alone */
    found = L85_UNWRITTEN;
    assert(rome2_l85_actor_find_instance(&f.fx, L85_ACTOR_VA, L85_INSTANCE_B, &found) == 1u && found == second_va);
    found = L85_UNWRITTEN;
    assert(rome2_l85_actor_find_instance(&f.fx, L85_ACTOR_VA, 0x70000004u, &found) == 0u && found == L85_UNWRITTEN);
    assert(rome2_l85_actor_find_instance(&f.fx, L85_ACTOR_VA, L85_INSTANCE_A, NULL) == 1u);

    /* JL at 0x10ee8b3d and 0x10ee9c4c: at level 3 the list changes without the level-4 entry */
    rome2_l80_log_manager_set_max_level(f.manager, 3);
    rome2_l85_actor_add_instance(&f.sdk, L85_ACTOR_VA, 0x70000004u);
    assert(get_u32(list_va + 4u) == 3u && s_log_count == 3u);
    rome2_l85_actor_remove_instance(&f.sdk, L85_ACTOR_VA, 0x70000004u);
    assert(get_u32(list_va + 4u) == 2u && s_log_count == 3u && s_call_count == 1u);
    /* JL at 0x10ee8bde and 0x10ee9bd0: at level 2 the complaints are silent too */
    rome2_l80_log_manager_set_max_level(f.manager, 2);
    rome2_l85_actor_add_instance(&f.sdk, L85_ACTOR_VA, L85_INSTANCE_A);
    rome2_l85_actor_remove_instance(&f.sdk, L85_ACTOR_VA, 0x70000004u);
    assert(get_u32(list_va + 4u) == 2u && s_log_count == 3u);
    rome2_l80_log_manager_set_max_level(f.manager, 6);

    /* 0x10ee9b60: unlinked, released as 0xc bytes, counted down, then reported at level 4 */
    reset_records();
    rome2_l85_actor_remove_instance(&f.sdk, L85_ACTOR_VA, L85_INSTANCE_A);
    expect_node(second_va, L85_INSTANCE_B, head_va, head_va);
    assert(get_u32(head_va + 4u) == second_va && get_u32(head_va + 8u) == second_va);
    assert(get_u32(list_va + 4u) == 1u && s_call_count == 1u && s_log_count == 1u);
    expect_call(0u, CALL_FREE, first_va, 0x0cu, 0u, 0u);
    expect_log(0u, 4, 0u, "Removed instance 70000000 from the actor named \"Legate\" [1 instances].");
    /* an instance that is not there is reported at level 3 */
    rome2_l85_actor_remove_instance(&f.sdk, L85_ACTOR_VA, L85_INSTANCE_A);
    assert(get_u32(list_va + 4u) == 1u && s_log_count == 2u && s_call_count == 1u);
    expect_log(1u, 3, 0u, "Attempt to remove non-existing actor instance!");
    rome2_l85_actor_remove_instance(&f.sdk, L85_ACTOR_VA, L85_INSTANCE_B);
    expect_log(2u, 4, 0u, "Removed instance 7000ABCD from the actor named \"Legate\" [0 instances].");
    assert(get_u32(head_va + 4u) == head_va && get_u32(head_va + 8u) == head_va);
    /* an empty list answers a find with 0; a list without a sentinel gets one from each body */
    assert(rome2_l85_actor_find_instance(&f.fx, L85_ACTOR_VA, L85_INSTANCE_B, &found) == 0u);
    put_u32(list_va, 0u);
    assert(rome2_l85_actor_find_instance(&f.fx, L85_ACTOR_VA, L85_INSTANCE_B, &found) == 0u);
    assert(get_u32(list_va) != 0u && get_u32(list_va) != head_va);
    put_u32(list_va, 0u);
    rome2_l85_actor_remove_instance(&f.sdk, L85_ACTOR_VA, L85_INSTANCE_B);
    assert(get_u32(list_va) != 0u && s_log_count == 4u);
    expect_log(3u, 3, 0u, "Attempt to remove non-existing actor instance!");

    /* 0x10eea2e0 / 0x10eea2f0: one byte each at +9 and +0xa */
    put_u32(L85_ACTOR_VA + 8u, L85_UNWRITTEN);
    rome2_l85_actor_set_is_open_in_studio(&f.fx, L85_ACTOR_VA, 1u);
    assert(get_u32(L85_ACTOR_VA + 8u) == 0xa5a501a5u);
    rome2_l85_actor_set_is_published(&f.fx, L85_ACTOR_VA, 2u);
    assert(get_u32(L85_ACTOR_VA + 8u) == 0xa50201a5u);
    /* 0x10ee7850 is FxActor::SetShouldClientRelink as well: the byte at +8 */
    rome2_l85_anim_set_set_is_published(&f.fx, L85_ACTOR_VA, 3u);
    assert(get_u32(L85_ACTOR_VA + 8u) == 0xa5020103u);

    /* 0x10ee7860: FxName::operator= on the name at FxAnimSet +0xc */
    legate_entry = (const rome2_fx_name_entry_32 *)at(legate.entry_va, (uint32_t)sizeof(*legate_entry));
    tribune_entry = (const rome2_fx_name_entry_32 *)at(tribune.entry_va, (uint32_t)sizeof(*tribune_entry));
    put_u32(L85_SET_VA + 0x0cu, legate.entry_va);
    put_u32(L85_STRINGS_VA, tribune.entry_va);
    legate_refs = legate_entry->ref_count;
    tribune_refs = tribune_entry->ref_count;
    assert(rome2_l85_anim_set_set_owning_actor_name(&f.sdk, L85_SET_VA, L85_STRINGS_VA) == L85_SET_VA + 0x0cu);
    assert(get_u32(L85_SET_VA + 0x0cu) == tribune.entry_va);
    assert(legate_entry->ref_count == legate_refs - 1 && tribune_entry->ref_count == tribune_refs + 1);
    assert(rome2_l85_anim_set_set_owning_actor_name(&f.sdk, L85_SET_VA, L85_UNMAPPED_VA) == L85_SET_VA + 0x0cu);
    assert(get_u32(L85_SET_VA + 0x0cu) == tribune.entry_va);
    assert(rome2_l85_anim_set_set_owning_actor_name(NULL, L85_SET_VA, L85_STRINGS_VA) == L85_SET_VA + 0x0cu);

    /* bounded */
    rome2_l85_actor_add_instance(&f.sdk, L85_UNMAPPED_VA, L85_INSTANCE_A);
    rome2_l85_actor_remove_instance(&f.sdk, L85_UNMAPPED_VA, L85_INSTANCE_A);
    rome2_l85_actor_add_instance(NULL, L85_ACTOR_VA, L85_INSTANCE_A);
    rome2_l85_actor_remove_instance(NULL, L85_ACTOR_VA, L85_INSTANCE_A);
    assert(rome2_l85_actor_find_instance(NULL, L85_ACTOR_VA, L85_INSTANCE_A, &found) == 0u);
    assert(rome2_l85_actor_find_instance(&f.fx, L85_UNMAPPED_VA, L85_INSTANCE_A, &found) == 0u);
    assert(rome2_l85_actor_get_instance_count(NULL, L85_ACTOR_VA) == 0u);
    rome2_l85_actor_set_is_open_in_studio(NULL, L85_ACTOR_VA, 1u);
    rome2_l85_actor_set_is_published(NULL, L85_ACTOR_VA, 1u);
}

/* A bone record: weight node at +0, reference transform at +0xc, link array at +0x34, link count at +0x3c. */
static void put_bone(uint32_t index, uint32_t weight_node, float rot_w, float rot_x, uint32_t links_va, uint32_t links) {
    static const float reference[10] = {1.0f, 2.0f, 3.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f};
    uint32_t va = L85_BONES_VA + index * 0x40u;
    uint32_t i;
    put_u32(va, weight_node);
    for (i = 0u; i < 10u; ++i) {
        put_f32(va + 0x0cu + i * 4u, reference[i]);
    }
    put_f32(va + 0x18u, rot_w);
    put_f32(va + 0x1cu, rot_x);
    put_u32(va + 0x34u, links_va);
    put_u32(va + 0x38u, L85_UNWRITTEN);
    put_u32(va + 0x3cu, links);
}

/* A link: node index, position delta, rotation delta (w, x, y, z) and scale delta. */
static uint32_t put_link(uint32_t index, uint32_t node, const float deltas[10]) {
    uint32_t va = L85_LINKS_VA + index * 0x2cu;
    uint32_t i;
    put_u32(va, node);
    for (i = 0u; i < 10u; ++i) {
        put_f32(va + 4u + i * 4u, deltas[i]);
    }
    return va;
}

static void expect_transform(uint32_t index, const float expected[10]) {
    uint32_t i;
    for (i = 0u; i < 10u; ++i) {
        assert(get_f32(L85_OUTPUT_VA + index * 0x2cu + i * 4u) == expected[i]);
    }
}

static void test_bone_frames(void) {
    static const float blend[10] = {0.5f, 0.25f, -1.0f, 0.0f, 0.5f, 0.0f, 0.0f, 1.0f, 0.0f, -0.25f};
    static const float still[10] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    static const float turn[10] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    static const float untouched[10] = {9.0f, 9.0f, 9.0f, 9.0f, 9.0f, 9.0f, 9.0f, 9.0f, 9.0f, 9.0f};
    static const float blended[10] = {2.0f, 2.5f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 3.0f, 1.0f, 0.5f};
    static const float unit_x[10] = {1.0f, 2.0f, 3.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f};
    static const float unit_w[10] = {1.0f, 2.0f, 3.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f};
    static const float turned[10] = {1.0f, 2.0f, 3.0f, 1.0f, 0.0f, 3.0f, 0.0f, 1.0f, 1.0f, 1.0f};
    l85_fixture f;
    uint32_t i;
    uint32_t out2 = L85_OUTPUT_VA + 2u * 0x2cu;
    fixture_init(&f, 0);
    put_u32(L85_ACTOR_VA + 0x14u, L85_BONES_VA);
    put_u32(L85_ACTOR_VA + 0x1cu, 7u);
    put_u32(L85_ACTOR_VA + 0x20u, L85_REFERENCE_VA);
    put_u32(L85_INSTANCE_VA + 0x38u, L85_VALUES_VA);
    put_u32(L85_INSTANCE_VA + 0xa0u, L85_BITSET_VA);
    put_u32(L85_INSTANCE_VA + 0xacu, L85_OUTPUT_VA);
    for (i = 0u; i < 8u * 11u; ++i) {
        put_f32(L85_OUTPUT_VA + i * 4u, 9.0f);
        put_f32(L85_REFERENCE_VA + i * 4u, (float)i);
    }
    /* node values; nodes 4, 6, 37 and 40 changed this frame (word 0 bits 4 and 6, word 1 bits 5 and 8) */
    put_f32(L85_VALUES_VA + 1u * 4u, 0.75f);
    put_u32(L85_VALUES_VA + 2u * 4u, 0x7fa00001u); /* a signalling NaN, to show the weight is a dword copy */
    put_f32(L85_VALUES_VA + 3u * 4u, -0.0f);
    put_f32(L85_VALUES_VA + 4u * 4u, 2.0f);
    put_f32(L85_VALUES_VA + 5u * 4u, 8.0f);
    put_f32(L85_VALUES_VA + 6u * 4u, 5.0f);
    put_f32(L85_VALUES_VA + 37u * 4u, 3.0f);
    put_f32(L85_VALUES_VA + 40u * 4u, f32_of(0x7fc00000u));
    put_u32(L85_BITSET_VA, 0x00000050u);
    put_u32(L85_BITSET_VA + 4u, 0x00000120u);

    /* bone 0: no links; only the weight is written, as a dword copy of node 2 */
    put_bone(0u, 2u, 1.0f, 0.0f, 0u, 0u);
    /* bone 1: one link to an unchanged node and no weight node: nothing is written */
    put_bone(1u, 0xffffffffu, 1.0f, 0.0f, put_link(0u, 5u, blend), 1u);
    /* bone 2: links to node 3 (unchanged, value -0.0) and node 4 (changed, value 2.0) */
    (void)put_link(1u, 3u, blend);
    put_bone(2u, 1u, 1.0f, 0.0f, L85_LINKS_VA + 0x2cu, 2u);
    (void)put_link(2u, 4u, blend);
    /* bone 3: a changed node with zero deltas over a unit rotation: restarted from the reference, not rescaled */
    put_bone(3u, 0xffffffffu, 0.0f, 1.0f, put_link(3u, 6u, still), 1u);
    /* bone 4: the same over rotation (2, 0, 0, 0): squared length 4, rescaled by 1 / 2 */
    put_bone(4u, 0xffffffffu, 2.0f, 0.0f, put_link(4u, 6u, still), 1u);
    /* bone 5: node 37 lives in the second bitset word; a y turn of 3 on (1, 0, 0, 0) gives (1, 0, 3, 0) */
    put_bone(5u, 0xffffffffu, 1.0f, 0.0f, put_link(5u, 37u, turn), 1u);
    /* bone 6: a NaN node value is blended in like any other */
    put_bone(6u, 0xffffffffu, 1.0f, 0.0f, put_link(6u, 40u, blend), 1u);
    /* an eighth record, past the count */
    put_bone(7u, 1u, 1.0f, 0.0f, put_link(7u, 4u, blend), 1u);

    /* 0x10ed7970 -> 0x10efd630 */
    rome2_l85_actor_process_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
    expect_transform(0u, untouched);
    assert(get_u32(L85_OUTPUT_VA + 0x28u) == 0x7fa00001u);
    expect_transform(1u, untouched);
    assert(get_f32(L85_OUTPUT_VA + 0x2cu + 0x28u) == 9.0f);
    /* position and scale: reference + delta * 2; rotation (1, 0, 0, 0) * (1, 1, 0, 0) = (1, 1, 0, 0), length^2 2 */
    for (i = 0u; i < 3u; ++i) {
        assert(get_f32(out2 + i * 4u) == blended[i] && get_f32(out2 + 0x1cu + i * 4u) == blended[7u + i]);
    }
    assert(get_u32(out2 + 0x0cu) == 0x3f3504f3u && get_u32(out2 + 0x10u) == 0x3f3504f3u);
    assert(get_f32(out2 + 0x14u) == 0.0f && get_f32(out2 + 0x18u) == 0.0f);
    assert(get_f32(out2 + 0x28u) == 0.75f);
    expect_transform(3u, unit_x);
    expect_transform(4u, unit_w);
    assert(get_f32(L85_OUTPUT_VA + 3u * 0x2cu + 0x28u) == 9.0f && get_f32(L85_OUTPUT_VA + 4u * 0x2cu + 0x28u) == 9.0f);
    /* (1, 0, 3, 0) has squared length 10 and is rescaled by 1 / sqrt(10) */
    {
        float inverse = 1.0f / sqrtf(10.0f);
        uint32_t out5 = L85_OUTPUT_VA + 5u * 0x2cu;
        assert(get_f32(out5) == turned[0] && get_f32(out5 + 0x24u) == turned[9]);
        assert(get_f32(out5 + 0x0cu) == inverse * 1.0f && get_f32(out5 + 0x14u) == inverse * 3.0f);
        assert(get_f32(out5 + 0x10u) == 0.0f && get_f32(out5 + 0x18u) == 0.0f);
    }
    for (i = 0u; i < 10u; ++i) {
        assert(isnan(get_f32(L85_OUTPUT_VA + 6u * 0x2cu + i * 4u)));
    }
    expect_transform(7u, untouched);
    assert(get_f32(L85_OUTPUT_VA + 7u * 0x2cu + 0x28u) == 9.0f);

    /*
     * The thresholds: a squared length of 0.99999988 (0x3f7ffffe) or less, or of 1.00000012 (0x3f800001)
     * or more, is rescaled. (1 - 2^-12)^2 is exact in single precision and a small second component
     * puts the sum on each neighbouring single. At 1.00000012 the factor 1 / sqrt(n) is exactly 1.
     */
    {
        static const uint32_t squared[5] = {0x3f7ffffeu, 0x3f7fffffu, 0x3f800000u, 0x3f800001u, 0x3f800002u};
        static const int rescaled[5] = {1, 0, 0, 1, 1};
        static const int factor_is_one[5] = {0, 0, 1, 1, 0};
        put_u32(L85_ACTOR_VA + 0x1cu, 1u);
        for (i = 0u; i < 5u; ++i) {
            volatile float a = f32_of(0x3f7ff000u);
            volatile float a2 = a * a;
            volatile float b = sqrtf(f32_of(squared[i]) - a2);
            volatile float b2 = b * b;
            volatile float n = a2 + b2;
            volatile float inverse = 1.0f / sqrtf(n);
            volatile float scaled_a = inverse * a;
            volatile float scaled_b = inverse * b;
            assert(n == f32_of(squared[i]) && (inverse == 1.0f) == factor_is_one[i]);
            put_bone(0u, 0xffffffffu, a, b, put_link(0u, 6u, still), 1u);
            rome2_l85_actor_process_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
            if (rescaled[i]) {
                assert(get_f32(L85_OUTPUT_VA + 0x0cu) == scaled_a && get_f32(L85_OUTPUT_VA + 0x10u) == scaled_b);
                assert(factor_is_one[i] || scaled_a != a);
            } else {
                assert(get_f32(L85_OUTPUT_VA + 0x0cu) == a && get_f32(L85_OUTPUT_VA + 0x10u) == b);
            }
            assert(get_f32(L85_OUTPUT_VA + 0x14u) == 0.0f && get_f32(L85_OUTPUT_VA + 0x18u) == 0.0f);
        }
        /* a zero rotation has squared length 0: 1 / sqrt(0) is infinite and 0 * infinity is not a number */
        put_bone(0u, 0xffffffffu, 0.0f, 0.0f, put_link(0u, 6u, still), 1u);
        rome2_l85_actor_process_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
        assert(isnan(get_f32(L85_OUTPUT_VA + 0x0cu)) && isnan(get_f32(L85_OUTPUT_VA + 0x18u)));
        assert(get_f32(L85_OUTPUT_VA) == 1.0f && get_f32(L85_OUTPUT_VA + 0x1cu) == 1.0f);
    }

    /* 0x10ed78a0 -> 0x10efd610: count * 0x2c bytes of the reference array, and no more */
    put_u32(L85_ACTOR_VA + 0x1cu, 2u);
    for (i = 0u; i < 8u * 11u; ++i) {
        put_f32(L85_OUTPUT_VA + i * 4u, 9.0f);
    }
    rome2_l85_actor_initialize_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
    for (i = 0u; i < 22u; ++i) {
        assert(get_f32(L85_OUTPUT_VA + i * 4u) == (float)i);
    }
    assert(get_f32(L85_OUTPUT_VA + 22u * 4u) == 9.0f);

    /* a bone count of 0 touches nothing, through the actor or on the table directly */
    put_u32(L85_ACTOR_VA + 0x1cu, 0u);
    put_f32(L85_OUTPUT_VA, 9.0f);
    rome2_l85_actor_initialize_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
    rome2_l85_bone_table_process_frame(&f.fx, L85_ACTOR_VA + 0x0cu, L85_UNMAPPED_VA);
    assert(get_f32(L85_OUTPUT_VA) == 9.0f);
    /* bounded: an unmapped output, bitset, link array, record array or operand writes nothing */
    put_u32(L85_ACTOR_VA + 0x1cu, 1u);
    put_bone(0u, 1u, 1.0f, 0.0f, put_link(0u, 4u, blend), 1u);
    for (i = 0u; i < 11u; ++i) {
        put_f32(L85_OUTPUT_VA + i * 4u, 9.0f);
    }
    put_u32(L85_INSTANCE_VA + 0xacu, L85_UNMAPPED_VA);
    rome2_l85_bone_table_process_frame(&f.fx, L85_ACTOR_VA + 0x0cu, L85_INSTANCE_VA);
    rome2_l85_bone_table_initialize_frame(&f.fx, L85_ACTOR_VA + 0x0cu, L85_INSTANCE_VA);
    put_u32(L85_INSTANCE_VA + 0xacu, L85_OUTPUT_VA);
    put_u32(L85_INSTANCE_VA + 0xa0u, L85_UNMAPPED_VA);
    rome2_l85_actor_process_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
    put_u32(L85_BONES_VA + 0x34u, L85_UNMAPPED_VA);
    rome2_l85_actor_process_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
    put_u32(L85_ACTOR_VA + 0x14u, L85_UNMAPPED_VA);
    rome2_l85_actor_process_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
    rome2_l85_actor_process_frame(&f.fx, L85_ACTOR_VA, L85_UNMAPPED_VA);
    rome2_l85_actor_initialize_frame(&f.fx, L85_ACTOR_VA, L85_UNMAPPED_VA);
    rome2_l85_actor_process_frame(&f.fx, L85_UNMAPPED_VA, L85_INSTANCE_VA);
    rome2_l85_actor_initialize_frame(&f.fx, L85_UNMAPPED_VA, L85_INSTANCE_VA);
    rome2_l85_actor_process_frame(NULL, L85_ACTOR_VA, L85_INSTANCE_VA);
    rome2_l85_actor_initialize_frame(NULL, L85_ACTOR_VA, L85_INSTANCE_VA);
    expect_transform(0u, untouched);
    assert(get_f32(L85_OUTPUT_VA + 0x28u) == 9.0f);
    /* unreadable node values stop the body after the reference transform is in place and before the weight */
    put_u32(L85_ACTOR_VA + 0x14u, L85_BONES_VA);
    put_u32(L85_BONES_VA + 0x34u, L85_LINKS_VA);
    put_u32(L85_INSTANCE_VA + 0xa0u, L85_BITSET_VA);
    put_u32(L85_INSTANCE_VA + 0x38u, L85_UNMAPPED_VA);
    rome2_l85_actor_process_frame(&f.fx, L85_ACTOR_VA, L85_INSTANCE_VA);
    expect_transform(0u, unit_w);
    assert(get_f32(L85_OUTPUT_VA + 0x28u) == 9.0f);
}

static void put_handle(uint32_t count, uint32_t pool_offset, uint32_t block_va) {
    put_u32(L85_HANDLE_VA, count);
    put_u32(L85_HANDLE_VA + 4u, pool_offset);
    put_u32(L85_HANDLE_VA + 8u, block_va);
    put_u32(L85_HANDLE_VA + 0x0cu, L85_UNWRITTEN);
}

static void expect_released_handle(void) {
    assert(get_u32(L85_HANDLE_VA) == 0xffffffffu && get_u32(L85_HANDLE_VA + 4u) == 0xffffffffu);
    assert(get_u32(L85_HANDLE_VA + 8u) == 0u && get_u32(L85_HANDLE_VA + 0x0cu) == L85_UNWRITTEN);
}

static void test_instance_frame_and_flags(void) {
    l85_fixture f;
    uint32_t i;
    fixture_init(&f, 0);

    /* 0x10eeaed0: the +0x7c dwords at [+0x78] are zero-filled and +0x74 cleared */
    for (i = 0u; i < 4u; ++i) {
        put_u32(L85_WORDS_VA + i * 4u, L85_UNWRITTEN);
    }
    put_u32(L85_INSTANCE_VA + 0x70u, L85_UNWRITTEN);
    put_u32(L85_INSTANCE_VA + 0x74u, 7u);
    put_u32(L85_INSTANCE_VA + 0x78u, L85_WORDS_VA);
    put_u32(L85_INSTANCE_VA + 0x7cu, 3u);
    rome2_l85_actor_instance_end_frame(&f.fx, L85_INSTANCE_VA);
    assert(get_u32(L85_WORDS_VA) == 0u && get_u32(L85_WORDS_VA + 8u) == 0u);
    assert(get_u32(L85_WORDS_VA + 0x0cu) == L85_UNWRITTEN);
    assert(get_u32(L85_INSTANCE_VA + 0x74u) == 0u && get_u32(L85_INSTANCE_VA + 0x70u) == L85_UNWRITTEN);
    assert(get_u32(L85_INSTANCE_VA + 0x78u) == L85_WORDS_VA && get_u32(L85_INSTANCE_VA + 0x7cu) == 3u);
    /* a count of 0 writes nothing through the pointer, which may be anything */
    put_u32(L85_INSTANCE_VA + 0x74u, 7u);
    put_u32(L85_INSTANCE_VA + 0x78u, L85_UNMAPPED_VA);
    put_u32(L85_INSTANCE_VA + 0x7cu, 0u);
    rome2_l85_actor_instance_end_frame(&f.fx, L85_INSTANCE_VA);
    assert(get_u32(L85_INSTANCE_VA + 0x74u) == 0u);
    /* bounded: an unmapped array stops the body before +0x74 */
    put_u32(L85_INSTANCE_VA + 0x74u, 7u);
    put_u32(L85_INSTANCE_VA + 0x7cu, 1u);
    rome2_l85_actor_instance_end_frame(&f.fx, L85_INSTANCE_VA);
    assert(get_u32(L85_INSTANCE_VA + 0x74u) == 7u);
    rome2_l85_actor_instance_end_frame(&f.fx, L85_UNMAPPED_VA);
    rome2_l85_actor_instance_end_frame(NULL, L85_INSTANCE_VA);

    /* 0x10eebbd0: one byte at +0xd */
    put_u32(L85_INSTANCE_VA + 0x0cu, L85_UNWRITTEN);
    rome2_l85_actor_instance_set_is_open_in_studio(&f.fx, L85_INSTANCE_VA, 1u);
    assert(get_u32(L85_INSTANCE_VA + 0x0cu) == 0xa5a501a5u);
    rome2_l85_actor_instance_set_is_open_in_studio(NULL, L85_INSTANCE_VA, 0u);

    /* 0x10ee56f0 / 0x10ee5c50: the byte at 0x11974fa0 is 1 in the image */
    assert(rome2_l85_anim_group_get_log_error_on_animation_not_found(&f.sdk) == 1u);
    rome2_l85_anim_group_set_log_error_on_animation_not_found(&f.sdk, 0u);
    assert(rome2_l85_anim_group_get_log_error_on_animation_not_found(&f.sdk) == 0u);
    rome2_l85_anim_group_set_log_error_on_animation_not_found(&f.sdk, 0x7fu);
    assert(rome2_l85_anim_group_get_log_error_on_animation_not_found(&f.sdk) == 0x7fu);
    rome2_l85_anim_group_set_log_error_on_animation_not_found(NULL, 1u);
    assert(rome2_l85_anim_group_get_log_error_on_animation_not_found(NULL) == 0u);

    /* 0x10ed7980 -> 0x10ed7990: the cache is the object at FxActorInstance +0x100; its first dword is the pool */
    put_u32(L85_INSTANCE_VA + 0x100u, L85_POOL_VA);
    memset(at(L85_POOL_VA, 0x20u), 0xa5, 0x20u);
    /* a pooled handle has count bytes zeroed at pool + offset; nothing is freed */
    put_handle(5u, 8u, 0x60000700u);
    rome2_l85_actor_instance_release_curve_state_handle(&f.fx, L85_INSTANCE_VA, L85_HANDLE_VA);
    expect_released_handle();
    assert(get_u8(L85_POOL_VA + 7u) == 0xa5u && get_u8(L85_POOL_VA + 8u) == 0u);
    assert(get_u8(L85_POOL_VA + 12u) == 0u && get_u8(L85_POOL_VA + 13u) == 0xa5u && s_call_count == 0u);
    /* released already: the second call does nothing, not even to the third dword */
    put_u32(L85_HANDLE_VA + 8u, 0x60000700u);
    rome2_l85_curve_state_cache_release(&f.fx, L85_INSTANCE_VA + 0x100u, L85_HANDLE_VA);
    assert(get_u32(L85_HANDLE_VA + 8u) == 0x60000700u && get_u32(L85_HANDLE_VA) == 0xffffffffu);
    /* a handle with a block of its own frees count * 0x30 bytes and leaves the pool alone */
    put_handle(3u, 0xffffffffu, 0x60000700u);
    rome2_l85_curve_state_cache_release(&f.fx, L85_INSTANCE_VA + 0x100u, L85_HANDLE_VA);
    expect_released_handle();
    assert(s_call_count == 1u && get_u8(L85_POOL_VA + 13u) == 0xa5u);
    expect_call(0u, CALL_FREE, 0x60000700u, 0x90u, 0u, 0u);
    /* count 0: nothing to free or clear, and the handle is still reset */
    put_handle(0u, 0xffffffffu, 0x60000700u);
    rome2_l85_curve_state_cache_release(&f.fx, L85_INSTANCE_VA + 0x100u, L85_HANDLE_VA);
    expect_released_handle();
    put_handle(0u, 4u, 0x60000700u);
    rome2_l85_curve_state_cache_release(&f.fx, L85_INSTANCE_VA + 0x100u, L85_HANDLE_VA);
    expect_released_handle();
    assert(s_call_count == 1u && get_u32(L85_POOL_VA + 4u) == L85_UNWRITTEN);
    /* bounded: an unmapped pool or handle */
    put_u32(L85_INSTANCE_VA + 0x100u, L85_UNMAPPED_VA);
    put_handle(5u, 8u, 0u);
    rome2_l85_actor_instance_release_curve_state_handle(&f.fx, L85_INSTANCE_VA, L85_HANDLE_VA);
    assert(get_u32(L85_HANDLE_VA) == 5u);
    rome2_l85_actor_instance_release_curve_state_handle(&f.fx, L85_INSTANCE_VA, L85_UNMAPPED_VA);
    rome2_l85_curve_state_cache_release(NULL, L85_INSTANCE_VA + 0x100u, L85_HANDLE_VA);
    assert(s_call_count == 1u);
}

int main(void) {
    test_class_queries();
    test_named_object_and_class_descriptors();
    test_fx_string_assign();
    test_name_stats_dump();
    test_resource_manager();
    test_event_time_range_and_frame_work();
    test_custom_event_callback_and_shutdown();
    test_anim_records_and_frame_rate();
    test_anim_group_iterators_and_clear();
    test_anim_group_find_remove_add();
    test_reference_list();
    test_actor_instances();
    test_bone_frames();
    test_instance_frame_and_flags();
    puts("facefx_sdk_group_list_frame_ops: ok");
    return 0;
}
