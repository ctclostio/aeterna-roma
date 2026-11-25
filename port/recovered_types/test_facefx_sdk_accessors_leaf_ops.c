#include "facefx_sdk_accessors_leaf_ops.h"

#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

/* Guest objects are placed at fixed arena addresses; every offset below is the one the image uses. */
#define L84_ARENA_BASE 0x30000000u
#define L84_LOG_MANAGER_VA 0x30000200u
#define L84_LISTENER_VA 0x30000400u
#define L84_ANIM_VA 0x30000800u
#define L84_SET_A_VA 0x30000a00u
#define L84_SET_B_VA 0x30000a40u
#define L84_INSTANCE_VA 0x30000c00u
#define L84_MANAGER_VA 0x30000e00u
#define L84_EVENTS_VA 0x30001000u
#define L84_FLAGS_VA 0x30001400u
#define L84_AUDIO_FUNCTOR_VA 0x30001500u
#define L84_CUSTOM_FUNCTOR_VA 0x30001510u
#define L84_SOURCE_FUNCTOR_VA 0x30001520u
#define L84_NEW_FUNCTOR_VA 0x30001530u
#define L84_BONES_VA 0x30001800u
#define L84_GROUPS_VA 0x30001a00u
#define L84_VALUES_VA 0x30001c00u
#define L84_NODE_A_VA 0x30001d00u
#define L84_NODE_B_VA 0x30001d10u
#define L84_ACTOR_VA 0x30010000u
#define L84_HEAP_START 0x30020000u
#define L84_UNMAPPED_VA 0x50000000u

/* FxName entries and functor implementations are only compared or handed to hooks, never read. */
#define L84_ENTRY_NULL 0x40000010u
#define L84_ENTRY_ONE 0x40000020u
#define L84_ENTRY_THREE 0x40000030u
#define L84_ENTRY_SET_A 0x40000040u
#define L84_ENTRY_SET_B 0x40000050u
#define L84_ENTRY_DEFAULT 0x40000060u
#define L84_ENTRY_ABSENT 0x40000070u
#define L84_IMPL_AUDIO 0x60000100u
#define L84_IMPL_CUSTOM 0x60000200u
#define L84_IMPL_SOURCE 0x60000300u
#define L84_IMPL_CLONE_1 0x60000400u
#define L84_IMPL_CLONE_2 0x60000500u
#define L84_ACTOR_INSTANCE_ARG 0x70000000u
#define L84_UNWRITTEN 0xa5a5a5a5u

#define L84_LOG_CAPACITY 8u
#define L84_CALL_CAPACITY 32u

typedef enum l84_call_kind {
    CALL_NEW,
    CALL_DELETE,
    CALL_DESTROY,
    CALL_CLONE,
    CALL_AUDIO,
    CALL_CUSTOM,
    CALL_GET_ID
} l84_call_kind;

typedef struct l84_call {
    l84_call_kind kind;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    int32_t action;
} l84_call;

typedef struct l84_log_line {
    int32_t level;
    char text[96];
} l84_log_line;

typedef struct l84_fixture {
    rome2_l80_fx_ctx fx;
    rome2_l81_fx_name_ctx names;
    rome2_l84_fx_event_ctx events;
    rome2_fx_log_manager_32 *manager;
} l84_fixture;

static uint8_t s_arena[0x40000];
static l84_log_line s_log[L84_LOG_CAPACITY];
static uint32_t s_log_count;
static l84_call s_calls[L84_CALL_CAPACITY];
static uint32_t s_call_count;
static uint32_t s_new_result;
static uint32_t s_clone_result;
static uint32_t s_event_ids[8];
static int s_audio_hook_clears_global;
static int s_get_id_hook_truncates;
/* when set, the destroy, clone and audio hooks store s_hook_global_value there, as a callee rebinding the static would */
static uint32_t *s_hook_global;
static uint32_t s_hook_global_value;
static const rome2_l80_fx_ctx *s_fx;

static void record(l84_call_kind kind, uint32_t a, uint32_t b, uint32_t c, int32_t action) {
    if (s_call_count < L84_CALL_CAPACITY) {
        l84_call *call = &s_calls[s_call_count];
        call->kind = kind;
        call->a = a;
        call->b = b;
        call->c = c;
        call->action = action;
    }
    ++s_call_count;
}

static void expect_call(uint32_t index, l84_call_kind kind, uint32_t a, uint32_t b, uint32_t c, int32_t action) {
    assert(index < s_call_count && index < L84_CALL_CAPACITY);
    assert(s_calls[index].kind == kind);
    assert(s_calls[index].a == a);
    assert(s_calls[index].b == b);
    assert(s_calls[index].c == c);
    assert(s_calls[index].action == action);
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

static uint32_t f32_bits(float value) {
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static void put_u8(uint32_t va, uint8_t value) {
    *(uint8_t *)at(va, 1u) = value;
}

static uint8_t get_u8(uint32_t va) {
    return *(const uint8_t *)at(va, 1u);
}

static void test_on_log(rome2_l80_fx_ctx *ctx, uint32_t listener_va, const char *msg, int32_t level) {
    (void)ctx;
    assert(listener_va == L84_LISTENER_VA && msg != NULL);
    if (s_log_count < L84_LOG_CAPACITY) {
        s_log[s_log_count].level = level;
        (void)snprintf(s_log[s_log_count].text, sizeof(s_log[s_log_count].text), "%s", msg);
    }
    ++s_log_count;
}

static uint32_t hook_new(rome2_l84_fx_event_ctx *ctx, uint32_t bytes) {
    (void)ctx;
    record(CALL_NEW, bytes, 0u, 0u, 0);
    return s_new_result;
}

static void hook_delete(rome2_l84_fx_event_ctx *ctx, uint32_t ptr_va, uint32_t bytes) {
    (void)ctx;
    record(CALL_DELETE, ptr_va, bytes, 0u, 0);
}

static void hook_rebind_global(void) {
    if (s_hook_global != NULL) {
        *s_hook_global = s_hook_global_value;
    }
}

static void hook_destroy(rome2_l84_fx_event_ctx *ctx, uint32_t impl_va, uint32_t flags) {
    (void)ctx;
    record(CALL_DESTROY, impl_va, flags, 0u, 0);
    hook_rebind_global();
}

static uint32_t hook_clone(rome2_l84_fx_event_ctx *ctx, uint32_t impl_va) {
    (void)ctx;
    record(CALL_CLONE, impl_va, 0u, 0u, 0);
    hook_rebind_global();
    return s_clone_result;
}

static void hook_audio(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t impl_va,
    const rome2_fx_event_callback_param_32 *param,
    const int32_t *action) {
    assert(param != NULL && action != NULL);
    record(CALL_AUDIO, impl_va, param->actor_instance_va, param->event_va, *action);
    if (s_audio_hook_clears_global != 0) {
        ctx->audio_callback_va = 0u;
    }
    hook_rebind_global();
}

static void hook_custom(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t impl_va,
    const rome2_fx_event_callback_param_32 *param) {
    (void)ctx;
    assert(param != NULL);
    record(CALL_CUSTOM, impl_va, param->actor_instance_va, param->event_va, 0);
}

static uint32_t hook_get_id(rome2_l84_fx_event_ctx *ctx, uint32_t event_va) {
    uint32_t slot = (event_va - L84_EVENTS_VA) / 0xacu;
    (void)ctx;
    assert(event_va >= L84_EVENTS_VA && (event_va - L84_EVENTS_VA) % 0xacu == 0u && slot < 8u);
    record(CALL_GET_ID, event_va, 0u, 0u, 0);
    if (s_get_id_hook_truncates != 0) {
        put_u32(L84_MANAGER_VA + 0x18u, 1u);
    }
    return s_event_ids[slot];
}

static void fixture_init(l84_fixture *f) {
    memset(s_arena, 0, sizeof(s_arena));
    memset(s_log, 0, sizeof(s_log));
    memset(s_calls, 0, sizeof(s_calls));
    memset(s_event_ids, 0, sizeof(s_event_ids));
    s_log_count = 0u;
    s_call_count = 0u;
    s_new_result = 0u;
    s_clone_result = 0u;
    s_audio_hook_clears_global = 0;
    s_get_id_hook_truncates = 0;
    s_hook_global = NULL;
    s_hook_global_value = 0u;

    rome2_l80_ctx_init(&f->fx, s_arena, L84_ARENA_BASE, (uint32_t)sizeof(s_arena), L84_HEAP_START);
    s_fx = &f->fx;
    f->fx.on_log_message = test_on_log;
    (void)rome2_l80_log_manager_ctor(&f->fx, L84_LOG_MANAGER_VA);
    f->manager = (rome2_fx_log_manager_32 *)at(L84_LOG_MANAGER_VA, (uint32_t)sizeof(*f->manager));
    rome2_l80_fx_log_add_listener(&f->manager->log, L84_LISTENER_VA);

    rome2_l81_ctx_init(&f->names, &f->fx);
    f->names.null_name.entry_va = L84_ENTRY_NULL;

    rome2_l84_event_ctx_init(&f->events, &f->fx);
    f->events.operator_new = hook_new;
    f->events.operator_delete = hook_delete;
    f->events.functor_impl_destroy = hook_destroy;
    f->events.functor_impl_clone = hook_clone;
    f->events.audio_callback_invoke = hook_audio;
    f->events.custom_event_callback_invoke = hook_custom;
    f->events.event_get_id = hook_get_id;
}

static void test_sdk_version_and_error_strings(void) {
    static const char *const known[15] = {
        "Success",
        "Internal error",
        "A parameter was null",
        "The archive store is invalid",
        "The archive store could not be opened for writing",
        "The archive store could not be opened for reading",
        "The save operation was refused",
        "The archive is not a valid FaceFX archive",
        "The archive format is newer than the current FaceFX SDK",
        "The animation group already exists",
        "The animation group is not a mounted animation set",
        "The unmount operation was refused because an actor instance is currently playing an animation from the animation set",
        "Too many events during take creation",
        "Cannot create resource because a resource of the same type with the same key already exists",
        "One of the supplied resource parameters was not a managed resource",
    };
    /* the text pointers of rows 0..14 of the table at 0x1183a958 */
    static const uint32_t known_va[15] = {
        0x1183a9d8u, 0x1183a9e0u, 0x1183a9f0u, 0x1183aa08u, 0x1183aa28u,
        0x1183aa5cu, 0x1183aa90u, 0x1183aab0u, 0x1183aadcu, 0x1183ab14u,
        0x1183ab38u, 0x1183ab70u, 0x1183abe8u, 0x1183ac10u, 0x1183ac70u,
    };
    l84_fixture f;
    int32_t code;
    uint32_t text_va;
    fixture_init(&f);

    assert(rome2_l84_fx_sdk_get_version() == 0x853u);

    /* codes 0..14 resolve without touching the log; EAX is the row's text pointer */
    for (code = 0; code < 15; ++code) {
        text_va = L84_UNWRITTEN;
        assert(strcmp(rome2_l84_fx_sdk_get_error_string(&f.fx, code, &text_va), known[code]) == 0);
        assert(text_va == known_va[code]);
    }
    assert(s_log_count == 0u);

    /* a code outside the table reaches the -1 row: level-1 entry, then "UNKNOWN" at 0x1178701c */
    text_va = L84_UNWRITTEN;
    assert(strcmp(rome2_l84_fx_sdk_get_error_string(&f.fx, 15, &text_va), "UNKNOWN") == 0);
    assert(text_va == 0x1178701cu);
    assert(s_log_count == 1u && s_log[0].level == 1);
    assert(strcmp(s_log[0].text, "Unknown FX_ERROR code: 15") == 0);

    /* -1 equals no row ahead of the terminator, so it is reported as unknown as well */
    text_va = L84_UNWRITTEN;
    assert(strcmp(rome2_l84_fx_sdk_get_error_string(&f.fx, -1, &text_va), "UNKNOWN") == 0);
    assert(text_va == 0x1178701cu);
    assert(s_log_count == 2u && strcmp(s_log[1].text, "Unknown FX_ERROR code: -1") == 0);

    /* the entry is indented by the manager's tab level, four spaces per tab */
    f.manager->tab_level = 2u;
    assert(strcmp(rome2_l84_fx_sdk_get_error_string(&f.fx, INT_MIN, NULL), "UNKNOWN") == 0);
    assert(s_log_count == 3u && strcmp(s_log[2].text, "        Unknown FX_ERROR code: -2147483648") == 0);
    f.manager->tab_level = 0u;

    /* JL at 0x10ed65e1: the entry needs a signed level of at least 1 */
    f.manager->max_log_level = 1;
    (void)rome2_l84_fx_sdk_get_error_string(&f.fx, 99, NULL);
    assert(s_log_count == 4u && strcmp(s_log[3].text, "Unknown FX_ERROR code: 99") == 0);
    f.manager->max_log_level = 0;
    assert(strcmp(rome2_l84_fx_sdk_get_error_string(&f.fx, 99, NULL), "UNKNOWN") == 0);
    f.manager->max_log_level = -1;
    text_va = L84_UNWRITTEN;
    assert(strcmp(rome2_l84_fx_sdk_get_error_string(&f.fx, 99, &text_va), "UNKNOWN") == 0);
    assert(text_va == 0x1178701cu);
    assert(s_log_count == 4u);

    /* bounded: no log manager, no log */
    f.fx.log_manager_singleton_va = 0u;
    assert(strcmp(rome2_l84_fx_sdk_get_error_string(&f.fx, 99, NULL), "UNKNOWN") == 0);
    assert(strcmp(rome2_l84_fx_sdk_get_error_string(NULL, 99, NULL), "UNKNOWN") == 0);
    text_va = L84_UNWRITTEN;
    assert(strcmp(rome2_l84_fx_sdk_get_error_string(NULL, 11, &text_va), known[11]) == 0);
    assert(text_va == 0x1183ab70u);
    assert(s_log_count == 4u);
}

static void test_value_types(void) {
    rome2_fx_event_callback_param_32 param = {0x11111111u, 0x22222222u};
    rome2_fx_event_callback_param_32 param_copy = {0u, 0u};
    rome2_fx_resource_manager_32 source = {0xdeadbeefu, 0x12345678u};
    rome2_fx_resource_manager_32 target = {0u, 0u};
    rome2_fx_mount_unmount_result_32 result = {0, 0};
    int32_t play_status;

    /* 0x10be8b50: both dwords, returns this */
    assert(rome2_l84_event_callback_param_assign(&param_copy, &param) == &param_copy);
    assert(param_copy.actor_instance_va == 0x11111111u && param_copy.event_va == 0x22222222u);
    assert(rome2_l84_event_callback_param_assign(&param, &param) == &param);
    assert(param.actor_instance_va == 0x11111111u && param.event_va == 0x22222222u);
    assert(rome2_l84_event_callback_param_assign(&param_copy, NULL) == &param_copy);
    assert(param_copy.event_va == 0x22222222u);
    assert(rome2_l84_event_callback_param_assign(NULL, &param) == NULL);

    /* 0x10ed5700: the class vtable, not the source's, and the data member */
    assert(rome2_l84_resource_manager_ctor_copy(&target, &source) == &target);
    assert(target.vtable_va == 0x1183a798u && target.field_04 == 0x12345678u);
    assert(source.vtable_va == 0xdeadbeefu);

    /* 0x10ed59e0: the data member only */
    target.vtable_va = 0x0badf00du;
    source.field_04 = 0x9abcdef0u;
    assert(rome2_l84_resource_manager_assign(&target, &source) == &target);
    assert(target.vtable_va == 0x0badf00du && target.field_04 == 0x9abcdef0u);
    assert(rome2_l84_resource_manager_assign(&target, NULL) == &target);
    assert(target.field_04 == 0x9abcdef0u);
    assert(rome2_l84_resource_manager_ctor_copy(NULL, &source) == NULL);

    /* 0x10ed7bf0: true only when both error codes are zero */
    assert(rome2_l84_mount_unmount_result_bool(&result) == 1u);
    result.mount_err = 9;
    assert(rome2_l84_mount_unmount_result_bool(&result) == 0u);
    result.mount_err = 0;
    result.unmount_err = 11;
    assert(rome2_l84_mount_unmount_result_bool(&result) == 0u);
    result.mount_err = -1;
    assert(rome2_l84_mount_unmount_result_bool(&result) == 0u);
    assert(rome2_l84_mount_unmount_result_bool(NULL) == 0u);

    /* 0x10ed7c10: every status but -1 */
    play_status = -1;
    assert(rome2_l84_play_result_bool(&play_status) == 0u);
    play_status = 0;
    assert(rome2_l84_play_result_bool(&play_status) == 1u);
    play_status = INT_MIN;
    assert(rome2_l84_play_result_bool(&play_status) == 1u);
    assert(rome2_l84_play_result_bool(NULL) == 0u);
}

static void test_anim_set_accessors(void) {
    l84_fixture f;
    fixture_init(&f);

    /* LEA bodies: plain address arithmetic, with no NULL test in the image */
    assert(rome2_l84_anim_set_get_anim_group_name(L84_SET_A_VA) == L84_SET_A_VA + 0x14u);
    assert(rome2_l84_anim_set_get_owning_actor_name(L84_SET_A_VA) == L84_SET_A_VA + 0x0cu);
    assert(rome2_l84_anim_set_get_anim_group(L84_SET_A_VA) == L84_SET_A_VA + 0x10u);
    assert(rome2_l84_anim_set_get_references(L84_SET_A_VA) == L84_SET_A_VA + 0x30u);
    assert(rome2_l84_anim_set_get_anim_group_name(0u) == 0x14u);
    assert(rome2_l84_anim_set_get_references(0xfffffff0u) == 0x20u);

    put_u32(L84_SET_A_VA + 0x30u, 0x11111111u);
    put_u32(L84_SET_A_VA + 0x34u, 7u);
    assert(rome2_l84_anim_set_get_reference_count(&f.fx, L84_SET_A_VA) == 7u);

    /* MOV AL, [ECX + 8]: the stored byte, not a normalised bool */
    assert(rome2_l84_anim_set_is_published(&f.fx, L84_SET_A_VA) == 0u);
    put_u8(L84_SET_A_VA + 0x08u, 0x80u);
    put_u8(L84_SET_A_VA + 0x09u, 0xffu);
    assert(rome2_l84_anim_set_is_published(&f.fx, L84_SET_A_VA) == 0x80u);

    /* the two folded bodies also serve FxActorInstance::GetChannelBank and FxActor::ShouldClientRelink */
    assert(rome2_l84_anim_set_get_anim_group(L84_INSTANCE_VA) == L84_INSTANCE_VA + 0x10u);
    put_u8(L84_ACTOR_VA + 0x08u, 1u);
    assert(rome2_l84_anim_set_is_published(&f.fx, L84_ACTOR_VA) == 1u);

    /* bounded loads */
    assert(rome2_l84_anim_set_get_reference_count(&f.fx, L84_UNMAPPED_VA) == 0u);
    assert(rome2_l84_anim_set_is_published(&f.fx, L84_UNMAPPED_VA) == 0u);
    assert(rome2_l84_anim_set_get_reference_count(NULL, L84_SET_A_VA) == 0u);
}

static void test_anim_accessors(void) {
    l84_fixture f;
    fixture_init(&f);

    assert(rome2_l84_anim_get_event_take(L84_ANIM_VA) == L84_ANIM_VA + 0x34u);
    assert(rome2_l84_anim_get_event_template(L84_ANIM_VA) == L84_ANIM_VA + 0x68u);
    assert(rome2_l84_anim_get_phon_word_list(L84_ANIM_VA) == L84_ANIM_VA + 0x84u);
    assert(rome2_l84_anim_get_audio_asset_path(L84_ANIM_VA) == L84_ANIM_VA + 0xb4u);
    assert(rome2_l84_anim_get_audio_asset_name(L84_ANIM_VA) == L84_ANIM_VA + 0xd0u);
    assert(rome2_l84_anim_get_audio_asset_path(0u) == 0xb4u);

    put_f32(L84_ANIM_VA + 0x24u, 1.5f);
    put_f32(L84_ANIM_VA + 0x28u, 4.0f);
    put_f32(L84_ANIM_VA + 0x2cu, 2.0f);
    put_f32(L84_ANIM_VA + 0x30u, 5.5f);
    put_u32(L84_ANIM_VA + 0xb0u, 0x30004000u);
    put_u32(L84_ANIM_VA + 0xecu, 42u);
    put_u32(L84_ANIM_VA + 0xf0u, 0x30005000u);
    put_f32(L84_ANIM_VA + 0xf4u, 30.0f);
    assert(rome2_l84_anim_get_real_start_time(&f.fx, L84_ANIM_VA) == 1.5f);
    assert(rome2_l84_anim_get_real_end_time(&f.fx, L84_ANIM_VA) == 4.0f);
    assert(rome2_l84_anim_get_curves_start_time(&f.fx, L84_ANIM_VA) == 2.0f);
    assert(rome2_l84_anim_get_curves_end_time(&f.fx, L84_ANIM_VA) == 5.5f);
    assert(rome2_l84_anim_get_editor_only_data(&f.fx, L84_ANIM_VA) == 0x30004000u);
    assert(rome2_l84_anim_get_audio_asset_index(&f.fx, L84_ANIM_VA) == 42u);
    assert(rome2_l84_anim_get_audio_asset_pointer(&f.fx, L84_ANIM_VA) == 0x30005000u);
    assert(rome2_l84_anim_get_frame_rate(&f.fx, L84_ANIM_VA) == 30.0f);

    /* 0x10abed80 stores the one dword at +0xf0 */
    rome2_l84_anim_set_audio_asset_pointer(&f.fx, L84_ANIM_VA, 0x30006000u);
    assert(get_u32(L84_ANIM_VA + 0xf0u) == 0x30006000u);
    assert(get_u32(L84_ANIM_VA + 0xecu) == 42u && get_f32(L84_ANIM_VA + 0xf4u) == 30.0f);
    assert(rome2_l84_anim_get_audio_asset_pointer(&f.fx, L84_ANIM_VA) == 0x30006000u);
    rome2_l84_anim_set_audio_asset_pointer(&f.fx, L84_UNMAPPED_VA, 1u); /* bounded: dropped */

    /* curve records: 0x28 bytes at +0x0c, compressed 0x18 bytes at +0x18 */
    put_u32(L84_ANIM_VA + 0x0cu, 0x30007000u);
    put_u32(L84_ANIM_VA + 0x18u, 0x30008000u);
    assert(rome2_l84_anim_get_anim_curve(&f.fx, L84_ANIM_VA, 0u) == 0x30007000u);
    assert(rome2_l84_anim_get_anim_curve(&f.fx, L84_ANIM_VA, 3u) == 0x30007078u);
    assert(rome2_l84_anim_get_compressed_anim_curve(&f.fx, L84_ANIM_VA, 0u) == 0x30008000u);
    assert(rome2_l84_anim_get_compressed_anim_curve(&f.fx, L84_ANIM_VA, 3u) == 0x30008048u);

    /* 0x10ed7770: FLD start, FSUB end */
    assert(rome2_l84_anim_get_curves_duration(&f.fx, L84_ANIM_VA) == -3.5f);

    /* 0x10ed7790 / 0x10ed77f0 with a real range */
    assert(rome2_l84_anim_get_duration(&f.fx, L84_ANIM_VA) == 2.5f);
    assert(rome2_l84_anim_get_end_time(&f.fx, L84_ANIM_VA) == 4.0f);
    /* only one of the two times zero: still the stored range */
    put_f32(L84_ANIM_VA + 0x24u, 0.0f);
    assert(rome2_l84_anim_get_duration(&f.fx, L84_ANIM_VA) == 4.0f);
    assert(rome2_l84_anim_get_end_time(&f.fx, L84_ANIM_VA) == 4.0f);
    put_f32(L84_ANIM_VA + 0x24u, 2.0f);
    put_f32(L84_ANIM_VA + 0x28u, 0.0f);
    assert(rome2_l84_anim_get_duration(&f.fx, L84_ANIM_VA) == -2.0f);
    assert(rome2_l84_anim_get_end_time(&f.fx, L84_ANIM_VA) == 0.0f);
    /* both zero, of either sign: the unit default */
    put_f32(L84_ANIM_VA + 0x24u, 0.0f);
    assert(rome2_l84_anim_get_duration(&f.fx, L84_ANIM_VA) == 1.0f);
    assert(rome2_l84_anim_get_end_time(&f.fx, L84_ANIM_VA) == 1.0f);
    put_f32(L84_ANIM_VA + 0x24u, -0.0f);
    put_f32(L84_ANIM_VA + 0x28u, -0.0f);
    assert(rome2_l84_anim_get_duration(&f.fx, L84_ANIM_VA) == 1.0f);
    assert(rome2_l84_anim_get_end_time(&f.fx, L84_ANIM_VA) == 1.0f);
    /* an unordered start is not zero */
    put_f32(L84_ANIM_VA + 0x24u, NAN);
    put_f32(L84_ANIM_VA + 0x28u, 0.0f);
    assert(isnan(rome2_l84_anim_get_duration(&f.fx, L84_ANIM_VA)));
    assert(rome2_l84_anim_get_end_time(&f.fx, L84_ANIM_VA) == 0.0f);

    /*
     * The five FLD m32 bodies (0x10228780, 0x10a9a5c0, 0x103bf2c0, 0x101db470,
     * 0x10ed7840) hand back the stored bits, except that a signalling NaN
     * comes back quiet with its sign and payload kept.
     */
    put_u32(L84_ANIM_VA + 0x24u, 0x7fa00000u);
    put_u32(L84_ANIM_VA + 0x28u, 0xff800001u);
    put_u32(L84_ANIM_VA + 0x2cu, 0x7fc12345u);
    put_u32(L84_ANIM_VA + 0x30u, 0xff800000u);
    put_u32(L84_ANIM_VA + 0xf4u, 0x80000001u);
    assert(f32_bits(rome2_l84_anim_get_real_start_time(&f.fx, L84_ANIM_VA)) == 0x7fe00000u);
    assert(f32_bits(rome2_l84_anim_get_real_end_time(&f.fx, L84_ANIM_VA)) == 0xffc00001u);
    assert(f32_bits(rome2_l84_anim_get_curves_start_time(&f.fx, L84_ANIM_VA)) == 0x7fc12345u);
    assert(f32_bits(rome2_l84_anim_get_curves_end_time(&f.fx, L84_ANIM_VA)) == 0xff800000u);
    assert(f32_bits(rome2_l84_anim_get_frame_rate(&f.fx, L84_ANIM_VA)) == 0x80000001u);
    /* the loads leave the stored bits alone */
    assert(get_u32(L84_ANIM_VA + 0x24u) == 0x7fa00000u && get_u32(L84_ANIM_VA + 0x28u) == 0xff800001u);
    /* 0x10ed77f0 returns the stored end through the same FLD; both times are unordered here */
    assert(f32_bits(rome2_l84_anim_get_end_time(&f.fx, L84_ANIM_VA)) == 0xffc00001u);
    /* 0x10ed7770 with one NaN operand: that NaN, quiet */
    put_f32(L84_ANIM_VA + 0x30u, 2.0f);
    assert(f32_bits(rome2_l84_anim_get_curves_duration(&f.fx, L84_ANIM_VA)) == 0x7fc12345u);

    /* bounded loads: a chained accessor carries on with the 0 an unmapped load yields */
    assert(rome2_l84_anim_get_frame_rate(&f.fx, L84_UNMAPPED_VA) == 0.0f);
    assert(rome2_l84_anim_get_anim_curve(&f.fx, L84_UNMAPPED_VA, 2u) == 0x50u);
    assert(rome2_l84_anim_get_compressed_anim_curve(&f.fx, L84_UNMAPPED_VA, 2u) == 0x30u);
}

static void test_actor_accessors(void) {
    l84_fixture f;
    fixture_init(&f);

    assert(rome2_l84_actor_get_decompiled_face_graph(L84_ACTOR_VA) == L84_ACTOR_VA + 0x2cu);
    assert(rome2_l84_actor_get_compiled_face_graph(L84_ACTOR_VA) == L84_ACTOR_VA + 0x4cu);
    assert(rome2_l84_actor_get_phoneme_map(L84_ACTOR_VA) == L84_ACTOR_VA + 0x60f0u);
    assert(rome2_l84_actor_get_editor_only_data(L84_ACTOR_VA) == L84_ACTOR_VA + 0x610cu);
    assert(rome2_l84_actor_get_editor_only_data(0u) == 0x610cu);

    put_u8(L84_ACTOR_VA + 0x08u, 0x11u);
    put_u8(L84_ACTOR_VA + 0x09u, 0x22u);
    put_u8(L84_ACTOR_VA + 0x0au, 0x33u);
    assert(rome2_l84_actor_is_open_in_studio(&f.fx, L84_ACTOR_VA) == 0x22u);
    assert(rome2_l84_actor_is_published(&f.fx, L84_ACTOR_VA) == 0x33u);

    /* 0x10ed75c0: records + 4 + (index << 6) */
    put_u32(L84_ACTOR_VA + 0x14u, L84_BONES_VA);
    assert(rome2_l84_actor_get_bone(&f.fx, L84_ACTOR_VA, 0u) == L84_BONES_VA + 4u);
    assert(rome2_l84_actor_get_bone(&f.fx, L84_ACTOR_VA, 5u) == L84_BONES_VA + 0x144u);

    /* 0x10ed7860: owned count, plus the default group, plus the mounted list's count */
    assert(rome2_l84_actor_get_num_anim_groups(&f.fx, L84_ACTOR_VA) == 1u);
    put_u32(L84_ACTOR_VA + 0x60dcu, 3u);
    put_u32(L84_ACTOR_VA + 0x60e4u, 2u);
    assert(rome2_l84_actor_get_num_anim_groups(&f.fx, L84_ACTOR_VA) == 6u);

    assert(rome2_l84_actor_is_published(&f.fx, L84_UNMAPPED_VA) == 0u);
    assert(rome2_l84_actor_get_num_anim_groups(&f.fx, L84_UNMAPPED_VA) == 1u);
}

/* Three owned groups named ONE, (empty), THREE and a default group named DEFAULT. */
static void actor_set_owned_groups(void) {
    put_u32(L84_ACTOR_VA + 0x60d4u, L84_GROUPS_VA);
    put_u32(L84_ACTOR_VA + 0x60dcu, 3u);
    put_u32(L84_GROUPS_VA + 0x04u, L84_ENTRY_ONE);
    put_u32(L84_GROUPS_VA + 0x24u, 0u);
    put_u32(L84_GROUPS_VA + 0x44u, L84_ENTRY_THREE);
    put_u32(L84_ACTOR_VA + 0x60b8u, L84_ENTRY_DEFAULT);
}

/* A mounted list head -> A -> B -> head, built in the arena heap. */
static uint32_t actor_set_mounted_list(l84_fixture *f) {
    uint32_t head_va = rome2_l80_fx_allocate(&f->fx, 0x0cu);
    assert(head_va != 0u);
    put_u32(head_va + 0x00u, L84_UNWRITTEN);
    put_u32(head_va + 0x04u, L84_NODE_A_VA);
    put_u32(head_va + 0x08u, L84_NODE_B_VA);
    put_u32(L84_NODE_A_VA + 0x00u, L84_SET_A_VA);
    put_u32(L84_NODE_A_VA + 0x04u, L84_NODE_B_VA);
    put_u32(L84_NODE_A_VA + 0x08u, head_va);
    put_u32(L84_NODE_B_VA + 0x00u, L84_SET_B_VA);
    put_u32(L84_NODE_B_VA + 0x04u, head_va);
    put_u32(L84_NODE_B_VA + 0x08u, L84_NODE_A_VA);
    put_u32(L84_SET_A_VA + 0x14u, L84_ENTRY_SET_A);
    put_u32(L84_SET_B_VA + 0x14u, L84_ENTRY_SET_B);
    put_u32(L84_ACTOR_VA + 0x60e0u, head_va);
    put_u32(L84_ACTOR_VA + 0x60e4u, 2u);
    return head_va;
}

static void test_actor_find_anim_group(void) {
    l84_fixture f;
    rome2_fx_name_32 name;
    uint32_t head_va;
    fixture_init(&f);

    /*
     * A fresh actor has no list head: the lookup allocates the 0xc-byte
     * sentinel, links it to itself and leaves its item slot alone. The default
     * group's empty name is bound to NullName on the way out.
     */
    put_u32(L84_HEAP_START, L84_UNWRITTEN);
    name.entry_va = L84_ENTRY_ABSENT;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 0xffffffffu);
    assert(f.fx.alloc_calls == 1u);
    head_va = get_u32(L84_ACTOR_VA + 0x60e0u);
    assert(head_va == L84_HEAP_START);
    assert(get_u32(head_va + 0x00u) == L84_UNWRITTEN);
    assert(get_u32(head_va + 0x04u) == head_va && get_u32(head_va + 0x08u) == head_va);
    assert(get_u32(L84_ACTOR_VA + 0x60b8u) == L84_ENTRY_NULL);

    /* the default group now compares equal to NullName and reports index 0; no second sentinel */
    name.entry_va = L84_ENTRY_NULL;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 0u);
    assert(f.fx.alloc_calls == 1u && get_u32(L84_ACTOR_VA + 0x60e0u) == head_va);

    /* owned groups report position + 1; an empty owned name is bound to NullName when visited */
    actor_set_owned_groups();
    name.entry_va = L84_ENTRY_ONE;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 1u);
    assert(get_u32(L84_GROUPS_VA + 0x24u) == 0u);
    name.entry_va = L84_ENTRY_THREE;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 3u);
    assert(get_u32(L84_GROUPS_VA + 0x24u) == L84_ENTRY_NULL);
    name.entry_va = L84_ENTRY_NULL;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 2u);
    name.entry_va = L84_ENTRY_DEFAULT;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 0u);
    name.entry_va = L84_ENTRY_ABSENT;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 0xffffffffu);
    /* an unbound name never matches: every name it is compared with has been bound first */
    name.entry_va = 0u;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 0xffffffffu);

    /*
     * The argument is read again at every compare (CMP reg, [ESI] at
     * 0x10ed6508, 0x10ed6547 and 0x10ed656d). Handed an owned group's own
     * unbound name, the lookup binds that slot to NullName and then finds the
     * argument equal to it.
     */
    put_u32(L84_GROUPS_VA + 0x24u, 0u);
    assert(
        rome2_l84_actor_find_anim_group(
            &f.names, L84_ACTOR_VA, (const rome2_fx_name_32 *)at(L84_GROUPS_VA + 0x24u, 4u)) == 2u);
    assert(get_u32(L84_GROUPS_VA + 0x24u) == L84_ENTRY_NULL);
    /* the same with the default group's own name once no owned group matches */
    put_u32(L84_GROUPS_VA + 0x24u, L84_ENTRY_ONE);
    put_u32(L84_ACTOR_VA + 0x60b8u, 0u);
    assert(
        rome2_l84_actor_find_anim_group(
            &f.names, L84_ACTOR_VA, (const rome2_fx_name_32 *)at(L84_ACTOR_VA + 0x60b8u, 4u)) == 0u);
    assert(get_u32(L84_ACTOR_VA + 0x60b8u) == L84_ENTRY_NULL);

    /*
     * With FxName::NullName itself unset (0x11fadb7c holds 0 before the name
     * table starts) an empty slot is rewritten with 0 and equals an unbound
     * argument: the first empty owned group answers.
     */
    f.names.null_name.entry_va = 0u;
    put_u32(L84_GROUPS_VA + 0x24u, 0u);
    put_u32(L84_ACTOR_VA + 0x60b8u, 0u);
    name.entry_va = 0u;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 2u);
    assert(get_u32(L84_GROUPS_VA + 0x24u) == 0u && get_u32(L84_ACTOR_VA + 0x60b8u) == 0u);
    put_u32(L84_GROUPS_VA + 0x24u, L84_ENTRY_ONE);
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 0u);
    assert(get_u32(L84_ACTOR_VA + 0x60b8u) == 0u);
    f.names.null_name.entry_va = L84_ENTRY_NULL;

    /* mounted sets report count + 1 + position and are searched before the owned groups */
    fixture_init(&f);
    actor_set_owned_groups();
    (void)actor_set_mounted_list(&f);
    name.entry_va = L84_ENTRY_SET_A;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 4u);
    name.entry_va = L84_ENTRY_SET_B;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 5u);
    put_u32(L84_SET_B_VA + 0x14u, L84_ENTRY_ONE);
    name.entry_va = L84_ENTRY_ONE;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 5u);
    put_u32(L84_SET_B_VA + 0x14u, 0u);
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 1u);
    assert(get_u32(L84_SET_B_VA + 0x14u) == L84_ENTRY_NULL);
    assert(f.fx.alloc_calls == 1u); /* the list fixture's own allocation */

    /* bounded: unmapped actor, missing arguments; no sentinel is allocated */
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_UNMAPPED_VA, &name) == 0xffffffffu);
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, NULL) == 0xffffffffu);
    assert(rome2_l84_actor_find_anim_group(NULL, L84_ACTOR_VA, &name) == 0xffffffffu);
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_UNMAPPED_VA, 9u) == 0u);
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_UNMAPPED_VA, &name) == 0u);
    assert(f.fx.alloc_calls == 1u);
}

static uint32_t alloc_fails(rome2_l80_fx_ctx *ctx, uint32_t bytes) {
    (void)ctx;
    (void)bytes;
    return 0u;
}

static void test_actor_get_anim_group_and_mounted(void) {
    l84_fixture f;
    rome2_fx_name_32 name;
    uint32_t head_va;
    fixture_init(&f);
    actor_set_owned_groups();
    head_va = actor_set_mounted_list(&f);

    /* 0x10ed7390: 0 is the embedded default group, 1..count index the owned array */
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 0u) == L84_ACTOR_VA + 0x60b4u);
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 1u) == L84_GROUPS_VA);
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 3u) == L84_GROUPS_VA + 0x40u);
    /* past the owned groups: the mounted set's embedded group at set + 0x10 */
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 4u) == L84_SET_A_VA + 0x10u);
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 5u) == L84_SET_B_VA + 0x10u);
    /* the walk has no end test: one step further is the sentinel, the next wraps to the first set */
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 6u) == L84_UNWRITTEN + 0x10u);
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 7u) == L84_SET_A_VA + 0x10u);
    assert(f.fx.alloc_calls == 1u && get_u32(L84_ACTOR_VA + 0x60e0u) == head_va);

    /* 0x10ed78d0 searches the mounted list only and binds an empty set name it passes */
    name.entry_va = L84_ENTRY_SET_B;
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_ACTOR_VA, &name) == 1u);
    name.entry_va = L84_ENTRY_SET_A;
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_ACTOR_VA, &name) == 1u);
    name.entry_va = L84_ENTRY_THREE;
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_ACTOR_VA, &name) == 0u);
    name.entry_va = L84_ENTRY_DEFAULT;
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_ACTOR_VA, &name) == 0u);
    put_u32(L84_SET_A_VA + 0x14u, 0u);
    name.entry_va = L84_ENTRY_SET_B;
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_ACTOR_VA, &name) == 1u);
    assert(get_u32(L84_SET_A_VA + 0x14u) == L84_ENTRY_NULL);
    assert(get_u32(L84_GROUPS_VA + 0x24u) == 0u); /* owned names are not visited */

    /* an actor without a list head gets its sentinel from either body */
    fixture_init(&f);
    put_u32(L84_HEAP_START, L84_UNWRITTEN);
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 1u) == L84_UNWRITTEN + 0x10u);
    head_va = get_u32(L84_ACTOR_VA + 0x60e0u);
    assert(f.fx.alloc_calls == 1u && head_va == L84_HEAP_START);
    assert(get_u32(head_va + 0x00u) == L84_UNWRITTEN);
    assert(get_u32(head_va + 0x04u) == head_va && get_u32(head_va + 0x08u) == head_va);
    /* indices that stay inside the owned range allocate nothing */
    fixture_init(&f);
    actor_set_owned_groups();
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 3u) == L84_GROUPS_VA + 0x40u);
    assert(f.fx.alloc_calls == 0u && get_u32(L84_ACTOR_VA + 0x60e0u) == 0u);

    fixture_init(&f);
    put_u32(L84_HEAP_START, L84_UNWRITTEN);
    name.entry_va = L84_ENTRY_NULL;
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_ACTOR_VA, &name) == 0u);
    head_va = get_u32(L84_ACTOR_VA + 0x60e0u);
    assert(f.fx.alloc_calls == 1u && head_va == L84_HEAP_START);
    assert(get_u32(head_va + 0x00u) == L84_UNWRITTEN);
    assert(get_u32(head_va + 0x04u) == head_va && get_u32(head_va + 0x08u) == head_va);
    assert(get_u32(L84_ACTOR_VA + 0x60b8u) == 0u); /* the default group is not visited */

    /* bounded: a failed sentinel allocation ends each body where the original writes through NULL */
    fixture_init(&f);
    f.fx.custom_alloc = alloc_fails;
    name.entry_va = L84_ENTRY_NULL;
    assert(rome2_l84_actor_find_anim_group(&f.names, L84_ACTOR_VA, &name) == 0xffffffffu);
    assert(rome2_l84_actor_get_anim_group(&f.fx, L84_ACTOR_VA, 1u) == 0u);
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_ACTOR_VA, &name) == 0u);
    assert(f.fx.alloc_calls == 3u && get_u32(L84_ACTOR_VA + 0x60e0u) == 0u);
    assert(rome2_l84_actor_is_anim_group_mounted(&f.names, L84_ACTOR_VA, NULL) == 0u);
    assert(rome2_l84_actor_is_anim_group_mounted(NULL, L84_ACTOR_VA, &name) == 0u);
}

static void test_actor_instance_accessors(void) {
    l84_fixture f;
    fixture_init(&f);

    assert(rome2_l84_actor_instance_get_weighted_bone_transforms(L84_INSTANCE_VA) == L84_INSTANCE_VA + 0xacu);
    assert(
        rome2_l84_actor_instance_get_accumulated_base_channel_track_values(L84_INSTANCE_VA) ==
        L84_INSTANCE_VA + 0x110u);
    assert(rome2_l84_actor_instance_get_weighted_bone_transforms(0u) == 0xacu);

    put_u8(L84_INSTANCE_VA + 0x0cu, 0x40u);
    put_u8(L84_INSTANCE_VA + 0x0du, 0x02u);
    put_u32(L84_INSTANCE_VA + 0xc4u, 5u);
    put_u32(L84_INSTANCE_VA + 0xd0u, 16u);
    put_u32(L84_INSTANCE_VA + 0x108u, 0x321u);
    assert(rome2_l84_actor_instance_is_no_work_frame(&f.fx, L84_INSTANCE_VA) == 0x40u);
    assert(rome2_l84_actor_instance_is_open_in_studio(&f.fx, L84_INSTANCE_VA) == 0x02u);
    assert(rome2_l84_actor_instance_get_num_client_events(&f.fx, L84_INSTANCE_VA) == 5u);
    assert(rome2_l84_actor_instance_get_max_num_client_events(&f.fx, L84_INSTANCE_VA) == 16u);
    assert(rome2_l84_actor_instance_get_curve_state_pool_length(&f.fx, L84_INSTANCE_VA) == 0x321u);

    /* the bone bodies go through the instance's actor at +8 */
    put_u32(L84_INSTANCE_VA + 0x08u, L84_ACTOR_VA);
    put_u32(L84_ACTOR_VA + 0x14u, L84_BONES_VA);
    put_u32(L84_ACTOR_VA + 0x1cu, 9u);
    assert(rome2_l84_actor_instance_get_num_bones(&f.fx, L84_INSTANCE_VA) == 9u);
    assert(rome2_l84_actor_instance_get_bone_name(&f.fx, L84_INSTANCE_VA, 0u) == L84_BONES_VA + 8u);
    assert(rome2_l84_actor_instance_get_bone_name(&f.fx, L84_INSTANCE_VA, 2u) == L84_BONES_VA + 0x88u);
    /* the name sits 4 bytes into the FxBone that FxActor::GetBone returns */
    assert(
        rome2_l84_actor_instance_get_bone_name(&f.fx, L84_INSTANCE_VA, 2u) ==
        rome2_l84_actor_get_bone(&f.fx, L84_ACTOR_VA, 2u) + 4u);

    /* 0x10ed7850: one float per node from the array at +0x38 */
    put_u32(L84_INSTANCE_VA + 0x38u, L84_VALUES_VA);
    put_f32(L84_VALUES_VA + 0x00u, 0.25f);
    put_f32(L84_VALUES_VA + 0x0cu, -7.5f);
    assert(rome2_l84_actor_instance_get_node_final_value(&f.fx, L84_INSTANCE_VA, 0u) == 0.25f);
    assert(rome2_l84_actor_instance_get_node_final_value(&f.fx, L84_INSTANCE_VA, 3u) == -7.5f);
    /* FLD m32 [EAX + index*4]: a signalling NaN comes back quiet */
    put_u32(L84_VALUES_VA + 0x04u, 0x7f800001u);
    assert(f32_bits(rome2_l84_actor_instance_get_node_final_value(&f.fx, L84_INSTANCE_VA, 1u)) == 0x7fc00001u);
    assert(get_u32(L84_VALUES_VA + 0x04u) == 0x7f800001u);

    /* bounded loads */
    put_u32(L84_INSTANCE_VA + 0x08u, L84_UNMAPPED_VA);
    assert(rome2_l84_actor_instance_get_num_bones(&f.fx, L84_INSTANCE_VA) == 0u);
    assert(rome2_l84_actor_instance_get_node_final_value(&f.fx, L84_UNMAPPED_VA, 0u) == 0.0f);
}

static void test_event_manager_ctor_and_state(void) {
    l84_fixture f;
    uint32_t offset;
    fixture_init(&f);

    /* 0x10ed7de0 writes 3 bytes and 15 dwords; the 9 pad bytes keep their old contents */
    memset(at(L84_MANAGER_VA, 0x48u), 0xee, 0x48u);
    put_u8(L84_MANAGER_VA + 0x48u, 0x77u);
    assert(rome2_l84_event_manager_ctor(&f.fx, L84_MANAGER_VA) == L84_MANAGER_VA);
    assert(get_u8(L84_MANAGER_VA + 0x00u) == 0u);
    assert(get_u32(L84_MANAGER_VA + 0x04u) == 0xcf000000u);
    for (offset = 0x08u; offset <= 0x30u; offset += 4u) {
        assert(get_u32(L84_MANAGER_VA + offset) == 0u);
    }
    assert(get_u8(L84_MANAGER_VA + 0x34u) == 1u);
    assert(get_u32(L84_MANAGER_VA + 0x38u) == 0u);
    assert(get_u32(L84_MANAGER_VA + 0x3cu) == 0u);
    assert(get_u32(L84_MANAGER_VA + 0x40u) == 0u);
    assert(get_u8(L84_MANAGER_VA + 0x44u) == 0u);
    for (offset = 1u; offset < 4u; ++offset) {
        assert(get_u8(L84_MANAGER_VA + 0x00u + offset) == 0xeeu);
        assert(get_u8(L84_MANAGER_VA + 0x34u + offset) == 0xeeu);
        assert(get_u8(L84_MANAGER_VA + 0x44u + offset) == 0xeeu);
    }
    assert(get_u8(L84_MANAGER_VA + 0x48u) == 0x77u);

    /* the constructed pause time is the float the image keeps at 0x1183b014 */
    assert(rome2_l84_event_manager_get_pause_time(&f.fx, L84_MANAGER_VA) == -2147483648.0f);
    assert(rome2_l84_event_manager_is_paused(&f.fx, L84_MANAGER_VA) == 0u);
    put_u8(L84_MANAGER_VA + 0x00u, 0x7fu);
    put_f32(L84_MANAGER_VA + 0x04u, 3.25f);
    assert(rome2_l84_event_manager_is_paused(&f.fx, L84_MANAGER_VA) == 0x7fu);
    assert(rome2_l84_event_manager_get_pause_time(&f.fx, L84_MANAGER_VA) == 3.25f);
    /* 0x101b0ee0 is FLD m32 [ECX + 4]: the constructed bits pass through, a signalling NaN comes back quiet */
    put_u32(L84_MANAGER_VA + 0x04u, 0xcf000000u);
    assert(f32_bits(rome2_l84_event_manager_get_pause_time(&f.fx, L84_MANAGER_VA)) == 0xcf000000u);
    put_u32(L84_MANAGER_VA + 0x04u, 0xffa00000u);
    assert(f32_bits(rome2_l84_event_manager_get_pause_time(&f.fx, L84_MANAGER_VA)) == 0xffe00000u);

    /* bounded */
    assert(rome2_l84_event_manager_ctor(&f.fx, L84_UNMAPPED_VA) == L84_UNMAPPED_VA);
    assert(rome2_l84_event_manager_is_paused(&f.fx, L84_UNMAPPED_VA) == 0u);
}

/* A constructed manager over `slots` 0xac-byte events with the given flag bytes. */
static void manager_set_events(l84_fixture *f, const uint8_t *flags, uint32_t slots) {
    uint32_t slot;
    (void)rome2_l84_event_manager_ctor(&f->fx, L84_MANAGER_VA);
    put_u32(L84_MANAGER_VA + 0x10u, L84_EVENTS_VA);
    put_u32(L84_MANAGER_VA + 0x1cu, L84_FLAGS_VA);
    for (slot = 0u; slot < slots; ++slot) {
        put_u8(L84_FLAGS_VA + slot, flags[slot]);
    }
}

static void test_event_manager_client_events_and_is_playing(void) {
    static const uint8_t flags[5] = {0u, 1u, 0x80u, 0u, 1u};
    l84_fixture f;
    fixture_init(&f);
    manager_set_events(&f, flags, 5u);

    /* 0x10ed86d0 is bounded by the count at +0x18; the one at +0x24 plays no part */
    put_u32(L84_MANAGER_VA + 0x18u, 5u);
    assert(rome2_l84_event_manager_get_client_event(&f.fx, L84_MANAGER_VA, 0u) == L84_EVENTS_VA + 0xacu);
    assert(rome2_l84_event_manager_get_client_event(&f.fx, L84_MANAGER_VA, 1u) == L84_EVENTS_VA + 0x158u);
    assert(rome2_l84_event_manager_get_client_event(&f.fx, L84_MANAGER_VA, 2u) == L84_EVENTS_VA + 0x2b0u);
    assert(rome2_l84_event_manager_get_client_event(&f.fx, L84_MANAGER_VA, 3u) == 0u);
    put_u32(L84_MANAGER_VA + 0x18u, 4u);
    assert(rome2_l84_event_manager_get_client_event(&f.fx, L84_MANAGER_VA, 2u) == 0u);
    put_u32(L84_MANAGER_VA + 0x18u, 0u);
    put_u32(L84_MANAGER_VA + 0x24u, 5u);
    assert(rome2_l84_event_manager_get_client_event(&f.fx, L84_MANAGER_VA, 0u) == 0u);
    assert(rome2_l84_event_manager_get_client_event(&f.fx, L84_UNMAPPED_VA, 0u) == 0u);

    /*
     * 0x10ed8f50 asks every slot for its id, active or not, and returns the
     * flag byte of the first slot whose id matches.
     */
    put_u32(L84_MANAGER_VA + 0x18u, 5u);
    put_u32(L84_MANAGER_VA + 0x24u, 0u);
    s_event_ids[0] = 10u;
    s_event_ids[1] = 20u;
    s_event_ids[2] = 30u;
    s_event_ids[3] = 20u;
    s_event_ids[4] = 50u;
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 30u) == 0x80u);
    assert(s_call_count == 3u);
    expect_call(0u, CALL_GET_ID, L84_EVENTS_VA, 0u, 0u, 0);
    expect_call(1u, CALL_GET_ID, L84_EVENTS_VA + 0xacu, 0u, 0u, 0);
    expect_call(2u, CALL_GET_ID, L84_EVENTS_VA + 0x158u, 0u, 0u, 0);
    s_call_count = 0u;
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 20u) == 1u);
    assert(s_call_count == 2u);
    s_call_count = 0u;
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 10u) == 0u);
    assert(s_call_count == 1u);
    s_call_count = 0u;
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 99u) == 0u);
    assert(s_call_count == 5u);

    /* the count is read again after each call */
    s_call_count = 0u;
    s_get_id_hook_truncates = 1;
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 50u) == 0u);
    assert(s_call_count == 1u && get_u32(L84_MANAGER_VA + 0x18u) == 1u);
    s_get_id_hook_truncates = 0;

    /* no slots, no calls */
    s_call_count = 0u;
    put_u32(L84_MANAGER_VA + 0x18u, 0u);
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 10u) == 0u);
    assert(s_call_count == 0u);

    /* an unset id hook answers 0 for every event */
    put_u32(L84_MANAGER_VA + 0x18u, 5u);
    f.events.event_get_id = NULL;
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 0u) == 0u);
    put_u8(L84_FLAGS_VA, 0x05u);
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 0u) == 0x05u);
    assert(rome2_l84_event_manager_is_playing(&f.events, L84_MANAGER_VA, 10u) == 0u);
    assert(rome2_l84_event_manager_is_playing(NULL, L84_MANAGER_VA, 0u) == 0u);
}

static void test_event_manager_pause_resume(void) {
    static const uint8_t flags[4] = {1u, 0u, 1u, 1u};
    l84_fixture f;
    fixture_init(&f);
    manager_set_events(&f, flags, 4u);
    put_u32(L84_AUDIO_FUNCTOR_VA, L84_IMPL_AUDIO);
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    /* both bodies are bounded by the count at +0x24: slot 3 is active but out of range */
    put_u32(L84_MANAGER_VA + 0x24u, 3u);
    put_f32(L84_EVENTS_VA + 0x000u + 0x88u, 3.0f);
    put_f32(L84_EVENTS_VA + 0x0acu + 0x88u, 5.0f);
    put_f32(L84_EVENTS_VA + 0x158u + 0x88u, -2147483648.0f);
    put_f32(L84_EVENTS_VA + 0x204u + 0x88u, 9.0f);

    /* 0x10ed99c0 does nothing while the manager is not paused */
    rome2_l84_event_manager_resume(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 50.0f);
    assert(s_call_count == 0u && get_f32(L84_EVENTS_VA + 0x88u) == 3.0f);
    assert(get_u32(L84_MANAGER_VA + 0x04u) == 0xcf000000u);

    /* 0x10ed8fa0: action 1 for each active slot in range, then the flag and the time */
    rome2_l84_event_manager_pause(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 12.5f);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_AUDIO, L84_IMPL_AUDIO, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA, 1);
    expect_call(1u, CALL_AUDIO, L84_IMPL_AUDIO, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA + 0x158u, 1);
    assert(get_u8(L84_MANAGER_VA) == 1u && get_f32(L84_MANAGER_VA + 0x04u) == 12.5f);
    assert(get_f32(L84_EVENTS_VA + 0x88u) == 3.0f); /* Pause moves no event time */

    /* a second Pause is ignored */
    rome2_l84_event_manager_pause(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 99.0f);
    assert(s_call_count == 2u && get_f32(L84_MANAGER_VA + 0x04u) == 12.5f);

    /*
     * Resume shifts each active in-range event time by the paused span unless
     * it holds -2147483648.0f, calls back with action 2, and restores the flag
     * and the invalid-time bits.
     */
    rome2_l84_event_manager_resume(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 20.0f);
    assert(s_call_count == 4u);
    expect_call(2u, CALL_AUDIO, L84_IMPL_AUDIO, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA, 2);
    expect_call(3u, CALL_AUDIO, L84_IMPL_AUDIO, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA + 0x158u, 2);
    assert(get_f32(L84_EVENTS_VA + 0x000u + 0x88u) == 10.5f);
    assert(get_f32(L84_EVENTS_VA + 0x0acu + 0x88u) == 5.0f);
    assert(get_u32(L84_EVENTS_VA + 0x158u + 0x88u) == 0xcf000000u);
    assert(get_f32(L84_EVENTS_VA + 0x204u + 0x88u) == 9.0f);
    assert(get_u8(L84_MANAGER_VA) == 0u && get_u32(L84_MANAGER_VA + 0x04u) == 0xcf000000u);

    /* a NaN event time is unordered with the sentinel, so it is rewritten (and stays NaN) */
    put_f32(L84_EVENTS_VA + 0x88u, NAN);
    put_u32(L84_EVENTS_VA + 0x158u + 0x88u, 0x7fc00001u);
    rome2_l84_event_manager_pause(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 1.0f);
    rome2_l84_event_manager_resume(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 2.0f);
    assert(isnan(get_f32(L84_EVENTS_VA + 0x88u)) && isnan(get_f32(L84_EVENTS_VA + 0x158u + 0x88u)));
    assert(s_call_count == 8u);

    /* Pause re-reads the functor global after each call; Resume reads it per slot */
    s_call_count = 0u;
    s_audio_hook_clears_global = 1;
    rome2_l84_event_manager_pause(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 4.0f);
    assert(s_call_count == 1u && f.events.audio_callback_va == 0u);
    assert(get_u8(L84_MANAGER_VA) == 1u && get_f32(L84_MANAGER_VA + 0x04u) == 4.0f);
    put_f32(L84_EVENTS_VA + 0x000u + 0x88u, 1.0f);
    put_f32(L84_EVENTS_VA + 0x158u + 0x88u, 2.0f);
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    rome2_l84_event_manager_resume(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 6.0f);
    assert(s_call_count == 2u && f.events.audio_callback_va == 0u);
    expect_call(1u, CALL_AUDIO, L84_IMPL_AUDIO, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA, 2);
    /* the times still move without a callback */
    assert(get_f32(L84_EVENTS_VA + 0x000u + 0x88u) == 3.0f);
    assert(get_f32(L84_EVENTS_VA + 0x158u + 0x88u) == 4.0f);
    assert(get_u8(L84_MANAGER_VA) == 0u);
    s_audio_hook_clears_global = 0;

    /* a callback that rebinds the static is replaced from the next slot on (0x10ed8ff7, 0x10ed9a1f) */
    s_call_count = 0u;
    put_u32(L84_CUSTOM_FUNCTOR_VA, L84_IMPL_CUSTOM);
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    s_hook_global = &f.events.audio_callback_va;
    s_hook_global_value = L84_CUSTOM_FUNCTOR_VA;
    rome2_l84_event_manager_pause(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 4.0f);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_AUDIO, L84_IMPL_AUDIO, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA, 1);
    expect_call(1u, CALL_AUDIO, L84_IMPL_CUSTOM, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA + 0x158u, 1);
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    rome2_l84_event_manager_resume(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 4.0f);
    assert(s_call_count == 4u);
    expect_call(2u, CALL_AUDIO, L84_IMPL_AUDIO, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA, 2);
    expect_call(3u, CALL_AUDIO, L84_IMPL_CUSTOM, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA + 0x158u, 2);
    s_hook_global = NULL;
    f.events.audio_callback_va = 0u;

    /* no audio callback installed: state changes only */
    s_call_count = 0u;
    rome2_l84_event_manager_pause(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 10.0f);
    assert(get_u8(L84_MANAGER_VA) == 1u && get_f32(L84_MANAGER_VA + 0x04u) == 10.0f);
    rome2_l84_event_manager_resume(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 10.5f);
    assert(get_f32(L84_EVENTS_VA + 0x88u) == 3.5f && get_u8(L84_MANAGER_VA) == 0u);
    assert(s_call_count == 0u);

    /* no slots in range: Pause still records, Resume still clears */
    put_u32(L84_MANAGER_VA + 0x24u, 0u);
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    rome2_l84_event_manager_pause(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 7.0f);
    assert(get_u8(L84_MANAGER_VA) == 1u && get_f32(L84_MANAGER_VA + 0x04u) == 7.0f);
    rome2_l84_event_manager_resume(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 8.0f);
    assert(get_u8(L84_MANAGER_VA) == 0u && get_u32(L84_MANAGER_VA + 0x04u) == 0xcf000000u);
    assert(get_f32(L84_EVENTS_VA + 0x88u) == 3.5f && s_call_count == 0u);

    /* bounded: an installed functor without an implementation stops Pause before the state change */
    put_u32(L84_MANAGER_VA + 0x24u, 3u);
    put_u32(L84_AUDIO_FUNCTOR_VA, 0u);
    rome2_l84_event_manager_pause(&f.events, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 7.0f);
    assert(get_u8(L84_MANAGER_VA) == 0u && s_call_count == 0u);
    rome2_l84_event_manager_pause(NULL, L84_MANAGER_VA, L84_ACTOR_INSTANCE_ARG, 7.0f);
    rome2_l84_event_manager_resume(&f.events, L84_UNMAPPED_VA, L84_ACTOR_INSTANCE_ARG, 7.0f);
    assert(s_call_count == 0u);
}

static void test_event_manager_callbacks(void) {
    l84_fixture f;
    fixture_init(&f);

    /* 0x10ed9a80, nothing installed: operator new(4), clone the argument's implementation, publish */
    put_u32(L84_SOURCE_FUNCTOR_VA, L84_IMPL_SOURCE);
    put_u32(L84_NEW_FUNCTOR_VA, L84_UNWRITTEN);
    s_new_result = L84_NEW_FUNCTOR_VA;
    s_clone_result = L84_IMPL_CLONE_1;
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_NEW, 4u, 0u, 0u, 0);
    expect_call(1u, CALL_CLONE, L84_IMPL_SOURCE, 0u, 0u, 0);
    assert(f.events.audio_callback_va == L84_NEW_FUNCTOR_VA);
    assert(get_u32(L84_NEW_FUNCTOR_VA) == L84_IMPL_CLONE_1);
    assert(get_u32(L84_SOURCE_FUNCTOR_VA) == L84_IMPL_SOURCE);
    assert(f.events.custom_event_callback_va == 0u);

    /* already installed: clone first, swap, then destroy the old implementation with flag 1 */
    s_call_count = 0u;
    s_clone_result = L84_IMPL_CLONE_2;
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_CLONE, L84_IMPL_SOURCE, 0u, 0u, 0);
    expect_call(1u, CALL_DESTROY, L84_IMPL_CLONE_1, 1u, 0u, 0);
    assert(f.events.audio_callback_va == L84_NEW_FUNCTOR_VA);
    assert(get_u32(L84_NEW_FUNCTOR_VA) == L84_IMPL_CLONE_2);

    /* an empty argument functor installs a NULL implementation without a clone call */
    s_call_count = 0u;
    put_u32(L84_SOURCE_FUNCTOR_VA, 0u);
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 1u);
    expect_call(0u, CALL_DESTROY, L84_IMPL_CLONE_2, 1u, 0u, 0);
    assert(get_u32(L84_NEW_FUNCTOR_VA) == 0u && f.events.audio_callback_va == L84_NEW_FUNCTOR_VA);
    /* and replacing a NULL implementation destroys nothing */
    s_call_count = 0u;
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 0u && get_u32(L84_NEW_FUNCTOR_VA) == 0u);

    /* 0x10ed8360 on a functor with no implementation: only the 4-byte release */
    rome2_l84_event_manager_clear_audio_callback(&f.events);
    assert(s_call_count == 1u);
    expect_call(0u, CALL_DELETE, L84_NEW_FUNCTOR_VA, 4u, 0u, 0);
    assert(f.events.audio_callback_va == 0u);
    /* nothing installed: nothing happens */
    rome2_l84_event_manager_clear_audio_callback(&f.events);
    assert(s_call_count == 1u);

    /* fresh install from an empty functor: the new functor's implementation slot is stored as 0, no clone */
    s_call_count = 0u;
    put_u32(L84_NEW_FUNCTOR_VA, L84_UNWRITTEN);
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 1u);
    expect_call(0u, CALL_NEW, 4u, 0u, 0u, 0);
    assert(get_u32(L84_NEW_FUNCTOR_VA) == 0u && f.events.audio_callback_va == L84_NEW_FUNCTOR_VA);

    /* a failed allocation leaves the global NULL and never looks at the argument */
    f.events.audio_callback_va = 0u;
    s_call_count = 0u;
    s_new_result = 0u;
    put_u32(L84_SOURCE_FUNCTOR_VA, L84_IMPL_SOURCE);
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 1u && f.events.audio_callback_va == 0u);
    expect_call(0u, CALL_NEW, 4u, 0u, 0u, 0);
    f.events.operator_new = NULL;
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 1u && f.events.audio_callback_va == 0u);

    /* Clear: implementation destroyed with flag 1, then the functor released, then the global */
    s_call_count = 0u;
    put_u32(L84_AUDIO_FUNCTOR_VA, L84_IMPL_AUDIO);
    put_u32(L84_CUSTOM_FUNCTOR_VA, L84_IMPL_CUSTOM);
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    f.events.custom_event_callback_va = L84_CUSTOM_FUNCTOR_VA;
    rome2_l84_event_manager_clear_audio_callback(&f.events);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_DESTROY, L84_IMPL_AUDIO, 1u, 0u, 0);
    expect_call(1u, CALL_DELETE, L84_AUDIO_FUNCTOR_VA, 4u, 0u, 0);
    assert(f.events.audio_callback_va == 0u && f.events.custom_event_callback_va == L84_CUSTOM_FUNCTOR_VA);

    /* 0x10ed83c0 hands the custom-event functor a {instance, event} pair built on the stack */
    s_call_count = 0u;
    rome2_l84_event_manager_fire_custom_event_callback(&f.events, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA + 0xacu);
    assert(s_call_count == 1u);
    expect_call(0u, CALL_CUSTOM, L84_IMPL_CUSTOM, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA + 0xacu, 0);

    /* 0x10ed8390 is the same sequence on the other global */
    s_call_count = 0u;
    rome2_l84_event_manager_clear_custom_event_callback(&f.events);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_DESTROY, L84_IMPL_CUSTOM, 1u, 0u, 0);
    expect_call(1u, CALL_DELETE, L84_CUSTOM_FUNCTOR_VA, 4u, 0u, 0);
    assert(f.events.custom_event_callback_va == 0u);

    /* nothing installed: Fire and Clear are no-ops */
    s_call_count = 0u;
    rome2_l84_event_manager_fire_custom_event_callback(&f.events, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA);
    rome2_l84_event_manager_clear_custom_event_callback(&f.events);
    assert(s_call_count == 0u);

    /* the audio global plays no part in Fire */
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    rome2_l84_event_manager_fire_custom_event_callback(&f.events, L84_ACTOR_INSTANCE_ARG, L84_EVENTS_VA);
    assert(s_call_count == 0u);

    /*
     * Both Clear bodies and the installed half of Set hold the functor pointer
     * they loaded on entry in ESI: a destructor or clone that rebinds the
     * static changes neither which functor is released nor which is rewritten.
     */
    s_call_count = 0u;
    put_u32(L84_AUDIO_FUNCTOR_VA, L84_IMPL_AUDIO);
    put_u32(L84_CUSTOM_FUNCTOR_VA, L84_IMPL_CUSTOM);
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    s_hook_global = &f.events.audio_callback_va;
    s_hook_global_value = L84_CUSTOM_FUNCTOR_VA;
    rome2_l84_event_manager_clear_audio_callback(&f.events);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_DESTROY, L84_IMPL_AUDIO, 1u, 0u, 0);
    expect_call(1u, CALL_DELETE, L84_AUDIO_FUNCTOR_VA, 4u, 0u, 0);
    assert(f.events.audio_callback_va == 0u); /* 0x10ed8382 stores 0 last */

    s_call_count = 0u;
    f.events.custom_event_callback_va = L84_CUSTOM_FUNCTOR_VA;
    s_hook_global = &f.events.custom_event_callback_va;
    s_hook_global_value = L84_AUDIO_FUNCTOR_VA;
    rome2_l84_event_manager_clear_custom_event_callback(&f.events);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_DESTROY, L84_IMPL_CUSTOM, 1u, 0u, 0);
    expect_call(1u, CALL_DELETE, L84_CUSTOM_FUNCTOR_VA, 4u, 0u, 0);
    assert(f.events.custom_event_callback_va == 0u);

    /* Set over an installed functor whose clone rebinds the static: the entry functor still gets the swap */
    s_call_count = 0u;
    put_u32(L84_SOURCE_FUNCTOR_VA, L84_IMPL_SOURCE);
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    s_hook_global = &f.events.audio_callback_va;
    s_hook_global_value = L84_CUSTOM_FUNCTOR_VA;
    s_clone_result = L84_IMPL_CLONE_1;
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_CLONE, L84_IMPL_SOURCE, 0u, 0u, 0);
    expect_call(1u, CALL_DESTROY, L84_IMPL_AUDIO, 1u, 0u, 0);
    assert(get_u32(L84_AUDIO_FUNCTOR_VA) == L84_IMPL_CLONE_1);
    assert(get_u32(L84_CUSTOM_FUNCTOR_VA) == L84_IMPL_CUSTOM);
    assert(f.events.audio_callback_va == L84_CUSTOM_FUNCTOR_VA); /* this half never stores the static */

    /* a clone that clears the static changes nothing either */
    s_call_count = 0u;
    f.events.audio_callback_va = L84_AUDIO_FUNCTOR_VA;
    s_hook_global_value = 0u;
    s_clone_result = L84_IMPL_CLONE_2;
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_CLONE, L84_IMPL_SOURCE, 0u, 0u, 0);
    expect_call(1u, CALL_DESTROY, L84_IMPL_CLONE_1, 1u, 0u, 0);
    assert(get_u32(L84_AUDIO_FUNCTOR_VA) == L84_IMPL_CLONE_2 && f.events.audio_callback_va == 0u);

    /* nothing installed: whatever the clone left in the static, 0x10ed9ab8 stores the new functor */
    s_call_count = 0u;
    f.events.operator_new = hook_new;
    s_new_result = L84_NEW_FUNCTOR_VA;
    s_hook_global_value = L84_CUSTOM_FUNCTOR_VA;
    s_clone_result = L84_IMPL_CLONE_1;
    rome2_l84_event_manager_set_audio_callback(&f.events, L84_SOURCE_FUNCTOR_VA);
    assert(s_call_count == 2u);
    expect_call(0u, CALL_NEW, 4u, 0u, 0u, 0);
    expect_call(1u, CALL_CLONE, L84_IMPL_SOURCE, 0u, 0u, 0);
    assert(f.events.audio_callback_va == L84_NEW_FUNCTOR_VA && get_u32(L84_NEW_FUNCTOR_VA) == L84_IMPL_CLONE_1);
    assert(get_u32(L84_CUSTOM_FUNCTOR_VA) == L84_IMPL_CUSTOM);
    s_hook_global = NULL;
    s_call_count = 0u;

    /* unset hooks: the global still clears */
    f.events.functor_impl_destroy = NULL;
    f.events.operator_delete = NULL;
    rome2_l84_event_manager_clear_audio_callback(&f.events);
    assert(f.events.audio_callback_va == 0u && s_call_count == 0u);
    rome2_l84_event_manager_clear_audio_callback(NULL);
    rome2_l84_event_manager_set_audio_callback(NULL, L84_SOURCE_FUNCTOR_VA);
    rome2_l84_event_manager_fire_custom_event_callback(NULL, 0u, 0u);
}

int main(void) {
    test_sdk_version_and_error_strings();
    test_value_types();
    test_anim_set_accessors();
    test_anim_accessors();
    test_actor_accessors();
    test_actor_find_anim_group();
    test_actor_get_anim_group_and_mounted();
    test_actor_instance_accessors();
    test_event_manager_ctor_and_state();
    test_event_manager_client_events_and_is_playing();
    test_event_manager_pause_resume();
    test_event_manager_callbacks();
    printf("facefx_sdk_accessors_leaf_ops tests passed\n");
    return 0;
}
