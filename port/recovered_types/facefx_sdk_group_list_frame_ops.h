#ifndef ROME2_FACEFX_SDK_GROUP_LIST_FRAME_OPS_H
#define ROME2_FACEFX_SDK_GROUP_LIST_FRAME_OPS_H

#include "facefx_sdk_accessors_leaf_ops.h"

/*
 * Layer 85: FaceFX class registration, FxAnimGroup trees, FxList membership
 * and per-frame bone and event work (0x1033c6a0..0x10f09320, Partition 12).
 *
 * Guest objects live in the Layer 80 arena and are named by guest address.
 * A load from an address outside the arena yields 0 and a store there is
 * dropped; a body that walks a list or tree, copies a block or calls through
 * an object returns at the first such access, where the original faults.
 * Walks are cut off after ROME2_L85_WALK_LIMIT steps and FxAnimGroup::Clear
 * after ROME2_L85_CLEAR_DEPTH_LIMIT nested groups, where the original spins
 * or exhausts its stack on a malformed structure.
 */

enum rome2_l85_fx_vtable_va {
    ROME2_FX_VTABLE_ANIM_GROUP_TREE = 0x1183bf74u,
    ROME2_FX_VTABLE_ANIM_GROUP = 0x1183bf8cu,
    ROME2_FX_VTABLE_ACTOR_INSTANCE = 0x1183c770u, /* slot +0x14 is EndFrame (0x10eeaed0) */
    ROME2_FX_VTABLE_NAMED_OBJECT = 0x1183ce30u
};

/* Constructor thunks the class descriptors are registered with. */
enum rome2_l85_fx_construct_va {
    ROME2_L85_VA_FX_ACTOR_INSTANCE_CONSTRUCT = 0x100dbc00u,
    ROME2_L85_VA_FX_ACTOR_CONSTRUCT = 0x10ed6420u,
    ROME2_L85_VA_FX_ANIM_CONSTRUCT = 0x10ed6440u,
    ROME2_L85_VA_FX_ANIM_GROUP_CONSTRUCT = 0x10ed6460u,
    ROME2_L85_VA_FX_ANIM_SET_CONSTRUCT = 0x10ed6480u,
    ROME2_L85_VA_FX_NAMED_OBJECT_CONSTRUCT = 0x10ef3350u
};

enum {
    ROME2_L85_WALK_LIMIT = 0x10000,
    ROME2_L85_CLEAR_DEPTH_LIMIT = 64,
    ROME2_FX_CURVE_STATE_BYTES = 0x30,       /* LEA EAX, [EAX + EAX*2]; SHL EAX, 4 at 0x10ed79c0 */
    ROME2_FX_ACTOR_BONE_TABLE_OFFSET = 0x0c, /* ADD ECX, 0xc at 0x10ed65a0, 0x10ed78a0 and 0x10ed7970 */
    /*
     * SUBSS XMM0, [ECX + 0x24] at 0x10ed87a1: the float HasWorkThisFrame
     * reads from the object an event names at +0x0c. The body reads nothing
     * else of that object, which leaves its type open.
     */
    ROME2_FX_EVENT_LINK_VALUE_OFFSET = 0x24
};

/* SetFrameRate accepts 24.0f (0x117667f8) through 120.0f (0x117580d8), both inclusive. */
#define ROME2_FX_MIN_FRAME_RATE 24.0f
#define ROME2_FX_MAX_FRAME_RATE 120.0f
/* ProcessFrame leaves a quaternion alone while its squared length is strictly between these. */
#define ROME2_FX_QUAT_NORM_LOW_BITS 0x3f7ffffeu  /* 0x1183c798 */
#define ROME2_FX_QUAT_NORM_HIGH_BITS 0x3f800001u /* 0x1183c79c */

typedef struct rome2_l85_fx_sdk_ctx {
    rome2_l80_fx_ctx *fx;
    rome2_l81_fx_name_ctx *names;             /* FxName statics, the class table and 0x11fadba4 */
    uint32_t fx_named_object_class_va;        /* 0x11fadba8 */
    uint8_t log_error_on_animation_not_found; /* 0x11974fa0; 1 in the image */

    /*
     * Effects of virtual calls into bodies outside the recovered set. An
     * unset hook does nothing; object_get_class_desc then yields 0 and
     * tree_insert leaves the result iterator {0, 0}.
     */
    /* vtable slot +0 of an FxObject-derived instance: its FxClass */
    uint32_t (*object_get_class_desc)(struct rome2_l85_fx_sdk_ctx *ctx, uint32_t object_va);
    /* vtable slot +8: the deleting destructor; the recovered bodies pass flag 1 */
    void (*object_destroy)(struct rome2_l85_fx_sdk_ctx *ctx, uint32_t object_va, uint32_t flags);
    /* tree vtable 0x1183bf74 slot +4 (0x10edeee0): drop every node */
    void (*tree_clear)(struct rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va);
    /*
     * tree vtable slot +0xc (0x10ee6490): insert. The original also passes
     * the address of the stack slot holding the value; the value is passed.
     */
    void (*tree_insert)(
        struct rome2_l85_fx_sdk_ctx *ctx,
        uint32_t tree_va,
        rome2_fx_tree_iterator_32 *result,
        uint32_t root_slot_va,
        uint32_t key_va,
        uint32_t value_va);
    /*
     * tree vtable slot +0x10 (0x10ee6810): unlink. The original passes the
     * address of a stack slot holding the node, which is 0 when the search
     * found nothing; the node is passed.
     */
    void (*tree_remove)(struct rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va, uint32_t node_va);
} rome2_l85_fx_sdk_ctx;

void rome2_l85_ctx_init(rome2_l85_fx_sdk_ctx *ctx, rome2_l80_fx_ctx *fx, rome2_l81_fx_name_ctx *names);

/* FxClass and the FxObject type queries */
uint8_t rome2_l85_fx_class_equals(uint32_t self_va, uint32_t other_va);
uint8_t rome2_l85_fx_class_is_kind_of(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t class_va);
uint8_t rome2_l85_fx_object_is_a(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t class_va);
uint8_t rome2_l85_fx_object_is_kind_of(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t class_va);

/* FxNamedObject and the static class descriptors */
uint32_t rome2_l85_fx_named_object_ctor(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va);
uint32_t rome2_l85_fx_named_object_static_class_init(rome2_l85_fx_sdk_ctx *ctx);
uint32_t rome2_l85_fx_anim_static_class_init(rome2_l85_fx_sdk_ctx *ctx);
uint32_t rome2_l85_fx_anim_group_static_class_init(rome2_l85_fx_sdk_ctx *ctx);
uint32_t rome2_l85_fx_anim_set_static_class_init(rome2_l85_fx_sdk_ctx *ctx);
uint32_t rome2_l85_fx_actor_static_class_init(rome2_l85_fx_sdk_ctx *ctx);
uint32_t rome2_l85_fx_actor_instance_static_class_init(rome2_l85_fx_sdk_ctx *ctx);

/* FxString and FxName */
uint32_t rome2_l85_fx_string_assign(rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t other_va);
void rome2_l85_fx_name_dump_stats_to_log(rome2_l81_fx_name_ctx *names);

/* FxResourceManager */
uint32_t rome2_l85_resource_manager_ctor(rome2_l80_fx_ctx *fx, uint32_t self_va);
void rome2_l85_resource_manager_set_automatic_garbage_collection(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    uint8_t enabled);

/* FxEventManager and FxEvent */
uint8_t rome2_l85_event_manager_has_work_this_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va, float time);
void rome2_l85_event_manager_set_custom_event_callback(rome2_l84_fx_event_ctx *ctx, uint32_t functor_va);
void rome2_l85_event_manager_shutdown(rome2_l84_fx_event_ctx *ctx);
void rome2_l85_event_set_time_range(const rome2_l80_fx_ctx *fx, uint32_t self_va, float offset);

/* FxAnim */
uint8_t rome2_l85_anim_destroy_editor_only_data(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va);
uint32_t rome2_l85_anim_find_anim_curve(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);
uint32_t rome2_l85_anim_find_compressed_anim_curve(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);
void rome2_l85_anim_set_audio_asset_index(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index);
uint32_t rome2_l85_anim_set_audio_asset_name(rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t string_va);
uint32_t rome2_l85_anim_set_audio_asset_path(rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t string_va);
uint8_t rome2_l85_anim_set_frame_rate(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, float frame_rate);

/* FxAnimGroup */
uint32_t rome2_l85_anim_group_ctor(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va);
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_begin_animations(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    rome2_fx_tree_iterator_32 *out);
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_begin_sub_groups(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    rome2_fx_tree_iterator_32 *out);
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_end_animations(uint32_t self_va, rome2_fx_tree_iterator_32 *out);
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_end_sub_groups(uint32_t self_va, rome2_fx_tree_iterator_32 *out);
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_reverse_begin_animations(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    rome2_fx_tree_iterator_32 *out);
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_reverse_begin_sub_groups(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    rome2_fx_tree_iterator_32 *out);
void rome2_l85_anim_group_clear(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va);
uint8_t rome2_l85_anim_group_get_log_error_on_animation_not_found(const rome2_l85_fx_sdk_ctx *ctx);
void rome2_l85_anim_group_set_log_error_on_animation_not_found(rome2_l85_fx_sdk_ctx *ctx, uint8_t enabled);
uint8_t rome2_l85_anim_group_remove_and_destroy_anim(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);
uint8_t rome2_l85_anim_group_remove_and_destroy_sub_group(
    rome2_l85_fx_sdk_ctx *ctx,
    uint32_t self_va,
    uint32_t name_va);
uint32_t rome2_l85_anim_group_remove_anim(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);
uint32_t rome2_l85_anim_group_remove_sub_group(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);
uint8_t rome2_l85_anim_group_add_anim(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t anim_va);
uint8_t rome2_l85_anim_group_add_sub_group(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t group_va);
uint32_t rome2_l85_anim_group_find_anim(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);
uint32_t rome2_l85_anim_group_find_sub_group(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);

/* FxList and FxAnimSet */
uint32_t *rome2_l85_fx_list_find(
    rome2_l80_fx_ctx *fx,
    uint32_t list_va,
    uint32_t *out_node_va,
    const uint32_t *value);
void rome2_l85_anim_set_add_reference(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t actor_va);
void rome2_l85_anim_set_remove_reference(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t actor_va);
void rome2_l85_anim_set_set_is_published(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint8_t value);
uint32_t rome2_l85_anim_set_set_owning_actor_name(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);

/* FxActor and its bone table */
uint32_t rome2_l85_actor_find_bone(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va);
void rome2_l85_actor_initialize_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t instance_va);
void rome2_l85_actor_process_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t instance_va);
void rome2_l85_actor_add_instance(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t instance_va);
uint32_t rome2_l85_actor_get_instance_count(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l85_actor_get_instances(uint32_t self_va);
void rome2_l85_actor_remove_instance(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t instance_va);
void rome2_l85_actor_set_is_open_in_studio(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint8_t value);
void rome2_l85_actor_set_is_published(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint8_t value);
uint8_t rome2_l85_actor_find_instance(
    rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    uint32_t instance_va,
    uint32_t *out_node_va);
uint32_t rome2_l85_bone_table_find_bone(rome2_l85_fx_sdk_ctx *ctx, uint32_t table_va, uint32_t name_va);
void rome2_l85_bone_table_initialize_frame(const rome2_l80_fx_ctx *fx, uint32_t table_va, uint32_t instance_va);
void rome2_l85_bone_table_process_frame(const rome2_l80_fx_ctx *fx, uint32_t table_va, uint32_t instance_va);

/* FxActorInstance */
void rome2_l85_actor_instance_release_curve_state_handle(
    rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    uint32_t handle_va);
void rome2_l85_curve_state_cache_release(rome2_l80_fx_ctx *fx, uint32_t cache_va, uint32_t handle_va);
void rome2_l85_actor_instance_end_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va);
void rome2_l85_actor_instance_set_is_open_in_studio(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint8_t value);

#endif
