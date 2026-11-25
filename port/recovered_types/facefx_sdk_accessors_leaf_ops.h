#ifndef ROME2_FACEFX_SDK_ACCESSORS_LEAF_OPS_H
#define ROME2_FACEFX_SDK_ACCESSORS_LEAF_OPS_H

/*
 * Layer 84: FaceFX SDK accessors and leaf routines (0x100e80c0..0x10ed9a80).
 *
 * FxAnimSet, FxAnim, FxActor, FxActorInstance and FxEventManager objects live
 * in the Layer 80 arena and are named by guest address. A body that only
 * forms an address (LEA) is 32-bit arithmetic on that address; a body that
 * loads or stores goes through the arena.
 *
 * Bounded: a load from outside the arena yields 0, a store there is dropped,
 * and a multi-step body returns at the first such access, where the original
 * faults. List walks stop after 0x10000 nodes.
 */

#include "facefx_name_avl_table_ops.h"
#include "guest32_layouts.h"

#include <stdint.h>

enum rome2_l84_fx_const {
    ROME2_FX_SDK_VERSION = 0x853,                    /* MOV EAX, 0x853 at 0x10ed6680 */
    ROME2_FX_VTABLE_RESOURCE_MANAGER = 0x1183a798,   /* one slot: 0x10ed61e0 */
    ROME2_FX_ANIM_CURVE_BYTES = 0x28,                /* index * 5 * 8 at 0x10ed7384 / 0x10ed738a */
    ROME2_FX_COMPRESSED_ANIM_CURVE_BYTES = 0x18,     /* index * 3 * 8 at 0x10ed76c4 / 0x10ed76ca */
    ROME2_FX_ERROR_STRING_ROWS = 16,                 /* 0x1183a958: codes 0..14 and the -1 row */
    ROME2_FX_AUDIO_CALLBACK_ACTION_ON_PAUSE = 1,     /* 0x10ed8fde */
    ROME2_FX_AUDIO_CALLBACK_ACTION_ON_RESUME = 2     /* 0x10ed9a3a */
};

/* FindAnimGroup's miss result: (match) - 1 at 0x10ed6578..0x10ed657c. */
#define ROME2_FX_ANIM_GROUP_NOT_FOUND 0xffffffffu
/* The float at 0x1183b014 and the dword the manager stores while not paused. */
#define ROME2_FX_INVALID_TIME (-2147483648.0f)
#define ROME2_FX_INVALID_TIME_BITS 0xcf000000u

/*
 * Process state and callees of the FxEventManager bodies.
 *
 * The two globals point at 4-byte FxFunctor objects whose one field points at
 * an implementation object. The bodies reach that object only through its
 * vtable (slot +0 deleting destructor, +4 clone, +8 invoke), and IsPlaying
 * compares its argument with what each FxEvent's vtable slot +0x30 returns;
 * none of those targets is in the recovered set, so each is a hook. The CRT
 * allocator pair 0x100d12b0 / 0x116835d7 is pinned by earlier layers but its
 * heap is not part of the FaceFX arena, so it is a hook pair as well.
 *
 * Unset hooks: operator_new returns 0 (the allocation-failure path),
 * functor_impl_clone and event_get_id return 0, the others do nothing.
 */
typedef struct rome2_l84_fx_event_ctx {
    rome2_l80_fx_ctx *fx;
    uint32_t audio_callback_va;        /* 0x11fadb6c FxEventManager::_audioCallback */
    uint32_t custom_event_callback_va; /* 0x11fadb70 FxEventManager::_customEventCallback */

    uint32_t (*operator_new)(struct rome2_l84_fx_event_ctx *ctx, uint32_t bytes);
    void (*operator_delete)(struct rome2_l84_fx_event_ctx *ctx, uint32_t ptr_va, uint32_t bytes);
    void (*functor_impl_destroy)(struct rome2_l84_fx_event_ctx *ctx, uint32_t impl_va, uint32_t flags);
    uint32_t (*functor_impl_clone)(struct rome2_l84_fx_event_ctx *ctx, uint32_t impl_va);
    /* param and action are the two stack locals whose addresses the body pushes */
    void (*audio_callback_invoke)(
        struct rome2_l84_fx_event_ctx *ctx,
        uint32_t impl_va,
        const rome2_fx_event_callback_param_32 *param,
        const int32_t *action);
    void (*custom_event_callback_invoke)(
        struct rome2_l84_fx_event_ctx *ctx,
        uint32_t impl_va,
        const rome2_fx_event_callback_param_32 *param);
    uint32_t (*event_get_id)(struct rome2_l84_fx_event_ctx *ctx, uint32_t event_va);
} rome2_l84_fx_event_ctx;

void rome2_l84_event_ctx_init(rome2_l84_fx_event_ctx *ctx, rome2_l80_fx_ctx *fx);

/* SDK version and error text (0x10ed6680, 0x10ed65b0) */
uint32_t rome2_l84_fx_sdk_get_version(void);
const char *rome2_l84_fx_sdk_get_error_string(rome2_l80_fx_ctx *fx, int32_t error);

/*
 * Value types (0x10be8b50, 0x10ed5700, 0x10ed59e0, 0x10ed7bf0, 0x10ed7c10).
 * 0x10be8b50 is also FxMountUnmountResult::operator=.
 */
rome2_fx_event_callback_param_32 *rome2_l84_event_callback_param_assign(
    rome2_fx_event_callback_param_32 *self,
    const rome2_fx_event_callback_param_32 *other);
rome2_fx_resource_manager_32 *rome2_l84_resource_manager_ctor_copy(
    rome2_fx_resource_manager_32 *self,
    const rome2_fx_resource_manager_32 *other);
rome2_fx_resource_manager_32 *rome2_l84_resource_manager_assign(
    rome2_fx_resource_manager_32 *self,
    const rome2_fx_resource_manager_32 *other);
uint8_t rome2_l84_mount_unmount_result_bool(const rome2_fx_mount_unmount_result_32 *self);
uint8_t rome2_l84_play_result_bool(const int32_t *self);

/*
 * FxAnimSet (0x100e80c0, 0x100e8110, 0x10170450, 0x1018aba0, 0x101a9b80, 0x1054d080).
 * 0x1018aba0 is also FxActorInstance::GetChannelBank and 0x1054d080 also
 * FxActor::ShouldClientRelink. The bool accessors return the stored byte.
 */
uint32_t rome2_l84_anim_set_get_anim_group_name(uint32_t self_va);
uint32_t rome2_l84_anim_set_get_reference_count(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_anim_set_get_owning_actor_name(uint32_t self_va);
uint32_t rome2_l84_anim_set_get_anim_group(uint32_t self_va);
uint32_t rome2_l84_anim_set_get_references(uint32_t self_va);
uint8_t rome2_l84_anim_set_is_published(const rome2_l80_fx_ctx *fx, uint32_t self_va);

/*
 * FxAnim (0x101db470, 0x101f8940, 0x10228780, 0x10298bc0, 0x10371c70, 0x103bf2c0, 0x105e13a0,
 * 0x10a281c0, 0x10a2d1e0, 0x10a34830, 0x10a9a5c0, 0x10abed80, 0x10ed7380, 0x10ed76c0,
 * 0x10ed7770, 0x10ed7790, 0x10ed77f0, 0x10ed7830, 0x10ed7840).
 * 0x10228780 is also GetStartTime and 0x10ed7380 also GetAnimCurveM.
 */
float rome2_l84_anim_get_curves_end_time(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_anim_get_audio_asset_path(uint32_t self_va);
float rome2_l84_anim_get_real_start_time(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_anim_get_phon_word_list(uint32_t self_va);
uint32_t rome2_l84_anim_get_audio_asset_index(const rome2_l80_fx_ctx *fx, uint32_t self_va);
float rome2_l84_anim_get_curves_start_time(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_anim_get_event_take(uint32_t self_va);
uint32_t rome2_l84_anim_get_audio_asset_pointer(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_anim_get_editor_only_data(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_anim_get_audio_asset_name(uint32_t self_va);
float rome2_l84_anim_get_real_end_time(const rome2_l80_fx_ctx *fx, uint32_t self_va);
void rome2_l84_anim_set_audio_asset_pointer(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t pointer_va);
uint32_t rome2_l84_anim_get_anim_curve(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index);
uint32_t rome2_l84_anim_get_compressed_anim_curve(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index);
float rome2_l84_anim_get_curves_duration(const rome2_l80_fx_ctx *fx, uint32_t self_va);
float rome2_l84_anim_get_duration(const rome2_l80_fx_ctx *fx, uint32_t self_va);
float rome2_l84_anim_get_end_time(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_anim_get_event_template(uint32_t self_va);
float rome2_l84_anim_get_frame_rate(const rome2_l80_fx_ctx *fx, uint32_t self_va);

/*
 * FxActor (0x102e3420, 0x104447e0, 0x1054d6a0, 0x105d0f20, 0x10ed64a0, 0x10ed7390, 0x10ed75c0,
 * 0x10ed77e0, 0x10ed7860, 0x10ed7880, 0x10ed78d0).
 * Animation group indices: 0 is the default group, 1..count the owned
 * groups, and count + 1 onwards the mounted animation sets in list order.
 */
uint32_t rome2_l84_actor_get_decompiled_face_graph(uint32_t self_va);
uint32_t rome2_l84_actor_get_compiled_face_graph(uint32_t self_va);
uint8_t rome2_l84_actor_is_open_in_studio(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint8_t rome2_l84_actor_is_published(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_actor_find_anim_group(
    rome2_l81_fx_name_ctx *names,
    uint32_t self_va,
    const rome2_fx_name_32 *name);
uint32_t rome2_l84_actor_get_anim_group(rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index);
uint32_t rome2_l84_actor_get_bone(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index);
uint32_t rome2_l84_actor_get_editor_only_data(uint32_t self_va);
uint32_t rome2_l84_actor_get_num_anim_groups(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_actor_get_phoneme_map(uint32_t self_va);
uint8_t rome2_l84_actor_is_anim_group_mounted(
    rome2_l81_fx_name_ctx *names,
    uint32_t self_va,
    const rome2_fx_name_32 *name);

/*
 * FxActorInstance (0x10298bd0, 0x105421e0, 0x105d0bb0, 0x106364c0, 0x1085b040, 0x10a2a300,
 * 0x10ed7370, 0x10ed7600, 0x10ed7850, 0x10ed7870)
 */
uint32_t rome2_l84_actor_instance_get_weighted_bone_transforms(uint32_t self_va);
uint32_t rome2_l84_actor_instance_get_num_client_events(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint8_t rome2_l84_actor_instance_is_no_work_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint8_t rome2_l84_actor_instance_is_open_in_studio(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_actor_instance_get_max_num_client_events(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_actor_instance_get_curve_state_pool_length(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_actor_instance_get_accumulated_base_channel_track_values(uint32_t self_va);
uint32_t rome2_l84_actor_instance_get_bone_name(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index);
float rome2_l84_actor_instance_get_node_final_value(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index);
uint32_t rome2_l84_actor_instance_get_num_bones(const rome2_l80_fx_ctx *fx, uint32_t self_va);

/*
 * FxEventManager (0x101b0ee0, 0x105699b0, 0x10ed7de0, 0x10ed8360, 0x10ed8390, 0x10ed83c0,
 * 0x10ed86d0, 0x10ed8f50, 0x10ed8fa0, 0x10ed99c0, 0x10ed9a80).
 * The callback setters and FireCustomEventCallback are static members.
 */
float rome2_l84_event_manager_get_pause_time(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint8_t rome2_l84_event_manager_is_paused(const rome2_l80_fx_ctx *fx, uint32_t self_va);
uint32_t rome2_l84_event_manager_ctor(const rome2_l80_fx_ctx *fx, uint32_t self_va);
void rome2_l84_event_manager_clear_audio_callback(rome2_l84_fx_event_ctx *ctx);
void rome2_l84_event_manager_clear_custom_event_callback(rome2_l84_fx_event_ctx *ctx);
void rome2_l84_event_manager_fire_custom_event_callback(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t actor_instance_va,
    uint32_t event_va);
uint32_t rome2_l84_event_manager_get_client_event(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index);
uint8_t rome2_l84_event_manager_is_playing(rome2_l84_fx_event_ctx *ctx, uint32_t self_va, uint32_t event_id);
void rome2_l84_event_manager_pause(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t self_va,
    uint32_t actor_instance_va,
    float app_time);
void rome2_l84_event_manager_resume(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t self_va,
    uint32_t actor_instance_va,
    float app_time);
void rome2_l84_event_manager_set_audio_callback(rome2_l84_fx_event_ctx *ctx, uint32_t functor_va);

#endif
