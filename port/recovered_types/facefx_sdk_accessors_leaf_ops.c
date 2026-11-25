#include "facefx_sdk_accessors_leaf_ops.h"

#include <stddef.h>
#include <string.h>

enum { L84_LIST_WALK_LIMIT = 0x10000 };

#define L84_OFFSET(type, field) ((uint32_t)offsetof(type, field))

/* ---- arena loads and stores; see the header for the out-of-arena rule ---- */

static uint32_t l84_load_u32(const rome2_l80_fx_ctx *fx, uint32_t va) {
    const void *p = rome2_l80_const_ptr(fx, va, 4u);
    uint32_t value = 0u;
    if (p != NULL) {
        memcpy(&value, p, sizeof(value));
    }
    return value;
}

static float l84_load_f32(const rome2_l80_fx_ctx *fx, uint32_t va) {
    const void *p = rome2_l80_const_ptr(fx, va, 4u);
    float value = 0.0f;
    if (p != NULL) {
        memcpy(&value, p, sizeof(value));
    }
    return value;
}

/*
 * FLD m32fp: the stored single reaches ST0 unchanged except that a signalling
 * NaN arrives quiet (bit 22 set), the masked invalid-operation response.
 */
static float l84_fld(float m32) {
    uint32_t bits;
    memcpy(&bits, &m32, sizeof(bits));
    if ((bits & 0x7f800000u) == 0x7f800000u && (bits & 0x007fffffu) != 0u) {
        bits |= 0x00400000u;
        memcpy(&m32, &bits, sizeof(m32));
    }
    return m32;
}

static uint8_t l84_load_u8(const rome2_l80_fx_ctx *fx, uint32_t va) {
    const uint8_t *p = (const uint8_t *)rome2_l80_const_ptr(fx, va, 1u);
    return (p != NULL) ? *p : 0u;
}

static void l84_store_u32(const rome2_l80_fx_ctx *fx, uint32_t va, uint32_t value) {
    void *p = rome2_l80_mut_ptr(fx, va, 4u);
    if (p != NULL) {
        memcpy(p, &value, sizeof(value));
    }
}

static rome2_fx_list_node_32 *l84_node(const rome2_l80_fx_ctx *fx, uint32_t va) {
    return (rome2_fx_list_node_32 *)rome2_l80_mut_ptr(fx, va, (uint32_t)sizeof(rome2_fx_list_node_32));
}

static rome2_fx_event_manager_prefix_32 *l84_manager(const rome2_l80_fx_ctx *fx, uint32_t va) {
    return (rome2_fx_event_manager_prefix_32 *)rome2_l80_mut_ptr(
        fx, va, (uint32_t)sizeof(rome2_fx_event_manager_prefix_32));
}

void rome2_l84_event_ctx_init(rome2_l84_fx_event_ctx *ctx, rome2_l80_fx_ctx *fx) {
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->fx = fx;
    }
}

/* ---- SDK version and error text ---- */

/* 0x10ed6680 */
uint32_t rome2_l84_fx_sdk_get_version(void) {
    return ROME2_FX_SDK_VERSION;
}

/* The 16 {int code; const char *text} rows at 0x1183a958, with each text's address. */
static const struct {
    int32_t code;
    uint32_t text_va;
    const char *text;
} l84_error_rows[ROME2_FX_ERROR_STRING_ROWS] = {
    {0, 0x1183a9d8u, "Success"},
    {1, 0x1183a9e0u, "Internal error"},
    {2, 0x1183a9f0u, "A parameter was null"},
    {3, 0x1183aa08u, "The archive store is invalid"},
    {4, 0x1183aa28u, "The archive store could not be opened for writing"},
    {5, 0x1183aa5cu, "The archive store could not be opened for reading"},
    {6, 0x1183aa90u, "The save operation was refused"},
    {7, 0x1183aab0u, "The archive is not a valid FaceFX archive"},
    {8, 0x1183aadcu, "The archive format is newer than the current FaceFX SDK"},
    {9, 0x1183ab14u, "The animation group already exists"},
    {10, 0x1183ab38u, "The animation group is not a mounted animation set"},
    {11, 0x1183ab70u, "The unmount operation was refused because an actor instance is currently playing an animation from the animation set"},
    {12, 0x1183abe8u, "Too many events during take creation"},
    {13, 0x1183ac10u, "Cannot create resource because a resource of the same type with the same key already exists"},
    {14, 0x1183ac70u, "One of the supplied resource parameters was not a managed resource"},
    {-1, 0x1178701cu, "UNKNOWN"},
};

/*
 * 0x10ed65b0: the scan starts from a literal 0 rather than row 0's code and
 * stops at the first code equal to the argument or to -1. Only the -1 stop
 * logs, so an argument of -1 is reported as unknown too. The level-1 entry
 * goes to the log at manager +4 when the manager's level is at least 1.
 * EAX is the stopping row's text pointer: the host copy of that text is
 * returned and its image address is stored through text_va.
 */
const char *rome2_l84_fx_sdk_get_error_string(rome2_l80_fx_ctx *fx, int32_t error, uint32_t *text_va) {
    uint32_t index = 0u;
    int32_t code = 0;
    while (code != error && index + 1u < ROME2_FX_ERROR_STRING_ROWS) {
        ++index;
        code = l84_error_rows[index].code;
        if (code == -1) {
            const rome2_fx_log_manager_32 *manager = (fx == NULL)
                ? NULL
                : (const rome2_fx_log_manager_32 *)rome2_l80_const_ptr(
                      fx, fx->log_manager_singleton_va, (uint32_t)sizeof(rome2_fx_log_manager_32));
            /* bounded: without a mapped manager the original faults on the level read */
            if (manager != NULL && manager->max_log_level >= 1) {
                rome2_fx_log_entry_32 entry;
                rome2_fx_log_stream_32 *stream;
                (void)rome2_l80_log_entry_create(&entry, fx->log_manager_singleton_va + 4u, 1);
                stream = rome2_l80_log_entry_get_stream(&entry, manager->tab_level);
                stream = rome2_l80_log_stream_push_cstr(stream, "Unknown FX_ERROR code: ");
                (void)rome2_l80_log_stream_push_int(stream, error);
                rome2_l80_log_entry_dtor(fx, &entry);
            }
            break;
        }
    }
    if (text_va != NULL) {
        *text_va = l84_error_rows[index].text_va;
    }
    return l84_error_rows[index].text;
}

/* ---- value types; a NULL operand returns early where the original faults ---- */

/* 0x10be8b50 */
rome2_fx_event_callback_param_32 *rome2_l84_event_callback_param_assign(
    rome2_fx_event_callback_param_32 *self,
    const rome2_fx_event_callback_param_32 *other) {
    if (self != NULL && other != NULL) {
        self->actor_instance_va = other->actor_instance_va;
        self->event_va = other->event_va;
    }
    return self;
}

/* 0x10ed5700: stamps the class vtable and copies the one data member. */
rome2_fx_resource_manager_32 *rome2_l84_resource_manager_ctor_copy(
    rome2_fx_resource_manager_32 *self,
    const rome2_fx_resource_manager_32 *other) {
    if (self != NULL && other != NULL) {
        self->vtable_va = ROME2_FX_VTABLE_RESOURCE_MANAGER;
        self->state_va = other->state_va;
    }
    return self;
}

/* 0x10ed59e0: the vtable slot is left alone. */
rome2_fx_resource_manager_32 *rome2_l84_resource_manager_assign(
    rome2_fx_resource_manager_32 *self,
    const rome2_fx_resource_manager_32 *other) {
    if (self != NULL && other != NULL) {
        self->state_va = other->state_va;
    }
    return self;
}

/* 0x10ed7bf0 */
uint8_t rome2_l84_mount_unmount_result_bool(const rome2_fx_mount_unmount_result_32 *self) {
    if (self == NULL) {
        return 0u;
    }
    return (self->mount_err == 0 && self->unmount_err == 0) ? 1u : 0u;
}

/* 0x10ed7c10: CMP dword [ECX], -1; SETNZ AL */
uint8_t rome2_l84_play_result_bool(const int32_t *self) {
    return (self != NULL && *self != -1) ? 1u : 0u;
}

/* ---- FxAnimSet ---- */

/* 0x100e80c0 */
uint32_t rome2_l84_anim_set_get_anim_group_name(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_set_prefix_32, anim_group) +
           L84_OFFSET(rome2_fx_anim_group_prefix_32, name);
}

/* 0x100e8110 */
uint32_t rome2_l84_anim_set_get_reference_count(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u32(
        fx, self_va + L84_OFFSET(rome2_fx_anim_set_prefix_32, references) + L84_OFFSET(rome2_fx_list_32, count));
}

/* 0x10170450 */
uint32_t rome2_l84_anim_set_get_owning_actor_name(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_set_prefix_32, owning_actor_name);
}

/* 0x1018aba0 */
uint32_t rome2_l84_anim_set_get_anim_group(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_set_prefix_32, anim_group);
}

/* 0x101a9b80 */
uint32_t rome2_l84_anim_set_get_references(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_set_prefix_32, references);
}

/* 0x1054d080 */
uint8_t rome2_l84_anim_set_is_published(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u8(fx, self_va + L84_OFFSET(rome2_fx_anim_set_prefix_32, is_published));
}

/* ---- FxAnim ---- */

/* 0x101db470 */
float rome2_l84_anim_get_curves_end_time(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_fld(l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, curves_end_time)));
}

/* 0x101f8940 */
uint32_t rome2_l84_anim_get_audio_asset_path(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_prefix_32, audio_asset_path);
}

/* 0x10228780 */
float rome2_l84_anim_get_real_start_time(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_fld(l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, real_start_time)));
}

/* 0x10298bc0 */
uint32_t rome2_l84_anim_get_phon_word_list(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_prefix_32, phon_word_list);
}

/* 0x10371c70 */
uint32_t rome2_l84_anim_get_audio_asset_index(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, audio_asset_index));
}

/* 0x103bf2c0 */
float rome2_l84_anim_get_curves_start_time(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_fld(l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, curves_start_time)));
}

/* 0x105e13a0 */
uint32_t rome2_l84_anim_get_event_take(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_prefix_32, event_take);
}

/* 0x10a281c0 */
uint32_t rome2_l84_anim_get_audio_asset_pointer(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, audio_asset_pointer_va));
}

/* 0x10a2d1e0 */
uint32_t rome2_l84_anim_get_editor_only_data(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, editor_only_data_va));
}

/* 0x10a34830 */
uint32_t rome2_l84_anim_get_audio_asset_name(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_prefix_32, audio_asset_name);
}

/* 0x10a9a5c0 */
float rome2_l84_anim_get_real_end_time(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_fld(l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, real_end_time)));
}

/* 0x10abed80 */
void rome2_l84_anim_set_audio_asset_pointer(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t pointer_va) {
    l84_store_u32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, audio_asset_pointer_va), pointer_va);
}

/* 0x10ed7380 */
uint32_t rome2_l84_anim_get_anim_curve(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, anim_curves_va)) +
           index * (uint32_t)ROME2_FX_ANIM_CURVE_BYTES;
}

/* 0x10ed76c0 */
uint32_t rome2_l84_anim_get_compressed_anim_curve(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, compressed_anim_curves_va)) +
           index * (uint32_t)ROME2_FX_COMPRESSED_ANIM_CURVE_BYTES;
}

/*
 * The three subtracting bodies below leave the x87 difference in ST0 at the
 * control word's precision. The value returned here is that difference
 * rounded to single, which is what a caller's FSTP m32 stores. A NaN operand
 * gives a quiet NaN; which payload survives when both operands are NaN is
 * not modelled.
 */

/* 0x10ed7770: curves start minus curves end, in that order. */
float rome2_l84_anim_get_curves_duration(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    float start = l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, curves_start_time));
    float end = l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, curves_end_time));
    return start - end;
}

/* 0x10ed7790: an animation whose real start and end both compare equal to zero lasts 1 - start. */
float rome2_l84_anim_get_duration(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    float start = l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, real_start_time));
    float end = l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, real_end_time));
    if (start == 0.0f && end == 0.0f) {
        return 1.0f - start;
    }
    return end - start;
}

/* 0x10ed77f0: the stored end is copied to the stack and returned through FLD. */
float rome2_l84_anim_get_end_time(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    float start = l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, real_start_time));
    float end = l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, real_end_time));
    if (start == 0.0f && end == 0.0f) {
        return 1.0f;
    }
    return l84_fld(end);
}

/* 0x10ed7830 */
uint32_t rome2_l84_anim_get_event_template(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_anim_prefix_32, event_template);
}

/* 0x10ed7840 */
float rome2_l84_anim_get_frame_rate(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_fld(l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_anim_prefix_32, frame_rate)));
}

/* ---- FxActor ---- */

/* 0x102e3420 */
uint32_t rome2_l84_actor_get_decompiled_face_graph(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_actor_prefix_32, decompiled_face_graph);
}

/* 0x104447e0 */
uint32_t rome2_l84_actor_get_compiled_face_graph(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_actor_prefix_32, compiled_face_graph);
}

/* 0x1054d6a0 */
uint8_t rome2_l84_actor_is_open_in_studio(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u8(fx, self_va + L84_OFFSET(rome2_fx_actor_prefix_32, is_open_in_studio));
}

/* 0x105d0f20 */
uint8_t rome2_l84_actor_is_published(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u8(fx, self_va + L84_OFFSET(rome2_fx_actor_prefix_32, is_published));
}

/*
 * The three list bodies below work on the whole actor record. An actor that
 * does not lie in the arena ends them at once, where the original faults on
 * its first load.
 */
static rome2_fx_actor_prefix_32 *l84_actor(const rome2_l80_fx_ctx *fx, uint32_t va) {
    return (rome2_fx_actor_prefix_32 *)rome2_l80_mut_ptr(fx, va, (uint32_t)sizeof(rome2_fx_actor_prefix_32));
}

/*
 * The mounted list's sentinel, created on first use: 0x10ed64a0, 0x10ed7390
 * and 0x10ed78d0 each inline FxAllocate(0xc), store the result in the actor,
 * zero both links and then point both at the node. The item slot keeps
 * whatever the allocator left there. Returns 0 when the allocation fails or
 * lies outside the arena, where the original writes the links regardless.
 */
static uint32_t l84_actor_mounted_head(rome2_l80_fx_ctx *fx, rome2_fx_actor_prefix_32 *actor) {
    rome2_fx_list_node_32 *head;
    if (actor->mounted_anim_sets.head_va != 0u) {
        return actor->mounted_anim_sets.head_va;
    }
    actor->mounted_anim_sets.head_va = rome2_l80_fx_allocate(fx, (uint32_t)sizeof(rome2_fx_list_node_32));
    head = l84_node(fx, actor->mounted_anim_sets.head_va);
    if (head == NULL) {
        return 0u;
    }
    head->next_va = actor->mounted_anim_sets.head_va;
    head->prev_va = actor->mounted_anim_sets.head_va;
    return actor->mounted_anim_sets.head_va;
}

/*
 * The FxName read the lookups inline: an empty name is first pointed at
 * FxName::NullName's entry (0x11fadb7c), with no reference added, and the
 * entry pointer is what gets compared. Returns 0 when the slot is unmapped.
 */
static int l84_name_entry(const rome2_l81_fx_name_ctx *names, uint32_t name_va, uint32_t *entry_va) {
    rome2_fx_name_32 *name = (rome2_fx_name_32 *)rome2_l80_mut_ptr(names->fx, name_va, (uint32_t)sizeof(*name));
    if (name == NULL) {
        return 0;
    }
    if (name->entry_va == 0u) {
        name->entry_va = names->null_name.entry_va;
    }
    *entry_va = name->entry_va;
    return 1;
}

/*
 * 0x10ed64a0: mounted animation sets are searched first and report
 * count + 1 + position, then the owned groups report position + 1, then the
 * default group reports 0. Every out-of-arena stop reports the miss value.
 */
uint32_t rome2_l84_actor_find_anim_group(
    rome2_l81_fx_name_ctx *names,
    uint32_t self_va,
    const rome2_fx_name_32 *name) {
    rome2_fx_actor_prefix_32 *actor;
    const rome2_fx_list_node_32 *node;
    uint32_t head_va;
    uint32_t count;
    uint32_t node_va;
    uint32_t position = 0u;
    uint32_t entry_va;
    uint32_t i;
    if (names == NULL || name == NULL) {
        return ROME2_FX_ANIM_GROUP_NOT_FOUND;
    }
    actor = l84_actor(names->fx, self_va);
    if (actor == NULL) {
        return ROME2_FX_ANIM_GROUP_NOT_FOUND;
    }
    count = actor->anim_group_count;
    head_va = l84_actor_mounted_head(names->fx, actor);
    node = l84_node(names->fx, head_va);
    if (node == NULL) {
        return ROME2_FX_ANIM_GROUP_NOT_FOUND;
    }
    for (node_va = node->next_va; node_va != head_va; node_va = node->next_va) {
        node = l84_node(names->fx, node_va);
        if (node == NULL || position >= L84_LIST_WALK_LIMIT ||
            !l84_name_entry(names, rome2_l84_anim_set_get_anim_group_name(node->item_va), &entry_va)) {
            return ROME2_FX_ANIM_GROUP_NOT_FOUND;
        }
        if (entry_va == name->entry_va) {
            return count + 1u + position;
        }
        ++position;
    }
    for (i = 0u; i < count;) {
        uint32_t name_va = actor->anim_groups_va + i * (uint32_t)sizeof(rome2_fx_anim_group_prefix_32) +
                           L84_OFFSET(rome2_fx_anim_group_prefix_32, name);
        if (!l84_name_entry(names, name_va, &entry_va)) {
            return ROME2_FX_ANIM_GROUP_NOT_FOUND;
        }
        ++i;
        if (entry_va == name->entry_va) {
            return i;
        }
    }
    if (actor->default_anim_group.name.entry_va == 0u) {
        actor->default_anim_group.name.entry_va = names->null_name.entry_va;
    }
    return (actor->default_anim_group.name.entry_va == name->entry_va) ? 0u : ROME2_FX_ANIM_GROUP_NOT_FOUND;
}

/*
 * 0x10ed7390: an index past the owned groups steps index - count - 1 links
 * from the first list node with no end-of-list test, so it can land on the
 * sentinel and wrap; the result is that node's item + 0x10 either way.
 * Out-of-arena stops and walks past the limit return 0.
 */
uint32_t rome2_l84_actor_get_anim_group(rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index) {
    rome2_fx_actor_prefix_32 *actor = l84_actor(fx, self_va);
    const rome2_fx_list_node_32 *node;
    uint32_t steps;
    if (actor == NULL) {
        return 0u;
    }
    if (index == 0u) {
        return self_va + L84_OFFSET(rome2_fx_actor_prefix_32, default_anim_group);
    }
    if (index <= actor->anim_group_count) {
        return actor->anim_groups_va + (index - 1u) * (uint32_t)sizeof(rome2_fx_anim_group_prefix_32);
    }
    steps = index - actor->anim_group_count - 1u;
    node = l84_node(fx, l84_actor_mounted_head(fx, actor));
    if (node == NULL || steps > L84_LIST_WALK_LIMIT) {
        return 0u;
    }
    node = l84_node(fx, node->next_va);
    for (; node != NULL && steps != 0u; --steps) {
        node = l84_node(fx, node->next_va);
    }
    if (node == NULL) {
        return 0u;
    }
    return rome2_l84_anim_set_get_anim_group(node->item_va);
}

/* 0x10ed75c0 */
uint32_t rome2_l84_actor_get_bone(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_actor_prefix_32, bone_records_va)) +
           L84_OFFSET(rome2_fx_actor_bone_record_32, bone_field_00) +
           index * (uint32_t)sizeof(rome2_fx_actor_bone_record_32);
}

/* 0x10ed77e0 */
uint32_t rome2_l84_actor_get_editor_only_data(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_actor_prefix_32, editor_only_data);
}

/* 0x10ed7860: owned groups, the default group, and the mounted list's count. */
uint32_t rome2_l84_actor_get_num_anim_groups(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_actor_prefix_32, anim_group_count)) + 1u +
           l84_load_u32(
               fx,
               self_va + L84_OFFSET(rome2_fx_actor_prefix_32, mounted_anim_sets) +
                   L84_OFFSET(rome2_fx_list_32, count));
}

/* 0x10ed7880 */
uint32_t rome2_l84_actor_get_phoneme_map(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_actor_prefix_32, phoneme_map);
}

/* 0x10ed78d0: the mounted-list half of FindAnimGroup; out-of-arena stops report 0. */
uint8_t rome2_l84_actor_is_anim_group_mounted(
    rome2_l81_fx_name_ctx *names,
    uint32_t self_va,
    const rome2_fx_name_32 *name) {
    rome2_fx_actor_prefix_32 *actor;
    const rome2_fx_list_node_32 *node;
    uint32_t head_va;
    uint32_t node_va;
    uint32_t steps = 0u;
    uint32_t entry_va;
    if (names == NULL || name == NULL) {
        return 0u;
    }
    actor = l84_actor(names->fx, self_va);
    if (actor == NULL) {
        return 0u;
    }
    head_va = l84_actor_mounted_head(names->fx, actor);
    node = l84_node(names->fx, head_va);
    if (node == NULL) {
        return 0u;
    }
    for (node_va = node->next_va; node_va != head_va; node_va = node->next_va) {
        node = l84_node(names->fx, node_va);
        if (node == NULL || steps++ >= L84_LIST_WALK_LIMIT ||
            !l84_name_entry(names, rome2_l84_anim_set_get_anim_group_name(node->item_va), &entry_va)) {
            return 0u;
        }
        if (entry_va == name->entry_va) {
            return 1u;
        }
    }
    return 0u;
}

/* ---- FxActorInstance ---- */

/* 0x10298bd0 */
uint32_t rome2_l84_actor_instance_get_weighted_bone_transforms(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, weighted_bone_transforms);
}

/* 0x105421e0 */
uint32_t rome2_l84_actor_instance_get_num_client_events(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, client_event_count));
}

/* 0x105d0bb0 */
uint8_t rome2_l84_actor_instance_is_no_work_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u8(fx, self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, is_no_work_frame));
}

/* 0x106364c0 */
uint8_t rome2_l84_actor_instance_is_open_in_studio(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u8(fx, self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, is_open_in_studio));
}

/* 0x1085b040 */
uint32_t rome2_l84_actor_instance_get_max_num_client_events(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, max_client_event_count));
}

/* 0x10a2a300 */
uint32_t rome2_l84_actor_instance_get_curve_state_pool_length(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, curve_state_pool_length));
}

/* 0x10ed7370 */
uint32_t rome2_l84_actor_instance_get_accumulated_base_channel_track_values(uint32_t self_va) {
    return self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, accumulated_base_channel_track_values);
}

/* 0x10ed7600: the instance's actor, then that actor's bone records. */
uint32_t rome2_l84_actor_instance_get_bone_name(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index) {
    uint32_t actor_va = l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, actor_va));
    return l84_load_u32(fx, actor_va + L84_OFFSET(rome2_fx_actor_prefix_32, bone_records_va)) +
           index * (uint32_t)sizeof(rome2_fx_actor_bone_record_32) +
           L84_OFFSET(rome2_fx_actor_bone_record_32, bone_name);
}

/* 0x10ed7850 */
float rome2_l84_actor_instance_get_node_final_value(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index) {
    uint32_t values_va =
        l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, node_final_values_va));
    return l84_fld(l84_load_f32(fx, values_va + index * 4u));
}

/* 0x10ed7870 */
uint32_t rome2_l84_actor_instance_get_num_bones(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    uint32_t actor_va = l84_load_u32(fx, self_va + L84_OFFSET(rome2_fx_actor_instance_prefix_32, actor_va));
    return l84_load_u32(fx, actor_va + L84_OFFSET(rome2_fx_actor_prefix_32, bone_count));
}

/* ---- FxEventManager ---- */

/* 0x101b0ee0 */
float rome2_l84_event_manager_get_pause_time(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_fld(l84_load_f32(fx, self_va + L84_OFFSET(rome2_fx_event_manager_prefix_32, pause_time)));
}

/* 0x105699b0 */
uint8_t rome2_l84_event_manager_is_paused(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    return l84_load_u8(fx, self_va + L84_OFFSET(rome2_fx_event_manager_prefix_32, paused));
}

/* 0x10ed7de0: three byte stores and fifteen dword stores; the nine pad bytes are not written. */
uint32_t rome2_l84_event_manager_ctor(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    rome2_fx_event_manager_prefix_32 *self = l84_manager(fx, self_va);
    if (self != NULL) {
        self->paused = 0u;
        self->pause_time = ROME2_FX_INVALID_TIME;
        self->field_08 = 0u;
        self->field_0c = 0u;
        self->events_va = 0u;
        self->field_14 = 0u;
        self->event_count = 0u;
        self->active_flags_va = 0u;
        self->field_20 = 0u;
        self->active_flag_count = 0u;
        self->field_28 = 0u;
        self->field_2c = 0u;
        self->field_30 = 0u;
        self->flag_34 = 1u;
        self->field_38 = 0u;
        self->field_3c = 0u;
        self->field_40 = 0u;
        self->flag_44 = 0u;
    }
    return self_va;
}

/*
 * 0x10ed8360 / 0x10ed8390: destroy the implementation through its vtable
 * slot +0 with flag 1, release the 4-byte functor, clear the global. The
 * global is read once (ESI) and that pointer is the one released, whatever
 * the destructor does to the global.
 */
static void l84_clear_callback(rome2_l84_fx_event_ctx *ctx, uint32_t *global_va) {
    const void *functor;
    uint32_t functor_va;
    uint32_t impl_va;
    if (ctx == NULL || *global_va == 0u) {
        return;
    }
    functor_va = *global_va;
    functor = rome2_l80_const_ptr(ctx->fx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    if (functor == NULL) {
        return; /* bounded */
    }
    memcpy(&impl_va, functor, sizeof(impl_va));
    if (impl_va != 0u && ctx->functor_impl_destroy != NULL) {
        ctx->functor_impl_destroy(ctx, impl_va, 1u);
    }
    if (ctx->operator_delete != NULL) {
        ctx->operator_delete(ctx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    }
    *global_va = 0u;
}

/* 0x10ed8360 */
void rome2_l84_event_manager_clear_audio_callback(rome2_l84_fx_event_ctx *ctx) {
    if (ctx != NULL) {
        l84_clear_callback(ctx, &ctx->audio_callback_va);
    }
}

/* 0x10ed8390 */
void rome2_l84_event_manager_clear_custom_event_callback(rome2_l84_fx_event_ctx *ctx) {
    if (ctx != NULL) {
        l84_clear_callback(ctx, &ctx->custom_event_callback_va);
    }
}

/*
 * Loads the functor's implementation pointer for an invoke through vtable
 * slot +8. Returns 0 for an unmapped functor or a NULL implementation, where
 * the original faults on the vtable read.
 */
static int l84_functor_impl(const rome2_l84_fx_event_ctx *ctx, uint32_t functor_va, uint32_t *impl_va) {
    const void *functor = rome2_l80_const_ptr(ctx->fx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    if (functor == NULL) {
        return 0;
    }
    memcpy(impl_va, functor, sizeof(*impl_va));
    return *impl_va != 0u;
}

/* 0x10ed83c0: builds {actor instance, event} on the stack and invokes the custom-event functor, if one is set. */
void rome2_l84_event_manager_fire_custom_event_callback(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t actor_instance_va,
    uint32_t event_va) {
    rome2_fx_event_callback_param_32 param;
    uint32_t impl_va;
    if (ctx == NULL || ctx->custom_event_callback_va == 0u) {
        return;
    }
    param.actor_instance_va = actor_instance_va;
    param.event_va = event_va;
    if (!l84_functor_impl(ctx, ctx->custom_event_callback_va, &impl_va)) {
        return; /* bounded */
    }
    if (ctx->custom_event_callback_invoke != NULL) {
        ctx->custom_event_callback_invoke(ctx, impl_va, &param);
    }
}

/* 0x10ed86d0: the index-th slot whose flag byte is non-zero, among the first event_count slots. */
uint32_t rome2_l84_event_manager_get_client_event(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index) {
    const rome2_fx_event_manager_prefix_32 *self = l84_manager(fx, self_va);
    uint32_t count;
    uint32_t flags_va;
    uint32_t active = 0u;
    uint32_t slot;
    if (self == NULL) {
        return 0u;
    }
    count = self->event_count;
    if (count == 0u) {
        return 0u;
    }
    flags_va = self->active_flags_va;
    for (slot = 0u; slot < count; ++slot) {
        const uint8_t *flag = (const uint8_t *)rome2_l80_const_ptr(fx, flags_va + slot, 1u);
        if (flag == NULL) {
            return 0u; /* bounded */
        }
        if (*flag != 0u) {
            if (active == index) {
                return slot * (uint32_t)sizeof(rome2_fx_event_prefix_32) + self->events_va;
            }
            ++active;
        }
    }
    return 0u;
}

/*
 * 0x10ed8f50: asks each slot's event for its id through vtable slot +0x30,
 * whether or not the slot is active, and returns the flag byte of the first
 * slot whose id matches. The count is re-read after every call.
 */
uint8_t rome2_l84_event_manager_is_playing(rome2_l84_fx_event_ctx *ctx, uint32_t self_va, uint32_t event_id) {
    const rome2_fx_event_manager_prefix_32 *self;
    uint32_t slot;
    if (ctx == NULL) {
        return 0u;
    }
    self = l84_manager(ctx->fx, self_va);
    if (self == NULL) {
        return 0u;
    }
    for (slot = 0u; slot < self->event_count; ++slot) {
        uint32_t event_va = self->events_va + slot * (uint32_t)sizeof(rome2_fx_event_prefix_32);
        uint32_t id;
        if (rome2_l80_const_ptr(ctx->fx, event_va, 4u) == NULL) {
            return 0u; /* bounded: the vtable read */
        }
        id = (ctx->event_get_id != NULL) ? ctx->event_get_id(ctx, event_va) : 0u;
        if (event_id == id) {
            return l84_load_u8(ctx->fx, self->active_flags_va + slot);
        }
    }
    return 0u;
}

/*
 * The audio functor call Pause and Resume share: {actor instance, event} and
 * the action are stack locals passed by address. Returns 0 where the
 * original faults.
 */
static int l84_invoke_audio_callback(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t functor_va,
    uint32_t actor_instance_va,
    uint32_t event_va,
    int32_t action) {
    rome2_fx_event_callback_param_32 param;
    uint32_t impl_va;
    param.actor_instance_va = actor_instance_va;
    param.event_va = event_va;
    if (!l84_functor_impl(ctx, functor_va, &impl_va)) {
        return 0;
    }
    if (ctx->audio_callback_invoke != NULL) {
        ctx->audio_callback_invoke(ctx, impl_va, &param, &action);
    }
    return 1;
}

/*
 * 0x10ed8fa0: a no-op while paused. Otherwise each of the first
 * active_flag_count slots with a non-zero flag gets the audio callback with
 * action 1, the functor global being re-read after every call, and then the
 * manager records the pause and its time.
 */
void rome2_l84_event_manager_pause(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t self_va,
    uint32_t actor_instance_va,
    float app_time) {
    rome2_fx_event_manager_prefix_32 *self;
    uint32_t count;
    uint32_t functor_va;
    uint32_t slot;
    if (ctx == NULL) {
        return;
    }
    self = l84_manager(ctx->fx, self_va);
    if (self == NULL || self->paused != 0u) {
        return;
    }
    count = self->active_flag_count;
    functor_va = (count != 0u) ? ctx->audio_callback_va : 0u;
    for (slot = 0u; slot < count; ++slot) {
        const uint8_t *flag = (const uint8_t *)rome2_l80_const_ptr(ctx->fx, self->active_flags_va + slot, 1u);
        if (flag == NULL) {
            return; /* bounded */
        }
        if (*flag != 0u && functor_va != 0u) {
            uint32_t event_va = self->events_va + slot * (uint32_t)sizeof(rome2_fx_event_prefix_32);
            if (!l84_invoke_audio_callback(
                    ctx, functor_va, actor_instance_va, event_va, ROME2_FX_AUDIO_CALLBACK_ACTION_ON_PAUSE)) {
                return; /* bounded */
            }
            functor_va = ctx->audio_callback_va;
        }
    }
    self->paused = 1u;
    self->pause_time = app_time;
}

/*
 * 0x10ed99c0: a no-op unless paused. Each active slot's event time at +0x88
 * moves forward by the paused span unless it holds the invalid-time value
 * (a NaN time is not equal to it and is rewritten too), then the audio
 * callback runs with action 2. Finally the pause flag clears and the pause
 * time returns to the invalid-time bits.
 */
void rome2_l84_event_manager_resume(
    rome2_l84_fx_event_ctx *ctx,
    uint32_t self_va,
    uint32_t actor_instance_va,
    float app_time) {
    rome2_fx_event_manager_prefix_32 *self;
    uint32_t count;
    uint32_t slot;
    if (ctx == NULL) {
        return;
    }
    self = l84_manager(ctx->fx, self_va);
    if (self == NULL || self->paused == 0u) {
        return;
    }
    count = self->active_flag_count;
    for (slot = 0u; slot < count; ++slot) {
        const uint8_t *flag = (const uint8_t *)rome2_l80_const_ptr(ctx->fx, self->active_flags_va + slot, 1u);
        uint32_t offset = slot * (uint32_t)sizeof(rome2_fx_event_prefix_32);
        void *time_slot;
        float event_time;
        if (flag == NULL) {
            return; /* bounded */
        }
        if (*flag == 0u) {
            continue;
        }
        time_slot = rome2_l80_mut_ptr(
            ctx->fx, self->events_va + offset + L84_OFFSET(rome2_fx_event_prefix_32, time_88), 4u);
        if (time_slot == NULL) {
            return; /* bounded */
        }
        memcpy(&event_time, time_slot, sizeof(event_time));
        if (event_time != ROME2_FX_INVALID_TIME) {
            event_time = (app_time - self->pause_time) + event_time;
            memcpy(time_slot, &event_time, sizeof(event_time));
        }
        if (ctx->audio_callback_va != 0u &&
            !l84_invoke_audio_callback(
                ctx,
                ctx->audio_callback_va,
                actor_instance_va,
                self->events_va + offset,
                ROME2_FX_AUDIO_CALLBACK_ACTION_ON_RESUME)) {
            return; /* bounded */
        }
    }
    self->paused = 0u;
    self->pause_time = ROME2_FX_INVALID_TIME;
}

/* The source functor's implementation cloned through its vtable slot +4, or 0 for an empty functor. */
static uint32_t l84_clone_functor_impl(rome2_l84_fx_event_ctx *ctx, uint32_t impl_va) {
    if (impl_va == 0u || ctx->functor_impl_clone == NULL) {
        return 0u;
    }
    return ctx->functor_impl_clone(ctx, impl_va);
}

/*
 * 0x10ed9a80: with a functor already installed, the clone of the argument's
 * implementation replaces the installed one, which is then destroyed with
 * flag 1. The installed functor is the one the global named on entry (ESI),
 * whatever the clone call does to the global. Otherwise a 4-byte functor is
 * allocated and receives the clone; a failed allocation leaves the global
 * NULL.
 */
void rome2_l84_event_manager_set_audio_callback(rome2_l84_fx_event_ctx *ctx, uint32_t functor_va) {
    const void *source;
    void *target;
    uint32_t source_impl_va;
    uint32_t new_impl_va;
    uint32_t old_impl_va;
    uint32_t new_functor_va;
    uint32_t installed_va;
    if (ctx == NULL) {
        return;
    }
    installed_va = ctx->audio_callback_va;
    if (installed_va != 0u) {
        source = rome2_l80_const_ptr(ctx->fx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
        if (source == NULL) {
            return; /* bounded */
        }
        memcpy(&source_impl_va, source, sizeof(source_impl_va));
        new_impl_va = l84_clone_functor_impl(ctx, source_impl_va);
        target = rome2_l80_mut_ptr(ctx->fx, installed_va, (uint32_t)sizeof(rome2_fx_functor_32));
        if (target == NULL) {
            return; /* bounded */
        }
        memcpy(&old_impl_va, target, sizeof(old_impl_va));
        memcpy(target, &new_impl_va, sizeof(new_impl_va));
        if (old_impl_va != 0u && ctx->functor_impl_destroy != NULL) {
            ctx->functor_impl_destroy(ctx, old_impl_va, 1u);
        }
        return;
    }
    new_functor_va = (ctx->operator_new != NULL)
        ? ctx->operator_new(ctx, (uint32_t)sizeof(rome2_fx_functor_32))
        : 0u;
    if (new_functor_va == 0u) {
        ctx->audio_callback_va = 0u;
        return;
    }
    source = rome2_l80_const_ptr(ctx->fx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    target = rome2_l80_mut_ptr(ctx->fx, new_functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    if (source == NULL || target == NULL) {
        return; /* bounded */
    }
    memcpy(&source_impl_va, source, sizeof(source_impl_va));
    new_impl_va = l84_clone_functor_impl(ctx, source_impl_va);
    memcpy(target, &new_impl_va, sizeof(new_impl_va));
    ctx->audio_callback_va = new_functor_va;
}
