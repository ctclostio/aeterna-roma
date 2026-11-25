#include "facefx_sdk_group_list_frame_ops.h"

#include <math.h>
#include <stddef.h>
#include <string.h>

/* Every product and sum of the frame bodies is its own single-precision SSE operation in the image. */
#if defined(_MSC_VER)
#pragma fp_contract(off)
#else
#pragma STDC FP_CONTRACT OFF
#endif

#define L85_OFFSET(type, field) ((uint32_t)offsetof(type, field))

/* ---- arena loads and stores; see the header for the out-of-arena rule ---- */

static uint32_t l85_load_u32(const rome2_l80_fx_ctx *fx, uint32_t va) {
    const void *p = rome2_l80_const_ptr(fx, va, 4u);
    uint32_t value = 0u;
    if (p != NULL) {
        memcpy(&value, p, sizeof(value));
    }
    return value;
}

static void l85_store_u32(const rome2_l80_fx_ctx *fx, uint32_t va, uint32_t value) {
    void *p = rome2_l80_mut_ptr(fx, va, 4u);
    if (p != NULL) {
        memcpy(p, &value, sizeof(value));
    }
}

static void l85_store_u8(const rome2_l80_fx_ctx *fx, uint32_t va, uint8_t value) {
    uint8_t *p = (uint8_t *)rome2_l80_mut_ptr(fx, va, 1u);
    if (p != NULL) {
        *p = value;
    }
}

static float l85_f32_from_bits(uint32_t bits) {
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static rome2_fx_list_node_32 *l85_list_node(const rome2_l80_fx_ctx *fx, uint32_t va) {
    return (rome2_fx_list_node_32 *)rome2_l80_mut_ptr(fx, va, (uint32_t)sizeof(rome2_fx_list_node_32));
}

static rome2_fx_avl_name_node_prefix_32 *l85_tree_node(const rome2_l80_fx_ctx *fx, uint32_t va) {
    return (rome2_fx_avl_name_node_prefix_32 *)rome2_l80_mut_ptr(
        fx, va, (uint32_t)sizeof(rome2_fx_avl_name_node_prefix_32));
}

static rome2_fx_name_32 *l85_name(const rome2_l80_fx_ctx *fx, uint32_t va) {
    return (rome2_fx_name_32 *)rome2_l80_mut_ptr(fx, va, (uint32_t)sizeof(rome2_fx_name_32));
}

/* ---- logging: every entry is gated on FxLogManager +0x84 >= level (signed) and indented by +0x88 ---- */

static rome2_fx_log_manager_32 *l85_log_manager(const rome2_l80_fx_ctx *fx) {
    if (fx->log_manager_singleton_va == 0u) {
        return NULL; /* bounded */
    }
    return (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(
        fx, fx->log_manager_singleton_va, (uint32_t)sizeof(rome2_fx_log_manager_32));
}

static rome2_fx_log_stream_32 *l85_log_open(rome2_l80_fx_ctx *fx, rome2_fx_log_entry_32 *entry, int32_t level) {
    const rome2_fx_log_manager_32 *mgr = l85_log_manager(fx);
    if (mgr == NULL || mgr->max_log_level < level) {
        return NULL;
    }
    (void)rome2_l80_log_entry_create(entry, fx->log_manager_singleton_va + 4u, level);
    return rome2_l80_log_entry_get_stream(entry, mgr->tab_level);
}

static void l85_log_line(rome2_l80_fx_ctx *fx, int32_t level, const char *text) {
    rome2_fx_log_entry_32 entry;
    rome2_fx_log_stream_32 *stream = l85_log_open(fx, &entry, level);
    if (stream != NULL) {
        (void)rome2_l80_log_stream_push_cstr(stream, text);
        rome2_l80_log_entry_dtor(fx, &entry);
    }
}

/* FxName::GetAsCstr (0x10edf6e0) on a guest FxName; an unresolvable name logs as empty text. */
static const char *l85_name_text(rome2_l81_fx_name_ctx *names, uint32_t name_va) {
    rome2_fx_name_32 *name = l85_name(names->fx, name_va);
    const char *text = (name != NULL) ? rome2_l81_fx_name_get_cstr(names, name) : NULL;
    return (text != NULL) ? text : "";
}

void rome2_l85_ctx_init(rome2_l85_fx_sdk_ctx *ctx, rome2_l80_fx_ctx *fx, rome2_l81_fx_name_ctx *names) {
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->fx = fx;
        ctx->names = names;
        ctx->log_error_on_animation_not_found = 1u;
    }
}

static int l85_ctx_ready(const rome2_l85_fx_sdk_ctx *ctx) {
    return ctx != NULL && ctx->fx != NULL && ctx->names != NULL && ctx->names->fx != NULL;
}

/* ---- FxClass and the FxObject type queries ---- */

/* 0x1033c6a0: CMP ECX, [ESP + 4]; SETZ AL. Class descriptors are compared by address. */
uint8_t rome2_l85_fx_class_equals(uint32_t self_va, uint32_t other_va) {
    return (uint8_t)(self_va == other_va);
}

/* 0x10ef2e80: walks the base-class chain at +8 from this descriptor; a NULL this is no kind of anything. */
uint8_t rome2_l85_fx_class_is_kind_of(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t class_va) {
    uint32_t steps = 0u;
    if (fx == NULL) {
        return 0u;
    }
    while (self_va != 0u) {
        const rome2_fx_class_32 *self;
        if (self_va == class_va) {
            return 1u;
        }
        self = (const rome2_fx_class_32 *)rome2_l80_const_ptr(fx, self_va, (uint32_t)sizeof(*self));
        if (self == NULL || ++steps > ROME2_L85_WALK_LIMIT) {
            return 0u; /* bounded */
        }
        self_va = self->base_class_va;
    }
    return 0u;
}

static uint32_t l85_class_desc(rome2_l85_fx_sdk_ctx *ctx, uint32_t object_va) {
    if (ctx == NULL || ctx->object_get_class_desc == NULL) {
        return 0u;
    }
    return ctx->object_get_class_desc(ctx, object_va);
}

/*
 * 0x10ed78b0: IsA and IsExactKindOf of FxActor, FxActorInstance, FxAnim,
 * FxAnimGroup and FxAnimSet. The object's class comes from vtable slot +0;
 * a NULL class answers 0, otherwise the body tail-jumps to 0x1033c6a0.
 */
uint8_t rome2_l85_fx_object_is_a(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t class_va) {
    uint32_t desc_va = l85_class_desc(ctx, self_va);
    if (desc_va == 0u) {
        return 0u;
    }
    return rome2_l85_fx_class_equals(desc_va, class_va);
}

/* 0x10ed7950: IsKindOf of the same five classes; tail-jumps to 0x10ef2e80. */
uint8_t rome2_l85_fx_object_is_kind_of(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t class_va) {
    uint32_t desc_va = l85_class_desc(ctx, self_va);
    if (ctx == NULL || desc_va == 0u) {
        return 0u;
    }
    return rome2_l85_fx_class_is_kind_of(ctx->fx, desc_va, class_va);
}

/* ---- FxNamedObject and the static class descriptors ---- */

/* 0x10ef3260: base bind (0x10ef3160), the class vtable, then the name copy-constructed from FxName::NullName. */
uint32_t rome2_l85_fx_named_object_ctor(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va) {
    rome2_fx_named_object_32 *self;
    if (!l85_ctx_ready(ctx)) {
        return 0u;
    }
    self = (rome2_fx_named_object_32 *)rome2_l80_mut_ptr(ctx->fx, self_va, (uint32_t)sizeof(*self));
    if (self == NULL) {
        return 0u; /* bounded */
    }
    (void)rome2_l81_fx_object_helper_bind(ctx->names, self_va);
    self->vtable_va = ROME2_FX_VTABLE_NAMED_OBJECT;
    (void)rome2_l81_fx_name_ctor_copy(ctx->names, &self->name, &ctx->names->null_name);
    return self_va;
}

/*
 * 0x10ef3310: FxAllocate(0x18) first; the FxObject descriptor at 0x11fadba4
 * is created on demand, then FxClass("FxNamedObject", 0, base, 8, 0x10ef3350).
 */
uint32_t rome2_l85_fx_named_object_static_class_init(rome2_l85_fx_sdk_ctx *ctx) {
    uint32_t block_va;
    if (!l85_ctx_ready(ctx)) {
        return 0u;
    }
    block_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_class_32));
    if (block_va == 0u) {
        return 0u;
    }
    if (ctx->names->fx_object_class_va == 0u) {
        ctx->names->fx_object_class_va = rome2_l81_fx_object_static_class_init(ctx->names);
    }
    return rome2_l81_fx_class_ctor(
        ctx->names, block_va, "FxNamedObject", 0u, ctx->names->fx_object_class_va,
        (uint32_t)sizeof(rome2_fx_named_object_32), ROME2_L85_VA_FX_NAMED_OBJECT_CONSTRUCT);
}

/*
 * The five AllocateStaticClass bodies: FxAllocate(0x18) first; the
 * FxNamedObject descriptor at 0x11fadba8 is created on demand and is the
 * base of each.
 */
static uint32_t l85_static_class_init(
    rome2_l85_fx_sdk_ctx *ctx,
    const char *name,
    uint16_t version,
    uint32_t size,
    uint32_t construct_fn_va) {
    uint32_t block_va;
    if (!l85_ctx_ready(ctx)) {
        return 0u;
    }
    block_va = rome2_l80_fx_allocate(ctx->fx, (uint32_t)sizeof(rome2_fx_class_32));
    if (block_va == 0u) {
        return 0u;
    }
    if (ctx->fx_named_object_class_va == 0u) {
        ctx->fx_named_object_class_va = rome2_l85_fx_named_object_static_class_init(ctx);
    }
    return rome2_l81_fx_class_ctor(
        ctx->names, block_va, name, version, ctx->fx_named_object_class_va, size, construct_fn_va);
}

/* 0x10ee2ad0: FxClass("FxAnim", 10, FxNamedObject, 0xf8, 0x10ed6440) */
uint32_t rome2_l85_fx_anim_static_class_init(rome2_l85_fx_sdk_ctx *ctx) {
    return l85_static_class_init(ctx, "FxAnim", 10u, 0xf8u, ROME2_L85_VA_FX_ANIM_CONSTRUCT);
}

/* 0x10ee5410: FxClass("FxAnimGroup", 1, FxNamedObject, 0x20, 0x10ed6460) */
uint32_t rome2_l85_fx_anim_group_static_class_init(rome2_l85_fx_sdk_ctx *ctx) {
    return l85_static_class_init(ctx, "FxAnimGroup", 1u, 0x20u, ROME2_L85_VA_FX_ANIM_GROUP_CONSTRUCT);
}

/* 0x10ee7570: FxClass("FxAnimSet", 1, FxNamedObject, 0x38, 0x10ed6480) */
uint32_t rome2_l85_fx_anim_set_static_class_init(rome2_l85_fx_sdk_ctx *ctx) {
    return l85_static_class_init(ctx, "FxAnimSet", 1u, 0x38u, ROME2_L85_VA_FX_ANIM_SET_CONSTRUCT);
}

/* 0x10ee8c10: FxClass("FxActor", 5, FxNamedObject, 0x6118, 0x10ed6420) */
uint32_t rome2_l85_fx_actor_static_class_init(rome2_l85_fx_sdk_ctx *ctx) {
    return l85_static_class_init(ctx, "FxActor", 5u, 0x6118u, ROME2_L85_VA_FX_ACTOR_CONSTRUCT);
}

/* 0x10eeae80: FxClass("FxActorInstance", 0, FxNamedObject, 0x11c, 0x100dbc00) */
uint32_t rome2_l85_fx_actor_instance_static_class_init(rome2_l85_fx_sdk_ctx *ctx) {
    return l85_static_class_init(ctx, "FxActorInstance", 0u, 0x11cu, ROME2_L85_VA_FX_ACTOR_INSTANCE_CONSTRUCT);
}

/* ---- FxString and FxName ---- */

/*
 * 0x10eda4c0: FxString::operator=(const FxString &). The body builds a
 * temporary copy and swaps it with *this. A source of 16 or more characters
 * gets FxAllocate(length + 1) and a terminator, and the block becomes the
 * destination's data. A shorter source is built in the temporary's inline
 * buffer and the swap moves exactly length bytes into the destination's
 * inline buffer: the byte after them, and every inline byte when the source
 * is empty, is left as it was. Capacity becomes length + 1, or 0 for an
 * empty source. The block *this owned is released with its old capacity.
 * Returns this.
 *
 * The temporary is not materialised for a short source: its length bytes
 * move straight into the destination's inline buffer, and the copy of the
 * destination's old inline bytes into the discarded temporary is dropped. A
 * source whose text is outside the arena, a failed allocation and a length
 * of 0xffffffff return with the destination untouched, where the original
 * faults.
 */
uint32_t rome2_l85_fx_string_assign(rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t other_va) {
    rome2_fx_string_32 *self;
    const rome2_fx_string_32 *other;
    const char *source = NULL;
    char *block = NULL;
    uint32_t length;
    uint32_t capacity;
    uint32_t block_va = 0u;
    uint32_t old_data_va;
    uint32_t old_capacity;
    int old_is_block;
    if (fx == NULL) {
        return self_va;
    }
    self = (rome2_fx_string_32 *)rome2_l80_mut_ptr(fx, self_va, (uint32_t)sizeof(*self));
    other = (const rome2_fx_string_32 *)rome2_l80_const_ptr(fx, other_va, (uint32_t)sizeof(*other));
    if (self == NULL || other == NULL) {
        return self_va; /* bounded */
    }
    length = other->length;
    capacity = (length != 0u) ? length + 1u : 0u;
    if (capacity <= (uint32_t)sizeof(self->inline_buf) && length >= (uint32_t)sizeof(self->inline_buf)) {
        return self_va; /* bounded: length 0xffffffff wraps the capacity to 0 */
    }
    if (length != 0u) {
        source = (const char *)rome2_l80_const_ptr(fx, other->data_va, length);
        if (source == NULL) {
            return self_va; /* bounded */
        }
    }
    if (capacity > (uint32_t)sizeof(self->inline_buf)) {
        block_va = rome2_l80_fx_allocate(fx, capacity);
        block = (block_va != 0u) ? (char *)rome2_l80_mut_ptr(fx, block_va, capacity) : NULL;
        if (block == NULL || source == NULL) {
            return self_va; /* bounded */
        }
        memcpy(block, source, length);
        block[length] = '\0';
    }

    old_data_va = self->data_va;
    old_capacity = self->capacity;
    old_is_block = (old_data_va != self_va);
    if (block_va != 0u) {
        self->data_va = block_va;
    } else {
        if (source != NULL) {
            memmove(self->inline_buf, source, length);
        }
        self->data_va = self_va;
    }
    self->capacity = capacity;
    self->length = length;
    if (old_is_block) {
        rome2_l80_fx_free(fx, old_data_va, old_capacity);
    }
    return self_va;
}

/*
 * 0x10edef40: FxName::DumpNameTableStatsToLog. A level-4 heading, the tab
 * level raised by one, the ten FxName::GetNameStats results as nine level-4
 * entries, and the tab level lowered again. The level is tested before the
 * heading and before each entry: a failed heading test skips the heading
 * alone, a failed entry test skips every entry after it. The two tab-level
 * calls are unconditional.
 */
void rome2_l85_fx_name_dump_stats_to_log(rome2_l81_fx_name_ctx *names) {
    static const struct {
        const char *prefix;
        const char *suffix;
    } lines[9] = {
        {NULL, " unique names"},
        {NULL, " peak collisions"},
        {NULL, " peak unique names"},
        {NULL, " peak probes"},
        {NULL, " used / "},
        {"minimum bin size: ", NULL},
        {"maximum bin size: ", NULL},
        {"average bin size: ", NULL},
        {NULL, " bytes used"},
    };
    rome2_l81_name_stats stats;
    rome2_fx_log_manager_32 *mgr;
    uint32_t values[9];
    uint32_t i;
    if (names == NULL || names->fx == NULL) {
        return;
    }
    mgr = l85_log_manager(names->fx);
    if (mgr == NULL) {
        return; /* bounded */
    }
    l85_log_line(names->fx, 4, "Name table stats:");
    rome2_l80_log_manager_set_tab_level(mgr, mgr->tab_level + 1u);
    memset(&stats, 0, sizeof(stats));
    rome2_l81_fx_name_get_stats(names, &stats);
    values[0] = stats.num_names;
    values[1] = stats.num_collisions;
    values[2] = stats.num_added;
    values[3] = stats.num_probes;
    values[4] = stats.non_empty_buckets;
    values[5] = stats.min_bucket_len;
    values[6] = stats.max_bucket_len;
    values[7] = stats.avg_bucket_len;
    values[8] = stats.mem_bytes;
    for (i = 0u; i < 9u; ++i) {
        rome2_fx_log_entry_32 entry;
        rome2_fx_log_stream_32 *stream = l85_log_open(names->fx, &entry, 4);
        if (stream == NULL) {
            break;
        }
        if (lines[i].prefix != NULL) {
            (void)rome2_l80_log_stream_push_cstr(stream, lines[i].prefix);
        }
        (void)rome2_l80_log_stream_push_int(stream, (int32_t)values[i]);
        if (lines[i].suffix != NULL) {
            (void)rome2_l80_log_stream_push_cstr(stream, lines[i].suffix);
        }
        if (i == 4u) {
            /* the used-bin count is followed by the bin total (the fifth GetNameStats result) */
            (void)rome2_l80_log_stream_push_int(stream, (int32_t)stats.bucket_count);
            (void)rome2_l80_log_stream_push_cstr(stream, " total hash bins");
        }
        rome2_l80_log_entry_dtor(names->fx, &entry);
    }
    rome2_l80_log_manager_set_tab_level(mgr, mgr->tab_level - 1u);
}

/* ---- FxResourceManager ---- */

/*
 * 0x10eda380: the singleton pointer 0x11bd14ac is set before anything else,
 * then the vtable; +4 receives a zeroed 0x14-byte state record, or 0 when
 * FxAllocate fails. The record's three pad bytes are not written.
 */
uint32_t rome2_l85_resource_manager_ctor(rome2_l80_fx_ctx *fx, uint32_t self_va) {
    rome2_fx_resource_manager_32 *self;
    rome2_fx_resource_manager_state_32 *state;
    uint32_t state_va;
    if (fx == NULL) {
        return self_va;
    }
    fx->resource_manager_singleton_va = self_va;
    self = (rome2_fx_resource_manager_32 *)rome2_l80_mut_ptr(fx, self_va, (uint32_t)sizeof(*self));
    if (self == NULL) {
        return self_va; /* bounded */
    }
    self->vtable_va = ROME2_FX_VTABLE_RESOURCE_MANAGER;
    state_va = rome2_l80_fx_allocate(fx, (uint32_t)sizeof(*state));
    if (state_va == 0u) {
        self->state_va = 0u;
        return self_va;
    }
    state = (rome2_fx_resource_manager_state_32 *)rome2_l80_mut_ptr(fx, state_va, (uint32_t)sizeof(*state));
    if (state == NULL) {
        return self_va; /* bounded */
    }
    state->field_00 = 0u;
    state->field_04 = 0u;
    state->field_08 = 0u;
    state->field_0c = 0u;
    state->automatic_garbage_collection = 0u;
    self->state_va = state_va;
    return self_va;
}

/* 0x10edd130: the flag byte at +0x10 of the state record */
void rome2_l85_resource_manager_set_automatic_garbage_collection(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    uint8_t enabled) {
    uint32_t state_va;
    if (fx == NULL) {
        return;
    }
    state_va = l85_load_u32(fx, self_va + L85_OFFSET(rome2_fx_resource_manager_32, state_va));
    l85_store_u8(
        fx, state_va + L85_OFFSET(rome2_fx_resource_manager_state_32, automatic_garbage_collection), enabled);
}

/* ---- FxEventManager and FxEvent ---- */

/*
 * 0x10f09320: bound_50 = range_min_10 * scale_24 + offset and bound_54 =
 * range_max_14 * scale_24 + offset; the offset is kept at +0x18. With a
 * negative scale the two bounds are stored in ascending order.
 */
void rome2_l85_event_set_time_range(const rome2_l80_fx_ctx *fx, uint32_t self_va, float offset) {
    rome2_fx_event_prefix_32 *self;
    float scale;
    float low;
    float high;
    if (fx == NULL) {
        return;
    }
    self = (rome2_fx_event_prefix_32 *)rome2_l80_mut_ptr(fx, self_va, (uint32_t)sizeof(*self));
    if (self == NULL) {
        return; /* bounded */
    }
    scale = self->scale_24;
    low = self->range_min_10 * scale + offset;
    high = self->range_max_14 * scale + offset;
    self->offset_18 = offset;
    self->bound_50 = low;
    self->bound_54 = high;
    if (0.0f > scale && low > high) {
        self->bound_50 = high;
        self->bound_54 = low;
    }
}

/*
 * 0x10ed8710: over the +0x24 slots whose flag byte is set. An event whose
 * time_88 still holds the -2147483648.0f sentinel is started first: time_90
 * takes offset_18, time_84 = time_90 + time, time_88 = time_84 less the
 * float at +0x24 of the linked object when there is one, and its range is
 * rebuilt with offset 0. The answer turns 1 at the first flagged event with
 * time >= time_84 and stays 1; a NaN on either side never sets it.
 */
uint8_t rome2_l85_event_manager_has_work_this_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va, float time) {
    const rome2_fx_event_manager_prefix_32 *self;
    uint8_t result = 0u;
    uint32_t count;
    uint32_t slot;
    if (fx == NULL) {
        return 0u;
    }
    self = (const rome2_fx_event_manager_prefix_32 *)rome2_l80_const_ptr(fx, self_va, (uint32_t)sizeof(*self));
    if (self == NULL) {
        return 0u; /* bounded */
    }
    count = self->active_flag_count;
    for (slot = 0u; slot < count; ++slot) {
        const uint8_t *flag = (const uint8_t *)rome2_l80_const_ptr(fx, self->active_flags_va + slot, 1u);
        rome2_fx_event_prefix_32 *event;
        uint32_t event_va;
        if (flag == NULL) {
            return result; /* bounded */
        }
        if (*flag == 0u) {
            continue;
        }
        event_va = self->events_va + slot * (uint32_t)sizeof(*event);
        event = (rome2_fx_event_prefix_32 *)rome2_l80_mut_ptr(fx, event_va, (uint32_t)sizeof(*event));
        if (event == NULL) {
            return result; /* bounded */
        }
        if (event->time_88 == ROME2_FX_INVALID_TIME) {
            memcpy(&event->time_90, &event->offset_18, sizeof(event->time_90));
            event->time_84 = event->time_90 + time;
            memcpy(&event->time_88, &event->time_84, sizeof(event->time_88));
            if (event->link_0c_va != 0u) {
                const void *linked = rome2_l80_const_ptr(
                    fx, event->link_0c_va + L85_OFFSET(rome2_fx_event_prefix_32, scale_24), 4u);
                float linked_value;
                if (linked == NULL) {
                    return result; /* bounded */
                }
                memcpy(&linked_value, linked, sizeof(linked_value));
                event->time_88 = event->time_88 - linked_value;
            }
            rome2_l85_event_set_time_range(fx, event_va, 0.0f);
        }
        if (time >= event->time_84) {
            result = 1u;
        }
    }
    return result;
}

/* The source functor's implementation cloned through its vtable slot +4, or 0 for an empty functor. */
static uint32_t l85_clone_functor_impl(rome2_l84_fx_event_ctx *ctx, uint32_t impl_va) {
    if (impl_va == 0u || ctx->functor_impl_clone == NULL) {
        return 0u;
    }
    return ctx->functor_impl_clone(ctx, impl_va);
}

/*
 * 0x10ed9af0: the custom-event twin of SetAudioCallback. The static at
 * 0x11fadb70 is loaded once. With a functor installed, the clone of the
 * argument's implementation is swapped in and the previous implementation
 * destroyed with flag 1; the static is not stored. Otherwise operator new(4)
 * runs first: on failure the static is stored as 0 and the argument is never
 * read, else the new functor receives the clone and becomes the static.
 */
void rome2_l85_event_manager_set_custom_event_callback(rome2_l84_fx_event_ctx *ctx, uint32_t functor_va) {
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
    installed_va = ctx->custom_event_callback_va;
    if (installed_va != 0u) {
        source = rome2_l80_const_ptr(ctx->fx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
        if (source == NULL) {
            return; /* bounded */
        }
        memcpy(&source_impl_va, source, sizeof(source_impl_va));
        new_impl_va = l85_clone_functor_impl(ctx, source_impl_va);
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
        ctx->custom_event_callback_va = 0u;
        return;
    }
    source = rome2_l80_const_ptr(ctx->fx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    target = rome2_l80_mut_ptr(ctx->fx, new_functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    if (source == NULL || target == NULL) {
        return; /* bounded */
    }
    memcpy(&source_impl_va, source, sizeof(source_impl_va));
    new_impl_va = l85_clone_functor_impl(ctx, source_impl_va);
    memcpy(target, &new_impl_va, sizeof(new_impl_va));
    ctx->custom_event_callback_va = new_functor_va;
}

/*
 * One half of Shutdown: the functor the static names on entry has its
 * implementation destroyed through vtable slot +0 with flag 1, is released
 * as 4 bytes, and the static is cleared. Returns 0 where the original faults.
 */
static int l85_release_callback(rome2_l84_fx_event_ctx *ctx, uint32_t *global_va) {
    const void *functor;
    uint32_t functor_va = *global_va;
    uint32_t impl_va;
    if (functor_va == 0u) {
        return 1;
    }
    functor = rome2_l80_const_ptr(ctx->fx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    if (functor == NULL) {
        return 0; /* bounded */
    }
    memcpy(&impl_va, functor, sizeof(impl_va));
    if (impl_va != 0u && ctx->functor_impl_destroy != NULL) {
        ctx->functor_impl_destroy(ctx, impl_va, 1u);
    }
    if (ctx->operator_delete != NULL) {
        ctx->operator_delete(ctx, functor_va, (uint32_t)sizeof(rome2_fx_functor_32));
    }
    *global_va = 0u;
    return 1;
}

/* 0x10ed9b60: releases the audio callback functor (0x11fadb6c), then the custom-event one (0x11fadb70). */
void rome2_l85_event_manager_shutdown(rome2_l84_fx_event_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (l85_release_callback(ctx, &ctx->audio_callback_va)) {
        (void)l85_release_callback(ctx, &ctx->custom_event_callback_va);
    }
}

/* ---- named records: FxAnim curves and the actor's bones ---- */

/*
 * The scan shared by 0x10ee3810, 0x10ee39d0 and 0x10efd5c0. The count is
 * read once; the array pointer is read again for every record. A record
 * name with a NULL entry is bound to FxName::NullName before it is compared
 * with the entry the argument holds at that moment. Returns the index, or
 * 0xffffffff.
 */
static uint32_t l85_find_named_record(
    rome2_l85_fx_sdk_ctx *ctx,
    uint32_t array_slot_va,
    uint32_t count_slot_va,
    uint32_t stride,
    uint32_t name_offset,
    uint32_t name_va) {
    uint32_t count;
    uint32_t index;
    if (!l85_ctx_ready(ctx)) {
        return 0xffffffffu;
    }
    count = l85_load_u32(ctx->fx, count_slot_va);
    for (index = 0u; index < count; ++index) {
        uint32_t array_va = l85_load_u32(ctx->fx, array_slot_va);
        rome2_fx_name_32 *record_name = l85_name(ctx->fx, array_va + index * stride + name_offset);
        const rome2_fx_name_32 *wanted = l85_name(ctx->fx, name_va);
        if (record_name == NULL || wanted == NULL) {
            return 0xffffffffu; /* bounded */
        }
        if (record_name->entry_va == 0u) {
            record_name->entry_va = ctx->names->null_name.entry_va;
        }
        if (record_name->entry_va == wanted->entry_va) {
            return index;
        }
    }
    return 0xffffffffu;
}

/* ---- FxAnim ---- */

/* 0x10ee37e0: destroys the object at +0xb0 through its vtable slot +8 with flag 1 and clears the pointer. */
uint8_t rome2_l85_anim_destroy_editor_only_data(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va) {
    uint32_t slot_va = self_va + L85_OFFSET(rome2_fx_anim_prefix_32, editor_only_data_va);
    uint32_t data_va;
    if (ctx == NULL || ctx->fx == NULL) {
        return 0u;
    }
    data_va = l85_load_u32(ctx->fx, slot_va);
    if (data_va == 0u) {
        return 0u;
    }
    if (ctx->object_destroy != NULL) {
        ctx->object_destroy(ctx, data_va, 1u);
    }
    l85_store_u32(ctx->fx, slot_va, 0u);
    return 1u;
}

/* 0x10ee3810: 0x28-byte records at +0x0c, count at +0x14 */
uint32_t rome2_l85_anim_find_anim_curve(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    return l85_find_named_record(
        ctx,
        self_va + L85_OFFSET(rome2_fx_anim_prefix_32, anim_curves_va),
        self_va + L85_OFFSET(rome2_fx_anim_prefix_32, anim_curve_count),
        (uint32_t)sizeof(rome2_fx_anim_curve_prefix_32),
        L85_OFFSET(rome2_fx_anim_curve_prefix_32, name),
        name_va);
}

/* 0x10ee39d0: 0x18-byte records at +0x18, count at +0x20 */
uint32_t rome2_l85_anim_find_compressed_anim_curve(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    return l85_find_named_record(
        ctx,
        self_va + L85_OFFSET(rome2_fx_anim_prefix_32, compressed_anim_curves_va),
        self_va + L85_OFFSET(rome2_fx_anim_prefix_32, compressed_anim_curve_count),
        (uint32_t)sizeof(rome2_fx_compressed_anim_curve_prefix_32),
        L85_OFFSET(rome2_fx_compressed_anim_curve_prefix_32, name),
        name_va);
}

/* 0x10ee47d0 */
void rome2_l85_anim_set_audio_asset_index(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t index) {
    if (fx != NULL) {
        l85_store_u32(fx, self_va + L85_OFFSET(rome2_fx_anim_prefix_32, audio_asset_index), index);
    }
}

/* 0x10ee47e0: ADD ECX, 0xd0; JMP 0x10eda4c0 */
uint32_t rome2_l85_anim_set_audio_asset_name(rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t string_va) {
    return rome2_l85_fx_string_assign(
        fx, self_va + L85_OFFSET(rome2_fx_anim_prefix_32, audio_asset_name), string_va);
}

/* 0x10ee47f0: ADD ECX, 0xb4; JMP 0x10eda4c0 */
uint32_t rome2_l85_anim_set_audio_asset_path(rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t string_va) {
    return rome2_l85_fx_string_assign(
        fx, self_va + L85_OFFSET(rome2_fx_anim_prefix_32, audio_asset_path), string_va);
}

/*
 * 0x10ee4840: a rate of 24.0f through 120.0f is stored at +0xf4 and answers
 * 1. Anything else, a NaN included, leaves the rate alone, logs a level-2
 * entry naming the animation and answers 0.
 */
uint8_t rome2_l85_anim_set_frame_rate(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, float frame_rate) {
    rome2_fx_log_entry_32 entry;
    rome2_fx_log_stream_32 *stream;
    if (!l85_ctx_ready(ctx)) {
        return 0u;
    }
    if (frame_rate >= ROME2_FX_MIN_FRAME_RATE && ROME2_FX_MAX_FRAME_RATE >= frame_rate) {
        void *slot = rome2_l80_mut_ptr(ctx->fx, self_va + L85_OFFSET(rome2_fx_anim_prefix_32, frame_rate), 4u);
        if (slot != NULL) {
            memcpy(slot, &frame_rate, sizeof(frame_rate));
        }
        return 1u;
    }
    stream = l85_log_open(ctx->fx, &entry, 2);
    if (stream != NULL) {
        (void)rome2_l80_log_stream_push_cstr(stream, "An attempt to set an invalid frame rate of ");
        (void)rome2_l80_log_stream_push_float(stream, frame_rate);
        (void)rome2_l80_log_stream_push_cstr(stream, " on animation \"");
        (void)rome2_l80_log_stream_push_cstr(
            stream, l85_name_text(ctx->names, self_va + L85_OFFSET(rome2_fx_anim_prefix_32, name)));
        (void)rome2_l80_log_stream_push_cstr(stream, "\" was ignored");
        rome2_l80_log_entry_dtor(ctx->fx, &entry);
    }
    return 0u;
}

/* ---- FxAnimGroup ---- */

/*
 * 0x10ee49f0: the FxNamedObject constructor, the class vtable, then the two
 * trees: root and count zeroed ahead of each tree's vtable.
 */
uint32_t rome2_l85_anim_group_ctor(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va) {
    rome2_fx_anim_group_prefix_32 *self;
    if (!l85_ctx_ready(ctx)) {
        return 0u;
    }
    self = (rome2_fx_anim_group_prefix_32 *)rome2_l80_mut_ptr(ctx->fx, self_va, (uint32_t)sizeof(*self));
    if (self == NULL) {
        return 0u; /* bounded */
    }
    (void)rome2_l85_fx_named_object_ctor(ctx, self_va);
    self->vtable_va = ROME2_FX_VTABLE_ANIM_GROUP;
    self->anims.root_va = 0u;
    self->anims.node_count = 0u;
    self->anims.vtable_va = ROME2_FX_VTABLE_ANIM_GROUP_TREE;
    self->sub_groups.root_va = 0u;
    self->sub_groups.node_count = 0u;
    self->sub_groups.vtable_va = ROME2_FX_VTABLE_ANIM_GROUP_TREE;
    return self_va;
}

/* The tree's first (left edge) or last (right edge) node; 0 for an empty tree. Returns 0 where the original faults. */
static int l85_tree_edge(const rome2_l80_fx_ctx *fx, uint32_t root_va, int right, uint32_t *edge_va) {
    uint32_t node_va = root_va;
    uint32_t steps = 0u;
    while (node_va != 0u) {
        const rome2_fx_avl_name_node_prefix_32 *node = l85_tree_node(fx, node_va);
        uint32_t next_va;
        if (node == NULL || ++steps > ROME2_L85_WALK_LIMIT) {
            return 0; /* bounded */
        }
        next_va = right ? node->right_va : node->left_va;
        if (next_va == 0u) {
            break;
        }
        node_va = next_va;
    }
    *edge_va = node_va;
    return 1;
}

static rome2_fx_tree_iterator_32 *l85_tree_begin(
    const rome2_l80_fx_ctx *fx,
    uint32_t tree_va,
    int right,
    rome2_fx_tree_iterator_32 *out) {
    const rome2_fx_avl_bucket_32 *tree;
    uint32_t node_va;
    if (fx == NULL || out == NULL) {
        return out;
    }
    tree = (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(fx, tree_va, (uint32_t)sizeof(*tree));
    if (tree == NULL || !l85_tree_edge(fx, tree->root_va, right, &node_va)) {
        return out; /* bounded */
    }
    out->tree_va = tree_va;
    out->node_va = node_va;
    return out;
}

/* 0x10ee5450: {anim tree, its leftmost node}; both the Iterator and the ConstIterator export */
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_begin_animations(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    rome2_fx_tree_iterator_32 *out) {
    return l85_tree_begin(fx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, anims), 0, out);
}

/* 0x10ee5490: {sub-group tree, its leftmost node} */
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_begin_sub_groups(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    rome2_fx_tree_iterator_32 *out) {
    return l85_tree_begin(fx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, sub_groups), 0, out);
}

/* 0x10ee55e0: {anim tree, 0}; EndAnimations and ReverseEndAnimations, const and not */
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_end_animations(uint32_t self_va, rome2_fx_tree_iterator_32 *out) {
    if (out != NULL) {
        out->tree_va = self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, anims);
        out->node_va = 0u;
    }
    return out;
}

/* 0x10ee5600: {sub-group tree, 0}; EndSubGroups and ReverseEndSubGroups, const and not */
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_end_sub_groups(uint32_t self_va, rome2_fx_tree_iterator_32 *out) {
    if (out != NULL) {
        out->tree_va = self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, sub_groups);
        out->node_va = 0u;
    }
    return out;
}

/* 0x10ee58c0: {anim tree, its rightmost node} */
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_reverse_begin_animations(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    rome2_fx_tree_iterator_32 *out) {
    return l85_tree_begin(fx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, anims), 1, out);
}

/* 0x10ee5900: {sub-group tree, its rightmost node} */
rome2_fx_tree_iterator_32 *rome2_l85_anim_group_reverse_begin_sub_groups(
    const rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    rome2_fx_tree_iterator_32 *out) {
    return l85_tree_begin(fx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, sub_groups), 1, out);
}

/*
 * In-order successor as Clear inlines it: the leftmost node of the right
 * subtree, else the first ancestor reached from its left child, else 0.
 */
static int l85_tree_successor(const rome2_l80_fx_ctx *fx, uint32_t *node_va) {
    const rome2_fx_avl_name_node_prefix_32 *node = l85_tree_node(fx, *node_va);
    uint32_t child_va;
    uint32_t parent_va;
    uint32_t steps = 0u;
    if (node == NULL) {
        return 0; /* bounded */
    }
    if (node->right_va != 0u) {
        return l85_tree_edge(fx, node->right_va, 0, node_va);
    }
    child_va = *node_va;
    parent_va = node->parent_va;
    while (parent_va != 0u) {
        node = l85_tree_node(fx, parent_va);
        if (node == NULL || ++steps > ROME2_L85_WALK_LIMIT) {
            return 0; /* bounded */
        }
        if (child_va != node->right_va) {
            break;
        }
        child_va = parent_va;
        parent_va = node->parent_va;
    }
    *node_va = parent_va;
    return 1;
}

static void l85_destroy_object(rome2_l85_fx_sdk_ctx *ctx, uint32_t object_va) {
    if (ctx->object_destroy != NULL) {
        ctx->object_destroy(ctx, object_va, 1u);
    }
}

static void l85_tree_clear(rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va) {
    if (ctx->tree_clear != NULL) {
        ctx->tree_clear(ctx, tree_va);
    }
}

static void l85_anim_group_clear(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t depth) {
    const rome2_fx_anim_group_prefix_32 *self =
        (const rome2_fx_anim_group_prefix_32 *)rome2_l80_const_ptr(ctx->fx, self_va, (uint32_t)sizeof(*self));
    uint32_t node_va;
    uint32_t steps = 0u;
    if (self == NULL || depth >= ROME2_L85_CLEAR_DEPTH_LIMIT) {
        return; /* bounded */
    }
    if (!l85_tree_edge(ctx->fx, self->anims.root_va, 0, &node_va)) {
        return; /* bounded */
    }
    while (node_va != 0u) {
        rome2_fx_avl_name_node_prefix_32 *node = l85_tree_node(ctx->fx, node_va);
        if (node == NULL || ++steps > ROME2_L85_WALK_LIMIT) {
            return; /* bounded */
        }
        if (node->value_va != 0u) {
            l85_destroy_object(ctx, node->value_va);
        }
        node->value_va = 0u;
        if (!l85_tree_successor(ctx->fx, &node_va)) {
            return; /* bounded */
        }
    }
    l85_tree_clear(ctx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, anims));

    if (!l85_tree_edge(ctx->fx, self->sub_groups.root_va, 0, &node_va)) {
        return; /* bounded */
    }
    steps = 0u;
    while (node_va != 0u) {
        rome2_fx_avl_name_node_prefix_32 *node = l85_tree_node(ctx->fx, node_va);
        if (node == NULL || node->value_va == 0u || ++steps > ROME2_L85_WALK_LIMIT) {
            return; /* bounded: the original clears through a NULL sub-group */
        }
        l85_anim_group_clear(ctx, node->value_va, depth + 1u);
        if (node->value_va != 0u) {
            l85_destroy_object(ctx, node->value_va);
        }
        node->value_va = 0u;
        if (!l85_tree_successor(ctx->fx, &node_va)) {
            return; /* bounded */
        }
    }
    l85_tree_clear(ctx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, sub_groups));
}

/*
 * 0x10ee54d0: every animation, in key order, is destroyed through its vtable
 * slot +8 with flag 1 and its node's value zeroed; the anim tree is emptied
 * through its vtable slot +4. Every sub-group is cleared by this same body,
 * destroyed the same way and zeroed, and the body leaves by tail-jumping to
 * slot +4 of the sub-group tree.
 */
void rome2_l85_anim_group_clear(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va) {
    if (ctx != NULL && ctx->fx != NULL) {
        l85_anim_group_clear(ctx, self_va, 0u);
    }
}

/* 0x10ee56f0: MOV AL, [0x11974fa0] */
uint8_t rome2_l85_anim_group_get_log_error_on_animation_not_found(const rome2_l85_fx_sdk_ctx *ctx) {
    return (ctx != NULL) ? ctx->log_error_on_animation_not_found : 0u;
}

/* 0x10ee5c50 */
void rome2_l85_anim_group_set_log_error_on_animation_not_found(rome2_l85_fx_sdk_ctx *ctx, uint8_t enabled) {
    if (ctx != NULL) {
        ctx->log_error_on_animation_not_found = enabled;
    }
}

/*
 * The search shared by 0x10ee5760, 0x10ee5810, 0x10ee6050 and 0x10ee63f0.
 * At each node the argument's NULL entry is bound to FxName::NullName; an
 * entry equal to the node's key ends the search. Otherwise the two names'
 * texts are compared as unsigned bytes: an argument that sorts lower goes
 * left, anything else, equal text included, goes right. Returns 0 where the
 * original faults.
 */
static int l85_tree_find(rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va, uint32_t name_va, uint32_t *found_va) {
    const rome2_fx_avl_bucket_32 *tree =
        (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(ctx->fx, tree_va, (uint32_t)sizeof(*tree));
    uint32_t node_va;
    uint32_t steps = 0u;
    if (tree == NULL) {
        return 0; /* bounded */
    }
    node_va = tree->root_va;
    while (node_va != 0u) {
        rome2_fx_avl_name_node_prefix_32 *node = l85_tree_node(ctx->fx, node_va);
        rome2_fx_name_32 *name = l85_name(ctx->fx, name_va);
        const char *node_text;
        const char *name_text;
        if (node == NULL || name == NULL || ++steps > ROME2_L85_WALK_LIMIT) {
            return 0; /* bounded */
        }
        if (name->entry_va == 0u) {
            name->entry_va = ctx->names->null_name.entry_va;
        }
        if (name->entry_va == node->key.entry_va) {
            break;
        }
        node_text = rome2_l81_fx_name_get_cstr(ctx->names, &node->key);
        name_text = rome2_l81_fx_name_get_cstr(ctx->names, name);
        if (node_text == NULL || name_text == NULL) {
            return 0; /* bounded */
        }
        node_va = (strcmp(name_text, node_text) < 0) ? node->left_va : node->right_va;
    }
    *found_va = node_va;
    return 1;
}

/*
 * RemoveAnim and RemoveSubGroup: the found node's value is read, then the
 * tree's vtable slot +0x10 is called whether or not a node was found.
 */
static uint32_t l85_tree_remove(rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va, uint32_t name_va) {
    const rome2_fx_avl_name_node_prefix_32 *node;
    uint32_t node_va;
    uint32_t value_va = 0u;
    if (!l85_ctx_ready(ctx) || !l85_tree_find(ctx, tree_va, name_va, &node_va)) {
        return 0u;
    }
    node = (node_va != 0u) ? l85_tree_node(ctx->fx, node_va) : NULL;
    if (node != NULL) {
        value_va = node->value_va;
    }
    if (ctx->tree_remove != NULL) {
        ctx->tree_remove(ctx, tree_va, node_va);
    }
    return value_va;
}

/* 0x10ee5760 */
uint32_t rome2_l85_anim_group_remove_anim(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    return l85_tree_remove(ctx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, anims), name_va);
}

/* 0x10ee5810 */
uint32_t rome2_l85_anim_group_remove_sub_group(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    return l85_tree_remove(ctx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, sub_groups), name_va);
}

/* 0x10ee5700: RemoveAnim, then the removed animation's vtable slot +8 with flag 1; answers whether one was removed. */
uint8_t rome2_l85_anim_group_remove_and_destroy_anim(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    uint32_t anim_va = rome2_l85_anim_group_remove_anim(ctx, self_va, name_va);
    if (anim_va != 0u) {
        l85_destroy_object(ctx, anim_va);
    }
    return (uint8_t)(anim_va != 0u);
}

/* 0x10ee5730: the same over RemoveSubGroup */
uint8_t rome2_l85_anim_group_remove_and_destroy_sub_group(
    rome2_l85_fx_sdk_ctx *ctx,
    uint32_t self_va,
    uint32_t name_va) {
    uint32_t group_va = rome2_l85_anim_group_remove_sub_group(ctx, self_va, name_va);
    if (group_va != 0u) {
        l85_destroy_object(ctx, group_va);
    }
    return (uint8_t)(group_va != 0u);
}

/*
 * _addAnim and _addSubGroup: a NULL value answers 0 without a call. Else the
 * tree's vtable slot +0xc receives the result iterator, the root slot
 * (tree + 4), the value's name (value + 4) and the value; the answer is
 * whether both dwords of the returned iterator are non-zero.
 */
static uint8_t l85_tree_add(rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va, uint32_t value_va) {
    rome2_fx_tree_iterator_32 result = {0u, 0u};
    if (ctx == NULL || value_va == 0u) {
        return 0u;
    }
    if (ctx->tree_insert != NULL) {
        ctx->tree_insert(
            ctx, tree_va, &result, tree_va + L85_OFFSET(rome2_fx_avl_bucket_32, root_va),
            value_va + L85_OFFSET(rome2_fx_named_object_32, name), value_va);
    }
    return (uint8_t)(result.tree_va != 0u && result.node_va != 0u);
}

/* 0x10ee5c60 */
uint8_t rome2_l85_anim_group_add_anim(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t anim_va) {
    return l85_tree_add(ctx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, anims), anim_va);
}

/* 0x10ee5cb0 */
uint8_t rome2_l85_anim_group_add_sub_group(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t group_va) {
    return l85_tree_add(ctx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, sub_groups), group_va);
}

/* _findAnim and _findSubGroup: the found node's value, or 0; the tree address itself is tested against NULL too. */
static uint32_t l85_tree_lookup(rome2_l85_fx_sdk_ctx *ctx, uint32_t tree_va, uint32_t name_va) {
    const rome2_fx_avl_name_node_prefix_32 *node;
    uint32_t node_va;
    if (!l85_ctx_ready(ctx) || !l85_tree_find(ctx, tree_va, name_va, &node_va)) {
        return 0u;
    }
    if (tree_va == 0u || node_va == 0u) {
        return 0u;
    }
    node = l85_tree_node(ctx->fx, node_va);
    return (node != NULL) ? node->value_va : 0u;
}

/* 0x10ee6050 */
uint32_t rome2_l85_anim_group_find_anim(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    return l85_tree_lookup(ctx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, anims), name_va);
}

/* 0x10ee63f0 */
uint32_t rome2_l85_anim_group_find_sub_group(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    return l85_tree_lookup(ctx, self_va + L85_OFFSET(rome2_fx_anim_group_prefix_32, sub_groups), name_va);
}

/* ---- FxList ---- */

/*
 * The sequence every list body inlines: a list with no sentinel gets one
 * from FxAllocate(0xc), linked to itself. The sentinel's item is never
 * written. Returns 0 where the original writes through a failed allocation.
 */
static uint32_t l85_list_head(rome2_l80_fx_ctx *fx, uint32_t list_va) {
    rome2_fx_list_32 *list = (rome2_fx_list_32 *)rome2_l80_mut_ptr(fx, list_va, (uint32_t)sizeof(*list));
    rome2_fx_list_node_32 *head;
    if (list == NULL) {
        return 0u; /* bounded */
    }
    if (list->head_va != 0u) {
        return list->head_va;
    }
    list->head_va = rome2_l80_fx_allocate(fx, (uint32_t)sizeof(*head));
    head = l85_list_node(fx, list->head_va);
    if (head == NULL) {
        return 0u; /* bounded */
    }
    head->next_va = list->head_va;
    head->prev_va = list->head_va;
    return list->head_va;
}

/* The first node from the sentinel onward that holds the item, or the sentinel. Returns 0 where the original faults. */
static int l85_list_scan(const rome2_l80_fx_ctx *fx, uint32_t head_va, uint32_t item_va, uint32_t *found_va) {
    const rome2_fx_list_node_32 *node = l85_list_node(fx, head_va);
    uint32_t node_va;
    uint32_t steps = 0u;
    if (node == NULL) {
        return 0; /* bounded */
    }
    for (node_va = node->next_va; node_va != head_va; node_va = node->next_va) {
        node = l85_list_node(fx, node_va);
        if (node == NULL || ++steps > ROME2_L85_WALK_LIMIT) {
            return 0; /* bounded */
        }
        if (node->item_va == item_va) {
            break;
        }
    }
    *found_va = node_va;
    return 1;
}

/* Appends ahead of the sentinel: FxAllocate(0xc), {item, sentinel, old tail}, both neighbours relinked, count + 1. */
static int l85_list_push_back(rome2_l80_fx_ctx *fx, uint32_t list_va, uint32_t head_va, uint32_t item_va) {
    uint32_t node_va = rome2_l80_fx_allocate(fx, (uint32_t)sizeof(rome2_fx_list_node_32));
    rome2_fx_list_node_32 *node = l85_list_node(fx, node_va);
    rome2_fx_list_node_32 *head = l85_list_node(fx, head_va);
    rome2_fx_list_node_32 *tail = (head != NULL) ? l85_list_node(fx, head->prev_va) : NULL;
    rome2_fx_list_32 *list = (rome2_fx_list_32 *)rome2_l80_mut_ptr(fx, list_va, (uint32_t)sizeof(*list));
    if (node_va == 0u || node == NULL || tail == NULL || list == NULL) {
        return 0; /* bounded */
    }
    node->item_va = item_va;
    node->next_va = head_va;
    node->prev_va = head->prev_va;
    tail->next_va = node_va;
    head->prev_va = node_va;
    list->count++;
    return 1;
}

/* Unlinks the node from both neighbours, releases its 0xc bytes and takes one off the count. */
static void l85_list_erase(rome2_l80_fx_ctx *fx, uint32_t list_va, uint32_t node_va) {
    const rome2_fx_list_node_32 *node = l85_list_node(fx, node_va);
    rome2_fx_list_node_32 *prev = (node != NULL) ? l85_list_node(fx, node->prev_va) : NULL;
    rome2_fx_list_node_32 *next = (node != NULL) ? l85_list_node(fx, node->next_va) : NULL;
    rome2_fx_list_32 *list = (rome2_fx_list_32 *)rome2_l80_mut_ptr(fx, list_va, (uint32_t)sizeof(*list));
    if (prev == NULL || next == NULL || list == NULL) {
        return; /* bounded */
    }
    prev->next_va = node->next_va;
    next->prev_va = node->prev_va;
    rome2_l80_fx_free(fx, node_va, (uint32_t)sizeof(*node));
    list->count--;
}

/*
 * 0x10ee75b0: FxList<T>::Find(Iterator *out, const T *value). *out walks
 * from the first node and is stored at every step; it ends on the node
 * holding *value, or on the sentinel. Returns out.
 */
uint32_t *rome2_l85_fx_list_find(
    rome2_l80_fx_ctx *fx,
    uint32_t list_va,
    uint32_t *out_node_va,
    const uint32_t *value) {
    uint32_t head_va;
    uint32_t found_va;
    if (fx == NULL || out_node_va == NULL || value == NULL) {
        return out_node_va;
    }
    head_va = l85_list_head(fx, list_va);
    if (head_va != 0u && l85_list_scan(fx, head_va, *value, &found_va)) {
        *out_node_va = found_va;
    }
    return out_node_va;
}

/* ---- FxAnimSet ---- */

/*
 * 0x10ee7460: an actor already in the reference list at +0x30 is reported
 * with a level-2 entry; otherwise it is appended.
 */
void rome2_l85_anim_set_add_reference(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t actor_va) {
    uint32_t list_va = self_va + L85_OFFSET(rome2_fx_anim_set_prefix_32, references);
    uint32_t found_va = 0u;
    uint32_t head_va;
    if (ctx == NULL || ctx->fx == NULL) {
        return;
    }
    (void)rome2_l85_fx_list_find(ctx->fx, list_va, &found_va, &actor_va);
    head_va = l85_list_head(ctx->fx, list_va);
    if (head_va == 0u || found_va == 0u) {
        return; /* bounded */
    }
    if (found_va != head_va) {
        l85_log_line(ctx->fx, 2, "FxAnimSet::AddReference: duplicate reference detected");
        return;
    }
    (void)l85_list_push_back(ctx->fx, list_va, head_va, actor_va);
}

/*
 * 0x10ee7670: an actor missing from the reference list is reported with a
 * level-2 entry and nothing is removed; otherwise its node is erased.
 */
void rome2_l85_anim_set_remove_reference(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t actor_va) {
    uint32_t list_va = self_va + L85_OFFSET(rome2_fx_anim_set_prefix_32, references);
    uint32_t found_va = 0u;
    uint32_t head_va;
    if (ctx == NULL || ctx->fx == NULL) {
        return;
    }
    (void)rome2_l85_fx_list_find(ctx->fx, list_va, &found_va, &actor_va);
    head_va = l85_list_head(ctx->fx, list_va);
    if (head_va == 0u || found_va == 0u) {
        return; /* bounded */
    }
    if (found_va == head_va) {
        l85_log_line(ctx->fx, 2, "FxAnimSet::RemoveReference: invalid reference detected");
        return;
    }
    l85_list_erase(ctx->fx, list_va, found_va);
}

/* 0x10ee7850: the byte at +8; the same body is FxActor::SetShouldClientRelink. */
void rome2_l85_anim_set_set_is_published(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint8_t value) {
    if (fx != NULL) {
        l85_store_u8(fx, self_va + L85_OFFSET(rome2_fx_anim_set_prefix_32, is_published), value);
    }
}

/* 0x10ee7860: ADD ECX, 0xc; JMP 0x10ede180 (FxName::operator=). Returns the assigned name's address. */
uint32_t rome2_l85_anim_set_set_owning_actor_name(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    uint32_t target_va = self_va + L85_OFFSET(rome2_fx_anim_set_prefix_32, owning_actor_name);
    rome2_fx_name_32 *target;
    const rome2_fx_name_32 *source;
    if (!l85_ctx_ready(ctx)) {
        return target_va;
    }
    target = l85_name(ctx->fx, target_va);
    source = l85_name(ctx->fx, name_va);
    if (target != NULL && source != NULL) {
        (void)rome2_l81_fx_name_assign_copy(ctx->names, target, source);
    }
    return target_va;
}

/* ---- FxActor ---- */

/* 0x10ed65a0: ADD ECX, 0xc; JMP 0x10efd5c0 */
uint32_t rome2_l85_actor_find_bone(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t name_va) {
    return rome2_l85_bone_table_find_bone(ctx, self_va + ROME2_FX_ACTOR_BONE_TABLE_OFFSET, name_va);
}

/* 0x10ed78a0: ADD ECX, 0xc; JMP 0x10efd610 */
void rome2_l85_actor_initialize_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t instance_va) {
    rome2_l85_bone_table_initialize_frame(fx, self_va + ROME2_FX_ACTOR_BONE_TABLE_OFFSET, instance_va);
}

/* 0x10ed7970: ADD ECX, 0xc; JMP 0x10efd630 */
void rome2_l85_actor_process_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint32_t instance_va) {
    rome2_l85_bone_table_process_frame(fx, self_va + ROME2_FX_ACTOR_BONE_TABLE_OFFSET, instance_va);
}

/* The level-4 entry AddInstance and RemoveInstance end with. */
static void l85_log_instance_change(
    rome2_l85_fx_sdk_ctx *ctx,
    const char *verb,
    const char *preposition,
    uint32_t self_va,
    uint32_t instance_va) {
    rome2_fx_log_entry_32 entry;
    rome2_fx_log_stream_32 *stream = l85_log_open(ctx->fx, &entry, 4);
    if (stream == NULL) {
        return;
    }
    (void)rome2_l80_log_stream_push_cstr(stream, verb);
    (void)rome2_l80_log_stream_push_ptr(stream, instance_va);
    (void)rome2_l80_log_stream_push_cstr(stream, preposition);
    (void)rome2_l80_log_stream_push_cstr(
        stream, l85_name_text(ctx->names, self_va + L85_OFFSET(rome2_fx_actor_prefix_32, name)));
    (void)rome2_l80_log_stream_push_cstr(stream, "\" [");
    (void)rome2_l80_log_stream_push_int(
        stream,
        (int32_t)l85_load_u32(
            ctx->fx,
            self_va + L85_OFFSET(rome2_fx_actor_prefix_32, instances) + L85_OFFSET(rome2_fx_list_32, count)));
    (void)rome2_l80_log_stream_push_cstr(stream, " instances].");
    rome2_l80_log_entry_dtor(ctx->fx, &entry);
}

/*
 * 0x10ee8a70: an instance already in the list at +0x60e8 is reported with a
 * level-3 entry; otherwise it is appended and a level-4 entry names the
 * instance, the actor and the new count.
 */
void rome2_l85_actor_add_instance(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t instance_va) {
    uint32_t list_va = self_va + L85_OFFSET(rome2_fx_actor_prefix_32, instances);
    uint32_t head_va;
    uint32_t found_va;
    if (!l85_ctx_ready(ctx)) {
        return;
    }
    head_va = l85_list_head(ctx->fx, list_va);
    if (head_va == 0u || !l85_list_scan(ctx->fx, head_va, instance_va, &found_va)) {
        return; /* bounded */
    }
    if (found_va != head_va) {
        l85_log_line(ctx->fx, 3, "Attempt to add duplicate actor instance!");
        return;
    }
    if (!l85_list_push_back(ctx->fx, list_va, head_va, instance_va)) {
        return; /* bounded */
    }
    l85_log_instance_change(ctx, "Added instance ", " to the actor named \"", self_va, instance_va);
}

/* 0x10ee9050 */
uint32_t rome2_l85_actor_get_instance_count(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    if (fx == NULL) {
        return 0u;
    }
    return l85_load_u32(
        fx, self_va + L85_OFFSET(rome2_fx_actor_prefix_32, instances) + L85_OFFSET(rome2_fx_list_32, count));
}

/* 0x10ee9060 */
uint32_t rome2_l85_actor_get_instances(uint32_t self_va) {
    return self_va + L85_OFFSET(rome2_fx_actor_prefix_32, instances);
}

/*
 * 0x10ee9b60: an instance missing from the list is reported with a level-3
 * entry; otherwise its node is erased and a level-4 entry names the
 * instance, the actor and the new count.
 */
void rome2_l85_actor_remove_instance(rome2_l85_fx_sdk_ctx *ctx, uint32_t self_va, uint32_t instance_va) {
    uint32_t list_va = self_va + L85_OFFSET(rome2_fx_actor_prefix_32, instances);
    uint32_t head_va;
    uint32_t found_va;
    if (!l85_ctx_ready(ctx)) {
        return;
    }
    head_va = l85_list_head(ctx->fx, list_va);
    if (head_va == 0u || !l85_list_scan(ctx->fx, head_va, instance_va, &found_va)) {
        return; /* bounded */
    }
    if (found_va == head_va) {
        l85_log_line(ctx->fx, 3, "Attempt to remove non-existing actor instance!");
        return;
    }
    l85_list_erase(ctx->fx, list_va, found_va);
    l85_log_instance_change(ctx, "Removed instance ", " from the actor named \"", self_va, instance_va);
}

/* 0x10eea2e0: the byte at +9 */
void rome2_l85_actor_set_is_open_in_studio(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint8_t value) {
    if (fx != NULL) {
        l85_store_u8(fx, self_va + L85_OFFSET(rome2_fx_actor_prefix_32, is_open_in_studio), value);
    }
}

/* 0x10eea2f0: the byte at +0xa */
void rome2_l85_actor_set_is_published(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint8_t value) {
    if (fx != NULL) {
        l85_store_u8(fx, self_va + L85_OFFSET(rome2_fx_actor_prefix_32, is_published), value);
    }
}

/* 0x10eea950: on a hit the node is stored through the iterator argument and 1 returned; a miss leaves it alone. */
uint8_t rome2_l85_actor_find_instance(
    rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    uint32_t instance_va,
    uint32_t *out_node_va) {
    uint32_t head_va;
    uint32_t found_va;
    if (fx == NULL) {
        return 0u;
    }
    head_va = l85_list_head(fx, self_va + L85_OFFSET(rome2_fx_actor_prefix_32, instances));
    if (head_va == 0u || !l85_list_scan(fx, head_va, instance_va, &found_va) || found_va == head_va) {
        return 0u;
    }
    if (out_node_va != NULL) {
        *out_node_va = found_va;
    }
    return 1u;
}

/* ---- the bone table at FxActor +0x0c ---- */

/* 0x10efd5c0: 0x40-byte records at +8, count at +0x10, name at record +8 */
uint32_t rome2_l85_bone_table_find_bone(rome2_l85_fx_sdk_ctx *ctx, uint32_t table_va, uint32_t name_va) {
    return l85_find_named_record(
        ctx,
        table_va + L85_OFFSET(rome2_fx_actor_bone_table_prefix_32, bone_records_va),
        table_va + L85_OFFSET(rome2_fx_actor_bone_table_prefix_32, bone_count),
        (uint32_t)sizeof(rome2_fx_actor_bone_record_32),
        L85_OFFSET(rome2_fx_actor_bone_record_32, bone_name),
        name_va);
}

/* The element pointer of the instance's weighted-bone-transform array, read from memory each time. */
static uint32_t l85_bone_output_va(const rome2_fx_actor_instance_prefix_32 *instance) {
    uint32_t va;
    memcpy(&va, instance->weighted_bone_transforms, sizeof(va));
    return va;
}

/*
 * 0x10efd610: memcpy(instance output, reference transforms, count * 0x2c).
 * The CRT routine at 0x116bd8d0 copes with overlap, so memmove is used.
 */
void rome2_l85_bone_table_initialize_frame(const rome2_l80_fx_ctx *fx, uint32_t table_va, uint32_t instance_va) {
    const rome2_fx_actor_bone_table_prefix_32 *table;
    const rome2_fx_actor_instance_prefix_32 *instance;
    const void *source;
    void *target;
    uint32_t bytes;
    if (fx == NULL) {
        return;
    }
    table = (const rome2_fx_actor_bone_table_prefix_32 *)rome2_l80_const_ptr(fx, table_va, (uint32_t)sizeof(*table));
    instance = (const rome2_fx_actor_instance_prefix_32 *)rome2_l80_const_ptr(
        fx, instance_va, (uint32_t)sizeof(*instance));
    if (table == NULL || instance == NULL) {
        return; /* bounded */
    }
    bytes = table->bone_count * (uint32_t)sizeof(rome2_fx_weighted_bone_transform_32);
    if (bytes == 0u) {
        return;
    }
    source = rome2_l80_const_ptr(fx, table->reference_bone_transforms_va, bytes);
    target = rome2_l80_mut_ptr(fx, l85_bone_output_va(instance), bytes);
    if (source == NULL || target == NULL) {
        return; /* bounded */
    }
    memmove(target, source, bytes);
}

/*
 * 0x10efd704..0x10efd9c8: the output transform restarts from the record's
 * reference transform; each link whose node value is not zero then adds its
 * scaled position and scale deltas and multiplies the rotation on the right
 * by (1 + w * v, x * v, y * v, z * v). A NaN node value is blended in like
 * any other. The rotation is rescaled by 1 / sqrt(n) unless its squared
 * length n lies strictly between 0.99999988 and 1.00000012.
 */
static int l85_recompute_bone(
    const rome2_l80_fx_ctx *fx,
    const rome2_fx_actor_instance_prefix_32 *instance,
    uint32_t record_va,
    uint32_t out_offset) {
    const rome2_fx_actor_bone_record_32 *record =
        (const rome2_fx_actor_bone_record_32 *)rome2_l80_const_ptr(fx, record_va, (uint32_t)sizeof(*record));
    rome2_fx_weighted_bone_transform_32 *out = (rome2_fx_weighted_bone_transform_32 *)rome2_l80_mut_ptr(
        fx, l85_bone_output_va(instance) + out_offset, (uint32_t)sizeof(*out));
    uint32_t remaining;
    uint32_t link_offset = 0u;
    float n;
    if (record == NULL || out == NULL) {
        return 0; /* bounded */
    }
    memmove(
        out, (const uint8_t *)record + offsetof(rome2_fx_actor_bone_record_32, reference_pos),
        offsetof(rome2_fx_weighted_bone_transform_32, weight));
    for (remaining = record->link_count; remaining != 0u; --remaining) {
        const rome2_fx_bone_link_32 *link = (const rome2_fx_bone_link_32 *)rome2_l80_const_ptr(
            fx, record->links_va + link_offset, (uint32_t)sizeof(*link));
        const void *value_slot;
        float v;
        float w;
        float x;
        float y;
        float z;
        float q0;
        float q1;
        float q2;
        float q3;
        link_offset += (uint32_t)sizeof(*link);
        if (link == NULL) {
            return 0; /* bounded */
        }
        value_slot = rome2_l80_const_ptr(fx, instance->node_final_values_va + link->node_index * 4u, 4u);
        out = (rome2_fx_weighted_bone_transform_32 *)rome2_l80_mut_ptr(
            fx, l85_bone_output_va(instance) + out_offset, (uint32_t)sizeof(*out));
        if (value_slot == NULL || out == NULL) {
            return 0; /* bounded */
        }
        memcpy(&v, value_slot, sizeof(v));
        if (v == 0.0f) {
            continue;
        }
        out->pos[0] = link->pos[0] * v + out->pos[0];
        out->pos[1] = link->pos[1] * v + out->pos[1];
        out->pos[2] = link->pos[2] * v + out->pos[2];
        w = link->rot[0] * v + 1.0f;
        x = link->rot[1] * v;
        y = link->rot[2] * v;
        z = link->rot[3] * v;
        q0 = out->rot[0];
        q1 = out->rot[1];
        q2 = out->rot[2];
        q3 = out->rot[3];
        out->rot[0] = ((q0 * w - q1 * x) - q2 * y) - q3 * z;
        out->rot[1] = ((x * q0 + q1 * w) + q2 * z) - q3 * y;
        out->rot[2] = ((y * q0 - z * q1) + q2 * w) + q3 * x;
        out->rot[3] = ((y * q1 + z * q0) - q2 * x) + q3 * w;
        out->scale[0] = link->scale[0] * v + out->scale[0];
        out->scale[1] = link->scale[1] * v + out->scale[1];
        out->scale[2] = link->scale[2] * v + out->scale[2];
    }
    n = ((out->rot[0] * out->rot[0] + out->rot[1] * out->rot[1]) + out->rot[2] * out->rot[2]) +
        out->rot[3] * out->rot[3];
    if (!(l85_f32_from_bits(ROME2_FX_QUAT_NORM_HIGH_BITS) > n) ||
        !(n > l85_f32_from_bits(ROME2_FX_QUAT_NORM_LOW_BITS))) {
        float inverse = 1.0f / sqrtf(n);
        out->rot[0] = inverse * out->rot[0];
        out->rot[1] = inverse * out->rot[1];
        out->rot[2] = inverse * out->rot[2];
        out->rot[3] = inverse * out->rot[3];
    }
    return 1;
}

/*
 * 0x10efd630: for each of the +0x10 bones (count read once, record array
 * read again per bone) the links are scanned for a node whose bit is set in
 * the instance's node bitset; the first hit recomputes the bone's output
 * transform. Whether or not that happened, a record whose weight node is
 * not 0xffffffff then has that node's value copied, as a dword, into the
 * output's weight.
 */
void rome2_l85_bone_table_process_frame(const rome2_l80_fx_ctx *fx, uint32_t table_va, uint32_t instance_va) {
    const rome2_fx_actor_bone_table_prefix_32 *table;
    const rome2_fx_actor_instance_prefix_32 *instance;
    uint32_t remaining;
    uint32_t record_offset = 0u;
    uint32_t out_offset = 0u;
    if (fx == NULL) {
        return;
    }
    table = (const rome2_fx_actor_bone_table_prefix_32 *)rome2_l80_const_ptr(fx, table_va, (uint32_t)sizeof(*table));
    if (table == NULL || table->bone_count == 0u) {
        return;
    }
    instance = (const rome2_fx_actor_instance_prefix_32 *)rome2_l80_const_ptr(
        fx, instance_va, (uint32_t)sizeof(*instance));
    if (instance == NULL) {
        return; /* bounded */
    }
    for (remaining = table->bone_count; remaining != 0u; --remaining) {
        uint32_t record_va = table->bone_records_va + record_offset;
        const rome2_fx_actor_bone_record_32 *record =
            (const rome2_fx_actor_bone_record_32 *)rome2_l80_const_ptr(fx, record_va, (uint32_t)sizeof(*record));
        uint32_t link_count;
        uint32_t link;
        int touched = 0;
        if (record == NULL) {
            return; /* bounded */
        }
        link_count = record->link_count;
        for (link = 0u; link < link_count; ++link) {
            const void *index_slot = rome2_l80_const_ptr(
                fx, record->links_va + link * (uint32_t)sizeof(rome2_fx_bone_link_32), 4u);
            const void *word_slot;
            uint32_t index;
            uint32_t word;
            if (index_slot == NULL) {
                return; /* bounded */
            }
            memcpy(&index, index_slot, sizeof(index));
            word_slot = rome2_l80_const_ptr(fx, instance->node_bitset_va + (index >> 5) * 4u, 4u);
            if (word_slot == NULL) {
                return; /* bounded */
            }
            memcpy(&word, word_slot, sizeof(word));
            if ((word & (1u << (index & 0x1fu))) != 0u) {
                touched = 1;
                break;
            }
        }
        if (touched && !l85_recompute_bone(fx, instance, record_va, out_offset)) {
            return; /* bounded */
        }
        record = (const rome2_fx_actor_bone_record_32 *)rome2_l80_const_ptr(
            fx, table->bone_records_va + record_offset, (uint32_t)sizeof(*record));
        if (record == NULL) {
            return; /* bounded */
        }
        if (record->weight_node_index != 0xffffffffu) {
            const void *value_slot = rome2_l80_const_ptr(
                fx, instance->node_final_values_va + record->weight_node_index * 4u, 4u);
            void *weight_slot = rome2_l80_mut_ptr(
                fx,
                l85_bone_output_va(instance) + out_offset + L85_OFFSET(rome2_fx_weighted_bone_transform_32, weight),
                4u);
            if (value_slot == NULL || weight_slot == NULL) {
                return; /* bounded */
            }
            memmove(weight_slot, value_slot, 4u);
        }
        record_offset += (uint32_t)sizeof(rome2_fx_actor_bone_record_32);
        out_offset += (uint32_t)sizeof(rome2_fx_weighted_bone_transform_32);
    }
}

/* ---- FxActorInstance ---- */

/*
 * 0x10ed7990: a handle whose count is 0xffffffff is already released. A
 * pooled handle has count bytes zeroed at pool + offset; a handle with a
 * block of its own and a non-zero count frees count * 0x30 bytes. The handle
 * ends as {0xffffffff, 0xffffffff, 0}.
 */
void rome2_l85_curve_state_cache_release(rome2_l80_fx_ctx *fx, uint32_t cache_va, uint32_t handle_va) {
    rome2_fx_cache_handle_32 *handle;
    uint32_t count;
    if (fx == NULL) {
        return;
    }
    handle = (rome2_fx_cache_handle_32 *)rome2_l80_mut_ptr(fx, handle_va, (uint32_t)sizeof(*handle));
    if (handle == NULL) {
        return; /* bounded */
    }
    count = handle->count;
    if (count == 0xffffffffu) {
        return;
    }
    if (handle->pool_offset != 0xffffffffu) {
        if (count != 0u) {
            void *states = rome2_l80_mut_ptr(fx, l85_load_u32(fx, cache_va) + handle->pool_offset, count);
            if (states == NULL) {
                return; /* bounded */
            }
            memset(states, 0, count);
        }
        count = handle->count;
    }
    if (count != 0u && handle->pool_offset == 0xffffffffu) {
        rome2_l80_fx_free(fx, handle->block_va, count * ROME2_FX_CURVE_STATE_BYTES);
    }
    handle->count = 0xffffffffu;
    handle->pool_offset = 0xffffffffu;
    handle->block_va = 0u;
}

/* 0x10ed7980: ADD ECX, 0x100; JMP 0x10ed7990 */
void rome2_l85_actor_instance_release_curve_state_handle(
    rome2_l80_fx_ctx *fx,
    uint32_t self_va,
    uint32_t handle_va) {
    rome2_l85_curve_state_cache_release(
        fx, self_va + L85_OFFSET(rome2_fx_actor_instance_prefix_32, curve_state_pool_va), handle_va);
}

/* 0x10eeaed0: zero-fills the +0x7c dwords at +0x78, then clears +0x74. */
void rome2_l85_actor_instance_end_frame(const rome2_l80_fx_ctx *fx, uint32_t self_va) {
    rome2_fx_actor_instance_prefix_32 *self;
    uint32_t bytes;
    if (fx == NULL) {
        return;
    }
    self = (rome2_fx_actor_instance_prefix_32 *)rome2_l80_mut_ptr(fx, self_va, (uint32_t)sizeof(*self));
    if (self == NULL) {
        return; /* bounded */
    }
    bytes = self->frame_word_count << 2;
    if (bytes != 0u) {
        void *words = rome2_l80_mut_ptr(fx, self->frame_words_va, bytes);
        if (words == NULL) {
            return; /* bounded */
        }
        memset(words, 0, bytes);
    }
    self->frame_state_74 = 0u;
}

/* 0x10eebbd0: the byte at +0xd */
void rome2_l85_actor_instance_set_is_open_in_studio(const rome2_l80_fx_ctx *fx, uint32_t self_va, uint8_t value) {
    if (fx != NULL) {
        l85_store_u8(fx, self_va + L85_OFFSET(rome2_fx_actor_instance_prefix_32, is_open_in_studio), value);
    }
}
