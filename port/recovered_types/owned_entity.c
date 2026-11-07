/*
 * owned_entity - owning adapter over the bounded FUN_10cbe350 host projection.
 * See owned_entity.h for the contract.  This is ordinary host C17: it never
 * converts an original image address into a pointer and never reads the
 * data of an empty descriptor.
 */
#include "owned_entity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define OWNED_ENTITY_STATE_VACANT    UINT32_C(0)
#define OWNED_ENTITY_STATE_BUILDING  UINT32_C(0x424C4447)  /* never published */
#define OWNED_ENTITY_STATE_LIVE      UINT32_C(0x454E5459)

/* The nine string members of rome2_battle_entity, in record order. */
enum owned_entity_slot {
    SLOT_EFFECT_NAME = 0,
    SLOT_CATEGORY,
    SLOT_LABEL,
    SLOT_DESCRIPTOR_TEXT,
    SLOT_CLIMATE_NAME,
    SLOT_CLIMATE_NAME_ALT,
    SLOT_LABEL_ALT,
    SLOT_EFFECT_KIND,
    SLOT_SOURCE_NAME,
    SLOT_COUNT
};

struct rome2_owned_battle_entity {
    uint32_t state;                               /* VACANT/BUILDING/LIVE */
    uint32_t reserved;                            /* always 0 */
    const rome2_owned_battle_entity *self;        /* address binding */
    void *record_raw;                             /* exact allocate() result */
    size_t record_bytes;                          /* exact request */
    rome2_owned_string_allocator allocator;       /* captured at create */
    rome2_battle_entity entity;                   /* published projection */
    /* Release authority.  The published entity holds field-by-field copies
     * of these descriptors.  These records are never handed out. */
    rome2_host_string8 strings[SLOT_COUNT];
    rome2_owned_string_owner string_owners[SLOT_COUNT];
    rome2_owned_string8_vector item_strings;
    void *items_raw;                              /* native items array */
    size_t items_bytes;
};

#define RECORD_ALIGNMENT  ((size_t)_Alignof(rome2_owned_battle_entity))
#define VIEW_ALIGNMENT    ((size_t)_Alignof(rome2_host_string8))
#define ITEM_ALIGNMENT    ((size_t)_Alignof(rome2_recovered_str))

/* ------------------------------------------------------------------------ */
/* Helpers.                                                                  */
/* ------------------------------------------------------------------------ */

static void entity_slots(rome2_battle_entity *entity,
    rome2_recovered_str *slots[SLOT_COUNT])
{
    slots[SLOT_EFFECT_NAME] = &entity->effect_name;
    slots[SLOT_CATEGORY] = &entity->category;
    slots[SLOT_LABEL] = &entity->label;
    slots[SLOT_DESCRIPTOR_TEXT] = &entity->descriptor_text;
    slots[SLOT_CLIMATE_NAME] = &entity->climate.name;
    slots[SLOT_CLIMATE_NAME_ALT] = &entity->climate.name_alt;
    slots[SLOT_LABEL_ALT] = &entity->label_alt;
    slots[SLOT_EFFECT_KIND] = &entity->effect_kind;
    slots[SLOT_SOURCE_NAME] = &entity->source_name;
}

/* length >= 0, capacity >= length (so capacity >= 0), data set if nonempty. */
static bool string_is_well_formed(const rome2_recovered_str *s)
{
    return s->length >= 0 && s->capacity >= s->length &&
        (s->length == 0 || s->data != NULL);
}

/* Borrowed explicit-length view.  Empty never carries the source pointer,
 * which may be an image-sentinel identity that must not be dereferenced. */
static rome2_string8_view borrowed_view(const rome2_recovered_str *s)
{
    rome2_string8_view view;
    view.data = s->length > 0 ? s->data : NULL;
    view.length = (ptrdiff_t)s->length;
    return view;
}

/* count elements of element_size bytes plus slack for any raw alignment. */
static bool aligned_request(size_t count, size_t element_size,
    size_t alignment, size_t *bytes_out)
{
    const size_t slack = alignment - 1u;
    if (element_size == 0u || count > (SIZE_MAX - slack) / element_size) {
        return false;
    }
    *bytes_out = count * element_size + slack;
    return true;
}

/* First alignment boundary inside [raw, raw + alignment), with provenance
 * kept by pointer arithmetic on the allocation. */
static void *align_within(void *raw, size_t alignment)
{
    const size_t misalignment = (size_t)((uintptr_t)raw % alignment);
    return (unsigned char *)raw +
        (misalignment == 0u ? 0u : alignment - misalignment);
}

static void release_block(const rome2_owned_string_allocator *captured,
    void *raw, size_t bytes)
{
    captured->release(captured->context, raw, bytes,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
}

static rome2_owned_entity_status from_string_status(
    rome2_owned_string_status status)
{
    switch (status) {
    case ROME2_OWNED_STRING_OK:
        return ROME2_OWNED_ENTITY_OK;
    case ROME2_OWNED_STRING_ALLOCATION_FAILED:
        return ROME2_OWNED_ENTITY_ALLOCATION_FAILED;
    default:
        /* Every input was validated first, so any other status is a
         * broken invariant rather than a caller error. */
        return ROME2_OWNED_ENTITY_INTERNAL_ERROR;
    }
}

static bool record_is_live(const rome2_owned_battle_entity *h)
{
    const uintptr_t at = (uintptr_t)h;
    const uintptr_t raw = (uintptr_t)h->record_raw;
    size_t expected_bytes = 0u;

    if (h->state != OWNED_ENTITY_STATE_LIVE || h->reserved != 0u ||
        h->self != h || h->record_raw == NULL) {
        return false;
    }
    if (!aligned_request(1u, sizeof *h, RECORD_ALIGNMENT, &expected_bytes) ||
        h->record_bytes != expected_bytes || at < raw ||
        at - raw >= RECORD_ALIGNMENT) {
        return false;
    }
    if (h->allocator.allocate == NULL || h->allocator.release == NULL) {
        return false;
    }
    /* The published items/counts are never authority, including liveness.
     * The private string vector records the allocation's actual element count. */
    if (h->items_raw == NULL) {
        return h->items_bytes == 0u && h->item_strings.count == 0u;
    }
    return h->item_strings.count > 0u && h->item_strings.count <= ROME2_ENTITY_MAX_ITEM_COUNT &&
        aligned_request(h->item_strings.count, sizeof(rome2_recovered_str),
            ITEM_ALIGNMENT, &expected_bytes) && h->items_bytes == expected_bytes;
}

/*
 * Release everything a (partially) built record owns, exactly once, then the
 * record itself.  Owners that were never filled are canonical VACANT, and
 * destroying them is a no-op.  A corrupted owner is left unreleased (leaked)
 * and reported as INTERNAL_ERROR.
 */
static rome2_owned_entity_status discard_record(rome2_owned_battle_entity *h)
{
    const rome2_owned_string_allocator captured = h->allocator;
    void *const record_raw = h->record_raw;
    const size_t record_bytes = h->record_bytes;
    void *const items_raw = h->items_raw;
    const size_t items_bytes = h->items_bytes;
    rome2_owned_entity_status result = ROME2_OWNED_ENTITY_OK;
    rome2_recovered_str *published[SLOT_COUNT];
    size_t i;

    h->state = OWNED_ENTITY_STATE_VACANT;
    h->items_raw = NULL;
    h->items_bytes = 0u;
    memset(&h->entity, 0, sizeof h->entity);
    entity_slots(&h->entity, published);
    for (i = 0u; i < SLOT_COUNT; ++i) {
        published[i]->data = rome2_host_string8_empty_sentinel;
    }

    if (rome2_owned_string8_vector_destroy(&h->item_strings)
        != ROME2_OWNED_STRING_OK) {
        result = ROME2_OWNED_ENTITY_INTERNAL_ERROR;
    }
    for (i = 0u; i < SLOT_COUNT; ++i) {
        if (rome2_owned_string8_destroy(&h->strings[i], &h->string_owners[i])
            != ROME2_OWNED_STRING_OK) {
            result = ROME2_OWNED_ENTITY_INTERNAL_ERROR;
        }
    }
    if (items_raw != NULL) {
        release_block(&captured, items_raw, items_bytes);
    }
    /* Last: h is not touched after this call. */
    release_block(&captured, record_raw, record_bytes);
    return result;
}

/* ------------------------------------------------------------------------ */
/* Validation (no effects).                                                  */
/* ------------------------------------------------------------------------ */

static rome2_owned_entity_status validate_inputs(
    rome2_owned_battle_entity *const *out_handle,
    const rome2_entity_ctor_args *args,
    const rome2_owned_string_allocator *allocator,
    uint32_t *count_out,
    const rome2_recovered_str **items_out)
{
    const rome2_recovered_str *const strings[3] = {
        args != NULL ? args->arg00 : NULL,
        args != NULL ? args->arg11 : NULL,
        args != NULL ? args->arg17 : NULL
    };
    uint32_t count = 0u;
    const rome2_recovered_str *items = NULL;
    size_t i;

    if (out_handle == NULL || args == NULL) {
        return ROME2_OWNED_ENTITY_BAD_ARGUMENT;
    }
    if (allocator == NULL || allocator->allocate == NULL ||
        allocator->release == NULL) {
        return ROME2_OWNED_ENTITY_INVALID_ALLOCATOR;
    }
    for (i = 0u; i < sizeof strings / sizeof strings[0]; ++i) {
        if (strings[i] != NULL && !string_is_well_formed(strings[i])) {
            return ROME2_OWNED_ENTITY_MALFORMED_STRING;
        }
    }
    if (args->arg10 != NULL) {
        count = args->arg10->item_count;
        items = args->arg10->items;
    }
    if (count > ROME2_ENTITY_MAX_ITEM_COUNT) {
        return ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE;
    }
    if (count != 0u && items == NULL) {
        return ROME2_OWNED_ENTITY_MALFORMED_DESCRIPTOR;
    }
    for (i = 0u; i < (size_t)count; ++i) {
        if (!string_is_well_formed(&items[i])) {
            return ROME2_OWNED_ENTITY_MALFORMED_STRING;
        }
    }
    *count_out = count;
    *items_out = items;
    return ROME2_OWNED_ENTITY_OK;
}

/* ------------------------------------------------------------------------ */
/* Construction.                                                             */
/* ------------------------------------------------------------------------ */

/* Deep-copy the nine projected strings into the record's owners. */
static rome2_owned_entity_status own_scalar_strings(
    rome2_owned_battle_entity *h, rome2_recovered_str *const projected[SLOT_COUNT])
{
    size_t i;
    for (i = 0u; i < SLOT_COUNT; ++i) {
        const rome2_owned_entity_status status = from_string_status(
            rome2_owned_string8_copy(&h->strings[i], &h->string_owners[i],
                borrowed_view(projected[i]), &h->allocator));
        if (status != ROME2_OWNED_ENTITY_OK) {
            return status;
        }
    }
    return ROME2_OWNED_ENTITY_OK;
}

/*
 * Deep-copy the items into the owned vector, then build the native items
 * array by explicit field projection.  The owned vector copies from a
 * transient rome2_host_string8 view array, filled field by field from the
 * borrowed rome2_recovered_str sources and released on every route.
 */
static rome2_owned_entity_status own_items(rome2_owned_battle_entity *h,
    const rome2_recovered_str *source, uint32_t count,
    size_t view_bytes, size_t items_bytes, rome2_recovered_str **items_out)
{
    void *views_raw;
    rome2_host_string8 *views;
    rome2_recovered_str *items;
    rome2_owned_entity_status status;
    size_t i;

    *items_out = NULL;
    if (count == 0u) {
        return ROME2_OWNED_ENTITY_OK;
    }

    views_raw = h->allocator.allocate(h->allocator.context, view_bytes,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (views_raw == NULL) {
        return ROME2_OWNED_ENTITY_ALLOCATION_FAILED;
    }
    views = (rome2_host_string8 *)align_within(views_raw, VIEW_ALIGNMENT);
    for (i = 0u; i < (size_t)count; ++i) {
        const rome2_string8_view view = borrowed_view(&source[i]);
        views[i].length = source[i].length;
        views[i].capacity = source[i].length;
        views[i].data = view.data;
    }
    status = from_string_status(rome2_owned_string8_vector_copy(
        &h->item_strings, views, (size_t)count, &h->allocator));
    release_block(&h->allocator, views_raw, view_bytes);
    if (status != ROME2_OWNED_ENTITY_OK) {
        return status;
    }

    h->items_raw = h->allocator.allocate(h->allocator.context, items_bytes,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (h->items_raw == NULL) {
        return ROME2_OWNED_ENTITY_ALLOCATION_FAILED;
    }
    h->items_bytes = items_bytes;
    items = (rome2_recovered_str *)align_within(h->items_raw, ITEM_ALIGNMENT);
    for (i = 0u; i < (size_t)count; ++i) {
        items[i].length = h->item_strings.items[i].length;
        items[i].capacity = h->item_strings.items[i].capacity;
        items[i].data = h->item_strings.items[i].data;
    }
    *items_out = items;
    return ROME2_OWNED_ENTITY_OK;
}

rome2_owned_entity_status rome2_owned_battle_entity_create(
    rome2_owned_battle_entity **out_handle,
    const rome2_entity_ctor_args *args,
    const rome2_entity_globals *globals,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_allocator captured;
    rome2_entity_ctor_args scalar_args;
    rome2_entity_descriptor no_items;
    rome2_battle_entity projection;
    rome2_recovered_str *projected[SLOT_COUNT];
    rome2_recovered_str *published[SLOT_COUNT];
    rome2_recovered_str *items = NULL;
    const rome2_recovered_str *source_items = NULL;
    rome2_owned_battle_entity *h;
    void *record_raw;
    uint32_t count = 0u;
    size_t record_bytes = 0u;
    size_t view_bytes = 0u;
    size_t items_bytes = 0u;
    size_t i;
    rome2_owned_entity_status status;

    status = validate_inputs(out_handle, args, allocator, &count,
        &source_items);
    if (status != ROME2_OWNED_ENTITY_OK) {
        return status;
    }
    if (!aligned_request(1u, sizeof *h, RECORD_ALIGNMENT, &record_bytes)) {
        return ROME2_OWNED_ENTITY_INTERNAL_ERROR;
    }
    if (count != 0u &&
        (!aligned_request(count, sizeof(rome2_host_string8), VIEW_ALIGNMENT,
             &view_bytes) ||
         !aligned_request(count, sizeof(rome2_recovered_str), ITEM_ALIGNMENT,
             &items_bytes))) {
        return ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE;
    }

    /* The only read of the caller's allocator object. */
    captured = *allocator;

    /*
     * Scalar projection into private storage through the unchanged old
     * constructor.  The count-zero arg10 means it allocates nothing and needs
     * no host.  arg06..arg08 pass through unread.  Its string members, some of
     * them image-sentinel identities, are only ever read as {length, data}
     * for nonempty values, which are native literals or validated sources.
     */
    scalar_args = *args;
    no_items.reserved_00 = 0u;
    no_items.item_count = 0u;
    no_items.items = NULL;
    scalar_args.arg10 = &no_items;
    if (rome2_battle_entity_ctor(&projection, &scalar_args, globals, NULL)
        != &projection) {
        return ROME2_OWNED_ENTITY_INTERNAL_ERROR;
    }
    entity_slots(&projection, projected);
    for (i = 0u; i < SLOT_COUNT; ++i) {
        if (!string_is_well_formed(projected[i]) ||
            projected[i]->capacity != projected[i]->length) {
            return ROME2_OWNED_ENTITY_INTERNAL_ERROR;
        }
    }
    if (projection.items != NULL || projection.item_count != 0u) {
        return ROME2_OWNED_ENTITY_INTERNAL_ERROR;
    }

    /* Effects start here.  The record holds every owner, so it never moves. */
    record_raw = captured.allocate(captured.context, record_bytes,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (record_raw == NULL) {
        return ROME2_OWNED_ENTITY_ALLOCATION_FAILED;
    }
    h = (rome2_owned_battle_entity *)align_within(record_raw,
        RECORD_ALIGNMENT);
    /* All-zero: every string owner and the vector are canonical VACANT. */
    memset(h, 0, sizeof *h);
    h->state = OWNED_ENTITY_STATE_BUILDING;
    h->self = h;
    h->record_raw = record_raw;
    h->record_bytes = record_bytes;
    h->allocator = captured;

    status = own_scalar_strings(h, projected);
    if (status == ROME2_OWNED_ENTITY_OK) {
        status = own_items(h, source_items, count, view_bytes, items_bytes,
            &items);
    }
    if (status != ROME2_OWNED_ENTITY_OK) {
        const rome2_owned_entity_status cleanup = discard_record(h);
        return cleanup != ROME2_OWNED_ENTITY_OK ? cleanup : status;
    }

    /* Publish: scalars from the projection, every string replaced. */
    h->entity = projection;
    entity_slots(&h->entity, published);
    for (i = 0u; i < SLOT_COUNT; ++i) {
        published[i]->length = h->strings[i].length;
        published[i]->capacity = h->strings[i].capacity;
        published[i]->data = h->strings[i].data;
    }
    h->entity.item_count = count;
    h->entity.item_capacity = count;
    h->entity.items = items;
    h->state = OWNED_ENTITY_STATE_LIVE;
    *out_handle = h;
    return ROME2_OWNED_ENTITY_OK;
}

const rome2_battle_entity *rome2_owned_battle_entity_get(
    const rome2_owned_battle_entity *handle)
{
    if (handle == NULL || !record_is_live(handle)) {
        return NULL;
    }
    return &handle->entity;
}

rome2_owned_entity_status rome2_owned_battle_entity_copy(
    rome2_owned_battle_entity **out_handle,
    const rome2_battle_entity *source,
    const rome2_owned_string_allocator *allocator)
{
    rome2_entity_ctor_args args = {0};
    rome2_entity_descriptor items;
    rome2_owned_battle_entity *h = NULL;
    const rome2_recovered_str *input[4];
    const unsigned replace_slots[4] = {
        SLOT_CATEGORY, SLOT_LABEL, SLOT_DESCRIPTOR_TEXT, SLOT_CLIMATE_NAME_ALT
    };
    rome2_recovered_str *published[SLOT_COUNT];
    rome2_owned_entity_status status;
    size_t i;
    if (out_handle == NULL || source == NULL) {
        return ROME2_OWNED_ENTITY_BAD_ARGUMENT;
    }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) {
        return ROME2_OWNED_ENTITY_INVALID_ALLOCATOR;
    }
    status = rome2_battle_entity_copy_source_validate(source);
    if (status != ROME2_OWNED_ENTITY_OK) { return status; }
    input[0] = &source->category;
    input[1] = &source->label;
    input[2] = &source->descriptor_text;
    input[3] = &source->climate.name_alt;
    /* The common owner constructs exactly the two required literal names,
     * owns the last three input strings, and checks/copies every item before
     * publishing its local handle. No caller output is written yet. */
    items.reserved_00 = 0;
    items.item_count = source->item_count;
    items.items = source->items;
    args.arg00 = &source->label_alt;
    args.arg10 = &items;
    args.arg11 = &source->source_name;
    args.arg17 = &source->effect_kind;
    status = rome2_owned_battle_entity_create(&h, &args, NULL, allocator);
    if (status != ROME2_OWNED_ENTITY_OK) {
        return status;
    }
    h->state = OWNED_ENTITY_STATE_BUILDING;
    for (i = 0; i < 4; ++i) {
        const unsigned slot = replace_slots[i];
        status = from_string_status(rome2_owned_string8_destroy(
            &h->strings[slot], &h->string_owners[slot]));
        if (status == ROME2_OWNED_ENTITY_OK) {
            status = from_string_status(rome2_owned_string8_copy(
                &h->strings[slot], &h->string_owners[slot],
                borrowed_view(input[i]), &h->allocator));
        }
        if (status != ROME2_OWNED_ENTITY_OK) {
            const rome2_owned_entity_status cleanup = discard_record(h);
            return cleanup == ROME2_OWNED_ENTITY_OK ? status : cleanup;
        }
    }
    /* Only observed copy fields. Byte copies preserve opaque float patterns
     * without arithmetic and never copy the source's unobserved padding. */
#define COPY_FIELD(field) memcpy(&h->entity.field, &source->field, sizeof h->entity.field)
    COPY_FIELD(origin_x); COPY_FIELD(origin_y);
    COPY_FIELD(grid_extent_min); COPY_FIELD(grid_extent_max);
    COPY_FIELD(field_050);
    COPY_FIELD(activation_radius_min); COPY_FIELD(activation_radius_max);
    COPY_FIELD(point_count); COPY_FIELD(owner_id); COPY_FIELD(mode);
    COPY_FIELD(field_068); COPY_FIELD(owner_ref);
    COPY_FIELD(climate.grid_a); COPY_FIELD(climate.grid_b); COPY_FIELD(climate.grid_c);
    COPY_FIELD(tag_lo); COPY_FIELD(tag_hi);
    COPY_FIELD(flag_0cc); COPY_FIELD(flag_0dc);
    COPY_FIELD(field_0e0); COPY_FIELD(flag_0e4);
#undef COPY_FIELD
    entity_slots(&h->entity, published);
    for (i = 0; i < SLOT_COUNT; ++i) {
        published[i]->length = h->strings[i].length;
        published[i]->capacity = h->strings[i].capacity;
        published[i]->data = h->strings[i].data;
    }
    h->state = OWNED_ENTITY_STATE_LIVE;
    *out_handle = h;
    return ROME2_OWNED_ENTITY_OK;
}

rome2_owned_entity_status rome2_battle_entity_copy_source_validate(const rome2_battle_entity *source)
{
    const rome2_recovered_str *input[7];
    size_t i;
    if (source == NULL) { return ROME2_OWNED_ENTITY_BAD_ARGUMENT; }
    input[0] = &source->category; input[1] = &source->label;
    input[2] = &source->descriptor_text; input[3] = &source->climate.name_alt;
    input[4] = &source->label_alt; input[5] = &source->effect_kind;
    input[6] = &source->source_name;
    for (i = 0; i < 7; ++i) {
        if (!string_is_well_formed(input[i])) { return ROME2_OWNED_ENTITY_MALFORMED_STRING; }
    }
    if (source->item_count > ROME2_ENTITY_MAX_ITEM_COUNT) { return ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE; }
    if (source->item_count != 0 && source->items == NULL) { return ROME2_OWNED_ENTITY_MALFORMED_DESCRIPTOR; }
    for (i = 0; i < source->item_count; ++i) {
        if (!string_is_well_formed(&source->items[i])) { return ROME2_OWNED_ENTITY_MALFORMED_STRING; }
    }
    return ROME2_OWNED_ENTITY_OK;
}

rome2_owned_entity_status rome2_owned_battle_entity_destroy(
    rome2_owned_battle_entity **handle)
{
    rome2_owned_battle_entity *h;

    if (handle == NULL) {
        return ROME2_OWNED_ENTITY_BAD_ARGUMENT;
    }
    h = *handle;
    if (h == NULL) {
        return ROME2_OWNED_ENTITY_OK;
    }
    if (!record_is_live(h)) {
        return ROME2_OWNED_ENTITY_INVALID_HANDLE;
    }
    *handle = NULL;
    return discard_record(h);
}
