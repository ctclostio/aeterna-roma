#include "owned_unit_card.h"

#include <stdbool.h>
#include <string.h>

#define CARD_BUILDING UINT32_C(0x43424c44)
#define CARD_LIVE UINT32_C(0x55434152)

struct rome2_owned_unit_card {
    uint32_t state, reserved;
    const rome2_owned_unit_card *self;
    void *raw;
    rome2_owned_string_allocator allocator;
    rome2_owned_u32_vector *words;
    rome2_owned_float2_vector *coordinates;
    rome2_owned_unit_card_tag *tag;
    rome2_owned_battle_entity *attachment;
    rome2_owned_fauna_vector *fauna;
    rome2_host_string16 text;
    rome2_owned_string_owner text_owner;
    rome2_native_unit_card view;
};

_Static_assert(_Alignof(rome2_owned_unit_card) == 8, "unit-card owner alignment");

static void *align_storage(void *raw)
{
    const size_t residue = (size_t)((uintptr_t)raw % 8u);
    return (unsigned char *)raw + (residue == 0 ? 0 : 8u - residue);
}
static bool live(const rome2_owned_unit_card *h)
{
    return h != NULL && h->state == CARD_LIVE && h->reserved == 0 &&
        h->self == h && h->raw != NULL && align_storage(h->raw) == h &&
        h->allocator.allocate != NULL && h->allocator.release != NULL;
}
static rome2_unit_card_status scalar_status(rome2_scalar_vector_status s)
{
    switch (s) {
    case ROME2_SCALAR_VECTOR_OK: return ROME2_UNIT_CARD_OK;
    case ROME2_SCALAR_VECTOR_ALLOCATION_FAILED: return ROME2_UNIT_CARD_ALLOCATION_FAILED;
    case ROME2_SCALAR_VECTOR_COUNT_OUT_OF_RANGE: return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
    default: return ROME2_UNIT_CARD_INTERNAL_ERROR;
    }
}
static rome2_unit_card_status fauna_status(rome2_fauna_status s)
{
    switch (s) {
    case ROME2_FAUNA_OK: return ROME2_UNIT_CARD_OK;
    case ROME2_FAUNA_ALLOCATION_FAILED: return ROME2_UNIT_CARD_ALLOCATION_FAILED;
    case ROME2_FAUNA_COUNT_OUT_OF_RANGE: return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
    case ROME2_FAUNA_BAD_ARGUMENT:
    case ROME2_FAUNA_MALFORMED_STRING: return ROME2_UNIT_CARD_MALFORMED_SOURCE;
    default: return ROME2_UNIT_CARD_INTERNAL_ERROR;
    }
}
static rome2_unit_card_status validate_config(const rome2_fauna_vector_view *source)
{
    uint32_t i, capacity = 1;
    if (source == NULL) { return ROME2_UNIT_CARD_CONFIG_REQUIRED; }
    if (source->count > ROME2_FAUNA_MAX_CAPACITY) { return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE; }
    while (capacity < source->count) {
        if (capacity > ROME2_FAUNA_MAX_CAPACITY / 2u) { return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE; }
        capacity *= 2u;
    }
    if (source->count != 0 && source->items == NULL) { return ROME2_UNIT_CARD_MALFORMED_SOURCE; }
    for (i = 0; i < source->count; ++i) {
        const rome2_unit_card_status status = fauna_status(rome2_fauna_record_validate(&source->items[i]));
        if (status != ROME2_UNIT_CARD_OK) { return status; }
    }
    return ROME2_UNIT_CARD_OK;
}

static bool synchronize(rome2_owned_unit_card *h)
{
    const rome2_u32_vector_view *words = rome2_owned_u32_vector_get(h->words);
    const rome2_float2_vector_view *coordinates = rome2_owned_float2_vector_get(h->coordinates);
    const rome2_fauna_vector_view *fauna = rome2_owned_fauna_vector_get(h->fauna);
    const rome2_unit_card_tag *tag = rome2_owned_unit_card_tag_get(h->tag);
    const rome2_battle_entity *attachment = rome2_owned_battle_entity_get(h->attachment);
    uint32_t common;
    if (words == NULL || coordinates == NULL || fauna == NULL || tag == NULL ||
        (h->attachment != NULL && attachment == NULL)) { return false; }
    h->view.words = *words;
    h->view.coordinates = *coordinates;
    h->view.fauna = *fauna;
    h->view.tag = tag;
    h->view.attachment = attachment;
    h->view.str_0fc = h->text;
    common = h->view.words.count < h->view.coordinates.count ? h->view.words.count : h->view.coordinates.count;
    h->view.last_common_index = common == 0 ? 0 : common - 1u;
    return true;
}

static rome2_unit_card_status discard(rome2_owned_unit_card *h)
{
    const rome2_owned_string_allocator captured = h->allocator;
    void *const raw = h->raw;
    rome2_unit_card_status result = ROME2_UNIT_CARD_OK;
    h->state = 0;
    memset(&h->view, 0, sizeof h->view);
    if (rome2_owned_fauna_vector_destroy(&h->fauna) != ROME2_FAUNA_OK) { result = ROME2_UNIT_CARD_INTERNAL_ERROR; }
    if (rome2_owned_battle_entity_destroy(&h->attachment) != ROME2_OWNED_ENTITY_OK) { result = ROME2_UNIT_CARD_INTERNAL_ERROR; }
    if (rome2_owned_unit_card_tag_destroy(&h->tag) != ROME2_OWNED_TAG_OK) { result = ROME2_UNIT_CARD_INTERNAL_ERROR; }
    if (rome2_owned_float2_vector_destroy(&h->coordinates) != ROME2_SCALAR_VECTOR_OK) { result = ROME2_UNIT_CARD_INTERNAL_ERROR; }
    if (rome2_owned_u32_vector_destroy(&h->words) != ROME2_SCALAR_VECTOR_OK) { result = ROME2_UNIT_CARD_INTERNAL_ERROR; }
    if (rome2_owned_string16_destroy(&h->text, &h->text_owner) != ROME2_OWNED_STRING_OK) { result = ROME2_UNIT_CARD_INTERNAL_ERROR; }
    captured.release(captured.context, raw, sizeof *h + 7u, 0);
    return result;
}

static void project_scalars(rome2_native_unit_card *out, const rome2_unit_card *source)
{
    rome2_host_string8 *strings[] = {&out->str_010, &out->str_028, &out->str_034, &out->str_044,
        &out->str_0a4, &out->str_0b0, &out->str_0bc, &out->str_0c8, &out->str_0d4,
        &out->str_0e0, &out->str_0f0, &out->str_108, &out->str_12c};
    size_t i;
    for (i = 0; i < sizeof strings / sizeof strings[0]; ++i) { *strings[i] = rome2_host_string8_empty(); }
#define COPY_FIELD(field) memcpy(&out->field, &source->field, sizeof out->field)
    COPY_FIELD(field_000); COPY_FIELD(field_004); COPY_FIELD(field_008); COPY_FIELD(owner);
    COPY_FIELD(selector); COPY_FIELD(variant); COPY_FIELD(priority); COPY_FIELD(control_flags);
    COPY_FIELD(unit_class); COPY_FIELD(deployment); COPY_FIELD(strength); COPY_FIELD(field_080);
    COPY_FIELD(field_084); COPY_FIELD(field_088); COPY_FIELD(field_08c); COPY_FIELD(field_090);
    COPY_FIELD(colour_lo_x); COPY_FIELD(colour_lo_y); COPY_FIELD(colour_hi_x); COPY_FIELD(colour_hi_y);
    COPY_FIELD(field_0ec); COPY_FIELD(field_114); COPY_FIELD(enabled);
    COPY_FIELD(flag_119); COPY_FIELD(flag_11a); COPY_FIELD(flag_11b); COPY_FIELD(flag_11c);
    COPY_FIELD(slot_count); COPY_FIELD(mutable_class); COPY_FIELD(flag_138);
    COPY_FIELD(field_14c); COPY_FIELD(field_150);
    COPY_FIELD(grid_extent_min); COPY_FIELD(grid_extent_max);
    COPY_FIELD(field_168); COPY_FIELD(field_16c); COPY_FIELD(field_170); COPY_FIELD(field_174);
#undef COPY_FIELD
    memcpy(out->auxiliary, source->aux_subobject, sizeof out->auxiliary);
}

static rome2_unit_card_status make_config(rome2_owned_unit_card *h,
    const rome2_fauna_vector_view *source, uint32_t minimum,
    rome2_owned_fauna_vector **out)
{
    rome2_owned_fauna_vector *fresh = NULL;
    rome2_unit_card_status status = fauna_status(rome2_owned_fauna_vector_create(&fresh, &h->allocator));
    uint32_t i;
    if (status == ROME2_UNIT_CARD_OK) {
        status = fauna_status(rome2_owned_fauna_vector_reserve_min(fresh, minimum));
    }
    for (i = 0; status == ROME2_UNIT_CARD_OK && i < source->count; ++i) {
        status = fauna_status(rome2_owned_fauna_vector_push(fresh, &source->items[i]));
    }
    if (status != ROME2_UNIT_CARD_OK) {
        (void)rome2_owned_fauna_vector_destroy(&fresh);
        return status;
    }
    *out = fresh;
    return ROME2_UNIT_CARD_OK;
}

rome2_unit_card_status rome2_owned_unit_card_create_from_config(
    rome2_owned_unit_card **out, const rome2_unit_card_args *args,
    const rome2_unit_card_globals *globals, const rome2_fauna_vector_view *decoded_config,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_unit_card *h;
    rome2_unit_card_args scalar_args;
    rome2_unit_card_globals initial;
    rome2_unit_card projection;
    rome2_float2 normalized, input;
    const rome2_unit_card_tag_vector empty_tag = {0, 0, NULL};
    const rome2_unit_card_tag_vector *tag_source;
    rome2_owned_string_allocator captured;
    rome2_unit_card_status status;
    rome2_owned_tag_status tag_status;
    rome2_owned_entity_status entity_status;
    void *raw;
    if (out == NULL || args == NULL) { return ROME2_UNIT_CARD_BAD_ARGUMENT; }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) { return ROME2_UNIT_CARD_INVALID_ALLOCATOR; }
    status = validate_config(decoded_config);
    if (status != ROME2_UNIT_CARD_OK) { return status; }
    tag_source = args->arg01 == NULL ? &empty_tag : &args->arg01->elements;
    tag_status = rome2_unit_card_tag_validate(tag_source);
    if (tag_status != ROME2_OWNED_TAG_OK) {
        return tag_status == ROME2_OWNED_TAG_COUNT_OUT_OF_RANGE ? ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE : ROME2_UNIT_CARD_MALFORMED_SOURCE;
    }
    if (args->arg00 != NULL) {
        entity_status = rome2_battle_entity_copy_source_validate(args->arg00);
        if (entity_status != ROME2_OWNED_ENTITY_OK) {
            return entity_status == ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE ? ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE : ROME2_UNIT_CARD_MALFORMED_SOURCE;
        }
    }
    if (globals == NULL) { rome2_unit_card_globals_from_image(&initial); globals = &initial; }
    input.x = globals->colour_component_a; input.y = globals->colour_component_b;
    if (!rome2_float2_normalize_unit_disk(input, &normalized)) { return ROME2_UNIT_CARD_UNSUPPORTED_COORDINATE; }
    captured = *allocator;
    raw = captured.allocate(captured.context, sizeof *h + 7u, 0);
    if (raw == NULL) { return ROME2_UNIT_CARD_ALLOCATION_FAILED; }
    h = align_storage(raw); memset(h, 0, sizeof *h);
    h->state = CARD_BUILDING; h->self = h; h->raw = raw; h->allocator = captured;
    scalar_args = *args; scalar_args.arg00 = NULL; scalar_args.arg01 = NULL;
    rome2_unit_card_ctor(&projection, &scalar_args, globals, NULL);
    project_scalars(&h->view, &projection);
    {
        const rome2_string16_view empty = {NULL, 0};
        status = rome2_owned_string16_copy(&h->text, &h->text_owner, empty, &captured) == ROME2_OWNED_STRING_OK ?
            ROME2_UNIT_CARD_OK : ROME2_UNIT_CARD_INTERNAL_ERROR;
    }
    if (status == ROME2_UNIT_CARD_OK) { status = scalar_status(rome2_owned_u32_vector_create(&h->words, &captured)); }
    if (status == ROME2_UNIT_CARD_OK) { status = scalar_status(rome2_owned_float2_vector_create(&h->coordinates, &captured)); }
    if (status == ROME2_UNIT_CARD_OK) { status = scalar_status(rome2_owned_u32_vector_push(h->words, args->arg06)); }
    if (status == ROME2_UNIT_CARD_OK) { status = scalar_status(rome2_owned_float2_vector_push(h->coordinates, &normalized)); }
    if (status == ROME2_UNIT_CARD_OK) {
        tag_status = rome2_owned_unit_card_tag_create(&h->tag, tag_source, &captured);
        status = tag_status == ROME2_OWNED_TAG_OK ? ROME2_UNIT_CARD_OK :
            (tag_status == ROME2_OWNED_TAG_ALLOCATION_FAILED ? ROME2_UNIT_CARD_ALLOCATION_FAILED : ROME2_UNIT_CARD_INTERNAL_ERROR);
    }
    if (status == ROME2_UNIT_CARD_OK && args->arg00 != NULL) {
        entity_status = rome2_owned_battle_entity_copy(&h->attachment, args->arg00, &captured);
        status = entity_status == ROME2_OWNED_ENTITY_OK ? ROME2_UNIT_CARD_OK :
            (entity_status == ROME2_OWNED_ENTITY_ALLOCATION_FAILED ? ROME2_UNIT_CARD_ALLOCATION_FAILED : ROME2_UNIT_CARD_INTERNAL_ERROR);
    }
    if (status == ROME2_UNIT_CARD_OK) { status = make_config(h, decoded_config, 0, &h->fauna); }
    if (status != ROME2_UNIT_CARD_OK) {
        const rome2_unit_card_status cleanup = discard(h);
        return cleanup == ROME2_UNIT_CARD_OK ? status : cleanup;
    }
    if (!synchronize(h)) { (void)discard(h); return ROME2_UNIT_CARD_INTERNAL_ERROR; }
    h->state = CARD_LIVE; *out = h;
    return ROME2_UNIT_CARD_OK;
}

const rome2_native_unit_card *rome2_owned_unit_card_get(const rome2_owned_unit_card *h)
{ return live(h) ? &h->view : NULL; }

rome2_unit_card_status rome2_owned_unit_card_destroy(rome2_owned_unit_card **handle)
{
    rome2_owned_unit_card *h;
    if (handle == NULL) { return ROME2_UNIT_CARD_BAD_ARGUMENT; }
    h = *handle;
    if (h == NULL) { return ROME2_UNIT_CARD_OK; }
    if (!live(h)) { return ROME2_UNIT_CARD_INVALID_HANDLE; }
    *handle = NULL; return discard(h);
}
rome2_unit_card_status rome2_owned_unit_card_append_word(rome2_owned_unit_card *h, uint32_t value)
{
    rome2_unit_card_status status;
    if (!live(h)) { return ROME2_UNIT_CARD_INVALID_HANDLE; }
    status = scalar_status(rome2_owned_u32_vector_push(h->words, value));
    if (status == ROME2_UNIT_CARD_OK && !synchronize(h)) { return ROME2_UNIT_CARD_INTERNAL_ERROR; }
    return status;
}
rome2_unit_card_status rome2_owned_unit_card_append_coordinate(rome2_owned_unit_card *h, rome2_float2 value)
{
    rome2_float2 normalized;
    rome2_unit_card_status status;
    if (!live(h)) { return ROME2_UNIT_CARD_INVALID_HANDLE; }
    if (!rome2_float2_normalize_unit_disk(value, &normalized)) { return ROME2_UNIT_CARD_UNSUPPORTED_COORDINATE; }
    status = scalar_status(rome2_owned_float2_vector_push(h->coordinates, &normalized));
    if (status == ROME2_UNIT_CARD_OK && !synchronize(h)) { return ROME2_UNIT_CARD_INTERNAL_ERROR; }
    return status;
}
rome2_unit_card_status rome2_owned_unit_card_set_text16(rome2_owned_unit_card *h, rome2_string16_view source)
{
    rome2_host_string16 fresh = {0};
    rome2_host_string16 old = rome2_host_string16_empty();
    rome2_owned_string_owner owner = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner old_owner = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_status status;
    if (!live(h)) { return ROME2_UNIT_CARD_INVALID_HANDLE; }
    status = rome2_owned_string16_copy(&fresh, &owner, source, &h->allocator);
    if (status != ROME2_OWNED_STRING_OK) {
        return status == ROME2_OWNED_STRING_ALLOCATION_FAILED ? ROME2_UNIT_CARD_ALLOCATION_FAILED : ROME2_UNIT_CARD_MALFORMED_SOURCE;
    }
    /* Move both capabilities before release. Observers reading a cached card
     * view see the new text, never an already-released old payload. */
    status = rome2_owned_string16_move(&old, &old_owner, &h->text, &h->text_owner);
    if (status == ROME2_OWNED_STRING_OK) { status = rome2_owned_string16_move(&h->text, &h->text_owner, &fresh, &owner); }
    if (status != ROME2_OWNED_STRING_OK) {
        if (rome2_owned_string_owner_is_live(&old_owner)) {
            (void)rome2_owned_string16_move(&h->text, &h->text_owner, &old, &old_owner);
        }
        (void)synchronize(h);
        (void)rome2_owned_string16_destroy(&fresh, &owner);
        (void)rome2_owned_string16_destroy(&old, &old_owner);
        return ROME2_UNIT_CARD_INTERNAL_ERROR;
    }
    {
        const bool published = synchronize(h);
        status = rome2_owned_string16_destroy(&old, &old_owner);
        return published && status == ROME2_OWNED_STRING_OK ? ROME2_UNIT_CARD_OK : ROME2_UNIT_CARD_INTERNAL_ERROR;
    }
}
rome2_unit_card_status rome2_owned_unit_card_clear_fauna(rome2_owned_unit_card *h)
{
    rome2_unit_card_status status;
    if (!live(h)) { return ROME2_UNIT_CARD_INVALID_HANDLE; }
    h->view.fauna.count = 0; /* publish before nested release callbacks */
    status = fauna_status(rome2_owned_fauna_vector_clear(h->fauna));
    if (status == ROME2_UNIT_CARD_OK && !synchronize(h)) { return ROME2_UNIT_CARD_INTERNAL_ERROR; }
    return status;
}
rome2_unit_card_status rome2_owned_unit_card_replace_config(rome2_owned_unit_card *h,
    const rome2_fauna_vector_view *source)
{
    rome2_owned_fauna_vector *fresh = NULL, *old;
    rome2_unit_card_status status;
    if (!live(h)) { return ROME2_UNIT_CARD_INVALID_HANDLE; }
    status = validate_config(source);
    if (status != ROME2_UNIT_CARD_OK) { return status; }
    status = make_config(h, source, rome2_owned_fauna_vector_get(h->fauna)->capacity, &fresh);
    if (status != ROME2_UNIT_CARD_OK) { return status; }
    old = h->fauna; h->fauna = fresh;
    status = synchronize(h) ? ROME2_UNIT_CARD_OK : ROME2_UNIT_CARD_INTERNAL_ERROR;
    if (rome2_owned_fauna_vector_destroy(&old) != ROME2_FAUNA_OK) { status = ROME2_UNIT_CARD_INTERNAL_ERROR; }
    return status;
}
