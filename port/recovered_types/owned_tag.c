#include "owned_tag.h"

#include <stdbool.h>
#include <string.h>

#define TAG_BUILDING UINT32_C(0x54424c44)
#define TAG_LIVE UINT32_C(0x54414753)
#define STORAGE_ALIGN ((size_t)8)

typedef struct leaf_owner {
    rome2_host_string8 name;
    rome2_owned_string_owner owner;
} leaf_owner;

typedef struct element_owner {
    rome2_host_string8 name;
    rome2_host_string16 text;
    rome2_owned_string_owner name_owner;
    rome2_owned_string_owner text_owner;
    void *children_raw;
    size_t children_bytes;
    size_t child_count;
    leaf_owner *children;
} element_owner;

struct rome2_owned_unit_card_tag {
    uint32_t state;
    uint32_t reserved;
    const rome2_owned_unit_card_tag *self;
    void *record_raw;
    size_t record_bytes;
    rome2_owned_string_allocator allocator;
    void *elements_raw;
    size_t elements_bytes;
    size_t element_count;
    element_owner *elements;
    rome2_unit_card_tag view;
};

_Static_assert(_Alignof(rome2_owned_unit_card_tag) == STORAGE_ALIGN, "handle alignment");
_Static_assert(_Alignof(element_owner) == STORAGE_ALIGN, "outer owner alignment");
_Static_assert(_Alignof(leaf_owner) == STORAGE_ALIGN, "leaf owner alignment");
_Static_assert(sizeof(element_owner) % STORAGE_ALIGN == 0, "outer split alignment");
_Static_assert(sizeof(leaf_owner) % STORAGE_ALIGN == 0, "leaf split alignment");

static void *align_storage(void *raw)
{
    const size_t misalignment = (size_t)((uintptr_t)raw % STORAGE_ALIGN);
    return (unsigned char *)raw +
        (misalignment == 0u ? 0u : STORAGE_ALIGN - misalignment);
}

static bool storage_bytes(size_t count, size_t private_size,
    size_t public_size, size_t *out)
{
    if (private_size > SIZE_MAX - public_size ||
        count > (SIZE_MAX - (STORAGE_ALIGN - 1u)) / (private_size + public_size)) {
        return false;
    }
    *out = count * (private_size + public_size) + STORAGE_ALIGN - 1u;
    return true;
}

static bool valid_string8(const rome2_host_string8 *s)
{
    return s->length >= 0 && s->capacity >= s->length &&
        (s->length == 0 || s->data != NULL);
}

static bool valid_string16(const rome2_host_string16 *s)
{
    return s->length_units >= 0 &&
        s->length_units <= ROME2_OWNED_STRING16_MAX_UNITS &&
        s->capacity_units >= s->length_units &&
        (s->length_units == 0 || s->data != NULL);
}

static rome2_owned_tag_status validate_source(
    const rome2_unit_card_tag_vector *source)
{
    size_t i, j, ignored;
    if (source->count < 0 || (size_t)source->count > ROME2_TAG_MAX_ELEMENTS ||
        !storage_bytes((size_t)source->count, sizeof(element_owner),
            sizeof(rome2_unit_card_tag_element), &ignored)) {
        return ROME2_OWNED_TAG_COUNT_OUT_OF_RANGE;
    }
    if (source->count == 0) {
        return ROME2_OWNED_TAG_OK;
    }
    if (source->items == NULL) {
        return ROME2_OWNED_TAG_BAD_ARGUMENT;
    }
    for (i = 0u; i < (size_t)source->count; ++i) {
        const rome2_unit_card_tag_element *s = &source->items[i];
        if (!valid_string8(&s->name) || !valid_string16(&s->text)) {
            return ROME2_OWNED_TAG_MALFORMED_STRING;
        }
        if (s->children.count < 0 ||
            (size_t)s->children.count > ROME2_TAG_MAX_CHILDREN ||
            !storage_bytes((size_t)s->children.count, sizeof(leaf_owner),
                sizeof(rome2_unit_card_tag_leaf), &ignored)) {
            return ROME2_OWNED_TAG_COUNT_OUT_OF_RANGE;
        }
        if (s->children.count == 0) {
            continue;
        }
        if (s->children.items == NULL) {
            return ROME2_OWNED_TAG_BAD_ARGUMENT;
        }
        for (j = 0u; j < (size_t)s->children.count; ++j) {
            if (!valid_string8(&s->children.items[j].name)) {
                return ROME2_OWNED_TAG_MALFORMED_STRING;
            }
        }
    }
    return ROME2_OWNED_TAG_OK;
}

static void release_metadata(const rome2_owned_string_allocator *a,
    void *raw, size_t bytes)
{
    if (raw != NULL) {
        a->release(a->context, raw, bytes, ROME2_OWNED_STRING_ALLOCATION_CLASS);
    }
}

rome2_owned_tag_status rome2_unit_card_tag_validate(const rome2_unit_card_tag_vector *source)
{
    return source == NULL ? ROME2_OWNED_TAG_BAD_ARGUMENT : validate_source(source);
}

/* Private bookkeeping is the only release authority. In particular, never
 * iterate counts or pointers taken from the externally visible tag view.
 */
static rome2_owned_tag_status discard(rome2_owned_unit_card_tag *h)
{
    const rome2_owned_string_allocator captured = h->allocator;
    void *const record_raw = h->record_raw;
    const size_t record_bytes = h->record_bytes;
    size_t i, j;
    rome2_owned_tag_status result = ROME2_OWNED_TAG_OK;
    h->state = 0;
    memset(&h->view, 0, sizeof h->view);
    for (i = 0u; i < h->element_count; ++i) {
        element_owner *e = &h->elements[i];
        for (j = 0u; j < e->child_count; ++j) {
            if (rome2_owned_string8_destroy(&e->children[j].name,
                &e->children[j].owner) != ROME2_OWNED_STRING_OK) {
                result = ROME2_OWNED_TAG_INTERNAL_ERROR;
            }
        }
        release_metadata(&captured, e->children_raw, e->children_bytes);
        if (rome2_owned_string16_destroy(&e->text, &e->text_owner)
            != ROME2_OWNED_STRING_OK) {
            result = ROME2_OWNED_TAG_INTERNAL_ERROR;
        }
        if (rome2_owned_string8_destroy(&e->name, &e->name_owner)
            != ROME2_OWNED_STRING_OK) {
            result = ROME2_OWNED_TAG_INTERNAL_ERROR;
        }
    }
    release_metadata(&captured, h->elements_raw, h->elements_bytes);
    release_metadata(&captured, record_raw, record_bytes);
    return result;
}

static rome2_owned_tag_status string_status(rome2_owned_string_status status)
{
    if (status == ROME2_OWNED_STRING_OK) {
        return ROME2_OWNED_TAG_OK;
    }
    return status == ROME2_OWNED_STRING_ALLOCATION_FAILED ?
        ROME2_OWNED_TAG_ALLOCATION_FAILED : ROME2_OWNED_TAG_INTERNAL_ERROR;
}

static rome2_owned_string_status copy_name(rome2_host_string8 *destination,
    rome2_owned_string_owner *owner, const rome2_host_string8 *source,
    const rome2_owned_string_allocator *allocator)
{
    rome2_string8_view view;
    view.length = (ptrdiff_t)source->length;
    view.data = source->length == 0 ? NULL : source->data;
    return rome2_owned_string8_copy(destination, owner, view, allocator);
}

static rome2_owned_tag_status copy_element(rome2_owned_unit_card_tag *h,
    element_owner *owner, rome2_unit_card_tag_element *out,
    const rome2_unit_card_tag_element *source)
{
    size_t j, bytes = 0;
    rome2_unit_card_tag_leaf *children;
    rome2_string16_view text;
    rome2_owned_tag_status status = string_status(copy_name(&owner->name,
        &owner->name_owner, &source->name, &h->allocator));
    if (status != ROME2_OWNED_TAG_OK) {
        return status;
    }
    text.length_units = (ptrdiff_t)source->text.length_units;
    text.data = source->text.length_units == 0 ? NULL : source->text.data;
    status = string_status(rome2_owned_string16_copy(&owner->text,
        &owner->text_owner, text, &h->allocator));
    if (status != ROME2_OWNED_TAG_OK) {
        return status;
    }
    out->name = owner->name;
    out->text = owner->text;
    memcpy(out->words_00c, source->words_00c, sizeof out->words_00c);
    out->word_01c = source->word_01c;
    memcpy(out->words_020, source->words_020, sizeof out->words_020);
    memcpy(out->bytes_050, source->bytes_050, sizeof out->bytes_050);
    out->word_058 = source->word_058;
    memcpy(out->words_068, source->words_068, sizeof out->words_068);
    out->children.capacity = source->children.count;
    out->children.count = source->children.count;
    if (source->children.count == 0) {
        return ROME2_OWNED_TAG_OK;
    }
    if (!storage_bytes((size_t)source->children.count, sizeof(leaf_owner),
        sizeof *children, &bytes)) {
        return ROME2_OWNED_TAG_INTERNAL_ERROR;
    }
    owner->children_raw = h->allocator.allocate(h->allocator.context, bytes,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (owner->children_raw == NULL) {
        return ROME2_OWNED_TAG_ALLOCATION_FAILED;
    }
    owner->children_bytes = bytes;
    owner->children = (leaf_owner *)align_storage(owner->children_raw);
    owner->child_count = (size_t)source->children.count;
    memset(owner->children, 0, owner->child_count * (sizeof(leaf_owner) + sizeof *children));
    children = (rome2_unit_card_tag_leaf *)(void *)
        ((unsigned char *)owner->children + owner->child_count * sizeof(leaf_owner));
    for (j = 0; j < owner->child_count; ++j) {
        const rome2_unit_card_tag_leaf *s = &source->children.items[j];
        status = string_status(copy_name(&owner->children[j].name,
            &owner->children[j].owner, &s->name, &h->allocator));
        if (status != ROME2_OWNED_TAG_OK) {
            return status;
        }
        children[j].name = owner->children[j].name;
        memcpy(children[j].words_00c, s->words_00c, sizeof children[j].words_00c);
    }
    out->children.items = children;
    return ROME2_OWNED_TAG_OK;
}

rome2_owned_tag_status rome2_owned_unit_card_tag_create(
    rome2_owned_unit_card_tag **out, const rome2_unit_card_tag_vector *source,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_unit_card_tag *h;
    rome2_unit_card_tag_element *elements = NULL;
    rome2_owned_string_allocator captured;
    void *raw;
    size_t bytes = 0, i;
    rome2_owned_tag_status status;
    if (out == NULL || source == NULL) {
        return ROME2_OWNED_TAG_BAD_ARGUMENT;
    }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) {
        return ROME2_OWNED_TAG_INVALID_ALLOCATOR;
    }
    status = validate_source(source);
    if (status != ROME2_OWNED_TAG_OK) {
        return status;
    }
    captured = *allocator;
    if (!storage_bytes(1, sizeof *h, 0, &bytes)) {
        return ROME2_OWNED_TAG_INTERNAL_ERROR;
    }
    raw = captured.allocate(captured.context, bytes, ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (raw == NULL) {
        return ROME2_OWNED_TAG_ALLOCATION_FAILED;
    }
    h = (rome2_owned_unit_card_tag *)align_storage(raw);
    memset(h, 0, sizeof *h);
    h->state = TAG_BUILDING;
    h->self = h;
    h->record_raw = raw;
    h->record_bytes = bytes;
    h->allocator = captured;
    if (source->count != 0) {
        if (!storage_bytes((size_t)source->count, sizeof(element_owner),
            sizeof *elements, &bytes)) {
            (void)discard(h);
            return ROME2_OWNED_TAG_INTERNAL_ERROR;
        }
        h->elements_raw = captured.allocate(captured.context, bytes,
            ROME2_OWNED_STRING_ALLOCATION_CLASS);
        if (h->elements_raw == NULL) {
            (void)discard(h);
            return ROME2_OWNED_TAG_ALLOCATION_FAILED;
        }
        h->elements_bytes = bytes;
        h->element_count = (size_t)source->count;
        h->elements = (element_owner *)align_storage(h->elements_raw);
        memset(h->elements, 0, h->element_count * (sizeof(element_owner) + sizeof *elements));
        elements = (rome2_unit_card_tag_element *)(void *)
            ((unsigned char *)h->elements + h->element_count * sizeof(element_owner));
        for (i = 0; i < h->element_count; ++i) {
            status = copy_element(h, &h->elements[i], &elements[i], &source->items[i]);
            if (status != ROME2_OWNED_TAG_OK) {
                const rome2_owned_tag_status cleanup = discard(h);
                return cleanup == ROME2_OWNED_TAG_OK ? status : cleanup;
            }
        }
    }
    h->view.vtable_identity = ROME2_TAG_VTABLE_IDENTITY;
    h->view.elements.capacity = source->count;
    h->view.elements.count = source->count;
    h->view.elements.items = elements;
    h->state = TAG_LIVE;
    *out = h;
    return ROME2_OWNED_TAG_OK;
}

static bool live(const rome2_owned_unit_card_tag *h)
{
    return h->state == TAG_LIVE && h->reserved == 0 && h->self == h &&
        h->record_raw != NULL && h->record_bytes == sizeof *h + STORAGE_ALIGN - 1u &&
        align_storage(h->record_raw) == h &&
        h->allocator.allocate != NULL && h->allocator.release != NULL;
}

const rome2_unit_card_tag *rome2_owned_unit_card_tag_get(
    const rome2_owned_unit_card_tag *handle)
{
    return handle != NULL && live(handle) ? &handle->view : NULL;
}

rome2_owned_tag_status rome2_owned_unit_card_tag_destroy(
    rome2_owned_unit_card_tag **handle)
{
    rome2_owned_unit_card_tag *h;
    if (handle == NULL) {
        return ROME2_OWNED_TAG_BAD_ARGUMENT;
    }
    h = *handle;
    if (h == NULL) {
        return ROME2_OWNED_TAG_OK;
    }
    if (!live(h)) {
        return ROME2_OWNED_TAG_INVALID_HANDLE;
    }
    *handle = NULL;
    return discard(h);
}
