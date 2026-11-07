#include "owned_fauna.h"

#include <stdbool.h>
#include <string.h>

#define FAUNA_LIVE UINT32_C(0x4641554e)
typedef struct fauna_owner {
    void *raw;
    size_t bytes;
    rome2_owned_string8_vector strings;
} fauna_owner;
typedef struct fauna_storage {
    void *raw;
    size_t bytes;
    fauna_owner **owners;
    rome2_fauna_record *items;
    uint32_t capacity;
} fauna_storage;
struct rome2_owned_fauna_vector {
    uint32_t state, count;
    const rome2_owned_fauna_vector *self;
    void *raw;
    rome2_owned_string_allocator allocator;
    fauna_storage storage;
    rome2_fauna_vector_view view;
};

_Static_assert(_Alignof(rome2_owned_fauna_vector) == 8, "fauna handle alignment");
_Static_assert(sizeof(fauna_owner) % 8 == 0, "fauna descriptor split alignment");

static void *align_storage(void *raw)
{
    const size_t residue = (size_t)((uintptr_t)raw % 8u);
    return (unsigned char *)raw + (residue == 0 ? 0 : 8u - residue);
}

static bool live(const rome2_owned_fauna_vector *h)
{
    return h != NULL && h->state == FAUNA_LIVE && h->self == h &&
        h->raw != NULL && align_storage(h->raw) == h &&
        h->allocator.allocate != NULL && h->allocator.release != NULL &&
        h->count <= h->storage.capacity && h->storage.capacity <= ROME2_FAUNA_MAX_CAPACITY;
}

static void publish(rome2_owned_fauna_vector *h)
{
    h->view.capacity = h->storage.capacity;
    h->view.count = h->count;
    h->view.items = h->storage.items;
}

static void release_raw(const rome2_owned_string_allocator *a, void *raw, size_t bytes)
{
    if (raw != NULL) { a->release(a->context, raw, bytes, 0); }
}

static rome2_fauna_status from_string(rome2_owned_string_status status)
{
    if (status == ROME2_OWNED_STRING_OK) { return ROME2_FAUNA_OK; }
    return status == ROME2_OWNED_STRING_ALLOCATION_FAILED ? ROME2_FAUNA_ALLOCATION_FAILED :
        ROME2_FAUNA_INTERNAL_ERROR;
}

rome2_fauna_status rome2_fauna_record_validate(const rome2_fauna_record *source)
{
    size_t i;
    if (source == NULL) { return ROME2_FAUNA_BAD_ARGUMENT; }
    if (source->strings.count > ROME2_FAUNA_MAX_STRINGS) { return ROME2_FAUNA_COUNT_OUT_OF_RANGE; }
    if (source->strings.count != 0 && source->strings.items == NULL) { return ROME2_FAUNA_BAD_ARGUMENT; }
    for (i = 0; i < source->strings.count; ++i) {
        const rome2_host_string8 *s = &source->strings.items[i];
        if (s->length < 0 || s->capacity < s->length || (s->length != 0 && s->data == NULL)) {
            return ROME2_FAUNA_MALFORMED_STRING;
        }
    }
    return ROME2_FAUNA_OK;
}

static rome2_fauna_status create_owner(rome2_owned_fauna_vector *h,
    const rome2_fauna_record *source, fauna_owner **out, rome2_fauna_record *view)
{
    const size_t bytes = sizeof(fauna_owner) + (size_t)source->strings.count * sizeof(rome2_host_string8) + 7u;
    fauna_owner *owner;
    rome2_host_string8 *strings;
    void *raw = h->allocator.allocate(h->allocator.context, bytes, 0);
    rome2_fauna_status status;
    size_t i;
    if (raw == NULL) { return ROME2_FAUNA_ALLOCATION_FAILED; }
    owner = align_storage(raw);
    memset(owner, 0, sizeof *owner);
    owner->raw = raw; owner->bytes = bytes;
    strings = (rome2_host_string8 *)(void *)((unsigned char *)owner + sizeof *owner);
    status = from_string(rome2_owned_string8_vector_copy(&owner->strings,
        source->strings.count == 0 ? NULL : source->strings.items,
        source->strings.count, &h->allocator));
    if (status != ROME2_FAUNA_OK) {
        release_raw(&h->allocator, raw, bytes);
        return status;
    }
    for (i = 0; i < source->strings.count; ++i) { strings[i] = owner->strings.items[i]; }
    memset(view, 0, sizeof *view);
    memcpy(view->words_000, source->words_000, sizeof view->words_000);
    view->strings.capacity = source->strings.count;
    view->strings.count = source->strings.count;
    view->strings.items = source->strings.count == 0 ? NULL : strings;
    *out = owner;
    return ROME2_FAUNA_OK;
}

static rome2_fauna_status free_owner(const rome2_owned_string_allocator *a, fauna_owner *owner)
{
    void *raw = owner->raw;
    const size_t bytes = owner->bytes;
    const rome2_fauna_status status = from_string(rome2_owned_string8_vector_destroy(&owner->strings));
    release_raw(a, raw, bytes);
    return status;
}

static rome2_fauna_status prepare_storage(rome2_owned_fauna_vector *h,
    uint32_t minimum, fauna_storage *out)
{
    uint32_t capacity = h->storage.capacity == 0 ? 1 : h->storage.capacity;
    fauna_storage result = {0};
    if (minimum > ROME2_FAUNA_MAX_CAPACITY) { return ROME2_FAUNA_COUNT_OUT_OF_RANGE; }
    while (capacity < minimum) {
        if (capacity > ROME2_FAUNA_MAX_CAPACITY / 2u) { return ROME2_FAUNA_COUNT_OUT_OF_RANGE; }
        capacity *= 2u;
    }
    result.bytes = (size_t)capacity * (sizeof(fauna_owner *) + sizeof(rome2_fauna_record)) + 7u;
    result.raw = h->allocator.allocate(h->allocator.context, result.bytes, 0);
    if (result.raw == NULL) { return ROME2_FAUNA_ALLOCATION_FAILED; }
    result.capacity = capacity;
    result.owners = align_storage(result.raw);
    result.items = (rome2_fauna_record *)(void *)((unsigned char *)result.owners +
        (size_t)capacity * sizeof(fauna_owner *));
    memset(result.owners, 0, (size_t)capacity * (sizeof(fauna_owner *) + sizeof(rome2_fauna_record)));
    if (h->count != 0) {
        memcpy(result.owners, h->storage.owners, (size_t)h->count * sizeof(fauna_owner *));
        memcpy(result.items, h->storage.items, (size_t)h->count * sizeof(rome2_fauna_record));
    }
    *out = result;
    return ROME2_FAUNA_OK;
}

rome2_fauna_status rome2_owned_fauna_vector_create(rome2_owned_fauna_vector **out,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_allocator captured;
    rome2_owned_fauna_vector *h;
    void *raw;
    if (out == NULL) { return ROME2_FAUNA_BAD_ARGUMENT; }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) {
        return ROME2_FAUNA_INVALID_ALLOCATOR;
    }
    captured = *allocator;
    raw = captured.allocate(captured.context, sizeof *h + 7u, 0);
    if (raw == NULL) { return ROME2_FAUNA_ALLOCATION_FAILED; }
    h = align_storage(raw);
    memset(h, 0, sizeof *h);
    h->state = FAUNA_LIVE; h->self = h; h->raw = raw; h->allocator = captured;
    publish(h); *out = h;
    return ROME2_FAUNA_OK;
}

const rome2_fauna_vector_view *rome2_owned_fauna_vector_get(const rome2_owned_fauna_vector *h)
{ return live(h) ? &h->view : NULL; }

rome2_fauna_status rome2_owned_fauna_vector_push(rome2_owned_fauna_vector *h,
    const rome2_fauna_record *source)
{
    fauna_storage spare = {0};
    fauna_storage old;
    fauna_storage *destination;
    fauna_owner *owner = NULL;
    rome2_fauna_record view;
    rome2_fauna_status status;
    if (!live(h)) { return ROME2_FAUNA_INVALID_HANDLE; }
    status = rome2_fauna_record_validate(source);
    if (status != ROME2_FAUNA_OK) { return status; }
    if (h->count == h->storage.capacity) {
        status = prepare_storage(h, h->count + 1u, &spare);
        if (status != ROME2_FAUNA_OK) { return status; }
    }
    status = create_owner(h, source, &owner, &view);
    if (status != ROME2_FAUNA_OK) {
        release_raw(&h->allocator, spare.raw, spare.bytes);
        return status;
    }
    destination = spare.raw == NULL ? &h->storage : &spare;
    destination->owners[h->count] = owner;
    destination->items[h->count] = view;
    old = h->storage;
    if (spare.raw != NULL) { h->storage = spare; }
    ++h->count; publish(h);
    if (spare.raw != NULL) { release_raw(&h->allocator, old.raw, old.bytes); }
    return ROME2_FAUNA_OK;
}

rome2_fauna_status rome2_owned_fauna_vector_reserve_min(rome2_owned_fauna_vector *h,
    uint32_t minimum)
{
    fauna_storage spare = {0}, old;
    rome2_fauna_status status;
    if (!live(h)) { return ROME2_FAUNA_INVALID_HANDLE; }
    if (minimum <= h->storage.capacity) { return ROME2_FAUNA_OK; }
    status = prepare_storage(h, minimum, &spare);
    if (status != ROME2_FAUNA_OK) { return status; }
    old = h->storage; h->storage = spare; publish(h);
    release_raw(&h->allocator, old.raw, old.bytes);
    return ROME2_FAUNA_OK;
}

static rome2_fauna_status clear(rome2_owned_fauna_vector *h)
{
    uint32_t i, count = h->count;
    rome2_fauna_status status = ROME2_FAUNA_OK;
    h->count = 0; publish(h);
    for (i = 0; i < count; ++i) {
        fauna_owner *owner = h->storage.owners[i];
        h->storage.owners[i] = NULL;
        if (free_owner(&h->allocator, owner) != ROME2_FAUNA_OK) { status = ROME2_FAUNA_INTERNAL_ERROR; }
    }
    return status;
}

rome2_fauna_status rome2_owned_fauna_vector_clear(rome2_owned_fauna_vector *h)
{ return live(h) ? clear(h) : ROME2_FAUNA_INVALID_HANDLE; }

rome2_fauna_status rome2_owned_fauna_vector_destroy(rome2_owned_fauna_vector **handle)
{
    rome2_owned_fauna_vector *h;
    rome2_owned_string_allocator captured;
    void *raw;
    rome2_fauna_status status;
    if (handle == NULL) { return ROME2_FAUNA_BAD_ARGUMENT; }
    h = *handle;
    if (h == NULL) { return ROME2_FAUNA_OK; }
    if (!live(h)) { return ROME2_FAUNA_INVALID_HANDLE; }
    *handle = NULL;
    captured = h->allocator; raw = h->raw;
    status = clear(h); h->state = 0;
    release_raw(&captured, h->storage.raw, h->storage.bytes);
    release_raw(&captured, raw, sizeof *h + 7u);
    return status;
}
