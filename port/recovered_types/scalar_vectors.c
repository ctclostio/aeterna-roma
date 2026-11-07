#include "scalar_vectors.h"

#include <math.h>
#include <string.h>

#define SCALAR_LIVE UINT32_C(0x5343414c)
#define WORD_KIND 4u
#define PAIR_KIND 8u

struct rome2_owned_scalar_vector {
    uint32_t state, kind;
    const struct rome2_owned_scalar_vector *self;
    void *record_raw;
    rome2_owned_string_allocator allocator;
    void *backing_raw;
    unsigned char *backing;
    size_t backing_bytes;
    uint32_t capacity, count;
    union {
        rome2_u32_vector_view words;
        rome2_float2_vector_view pairs;
    } view;
};

_Static_assert(_Alignof(struct rome2_owned_scalar_vector) == 8, "owner alignment");

static void *align_to(void *raw, size_t alignment)
{
    const size_t residue = (size_t)((uintptr_t)raw % alignment);
    return (unsigned char *)raw + (residue == 0 ? 0 : alignment - residue);
}

static uint32_t maximum(uint32_t kind)
{
    return kind == WORD_KIND ? ROME2_U32_VECTOR_MAX_CAPACITY : ROME2_FLOAT2_VECTOR_MAX_CAPACITY;
}

static bool live(const struct rome2_owned_scalar_vector *h, uint32_t kind)
{
    return h != NULL && h->state == SCALAR_LIVE && h->kind == kind &&
        h->self == h && h->record_raw != NULL && align_to(h->record_raw, 8) == h &&
        h->allocator.allocate != NULL && h->allocator.release != NULL &&
        h->count <= h->capacity && h->capacity <= maximum(kind) &&
        (h->capacity == 0 ? h->backing_raw == NULL && h->backing == NULL && h->backing_bytes == 0 :
            h->backing_raw != NULL && align_to(h->backing_raw, 4) == h->backing &&
            h->backing_bytes == (size_t)h->capacity * kind + 3u);
}

static void publish(struct rome2_owned_scalar_vector *h)
{
    if (h->kind == WORD_KIND) {
        h->view.words.capacity = h->capacity;
        h->view.words.count = h->count;
        h->view.words.items = (const uint32_t *)(const void *)h->backing;
    } else {
        h->view.pairs.capacity = h->capacity;
        h->view.pairs.count = h->count;
        h->view.pairs.items = (const rome2_float2 *)(const void *)h->backing;
    }
}

static rome2_scalar_vector_status create(struct rome2_owned_scalar_vector **out,
    const rome2_owned_string_allocator *allocator, uint32_t kind)
{
    rome2_owned_string_allocator captured;
    struct rome2_owned_scalar_vector *h;
    void *raw;
    if (out == NULL) { return ROME2_SCALAR_VECTOR_BAD_ARGUMENT; }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) {
        return ROME2_SCALAR_VECTOR_INVALID_ALLOCATOR;
    }
    captured = *allocator;
    raw = captured.allocate(captured.context, sizeof *h + 7u, 0);
    if (raw == NULL) { return ROME2_SCALAR_VECTOR_ALLOCATION_FAILED; }
    h = align_to(raw, 8);
    memset(h, 0, sizeof *h);
    h->state = SCALAR_LIVE; h->kind = kind; h->self = h;
    h->record_raw = raw; h->allocator = captured;
    publish(h);
    *out = h;
    return ROME2_SCALAR_VECTOR_OK;
}

static rome2_scalar_vector_status push(struct rome2_owned_scalar_vector *h,
    const void *value, uint32_t kind)
{
    uint32_t capacity;
    size_t bytes;
    void *raw, *old_raw;
    unsigned char *backing;
    size_t old_bytes;
    if (!live(h, kind)) { return ROME2_SCALAR_VECTOR_INVALID_HANDLE; }
    if (h->count < h->capacity) {
        memcpy(h->backing + (size_t)h->count * kind, value, kind);
        ++h->count;
        publish(h);
        return ROME2_SCALAR_VECTOR_OK;
    }
    if (h->capacity > maximum(kind) / 2u) { return ROME2_SCALAR_VECTOR_COUNT_OUT_OF_RANGE; }
    capacity = h->capacity == 0 ? 1u : h->capacity * 2u;
    bytes = (size_t)capacity * kind + 3u;
    raw = h->allocator.allocate(h->allocator.context, bytes, 0);
    if (raw == NULL) { return ROME2_SCALAR_VECTOR_ALLOCATION_FAILED; }
    backing = align_to(raw, 4);
    if (h->count != 0) { memcpy(backing, h->backing, (size_t)h->count * kind); }
    memcpy(backing + (size_t)h->count * kind, value, kind);
    old_raw = h->backing_raw; old_bytes = h->backing_bytes;
    h->backing_raw = raw; h->backing_bytes = bytes; h->backing = backing;
    h->capacity = capacity; ++h->count;
    publish(h);
    if (old_raw != NULL) { h->allocator.release(h->allocator.context, old_raw, old_bytes, 0); }
    return ROME2_SCALAR_VECTOR_OK;
}

static rome2_scalar_vector_status destroy(struct rome2_owned_scalar_vector **handle, uint32_t kind)
{
    struct rome2_owned_scalar_vector *h;
    rome2_owned_string_allocator captured;
    void *record_raw, *backing_raw;
    size_t bytes;
    if (handle == NULL) { return ROME2_SCALAR_VECTOR_BAD_ARGUMENT; }
    h = *handle;
    if (h == NULL) { return ROME2_SCALAR_VECTOR_OK; }
    if (!live(h, kind)) { return ROME2_SCALAR_VECTOR_INVALID_HANDLE; }
    captured = h->allocator; record_raw = h->record_raw;
    backing_raw = h->backing_raw; bytes = h->backing_bytes;
    *handle = NULL; h->state = 0;
    if (backing_raw != NULL) { captured.release(captured.context, backing_raw, bytes, 0); }
    captured.release(captured.context, record_raw, sizeof *h + 7u, 0);
    return ROME2_SCALAR_VECTOR_OK;
}

rome2_scalar_vector_status rome2_owned_u32_vector_create(
    rome2_owned_u32_vector **out, const rome2_owned_string_allocator *a)
{ return create(out, a, WORD_KIND); }
rome2_scalar_vector_status rome2_owned_float2_vector_create(
    rome2_owned_float2_vector **out, const rome2_owned_string_allocator *a)
{ return create(out, a, PAIR_KIND); }
const rome2_u32_vector_view *rome2_owned_u32_vector_get(const rome2_owned_u32_vector *h)
{ return live(h, WORD_KIND) ? &h->view.words : NULL; }
const rome2_float2_vector_view *rome2_owned_float2_vector_get(const rome2_owned_float2_vector *h)
{ return live(h, PAIR_KIND) ? &h->view.pairs : NULL; }
rome2_scalar_vector_status rome2_owned_u32_vector_push(rome2_owned_u32_vector *h, uint32_t value)
{ return push(h, &value, WORD_KIND); }
rome2_scalar_vector_status rome2_owned_float2_vector_push(rome2_owned_float2_vector *h,
    const rome2_float2 *value)
{
    rome2_float2 snapshot;
    if (!live(h, PAIR_KIND)) { return ROME2_SCALAR_VECTOR_INVALID_HANDLE; }
    if (value == NULL) { return ROME2_SCALAR_VECTOR_BAD_ARGUMENT; }
    memcpy(&snapshot, value, sizeof snapshot);
    return push(h, &snapshot, PAIR_KIND);
}
rome2_scalar_vector_status rome2_owned_u32_vector_destroy(rome2_owned_u32_vector **h)
{ return destroy(h, WORD_KIND); }
rome2_scalar_vector_status rome2_owned_float2_vector_destroy(rome2_owned_float2_vector **h)
{ return destroy(h, PAIR_KIND); }

bool rome2_float2_normalize_unit_disk(rome2_float2 input, rome2_float2 *output)
{
    float xx, yy, sum, scale;
    if (output == NULL || !isfinite(input.x) || !isfinite(input.y)) { return false; }
    yy = input.y * input.y;
    xx = input.x * input.x;
    sum = yy + xx;
    if (!isfinite(sum)) { return false; }
    if (sum > 1.0f) {
        scale = 1.0f / sqrtf(sum);
        input.y = scale * input.y;
        input.x = scale * input.x;
    }
    *output = input;
    return true;
}
