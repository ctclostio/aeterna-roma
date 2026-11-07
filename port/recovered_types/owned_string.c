/*
 * owned_string.c - native x64 owned-string runtime.  See owned_string.h for
 * the evidence summary, preserved semantics, host design choices, and the
 * owner/callback contracts.  Every public entry point validates all inputs
 * before its first effect (allocation, write, or callback).
 */

#include "owned_string.h"

#include <string.h>

const char rome2_host_string8_empty_sentinel[1] = { 0 };
const uint16_t rome2_host_string16_empty_sentinel[1] = { 0 };

static const rome2_owned_string_owner k_vacant_owner =
    ROME2_OWNED_STRING_OWNER_INIT;
static const rome2_owned_string8_vector k_vacant_vector =
    ROME2_OWNED_STRING8_VECTOR_INIT;

/* Original payload placement: (raw + 8) & ~3, header cell at payload - 4. */
#define OWNED_PAYLOAD_BIAS          8u
#define OWNED_HEADER_CELL_BYTES     4u
/* Host vector storage alignment for descriptors and owners. */
#define VECTOR_STORAGE_ALIGNMENT    8u

_Static_assert(ROME2_OWNED_STRING_PAYLOAD_ALIGNMENT == 4u,
    "payload alignment is the original (raw + 8) & ~3 rule");
_Static_assert(_Alignof(rome2_host_string8) <= VECTOR_STORAGE_ALIGNMENT &&
    VECTOR_STORAGE_ALIGNMENT % _Alignof(rome2_host_string8) == 0,
    "vector storage alignment covers descriptors");
_Static_assert(_Alignof(rome2_owned_string_owner) <= VECTOR_STORAGE_ALIGNMENT &&
    VECTOR_STORAGE_ALIGNMENT % _Alignof(rome2_owned_string_owner) == 0,
    "vector storage alignment covers owners");
_Static_assert(sizeof(rome2_host_string8) % _Alignof(rome2_owned_string_owner)
    == 0, "owner array following the descriptor array stays aligned");

typedef enum owner_class {
    OWNER_VACANT,
    OWNER_LIVE,
    OWNER_INVALID
} owner_class;

/* Fields every descriptor kind shares, read without type punning. */
typedef struct descriptor_fields {
    int32_t length;
    int32_t capacity;
    const void *data;
} descriptor_fields;

/* ------------------------------------------------------------------------ */
/* Small pure helpers.                                                       */
/* ------------------------------------------------------------------------ */

static bool ranges_overlap(const void *a, size_t a_size,
    const void *b, size_t b_size)
{
    const uintptr_t a0 = (uintptr_t)a;
    const uintptr_t b0 = (uintptr_t)b;
    return a0 < b0 + b_size && b0 < a0 + a_size;
}

static int32_t kind_max_units(uint32_t kind)
{
    return kind == ROME2_OWNED_STRING_KIND_NARROW
        ? ROME2_OWNED_STRING8_MAX_LENGTH
        : ROME2_OWNED_STRING16_MAX_UNITS;
}

static size_t kind_unit_bytes(uint32_t kind)
{
    return kind == ROME2_OWNED_STRING_KIND_NARROW ? 1u : 2u;
}

/*
 * Original request formulas.  Precondition: 1 <= units <= kind_max_units,
 * which keeps both results <= UINT32_MAX and far from SIZE_MAX on x64.
 */
static size_t kind_request_bytes(uint32_t kind, int32_t units)
{
    return kind == ROME2_OWNED_STRING_KIND_NARROW
        ? (size_t)units + 9u
        : (size_t)units * 2u + 10u;
}

/* Integer form of (raw + 8) & ~3, used only for validation comparisons. */
static uintptr_t payload_identity_for(uintptr_t raw)
{
    return (raw + OWNED_PAYLOAD_BIAS) & ~(uintptr_t)3u;
}

static const void *kind_empty_sentinel(uint32_t kind)
{
    return kind == ROME2_OWNED_STRING_KIND_NARROW
        ? (const void *)rome2_host_string8_empty_sentinel
        : (const void *)rome2_host_string16_empty_sentinel;
}

static descriptor_fields fields8(const rome2_host_string8 *d)
{
    descriptor_fields f;
    f.length = d->length;
    f.capacity = d->capacity;
    f.data = d->data;
    return f;
}

static descriptor_fields fields16(const rome2_host_string16 *d)
{
    descriptor_fields f;
    f.length = d->length_units;
    f.capacity = d->capacity_units;
    f.data = d->data;
    return f;
}

static bool allocator_is_zero(const rome2_owned_string_allocator *a)
{
    return a->allocate == NULL && a->release == NULL && a->context == NULL &&
        a->release_observer == NULL && a->observer_context == NULL;
}

static bool allocator_is_usable(const rome2_owned_string_allocator *a)
{
    return a->allocate != NULL && a->release != NULL;
}

/* ------------------------------------------------------------------------ */
/* Owner classification.                                                     */
/* ------------------------------------------------------------------------ */

static bool owner_is_vacant(const rome2_owned_string_owner *o)
{
    return o->state == ROME2_OWNED_STRING_STATE_VACANT &&
        o->kind == ROME2_OWNED_STRING_KIND_NONE && o->length == 0 &&
        o->reserved == 0u && o->self == NULL && o->raw_base == NULL &&
        o->payload == NULL && o->allocation_bytes == 0u &&
        allocator_is_zero(&o->allocator);
}

static bool owner_is_live_kind(const rome2_owned_string_owner *o,
    uint32_t kind)
{
    if (o->state != ROME2_OWNED_STRING_STATE_LIVE || o->kind != kind ||
        o->self != o || o->reserved != 0u) {
        return false;
    }
    if (o->length < 1 || o->length > kind_max_units(kind)) {
        return false;
    }
    if (o->raw_base == NULL || !allocator_is_usable(&o->allocator)) {
        return false;
    }
    if (o->allocation_bytes != kind_request_bytes(kind, o->length)) {
        return false;
    }
    return (uintptr_t)o->payload ==
        payload_identity_for((uintptr_t)o->raw_base);
}

static owner_class classify_owner(const rome2_owned_string_owner *o,
    uint32_t kind)
{
    if (owner_is_vacant(o)) {
        return OWNER_VACANT;
    }
    return owner_is_live_kind(o, kind) ? OWNER_LIVE : OWNER_INVALID;
}

static bool descriptor_matches_owner(descriptor_fields f,
    const rome2_owned_string_owner *o)
{
    return f.length == o->length && f.capacity == o->length &&
        f.data == o->payload;
}

static bool descriptor_is_empty(uint32_t kind, descriptor_fields f)
{
    return f.length == 0 && f.capacity == 0 &&
        f.data == kind_empty_sentinel(kind);
}

/*
 * Validate a source/owner pair as a coherent unit: LIVE with its published
 * descriptor, or VACANT with exactly the empty descriptor.
 */
static rome2_owned_string_status validate_pair(uint32_t kind,
    descriptor_fields f, const rome2_owned_string_owner *o, bool *live_out)
{
    switch (classify_owner(o, kind)) {
    case OWNER_VACANT:
        *live_out = false;
        return descriptor_is_empty(kind, f)
            ? ROME2_OWNED_STRING_OK
            : ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH;
    case OWNER_LIVE:
        *live_out = true;
        return descriptor_matches_owner(f, o)
            ? ROME2_OWNED_STRING_OK
            : ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH;
    case OWNER_INVALID:
    default:
        *live_out = false;
        return ROME2_OWNED_STRING_INVALID_OWNER;
    }
}

static rome2_owned_string_status validate_destination_owner(
    const rome2_owned_string_owner *o, uint32_t kind)
{
    switch (classify_owner(o, kind)) {
    case OWNER_VACANT:
        return ROME2_OWNED_STRING_OK;
    case OWNER_LIVE:
        return ROME2_OWNED_STRING_DESTINATION_OCCUPIED;
    case OWNER_INVALID:
    default:
        /* A LIVE owner of the other kind is still occupied. */
        if (owner_is_live_kind(o, kind == ROME2_OWNED_STRING_KIND_NARROW
                ? ROME2_OWNED_STRING_KIND_UTF16
                : ROME2_OWNED_STRING_KIND_NARROW)) {
            return ROME2_OWNED_STRING_DESTINATION_OCCUPIED;
        }
        return ROME2_OWNED_STRING_INVALID_OWNER;
    }
}

static rome2_owned_string_status validate_source(uint32_t kind,
    const void *data, ptrdiff_t length)
{
    if (length < 0) {
        return ROME2_OWNED_STRING_NEGATIVE_LENGTH;
    }
    if (length > (ptrdiff_t)kind_max_units(kind)) {
        return ROME2_OWNED_STRING_LENGTH_OUT_OF_RANGE;
    }
    if (length > 0 && data == NULL) {
        return ROME2_OWNED_STRING_NULL_DATA;
    }
    return ROME2_OWNED_STRING_OK;
}

static rome2_owned_string_status validate_allocator(
    const rome2_owned_string_allocator *a, bool required)
{
    if (a == NULL) {
        return required ? ROME2_OWNED_STRING_INVALID_ALLOCATOR
                        : ROME2_OWNED_STRING_OK;
    }
    return allocator_is_usable(a) ? ROME2_OWNED_STRING_OK
                                  : ROME2_OWNED_STRING_INVALID_ALLOCATOR;
}

/* ------------------------------------------------------------------------ */
/* Effects.                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Allocate and build one owned payload with the captured allocator, then
 * commit a LIVE owner at *owner.  Precondition: every input was validated,
 * units >= 1, and *owner is VACANT.  On allocation failure nothing is
 * written.
 */
static rome2_owned_string_status materialize(uint32_t kind,
    const void *data, int32_t units,
    const rome2_owned_string_allocator *captured,
    rome2_owned_string_owner *owner, const void **payload_out)
{
    const size_t request = kind_request_bytes(kind, units);
    const size_t unit_bytes = kind_unit_bytes(kind);
    const size_t data_bytes = (size_t)units * unit_bytes;
    void *raw;
    unsigned char *payload;
    size_t payload_offset;
    uint32_t header_cell;
    rome2_owned_string_owner staged;

    raw = captured->allocate(captured->context, request,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (raw == NULL) {
        return ROME2_OWNED_STRING_ALLOCATION_FAILED;
    }

    /*
     * (raw + 8) & ~3 == raw + (8 - (raw & 3)), formed by pointer arithmetic
     * within the allocation so provenance is preserved.  The offset is 5..8,
     * so [payload - 4, payload + data_bytes + unit_bytes) lies inside
     * [raw, raw + request) for both request formulas.
     */
    payload_offset = OWNED_PAYLOAD_BIAS - (size_t)((uintptr_t)raw & 3u);
    payload = (unsigned char *)raw + payload_offset;

    /* Host-defined header cell: payload offset, NOT the original address. */
    header_cell = (uint32_t)payload_offset;
    memcpy(payload - OWNED_HEADER_CELL_BYTES, &header_cell,
        sizeof header_cell);
    memcpy(payload, data, data_bytes);
    memset(payload + data_bytes, 0, unit_bytes);

    staged = k_vacant_owner;
    staged.state = ROME2_OWNED_STRING_STATE_LIVE;
    staged.kind = kind;
    staged.length = units;
    staged.self = owner;
    staged.raw_base = raw;
    staged.payload = payload;
    staged.allocation_bytes = request;
    staged.allocator = *captured;
    *owner = staged;

    *payload_out = payload;
    return ROME2_OWNED_STRING_OK;
}

/*
 * Release a consumed owner snapshot.  The caller has already reset the live
 * owner record, so callbacks observe it as VACANT.
 */
static void release_snapshot(const rome2_owned_string_owner *snapshot)
{
    const uintptr_t identity = (uintptr_t)snapshot->raw_base;
    snapshot->allocator.release(snapshot->allocator.context,
        snapshot->raw_base, snapshot->allocation_bytes,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (snapshot->allocator.release_observer != NULL) {
        snapshot->allocator.release_observer(
            snapshot->allocator.observer_context, identity,
            snapshot->allocation_bytes);
    }
}

/* Shared argument/precondition checks for the two copy entry points. */
static rome2_owned_string_status prepare_copy(uint32_t kind,
    const void *destination, size_t destination_size,
    const rome2_owned_string_owner *destination_owner,
    const void *data, ptrdiff_t length,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_status status;

    if (destination == NULL || destination_owner == NULL) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    if (ranges_overlap(destination, destination_size, destination_owner,
            sizeof *destination_owner)) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    status = validate_destination_owner(destination_owner, kind);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    status = validate_source(kind, data, length);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    return validate_allocator(allocator, length > 0);
}

/* ------------------------------------------------------------------------ */
/* Public descriptor helpers.                                                */
/* ------------------------------------------------------------------------ */

rome2_host_string8 rome2_host_string8_empty(void)
{
    rome2_host_string8 d;
    d.length = 0;
    d.capacity = 0;
    d.data = rome2_host_string8_empty_sentinel;
    return d;
}

rome2_host_string16 rome2_host_string16_empty(void)
{
    rome2_host_string16 d;
    d.length_units = 0;
    d.capacity_units = 0;
    d.data = rome2_host_string16_empty_sentinel;
    return d;
}

rome2_string8_view rome2_host_string8_as_view(rome2_host_string8 descriptor)
{
    rome2_string8_view v;
    v.data = descriptor.data;
    v.length = (ptrdiff_t)descriptor.length;
    return v;
}

rome2_string16_view rome2_host_string16_as_view(
    rome2_host_string16 descriptor)
{
    rome2_string16_view v;
    v.data = descriptor.data;
    v.length_units = (ptrdiff_t)descriptor.length_units;
    return v;
}

bool rome2_owned_string_owner_is_live(const rome2_owned_string_owner *owner)
{
    return owner != NULL &&
        (owner_is_live_kind(owner, ROME2_OWNED_STRING_KIND_NARROW) ||
         owner_is_live_kind(owner, ROME2_OWNED_STRING_KIND_UTF16));
}

/* ------------------------------------------------------------------------ */
/* Copy.                                                                     */
/* ------------------------------------------------------------------------ */

rome2_owned_string_status rome2_owned_string8_copy(
    rome2_host_string8 *destination,
    rome2_owned_string_owner *destination_owner,
    rome2_string8_view source,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_allocator captured;
    const void *payload = NULL;
    int32_t units;
    rome2_owned_string_status status = prepare_copy(
        ROME2_OWNED_STRING_KIND_NARROW, destination, sizeof *destination,
        destination_owner, source.data, source.length, allocator);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    if (source.length == 0) {
        *destination = rome2_host_string8_empty();
        return ROME2_OWNED_STRING_OK;
    }

    units = (int32_t)source.length;
    captured = *allocator;
    status = materialize(ROME2_OWNED_STRING_KIND_NARROW, source.data, units,
        &captured, destination_owner, &payload);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    destination->length = units;
    destination->capacity = units;
    destination->data = (const char *)payload;
    return ROME2_OWNED_STRING_OK;
}

rome2_owned_string_status rome2_owned_string16_copy(
    rome2_host_string16 *destination,
    rome2_owned_string_owner *destination_owner,
    rome2_string16_view source,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_allocator captured;
    const void *payload = NULL;
    int32_t units;
    rome2_owned_string_status status = prepare_copy(
        ROME2_OWNED_STRING_KIND_UTF16, destination, sizeof *destination,
        destination_owner, source.data, source.length_units, allocator);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    if (source.length_units == 0) {
        *destination = rome2_host_string16_empty();
        return ROME2_OWNED_STRING_OK;
    }

    units = (int32_t)source.length_units;
    captured = *allocator;
    status = materialize(ROME2_OWNED_STRING_KIND_UTF16, source.data, units,
        &captured, destination_owner, &payload);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    destination->length_units = units;
    destination->capacity_units = units;
    /* payload is 4-byte aligned, so it is a valid uint16_t pointer. */
    destination->data = (const uint16_t *)payload;
    return ROME2_OWNED_STRING_OK;
}

/* ------------------------------------------------------------------------ */
/* Move.                                                                     */
/* ------------------------------------------------------------------------ */

static bool four_objects_disjoint(const void *dd, const void *downer,
    const void *sd, const void *sowner, size_t descriptor_size)
{
    const size_t os = sizeof(rome2_owned_string_owner);
    return !ranges_overlap(dd, descriptor_size, downer, os) &&
        !ranges_overlap(dd, descriptor_size, sd, descriptor_size) &&
        !ranges_overlap(dd, descriptor_size, sowner, os) &&
        !ranges_overlap(downer, os, sd, descriptor_size) &&
        !ranges_overlap(downer, os, sowner, os) &&
        !ranges_overlap(sd, descriptor_size, sowner, os);
}

/*
 * Pointer-only aliasing check for both move kinds; reads no object.  An
 * exact self-move (same descriptor, same owner) sets *self_move.
 */
static rome2_owned_string_status check_move_aliasing(const void *destination,
    const void *destination_owner, const void *source,
    const void *source_owner, size_t descriptor_size, bool *self_move)
{
    *self_move = false;
    if (destination == NULL || destination_owner == NULL || source == NULL ||
        source_owner == NULL) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    if (destination == source && destination_owner == source_owner) {
        *self_move = true;
        return ranges_overlap(source, descriptor_size, source_owner,
                   sizeof(rome2_owned_string_owner))
            ? ROME2_OWNED_STRING_BAD_ARGUMENT
            : ROME2_OWNED_STRING_OK;
    }
    return four_objects_disjoint(destination, destination_owner, source,
               source_owner, descriptor_size)
        ? ROME2_OWNED_STRING_OK
        : ROME2_OWNED_STRING_BAD_ARGUMENT;
}

/* Object validation for both move kinds, after aliasing was ruled out. */
static rome2_owned_string_status validate_move(uint32_t kind,
    descriptor_fields source_fields,
    const rome2_owned_string_owner *destination_owner,
    const rome2_owned_string_owner *source_owner, bool self_move,
    bool *source_live)
{
    const rome2_owned_string_status status =
        validate_pair(kind, source_fields, source_owner, source_live);
    if (status != ROME2_OWNED_STRING_OK || self_move) {
        return status;
    }
    return validate_destination_owner(destination_owner, kind);
}

rome2_owned_string_status rome2_owned_string8_move(
    rome2_host_string8 *destination,
    rome2_owned_string_owner *destination_owner,
    rome2_host_string8 *source,
    rome2_owned_string_owner *source_owner)
{
    bool self_move = false;
    bool source_live = false;
    rome2_owned_string_owner moved;
    rome2_host_string8 published;
    rome2_owned_string_status status = check_move_aliasing(destination,
        destination_owner, source, source_owner, sizeof(rome2_host_string8),
        &self_move);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    status = validate_move(ROME2_OWNED_STRING_KIND_NARROW, fields8(source),
        destination_owner, source_owner, self_move, &source_live);
    if (status != ROME2_OWNED_STRING_OK || self_move) {
        return status;
    }
    if (!source_live) {
        *destination = rome2_host_string8_empty();
        return ROME2_OWNED_STRING_OK;
    }

    moved = *source_owner;
    moved.self = destination_owner;
    published = *source;
    *source_owner = k_vacant_owner;
    *source = rome2_host_string8_empty();
    *destination_owner = moved;
    *destination = published;
    return ROME2_OWNED_STRING_OK;
}

rome2_owned_string_status rome2_owned_string16_move(
    rome2_host_string16 *destination,
    rome2_owned_string_owner *destination_owner,
    rome2_host_string16 *source,
    rome2_owned_string_owner *source_owner)
{
    bool self_move = false;
    bool source_live = false;
    rome2_owned_string_owner moved;
    rome2_host_string16 published;
    rome2_owned_string_status status = check_move_aliasing(destination,
        destination_owner, source, source_owner, sizeof(rome2_host_string16),
        &self_move);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    status = validate_move(ROME2_OWNED_STRING_KIND_UTF16, fields16(source),
        destination_owner, source_owner, self_move, &source_live);
    if (status != ROME2_OWNED_STRING_OK || self_move) {
        return status;
    }
    if (!source_live) {
        *destination = rome2_host_string16_empty();
        return ROME2_OWNED_STRING_OK;
    }

    moved = *source_owner;
    moved.self = destination_owner;
    published = *source;
    *source_owner = k_vacant_owner;
    *source = rome2_host_string16_empty();
    *destination_owner = moved;
    *destination = published;
    return ROME2_OWNED_STRING_OK;
}

/* ------------------------------------------------------------------------ */
/* Destroy.                                                                  */
/* ------------------------------------------------------------------------ */

/* Pointer-only aliasing check for both destroy kinds; reads no object. */
static rome2_owned_string_status check_destroy_aliasing(
    const void *descriptor, size_t descriptor_size,
    const rome2_owned_string_owner *owner)
{
    if (owner == NULL) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    if (descriptor != NULL && ranges_overlap(descriptor, descriptor_size,
            owner, sizeof *owner)) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    return ROME2_OWNED_STRING_OK;
}

/*
 * Object validation for both destroy kinds, after aliasing was ruled out.
 * Returns OK with *live set when a release must happen.  fields is NULL
 * when no descriptor was supplied.
 */
static rome2_owned_string_status validate_destroy(uint32_t kind,
    const descriptor_fields *fields, const rome2_owned_string_owner *owner,
    bool *live)
{
    *live = false;
    switch (classify_owner(owner, kind)) {
    case OWNER_VACANT:
        return ROME2_OWNED_STRING_OK;
    case OWNER_LIVE:
        break;
    case OWNER_INVALID:
    default:
        return ROME2_OWNED_STRING_INVALID_OWNER;
    }
    if (fields != NULL && !descriptor_matches_owner(*fields, owner)) {
        return ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH;
    }
    *live = true;
    return ROME2_OWNED_STRING_OK;
}

rome2_owned_string_status rome2_owned_string8_destroy(
    rome2_host_string8 *descriptor,
    rome2_owned_string_owner *owner)
{
    bool live = false;
    descriptor_fields fields = { 0, 0, NULL };
    rome2_owned_string_owner snapshot;
    rome2_owned_string_status status = check_destroy_aliasing(descriptor,
        sizeof(rome2_host_string8), owner);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    if (descriptor != NULL) {
        fields = fields8(descriptor);
    }
    status = validate_destroy(ROME2_OWNED_STRING_KIND_NARROW,
        descriptor != NULL ? &fields : NULL, owner, &live);
    if (status != ROME2_OWNED_STRING_OK || !live) {
        return status;
    }

    snapshot = *owner;
    *owner = k_vacant_owner;
    if (descriptor != NULL) {
        *descriptor = rome2_host_string8_empty();
    }
    release_snapshot(&snapshot);
    return ROME2_OWNED_STRING_OK;
}

rome2_owned_string_status rome2_owned_string16_destroy(
    rome2_host_string16 *descriptor,
    rome2_owned_string_owner *owner)
{
    bool live = false;
    descriptor_fields fields = { 0, 0, NULL };
    rome2_owned_string_owner snapshot;
    rome2_owned_string_status status = check_destroy_aliasing(descriptor,
        sizeof(rome2_host_string16), owner);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    if (descriptor != NULL) {
        fields = fields16(descriptor);
    }
    status = validate_destroy(ROME2_OWNED_STRING_KIND_UTF16,
        descriptor != NULL ? &fields : NULL, owner, &live);
    if (status != ROME2_OWNED_STRING_OK || !live) {
        return status;
    }

    snapshot = *owner;
    *owner = k_vacant_owner;
    if (descriptor != NULL) {
        *descriptor = rome2_host_string16_empty();
    }
    release_snapshot(&snapshot);
    return ROME2_OWNED_STRING_OK;
}

/* ------------------------------------------------------------------------ */
/* Narrow string vector.                                                     */
/* ------------------------------------------------------------------------ */

static const size_t k_vector_bytes_per_item =
    sizeof(rome2_host_string8) + sizeof(rome2_owned_string_owner);

/* request = count * (16 + 88) + 7; false on bound or overflow. */
static bool vector_storage_bytes(size_t count, size_t *bytes_out)
{
    const size_t slack = VECTOR_STORAGE_ALIGNMENT - 1u;
    if (count == 0u || count > ROME2_OWNED_STRING8_VECTOR_MAX_COUNT) {
        return false;
    }
    if (count > (SIZE_MAX - slack) / k_vector_bytes_per_item) {
        return false;
    }
    *bytes_out = count * k_vector_bytes_per_item + slack;
    return true;
}

static uintptr_t vector_items_identity_for(uintptr_t raw)
{
    return (raw + (VECTOR_STORAGE_ALIGNMENT - 1u)) &
        ~(uintptr_t)(VECTOR_STORAGE_ALIGNMENT - 1u);
}

static bool vector_is_vacant(const rome2_owned_string8_vector *v)
{
    return v->items == NULL && v->owners == NULL && v->count == 0u &&
        v->state == ROME2_OWNED_STRING_STATE_VACANT && v->reserved == 0u &&
        v->self == NULL && v->storage_raw == NULL &&
        v->storage_bytes == 0u && allocator_is_zero(&v->allocator);
}

static bool vector_is_live(const rome2_owned_string8_vector *v)
{
    size_t bytes = 0u;
    uintptr_t items;

    if (v->state != ROME2_OWNED_STRING8_VECTOR_STATE_LIVE || v->self != v ||
        v->reserved != 0u) {
        return false;
    }
    if (!vector_storage_bytes(v->count, &bytes) || bytes != v->storage_bytes) {
        return false;
    }
    if (v->storage_raw == NULL || !allocator_is_usable(&v->allocator)) {
        return false;
    }
    items = vector_items_identity_for((uintptr_t)v->storage_raw);
    return (uintptr_t)v->items == items &&
        (uintptr_t)v->owners == items + v->count * sizeof(rome2_host_string8);
}

static owner_class classify_vector(const rome2_owned_string8_vector *v)
{
    if (vector_is_vacant(v)) {
        return OWNER_VACANT;
    }
    return vector_is_live(v) ? OWNER_LIVE : OWNER_INVALID;
}

/* Release every LIVE element pair in [0, count); storage stays allocated. */
static void vector_release_elements(rome2_host_string8 *items,
    rome2_owned_string_owner *owners, size_t count)
{
    size_t i;
    for (i = 0u; i < count; ++i) {
        rome2_owned_string_owner snapshot;
        if (owners[i].state != ROME2_OWNED_STRING_STATE_LIVE) {
            continue;
        }
        snapshot = owners[i];
        owners[i] = k_vacant_owner;
        items[i] = rome2_host_string8_empty();
        release_snapshot(&snapshot);
    }
}

rome2_owned_string_status rome2_owned_string8_vector_copy(
    rome2_owned_string8_vector *destination,
    const rome2_host_string8 *source,
    size_t count,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_allocator captured;
    rome2_owned_string8_vector staged;
    rome2_host_string8 *items;
    rome2_owned_string_owner *owners;
    unsigned char *base;
    size_t storage_bytes = 0u;
    void *raw;
    size_t i;
    rome2_owned_string_status status;

    if (destination == NULL) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    switch (classify_vector(destination)) {
    case OWNER_VACANT:
        break;
    case OWNER_LIVE:
        return ROME2_OWNED_STRING_DESTINATION_OCCUPIED;
    case OWNER_INVALID:
    default:
        return ROME2_OWNED_STRING_INVALID_OWNER;
    }
    if (count == 0u) {
        return validate_allocator(allocator, false);
    }
    if (!vector_storage_bytes(count, &storage_bytes)) {
        return ROME2_OWNED_STRING_COUNT_OUT_OF_RANGE;
    }
    if (source == NULL) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    status = validate_allocator(allocator, true);
    if (status != ROME2_OWNED_STRING_OK) {
        return status;
    }
    for (i = 0u; i < count; ++i) {
        status = validate_source(ROME2_OWNED_STRING_KIND_NARROW,
            source[i].data, (ptrdiff_t)source[i].length);
        if (status != ROME2_OWNED_STRING_OK) {
            return status;
        }
    }

    captured = *allocator;
    raw = captured.allocate(captured.context, storage_bytes,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (raw == NULL) {
        return ROME2_OWNED_STRING_ALLOCATION_FAILED;
    }
    base = (unsigned char *)raw +
        (size_t)(vector_items_identity_for((uintptr_t)raw) - (uintptr_t)raw);
    items = (rome2_host_string8 *)(void *)base;
    owners = (rome2_owned_string_owner *)(void *)
        (base + count * sizeof(rome2_host_string8));
    for (i = 0u; i < count; ++i) {
        items[i] = rome2_host_string8_empty();
        owners[i] = k_vacant_owner;
    }

    for (i = 0u; i < count; ++i) {
        const int32_t units = source[i].length;
        const char *data = source[i].data;
        const void *payload = NULL;
        /*
         * Every element was validated before the storage allocation.  This
         * re-check only keeps memory safe if a callback breaks its contract
         * by mutating the source; it then rolls back like any failure.
         */
        status = validate_source(ROME2_OWNED_STRING_KIND_NARROW, data,
            (ptrdiff_t)units);
        if (status == ROME2_OWNED_STRING_OK && units == 0) {
            continue;
        }
        if (status == ROME2_OWNED_STRING_OK) {
            status = materialize(ROME2_OWNED_STRING_KIND_NARROW, data,
                units, &captured, &owners[i], &payload);
        }
        if (status != ROME2_OWNED_STRING_OK) {
            vector_release_elements(items, owners, i);
            captured.release(captured.context, raw, storage_bytes,
                ROME2_OWNED_STRING_ALLOCATION_CLASS);
            return status;
        }
        items[i].length = units;
        items[i].capacity = units;
        items[i].data = (const char *)payload;
    }

    staged = k_vacant_vector;
    staged.items = items;
    staged.owners = owners;
    staged.count = count;
    staged.state = ROME2_OWNED_STRING8_VECTOR_STATE_LIVE;
    staged.self = destination;
    staged.storage_raw = raw;
    staged.storage_bytes = storage_bytes;
    staged.allocator = captured;
    *destination = staged;
    return ROME2_OWNED_STRING_OK;
}

rome2_owned_string_status rome2_owned_string8_vector_move(
    rome2_owned_string8_vector *destination,
    rome2_owned_string8_vector *source)
{
    owner_class source_class;
    rome2_owned_string8_vector moved;

    if (destination == NULL || source == NULL) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    source_class = classify_vector(source);
    if (source_class == OWNER_INVALID) {
        return ROME2_OWNED_STRING_INVALID_OWNER;
    }
    if (destination == source) {
        return ROME2_OWNED_STRING_OK;
    }
    if (ranges_overlap(destination, sizeof *destination, source,
            sizeof *source)) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    switch (classify_vector(destination)) {
    case OWNER_VACANT:
        break;
    case OWNER_LIVE:
        return ROME2_OWNED_STRING_DESTINATION_OCCUPIED;
    case OWNER_INVALID:
    default:
        return ROME2_OWNED_STRING_INVALID_OWNER;
    }
    if (source_class == OWNER_VACANT) {
        return ROME2_OWNED_STRING_OK;
    }

    moved = *source;
    moved.self = destination;
    *source = k_vacant_vector;
    *destination = moved;
    return ROME2_OWNED_STRING_OK;
}

rome2_owned_string_status rome2_owned_string8_vector_destroy(
    rome2_owned_string8_vector *vector)
{
    rome2_owned_string8_vector snapshot;
    size_t i;

    if (vector == NULL) {
        return ROME2_OWNED_STRING_BAD_ARGUMENT;
    }
    switch (classify_vector(vector)) {
    case OWNER_VACANT:
        return ROME2_OWNED_STRING_OK;
    case OWNER_LIVE:
        break;
    case OWNER_INVALID:
    default:
        return ROME2_OWNED_STRING_INVALID_OWNER;
    }
    for (i = 0u; i < vector->count; ++i) {
        switch (classify_owner(&vector->owners[i],
                    ROME2_OWNED_STRING_KIND_NARROW)) {
        case OWNER_VACANT:
            break;
        case OWNER_LIVE:
            if (!descriptor_matches_owner(fields8(&vector->items[i]),
                    &vector->owners[i])) {
                return ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH;
            }
            break;
        case OWNER_INVALID:
        default:
            return ROME2_OWNED_STRING_INVALID_OWNER;
        }
    }

    snapshot = *vector;
    *vector = k_vacant_vector;
    vector_release_elements(snapshot.items, snapshot.owners, snapshot.count);
    snapshot.allocator.release(snapshot.allocator.context,
        snapshot.storage_raw, snapshot.storage_bytes,
        ROME2_OWNED_STRING_ALLOCATION_CLASS);
    return ROME2_OWNED_STRING_OK;
}
