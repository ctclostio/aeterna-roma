#include "free_list_pool.h"

#include <stdbool.h>
#include <string.h>

#define POOL_LIVE UINT32_C(0x504f4f4c)

typedef struct pool_storage {
    uint32_t state, kind, count, reserved;
    const void *self;
    void *record_raw;
    size_t record_bytes;
    void *slots_raw;
    size_t slots_bytes;
    rome2_owned_string_allocator allocator;
} pool_storage;

struct rome2_owned_free_list_pool_10328370 {
    pool_storage storage;
    rome2_free_list_pool_10328370 value;
};
struct rome2_owned_free_list_pool_1064d4e0 {
    pool_storage storage;
    rome2_free_list_pool_1064d4e0 value;
};
_Static_assert(offsetof(rome2_owned_free_list_pool_10328370, storage) == 0,
    "common ownership prefix");
_Static_assert(offsetof(rome2_owned_free_list_pool_1064d4e0, storage) == 0,
    "common ownership prefix");

static bool request_bytes(size_t count, size_t stride, size_t alignment,
    size_t *result)
{
    if (count > (SIZE_MAX - (alignment - 1u)) / stride) {
        return false;
    }
    *result = count * stride + alignment - 1u;
    return true;
}

static void *align_grant(void *raw, size_t alignment)
{
    size_t residue = (size_t)((uintptr_t)raw % alignment);
    return (uint8_t *)raw + (residue == 0 ? 0 : alignment - residue);
}

static void release_grant(const rome2_owned_string_allocator *allocator,
    void *raw, size_t bytes)
{
    allocator->release(allocator->context, raw, bytes,
        ROME2_FREE_LIST_POOL_ALLOCATION_CLASS);
}

static rome2_free_list_pool_status allocate_pool(void **record,
    void **slots, pool_storage *owner, uint32_t count, uint32_t guest_stride,
    size_t native_stride, size_t record_size, size_t record_alignment,
    const rome2_owned_string_allocator *allocator)
{
    pool_storage value = {0};
    size_t record_bytes, slots_bytes = 0;
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) {
        return ROME2_FREE_LIST_POOL_INVALID_ALLOCATOR;
    }
    if (count > UINT32_MAX / guest_stride
        || !request_bytes(1, record_size, record_alignment, &record_bytes)
        || (count != 0 && !request_bytes(count, native_stride, 8, &slots_bytes))) {
        return ROME2_FREE_LIST_POOL_COUNT_OUT_OF_RANGE;
    }
    value.allocator = *allocator;
    value.kind = guest_stride;
    value.count = count;
    value.record_bytes = record_bytes;
    value.slots_bytes = slots_bytes;
    if (count != 0) {
        value.slots_raw = value.allocator.allocate(value.allocator.context,
            slots_bytes, ROME2_FREE_LIST_POOL_ALLOCATION_CLASS);
        if (value.slots_raw == NULL) {
            return ROME2_FREE_LIST_POOL_ALLOCATION_FAILED;
        }
    }
    value.record_raw = value.allocator.allocate(value.allocator.context,
        record_bytes, ROME2_FREE_LIST_POOL_ALLOCATION_CLASS);
    if (value.record_raw == NULL) {
        if (value.slots_raw != NULL) {
            release_grant(&value.allocator, value.slots_raw, slots_bytes);
        }
        return ROME2_FREE_LIST_POOL_ALLOCATION_FAILED;
    }
    *record = align_grant(value.record_raw, record_alignment);
    *slots = value.slots_raw != NULL ? align_grant(value.slots_raw, 8) : NULL;
    value.self = *record;
    value.state = POOL_LIVE;
    *owner = value;
    return ROME2_FREE_LIST_POOL_OK;
}

static bool coherent(const pool_storage *owner, const void *handle,
    uint32_t kind, size_t native_stride, size_t record_size, size_t alignment)
{
    size_t expected_record, expected_slots = 0;
    if (owner->state != POOL_LIVE || owner->kind != kind || owner->self != handle
        || owner->reserved != 0 || owner->record_raw == NULL
        || owner->allocator.allocate == NULL || owner->allocator.release == NULL
        || owner->count > UINT32_MAX / kind) {
        return false;
    }
    if (!request_bytes(1, record_size, alignment, &expected_record)
        || (owner->count != 0
            && !request_bytes(owner->count, native_stride, 8, &expected_slots))) {
        return false;
    }
    return owner->record_bytes == expected_record
        && owner->slots_bytes == expected_slots
        && ((owner->slots_raw == NULL) == (owner->count == 0))
        && align_grant(owner->record_raw, alignment) == handle;
}

static void destroy_storage(pool_storage *storage)
{
    pool_storage captured = *storage;
    memset(storage, 0, sizeof *storage);
    if (captured.slots_raw != NULL) {
        release_grant(&captured.allocator, captured.slots_raw, captured.slots_bytes);
    }
    release_grant(&captured.allocator, captured.record_raw, captured.record_bytes);
}

/* Typed wrappers keep native link members real pointers. Shared helpers only
 * handle ownership metadata; no descriptor or slot array is type-punned.
 */
#define DEFINE_POOL(suffix, guest_stride) \
rome2_free_list_pool_status rome2_free_list_pool_##suffix##_create( \
    rome2_owned_free_list_pool_##suffix **out_handle, uint32_t count, \
    uint32_t tag, const rome2_owned_string_allocator *allocator) \
{ \
    rome2_owned_free_list_pool_##suffix *handle; \
    rome2_free_list_slot_##suffix *slots; \
    void *record, *block; \
    pool_storage owner; \
    uint32_t i; \
    rome2_free_list_pool_status status; \
    if (out_handle == NULL) return ROME2_FREE_LIST_POOL_BAD_ARGUMENT; \
    status = allocate_pool(&record, &block, &owner, count, guest_stride, \
        sizeof *slots, sizeof *handle, _Alignof(rome2_owned_free_list_pool_##suffix), \
        allocator); \
    if (status != ROME2_FREE_LIST_POOL_OK) return status; \
    handle = (rome2_owned_free_list_pool_##suffix *)record; \
    slots = (rome2_free_list_slot_##suffix *)block; \
    handle->storage = owner; \
    handle->value.head = slots; \
    handle->value.tag = tag; \
    for (i = 0; i < count; ++i) { \
        slots[i].next = i + 1u < count ? &slots[i + 1u] : NULL; \
    } \
    *out_handle = handle; \
    return ROME2_FREE_LIST_POOL_OK; \
} \
const rome2_free_list_pool_##suffix *rome2_free_list_pool_##suffix##_get( \
    const rome2_owned_free_list_pool_##suffix *handle) \
{ \
    const pool_storage *owner; \
    if (handle == NULL) return NULL; \
    owner = (const pool_storage *)(const void *)handle; \
    if (!coherent(owner, handle, guest_stride, sizeof(rome2_free_list_slot_##suffix), \
        sizeof *handle, _Alignof(rome2_owned_free_list_pool_##suffix))) return NULL; \
    return &handle->value; \
} \
rome2_free_list_pool_status rome2_free_list_pool_##suffix##_destroy( \
    rome2_owned_free_list_pool_##suffix **handle) \
{ \
    rome2_owned_free_list_pool_##suffix *value; \
    if (handle == NULL) return ROME2_FREE_LIST_POOL_BAD_ARGUMENT; \
    value = *handle; \
    if (value == NULL) return ROME2_FREE_LIST_POOL_OK; \
    if (rome2_free_list_pool_##suffix##_get(value) == NULL) \
        return ROME2_FREE_LIST_POOL_INVALID_HANDLE; \
    *handle = NULL; \
    destroy_storage(&value->storage); \
    return ROME2_FREE_LIST_POOL_OK; \
}

DEFINE_POOL(10328370, 0x50u)
DEFINE_POOL(1064d4e0, 0x4cu)
#undef DEFINE_POOL
