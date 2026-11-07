#include "free_list_pool.h"
#include "guest32_layouts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
    exit(1); } } while (0)

typedef struct test_heap {
    unsigned allocations, releases, fail_at, residue, observations;
    void *raw[4], *actual[4];
    size_t bytes[4];
    unsigned live;
} test_heap;

static void *allocate(void *context, size_t bytes, uint32_t allocation_class)
{
    test_heap *heap = context;
    uint8_t *actual;
    unsigned i;
    ++heap->allocations;
    CHECK(allocation_class == 0);
    if (heap->allocations == heap->fail_at) {
        return NULL;
    }
    /* These tests never ask the machine to reserve boundary-sized pools. */
    CHECK(bytes < 1024u * 1024u && heap->live < 4);
    actual = malloc(bytes + 16);
    CHECK(actual != NULL);
    memset(actual, 0xa5, bytes + 16);
    for (i = 0; i < 4; ++i) {
        if (heap->raw[i] == NULL) {
            heap->actual[i] = actual;
            heap->raw[i] = actual + heap->residue;
            heap->bytes[i] = bytes;
            ++heap->live;
            return heap->raw[i];
        }
    }
    CHECK(0);
    return NULL;
}

static void release(void *context, void *raw, size_t bytes, uint32_t allocation_class)
{
    test_heap *heap = context;
    unsigned i;
    CHECK(allocation_class == 0);
    for (i = 0; i < 4; ++i) {
        if (heap->raw[i] == raw) {
            CHECK(heap->bytes[i] == bytes && heap->live != 0);
            free(heap->actual[i]);
            heap->raw[i] = NULL;
            heap->actual[i] = NULL;
            --heap->live;
            ++heap->releases;
            return;
        }
    }
    CHECK(0); /* foreign pointer or duplicate release */
}

static void observer(void *context, uintptr_t identity, size_t bytes)
{
    test_heap *heap = context;
    (void)identity;
    (void)bytes;
    ++heap->observations;
}

static rome2_owned_string_allocator policy(test_heap *heap)
{
    rome2_owned_string_allocator value = {allocate, release, heap, observer, heap};
    return value;
}

#define TEST_POOL(suffix, original_stride, maximum) \
static void test_##suffix(void) \
{ \
    const uint32_t counts[] = {0, 1, 2, 7, 24}; \
    unsigned residue, c; \
    for (residue = 0; residue < 8; ++residue) { \
        for (c = 0; c < sizeof counts / sizeof counts[0]; ++c) { \
            test_heap a = {0}, b = {0}; \
            rome2_owned_string_allocator allocator; \
            rome2_owned_free_list_pool_##suffix *handle = NULL; \
            const rome2_free_list_pool_##suffix *value; \
            uint32_t i; \
            a.residue = residue; \
            allocator = policy(&a); \
            CHECK(rome2_free_list_pool_##suffix##_create(&handle, counts[c], \
                UINT32_C(0xdeadbeef), &allocator) == ROME2_FREE_LIST_POOL_OK); \
            value = rome2_free_list_pool_##suffix##_get(handle); \
            CHECK(value != NULL && value->tag == UINT32_C(0xdeadbeef)); \
            CHECK((value->head == NULL) == (counts[c] == 0)); \
            CHECK(a.live == (counts[c] == 0 ? 1u : 2u)); \
            CHECK((uintptr_t)handle % 8u == 0); \
            for (i = 0; i < counts[c]; ++i) { \
                size_t byte; \
                const rome2_free_list_slot_##suffix *slot = &value->head[i]; \
                CHECK((uintptr_t)slot % 8u == 0); \
                if (i + 1u == counts[c]) { CHECK(slot->next == NULL); } \
                else { \
                    const uint32_t guest_next_offset = (i + 1u) * original_stride; \
                    CHECK(slot->next == &value->head[i + 1u]); \
                    CHECK((size_t)(slot->next - value->head) \
                        == guest_next_offset / original_stride); \
                } \
                for (byte = 8; byte < sizeof *slot; ++byte) { \
                    CHECK(((const uint8_t *)slot)[byte] == 0xa5); \
                } \
            } \
            allocator = policy(&b); /* caller edits cannot redirect cleanup */ \
            CHECK(rome2_free_list_pool_##suffix##_destroy(&handle) == ROME2_FREE_LIST_POOL_OK); \
            CHECK(handle == NULL && a.live == 0 && b.allocations == 0 && b.releases == 0); \
            CHECK(a.observations == 0); \
            CHECK(rome2_free_list_pool_##suffix##_destroy(&handle) == ROME2_FREE_LIST_POOL_OK); \
        } \
    } \
    { \
        unsigned fail; \
        for (fail = 1; fail <= 2; ++fail) { \
            test_heap heap = {0}; \
            rome2_owned_string_allocator allocator = policy(&heap); \
            rome2_owned_free_list_pool_##suffix *sentinel = \
                (rome2_owned_free_list_pool_##suffix *)(void *)&heap; \
            rome2_owned_free_list_pool_##suffix *handle = sentinel; \
            heap.fail_at = fail; \
            CHECK(rome2_free_list_pool_##suffix##_create(&handle, 5, 7, &allocator) \
                == ROME2_FREE_LIST_POOL_ALLOCATION_FAILED); \
            CHECK(handle == sentinel && heap.live == 0 && heap.allocations == fail); \
            CHECK(heap.releases == fail - 1u); \
        } \
    } \
    { \
        test_heap heap = {0}; \
        rome2_owned_string_allocator allocator = policy(&heap); \
        rome2_owned_free_list_pool_##suffix *handle = NULL; \
        heap.fail_at = 1; \
        CHECK(rome2_free_list_pool_##suffix##_create(&handle, 0, 0, &allocator) \
            == ROME2_FREE_LIST_POOL_ALLOCATION_FAILED); \
        CHECK(handle == NULL && heap.live == 0 && heap.releases == 0); \
    } \
    { \
        test_heap heap = {0}; \
        rome2_owned_string_allocator allocator = policy(&heap); \
        rome2_owned_free_list_pool_##suffix *handle = NULL; \
        CHECK(rome2_free_list_pool_##suffix##_create(&handle, (maximum) + 1u, 0, &allocator) \
            == ROME2_FREE_LIST_POOL_COUNT_OUT_OF_RANGE); \
        CHECK(rome2_free_list_pool_##suffix##_create(&handle, UINT32_MAX, 0, &allocator) \
            == ROME2_FREE_LIST_POOL_COUNT_OUT_OF_RANGE); \
        CHECK(rome2_free_list_pool_##suffix##_create(NULL, 1, 0, &allocator) \
            == ROME2_FREE_LIST_POOL_BAD_ARGUMENT); \
        allocator.release = NULL; \
        CHECK(rome2_free_list_pool_##suffix##_create(&handle, 1, 0, &allocator) \
            == ROME2_FREE_LIST_POOL_INVALID_ALLOCATOR); \
        CHECK(heap.allocations == 0 && handle == NULL); \
        CHECK(rome2_free_list_pool_##suffix##_destroy(NULL) == ROME2_FREE_LIST_POOL_BAD_ARGUMENT); \
        CHECK(rome2_free_list_pool_##suffix##_get(NULL) == NULL); \
    } \
}

TEST_POOL(10328370, 0x50u, ROME2_FREE_LIST_POOL_10328370_MAX_SLOTS)
TEST_POOL(1064d4e0, 0x4cu, ROME2_FREE_LIST_POOL_1064D4E0_MAX_SLOTS)
#undef TEST_POOL

int main(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator allocator = policy(&heap);
    rome2_owned_free_list_pool_1064d4e0 *handle = NULL;
    rome2_owned_free_list_pool_10328370 *wrong;
    test_10328370();
    test_1064d4e0();
    CHECK(rome2_free_list_pool_1064d4e0_create(&handle, 1, 1, &allocator)
        == ROME2_FREE_LIST_POOL_OK);
    wrong = (rome2_owned_free_list_pool_10328370 *)(void *)handle;
    CHECK(rome2_free_list_pool_10328370_get(wrong) == NULL);
    CHECK(rome2_free_list_pool_10328370_destroy(&wrong) == ROME2_FREE_LIST_POOL_INVALID_HANDLE);
    CHECK(heap.live == 2);
    CHECK(rome2_free_list_pool_1064d4e0_destroy(&handle) == ROME2_FREE_LIST_POOL_OK);
    CHECK(heap.live == 0);
    printf("free-list pool constructors: %u checks passed\n", checks);
    return 0;
}
