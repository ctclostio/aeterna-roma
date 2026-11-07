#include "scalar_vectors.h"
#include "test_support.h"
#include <float.h>
#include <math.h>

static uint32_t capacity_for(uint32_t count)
{
    uint32_t result = 1;
    while (result < count) { result *= 2; }
    return result;
}

static size_t exercise(unsigned residue, size_t fail_at)
{
    test_heap heap = {0}, other = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_u32_vector *words = NULL;
    rome2_owned_float2_vector *pairs = NULL;
    rome2_scalar_vector_status status;
    rome2_float2 expected[33];
    uint32_t i, j;
    bool failed = false;
    heap.residue = residue; heap.fail_at = fail_at;
    status = rome2_owned_u32_vector_create(&words, &p);
    if (status != ROME2_SCALAR_VECTOR_OK) { CHECK(status == ROME2_SCALAR_VECTOR_ALLOCATION_FAILED); failed = true; }
    if (!failed) {
        status = rome2_owned_float2_vector_create(&pairs, &p);
        if (status != ROME2_SCALAR_VECTOR_OK) { CHECK(status == ROME2_SCALAR_VECTOR_ALLOCATION_FAILED); failed = true; }
    }
    p = test_policy(&other); /* subsequent growth must use captured heap */
    for (i = 0; !failed && i < 33; ++i) {
        const rome2_u32_vector_view before = *rome2_owned_u32_vector_get(words);
        const size_t live_before = heap.live;
        status = rome2_owned_u32_vector_push(words, UINT32_C(0xf0000000) + i);
        if (status == ROME2_SCALAR_VECTOR_ALLOCATION_FAILED) {
            CHECK(memcmp(&before, rome2_owned_u32_vector_get(words), sizeof before) == 0);
            CHECK(heap.live == live_before); failed = true; break;
        }
        CHECK(status == ROME2_SCALAR_VECTOR_OK);
        CHECK(rome2_owned_u32_vector_get(words)->count == i + 1);
        CHECK(rome2_owned_u32_vector_get(words)->capacity == capacity_for(i + 1));
        for (j = 0; j <= i; ++j) { CHECK(rome2_owned_u32_vector_get(words)->items[j] == UINT32_C(0xf0000000) + j); }
        {
            const rome2_float2_vector_view pair_before = *rome2_owned_float2_vector_get(pairs);
            rome2_float2 value;
            const rome2_float2 *source;
            const size_t pair_live = heap.live;
            value.x = (float)i; value.y = -(float)i;
            source = &value;
            if (i != 0 && (i & (i - 1u)) == 0) { source = &pair_before.items[0]; }
            memcpy(&expected[i], source, sizeof value);
            status = rome2_owned_float2_vector_push(pairs, source);
            if (status == ROME2_SCALAR_VECTOR_ALLOCATION_FAILED) {
                CHECK(memcmp(&pair_before, rome2_owned_float2_vector_get(pairs), sizeof pair_before) == 0);
                CHECK(heap.live == pair_live); failed = true; break;
            }
            CHECK(status == ROME2_SCALAR_VECTOR_OK);
            CHECK(rome2_owned_float2_vector_get(pairs)->capacity == capacity_for(i + 1));
            CHECK(rome2_owned_float2_vector_get(pairs)->count == i + 1);
            for (j = 0; j <= i; ++j) { CHECK(memcmp(&rome2_owned_float2_vector_get(pairs)->items[j], &expected[j], sizeof value) == 0); }
        }
    }
    CHECK(failed == (fail_at != 0));
    if (pairs != NULL) {
        rome2_owned_float2_vector *alias = pairs;
        CHECK(rome2_owned_u32_vector_get(pairs) == NULL);
        CHECK(rome2_owned_u32_vector_push(pairs, 1) == ROME2_SCALAR_VECTOR_INVALID_HANDLE);
        CHECK(rome2_owned_u32_vector_destroy(&alias) == ROME2_SCALAR_VECTOR_INVALID_HANDLE && alias == pairs);
    }
    CHECK(rome2_owned_u32_vector_destroy(&words) == ROME2_SCALAR_VECTOR_OK);
    CHECK(rome2_owned_float2_vector_destroy(&pairs) == ROME2_SCALAR_VECTOR_OK);
    CHECK(words == NULL && pairs == NULL && heap.live == 0);
    CHECK(heap.releases == heap.allocations - (failed ? 1u : 0u));
    CHECK(other.allocations == 0 && other.releases == 0 && heap.observations == 0);
    return heap.allocations;
}

static void normalization(void)
{
    const rome2_float2 inside = {0.25f, -0.75f};
    const rome2_float2 outside = {3.0f, 4.0f};
    const rome2_float2 invalid[] = {{NAN, 0}, {0, INFINITY}, {FLT_MAX, FLT_MAX}};
    rome2_float2 result;
    size_t i;
    CHECK(rome2_float2_normalize_unit_disk(inside, &result));
    CHECK(memcmp(&result, &inside, sizeof result) == 0);
    CHECK(rome2_float2_normalize_unit_disk(outside, &result));
    CHECK(result.x == 0.6f && result.y == 0.8f);
    {
        /* Original SSE reciprocal-then-multiply differs from direct division
         * for (3,14): the latter would produce x bits 0x3e568ecb. */
        const rome2_float2 sensitive = {3.0f,14.0f};
        const uint32_t expected[2] = {UINT32_C(0x3e568eca),UINT32_C(0x3f7a5141)};
        CHECK(rome2_float2_normalize_unit_disk(sensitive,&result));
        CHECK(memcmp(&result,expected,sizeof result) == 0);
    }
    for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        const rome2_float2 before = {17.0f, 23.0f};
        result = before;
        CHECK(!rome2_float2_normalize_unit_disk(invalid[i], &result));
        CHECK(memcmp(&result, &before, sizeof result) == 0);
    }
    CHECK(!rome2_float2_normalize_unit_disk(inside, NULL));
}

static void raw_bits_and_guards(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_float2_vector *pairs = NULL;
    const uint32_t bits[2] = {UINT32_C(0x7f800001), UINT32_C(0xff800001)};
    rome2_float2 value;
    memcpy(&value, bits, sizeof value);
    CHECK(rome2_owned_float2_vector_create(&pairs, &p) == ROME2_SCALAR_VECTOR_OK);
    CHECK(rome2_owned_float2_vector_get(pairs)->items == NULL);
    CHECK(rome2_owned_float2_vector_push(pairs, &value) == ROME2_SCALAR_VECTOR_OK);
    CHECK(rome2_owned_float2_vector_push(pairs, &rome2_owned_float2_vector_get(pairs)->items[0]) == ROME2_SCALAR_VECTOR_OK);
    CHECK(memcmp(&rome2_owned_float2_vector_get(pairs)->items[0], bits, sizeof bits) == 0);
    CHECK(memcmp(&rome2_owned_float2_vector_get(pairs)->items[1], bits, sizeof bits) == 0);
    CHECK(rome2_owned_float2_vector_push(pairs, NULL) == ROME2_SCALAR_VECTOR_BAD_ARGUMENT);
    CHECK(rome2_owned_float2_vector_destroy(&pairs) == ROME2_SCALAR_VECTOR_OK);
    CHECK(rome2_owned_float2_vector_destroy(&pairs) == ROME2_SCALAR_VECTOR_OK);
    CHECK(rome2_owned_u32_vector_create(NULL, &p) == ROME2_SCALAR_VECTOR_BAD_ARGUMENT);
    CHECK(rome2_owned_u32_vector_destroy(NULL) == ROME2_SCALAR_VECTOR_BAD_ARGUMENT);
    CHECK(rome2_owned_u32_vector_get(NULL) == NULL);
    CHECK(heap.live == 0);
}

int main(void)
{
    unsigned residue;
    size_t fail, calls = 0;
    for (residue = 0; residue < 8; ++residue) { calls = exercise(residue, 0); }
    CHECK(calls == 16);
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 1; fail <= calls; ++fail) { (void)exercise(residue, fail); }
    }
    normalization(); raw_bits_and_guards();
    printf("scalar vectors: %zu checks, %zu allocation failure positions x 8 alignments\n", checks, calls);
    return 0;
}
