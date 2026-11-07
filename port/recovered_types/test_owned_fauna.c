#include "owned_fauna.h"
#include "test_support.h"

typedef struct fixture {
    rome2_fauna_record record;
    rome2_host_string8 strings[2];
    char bytes[3];
} fixture;
static void make_fixture(fixture *f)
{
    size_t i;
    memset(f, 0, sizeof *f);
    for (i = 0; i < 8; ++i) { f->record.words_000[i] = UINT32_C(0xff800001) + (uint32_t)i; }
    f->bytes[0] = 'F'; f->bytes[1] = 0; f->bytes[2] = -2;
    f->strings[0].length = 3; f->strings[0].capacity = 19; f->strings[0].data = f->bytes;
    f->strings[1].length = 0; f->strings[1].capacity = 0; f->strings[1].data = (const char *)(uintptr_t)1;
    f->record.strings.capacity = UINT32_MAX; /* unread source capacity */
    f->record.strings.count = 2; f->record.strings.items = f->strings;
}

static void verify(const rome2_fauna_vector_view *view, uint32_t count)
{
    uint32_t i, j;
    CHECK(view->count == count);
    for (i = 0; i < count; ++i) {
        const rome2_fauna_record *v = &view->items[i];
        CHECK(v->strings.count == 2 && v->strings.capacity == 2);
        for (j = 0; j < 8; ++j) { CHECK(v->words_000[j] == UINT32_C(0xff800001) + j); }
        CHECK(v->strings.items[0].length == 3 && v->strings.items[0].capacity == 3);
        CHECK(v->strings.items[0].data[0] == 'F' && v->strings.items[0].data[1] == 0);
        CHECK((unsigned char)v->strings.items[0].data[2] == 0xfe && v->strings.items[0].data[3] == 0);
        CHECK(v->strings.items[1].data == rome2_host_string8_empty_sentinel);
        for (j = 0; j < i; ++j) {
            CHECK(v->strings.items[0].data != view->items[j].strings.items[0].data);
            CHECK(v->strings.items != view->items[j].strings.items);
        }
    }
}

static size_t exercise(unsigned residue, size_t fail_at)
{
    test_heap heap = {0}, other = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_fauna_vector *h = NULL;
    rome2_fauna_status status;
    fixture f;
    uint32_t i;
    bool failed = false;
    heap.residue = residue; heap.fail_at = fail_at;
    make_fixture(&f);
    status = rome2_owned_fauna_vector_create(&h, &p);
    if (status != ROME2_FAUNA_OK) { CHECK(status == ROME2_FAUNA_ALLOCATION_FAILED); failed = true; goto done; }
    p = test_policy(&other);
    for (i = 0; i < 5; ++i) {
        const rome2_fauna_vector_view before = *rome2_owned_fauna_vector_get(h);
        const size_t live_before = heap.live;
        const rome2_fauna_record *source = i == 1 ? &before.items[0] : &f.record;
        status = rome2_owned_fauna_vector_push(h, source);
        if (status == ROME2_FAUNA_ALLOCATION_FAILED) {
            CHECK(memcmp(&before, rome2_owned_fauna_vector_get(h), sizeof before) == 0);
            CHECK(heap.live == live_before); verify(&before, i);
            failed = true; goto done;
        }
        CHECK(status == ROME2_FAUNA_OK); verify(rome2_owned_fauna_vector_get(h), i + 1);
    }
    memset(&f, 0xdd, sizeof f); /* revoke the entire borrowed source */
    verify(rome2_owned_fauna_vector_get(h), 5);
    {
        const rome2_fauna_vector_view before = *rome2_owned_fauna_vector_get(h);
        const char *payload = before.items[0].strings.items[0].data;
        const rome2_host_string8 *descriptors = before.items[0].strings.items;
        const size_t live_before = heap.live;
        status = rome2_owned_fauna_vector_reserve_min(h, 9);
        if (status == ROME2_FAUNA_ALLOCATION_FAILED) {
            CHECK(memcmp(&before, rome2_owned_fauna_vector_get(h), sizeof before) == 0);
            CHECK(heap.live == live_before); failed = true; goto done;
        }
        CHECK(status == ROME2_FAUNA_OK);
        CHECK(rome2_owned_fauna_vector_get(h)->capacity == 16);
        CHECK(rome2_owned_fauna_vector_get(h)->items[0].strings.items == descriptors);
        CHECK(rome2_owned_fauna_vector_get(h)->items[0].strings.items[0].data == payload);
    }
    CHECK(rome2_owned_fauna_vector_clear(h) == ROME2_FAUNA_OK);
    CHECK(rome2_owned_fauna_vector_get(h)->count == 0 && rome2_owned_fauna_vector_get(h)->capacity == 16);
    CHECK(heap.live == 2 && heap.observations == 5);
    {
        const rome2_fauna_record empty = {{0}, {UINT32_MAX, 0, (const rome2_host_string8 *)(uintptr_t)1}};
        const rome2_fauna_vector_view before = *rome2_owned_fauna_vector_get(h);
        status = rome2_owned_fauna_vector_push(h, &empty);
        if (status == ROME2_FAUNA_ALLOCATION_FAILED) {
            CHECK(memcmp(&before, rome2_owned_fauna_vector_get(h), sizeof before) == 0);
            CHECK(heap.live == 2); failed = true; goto done;
        }
        CHECK(status == ROME2_FAUNA_OK);
        CHECK(rome2_owned_fauna_vector_get(h)->items[0].strings.items == NULL);
        CHECK(rome2_owned_fauna_vector_clear(h) == ROME2_FAUNA_OK);
        CHECK(heap.live == 2 && heap.observations == 5);
    }
done:
    CHECK(failed == (fail_at != 0));
    CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK);
    CHECK(h == NULL && heap.live == 0);
    CHECK(heap.releases == heap.allocations - (failed ? 1u : 0u));
    CHECK(other.allocations == 0 && other.releases == 0);
    return heap.allocations;
}

static void invalid_and_release_authority(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_fauna_vector *h = NULL;
    fixture f;
    size_t i;
    CHECK(rome2_owned_fauna_vector_create(&h, &p) == ROME2_FAUNA_OK);
    for (i = 0; i < 5; ++i) {
        size_t calls = heap.allocations;
        rome2_fauna_status expected = ROME2_FAUNA_MALFORMED_STRING;
        make_fixture(&f);
        if (i == 0) { f.record.strings.count = UINT32_MAX; expected = ROME2_FAUNA_COUNT_OUT_OF_RANGE; }
        if (i == 1) { f.record.strings.items = NULL; expected = ROME2_FAUNA_BAD_ARGUMENT; }
        if (i == 2) { f.strings[0].length = -1; }
        if (i == 3) { f.strings[0].capacity = 2; }
        if (i == 4) { f.strings[0].data = NULL; }
        CHECK(rome2_owned_fauna_vector_push(h, &f.record) == expected);
        CHECK(heap.allocations == calls && rome2_owned_fauna_vector_get(h)->count == 0);
    }
    CHECK(rome2_owned_fauna_vector_reserve_min(h, UINT32_MAX) == ROME2_FAUNA_COUNT_OUT_OF_RANGE);
    CHECK(heap.allocations == 1);
    make_fixture(&f);
    CHECK(rome2_owned_fauna_vector_push(h, &f.record) == ROME2_FAUNA_OK);
    {
        /* Deliberate view-contract violation checks only release authority. */
        rome2_fauna_vector_view *view = (rome2_fauna_vector_view *)(uintptr_t)rome2_owned_fauna_vector_get(h);
        rome2_fauna_record *record = (rome2_fauna_record *)(uintptr_t)view->items;
        rome2_host_string8 *strings = (rome2_host_string8 *)(uintptr_t)record[0].strings.items;
        strings[0].data = (const char *)(uintptr_t)1;
        record[0].strings.count = UINT32_MAX; record[0].strings.items = NULL;
        view->count = UINT32_MAX; view->items = NULL;
    }
    CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK);
    CHECK(heap.live == 0 && heap.releases == heap.allocations);
    CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK);
}

static void empty_and_argument_guards(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_fauna_vector *h = NULL;
    size_t calls;
    CHECK(rome2_owned_fauna_vector_create(NULL,&p) == ROME2_FAUNA_BAD_ARGUMENT);
    CHECK(rome2_owned_fauna_vector_create(&h,NULL) == ROME2_FAUNA_INVALID_ALLOCATOR);
    CHECK(h == NULL && heap.allocations == 0);
    CHECK(rome2_owned_fauna_vector_get(NULL) == NULL);
    CHECK(rome2_owned_fauna_vector_clear(NULL) == ROME2_FAUNA_INVALID_HANDLE);
    CHECK(rome2_owned_fauna_vector_destroy(NULL) == ROME2_FAUNA_BAD_ARGUMENT);
    CHECK(rome2_owned_fauna_vector_create(&h,&p) == ROME2_FAUNA_OK);
    calls = heap.allocations;
    CHECK(rome2_owned_fauna_vector_clear(h) == ROME2_FAUNA_OK);
    CHECK(rome2_owned_fauna_vector_reserve_min(h,0) == ROME2_FAUNA_OK);
    CHECK(rome2_owned_fauna_vector_push(h,NULL) == ROME2_FAUNA_BAD_ARGUMENT);
    CHECK(heap.allocations == calls);
    CHECK(rome2_owned_fauna_vector_reserve_min(h,3) == ROME2_FAUNA_OK);
    calls = heap.allocations;
    CHECK(rome2_owned_fauna_vector_reserve_min(h,2) == ROME2_FAUNA_OK);
    CHECK(rome2_owned_fauna_vector_clear(h) == ROME2_FAUNA_OK);
    CHECK(heap.allocations == calls && rome2_owned_fauna_vector_get(h)->capacity == 4);
    CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK);
    CHECK(heap.live == 0 && heap.observations == 0);
}

int main(void)
{
    unsigned residue;
    size_t fail, calls = 0;
    for (residue = 0; residue < 8; ++residue) { calls = exercise(residue, 0); }
    CHECK(calls == 22);
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 1; fail <= calls; ++fail) { (void)exercise(residue, fail); }
    }
    invalid_and_release_authority();
    empty_and_argument_guards();
    printf("owned fauna: %zu checks, %zu failure positions x 8 alignments\n", checks, calls);
    return 0;
}
