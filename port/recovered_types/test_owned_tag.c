#include "owned_tag.h"
#include "guest32_layouts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
    exit(1); } } while (0)

typedef struct grant {
    unsigned char *actual, *raw;
    size_t bytes, total;
} grant;

typedef struct test_heap {
    unsigned allocations, releases, fail_at, residue, live, observations;
    grant grants[32];
    uintptr_t last_release;
    size_t last_release_bytes;
} test_heap;

static void *allocate(void *context, size_t bytes, uint32_t allocation_class)
{
    test_heap *heap = context;
    grant *g;
    unsigned i;
    ++heap->allocations;
    CHECK(allocation_class == 0);
    if (heap->allocations == heap->fail_at) {
        return NULL;
    }
    CHECK(bytes < 1024u * 1024u && heap->live < 32);
    for (i = 0; i < 32; ++i) {
        if (heap->grants[i].actual == NULL) {
            g = &heap->grants[i];
            g->total = bytes + 80;
            g->actual = malloc(g->total);
            CHECK(g->actual != NULL);
            memset(g->actual, 0xa5, g->total);
            g->raw = g->actual + 32 + heap->residue;
            g->bytes = bytes;
            ++heap->live;
            return g->raw;
        }
    }
    CHECK(0);
    return NULL;
}

static void release(void *context, void *raw, size_t bytes, uint32_t allocation_class)
{
    test_heap *heap = context;
    unsigned i;
    size_t j;
    CHECK(allocation_class == 0);
    for (i = 0; i < 32; ++i) {
        grant *g = &heap->grants[i];
        if (g->actual != NULL && g->raw == raw) {
            CHECK(g->bytes == bytes && heap->live != 0);
            for (j = 0; j < (size_t)(g->raw - g->actual); ++j) {
                CHECK(g->actual[j] == 0xa5);
            }
            for (j = (size_t)(g->raw - g->actual) + bytes; j < g->total; ++j) {
                CHECK(g->actual[j] == 0xa5);
            }
            heap->last_release = (uintptr_t)raw;
            heap->last_release_bytes = bytes;
            memset(g->raw, 0xdd, bytes);
            free(g->actual);
            memset(g, 0, sizeof *g);
            --heap->live;
            ++heap->releases;
            return;
        }
    }
    CHECK(0); /* foreign allocator, wrong raw base, or duplicate release */
}

static void observer(void *context, uintptr_t identity, size_t bytes)
{
    test_heap *heap = context;
    CHECK(heap->last_release == identity && heap->last_release_bytes == bytes);
    CHECK(heap->observations < heap->releases);
    ++heap->observations;
}

static rome2_owned_string_allocator policy(test_heap *heap)
{
    rome2_owned_string_allocator value = {allocate, release, heap, observer, heap};
    return value;
}

typedef struct fixture {
    char name[3];
    uint16_t text[4];
    rome2_unit_card_tag_leaf children[3];
    rome2_unit_card_tag_element elements[2];
    rome2_unit_card_tag source;
} fixture;

static void make_fixture(fixture *f)
{
    size_t i, j;
    memset(f, 0, sizeof *f);
    f->name[0] = 'A'; f->name[1] = 0; f->name[2] = -2;
    f->text[0] = 0xd800; f->text[1] = 0; f->text[2] = 0xdcff; f->text[3] = 0xffff;
    for (i = 0; i < 3; ++i) {
        f->children[i].name.length = 3;
        f->children[i].name.capacity = 9;
        f->children[i].name.data = f->name;
        for (j = 0; j < 16; ++j) {
            f->children[i].words_00c[j] = UINT32_C(0x7f800001) + (uint32_t)(17 * i + j);
        }
    }
    for (i = 0; i < 2; ++i) {
        rome2_unit_card_tag_element *e = &f->elements[i];
        e->name = f->children[0].name;
        for (j = 0; j < 4; ++j) { e->words_00c[j] = (uint32_t)(101 + 13 * i + j); }
        e->word_01c = (uint16_t)(0xfedc + i);
        memset(e->unobserved_01e, 0xcc, sizeof e->unobserved_01e);
        for (j = 0; j < 12; ++j) { e->words_020[j] = UINT32_C(0xff800000) + (uint32_t)(19 * i + j); }
        for (j = 0; j < 7; ++j) { e->bytes_050[j] = (uint8_t)(0xf0 + i + j); }
        e->unobserved_057 = 0xcc;
        e->word_058 = UINT32_C(0xffffffff) - (uint32_t)i;
        e->text.length_units = 4;
        e->text.capacity_units = 17;
        e->text.data = f->text;
        for (j = 0; j < 5; ++j) { e->words_068[j] = UINT32_C(0x80000000) + (uint32_t)(7 * i + j); }
        /* Source capacity deliberately disagrees. The helper never reads it. */
        e->children.capacity = -1;
        e->children.count = i == 0 ? 2 : 1;
        e->children.items = &f->children[i == 0 ? 0 : 2];
    }
    f->source.vtable_identity = 0xdeadbeef; /* not copied or invoked */
    f->source.elements.capacity = -1;
    f->source.elements.count = 2;
    f->source.elements.items = f->elements;
}

static void compare_name(const rome2_host_string8 *actual, const rome2_host_string8 *source)
{
    CHECK(actual->length == source->length && actual->capacity == source->length);
    CHECK(actual->data != source->data && actual->data[actual->length] == 0);
    CHECK(memcmp(actual->data, source->data, (size_t)source->length) == 0);
}

static void compare_copy(const rome2_unit_card_tag *actual, const fixture *f)
{
    size_t i, j;
    CHECK(actual->vtable_identity == ROME2_TAG_VTABLE_IDENTITY);
    CHECK(actual->elements.count == 2 && actual->elements.capacity == 2);
    CHECK(actual->elements.items != f->elements);
    CHECK((uintptr_t)actual->elements.items % 8u == 0);
    for (i = 0; i < 2; ++i) {
        const rome2_unit_card_tag_element *a = &actual->elements.items[i];
        const rome2_unit_card_tag_element *s = &f->elements[i];
        compare_name(&a->name, &s->name);
        CHECK(memcmp(a->words_00c, s->words_00c, sizeof a->words_00c) == 0);
        CHECK(a->word_01c == s->word_01c);
        CHECK(a->unobserved_01e[0] == 0 && a->unobserved_01e[1] == 0);
        CHECK(memcmp(a->words_020, s->words_020, sizeof a->words_020) == 0);
        CHECK(memcmp(a->bytes_050, s->bytes_050, sizeof a->bytes_050) == 0);
        CHECK(a->unobserved_057 == 0 && a->word_058 == s->word_058);
        CHECK(a->text.length_units == 4 && a->text.capacity_units == 4);
        CHECK(a->text.data != s->text.data && a->text.data[4] == 0);
        CHECK(memcmp(a->text.data, s->text.data, 8) == 0);
        CHECK(memcmp(a->words_068, s->words_068, sizeof a->words_068) == 0);
        CHECK(a->children.count == s->children.count && a->children.capacity == s->children.count);
        CHECK(a->children.items != s->children.items);
        CHECK((uintptr_t)a->children.items % 8u == 0);
        for (j = 0; j < (size_t)s->children.count; ++j) {
            compare_name(&a->children.items[j].name, &s->children.items[j].name);
            CHECK(memcmp(a->children.items[j].words_00c, s->children.items[j].words_00c,
                sizeof a->children.items[j].words_00c) == 0);
        }
    }
    CHECK(actual->elements.items[0].name.data != actual->elements.items[1].name.data);
    CHECK(actual->elements.items[0].text.data != actual->elements.items[1].text.data);
    CHECK(actual->elements.items[0].children.items[0].name.data !=
        actual->elements.items[0].children.items[1].name.data);
}

static unsigned test_success(void)
{
    unsigned residue, allocations = 0;
    for (residue = 0; residue < 8; ++residue) {
        test_heap a = {0}, b = {0};
        rome2_owned_string_allocator allocator = policy(&a);
        rome2_owned_unit_card_tag *handle = NULL;
        const rome2_unit_card_tag *value;
        fixture f;
        make_fixture(&f);
        a.residue = residue;
        CHECK(rome2_owned_unit_card_tag_create(&handle, &f.source.elements, &allocator) == ROME2_OWNED_TAG_OK);
        CHECK((uintptr_t)handle % 8u == 0);
        value = rome2_owned_unit_card_tag_get(handle);
        CHECK(value != NULL);
        compare_copy(value, &f);
        /* Revoke all source storage, including arrays, while the copy lives. */
        memset(&f, 0xdd, sizeof f);
        CHECK(value->elements.items[1].name.data[0] == 'A');
        CHECK(value->elements.items[0].text.data[2] == 0xdcff);
        CHECK((unsigned char)value->elements.items[1].children.items[0].name.data[2] == 0xfe);
        allocations = a.allocations;
        allocator = policy(&b);
        CHECK(rome2_owned_unit_card_tag_destroy(&handle) == ROME2_OWNED_TAG_OK);
        CHECK(handle == NULL && a.live == 0 && a.releases == allocations);
        CHECK(a.observations == 7 && b.allocations == 0 && b.releases == 0);
        CHECK(rome2_owned_unit_card_tag_destroy(&handle) == ROME2_OWNED_TAG_OK);
    }
    return allocations;
}

static void test_failures(unsigned allocations)
{
    unsigned fail, residue;
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 1; fail <= allocations; ++fail) {
            test_heap heap = {0};
            rome2_owned_string_allocator allocator = policy(&heap);
            rome2_owned_unit_card_tag *sentinel = (rome2_owned_unit_card_tag *)(void *)&heap;
            rome2_owned_unit_card_tag *out = sentinel;
            fixture f, before;
            make_fixture(&f);
            memcpy(&before, &f, sizeof f);
            heap.residue = residue;
            heap.fail_at = fail;
            CHECK(rome2_owned_unit_card_tag_create(&out, &f.source.elements, &allocator) == ROME2_OWNED_TAG_ALLOCATION_FAILED);
            CHECK(out == sentinel && heap.live == 0 && heap.allocations == fail);
            CHECK(heap.releases == fail - 1);
            CHECK(memcmp(&f, &before, sizeof f) == 0);
        }
    }
}

static void test_empty(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator allocator = policy(&heap);
    rome2_owned_unit_card_tag *handle = NULL;
    rome2_unit_card_tag_vector source = {INT32_MIN, 0,
        (const rome2_unit_card_tag_element *)(uintptr_t)1};
    const rome2_unit_card_tag *value;
    fixture f;
    CHECK(rome2_owned_unit_card_tag_create(&handle, &source, &allocator) == ROME2_OWNED_TAG_OK);
    value = rome2_owned_unit_card_tag_get(handle);
    CHECK(value != NULL && value->elements.items == NULL && value->elements.count == 0);
    CHECK(heap.allocations == 1);
    CHECK(rome2_owned_unit_card_tag_destroy(&handle) == ROME2_OWNED_TAG_OK);
    CHECK(heap.live == 0 && heap.observations == 0);
    heap.fail_at = heap.allocations + 1;
    CHECK(rome2_owned_unit_card_tag_create(&handle, &source, &allocator) == ROME2_OWNED_TAG_ALLOCATION_FAILED);
    CHECK(handle == NULL && heap.live == 0);
    heap.fail_at = 0;
    make_fixture(&f);
    f.source.elements.count = 1;
    f.elements[0].name.length = 0;
    f.elements[0].name.data = (const char *)(uintptr_t)1;
    f.elements[0].text.length_units = 0;
    f.elements[0].text.data = (const uint16_t *)(uintptr_t)1;
    f.elements[0].children.count = 0;
    f.elements[0].children.items = (const rome2_unit_card_tag_leaf *)(uintptr_t)1;
    CHECK(rome2_owned_unit_card_tag_create(&handle, &f.source.elements, &allocator) == ROME2_OWNED_TAG_OK);
    value = rome2_owned_unit_card_tag_get(handle);
    CHECK(value->elements.items[0].name.data == rome2_host_string8_empty_sentinel);
    CHECK(value->elements.items[0].text.data == rome2_host_string16_empty_sentinel);
    CHECK(value->elements.items[0].children.items == NULL);
    CHECK(rome2_owned_unit_card_tag_destroy(&handle) == ROME2_OWNED_TAG_OK);
    CHECK(heap.live == 0 && heap.observations == 0);
    make_fixture(&f);
    f.children[0].name.length = 0;
    f.children[0].name.capacity = 0;
    f.children[0].name.data = (const char *)(uintptr_t)1;
    CHECK(rome2_owned_unit_card_tag_create(&handle, &f.source.elements, &allocator) == ROME2_OWNED_TAG_OK);
    value = rome2_owned_unit_card_tag_get(handle);
    CHECK(value->elements.items[0].children.items[0].name.data == rome2_host_string8_empty_sentinel);
    CHECK(value->elements.items[0].children.items[1].name.length == 3);
    CHECK(rome2_owned_unit_card_tag_destroy(&handle) == ROME2_OWNED_TAG_OK);
    CHECK(heap.live == 0 && heap.observations == 6);
}

static void test_invalid(void)
{
    unsigned which;
    for (which = 0; which < 17; ++which) {
        test_heap heap = {0};
        rome2_owned_string_allocator allocator = policy(&heap);
        rome2_owned_unit_card_tag *out = NULL;
        fixture f;
        rome2_owned_tag_status expected = ROME2_OWNED_TAG_MALFORMED_STRING;
        make_fixture(&f);
        switch (which) {
        case 0: f.source.elements.count = -1; expected = ROME2_OWNED_TAG_COUNT_OUT_OF_RANGE; break;
        case 1: f.source.elements.count = (int32_t)ROME2_TAG_MAX_ELEMENTS + 1; expected = ROME2_OWNED_TAG_COUNT_OUT_OF_RANGE; break;
        case 2: f.source.elements.items = NULL; expected = ROME2_OWNED_TAG_BAD_ARGUMENT; break;
        case 3: f.elements[1].children.count = -1; expected = ROME2_OWNED_TAG_COUNT_OUT_OF_RANGE; break;
        case 4: f.elements[1].children.count = (int32_t)ROME2_TAG_MAX_CHILDREN + 1; expected = ROME2_OWNED_TAG_COUNT_OUT_OF_RANGE; break;
        case 5: f.elements[1].children.items = NULL; expected = ROME2_OWNED_TAG_BAD_ARGUMENT; break;
        case 6: f.elements[1].name.length = -1; break;
        case 7: f.elements[1].name.capacity = 2; break;
        case 8: f.elements[1].name.data = NULL; break;
        case 9: f.elements[1].text.length_units = -1; break;
        case 10: f.elements[1].text.capacity_units = 3; break;
        case 11: f.elements[1].text.data = NULL; break;
        case 12: f.elements[1].text.length_units = INT32_MAX; f.elements[1].text.capacity_units = INT32_MAX; break;
        case 13: f.children[2].name.length = -1; break;
        case 14: f.children[2].name.capacity = -1; break;
        case 15: f.children[2].name.data = NULL; break;
        default: allocator.release = NULL; expected = ROME2_OWNED_TAG_INVALID_ALLOCATOR; break;
        }
        CHECK(rome2_owned_unit_card_tag_create(&out, &f.source.elements, &allocator) == expected);
        CHECK(out == NULL && heap.allocations == 0 && heap.releases == 0);
    }
    {
        test_heap heap = {0};
        rome2_owned_string_allocator allocator = policy(&heap);
        rome2_owned_unit_card_tag *out = NULL;
        fixture f;
        make_fixture(&f);
        CHECK(rome2_owned_unit_card_tag_create(NULL, &f.source.elements, &allocator) == ROME2_OWNED_TAG_BAD_ARGUMENT);
        CHECK(rome2_owned_unit_card_tag_create(&out, NULL, &allocator) == ROME2_OWNED_TAG_BAD_ARGUMENT);
        CHECK(rome2_owned_unit_card_tag_create(&out, &f.source.elements, NULL) == ROME2_OWNED_TAG_INVALID_ALLOCATOR);
        CHECK(rome2_owned_unit_card_tag_get(NULL) == NULL);
        CHECK(rome2_owned_unit_card_tag_destroy(NULL) == ROME2_OWNED_TAG_BAD_ARGUMENT);
        CHECK(heap.allocations == 0);
    }
}

static void test_release_authority(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator allocator = policy(&heap);
    rome2_owned_unit_card_tag *handle = NULL;
    fixture f;
    rome2_unit_card_tag *view;
    rome2_unit_card_tag_element *elements;
    make_fixture(&f);
    CHECK(rome2_owned_unit_card_tag_create(&handle, &f.source.elements, &allocator) == ROME2_OWNED_TAG_OK);
    /* Deliberately violate the read-only-view contract to verify the narrow
     * release-authority guarantee: these are copies, not owner bookkeeping.
     * This does not make arbitrary memory corruption a supported use. */
    view = (rome2_unit_card_tag *)(uintptr_t)rome2_owned_unit_card_tag_get(handle);
    elements = (rome2_unit_card_tag_element *)(uintptr_t)view->elements.items;
    elements[0].name.data = (const char *)(uintptr_t)1;
    elements[1].text.length_units = INT32_MAX;
    elements[0].children.items = NULL;
    elements[0].children.count = INT32_MAX;
    view->elements.items = NULL;
    view->elements.count = INT32_MAX;
    CHECK(rome2_owned_unit_card_tag_destroy(&handle) == ROME2_OWNED_TAG_OK);
    CHECK(handle == NULL && heap.live == 0 && heap.releases == heap.allocations);
    CHECK(heap.observations == 7);
}

int main(void)
{
    const unsigned allocations = test_success();
    CHECK(allocations == 11);
    test_failures(allocations);
    test_empty();
    test_invalid();
    test_release_authority();
    printf("owned tag: %u checks, %u allocation failure positions x 8 alignments\n", checks, allocations);
    return 0;
}
