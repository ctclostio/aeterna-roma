#include "owned_unit_card.h"
#include "test_support.h"

typedef struct observed_heap {
    test_heap heap;
    const rome2_native_unit_card *view;
    bool active;
    int32_t expected_units;
    uint16_t expected_first;
    uint32_t expected_fauna_count;
    unsigned reads;
} observed_heap;

static void read_published_view(void *context, uintptr_t identity, size_t bytes)
{
    observed_heap *h = context;
    test_observer(&h->heap, identity, bytes);
    if (h->active) {
        /* Direct reads through a cached const view: no API re-entry and no
         * mutation of the object being changed by the call in progress. */
        CHECK(h->view->str_0fc.length_units == h->expected_units);
        CHECK(h->view->str_0fc.data[0] == h->expected_first);
        CHECK(h->view->fauna.count == h->expected_fauna_count);
        if (h->view->fauna.count != 0) {
            CHECK(h->view->fauna.items[0].strings.items[0].data[0] == 'F');
        }
        ++h->reads;
    }
}

int main(void)
{
    observed_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap.heap);
    rome2_owned_unit_card *h = NULL;
    rome2_unit_card_args args = {0};
    const rome2_host_string8 name = {1,1,"F"};
    const rome2_fauna_record fauna = {{0},{0,1,&name}};
    const rome2_fauna_vector_view config = {0,1,&fauna};
    rome2_fauna_record pair[2];
    rome2_fauna_vector_view replacement;
    const uint16_t first[] = {11,12}, second[] = {21,22};
    const rome2_string16_view old_text = {first,2}, new_text = {second,2};
    const rome2_string16_view empty = {(const uint16_t *)(uintptr_t)1,0};
    p.release_observer = read_published_view; p.observer_context = &heap;
    CHECK(rome2_owned_unit_card_create_from_config(&h,&args,NULL,&config,&p) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_set_text16(h,old_text) == ROME2_UNIT_CARD_OK);
    heap.view = rome2_owned_unit_card_get(h);
    heap.active = true; heap.expected_units = 2; heap.expected_first = 21; heap.expected_fauna_count = 1;
    CHECK(rome2_owned_unit_card_set_text16(h,new_text) == ROME2_UNIT_CARD_OK);
    CHECK(heap.reads == 1);
    pair[0] = fauna; pair[1] = fauna;
    replacement.capacity = 0; replacement.count = 2; replacement.items = pair;
    heap.expected_fauna_count = 2;
    CHECK(rome2_owned_unit_card_replace_config(h,&replacement) == ROME2_UNIT_CARD_OK);
    CHECK(heap.reads == 2);
    heap.expected_fauna_count = 0;
    CHECK(rome2_owned_unit_card_clear_fauna(h) == ROME2_UNIT_CARD_OK);
    CHECK(heap.reads == 4);
    heap.expected_units = 0; heap.expected_first = 0;
    CHECK(rome2_owned_unit_card_set_text16(h,empty) == ROME2_UNIT_CARD_OK);
    CHECK(heap.reads == 5);
    heap.active = false;
    CHECK(rome2_owned_unit_card_destroy(&h) == ROME2_UNIT_CARD_OK);
    CHECK(h == NULL && heap.heap.live == 0 && heap.heap.releases == heap.heap.allocations);
    printf("unit-card callback publication: %zu checks\n",checks);
    return 0;
}
