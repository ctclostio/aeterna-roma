#include "unit_card_resource.h"
#include "test_resource_support.h"

static const char source_xml[] = "<unrelated><chosen><WOLF><min_entities>7</min_entities>"
    "<spawn_probability>0.5</spawn_probability><spawn_conditions><climate>NEW_Climate</climate>"
    "<climate>second</climate></spawn_conditions></WOLF><seagull/></chosen><ignored/></unrelated>";

static rome2_xml_document *document(resource_heap *heap, const char *xml)
{
    rome2_xml_document *doc = NULL;
    rome2_owned_string_allocator a = resource_policy(heap);
    CHECK(rome2_xml_document_parse(&doc, (const unsigned char *)xml, strlen(xml), &a) == ROME2_XML_OK);
    return doc;
}

static rome2_owned_unit_card *seed_card(const rome2_owned_string_allocator *a)
{
    const rome2_host_string8 text = {3, 3, "old"};
    const rome2_fauna_record old = {.words_000 = {0, 5}, .strings = {1, 1, &text}};
    const rome2_fauna_vector_view config = {1, 1, &old};
    const rome2_unit_card_args args = {.arg06 = 0x12345678u};
    rome2_owned_unit_card *card = NULL;
    CHECK(rome2_owned_unit_card_create_from_config(&card, &args, NULL, &config, a) == ROME2_UNIT_CARD_OK);
    return card;
}

static void expect_decoded(const rome2_fauna_vector_view *view)
{
    CHECK(view != NULL && view->count == 2);
    CHECK(view->items[0].values.animal_type == 1 && view->items[0].values.min_entities == 7);
    CHECK(view->items[0].words_000[3] == 0x3f000000 && view->items[1].values.animal_type == 14);
    CHECK(view->items[0].strings.count == 2 && strcmp(view->items[0].strings.items[0].data, "new_climate") == 0);
}

static void membership_lifetime_and_validation(void)
{
    resource_heap source = {0}, other = {0}, owner = {0}, loading = {0};
    rome2_xml_document *doc = document(&source, source_xml), *foreign = document(&other, "<foreign/>");
    const rome2_xml_node *root = rome2_xml_document_root(doc), *parent = root->first_child;
    rome2_xml_node fabricated = {0};
    rome2_owned_string_allocator a = resource_policy(&owner), b = resource_policy(&loading), bad = {0};
    rome2_owned_fauna_vector *decoded = NULL, *saved;
    rome2_owned_unit_card *card = seed_card(&a);
    const rome2_native_unit_card *view = rome2_owned_unit_card_get(card);
    const rome2_fauna_vector_view before = view->fauna;
    rome2_card_resource_diagnostic d;
    size_t allocations = owner.allocations;
    CHECK(rome2_xml_document_contains_node(doc, root) && rome2_xml_document_contains_node(doc, parent));
    CHECK(!rome2_xml_document_contains_node(doc, NULL) && !rome2_xml_document_contains_node(NULL, parent));
    CHECK(!rome2_xml_document_contains_node(doc, &fabricated));
    CHECK(!rome2_xml_document_contains_node(doc, rome2_xml_document_root(foreign)));
    CHECK(rome2_owned_unit_card_setup_from_xml_node(NULL, doc, parent, &b, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_setup_from_xml_node(card, doc, &fabricated, &b, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_setup_from_xml_node(card, doc, rome2_xml_document_root(foreign), &b, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_setup_from_xml_node(card, NULL, parent, &b, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_setup_from_xml_node(card, doc, parent, &bad, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(owner.allocations == allocations && loading.allocations == 0);
    CHECK(view->fauna.items == before.items && view->fauna.count == before.count);
    CHECK(rome2_fauna_config_decode_node(&decoded, doc, &fabricated, &b) == ROME2_FAUNA_CONFIG_BAD_ARGUMENT);
    CHECK(rome2_fauna_config_decode_node(&decoded, doc, parent, &bad) == ROME2_FAUNA_CONFIG_INVALID_ALLOCATOR);
    CHECK(decoded == NULL && loading.allocations == 0);
    CHECK(rome2_fauna_config_decode_node(&decoded, doc, parent, &b) == ROME2_FAUNA_CONFIG_OK);
    saved = decoded; allocations = loading.allocations;
    CHECK(rome2_fauna_config_decode_node(&decoded, doc, parent, &b) == ROME2_FAUNA_CONFIG_BAD_ARGUMENT);
    CHECK(decoded == saved && loading.allocations == allocations);
    expect_decoded(rome2_owned_fauna_vector_get(decoded));
    CHECK(rome2_owned_fauna_vector_destroy(&decoded) == ROME2_FAUNA_OK && loading.live == 0);
    CHECK(rome2_owned_unit_card_setup_from_xml_node(card, doc, parent, &b, &d) == ROME2_CARD_RESOURCE_OK);
    CHECK(d.pack == ROME2_PACK_OK && d.xml == ROME2_XML_OK && d.config == ROME2_FAUNA_CONFIG_OK);
    CHECK(d.card == ROME2_UNIT_CARD_OK && d.selected_archive == SIZE_MAX && loading.live == 0);
    CHECK(view->words.count == 1 && view->words.items[0] == 0x12345678u);
    CHECK(rome2_xml_document_destroy(&doc) == ROME2_XML_OK && source.live == 0);
    CHECK(!rome2_xml_document_contains_node(doc, parent));
    expect_decoded(&view->fauna);
    CHECK(rome2_owned_unit_card_destroy(&card) == ROME2_UNIT_CARD_OK && owner.live == 0);
    CHECK(rome2_xml_document_destroy(&foreign) == ROME2_XML_OK && other.live == 0);
}

static size_t decoder_failures(void)
{
    resource_heap source = {0};
    rome2_xml_document *doc = document(&source, source_xml);
    const rome2_xml_node *parent = rome2_xml_document_root(doc)->first_child;
    size_t baseline = 0, fail;
    unsigned residue;
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 0; fail <= baseline; ++fail) {
            resource_heap heap = {0};
            rome2_owned_string_allocator a = resource_policy(&heap);
            rome2_owned_fauna_vector *out = NULL;
            rome2_fauna_config_status status;
            heap.residue = residue; heap.fail_at = fail;
            status = rome2_fauna_config_decode_node(&out, doc, parent, &a);
            if (fail == 0) {
                CHECK(status == ROME2_FAUNA_CONFIG_OK);
                expect_decoded(rome2_owned_fauna_vector_get(out));
                if (residue == 0) { baseline = heap.allocations; }
                CHECK(heap.allocations == baseline);
                CHECK(rome2_owned_fauna_vector_destroy(&out) == ROME2_FAUNA_OK);
            } else { CHECK(status == ROME2_FAUNA_CONFIG_ALLOCATION_FAILED && out == NULL); }
            CHECK(heap.live == 0 && heap.grants == NULL);
            CHECK(rome2_xml_document_contains_node(doc, parent));
        }
    }
    CHECK(rome2_xml_document_destroy(&doc) == ROME2_XML_OK && source.live == 0);
    return baseline;
}

static size_t setup_failures(bool fail_card)
{
    resource_heap source = {0};
    rome2_xml_document *doc = document(&source, source_xml);
    const rome2_xml_node *parent = rome2_xml_document_root(doc)->first_child;
    size_t baseline = 0, fail;
    unsigned residue;
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 0; fail <= baseline; ++fail) {
            resource_heap owner = {0}, loading = {0};
            rome2_owned_string_allocator a = resource_policy(&owner), b = resource_policy(&loading);
            rome2_owned_unit_card *card;
            const rome2_native_unit_card *view;
            rome2_fauna_vector_view before;
            rome2_card_resource_diagnostic d;
            rome2_card_resource_status status;
            size_t allocations;
            owner.residue = residue; loading.residue = residue;
            card = seed_card(&a); view = rome2_owned_unit_card_get(card); before = view->fauna;
            allocations = owner.allocations;
            if (fail != 0) {
                if (fail_card) { owner.fail_at = allocations + fail; }
                else { loading.fail_at = fail; }
            }
            status = rome2_owned_unit_card_setup_from_xml_node(card, doc, parent, &b, &d);
            CHECK(loading.live == 0 && loading.grants == NULL);
            CHECK(d.pack == ROME2_PACK_OK && d.xml == ROME2_XML_OK && d.selected_archive == SIZE_MAX);
            if (fail == 0) {
                CHECK(status == ROME2_CARD_RESOURCE_OK);
                expect_decoded(&view->fauna);
                if (residue == 0) { baseline = fail_card ? owner.allocations - allocations : loading.allocations; }
                CHECK((fail_card ? owner.allocations - allocations : loading.allocations) == baseline);
            } else {
                CHECK(status == (fail_card ? ROME2_CARD_RESOURCE_CARD_ERROR : ROME2_CARD_RESOURCE_CONFIG_ERROR));
                CHECK((fail_card ? d.card == ROME2_UNIT_CARD_ALLOCATION_FAILED : d.config == ROME2_FAUNA_CONFIG_ALLOCATION_FAILED));
                CHECK(view->fauna.count == 0 && view->fauna.items == before.items && view->fauna.capacity == before.capacity);
            }
            CHECK(rome2_owned_unit_card_destroy(&card) == ROME2_UNIT_CARD_OK && owner.live == 0 && owner.grants == NULL);
            CHECK(rome2_xml_document_contains_node(doc, parent));
        }
    }
    CHECK(rome2_xml_document_destroy(&doc) == ROME2_XML_OK && source.live == 0);
    return baseline;
}

typedef struct node_trace {
    resource_heap card, loading;
    const rome2_native_unit_card *view;
    rome2_owned_string_allocator *caller_loading;
    bool watch;
    size_t early_releases, early_observations;
} node_trace;

static void traced_card_release(void *context, void *raw, size_t bytes, uint32_t kind)
{
    node_trace *t = context;
    if (t->watch && t->loading.allocations == 0) {
        CHECK(t->view->fauna.count == 0); ++t->early_releases;
        memset(t->caller_loading, 0, sizeof *t->caller_loading);
    }
    resource_release(&t->card, raw, bytes, kind);
}

static void traced_card_observer(void *context, uintptr_t raw, size_t bytes)
{
    node_trace *t = context;
    if (t->watch && t->loading.allocations == 0) {
        CHECK(t->view->fauna.count == 0); ++t->early_observations;
    }
    resource_observer(&t->card, raw, bytes);
}

static void *traced_loading_allocate(void *context, size_t bytes, uint32_t kind)
{
    node_trace *t = context;
    CHECK(t->view->fauna.count == 0 && t->early_releases != 0 && t->early_observations != 0);
    return resource_allocate(&t->loading, bytes, kind);
}

static void traced_loading_release(void *context, void *raw, size_t bytes, uint32_t kind)
{
    node_trace *t = context;
    resource_release(&t->loading, raw, bytes, kind);
}

static void allocator_capture_and_empty_reuse(void)
{
    resource_heap source = {0};
    rome2_xml_document *doc = document(&source, source_xml), *empty = document(&source, "<arbitrary/>");
    const rome2_xml_node *parent = rome2_xml_document_root(doc)->first_child;
    node_trace trace = {0};
    rome2_owned_string_allocator a = resource_policy(&trace.card);
    rome2_owned_string_allocator b = {traced_loading_allocate, traced_loading_release, &trace,
        resource_observer, &trace.loading};
    rome2_owned_unit_card *card;
    rome2_card_resource_diagnostic d;
    const rome2_native_unit_card *view;
    rome2_fauna_vector_view before;
    size_t allocations;
    a.release = traced_card_release; a.release_observer = traced_card_observer;
    card = seed_card(&a); view = rome2_owned_unit_card_get(card);
    trace.view = view; trace.caller_loading = &b; trace.watch = true;
    CHECK(rome2_owned_unit_card_setup_from_xml_node(card, doc, parent, &b, &d) == ROME2_CARD_RESOURCE_OK);
    trace.watch = false;
    CHECK(b.allocate == NULL && trace.loading.allocations != 0 && trace.loading.live == 0);
    expect_decoded(&view->fauna);
    b = resource_policy(&trace.loading);
    allocations = trace.card.allocations; before = view->fauna;
    CHECK(rome2_owned_unit_card_setup_from_xml_node(card, empty, rome2_xml_document_root(empty), &b, &d) == ROME2_CARD_RESOURCE_OK);
    CHECK(trace.card.allocations == allocations && trace.loading.live == 0);
    CHECK(view->fauna.count == 0 && view->fauna.items == before.items && view->fauna.capacity == before.capacity);
    CHECK(d.config == ROME2_FAUNA_CONFIG_OK && d.card == ROME2_UNIT_CARD_OK && d.selected_archive == SIZE_MAX);
    CHECK(rome2_owned_unit_card_destroy(&card) == ROME2_UNIT_CARD_OK && trace.card.live == 0);
    CHECK(rome2_xml_document_destroy(&doc) == ROME2_XML_OK && rome2_xml_document_destroy(&empty) == ROME2_XML_OK && source.live == 0);
}

int main(void)
{
    size_t decoder, loading, card;
    membership_lifetime_and_validation(); allocator_capture_and_empty_reuse();
    decoder = decoder_failures(); loading = setup_failures(false); card = setup_failures(true);
    printf("unit-card XML node: %zu checks, decoder%zu/loading%zu/card%zu failure positions x8 alignments\n",
        checks, decoder, loading, card);
    return 0;
}
