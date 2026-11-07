#include "native_xml.h"
#include "test_resource_support.h"

static bool equal16(const rome2_host_string16 *s, const uint16_t *expected, size_t count)
{
    return s->length_units == (int32_t)count && s->capacity_units == (int32_t)count &&
        s->data != NULL && s->data[count] == 0 && memcmp(s->data, expected, count * sizeof *expected) == 0;
}

static bool ascii16(const rome2_host_string16 *s, const char *expected)
{
    size_t i, count = strlen(expected);
    if (s->length_units != (int32_t)count || s->capacity_units != (int32_t)count || s->data == NULL || s->data[count] != 0) {
        return false;
    }
    for (i = 0; i < count; ++i) { if (s->data[i] != (unsigned char)expected[i]) { return false; } }
    return true;
}

static void document_values(void)
{
    char xml[] = "<?xml version='1.0'?>\r\n<!--before--><?pi value?><Root ignored='x'>"
        "a&amp;<![CDATA[<b>]]><!--gap-->c<child>value</child>tail<Empty/>\r\n\t"
        "<Child>&#65;&#x1F600;</Child></Root><!--after-->";
    static const uint16_t unicode[] = {65, 0xd83d, 0xde00};
    resource_heap heap = {0};
    rome2_owned_string_allocator a = resource_policy(&heap);
    rome2_xml_document *h = NULL;
    const rome2_xml_node *root, *child;
    CHECK(rome2_xml_document_parse(&h, (const unsigned char *)xml, sizeof xml - 1u, &a) == ROME2_XML_OK);
    root = rome2_xml_document_root(h);
    CHECK(root != NULL && ascii16(&root->name, "Root") && ascii16(&root->text, "a&<b>ctail\n\t"));
    CHECK(root->child_count == 3 && root->next_sibling == NULL);
    child = root->first_child;
    CHECK(child != NULL && ascii16(&child->name, "child") && ascii16(&child->text, "value") && child->child_count == 0);
    child = child->next_sibling;
    CHECK(child != NULL && ascii16(&child->name, "Empty") && ascii16(&child->text, "") && child->first_child == NULL);
    child = child->next_sibling;
    CHECK(child != NULL && ascii16(&child->name, "Child") && equal16(&child->text, unicode, 3) && child->next_sibling == NULL);
    memset(xml, 'x', sizeof xml);
    CHECK(ascii16(&root->name, "Root") && ascii16(&root->text, "a&<b>ctail\n\t"));
    memset(&a, 0, sizeof a);
    CHECK(rome2_xml_document_destroy(&h) == ROME2_XML_OK && h == NULL);
    CHECK(heap.live == 0 && heap.grants == NULL && heap.allocations == heap.releases && heap.observations != 0);
}

static void encodings(void)
{
    static const unsigned char utf8[] = {0xef,0xbb,0xbf,'<','a','>',0xc3,0xa9,'<','/','a','>'};
    static const unsigned char le[] = {0xff,0xfe,'<',0,'a',0,'>',0,0xe9,0,'<',0,'/',0,'a',0,'>',0};
    static const unsigned char be[] = {0xfe,0xff,0,'<',0,'a',0,'>',0,0xe9,0,'<',0,'/',0,'a',0,'>'};
    static const struct { const unsigned char *data; size_t size; } sources[] = {
        {utf8,sizeof utf8}, {le,sizeof le}, {be,sizeof be}
    };
    static const uint16_t expected[] = {0xe9};
    size_t i;
    for (i = 0; i < sizeof sources / sizeof sources[0]; ++i) {
        resource_heap heap = {0};
        rome2_owned_string_allocator a = resource_policy(&heap);
        rome2_xml_document *h = NULL;
        CHECK(rome2_xml_document_parse(&h, sources[i].data, sources[i].size, &a) == ROME2_XML_OK);
        CHECK(equal16(&rome2_xml_document_root(h)->text, expected, 1));
        CHECK(rome2_xml_document_destroy(&h) == ROME2_XML_OK && heap.live == 0);
    }
}

static void malformed(void)
{
    static const char *const invalid[] = {"", " ", "<!--x-->", "<a", "<a>", "<a><b/>", "<a></b>",
        "<a/><b/>", "<a/>tail", "<a>&unknown;</a>", "<a>&#0;</a>", "<a>&#xD800;</a>",
        "<a x='1' x='2'/>", "<a><1bad/></a>", "<a>]]></a>", "<a>\xc3\x28</a>",
        "<a>\xc0\xbc</a>", "<a>\xed\xa0\x80</a>", "<?xml version='1.0' encoding='UTF-16'?><a/>"};
    static const char *const unsupported[] = {
        "<!DOCTYPE a [<!ENTITY e 'x'>]><a>&e;</a>", "<!DOCTYPE a SYSTEM 'file:///absent.dtd'><a/>",
        "<a xmlns='urn:x'/>", "<p:a xmlns:p='urn:x'/>", "<a xmlns:p='urn:x' p:x='1'/>", "<a xml:lang='en'/>"
    };
    static const unsigned char zeros[] = {'<','a','>','x',0,'y','<','/','a','>'};
    resource_heap heap = {0};
    rome2_owned_string_allocator a = resource_policy(&heap);
    rome2_xml_document *h = NULL;
    size_t i;
    for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        CHECK(rome2_xml_document_parse(&h, (const unsigned char *)invalid[i], strlen(invalid[i]), &a) == ROME2_XML_MALFORMED);
        CHECK(h == NULL && heap.live == 0);
    }
    for (i = 0; i < sizeof unsupported / sizeof unsupported[0]; ++i) {
        CHECK(rome2_xml_document_parse(&h, (const unsigned char *)unsupported[i], strlen(unsupported[i]), &a) == ROME2_XML_UNSUPPORTED);
        CHECK(h == NULL && heap.live == 0);
    }
    CHECK(rome2_xml_document_parse(&h, zeros, sizeof zeros, &a) == ROME2_XML_MALFORMED && h == NULL && heap.live == 0);
}

static void limits_and_arguments(void)
{
    resource_heap heap = {0};
    rome2_owned_string_allocator a = resource_policy(&heap), bad = {0};
    rome2_xml_document *h = NULL, *saved;
    char deep[1024];
    size_t i, cursor, before;
    CHECK(rome2_xml_document_root(NULL) == NULL && rome2_xml_document_destroy(NULL) == ROME2_XML_BAD_ARGUMENT);
    CHECK(rome2_xml_document_destroy(&h) == ROME2_XML_OK);
    CHECK(rome2_xml_document_parse(NULL, NULL, 0, &a) == ROME2_XML_BAD_ARGUMENT);
    CHECK(rome2_xml_document_parse(&h, NULL, 1, &a) == ROME2_XML_BAD_ARGUMENT);
    CHECK(rome2_xml_document_parse(&h, NULL, 0, &bad) == ROME2_XML_INVALID_ALLOCATOR);
    CHECK(rome2_xml_document_parse(&h, (const unsigned char *)"x", 16u * 1024u * 1024u + 1u, &a) == ROME2_XML_LIMIT_EXCEEDED);
    CHECK(heap.allocations == 0);
    for (i = 128; i <= 129; ++i) {
        size_t j;
        cursor = 0;
        for (j = 0; j < i; ++j) { memcpy(deep + cursor, "<a>", 3); cursor += 3; }
        for (j = 0; j < i; ++j) { memcpy(deep + cursor, "</a>", 4); cursor += 4; }
        CHECK(rome2_xml_document_parse(&h, (const unsigned char *)deep, cursor, &a) ==
            (i == 128 ? ROME2_XML_OK : ROME2_XML_LIMIT_EXCEEDED));
        if (h != NULL) { CHECK(rome2_xml_document_destroy(&h) == ROME2_XML_OK); }
        CHECK(heap.live == 0);
    }
    CHECK(rome2_xml_document_parse(&h, (const unsigned char *)"<a/>", 4, &a) == ROME2_XML_OK);
    saved = h; before = heap.allocations;
    CHECK(rome2_xml_document_parse(&h, (const unsigned char *)"<b/>", 4, &a) == ROME2_XML_BAD_ARGUMENT);
    CHECK(h == saved && heap.allocations == before);
    CHECK(rome2_xml_document_destroy(&h) == ROME2_XML_OK && heap.live == 0);
}

typedef struct observation { resource_heap *heap; rome2_xml_document **handle; } observation;
static void observe_consumed(void *context, uintptr_t raw, size_t bytes)
{
    observation *o = context;
    resource_observer(o->heap, raw, bytes);
    CHECK(*o->handle == NULL && rome2_xml_document_root(*o->handle) == NULL);
}

static void release_authority(void)
{
    static const char xml[] = "<a><b>secret</b><c>other</c></a>";
    resource_heap heap = {0};
    rome2_owned_string_allocator a = resource_policy(&heap);
    rome2_xml_document *h = NULL;
    observation o = {&heap, &h};
    rome2_xml_node *root, *child;
    a.release_observer = observe_consumed; a.observer_context = &o;
    CHECK(rome2_xml_document_parse(&h, (const unsigned char *)xml, sizeof xml - 1u, &a) == ROME2_XML_OK);
    root = (rome2_xml_node *)(uintptr_t)rome2_xml_document_root(h);
    child = (rome2_xml_node *)(uintptr_t)root->first_child;
    root->name.data = (const uint16_t *)(uintptr_t)0x17u; root->name.length_units = INT32_MAX;
    root->first_child = NULL; root->child_count = UINT32_MAX;
    child->text.data = NULL; child->text.capacity_units = -1; child->next_sibling = root;
    memset(&a, 0, sizeof a);
    CHECK(rome2_xml_document_destroy(&h) == ROME2_XML_OK && h == NULL && heap.live == 0);
    CHECK(heap.observations != 0);
}

static size_t failures(void)
{
    static const char xml[] = "<root>first<![CDATA[second]]><!--split-->third<leaf>value&amp;x</leaf>tail</root>";
    size_t baseline = 0, fail;
    unsigned residue;
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 0; fail <= baseline; ++fail) {
            resource_heap heap = {0};
            rome2_owned_string_allocator a = resource_policy(&heap);
            rome2_xml_document *h = NULL;
            rome2_xml_status s;
            heap.residue = residue; heap.fail_at = fail;
            s = rome2_xml_document_parse(&h, (const unsigned char *)xml, sizeof xml - 1u, &a);
            if (fail == 0) {
                CHECK(s == ROME2_XML_OK && h != NULL);
                if (residue == 0) { baseline = heap.allocations; }
                CHECK(heap.allocations == baseline);
                CHECK(ascii16(&rome2_xml_document_root(h)->text, "firstsecondthirdtail"));
                CHECK(rome2_xml_document_destroy(&h) == ROME2_XML_OK);
            } else { CHECK(s == ROME2_XML_ALLOCATION_FAILED && h == NULL); }
            CHECK(heap.live == 0 && heap.grants == NULL && heap.releases + (fail != 0 ? 1u : 0u) == heap.allocations);
        }
    }
    return baseline;
}

int main(void)
{
    size_t positions;
    document_values(); encodings(); malformed(); limits_and_arguments(); release_authority(); positions = failures();
    printf("native XML: %zu checks, %zu failure positions x8 raw alignments\n", checks, positions);
    return 0;
}
