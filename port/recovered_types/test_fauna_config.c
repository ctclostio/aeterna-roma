#include "fauna_config.h"
#include "test_resource_support.h"

static const rome2_fauna_vector_view *decode(rome2_owned_fauna_vector **h,
    const char *xml, const rome2_owned_string_allocator *a)
{
    rome2_xml_status detail = ROME2_XML_SYSTEM_ERROR;
    CHECK(rome2_fauna_config_decode(h, (const unsigned char *)xml, strlen(xml), a, &detail) == ROME2_FAUNA_CONFIG_OK);
    CHECK(detail == ROME2_XML_OK);
    return rome2_owned_fauna_vector_get(*h);
}

static void animal_ids(void)
{
    static const char source[] = "<fauna_config><deer/><WOLF/><Lion/><elephant/><camel/><boar/>"
        "<horse/><milan/><turtle_dove/><crow/><vulture/><ibis/><peasant/><whale/><seagull/>"
        "<pheasant/><unknown/></fauna_config>";
    resource_heap heap = {0};
    rome2_owned_string_allocator a = resource_policy(&heap);
    rome2_owned_fauna_vector *h = NULL;
    const rome2_fauna_vector_view *v = decode(&h, source, &a);
    size_t i, j;
    CHECK(v != NULL && v->count == 17 && v->capacity == 32);
    for (i = 0; i < 17; ++i) {
        CHECK(v->items[i].values.animal_type == (i < 15 ? (uint32_t)i : 0));
        for (j = 1; j < 8; ++j) { CHECK(v->items[i].words_000[j] == 0); }
        CHECK(v->items[i].strings.count == 0 && v->items[i].strings.items == NULL);
    }
    CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK);
    CHECK(heap.live == 0 && heap.allocations == heap.releases);
}

static void scalar_cases(void)
{
    static const struct { const char *input; uint32_t expect; } integers[] = {
        {"",0}, {"0",0}, {"00017",17}, {"4294967295",UINT32_MAX}, {"4294967296",0},
        {"4294967297",1}, {"18446744073709551615",UINT32_MAX}, {"-1",0}, {"+1",0},
        {" 3",0}, {"3 ",0}, {"12x",0}, {"1e2",0}, {"&#x31;&#x32;",12}
    };
    static const struct { const char *input; uint32_t bits; } floats[] = {
        {"",0}, {"1.0",0x3f800000}, {"0.5",0x3f000000}, {"0.25",0x3e800000},
        {"0.2",0x3e4ccccd}, {"0.4",0x3ecccccd}, {"0.6",0x3f19999a}, {"  +.5tail",0x3f000000},
        {"-1.5",0xbfc00000}, {"1e+2",0x42c80000}, {"1e+",0}, {"garbage",0},
        {"NaN",0}, {"inf",0}, {"1,5",0x3f800000}, {"1.25.5",0x3fa00000},
        {"-0.0",0x80000000}, {"1e0000000002",0x42c80000},
        {"0.001",0x3a83126f}, {"0.0001",0x38d1b718}, {"0.00001",0x3727c5ad},
        {"0.000000001",0x30897061}, {"0.0000000001",0x2edbe702},
        {"0.00000000001",0x2d2fec02}, {"0.00000000000000001",0x233877af},
        {"-.0001",0xb8d1b718}
    };
    size_t i;
    for (i = 0; i < sizeof integers / sizeof integers[0]; ++i) {
        char xml[512];
        resource_heap heap = {0};
        rome2_owned_string_allocator a = resource_policy(&heap);
        rome2_owned_fauna_vector *h = NULL;
        const rome2_fauna_vector_view *v;
        CHECK(sprintf_s(xml, sizeof xml, "<fauna_config><wolf><Min_entities>99</Min_entities>"
            "<min_entities>%s</min_entities><min_entities>777</min_entities>"
            "<max_entities>%s</max_entities></wolf></fauna_config>", integers[i].input, integers[i].input) > 0);
        v = decode(&h, xml, &a);
        CHECK(v->count == 1 && v->items[0].values.min_entities == integers[i].expect);
        CHECK(v->items[0].values.max_entities == integers[i].expect);
        CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK && heap.live == 0);
    }
    for (i = 0; i < sizeof floats / sizeof floats[0]; ++i) {
        char xml[512];
        resource_heap heap = {0};
        rome2_owned_string_allocator a = resource_policy(&heap);
        rome2_owned_fauna_vector *h = NULL;
        const rome2_fauna_vector_view *v;
        CHECK(sprintf_s(xml, sizeof xml, "<fauna_config><wolf><spawn_probability>%s</spawn_probability>"
            "</wolf></fauna_config>", floats[i].input) > 0);
        v = decode(&h, xml, &a);
        CHECK(v->count == 1 && v->items[0].words_000[3] == floats[i].bits);
        CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK && heap.live == 0);
    }
}

static void masks_and_strings(void)
{
    char xml[] = "<fauna_config><wolf><min_entities>2</min_entities><spawn_conditions>"
        "<tile>INLAND</tile><tile>coastal</tile><tile>open_sea</tile><tile>any</tile>"
        "<Tile>inland</Tile><tile> inland</tile><season>spring</season><season>WINTER</season>"
        "<time_of_day>NiGhT</time_of_day><precipitation>snow</precipitation><precipitation>RAIN</precipitation>"
        "<climate>ROME_Continental</climate><climate>R&#xD6;ME_&#x416;</climate>"
        "<climate>&#x1F600;_A</climate><climate/><Climate>ignored</Climate>"
        "</spawn_conditions><spawn_conditions><climate>ignored</climate></spawn_conditions>"
        "</wolf><deer><spawn_conditions><season>spring</season><season>any</season><season>summer</season>"
        "<time_of_day>any</time_of_day><time_of_day>day</time_of_day>"
        "<precipitation>fog</precipitation><precipitation>any</precipitation><precipitation>dry</precipitation>"
        "</spawn_conditions></deer></fauna_config>";
    static const unsigned char expected_bmp[] = {'r',0xc3,0x96,'m','e','_',0xd0,0x96,0};
    static const unsigned char expected_surrogates[] = {0xed,0xa0,0xbd,0xed,0xb8,0x80,'_','a',0};
    resource_heap heap = {0};
    rome2_owned_string_allocator a = resource_policy(&heap);
    rome2_owned_fauna_vector *h = NULL;
    const rome2_fauna_vector_view *v = decode(&h, xml, &a);
    const rome2_fauna_record *r = &v->items[0];
    CHECK(v->count == 2 && r->values.animal_type == 1 && r->values.min_entities == 2);
    CHECK(r->values.tile_mask == 7 && r->values.season_mask == 9);
    CHECK(r->values.time_of_day_mask == 2 && r->values.precipitation_mask == 6);
    CHECK(r->strings.count == 4 && strcmp(r->strings.items[0].data, "rome_continental") == 0);
    CHECK(r->strings.items[1].length == 8 && memcmp(r->strings.items[1].data, expected_bmp, sizeof expected_bmp) == 0);
    CHECK(r->strings.items[2].length == 8 && memcmp(r->strings.items[2].data, expected_surrogates, sizeof expected_surrogates) == 0);
    CHECK(r->strings.items[3].length == 0 && r->strings.items[3].data[0] == 0);
    CHECK(v->items[1].values.season_mask == 15 && v->items[1].values.time_of_day_mask == 3 &&
        v->items[1].values.precipitation_mask == 15);
    memset(xml, 'x', sizeof xml);
    CHECK(strcmp(r->strings.items[0].data, "rome_continental") == 0);
    memset(&a, 0, sizeof a);
    CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK);
    CHECK(heap.live == 0 && heap.allocations == heap.releases && heap.observations != 0);
}

static size_t failure_matrix(void)
{
    static const char xml[] = "<fauna_config><wolf><min_entities>2</min_entities><spawn_probability>0.5</spawn_probability>"
        "<spawn_conditions><climate>ROME_Med</climate><climate/></spawn_conditions></wolf><deer/></fauna_config>";
    size_t baseline = 0, fail;
    unsigned residue;
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 0; fail <= baseline; ++fail) {
            resource_heap heap = {0};
            rome2_owned_string_allocator a = resource_policy(&heap);
            rome2_owned_fauna_vector *h = NULL;
            rome2_fauna_config_status s;
            heap.residue = residue; heap.fail_at = fail;
            s = rome2_fauna_config_decode(&h, (const unsigned char *)xml, sizeof xml - 1u, &a, NULL);
            if (fail == 0) {
                CHECK(s == ROME2_FAUNA_CONFIG_OK && h != NULL);
                if (residue == 0) { baseline = heap.allocations; }
                CHECK(heap.allocations == baseline);
                CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK);
            } else { CHECK(s == ROME2_FAUNA_CONFIG_ALLOCATION_FAILED && h == NULL); }
            CHECK(heap.live == 0 && heap.grants == NULL && heap.releases + (fail != 0 ? 1u : 0u) == heap.allocations);
        }
    }
    return baseline;
}

static void errors(void)
{
    resource_heap heap = {0};
    rome2_owned_string_allocator a = resource_policy(&heap), bad = {0};
    rome2_owned_fauna_vector *h = NULL, *saved;
    rome2_xml_status xml;
    const rome2_fauna_vector_view *v = decode(&h, "<fauna_config/>", &a);
    size_t before = heap.allocations;
    CHECK(v != NULL && v->count == 0 && v->items == NULL);
    saved = h;
    CHECK(rome2_fauna_config_decode(&h, (const unsigned char *)"x", 1, &a, &xml) == ROME2_FAUNA_CONFIG_BAD_ARGUMENT);
    CHECK(h == saved && heap.allocations == before);
    CHECK(rome2_owned_fauna_vector_destroy(&h) == ROME2_FAUNA_OK);
    CHECK(rome2_fauna_config_decode(&h, NULL, 1, &a, &xml) == ROME2_FAUNA_CONFIG_BAD_ARGUMENT && h == NULL);
    CHECK(rome2_fauna_config_decode(&h, NULL, 0, &bad, &xml) == ROME2_FAUNA_CONFIG_INVALID_ALLOCATOR && h == NULL);
    CHECK(rome2_fauna_config_decode(&h, NULL, 0, &a, &xml) == ROME2_FAUNA_CONFIG_XML_ERROR && h == NULL);
    CHECK(rome2_fauna_config_decode(&h, (const unsigned char *)"<Fauna_config/>", 15, &a, &xml) == ROME2_FAUNA_CONFIG_ROOT_NOT_FOUND);
    CHECK(rome2_fauna_config_decode(&h, (const unsigned char *)"<fauna_config>", 14, &a, &xml) == ROME2_FAUNA_CONFIG_XML_ERROR);
    CHECK(heap.live == 0);
}

int main(void)
{
    size_t positions;
    animal_ids(); scalar_cases(); masks_and_strings(); errors(); positions = failure_matrix();
    printf("fauna config: %zu checks, %zu failure positions x8 raw alignments\n", checks, positions);
    return 0;
}
