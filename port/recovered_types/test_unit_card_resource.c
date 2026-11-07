#include "unit_card_resource.h"
#include "test_resource_support.h"
#include <wchar.h>

static const char deer_xml[] = "<fauna_config><deer><min_entities>1</min_entities>"
    "<spawn_conditions><climate>OLD_Climate</climate></spawn_conditions></deer></fauna_config>";
static const char wolf_xml[] = "<fauna_config><wolf><min_entities>2</min_entities><max_entities>15</max_entities>"
    "<spawn_probability>0.5</spawn_probability><spawn_conditions><climate>NEW_Climate</climate>"
    "<climate>any</climate><tile>inland</tile></spawn_conditions></wolf><seagull/></fauna_config>";

static void write_u32(FILE *f, uint32_t value)
{
    const unsigned char b[] = {(unsigned char)value, (unsigned char)(value >> 8),
        (unsigned char)(value >> 16), (unsigned char)(value >> 24)};
    CHECK(fwrite(b, 1, sizeof b, f) == sizeof b);
}

static void fixture(const wchar_t *path, const char *name, const char *contents)
{
    FILE *f = NULL;
    const size_t size = strlen(contents), name_bytes = strlen(name) + 1u;
    CHECK(_wfopen_s(&f, path, L"wb") == 0 && f != NULL);
    CHECK(fwrite("PFH4", 1, 4, f) == 4);
    write_u32(f, 2); write_u32(f, 0); write_u32(f, 0); write_u32(f, 1);
    write_u32(f, (uint32_t)(4u + name_bytes)); write_u32(f, 0);
    write_u32(f, (uint32_t)size);
    CHECK(fwrite(name, 1, name_bytes, f) == name_bytes);
    CHECK(fwrite(contents, 1, size, f) == size);
    CHECK(fclose(f) == 0);
}

static void lookup_and_reload(const wchar_t *first, const wchar_t *second)
{
    resource_heap heap = {0}, transient = {0};
    rome2_owned_string_allocator a = resource_policy(&heap), b = resource_policy(&transient);
    rome2_owned_unit_card *h = NULL, *saved;
    rome2_unit_card_args args = {0};
    const uint16_t *paths[2] = {(const uint16_t *)first, (const uint16_t *)second};
    rome2_card_resource_diagnostic d;
    const rome2_native_unit_card *v;
    rome2_fauna_vector_view prior;
    size_t before;
    args.arg06 = 0x12345678u;
    fixture(first, "script/fauna_config.xml", wolf_xml);
    fixture(second, "script\\fauna_config.xml", deer_xml);
    CHECK(rome2_owned_unit_card_create_from_packs(&h, &args, NULL, paths, 2, &a, &d) == ROME2_CARD_RESOURCE_OK);
    CHECK(d.selected_archive == 0 && d.pack == ROME2_PACK_OK && d.config == ROME2_FAUNA_CONFIG_OK && d.card == ROME2_UNIT_CARD_OK);
    v = rome2_owned_unit_card_get(h);
    CHECK(v != NULL && v->fauna.count == 2 && v->fauna.items[0].values.animal_type == 1);
    CHECK(v->fauna.items[0].values.min_entities == 2 && v->fauna.items[0].words_000[3] == 0x3f000000);
    CHECK(v->words.count == 1 && v->words.items[0] == args.arg06);
    fixture(first, "other_file.xml", "not a configuration");
    CHECK(strcmp(v->fauna.items[0].strings.items[0].data, "new_climate") == 0);
    CHECK(rome2_owned_unit_card_reload_from_packs(h, paths, 2, &b, &d) == ROME2_CARD_RESOURCE_OK);
    CHECK(d.selected_archive == 1 && v->fauna.count == 1 && v->fauna.capacity >= 2);
    CHECK(v->fauna.items[0].values.animal_type == 0 && strcmp(v->fauna.items[0].strings.items[0].data, "old_climate") == 0);
    CHECK(transient.allocations != 0 && transient.live == 0);
    prior = v->fauna;
    fixture(first, "script/fauna_config.xml", "<fauna_config>");
    CHECK(rome2_owned_unit_card_reload_from_packs(h, paths, 2, &a, &d) == ROME2_CARD_RESOURCE_CONFIG_ERROR);
    CHECK(d.selected_archive == 0 && d.config == ROME2_FAUNA_CONFIG_XML_ERROR);
    CHECK(v->fauna.items == prior.items && v->fauna.count == prior.count && v->fauna.capacity == prior.capacity);
    CHECK(strcmp(v->fauna.items[0].strings.items[0].data, "old_climate") == 0);
    fixture(first, "script/fauna_config.xml", "<another_root/>");
    CHECK(rome2_owned_unit_card_reload_from_packs(h, paths, 2, &a, &d) == ROME2_CARD_RESOURCE_CONFIG_ERROR);
    CHECK(d.config == ROME2_FAUNA_CONFIG_ROOT_NOT_FOUND && v->fauna.items == prior.items);
    fixture(first, "script/fauna_config.xml", "<fauna_config/>");
    CHECK(rome2_owned_unit_card_reload_from_packs(h, paths, 2, &a, &d) == ROME2_CARD_RESOURCE_OK);
    CHECK(v->fauna.count == 0 && v->fauna.capacity >= prior.capacity);
    saved = h; before = heap.allocations;
    CHECK(rome2_owned_unit_card_create_from_packs(&h, &args, NULL, paths, 2, &a, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(h == saved && before == heap.allocations);
    memset(&a, 0, sizeof a);
    CHECK(rome2_owned_unit_card_destroy(&h) == ROME2_UNIT_CARD_OK && heap.live == 0);
}

static void errors(const wchar_t *path)
{
    resource_heap heap = {0};
    rome2_owned_string_allocator a = resource_policy(&heap), bad = {0};
    rome2_owned_unit_card *h = NULL;
    rome2_unit_card_args args = {0};
    const uint16_t *paths[] = {(const uint16_t *)path};
    const uint16_t *null_paths[] = {NULL};
    rome2_card_resource_diagnostic d;
    CHECK(rome2_owned_unit_card_create_from_packs(NULL, &args, NULL, paths, 1, &a, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_create_from_packs(&h, NULL, NULL, paths, 1, &a, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_create_from_packs(&h, &args, NULL, NULL, 1, &a, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_create_from_packs(&h, &args, NULL, null_paths, 1, &a, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_create_from_packs(&h, &args, NULL, paths, 1, &bad, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(heap.allocations == 0 && h == NULL);
    CHECK(rome2_owned_unit_card_create_from_packs(&h, &args, NULL, NULL, 0, &a, &d) == ROME2_CARD_RESOURCE_PACK_ERROR);
    CHECK(d.pack == ROME2_PACK_NOT_FOUND && d.selected_archive == SIZE_MAX && heap.allocations == 0);
    fixture(path, "unrelated.xml", "<x/>");
    CHECK(rome2_owned_unit_card_create_from_packs(&h, &args, NULL, paths, 1, &a, &d) == ROME2_CARD_RESOURCE_PACK_ERROR);
    CHECK(d.pack == ROME2_PACK_NOT_FOUND && h == NULL && heap.live == 0);
    fixture(path, "script/fauna_config.xml", wolf_xml);
    args.arg00 = NULL;
    {
        rome2_unit_card_globals globals;
        uint32_t nan = 0x7fc00000u;
        rome2_unit_card_globals_from_image(&globals);
        memcpy(&globals.colour_component_a, &nan, sizeof nan);
        CHECK(rome2_owned_unit_card_create_from_packs(&h, &args, &globals, paths, 1, &a, &d) == ROME2_CARD_RESOURCE_CARD_ERROR);
        CHECK(d.card == ROME2_UNIT_CARD_UNSUPPORTED_COORDINATE && h == NULL && heap.live == 0);
    }
    CHECK(rome2_owned_unit_card_reload_from_packs(NULL, paths, 1, &a, &d) == ROME2_CARD_RESOURCE_BAD_ARGUMENT);
    CHECK(heap.live == 0);
}

static size_t factory_failures(const wchar_t *path)
{
    const uint16_t *paths[] = {(const uint16_t *)path};
    rome2_unit_card_args args = {0};
    size_t baseline = 0, fail;
    unsigned residue;
    fixture(path, "script/fauna_config.xml", wolf_xml);
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 0; fail <= baseline; ++fail) {
            resource_heap heap = {0};
            rome2_owned_string_allocator a = resource_policy(&heap);
            rome2_owned_unit_card *h = NULL;
            rome2_card_resource_diagnostic d;
            rome2_card_resource_status s;
            heap.residue = residue; heap.fail_at = fail;
            s = rome2_owned_unit_card_create_from_packs(&h, &args, NULL, paths, 1, &a, &d);
            if (fail == 0) {
                CHECK(s == ROME2_CARD_RESOURCE_OK && h != NULL);
                if (residue == 0) { baseline = heap.allocations; }
                CHECK(heap.allocations == baseline);
                CHECK(rome2_owned_unit_card_destroy(&h) == ROME2_UNIT_CARD_OK);
            } else {
                CHECK(h == NULL && (s == ROME2_CARD_RESOURCE_PACK_ERROR || s == ROME2_CARD_RESOURCE_CONFIG_ERROR || s == ROME2_CARD_RESOURCE_CARD_ERROR));
                CHECK(d.pack == ROME2_PACK_ALLOCATION_FAILED || d.config == ROME2_FAUNA_CONFIG_ALLOCATION_FAILED || d.card == ROME2_UNIT_CARD_ALLOCATION_FAILED);
            }
            CHECK(heap.live == 0 && heap.grants == NULL && heap.releases + (fail != 0 ? 1u : 0u) == heap.allocations);
        }
    }
    return baseline;
}

static size_t reload_failures(const wchar_t *path)
{
    const uint16_t *paths[] = {(const uint16_t *)path};
    rome2_unit_card_args args = {0};
    const rome2_fauna_record original = {.words_000 = {0, 5}};
    const rome2_fauna_vector_view config = {1, 1, &original};
    size_t baseline = 0, fail;
    unsigned residue;
    fixture(path, "script/fauna_config.xml", wolf_xml);
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 0; fail <= baseline; ++fail) {
            resource_heap heap = {0};
            rome2_owned_string_allocator a = resource_policy(&heap);
            rome2_owned_unit_card *h = NULL;
            const rome2_native_unit_card *v;
            rome2_fauna_vector_view before;
            size_t allocations, live;
            rome2_card_resource_status s;
            heap.residue = residue;
            CHECK(rome2_owned_unit_card_create_from_config(&h, &args, NULL, &config, &a) == ROME2_UNIT_CARD_OK);
            v = rome2_owned_unit_card_get(h); before = v->fauna;
            allocations = heap.allocations; live = heap.live;
            if (fail != 0) { heap.fail_at = allocations + fail; }
            s = rome2_owned_unit_card_reload_from_packs(h, paths, 1, &a, NULL);
            if (fail == 0) {
                CHECK(s == ROME2_CARD_RESOURCE_OK && v->fauna.count == 2 && v->fauna.items[0].values.animal_type == 1);
                if (residue == 0) { baseline = heap.allocations - allocations; }
                CHECK(heap.allocations - allocations == baseline);
            } else {
                CHECK(s != ROME2_CARD_RESOURCE_OK && v->fauna.items == before.items && v->fauna.count == before.count && v->fauna.capacity == before.capacity);
                CHECK(v->fauna.items[0].values.min_entities == 5 && heap.live == live);
            }
            CHECK(rome2_owned_unit_card_destroy(&h) == ROME2_UNIT_CARD_OK);
            CHECK(heap.live == 0 && heap.grants == NULL);
        }
    }
    return baseline;
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t second[1024];
    size_t factory, reload;
    CHECK(argc == 2 && swprintf_s(second, sizeof second / sizeof second[0], L"%ls.second", argv[1]) > 0);
    lookup_and_reload(argv[1], second); errors(argv[1]);
    factory = factory_failures(argv[1]); reload = reload_failures(argv[1]);
    CHECK(_wremove(argv[1]) == 0 && _wremove(second) == 0);
    printf("unit-card resource: %zu checks, factory%zu/reload%zu failures x8 raw alignments\n", checks, factory, reload);
    return 0;
}
