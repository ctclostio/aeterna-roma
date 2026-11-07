#include "owned_entity.h"
#include "test_support.h"

typedef struct fixture {
    rome2_battle_entity source;
    rome2_recovered_str items[2];
    char bytes[3];
} fixture;

static void make_fixture(fixture *f)
{
    rome2_recovered_str s;
    memset(f, 0xa5, sizeof *f);
    f->bytes[0] = 'x'; f->bytes[1] = 0; f->bytes[2] = -2;
    s.length = 3; s.capacity = 17; s.data = f->bytes;
    f->source.category = s;
    f->source.label = s;
    f->source.descriptor_text = s;
    f->source.climate.name_alt = s;
    f->source.label_alt = s;
    f->source.effect_kind = s;
    f->source.source_name = s;
    f->source.item_count = 2;
    f->source.item_capacity = 0; /* ignored original source capacity */
    f->source.items = f->items;
    f->items[0] = s; f->items[1] = s;
    /* Both fixed names, all dispatch cells and field_00c deliberately remain
     * malformed poison: the original copy constructs rather than reads them. */
}

static void compare(const rome2_battle_entity *value, const fixture *f)
{
    const rome2_battle_entity *source = &f->source;
    const rome2_recovered_str *strings[] = {&value->category, &value->label,
        &value->descriptor_text, &value->climate.name_alt, &value->label_alt,
        &value->effect_kind, &value->source_name, &value->items[0], &value->items[1]};
    size_t i, j;
    CHECK(value->dispatch.slot3 == 0);
    CHECK(value->climate.dispatch2 == 0);
    CHECK(strcmp(value->effect_name.data, "auto_generator_input") == 0);
    CHECK(strcmp(value->climate.name.data, "Climate Conditions") == 0);
    CHECK(value->item_count == 2 && value->item_capacity == 2 && value->items != f->items);
    for (i = 0; i < sizeof strings / sizeof strings[0]; ++i) {
        CHECK(strings[i]->length == 3 && strings[i]->capacity == 3);
        CHECK(strings[i]->data != f->bytes && strings[i]->data[3] == 0);
        CHECK(memcmp(strings[i]->data, f->bytes, 3) == 0);
        for (j = 0; j < i; ++j) { CHECK(strings[i]->data != strings[j]->data); }
    }
#define SAME(field) CHECK(memcmp(&value->field, &source->field, sizeof value->field) == 0)
    SAME(origin_x); SAME(origin_y); SAME(grid_extent_min); SAME(grid_extent_max);
    SAME(field_050); SAME(activation_radius_min); SAME(activation_radius_max);
    SAME(point_count); SAME(owner_id); SAME(mode); SAME(field_068); SAME(owner_ref);
    SAME(climate.grid_a); SAME(climate.grid_b); SAME(climate.grid_c);
    SAME(tag_lo); SAME(tag_hi); SAME(flag_0cc); SAME(flag_0dc); SAME(field_0e0); SAME(flag_0e4);
#undef SAME
}

static size_t test_success(void)
{
    unsigned residue;
    size_t calls = 0;
    for (residue = 0; residue < 8; ++residue) {
        test_heap a = {0}, b = {0};
        rome2_owned_string_allocator p = test_policy(&a);
        rome2_owned_battle_entity *handle = NULL;
        const rome2_battle_entity *value;
        fixture f;
        a.residue = residue;
        make_fixture(&f);
        CHECK(rome2_owned_battle_entity_copy(&handle, &f.source, &p) == ROME2_OWNED_ENTITY_OK);
        value = rome2_owned_battle_entity_get(handle);
        CHECK(value != NULL && (uintptr_t)value % 8 == 0);
        compare(value, &f);
        calls = a.allocations;
        memset(&f, 0xdd, sizeof f);
        CHECK(value->category.data[0] == 'x' && value->items[1].data[1] == 0);
        p = test_policy(&b);
        CHECK(rome2_owned_battle_entity_destroy(&handle) == ROME2_OWNED_ENTITY_OK);
        CHECK(handle == NULL && a.live == 0 && a.releases == a.allocations);
        CHECK(a.observations == 11 && b.allocations == 0 && b.releases == 0);
    }
    return calls;
}

static void test_failures(size_t calls)
{
    unsigned residue;
    size_t fail;
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 1; fail <= calls; ++fail) {
            test_heap heap = {0};
            rome2_owned_string_allocator p = test_policy(&heap);
            rome2_owned_battle_entity *sentinel = (rome2_owned_battle_entity *)(void *)&heap;
            rome2_owned_battle_entity *out = sentinel;
            fixture f, before;
            heap.residue = residue; heap.fail_at = fail;
            make_fixture(&f); memcpy(&before, &f, sizeof f);
            CHECK(rome2_owned_battle_entity_copy(&out, &f.source, &p) == ROME2_OWNED_ENTITY_ALLOCATION_FAILED);
            CHECK(out == sentinel && heap.live == 0 && heap.releases == fail - 1);
            CHECK(memcmp(&f, &before, sizeof f) == 0);
        }
    }
}

static void test_invalid(void)
{
    size_t i;
    for (i = 0; i < 10; ++i) {
        test_heap heap = {0};
        rome2_owned_string_allocator p = test_policy(&heap);
        rome2_owned_battle_entity *out = NULL;
        fixture f;
        rome2_recovered_str *strings[7];
        rome2_owned_entity_status expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
        make_fixture(&f);
        strings[0] = &f.source.category; strings[1] = &f.source.label;
        strings[2] = &f.source.descriptor_text; strings[3] = &f.source.climate.name_alt;
        strings[4] = &f.source.label_alt; strings[5] = &f.source.effect_kind;
        strings[6] = &f.source.source_name;
        if (i < 7) { strings[i]->capacity = 2; }
        else if (i == 7) { f.source.item_count = UINT32_MAX; expected = ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE; }
        else if (i == 8) { f.source.items = NULL; expected = ROME2_OWNED_ENTITY_MALFORMED_DESCRIPTOR; }
        else { f.items[1].length = -1; }
        CHECK(rome2_owned_battle_entity_copy(&out, &f.source, &p) == expected);
        CHECK(out == NULL && heap.allocations == 0);
    }
}

static void test_empty_sources_and_arguments(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_battle_entity *h = NULL;
    fixture f;
    rome2_recovered_str *source[9];
    const rome2_recovered_str *copied[9];
    const rome2_battle_entity *value;
    size_t i;
    make_fixture(&f);
    CHECK(rome2_owned_battle_entity_copy(NULL,&f.source,&p) == ROME2_OWNED_ENTITY_BAD_ARGUMENT);
    CHECK(rome2_owned_battle_entity_copy(&h,NULL,&p) == ROME2_OWNED_ENTITY_BAD_ARGUMENT);
    CHECK(rome2_owned_battle_entity_copy(&h,&f.source,NULL) == ROME2_OWNED_ENTITY_INVALID_ALLOCATOR);
    CHECK(heap.allocations == 0);
    source[0] = &f.source.category; source[1] = &f.source.label;
    source[2] = &f.source.descriptor_text; source[3] = &f.source.climate.name_alt;
    source[4] = &f.source.label_alt; source[5] = &f.source.effect_kind;
    source[6] = &f.source.source_name; source[7] = &f.items[0]; source[8] = &f.items[1];
    for (i = 0; i < 9; ++i) { source[i]->length = 0; source[i]->capacity = 0; source[i]->data = (const char *)(uintptr_t)1; }
    CHECK(rome2_owned_battle_entity_copy(&h,&f.source,&p) == ROME2_OWNED_ENTITY_OK);
    value = rome2_owned_battle_entity_get(h);
    copied[0] = &value->category; copied[1] = &value->label;
    copied[2] = &value->descriptor_text; copied[3] = &value->climate.name_alt;
    copied[4] = &value->label_alt; copied[5] = &value->effect_kind;
    copied[6] = &value->source_name; copied[7] = &value->items[0]; copied[8] = &value->items[1];
    for (i = 0; i < 9; ++i) { CHECK(copied[i]->length == 0 && copied[i]->data == rome2_host_string8_empty_sentinel && copied[i]->data[0] == 0); }
    CHECK(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    CHECK(heap.live == 0 && heap.observations == 2);
}

int main(void)
{
    const size_t calls = test_success();
    CHECK(calls == 15);
    test_failures(calls);
    test_invalid();
    test_empty_sources_and_arguments();
    printf("owned attachment: %zu checks, %zu failure positions x 8 alignments\n", checks, calls);
    return 0;
}
