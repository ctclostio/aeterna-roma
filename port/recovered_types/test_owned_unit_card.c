/*
 * Native regression suite for the owning unit-card composition
 * (owned_unit_card.h).  Public API only, plus the shared tracking allocator in
 * test_support.h.  CHECK is unconditional, so every assertion stays active in
 * Release/NDEBUG builds.
 *
 * Covered: the full integrated fixture (nested tag with a child, optional
 * entity copy, two decoded fauna records) and every byte of the 472-byte
 * native prefix; deep independence from revoked sources and from a sibling
 * card; empty/optional variants; failure injection at every allocation
 * position for raw residues 0..7; validation before allocator effects;
 * captured-allocator release authority; and the append, UTF-16 text and
 * configuration mutators including their atomic failures.
 */
#include "owned_unit_card.h"
#include "test_support.h"

#include <float.h>
#include <math.h>

/* ------------------------------------------------------------------------ */
/* Golden data.  Fixtures copy these into revocable buffers; verification     */
/* compares against these, never against the (possibly revoked) fixture.     */
/* ------------------------------------------------------------------------ */

#define K_ARG02 0x02
#define K_ARG03 UINT32_C(0x03c0ffee)
#define K_ARG04 0x44
#define K_ARG05 UINT32_C(0x05050505)
#define K_ARG06 UINT32_C(0xdeadbeef)
#define K_ARG07 UINT32_C(0x07070707)
#define K_ARG08 UINT32_C(9)
#define K_ARG09 1234.5f
#define K_ARG10 UINT32_C(0x0a0a0a0a)
#define K_ARG11 UINT32_C(0xbbbbbbbb)
#define K_ARG12 0x12
#define K_ARG13 0x13
#define K_ARG14 0x14
#define K_ARG15 0x80
#define K_ARG16 0x16

#define E_ORIGIN_X UINT32_C(0x11111111)
#define E_ORIGIN_Y UINT32_C(0x22222222)
#define E_GRID_MIN UINT32_C(0x7fc0abcd) /* NaN payload: bits, never arithmetic */
#define E_GRID_MAX UINT32_C(0xbf400000)
#define E_FIELD_050 UINT32_C(0x0500c0de)
#define E_RADIUS_MIN UINT32_C(0x45000001)
#define E_RADIUS_MAX UINT32_C(0x44ffffff)
#define E_POINTS UINT32_C(0x5c5c5c5c)
#define E_OWNER_ID UINT32_C(0x60606060)
#define E_MODE 0x64
#define E_FIELD_068 UINT32_C(0x68686868)
#define E_OWNER_REF UINT32_C(0x6c6c6c6c)
#define E_GRID_A UINT32_C(0xa0a0a0a0)
#define E_GRID_B UINT32_C(0xb0b0b0b0)
#define E_GRID_C UINT32_C(0xc0c0c0c0)
#define E_TAG_LO UINT32_C(0x0000ac01)
#define E_TAG_HI UINT32_C(0x0000b002)
#define E_FLAG_0CC 0xcc
#define E_FLAG_0DC 0xdc
#define E_FIELD_0E0 UINT32_C(0xe0e0e0e0)
#define E_FLAG_0E4 0xe4

static const char k_tag_name[3] = {'T', 0, '\xfe'};
static const char k_leaf_name[3] = {'L', 0, 'f'};
static const uint16_t k_tag_text0[5] = {0x0054, 0x0000, 0xd800, 0xdc00, 0xffff};
static const uint16_t k_tag_text1[2] = {0xdfff, 0x0000};
/* category, label, descriptor_text, climate.name_alt, label_alt,
 * effect_kind, source_name: distinct so that cross-wiring is visible. */
static const char k_entity_text[7][4] = {
    {'c', 0, '\xfe', '0'}, {'l', 0, '\xfe', '1'}, {'d', 0, '\xfe', '2'},
    {'n', 0, '\xfe', '3'}, {'a', 0, '\xfe', '4'}, {'k', 0, '\xfe', '5'},
    {'s', 0, '\xfe', '6'}};
static const char k_item_text[2][3] = {{'i', 0, '0'}, {'j', '\x80', '1'}};

static float f32(uint32_t bits) { float f; memcpy(&f, &bits, sizeof f); return f; }
static uint32_t bits32(float f) { uint32_t b; memcpy(&b, &f, sizeof b); return b; }
static void set_bits(float *destination, uint32_t bits) { memcpy(destination, &bits, sizeof bits); }

static rome2_host_string8 s8(int32_t length, int32_t capacity, const char *data)
{ rome2_host_string8 s; s.length = length; s.capacity = capacity; s.data = data; return s; }
static rome2_host_string16 s16(int32_t length, int32_t capacity, const uint16_t *data)
{ rome2_host_string16 s; s.length_units = length; s.capacity_units = capacity; s.data = data; return s; }
static rome2_recovered_str rs(int32_t length, int32_t capacity, const char *data)
{ rome2_recovered_str s; s.length = length; s.capacity = capacity; s.data = data; return s; }

/* ------------------------------------------------------------------------ */
/* Decoded fauna configuration fixture.                                      */
/* ------------------------------------------------------------------------ */

#define CONFIG_MAX 4u
typedef struct config_fixture {
    rome2_fauna_vector_view view;
    rome2_fauna_record records[CONFIG_MAX];
    rome2_host_string8 strings[CONFIG_MAX][2];
    char bytes[CONFIG_MAX][3];
} config_fixture;

static uint32_t fauna_word(uint32_t seed, uint32_t record, uint32_t j)
{ return UINT32_C(0xff800001) + seed * 0x100u + record * 0x10u + j; }
static char fauna_lead(uint32_t seed, uint32_t record)
{ return (char)('A' + (int)(seed * 8u + record)); }

static void make_config(config_fixture *c, uint32_t count, uint32_t seed)
{
    uint32_t r, j;
    CHECK(count <= CONFIG_MAX);
    memset(c, 0x5a, sizeof *c);
    for (r = 0; r < count; ++r) {
        for (j = 0; j < 8; ++j) { c->records[r].words_000[j] = fauna_word(seed, r, j); }
        c->bytes[r][0] = fauna_lead(seed, r); c->bytes[r][1] = 0; c->bytes[r][2] = '\xfe';
        c->strings[r][0] = s8(3, 40 + (int32_t)r, c->bytes[r]);   /* spare capacity unread */
        c->strings[r][1] = s8(0, 7, (const char *)(uintptr_t)1);  /* empty: data never read */
        c->records[r].strings.capacity = UINT32_MAX;               /* unread source capacity */
        c->records[r].strings.count = 2;
        c->records[r].strings.items = c->strings[r];
    }
    c->view.capacity = 0; /* unread: deliberately below count */
    c->view.count = count;
    c->view.items = count == 0 ? NULL : c->records;
}

/* `first` maps output record r to golden record first + r.  `source` is used
 * only for address comparisons, so it may already be revoked. */
static void verify_config(const rome2_fauna_vector_view *v, uint32_t count,
    uint32_t seed, uint32_t first, const config_fixture *source)
{
    uint32_t r, q, j;
    CHECK(v->count == count && v->capacity >= count);
    if (count == 0) { return; }
    CHECK(v->items != NULL && v->items != source->records && (uintptr_t)v->items % 8 == 0);
    for (r = 0; r < count; ++r) {
        const rome2_fauna_record *record = &v->items[r];
        const uint32_t k = first + r;
        const rome2_host_string8 *s = record->strings.items;
        CHECK(k < CONFIG_MAX);
        for (j = 0; j < 8; ++j) { CHECK(record->words_000[j] == fauna_word(seed, k, j)); }
        CHECK(record->strings.count == 2 && record->strings.capacity == 2);
        CHECK(s != NULL && s != source->strings[k]);
        CHECK(s[0].length == 3 && s[0].capacity == 3 && s[0].data != source->bytes[k]);
        CHECK((uintptr_t)s[0].data % 4 == 0);
        CHECK(s[0].data[0] == fauna_lead(seed, k) && s[0].data[1] == 0);
        CHECK(s[0].data[2] == '\xfe' && s[0].data[3] == 0);
        CHECK(s[1].length == 0 && s[1].capacity == 0);
        CHECK(s[1].data == rome2_host_string8_empty_sentinel && s[1].data[0] == 0);
        for (q = 0; q < r; ++q) {
            CHECK(s != v->items[q].strings.items);
            CHECK(s[0].data != v->items[q].strings.items[0].data);
        }
    }
}

#define CONFIG_CORRUPTIONS 9u
/* Requires a fixture with at least two records.  Every corruption sits at or
 * behind the last record, so validation must scan the whole forest. */
static rome2_unit_card_status corrupt_config(config_fixture *c, unsigned which)
{
    switch (which) {
    case 0: c->view.count = ROME2_FAUNA_MAX_CAPACITY + 1u; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
    /* Not reachable by 1-and-doubling growth; accepting it would read past
     * the four-record source array. */
    case 1: c->view.count = ROME2_FAUNA_MAX_CAPACITY; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
    case 2: c->view.count = UINT32_MAX; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
    case 3: c->view.items = NULL; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
    case 4: c->records[1].strings.count = ROME2_FAUNA_MAX_STRINGS + 1u; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
    case 5: c->records[1].strings.items = NULL; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
    case 6: c->strings[1][1].length = -1; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
    case 7: c->strings[1][1].length = 8; return ROME2_UNIT_CARD_MALFORMED_SOURCE; /* capacity 7 */
    default:
        c->strings[1][1].length = 1; c->strings[1][1].data = NULL;
        return ROME2_UNIT_CARD_MALFORMED_SOURCE;
    }
}

/* ------------------------------------------------------------------------ */
/* Integrated card fixture.                                                  */
/* ------------------------------------------------------------------------ */

typedef struct card_fixture {
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_tag tag;
    rome2_unit_card_tag_element elements[2];
    rome2_unit_card_tag_leaf leaves[2];
    char tag_name[3], leaf_name[3];
    uint16_t tag_text0[5], tag_text1[2];
    rome2_battle_entity entity;
    rome2_recovered_str items[2];
    char entity_text[7][4];
    char item_text[2][3];
    config_fixture config;
} card_fixture;

static uint32_t tag_word(uint32_t owner, uint32_t group, uint32_t i)
{ return UINT32_C(0xc0000000) | owner << 16 | group << 8 | i; }

static void fill_element_scalars(rome2_unit_card_tag_element *e, uint32_t index)
{
    uint32_t i;
    for (i = 0; i < 4; ++i) { e->words_00c[i] = tag_word(index, 0, i); }
    e->word_01c = (uint16_t)(0xbee0u + index);
    for (i = 0; i < 12; ++i) { e->words_020[i] = tag_word(index, 1, i); }
    for (i = 0; i < 7; ++i) { e->bytes_050[i] = (uint8_t)(0x50u + index * 0x10u + i); }
    e->word_058 = tag_word(index, 3, 0);
    for (i = 0; i < 5; ++i) { e->words_068[i] = tag_word(index, 2, i); }
}

static void fill_leaf_words(rome2_unit_card_tag_leaf *leaf, uint32_t index)
{
    uint32_t i;
    for (i = 0; i < 16; ++i) { leaf->words_00c[i] = tag_word(index, 4, i); }
}

static void entity_sources(rome2_battle_entity *e, rome2_recovered_str *s[7])
{
    s[0] = &e->category; s[1] = &e->label; s[2] = &e->descriptor_text;
    s[3] = &e->climate.name_alt; s[4] = &e->label_alt; s[5] = &e->effect_kind;
    s[6] = &e->source_name;
}

static void entity_outputs(const rome2_battle_entity *e, const rome2_recovered_str *s[7])
{
    s[0] = &e->category; s[1] = &e->label; s[2] = &e->descriptor_text;
    s[3] = &e->climate.name_alt; s[4] = &e->label_alt; s[5] = &e->effect_kind;
    s[6] = &e->source_name;
}

static void make_card_fixture(card_fixture *f)
{
    rome2_recovered_str *slots[7];
    uint32_t i;
    /* Poison: every unread member keeps 0xa5, including the tag vtable cell,
     * unobserved tag gaps, entity dispatch cells, both entity literal-name
     * slots (length 0xa5a5a5a5 is malformed) and every source gap. */
    memset(f, 0xa5, sizeof *f);

    memcpy(f->tag_name, k_tag_name, sizeof f->tag_name);
    memcpy(f->leaf_name, k_leaf_name, sizeof f->leaf_name);
    memcpy(f->tag_text0, k_tag_text0, sizeof f->tag_text0);
    memcpy(f->tag_text1, k_tag_text1, sizeof f->tag_text1);
    f->tag.elements.capacity = -1; /* unread */
    f->tag.elements.count = 2;
    f->tag.elements.items = f->elements;
    fill_element_scalars(&f->elements[0], 0);
    f->elements[0].name = s8(3, 30, f->tag_name);
    f->elements[0].text = s16(5, 9, f->tag_text0);
    f->elements[0].children.capacity = 0; /* unread, below count */
    f->elements[0].children.count = 2;
    f->elements[0].children.items = f->leaves;
    f->leaves[0].name = s8(3, 3, f->leaf_name);
    fill_leaf_words(&f->leaves[0], 0);
    f->leaves[1].name = s8(0, 0, (const char *)(uintptr_t)1);
    fill_leaf_words(&f->leaves[1], 1);
    fill_element_scalars(&f->elements[1], 1);
    f->elements[1].name = s8(0, 4, (const char *)(uintptr_t)1);
    f->elements[1].text = s16(2, 2, f->tag_text1);
    f->elements[1].children.capacity = -5;
    f->elements[1].children.count = 0;
    f->elements[1].children.items = NULL;

    entity_sources(&f->entity, slots);
    for (i = 0; i < 7; ++i) {
        memcpy(f->entity_text[i], k_entity_text[i], sizeof f->entity_text[i]);
        *slots[i] = rs(4, 20 + (int32_t)i, f->entity_text[i]);
    }
    for (i = 0; i < 2; ++i) { memcpy(f->item_text[i], k_item_text[i], sizeof f->item_text[i]); }
    f->items[0] = rs(3, 3, f->item_text[0]);
    f->items[1] = rs(3, 99, f->item_text[1]);
    f->entity.item_capacity = UINT32_C(0xfffffff0); /* ignored source capacity */
    f->entity.item_count = 2;
    f->entity.items = f->items;
    f->entity.origin_x = E_ORIGIN_X; f->entity.origin_y = E_ORIGIN_Y;
    set_bits(&f->entity.grid_extent_min, E_GRID_MIN);
    set_bits(&f->entity.grid_extent_max, E_GRID_MAX);
    f->entity.field_050 = E_FIELD_050;
    set_bits(&f->entity.activation_radius_min, E_RADIUS_MIN);
    set_bits(&f->entity.activation_radius_max, E_RADIUS_MAX);
    f->entity.point_count = E_POINTS; f->entity.owner_id = E_OWNER_ID;
    f->entity.mode = E_MODE; f->entity.field_068 = E_FIELD_068;
    f->entity.owner_ref = E_OWNER_REF;
    f->entity.climate.grid_a = E_GRID_A; f->entity.climate.grid_b = E_GRID_B;
    f->entity.climate.grid_c = E_GRID_C;
    f->entity.tag_lo = E_TAG_LO; f->entity.tag_hi = E_TAG_HI;
    f->entity.flag_0cc = E_FLAG_0CC; f->entity.flag_0dc = E_FLAG_0DC;
    f->entity.field_0e0 = E_FIELD_0E0; f->entity.flag_0e4 = E_FLAG_0E4;

    f->args.arg00 = &f->entity; f->args.arg01 = &f->tag;
    f->args.arg02 = K_ARG02; f->args.arg03 = K_ARG03; f->args.arg04 = K_ARG04;
    f->args.arg05 = K_ARG05; f->args.arg06 = K_ARG06; f->args.arg07 = K_ARG07;
    f->args.arg08 = K_ARG08; f->args.arg09 = K_ARG09; f->args.arg10 = K_ARG10;
    f->args.arg11 = K_ARG11; f->args.arg12 = K_ARG12; f->args.arg13 = K_ARG13;
    f->args.arg14 = K_ARG14; f->args.arg15 = K_ARG15; f->args.arg16 = K_ARG16;
    f->globals.colour_component_a = 3.0f; f->globals.colour_component_b = 4.0f;
    f->globals.global_retail_flag = false;
    f->globals.grid_extent_unset = -7.5f; f->globals.grid_extent_unset_hi = 8.25f;
    make_config(&f->config, 2, 0);
}

enum { SCENARIO_FULL, SCENARIO_MINIMAL, SCENARIO_EMPTY_PARTS, SCENARIO_COUNT };

typedef struct expectation {
    rome2_unit_card_args args;       /* arguments as passed */
    rome2_unit_card_globals globals; /* effective globals */
    bool tag_populated, attachment, attachment_populated;
    uint32_t fauna_count;
    rome2_float2 coordinate;         /* exact binary32 initial coordinate */
    size_t observations;             /* string payloads released by destroy */
} expectation;

/* Returns the globals pointer to pass (NULL selects image defaults). */
static const rome2_unit_card_globals *make_scenario(card_fixture *f, int scenario, expectation *ex)
{
    make_card_fixture(f);
    memset(ex, 0, sizeof *ex);
    ex->tag_populated = true; ex->attachment = true; ex->attachment_populated = true;
    ex->fauna_count = 2;
    ex->coordinate.x = 0.6f; ex->coordinate.y = 0.8f;
    /* tag: element0 name/text, child0 name, element1 text; entity: two literal
     * names, seven copied strings, two items; fauna: one per record. */
    ex->observations = 4 + 11 + 2;
    if (scenario == SCENARIO_MINIMAL) {
        f->args.arg00 = NULL; f->args.arg01 = NULL;
        f->config.view.count = 0; f->config.view.items = NULL;
        ex->tag_populated = false; ex->attachment = false; ex->attachment_populated = false;
        ex->fauna_count = 0; ex->observations = 0;
    } else if (scenario == SCENARIO_EMPTY_PARTS) {
        rome2_recovered_str *slots[7];
        uint32_t i;
        f->tag.elements.count = 0; /* present but empty: items never read */
        f->tag.elements.items = (const rome2_unit_card_tag_element *)(uintptr_t)8;
        entity_sources(&f->entity, slots);
        for (i = 0; i < 7; ++i) { *slots[i] = rs(0, (int32_t)i, (const char *)(uintptr_t)1); }
        f->entity.item_count = 0; f->entity.items = NULL;
        f->config.view.count = 0; f->config.view.items = NULL;
        ex->tag_populated = false; ex->attachment_populated = false;
        ex->fauna_count = 0; ex->observations = 2;
        ex->coordinate.x = 0.0f; ex->coordinate.y = 0.0f;
        ex->args = f->args;
        rome2_unit_card_globals_from_image(&ex->globals);
        return NULL;
    }
    ex->args = f->args;
    ex->globals = f->globals;
    return &f->globals;
}

/* ------------------------------------------------------------------------ */
/* Verification.                                                             */
/* ------------------------------------------------------------------------ */

static void check_copy8(const rome2_host_string8 *s, const char *golden, int32_t n, const void *source)
{
    CHECK(s->length == n && s->capacity == n && s->data != NULL);
    CHECK((const void *)s->data != source && (uintptr_t)s->data % 4 == 0);
    CHECK(memcmp(s->data, golden, (size_t)n) == 0 && s->data[n] == 0);
}

static void check_copy16(const rome2_host_string16 *s, const uint16_t *golden, int32_t n, const void *source)
{
    CHECK(s->length_units == n && s->capacity_units == n && s->data != NULL);
    CHECK((const void *)s->data != source && (uintptr_t)s->data % 4 == 0);
    CHECK(memcmp(s->data, golden, (size_t)n * 2u) == 0 && s->data[n] == 0);
}

static void check_recovered(const rome2_recovered_str *s, const char *golden, int32_t n, const void *source)
{
    CHECK(s->length == n && s->capacity == n && s->data != NULL);
    CHECK((const void *)s->data != source && (uintptr_t)s->data % 4 == 0);
    CHECK(memcmp(s->data, golden, (size_t)n) == 0 && s->data[n] == 0);
}

static void verify_tag(const rome2_unit_card_tag *t, const card_fixture *f, bool populated)
{
    const rome2_unit_card_tag_element *e0, *e1;
    rome2_unit_card_tag_element x;
    rome2_unit_card_tag_leaf y;
    uint32_t i;
    CHECK(t != NULL && t != &f->tag && (uintptr_t)t % 8 == 0);
    CHECK(t->vtable_identity == ROME2_TAG_VTABLE_IDENTITY);
    if (!populated) {
        CHECK(t->elements.capacity == 0 && t->elements.count == 0 && t->elements.items == NULL);
        return;
    }
    CHECK(t->elements.capacity == 2 && t->elements.count == 2);
    CHECK(t->elements.items != NULL && t->elements.items != f->elements);
    CHECK((uintptr_t)t->elements.items % 8 == 0);
    e0 = &t->elements.items[0];
    e1 = &t->elements.items[1];
    check_copy8(&e0->name, k_tag_name, 3, f->tag_name);
    check_copy16(&e0->text, k_tag_text0, 5, f->tag_text0);
    CHECK(e0->children.items != NULL && e0->children.items != f->leaves);
    check_copy8(&e0->children.items[0].name, k_leaf_name, 3, f->leaf_name);
    CHECK(e0->children.items[1].name.length == 0 && e0->children.items[1].name.capacity == 0);
    CHECK(e0->children.items[1].name.data == rome2_host_string8_empty_sentinel);
    CHECK(e1->name.length == 0 && e1->name.capacity == 0);
    CHECK(e1->name.data == rome2_host_string8_empty_sentinel);
    check_copy16(&e1->text, k_tag_text1, 2, f->tag_text1);
    CHECK(e0->name.data != e0->children.items[0].name.data);
    CHECK(e0->text.data != e1->text.data);
    /* Every byte of each element and leaf, unobserved gaps and padding
     * included (source gaps are 0xa5 poison; the owner zeroes them). */
    memset(&x, 0, sizeof x);
    fill_element_scalars(&x, 0);
    x.name = e0->name; x.text = e0->text;
    x.children.capacity = 2; x.children.count = 2; x.children.items = e0->children.items;
    CHECK(memcmp(&x, e0, sizeof x) == 0);
    memset(&x, 0, sizeof x);
    fill_element_scalars(&x, 1);
    x.name = e1->name; x.text = e1->text; /* children {0, 0, NULL} */
    CHECK(memcmp(&x, e1, sizeof x) == 0);
    for (i = 0; i < 2; ++i) {
        memset(&y, 0, sizeof y);
        fill_leaf_words(&y, i);
        y.name = e0->children.items[i].name;
        CHECK(memcmp(&y, &e0->children.items[i], sizeof y) == 0);
    }
}

static void verify_attachment(const rome2_battle_entity *e, const card_fixture *f, bool populated)
{
    const rome2_recovered_str *out[7];
    const char *payloads[11];
    size_t n = 0, i, j;
    CHECK(e != NULL && e != &f->entity && (uintptr_t)e % 8 == 0);
    CHECK(e->dispatch.slot0 == ROME2_ENTITY_DISPATCH0 && e->dispatch.slot1 == ROME2_ENTITY_DISPATCH1);
    CHECK(e->dispatch.slot2 == ROME2_ENTITY_DISPATCH2 && e->dispatch.slot3 == ROME2_ENTITY_DISPATCH3);
    CHECK(e->climate.dispatch0 == ROME2_CLIMATE_DISPATCH0);
    CHECK(e->climate.dispatch1 == ROME2_CLIMATE_DISPATCH1 && e->climate.dispatch2 == 0);
    /* Reconstructed literals; the poisoned source slots are never read. */
    check_recovered(&e->effect_name, ROME2_ENTITY_NAME, (int32_t)(sizeof ROME2_ENTITY_NAME - 1u), NULL);
    check_recovered(&e->climate.name, ROME2_ENTITY_CLIMATE_NAME,
        (int32_t)(sizeof ROME2_ENTITY_CLIMATE_NAME - 1u), NULL);
    payloads[n++] = e->effect_name.data;
    payloads[n++] = e->climate.name.data;
    entity_outputs(e, out);
    for (i = 0; i < 7; ++i) {
        if (populated) {
            check_recovered(out[i], k_entity_text[i], 4, f->entity_text[i]);
            payloads[n++] = out[i]->data;
        } else {
            CHECK(out[i]->length == 0 && out[i]->capacity == 0);
            CHECK(out[i]->data == rome2_host_string8_empty_sentinel);
        }
    }
    if (populated) {
        CHECK(e->item_capacity == 2 && e->item_count == 2);
        CHECK(e->items != NULL && e->items != f->items);
        for (i = 0; i < 2; ++i) {
            check_recovered(&e->items[i], k_item_text[i], 3, f->item_text[i]);
            payloads[n++] = e->items[i].data;
        }
    } else {
        CHECK(e->item_capacity == 0 && e->item_count == 0);
    }
    for (i = 0; i < n; ++i) {
        for (j = 0; j < i; ++j) { CHECK(payloads[i] != payloads[j]); }
    }
    CHECK(e->origin_x == E_ORIGIN_X && e->origin_y == E_ORIGIN_Y);
    CHECK(bits32(e->grid_extent_min) == E_GRID_MIN && bits32(e->grid_extent_max) == E_GRID_MAX);
    CHECK(e->field_050 == E_FIELD_050);
    CHECK(bits32(e->activation_radius_min) == E_RADIUS_MIN);
    CHECK(bits32(e->activation_radius_max) == E_RADIUS_MAX);
    CHECK(e->point_count == E_POINTS && e->owner_id == E_OWNER_ID && e->mode == E_MODE);
    CHECK(e->field_068 == E_FIELD_068 && e->owner_ref == E_OWNER_REF);
    CHECK(e->climate.grid_a == E_GRID_A && e->climate.grid_b == E_GRID_B && e->climate.grid_c == E_GRID_C);
    CHECK(e->tag_lo == E_TAG_LO && e->tag_hi == E_TAG_HI);
    CHECK(e->flag_0cc == E_FLAG_0CC && e->flag_0dc == E_FLAG_0DC);
    CHECK(e->field_0e0 == E_FIELD_0E0 && e->flag_0e4 == E_FLAG_0E4);
    for (i = 0; i < 3; ++i) {
        CHECK(e->pad_065[i] == 0 && e->pad_0cd[i] == 0 && e->pad_0dd[i] == 0 && e->pad_0e5[i] == 0);
    }
}

#define NARROW_MEMBERS(v) { &(v)->str_010, &(v)->str_028, &(v)->str_034, &(v)->str_044, \
    &(v)->str_0a4, &(v)->str_0b0, &(v)->str_0bc, &(v)->str_0c8, &(v)->str_0d4, \
    &(v)->str_0e0, &(v)->str_0f0, &(v)->str_108, &(v)->str_12c }

/* Expected bytes of a fresh card: the documented constructor projection of
 * args/globals, real subobject views copied from the (separately verified)
 * actual view, and zero everywhere else. */
static void expect_prefix(rome2_native_unit_card *x, const rome2_native_unit_card *v, const expectation *ex)
{
    const rome2_unit_card_args *a = &ex->args;
    const rome2_unit_card_globals *g = &ex->globals;
    rome2_host_string8 *narrow[13] = NARROW_MEMBERS(x);
    size_t i;
    memset(x, 0, sizeof *x);
    for (i = 0; i < 13; ++i) { *narrow[i] = rome2_host_string8_empty(); }
    x->owner = a->arg03;
    x->attachment = v->attachment; x->tag = v->tag;
    x->selector = a->arg02; x->variant = a->arg04;
    x->priority = a->arg05; x->control_flags = a->arg07;
    x->words = v->words; x->coordinates = v->coordinates;
    x->unit_class = a->arg08; x->deployment = a->arg09; x->strength = a->arg10;
    x->colour_lo_x = g->colour_component_a; x->colour_lo_y = g->colour_component_b;
    x->colour_hi_x = g->colour_component_a; x->colour_hi_y = g->colour_component_b;
    x->str_0fc = rome2_host_string16_empty();
    x->enabled = 1;
    x->flag_119 = a->arg12; x->flag_11a = a->arg13; x->flag_11b = a->arg14;
    x->flag_11c = (uint8_t)((a->arg15 != 0 || g->global_retail_flag) ? 1 : 0);
    x->last_common_index = 0;
    x->slot_count = 20;
    x->mutable_class = (uint8_t)((a->arg08 == 6 || a->arg08 == 14) ? 0 : 1);
    x->flag_138 = a->arg16;
    x->grid_extent_min = g->grid_extent_unset; x->grid_extent_max = g->grid_extent_unset_hi;
    x->fauna = v->fauna;
}

static void verify_card(const rome2_native_unit_card *v, const card_fixture *f, const expectation *ex)
{
    rome2_native_unit_card x;
    size_t i;
    CHECK(v != NULL && (uintptr_t)v % 8 == 0);
    CHECK(v->words.count == 1 && v->words.capacity == 1 && v->words.items != NULL);
    CHECK((uintptr_t)v->words.items % 4 == 0 && v->words.items[0] == ex->args.arg06);
    CHECK(v->coordinates.count == 1 && v->coordinates.capacity == 1 && v->coordinates.items != NULL);
    CHECK((uintptr_t)v->coordinates.items % 4 == 0);
    CHECK(bits32(v->coordinates.items[0].x) == bits32(ex->coordinate.x));
    CHECK(bits32(v->coordinates.items[0].y) == bits32(ex->coordinate.y));
    verify_tag(v->tag, f, ex->tag_populated);
    if (ex->attachment) { verify_attachment(v->attachment, f, ex->attachment_populated); }
    else { CHECK(v->attachment == NULL); }
    verify_config(&v->fauna, ex->fauna_count, 0, 0, &f->config);
    {
        const rome2_host_string8 *narrow[13] = NARROW_MEMBERS(v);
        for (i = 0; i < 13; ++i) {
            CHECK(narrow[i]->length == 0 && narrow[i]->capacity == 0);
            CHECK(narrow[i]->data == rome2_host_string8_empty_sentinel && narrow[i]->data[0] == 0);
        }
    }
    CHECK(v->str_0fc.length_units == 0 && v->str_0fc.capacity_units == 0);
    CHECK(v->str_0fc.data == rome2_host_string16_empty_sentinel && v->str_0fc.data[0] == 0);
    expect_prefix(&x, v, ex);
    CHECK(memcmp(&x, v, sizeof x) == 0);
}

static const rome2_native_unit_card *get(const rome2_owned_unit_card *h)
{
    const rome2_native_unit_card *v = rome2_owned_unit_card_get(h);
    CHECK(v != NULL);
    return v;
}

static void create_ok(rome2_owned_unit_card **h, card_fixture *f, int scenario,
    expectation *ex, const rome2_owned_string_allocator *p)
{
    const rome2_unit_card_globals *g = make_scenario(f, scenario, ex);
    *h = NULL;
    CHECK(rome2_owned_unit_card_create_from_config(h, &f->args, g, &f->config.view, p) == ROME2_UNIT_CARD_OK);
    CHECK(*h != NULL);
}

static void destroy_all(rome2_owned_unit_card **h, test_heap *heap, size_t injected_failures)
{
    CHECK(rome2_owned_unit_card_destroy(h) == ROME2_UNIT_CARD_OK && *h == NULL);
    CHECK(heap->live == 0 && heap->releases + injected_failures == heap->allocations);
}

/* ------------------------------------------------------------------------ */
/* Factory: success, revocation and every allocation failure.                */
/* ------------------------------------------------------------------------ */

static void check_image_defaults(void)
{
    rome2_unit_card_globals g;
    memset(&g, 0x5a, sizeof g);
    rome2_unit_card_globals_from_image(&g);
    CHECK(bits32(g.colour_component_a) == 0 && bits32(g.colour_component_b) == 0);
    CHECK(!g.global_retail_flag && g.grid_extent_unset == -1.0f && g.grid_extent_unset_hi == -1.0f);
}

static size_t scenario_success(int scenario)
{
    unsigned residue;
    size_t calls = 0;
    for (residue = 0; residue < 8; ++residue) {
        test_heap heap = {0};
        rome2_owned_string_allocator p = test_policy(&heap);
        rome2_owned_unit_card *h = NULL;
        card_fixture f, before;
        expectation ex;
        const rome2_unit_card_globals *g;
        const rome2_native_unit_card *v;
        heap.residue = residue;
        g = make_scenario(&f, scenario, &ex);
        memcpy(&before, &f, sizeof f);
        CHECK(rome2_owned_unit_card_create_from_config(&h, &f.args, g, &f.config.view, &p) == ROME2_UNIT_CARD_OK);
        CHECK(memcmp(&f, &before, sizeof f) == 0); /* sources are only read */
        v = get(h);
        verify_card(v, &f, &ex);
        if (scenario == SCENARIO_FULL) {
            /* Independent spot oracle for the projection rules. */
            CHECK(v->owner == K_ARG03 && v->selector == K_ARG02 && v->variant == K_ARG04);
            CHECK(v->unit_class == K_ARG08 && v->deployment == K_ARG09 && v->strength == K_ARG10);
            CHECK(v->flag_11c == 1 && v->mutable_class == 1 && v->enabled == 1 && v->slot_count == 20);
            CHECK(v->colour_lo_x == 3.0f && v->colour_lo_y == 4.0f);
            CHECK(v->colour_hi_x == 3.0f && v->colour_hi_y == 4.0f);
            CHECK(v->grid_extent_min == -7.5f && v->grid_extent_max == 8.25f);
            CHECK(v->coordinates.items[0].x == 0.6f && v->coordinates.items[0].y == 0.8f);
            CHECK(v->words.items[0] == UINT32_C(0xdeadbeef) && v->last_common_index == 0);
        }
        if (residue == 0) { calls = heap.allocations; }
        CHECK(heap.allocations == calls && calls != 0); /* deterministic for every residue */
        memset(&f, 0xdd, sizeof f); /* revoke every borrowed buffer and record */
        verify_card(get(h), &f, &ex);
        destroy_all(&h, &heap, 0);
        CHECK(heap.observations == ex.observations); /* string payloads only */
        CHECK(rome2_owned_unit_card_destroy(&h) == ROME2_UNIT_CARD_OK);
        CHECK(heap.releases == heap.allocations); /* repeated destroy is inert */
    }
    return calls;
}

static void scenario_failures(int scenario, size_t calls)
{
    unsigned residue;
    size_t fail;
    for (residue = 0; residue < 8; ++residue) {
        for (fail = 1; fail <= calls; ++fail) {
            test_heap heap = {0};
            rome2_owned_string_allocator p = test_policy(&heap);
            rome2_owned_unit_card *const sentinel = (rome2_owned_unit_card *)(void *)&heap;
            rome2_owned_unit_card *out = sentinel;
            card_fixture f, before;
            expectation ex;
            const rome2_unit_card_globals *g;
            heap.residue = residue;
            heap.fail_at = fail;
            g = make_scenario(&f, scenario, &ex);
            memcpy(&before, &f, sizeof f);
            CHECK(rome2_owned_unit_card_create_from_config(&out, &f.args, g, &f.config.view, &p) ==
                ROME2_UNIT_CARD_ALLOCATION_FAILED);
            CHECK(out == sentinel);
            CHECK(heap.allocations == fail && heap.releases == fail - 1 && heap.live == 0);
            CHECK(memcmp(&f, &before, sizeof f) == 0);
        }
    }
}

static void test_sibling_independence(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *a = NULL, *b = NULL;
    card_fixture f;
    expectation ex;
    const rome2_native_unit_card *va, *vb;
    rome2_native_unit_card snapshot;
    const uint16_t units[2] = {0x0042, 0xd801};
    const rome2_string16_view text = {units, 2};
    rome2_float2 pair;
    create_ok(&a, &f, SCENARIO_FULL, &ex, &p);
    CHECK(rome2_owned_unit_card_create_from_config(&b, &f.args, &f.globals, &f.config.view, &p) ==
        ROME2_UNIT_CARD_OK);
    va = get(a); vb = get(b);
    CHECK(va != vb && va->tag != vb->tag && va->attachment != vb->attachment);
    CHECK(va->words.items != vb->words.items && va->coordinates.items != vb->coordinates.items);
    CHECK(va->fauna.items != vb->fauna.items);
    CHECK(va->tag->elements.items[0].name.data != vb->tag->elements.items[0].name.data);
    CHECK(va->tag->elements.items[0].children.items != vb->tag->elements.items[0].children.items);
    CHECK(va->attachment->category.data != vb->attachment->category.data);
    CHECK(va->attachment->items != vb->attachment->items);
    CHECK(va->fauna.items[0].strings.items[0].data != vb->fauna.items[0].strings.items[0].data);
    memcpy(&snapshot, vb, sizeof snapshot);
    pair.x = 0.5f; pair.y = 0.25f;
    CHECK(rome2_owned_unit_card_append_word(a, 1) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_append_coordinate(a, pair) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_set_text16(a, text) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_clear_fauna(a) == ROME2_UNIT_CARD_OK);
    CHECK(memcmp(&snapshot, get(b), sizeof snapshot) == 0);
    CHECK(rome2_owned_unit_card_destroy(&a) == ROME2_UNIT_CARD_OK && a == NULL);
    memset(&f, 0xdd, sizeof f);
    verify_card(get(b), &f, &ex); /* released memory of a was scribbled 0xdd */
    destroy_all(&b, &heap, 0);
}

static void test_projection_variants(void)
{
    static const uint32_t classes[] = {6, 14, 0, 5, 7, 13, 15, UINT32_MAX};
    static const uint8_t arg15[] = {0, 1, 0xff};
    size_t c, k;
    int flag;
    for (c = 0; c < sizeof classes / sizeof classes[0]; ++c) {
        for (flag = 0; flag < 2; ++flag) {
            for (k = 0; k < sizeof arg15; ++k) {
                test_heap heap = {0};
                rome2_owned_string_allocator p = test_policy(&heap);
                rome2_owned_unit_card *h = NULL;
                card_fixture f;
                expectation ex;
                const rome2_native_unit_card *v;
                (void)make_scenario(&f, SCENARIO_MINIMAL, &ex);
                f.args.arg08 = classes[c];
                f.args.arg15 = arg15[k];
                f.globals.global_retail_flag = flag != 0;
                ex.args = f.args; ex.globals = f.globals;
                CHECK(rome2_owned_unit_card_create_from_config(&h, &f.args, &f.globals, &f.config.view, &p) ==
                    ROME2_UNIT_CARD_OK);
                v = get(h);
                CHECK(v->unit_class == classes[c]);
                CHECK(v->mutable_class == ((classes[c] == 6 || classes[c] == 14) ? 0 : 1));
                CHECK(v->flag_11c == ((arg15[k] != 0 || flag != 0) ? 1 : 0));
                verify_card(v, &f, &ex);
                destroy_all(&h, &heap, 0);
            }
        }
    }
}

static void test_initial_coordinates(void)
{
    typedef struct coordinate_case { float a, b, x, y; int approximate; } coordinate_case;
    static const coordinate_case cases[] = {
        {3.0f, 4.0f, 0.6f, 0.8f, 0}, {-3.0f, 4.0f, -0.6f, 0.8f, 0}, {0.0f, -8.0f, 0.0f, -1.0f, 0},
        {0.25f, -0.5f, 0.25f, -0.5f, 0}, {-0.0f, 1.0f, -0.0f, 1.0f, 0}, {0.0f, 0.0f, 0.0f, 0.0f, 0},
        {1e19f, 1e19f, 0.70710678f, 0.70710678f, 1}}; /* finite squared length 2e38 */
    size_t i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        test_heap heap = {0};
        rome2_owned_string_allocator p = test_policy(&heap);
        rome2_owned_unit_card *h = NULL;
        card_fixture f;
        expectation ex;
        const rome2_native_unit_card *v;
        rome2_float2 c;
        (void)make_scenario(&f, SCENARIO_MINIMAL, &ex);
        f.globals.colour_component_a = cases[i].a;
        f.globals.colour_component_b = cases[i].b;
        CHECK(rome2_owned_unit_card_create_from_config(&h, &f.args, &f.globals, &f.config.view, &p) ==
            ROME2_UNIT_CARD_OK);
        v = get(h);
        /* The original colour scalars keep the unnormalized global pair. */
        CHECK(bits32(v->colour_lo_x) == bits32(cases[i].a) && bits32(v->colour_lo_y) == bits32(cases[i].b));
        CHECK(bits32(v->colour_hi_x) == bits32(cases[i].a) && bits32(v->colour_hi_y) == bits32(cases[i].b));
        CHECK(v->coordinates.count == 1 && v->last_common_index == 0);
        c = v->coordinates.items[0];
        if (cases[i].approximate) {
            CHECK(bits32(c.x) == bits32(c.y) && fabsf(c.x - cases[i].x) <= 2e-6f);
            CHECK(c.x * c.x + c.y * c.y <= 1.0f + 4e-6f);
        } else {
            CHECK(bits32(c.x) == bits32(cases[i].x) && bits32(c.y) == bits32(cases[i].y));
        }
        destroy_all(&h, &heap, 0);
    }
}

/* ------------------------------------------------------------------------ */
/* Arguments, handles and malformed sources: no allocator effects.           */
/* ------------------------------------------------------------------------ */

static void test_arguments_and_handles(void)
{
    static uint64_t fake[512]; /* zero-filled storage that is not a handle */
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap), q;
    rome2_owned_unit_card *const sentinel = (rome2_owned_unit_card *)(void *)&heap;
    rome2_owned_unit_card *out = sentinel, *h = NULL;
    rome2_owned_unit_card *const forged = (rome2_owned_unit_card *)(void *)fake;
    rome2_owned_unit_card *forged_ref = forged;
    card_fixture f, before;
    expectation ex;
    rome2_native_unit_card snapshot;
    rome2_float2 pair;
    const rome2_string16_view text = {NULL, 0};
    size_t i;
    (void)make_scenario(&f, SCENARIO_FULL, &ex);
    memcpy(&before, &f, sizeof f);
    CHECK(rome2_owned_unit_card_create_from_config(NULL, &f.args, &f.globals, &f.config.view, &p) ==
        ROME2_UNIT_CARD_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_create_from_config(&out, NULL, &f.globals, &f.config.view, &p) ==
        ROME2_UNIT_CARD_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_create_from_config(&out, &f.args, &f.globals, &f.config.view, NULL) ==
        ROME2_UNIT_CARD_INVALID_ALLOCATOR);
    q = p; q.allocate = NULL;
    CHECK(rome2_owned_unit_card_create_from_config(&out, &f.args, &f.globals, &f.config.view, &q) ==
        ROME2_UNIT_CARD_INVALID_ALLOCATOR);
    q = p; q.release = NULL;
    CHECK(rome2_owned_unit_card_create_from_config(&out, &f.args, &f.globals, &f.config.view, &q) ==
        ROME2_UNIT_CARD_INVALID_ALLOCATOR);
    /* Missing configuration is never inferred or loaded. */
    CHECK(rome2_owned_unit_card_create_from_config(&out, &f.args, &f.globals, NULL, &p) ==
        ROME2_UNIT_CARD_CONFIG_REQUIRED);
    CHECK(out == sentinel && heap.allocations == 0 && memcmp(&f, &before, sizeof f) == 0);

    pair.x = 0.0f; pair.y = 0.0f;
    CHECK(rome2_owned_unit_card_get(NULL) == NULL);
    CHECK(rome2_owned_unit_card_destroy(NULL) == ROME2_UNIT_CARD_BAD_ARGUMENT);
    CHECK(rome2_owned_unit_card_destroy(&h) == ROME2_UNIT_CARD_OK && h == NULL);
    CHECK(rome2_owned_unit_card_append_word(NULL, 1) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_append_coordinate(NULL, pair) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_set_text16(NULL, text) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_clear_fauna(NULL) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_replace_config(NULL, &f.config.view) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_get(forged) == NULL);
    CHECK(rome2_owned_unit_card_append_word(forged, 1) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_append_coordinate(forged, pair) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_set_text16(forged, text) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_clear_fauna(forged) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_replace_config(forged, &f.config.view) == ROME2_UNIT_CARD_INVALID_HANDLE);
    CHECK(rome2_owned_unit_card_destroy(&forged_ref) == ROME2_UNIT_CARD_INVALID_HANDLE && forged_ref == forged);
    for (i = 0; i < sizeof fake / sizeof fake[0]; ++i) { CHECK(fake[i] == 0); }
    CHECK(heap.allocations == 0);

    /* A live handle rejects a missing replacement configuration. */
    create_ok(&h, &f, SCENARIO_FULL, &ex, &p);
    memcpy(&snapshot, get(h), sizeof snapshot);
    i = heap.allocations;
    CHECK(rome2_owned_unit_card_replace_config(h, NULL) == ROME2_UNIT_CARD_CONFIG_REQUIRED);
    CHECK(heap.allocations == i && memcmp(&snapshot, get(h), sizeof snapshot) == 0);
    destroy_all(&h, &heap, 0);
    CHECK(rome2_owned_unit_card_destroy(&h) == ROME2_UNIT_CARD_OK && heap.releases == heap.allocations);
}

#define TAG_CASES 13u
#define ENTITY_CASES 12u
#define COORDINATE_CASES 7u

static rome2_unit_card_status corrupt_card(card_fixture *f, unsigned which)
{
    rome2_recovered_str *slots[7];
    entity_sources(&f->entity, slots);
    if (which < TAG_CASES) {
        switch (which) {
        case 0: f->tag.elements.count = -1; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
        case 1: f->tag.elements.count = (int32_t)ROME2_TAG_MAX_ELEMENTS + 1; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
        case 2: f->tag.elements.items = NULL; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 3: f->elements[0].name.capacity = 2; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 4: f->elements[0].name.data = NULL; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 5: f->elements[1].text.length_units = -1; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 6: f->elements[1].text.data = NULL; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 7: f->elements[1].text.capacity_units = 1; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 8: f->elements[0].children.count = -1; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
        case 9: f->elements[0].children.count = (int32_t)ROME2_TAG_MAX_CHILDREN + 1; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
        case 10: f->elements[0].children.items = NULL; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 11: f->leaves[1].name.length = -1; return ROME2_UNIT_CARD_MALFORMED_SOURCE; /* last nested */
        default: f->leaves[1].name = s8(1, 1, NULL); return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        }
    }
    which -= TAG_CASES;
    if (which < ENTITY_CASES) {
        if (which < 7) { slots[which]->capacity = slots[which]->length - 1; return ROME2_UNIT_CARD_MALFORMED_SOURCE; }
        switch (which) {
        case 7: slots[6]->data = NULL; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 8: f->entity.item_count = ROME2_ENTITY_MAX_ITEM_COUNT + 1u; return ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE;
        case 9: f->entity.items = NULL; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        case 10: f->items[1].length = -1; return ROME2_UNIT_CARD_MALFORMED_SOURCE; /* last nested */
        default: f->items[1].capacity = 2; return ROME2_UNIT_CARD_MALFORMED_SOURCE;
        }
    }
    which -= ENTITY_CASES;
    if (which < CONFIG_CORRUPTIONS) { return corrupt_config(&f->config, which); }
    which -= CONFIG_CORRUPTIONS;
    switch (which) {
    case 0: f->globals.colour_component_a = f32(UINT32_C(0x7fc00000)); break;  /* quiet NaN */
    case 1: f->globals.colour_component_b = f32(UINT32_C(0x7f800001)); break;  /* signalling NaN */
    case 2: f->globals.colour_component_b = f32(UINT32_C(0x7f800000)); break;  /* +inf */
    case 3: f->globals.colour_component_a = f32(UINT32_C(0xff800000)); break;  /* -inf */
    case 4: f->globals.colour_component_a = 2e19f; f->globals.colour_component_b = 0.0f; break;
    case 5: f->globals.colour_component_a = 1.5e19f; f->globals.colour_component_b = -1.5e19f; break;
    default: f->globals.colour_component_a = FLT_MAX; f->globals.colour_component_b = FLT_MAX; break;
    }
    return ROME2_UNIT_CARD_UNSUPPORTED_COORDINATE;
}

static void test_malformed_sources(void)
{
    unsigned which;
    for (which = 0; which < TAG_CASES + ENTITY_CASES + CONFIG_CORRUPTIONS + COORDINATE_CASES; ++which) {
        test_heap heap = {0};
        rome2_owned_string_allocator p = test_policy(&heap);
        rome2_owned_unit_card *const sentinel = (rome2_owned_unit_card *)(void *)&heap;
        rome2_owned_unit_card *out = sentinel;
        card_fixture f, before;
        expectation ex;
        rome2_unit_card_status expected;
        (void)make_scenario(&f, SCENARIO_FULL, &ex);
        expected = corrupt_card(&f, which);
        memcpy(&before, &f, sizeof f);
        CHECK(rome2_owned_unit_card_create_from_config(&out, &f.args, &f.globals, &f.config.view, &p) == expected);
        CHECK(out == sentinel && heap.allocations == 0 && heap.releases == 0);
        CHECK(memcmp(&f, &before, sizeof f) == 0);
    }
}

/* ------------------------------------------------------------------------ */
/* Allocator capture and release authority.                                  */
/* ------------------------------------------------------------------------ */

static void test_captured_allocator(void)
{
    test_heap a = {0}, b = {0};
    rome2_owned_string_allocator p = test_policy(&a);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    config_fixture c;
    expectation ex;
    const uint16_t units[3] = {0x0043, 0x0000, 0xdbff};
    rome2_string16_view text = {units, 3};
    rome2_float2 pair;
    a.residue = 3;
    create_ok(&h, &f, SCENARIO_FULL, &ex, &p);
    p = test_policy(&b); /* the caller re-points its allocator object */
    pair.x = 6.0f; pair.y = -8.0f;
    CHECK(rome2_owned_unit_card_append_word(h, 2) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_append_word(h, 3) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_append_coordinate(h, pair) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_append_coordinate(h, pair) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_set_text16(h, text) == ROME2_UNIT_CARD_OK);
    make_config(&c, 3, 1);
    CHECK(rome2_owned_unit_card_replace_config(h, &c.view) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_clear_fauna(h) == ROME2_UNIT_CARD_OK);
    make_config(&c, 4, 2);
    CHECK(rome2_owned_unit_card_replace_config(h, &c.view) == ROME2_UNIT_CARD_OK);
    memset(&p, 0, sizeof p); /* and finally erases it */
    text.length_units = 0;
    CHECK(rome2_owned_unit_card_set_text16(h, text) == ROME2_UNIT_CARD_OK);
    CHECK(b.allocations == 0 && b.releases == 0 && b.observations == 0);
    destroy_all(&h, &a, 0);
    CHECK(b.allocations == 0 && b.releases == 0 && b.observations == 0);
}

static void test_release_authority(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    expectation ex;
    const uint16_t units[2] = {0x0044, 0xdc00};
    const rome2_string16_view text = {units, 2};
    create_ok(&h, &f, SCENARIO_FULL, &ex, &p);
    CHECK(rome2_owned_unit_card_set_text16(h, text) == ROME2_UNIT_CARD_OK);
    CHECK(rome2_owned_unit_card_append_word(h, 7) == ROME2_UNIT_CARD_OK);
    {
        /* Deliberate view-contract violation.  It checks ONLY that published
         * descriptor copies are not release authority; it makes no general
         * corruption-safety claim. */
        rome2_native_unit_card *w = (rome2_native_unit_card *)(uintptr_t)get(h);
        w->str_0fc = s16(77, 77, (const uint16_t *)(uintptr_t)8);
        w->str_010 = s8(5, 5, (const char *)(uintptr_t)8);
        w->words.count = UINT32_MAX; w->words.items = NULL;
        w->coordinates.capacity = 0; w->coordinates.items = (const rome2_float2 *)(uintptr_t)8;
        w->fauna.count = UINT32_MAX; w->fauna.items = NULL;
        w->tag = NULL;
        w->attachment = (const rome2_battle_entity *)(uintptr_t)8;
    }
    destroy_all(&h, &heap, 0);
    CHECK(heap.observations == ex.observations + 1); /* plus the owned text */
}

static void test_no_observer(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    expectation ex;
    p.release_observer = NULL; p.observer_context = NULL; /* optional */
    create_ok(&h, &f, SCENARIO_FULL, &ex, &p);
    verify_card(get(h), &f, &ex);
    destroy_all(&h, &heap, 0);
    CHECK(heap.observations == 0);
}

/* ------------------------------------------------------------------------ */
/* Append mutators.                                                          */
/* ------------------------------------------------------------------------ */

static void check_common_index(const rome2_native_unit_card *v)
{
    const uint32_t common = v->words.count < v->coordinates.count ? v->words.count : v->coordinates.count;
    CHECK(v->last_common_index == (common == 0 ? 0u : common - 1u));
}

static void test_append_growth(void)
{
    typedef struct step {
        int coordinate;
        uint32_t word;
        float x, y;
        uint32_t words, word_capacity, pairs, pair_capacity, index;
        size_t grants;
    } step;
    static const step steps[] = {
        {0, 1, 0, 0, 2, 2, 1, 1, 0, 1},
        {0, 2, 0, 0, 3, 4, 1, 1, 0, 1},
        {0, 3, 0, 0, 4, 4, 1, 1, 0, 0},
        {1, 0, 0.25f, -0.5f, 4, 4, 2, 2, 1, 1},
        {1, 0, -6.0f, 8.0f, 4, 4, 3, 4, 2, 1},
        {1, 0, -0.0f, 1.0f, 4, 4, 4, 4, 3, 0},
        {1, 0, 1e19f, 1e19f, 4, 4, 5, 8, 3, 1},
        {0, 4, 0, 0, 5, 8, 5, 8, 4, 1},
        {0, 5, 0, 0, 6, 8, 5, 8, 4, 0},
    };
    static const uint32_t words[] = {K_ARG06, 1, 2, 3, 4, 5};
    static const float pairs[4][2] = {{0.6f, 0.8f}, {0.25f, -0.5f}, {-0.6f, 0.8f}, {-0.0f, 1.0f}};
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    expectation ex;
    size_t s, i, live;
    heap.residue = 5;
    create_ok(&h, &f, SCENARIO_MINIMAL, &ex, &p);
    live = heap.live;
    for (s = 0; s < sizeof steps / sizeof steps[0]; ++s) {
        const step *t = &steps[s];
        const size_t allocations = heap.allocations;
        rome2_native_unit_card snapshot;
        const rome2_native_unit_card *v;
        memcpy(&snapshot, get(h), sizeof snapshot);
        if (t->coordinate) {
            rome2_float2 pair;
            pair.x = t->x; pair.y = t->y;
            CHECK(rome2_owned_unit_card_append_coordinate(h, pair) == ROME2_UNIT_CARD_OK);
        } else {
            CHECK(rome2_owned_unit_card_append_word(h, t->word) == ROME2_UNIT_CARD_OK);
        }
        v = get(h);
        CHECK(heap.allocations == allocations + t->grants && heap.live == live);
        CHECK(v->words.count == t->words && v->words.capacity == t->word_capacity);
        CHECK(v->coordinates.count == t->pairs && v->coordinates.capacity == t->pair_capacity);
        CHECK(v->last_common_index == t->index);
        check_common_index(v);
        for (i = 0; i < v->words.count; ++i) { CHECK(v->words.items[i] == words[i]); }
        for (i = 0; i < v->coordinates.count && i < 4; ++i) {
            CHECK(bits32(v->coordinates.items[i].x) == bits32(pairs[i][0]));
            CHECK(bits32(v->coordinates.items[i].y) == bits32(pairs[i][1]));
        }
        if (v->coordinates.count == 5) {
            const rome2_float2 c = v->coordinates.items[4];
            CHECK(bits32(c.x) == bits32(c.y) && fabsf(c.x - 0.70710678f) <= 2e-6f);
        }
        /* Nothing but the touched vector and the shared index changed. */
        snapshot.words = v->words; snapshot.coordinates = v->coordinates;
        snapshot.last_common_index = v->last_common_index;
        CHECK(memcmp(&snapshot, v, sizeof snapshot) == 0);
    }
    destroy_all(&h, &heap, 0);
}

static void test_append_failures(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    expectation ex;
    unsigned round;
    int kind;
    size_t injected = 0;
    heap.residue = 6;
    create_ok(&h, &f, SCENARIO_MINIMAL, &ex, &p);
    for (round = 0; round < 3; ++round) {
        /* Both vectors are full here (1/1, 2/2, then 4/4). */
        for (kind = 0; kind < 2; ++kind) {
            rome2_native_unit_card snapshot;
            uint32_t saved_words[8];
            rome2_float2 saved_pairs[8];
            const size_t allocations = heap.allocations, releases = heap.releases, live = heap.live;
            rome2_float2 pair;
            const rome2_native_unit_card *v = get(h);
            CHECK(v->words.count == v->words.capacity && v->coordinates.count == v->coordinates.capacity);
            CHECK(v->words.count <= 8 && v->coordinates.count <= 8);
            memcpy(&snapshot, v, sizeof snapshot);
            memcpy(saved_words, v->words.items, v->words.count * sizeof saved_words[0]);
            memcpy(saved_pairs, v->coordinates.items, v->coordinates.count * sizeof saved_pairs[0]);
            heap.fail_at = heap.allocations + 1;
            pair.x = 0.125f; pair.y = 0.25f;
            CHECK((kind == 0 ? rome2_owned_unit_card_append_word(h, 0x1000u + round) :
                rome2_owned_unit_card_append_coordinate(h, pair)) == ROME2_UNIT_CARD_ALLOCATION_FAILED);
            ++injected;
            heap.fail_at = 0;
            CHECK(heap.allocations == allocations + 1 && heap.releases == releases && heap.live == live);
            v = get(h);
            CHECK(memcmp(&snapshot, v, sizeof snapshot) == 0);
            CHECK(memcmp(saved_words, v->words.items, v->words.count * sizeof saved_words[0]) == 0);
            CHECK(memcmp(saved_pairs, v->coordinates.items, v->coordinates.count * sizeof saved_pairs[0]) == 0);
        }
        /* Grow both by one doubling and fill them again. */
        do {
            CHECK(rome2_owned_unit_card_append_word(h, 0x2000u + get(h)->words.count) == ROME2_UNIT_CARD_OK);
        } while (get(h)->words.count != get(h)->words.capacity);
        do {
            rome2_float2 pair;
            pair.x = 0.0f; pair.y = (float)get(h)->coordinates.count / 16.0f;
            CHECK(rome2_owned_unit_card_append_coordinate(h, pair) == ROME2_UNIT_CARD_OK);
        } while (get(h)->coordinates.count != get(h)->coordinates.capacity);
        check_common_index(get(h));
    }
    destroy_all(&h, &heap, injected);
}

static void test_coordinate_rejection(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    expectation ex;
    rome2_float2 bad[8];
    int state;
    size_t i;
    bad[0].x = f32(UINT32_C(0x7fc00000)); bad[0].y = 0.0f;  /* quiet NaN */
    bad[1].x = 0.0f; bad[1].y = f32(UINT32_C(0xffc00001));  /* negative NaN payload */
    bad[2].x = f32(UINT32_C(0x7f800001)); bad[2].y = 0.0f;  /* signalling NaN */
    bad[3].x = f32(UINT32_C(0x7f800000)); bad[3].y = 0.0f;  /* +inf */
    bad[4].x = 0.0f; bad[4].y = f32(UINT32_C(0xff800000));  /* -inf */
    bad[5].x = 2e19f; bad[5].y = 0.0f;                      /* x*x overflows */
    bad[6].x = 1.5e19f; bad[6].y = -1.5e19f;                /* finite squares, sum overflows */
    bad[7].x = FLT_MAX; bad[7].y = FLT_MAX;
    create_ok(&h, &f, SCENARIO_MINIMAL, &ex, &p);
    for (state = 0; state < 2; ++state) {
        /* state 0: 1/1 (growth would be needed); state 1: 3/4 (spare slot). */
        for (i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
            rome2_native_unit_card snapshot;
            const size_t allocations = heap.allocations, releases = heap.releases;
            memcpy(&snapshot, get(h), sizeof snapshot);
            CHECK(rome2_owned_unit_card_append_coordinate(h, bad[i]) == ROME2_UNIT_CARD_UNSUPPORTED_COORDINATE);
            CHECK(heap.allocations == allocations && heap.releases == releases);
            CHECK(memcmp(&snapshot, get(h), sizeof snapshot) == 0);
        }
        if (state == 0) {
            rome2_float2 pair;
            pair.x = 0.5f; pair.y = 0.5f;
            CHECK(rome2_owned_unit_card_append_coordinate(h, pair) == ROME2_UNIT_CARD_OK);
            CHECK(rome2_owned_unit_card_append_coordinate(h, pair) == ROME2_UNIT_CARD_OK);
            CHECK(get(h)->coordinates.count == 3 && get(h)->coordinates.capacity == 4);
        }
    }
    destroy_all(&h, &heap, 0);
}

/* ------------------------------------------------------------------------ */
/* UTF-16 writer.                                                            */
/* ------------------------------------------------------------------------ */

static void test_text16(void)
{
    static const uint16_t golden[7] = {0x0041, 0x0000, 0xd800, 0xdc00, 0xdfff, 0xffff, 0xd83d};
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    expectation ex;
    uint16_t units[7];
    rome2_string16_view source;
    rome2_native_unit_card snapshot;
    rome2_host_string16 old;
    size_t live, allocations, releases, observations;
    heap.residue = 1;
    create_ok(&h, &f, SCENARIO_FULL, &ex, &p);

    /* Deep copy with embedded zero, paired and lone surrogates. */
    memcpy(units, golden, sizeof units);
    source.data = units; source.length_units = 7;
    memcpy(&snapshot, get(h), sizeof snapshot);
    live = heap.live; allocations = heap.allocations; observations = heap.observations;
    CHECK(rome2_owned_unit_card_set_text16(h, source) == ROME2_UNIT_CARD_OK);
    check_copy16(&get(h)->str_0fc, golden, 7, units);
    CHECK(heap.live == live + 1 && heap.allocations == allocations + 1 && heap.observations == observations);
    snapshot.str_0fc = get(h)->str_0fc;
    CHECK(memcmp(&snapshot, get(h), sizeof snapshot) == 0); /* only str_0fc changed */
    memset(units, 0xdd, sizeof units); /* revoke the source */
    check_copy16(&get(h)->str_0fc, golden, 7, units);

    /* Borrow the entire previous value. */
    old = get(h)->str_0fc;
    CHECK(rome2_owned_unit_card_set_text16(h, rome2_host_string16_as_view(old)) == ROME2_UNIT_CARD_OK);
    check_copy16(&get(h)->str_0fc, golden, 7, old.data);
    CHECK(heap.live == live + 1 && heap.observations == observations + 1);

    /* Borrow an interior range of the previous value. */
    source.data = get(h)->str_0fc.data + 1; source.length_units = 4;
    CHECK(rome2_owned_unit_card_set_text16(h, source) == ROME2_UNIT_CARD_OK);
    check_copy16(&get(h)->str_0fc, golden + 1, 4, source.data);
    CHECK(heap.live == live + 1 && heap.observations == observations + 2);

    /* Allocation failure preserves the old string. */
    memcpy(&snapshot, get(h), sizeof snapshot);
    allocations = heap.allocations; releases = heap.releases;
    heap.fail_at = heap.allocations + 1;
    source.data = golden; source.length_units = 7;
    CHECK(rome2_owned_unit_card_set_text16(h, source) == ROME2_UNIT_CARD_ALLOCATION_FAILED);
    heap.fail_at = 0;
    CHECK(heap.allocations == allocations + 1 && heap.releases == releases && heap.live == live + 1);
    CHECK(memcmp(&snapshot, get(h), sizeof snapshot) == 0);
    check_copy16(&get(h)->str_0fc, golden + 1, 4, golden);

    /* Nonempty NULL data, negative and too-large lengths: MALFORMED_SOURCE
     * without allocator effects (the length is never trusted for reading). */
    {
        static const ptrdiff_t lengths[3] = {3, -1, (ptrdiff_t)ROME2_OWNED_STRING16_MAX_UNITS + 1};
        size_t i;
        allocations = heap.allocations;
        for (i = 0; i < 3; ++i) {
            source.data = i == 0 ? NULL : golden;
            source.length_units = lengths[i];
            CHECK(rome2_owned_unit_card_set_text16(h, source) == ROME2_UNIT_CARD_MALFORMED_SOURCE);
            CHECK(heap.allocations == allocations && memcmp(&snapshot, get(h), sizeof snapshot) == 0);
        }
    }

    /* Clear to the typed native empty, then stay empty without effects. */
    releases = heap.releases; allocations = heap.allocations;
    source.data = NULL; source.length_units = 0;
    CHECK(rome2_owned_unit_card_set_text16(h, source) == ROME2_UNIT_CARD_OK);
    CHECK(get(h)->str_0fc.length_units == 0 && get(h)->str_0fc.capacity_units == 0);
    CHECK(get(h)->str_0fc.data == rome2_host_string16_empty_sentinel && get(h)->str_0fc.data[0] == 0);
    CHECK(heap.live == live && heap.releases == releases + 1 && heap.allocations == allocations);
    CHECK(heap.observations == observations + 3);
    source.data = golden; source.length_units = 0;
    CHECK(rome2_owned_unit_card_set_text16(h, source) == ROME2_UNIT_CARD_OK);
    CHECK(get(h)->str_0fc.data == rome2_host_string16_empty_sentinel);
    CHECK(heap.releases == releases + 1 && heap.allocations == allocations);
    source.length_units = 1;
    CHECK(rome2_owned_unit_card_set_text16(h, source) == ROME2_UNIT_CARD_OK);
    check_copy16(&get(h)->str_0fc, golden, 1, golden);
    destroy_all(&h, &heap, 1);
    CHECK(heap.observations == ex.observations + 4);
}

/* ------------------------------------------------------------------------ */
/* Configuration mutators.                                                   */
/* ------------------------------------------------------------------------ */

static void test_config_mutators(void)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    config_fixture c;
    expectation ex;
    rome2_native_unit_card snapshot;
    uint32_t capacity;
    size_t observations, allocations, releases, live;
    unsigned which;
    heap.residue = 2;
    create_ok(&h, &f, SCENARIO_FULL, &ex, &p);
    capacity = get(h)->fauna.capacity;
    CHECK(capacity >= 2);

    /* Larger replacement: deep copy, old nested owners destroyed. */
    make_config(&c, 3, 1);
    memcpy(&snapshot, get(h), sizeof snapshot);
    observations = heap.observations;
    CHECK(rome2_owned_unit_card_replace_config(h, &c.view) == ROME2_UNIT_CARD_OK);
    CHECK(heap.observations == observations + 2);
    verify_config(&get(h)->fauna, 3, 1, 0, &c);
    CHECK(get(h)->fauna.capacity >= capacity);
    snapshot.fauna = get(h)->fauna;
    CHECK(memcmp(&snapshot, get(h), sizeof snapshot) == 0); /* only the fauna view changed */
    memset(&c, 0xdd, sizeof c);
    verify_config(&get(h)->fauna, 3, 1, 0, &c);

    /* Smaller replacement retains at least the previous capacity. */
    capacity = get(h)->fauna.capacity;
    make_config(&c, 1, 2);
    CHECK(rome2_owned_unit_card_replace_config(h, &c.view) == ROME2_UNIT_CARD_OK);
    verify_config(&get(h)->fauna, 1, 2, 0, &c);
    CHECK(get(h)->fauna.capacity >= capacity);

    /* Alias the whole published view: rebuilt from itself, never shared. */
    make_config(&c, 3, 1);
    CHECK(rome2_owned_unit_card_replace_config(h, &c.view) == ROME2_UNIT_CARD_OK);
    capacity = get(h)->fauna.capacity;
    {
        /* Identities only; the old storage is released by the call. */
        const uintptr_t old_payload = (uintptr_t)get(h)->fauna.items[2].strings.items[0].data;
        observations = heap.observations;
        CHECK(rome2_owned_unit_card_replace_config(h, &get(h)->fauna) == ROME2_UNIT_CARD_OK);
        verify_config(&get(h)->fauna, 3, 1, 0, &c);
        CHECK(get(h)->fauna.capacity >= capacity && heap.observations == observations + 3);
        CHECK((uintptr_t)get(h)->fauna.items[2].strings.items[0].data != old_payload);
    }

    /* Alias a caller-made window over the current records. */
    {
        rome2_fauna_vector_view window;
        window.capacity = 0; window.count = 2; window.items = &get(h)->fauna.items[1];
        capacity = get(h)->fauna.capacity;
        CHECK(rome2_owned_unit_card_replace_config(h, &window) == ROME2_UNIT_CARD_OK);
        verify_config(&get(h)->fauna, 2, 1, 1, &c);
        CHECK(get(h)->fauna.capacity >= capacity);
    }

    /* Explicit empty configuration. */
    {
        rome2_fauna_vector_view empty;
        empty.capacity = UINT32_MAX; empty.count = 0; empty.items = NULL;
        capacity = get(h)->fauna.capacity;
        CHECK(rome2_owned_unit_card_replace_config(h, &empty) == ROME2_UNIT_CARD_OK);
        CHECK(get(h)->fauna.count == 0 && get(h)->fauna.capacity >= capacity);
    }

    /* clear destroys nested owners, keeps the exact capacity, allocates nothing. */
    make_config(&c, 3, 1);
    CHECK(rome2_owned_unit_card_replace_config(h, &c.view) == ROME2_UNIT_CARD_OK);
    capacity = get(h)->fauna.capacity;
    memcpy(&snapshot, get(h), sizeof snapshot);
    allocations = heap.allocations; observations = heap.observations; live = heap.live;
    CHECK(rome2_owned_unit_card_clear_fauna(h) == ROME2_UNIT_CARD_OK);
    CHECK(get(h)->fauna.count == 0 && get(h)->fauna.capacity == capacity);
    CHECK(heap.allocations == allocations && heap.observations == observations + 3 && heap.live < live);
    snapshot.fauna = get(h)->fauna;
    CHECK(memcmp(&snapshot, get(h), sizeof snapshot) == 0);
    releases = heap.releases;
    CHECK(rome2_owned_unit_card_clear_fauna(h) == ROME2_UNIT_CARD_OK);
    CHECK(heap.releases == releases && heap.allocations == allocations);
    CHECK(get(h)->fauna.count == 0 && get(h)->fauna.capacity == capacity);
    make_config(&c, 2, 3);
    CHECK(rome2_owned_unit_card_replace_config(h, &c.view) == ROME2_UNIT_CARD_OK);
    verify_config(&get(h)->fauna, 2, 3, 0, &c);
    CHECK(get(h)->fauna.capacity >= capacity);

    /* Rejected replacements change nothing and allocate nothing. */
    for (which = 0; which < CONFIG_CORRUPTIONS; ++which) {
        config_fixture bad, before;
        rome2_unit_card_status expected;
        make_config(&bad, 2, 4);
        expected = corrupt_config(&bad, which);
        memcpy(&before, &bad, sizeof bad);
        memcpy(&snapshot, get(h), sizeof snapshot);
        allocations = heap.allocations;
        CHECK(rome2_owned_unit_card_replace_config(h, &bad.view) == expected);
        CHECK(heap.allocations == allocations && memcmp(&snapshot, get(h), sizeof snapshot) == 0);
        CHECK(memcmp(&bad, &before, sizeof bad) == 0);
    }
    verify_config(&get(h)->fauna, 2, 3, 0, &c);
    destroy_all(&h, &heap, 0);
}

/* fail == 0 measures a successful replacement and returns its grant count. */
static size_t replace_run(unsigned residue, size_t fail, bool alias)
{
    test_heap heap = {0};
    rome2_owned_string_allocator p = test_policy(&heap);
    rome2_owned_unit_card *h = NULL;
    card_fixture f;
    config_fixture c, before;
    expectation ex;
    rome2_native_unit_card snapshot;
    const rome2_fauna_vector_view *source;
    size_t allocations, releases, live, observations, grants;
    uintptr_t old_payload;
    rome2_unit_card_status status;
    heap.residue = residue;
    create_ok(&h, &f, SCENARIO_FULL, &ex, &p);
    make_config(&c, 3, 1);
    memcpy(&before, &c, sizeof c);
    source = alias ? &get(h)->fauna : &c.view;
    memcpy(&snapshot, get(h), sizeof snapshot);
    /* Identity only: on success the old storage is released by the call. */
    old_payload = (uintptr_t)snapshot.fauna.items[1].strings.items[0].data;
    allocations = heap.allocations; releases = heap.releases;
    live = heap.live; observations = heap.observations;
    heap.fail_at = fail == 0 ? 0 : allocations + fail;
    status = rome2_owned_unit_card_replace_config(h, source);
    heap.fail_at = 0;
    grants = heap.allocations - allocations;
    if (fail == 0) {
        CHECK(status == ROME2_UNIT_CARD_OK);
        verify_config(&get(h)->fauna, alias ? 2u : 3u, alias ? 0u : 1u, 0, alias ? &f.config : &c);
        CHECK(get(h)->fauna.capacity >= snapshot.fauna.capacity);
        CHECK(heap.observations == observations + 2);
        if (alias) {
            CHECK(get(h)->fauna.items != snapshot.fauna.items);
            CHECK((uintptr_t)get(h)->fauna.items[1].strings.items[0].data != old_payload);
        }
    } else {
        CHECK(status == ROME2_UNIT_CARD_ALLOCATION_FAILED);
        CHECK(grants == fail && heap.releases == releases + fail - 1 && heap.live == live);
        CHECK(memcmp(&snapshot, get(h), sizeof snapshot) == 0);
        verify_config(&get(h)->fauna, 2, 0, 0, &f.config);
    }
    CHECK(memcmp(&c, &before, sizeof c) == 0);
    destroy_all(&h, &heap, fail == 0 ? 0u : 1u);
    return grants;
}

static size_t test_replace_failures(bool alias)
{
    unsigned residue;
    size_t calls = 0, fail;
    for (residue = 0; residue < 8; ++residue) {
        const size_t measured = replace_run(residue, 0, alias);
        if (residue == 0) { calls = measured; }
        CHECK(measured == calls && calls != 0);
        for (fail = 1; fail <= calls; ++fail) { (void)replace_run(residue, fail, alias); }
    }
    return calls;
}

int main(void)
{
    size_t calls[SCENARIO_COUNT], replace_calls, alias_calls;
    int s;
    check_image_defaults();
    for (s = 0; s < SCENARIO_COUNT; ++s) {
        calls[s] = scenario_success(s);
        scenario_failures(s, calls[s]);
    }
    CHECK(calls[SCENARIO_FULL] > calls[SCENARIO_EMPTY_PARTS]);
    CHECK(calls[SCENARIO_EMPTY_PARTS] > calls[SCENARIO_MINIMAL]);
    test_sibling_independence();
    test_projection_variants();
    test_initial_coordinates();
    test_arguments_and_handles();
    test_malformed_sources();
    test_captured_allocator();
    test_release_authority();
    test_no_observer();
    test_append_growth();
    test_append_failures();
    test_coordinate_rejection();
    test_text16();
    test_config_mutators();
    replace_calls = test_replace_failures(false);
    alias_calls = test_replace_failures(true);
    printf("owned unit card: %zu checks; factory failure positions full=%zu empty-parts=%zu "
        "minimal=%zu, replace=%zu alias-replace=%zu, each x 8 raw alignments\n",
        checks, calls[SCENARIO_FULL], calls[SCENARIO_EMPTY_PARTS], calls[SCENARIO_MINIMAL],
        replace_calls, alias_calls);
    return 0;
}
