/*
 * test_owned_entity.c - native tests for the owned_entity adapter.
 *
 * No game image is read.  Sources live in exact-length heap buffers with no
 * terminator, so any read past an explicit length or after release shows up
 * under AddressSanitizer.  A tracking allocator records every request and
 * checks that each release matches it exactly.
 */
#include "owned_entity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* REQUIRE always evaluates (unlike assert under /DNDEBUG) and keeps going. */
static int g_failures;

#define REQUIRE(cond)                                                      \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

/* ------------------------------------------------------------------------ */
/* Tracking allocator.                                                       */
/* ------------------------------------------------------------------------ */

#define TRACK_MAX 64u

typedef struct track_record {
    unsigned char *block;      /* malloc result */
    void *raw;                 /* block + misalign, handed to the adapter */
    size_t bytes;
    uint32_t allocation_class;
    bool live;
} track_record;

typedef struct tracker {
    size_t allocate_calls;
    size_t release_calls;
    size_t observer_calls;
    size_t fail_at;            /* 1-based allocate call that fails; 0 = never */
    size_t misalign;           /* byte offset of every returned pointer */
    size_t live;
    size_t errors;             /* unknown or repeated release, size/class or
                                  observer mismatch, tracker exhaustion */
    size_t record_count;
    uintptr_t last_released;
    track_record records[TRACK_MAX];
} tracker;

static void *track_allocate(void *context, size_t bytes,
    uint32_t allocation_class)
{
    tracker *t = (tracker *)context;
    track_record *r;
    unsigned char *block;

    ++t->allocate_calls;
    if (allocation_class != ROME2_OWNED_STRING_ALLOCATION_CLASS) {
        ++t->errors;
    }
    if (t->allocate_calls == t->fail_at) {
        return NULL;
    }
    if (t->record_count == TRACK_MAX || bytes > SIZE_MAX - t->misalign) {
        ++t->errors;
        return NULL;
    }
    block = (unsigned char *)malloc(t->misalign + bytes);
    if (block == NULL) {
        ++t->errors;
        return NULL;
    }
    /* Never hand out zeroed memory. */
    memset(block, 0xCD, t->misalign + bytes);
    r = &t->records[t->record_count++];
    r->block = block;
    r->raw = block + t->misalign;
    r->bytes = bytes;
    r->allocation_class = allocation_class;
    r->live = true;
    ++t->live;
    return r->raw;
}

static void track_release(void *context, void *raw, size_t bytes,
    uint32_t allocation_class)
{
    tracker *t = (tracker *)context;
    size_t i;

    ++t->release_calls;
    for (i = 0u; i < t->record_count; ++i) {
        track_record *r = &t->records[i];
        if (r->live && r->raw == raw) {
            if (r->bytes != bytes || r->allocation_class != allocation_class) {
                ++t->errors;
            }
            r->live = false;
            --t->live;
            t->last_released = (uintptr_t)raw;
            free(r->block);
            return;
        }
    }
    ++t->errors;
}

static void track_observe(void *context, uintptr_t identity, size_t bytes)
{
    tracker *t = (tracker *)context;
    ++t->observer_calls;
    /* owned_string notifies right after the matching release. */
    if (identity != t->last_released || bytes == 0u) {
        ++t->errors;
    }
}

static rome2_owned_string_allocator track_allocator(tracker *t)
{
    rome2_owned_string_allocator a;
    a.allocate = track_allocate;
    a.release = track_release;
    a.context = t;
    a.release_observer = track_observe;
    a.observer_context = t;
    return a;
}

static void tracker_init(tracker *t, size_t fail_at, size_t misalign)
{
    memset(t, 0, sizeof *t);
    t->fail_at = fail_at;
    t->misalign = misalign;
}

static bool tracker_clean(const tracker *t)
{
    return t->live == 0u && t->errors == 0u &&
        t->release_calls == t->record_count;
}

/* Allocator "B": any call through it is a defect. */
static size_t g_poison_calls;

static void *poison_allocate(void *context, size_t bytes, uint32_t cls)
{
    (void)context;
    (void)bytes;
    (void)cls;
    ++g_poison_calls;
    return NULL;
}

static void poison_release(void *context, void *raw, size_t bytes,
    uint32_t cls)
{
    (void)context;
    (void)raw;
    (void)bytes;
    (void)cls;
    ++g_poison_calls;
}

static void poison_observe(void *context, uintptr_t identity, size_t bytes)
{
    (void)context;
    (void)identity;
    (void)bytes;
    ++g_poison_calls;
}

/* ------------------------------------------------------------------------ */
/* Fixture: heap-backed sources with exact-length, unterminated buffers.     */
/* ------------------------------------------------------------------------ */

#define ITEM_COUNT 5u
#define NONEMPTY_ITEMS 3u
#define NONEMPTY_SCALARS 5u   /* two literals + arg00 + arg11 + arg17 */
/* handle + 5 scalar payloads + view array + vector storage
 * + 3 item payloads + native items array */
#define FULL_ALLOCATIONS 12u

static const char k_label_alt[] = "roman_legion";
static const char k_source[] = "auto\0deploy";      /* embedded zero byte */
static const char k_kind[] = "hellenic_general";
static const char k_item0[] = "legionary";
static const char k_item2[] = "eq\0ites";           /* embedded zero byte */
static const char k_item4[] = "hastati";
static const char k_ignored[] = "ignored";          /* behind a zero length */
static const char k_arg08[] = "hello";

#define LEN(literal) ((int32_t)(sizeof(literal) - 1u))

typedef struct fixture {
    char *buf_label_alt;
    char *buf_source;
    char *buf_kind;
    char *buf_item0;
    char *buf_item1;
    char *buf_item2;
    char *buf_item4;
    char *buf_arg08;
    rome2_recovered_str arg00;
    rome2_recovered_str arg11;
    rome2_recovered_str arg17;
    rome2_recovered_str items[ITEM_COUNT];
    rome2_entity_descriptor desc;
    rome2_entity_origin origin;
    uint32_t tag_pair[2];
    rome2_entity_globals globals;
    rome2_entity_ctor_args args;
} fixture;

static char *dup_exact(const char *bytes, int32_t length)
{
    char *p = (char *)malloc((size_t)length);
    if (p == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(2);
    }
    memcpy(p, bytes, (size_t)length);
    return p;
}

static void fixture_init(fixture *fx)
{
    memset(fx, 0, sizeof *fx);
    fx->buf_label_alt = dup_exact(k_label_alt, LEN(k_label_alt));
    fx->buf_source = dup_exact(k_source, LEN(k_source));
    fx->buf_kind = dup_exact(k_kind, LEN(k_kind));
    fx->buf_item0 = dup_exact(k_item0, LEN(k_item0));
    fx->buf_item1 = dup_exact(k_ignored, LEN(k_ignored));
    fx->buf_item2 = dup_exact(k_item2, LEN(k_item2));
    fx->buf_item4 = dup_exact(k_item4, LEN(k_item4));
    fx->buf_arg08 = dup_exact(k_arg08, LEN(k_arg08));

    fx->arg00.length = LEN(k_label_alt);
    fx->arg00.capacity = LEN(k_label_alt);
    fx->arg00.data = fx->buf_label_alt;
    fx->arg11.length = LEN(k_source);
    fx->arg11.capacity = LEN(k_source) + 9;           /* capacity > length */
    fx->arg11.data = fx->buf_source;
    fx->arg17.length = LEN(k_kind);
    fx->arg17.capacity = LEN(k_kind);
    fx->arg17.data = fx->buf_kind;

    fx->items[0].length = LEN(k_item0);
    fx->items[0].capacity = LEN(k_item0);
    fx->items[0].data = fx->buf_item0;
    fx->items[1].length = 0;                          /* data never read */
    fx->items[1].capacity = LEN(k_ignored);
    fx->items[1].data = fx->buf_item1;
    fx->items[2].length = LEN(k_item2);
    fx->items[2].capacity = LEN(k_item2);
    fx->items[2].data = fx->buf_item2;
    /* The old API's empty descriptor: its data is the image-sentinel
     * identity, which must never be dereferenced. */
    rome2_unit_card_str_reset(&fx->items[3]);
    fx->items[4].length = LEN(k_item4);
    fx->items[4].capacity = LEN(k_item4) + 3;
    fx->items[4].data = fx->buf_item4;

    fx->desc.reserved_00 = 0xabcdef01u;
    fx->desc.item_count = ITEM_COUNT;
    fx->desc.items = fx->items;
    fx->origin.x = 0x1234u;
    fx->origin.y = 0x5678u;
    fx->tag_pair[0] = 0xaabbccddu;
    fx->tag_pair[1] = 0x01020304u;
    fx->globals.grid_extent_min = 1.5f;
    fx->globals.grid_extent_max = -2.25f;

    fx->args.arg00 = &fx->arg00;
    fx->args.arg01 = fx->tag_pair;
    fx->args.arg02 = 0x1111u;
    fx->args.arg03 = 0x2222u;
    fx->args.arg04 = 0x3333u;
    fx->args.arg05 = 0x4444u;
    fx->args.arg06 = LEN(k_arg08);                    /* never read or freed */
    fx->args.arg07 = LEN(k_arg08);
    fx->args.arg08 = fx->buf_arg08;
    fx->args.arg09 = &fx->origin;
    fx->args.arg10 = &fx->desc;
    fx->args.arg11 = &fx->arg11;
    fx->args.arg12 = 0x123400b6u;
    fx->args.arg13 = 0x567800a5u;
    fx->args.arg14 = 0x0badf00du;
    fx->args.arg15 = 0x13579bdfu;
    fx->args.arg16 = 0xabcd00c7u;
    fx->args.arg17 = &fx->arg17;
    fx->args.arg18 = 0xefab00e8u;
}

static void fixture_free(fixture *fx)
{
    free(fx->buf_label_alt);
    free(fx->buf_source);
    free(fx->buf_kind);
    free(fx->buf_item0);
    free(fx->buf_item1);
    free(fx->buf_item2);
    free(fx->buf_item4);
    free(fx->buf_arg08);
    memset(fx, 0, sizeof *fx);
}

static bool fixture_buffers_intact(const fixture *fx)
{
    return memcmp(fx->buf_label_alt, k_label_alt, sizeof k_label_alt - 1u) == 0
        && memcmp(fx->buf_source, k_source, sizeof k_source - 1u) == 0
        && memcmp(fx->buf_kind, k_kind, sizeof k_kind - 1u) == 0
        && memcmp(fx->buf_item0, k_item0, sizeof k_item0 - 1u) == 0
        && memcmp(fx->buf_item1, k_ignored, sizeof k_ignored - 1u) == 0
        && memcmp(fx->buf_item2, k_item2, sizeof k_item2 - 1u) == 0
        && memcmp(fx->buf_item4, k_item4, sizeof k_item4 - 1u) == 0
        && memcmp(fx->buf_arg08, k_arg08, sizeof k_arg08 - 1u) == 0;
}

/* ------------------------------------------------------------------------ */
/* Assertions on published strings.                                          */
/* ------------------------------------------------------------------------ */

static bool is_image_identity(const char *data)
{
    /* Integer comparison only; the identity is never dereferenced. */
    const uintptr_t v = (uintptr_t)data;
    return v == ROME2_UNITCARD_EMPTY_SENTINEL_A ||
        v == ROME2_UNITCARD_EMPTY_SENTINEL_B;
}

/* Owned nonempty value: exact bytes, capacity == length, terminated. */
static bool owned_equals(const rome2_recovered_str *s, const char *bytes,
    int32_t length)
{
    return s->length == length && s->capacity == length && s->data != NULL &&
        s->data != rome2_host_string8_empty_sentinel &&
        !is_image_identity(s->data) &&
        memcmp(s->data, bytes, (size_t)length) == 0 &&
        s->data[length] == '\0';
}

/* Readable native empty sentinel. */
static bool is_native_empty(const rome2_recovered_str *s)
{
    return s->length == 0 && s->capacity == 0 &&
        s->data == rome2_host_string8_empty_sentinel && s->data[0] == '\0';
}

/* Owned copy of an old-projection value; reads ref->data only if nonempty. */
static bool matches_reference(const rome2_recovered_str *owned,
    const rome2_recovered_str *ref)
{
    if (ref->length == 0) {
        return is_native_empty(owned);
    }
    return owned_equals(owned, ref->data, ref->length) &&
        owned->data != ref->data;
}

static void entity_strings(const rome2_battle_entity *e,
    const rome2_recovered_str *out[9])
{
    out[0] = &e->effect_name;
    out[1] = &e->category;
    out[2] = &e->label;
    out[3] = &e->descriptor_text;
    out[4] = &e->climate.name;
    out[5] = &e->climate.name_alt;
    out[6] = &e->label_alt;
    out[7] = &e->effect_kind;
    out[8] = &e->source_name;
}

static void require_scalars_match(const rome2_battle_entity *e,
    const rome2_battle_entity *ref)
{
    REQUIRE(e->dispatch.slot0 == ref->dispatch.slot0);
    REQUIRE(e->dispatch.slot1 == ref->dispatch.slot1);
    REQUIRE(e->dispatch.slot2 == ref->dispatch.slot2);
    REQUIRE(e->dispatch.slot3 == ref->dispatch.slot3);
    REQUIRE(e->origin_x == ref->origin_x);
    REQUIRE(e->origin_y == ref->origin_y);
    REQUIRE(e->grid_extent_min == ref->grid_extent_min);
    REQUIRE(e->grid_extent_max == ref->grid_extent_max);
    REQUIRE(e->activation_radius_min == ref->activation_radius_min);
    REQUIRE(e->activation_radius_max == ref->activation_radius_max);
    REQUIRE(e->point_count == ref->point_count);
    REQUIRE(e->owner_id == ref->owner_id);
    REQUIRE(e->mode == ref->mode);
    REQUIRE(memcmp(e->pad_065, ref->pad_065, sizeof e->pad_065) == 0);
    REQUIRE(e->field_068 == ref->field_068);
    REQUIRE(e->owner_ref == ref->owner_ref);
    REQUIRE(e->climate.dispatch0 == ref->climate.dispatch0);
    REQUIRE(e->climate.dispatch1 == ref->climate.dispatch1);
    REQUIRE(e->climate.dispatch2 == ref->climate.dispatch2);
    REQUIRE(e->climate.grid_a == ref->climate.grid_a);
    REQUIRE(e->climate.grid_b == ref->climate.grid_b);
    REQUIRE(e->climate.grid_c == ref->climate.grid_c);
    REQUIRE(e->tag_lo == ref->tag_lo);
    REQUIRE(e->tag_hi == ref->tag_hi);
    REQUIRE(e->item_count == ref->item_count);
    REQUIRE(e->item_capacity == ref->item_capacity);
    REQUIRE(e->flag_0cc == ref->flag_0cc);
    REQUIRE(memcmp(e->pad_0cd, ref->pad_0cd, sizeof e->pad_0cd) == 0);
    REQUIRE(e->flag_0dc == ref->flag_0dc);
    REQUIRE(memcmp(e->pad_0dd, ref->pad_0dd, sizeof e->pad_0dd) == 0);
    REQUIRE(e->field_0e0 == ref->field_0e0);
    REQUIRE(e->flag_0e4 == ref->flag_0e4);
    REQUIRE(memcmp(e->pad_0e5, ref->pad_0e5, sizeof e->pad_0e5) == 0);
}

/* Expected owned values for the full fixture, independent of any source. */
static void require_full_fixture_values(const rome2_battle_entity *e)
{
    REQUIRE(owned_equals(&e->effect_name, ROME2_ENTITY_NAME,
        LEN(ROME2_ENTITY_NAME)));
    REQUIRE(is_native_empty(&e->category));
    REQUIRE(is_native_empty(&e->label));
    REQUIRE(is_native_empty(&e->descriptor_text));
    REQUIRE(owned_equals(&e->climate.name, ROME2_ENTITY_CLIMATE_NAME,
        LEN(ROME2_ENTITY_CLIMATE_NAME)));
    REQUIRE(is_native_empty(&e->climate.name_alt));
    REQUIRE(owned_equals(&e->label_alt, k_label_alt, LEN(k_label_alt)));
    REQUIRE(owned_equals(&e->effect_kind, k_kind, LEN(k_kind)));
    REQUIRE(owned_equals(&e->source_name, k_source, LEN(k_source)));
    REQUIRE(e->item_count == ITEM_COUNT);
    REQUIRE(e->item_capacity == ITEM_COUNT);
    REQUIRE(e->items != NULL);
    if (e->items != NULL) {
        REQUIRE(owned_equals(&e->items[0], k_item0, LEN(k_item0)));
        REQUIRE(is_native_empty(&e->items[1]));
        REQUIRE(owned_equals(&e->items[2], k_item2, LEN(k_item2)));
        REQUIRE(is_native_empty(&e->items[3]));
        REQUIRE(owned_equals(&e->items[4], k_item4, LEN(k_item4)));
    }
}

/* ------------------------------------------------------------------------ */
/* Reference: the unchanged old projection with a real item host.            */
/* ------------------------------------------------------------------------ */

static void *ref_alloc(size_t bytes)
{
    return malloc(bytes);
}

static void ref_free(void *items)
{
    free(items);
}

static const rome2_entity_host k_ref_host = { ref_alloc, ref_free };

/* ------------------------------------------------------------------------ */
/* Tests.                                                                    */
/* ------------------------------------------------------------------------ */

static void test_deep_copy_survives_source_release(void)
{
    fixture fx;
    tracker a;
    rome2_owned_string_allocator alloc;
    rome2_owned_battle_entity *h = NULL;
    rome2_battle_entity ref;
    const rome2_battle_entity *e;
    const rome2_recovered_str *owned_s[9];
    const rome2_recovered_str *ref_s[9];
    size_t i;
    size_t j;

    printf("[TEST] deep copy survives source mutation and release... ");
    fixture_init(&fx);
    tracker_init(&a, 0u, 0u);
    alloc = track_allocator(&a);

    REQUIRE(rome2_battle_entity_ctor(&ref, &fx.args, &fx.globals,
        &k_ref_host) == &ref);
    REQUIRE(rome2_owned_battle_entity_create(&h, &fx.args, &fx.globals,
        &alloc) == ROME2_OWNED_ENTITY_OK);
    e = rome2_owned_battle_entity_get(h);
    REQUIRE(e != NULL);
    if (e == NULL) {
        return;
    }
    REQUIRE(a.allocate_calls == FULL_ALLOCATIONS);
    /* Only the transient borrowed-view array is gone when create returns. */
    REQUIRE(a.release_calls == 1u);
    REQUIRE(a.observer_calls == 0u);
    REQUIRE(a.live == FULL_ALLOCATIONS - 1u);

    /* Scalars and string values equal the old projection's. */
    require_scalars_match(e, &ref);
    entity_strings(e, owned_s);
    entity_strings(&ref, ref_s);
    for (i = 0u; i < 9u; ++i) {
        REQUIRE(matches_reference(owned_s[i], ref_s[i]));
        for (j = 0u; j < i; ++j) {
            REQUIRE(owned_s[i]->length == 0 ||
                owned_s[i]->data != owned_s[j]->data);
        }
    }
    for (i = 0u; i < ITEM_COUNT; ++i) {
        REQUIRE(matches_reference(&e->items[i], &ref.items[i]));
        REQUIRE(e->items[i].data != fx.items[i].data);
    }
    REQUIRE(e->items != ref.items);
    REQUIRE(e->label_alt.data != fx.buf_label_alt);
    REQUIRE(e->source_name.data != fx.buf_source);
    REQUIRE(e->effect_kind.data != fx.buf_kind);
    REQUIRE(rome2_battle_entity_release_items(&ref, &k_ref_host));
    REQUIRE(fixture_buffers_intact(&fx));

    /* Scribble over and release every source, including the descriptors. */
    memset(fx.buf_label_alt, 'X', sizeof k_label_alt - 1u);
    memset(fx.buf_source, 'X', sizeof k_source - 1u);
    memset(fx.buf_kind, 'X', sizeof k_kind - 1u);
    memset(fx.buf_item0, 'X', sizeof k_item0 - 1u);
    memset(fx.buf_item2, 'X', sizeof k_item2 - 1u);
    memset(fx.buf_item4, 'X', sizeof k_item4 - 1u);
    fixture_free(&fx);
    memset(&fx, 0xEE, sizeof fx);

    require_full_fixture_values(e);
    REQUIRE(e->origin_x == 0x1234u && e->origin_y == 0x5678u);
    REQUIRE(e->tag_lo == 0xaabbccddu && e->tag_hi == 0x01020304u);
    REQUIRE(e->grid_extent_min == 1.5f && e->grid_extent_max == -2.25f);
    REQUIRE(e->mode == 0xb6u && e->flag_0cc == 0xe8u);
    REQUIRE(e->field_0e0 == 0x13579bdfu && e->owner_ref == 0x0badf00du);
    REQUIRE(e->climate.grid_a == 0x1111u && e->climate.grid_c == 0x3333u);

    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(h == NULL);
    REQUIRE(tracker_clean(&a));
    REQUIRE(a.release_calls == FULL_ALLOCATIONS);
    /* The observer sees string payloads only, never metadata blocks. */
    REQUIRE(a.observer_calls == NONEMPTY_SCALARS + NONEMPTY_ITEMS);
    printf("PASS\n");
}

static void test_empty_inputs_use_native_sentinels(void)
{
    rome2_entity_ctor_args args;
    rome2_entity_descriptor desc;
    rome2_recovered_str img_a;
    rome2_recovered_str img_b;
    rome2_recovered_str img_items[2];
    rome2_battle_entity ref;
    tracker a;
    rome2_owned_string_allocator alloc;
    rome2_owned_battle_entity *h = NULL;
    const rome2_battle_entity *e;
    const rome2_recovered_str *s[9];
    size_t i;

    printf("[TEST] empty inputs publish readable native sentinels... ");
    memset(&args, 0, sizeof args);
    tracker_init(&a, 0u, 0u);
    alloc = track_allocator(&a);

    /* All-NULL optional inputs and NULL globals (image defaults). */
    REQUIRE(rome2_battle_entity_ctor(&ref, &args, NULL, NULL) == &ref);
    REQUIRE(rome2_owned_battle_entity_create(&h, &args, NULL, &alloc)
        == ROME2_OWNED_ENTITY_OK);
    e = rome2_owned_battle_entity_get(h);
    REQUIRE(e != NULL);
    if (e != NULL) {
        REQUIRE(a.allocate_calls == 3u);     /* record + two literals */
        require_scalars_match(e, &ref);
        REQUIRE(e->grid_extent_min == 0.0f && e->grid_extent_max == 0.0f);
        REQUIRE(owned_equals(&e->effect_name, ROME2_ENTITY_NAME,
            LEN(ROME2_ENTITY_NAME)));
        REQUIRE(e->effect_name.data != ref.effect_name.data);
        REQUIRE(owned_equals(&e->climate.name, ROME2_ENTITY_CLIMATE_NAME,
            LEN(ROME2_ENTITY_CLIMATE_NAME)));
        REQUIRE(e->climate.name.data != ref.climate.name.data);
        entity_strings(e, s);
        for (i = 0u; i < 9u; ++i) {
            /* Check the identity first so a regression fails, not faults. */
            REQUIRE(!is_image_identity(s[i]->data));
            REQUIRE(is_image_identity(s[i]->data) ||
                s[i]->data[s[i]->length] == '\0');
            if (i != 0u && i != 4u) {
                REQUIRE(is_native_empty(s[i]));
            }
        }
        REQUIRE(e->items == NULL);
        REQUIRE(e->item_count == 0u && e->item_capacity == 0u);
    }
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(tracker_clean(&a));
    REQUIRE(a.observer_calls == 2u);

    /*
     * Empty sources whose data is the old API's image-sentinel identity, for
     * both scalar arguments and items.  Dereferencing such an identity would
     * fault.  The result must use native sentinels only.
     */
    rome2_unit_card_str_reset(&img_a);
    rome2_unit_card_str_reset_alt(&img_b);
    rome2_unit_card_str_reset(&img_items[0]);
    rome2_unit_card_str_reset_alt(&img_items[1]);
    desc.reserved_00 = 0u;
    desc.item_count = 2u;
    desc.items = img_items;
    args.arg00 = &img_a;
    args.arg11 = &img_b;
    args.arg17 = &img_a;
    args.arg10 = &desc;
    tracker_init(&a, 0u, 0u);
    REQUIRE(rome2_owned_battle_entity_create(&h, &args, NULL, &alloc)
        == ROME2_OWNED_ENTITY_OK);
    e = rome2_owned_battle_entity_get(h);
    REQUIRE(e != NULL);
    if (e != NULL) {
        /* record + two literals + view array + vector storage + items. */
        REQUIRE(a.allocate_calls == 6u);
        entity_strings(e, s);
        for (i = 0u; i < 9u; ++i) {
            REQUIRE(!is_image_identity(s[i]->data));
            if (i != 0u && i != 4u) {
                REQUIRE(is_native_empty(s[i]));
            }
        }
        REQUIRE(e->item_count == 2u && e->items != NULL);
        if (e->items != NULL) {
            REQUIRE(is_native_empty(&e->items[0]));
            REQUIRE(is_native_empty(&e->items[1]));
        }
    }
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(tracker_clean(&a));

    /* A count-zero descriptor with non-NULL items publishes no items. */
    desc.item_count = 0u;
    tracker_init(&a, 0u, 0u);
    REQUIRE(rome2_owned_battle_entity_create(&h, &args, NULL, &alloc)
        == ROME2_OWNED_ENTITY_OK);
    e = rome2_owned_battle_entity_get(h);
    REQUIRE(e != NULL && e->items == NULL && e->item_count == 0u);
    REQUIRE(a.allocate_calls == 3u);
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(tracker_clean(&a));
    printf("PASS\n");
}

static void test_destroy_null_and_repeated(void)
{
    fixture fx;
    tracker a;
    rome2_owned_string_allocator alloc;
    rome2_owned_battle_entity *h = NULL;
    size_t released;

    printf("[TEST] destroy NULL / repeated destroy... ");
    REQUIRE(rome2_owned_battle_entity_destroy(NULL)
        == ROME2_OWNED_ENTITY_BAD_ARGUMENT);
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(h == NULL);
    REQUIRE(rome2_owned_battle_entity_get(NULL) == NULL);

    fixture_init(&fx);
    tracker_init(&a, 0u, 0u);
    alloc = track_allocator(&a);
    REQUIRE(rome2_owned_battle_entity_create(&h, &fx.args, NULL, &alloc)
        == ROME2_OWNED_ENTITY_OK);
    REQUIRE(h != NULL);
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(h == NULL);
    released = a.release_calls;
    REQUIRE(released == FULL_ALLOCATIONS);
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(a.release_calls == released);
    REQUIRE(rome2_owned_battle_entity_get(h) == NULL);
    REQUIRE(tracker_clean(&a));
    REQUIRE(fixture_buffers_intact(&fx));
    fixture_free(&fx);
    printf("PASS\n");
}

static void test_captured_allocator_survives_caller_change(void)
{
    fixture fx;
    tracker a;
    rome2_owned_string_allocator alloc;
    rome2_owned_battle_entity *h = NULL;

    printf("[TEST] allocator A releases everything after caller switches "
           "to B... ");
    fixture_init(&fx);
    tracker_init(&a, 0u, 0u);
    alloc = track_allocator(&a);
    REQUIRE(rome2_owned_battle_entity_create(&h, &fx.args, &fx.globals,
        &alloc) == ROME2_OWNED_ENTITY_OK);

    g_poison_calls = 0u;
    alloc.allocate = poison_allocate;
    alloc.release = poison_release;
    alloc.context = &g_poison_calls;
    alloc.release_observer = poison_observe;
    alloc.observer_context = &g_poison_calls;

    REQUIRE(rome2_owned_battle_entity_get(h) != NULL);
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(g_poison_calls == 0u);
    REQUIRE(a.release_calls == FULL_ALLOCATIONS);
    REQUIRE(a.observer_calls == NONEMPTY_SCALARS + NONEMPTY_ITEMS);
    REQUIRE(tracker_clean(&a));
    fixture_free(&fx);
    printf("PASS\n");
}

static void test_allocation_failure_at_every_position(void)
{
    static const size_t misaligns[] = { 0u, 3u };
    static unsigned char marker;
    rome2_owned_battle_entity *const untouched =
        (rome2_owned_battle_entity *)(void *)&marker;
    size_t m;
    size_t positions = 0u;

    printf("[TEST] allocation failure at every position... ");
    for (m = 0u; m < sizeof misaligns / sizeof misaligns[0]; ++m) {
        fixture fx;
        unsigned char before[sizeof fx];
        tracker t;
        rome2_owned_string_allocator alloc;
        rome2_owned_battle_entity *h;
        size_t total;
        size_t n;

        fixture_init(&fx);
        memcpy(before, &fx, sizeof fx);

        /* Measure the allocation plan of a successful build. */
        tracker_init(&t, 0u, misaligns[m]);
        alloc = track_allocator(&t);
        h = NULL;
        REQUIRE(rome2_owned_battle_entity_create(&h, &fx.args, &fx.globals,
            &alloc) == ROME2_OWNED_ENTITY_OK);
        total = t.allocate_calls;
        REQUIRE(total == FULL_ALLOCATIONS);
        REQUIRE(rome2_owned_battle_entity_destroy(&h)
            == ROME2_OWNED_ENTITY_OK);
        REQUIRE(tracker_clean(&t));

        for (n = 1u; n <= total; ++n) {
            tracker_init(&t, n, misaligns[m]);
            alloc = track_allocator(&t);
            h = untouched;
            REQUIRE(rome2_owned_battle_entity_create(&h, &fx.args,
                &fx.globals, &alloc) == ROME2_OWNED_ENTITY_ALLOCATION_FAILED);
            REQUIRE(h == untouched);
            REQUIRE(t.allocate_calls == n);       /* stops at the failure */
            REQUIRE(t.release_calls == n - 1u);   /* each success released */
            REQUIRE(tracker_clean(&t));
            REQUIRE(memcmp(before, &fx, sizeof fx) == 0);
            REQUIRE(fixture_buffers_intact(&fx));
            ++positions;
        }

        /* One past the plan: success again. */
        tracker_init(&t, total + 1u, misaligns[m]);
        alloc = track_allocator(&t);
        h = NULL;
        REQUIRE(rome2_owned_battle_entity_create(&h, &fx.args, &fx.globals,
            &alloc) == ROME2_OWNED_ENTITY_OK);
        if (h != NULL) {
            require_full_fixture_values(rome2_owned_battle_entity_get(h));
        }
        REQUIRE(rome2_owned_battle_entity_destroy(&h)
            == ROME2_OWNED_ENTITY_OK);
        REQUIRE(tracker_clean(&t));
        fixture_free(&fx);
    }
    REQUIRE(positions == 2u * FULL_ALLOCATIONS);
    printf("PASS (%zu failure positions)\n", positions);
}

typedef enum malformed_case {
    CASE_NULL_OUT,
    CASE_NULL_ARGS,
    CASE_NULL_ALLOCATOR,
    CASE_NULL_ALLOCATE,
    CASE_NULL_RELEASE,
    CASE_ARG00_NEGATIVE_LENGTH,
    CASE_ARG11_NEGATIVE_CAPACITY,
    CASE_ARG17_CAPACITY_BELOW_LENGTH,
    CASE_ARG00_NULL_DATA,
    CASE_COUNT_ABOVE_MAX,
    CASE_COUNT_UINT32_MAX,
    CASE_COUNT_HIGH_BIT,
    CASE_ITEMS_NULL,
    CASE_LAST_ITEM_NEGATIVE_LENGTH,
    CASE_LAST_ITEM_NEGATIVE_CAPACITY,
    CASE_LAST_ITEM_CAPACITY_BELOW_LENGTH,
    CASE_LAST_ITEM_NULL_DATA,
    CASE_COUNT
} malformed_case;

static void test_malformed_rejected_before_allocation(void)
{
    static unsigned char marker;
    rome2_owned_battle_entity *const untouched =
        (rome2_owned_battle_entity *)(void *)&marker;
    int c;

    printf("[TEST] malformed input rejected before any allocation... ");
    for (c = 0; c < (int)CASE_COUNT; ++c) {
        fixture fx;
        unsigned char before[sizeof fx];
        tracker t;
        rome2_owned_string_allocator alloc;
        const rome2_owned_string_allocator *alloc_arg = &alloc;
        rome2_owned_battle_entity *h = untouched;
        rome2_owned_battle_entity **out = &h;
        const rome2_entity_ctor_args *args_arg;
        rome2_owned_entity_status expected;
        rome2_owned_entity_status got;

        fixture_init(&fx);
        tracker_init(&t, 0u, 0u);
        alloc = track_allocator(&t);
        args_arg = &fx.args;
        switch ((malformed_case)c) {
        case CASE_NULL_OUT:
            out = NULL;
            expected = ROME2_OWNED_ENTITY_BAD_ARGUMENT;
            break;
        case CASE_NULL_ARGS:
            args_arg = NULL;
            expected = ROME2_OWNED_ENTITY_BAD_ARGUMENT;
            break;
        case CASE_NULL_ALLOCATOR:
            alloc_arg = NULL;
            expected = ROME2_OWNED_ENTITY_INVALID_ALLOCATOR;
            break;
        case CASE_NULL_ALLOCATE:
            alloc.allocate = NULL;
            expected = ROME2_OWNED_ENTITY_INVALID_ALLOCATOR;
            break;
        case CASE_NULL_RELEASE:
            alloc.release = NULL;
            expected = ROME2_OWNED_ENTITY_INVALID_ALLOCATOR;
            break;
        case CASE_ARG00_NEGATIVE_LENGTH:
            fx.arg00.length = -1;
            expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
            break;
        case CASE_ARG11_NEGATIVE_CAPACITY:
            fx.arg11.length = 0;
            fx.arg11.capacity = -1;
            expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
            break;
        case CASE_ARG17_CAPACITY_BELOW_LENGTH:
            fx.arg17.capacity = fx.arg17.length - 1;
            expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
            break;
        case CASE_ARG00_NULL_DATA:
            fx.arg00.data = NULL;
            expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
            break;
        case CASE_COUNT_ABOVE_MAX:
            fx.desc.item_count = ROME2_ENTITY_MAX_ITEM_COUNT + 1u;
            expected = ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE;
            break;
        case CASE_COUNT_UINT32_MAX:
            fx.desc.item_count = UINT32_MAX;
            expected = ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE;
            break;
        case CASE_COUNT_HIGH_BIT:
            fx.desc.item_count = UINT32_C(0x80000000);
            expected = ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE;
            break;
        case CASE_ITEMS_NULL:
            fx.desc.items = NULL;
            expected = ROME2_OWNED_ENTITY_MALFORMED_DESCRIPTOR;
            break;
        case CASE_LAST_ITEM_NEGATIVE_LENGTH:
            fx.items[ITEM_COUNT - 1u].length = -5;
            expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
            break;
        case CASE_LAST_ITEM_NEGATIVE_CAPACITY:
            fx.items[ITEM_COUNT - 1u].length = 0;
            fx.items[ITEM_COUNT - 1u].capacity = INT32_MIN;
            expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
            break;
        case CASE_LAST_ITEM_CAPACITY_BELOW_LENGTH:
            fx.items[ITEM_COUNT - 1u].capacity = 1;
            expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
            break;
        case CASE_LAST_ITEM_NULL_DATA:
            fx.items[ITEM_COUNT - 1u].data = NULL;
            expected = ROME2_OWNED_ENTITY_MALFORMED_STRING;
            break;
        case CASE_COUNT:
        default:
            expected = ROME2_OWNED_ENTITY_OK;
            break;
        }
        memcpy(before, &fx, sizeof fx);
        got = rome2_owned_battle_entity_create(out, args_arg, NULL, alloc_arg);
        if (got != expected) {
            fprintf(stderr, "  case %d: status %d, expected %d\n", c,
                (int)got, (int)expected);
        }
        REQUIRE(got == expected);
        REQUIRE(t.allocate_calls == 0u);
        REQUIRE(t.release_calls == 0u);
        REQUIRE(h == untouched);
        REQUIRE(memcmp(before, &fx, sizeof fx) == 0);
        REQUIRE(fixture_buffers_intact(&fx));
        fixture_free(&fx);
    }
    printf("PASS (%d cases)\n", (int)CASE_COUNT);
}

static void test_any_raw_alignment(void)
{
    size_t misalign;

    printf("[TEST] allocator may return any alignment... ");
    for (misalign = 0u; misalign < 8u; ++misalign) {
        fixture fx;
        tracker t;
        rome2_owned_string_allocator alloc;
        rome2_owned_battle_entity *h = NULL;
        const rome2_battle_entity *e;

        fixture_init(&fx);
        tracker_init(&t, 0u, misalign);
        alloc = track_allocator(&t);
        REQUIRE(rome2_owned_battle_entity_create(&h, &fx.args, &fx.globals,
            &alloc) == ROME2_OWNED_ENTITY_OK);
        e = rome2_owned_battle_entity_get(h);
        REQUIRE(e != NULL);
        if (e != NULL) {
            REQUIRE((uintptr_t)e % _Alignof(rome2_battle_entity) == 0u);
            REQUIRE((uintptr_t)e->items % _Alignof(rome2_recovered_str) == 0u);
            require_full_fixture_values(e);
        }
        REQUIRE(rome2_owned_battle_entity_destroy(&h)
            == ROME2_OWNED_ENTITY_OK);
        REQUIRE(tracker_clean(&t));
        fixture_free(&fx);
    }
    printf("PASS\n");
}

static void test_view_writes_cannot_redirect_release(void)
{
    static const char foreign[] = "foreign";
    fixture fx;
    tracker t;
    rome2_owned_string_allocator alloc;
    rome2_owned_battle_entity *h = NULL;
    rome2_battle_entity *writable;

    printf("[TEST] writes to the published view cannot redirect release... ");
    fixture_init(&fx);
    tracker_init(&t, 0u, 0u);
    alloc = track_allocator(&t);
    REQUIRE(rome2_owned_battle_entity_create(&h, &fx.args, &fx.globals,
        &alloc) == ROME2_OWNED_ENTITY_OK);
    /* Contract violation on purpose.  The record is heap memory, not a const
     * object, so this write is defined behaviour. */
    writable = (rome2_battle_entity *)rome2_owned_battle_entity_get(h);
    REQUIRE(writable != NULL);
    if (writable != NULL) {
        writable->effect_name.data = foreign;
        writable->label_alt.length = 3;
        writable->items[0].data = foreign;
        writable->items[2].length = 1;
        writable->items = NULL;
        writable->item_count = UINT32_MAX;
        writable->item_capacity = 0;
        REQUIRE(rome2_owned_battle_entity_get(h) != NULL);
    }
    REQUIRE(rome2_owned_battle_entity_destroy(&h) == ROME2_OWNED_ENTITY_OK);
    REQUIRE(tracker_clean(&t));
    REQUIRE(t.release_calls == FULL_ALLOCATIONS);
    fixture_free(&fx);
    printf("PASS\n");
}

int main(void)
{
    printf("=== owned_entity (owning adapter over 0x10cbe350 projection) ===\n");
    test_deep_copy_survives_source_release();
    test_empty_inputs_use_native_sentinels();
    test_destroy_null_and_repeated();
    test_captured_allocator_survives_caller_change();
    test_allocation_failure_at_every_position();
    test_malformed_rejected_before_allocation();
    test_any_raw_alignment();
    test_view_writes_cannot_redirect_release();
    if (g_failures != 0) {
        fprintf(stderr, "=== %d owned_entity check(s) FAILED ===\n",
            g_failures);
        return 1;
    }
    printf("=== All owned_entity tests PASSED ===\n");
    return 0;
}
