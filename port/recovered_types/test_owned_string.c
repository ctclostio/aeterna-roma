/*
 * test_owned_string.c - native tests for the x64 owned-string runtime.
 * No game image, guest memory, or original address is used.
 *
 * Build (from the repository root, inside a vcvars64 environment):
 *   cl /nologo /std:c17 /W4 /WX /sdl /I port\recovered_types
 *      /I port\x64_ported port\recovered_types\owned_string.c
 *      port\recovered_types\test_owned_string.c
 */

#include "owned_string.h"

/* Cross-checks only: both headers are included read-only. */
#include "guest32_layouts.h"
#include "ported_10145c70_unitcard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Layout cross-checks.                                                      */
/* ------------------------------------------------------------------------ */

/* Host narrow descriptor reproduces the existing 16-byte unit-card view. */
_Static_assert(sizeof(rome2_host_string8) == sizeof(rome2_recovered_str),
    "host narrow descriptor matches the unit-card host view size");
_Static_assert(offsetof(rome2_host_string8, length) ==
    offsetof(rome2_recovered_str, length), "length offset matches");
_Static_assert(offsetof(rome2_host_string8, capacity) ==
    offsetof(rome2_recovered_str, capacity), "capacity offset matches");
_Static_assert(offsetof(rome2_host_string8, data) ==
    offsetof(rome2_recovered_str, data), "data offset matches");

/* Guest descriptors stay 12 bytes with a 32-bit identity; host is 16. */
_Static_assert(sizeof(rome2_string8_layout32) == 12, "guest narrow is 12");
_Static_assert(sizeof(rome2_string16_layout32) == 12, "guest UTF-16 is 12");
_Static_assert(sizeof(((rome2_string8_layout32 *)0)->data) == 4,
    "guest data stays an opaque 32-bit identity");
_Static_assert(sizeof(((rome2_host_string8 *)0)->data) == 8,
    "host data is a native x64 pointer");
_Static_assert(offsetof(rome2_string8_layout32, capacity) ==
    offsetof(rome2_host_string8, capacity), "shared capacity offset");
_Static_assert(offsetof(rome2_string16_layout32, data) ==
    offsetof(rome2_host_string16, data), "shared UTF-16 data offset");

/* ------------------------------------------------------------------------ */
/* Minimal check harness.                                                    */
/* ------------------------------------------------------------------------ */

static unsigned g_checks;
static unsigned g_failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_failures;                                                    \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,           \
                __LINE__, #cond);                                            \
        }                                                                    \
    } while (0)

/* ------------------------------------------------------------------------ */
/* Instrumented allocator.                                                   */
/* ------------------------------------------------------------------------ */

#define HEAP_MAX_BLOCKS 64u
#define EVENT_MAX 256u

typedef struct test_event {
    char heap;
    char what;               /* 'a' allocate, 'r' release, 'o' observe */
    uintptr_t identity;
    size_t bytes;
} test_event;

static test_event g_events[EVENT_MAX];
static size_t g_event_count;

static void log_event(char heap, char what, uintptr_t identity, size_t bytes)
{
    if (g_event_count < EVENT_MAX) {
        g_events[g_event_count].heap = heap;
        g_events[g_event_count].what = what;
        g_events[g_event_count].identity = identity;
        g_events[g_event_count].bytes = bytes;
    }
    ++g_event_count;
}

typedef struct test_block {
    unsigned char *base;     /* malloc result */
    void *raw;               /* base + misalignment, handed to the runtime */
    size_t bytes;
    int live;
} test_block;

typedef struct test_heap {
    char tag;
    int rotate_misalign;     /* misalignment = (ordinal - 1) % 4 */
    size_t fixed_misalign;
    size_t fail_on_call;     /* 1-based ordinal to deny; 0 = never */
    int fail_all;
    size_t allocate_calls;
    size_t release_calls;
    size_t observer_calls;
    size_t outstanding;
    size_t protocol_errors;  /* foreign/duplicate release, size/class skew */
    size_t requests[HEAP_MAX_BLOCKS];
    uint32_t classes[HEAP_MAX_BLOCKS];
    test_block blocks[HEAP_MAX_BLOCKS];
    size_t block_count;
    uintptr_t last_released_identity;
    size_t last_released_bytes;
    /* Consume-before-release probe. */
    const rome2_owned_string_owner *probe_owner;
    const rome2_host_string8 *probe_descriptor;
    size_t probe_hits;
    size_t probe_owner_vacant;
    size_t probe_descriptor_empty;
    /* Re-entrancy probe: destroy the same pair again from inside release. */
    rome2_host_string8 *reenter_descriptor;
    rome2_owned_string_owner *reenter_owner;
    int reentered;
    rome2_owned_string_status reenter_status;
} test_heap;

static void heap_init(test_heap *h, char tag)
{
    memset(h, 0, sizeof *h);
    h->tag = tag;
}

static void *heap_allocate(void *context, size_t byte_count,
    uint32_t allocation_class)
{
    test_heap *h = (test_heap *)context;
    const size_t ordinal = ++h->allocate_calls;
    const size_t misalign = h->rotate_misalign
        ? (ordinal - 1u) % 4u : h->fixed_misalign;
    unsigned char *base;
    test_block *block;

    if (ordinal <= HEAP_MAX_BLOCKS) {
        h->requests[ordinal - 1u] = byte_count;
        h->classes[ordinal - 1u] = allocation_class;
    }
    if (h->fail_all || h->fail_on_call == ordinal) {
        log_event(h->tag, 'a', 0u, byte_count);
        return NULL;
    }
    if (h->block_count >= HEAP_MAX_BLOCKS) {
        ++h->protocol_errors;
        return NULL;
    }
    base = (unsigned char *)malloc(misalign + byte_count);
    if (base == NULL) {
        ++h->protocol_errors;
        return NULL;
    }
    block = &h->blocks[h->block_count++];
    block->base = base;
    block->raw = base + misalign;
    block->bytes = byte_count;
    block->live = 1;
    ++h->outstanding;
    log_event(h->tag, 'a', (uintptr_t)block->raw, byte_count);
    return block->raw;
}

static void heap_release(void *context, void *raw_base, size_t byte_count,
    uint32_t allocation_class)
{
    test_heap *h = (test_heap *)context;
    size_t i;

    ++h->release_calls;
    log_event(h->tag, 'r', (uintptr_t)raw_base, byte_count);
    if (allocation_class != ROME2_OWNED_STRING_ALLOCATION_CLASS) {
        ++h->protocol_errors;
    }
    if (h->probe_owner != NULL) {
        ++h->probe_hits;
        if (h->probe_owner->state == ROME2_OWNED_STRING_STATE_VACANT &&
            h->probe_owner->raw_base == NULL &&
            !rome2_owned_string_owner_is_live(h->probe_owner)) {
            ++h->probe_owner_vacant;
        }
        if (h->probe_descriptor != NULL &&
            h->probe_descriptor->length == 0 &&
            h->probe_descriptor->capacity == 0 &&
            h->probe_descriptor->data == rome2_host_string8_empty_sentinel) {
            ++h->probe_descriptor_empty;
        }
    }
    if (h->reenter_owner != NULL && !h->reentered) {
        h->reentered = 1;
        h->reenter_status = rome2_owned_string8_destroy(
            h->reenter_descriptor, h->reenter_owner);
    }
    for (i = 0u; i < h->block_count; ++i) {
        test_block *block = &h->blocks[i];
        if (block->live && block->raw == raw_base) {
            if (block->bytes != byte_count) {
                ++h->protocol_errors;
            }
            free(block->base);
            block->live = 0;
            --h->outstanding;
            h->last_released_identity = (uintptr_t)raw_base;
            h->last_released_bytes = byte_count;
            return;
        }
    }
    /* Foreign pointer (borrowed source, sentinel) or duplicate release. */
    ++h->protocol_errors;
}

static void heap_observe(void *observer_context, uintptr_t identity,
    size_t byte_count)
{
    test_heap *h = (test_heap *)observer_context;
    ++h->observer_calls;
    log_event(h->tag, 'o', identity, byte_count);
    /* The observer must follow the release of the same allocation. */
    if (identity != h->last_released_identity ||
        byte_count != h->last_released_bytes) {
        ++h->protocol_errors;
    }
}

static rome2_owned_string_allocator heap_allocator(test_heap *h,
    int with_observer)
{
    rome2_owned_string_allocator a;
    a.allocate = heap_allocate;
    a.release = heap_release;
    a.context = h;
    a.release_observer = with_observer ? heap_observe : NULL;
    a.observer_context = with_observer ? h : NULL;
    return a;
}

static void *heap_last_raw(const test_heap *h)
{
    return h->block_count == 0u ? NULL : h->blocks[h->block_count - 1u].raw;
}

/* Verify no leaks or protocol errors, then reclaim anything left over. */
static void heap_finish(test_heap *h)
{
    size_t i;
    CHECK(h->outstanding == 0u);
    CHECK(h->protocol_errors == 0u);
    for (i = 0u; i < h->block_count; ++i) {
        if (h->blocks[i].live) {
            free(h->blocks[i].base);
            h->blocks[i].live = 0;
        }
    }
}

static int owner_bytes_are_zero(const rome2_owned_string_owner *o)
{
    static const rome2_owned_string_owner zero = ROME2_OWNED_STRING_OWNER_INIT;
    return memcmp(o, &zero, sizeof zero) == 0;
}

static int is_empty8(const rome2_host_string8 *d)
{
    return d->length == 0 && d->capacity == 0 &&
        d->data == rome2_host_string8_empty_sentinel && d->data[0] == '\0';
}

static int is_empty16(const rome2_host_string16 *d)
{
    return d->length_units == 0 && d->capacity_units == 0 &&
        d->data == rome2_host_string16_empty_sentinel && d->data[0] == 0u;
}

static rome2_string8_view view8(const char *data, ptrdiff_t length)
{
    rome2_string8_view v;
    v.data = data;
    v.length = length;
    return v;
}

static rome2_string16_view view16(const uint16_t *data, ptrdiff_t length)
{
    rome2_string16_view v;
    v.data = data;
    v.length_units = length;
    return v;
}

/* ------------------------------------------------------------------------ */
/* Tests.                                                                    */
/* ------------------------------------------------------------------------ */

static void test_sentinels_and_helpers(void)
{
    rome2_host_string8 e8 = rome2_host_string8_empty();
    rome2_host_string16 e16 = rome2_host_string16_empty();
    rome2_host_string8 d;
    rome2_string8_view v;

    CHECK(rome2_host_string8_empty_sentinel[0] == '\0');
    CHECK(rome2_host_string16_empty_sentinel[0] == 0u);
    CHECK((const void *)rome2_host_string8_empty_sentinel !=
          (const void *)rome2_host_string16_empty_sentinel);
    CHECK(is_empty8(&e8));
    CHECK(is_empty16(&e16));

    d.length = 3;
    d.capacity = 40;
    d.data = "abcdef";
    v = rome2_host_string8_as_view(d);
    CHECK(v.data == d.data && v.length == 3);
    CHECK(!rome2_owned_string_owner_is_live(NULL));
}

static void test_empty_construction(void)
{
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_owned_string_allocator broken;
    rome2_host_string8 d8;
    rome2_host_string16 d16;
    rome2_owned_string_owner o8 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner o16 = ROME2_OWNED_STRING_OWNER_INIT;
    static const uint16_t some_units[2] = { 0x41u, 0x42u };

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 1);

    /* Prior descriptor bytes are unowned scratch; NULL allocator is fine. */
    memset(&d8, 0x5A, sizeof d8);
    CHECK(rome2_owned_string8_copy(&d8, &o8, view8(NULL, 0), NULL) ==
          ROME2_OWNED_STRING_OK);
    CHECK(is_empty8(&d8));
    CHECK(owner_bytes_are_zero(&o8));
    CHECK(!rome2_owned_string_owner_is_live(&o8));

    /* Non-NULL data with length 0 is still empty and reads nothing. */
    CHECK(rome2_owned_string8_copy(&d8, &o8, view8("xyz", 0), &alloc) ==
          ROME2_OWNED_STRING_OK);
    CHECK(is_empty8(&d8));

    memset(&d16, 0x5A, sizeof d16);
    CHECK(rome2_owned_string16_copy(&d16, &o16, view16(some_units, 0),
          &alloc) == ROME2_OWNED_STRING_OK);
    CHECK(is_empty16(&d16));
    CHECK(owner_bytes_are_zero(&o16));

    /* A supplied allocator is validated even when unused. */
    broken = alloc;
    broken.release = NULL;
    CHECK(rome2_owned_string8_copy(&d8, &o8, view8(NULL, 0), &broken) ==
          ROME2_OWNED_STRING_INVALID_ALLOCATOR);

    /* Destroying an empty string never releases the sentinel. */
    CHECK(rome2_owned_string8_destroy(&d8, &o8) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string16_destroy(&d16, &o16) == ROME2_OWNED_STRING_OK);
    CHECK(is_empty8(&d8));
    CHECK(is_empty16(&d16));
    CHECK(h.allocate_calls == 0u);
    CHECK(h.release_calls == 0u);
    CHECK(h.observer_calls == 0u);
    heap_finish(&h);
}

static void test_narrow_formula_alignment_embedded_zero(void)
{
    static const char source[8] = {
        'a', '\0', 'b', '\0', '\xFF', 'z', '\0', 'q'
    };
    static const ptrdiff_t lengths[] = { 1, 2, 3, 4, 5, 7, 8 };
    size_t misalign;
    size_t li;

    for (misalign = 0u; misalign < 4u; ++misalign) {
        for (li = 0u; li < sizeof lengths / sizeof lengths[0]; ++li) {
            const ptrdiff_t n = lengths[li];
            const size_t request = (size_t)n + 9u;
            test_heap h;
            rome2_owned_string_allocator alloc;
            rome2_host_string8 d;
            rome2_owned_string_owner o = ROME2_OWNED_STRING_OWNER_INIT;
            const unsigned char *raw;
            const unsigned char *payload;
            uint32_t cell = 0u;

            heap_init(&h, 'A');
            h.fixed_misalign = misalign;
            alloc = heap_allocator(&h, 1);
            CHECK(rome2_owned_string8_copy(&d, &o, view8(source, n), &alloc)
                  == ROME2_OWNED_STRING_OK);
            CHECK(h.allocate_calls == 1u);
            CHECK(h.requests[0] == request);
            CHECK(h.classes[0] == 0u);

            raw = (const unsigned char *)heap_last_raw(&h);
            payload = (const unsigned char *)d.data;
            CHECK(raw != NULL && ((uintptr_t)raw & 3u) == misalign);
            CHECK(raw != NULL &&
                  (size_t)(payload - raw) == 8u - misalign);
            CHECK(((uintptr_t)payload & 3u) == 0u);
            CHECK((uintptr_t)payload ==
                  (((uintptr_t)raw + 8u) & ~(uintptr_t)3u));
            /* Terminator ends inside the requested extent. */
            CHECK(raw != NULL &&
                  (size_t)(payload - raw) + (size_t)n + 1u <= request);

            /* Host header cell: payload offset, never an address. */
            memcpy(&cell, payload - 4, sizeof cell);
            CHECK(cell == (uint32_t)(8u - misalign));

            CHECK(d.length == (int32_t)n && d.capacity == (int32_t)n);
            CHECK(d.data != source);
            CHECK(memcmp(d.data, source, (size_t)n) == 0);
            CHECK(d.data[n] == '\0');

            CHECK(rome2_owned_string_owner_is_live(&o));
            CHECK(o.raw_base == (const void *)raw);
            CHECK(o.allocation_bytes == request);
            CHECK(o.self == &o);

            CHECK(rome2_owned_string8_destroy(&d, &o) ==
                  ROME2_OWNED_STRING_OK);
            CHECK(h.release_calls == 1u && h.observer_calls == 1u);
            CHECK(h.last_released_identity == (uintptr_t)raw);
            CHECK(h.last_released_bytes == request);
            CHECK(is_empty8(&d));
            CHECK(owner_bytes_are_zero(&o));
            heap_finish(&h);
        }
    }
}

static void test_utf16_opaque_units(void)
{
    /* Lone high, zero, lone low, U+FFFF, paired surrogates, A, BOM. */
    static const uint16_t units[8] = {
        0xD800u, 0x0000u, 0xDC00u, 0xFFFFu, 0xD83Du, 0xDE00u, 0x0041u, 0xFEFFu
    };
    size_t misalign;

    for (misalign = 0u; misalign < 4u; ++misalign) {
        test_heap h;
        rome2_owned_string_allocator alloc;
        rome2_host_string16 d;
        rome2_owned_string_owner o = ROME2_OWNED_STRING_OWNER_INIT;
        const unsigned char *raw;
        const unsigned char *payload;
        uint32_t cell = 0u;

        heap_init(&h, 'A');
        h.fixed_misalign = misalign;
        alloc = heap_allocator(&h, 1);
        CHECK(rome2_owned_string16_copy(&d, &o, view16(units, 8), &alloc) ==
              ROME2_OWNED_STRING_OK);
        CHECK(h.allocate_calls == 1u);
        CHECK(h.requests[0] == 2u * 8u + 10u);
        CHECK(h.classes[0] == 0u);

        raw = (const unsigned char *)heap_last_raw(&h);
        payload = (const unsigned char *)d.data;
        CHECK(raw != NULL && (size_t)(payload - raw) == 8u - misalign);
        CHECK(((uintptr_t)payload & 3u) == 0u);
        memcpy(&cell, payload - 4, sizeof cell);
        CHECK(cell == (uint32_t)(8u - misalign));

        CHECK(d.length_units == 8 && d.capacity_units == 8);
        CHECK(d.data != units);
        CHECK(memcmp(d.data, units, sizeof units) == 0);
        CHECK(d.data[8] == 0u);
        CHECK(raw != NULL &&
              (size_t)(payload - raw) + 2u * 8u + 2u <= 2u * 8u + 10u);

        CHECK(rome2_owned_string16_destroy(&d, &o) == ROME2_OWNED_STRING_OK);
        CHECK(h.release_calls == 1u && h.observer_calls == 1u);
        CHECK(h.last_released_bytes == 26u);
        CHECK(is_empty16(&d));
        heap_finish(&h);
    }
}

static void test_deep_copy_survives_source(void)
{
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_host_string8 d1;
    rome2_host_string8 d2;
    rome2_host_string16 w;
    rome2_owned_string_owner o1 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner o2 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner ow = ROME2_OWNED_STRING_OWNER_INIT;
    static const uint16_t expect16[3] = { 0xD800u, 0x0000u, 0x0062u };
    char *buffer = (char *)malloc(6);
    uint16_t *buffer16 = (uint16_t *)malloc(3u * sizeof(uint16_t));

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 0);
    CHECK(buffer != NULL && buffer16 != NULL);
    if (buffer == NULL || buffer16 == NULL) {
        free(buffer);
        free(buffer16);
        return;
    }
    memcpy(buffer, "hello", 6);
    memcpy(buffer16, expect16, sizeof expect16);

    CHECK(rome2_owned_string8_copy(&d1, &o1, view8(buffer, 5), &alloc) ==
          ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string16_copy(&w, &ow, view16(buffer16, 3), &alloc) ==
          ROME2_OWNED_STRING_OK);

    /* Mutate, then free, the sources; ASan flags any retained alias. */
    buffer[0] = 'J';
    buffer16[0] = 0x0000u;
    free(buffer);
    free(buffer16);
    CHECK(memcmp(d1.data, "hello", 6) == 0);
    CHECK(memcmp(w.data, expect16, sizeof expect16) == 0 && w.data[3] == 0u);

    /* Owned-to-owned deep copy survives destruction of the original. */
    CHECK(rome2_owned_string8_copy(&d2, &o2, rome2_host_string8_as_view(d1),
          &alloc) == ROME2_OWNED_STRING_OK);
    CHECK(d2.data != d1.data);
    CHECK(rome2_owned_string8_destroy(&d1, &o1) == ROME2_OWNED_STRING_OK);
    CHECK(d2.length == 5 && memcmp(d2.data, "hello", 6) == 0);

    CHECK(rome2_owned_string8_destroy(&d2, &o2) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string16_destroy(&w, &ow) == ROME2_OWNED_STRING_OK);
    CHECK(h.allocate_calls == 3u && h.release_calls == 3u);
    heap_finish(&h);
}

static void test_allocation_failure_preserves_destination(void)
{
    static const uint16_t units[3] = { 1u, 2u, 3u };
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_host_string8 d8;
    rome2_host_string16 d16;
    rome2_owned_string_owner o8 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner o16 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_host_string8 before8;
    rome2_host_string16 before16;
    rome2_owned_string_owner before_owner;

    heap_init(&h, 'A');
    h.fail_all = 1;
    alloc = heap_allocator(&h, 1);

    d8.length = 77;
    d8.capacity = 88;
    d8.data = "borrowed";
    before8 = d8;
    before_owner = o8;
    CHECK(rome2_owned_string8_copy(&d8, &o8, view8("payload", 7), &alloc) ==
          ROME2_OWNED_STRING_ALLOCATION_FAILED);
    CHECK(h.allocate_calls == 1u && h.requests[0] == 16u);
    CHECK(memcmp(&d8, &before8, sizeof d8) == 0);
    CHECK(memcmp(&o8, &before_owner, sizeof o8) == 0);

    d16.length_units = 5;
    d16.capacity_units = 6;
    d16.data = units;
    before16 = d16;
    CHECK(rome2_owned_string16_copy(&d16, &o16, view16(units, 3), &alloc) ==
          ROME2_OWNED_STRING_ALLOCATION_FAILED);
    CHECK(h.allocate_calls == 2u && h.requests[1] == 16u);
    CHECK(memcmp(&d16, &before16, sizeof d16) == 0);
    CHECK(owner_bytes_are_zero(&o16));

    CHECK(h.release_calls == 0u && h.observer_calls == 0u);
    heap_finish(&h);
}

static void test_invalid_inputs_rejected_before_allocation(void)
{
    static const char text[4] = { 'a', 'b', 'c', 'd' };
    static const uint16_t units[2] = { 1u, 2u };
    test_heap h;
    test_heap deny;
    rome2_owned_string_allocator alloc;
    rome2_owned_string_allocator denying;
    rome2_owned_string_allocator broken;
    rome2_host_string8 d;
    rome2_host_string8 before;
    rome2_host_string16 d16;
    rome2_owned_string_owner o = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner garbage;
    rome2_owned_string_owner live = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner live16 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner live_before;
    rome2_owned_string_owner overlap_storage[2];
    rome2_host_string8 live_d;
    rome2_host_string8 live_d_before;

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 1);
    d.length = 11;
    d.capacity = 22;
    d.data = "untouched";
    before = d;

    CHECK(rome2_owned_string8_copy(&d, &o, view8(text, -1), &alloc) ==
          ROME2_OWNED_STRING_NEGATIVE_LENGTH);
    CHECK(rome2_owned_string8_copy(&d, &o, view8(text, PTRDIFF_MIN), &alloc)
          == ROME2_OWNED_STRING_NEGATIVE_LENGTH);
    CHECK(rome2_owned_string8_copy(&d, &o,
          view8(text, (ptrdiff_t)INT32_MAX + 1), &alloc) ==
          ROME2_OWNED_STRING_LENGTH_OUT_OF_RANGE);
    CHECK(rome2_owned_string8_copy(&d, &o, view8(text, PTRDIFF_MAX), &alloc)
          == ROME2_OWNED_STRING_LENGTH_OUT_OF_RANGE);
    CHECK(rome2_owned_string8_copy(&d, &o, view8(NULL, 1), &alloc) ==
          ROME2_OWNED_STRING_NULL_DATA);
    CHECK(rome2_owned_string8_copy(&d, &o, view8(NULL, INT32_MAX), &alloc) ==
          ROME2_OWNED_STRING_NULL_DATA);
    CHECK(rome2_owned_string8_copy(NULL, &o, view8(text, 2), &alloc) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);
    CHECK(rome2_owned_string8_copy(&d, NULL, view8(text, 2), &alloc) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);
    CHECK(rome2_owned_string8_copy(&d, &o, view8(text, 2), NULL) ==
          ROME2_OWNED_STRING_INVALID_ALLOCATOR);
    broken = alloc;
    broken.allocate = NULL;
    CHECK(rome2_owned_string8_copy(&d, &o, view8(text, 2), &broken) ==
          ROME2_OWNED_STRING_INVALID_ALLOCATOR);
    broken = alloc;
    broken.release = NULL;
    CHECK(rome2_owned_string8_copy(&d, &o, view8(text, 2), &broken) ==
          ROME2_OWNED_STRING_INVALID_ALLOCATOR);

    /* Descriptor overlapping its owner is rejected before any read. */
    memset(overlap_storage, 0, sizeof overlap_storage);
    CHECK(rome2_owned_string8_copy(
          (rome2_host_string8 *)(void *)&overlap_storage[0],
          &overlap_storage[0], view8(text, 2), &alloc) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);

    /* Uninitialized/garbage or non-canonical owners are rejected. */
    memset(&garbage, 0xA5, sizeof garbage);
    CHECK(rome2_owned_string8_copy(&d, &garbage, view8(text, 2), &alloc) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    memset(&garbage, 0, sizeof garbage);
    garbage.reserved = 1u;
    CHECK(rome2_owned_string8_copy(&d, &garbage, view8(text, 2), &alloc) ==
          ROME2_OWNED_STRING_INVALID_OWNER);

    CHECK(rome2_owned_string16_copy(&d16, &o, view16(units, -5), &alloc) ==
          ROME2_OWNED_STRING_NEGATIVE_LENGTH);
    CHECK(rome2_owned_string16_copy(&d16, &o,
          view16(units, (ptrdiff_t)ROME2_OWNED_STRING16_MAX_UNITS + 1),
          &alloc) == ROME2_OWNED_STRING_LENGTH_OUT_OF_RANGE);
    CHECK(rome2_owned_string16_copy(&d16, &o, view16(NULL, 2), &alloc) ==
          ROME2_OWNED_STRING_NULL_DATA);

    CHECK(h.allocate_calls == 0u);
    CHECK(memcmp(&d, &before, sizeof d) == 0);
    CHECK(owner_bytes_are_zero(&o));

    /* A LIVE destination is never overwritten (that would leak). */
    CHECK(rome2_owned_string8_copy(&live_d, &live, view8("keep", 4), &alloc)
          == ROME2_OWNED_STRING_OK);
    live_d_before = live_d;
    live_before = live;
    CHECK(rome2_owned_string8_copy(&live_d, &live, view8("next", 4), &alloc)
          == ROME2_OWNED_STRING_DESTINATION_OCCUPIED);
    CHECK(memcmp(&live_d, &live_d_before, sizeof live_d) == 0);
    CHECK(memcmp(&live, &live_before, sizeof live) == 0);
    CHECK(memcmp(live_d.data, "keep", 5) == 0);
    /* Cross-kind: a LIVE UTF-16 owner is also occupied for narrow copy. */
    CHECK(rome2_owned_string16_copy(&d16, &live16, view16(units, 2), &alloc)
          == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_copy(&d, &live16, view8(text, 2), &alloc) ==
          ROME2_OWNED_STRING_DESTINATION_OCCUPIED);
    CHECK(h.allocate_calls == 2u);
    CHECK(rome2_owned_string8_destroy(&live_d, &live) ==
          ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string16_destroy(&d16, &live16) ==
          ROME2_OWNED_STRING_OK);
    heap_finish(&h);

    /*
     * Boundary request formulas at the maximum accepted lengths.  The
     * denying allocator fails, so the (deliberately short) source buffer
     * is never read; this probes arithmetic only.
     */
    heap_init(&deny, 'D');
    deny.fail_all = 1;
    denying = heap_allocator(&deny, 1);
    CHECK(rome2_owned_string8_copy(&d, &o,
          view8(text, ROME2_OWNED_STRING8_MAX_LENGTH), &denying) ==
          ROME2_OWNED_STRING_ALLOCATION_FAILED);
    CHECK(deny.requests[0] == (size_t)0x80000008u);
    CHECK(rome2_owned_string16_copy(&d16, &o,
          view16(units, ROME2_OWNED_STRING16_MAX_UNITS), &denying) ==
          ROME2_OWNED_STRING_ALLOCATION_FAILED);
    CHECK(deny.requests[1] == (size_t)0xFFFFFFFEu);
    CHECK(deny.allocate_calls == 2u && deny.release_calls == 0u);
    CHECK(owner_bytes_are_zero(&o));
    heap_finish(&deny);
}

static void test_move(void)
{
    static const uint16_t units[3] = { 0xDBFFu, 0xDFFFu, 0x0000u };
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_host_string8 d1, d2, d3, d4, d5, d6, before_d2, before_d3;
    rome2_owned_string_owner o1 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner o2 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner o3 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner o4 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner o5 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner o6 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner before_o2, before_o3;
    rome2_host_string16 w1, w2;
    rome2_owned_string_owner ow1 = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner ow2 = ROME2_OWNED_STRING_OWNER_INIT;
    const char *payload;
    const uint16_t *payload16;

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 1);

    CHECK(rome2_owned_string8_copy(&d1, &o1, view8("movable", 7), &alloc) ==
          ROME2_OWNED_STRING_OK);
    payload = d1.data;
    memset(&d2, 0x33, sizeof d2);
    CHECK(rome2_owned_string8_move(&d2, &o2, &d1, &o1) ==
          ROME2_OWNED_STRING_OK);
    CHECK(d2.data == payload && d2.length == 7 && d2.capacity == 7);
    CHECK(o2.self == &o2 && rome2_owned_string_owner_is_live(&o2));
    CHECK(is_empty8(&d1) && owner_bytes_are_zero(&o1));
    CHECK(h.allocate_calls == 1u);
    CHECK(rome2_owned_string8_destroy(&d1, &o1) == ROME2_OWNED_STRING_OK);
    CHECK(h.release_calls == 0u);

    /* Self-move validates and changes nothing. */
    before_d2 = d2;
    before_o2 = o2;
    CHECK(rome2_owned_string8_move(&d2, &o2, &d2, &o2) ==
          ROME2_OWNED_STRING_OK);
    CHECK(memcmp(&d2, &before_d2, sizeof d2) == 0);
    CHECK(memcmp(&o2, &before_o2, sizeof o2) == 0);

    /* Occupied destination: both pairs unchanged. */
    CHECK(rome2_owned_string8_copy(&d3, &o3, view8("other", 5), &alloc) ==
          ROME2_OWNED_STRING_OK);
    before_d3 = d3;
    before_o3 = o3;
    CHECK(rome2_owned_string8_move(&d3, &o3, &d2, &o2) ==
          ROME2_OWNED_STRING_DESTINATION_OCCUPIED);
    CHECK(memcmp(&d2, &before_d2, sizeof d2) == 0);
    CHECK(memcmp(&o2, &before_o2, sizeof o2) == 0);
    CHECK(memcmp(&d3, &before_d3, sizeof d3) == 0);
    CHECK(memcmp(&o3, &before_o3, sizeof o3) == 0);

    /* Partial aliasing is rejected. */
    CHECK(rome2_owned_string8_move(&d2, &o4, &d2, &o2) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);
    CHECK(rome2_owned_string8_move(&d4, &o2, &d2, &o2) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);
    CHECK(rome2_owned_string8_move(NULL, &o4, &d2, &o2) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);

    /* A tampered source descriptor is not trusted. */
    d2.length = 3;
    CHECK(rome2_owned_string8_move(&d4, &o4, &d2, &o2) ==
          ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH);
    CHECK(owner_bytes_are_zero(&o4));
    d2.length = 7;

    /* Moving a VACANT empty pair publishes empty into the destination. */
    d5 = rome2_host_string8_empty();
    d6.length = 9;
    d6.capacity = 9;
    d6.data = "scratch";
    CHECK(rome2_owned_string8_move(&d6, &o6, &d5, &o5) ==
          ROME2_OWNED_STRING_OK);
    CHECK(is_empty8(&d6) && owner_bytes_are_zero(&o6));
    /* VACANT owner with a borrowed nonempty descriptor is not a pair. */
    d5.length = 3;
    d5.capacity = 3;
    d5.data = "abc";
    CHECK(rome2_owned_string8_move(&d6, &o6, &d5, &o5) ==
          ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH);

    /* UTF-16 move; a UTF-16 owner is not a narrow source. */
    CHECK(rome2_owned_string16_copy(&w1, &ow1, view16(units, 3), &alloc) ==
          ROME2_OWNED_STRING_OK);
    payload16 = w1.data;
    d5 = rome2_host_string8_empty();
    CHECK(rome2_owned_string8_move(&d4, &o4, &d5, &ow1) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(rome2_owned_string16_move(&w2, &ow2, &w1, &ow1) ==
          ROME2_OWNED_STRING_OK);
    CHECK(w2.data == payload16 && w2.length_units == 3);
    CHECK(is_empty16(&w1) && owner_bytes_are_zero(&ow1));
    CHECK(ow2.self == &ow2);

    CHECK(rome2_owned_string8_destroy(&d2, &o2) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_destroy(&d3, &o3) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string16_destroy(&w1, &ow1) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string16_destroy(&w2, &ow2) == ROME2_OWNED_STRING_OK);
    CHECK(h.allocate_calls == 3u && h.release_calls == 3u);
    CHECK(h.observer_calls == 3u);
    heap_finish(&h);
}

static void test_byte_copy_is_detected(void)
{
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_host_string8 d, dclone, dx;
    rome2_owned_string_owner o = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner clone;
    rome2_owned_string_owner ox = ROME2_OWNED_STRING_OWNER_INIT;

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 1);
    CHECK(rome2_owned_string8_copy(&d, &o, view8("unique", 6), &alloc) ==
          ROME2_OWNED_STRING_OK);

    /* A forbidden raw duplicate at another address carries no authority. */
    memcpy(&clone, &o, sizeof clone);
    dclone = d;
    CHECK(!rome2_owned_string_owner_is_live(&clone));
    CHECK(rome2_owned_string8_destroy(&dclone, &clone) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(rome2_owned_string8_move(&dx, &ox, &dclone, &clone) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(rome2_owned_string8_copy(&dx, &clone, view8("x", 1), &alloc) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(h.release_calls == 0u && h.allocate_calls == 1u);

    CHECK(rome2_owned_string8_destroy(&d, &o) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_destroy(&d, &o) == ROME2_OWNED_STRING_OK);
    CHECK(h.release_calls == 1u);
    heap_finish(&h);
}

static void test_repeated_destroy_and_mismatch(void)
{
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_host_string8 d;
    rome2_host_string16 w;
    rome2_owned_string_owner o = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner before;

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 1);

    CHECK(rome2_owned_string8_copy(&d, &o, view8("twice", 5), &alloc) ==
          ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_destroy(&d, &o) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_destroy(&d, &o) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_destroy(NULL, &o) == ROME2_OWNED_STRING_OK);
    CHECK(h.release_calls == 1u && h.observer_calls == 1u);

    /* Descriptor no longer equal to the publication: no effect at all. */
    CHECK(rome2_owned_string8_copy(&d, &o, view8("tampered", 8), &alloc) ==
          ROME2_OWNED_STRING_OK);
    d.capacity = 99;
    before = o;
    CHECK(rome2_owned_string8_destroy(&d, &o) ==
          ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH);
    CHECK(memcmp(&o, &before, sizeof o) == 0 && d.capacity == 99);
    CHECK(h.release_calls == 1u);
    d.capacity = 8;

    /* Wrong kind, NULL owner, and descriptor/owner overlap. */
    w.length_units = d.length;
    w.capacity_units = d.capacity;
    w.data = rome2_host_string16_empty_sentinel;
    CHECK(rome2_owned_string16_destroy(&w, &o) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(rome2_owned_string16_destroy(NULL, &o) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(rome2_owned_string8_destroy(&d, NULL) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);
    CHECK(rome2_owned_string8_destroy((rome2_host_string8 *)(void *)&o, &o)
          == ROME2_OWNED_STRING_BAD_ARGUMENT);
    CHECK(h.release_calls == 1u);

    CHECK(rome2_owned_string8_destroy(&d, &o) == ROME2_OWNED_STRING_OK);
    CHECK(h.release_calls == 2u);

    /* Owner-only destroy when the descriptor storage is gone. */
    CHECK(rome2_owned_string8_copy(&d, &o, view8("nodesc", 6), &alloc) ==
          ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_destroy(NULL, &o) == ROME2_OWNED_STRING_OK);
    CHECK(owner_bytes_are_zero(&o));
    CHECK(h.release_calls == 3u && h.observer_calls == 3u);
    heap_finish(&h);
}

static void test_captured_allocator(void)
{
    static const uint16_t units[2] = { 0x20ACu, 0x0000u };
    test_heap a;
    test_heap b;
    rome2_owned_string_allocator current;
    rome2_host_string8 d;
    rome2_host_string16 w;
    rome2_owned_string_owner o = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner ow = ROME2_OWNED_STRING_OWNER_INIT;

    heap_init(&a, 'A');
    heap_init(&b, 'B');
    current = heap_allocator(&a, 1);
    CHECK(rome2_owned_string8_copy(&d, &o, view8("captured", 8), &current) ==
          ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string16_copy(&w, &ow, view16(units, 2), &current) ==
          ROME2_OWNED_STRING_OK);

    /* The caller re-points its allocator object at B after construction. */
    current = heap_allocator(&b, 1);
    CHECK(rome2_owned_string8_destroy(&d, &o) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string16_destroy(&w, &ow) == ROME2_OWNED_STRING_OK);
    CHECK(a.release_calls == 2u && a.observer_calls == 2u);
    CHECK(b.release_calls == 0u && b.observer_calls == 0u);
    CHECK(b.allocate_calls == 0u);
    heap_finish(&a);
    heap_finish(&b);
}

static void test_observer_ordering_and_consumption(void)
{
    test_heap h;
    test_heap quiet;
    rome2_owned_string_allocator alloc;
    rome2_owned_string_allocator no_observer;
    rome2_host_string8 d;
    rome2_owned_string_owner o = ROME2_OWNED_STRING_OWNER_INIT;
    uintptr_t raw;

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 1);
    g_event_count = 0u;
    CHECK(rome2_owned_string8_copy(&d, &o, view8("observe", 7), &alloc) ==
          ROME2_OWNED_STRING_OK);
    raw = (uintptr_t)heap_last_raw(&h);

    h.probe_owner = &o;
    h.probe_descriptor = &d;
    h.reenter_owner = &o;
    h.reenter_descriptor = &d;
    CHECK(rome2_owned_string8_destroy(&d, &o) == ROME2_OWNED_STRING_OK);

    CHECK(g_event_count == 3u);
    CHECK(g_events[0].heap == 'A' && g_events[0].what == 'a' &&
          g_events[0].identity == raw && g_events[0].bytes == 16u);
    CHECK(g_events[1].heap == 'A' && g_events[1].what == 'r' &&
          g_events[1].identity == raw && g_events[1].bytes == 16u);
    CHECK(g_events[2].heap == 'A' && g_events[2].what == 'o' &&
          g_events[2].identity == raw && g_events[2].bytes == 16u);
    /* The owner was consumed and the descriptor emptied before release. */
    CHECK(h.probe_hits == 1u && h.probe_owner_vacant == 1u);
    CHECK(h.probe_descriptor_empty == 1u);
    /* A re-entrant destroy from inside release sees VACANT: no second. */
    CHECK(h.reentered == 1 && h.reenter_status == ROME2_OWNED_STRING_OK);
    CHECK(h.release_calls == 1u && h.observer_calls == 1u);
    h.probe_owner = NULL;
    h.probe_descriptor = NULL;
    h.reenter_owner = NULL;
    h.reenter_descriptor = NULL;
    heap_finish(&h);

    /* The observer is optional. */
    heap_init(&quiet, 'Q');
    no_observer = heap_allocator(&quiet, 0);
    g_event_count = 0u;
    CHECK(rome2_owned_string8_copy(&d, &o, view8("q", 1), &no_observer) ==
          ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_destroy(&d, &o) == ROME2_OWNED_STRING_OK);
    CHECK(g_event_count == 2u && g_events[1].what == 'r');
    CHECK(quiet.release_calls == 1u && quiet.observer_calls == 0u);
    heap_finish(&quiet);
}

static void test_vector_success(void)
{
    char alpha[6];
    char zeroed[3];
    char longer[100];
    rome2_host_string8 source[4];
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_owned_string8_vector vec = ROME2_OWNED_STRING8_VECTOR_INIT;
    rome2_owned_string8_vector copy = ROME2_OWNED_STRING8_VECTOR_INIT;
    const size_t storage_request = 4u * (16u + 88u) + 7u;
    uintptr_t storage_raw;
    size_t i;

    memcpy(alpha, "alpha", 6);
    zeroed[0] = 'a';
    zeroed[1] = '\0';
    zeroed[2] = 'b';
    memset(longer, 'x', sizeof longer);
    source[0].length = 5;
    source[0].capacity = 32;              /* capacity is ignored */
    source[0].data = alpha;
    source[1].length = 0;
    source[1].capacity = 0;
    source[1].data = NULL;                /* empty may have NULL data */
    source[2].length = 3;
    source[2].capacity = 3;
    source[2].data = zeroed;
    source[3].length = 100;
    source[3].capacity = 1000;
    source[3].data = longer;

    heap_init(&h, 'A');
    h.rotate_misalign = 1;
    alloc = heap_allocator(&h, 1);
    CHECK(rome2_owned_string8_vector_copy(&vec, source, 4u, &alloc) ==
          ROME2_OWNED_STRING_OK);
    CHECK(vec.items != NULL && vec.owners != NULL);
    if (vec.items == NULL || vec.owners == NULL) {
        return;
    }
    CHECK(h.allocate_calls == 4u);
    CHECK(h.requests[0] == storage_request);
    CHECK(h.requests[1] == 14u && h.requests[2] == 12u &&
          h.requests[3] == 109u);
    storage_raw = (uintptr_t)h.blocks[0].raw;
    CHECK(vec.count == 4u && vec.self == &vec);
    CHECK(((uintptr_t)vec.items & 7u) == 0u);
    CHECK((uintptr_t)vec.items == ((storage_raw + 7u) & ~(uintptr_t)7u));
    CHECK((const unsigned char *)vec.owners ==
          (const unsigned char *)vec.items + 4u * sizeof(rome2_host_string8));

    CHECK(is_empty8(&vec.items[1]) && owner_bytes_are_zero(&vec.owners[1]));
    for (i = 0u; i < 4u; ++i) {
        if (i == 1u) {
            continue;
        }
        CHECK(vec.items[i].length == source[i].length);
        CHECK(vec.items[i].capacity == source[i].length);
        CHECK(vec.items[i].data != source[i].data);
        CHECK(((uintptr_t)vec.items[i].data & 3u) == 0u);
        CHECK(vec.items[i].data[vec.items[i].length] == '\0');
        CHECK(vec.owners[i].self == &vec.owners[i]);
        CHECK(rome2_owned_string_owner_is_live(&vec.owners[i]));
    }

    /* Mutate every source; the copies are independent. */
    alpha[0] = 'A';
    zeroed[2] = 'Z';
    memset(longer, 'y', sizeof longer);
    CHECK(memcmp(vec.items[0].data, "alpha", 6) == 0);
    CHECK(vec.items[2].data[0] == 'a' && vec.items[2].data[1] == '\0' &&
          vec.items[2].data[2] == 'b' && vec.items[2].data[3] == '\0');
    for (i = 0u; i < 100u; ++i) {
        CHECK(vec.items[3].data[i] == 'x');
    }

    CHECK(rome2_owned_string8_vector_copy(&vec, source, 4u, &alloc) ==
          ROME2_OWNED_STRING_DESTINATION_OCCUPIED);

    /* Vector-to-vector deep copy. */
    CHECK(rome2_owned_string8_vector_copy(&copy, vec.items, vec.count,
          &alloc) == ROME2_OWNED_STRING_OK);
    CHECK(copy.items != NULL);
    if (copy.items == NULL) {
        return;
    }
    CHECK(copy.items[0].data != vec.items[0].data);
    CHECK(memcmp(copy.items[3].data, vec.items[3].data, 101) == 0);

    g_event_count = 0u;
    CHECK(rome2_owned_string8_vector_destroy(&vec) == ROME2_OWNED_STRING_OK);
    CHECK(vec.count == 0u && vec.items == NULL && vec.state == 0u);
    /* Elements (release then observe), storage last, no storage observe. */
    CHECK(g_event_count == 7u);
    CHECK(g_events[0].what == 'r' && g_events[1].what == 'o');
    CHECK(g_events[2].what == 'r' && g_events[3].what == 'o');
    CHECK(g_events[4].what == 'r' && g_events[5].what == 'o');
    CHECK(g_events[6].what == 'r' && g_events[6].identity == storage_raw &&
          g_events[6].bytes == storage_request);
    CHECK(rome2_owned_string8_vector_destroy(&vec) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_vector_destroy(&copy) == ROME2_OWNED_STRING_OK);
    CHECK(h.allocate_calls == 8u && h.release_calls == 8u);
    CHECK(h.observer_calls == 6u);
    heap_finish(&h);
}

static void test_vector_partial_failure_rollback(void)
{
    static const size_t fail_points[] = { 1u, 2u, 4u, 6u };
    char storage[5][8];
    rome2_host_string8 source[5];
    rome2_host_string8 source_before[5];
    char storage_before[5][8];
    size_t fi;
    size_t i;

    for (i = 0u; i < 5u; ++i) {
        memset(storage[i], (int)('a' + (int)i), sizeof storage[i]);
        source[i].length = (int32_t)(i + 1u);
        source[i].capacity = 50;
        source[i].data = storage[i];
    }
    memcpy(source_before, source, sizeof source);
    memcpy(storage_before, storage, sizeof storage);

    for (fi = 0u; fi < sizeof fail_points / sizeof fail_points[0]; ++fi) {
        const size_t fail_on = fail_points[fi];
        /* Allocation 1 is storage; allocation k >= 2 is element k - 2. */
        const size_t built_elements = fail_on >= 2u ? fail_on - 2u : 0u;
        test_heap h;
        rome2_owned_string_allocator alloc;
        rome2_owned_string8_vector vec = ROME2_OWNED_STRING8_VECTOR_INIT;
        rome2_owned_string8_vector vec_before;

        heap_init(&h, 'A');
        h.rotate_misalign = 1;
        h.fail_on_call = fail_on;
        alloc = heap_allocator(&h, 1);
        vec_before = vec;
        CHECK(rome2_owned_string8_vector_copy(&vec, source, 5u, &alloc) ==
              ROME2_OWNED_STRING_ALLOCATION_FAILED);
        CHECK(h.allocate_calls == fail_on);
        CHECK(h.release_calls ==
              built_elements + (fail_on >= 2u ? 1u : 0u));
        CHECK(h.observer_calls == built_elements);
        CHECK(memcmp(&vec, &vec_before, sizeof vec) == 0);
        CHECK(memcmp(source, source_before, sizeof source) == 0);
        CHECK(memcmp(storage, storage_before, sizeof storage) == 0);
        heap_finish(&h);
    }
}

static void test_vector_invalid_inputs(void)
{
    rome2_host_string8 source[3];
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_owned_string8_vector vec = ROME2_OWNED_STRING8_VECTOR_INIT;
    rome2_owned_string8_vector garbage;

    source[0].length = 2;
    source[0].capacity = 2;
    source[0].data = "ok";
    source[1].length = 2;
    source[1].capacity = 2;
    source[1].data = "ok";
    source[2].length = -1;
    source[2].capacity = 0;
    source[2].data = "bad";

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 1);

    /* Counts that cannot be represented never reach the source array. */
    CHECK(rome2_owned_string8_vector_copy(&vec, source, SIZE_MAX, &alloc) ==
          ROME2_OWNED_STRING_COUNT_OUT_OF_RANGE);
    CHECK(rome2_owned_string8_vector_copy(&vec, source,
          ROME2_OWNED_STRING8_VECTOR_MAX_COUNT + 1u, &alloc) ==
          ROME2_OWNED_STRING_COUNT_OUT_OF_RANGE);
    CHECK(rome2_owned_string8_vector_copy(&vec, source,
          SIZE_MAX / (16u + 88u), &alloc) ==
          ROME2_OWNED_STRING_COUNT_OUT_OF_RANGE);
    CHECK(rome2_owned_string8_vector_copy(&vec, NULL, 2u, &alloc) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);
    CHECK(rome2_owned_string8_vector_copy(&vec, source, 2u, NULL) ==
          ROME2_OWNED_STRING_INVALID_ALLOCATOR);
    CHECK(rome2_owned_string8_vector_copy(NULL, source, 2u, &alloc) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);
    /* A bad element anywhere is rejected before the first allocation. */
    CHECK(rome2_owned_string8_vector_copy(&vec, source, 3u, &alloc) ==
          ROME2_OWNED_STRING_NEGATIVE_LENGTH);
    source[2].length = 4;
    source[2].data = NULL;
    CHECK(rome2_owned_string8_vector_copy(&vec, source, 3u, &alloc) ==
          ROME2_OWNED_STRING_NULL_DATA);
    memset(&garbage, 0xA5, sizeof garbage);
    CHECK(rome2_owned_string8_vector_copy(&garbage, source, 2u, &alloc) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(rome2_owned_string8_vector_destroy(&garbage) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(h.allocate_calls == 0u);

    /* count 0 is an empty vector: no allocation, still VACANT. */
    CHECK(rome2_owned_string8_vector_copy(&vec, NULL, 0u, NULL) ==
          ROME2_OWNED_STRING_OK);
    CHECK(vec.count == 0u && vec.items == NULL && vec.state == 0u);
    CHECK(rome2_owned_string8_vector_destroy(&vec) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_vector_destroy(NULL) ==
          ROME2_OWNED_STRING_BAD_ARGUMENT);
    CHECK(h.allocate_calls == 0u && h.release_calls == 0u);
    heap_finish(&h);
}

static void test_vector_mixed_allocators_and_element_moves(void)
{
    rome2_host_string8 source[3];
    test_heap a;
    test_heap b;
    rome2_owned_string_allocator current;
    rome2_owned_string8_vector vec = ROME2_OWNED_STRING8_VECTOR_INIT;
    rome2_host_string8 bd, xd;
    rome2_owned_string_owner bo = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_owned_string_owner xo = ROME2_OWNED_STRING_OWNER_INIT;
    const char *moved_in_payload;

    source[0].length = 3;
    source[0].capacity = 3;
    source[0].data = "one";
    source[1] = rome2_host_string8_empty();
    source[2].length = 5;
    source[2].capacity = 5;
    source[2].data = "three";

    heap_init(&a, 'A');
    heap_init(&b, 'B');
    current = heap_allocator(&a, 1);
    CHECK(rome2_owned_string8_vector_copy(&vec, source, 3u, &current) ==
          ROME2_OWNED_STRING_OK);
    CHECK(a.allocate_calls == 3u);
    CHECK(vec.items != NULL && vec.owners != NULL);
    if (vec.items == NULL || vec.owners == NULL) {
        return;
    }

    /* Re-point the caller's allocator object; the vector captured A. */
    current = heap_allocator(&b, 1);
    CHECK(rome2_owned_string8_copy(&bd, &bo, view8("from-B", 6), &current) ==
          ROME2_OWNED_STRING_OK);
    moved_in_payload = bd.data;

    /* Move a B-owned string into the VACANT slot 1. */
    CHECK(rome2_owned_string8_move(&vec.items[1], &vec.owners[1], &bd, &bo)
          == ROME2_OWNED_STRING_OK);
    CHECK(vec.items[1].data == moved_in_payload);
    CHECK(vec.owners[1].self == &vec.owners[1]);
    /* Slot 1 is now occupied. */
    CHECK(rome2_owned_string8_move(&vec.items[1], &vec.owners[1], &bd, &bo)
          == ROME2_OWNED_STRING_DESTINATION_OCCUPIED);

    /* Move the A-owned element 0 out of the vector. */
    CHECK(rome2_owned_string8_move(&xd, &xo, &vec.items[0], &vec.owners[0])
          == ROME2_OWNED_STRING_OK);
    CHECK(is_empty8(&vec.items[0]) && owner_bytes_are_zero(&vec.owners[0]));
    CHECK(memcmp(xd.data, "one", 4) == 0);

    CHECK(rome2_owned_string8_vector_destroy(&vec) == ROME2_OWNED_STRING_OK);
    /* A: element 2 + storage; B: the moved-in element. */
    CHECK(a.release_calls == 2u && a.observer_calls == 1u);
    CHECK(b.release_calls == 1u && b.observer_calls == 1u);
    CHECK(b.outstanding == 0u);

    CHECK(rome2_owned_string8_destroy(&xd, &xo) == ROME2_OWNED_STRING_OK);
    CHECK(a.release_calls == 3u && a.observer_calls == 2u);
    heap_finish(&a);
    heap_finish(&b);
}

static void test_vector_move_and_copy_detection(void)
{
    rome2_host_string8 source[2];
    test_heap h;
    rome2_owned_string_allocator alloc;
    rome2_owned_string8_vector v1 = ROME2_OWNED_STRING8_VECTOR_INIT;
    rome2_owned_string8_vector v2 = ROME2_OWNED_STRING8_VECTOR_INIT;
    rome2_owned_string8_vector v3 = ROME2_OWNED_STRING8_VECTOR_INIT;
    rome2_owned_string8_vector clone;
    rome2_owned_string8_vector before;
    rome2_host_string8 *items;

    source[0].length = 1;
    source[0].capacity = 1;
    source[0].data = "a";
    source[1].length = 2;
    source[1].capacity = 2;
    source[1].data = "bb";

    heap_init(&h, 'A');
    alloc = heap_allocator(&h, 1);
    CHECK(rome2_owned_string8_vector_copy(&v1, source, 2u, &alloc) ==
          ROME2_OWNED_STRING_OK);
    CHECK(v1.items != NULL);
    if (v1.items == NULL) {
        return;
    }
    items = v1.items;
    CHECK(rome2_owned_string8_vector_move(&v2, &v1) == ROME2_OWNED_STRING_OK);
    CHECK(v2.items == items && v2.self == &v2 && v2.count == 2u);
    CHECK(v1.items == NULL && v1.count == 0u && v1.state == 0u);
    CHECK(rome2_owned_string8_vector_destroy(&v1) == ROME2_OWNED_STRING_OK);
    CHECK(h.release_calls == 0u);

    before = v2;
    CHECK(rome2_owned_string8_vector_move(&v2, &v2) == ROME2_OWNED_STRING_OK);
    CHECK(memcmp(&v2, &before, sizeof v2) == 0);

    CHECK(rome2_owned_string8_vector_copy(&v3, source, 1u, &alloc) ==
          ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_vector_move(&v3, &v2) ==
          ROME2_OWNED_STRING_DESTINATION_OCCUPIED);
    CHECK(memcmp(&v2, &before, sizeof v2) == 0);

    /* A raw byte copy of the record cannot release. */
    memcpy(&clone, &v2, sizeof clone);
    CHECK(rome2_owned_string8_vector_destroy(&clone) ==
          ROME2_OWNED_STRING_INVALID_OWNER);
    CHECK(h.release_calls == 0u);

    /* A tampered element blocks the whole destroy before any release. */
    v2.items[1].length = 1;
    CHECK(rome2_owned_string8_vector_destroy(&v2) ==
          ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH);
    CHECK(h.release_calls == 0u && memcmp(&v2, &before, sizeof v2) == 0);
    v2.items[1].length = 2;

    CHECK(rome2_owned_string8_vector_destroy(&v2) == ROME2_OWNED_STRING_OK);
    CHECK(rome2_owned_string8_vector_destroy(&v3) == ROME2_OWNED_STRING_OK);
    CHECK(h.allocate_calls == 5u && h.release_calls == 5u);
    heap_finish(&h);
}

int main(void)
{
    test_sentinels_and_helpers();
    test_empty_construction();
    test_narrow_formula_alignment_embedded_zero();
    test_utf16_opaque_units();
    test_deep_copy_survives_source();
    test_allocation_failure_preserves_destination();
    test_invalid_inputs_rejected_before_allocation();
    test_move();
    test_byte_copy_is_detected();
    test_repeated_destroy_and_mismatch();
    test_captured_allocator();
    test_observer_ordering_and_consumption();
    test_vector_success();
    test_vector_partial_failure_rollback();
    test_vector_invalid_inputs();
    test_vector_mixed_allocators_and_element_moves();
    test_vector_move_and_copy_detection();

    printf("owned_string tests: %u checks, %u failures\n", g_checks,
        g_failures);
    return g_failures == 0u ? 0 : 1;
}
