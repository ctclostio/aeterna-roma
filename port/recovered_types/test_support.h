#ifndef ROME2_TYPES_TEST_SUPPORT_H
#define ROME2_TYPES_TEST_SUPPORT_H

#include "owned_string.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
    exit(1); } } while (0)

typedef struct test_grant {
    unsigned char *actual, *raw;
    size_t bytes, total;
} test_grant;
typedef struct test_heap {
    size_t allocations, releases, observations, live, peak, fail_at;
    unsigned residue;
    uintptr_t last_release;
    size_t last_release_bytes;
    test_grant grants[128];
} test_heap;

static void *test_allocate(void *context, size_t bytes, uint32_t allocation_class)
{
    test_heap *h = context;
    size_t i;
    ++h->allocations;
    CHECK(allocation_class == 0);
    if (h->fail_at == h->allocations) { return NULL; }
    CHECK(bytes < 1024u * 1024u && h->live < 128);
    for (i = 0; i < 128; ++i) {
        test_grant *g = &h->grants[i];
        if (g->actual == NULL) {
            g->total = bytes + 80;
            g->actual = malloc(g->total);
            CHECK(g->actual != NULL);
            memset(g->actual, 0xa5, g->total);
            g->raw = g->actual + 32 + h->residue;
            g->bytes = bytes;
            ++h->live;
            if (h->live > h->peak) { h->peak = h->live; }
            return g->raw;
        }
    }
    CHECK(0);
    return NULL;
}

static void test_release(void *context, void *raw, size_t bytes, uint32_t allocation_class)
{
    test_heap *h = context;
    size_t i, j;
    CHECK(allocation_class == 0);
    for (i = 0; i < 128; ++i) {
        test_grant *g = &h->grants[i];
        if (g->actual != NULL && g->raw == raw) {
            CHECK(bytes == g->bytes && h->live != 0);
            for (j = 0; j < (size_t)(g->raw - g->actual); ++j) { CHECK(g->actual[j] == 0xa5); }
            for (j = (size_t)(g->raw - g->actual) + bytes; j < g->total; ++j) { CHECK(g->actual[j] == 0xa5); }
            h->last_release = (uintptr_t)raw;
            h->last_release_bytes = bytes;
            memset(raw, 0xdd, bytes);
            free(g->actual);
            memset(g, 0, sizeof *g);
            --h->live;
            ++h->releases;
            return;
        }
    }
    CHECK(0);
}

static void test_observer(void *context, uintptr_t identity, size_t bytes)
{
    test_heap *h = context;
    CHECK(h->last_release == identity && h->last_release_bytes == bytes);
    CHECK(h->observations < h->releases);
    ++h->observations;
}

static rome2_owned_string_allocator test_policy(test_heap *h)
{
    rome2_owned_string_allocator p = {test_allocate, test_release, h, test_observer, h};
    return p;
}
#endif
