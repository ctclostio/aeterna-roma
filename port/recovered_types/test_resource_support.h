#ifndef ROME2_TEST_RESOURCE_SUPPORT_H
#define ROME2_TEST_RESOURCE_SUPPORT_H

#include "owned_string.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

typedef struct resource_grant {
    struct resource_grant *next;
    unsigned char *actual, *raw;
    size_t bytes, total;
} resource_grant;
typedef struct resource_heap {
    resource_grant *grants;
    size_t allocations, releases, live, fail_at, observations;
    uintptr_t last_release;
    size_t last_bytes;
    unsigned residue;
} resource_heap;

static void *resource_allocate(void *context, size_t bytes, uint32_t kind)
{
    resource_heap *h = context;
    resource_grant *g;
    ++h->allocations;
    CHECK(kind == 0 && bytes <= 64u * 1024u * 1024u + 64u);
    if (h->allocations == h->fail_at) { return NULL; }
    g = malloc(sizeof *g); CHECK(g != NULL);
    g->total = bytes + 80u; g->actual = malloc(g->total); CHECK(g->actual != NULL);
    memset(g->actual, 0xa5, g->total);
    g->raw = g->actual + 32u + h->residue; g->bytes = bytes;
    g->next = h->grants; h->grants = g; ++h->live;
    return g->raw;
}

static void resource_release(void *context, void *raw, size_t bytes, uint32_t kind)
{
    resource_heap *h = context;
    resource_grant **link = &h->grants, *g;
    size_t i;
    CHECK(kind == 0 && raw != NULL);
    while (*link != NULL && (*link)->raw != raw) { link = &(*link)->next; }
    CHECK(*link != NULL && h->live != 0);
    g = *link; CHECK(g->bytes == bytes);
    for (i = 0; i < (size_t)(g->raw - g->actual); ++i) { CHECK(g->actual[i] == 0xa5); }
    for (i = (size_t)(g->raw - g->actual) + bytes; i < g->total; ++i) { CHECK(g->actual[i] == 0xa5); }
    h->last_release = (uintptr_t)raw; h->last_bytes = bytes;
    *link = g->next; --h->live; ++h->releases;
    memset(raw, 0xdd, bytes); free(g->actual); free(g);
}

static void resource_observer(void *context, uintptr_t raw, size_t bytes)
{
    resource_heap *h = context;
    CHECK(h->last_release == raw && h->last_bytes == bytes && h->observations < h->releases);
    ++h->observations;
}

static rome2_owned_string_allocator resource_policy(resource_heap *h)
{
    rome2_owned_string_allocator a = {resource_allocate, resource_release, h, resource_observer, h};
    return a;
}

#endif
