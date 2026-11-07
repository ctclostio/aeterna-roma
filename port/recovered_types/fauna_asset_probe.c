#include "unit_card_resource.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static size_t live;
static void *allocate(void *context, size_t size, uint32_t kind)
{
    void *raw;
    (void)context;
    if (kind != 0) { return NULL; }
    raw = malloc(size);
    if (raw != NULL) { ++live; }
    return raw;
}
static void release(void *context, void *raw, size_t size, uint32_t kind)
{
    (void)context; (void)size;
    if (kind != 0 || raw == NULL || live == 0) { abort(); }
    --live; free(raw);
}

int wmain(int argc, wchar_t **argv)
{
    rome2_owned_string_allocator a = {allocate, release, NULL, NULL, NULL};
    rome2_owned_unit_card *card = NULL;
    rome2_unit_card_args args = {0};
    rome2_card_resource_diagnostic d = {0};
    const rome2_native_unit_card *v;
    const uint16_t *paths[2];
    uint32_t i, j;
    size_t k;
    int first = 1;
    size_t path_count;
    const bool setup = argc > 1 && wcscmp(argv[1], L"--setup") == 0;
    rome2_card_resource_status s;
    if (setup) { first = 2; }
    if (argc <= first || argc > first + 2) { return 2; }
    path_count = (size_t)(argc - first);
    for (k = 0; k < path_count; ++k) { paths[k] = (const uint16_t *)argv[first + (int)k]; }
    if (setup) {
        const rome2_fauna_record seed = {.words_000 = {0, 0xdead}};
        const rome2_fauna_vector_view initial = {1, 1, &seed};
        d.selected_archive = SIZE_MAX;
        d.card = rome2_owned_unit_card_create_from_config(&card, &args, NULL, &initial, &a);
        s = d.card == ROME2_UNIT_CARD_OK ?
            rome2_owned_unit_card_setup_from_packs(card, paths, path_count, &a, &d) : ROME2_CARD_RESOURCE_CARD_ERROR;
    } else {
        s = rome2_owned_unit_card_create_from_packs(&card, &args, NULL, paths, path_count, &a, &d);
    }
    if (s != ROME2_CARD_RESOURCE_OK) {
        (void)rome2_owned_unit_card_destroy(&card);
        fprintf(stderr, "resource failure status%d pack%d config%d xml%d card%d; live%zu\n",
            s, d.pack, d.config, d.xml, d.card, live);
        return 1;
    }
    v = rome2_owned_unit_card_get(card);
    if (v == NULL) { (void)rome2_owned_unit_card_destroy(&card); return 1; }
    printf("{\"selected_archive\":%zu,\"records\":[", d.selected_archive);
    for (i = 0; i < v->fauna.count; ++i) {
        const rome2_fauna_record *r = &v->fauna.items[i];
        printf("%s{\"words\":[", i == 0 ? "" : ",");
        for (k = 0; k < 8; ++k) { printf("%s%u", k == 0 ? "" : ",", r->words_000[k]); }
        printf("],\"climates_hex\":[");
        for (j = 0; j < r->strings.count; ++j) {
            const rome2_host_string8 *str = &r->strings.items[j];
            printf("%s\"", j == 0 ? "" : ",");
            for (k = 0; k < (size_t)str->length; ++k) { printf("%02x", (unsigned char)str->data[k]); }
            printf("\"");
        }
        printf("]}");
    }
    printf("]}\n");
    if (rome2_owned_unit_card_destroy(&card) != ROME2_UNIT_CARD_OK || live != 0) {
        fprintf(stderr, "asset probe cleanup failure; live%zu\n", live); return 1;
    }
    return 0;
}
