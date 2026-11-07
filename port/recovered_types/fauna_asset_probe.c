#include "unit_card_resource.h"
#include <stdio.h>
#include <stdlib.h>

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
    rome2_card_resource_diagnostic d;
    const rome2_native_unit_card *v;
    const uint16_t *paths[2];
    uint32_t i, j;
    size_t k;
    rome2_card_resource_status s;
    if (argc < 2 || argc > 3) { return 2; }
    paths[0] = (const uint16_t *)argv[1];
    if (argc == 3) { paths[1] = (const uint16_t *)argv[2]; }
    s = rome2_owned_unit_card_create_from_packs(&card, &args, NULL, paths, (size_t)argc - 1u, &a, &d);
    if (s != ROME2_CARD_RESOURCE_OK) {
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
