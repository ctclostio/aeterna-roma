/*
 * test_battle_entity_10cbe350.c - Phase 4.2 regression tests for the battle
 * entity dispatcher record reconstructed from empire.retail.dll 0x10cbe350.
 *
 * Every assertion below is tied to a recovered address in the retail body.
 */

#include "ported_10cbe350_entity.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * assert() is elided under the release /DNDEBUG profile, which would silently
 * drop every recovered-value check.  REQUIRE always evaluates its condition,
 * prints the failing expression with file and line, and records the failure so
 * the harness exits non-zero.
 */
static int g_failures;

#define REQUIRE(cond)                                                      \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

static size_t g_alloc_calls;
static size_t g_alloc_bytes;
static size_t g_free_calls;

static void *test_alloc(size_t bytes)
{
    ++g_alloc_calls;
    g_alloc_bytes = bytes;
    return calloc(1, bytes != 0 ? bytes : 1u);
}

static void test_free(void *items)
{
    ++g_free_calls;
    free(items);
}

static void test_dispatch_triple_and_identity(void)
{
    printf("[TEST] test_dispatch_triple_and_identity... ");

    rome2_battle_entity entity;
    rome2_entity_ctor_args args;
    rome2_entity_globals globals;
    rome2_entity_host host;

    memset(&args, 0, sizeof(args));
    rome2_entity_globals_from_image(&globals);
    host.alloc_items = test_alloc;
    host.free_items = test_free;
    g_alloc_calls = 0;
    g_alloc_bytes = 0;

    /* 0x10cbe36a installs the base triple, 0x10cbe39a overwrites it with the
     * derived triple, and 0x10cbe382 leaves slot +0x0c at zero. */
    REQUIRE(ROME2_ENTITY_BASE_DISPATCH0 == 0x1174bbb0u);
    REQUIRE(ROME2_ENTITY_DISPATCH0 == 0x1174e12cu);
    REQUIRE(ROME2_ENTITY_DISPATCH1 == 0x1174e150u);
    REQUIRE(ROME2_ENTITY_DISPATCH2 == 0x1174e178u);

    REQUIRE(rome2_battle_entity_ctor(&entity, &args, &globals, &host) == &entity);

    REQUIRE(entity.dispatch.slot0 == ROME2_ENTITY_DISPATCH0);
    REQUIRE(entity.dispatch.slot1 == ROME2_ENTITY_DISPATCH1);
    REQUIRE(entity.dispatch.slot2 == ROME2_ENTITY_DISPATCH2);
    REQUIRE(entity.dispatch.slot3 == ROME2_ENTITY_DISPATCH3);
    REQUIRE(entity.dispatch.slot3 == 0u);

    /* 0x10cbe35c / 0x10cbe389: the name from 0x1174e298 lands at +0x010. */
    REQUIRE(entity.effect_name.length == (int32_t)strlen(ROME2_ENTITY_NAME));
    REQUIRE(strncmp(entity.effect_name.data, "auto_generator_input",
                   (size_t)entity.effect_name.length) == 0);

    /* 0x10cbe3ae / 0x10cbe3c5 / 0x10cbe3e7: the three neighbouring strings are
     * left at the FUN_100f1850 sentinel {0, 0, 0x11af408e}. */
    REQUIRE(entity.category.length == 0);
    REQUIRE((uint32_t)(uintptr_t)entity.category.data
           == ROME2_UNITCARD_EMPTY_SENTINEL_A);
    REQUIRE(entity.label.length == 0);
    REQUIRE((uint32_t)(uintptr_t)entity.label.data
           == ROME2_UNITCARD_EMPTY_SENTINEL_A);
    REQUIRE(entity.descriptor_text.length == 0);
    REQUIRE((uint32_t)(uintptr_t)entity.descriptor_text.data
           == ROME2_UNITCARD_EMPTY_SENTINEL_A);

    printf("PASS\n");
}

static void test_embedded_literals_and_anchors(void)
{
    printf("[TEST] test_embedded_literals_and_anchors... ");

    rome2_battle_entity entity;
    rome2_entity_ctor_args args;
    rome2_entity_globals globals;
    rome2_entity_host host;

    memset(&args, 0, sizeof(args));
    rome2_entity_globals_from_image(&globals);
    host.alloc_items = test_alloc;
    host.free_items = test_free;

    REQUIRE(rome2_battle_entity_ctor(&entity, &args, &globals, &host) == &entity);

    /* 0x10cbe40f / 0x10cbe416: literal 0x45000000 into +0x54 and +0x58. */
    REQUIRE(entity.activation_radius_min == 2048.0f);
    REQUIRE(entity.activation_radius_max == 2048.0f);

    /* 0x10cbe422: literal 3 into +0x5c. */
    REQUIRE(entity.point_count == 3u);

    /* 0x10cbe429: literal zero into +0x68. */
    REQUIRE(entity.field_068 == 0u);

    /* 0x10cbe3d5 / 0x10cbe3e2: DAT_11f958ec / DAT_11f958f0 into +0x3c/+0x40. */
    REQUIRE(entity.grid_extent_min == globals.grid_extent_min);
    REQUIRE(entity.grid_extent_max == globals.grid_extent_max);
    REQUIRE(entity.grid_extent_min == 0.0f);

    /* 0x10cbe438 / 0x10cbe43b: the nested "Climate Conditions" record at +0x70. */
    REQUIRE(entity.climate.dispatch0 == ROME2_CLIMATE_DISPATCH0);
    REQUIRE(entity.climate.dispatch1 == ROME2_CLIMATE_DISPATCH1);
    REQUIRE(entity.climate.dispatch2 == 0u);
    REQUIRE(strncmp(entity.climate.name.data, "Climate Conditions",
                   (size_t)entity.climate.name.length) == 0);
    REQUIRE(entity.climate.name.length == 18);

    printf("PASS\n");
}

static void test_descriptor_projection_and_item_vector(void)
{
    printf("[TEST] test_descriptor_projection_and_item_vector... ");

    rome2_battle_entity entity;
    rome2_entity_ctor_args args;
    rome2_entity_globals globals;
    rome2_entity_host host;
    rome2_entity_descriptor desc;
    rome2_entity_origin origin = { 0x1234u, 0x5678u };
    rome2_recovered_str source_items[3];
    uint32_t tag_pair[2];

    memset(&args, 0, sizeof(args));
    memset(source_items, 0, sizeof(source_items));
    memset(tag_pair, 0, sizeof(tag_pair));
    rome2_entity_globals_from_image(&globals);
    host.alloc_items = test_alloc;
    host.free_items = test_free;

    rome2_entity_str_assign_literal(&source_items[0], "legionary");
    rome2_entity_str_assign_literal(&source_items[1], "hastati");
    rome2_entity_str_assign_literal(&source_items[2], "equites");

    desc.reserved_00 = 0xabcdef01u;      /* not consumed as origin or count */
    desc.item_count = 3u;
    desc.items = source_items;

    tag_pair[0] = 0xaabbccddu;
    tag_pair[1] = 0x01020304u;

    args.arg09 = &origin;
    args.arg10 = &desc;
    args.arg01 = tag_pair;

    g_alloc_calls = 0;
    g_alloc_bytes = 0;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, &globals, &host) == &entity);

    /* 0x10cbe3b9 / 0x10cbe3c2: the descriptor head is copied into +0x28/+0x2c. */
    REQUIRE(entity.origin_x == 0x1234u);
    REQUIRE(entity.origin_y == 0x5678u);

    /* 0x10cbe489 / 0x10cbe492: the count is mirrored into +0xb4 and +0xb8. */
    REQUIRE(entity.item_count == 3u);
    REQUIRE(entity.item_alloc_count == 3u);

    /* 0x10cbe4a4 / 0x10cbe4a7: LEA + SHL give count * stride bytes.  The x86
     * stride is 12; the host block scales with sizeof(rome2_recovered_str). */
    REQUIRE(g_alloc_calls == 1u);
    REQUIRE(g_alloc_bytes == 3u * sizeof(rome2_recovered_str));
    REQUIRE(ROME2_ENTITY_ITEM_STRIDE == sizeof(rome2_recovered_str));
    REQUIRE(sizeof(rome2_recovered_str) == 16u);

    /* 0x10cbe4d2 .. 0x10cbe4f4: exactly `count` 12-byte string copies. */
    REQUIRE(entity.items != NULL);
    REQUIRE(strncmp(entity.items[0].data, "legionary",
                   (size_t)entity.items[0].length) == 0);
    REQUIRE(strncmp(entity.items[1].data, "hastati",
                   (size_t)entity.items[1].length) == 0);
    REQUIRE(strncmp(entity.items[2].data, "equites",
                   (size_t)entity.items[2].length) == 0);

    /* 0x10cbe459 .. 0x10cbe46c: the eight-byte pair lands at +0xac/+0xb0. */
    REQUIRE(entity.tag_lo == 0xaabbccddu);
    REQUIRE(entity.tag_hi == 0x01020304u);

    REQUIRE(rome2_battle_entity_release_items(&entity, &host));
    REQUIRE(entity.items == NULL);
    printf("PASS\n");
}

static void test_zero_count_skips_allocation(void)
{
    printf("[TEST] test_zero_count_skips_allocation... ");

    rome2_battle_entity entity;
    rome2_entity_ctor_args args;
    rome2_entity_globals globals;
    rome2_entity_host host;
    rome2_entity_descriptor desc;

    memset(&args, 0, sizeof(args));
    rome2_entity_globals_from_image(&globals);
    host.alloc_items = test_alloc;
    host.free_items = test_free;

    /* 0x10cbe49a: JZ skips FUN_100fcc80 entirely when the count is zero. */
    desc.reserved_00 = 7u;
    desc.item_count = 0u;
    desc.items = NULL;
    args.arg10 = &desc;

    g_alloc_calls = 0;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, &globals, &host) == &entity);
    REQUIRE(g_alloc_calls == 0u);
    REQUIRE(entity.items == NULL);
    REQUIRE(entity.item_count == 0u);
    REQUIRE(entity.item_alloc_count == 0u);

    /* A NULL descriptor leaves the same three fields zeroed. */
    args.arg10 = NULL;
    g_alloc_calls = 0;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, &globals, &host) == &entity);
    REQUIRE(g_alloc_calls == 0u);
    REQUIRE(entity.origin_x == 0u);
    REQUIRE(entity.origin_y == 0u);

    printf("PASS\n");
}

static void test_scalar_projection(void)
{
    printf("[TEST] test_scalar_projection... ");

    rome2_battle_entity entity;
    rome2_entity_ctor_args args;
    rome2_entity_globals globals;
    rome2_entity_host host;
    rome2_recovered_str label_a;
    rome2_recovered_str label_b;
    rome2_recovered_str label_c;
    uint32_t tag_pair[2] = { 11u, 22u };

    rome2_entity_str_assign_literal(&label_a, "roman_legion");
    rome2_entity_str_assign_literal(&label_b, "auto_deploy");
    rome2_entity_str_assign_literal(&label_c, "hellenic_general");

    memset(&args, 0, sizeof(args));
    rome2_entity_globals_from_image(&globals);
    host.alloc_items = test_alloc;
    host.free_items = test_free;

    args.arg00 = &label_a;          /* -> +0x0a0 */
    args.arg01 = tag_pair;          /* -> +0x0ac / +0x0b0 */
    args.arg02 = 0x1111u;           /* -> climate.grid_a */
    args.arg03 = 0x2222u;           /* -> climate.grid_b */
    args.arg04 = 0x3333u;           /* -> climate.grid_c */
    args.arg05 = 0x4444u;           /* -> +0x060 */
    args.arg06 = 1;                /* incoming by-value string is not owned */
    args.arg07 = 99;
    args.arg08 = "x";
    args.arg11 = &label_b;          /* -> +0x0d0 */
    args.arg12 = 0x123400b6u;       /* -> +0x064 low byte only */
    args.arg13 = 0x567800a5u;       /* -> +0x0dc low byte */
    args.arg14 = 0x0badf00du;       /* -> +0x06c */
    args.arg15 = 0x13579bdfu;       /* -> +0x0e0 full dword */
    args.arg16 = 0xabcd00c7u;       /* -> +0x0e4 low byte */
    args.arg17 = &label_c;          /* -> +0x0c0 */
    args.arg18 = 0xefab00e8u;       /* -> +0x0cc low byte */

    REQUIRE(rome2_battle_entity_ctor(&entity, &args, &globals, &host) == &entity);

    REQUIRE(strncmp(entity.label_alt.data, "roman_legion",
                   (size_t)entity.label_alt.length) == 0);
    REQUIRE(strncmp(entity.source_name.data, "auto_deploy",
                   (size_t)entity.source_name.length) == 0);
    REQUIRE(strncmp(entity.effect_kind.data, "hellenic_general",
                   (size_t)entity.effect_kind.length) == 0);

    REQUIRE(entity.climate.grid_a == 0x1111u);
    REQUIRE(entity.climate.grid_b == 0x2222u);
    REQUIRE(entity.climate.grid_c == 0x3333u);

    REQUIRE(entity.owner_id == 0x4444u);
    REQUIRE(entity.mode == 0xb6u);
    REQUIRE(entity.flag_0dc == 0xa5u);
    REQUIRE(entity.flag_0e4 == 0xc7u);
    REQUIRE(entity.flag_0cc == 0xe8u);
    REQUIRE(entity.field_0e0 == 0x13579bdfu);
    REQUIRE(entity.owner_ref == 0x0badf00du);
    REQUIRE(entity.tag_lo == 11u);
    REQUIRE(entity.tag_hi == 22u);

    printf("PASS\n");
}

static void test_climate_record_ctor(void)
{
    printf("[TEST] test_climate_record_ctor... ");

    rome2_climate_record climate;
    rome2_recovered_str alt;

    rome2_entity_str_assign_literal(&alt, "clear");

    rome2_climate_record_ctor(&climate, &alt, 1u, 2u, 3u);

    /* The retail ctor writes the base triple at 0x10cc1a28 and then overwrites
     * slot0/slot1 with the derived pair at 0x10cc1a52 / 0x10cc1a5c, so the
     * only observable post-state is the derived pair plus the literal zero. */
    REQUIRE(climate.dispatch0 == ROME2_CLIMATE_DISPATCH0);
    REQUIRE(climate.dispatch1 == ROME2_CLIMATE_DISPATCH1);
    REQUIRE(climate.dispatch2 == 0u);
    REQUIRE(climate.grid_a == 1u);
    REQUIRE(climate.grid_b == 2u);
    REQUIRE(climate.grid_c == 3u);

    rome2_climate_record_ctor(&climate, NULL, 4u, 5u, 6u);
    REQUIRE(climate.dispatch0 == ROME2_CLIMATE_DISPATCH0);
    REQUIRE(climate.dispatch1 == ROME2_CLIMATE_DISPATCH1);
    REQUIRE(climate.dispatch2 == 0u);

    /* 0x10cc1a1a: the "Climate Conditions" literal is 18 bytes. */
    REQUIRE(climate.name.length == 18);
    REQUIRE(memcmp(climate.name.data, "Climate Conditions", 18) == 0);

    /* 0x10cc1a70 .. 0x10cc1a7e: the three-word grid chain. */
    REQUIRE(climate.grid_a == 4u);
    REQUIRE(climate.grid_b == 5u);
    REQUIRE(climate.grid_c == 6u);

    /* A NULL source leaves +0x18 at the FUN_100f1850 sentinel. */
    REQUIRE(climate.name_alt.length == 0);
    REQUIRE((uint32_t)(uintptr_t)climate.name_alt.data
           == ROME2_UNITCARD_EMPTY_SENTINEL_A);

    rome2_climate_record_ctor(&climate, &alt, 1u, 2u, 3u);
    REQUIRE(climate.name_alt.length == 5);
    REQUIRE(memcmp(climate.name_alt.data, "clear", 5) == 0);
    REQUIRE(climate.grid_a == 1u);
    REQUIRE(climate.grid_b == 2u);
    REQUIRE(climate.grid_c == 3u);

    printf("PASS\n");
}

static void test_record_layout(void)
{
    printf("[TEST] test_record_layout... ");

    REQUIRE(sizeof(rome2_battle_entity) == ROME2_ENTITY_RECORD_SIZE);
    REQUIRE(ROME2_ENTITY_RECORD_SIZE == 0x120u);
    REQUIRE(ROME2_ENTITY_RECORD_SIZE_X86 == 0xE8u);
    REQUIRE(sizeof(rome2_entity_descriptor) == ROME2_ENTITY_DESCRIPTOR_SIZE);
    REQUIRE(ROME2_ENTITY_DESCRIPTOR_SIZE == 16u);
    REQUIRE(sizeof(rome2_climate_record) == ROME2_CLIMATE_RECORD_SIZE);
    REQUIRE(sizeof(rome2_recovered_str) == 16u);
    REQUIRE(offsetof(rome2_battle_entity, effect_name) == 0x10u);
    REQUIRE(offsetof(rome2_battle_entity, category) == 0x20u);
    REQUIRE(offsetof(rome2_battle_entity, origin_x) == 0x30u);
    REQUIRE(offsetof(rome2_battle_entity, climate) == 0x80u);
    REQUIRE(offsetof(rome2_battle_entity, label_alt) == 0xc0u);
    REQUIRE(offsetof(rome2_battle_entity, items) == 0xe0u);
    REQUIRE(offsetof(rome2_battle_entity, flag_0e4) == 0x118u);
    REQUIRE(ROME2_ENTITY_ITEM_STRIDE_X86 == 12u);
    REQUIRE(ROME2_ENTITY_ITEM_STRIDE == sizeof(rome2_recovered_str));
    REQUIRE(ROME2_ENTITY_ACTIVATION_RADIUS == 2048.0f);

    printf("PASS\n");
}

static void *test_failed_alloc(size_t bytes)
{
    ++g_alloc_calls;
    g_alloc_bytes = bytes;
    return NULL;
}

static void test_rejected_counts_preserve_output(void)
{
    const uint32_t rejected[] = {
        UINT32_C(0x80000000), UINT32_MAX,
        ROME2_ENTITY_MAX_ITEM_COUNT + 1u
    };
    rome2_battle_entity entity;
    unsigned char before[sizeof(entity)];
    rome2_recovered_str source;
    rome2_entity_descriptor desc = { 0u, 0u, &source };
    rome2_entity_ctor_args args = { 0 };
    rome2_entity_host host = { test_alloc, test_free };
    size_t i;

    printf("[TEST] test_rejected_counts_preserve_output... ");
    memset(&entity, 0xa5, sizeof(entity));
    memcpy(before, &entity, sizeof(before));
    args.arg10 = &desc;
    g_alloc_calls = 0;
    for (i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        desc.item_count = rejected[i];
        REQUIRE(rome2_battle_entity_ctor(&entity, &args, NULL, &host) == NULL);
        REQUIRE(memcmp(before, &entity, sizeof(before)) == 0);
        REQUIRE(g_alloc_calls == 0u);
    }
    REQUIRE(rome2_battle_entity_ctor(&entity, NULL, NULL, &host) == NULL);
    REQUIRE(memcmp(before, &entity, sizeof(before)) == 0);
    REQUIRE(rome2_battle_entity_ctor(NULL, &args, NULL, &host) == NULL);
    printf("PASS\n");
}

static void test_missing_services_and_allocation_failure(void)
{
    rome2_battle_entity entity;
    unsigned char before[sizeof(entity)];
    rome2_recovered_str source;
    rome2_entity_descriptor desc = { 0u, 1u, &source };
    rome2_entity_ctor_args args = { 0 };
    rome2_entity_host host = { test_alloc, test_free };

    printf("[TEST] test_missing_services_and_allocation_failure... ");
    memset(&entity, 0x5a, sizeof(entity));
    memcpy(before, &entity, sizeof(before));
    args.arg10 = &desc;
    g_alloc_calls = 0;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, NULL, NULL) == NULL);
    host.alloc_items = NULL;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, NULL, &host) == NULL);
    host.alloc_items = test_alloc;
    host.free_items = NULL;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, NULL, &host) == NULL);
    host.free_items = test_free;
    desc.items = NULL;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, NULL, &host) == NULL);
    REQUIRE(g_alloc_calls == 0u);
    REQUIRE(memcmp(before, &entity, sizeof(before)) == 0);

    desc.items = &source;
    host.alloc_items = test_failed_alloc;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, NULL, &host) == NULL);
    REQUIRE(g_alloc_calls == 1u);
    REQUIRE(g_alloc_bytes == sizeof(rome2_recovered_str));
    REQUIRE(memcmp(before, &entity, sizeof(before)) == 0);
    /* Largest admitted x86 count: the host request must not wrap at 32 bits.
     * The failing allocator avoids reading a fictitious huge source span. */
    desc.item_count = ROME2_ENTITY_MAX_ITEM_COUNT;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, NULL, &host) == NULL);
    REQUIRE(g_alloc_calls == 2u);
    REQUIRE(g_alloc_bytes == (size_t)desc.item_count * sizeof(source));
    REQUIRE(g_alloc_bytes > UINT32_MAX);
    REQUIRE(memcmp(before, &entity, sizeof(before)) == 0);
    printf("PASS\n");
}

static rome2_recovered_str g_custom_items[2];

static void *test_custom_alloc(size_t bytes)
{
    ++g_alloc_calls;
    REQUIRE(bytes == sizeof(g_custom_items));
    return g_custom_items;
}

static void test_custom_free(void *items)
{
    ++g_free_calls;
    REQUIRE(items == g_custom_items);
}

static void test_allocator_pair_and_borrowed_strings(void)
{
    rome2_battle_entity entity;
    rome2_recovered_str sources[2] = { { 3, 99, "abc" }, { 0, 42, "" } };
    rome2_entity_descriptor desc = { 0u, 2u, sources };
    rome2_entity_ctor_args args = { 0 };
    rome2_entity_host host = { test_custom_alloc, test_custom_free };
    rome2_entity_host missing_free = { test_custom_alloc, NULL };

    printf("[TEST] test_allocator_pair_and_borrowed_strings... ");
    args.arg10 = &desc;
    args.arg11 = &sources[0];
    g_alloc_calls = 0;
    g_free_calls = 0;
    REQUIRE(rome2_battle_entity_ctor(&entity, &args, NULL, &host) == &entity);
    REQUIRE(g_alloc_calls == 1u);
    REQUIRE(entity.items == g_custom_items);
    REQUIRE(entity.items[0].length == 3);
    REQUIRE(entity.items[0].capacity == 3);
    REQUIRE(entity.items[0].data == sources[0].data);
    REQUIRE(entity.source_name.capacity == 3);
    REQUIRE(entity.items[1].length == 0);
    REQUIRE(entity.items[1].capacity == 0);
    REQUIRE((uintptr_t)entity.items[1].data == ROME2_UNITCARD_EMPTY_SENTINEL_A);
    REQUIRE(!rome2_battle_entity_release_items(&entity, NULL));
    REQUIRE(!rome2_battle_entity_release_items(&entity, &missing_free));
    REQUIRE(g_free_calls == 0u);
    REQUIRE(entity.items == g_custom_items);
    REQUIRE(entity.item_count == 2u);
    REQUIRE(entity.item_alloc_count == 2u);
    REQUIRE(rome2_battle_entity_release_items(&entity, &host));
    REQUIRE(g_free_calls == 1u);
    REQUIRE(entity.items == NULL);
    REQUIRE(entity.item_count == 0u);
    REQUIRE(entity.item_alloc_count == 0u);
    REQUIRE(rome2_battle_entity_release_items(&entity, NULL));
    REQUIRE(g_free_calls == 1u);
    REQUIRE(!rome2_battle_entity_release_items(NULL, &host));
    /* Releasing the vector never frees its borrowed string bytes. */
    REQUIRE(memcmp(entity.source_name.data, "abc", 3) == 0);
    printf("PASS\n");
}

int main(void)
{
    printf("=== Phase 4.2 battle entity dispatcher (0x10cbe350) ===\n");
    test_record_layout();
    test_dispatch_triple_and_identity();
    test_embedded_literals_and_anchors();
    test_descriptor_projection_and_item_vector();
    test_zero_count_skips_allocation();
    test_scalar_projection();
    test_climate_record_ctor();
    test_rejected_counts_preserve_output();
    test_missing_services_and_allocation_failure();
    test_allocator_pair_and_borrowed_strings();
    if (g_failures != 0) {
        fprintf(stderr, "=== %d check(s) FAILED for 0x10cbe350 ===\n",
            g_failures);
        return 1;
    }
    printf("=== All 0x10cbe350 tests PASSED ===\n");
    return 0;
}
