/*
 * test_battle_unitcard_10145c70.c - Phase 4.2 regression tests for the battle
 * unit card descriptor reconstructed from empire.retail.dll 0x10145c70.
 *
 * Every assertion below is tied to a recovered address in the retail body.
 */

#include "ported_10145c70_unitcard.h"

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

typedef struct test_host_state {
    unsigned alloc_tag_calls;
    unsigned alloc_attachment_calls;
    unsigned init_tag_calls;
    unsigned init_attachment_calls;
    unsigned finish_setup_calls;
    size_t   last_tag_size;
    size_t   last_attachment_size;
    uint32_t seen_tag_vtable;
} test_host_state;

static test_host_state g_state;

static void *test_alloc(size_t size)
{
    return calloc(1, size != 0 ? size : 1u);
}

static void test_init_tag(void *tag_slot, const void *source)
{
    (void)tag_slot;
    (void)source;
    ++g_state.init_tag_calls;
}

static void *test_init_attachment(const void *source)
{
    ++g_state.init_attachment_calls;
    return (void *)(uintptr_t)(source != NULL ? 0xA77AC0DEu : 0u);
}

static void test_finish_setup(void *self)
{
    (void)self;
    ++g_state.finish_setup_calls;
}

static rome2_unit_card_host make_host(void)
{
    rome2_unit_card_host host;
    memset(&g_state, 0, sizeof(g_state));
    host.alloc_block = test_alloc;
    host.init_tag = test_init_tag;
    host.init_attachment = test_init_attachment;
    host.finish_setup = test_finish_setup;
    return host;
}

static void args_zero(rome2_unit_card_args *args)
{
    memset(args, 0, sizeof(*args));
}

static void test_sentinels_and_reset(void)
{
    printf("[TEST] test_sentinels_and_reset... ");

    rome2_recovered_str s;

    /* FUN_100f1850 @ 0x100f1850 writes {0, 0, 0x11af408e}. */
    rome2_unit_card_str_reset(&s);
    REQUIRE(s.length == 0);
    REQUIRE(s.capacity == 0);
    REQUIRE((uint32_t)(uintptr_t)s.data == ROME2_UNITCARD_EMPTY_SENTINEL_A);

    /* FUN_100f1c10 @ 0x100f1c10 writes {0, 0, 0x11af4090}. */
    rome2_unit_card_str_reset_alt(&s);
    REQUIRE(s.length == 0);
    REQUIRE(s.capacity == 0);
    REQUIRE((uint32_t)(uintptr_t)s.data == ROME2_UNITCARD_EMPTY_SENTINEL_B);

    REQUIRE(ROME2_UNITCARD_EMPTY_SENTINEL_A != ROME2_UNITCARD_EMPTY_SENTINEL_B);

    /* NULL targets are tolerated by both helpers. */
    rome2_unit_card_str_reset(NULL);
    rome2_unit_card_str_reset_alt(NULL);

    printf("PASS\n");
}

static void test_class_immutability(void)
{
    printf("[TEST] test_class_immutability... ");

    /* CMP EDI,0x6 / CMP EDI,0xe at 0x10145e64 .. 0x10145e6c. */
    REQUIRE(rome2_unit_card_class_is_immutable(6u));
    REQUIRE(rome2_unit_card_class_is_immutable(14u));
    REQUIRE(!rome2_unit_card_class_is_immutable(0u));
    REQUIRE(!rome2_unit_card_class_is_immutable(5u));
    REQUIRE(!rome2_unit_card_class_is_immutable(7u));
    REQUIRE(!rome2_unit_card_class_is_immutable(13u));
    REQUIRE(!rome2_unit_card_class_is_immutable(15u));
    REQUIRE(!rome2_unit_card_class_is_immutable(0xffffffffu));

    printf("PASS\n");
}

static void test_literal_fields(void)
{
    printf("[TEST] test_literal_fields... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);

    rome2_unit_card_ctor(&card, &args, &globals, &host);

    /* 0x10145c7b .. 0x10145c88: the first three dwords are zeroed. */
    REQUIRE(card.field_000 == 0u);
    REQUIRE(card.field_004 == 0u);
    REQUIRE(card.field_008 == 0u);

    /* 0x10145e5a: +0x124 receives the literal 20. */
    REQUIRE(card.slot_count == 20u);
    REQUIRE(ROME2_UNITCARD_LIT_SLOT_COUNT == 20u);

    /* 0x10145e25: +0x118 receives the literal 1. */
    REQUIRE(card.enabled == 1u);
    REQUIRE(ROME2_UNITCARD_LIT_ENABLED == 1u);

    /* 0x10145cf3 .. 0x10145d16: +0x5c..+0x70 are six consecutive zeroes. */
    REQUIRE(card.field_05c == 0u);
    REQUIRE(card.field_060 == 0u);
    REQUIRE(card.field_064 == 0u);
    REQUIRE(card.field_068 == 0u);
    REQUIRE(card.field_06c == 0u);
    REQUIRE(card.field_070 == 0u);

    /* 0x10145d28 .. 0x10145d4d: +0x80, +0x84, +0x88, +0x8c, +0x90. */
    REQUIRE(card.field_080 == 0u);
    REQUIRE(card.field_084 == 0u);
    REQUIRE(card.field_088 == 0u);
    REQUIRE(card.field_08c == 0u);
    REQUIRE(card.field_090 == 0u);

    /* 0x10145dde / 0x10145e49 / 0x10145e50 / 0x10145ea7 / 0x10145eb3. */
    REQUIRE(card.field_114 == 0u);
    REQUIRE(card.flag_11d == 0u);
    REQUIRE(card.field_120 == 0u);
    REQUIRE(card.field_14c == 0u);
    REQUIRE(card.field_150 == 0u);
    REQUIRE(card.field_15c == 0u);
    REQUIRE(card.field_160 == 0u);
    REQUIRE(card.field_164 == 0u);
    REQUIRE(card.field_168 == 0u);
    REQUIRE(card.field_16c == 0u);
    REQUIRE(card.field_170 == 0u);
    REQUIRE(card.field_174 == 0u);
    REQUIRE(card.pad_050 == 0u);
    REQUIRE(card.pad_139 == 0u);
    REQUIRE(card.pad_176 == 0u);

    /* FUN_101a97f0 runs exactly once on the arg00 == NULL exit. */
    REQUIRE(g_state.finish_setup_calls == 1u);
    free(card.tag);
    printf("PASS\n");
}

static void test_string_field_census(void)
{
    printf("[TEST] test_string_field_census... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();
    rome2_recovered_str *plain[9];
    rome2_recovered_str *alt[1];
    size_t i;

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);
    rome2_unit_card_ctor(&card, &args, &globals, &host);

    plain[0] = &card.str_010;
    plain[1] = &card.str_028;
    plain[2] = &card.str_034;
    plain[3] = &card.str_044;
    plain[4] = &card.str_0a4;
    plain[5] = &card.str_0b0;
    plain[6] = &card.str_0bc;
    plain[7] = &card.str_0c8;
    plain[8] = &card.str_0d4;

    /* FUN_100f1850 resets: nine of the ten string members carry sentinel A. */
    for (i = 0; i < sizeof(plain) / sizeof(plain[0]); ++i) {
        REQUIRE(plain[i]->length == 0);
        REQUIRE(plain[i]->capacity == 0);
        REQUIRE((uint32_t)(uintptr_t)plain[i]->data
               == ROME2_UNITCARD_EMPTY_SENTINEL_A);
    }

    REQUIRE(card.str_0e0.length == 0);
    REQUIRE((uint32_t)(uintptr_t)card.str_0e0.data
           == ROME2_UNITCARD_EMPTY_SENTINEL_A);
    REQUIRE(card.str_0f0.length == 0);
    REQUIRE((uint32_t)(uintptr_t)card.str_0f0.data
           == ROME2_UNITCARD_EMPTY_SENTINEL_A);
    REQUIRE(card.str_108.length == 0);
    REQUIRE((uint32_t)(uintptr_t)card.str_108.data
           == ROME2_UNITCARD_EMPTY_SENTINEL_A);
    REQUIRE(card.str_12c.length == 0);
    REQUIRE((uint32_t)(uintptr_t)card.str_12c.data
           == ROME2_UNITCARD_EMPTY_SENTINEL_A);

    /* 0x10145dee: the only member cleared through FUN_100f1c10. */
    alt[0] = &card.str_0fc;
    REQUIRE(alt[0]->length == 0);
    REQUIRE(alt[0]->capacity == 0);
    REQUIRE((uint32_t)(uintptr_t)alt[0]->data
           == ROME2_UNITCARD_EMPTY_SENTINEL_B);

    free(card.tag);
    printf("PASS\n");
}

static void test_colour_and_grid_anchors(void)
{
    printf("[TEST] test_colour_and_grid_anchors... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);

    /* Image defaults: DAT_11afbf14/18 are zero, DAT_11971460/64 are -1.0f. */
    REQUIRE(globals.colour_component_a == 0.0f);
    REQUIRE(globals.colour_component_b == 0.0f);
    REQUIRE(globals.global_retail_flag == false);
    REQUIRE(globals.grid_extent_unset == -1.0f);
    REQUIRE(globals.grid_extent_unset_hi == -1.0f);

    rome2_unit_card_ctor(&card, &args, &globals, &host);

    /* 0x10145d57 .. 0x10145d8f: the pair is duplicated into the hi corner. */
    REQUIRE(card.colour_lo_x == globals.colour_component_a);
    REQUIRE(card.colour_lo_y == globals.colour_component_b);
    REQUIRE(card.colour_hi_x == globals.colour_component_a);
    REQUIRE(card.colour_hi_y == globals.colour_component_b);

    /* 0x10145ebd / 0x10145ecd: the tactical grid extent starts unbounded. */
    REQUIRE(card.grid_extent_min == -1.0f);
    REQUIRE(card.grid_extent_max == -1.0f);

    free(card.tag);
    printf("PASS\n");
}

static void test_argument_projection(void)
{
    printf("[TEST] test_argument_projection... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);

    args.arg03 = 0x12345678u;   /* 0x10145c8f  -> +0x00c          */
    args.arg05 = 0x0a0b0c0du;   /* 0x10145cdf -> +0x054          */
    args.arg07 = 0x0f0e0d0cu;   /* 0x10145ce6 -> +0x058          */
    args.arg08 = 0x0000000bu;   /* 0x10145d1d -> +0x074          */
    args.arg09 = 0.5f;          /* 0x10145d20 -> +0x078 MOVSS    */
    args.arg10 = 0x0000abcdfu;  /* 0x10145d25 -> +0x07c          */
    args.arg06 = 0x55u;         /* 0x10145ea3 -> FUN_1016db10    */

    rome2_unit_card_ctor(&card, &args, &globals, &host);

    REQUIRE(card.owner == 0x12345678u);
    REQUIRE(card.priority == 0x0a0b0c0du);
    REQUIRE(card.control_flags == 0x0f0e0d0cu);
    REQUIRE(card.unit_class == 0x0bu);
    REQUIRE(card.deployment == 0.5f);
    REQUIRE(card.strength == 0x0000abcdfu);

    free(card.tag);
    printf("PASS\n");
}

static void test_byte_flags(void)
{
    printf("[TEST] test_byte_flags... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);

    args.arg02 = 0xa1u;         /* 0x10145cac -> +0x024 */
    args.arg04 = 0xb2u;         /* 0x10145cc3 -> +0x040 */
    args.arg12 = 0xc3u;         /* 0x10145e07 -> +0x119 */
    args.arg13 = 0xd4u;         /* 0x10145e11 -> +0x11a */
    args.arg14 = 0xe5u;         /* 0x10145e1b -> +0x11b */
    args.arg16 = 0xf6u;         /* 0x10145e8f -> +0x138 */

    rome2_unit_card_ctor(&card, &args, &globals, &host);

    REQUIRE(card.selector == 0xa1u);
    REQUIRE(card.variant == 0xb2u);
    REQUIRE(card.flag_119 == 0xc3u);
    REQUIRE(card.flag_11a == 0xd4u);
    REQUIRE(card.flag_11b == 0xe5u);
    REQUIRE(card.flag_138 == 0xf6u);

    free(card.tag);
    printf("PASS\n");
}

static void test_global_flag_gate(void)
{
    printf("[TEST] test_global_flag_gate... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();

    args_zero(&args);

    /* 0x10145dfe .. 0x10145e43: (arg15 || DAT_11afbd20) ? 1 : 0 */
    globals = (rome2_unit_card_globals){ 0.0f, 0.0f, false, -1.0f, -1.0f };

    args.arg15 = 0u;
    rome2_unit_card_ctor(&card, &args, &globals, &host);
    REQUIRE(card.flag_11c == 0u);
    free(card.tag);

    args.arg15 = 1u;
    rome2_unit_card_ctor(&card, &args, &globals, &host);
    REQUIRE(card.flag_11c == 1u);
    free(card.tag);

    args.arg15 = 0u;
    globals.global_retail_flag = true;
    rome2_unit_card_ctor(&card, &args, &globals, &host);
    REQUIRE(card.flag_11c == 1u);
    free(card.tag);

    args.arg15 = 0xffu;
    globals.global_retail_flag = false;
    rome2_unit_card_ctor(&card, &args, &globals, &host);
    REQUIRE(card.flag_11c == 1u);
    free(card.tag);

    printf("PASS\n");
}

static void test_mutable_class_gate(void)
{
    printf("[TEST] test_mutable_class_gate... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();
    static const uint32_t probes[] = { 0u, 5u, 6u, 7u, 13u, 14u, 15u };
    size_t i;

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);

    for (i = 0; i < sizeof(probes) / sizeof(probes[0]); ++i) {
        args.arg08 = probes[i];
        rome2_unit_card_ctor(&card, &args, &globals, &host);
        REQUIRE(card.mutable_class == (rome2_unit_card_class_is_immutable(probes[i])
                                      ? 0u : 1u));
        REQUIRE(card.unit_class == probes[i]);
        free(card.tag);
    }

    printf("PASS\n");
}

static void test_tag_subobject(void)
{
    printf("[TEST] test_tag_subobject... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();
    int marker = 0;

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);

    /* 0x10145f3a: PUSH 0x10 -> FUN_100d12b0 allocates a 16-byte block. */
    args.arg01 = &marker;
    rome2_unit_card_ctor(&card, &args, &globals, &host);

    REQUIRE(card.tag != NULL);
    REQUIRE(card.tag->vtable == ROME2_UNITCARD_TAG_VTABLE);
    REQUIRE(ROME2_UNITCARD_TAG_VTABLE == 0x1173fae4u);
    REQUIRE(ROME2_UNITCARD_TAG_BLOCK_SIZE == 0x10u);
    REQUIRE(g_state.init_tag_calls == 1u);
    REQUIRE(g_state.finish_setup_calls == 1u);

    /* 0x10145f67: arg00 == NULL skips the 0xE8-byte attachment entirely. */
    REQUIRE(card.attachment == NULL);
    REQUIRE(g_state.init_attachment_calls == 0u);

    free(card.tag);
    printf("PASS\n");
}

static void test_attachment_subobject(void)
{
    printf("[TEST] test_attachment_subobject... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();
    int source = 0;

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);
    args.arg00 = &source;

    rome2_unit_card_ctor(&card, &args, &globals, &host);

    /* 0x10145f6f: PUSH 0xe8 -> the attachment block, then FUN_101350c0. */
    REQUIRE(ROME2_UNITCARD_ATTACHMENT_BLOCK_SIZE == 0xe8u);
    REQUIRE(g_state.init_attachment_calls == 1u);
    REQUIRE(card.attachment == (void *)(uintptr_t)0xA77AC0DEu);
    REQUIRE(g_state.finish_setup_calls == 1u);

    free(card.tag);
    printf("PASS\n");
}

static void test_record_layout(void)
{
    printf("[TEST] test_record_layout... ");

    REQUIRE(sizeof(rome2_unit_card) == ROME2_UNITCARD_RECORD_SIZE);
    REQUIRE(ROME2_UNITCARD_RECORD_SIZE == 0x1C8u);
    REQUIRE(ROME2_UNITCARD_RECORD_SIZE_X86 == 0x178u);
    REQUIRE(sizeof(rome2_recovered_str) == ROME2_UNITCARD_STR_SIZE);
    REQUIRE(offsetof(rome2_unit_card, owner) == 0x0cu);
    REQUIRE(offsetof(rome2_unit_card, str_010) == 0x10u);
    REQUIRE(offsetof(rome2_unit_card, attachment) == 0x20u);
    REQUIRE(offsetof(rome2_unit_card, tag) == 0x28u);
    REQUIRE(offsetof(rome2_unit_card, selector) == 0x30u);
    REQUIRE(offsetof(rome2_unit_card, priority) == 0x74u);
    REQUIRE(offsetof(rome2_unit_card, control_flags) == 0x78u);
    REQUIRE(offsetof(rome2_unit_card, unit_class) == 0x94u);
    REQUIRE(offsetof(rome2_unit_card, deployment) == 0x98u);
    REQUIRE(offsetof(rome2_unit_card, strength) == 0x9cu);
    REQUIRE(offsetof(rome2_unit_card, colour_lo_x) == 0xb4u);
    REQUIRE(offsetof(rome2_unit_card, str_0fc) == 0x140u);
    REQUIRE(offsetof(rome2_unit_card, enabled) == 0x164u);
    REQUIRE(offsetof(rome2_unit_card, slot_count) == 0x170u);
    REQUIRE(offsetof(rome2_unit_card, mutable_class) == 0x174u);
    REQUIRE(offsetof(rome2_unit_card, flag_138) == 0x188u);
    REQUIRE(offsetof(rome2_unit_card, aux_subobject) == 0x18au);
    REQUIRE(offsetof(rome2_unit_card, grid_extent_min) == 0x1a4u);
    REQUIRE(offsetof(rome2_unit_card, grid_extent_max) == 0x1a8u);
    REQUIRE(ROME2_UNITCARD_AUX_SUBOBJECT_OFFSET == 0x13cu);
    REQUIRE(ROME2_UNITCARD_AUX_SUBOBJECT_SIZE == 0x10u);
    REQUIRE(ROME2_UNITCARD_TAG_VTABLE_FIRST_SLOT == 0x10cecea0u);

    printf("PASS\n");
}

static void test_null_guards(void)
{
    printf("[TEST] test_null_guards... ");

    rome2_unit_card card;
    rome2_unit_card_args args;
    rome2_unit_card_globals globals;
    rome2_unit_card_host host = make_host();

    args_zero(&args);
    rome2_unit_card_globals_from_image(&globals);

    /* A NULL host reproduces the two JZ branches at 0x10145f48 / 0x10145f6d. */
    rome2_unit_card_ctor(&card, &args, &globals, NULL);
    REQUIRE(card.tag == NULL);
    REQUIRE(card.attachment == NULL);

    rome2_unit_card_globals_from_image(NULL);
    rome2_unit_card_ctor(NULL, &args, &globals, &host);
    rome2_unit_card_ctor(&card, NULL, &globals, &host);

    printf("PASS\n");
}

int main(void)
{
    printf("=== Phase 4.2 battle unit card descriptor (0x10145c70) ===\n");
    test_record_layout();
    test_sentinels_and_reset();
    test_class_immutability();
    test_literal_fields();
    test_string_field_census();
    test_colour_and_grid_anchors();
    test_argument_projection();
    test_byte_flags();
    test_global_flag_gate();
    test_mutable_class_gate();
    test_tag_subobject();
    test_attachment_subobject();
    test_null_guards();
    if (g_failures != 0) {
        fprintf(stderr, "=== %d check(s) FAILED for 0x10145c70 ===\n",
            g_failures);
        return 1;
    }
    printf("=== All 0x10145c70 tests PASSED ===\n");
    return 0;
}