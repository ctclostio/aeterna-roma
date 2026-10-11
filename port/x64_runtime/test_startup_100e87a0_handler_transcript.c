#include "ported_100e87a0_handler_transcript.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_MEMORY_BYTES 160U
#define TEST_GUEST_BASE UINT32_C(0x24000000)
#define TEST_OUTPUT_SENTINEL UINT8_C(0xa6)

typedef union test_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_MEMORY_BYTES];
} test_memory;

typedef struct test_context {
    test_memory *memory;
    rome2_100e87a0_effects *caller_effects;
    uint8_t *return_al;
    rome2_guest_addr32 allocation_result;
    rome2_guest_addr32 published_listener;
    rome2_guest_addr32 startup_listener;
    rome2_100e87a0_memory_policy startup_policy;
    uint32_t startup_level;
    uint32_t effect_order;
    uint32_t allocation_order;
    uint32_t publication_order;
    uint32_t startup_order;
    uint32_t allocation_calls;
    uint32_t publication_calls;
    uint32_t startup_calls;
    uint32_t evil_calls;
    uint32_t bad_observations;
    int mutate_caller_effects;
} test_context;

typedef struct test_fixture {
    test_memory memory;
    rome2_guest_write_view view;
    rome2_100e87a0_effects effects;
    test_context context;
    uint8_t return_al;
} test_fixture;

static uint32_t test_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void test_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void test_evil_publish(
    void *opaque,
    rome2_guest_addr32 listener)
{
    test_context *context = (test_context *)opaque;

    (void)listener;
    context->evil_calls += UINT32_C(1);
}

static void test_evil_startup(
    void *opaque,
    rome2_100e87a0_memory_policy policy,
    rome2_guest_addr32 listener,
    uint32_t level)
{
    test_context *context = (test_context *)opaque;

    (void)policy;
    (void)listener;
    (void)level;
    context->evil_calls += UINT32_C(1);
}

static rome2_guest_addr32 test_allocate(
    void *opaque,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    test_context *context = (test_context *)opaque;

    context->allocation_calls += UINT32_C(1);
    context->effect_order += UINT32_C(1);
    context->allocation_order = context->effect_order;
    if (byte_count != UINT32_C(4) || allocation_class != UINT32_C(0) ||
        context->return_al == NULL ||
        *context->return_al != TEST_OUTPUT_SENTINEL) {
        context->bad_observations += UINT32_C(1);
    }
    if (context->mutate_caller_effects != 0 &&
        context->caller_effects != NULL) {
        context->caller_effects->publish_listener = test_evil_publish;
        context->caller_effects->startup_facefx = test_evil_startup;
        context->caller_effects->context = NULL;
    }
    return context->allocation_result;
}

static void test_publish(
    void *opaque,
    rome2_guest_addr32 listener)
{
    test_context *context = (test_context *)opaque;

    context->publication_calls += UINT32_C(1);
    context->effect_order += UINT32_C(1);
    context->publication_order = context->effect_order;
    context->published_listener = listener;
    if (context->return_al == NULL ||
        *context->return_al != TEST_OUTPUT_SENTINEL ||
        context->allocation_calls != UINT32_C(1) ||
        context->startup_calls != UINT32_C(0)) {
        context->bad_observations += UINT32_C(1);
    }
    if (listener.value != 0 && context->memory != NULL) {
        uint32_t offset = listener.value - TEST_GUEST_BASE;
        if (offset > TEST_MEMORY_BYTES - UINT32_C(4) ||
            test_read_u32_le(context->memory->bytes + offset) !=
                UINT32_C(0x1173ff28)) {
            context->bad_observations += UINT32_C(1);
        }
    }
}

static void test_startup(
    void *opaque,
    rome2_100e87a0_memory_policy policy,
    rome2_guest_addr32 listener,
    uint32_t level)
{
    test_context *context = (test_context *)opaque;

    context->startup_calls += UINT32_C(1);
    context->effect_order += UINT32_C(1);
    context->startup_order = context->effect_order;
    context->startup_policy = policy;
    context->startup_listener = listener;
    context->startup_level = level;
    if (context->return_al == NULL ||
        *context->return_al != TEST_OUTPUT_SENTINEL ||
        context->allocation_calls != UINT32_C(1) ||
        context->publication_calls != UINT32_C(1) ||
        context->published_listener.value != listener.value ||
        policy.allocation_type != UINT32_C(2) ||
        policy.track_allocations != UINT32_C(1) ||
        policy.allocate_identity != UINT32_C(0x100d12b0) ||
        policy.allocate_debug_identity != UINT32_C(0x100e2190) ||
        policy.free_identity != UINT32_C(0x100e21a0) ||
        level != UINT32_C(6)) {
        context->bad_observations += UINT32_C(1);
    }
}

static void test_init_fixture(test_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->memory.bytes, 0x5a, sizeof(fixture->memory.bytes));
    fixture->view.host_base = fixture->memory.bytes;
    fixture->view.guest_base = TEST_GUEST_BASE;
    fixture->view.byte_count = sizeof(fixture->memory.bytes);
    fixture->effects.allocate_listener = test_allocate;
    fixture->effects.publish_listener = test_publish;
    fixture->effects.startup_facefx = test_startup;
    fixture->effects.context = &fixture->context;
    fixture->return_al = TEST_OUTPUT_SENTINEL;
    fixture->context.memory = &fixture->memory;
    fixture->context.caller_effects = &fixture->effects;
    fixture->context.return_al = &fixture->return_al;
    fixture->context.allocation_result.value = TEST_GUEST_BASE + UINT32_C(13);
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) {
        return 0;
    }
    fprintf(stderr, "100e87a0 runtime: %s: %s\n", case_name, detail);
    return 1;
}

static int test_success_nonnull_is_exact(void)
{
    static const char case_name[] = "nonnull listener commits exact ordered transcript";
    test_fixture fixture;
    test_memory expected;
    rome2_100e87a0_status status;
    int failed = 0;

    test_init_fixture(&fixture);
    expected = fixture.memory;
    test_write_u32_le(
        expected.bytes + 13U, UINT32_C(0x1173ff28));
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view,
        (rome2_guest_addr32){UINT32_C(0)},
        (rome2_guest_addr32){UINT32_C(0xffffffff)},
        &fixture.effects,
        &fixture.return_al);

    failed |= test_expect(status == ROME2_100E87A0_OK,
        case_name, "status was not OK");
    failed |= test_expect(fixture.return_al == UINT8_C(1),
        case_name, "AL was not published as one");
    failed |= test_expect(
        memcmp(fixture.memory.bytes, expected.bytes,
            sizeof(expected.bytes)) == 0,
        case_name, "guest mutation differed from one vtable store");
    failed |= test_expect(
        fixture.context.allocation_calls == UINT32_C(1) &&
        fixture.context.publication_calls == UINT32_C(1) &&
        fixture.context.startup_calls == UINT32_C(1) &&
        fixture.context.allocation_order == UINT32_C(1) &&
        fixture.context.publication_order == UINT32_C(2) &&
        fixture.context.startup_order == UINT32_C(3),
        case_name, "effect count/order changed");
    failed |= test_expect(
        fixture.context.published_listener.value == TEST_GUEST_BASE + 13U &&
        fixture.context.startup_listener.value == TEST_GUEST_BASE + 13U &&
        fixture.context.startup_level == UINT32_C(6),
        case_name, "listener publication/startup arguments changed");
    failed |= test_expect(fixture.context.bad_observations == UINT32_C(0),
        case_name, "a callback observed an early or malformed commit");
    return failed;
}

static int test_null_allocation_is_normal(void)
{
    static const char case_name[] = "null allocation still publishes and starts FaceFX";
    test_fixture fixture;
    test_memory snapshot;
    rome2_100e87a0_status status;
    int failed = 0;

    test_init_fixture(&fixture);
    fixture.context.allocation_result.value = UINT32_C(0);
    fixture.view.byte_count = UINT64_C(0);
    snapshot = fixture.memory;
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view,
        (rome2_guest_addr32){UINT32_C(0xffffffff)},
        (rome2_guest_addr32){UINT32_C(0)},
        &fixture.effects,
        &fixture.return_al);

    failed |= test_expect(status == ROME2_100E87A0_OK,
        case_name, "null route did not succeed");
    failed |= test_expect(
        fixture.context.published_listener.value == UINT32_C(0) &&
        fixture.context.startup_listener.value == UINT32_C(0),
        case_name, "null listener was not preserved");
    failed |= test_expect(
        fixture.context.effect_order == UINT32_C(3) &&
        fixture.context.bad_observations == UINT32_C(0),
        case_name, "null route effect sequence changed");
    failed |= test_expect(
        memcmp(fixture.memory.bytes, snapshot.bytes,
            sizeof(snapshot.bytes)) == 0,
        case_name, "null route mutated guest bytes");
    failed |= test_expect(fixture.return_al == UINT8_C(1),
        case_name, "null route did not publish AL");
    return failed;
}

static int test_guest_end_boundary_is_admitted(void)
{
    static const char case_name[] = "listener cell may end at guest address-space end";
    test_fixture fixture;
    rome2_100e87a0_status status;
    int failed = 0;

    test_init_fixture(&fixture);
    fixture.view.guest_base = UINT32_C(0xfffffffc);
    fixture.view.byte_count = UINT64_C(4);
    fixture.context.allocation_result.value = UINT32_C(0xfffffffc);
    fixture.context.memory = NULL;
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view,
        (rome2_guest_addr32){UINT32_C(0x80000000)},
        (rome2_guest_addr32){UINT32_C(0x7fffffff)},
        &fixture.effects,
        &fixture.return_al);

    failed |= test_expect(status == ROME2_100E87A0_OK,
        case_name, "exact address-space end was rejected");
    failed |= test_expect(
        test_read_u32_le(fixture.memory.bytes) == UINT32_C(0x1173ff28),
        case_name, "boundary vtable store changed");
    failed |= test_expect(fixture.context.effect_order == UINT32_C(3),
        case_name, "boundary route did not complete");
    return failed;
}

static int test_snapshot_precedes_first_effect(void)
{
    static const char case_name[] = "effects snapshot precedes allocator callback";
    test_fixture fixture;
    rome2_100e87a0_status status;
    int failed = 0;

    test_init_fixture(&fixture);
    fixture.context.mutate_caller_effects = 1;
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view,
        (rome2_guest_addr32){UINT32_C(0x13579bdf)},
        (rome2_guest_addr32){UINT32_C(0x2468ace0)},
        &fixture.effects,
        &fixture.return_al);

    failed |= test_expect(status == ROME2_100E87A0_OK,
        case_name, "snapshot route failed");
    failed |= test_expect(
        fixture.context.publication_calls == UINT32_C(1) &&
        fixture.context.startup_calls == UINT32_C(1) &&
        fixture.context.evil_calls == UINT32_C(0),
        case_name, "caller effects were reread after allocation");
    failed |= test_expect(fixture.context.bad_observations == UINT32_C(0),
        case_name, "snapshotted callbacks observed bad state");
    return failed;
}

static int test_invalid_allocation_prefix_is_exact(void)
{
    static const char *const labels[] = {
        "allocation result below view",
        "allocation result is truncated",
        "allocation result lies after view",
        "allocation result guest span overflows",
    };
    const uint32_t results[] = {
        TEST_GUEST_BASE - UINT32_C(1),
        TEST_GUEST_BASE + TEST_MEMORY_BYTES - UINT32_C(2),
        TEST_GUEST_BASE + TEST_MEMORY_BYTES,
        UINT32_C(0xfffffffe),
    };
    size_t index;
    int failed = 0;

    for (index = 0; index < sizeof(results) / sizeof(results[0]); ++index) {
        test_fixture fixture;
        test_memory snapshot;
        rome2_100e87a0_status status;

        test_init_fixture(&fixture);
        fixture.context.allocation_result.value = results[index];
        snapshot = fixture.memory;
        status = rome2_port_100e87a0_run_handler_transcript(
            &fixture.view,
            (rome2_guest_addr32){UINT32_C(0)},
            (rome2_guest_addr32){UINT32_C(0)},
            &fixture.effects,
            &fixture.return_al);
        failed |= test_expect(
            status == ROME2_100E87A0_ALLOCATION_RESULT_INVALID,
            labels[index], "invalid result status changed");
        failed |= test_expect(
            fixture.context.allocation_calls == UINT32_C(1) &&
            fixture.context.publication_calls == UINT32_C(0) &&
            fixture.context.startup_calls == UINT32_C(0) &&
            fixture.context.effect_order == UINT32_C(1),
            labels[index], "invalid result did not preserve allocation-only prefix");
        failed |= test_expect(fixture.return_al == TEST_OUTPUT_SENTINEL,
            labels[index], "invalid result modified AL output");
        failed |= test_expect(
            memcmp(fixture.memory.bytes, snapshot.bytes,
                sizeof(snapshot.bytes)) == 0,
            labels[index], "invalid result mutated guest bytes");
    }
    return failed;
}

static int test_validation_failures_have_no_effect(void)
{
    static const char case_name[] = "pre-effect validation is fail-closed";
    test_fixture fixture;
    test_memory snapshot;
    rome2_100e87a0_effects saved_effects;
    rome2_100e87a0_status status;
    uint8_t raw_effects[sizeof(rome2_100e87a0_effects) + 1U];
    int failed = 0;

    test_init_fixture(&fixture);
    snapshot = fixture.memory;
    status = rome2_port_100e87a0_run_handler_transcript(
        NULL, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "null state view was accepted");

    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        NULL, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "null effects were accepted");
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, NULL);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "null AL output was accepted");

    saved_effects = fixture.effects;
    fixture.effects.allocate_listener = NULL;
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "null allocator was accepted");
    fixture.effects = saved_effects;
    fixture.effects.publish_listener = NULL;
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "null publisher was accepted");
    fixture.effects = saved_effects;
    fixture.effects.startup_facefx = NULL;
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "null FaceFX callback was accepted");
    fixture.effects = saved_effects;
    fixture.effects.context = NULL;
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "null callback context was accepted");
    fixture.effects = saved_effects;

    fixture.view.host_base = NULL;
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "null state host was accepted");
    fixture.view.host_base = fixture.memory.bytes;
    fixture.view.guest_base = UINT32_C(0xfffffff0);
    fixture.view.byte_count = UINT64_C(32);
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_RANGE_OVERFLOW,
        case_name, "guest view overflow was accepted");

    test_init_fixture(&fixture);
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, (uint8_t *)&fixture.effects);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "effects/output alias was accepted");
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        (const rome2_100e87a0_effects *)&fixture.view,
        &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "view/effects descriptor alias was accepted");

    fixture.view.host_base = (uint8_t *)&fixture.effects;
    fixture.view.byte_count = sizeof(fixture.effects);
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        &fixture.effects, &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "guest host/effects alias was accepted");

    test_init_fixture(&fixture);
    memcpy(raw_effects + 1U, &fixture.effects, sizeof(fixture.effects));
    status = rome2_port_100e87a0_run_handler_transcript(
        &fixture.view, (rome2_guest_addr32){0}, (rome2_guest_addr32){0},
        (const rome2_100e87a0_effects *)(const void *)(raw_effects + 1U),
        &fixture.return_al);
    failed |= test_expect(status == ROME2_100E87A0_BAD_ARGUMENT,
        case_name, "misaligned effects were accepted");

    failed |= test_expect(
        fixture.context.allocation_calls == UINT32_C(0) &&
        fixture.context.publication_calls == UINT32_C(0) &&
        fixture.context.startup_calls == UINT32_C(0),
        case_name, "validation failure emitted an effect");
    failed |= test_expect(fixture.return_al == TEST_OUTPUT_SENTINEL,
        case_name, "validation failure modified AL output");
    failed |= test_expect(
        memcmp(fixture.memory.bytes, snapshot.bytes,
            sizeof(snapshot.bytes)) == 0,
        case_name, "validation failure mutated guest bytes");
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_success_nonnull_is_exact();
    failed |= test_null_allocation_is_normal();
    failed |= test_guest_end_boundary_is_admitted();
    failed |= test_snapshot_precedes_first_effect();
    failed |= test_invalid_allocation_prefix_is_exact();
    failed |= test_validation_failures_have_no_effect();
    if (failed != 0) {
        return 1;
    }
    puts("100e87a0 handler transcript runtime: 9/9 cases passed");
    return 0;
}
