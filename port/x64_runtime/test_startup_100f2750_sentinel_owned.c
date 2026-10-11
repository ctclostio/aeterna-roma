#include "ported_100f2750_first_use_owned.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_DESCRIPTOR_BYTES UINT32_C(128)
#define TEST_TEXT_BYTES UINT32_C(65584)
#define TEST_HEAP_BYTES UINT32_C(65664)
#define TEST_PERSISTENT_DESCRIPTOR_BASE UINT32_C(0x119f3a80)
#define TEST_TEMPORARY_DESCRIPTOR_BASE UINT32_C(0x21000001)
#define TEST_TEXT_BASE UINT32_C(0x31000001)
#define TEST_TEMPORARY_HEAP_BASE UINT32_C(0x41000001)
#define TEST_PERSISTENT_HEAP_BASE UINT32_C(0x51000001)
#define TEST_TEMPORARY_DESCRIPTOR_OFFSET UINT32_C(5)
#define TEST_TEXT_OFFSET UINT32_C(6)
#define TEST_TEMPORARY_RAW_OFFSET UINT32_C(32)
#define TEST_PERSISTENT_RAW_OFFSET UINT32_C(64)
#define TEST_SOURCE_TOKEN UINT64_C(0x1122334455667788)
#define TEST_DESTINATION_TOKEN UINT64_C(0x8877665544332211)
#define TEST_RETURN_SENTINEL UINT32_C(0xdeadbeef)
#define TEST_EVENT_ALLOCATE UINT32_C(1)
#define TEST_EVENT_RELEASE UINT32_C(2)
#define TEST_EVENT_HOOK UINT32_C(3)
#define TEST_RELEASE_NONE UINT32_C(0)
#define TEST_RELEASE_COMPENSATE UINT32_C(1)
#define TEST_RELEASE_TEARDOWN UINT32_C(2)
#define TEST_OBSERVE_NONE UINT32_C(0)
#define TEST_OBSERVE_BUILD UINT32_C(1)
#define TEST_OBSERVE_TEARDOWN UINT32_C(2)
#define TEST_MAX_EVENTS UINT32_C(8)

_Static_assert(
    ROME2_PORT_100F2750_FIRST_USE_DESTINATION == UINT32_C(0x119f3aa0),
    "the fixed persistent descriptor identity changed");
_Static_assert(
    ROME2_PORT_100F2750_FIRST_USE_SENTINEL == UINT32_C(0x11af4090),
    "the fixed persistent descriptor sentinel changed");
_Static_assert(
    ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL ==
            UINT32_C(1) &&
        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE ==
            UINT32_C(2) &&
        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED == UINT32_C(3),
    "the registered lifecycle values changed");
_Static_assert(sizeof(rome2_100f2750_first_use_lifecycle) == 8U,
    "the registered lifecycle ABI changed");
_Static_assert(sizeof(rome2_100f1bb0_owned_owner) == 32U,
    "the owned UTF-16 authority ABI changed");

typedef union test_descriptor_storage {
    uint64_t alignment;
    uint8_t bytes[TEST_DESCRIPTOR_BYTES];
} test_descriptor_storage;

typedef union test_text_storage {
    uint64_t alignment;
    uint8_t bytes[TEST_TEXT_BYTES];
} test_text_storage;

typedef union test_heap_storage {
    uint64_t alignment;
    uint8_t bytes[TEST_HEAP_BYTES];
} test_heap_storage;

typedef struct test_effect_context {
    rome2_100f1bb0_owned_grant_result allocation_result;
    rome2_100f1bb0_owned_grant grant;
    uint32_t expected_bytes;
    uint32_t expected_release_mode;
    uint64_t expected_release_token;
    rome2_guest_addr32 expected_release_raw;
    uint32_t observation_mode;
    const uint8_t *observed_persistent_descriptor;
    const uint8_t *observed_temporary_descriptor;
    const rome2_100f1bb0_owned_owner *observed_temporary_owner;
    const rome2_100f1bb0_owned_owner *observed_persistent_owner;
    const rome2_100f2750_first_use_lifecycle *observed_lifecycle;
    const rome2_guest_addr32 *observed_return;
    uint8_t persistent_descriptor_before[12];
    uint8_t temporary_descriptor_before[12];
    rome2_100f1bb0_owned_owner temporary_owner_before;
    rome2_100f1bb0_owned_owner persistent_owner_before;
    rome2_100f2750_first_use_lifecycle lifecycle_before;
    rome2_guest_addr32 return_before;
    uint32_t events[TEST_MAX_EVENTS];
    uint32_t event_count;
    uint32_t allocate_calls;
    uint32_t lifetime_allocate_calls;
    uint32_t release_calls;
    uint32_t hook_calls;
    uint32_t observed_allocate_bytes;
    uint32_t observed_allocate_class;
    uint64_t observed_release_token;
    rome2_guest_addr32 observed_release_raw;
    uint32_t observed_release_bytes;
    uint32_t observed_release_class;
    rome2_guest_addr32 observed_hook_raw;
    uint32_t observed_hook_zero;
    uint32_t bad_observations;
} test_effect_context;

typedef struct test_fixture {
    test_descriptor_storage persistent_descriptor;
    test_descriptor_storage temporary_descriptor;
    test_text_storage text;
    test_heap_storage temporary_heap;
    test_heap_storage persistent_heap;
    rome2_guest_write_view persistent_descriptor_view;
    rome2_guest_write_view temporary_descriptor_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view temporary_heap_view;
    rome2_guest_write_view persistent_heap_view;
    rome2_100f1bb0_owned_effects effects;
    rome2_100f1bb0_owned_owner temporary_owner;
    rome2_100f1bb0_owned_owner persistent_owner;
    rome2_100f2750_first_use_lifecycle lifecycle;
    rome2_guest_addr32 temporary_descriptor_identity;
    rome2_guest_addr32 text_identity;
    rome2_guest_addr32 guest_return;
    uint32_t length_units;
    test_effect_context context;
} test_fixture;

static test_fixture test_fixture_storage;
static test_fixture test_snapshot_storage;
static uint32_t test_case_count;

static uint32_t test_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static uint16_t test_read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static void test_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void test_write_u16_le(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) {
        return 0;
    }
    (void)fprintf(stderr,
        "100f2750 first-use owned runtime: %s: %s\n", case_name, detail);
    return 1;
}

static void test_begin_case(void)
{
    ++test_case_count;
}

static void test_trace(test_effect_context *context, uint32_t event)
{
    if (context->event_count >= TEST_MAX_EVENTS) {
        ++context->bad_observations;
        return;
    }
    context->events[context->event_count] = event;
    ++context->event_count;
}

static int test_controls_match_before(const test_effect_context *context)
{
    if (context->observation_mode == TEST_OBSERVE_NONE) {
        return 1;
    }
    if (context->observed_persistent_descriptor == NULL ||
        context->observed_temporary_descriptor == NULL ||
        context->observed_temporary_owner == NULL ||
        context->observed_persistent_owner == NULL ||
        context->observed_lifecycle == NULL ||
        context->observed_return == NULL) {
        return 0;
    }
    return
        memcmp(context->observed_persistent_descriptor,
            context->persistent_descriptor_before,
            sizeof(context->persistent_descriptor_before)) == 0 &&
        memcmp(context->observed_temporary_descriptor,
            context->temporary_descriptor_before,
            sizeof(context->temporary_descriptor_before)) == 0 &&
        memcmp(context->observed_temporary_owner,
            &context->temporary_owner_before,
            sizeof(context->temporary_owner_before)) == 0 &&
        memcmp(context->observed_persistent_owner,
            &context->persistent_owner_before,
            sizeof(context->persistent_owner_before)) == 0 &&
        memcmp(context->observed_lifecycle, &context->lifecycle_before,
            sizeof(context->lifecycle_before)) == 0 &&
        context->observed_return->value == context->return_before.value;
}

static rome2_100f1bb0_owned_grant_result test_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class,
    rome2_100f1bb0_owned_grant *grant_out)
{
    test_effect_context *context = (test_effect_context *)opaque_context;

    test_trace(context, TEST_EVENT_ALLOCATE);
    ++context->allocate_calls;
    ++context->lifetime_allocate_calls;
    context->observed_allocate_bytes = byte_count;
    context->observed_allocate_class = allocation_class;
    if (context->event_count != UINT32_C(1) ||
        context->release_calls != UINT32_C(0) ||
        context->hook_calls != UINT32_C(0) || grant_out == NULL ||
        (grant_out != NULL &&
            (grant_out->token != UINT64_C(0) ||
             grant_out->raw_base.value != UINT32_C(0) ||
             grant_out->reserved != UINT32_C(0))) ||
        byte_count != context->expected_bytes ||
        allocation_class != ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS ||
        !test_controls_match_before(context)) {
        ++context->bad_observations;
    }
    if (grant_out != NULL) {
        *grant_out = context->grant;
    }
    return context->allocation_result;
}

static void test_release(
    void *opaque_context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    test_effect_context *context = (test_effect_context *)opaque_context;

    test_trace(context, TEST_EVENT_RELEASE);
    ++context->release_calls;
    context->observed_release_token = token;
    context->observed_release_raw = raw_base;
    context->observed_release_bytes = byte_count;
    context->observed_release_class = allocation_class;
    if (context->hook_calls != UINT32_C(0) ||
        token != context->expected_release_token ||
        raw_base.value != context->expected_release_raw.value ||
        byte_count != context->expected_bytes ||
        allocation_class != ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS) {
        ++context->bad_observations;
    }
    if (context->expected_release_mode == TEST_RELEASE_COMPENSATE) {
        if (context->event_count != UINT32_C(2) ||
            context->events[0] != TEST_EVENT_ALLOCATE ||
            context->events[1] != TEST_EVENT_RELEASE ||
            context->allocate_calls != UINT32_C(1) ||
            !test_controls_match_before(context)) {
            ++context->bad_observations;
        }
    } else if (context->expected_release_mode == TEST_RELEASE_TEARDOWN) {
        if (context->event_count != UINT32_C(1) ||
            context->events[0] != TEST_EVENT_RELEASE ||
            context->allocate_calls != UINT32_C(0) ||
            context->observed_persistent_owner == NULL ||
            context->observed_lifecycle == NULL ||
            (context->observed_persistent_owner != NULL &&
                context->observed_persistent_owner->phase !=
                    ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED) ||
            (context->observed_lifecycle != NULL &&
                context->observed_lifecycle->phase !=
                    ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED)) {
            ++context->bad_observations;
        }
    } else {
        ++context->bad_observations;
    }
}

static void test_release_hook(
    void *opaque_context,
    rome2_guest_addr32 raw_base,
    uint32_t zero_argument)
{
    test_effect_context *context = (test_effect_context *)opaque_context;

    test_trace(context, TEST_EVENT_HOOK);
    ++context->hook_calls;
    context->observed_hook_raw = raw_base;
    context->observed_hook_zero = zero_argument;
    if (context->expected_release_mode != TEST_RELEASE_TEARDOWN ||
        context->event_count != UINT32_C(2) ||
        context->events[0] != TEST_EVENT_RELEASE ||
        context->events[1] != TEST_EVENT_HOOK ||
        context->release_calls != UINT32_C(1) ||
        raw_base.value != context->expected_release_raw.value ||
        zero_argument != UINT32_C(0) ||
        context->observed_persistent_owner == NULL ||
        context->observed_lifecycle == NULL ||
        (context->observed_persistent_owner != NULL &&
            context->observed_persistent_owner->phase !=
                ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED) ||
        (context->observed_lifecycle != NULL &&
            context->observed_lifecycle->phase !=
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED)) {
        ++context->bad_observations;
    }
}

static uint32_t test_raw_offset_for_residue(
    uint32_t guest_base,
    uint32_t base_offset,
    uint32_t residue)
{
    uint32_t raw = guest_base + base_offset;
    return base_offset +
        ((residue - (raw & UINT32_C(3))) & UINT32_C(3));
}

static void test_reset_events(test_fixture *fixture)
{
    test_effect_context *context = &fixture->context;

    memset(context->events, 0, sizeof(context->events));
    context->event_count = UINT32_C(0);
    context->allocate_calls = UINT32_C(0);
    context->release_calls = UINT32_C(0);
    context->hook_calls = UINT32_C(0);
    context->observed_allocate_bytes = UINT32_C(0);
    context->observed_allocate_class = UINT32_C(0);
    context->observed_release_token = UINT64_C(0);
    context->observed_release_raw.value = UINT32_C(0);
    context->observed_release_bytes = UINT32_C(0);
    context->observed_release_class = UINT32_C(0);
    context->observed_hook_raw.value = UINT32_C(0);
    context->observed_hook_zero = UINT32_C(0);
    context->bad_observations = UINT32_C(0);
}

static void test_init_fixture(
    test_fixture *fixture,
    uint32_t length_units,
    int enable_hook)
{
    uint32_t index;
    uint32_t text_offset;
    uint8_t *persistent_triplet;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->persistent_descriptor.bytes, 0xd3,
        sizeof(fixture->persistent_descriptor.bytes));
    memset(fixture->temporary_descriptor.bytes, 0xc5,
        sizeof(fixture->temporary_descriptor.bytes));
    memset(fixture->text.bytes, 0xb7, sizeof(fixture->text.bytes));
    memset(fixture->temporary_heap.bytes, 0xa5,
        sizeof(fixture->temporary_heap.bytes));
    memset(fixture->persistent_heap.bytes, 0x96,
        sizeof(fixture->persistent_heap.bytes));

    fixture->persistent_descriptor_view.host_base =
        fixture->persistent_descriptor.bytes + 1U;
    fixture->persistent_descriptor_view.guest_base =
        TEST_PERSISTENT_DESCRIPTOR_BASE;
    fixture->persistent_descriptor_view.byte_count =
        TEST_DESCRIPTOR_BYTES - UINT32_C(2);
    fixture->temporary_descriptor_view.host_base =
        fixture->temporary_descriptor.bytes + 1U;
    fixture->temporary_descriptor_view.guest_base =
        TEST_TEMPORARY_DESCRIPTOR_BASE;
    fixture->temporary_descriptor_view.byte_count =
        TEST_DESCRIPTOR_BYTES - UINT32_C(2);
    fixture->text_view.host_base = fixture->text.bytes + 1U;
    fixture->text_view.guest_base = TEST_TEXT_BASE;
    fixture->text_view.byte_count = TEST_TEXT_BYTES - UINT32_C(2);
    fixture->temporary_heap_view.host_base =
        fixture->temporary_heap.bytes + 1U;
    fixture->temporary_heap_view.guest_base = TEST_TEMPORARY_HEAP_BASE;
    fixture->temporary_heap_view.byte_count =
        TEST_HEAP_BYTES - UINT32_C(2);
    fixture->persistent_heap_view.host_base =
        fixture->persistent_heap.bytes + 1U;
    fixture->persistent_heap_view.guest_base = TEST_PERSISTENT_HEAP_BASE;
    fixture->persistent_heap_view.byte_count =
        TEST_HEAP_BYTES - UINT32_C(2);

    fixture->temporary_descriptor_identity.value =
        TEST_TEMPORARY_DESCRIPTOR_BASE + TEST_TEMPORARY_DESCRIPTOR_OFFSET;
    fixture->text_identity.value = TEST_TEXT_BASE + TEST_TEXT_OFFSET;
    fixture->guest_return.value = TEST_RETURN_SENTINEL;
    fixture->length_units = length_units;

    text_offset = fixture->text_identity.value - fixture->text_view.guest_base;
    for (index = UINT32_C(0); index < length_units; ++index) {
        uint16_t unit = (uint16_t)(UINT16_C(0x0101) +
            (uint16_t)(index % UINT32_C(0x7e00)));
        test_write_u16_le(fixture->text.bytes + 1U + text_offset +
            index * UINT32_C(2), unit);
    }
    test_write_u16_le(fixture->text.bytes + 1U + text_offset +
        length_units * UINT32_C(2), UINT16_C(0));

    persistent_triplet = fixture->persistent_descriptor_view.host_base +
        (ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
            fixture->persistent_descriptor_view.guest_base);
    test_write_u32_le(persistent_triplet, UINT32_C(0));
    test_write_u32_le(persistent_triplet + 4U, UINT32_C(0));
    test_write_u32_le(persistent_triplet + 8U,
        ROME2_PORT_100F2750_FIRST_USE_SENTINEL);

    fixture->effects.allocate = test_allocate;
    fixture->effects.release = test_release;
    fixture->effects.release_hook = enable_hook ? test_release_hook : NULL;
    fixture->effects.context = &fixture->context;
    fixture->effects.context_byte_count = sizeof(fixture->context);
    fixture->context.expected_release_mode = TEST_RELEASE_NONE;
    fixture->context.observation_mode = TEST_OBSERVE_NONE;
}

static void test_set_observer(test_fixture *fixture, uint32_t mode)
{
    test_effect_context *context = &fixture->context;
    uint32_t persistent_offset =
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
        fixture->persistent_descriptor_view.guest_base;
    uint32_t temporary_offset = fixture->temporary_descriptor_identity.value -
        fixture->temporary_descriptor_view.guest_base;

    context->observation_mode = mode;
    context->observed_persistent_descriptor =
        fixture->persistent_descriptor_view.host_base + persistent_offset;
    context->observed_temporary_descriptor =
        fixture->temporary_descriptor_view.host_base + temporary_offset;
    context->observed_temporary_owner = &fixture->temporary_owner;
    context->observed_persistent_owner = &fixture->persistent_owner;
    context->observed_lifecycle = &fixture->lifecycle;
    context->observed_return = &fixture->guest_return;
    memcpy(context->persistent_descriptor_before,
        context->observed_persistent_descriptor,
        sizeof(context->persistent_descriptor_before));
    memcpy(context->temporary_descriptor_before,
        context->observed_temporary_descriptor,
        sizeof(context->temporary_descriptor_before));
    context->temporary_owner_before = fixture->temporary_owner;
    context->persistent_owner_before = fixture->persistent_owner;
    context->lifecycle_before = fixture->lifecycle;
    context->return_before = fixture->guest_return;
}

static int test_prepare_ready(
    test_fixture *fixture,
    uint32_t length_units,
    uint32_t source_residue,
    uint32_t destination_residue,
    int enable_hook)
{
    rome2_100f1bb0_owned_status status;
    rome2_guest_addr32 temporary_return = {TEST_RETURN_SENTINEL};
    uint32_t raw_offset;

    test_init_fixture(fixture, length_units, enable_hook);
    raw_offset = test_raw_offset_for_residue(
        fixture->temporary_heap_view.guest_base,
        TEST_TEMPORARY_RAW_OFFSET, source_residue);
    fixture->context.allocation_result =
        ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    fixture->context.grant.token = TEST_SOURCE_TOKEN;
    fixture->context.grant.raw_base.value =
        fixture->temporary_heap_view.guest_base + raw_offset;
    fixture->context.grant.reserved = UINT32_C(0);
    fixture->context.expected_bytes =
        length_units * UINT32_C(2) + UINT32_C(10);
    test_reset_events(fixture);
    status = rome2_port_100f1bb0_build_owned_utf16(
        &fixture->temporary_descriptor_view,
        fixture->temporary_descriptor_identity,
        &fixture->text_view,
        fixture->text_identity,
        length_units + UINT32_C(1),
        &fixture->temporary_heap_view,
        &fixture->effects,
        &fixture->temporary_owner,
        &temporary_return);
    if (status != ROME2_100F1BB0_OWNED_OK ||
        temporary_return.value != fixture->temporary_descriptor_identity.value ||
        fixture->context.allocate_calls != UINT32_C(1) ||
        fixture->context.bad_observations != UINT32_C(0)) {
        (void)fprintf(stderr,
            "100f2750 first-use owned runtime: fixture source build failed\n");
        return 1;
    }

    status = rome2_port_100f2750_register_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    if (status != ROME2_100F1BB0_OWNED_OK ||
        fixture->lifecycle.phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL ||
        fixture->lifecycle.reserved != UINT32_C(0)) {
        (void)fprintf(stderr,
            "100f2750 first-use owned runtime: fixture registration failed\n");
        return 1;
    }

    raw_offset = test_raw_offset_for_residue(
        fixture->persistent_heap_view.guest_base,
        TEST_PERSISTENT_RAW_OFFSET, destination_residue);
    fixture->context.allocation_result =
        ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    fixture->context.grant.token = TEST_DESTINATION_TOKEN;
    fixture->context.grant.raw_base.value =
        fixture->persistent_heap_view.guest_base + raw_offset;
    fixture->context.grant.reserved = UINT32_C(0);
    fixture->context.expected_bytes =
        length_units * UINT32_C(2) + UINT32_C(10);
    fixture->context.expected_release_mode = TEST_RELEASE_NONE;
    fixture->context.expected_release_token = TEST_DESTINATION_TOKEN;
    fixture->context.expected_release_raw = fixture->context.grant.raw_base;
    test_reset_events(fixture);
    test_set_observer(fixture, TEST_OBSERVE_BUILD);
    return 0;
}

static void test_take_snapshot(const test_fixture *fixture)
{
    test_snapshot_storage = *fixture;
}

static int test_expect_preserved(
    const char *case_name,
    const test_fixture *fixture,
    int expect_context_unchanged)
{
    const test_fixture *before = &test_snapshot_storage;
    int failed = 0;

    failed |= test_expect(memcmp(&fixture->persistent_descriptor,
            &before->persistent_descriptor,
            sizeof(fixture->persistent_descriptor)) == 0,
        case_name, "persistent descriptor backing changed on failure");
    failed |= test_expect(memcmp(&fixture->temporary_descriptor,
            &before->temporary_descriptor,
            sizeof(fixture->temporary_descriptor)) == 0,
        case_name, "temporary descriptor backing changed on failure");
    failed |= test_expect(memcmp(&fixture->text, &before->text,
            sizeof(fixture->text)) == 0,
        case_name, "source text changed on failure");
    failed |= test_expect(memcmp(&fixture->temporary_heap,
            &before->temporary_heap, sizeof(fixture->temporary_heap)) == 0,
        case_name, "temporary allocation changed on failure");
    failed |= test_expect(memcmp(&fixture->persistent_heap,
            &before->persistent_heap, sizeof(fixture->persistent_heap)) == 0,
        case_name, "persistent heap changed on failure");
    failed |= test_expect(memcmp(&fixture->persistent_descriptor_view,
            &before->persistent_descriptor_view,
            sizeof(fixture->persistent_descriptor_view)) == 0 &&
        memcmp(&fixture->temporary_descriptor_view,
            &before->temporary_descriptor_view,
            sizeof(fixture->temporary_descriptor_view)) == 0 &&
        memcmp(&fixture->text_view, &before->text_view,
            sizeof(fixture->text_view)) == 0 &&
        memcmp(&fixture->temporary_heap_view, &before->temporary_heap_view,
            sizeof(fixture->temporary_heap_view)) == 0 &&
        memcmp(&fixture->persistent_heap_view, &before->persistent_heap_view,
            sizeof(fixture->persistent_heap_view)) == 0 &&
        memcmp(&fixture->effects, &before->effects,
            sizeof(fixture->effects)) == 0,
        case_name, "a control descriptor changed on failure");
    failed |= test_expect(memcmp(&fixture->temporary_owner,
            &before->temporary_owner,
            sizeof(fixture->temporary_owner)) == 0,
        case_name, "temporary owner changed on failure");
    failed |= test_expect(memcmp(&fixture->persistent_owner,
            &before->persistent_owner,
            sizeof(fixture->persistent_owner)) == 0,
        case_name, "persistent owner changed on failure");
    failed |= test_expect(memcmp(&fixture->lifecycle, &before->lifecycle,
            sizeof(fixture->lifecycle)) == 0,
        case_name, "registered lifecycle changed on failure");
    failed |= test_expect(fixture->guest_return.value ==
            before->guest_return.value,
        case_name, "guest return changed on failure");
    if (expect_context_unchanged) {
        failed |= test_expect(memcmp(&fixture->context, &before->context,
                sizeof(fixture->context)) == 0,
            case_name, "preflight failure changed callback context");
    }
    return failed;
}

static rome2_100f1bb0_owned_status test_call_first_use(
    test_fixture *fixture,
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *temporary_descriptor_view,
    rome2_guest_addr32 temporary_descriptor,
    const rome2_guest_write_view *temporary_heap_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    const rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_guest_addr32 *guest_return)
{
    (void)fixture;
    return rome2_port_100f2750_first_use_owned(
        persistent_descriptor_view,
        temporary_descriptor_view,
        temporary_descriptor,
        temporary_heap_view,
        persistent_heap_view,
        effects,
        temporary_owner,
        persistent_owner,
        lifecycle,
        guest_return);
}

static rome2_100f1bb0_owned_status test_call_first_use_default(
    test_fixture *fixture)
{
    return test_call_first_use(fixture,
        &fixture->persistent_descriptor_view,
        &fixture->temporary_descriptor_view,
        fixture->temporary_descriptor_identity,
        &fixture->temporary_heap_view,
        &fixture->persistent_heap_view,
        &fixture->effects,
        &fixture->temporary_owner,
        &fixture->persistent_owner,
        &fixture->lifecycle,
        &fixture->guest_return);
}

static int test_verify_first_use_success(
    const char *case_name,
    test_fixture *fixture,
    rome2_100f1bb0_owned_status status)
{
    const test_fixture *before = &test_snapshot_storage;
    uint32_t raw = fixture->context.grant.raw_base.value;
    uint32_t payload = (raw + UINT32_C(8)) & UINT32_C(0xfffffffc);
    uint32_t descriptor_offset =
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
        fixture->persistent_descriptor_view.guest_base;
    uint32_t header_offset = payload - UINT32_C(4) -
        fixture->persistent_heap_view.guest_base;
    uint32_t payload_offset =
        payload - fixture->persistent_heap_view.guest_base;
    uint32_t source_offset = fixture->temporary_owner.payload.value -
        fixture->temporary_heap_view.guest_base;
    size_t view_host_offset = (size_t)(fixture->persistent_heap_view.host_base -
        fixture->persistent_heap.bytes);
    uint32_t index;
    int failed = 0;

    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK,
        case_name, "success status changed");
    failed |= test_expect(fixture->context.event_count == UINT32_C(1) &&
            fixture->context.events[0] == TEST_EVENT_ALLOCATE &&
            fixture->context.allocate_calls == UINT32_C(1) &&
            fixture->context.lifetime_allocate_calls == UINT32_C(2) &&
            fixture->context.release_calls == UINT32_C(0) &&
            fixture->context.hook_calls == UINT32_C(0) &&
            fixture->context.bad_observations == UINT32_C(0),
        case_name, "the second allocation transcript changed");
    failed |= test_expect(fixture->context.observed_allocate_bytes ==
            fixture->length_units * UINT32_C(2) + UINT32_C(10) &&
        fixture->context.observed_allocate_class ==
            ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS,
        case_name, "the exact second allocation request changed");
    failed |= test_expect(test_read_u32_le(
            fixture->persistent_descriptor_view.host_base +
                descriptor_offset) == fixture->length_units &&
        test_read_u32_le(fixture->persistent_descriptor_view.host_base +
            descriptor_offset + 4U) == fixture->length_units &&
        test_read_u32_le(fixture->persistent_descriptor_view.host_base +
            descriptor_offset + 8U) == payload,
        case_name, "the persistent descriptor commit is not exact");
    failed |= test_expect(test_read_u32_le(
            fixture->persistent_heap_view.host_base + header_offset) == raw,
        case_name, "the persistent hidden header is not exact");
    for (index = UINT32_C(0); index < fixture->length_units; ++index) {
        failed |= test_expect(test_read_u16_le(
                fixture->persistent_heap_view.host_base + payload_offset +
                    index * UINT32_C(2)) ==
            test_read_u16_le(fixture->temporary_heap_view.host_base +
                source_offset + index * UINT32_C(2)),
            case_name, "persistent payload differs from temporary source");
    }
    failed |= test_expect(test_read_u16_le(
            fixture->persistent_heap_view.host_base + payload_offset +
                fixture->length_units * UINT32_C(2)) == UINT16_C(0),
        case_name, "the persistent literal terminator is missing");
    for (index = UINT32_C(0);
         index < (uint32_t)fixture->persistent_heap_view.byte_count;
         ++index) {
        int is_header = index >= header_offset &&
            index < header_offset + UINT32_C(4);
        int is_payload = index >= payload_offset &&
            index < payload_offset + fixture->length_units * UINT32_C(2);
        int is_terminator = index >=
                payload_offset + fixture->length_units * UINT32_C(2) &&
            index < payload_offset + fixture->length_units * UINT32_C(2) +
                UINT32_C(2);
        if (!is_header && !is_payload && !is_terminator) {
            failed |= test_expect(
                fixture->persistent_heap_view.host_base[index] ==
                    before->persistent_heap.bytes[view_host_offset + index],
                case_name, "unrelated persistent heap byte changed");
        }
    }
    failed |= test_expect(memcmp(&fixture->temporary_descriptor,
            &before->temporary_descriptor,
            sizeof(fixture->temporary_descriptor)) == 0 &&
        memcmp(&fixture->temporary_heap, &before->temporary_heap,
            sizeof(fixture->temporary_heap)) == 0 &&
        memcmp(&fixture->temporary_owner, &before->temporary_owner,
            sizeof(fixture->temporary_owner)) == 0 &&
        memcmp(&fixture->text, &before->text, sizeof(fixture->text)) == 0,
        case_name, "temporary source ownership was not preserved");
    failed |= test_expect(fixture->persistent_owner.token ==
            TEST_DESTINATION_TOKEN &&
        fixture->persistent_owner.raw_base.value == raw &&
        fixture->persistent_owner.payload.value == payload &&
        fixture->persistent_owner.allocation_bytes ==
            fixture->length_units * UINT32_C(2) + UINT32_C(10) &&
        fixture->persistent_owner.length_units == fixture->length_units &&
        fixture->persistent_owner.phase ==
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
        fixture->persistent_owner.reserved == UINT32_C(0),
        case_name, "the persistent LIVE owner commit is not exact");
    failed |= test_expect(fixture->lifecycle.phase ==
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE &&
        fixture->lifecycle.reserved == UINT32_C(0),
        case_name, "the registered lifecycle did not become LIVE");
    failed |= test_expect(fixture->guest_return.value ==
            ROME2_PORT_100F2750_FIRST_USE_DESTINATION,
        case_name, "the fixed descriptor return changed");
    return failed;
}

static int test_expect_first_use_failure(
    const char *case_name,
    test_fixture *fixture,
    rome2_100f1bb0_owned_status status,
    rome2_100f1bb0_owned_status expected_status,
    uint32_t expected_allocate_calls,
    uint32_t expected_release_calls)
{
    int failed = 0;

    failed |= test_expect(status == expected_status,
        case_name, "failure status changed");
    failed |= test_expect(fixture->context.allocate_calls ==
            expected_allocate_calls &&
        fixture->context.release_calls == expected_release_calls &&
        fixture->context.hook_calls == UINT32_C(0) &&
        fixture->context.event_count ==
            expected_allocate_calls + expected_release_calls &&
        (expected_allocate_calls == UINT32_C(0) ||
            fixture->context.events[0] == TEST_EVENT_ALLOCATE) &&
        (expected_release_calls == UINT32_C(0) ||
            fixture->context.events[expected_allocate_calls] ==
                TEST_EVENT_RELEASE) &&
        fixture->context.bad_observations == UINT32_C(0),
        case_name, "failure effect transcript changed");
    failed |= test_expect_preserved(case_name, fixture,
        expected_allocate_calls == UINT32_C(0));
    return failed;
}

static int test_registration_contract(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), 1);
    test_take_snapshot(fixture);
    status = rome2_port_100f2750_register_first_use_owned(
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK,
        "valid registration", "registration status changed");
    failed |= test_expect(memcmp(&fixture->persistent_descriptor,
            &test_snapshot_storage.persistent_descriptor,
            sizeof(fixture->persistent_descriptor)) == 0 &&
        memcmp(&fixture->persistent_owner,
            &test_snapshot_storage.persistent_owner,
            sizeof(fixture->persistent_owner)) == 0 &&
        fixture->lifecycle.phase ==
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL &&
        fixture->lifecycle.reserved == UINT32_C(0),
        "valid registration", "registration changed more than lifecycle");

#define TEST_REGISTER_FAILURE(label_, mutation_, view_, owner_, lifecycle_, expected_) \
    do { \
        test_begin_case(); \
        test_init_fixture(fixture, UINT32_C(3), 1); \
        mutation_; \
        test_take_snapshot(fixture); \
        status = rome2_port_100f2750_register_first_use_owned( \
            (view_), (owner_), (lifecycle_)); \
        failed |= test_expect(status == (expected_), (label_), \
            "registration failure status changed"); \
        failed |= test_expect_preserved((label_), fixture, 1); \
    } while (0)

    TEST_REGISTER_FAILURE("null registration descriptor", (void)0,
        NULL, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_REGISTER_FAILURE("null registration owner", (void)0,
        &fixture->persistent_descriptor_view, NULL, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_REGISTER_FAILURE("null registration lifecycle", (void)0,
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        NULL, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_REGISTER_FAILURE("noncanonical registration sentinel",
        test_write_u32_le(fixture->persistent_descriptor_view.host_base +
            (ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
                fixture->persistent_descriptor_view.guest_base), UINT32_C(1)),
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_REGISTER_FAILURE("nonempty registration owner",
        fixture->persistent_owner.token = UINT64_C(1),
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_REGISTER_FAILURE("dirty registration lifecycle",
        fixture->lifecycle.reserved = UINT32_C(1),
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_REGISTER_FAILURE("null registration backing",
        fixture->persistent_descriptor_view.host_base = NULL,
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_REGISTER_FAILURE("registration guest range overflow",
        (fixture->persistent_descriptor_view.guest_base = UINT32_C(0xfffffff8),
         fixture->persistent_descriptor_view.byte_count = UINT64_C(16)),
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle, ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);
    TEST_REGISTER_FAILURE("registration descriptor truncated",
        fixture->persistent_descriptor_view.byte_count = UINT64_C(42),
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle, ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    TEST_REGISTER_FAILURE("registration control alias",
        (void)0, &fixture->persistent_descriptor_view,
        &fixture->persistent_owner,
        (rome2_100f2750_first_use_lifecycle *)(void *)&fixture->persistent_owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_REGISTER_FAILURE("registration backing-control alias",
        (fixture->persistent_descriptor_view.host_base =
            (uint8_t *)(void *)&fixture->persistent_owner,
         fixture->persistent_descriptor_view.guest_base =
            ROME2_PORT_100F2750_FIRST_USE_DESTINATION,
         fixture->persistent_descriptor_view.byte_count =
            sizeof(fixture->persistent_owner)),
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), 1);
    status = rome2_port_100f2750_register_first_use_owned(
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle);
    if (status != ROME2_100F1BB0_OWNED_OK) {
        return failed | 1;
    }
    test_take_snapshot(fixture);
    status = rome2_port_100f2750_register_first_use_owned(
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(status ==
            ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID,
        "repeat registration", "repeat registration status changed");
    failed |= test_expect_preserved("repeat registration", fixture, 1);

#undef TEST_REGISTER_FAILURE
    return failed;
}

static int test_success_residues_and_maximum(void)
{
    test_fixture *fixture = &test_fixture_storage;
    uint32_t destination_residue;
    uint32_t source_residue;
    int failed = 0;

    for (source_residue = UINT32_C(0); source_residue < UINT32_C(4);
            ++source_residue) {
        for (destination_residue = UINT32_C(0);
                destination_residue < UINT32_C(4);
                ++destination_residue) {
            char case_name[96];
            rome2_100f1bb0_owned_status status;

            test_begin_case();
            if (test_prepare_ready(fixture, UINT32_C(3), source_residue,
                    destination_residue, 1) != 0) {
                return failed | 1;
            }
            (void)snprintf(case_name, sizeof(case_name),
                "source raw residue %u / destination raw residue %u",
                (unsigned int)source_residue,
                (unsigned int)destination_residue);
            test_take_snapshot(fixture);
            status = test_call_first_use_default(fixture);
            failed |= test_verify_first_use_success(
                case_name, fixture, status);
        }
    }

    test_begin_case();
    if (test_prepare_ready(fixture, UINT32_C(1), UINT32_C(2),
            UINT32_C(3), 1) != 0) {
        return failed | 1;
    }
    test_take_snapshot(fixture);
    failed |= test_verify_first_use_success("minimum finite owned payload",
        fixture, test_call_first_use_default(fixture));

    test_begin_case();
    if (test_prepare_ready(fixture,
            ROME2_PORT_100F1BB0_OWNED_MAX_UNITS - UINT32_C(1),
            UINT32_C(3), UINT32_C(2), 0) != 0) {
        return failed | 1;
    }
    test_take_snapshot(fixture);
    failed |= test_verify_first_use_success("maximum finite owned payload",
        fixture, test_call_first_use_default(fixture));

    test_begin_case();
    if (test_prepare_ready(fixture, UINT32_C(5), UINT32_C(0),
            UINT32_C(1), 1) != 0) {
        return failed | 1;
    }
    test_write_u16_le(fixture->temporary_heap_view.host_base +
        (fixture->temporary_owner.payload.value -
            fixture->temporary_heap_view.guest_base) + UINT32_C(4),
        UINT16_C(0));
    test_set_observer(fixture, TEST_OBSERVE_BUILD);
    test_take_snapshot(fixture);
    failed |= test_verify_first_use_success(
        "opaque source units include an interior zero", fixture,
        test_call_first_use_default(fixture));
    return failed;
}

static int test_allocation_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

#define TEST_EFFECT_FAILURE(label_, mutation_, expected_, releases_) \
    do { \
        test_begin_case(); \
        if (test_prepare_ready(fixture, UINT32_C(4), UINT32_C(0), \
                UINT32_C(1), 1) != 0) { \
            return failed | 1; \
        } \
        mutation_; \
        fixture->context.expected_release_token = fixture->context.grant.token; \
        fixture->context.expected_release_raw = fixture->context.grant.raw_base; \
        fixture->context.expected_release_mode = (releases_) != UINT32_C(0) ? \
            TEST_RELEASE_COMPENSATE : TEST_RELEASE_NONE; \
        test_set_observer(fixture, TEST_OBSERVE_BUILD); \
        test_take_snapshot(fixture); \
        status = test_call_first_use_default(fixture); \
        failed |= test_expect_first_use_failure((label_), fixture, status, \
            (expected_), UINT32_C(1), (releases_)); \
    } while (0)

    TEST_EFFECT_FAILURE("canonical destination allocation denial",
        (fixture->context.allocation_result =
             ROME2_100F1BB0_OWNED_GRANT_DENIED,
         memset(&fixture->context.grant, 0,
             sizeof(fixture->context.grant))),
        ROME2_100F1BB0_OWNED_ALLOCATION_DENIED, UINT32_C(0));
    TEST_EFFECT_FAILURE("denial with destination authority",
        fixture->context.allocation_result =
            ROME2_100F1BB0_OWNED_GRANT_DENIED,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(1));
    TEST_EFFECT_FAILURE("invalid destination result with authority",
        fixture->context.allocation_result =
            (rome2_100f1bb0_owned_grant_result)2,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(1));
    TEST_EFFECT_FAILURE("granted destination without authority",
        fixture->context.grant.token = UINT64_C(0),
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(0));
    TEST_EFFECT_FAILURE("dirty granted destination",
        fixture->context.grant.reserved = UINT32_C(1),
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(1));
    TEST_EFFECT_FAILURE("null destination raw identity",
        fixture->context.grant.raw_base.value = UINT32_C(0),
        ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID, UINT32_C(1));
    TEST_EFFECT_FAILURE("destination raw below arena",
        fixture->context.grant.raw_base.value =
            TEST_PERSISTENT_HEAP_BASE - UINT32_C(1),
        ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID, UINT32_C(1));
    TEST_EFFECT_FAILURE("destination extent truncated by arena",
        fixture->context.grant.raw_base.value =
            TEST_PERSISTENT_HEAP_BASE + TEST_HEAP_BYTES - UINT32_C(8),
        ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID, UINT32_C(1));
    TEST_EFFECT_FAILURE("destination guest endpoint overflow",
        fixture->context.grant.raw_base.value = UINT32_C(0xfffffff8),
        ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID, UINT32_C(1));
    TEST_EFFECT_FAILURE("live source token collision",
        fixture->context.grant.token = TEST_SOURCE_TOKEN,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(0));
    TEST_EFFECT_FAILURE("denied destination with live source token collision",
        (fixture->context.allocation_result =
             ROME2_100F1BB0_OWNED_GRANT_DENIED,
         fixture->context.grant.token = TEST_SOURCE_TOKEN),
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(0));
    TEST_EFFECT_FAILURE("dirty denial without authority",
        (fixture->context.allocation_result =
             ROME2_100F1BB0_OWNED_GRANT_DENIED,
         fixture->context.grant.token = UINT64_C(0)),
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(0));

#undef TEST_EFFECT_FAILURE
    return failed;
}

static int test_source_authentication_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t descriptor_offset;
    uint32_t header_offset;
    uint32_t terminator_offset;
    int failed = 0;

#define TEST_AUTH_FAILURE(label_, mutation_, expected_) \
    do { \
        test_begin_case(); \
        if (test_prepare_ready(fixture, UINT32_C(4), UINT32_C(0), \
                UINT32_C(0), 1) != 0) { \
            return failed | 1; \
        } \
        descriptor_offset = fixture->temporary_descriptor_identity.value - \
            fixture->temporary_descriptor_view.guest_base; \
        header_offset = fixture->temporary_owner.payload.value - UINT32_C(4) - \
            fixture->temporary_heap_view.guest_base; \
        terminator_offset = fixture->temporary_owner.payload.value + \
            fixture->temporary_owner.length_units * UINT32_C(2) - \
            fixture->temporary_heap_view.guest_base; \
        mutation_; \
        test_set_observer(fixture, TEST_OBSERVE_BUILD); \
        test_take_snapshot(fixture); \
        status = test_call_first_use_default(fixture); \
        failed |= test_expect_first_use_failure((label_), fixture, status, \
            (expected_), UINT32_C(0), UINT32_C(0)); \
    } while (0)

    TEST_AUTH_FAILURE("temporary owner is not LIVE",
        fixture->temporary_owner.phase =
            ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary owner has no token",
        fixture->temporary_owner.token = UINT64_C(0),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary owner has dirty reserved field",
        fixture->temporary_owner.reserved = UINT32_C(1),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("zero-length temporary owner",
        fixture->temporary_owner.length_units = UINT32_C(0),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("out-of-domain temporary owner length",
        fixture->temporary_owner.length_units =
            ROME2_PORT_100F1BB0_OWNED_MAX_UNITS,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary owner allocation formula mismatch",
        ++fixture->temporary_owner.allocation_bytes,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary owner payload mismatch",
        fixture->temporary_owner.payload.value += UINT32_C(4),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary descriptor length mismatch",
        test_write_u32_le(fixture->temporary_descriptor_view.host_base +
            descriptor_offset, UINT32_C(3)),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary descriptor capacity mismatch",
        test_write_u32_le(fixture->temporary_descriptor_view.host_base +
            descriptor_offset + 4U, UINT32_C(3)),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary descriptor payload mismatch",
        test_write_u32_le(fixture->temporary_descriptor_view.host_base +
            descriptor_offset + 8U,
            fixture->temporary_owner.payload.value + UINT32_C(4)),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary hidden header mismatch",
        test_write_u32_le(fixture->temporary_heap_view.host_base +
            header_offset, UINT32_C(0)),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary terminator mismatch",
        test_write_u16_le(fixture->temporary_heap_view.host_base +
            terminator_offset, UINT16_C(1)),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_AUTH_FAILURE("temporary allocation extent truncated",
        fixture->temporary_heap_view.byte_count =
            (uint64_t)(fixture->temporary_owner.raw_base.value -
                fixture->temporary_heap_view.guest_base) +
            fixture->temporary_owner.allocation_bytes - UINT32_C(1),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

#undef TEST_AUTH_FAILURE
    return failed;
}

static int test_preflight_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    rome2_guest_addr32 null_descriptor = {UINT32_C(0)};
    int failed = 0;

#define TEST_PREFLIGHT_CALL(label_, mutation_, call_, expected_) \
    do { \
        test_begin_case(); \
        if (test_prepare_ready(fixture, UINT32_C(3), UINT32_C(0), \
                UINT32_C(0), 1) != 0) { \
            return failed | 1; \
        } \
        test_set_observer(fixture, TEST_OBSERVE_BUILD); \
        mutation_; \
        test_take_snapshot(fixture); \
        status = (call_); \
        failed |= test_expect_first_use_failure((label_), fixture, status, \
            (expected_), UINT32_C(0), UINT32_C(0)); \
    } while (0)

    TEST_PREFLIGHT_CALL("missing registration",
        fixture->lifecycle.phase = UINT32_C(0),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_PREFLIGHT_CALL("bad registered sentinel state",
        fixture->lifecycle.reserved = UINT32_C(1),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_PREFLIGHT_CALL("nonempty persistent owner",
        fixture->persistent_owner.token = UINT64_C(1),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_PREFLIGHT_CALL("noncanonical persistent descriptor",
        test_write_u32_le(fixture->persistent_descriptor_view.host_base +
            (ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
                fixture->persistent_descriptor_view.guest_base), UINT32_C(1)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_PREFLIGHT_CALL("null temporary descriptor identity", (void)0,
        test_call_first_use(fixture,
            &fixture->persistent_descriptor_view,
            &fixture->temporary_descriptor_view, null_descriptor,
            &fixture->temporary_heap_view, &fixture->persistent_heap_view,
            &fixture->effects, &fixture->temporary_owner,
            &fixture->persistent_owner, &fixture->lifecycle,
            &fixture->guest_return),
        ROME2_100F1BB0_OWNED_NULL_ADDRESS);
    TEST_PREFLIGHT_CALL("persistent heap cannot satisfy exact request",
        fixture->persistent_heap_view.byte_count =
            fixture->length_units * UINT32_C(2) + UINT32_C(9),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    TEST_PREFLIGHT_CALL("persistent descriptor guest range overflow",
        (fixture->persistent_descriptor_view.guest_base =
             UINT32_C(0xfffffff8),
         fixture->persistent_descriptor_view.byte_count = UINT64_C(16)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);
    TEST_PREFLIGHT_CALL("temporary descriptor guest range overflow",
        (fixture->temporary_descriptor_view.guest_base =
             UINT32_C(0xfffffff8),
         fixture->temporary_descriptor_view.byte_count = UINT64_C(16)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);
    TEST_PREFLIGHT_CALL("temporary heap guest range overflow",
        (fixture->temporary_heap_view.guest_base = UINT32_C(0xfffffff8),
         fixture->temporary_heap_view.byte_count = UINT64_C(16)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);
    TEST_PREFLIGHT_CALL("persistent heap guest range overflow",
        (fixture->persistent_heap_view.guest_base = UINT32_C(0xfffffff8),
         fixture->persistent_heap_view.byte_count = UINT64_C(16)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);
    TEST_PREFLIGHT_CALL("zero-based persistent heap lacks a usable first byte",
        (fixture->persistent_heap_view.guest_base = UINT32_C(0),
         fixture->persistent_heap_view.byte_count =
            fixture->length_units * UINT32_C(2) + UINT32_C(10)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    TEST_PREFLIGHT_CALL("persistent descriptor truncated",
        fixture->persistent_descriptor_view.byte_count = UINT64_C(42),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    TEST_PREFLIGHT_CALL("null allocate effect",
        fixture->effects.allocate = NULL,
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("null release effect",
        fixture->effects.release = NULL,
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("null callback context",
        fixture->effects.context = NULL,
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("empty callback context",
        fixture->effects.context_byte_count = UINT64_C(0),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("physical backing alias",
        fixture->persistent_heap_view.host_base =
            fixture->temporary_heap_view.host_base,
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("backing overlaps lifecycle control",
        (fixture->persistent_heap_view.host_base =
             (uint8_t *)(void *)&fixture->lifecycle,
         fixture->persistent_heap_view.byte_count =
             sizeof(fixture->lifecycle)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("logical guest-view alias",
        fixture->persistent_heap_view.guest_base =
            fixture->temporary_heap_view.guest_base,
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("callback context overlaps backing",
        (fixture->effects.context = fixture->persistent_heap_view.host_base,
         fixture->effects.context_byte_count = UINT64_C(8)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("callback context overlaps control",
        (fixture->effects.context = &fixture->persistent_owner,
         fixture->effects.context_byte_count =
            sizeof(fixture->persistent_owner)),
        test_call_first_use_default(fixture),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_PREFLIGHT_CALL("owner controls alias", (void)0,
        test_call_first_use(fixture,
            &fixture->persistent_descriptor_view,
            &fixture->temporary_descriptor_view,
            fixture->temporary_descriptor_identity,
            &fixture->temporary_heap_view, &fixture->persistent_heap_view,
            &fixture->effects, &fixture->temporary_owner,
            &fixture->temporary_owner, &fixture->lifecycle,
            &fixture->guest_return),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

#define TEST_NULL_CONTROL(label_, pdesc_, tdesc_, theap_, pheap_, effects_, \
        towner_, powner_, lifecycle_, ret_) \
    TEST_PREFLIGHT_CALL((label_), (void)0, \
        test_call_first_use(fixture, (pdesc_), (tdesc_), \
            fixture->temporary_descriptor_identity, (theap_), (pheap_), \
            (effects_), (towner_), (powner_), (lifecycle_), (ret_)), \
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT)

    TEST_NULL_CONTROL("null persistent descriptor control", NULL,
        &fixture->temporary_descriptor_view, &fixture->temporary_heap_view,
        &fixture->persistent_heap_view, &fixture->effects,
        &fixture->temporary_owner, &fixture->persistent_owner,
        &fixture->lifecycle, &fixture->guest_return);
    TEST_NULL_CONTROL("null temporary descriptor control",
        &fixture->persistent_descriptor_view, NULL,
        &fixture->temporary_heap_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle,
        &fixture->guest_return);
    TEST_NULL_CONTROL("null temporary heap control",
        &fixture->persistent_descriptor_view,
        &fixture->temporary_descriptor_view, NULL,
        &fixture->persistent_heap_view, &fixture->effects,
        &fixture->temporary_owner, &fixture->persistent_owner,
        &fixture->lifecycle, &fixture->guest_return);
    TEST_NULL_CONTROL("null persistent heap control",
        &fixture->persistent_descriptor_view,
        &fixture->temporary_descriptor_view, &fixture->temporary_heap_view,
        NULL, &fixture->effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle,
        &fixture->guest_return);
    TEST_NULL_CONTROL("null effects control",
        &fixture->persistent_descriptor_view,
        &fixture->temporary_descriptor_view, &fixture->temporary_heap_view,
        &fixture->persistent_heap_view, NULL, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle,
        &fixture->guest_return);
    TEST_NULL_CONTROL("null temporary owner control",
        &fixture->persistent_descriptor_view,
        &fixture->temporary_descriptor_view, &fixture->temporary_heap_view,
        &fixture->persistent_heap_view, &fixture->effects, NULL,
        &fixture->persistent_owner, &fixture->lifecycle,
        &fixture->guest_return);
    TEST_NULL_CONTROL("null persistent owner control",
        &fixture->persistent_descriptor_view,
        &fixture->temporary_descriptor_view, &fixture->temporary_heap_view,
        &fixture->persistent_heap_view, &fixture->effects,
        &fixture->temporary_owner, NULL, &fixture->lifecycle,
        &fixture->guest_return);
    TEST_NULL_CONTROL("null lifecycle control",
        &fixture->persistent_descriptor_view,
        &fixture->temporary_descriptor_view, &fixture->temporary_heap_view,
        &fixture->persistent_heap_view, &fixture->effects,
        &fixture->temporary_owner, &fixture->persistent_owner, NULL,
        &fixture->guest_return);
    TEST_NULL_CONTROL("null return control",
        &fixture->persistent_descriptor_view,
        &fixture->temporary_descriptor_view, &fixture->temporary_heap_view,
        &fixture->persistent_heap_view, &fixture->effects,
        &fixture->temporary_owner, &fixture->persistent_owner,
        &fixture->lifecycle, NULL);

#undef TEST_NULL_CONTROL
#undef TEST_PREFLIGHT_CALL
    return failed;
}

static int test_teardown_contract(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_owner expected_owner;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    if (test_prepare_ready(fixture, UINT32_C(5), UINT32_C(2),
            UINT32_C(3), 1) != 0) {
        return 1;
    }
    test_take_snapshot(fixture);
    status = test_call_first_use_default(fixture);
    failed |= test_verify_first_use_success(
        "build before registered LIVE teardown", fixture, status);
    if (status != ROME2_100F1BB0_OWNED_OK) {
        return failed | 1;
    }

    test_begin_case();
    test_reset_events(fixture);
    fixture->context.expected_release_mode = TEST_RELEASE_TEARDOWN;
    fixture->context.expected_release_token = fixture->persistent_owner.token;
    fixture->context.expected_release_raw = fixture->persistent_owner.raw_base;
    fixture->context.expected_bytes = fixture->persistent_owner.allocation_bytes;
    test_set_observer(fixture, TEST_OBSERVE_TEARDOWN);
    test_take_snapshot(fixture);
    expected_owner = fixture->persistent_owner;
    expected_owner.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK,
        "registered LIVE teardown", "teardown status changed");
    failed |= test_expect(fixture->context.event_count == UINT32_C(2) &&
            fixture->context.events[0] == TEST_EVENT_RELEASE &&
            fixture->context.events[1] == TEST_EVENT_HOOK &&
            fixture->context.allocate_calls == UINT32_C(0) &&
            fixture->context.release_calls == UINT32_C(1) &&
            fixture->context.hook_calls == UINT32_C(1) &&
            fixture->context.bad_observations == UINT32_C(0),
        "registered LIVE teardown",
        "consume-before-release/hook order changed");
    failed |= test_expect(memcmp(&fixture->persistent_owner,
            &expected_owner, sizeof(expected_owner)) == 0 &&
        fixture->lifecycle.phase ==
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED &&
        fixture->lifecycle.reserved == UINT32_C(0),
        "registered LIVE teardown", "consumed state is not exact");
    failed |= test_expect(memcmp(&fixture->persistent_descriptor,
            &test_snapshot_storage.persistent_descriptor,
            sizeof(fixture->persistent_descriptor)) == 0 &&
        memcmp(&fixture->persistent_heap,
            &test_snapshot_storage.persistent_heap,
            sizeof(fixture->persistent_heap)) == 0 &&
        memcmp(&fixture->temporary_owner,
            &test_snapshot_storage.temporary_owner,
            sizeof(fixture->temporary_owner)) == 0,
        "registered LIVE teardown", "teardown changed guest/source bytes");

    test_begin_case();
    test_reset_events(fixture);
    test_take_snapshot(fixture);
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_ALREADY_CONSUMED,
        "repeat registered teardown", "repeat teardown status changed");
    failed |= test_expect_preserved("repeat registered teardown", fixture, 1);

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), 1);
    status = rome2_port_100f2750_register_first_use_owned(
        &fixture->persistent_descriptor_view, &fixture->persistent_owner,
        &fixture->lifecycle);
    if (status != ROME2_100F1BB0_OWNED_OK) {
        return failed | 1;
    }
    test_reset_events(fixture);
    test_take_snapshot(fixture);
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED &&
            fixture->lifecycle.reserved == UINT32_C(0) &&
            memcmp(&fixture->persistent_owner,
                &test_snapshot_storage.persistent_owner,
                sizeof(fixture->persistent_owner)) == 0 &&
            memcmp(&fixture->persistent_descriptor,
                &test_snapshot_storage.persistent_descriptor,
                sizeof(fixture->persistent_descriptor)) == 0 &&
            fixture->context.event_count == UINT32_C(0),
        "registered sentinel teardown",
        "sentinel shutdown did not consume without effects");

    return failed;
}

static int test_teardown_validation_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t descriptor_offset;
    uint32_t header_offset;
    int failed = 0;

#define TEST_TEARDOWN_FAILURE(label_, mutation_, descriptor_, heap_, effects_, \
        owner_, lifecycle_, expected_) \
    do { \
        test_begin_case(); \
        if (test_prepare_ready(fixture, UINT32_C(4), UINT32_C(0), \
                UINT32_C(0), 1) != 0) { \
            return failed | 1; \
        } \
        status = test_call_first_use_default(fixture); \
        if (status != ROME2_100F1BB0_OWNED_OK) { \
            return failed | 1; \
        } \
        test_reset_events(fixture); \
        descriptor_offset = ROME2_PORT_100F2750_FIRST_USE_DESTINATION - \
            fixture->persistent_descriptor_view.guest_base; \
        header_offset = fixture->persistent_owner.payload.value - \
            UINT32_C(4) - fixture->persistent_heap_view.guest_base; \
        mutation_; \
        test_set_observer(fixture, TEST_OBSERVE_TEARDOWN); \
        test_take_snapshot(fixture); \
        status = rome2_port_100f2750_teardown_first_use_owned( \
            (descriptor_), (heap_), (effects_), (owner_), (lifecycle_)); \
        failed |= test_expect(status == (expected_), (label_), \
            "teardown failure status changed"); \
        failed |= test_expect(fixture->context.event_count == UINT32_C(0), \
            (label_), "teardown failure invoked an effect"); \
        failed |= test_expect_preserved((label_), fixture, 1); \
    } while (0)

    TEST_TEARDOWN_FAILURE("teardown descriptor mismatch",
        test_write_u32_le(fixture->persistent_descriptor_view.host_base +
            descriptor_offset, UINT32_C(3)),
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_TEARDOWN_FAILURE("teardown hidden header mismatch",
        test_write_u32_le(fixture->persistent_heap_view.host_base +
            header_offset, UINT32_C(0)),
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_TEARDOWN_FAILURE("teardown owner mismatch",
        ++fixture->persistent_owner.allocation_bytes,
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_TEARDOWN_FAILURE("teardown lifecycle mismatch",
        fixture->lifecycle.phase =
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL,
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_TEARDOWN_FAILURE("teardown callback context overlaps backing",
        (fixture->effects.context = fixture->persistent_heap_view.host_base,
         fixture->effects.context_byte_count = UINT64_C(8)),
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("teardown callback context overlaps control",
        (fixture->effects.context = &fixture->lifecycle,
         fixture->effects.context_byte_count = sizeof(fixture->lifecycle)),
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("teardown null callback context",
        fixture->effects.context = NULL,
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("teardown empty callback context",
        fixture->effects.context_byte_count = UINT64_C(0),
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("teardown null release effect",
        fixture->effects.release = NULL,
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("teardown controls alias", (void)0,
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner,
        (rome2_100f2750_first_use_lifecycle *)(void *)&fixture->persistent_owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("null teardown lifecycle", (void)0,
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, &fixture->persistent_owner, NULL,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("null teardown descriptor view", (void)0,
        NULL, &fixture->persistent_heap_view, &fixture->effects,
        &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("null teardown heap view", (void)0,
        &fixture->persistent_descriptor_view, NULL, &fixture->effects,
        &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("null teardown effects", (void)0,
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        NULL, &fixture->persistent_owner, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TEARDOWN_FAILURE("null teardown owner", (void)0,
        &fixture->persistent_descriptor_view, &fixture->persistent_heap_view,
        &fixture->effects, NULL, &fixture->lifecycle,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

#undef TEST_TEARDOWN_FAILURE
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_registration_contract();
    failed |= test_success_residues_and_maximum();
    failed |= test_allocation_failures();
    failed |= test_source_authentication_failures();
    failed |= test_preflight_failures();
    failed |= test_teardown_contract();
    failed |= test_teardown_validation_failures();

    if (failed != 0) {
        return 1;
    }
    (void)printf(
        "100f2750 first-use owned runtime checks passed (%u cases)\n",
        (unsigned int)test_case_count);
    return 0;
}
