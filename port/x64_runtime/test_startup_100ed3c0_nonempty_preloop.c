#include "ported_100ed3c0_nonempty_preloop.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_FRAME_BYTES UINT32_C(0x90c)
#define TEST_TEXT_BYTES UINT32_C(65584)
#define TEST_SELECTOR_BYTES UINT32_C(16)
#define TEST_HEAP_BYTES UINT32_C(65664)
#define TEST_PERSISTENT_DESCRIPTOR_BYTES UINT32_C(128)
#define TEST_FRAME_BASE UINT32_C(0x22000001)
#define TEST_TEXT_BASE UINT32_C(0x33000001)
#define TEST_SELECTOR_BASE UINT32_C(0x44000001)
#define TEST_TEMPORARY_HEAP_BASE UINT32_C(0x55000001)
#define TEST_PERSISTENT_DESCRIPTOR_BASE UINT32_C(0x119f3a80)
#define TEST_PERSISTENT_HEAP_BASE UINT32_C(0x66000001)
#define TEST_TEXT_OFFSET UINT32_C(6)
#define TEST_FIRST_SELECTOR_OFFSET UINT32_C(0)
#define TEST_SECOND_SELECTOR_OFFSET UINT32_C(8)
#define TEST_TEMPORARY_RAW_OFFSET UINT32_C(32)
#define TEST_PERSISTENT_RAW_OFFSET UINT32_C(64)
#define TEST_ARGUMENT1 UINT32_C(0x89abcdef)
#define TEST_CREATED_MUTEX UINT32_C(0x13579bdf)
#define TEST_TEMPORARY_TOKEN UINT64_C(0x1122334455667788)
#define TEST_PERSISTENT_TOKEN UINT64_C(0x8877665544332211)
#define TEST_RESULT_SENTINEL UINT32_C(0xa55a5aa5)
#define TEST_MAX_EVENTS UINT32_C(64)
#define TEST_EXPECTED_CASES UINT32_C(48)

#define TEST_EVENT_PARENT_BASE UINT32_C(0x100)
#define TEST_EVENT_PREFIX_BASE UINT32_C(0x200)
#define TEST_EVENT_SUFFIX_BASE UINT32_C(0x300)
#define TEST_EVENT_ALLOCATE_TEMPORARY UINT32_C(0x401)
#define TEST_EVENT_ALLOCATE_PERSISTENT UINT32_C(0x402)
#define TEST_EVENT_RELEASE_TEMPORARY UINT32_C(0x403)
#define TEST_EVENT_RELEASE_PERSISTENT UINT32_C(0x404)
#define TEST_EVENT_HOOK_TEMPORARY UINT32_C(0x405)
#define TEST_EVENT_HOOK_PERSISTENT UINT32_C(0x406)

_Static_assert(
    ROME2_PORT_100ED3C0_NONEMPTY_STEP_COUNT == UINT32_C(9),
    "the authenticated nonempty parent operation count changed");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES == TEST_FRAME_BYTES,
    "the authenticated parent frame size changed");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET == UINT32_C(0x28) &&
        ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET == UINT32_C(0x34) &&
        ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET == UINT32_C(0x64),
    "the authenticated parent field layout changed");
_Static_assert(
    ROME2_PORT_100F2750_FIRST_USE_DESTINATION == UINT32_C(0x119f3aa0),
    "the persistent descriptor identity changed");

typedef union test_frame_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_FRAME_BYTES];
} test_frame_memory;

typedef union test_text_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_TEXT_BYTES];
} test_text_memory;

typedef union test_selector_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_SELECTOR_BYTES];
} test_selector_memory;

typedef union test_heap_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_HEAP_BYTES];
} test_heap_memory;

typedef union test_persistent_descriptor_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_PERSISTENT_DESCRIPTOR_BYTES];
} test_persistent_descriptor_memory;

typedef struct test_allocation_plan {
    rome2_100f1bb0_owned_grant_result result;
    rome2_100f1bb0_owned_grant grant;
} test_allocation_plan;

typedef struct test_trace {
    uint32_t events[TEST_MAX_EVENTS];
    uint32_t event_count;
    uint32_t bad_observations;
    uint32_t parent_count;
    uint32_t prefix_count;
    uint32_t suffix_count;
    uint32_t allocate_calls;
    uint32_t release_calls;
    uint32_t hook_calls;
    uint32_t expected_length;
    uint32_t expected_allocation_bytes;
    uint32_t mutate_effects_after_first;
    uint32_t mutation_performed;
    test_allocation_plan temporary_plan;
    test_allocation_plan persistent_plan;
    rome2_guest_addr32 temporary_raw;
    rome2_guest_addr32 persistent_raw;
    rome2_100ed3c0_nonempty_effects *caller_effects;
    rome2_100f1bb0_owned_owner *temporary_owner;
    rome2_100f1bb0_owned_owner *persistent_owner;
    rome2_100f2750_first_use_lifecycle *lifecycle;
    rome2_100ed3c0_preloop_result *result;
} test_trace;

typedef struct test_fixture {
    test_frame_memory frame;
    test_text_memory text;
    test_selector_memory selector;
    test_heap_memory temporary_heap;
    test_persistent_descriptor_memory persistent_descriptor;
    test_heap_memory persistent_heap;
    rome2_guest_write_view frame_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view selector_view;
    rome2_guest_write_view temporary_heap_view;
    rome2_guest_write_view persistent_descriptor_view;
    rome2_guest_write_view persistent_heap_view;
    rome2_100ed3c0_nonempty_effects effects;
    rome2_100f1bb0_owned_owner temporary_owner;
    rome2_100f1bb0_owned_owner persistent_owner;
    rome2_100f2750_first_use_lifecycle lifecycle;
    rome2_100ed3c0_preloop_result result;
    rome2_guest_addr32 text_identity;
    uint32_t length_units;
    test_trace trace;
} test_fixture;

static test_fixture test_fixture_storage;
static test_fixture test_snapshot_storage;
static test_fixture test_expected_storage;
static uint32_t test_case_count;

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

static void test_write_u16_le(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static void test_write_triplet(uint8_t *bytes)
{
    test_write_u32_le(bytes, UINT32_C(0));
    test_write_u32_le(bytes + 4U, UINT32_C(0));
    test_write_u32_le(
        bytes + 8U, ROME2_PORT_100F2750_FIRST_USE_SENTINEL);
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) {
        return 0;
    }
    (void)fprintf(stderr,
        "100ed3c0 nonempty preloop runtime: %s: %s\n",
        case_name,
        detail);
    return 1;
}

static void test_begin_case(void)
{
    ++test_case_count;
}

static void test_append_event(test_trace *trace, uint32_t event)
{
    if (trace->event_count >= TEST_MAX_EVENTS) {
        ++trace->bad_observations;
        return;
    }
    trace->events[trace->event_count] = event;
    ++trace->event_count;
}

static int test_result_is_sentinel(
    const rome2_100ed3c0_preloop_result *result)
{
    return
        result->child_receiver.value == TEST_RESULT_SENTINEL &&
        result->child_packet.value == TEST_RESULT_SENTINEL &&
        result->child_argument.value == TEST_RESULT_SENTINEL &&
        result->next_original_pc == TEST_RESULT_SENTINEL;
}

static int test_owner_is_empty(const rome2_100f1bb0_owned_owner *owner)
{
    const rome2_100f1bb0_owned_owner empty_owner = {0};

    return memcmp(owner, &empty_owner, sizeof(*owner)) == 0;
}

static void test_evil_parent_emit(
    void *opaque_context,
    rome2_100ed3c0_nonempty_step step)
{
    test_trace *trace = (test_trace *)opaque_context;

    (void)step;
    ++trace->bad_observations;
}

static void test_evil_prefix_emit(
    void *opaque_context,
    rome2_100df270_prefix_step step)
{
    test_trace *trace = (test_trace *)opaque_context;

    (void)step;
    ++trace->bad_observations;
}

static void test_evil_suffix_emit(
    void *opaque_context,
    rome2_100df270_suffix_step step)
{
    test_trace *trace = (test_trace *)opaque_context;

    (void)step;
    ++trace->bad_observations;
}

static rome2_100f1bb0_owned_grant_result test_evil_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class,
    rome2_100f1bb0_owned_grant *grant_out)
{
    test_trace *trace = (test_trace *)opaque_context;

    (void)byte_count;
    (void)allocation_class;
    (void)grant_out;
    ++trace->bad_observations;
    return ROME2_100F1BB0_OWNED_GRANT_DENIED;
}

static void test_evil_release(
    void *opaque_context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    test_trace *trace = (test_trace *)opaque_context;

    (void)token;
    (void)raw_base;
    (void)byte_count;
    (void)allocation_class;
    ++trace->bad_observations;
}

static void test_evil_hook(
    void *opaque_context,
    rome2_guest_addr32 raw_base,
    uint32_t zero_argument)
{
    test_trace *trace = (test_trace *)opaque_context;

    (void)raw_base;
    (void)zero_argument;
    ++trace->bad_observations;
}

static void test_mutate_caller_effects(test_trace *trace)
{
    rome2_100ed3c0_nonempty_effects *effects = trace->caller_effects;

    effects->emit_step = test_evil_parent_emit;
    effects->child_prefix.emit_step = test_evil_prefix_emit;
    effects->child_prefix.created_mutex = UINT32_C(0);
    effects->child_prefix.last_error = UINT32_C(0xb7);
    effects->child_suffix.emit_step = test_evil_suffix_emit;
    effects->child_suffix.result_100e8240.value = UINT32_C(0);
    effects->child_suffix.first_selector_result.value = UINT32_C(0);
    effects->child_suffix.second_selector_result.value = UINT32_C(0);
    effects->temporary_owned.allocate = test_evil_allocate;
    effects->temporary_owned.release = test_evil_release;
    effects->temporary_owned.release_hook = test_evil_hook;
    effects->persistent_owned.allocate = test_evil_allocate;
    effects->persistent_owned.release = test_evil_release;
    effects->persistent_owned.release_hook = test_evil_hook;
    trace->mutation_performed = UINT32_C(1);
}

static void test_parent_emit(
    void *opaque_context,
    rome2_100ed3c0_nonempty_step step)
{
    test_trace *trace = (test_trace *)opaque_context;
    uint32_t expected_kind = trace->parent_count + UINT32_C(1);

    test_append_event(trace, TEST_EVENT_PARENT_BASE + (uint32_t)step.kind);
    if ((uint32_t)step.kind != expected_kind ||
        !test_result_is_sentinel(trace->result)) {
        ++trace->bad_observations;
    }
    if (step.kind == ROME2_100ED3C0_NONEMPTY_STEP_BUILD_OWNED_DESCRIPTOR) {
        if (step.argument_count != UINT32_C(3) ||
            step.argument0.kind !=
                ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY ||
            step.argument0.value !=
                TEST_FRAME_BASE +
                    ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET ||
            step.argument1.kind !=
                ROME2_100ED3C0_PRELOOP_VALUE_GUEST_IDENTITY ||
            step.argument1.value != TEST_TEXT_BASE + TEST_TEXT_OFFSET ||
            step.argument2.kind !=
                ROME2_100ED3C0_PRELOOP_VALUE_SCALAR ||
            step.argument2.value != trace->expected_length ||
            step.result_count != UINT32_C(1) ||
            step.result0.value != step.argument0.value) {
            ++trace->bad_observations;
        }
    }
    if (step.kind == ROME2_100ED3C0_NONEMPTY_STEP_RUN_100DF270 &&
        (step.argument_count != UINT32_C(3) ||
         step.argument0.value !=
            TEST_FRAME_BASE + ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET ||
         step.argument1.value !=
            TEST_FRAME_BASE + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET ||
         step.argument2.value !=
            TEST_FRAME_BASE + ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET)) {
        ++trace->bad_observations;
    }
    ++trace->parent_count;
    if (trace->mutate_effects_after_first != UINT32_C(0) &&
        trace->parent_count == UINT32_C(1)) {
        test_mutate_caller_effects(trace);
    }
}

static void test_prefix_emit(
    void *opaque_context,
    rome2_100df270_prefix_step step)
{
    static const rome2_100df270_prefix_step_kind expected[] = {
        ROME2_100DF270_PREFIX_STEP_LOAD_TITLE,
        ROME2_100DF270_PREFIX_STEP_LOAD_NAME,
        ROME2_100DF270_PREFIX_STEP_FORMAT_MUTEX_NAME,
        ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX,
        ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR,
        ROME2_100DF270_PREFIX_STEP_GET_MOUSE_TRAILS,
        ROME2_100DF270_PREFIX_STEP_SET_MOUSE_TRAILS
    };
    test_trace *trace = (test_trace *)opaque_context;

    test_append_event(trace, TEST_EVENT_PREFIX_BASE + (uint32_t)step.kind);
    if (trace->prefix_count >= sizeof(expected) / sizeof(expected[0]) ||
        (trace->prefix_count < sizeof(expected) / sizeof(expected[0]) &&
         step.kind != expected[trace->prefix_count]) ||
        !test_result_is_sentinel(trace->result)) {
        ++trace->bad_observations;
    }
    ++trace->prefix_count;
}

static void test_suffix_emit(
    void *opaque_context,
    rome2_100df270_suffix_step step)
{
    static const rome2_100df270_suffix_step_kind expected[] = {
        ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER,
        ROME2_100DF270_SUFFIX_STEP_CALL_100E8240,
        ROME2_100DF270_SUFFIX_STEP_CALL_100F2750,
        ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0,
        ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST,
        ROME2_100DF270_SUFFIX_STEP_CALL_101046D0,
        ROME2_100DF270_SUFFIX_STEP_CALL_101046D0,
        ROME2_100DF270_SUFFIX_STEP_CALL_101046D0,
        ROME2_100DF270_SUFFIX_STEP_CALL_101046D0,
        ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND,
        ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER
    };
    test_trace *trace = (test_trace *)opaque_context;

    test_append_event(trace, TEST_EVENT_SUFFIX_BASE + (uint32_t)step.kind);
    if (trace->suffix_count >= sizeof(expected) / sizeof(expected[0]) ||
        (trace->suffix_count < sizeof(expected) / sizeof(expected[0]) &&
         step.kind != expected[trace->suffix_count]) ||
        !test_result_is_sentinel(trace->result)) {
        ++trace->bad_observations;
    }
    if (step.kind == ROME2_100DF270_SUFFIX_STEP_CALL_100F2750 &&
        (!test_owner_is_empty(trace->persistent_owner) ||
         trace->lifecycle->phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL)) {
        ++trace->bad_observations;
    }
    if (step.kind == ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0 &&
        (trace->persistent_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
         trace->lifecycle->phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE)) {
        ++trace->bad_observations;
    }
    ++trace->suffix_count;
}

static rome2_100f1bb0_owned_grant_result test_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class,
    rome2_100f1bb0_owned_grant *grant_out)
{
    test_trace *trace = (test_trace *)opaque_context;
    const test_allocation_plan *plan;

    if (trace->allocate_calls == UINT32_C(0)) {
        plan = &trace->temporary_plan;
        test_append_event(trace, TEST_EVENT_ALLOCATE_TEMPORARY);
        if (!test_owner_is_empty(trace->temporary_owner) ||
            !test_owner_is_empty(trace->persistent_owner) ||
            trace->lifecycle->phase !=
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL) {
            ++trace->bad_observations;
        }
    } else {
        plan = &trace->persistent_plan;
        test_append_event(trace, TEST_EVENT_ALLOCATE_PERSISTENT);
        if (trace->temporary_owner->phase !=
                ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
            !test_owner_is_empty(trace->persistent_owner) ||
            trace->lifecycle->phase !=
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL) {
            ++trace->bad_observations;
        }
    }
    if (trace->allocate_calls >= UINT32_C(2) ||
        byte_count != trace->expected_allocation_bytes ||
        allocation_class != ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS ||
        grant_out->token != UINT64_C(0) ||
        grant_out->raw_base.value != UINT32_C(0) ||
        grant_out->reserved != UINT32_C(0) ||
        !test_result_is_sentinel(trace->result)) {
        ++trace->bad_observations;
    }
    *grant_out = plan->grant;
    ++trace->allocate_calls;
    return plan->result;
}

static void test_release(
    void *opaque_context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    test_trace *trace = (test_trace *)opaque_context;
    int is_temporary =
        raw_base.value == trace->temporary_plan.grant.raw_base.value;

    test_append_event(trace, is_temporary
        ? TEST_EVENT_RELEASE_TEMPORARY
        : TEST_EVENT_RELEASE_PERSISTENT);
    if (byte_count != trace->expected_allocation_bytes ||
        allocation_class != ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS ||
        token == UINT64_C(0) ||
        !test_result_is_sentinel(trace->result)) {
        ++trace->bad_observations;
    }
    if (is_temporary && trace->temporary_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED &&
        trace->temporary_owner->phase != UINT32_C(0)) {
        ++trace->bad_observations;
    }
    if (!is_temporary &&
        trace->persistent_owner->phase ==
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
        trace->allocate_calls == UINT32_C(0)) {
        ++trace->bad_observations;
    }
    ++trace->release_calls;
}

static void test_release_hook(
    void *opaque_context,
    rome2_guest_addr32 raw_base,
    uint32_t zero_argument)
{
    test_trace *trace = (test_trace *)opaque_context;
    int is_temporary =
        raw_base.value == trace->temporary_plan.grant.raw_base.value;

    test_append_event(trace, is_temporary
        ? TEST_EVENT_HOOK_TEMPORARY
        : TEST_EVENT_HOOK_PERSISTENT);
    if (zero_argument != UINT32_C(0) || trace->release_calls == UINT32_C(0) ||
        !test_result_is_sentinel(trace->result)) {
        ++trace->bad_observations;
    }
    ++trace->hook_calls;
}

static uint32_t test_raw_offset_for_residue(
    uint32_t guest_base,
    uint32_t base_offset,
    uint32_t residue)
{
    uint32_t raw = guest_base + base_offset;

    return base_offset + ((residue - (raw & UINT32_C(3))) & UINT32_C(3));
}

static void test_reset_trace(test_fixture *fixture)
{
    test_trace *trace = &fixture->trace;

    memset(trace->events, 0, sizeof(trace->events));
    trace->event_count = UINT32_C(0);
    trace->bad_observations = UINT32_C(0);
    trace->parent_count = UINT32_C(0);
    trace->prefix_count = UINT32_C(0);
    trace->suffix_count = UINT32_C(0);
    trace->allocate_calls = UINT32_C(0);
    trace->release_calls = UINT32_C(0);
    trace->hook_calls = UINT32_C(0);
    trace->mutation_performed = UINT32_C(0);
}

static void test_init_fixture(
    test_fixture *fixture,
    uint32_t length_units,
    uint32_t temporary_residue,
    uint32_t persistent_residue,
    int mutate_effects)
{
    rome2_100f1bb0_owned_status status;
    uint32_t index;
    uint32_t raw_offset;
    uint8_t *persistent_descriptor;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->frame.bytes, 0xa7, sizeof(fixture->frame.bytes));
    memset(fixture->text.bytes, 0xb8, sizeof(fixture->text.bytes));
    memset(fixture->selector.bytes, 0xc9, sizeof(fixture->selector.bytes));
    memset(fixture->temporary_heap.bytes, 0xda,
        sizeof(fixture->temporary_heap.bytes));
    memset(fixture->persistent_descriptor.bytes, 0xeb,
        sizeof(fixture->persistent_descriptor.bytes));
    memset(fixture->persistent_heap.bytes, 0xfc,
        sizeof(fixture->persistent_heap.bytes));

    fixture->frame_view.host_base = fixture->frame.bytes;
    fixture->frame_view.guest_base = TEST_FRAME_BASE;
    fixture->frame_view.byte_count = sizeof(fixture->frame.bytes);
    fixture->text_view.host_base = fixture->text.bytes;
    fixture->text_view.guest_base = TEST_TEXT_BASE;
    fixture->text_view.byte_count = sizeof(fixture->text.bytes);
    fixture->selector_view.host_base = fixture->selector.bytes;
    fixture->selector_view.guest_base = TEST_SELECTOR_BASE;
    fixture->selector_view.byte_count = sizeof(fixture->selector.bytes);
    fixture->temporary_heap_view.host_base = fixture->temporary_heap.bytes;
    fixture->temporary_heap_view.guest_base = TEST_TEMPORARY_HEAP_BASE;
    fixture->temporary_heap_view.byte_count =
        sizeof(fixture->temporary_heap.bytes);
    fixture->persistent_descriptor_view.host_base =
        fixture->persistent_descriptor.bytes;
    fixture->persistent_descriptor_view.guest_base =
        TEST_PERSISTENT_DESCRIPTOR_BASE;
    fixture->persistent_descriptor_view.byte_count =
        sizeof(fixture->persistent_descriptor.bytes);
    fixture->persistent_heap_view.host_base = fixture->persistent_heap.bytes;
    fixture->persistent_heap_view.guest_base = TEST_PERSISTENT_HEAP_BASE;
    fixture->persistent_heap_view.byte_count =
        sizeof(fixture->persistent_heap.bytes);

    fixture->length_units = length_units;
    fixture->text_identity.value = TEST_TEXT_BASE + TEST_TEXT_OFFSET;
    for (index = UINT32_C(0); index < length_units; ++index) {
        uint16_t unit = (uint16_t)(UINT16_C(0x0101) +
            (uint16_t)(index % UINT32_C(0x7e00)));
        test_write_u16_le(
            fixture->text.bytes + TEST_TEXT_OFFSET + index * UINT32_C(2),
            unit);
    }
    test_write_u16_le(
        fixture->text.bytes + TEST_TEXT_OFFSET + length_units * UINT32_C(2),
        UINT16_C(0));
    test_write_u32_le(
        fixture->selector.bytes + TEST_FIRST_SELECTOR_OFFSET,
        UINT32_C(0));
    test_write_u32_le(
        fixture->selector.bytes + TEST_SECOND_SELECTOR_OFFSET,
        UINT32_C(0x12345678));

    persistent_descriptor = fixture->persistent_descriptor.bytes +
        (ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
            TEST_PERSISTENT_DESCRIPTOR_BASE);
    test_write_triplet(persistent_descriptor);

    fixture->effects.emit_step = test_parent_emit;
    fixture->effects.context = &fixture->trace;
    fixture->effects.context_byte_count = sizeof(fixture->trace);
    fixture->effects.child_prefix.emit_step = test_prefix_emit;
    fixture->effects.child_prefix.context = &fixture->trace;
    fixture->effects.child_prefix_context_byte_count = sizeof(fixture->trace);
    fixture->effects.child_prefix.created_mutex = TEST_CREATED_MUTEX;
    fixture->effects.child_prefix.last_error = UINT32_C(0);
    fixture->effects.child_suffix.emit_step = test_suffix_emit;
    fixture->effects.child_suffix.context = &fixture->trace;
    fixture->effects.child_suffix_context_byte_count = sizeof(fixture->trace);
    fixture->effects.child_suffix.result_100e8240.value =
        ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD;
    fixture->effects.child_suffix.first_selector_result.value =
        TEST_SELECTOR_BASE + TEST_FIRST_SELECTOR_OFFSET;
    fixture->effects.child_suffix.second_selector_result.value =
        TEST_SELECTOR_BASE + TEST_SECOND_SELECTOR_OFFSET;
    fixture->effects.temporary_owned.allocate = test_allocate;
    fixture->effects.temporary_owned.release = test_release;
    fixture->effects.temporary_owned.release_hook = test_release_hook;
    fixture->effects.temporary_owned.context = &fixture->trace;
    fixture->effects.temporary_owned.context_byte_count = sizeof(fixture->trace);
    fixture->effects.persistent_owned = fixture->effects.temporary_owned;

    fixture->result.child_receiver.value = TEST_RESULT_SENTINEL;
    fixture->result.child_packet.value = TEST_RESULT_SENTINEL;
    fixture->result.child_argument.value = TEST_RESULT_SENTINEL;
    fixture->result.next_original_pc = TEST_RESULT_SENTINEL;

    fixture->trace.expected_length = length_units;
    fixture->trace.expected_allocation_bytes =
        length_units * UINT32_C(2) + UINT32_C(10);
    fixture->trace.mutate_effects_after_first = mutate_effects != 0
        ? UINT32_C(1)
        : UINT32_C(0);
    fixture->trace.caller_effects = &fixture->effects;
    fixture->trace.temporary_owner = &fixture->temporary_owner;
    fixture->trace.persistent_owner = &fixture->persistent_owner;
    fixture->trace.lifecycle = &fixture->lifecycle;
    fixture->trace.result = &fixture->result;

    raw_offset = test_raw_offset_for_residue(
        TEST_TEMPORARY_HEAP_BASE,
        TEST_TEMPORARY_RAW_OFFSET,
        temporary_residue);
    fixture->trace.temporary_raw.value =
        TEST_TEMPORARY_HEAP_BASE + raw_offset;
    fixture->trace.temporary_plan.result =
        ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    fixture->trace.temporary_plan.grant.token = TEST_TEMPORARY_TOKEN;
    fixture->trace.temporary_plan.grant.raw_base =
        fixture->trace.temporary_raw;
    fixture->trace.temporary_plan.grant.reserved = UINT32_C(0);

    raw_offset = test_raw_offset_for_residue(
        TEST_PERSISTENT_HEAP_BASE,
        TEST_PERSISTENT_RAW_OFFSET,
        persistent_residue);
    fixture->trace.persistent_raw.value =
        TEST_PERSISTENT_HEAP_BASE + raw_offset;
    fixture->trace.persistent_plan.result =
        ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    fixture->trace.persistent_plan.grant.token = TEST_PERSISTENT_TOKEN;
    fixture->trace.persistent_plan.grant.raw_base =
        fixture->trace.persistent_raw;
    fixture->trace.persistent_plan.grant.reserved = UINT32_C(0);

    status = rome2_port_100f2750_register_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    if (status != ROME2_100F1BB0_OWNED_OK) {
        (void)fprintf(stderr,
            "100ed3c0 nonempty preloop runtime: fixture registration failed\n");
        ++fixture->trace.bad_observations;
    }
    test_reset_trace(fixture);
}

static rome2_100f1bb0_owned_status test_call_parent(
    test_fixture *fixture,
    uint32_t text_max_units)
{
    return rome2_port_100ed3c0_run_nonempty_preloop(
        &fixture->frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE},
        TEST_ARGUMENT1,
        &fixture->text_view,
        fixture->text_identity,
        text_max_units,
        &fixture->selector_view,
        &fixture->temporary_heap_view,
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects,
        &fixture->temporary_owner,
        &fixture->persistent_owner,
        &fixture->lifecycle,
        &fixture->result);
}

static void test_build_parent_success_events(
    uint32_t *events,
    uint32_t *count_out)
{
    static const uint32_t prefix_kinds[] = {1U, 2U, 3U, 4U, 5U, 9U, 10U};
    static const uint32_t suffix_tail[] = {4U, 5U, 6U, 6U, 6U, 6U, 7U, 8U};
    uint32_t count = UINT32_C(0);
    uint32_t index;

    for (index = UINT32_C(1); index <= UINT32_C(7); ++index) {
        events[count++] = TEST_EVENT_PARENT_BASE + index;
    }
    events[count++] = TEST_EVENT_ALLOCATE_TEMPORARY;
    events[count++] = TEST_EVENT_PARENT_BASE + UINT32_C(8);
    for (index = UINT32_C(0);
            index < sizeof(prefix_kinds) / sizeof(prefix_kinds[0]); ++index) {
        events[count++] = TEST_EVENT_PREFIX_BASE + prefix_kinds[index];
    }
    events[count++] = TEST_EVENT_SUFFIX_BASE + UINT32_C(1);
    events[count++] = TEST_EVENT_SUFFIX_BASE + UINT32_C(2);
    events[count++] = TEST_EVENT_SUFFIX_BASE + UINT32_C(3);
    events[count++] = TEST_EVENT_ALLOCATE_PERSISTENT;
    for (index = UINT32_C(0);
            index < sizeof(suffix_tail) / sizeof(suffix_tail[0]); ++index) {
        events[count++] = TEST_EVENT_SUFFIX_BASE + suffix_tail[index];
    }
    events[count++] = TEST_EVENT_PARENT_BASE + UINT32_C(9);
    events[count++] = TEST_EVENT_RELEASE_TEMPORARY;
    events[count++] = TEST_EVENT_HOOK_TEMPORARY;
    *count_out = count;
}

static void test_build_frame_expected(
    test_fixture *expected,
    uint32_t temporary_payload)
{
    uint8_t *frame = expected->frame.bytes;
    uint8_t *receiver = frame + ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET;
    uint32_t receiver_guest =
        TEST_FRAME_BASE + ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET;

    test_write_u32_le(frame + UINT32_C(0x00), UINT32_C(0));
    test_write_triplet(frame + UINT32_C(0x04));
    test_write_triplet(frame + UINT32_C(0x10));
    test_write_u32_le(frame + UINT32_C(0x1c), TEST_ARGUMENT1);
    frame[UINT32_C(0x20)] = UINT8_C(0);
    test_write_u32_le(frame + UINT32_C(0x24), UINT32_C(0));
    test_write_u32_le(frame + UINT32_C(0x28), expected->length_units);
    test_write_u32_le(frame + UINT32_C(0x2c), expected->length_units);
    test_write_u32_le(frame + UINT32_C(0x30), temporary_payload);
    test_write_u32_le(frame + UINT32_C(0x34), TEST_ARGUMENT1);
    test_write_u32_le(frame + UINT32_C(0x38), UINT32_C(0));
    test_write_triplet(frame + UINT32_C(0x3c));
    test_write_triplet(frame + UINT32_C(0x48));
    test_write_u32_le(frame + UINT32_C(0x54), TEST_ARGUMENT1);
    frame[UINT32_C(0x58)] = UINT8_C(0);
    test_write_u32_le(frame + UINT32_C(0x5c), UINT32_C(0));
    frame[UINT32_C(0x60)] = UINT8_C(0);

    test_write_u32_le(receiver + UINT32_C(0x000), UINT32_C(0x1173f2f4));
    test_write_u32_le(receiver + UINT32_C(0x004), TEST_ARGUMENT1);
    test_write_u32_le(receiver + UINT32_C(0x808), TEST_CREATED_MUTEX);
    test_write_u32_le(receiver + UINT32_C(0x80c), UINT32_C(0x11741e08));
    test_write_u32_le(receiver + UINT32_C(0x810), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x814), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x81c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x820), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x824), TEST_ARGUMENT1);
    test_write_u32_le(receiver + UINT32_C(0x828), UINT32_C(0));
    test_write_triplet(receiver + UINT32_C(0x82c));
    test_write_triplet(receiver + UINT32_C(0x838));
    test_write_u32_le(receiver + UINT32_C(0x844), TEST_ARGUMENT1);
    receiver[UINT32_C(0x848)] = UINT8_C(0);
    test_write_u32_le(receiver + UINT32_C(0x84c), UINT32_C(0));
    receiver[UINT32_C(0x850)] = UINT8_C(0);
    test_write_u32_le(receiver + UINT32_C(0x854), receiver_guest);
    test_write_u32_le(receiver + UINT32_C(0x858), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x85c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x860), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x864), receiver_guest);
    test_write_u32_le(receiver + UINT32_C(0x868), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x86c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x870), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x874), UINT32_C(0x1173dc18));
    test_write_u32_le(receiver + UINT32_C(0x878), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x87c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x880), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x888), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x88c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x894), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x898), UINT32_MAX);
    test_write_u32_le(receiver + UINT32_C(0x89c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x8a0), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x8a4), UINT32_C(0));
}

static void test_build_allocation_expected(
    uint8_t *heap,
    uint32_t heap_base,
    rome2_guest_addr32 raw,
    const test_fixture *source)
{
    uint32_t payload = (raw.value + UINT32_C(8)) & ~UINT32_C(3);
    uint32_t header_offset = payload - UINT32_C(4) - heap_base;
    uint32_t payload_offset = payload - heap_base;
    uint32_t text_offset = source->text_identity.value - TEST_TEXT_BASE;

    test_write_u32_le(heap + header_offset, raw.value);
    memcpy(
        heap + payload_offset,
        source->text.bytes + text_offset,
        source->length_units * UINT32_C(2));
    test_write_u16_le(
        heap + payload_offset + source->length_units * UINT32_C(2),
        UINT16_C(0));
}

static void test_build_success_expected(test_fixture *expected)
{
    uint32_t temporary_payload =
        (expected->trace.temporary_raw.value + UINT32_C(8)) & ~UINT32_C(3);
    uint32_t persistent_payload =
        (expected->trace.persistent_raw.value + UINT32_C(8)) & ~UINT32_C(3);
    uint8_t *persistent_descriptor = expected->persistent_descriptor.bytes +
        (ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
            TEST_PERSISTENT_DESCRIPTOR_BASE);

    test_build_frame_expected(expected, temporary_payload);
    test_build_allocation_expected(
        expected->temporary_heap.bytes,
        TEST_TEMPORARY_HEAP_BASE,
        expected->trace.temporary_raw,
        expected);
    test_build_allocation_expected(
        expected->persistent_heap.bytes,
        TEST_PERSISTENT_HEAP_BASE,
        expected->trace.persistent_raw,
        expected);
    test_write_u32_le(persistent_descriptor, expected->length_units);
    test_write_u32_le(persistent_descriptor + 4U, expected->length_units);
    test_write_u32_le(persistent_descriptor + 8U, persistent_payload);
    test_write_u32_le(
        expected->selector.bytes + TEST_SECOND_SELECTOR_OFFSET,
        ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER);
}

static int test_expect_success_state(
    const char *case_name,
    const test_fixture *fixture,
    int expect_mutation)
{
    const test_fixture *expected = &test_expected_storage;
    uint32_t expected_events[TEST_MAX_EVENTS] = {0};
    uint32_t expected_count = UINT32_C(0);
    uint32_t temporary_payload =
        (fixture->trace.temporary_raw.value + UINT32_C(8)) & ~UINT32_C(3);
    uint32_t persistent_payload =
        (fixture->trace.persistent_raw.value + UINT32_C(8)) & ~UINT32_C(3);
    int failed = 0;

    test_build_parent_success_events(expected_events, &expected_count);
    failed |= test_expect(fixture->trace.event_count == expected_count &&
            memcmp(fixture->trace.events, expected_events,
                expected_count * sizeof(expected_events[0])) == 0,
        case_name, "the total callback order changed");
    failed |= test_expect(fixture->trace.parent_count == UINT32_C(9) &&
            fixture->trace.prefix_count == UINT32_C(7) &&
            fixture->trace.suffix_count == UINT32_C(11) &&
            fixture->trace.allocate_calls == UINT32_C(2) &&
            fixture->trace.release_calls == UINT32_C(1) &&
            fixture->trace.hook_calls == UINT32_C(1) &&
            fixture->trace.bad_observations == UINT32_C(0),
        case_name, "callback counts or callback-time invariants changed");
    failed |= test_expect(memcmp(&fixture->frame, &expected->frame,
            sizeof(fixture->frame)) == 0,
        case_name, "the final frame bytes changed");
    failed |= test_expect(memcmp(&fixture->text, &expected->text,
            sizeof(fixture->text)) == 0,
        case_name, "the source text changed");
    failed |= test_expect(memcmp(&fixture->selector, &expected->selector,
            sizeof(fixture->selector)) == 0,
        case_name, "the selector marker result changed");
    failed |= test_expect(memcmp(&fixture->temporary_heap,
            &expected->temporary_heap, sizeof(fixture->temporary_heap)) == 0,
        case_name, "the temporary owned allocation changed");
    failed |= test_expect(memcmp(&fixture->persistent_descriptor,
            &expected->persistent_descriptor,
            sizeof(fixture->persistent_descriptor)) == 0,
        case_name, "the persistent descriptor changed");
    failed |= test_expect(memcmp(&fixture->persistent_heap,
            &expected->persistent_heap, sizeof(fixture->persistent_heap)) == 0,
        case_name, "the persistent owned allocation changed");
    failed |= test_expect(
        fixture->temporary_owner.token == TEST_TEMPORARY_TOKEN &&
        fixture->temporary_owner.raw_base.value ==
            fixture->trace.temporary_raw.value &&
        fixture->temporary_owner.payload.value == temporary_payload &&
        fixture->temporary_owner.allocation_bytes ==
            fixture->trace.expected_allocation_bytes &&
        fixture->temporary_owner.length_units == fixture->length_units &&
        fixture->temporary_owner.phase ==
            ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED,
        case_name, "the temporary owner did not finish CONSUMED");
    failed |= test_expect(
        fixture->persistent_owner.token == TEST_PERSISTENT_TOKEN &&
        fixture->persistent_owner.raw_base.value ==
            fixture->trace.persistent_raw.value &&
        fixture->persistent_owner.payload.value == persistent_payload &&
        fixture->persistent_owner.allocation_bytes ==
            fixture->trace.expected_allocation_bytes &&
        fixture->persistent_owner.length_units == fixture->length_units &&
        fixture->persistent_owner.phase ==
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
        fixture->lifecycle.phase ==
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE,
        case_name, "the persistent owner/lifecycle handoff changed");
    failed |= test_expect(
        fixture->result.child_receiver.value ==
            TEST_FRAME_BASE + ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET &&
        fixture->result.child_packet.value ==
            TEST_FRAME_BASE + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET &&
        fixture->result.child_argument.value ==
            TEST_FRAME_BASE + ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET &&
        fixture->result.next_original_pc ==
            ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC,
        case_name, "the final parent result changed");
    failed |= test_expect(
        fixture->trace.mutation_performed ==
            (expect_mutation != 0 ? UINT32_C(1) : UINT32_C(0)),
        case_name, "the effects snapshot adversary did not run as expected");
    return failed;
}

static int test_teardown_after_success(test_fixture *fixture)
{
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_reset_trace(fixture);
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK,
        "persistent teardown", "the first teardown status changed");
    failed |= test_expect(fixture->trace.event_count == UINT32_C(2) &&
            fixture->trace.events[0] == TEST_EVENT_RELEASE_PERSISTENT &&
            fixture->trace.events[1] == TEST_EVENT_HOOK_PERSISTENT &&
            fixture->persistent_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED,
        "persistent teardown", "the teardown order or final phases changed");

    test_begin_case();
    test_reset_trace(fixture);
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_ALREADY_CONSUMED &&
            fixture->trace.event_count == UINT32_C(0),
        "persistent teardown repeat",
        "a repeated teardown emitted an effect or changed status");
    return failed;
}

static int test_run_success(
    const char *case_name,
    uint32_t length_units,
    uint32_t temporary_residue,
    uint32_t persistent_residue,
    int mutate_effects,
    int exercise_teardown)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, length_units, temporary_residue,
        persistent_residue, mutate_effects);
    test_snapshot_storage = *fixture;
    test_expected_storage = test_snapshot_storage;
    test_build_success_expected(&test_expected_storage);
    status = test_call_parent(fixture, length_units + UINT32_C(1));
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK,
        case_name, "the success status changed");
    failed |= test_expect_success_state(case_name, fixture, mutate_effects);
    if (exercise_teardown != 0) {
        failed |= test_teardown_after_success(fixture);
    }
    return failed;
}

static int test_success_matrix(void)
{
    char case_name[96];
    uint32_t temporary_residue;
    uint32_t persistent_residue;
    int failed = 0;

    for (temporary_residue = UINT32_C(0);
            temporary_residue < UINT32_C(4); ++temporary_residue) {
        for (persistent_residue = UINT32_C(0);
                persistent_residue < UINT32_C(4); ++persistent_residue) {
            (void)snprintf(case_name, sizeof(case_name),
                "residue pair %u/%u",
                (unsigned)temporary_residue,
                (unsigned)persistent_residue);
            failed |= test_run_success(case_name, UINT32_C(3),
                temporary_residue, persistent_residue, 0, 0);
        }
    }
    failed |= test_run_success(
        "minimum N=1", UINT32_C(1), UINT32_C(2), UINT32_C(3), 0, 1);
    failed |= test_run_success(
        "maximum N=32767", UINT32_C(32767), UINT32_C(3), UINT32_C(2), 0, 0);
    failed |= test_run_success(
        "effects snapshot", UINT32_C(4), UINT32_C(1), UINT32_C(0), 1, 0);
    return failed;
}

static int test_expect_tier0_preserved(
    const char *case_name,
    const test_fixture *fixture,
    rome2_100f1bb0_owned_status status,
    rome2_100f1bb0_owned_status expected_status)
{
    const test_fixture *before = &test_snapshot_storage;
    int failed = 0;

    failed |= test_expect(status == expected_status,
        case_name, "the Tier-0 status changed");
    failed |= test_expect(fixture->trace.event_count == UINT32_C(0) &&
            fixture->trace.bad_observations == UINT32_C(0),
        case_name, "a Tier-0 failure emitted an external effect");
    failed |= test_expect(memcmp(&fixture->frame, &before->frame,
            sizeof(fixture->frame)) == 0 &&
        memcmp(&fixture->text, &before->text, sizeof(fixture->text)) == 0 &&
        memcmp(&fixture->selector, &before->selector,
            sizeof(fixture->selector)) == 0 &&
        memcmp(&fixture->temporary_heap, &before->temporary_heap,
            sizeof(fixture->temporary_heap)) == 0 &&
        memcmp(&fixture->persistent_descriptor,
            &before->persistent_descriptor,
            sizeof(fixture->persistent_descriptor)) == 0 &&
        memcmp(&fixture->persistent_heap, &before->persistent_heap,
            sizeof(fixture->persistent_heap)) == 0,
        case_name, "a Tier-0 failure changed guest bytes");
    failed |= test_expect(memcmp(&fixture->temporary_owner,
            &before->temporary_owner, sizeof(fixture->temporary_owner)) == 0 &&
        memcmp(&fixture->persistent_owner, &before->persistent_owner,
            sizeof(fixture->persistent_owner)) == 0 &&
        memcmp(&fixture->lifecycle, &before->lifecycle,
            sizeof(fixture->lifecycle)) == 0 &&
        memcmp(&fixture->result, &before->result,
            sizeof(fixture->result)) == 0,
        case_name, "a Tier-0 failure changed ownership or result controls");
    return failed;
}

static int test_tier0_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint8_t *persistent_descriptor;
    int failed = 0;

#define TEST_TIER0_CASE(label_, mutation_, max_units_, expected_) do { \
        test_begin_case(); \
        test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), \
            UINT32_C(1), 0); \
        mutation_; \
        test_snapshot_storage = *fixture; \
        status = test_call_parent(fixture, (max_units_)); \
        failed |= test_expect_tier0_preserved( \
            (label_), fixture, status, (expected_)); \
    } while (0)

    TEST_TIER0_CASE(
        "max-units one",
        (void)0,
        UINT32_C(1),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TIER0_CASE(
        "temporary owner nonempty",
        fixture->temporary_owner.phase =
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE,
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_TIER0_CASE(
        "lifecycle not registered",
        fixture->lifecycle.phase =
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_EMPTY,
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    persistent_descriptor = fixture->persistent_descriptor.bytes +
        (ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
            TEST_PERSISTENT_DESCRIPTOR_BASE);
    TEST_TIER0_CASE(
        "persistent descriptor dirty",
        (persistent_descriptor = fixture->persistent_descriptor.bytes +
            (ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
                TEST_PERSISTENT_DESCRIPTOR_BASE),
         test_write_u32_le(persistent_descriptor, UINT32_C(1))),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    TEST_TIER0_CASE(
        "wrong suffix crash identity",
        fixture->effects.child_suffix.result_100e8240.value = UINT32_C(1),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TIER0_CASE(
        "heap backing alias",
        (fixture->persistent_heap_view.host_base =
            fixture->temporary_heap_view.host_base,
         fixture->persistent_heap_view.guest_base =
            fixture->temporary_heap_view.guest_base),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TIER0_CASE(
        "partial callback-context alias",
        (fixture->effects.child_prefix.context =
            (uint8_t *)&fixture->trace + 1U,
         fixture->effects.child_prefix_context_byte_count =
            sizeof(fixture->trace) - UINT64_C(1)),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TIER0_CASE(
        "null selector result",
        fixture->effects.child_suffix.first_selector_result.value =
            UINT32_C(0),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_NULL_ADDRESS);
    TEST_TIER0_CASE(
        "max-units above bound",
        (void)0,
        ROME2_PORT_100F1BB0_OWNED_MAX_UNITS + UINT32_C(1),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TIER0_CASE(
        "empty text",
        test_write_u16_le(
            fixture->text.bytes + TEST_TEXT_OFFSET, UINT16_C(0)),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_TIER0_CASE(
        "unterminated text budget",
        test_write_u16_le(
            fixture->text.bytes + TEST_TEXT_OFFSET + UINT32_C(6),
            UINT16_C(0x2222)),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    TEST_TIER0_CASE(
        "temporary heap too short",
        fixture->temporary_heap_view.byte_count = UINT64_C(15),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    TEST_TIER0_CASE(
        "persistent heap too short",
        fixture->persistent_heap_view.byte_count = UINT64_C(15),
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    TEST_TIER0_CASE(
        "persistent owner nonempty",
        fixture->persistent_owner.phase =
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE,
        UINT32_C(4),
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

#undef TEST_TIER0_CASE
    (void)persistent_descriptor;
    return failed;
}

static void test_build_prebuild_frame_expected(test_fixture *expected)
{
    uint8_t *frame = expected->frame.bytes;

    test_write_u32_le(frame + UINT32_C(0x00), UINT32_C(0));
    test_write_triplet(frame + UINT32_C(0x04));
    test_write_triplet(frame + UINT32_C(0x10));
    test_write_u32_le(frame + UINT32_C(0x1c), TEST_ARGUMENT1);
    frame[UINT32_C(0x20)] = UINT8_C(0);
    test_write_u32_le(frame + UINT32_C(0x24), UINT32_C(0));
    test_write_u32_le(frame + UINT32_C(0x34), TEST_ARGUMENT1);
    test_write_u32_le(frame + UINT32_C(0x38), UINT32_C(0));
    test_write_triplet(frame + UINT32_C(0x3c));
    test_write_triplet(frame + UINT32_C(0x48));
    test_write_u32_le(frame + UINT32_C(0x54), TEST_ARGUMENT1);
    frame[UINT32_C(0x58)] = UINT8_C(0);
    test_write_u32_le(frame + UINT32_C(0x5c), UINT32_C(0));
    frame[UINT32_C(0x60)] = UINT8_C(0);
}

static int test_run_temporary_failure(
    const char *case_name,
    test_allocation_plan plan,
    rome2_100f1bb0_owned_status expected_status,
    int expect_release)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t expected_events[10] = {0};
    uint32_t expected_count = UINT32_C(0);
    uint32_t index;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), UINT32_C(1), 0);
    fixture->trace.temporary_plan = plan;
    test_snapshot_storage = *fixture;
    test_expected_storage = test_snapshot_storage;
    test_build_prebuild_frame_expected(&test_expected_storage);
    status = test_call_parent(fixture, UINT32_C(4));
    for (index = UINT32_C(1); index <= UINT32_C(7); ++index) {
        expected_events[expected_count++] = TEST_EVENT_PARENT_BASE + index;
    }
    expected_events[expected_count++] = TEST_EVENT_ALLOCATE_TEMPORARY;
    if (expect_release != 0) {
        expected_events[expected_count++] = TEST_EVENT_RELEASE_TEMPORARY;
    }
    failed |= test_expect(status == expected_status,
        case_name, "the temporary-build failure status changed");
    failed |= test_expect(fixture->trace.event_count == expected_count &&
            memcmp(fixture->trace.events, expected_events,
                expected_count * sizeof(expected_events[0])) == 0 &&
            fixture->trace.bad_observations == UINT32_C(0),
        case_name, "the temporary-build committed prefix changed");
    failed |= test_expect(memcmp(&fixture->frame,
            &test_expected_storage.frame, sizeof(fixture->frame)) == 0,
        case_name, "the temporary-build frame prefix changed");
    failed |= test_expect(memcmp(&fixture->temporary_heap,
            &test_snapshot_storage.temporary_heap,
            sizeof(fixture->temporary_heap)) == 0 &&
        memcmp(&fixture->persistent_descriptor,
            &test_snapshot_storage.persistent_descriptor,
            sizeof(fixture->persistent_descriptor)) == 0 &&
        memcmp(&fixture->persistent_heap,
            &test_snapshot_storage.persistent_heap,
            sizeof(fixture->persistent_heap)) == 0 &&
        memcmp(&fixture->selector, &test_snapshot_storage.selector,
            sizeof(fixture->selector)) == 0,
        case_name, "a temporary-build failure changed a later backing");
    failed |= test_expect(test_owner_is_empty(&fixture->temporary_owner) &&
            test_owner_is_empty(&fixture->persistent_owner) &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL &&
            test_result_is_sentinel(&fixture->result),
        case_name, "a temporary-build failure committed an owner or result");
    return failed;
}

static int test_temporary_failures(void)
{
    test_allocation_plan plan = {0};
    int failed = 0;

    plan.result = ROME2_100F1BB0_OWNED_GRANT_DENIED;
    failed |= test_run_temporary_failure(
        "temporary denial",
        plan,
        ROME2_100F1BB0_OWNED_ALLOCATION_DENIED,
        0);
    plan.grant.token = TEST_TEMPORARY_TOKEN;
    plan.grant.raw_base.value = TEST_TEMPORARY_HEAP_BASE + UINT32_C(32);
    failed |= test_run_temporary_failure(
        "temporary denial with token",
        plan,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID,
        1);

    plan.result = ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    plan.grant.token = UINT64_C(0);
    plan.grant.raw_base.value = TEST_TEMPORARY_HEAP_BASE + UINT32_C(32);
    plan.grant.reserved = UINT32_C(0);
    failed |= test_run_temporary_failure(
        "temporary granted without token",
        plan,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID,
        0);

    plan.grant.token = TEST_TEMPORARY_TOKEN;
    plan.grant.reserved = UINT32_C(1);
    failed |= test_run_temporary_failure(
        "temporary dirty grant",
        plan,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID,
        1);

    plan.grant.reserved = UINT32_C(0);
    plan.grant.raw_base.value = UINT32_C(0);
    failed |= test_run_temporary_failure(
        "temporary null raw",
        plan,
        ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID,
        1);

    plan.grant.raw_base.value = TEST_TEMPORARY_HEAP_BASE - UINT32_C(1);
    failed |= test_run_temporary_failure(
        "temporary raw below heap",
        plan,
        ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID,
        1);

    plan.grant.raw_base.value =
        TEST_TEMPORARY_HEAP_BASE + TEST_HEAP_BYTES - UINT32_C(15);
    failed |= test_run_temporary_failure(
        "temporary raw truncated",
        plan,
        ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID,
        1);
    return failed;
}

static void test_build_persistent_failure_events(
    uint32_t *events,
    uint32_t *count_out,
    int expect_release)
{
    static const uint32_t prefix_kinds[] = {1U, 2U, 3U, 4U, 5U, 9U, 10U};
    uint32_t count = UINT32_C(0);
    uint32_t index;

    for (index = UINT32_C(1); index <= UINT32_C(7); ++index) {
        events[count++] = TEST_EVENT_PARENT_BASE + index;
    }
    events[count++] = TEST_EVENT_ALLOCATE_TEMPORARY;
    events[count++] = TEST_EVENT_PARENT_BASE + UINT32_C(8);
    for (index = UINT32_C(0);
            index < sizeof(prefix_kinds) / sizeof(prefix_kinds[0]); ++index) {
        events[count++] = TEST_EVENT_PREFIX_BASE + prefix_kinds[index];
    }
    events[count++] = TEST_EVENT_SUFFIX_BASE + UINT32_C(1);
    events[count++] = TEST_EVENT_SUFFIX_BASE + UINT32_C(2);
    events[count++] = TEST_EVENT_SUFFIX_BASE + UINT32_C(3);
    events[count++] = TEST_EVENT_ALLOCATE_PERSISTENT;
    if (expect_release != 0) {
        events[count++] = TEST_EVENT_RELEASE_PERSISTENT;
    }
    *count_out = count;
}

static int test_cleanup_live_temporary(
    const char *case_name,
    test_fixture *fixture)
{
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_reset_trace(fixture);
    status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &fixture->frame_view,
        (rome2_guest_addr32){
            TEST_FRAME_BASE + ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET},
        &fixture->temporary_heap_view,
        &fixture->effects.temporary_owned,
        &fixture->temporary_owner);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK &&
            fixture->trace.event_count == UINT32_C(2) &&
            fixture->trace.events[0] == TEST_EVENT_RELEASE_TEMPORARY &&
            fixture->trace.events[1] == TEST_EVENT_HOOK_TEMPORARY &&
            fixture->temporary_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED,
        case_name, "explicit cleanup of the torn temporary owner failed");
    return failed;
}

static int test_run_persistent_failure(
    const char *case_name,
    test_allocation_plan plan,
    rome2_100f1bb0_owned_status expected_status,
    int expect_release,
    int exercise_sentinel_teardown)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t expected_events[TEST_MAX_EVENTS] = {0};
    uint32_t expected_count = UINT32_C(0);
    uint32_t temporary_payload;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), UINT32_C(1), 0);
    fixture->trace.persistent_plan = plan;
    test_snapshot_storage = *fixture;
    test_expected_storage = test_snapshot_storage;
    temporary_payload =
        (fixture->trace.temporary_raw.value + UINT32_C(8)) & ~UINT32_C(3);
    test_build_frame_expected(&test_expected_storage, temporary_payload);
    test_build_allocation_expected(
        test_expected_storage.temporary_heap.bytes,
        TEST_TEMPORARY_HEAP_BASE,
        fixture->trace.temporary_raw,
        &test_expected_storage);
    status = test_call_parent(fixture, UINT32_C(4));
    test_build_persistent_failure_events(
        expected_events, &expected_count, expect_release);
    failed |= test_expect(status == expected_status,
        case_name, "the delegated persistent failure status changed");
    failed |= test_expect(fixture->trace.event_count == expected_count &&
            memcmp(fixture->trace.events, expected_events,
                expected_count * sizeof(expected_events[0])) == 0 &&
            fixture->trace.bad_observations == UINT32_C(0),
        case_name, "the delegated persistent committed prefix changed");
    failed |= test_expect(memcmp(&fixture->frame,
            &test_expected_storage.frame, sizeof(fixture->frame)) == 0 &&
        memcmp(&fixture->temporary_heap,
            &test_expected_storage.temporary_heap,
            sizeof(fixture->temporary_heap)) == 0,
        case_name, "the live temporary state changed on delegated failure");
    failed |= test_expect(memcmp(&fixture->persistent_descriptor,
            &test_snapshot_storage.persistent_descriptor,
            sizeof(fixture->persistent_descriptor)) == 0 &&
        memcmp(&fixture->persistent_heap,
            &test_snapshot_storage.persistent_heap,
            sizeof(fixture->persistent_heap)) == 0 &&
        memcmp(&fixture->selector, &test_snapshot_storage.selector,
            sizeof(fixture->selector)) == 0,
        case_name, "a delegated failure committed persistent/marker bytes");
    failed |= test_expect(fixture->temporary_owner.phase ==
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
        test_owner_is_empty(&fixture->persistent_owner) &&
        fixture->lifecycle.phase ==
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL &&
        test_result_is_sentinel(&fixture->result),
        case_name, "a delegated failure committed the wrong ownership state");
    failed |= test_cleanup_live_temporary(case_name, fixture);
    if (exercise_sentinel_teardown != 0) {
        test_begin_case();
        test_reset_trace(fixture);
        status = rome2_port_100f2750_teardown_first_use_owned(
            &fixture->persistent_descriptor_view,
            &fixture->persistent_heap_view,
            &fixture->effects.persistent_owned,
            &fixture->persistent_owner,
            &fixture->lifecycle);
        failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK &&
                fixture->trace.event_count == UINT32_C(0) &&
                test_owner_is_empty(&fixture->persistent_owner) &&
                fixture->lifecycle.phase ==
                    ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED,
            "sentinel teardown after delegated failure",
            "the registered-sentinel no-effect teardown changed");
    }
    return failed;
}

static int test_persistent_failures(void)
{
    test_allocation_plan plan = {0};
    int failed = 0;

    plan.result = ROME2_100F1BB0_OWNED_GRANT_DENIED;
    failed |= test_run_persistent_failure(
        "persistent denial",
        plan,
        ROME2_100F1BB0_OWNED_ALLOCATION_DENIED,
        0,
        1);

    plan.grant.token = TEST_PERSISTENT_TOKEN;
    plan.grant.raw_base.value = TEST_PERSISTENT_HEAP_BASE + UINT32_C(64);
    failed |= test_run_persistent_failure(
        "persistent denial with token",
        plan,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID,
        1,
        0);

    plan.result = ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    plan.grant.token = TEST_TEMPORARY_TOKEN;
    plan.grant.reserved = UINT32_C(0);
    failed |= test_run_persistent_failure(
        "persistent token collision",
        plan,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID,
        0,
        0);

    plan.grant.token = UINT64_C(0);
    failed |= test_run_persistent_failure(
        "persistent granted without token",
        plan,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID,
        0,
        0);

    plan.grant.token = TEST_PERSISTENT_TOKEN;
    plan.grant.reserved = UINT32_C(1);
    failed |= test_run_persistent_failure(
        "persistent dirty grant",
        plan,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID,
        1,
        0);
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_success_matrix();
    failed |= test_tier0_failures();
    failed |= test_temporary_failures();
    failed |= test_persistent_failures();
    failed |= test_expect(test_case_count == TEST_EXPECTED_CASES,
        "case accounting", "the runtime matrix case count changed");
    if (failed != 0) {
        (void)fprintf(stderr,
            "100ed3c0 nonempty preloop runtime: FAIL (%u/%u cases)\n",
            (unsigned)test_case_count,
            (unsigned)TEST_EXPECTED_CASES);
        return 1;
    }
    (void)printf(
        "100ed3c0 nonempty preloop runtime: PASS (%u cases)\n",
        (unsigned)test_case_count);
    return 0;
}
