#include "ported_100edd70_caller_closure.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_FRAME_BYTES UINT32_C(0x90c)
#define TEST_TEXT_BYTES UINT32_C(65584)
#define TEST_SELECTOR_BYTES UINT32_C(16)
#define TEST_HEAP_BYTES UINT32_C(65664)
#define TEST_PERSISTENT_DESCRIPTOR_BYTES UINT32_C(128)
#define TEST_DISPATCH_BASE UINT32_C(0x11897860)
#define TEST_DISPATCH_BYTES \
    (ROME2_PORT_100ED471_FALLBACK_OBJECT + UINT32_C(4) - TEST_DISPATCH_BASE)
#define TEST_FRAME_BASE UINT32_C(0x22000001)
#define TEST_FRAME_ENDPOINT_BASE UINT32_C(0xfffff6f4)
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
#define TEST_ARGUMENT2 UINT32_C(0x2468ace0)
#define TEST_ARGUMENT4 UINT32_C(0x0badc0de)
#define TEST_CREATED_MUTEX UINT32_C(0x13579bdf)
#define TEST_TEMPORARY_TOKEN UINT64_C(0x1122334455667788)
#define TEST_PERSISTENT_TOKEN UINT64_C(0x8877665544332211)
#define TEST_TIMESTAMP_LOW UINT32_C(0x76543210)
#define TEST_TIMESTAMP_HIGH UINT32_C(0xfedcba98)
#define TEST_RESULT_BYTE UINT8_C(0xa5)
#define TEST_MAX_EVENTS UINT32_C(128)
#define TEST_EXPECTED_CASES UINT32_C(54)

#define TEST_EVENT_PARENT_BASE UINT32_C(0x100)
#define TEST_EVENT_PREFIX_BASE UINT32_C(0x200)
#define TEST_EVENT_SUFFIX_BASE UINT32_C(0x300)
#define TEST_EVENT_ALLOCATE_TEMPORARY UINT32_C(0x401)
#define TEST_EVENT_ALLOCATE_PERSISTENT UINT32_C(0x402)
#define TEST_EVENT_RELEASE_TEMPORARY UINT32_C(0x403)
#define TEST_EVENT_RELEASE_PERSISTENT UINT32_C(0x404)
#define TEST_EVENT_HOOK_TEMPORARY UINT32_C(0x405)
#define TEST_EVENT_HOOK_PERSISTENT UINT32_C(0x406)
#define TEST_EVENT_ORDINARY_BASE UINT32_C(0x500)
#define TEST_EVENT_CALLER_BASE UINT32_C(0x600)

_Static_assert(
    ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FRAME_BYTES == TEST_FRAME_BYTES,
    "the composition frame changed");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC ==
            ROME2_PORT_100ED471_START_PC &&
        ROME2_PORT_100ED471_RETURN_PC ==
            ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC,
    "the child seam or terminal boundary changed");
_Static_assert(
    ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_MISMATCH_PRELOOP_EVENTS ==
            UINT32_C(31) &&
        ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FIXED_TAIL_EVENTS ==
            UINT32_C(11),
    "the total-order cardinality constants changed");
_Static_assert(
    TEST_FRAME_ENDPOINT_BASE + TEST_FRAME_BYTES == UINT32_C(0),
    "the exact 32-bit frame endpoint fixture changed");
_Static_assert(
    ROME2_INVALID_PARAMETER_INSTALL_HANDLER == UINT32_C(0) &&
        ROME2_INVALID_PARAMETER_SKIP_HANDLER == UINT32_C(1) &&
        ROME2_PORT_100EDD70_CONTINUATION_STEP_COUNT == UINT32_C(3) &&
        ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES == UINT32_C(24),
    "the caller policy or continuation cardinality changed");

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

typedef union test_dispatch_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_DISPATCH_BYTES];
} test_dispatch_memory;

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
    uint32_t ordinary_count;
    uint32_t caller_count;
    uint32_t temporary_allocate_calls;
    uint32_t persistent_allocate_calls;
    uint32_t temporary_release_calls;
    uint32_t persistent_release_calls;
    uint32_t temporary_hook_calls;
    uint32_t persistent_hook_calls;
    uint32_t expected_length;
    uint32_t expected_poll_count;
    rome2_invalid_parameter_policy expected_policy;
    uint32_t mutate_after_first;
    uint32_t mutation_performed;
    uint32_t require_result_sentinel;
    uint32_t expected_frame_base;
    test_allocation_plan temporary_plan;
    test_allocation_plan persistent_plan;
    rome2_guest_addr32 temporary_raw;
    rome2_guest_addr32 persistent_raw;
    rome2_100ed3c0_nonempty_lifecycle_effects *caller_effects;
    rome2_100edd70_caller_closure_effects *caller_continuation_effects;
    rome2_100f1bb0_owned_owner *temporary_owner;
    rome2_100f1bb0_owned_owner *persistent_owner;
    rome2_100f2750_first_use_lifecycle *lifecycle;
    rome2_100edd70_caller_closure_result *result;
    test_frame_memory *frame;
    rome2_100edd70_caller_closure_result initial_result;
} test_trace;

typedef struct test_fixture {
    test_frame_memory frame;
    test_text_memory text;
    test_selector_memory selector;
    test_heap_memory temporary_heap;
    test_persistent_descriptor_memory persistent_descriptor;
    test_heap_memory persistent_heap;
    test_dispatch_memory dispatch;
    rome2_guest_write_view frame_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view selector_view;
    rome2_guest_write_view temporary_heap_view;
    rome2_guest_write_view persistent_descriptor_view;
    rome2_guest_write_view persistent_heap_view;
    rome2_guest_read_view dispatch_view;
    rome2_100ed3c0_nonempty_lifecycle_effects effects;
    rome2_100edd70_caller_closure_effects continuation_effects;
    rome2_100f1bb0_owned_owner temporary_owner;
    rome2_100f1bb0_owned_owner persistent_owner;
    rome2_100f2750_first_use_lifecycle lifecycle;
    rome2_100edd70_caller_closure_result result;
    rome2_guest_addr32 text_identity;
    rome2_guest_addr32 dispatch_receiver;
    rome2_invalid_parameter_policy policy;
    uint32_t caller_position2;
    uint32_t caller_position4;
    uint32_t length_units;
    uint32_t max_poll_calls;
    test_trace trace;
} test_fixture;

typedef struct test_observable {
    test_frame_memory frame;
    test_text_memory text;
    test_selector_memory selector;
    test_heap_memory temporary_heap;
    test_persistent_descriptor_memory persistent_descriptor;
    test_heap_memory persistent_heap;
    test_dispatch_memory dispatch;
    rome2_100f1bb0_owned_owner temporary_owner;
    rome2_100f1bb0_owned_owner persistent_owner;
    rome2_100f2750_first_use_lifecycle lifecycle;
    rome2_100edd70_caller_closure_result result;
} test_observable;

static test_fixture test_fixture_storage;
static test_observable test_observable_storage;
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
    test_write_u32_le(bytes + 8U, ROME2_PORT_100F2750_FIRST_USE_SENTINEL);
}

static int test_is_triplet(const uint8_t *bytes)
{
    return
        test_read_u32_le(bytes) == UINT32_C(0) &&
        test_read_u32_le(bytes + 4U) == UINT32_C(0) &&
        test_read_u32_le(bytes + 8U) ==
            ROME2_PORT_100F2750_FIRST_USE_SENTINEL;
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) return 0;
    (void)fprintf(stderr,
        "100ed3c0 nonempty lifecycle runtime: %s: %s\n",
        case_name,
        detail);
    return 1;
}

static void test_begin_case(void)
{
    ++test_case_count;
}

static int test_result_is_sentinel(const test_trace *trace)
{
    return memcmp(
        trace->result,
        &trace->initial_result,
        sizeof(trace->initial_result)) == 0;
}

static void test_append_event(test_trace *trace, uint32_t event)
{
    if (trace->event_count >= TEST_MAX_EVENTS) {
        ++trace->bad_observations;
        return;
    }
    trace->events[trace->event_count++] = event;
    if (trace->require_result_sentinel != UINT32_C(0) &&
        !test_result_is_sentinel(trace)) {
        ++trace->bad_observations;
    }
}

static void test_evil_parent(
    void *context,
    rome2_100ed3c0_nonempty_step step)
{
    (void)step;
    ++((test_trace *)context)->bad_observations;
}

static void test_evil_prefix(void *context, rome2_100df270_prefix_step step)
{
    (void)step;
    ++((test_trace *)context)->bad_observations;
}

static void test_evil_suffix(void *context, rome2_100df270_suffix_step step)
{
    (void)step;
    ++((test_trace *)context)->bad_observations;
}

static void test_evil_ordinary(void *context, rome2_100ed471_step step)
{
    (void)step;
    ++((test_trace *)context)->bad_observations;
}

static void test_evil_caller(
    void *context,
    rome2_100edd70_caller_closure_step step)
{
    (void)step;
    ++((test_trace *)context)->bad_observations;
}

static rome2_100f1bb0_owned_grant_result test_evil_allocate(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class,
    rome2_100f1bb0_owned_grant *grant_out)
{
    (void)byte_count;
    (void)allocation_class;
    (void)grant_out;
    ++((test_trace *)context)->bad_observations;
    return ROME2_100F1BB0_OWNED_GRANT_DENIED;
}

static void test_evil_release(
    void *context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    (void)token;
    (void)raw_base;
    (void)byte_count;
    (void)allocation_class;
    ++((test_trace *)context)->bad_observations;
}

static void test_evil_hook(
    void *context,
    rome2_guest_addr32 raw_base,
    uint32_t zero_argument)
{
    (void)raw_base;
    (void)zero_argument;
    ++((test_trace *)context)->bad_observations;
}

static void test_mutate_caller_effects(test_trace *trace)
{
    rome2_100ed3c0_nonempty_lifecycle_effects *effects =
        trace->caller_effects;

    effects->preloop.emit_step = test_evil_parent;
    effects->preloop.child_prefix.emit_step = test_evil_prefix;
    effects->preloop.child_suffix.emit_step = test_evil_suffix;
    effects->preloop.child_suffix.result_100e8240.value = UINT32_C(0);
    effects->preloop.temporary_owned.allocate = test_evil_allocate;
    effects->preloop.temporary_owned.release = test_evil_release;
    effects->preloop.temporary_owned.release_hook = test_evil_hook;
    effects->preloop.persistent_owned = effects->preloop.temporary_owned;
    effects->ordinary.emit_step = test_evil_ordinary;
    effects->ordinary.timestamp_low = UINT32_C(0xdeadbeef);
    effects->ordinary.timestamp_high = UINT32_C(0xcafef00d);
    effects->ordinary.poll_result_count = UINT32_C(1);
    effects->ordinary.poll_results[0] = UINT32_C(1);
    trace->caller_continuation_effects->emit_step = test_evil_caller;
    trace->mutation_performed = UINT32_C(1);
}

static void test_parent_emit(
    void *context,
    rome2_100ed3c0_nonempty_step step)
{
    test_trace *trace = (test_trace *)context;

    test_append_event(trace, TEST_EVENT_PARENT_BASE + (uint32_t)step.kind);
    if ((uint32_t)step.kind != trace->parent_count + UINT32_C(1)) {
        ++trace->bad_observations;
    }
    ++trace->parent_count;
    if (trace->mutate_after_first != UINT32_C(0) &&
        trace->parent_count == UINT32_C(1)) {
        test_mutate_caller_effects(trace);
    }
}

static void test_prefix_emit(void *context, rome2_100df270_prefix_step step)
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
    test_trace *trace = (test_trace *)context;

    test_append_event(trace, TEST_EVENT_PREFIX_BASE + (uint32_t)step.kind);
    if (trace->prefix_count >= sizeof(expected) / sizeof(expected[0]) ||
        step.kind != expected[trace->prefix_count]) {
        ++trace->bad_observations;
    }
    ++trace->prefix_count;
}

static void test_suffix_emit(void *context, rome2_100df270_suffix_step step)
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
    test_trace *trace = (test_trace *)context;

    test_append_event(trace, TEST_EVENT_SUFFIX_BASE + (uint32_t)step.kind);
    if (trace->suffix_count >= sizeof(expected) / sizeof(expected[0]) ||
        step.kind != expected[trace->suffix_count]) {
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

static void test_ordinary_emit(void *context, rome2_100ed471_step step)
{
    test_trace *trace = (test_trace *)context;
    uint32_t expected_kind;

    if (trace->ordinary_count < UINT32_C(6)) {
        expected_kind = trace->ordinary_count + UINT32_C(1);
    } else if (trace->ordinary_count <
            UINT32_C(6) + trace->expected_poll_count) {
        expected_kind = (uint32_t)ROME2_100ED471_STEP_CALL_100EC5C0;
    } else if (trace->ordinary_count ==
            UINT32_C(6) + trace->expected_poll_count) {
        expected_kind = (uint32_t)ROME2_100ED471_STEP_CALL_100E0650;
    } else {
        expected_kind = (uint32_t)ROME2_100ED471_STEP_CALL_100F1CC0;
    }
    test_append_event(trace, TEST_EVENT_ORDINARY_BASE + (uint32_t)step.kind);
    if ((uint32_t)step.kind != expected_kind ||
        trace->temporary_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED ||
        trace->persistent_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
        trace->lifecycle->phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE) {
        ++trace->bad_observations;
    }
    if (step.kind == ROME2_100ED471_STEP_CALL_100EC5C0 ||
        step.kind == ROME2_100ED471_STEP_CALL_100E0650 ||
        step.kind == ROME2_100ED471_STEP_CALL_100F1CC0) {
        if (test_read_u32_le(
                trace->frame->bytes + ROME2_PORT_100ED471_TIMESTAMP_OFFSET) !=
                    TEST_TIMESTAMP_LOW ||
            test_read_u32_le(
                trace->frame->bytes +
                    ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET) !=
                    TEST_TIMESTAMP_LOW) {
            ++trace->bad_observations;
        }
    }
    ++trace->ordinary_count;
}

static void test_caller_emit(
    void *context,
    rome2_100edd70_caller_closure_step step)
{
    test_trace *trace = (test_trace *)context;
    uint32_t byte_pc;
    uint32_t dword_pc;
    uint32_t cleanup_pc;

    if (trace->expected_policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER) {
        byte_pc = ROME2_PORT_100EDD70_HANDLER_KEEPER_BYTE_CALL_PC;
        dword_pc = ROME2_PORT_100EDD70_HANDLER_KEEPER_DWORD_CALL_PC;
        cleanup_pc = ROME2_PORT_100EDD70_HANDLER_CLEANUP_PC;
    } else {
        byte_pc = ROME2_PORT_100EDD70_SKIP_KEEPER_BYTE_CALL_PC;
        dword_pc = ROME2_PORT_100EDD70_SKIP_KEEPER_DWORD_CALL_PC;
        cleanup_pc = ROME2_PORT_100EDD70_SKIP_CLEANUP_PC;
    }
    test_append_event(trace, TEST_EVENT_CALLER_BASE + (uint32_t)step.kind);
    if ((uint32_t)step.kind != trace->caller_count + UINT32_C(1) ||
        trace->parent_count != UINT32_C(9) ||
        trace->prefix_count != UINT32_C(7) ||
        trace->suffix_count != UINT32_C(11) ||
        trace->ordinary_count != UINT32_C(11) + trace->expected_poll_count ||
        trace->temporary_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED ||
        trace->persistent_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
        trace->lifecycle->phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE) {
        ++trace->bad_observations;
    }
    if (step.kind == ROME2_100EDD70_CALLER_STEP_KEEPER_BYTE_STORE) {
        if (step.instruction_original_pc != byte_pc ||
            step.target_original_pc !=
                ROME2_PORT_100EDD70_KEEPER_BYTE_TARGET ||
            step.destination_identity !=
                ROME2_PORT_100EDD70_KEEPER_BYTE_DESTINATION ||
            step.value != ROME2_PORT_100EDD70_KEEPER_BYTE_VALUE ||
            step.width_or_cleanup_bytes != UINT32_C(1)) {
            ++trace->bad_observations;
        }
    } else if (step.kind ==
            ROME2_100EDD70_CALLER_STEP_KEEPER_DWORD_STORE) {
        if (step.instruction_original_pc != dword_pc ||
            step.target_original_pc !=
                ROME2_PORT_100EDD70_KEEPER_DWORD_TARGET ||
            step.destination_identity !=
                ROME2_PORT_100EDD70_KEEPER_DWORD_DESTINATION ||
            step.value != ROME2_PORT_100EDD70_KEEPER_DWORD_VALUE ||
            step.width_or_cleanup_bytes != UINT32_C(4)) {
            ++trace->bad_observations;
        }
    } else if (step.kind == ROME2_100EDD70_CALLER_STEP_CLEANUP_24) {
        if (step.instruction_original_pc != cleanup_pc ||
            step.target_original_pc != UINT32_C(0) ||
            step.destination_identity != UINT32_C(0) ||
            step.value != ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES ||
            step.width_or_cleanup_bytes !=
                ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES) {
            ++trace->bad_observations;
        }
    } else {
        ++trace->bad_observations;
    }
    ++trace->caller_count;
}

static rome2_100f1bb0_owned_grant_result test_allocate_temporary(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class,
    rome2_100f1bb0_owned_grant *grant_out)
{
    test_trace *trace = (test_trace *)context;

    test_append_event(trace, TEST_EVENT_ALLOCATE_TEMPORARY);
    if (byte_count != trace->expected_length * UINT32_C(2) + UINT32_C(10) ||
        allocation_class != ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS ||
        trace->temporary_owner->phase != UINT32_C(0)) {
        ++trace->bad_observations;
    }
    ++trace->temporary_allocate_calls;
    *grant_out = trace->temporary_plan.grant;
    return trace->temporary_plan.result;
}

static rome2_100f1bb0_owned_grant_result test_allocate_persistent(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class,
    rome2_100f1bb0_owned_grant *grant_out)
{
    test_trace *trace = (test_trace *)context;

    test_append_event(trace, TEST_EVENT_ALLOCATE_PERSISTENT);
    if (byte_count != trace->expected_length * UINT32_C(2) + UINT32_C(10) ||
        allocation_class != ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS ||
        trace->temporary_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
        trace->persistent_owner->phase != UINT32_C(0)) {
        ++trace->bad_observations;
    }
    ++trace->persistent_allocate_calls;
    *grant_out = trace->persistent_plan.grant;
    return trace->persistent_plan.result;
}

static void test_release_temporary(
    void *context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    test_trace *trace = (test_trace *)context;

    (void)byte_count;
    (void)allocation_class;
    test_append_event(trace, TEST_EVENT_RELEASE_TEMPORARY);
    if (token != trace->temporary_plan.grant.token ||
        raw_base.value != trace->temporary_plan.grant.raw_base.value) {
        ++trace->bad_observations;
    }
    ++trace->temporary_release_calls;
}

static void test_release_persistent(
    void *context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    test_trace *trace = (test_trace *)context;

    (void)byte_count;
    (void)allocation_class;
    test_append_event(trace, TEST_EVENT_RELEASE_PERSISTENT);
    if (token != trace->persistent_plan.grant.token ||
        raw_base.value != trace->persistent_plan.grant.raw_base.value) {
        ++trace->bad_observations;
    }
    ++trace->persistent_release_calls;
}

static void test_hook_temporary(
    void *context,
    rome2_guest_addr32 raw_base,
    uint32_t zero_argument)
{
    test_trace *trace = (test_trace *)context;

    test_append_event(trace, TEST_EVENT_HOOK_TEMPORARY);
    if (raw_base.value != trace->temporary_plan.grant.raw_base.value ||
        zero_argument != UINT32_C(0)) {
        ++trace->bad_observations;
    }
    ++trace->temporary_hook_calls;
}

static void test_hook_persistent(
    void *context,
    rome2_guest_addr32 raw_base,
    uint32_t zero_argument)
{
    test_trace *trace = (test_trace *)context;

    test_append_event(trace, TEST_EVENT_HOOK_PERSISTENT);
    if (raw_base.value != trace->persistent_plan.grant.raw_base.value ||
        zero_argument != UINT32_C(0)) {
        ++trace->bad_observations;
    }
    ++trace->persistent_hook_calls;
}

static uint32_t test_raw_offset_for_residue(
    uint32_t guest_base,
    uint32_t base_offset,
    uint32_t residue)
{
    uint32_t raw = guest_base + base_offset;
    return base_offset + ((residue - (raw & UINT32_C(3))) & UINT32_C(3));
}

static void test_set_result_sentinel(
    rome2_100edd70_caller_closure_result *result)
{
    memset(result, TEST_RESULT_BYTE, sizeof(*result));
}

static void test_set_poll(test_fixture *fixture, uint32_t count)
{
    uint32_t index;

    fixture->effects.ordinary.poll_result_count = count;
    fixture->trace.expected_poll_count = count;
    fixture->max_poll_calls = count;
    for (index = UINT32_C(0); index < count; ++index) {
        fixture->effects.ordinary.poll_results[index] =
            index + UINT32_C(1) == count ? UINT32_C(2) : UINT32_C(0);
    }
}

static void test_set_local_dispatch(test_fixture *fixture)
{
    memset(fixture->dispatch.bytes, 0xcc, sizeof(fixture->dispatch.bytes));
    fixture->dispatch_receiver.value = TEST_DISPATCH_BASE;
    test_write_u32_le(
        fixture->dispatch.bytes,
        ROME2_PORT_100ED471_LOCAL_VTABLE);
    test_write_u32_le(
        fixture->dispatch.bytes +
            (ROME2_PORT_100ED471_LOCAL_VTABLE +
                ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET -
                TEST_DISPATCH_BASE),
        ROME2_PORT_100ED471_LOCAL_METHOD);
}

static void test_set_fallback_dispatch(test_fixture *fixture)
{
    memset(fixture->dispatch.bytes, 0xcc, sizeof(fixture->dispatch.bytes));
    fixture->dispatch_receiver.value =
        ROME2_PORT_100ED471_FALLBACK_OBJECT;
    test_write_u32_le(
        fixture->dispatch.bytes +
            (ROME2_PORT_100ED471_FALLBACK_OBJECT - TEST_DISPATCH_BASE),
        ROME2_PORT_100ED471_FALLBACK_VTABLE);
    test_write_u32_le(
        fixture->dispatch.bytes +
            (ROME2_PORT_100ED471_FALLBACK_VTABLE +
                ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET -
                TEST_DISPATCH_BASE),
        ROME2_PORT_100ED471_FALLBACK_METHOD);
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
    trace->ordinary_count = UINT32_C(0);
    trace->caller_count = UINT32_C(0);
    trace->temporary_allocate_calls = UINT32_C(0);
    trace->persistent_allocate_calls = UINT32_C(0);
    trace->temporary_release_calls = UINT32_C(0);
    trace->persistent_release_calls = UINT32_C(0);
    trace->temporary_hook_calls = UINT32_C(0);
    trace->persistent_hook_calls = UINT32_C(0);
    trace->mutation_performed = UINT32_C(0);
    trace->require_result_sentinel = UINT32_C(1);
    trace->initial_result = fixture->result;
}

static void test_init_fixture(
    test_fixture *fixture,
    uint32_t length_units,
    uint32_t poll_count,
    uint32_t temporary_residue,
    uint32_t persistent_residue,
    int fallback,
    int mutate)
{
    uint8_t *persistent_descriptor;
    uint32_t raw_offset;
    uint32_t index;
    rome2_100f1bb0_owned_status status;

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
    fixture->temporary_heap_view.byte_count = sizeof(fixture->temporary_heap.bytes);
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
    fixture->dispatch_view.host_base = fixture->dispatch.bytes;
    fixture->dispatch_view.guest_base = TEST_DISPATCH_BASE;
    fixture->dispatch_view.byte_count = sizeof(fixture->dispatch.bytes);

    fixture->length_units = length_units;
    fixture->text_identity.value = TEST_TEXT_BASE + TEST_TEXT_OFFSET;
    for (index = UINT32_C(0); index < length_units; ++index) {
        test_write_u16_le(
            fixture->text.bytes + TEST_TEXT_OFFSET + index * UINT32_C(2),
            (uint16_t)(UINT16_C(0x101) +
                (uint16_t)(index % UINT32_C(0x7e00))));
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

    if (fallback != 0) test_set_fallback_dispatch(fixture);
    else test_set_local_dispatch(fixture);

    fixture->effects.preloop.emit_step = test_parent_emit;
    fixture->effects.preloop.context = &fixture->trace;
    fixture->effects.preloop.context_byte_count = sizeof(fixture->trace);
    fixture->effects.preloop.child_prefix.emit_step = test_prefix_emit;
    fixture->effects.preloop.child_prefix.context = &fixture->trace;
    fixture->effects.preloop.child_prefix_context_byte_count =
        sizeof(fixture->trace);
    fixture->effects.preloop.child_prefix.created_mutex = TEST_CREATED_MUTEX;
    fixture->effects.preloop.child_prefix.last_error = UINT32_C(0);
    fixture->effects.preloop.child_suffix.emit_step = test_suffix_emit;
    fixture->effects.preloop.child_suffix.context = &fixture->trace;
    fixture->effects.preloop.child_suffix_context_byte_count =
        sizeof(fixture->trace);
    fixture->effects.preloop.child_suffix.result_100e8240.value =
        ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD;
    fixture->effects.preloop.child_suffix.first_selector_result.value =
        TEST_SELECTOR_BASE + TEST_FIRST_SELECTOR_OFFSET;
    fixture->effects.preloop.child_suffix.second_selector_result.value =
        TEST_SELECTOR_BASE + TEST_SECOND_SELECTOR_OFFSET;
    fixture->effects.preloop.temporary_owned.allocate = test_allocate_temporary;
    fixture->effects.preloop.temporary_owned.release = test_release_temporary;
    fixture->effects.preloop.temporary_owned.release_hook = test_hook_temporary;
    fixture->effects.preloop.temporary_owned.context = &fixture->trace;
    fixture->effects.preloop.temporary_owned.context_byte_count =
        sizeof(fixture->trace);
    fixture->effects.preloop.persistent_owned.allocate = test_allocate_persistent;
    fixture->effects.preloop.persistent_owned.release = test_release_persistent;
    fixture->effects.preloop.persistent_owned.release_hook = test_hook_persistent;
    fixture->effects.preloop.persistent_owned.context = &fixture->trace;
    fixture->effects.preloop.persistent_owned.context_byte_count =
        sizeof(fixture->trace);
    fixture->effects.ordinary.emit_step = test_ordinary_emit;
    fixture->effects.ordinary.context = &fixture->trace;
    fixture->effects.ordinary.timestamp_low = TEST_TIMESTAMP_LOW;
    fixture->effects.ordinary.timestamp_high = TEST_TIMESTAMP_HIGH;
    fixture->effects.ordinary_context_byte_count = sizeof(fixture->trace);
    fixture->continuation_effects.emit_step = test_caller_emit;
    fixture->continuation_effects.context = &fixture->trace;
    fixture->continuation_effects.context_byte_count = sizeof(fixture->trace);
    test_set_poll(fixture, poll_count);

    raw_offset = test_raw_offset_for_residue(
        TEST_TEMPORARY_HEAP_BASE,
        TEST_TEMPORARY_RAW_OFFSET,
        temporary_residue);
    fixture->trace.temporary_raw.value =
        TEST_TEMPORARY_HEAP_BASE + raw_offset;
    fixture->trace.temporary_plan.result =
        ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    fixture->trace.temporary_plan.grant.token = TEST_TEMPORARY_TOKEN;
    fixture->trace.temporary_plan.grant.raw_base = fixture->trace.temporary_raw;
    raw_offset = test_raw_offset_for_residue(
        TEST_PERSISTENT_HEAP_BASE,
        TEST_PERSISTENT_RAW_OFFSET,
        persistent_residue);
    fixture->trace.persistent_raw.value =
        TEST_PERSISTENT_HEAP_BASE + raw_offset;
    fixture->trace.persistent_plan.result =
        ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    fixture->trace.persistent_plan.grant.token = TEST_PERSISTENT_TOKEN;
    fixture->trace.persistent_plan.grant.raw_base = fixture->trace.persistent_raw;

    test_set_result_sentinel(&fixture->result);
    fixture->policy = ROME2_INVALID_PARAMETER_INSTALL_HANDLER;
    fixture->caller_position2 = TEST_ARGUMENT2;
    fixture->caller_position4 = TEST_ARGUMENT4;
    fixture->trace.expected_length = length_units;
    fixture->trace.expected_policy = fixture->policy;
    fixture->trace.expected_frame_base = fixture->frame_view.guest_base;
    fixture->trace.mutate_after_first = mutate != 0 ? UINT32_C(1) : UINT32_C(0);
    fixture->trace.caller_effects = &fixture->effects;
    fixture->trace.caller_continuation_effects =
        &fixture->continuation_effects;
    fixture->trace.temporary_owner = &fixture->temporary_owner;
    fixture->trace.persistent_owner = &fixture->persistent_owner;
    fixture->trace.lifecycle = &fixture->lifecycle;
    fixture->trace.result = &fixture->result;
    fixture->trace.frame = &fixture->frame;

    status = rome2_port_100f2750_register_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    if (status != ROME2_100F1BB0_OWNED_OK) {
        ++fixture->trace.bad_observations;
    }
    test_reset_trace(fixture);
}

static rome2_100f1bb0_owned_status test_call_with(
    test_fixture *fixture,
    const rome2_guest_read_view *dispatch_view,
    const rome2_100ed3c0_nonempty_lifecycle_effects *parent_effects,
    const rome2_100edd70_caller_closure_effects *continuation_effects,
    rome2_100edd70_caller_closure_result *result_out)
{
    return rome2_port_100edd70_run_caller_closure(
        fixture->policy,
        TEST_ARGUMENT1,
        fixture->caller_position2,
        fixture->text_identity,
        fixture->caller_position4,
        &fixture->frame_view,
        (rome2_guest_addr32){fixture->frame_view.guest_base},
        &fixture->text_view,
        fixture->length_units + UINT32_C(1),
        &fixture->selector_view,
        &fixture->temporary_heap_view,
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        dispatch_view,
        fixture->dispatch_receiver,
        fixture->max_poll_calls,
        parent_effects,
        continuation_effects,
        &fixture->temporary_owner,
        &fixture->persistent_owner,
        &fixture->lifecycle,
        result_out);
}

static rome2_100f1bb0_owned_status test_call(test_fixture *fixture)
{
    return test_call_with(
        fixture,
        &fixture->dispatch_view,
        &fixture->effects,
        &fixture->continuation_effects,
        &fixture->result);
}

static void test_build_success_events(
    uint32_t poll_count,
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
    for (index = UINT32_C(1); index <= UINT32_C(6); ++index) {
        events[count++] = TEST_EVENT_ORDINARY_BASE + index;
    }
    for (index = UINT32_C(0); index < poll_count; ++index) {
        events[count++] = TEST_EVENT_ORDINARY_BASE + UINT32_C(7);
    }
    events[count++] = TEST_EVENT_ORDINARY_BASE + UINT32_C(8);
    for (index = UINT32_C(0); index < UINT32_C(4); ++index) {
        events[count++] = TEST_EVENT_ORDINARY_BASE + UINT32_C(9);
    }
    for (index = UINT32_C(1); index <= UINT32_C(3); ++index) {
        events[count++] = TEST_EVENT_CALLER_BASE + index;
    }
    *count_out = count;
}

static int test_verify_success(
    const char *case_name,
    test_fixture *fixture,
    const rome2_100ed3c0_nonempty_lifecycle_effects *teardown_effects,
    int expect_mutation)
{
    static const uint32_t cleanup_offsets[] = {
        ROME2_PORT_100ED471_CLEANUP0_OFFSET,
        ROME2_PORT_100ED471_CLEANUP1_OFFSET,
        ROME2_PORT_100ED471_CLEANUP2_OFFSET,
        ROME2_PORT_100ED471_CLEANUP3_OFFSET
    };
    uint32_t expected[TEST_MAX_EVENTS] = {0};
    uint32_t expected_count = UINT32_C(0);
    uint8_t *persistent_descriptor = fixture->persistent_descriptor.bytes +
        (ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
            TEST_PERSISTENT_DESCRIPTOR_BASE);
    uint32_t index;
    uint32_t before_teardown;
    uint32_t window_start;
    uint32_t parent_call;
    uint32_t continuation;
    uint32_t hard_stop;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_build_success_events(fixture->trace.expected_poll_count,
        expected, &expected_count);
    if (fixture->policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER) {
        window_start = ROME2_PORT_100EDD70_HANDLER_WINDOW_START_PC;
        parent_call = ROME2_PORT_100EDD70_HANDLER_PARENT_CALL_PC;
        continuation = ROME2_PORT_100EDD70_HANDLER_CONTINUATION_PC;
        hard_stop = ROME2_PORT_100EDD70_HANDLER_HARD_STOP_PC;
    } else {
        window_start = ROME2_PORT_100EDD70_SKIP_WINDOW_START_PC;
        parent_call = ROME2_PORT_100EDD70_SKIP_PARENT_CALL_PC;
        continuation = ROME2_PORT_100EDD70_SKIP_CONTINUATION_PC;
        hard_stop = ROME2_PORT_100EDD70_SKIP_HARD_STOP_PC;
    }
    failed |= test_expect(
        fixture->trace.event_count == expected_count &&
            memcmp(fixture->trace.events, expected,
                expected_count * sizeof(expected[0])) == 0,
        case_name,
        "the combined total order changed");
    failed |= test_expect(
        expected_count == UINT32_C(45) + fixture->trace.expected_poll_count &&
            fixture->trace.parent_count == UINT32_C(9) &&
            fixture->trace.prefix_count == UINT32_C(7) &&
            fixture->trace.suffix_count == UINT32_C(11) &&
            fixture->trace.ordinary_count ==
                UINT32_C(11) + fixture->trace.expected_poll_count &&
            fixture->trace.caller_count == UINT32_C(3),
        case_name,
        "the child event cardinality changed");
    failed |= test_expect(
        fixture->trace.bad_observations == UINT32_C(0) &&
            fixture->trace.mutation_performed ==
                (expect_mutation != 0 ? UINT32_C(1) : UINT32_C(0)),
        case_name,
        "an observer saw an invalid phase, result, or snapshot");
    failed |= test_expect(
        fixture->temporary_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED &&
            fixture->persistent_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE,
        case_name,
        "the success ownership handoff changed");
    failed |= test_expect(
        fixture->result.parent.preloop.child_receiver.value ==
                fixture->frame_view.guest_base +
                    ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET &&
            fixture->result.parent.preloop.child_packet.value ==
                fixture->frame_view.guest_base +
                    ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET &&
            fixture->result.parent.preloop.child_argument.value ==
                fixture->frame_view.guest_base +
                    ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET &&
            fixture->result.parent.preloop.next_original_pc ==
                ROME2_PORT_100ED471_START_PC &&
            fixture->result.parent.ordinary.dispatch_receiver.value ==
                fixture->dispatch_receiver.value &&
            fixture->result.parent.ordinary.dispatch_vtable.value ==
                (fixture->dispatch_receiver.value ==
                        ROME2_PORT_100ED471_FALLBACK_OBJECT
                    ? ROME2_PORT_100ED471_FALLBACK_VTABLE
                    : ROME2_PORT_100ED471_LOCAL_VTABLE) &&
            fixture->result.parent.ordinary.dispatch_target.value ==
                (fixture->dispatch_receiver.value ==
                        ROME2_PORT_100ED471_FALLBACK_OBJECT
                    ? ROME2_PORT_100ED471_FALLBACK_METHOD
                    : ROME2_PORT_100ED471_LOCAL_METHOD) &&
            fixture->result.parent.ordinary.poll_calls ==
                fixture->trace.expected_poll_count &&
            fixture->result.parent.ordinary.terminal_poll_result == UINT32_C(2) &&
            fixture->result.parent.ordinary.timestamp_low == TEST_TIMESTAMP_LOW &&
            fixture->result.parent.ordinary.timestamp_high == TEST_TIMESTAMP_HIGH &&
            fixture->result.parent.ordinary.return_original_pc ==
                ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC,
        case_name,
        "the combined result changed");
    failed |= test_expect(
        fixture->result.policy == fixture->policy &&
            fixture->result.window_start_original_pc == window_start &&
            fixture->result.parent_call_original_pc == parent_call &&
            fixture->result.continuation_original_pc == continuation &&
            fixture->result.hard_stop_original_pc == hard_stop &&
            fixture->result.cleanup_bytes ==
                ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES &&
            fixture->result.pushes[0].instruction_original_pc == window_start &&
            fixture->result.pushes[0].machine_order == UINT32_C(1) &&
            fixture->result.pushes[0].callee_position == UINT32_C(4) &&
            fixture->result.pushes[0].value == fixture->caller_position4 &&
            fixture->result.pushes[1].instruction_original_pc ==
                window_start + UINT32_C(3) &&
            fixture->result.pushes[1].machine_order == UINT32_C(2) &&
            fixture->result.pushes[1].callee_position == UINT32_C(3) &&
            fixture->result.pushes[1].value == fixture->text_identity.value &&
            fixture->result.pushes[2].instruction_original_pc ==
                window_start + UINT32_C(4) &&
            fixture->result.pushes[2].machine_order == UINT32_C(3) &&
            fixture->result.pushes[2].callee_position == UINT32_C(2) &&
            fixture->result.pushes[2].value == fixture->caller_position2 &&
            fixture->result.pushes[3].instruction_original_pc ==
                window_start + UINT32_C(7) &&
            fixture->result.pushes[3].machine_order == UINT32_C(4) &&
            fixture->result.pushes[3].callee_position == UINT32_C(1) &&
            fixture->result.pushes[3].value == TEST_ARGUMENT1,
        case_name,
        "the caller packet or branch boundary changed");
    failed |= test_expect(
        test_read_u32_le(
            fixture->frame.bytes + ROME2_PORT_100ED471_TIMESTAMP_OFFSET) ==
                TEST_TIMESTAMP_LOW &&
            test_read_u32_le(
                fixture->frame.bytes +
                    ROME2_PORT_100ED471_TIMESTAMP_OFFSET + UINT32_C(4)) ==
                TEST_TIMESTAMP_HIGH &&
            test_read_u32_le(
                fixture->frame.bytes +
                    ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET) ==
                TEST_TIMESTAMP_LOW &&
            test_read_u32_le(
                fixture->frame.bytes +
                    ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET + UINT32_C(4)) ==
                TEST_TIMESTAMP_HIGH,
        case_name,
        "the descriptor-to-timestamp handoff changed");
    for (index = UINT32_C(0);
            index < sizeof(cleanup_offsets) / sizeof(cleanup_offsets[0]);
            ++index) {
        failed |= test_expect(
            test_is_triplet(fixture->frame.bytes + cleanup_offsets[index]),
            case_name,
            "a terminal sentinel descriptor changed");
    }
    failed |= test_expect(
        test_read_u32_le(persistent_descriptor) == fixture->length_units &&
            test_read_u32_le(persistent_descriptor + 4U) ==
                fixture->length_units &&
            test_read_u32_le(persistent_descriptor + 8U) ==
                fixture->persistent_owner.payload.value &&
            test_read_u32_le(
                fixture->selector.bytes + TEST_SECOND_SELECTOR_OFFSET) ==
                ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER,
        case_name,
        "the persistent descriptor or selector marker changed");

    fixture->trace.require_result_sentinel = UINT32_C(0);
    before_teardown = fixture->trace.event_count;
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &teardown_effects->preloop.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK &&
            fixture->persistent_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED &&
            fixture->trace.event_count == before_teardown + UINT32_C(2) &&
            fixture->trace.events[before_teardown] ==
                TEST_EVENT_RELEASE_PERSISTENT &&
            fixture->trace.events[before_teardown + UINT32_C(1)] ==
                TEST_EVENT_HOOK_PERSISTENT,
        case_name,
        "persistent teardown did not consume exactly once");
    before_teardown = fixture->trace.event_count;
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &teardown_effects->preloop.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_ALREADY_CONSUMED &&
            fixture->trace.event_count == before_teardown,
        case_name,
        "repeated persistent teardown emitted an effect");
    return failed;
}

static int test_run_success(
    const char *case_name,
    uint32_t length_units,
    uint32_t poll_count,
    uint32_t temporary_residue,
    uint32_t persistent_residue,
    int fallback,
    int mutate,
    uint32_t frame_base)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100ed3c0_nonempty_lifecycle_effects effects_snapshot;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, length_units, poll_count,
        temporary_residue, persistent_residue, fallback, mutate);
    fixture->frame_view.guest_base = frame_base;
    fixture->trace.expected_frame_base = frame_base;
    effects_snapshot = fixture->effects;
    status = test_call(fixture);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK,
        case_name, "the composed success call failed");
    if (status == ROME2_100F1BB0_OWNED_OK) {
        failed |= test_verify_success(
            case_name, fixture, &effects_snapshot, mutate);
    }
    return failed;
}

static int test_run_policy_success(
    const char *case_name,
    rome2_invalid_parameter_policy policy,
    uint32_t poll_count,
    uint32_t caller_position2,
    uint32_t caller_position4)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100ed3c0_nonempty_lifecycle_effects effects_snapshot;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_init_fixture(
        fixture, UINT32_C(3), poll_count, UINT32_C(1), UINT32_C(2), 0, 0);
    fixture->policy = policy;
    fixture->caller_position2 = caller_position2;
    fixture->caller_position4 = caller_position4;
    fixture->trace.expected_policy = policy;
    effects_snapshot = fixture->effects;
    status = test_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK,
        case_name,
        "the selected caller window failed");
    if (status == ROME2_100F1BB0_OWNED_OK) {
        failed |= test_verify_success(
            case_name, fixture, &effects_snapshot, 0);
    }
    return failed;
}

static void test_capture_observable(
    const test_fixture *fixture,
    test_observable *snapshot)
{
    snapshot->frame = fixture->frame;
    snapshot->text = fixture->text;
    snapshot->selector = fixture->selector;
    snapshot->temporary_heap = fixture->temporary_heap;
    snapshot->persistent_descriptor = fixture->persistent_descriptor;
    snapshot->persistent_heap = fixture->persistent_heap;
    snapshot->dispatch = fixture->dispatch;
    snapshot->temporary_owner = fixture->temporary_owner;
    snapshot->persistent_owner = fixture->persistent_owner;
    snapshot->lifecycle = fixture->lifecycle;
    snapshot->result = fixture->result;
}

static int test_observable_matches(
    const test_fixture *fixture,
    const test_observable *snapshot)
{
    return
        memcmp(&fixture->frame, &snapshot->frame, sizeof(snapshot->frame)) == 0 &&
        memcmp(&fixture->text, &snapshot->text, sizeof(snapshot->text)) == 0 &&
        memcmp(&fixture->selector, &snapshot->selector,
            sizeof(snapshot->selector)) == 0 &&
        memcmp(&fixture->temporary_heap, &snapshot->temporary_heap,
            sizeof(snapshot->temporary_heap)) == 0 &&
        memcmp(&fixture->persistent_descriptor, &snapshot->persistent_descriptor,
            sizeof(snapshot->persistent_descriptor)) == 0 &&
        memcmp(&fixture->persistent_heap, &snapshot->persistent_heap,
            sizeof(snapshot->persistent_heap)) == 0 &&
        memcmp(&fixture->dispatch, &snapshot->dispatch,
            sizeof(snapshot->dispatch)) == 0 &&
        memcmp(&fixture->temporary_owner, &snapshot->temporary_owner,
            sizeof(snapshot->temporary_owner)) == 0 &&
        memcmp(&fixture->persistent_owner, &snapshot->persistent_owner,
            sizeof(snapshot->persistent_owner)) == 0 &&
        memcmp(&fixture->lifecycle, &snapshot->lifecycle,
            sizeof(snapshot->lifecycle)) == 0 &&
        memcmp(&fixture->result, &snapshot->result,
            sizeof(snapshot->result)) == 0;
}

static int test_expect_tier0(
    const char *case_name,
    test_fixture *fixture,
    rome2_100f1bb0_owned_status status,
    rome2_100f1bb0_owned_status expected_status)
{
    int failed = 0;

    failed |= test_expect(status == expected_status,
        case_name, "the Tier-0 status changed");
    failed |= test_expect(
        fixture->trace.event_count == UINT32_C(0) &&
            fixture->trace.bad_observations == UINT32_C(0),
        case_name,
        "a Tier-0 denial emitted an external effect");
    failed |= test_expect(
        test_observable_matches(fixture, &test_observable_storage),
        case_name,
        "a Tier-0 denial changed observable storage");
    return failed;
}

static int test_tier0_cases(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    rome2_100edd70_caller_closure_result *aliased_result;
    int failed = 0;

#define TEST_TIER0_BEGIN(label) \
    do { \
        test_begin_case(); \
        test_init_fixture(fixture, UINT32_C(3), UINT32_C(3), \
            UINT32_C(0), UINT32_C(1), 0, 0); \
        (void)(label); \
    } while (0)
#define TEST_TIER0_CALL(label, expected) \
    do { \
        test_capture_observable(fixture, &test_observable_storage); \
        status = test_call(fixture); \
        failed |= test_expect_tier0(label, fixture, status, expected); \
    } while (0)

    TEST_TIER0_BEGIN("empty poll transcript");
    fixture->effects.ordinary.poll_result_count = UINT32_C(0);
    TEST_TIER0_CALL("empty poll transcript", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("result one transcript");
    fixture->effects.ordinary.poll_results[2] = UINT32_C(1);
    TEST_TIER0_CALL("result one transcript", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("trailing value after two");
    fixture->effects.ordinary.poll_results[0] = UINT32_C(2);
    TEST_TIER0_CALL("trailing value after two", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("poll count exceeds budget");
    fixture->max_poll_calls = UINT32_C(2);
    TEST_TIER0_CALL("poll count exceeds budget", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("zero poll budget");
    fixture->max_poll_calls = UINT32_C(0);
    TEST_TIER0_CALL("zero poll budget", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("poll budget above ceiling");
    fixture->max_poll_calls = UINT32_C(65);
    TEST_TIER0_CALL("poll budget above ceiling", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("mixed dispatch pair");
    test_write_u32_le(
        fixture->dispatch.bytes +
            (ROME2_PORT_100ED471_LOCAL_VTABLE +
                ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET - TEST_DISPATCH_BASE),
        ROME2_PORT_100ED471_FALLBACK_METHOD);
    TEST_TIER0_CALL("mixed dispatch pair", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("dispatch host overlaps persistent heap");
    fixture->dispatch_view.host_base = fixture->persistent_heap.bytes;
    TEST_TIER0_CALL("dispatch host overlaps persistent heap",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("dispatch guest overlaps temporary heap");
    fixture->dispatch_view.guest_base = fixture->temporary_heap_view.guest_base;
    TEST_TIER0_CALL("dispatch guest overlaps temporary heap",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("ordinary context partially overlaps recorder");
    fixture->effects.ordinary.context = (uint8_t *)&fixture->trace + 1U;
    fixture->effects.ordinary_context_byte_count = sizeof(fixture->trace) - 1U;
    TEST_TIER0_CALL("ordinary context partially overlaps recorder",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("ordinary context overlaps selector backing");
    fixture->effects.ordinary.context = fixture->selector.bytes;
    fixture->effects.ordinary_context_byte_count = sizeof(fixture->selector.bytes);
    TEST_TIER0_CALL("ordinary context overlaps selector backing",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("ordinary context overlaps effects control");
    fixture->effects.ordinary.context = &fixture->effects;
    fixture->effects.ordinary_context_byte_count = sizeof(fixture->effects);
    TEST_TIER0_CALL("ordinary context overlaps effects control",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("temporary owner not empty");
    fixture->temporary_owner.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE;
    TEST_TIER0_CALL("temporary owner not empty",
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    TEST_TIER0_BEGIN("persistent owner not empty");
    fixture->persistent_owner.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE;
    TEST_TIER0_CALL("persistent owner not empty",
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    TEST_TIER0_BEGIN("persistent lifecycle phase invalid");
    fixture->lifecycle.phase =
        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;
    TEST_TIER0_CALL("persistent lifecycle phase invalid",
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    TEST_TIER0_BEGIN("persistent descriptor dirty");
    fixture->persistent_descriptor.bytes[
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
            TEST_PERSISTENT_DESCRIPTOR_BASE] = UINT8_C(1);
    TEST_TIER0_CALL("persistent descriptor dirty",
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    TEST_TIER0_BEGIN("empty text rejected by nonempty route");
    fixture->text.bytes[TEST_TEXT_OFFSET] = UINT8_C(0);
    fixture->text.bytes[TEST_TEXT_OFFSET + 1U] = UINT8_C(0);
    TEST_TIER0_CALL("empty text rejected by nonempty route",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("wrong crash identity");
    fixture->effects.preloop.child_suffix.result_100e8240.value = UINT32_C(0);
    TEST_TIER0_CALL("wrong crash identity", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("combined result aliases descriptor backing");
    aliased_result = (rome2_100edd70_caller_closure_result *)
        fixture->persistent_descriptor.bytes;
    test_capture_observable(fixture, &test_observable_storage);
    status = test_call_with(
        fixture, &fixture->dispatch_view, &fixture->effects,
        &fixture->continuation_effects, aliased_result);
    failed |= test_expect_tier0(
        "combined result aliases descriptor backing",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("dispatch control aliases text control");
    test_capture_observable(fixture, &test_observable_storage);
    status = test_call_with(
        fixture, &fixture->text_view, &fixture->effects,
        &fixture->continuation_effects, &fixture->result);
    failed |= test_expect_tier0(
        "dispatch control aliases text control",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("combined effects aliases frame control");
    test_capture_observable(fixture, &test_observable_storage);
    status = test_call_with(
        fixture,
        &fixture->dispatch_view,
        (const rome2_100ed3c0_nonempty_lifecycle_effects *)&fixture->frame_view,
        &fixture->continuation_effects,
        &fixture->result);
    failed |= test_expect_tier0(
        "combined effects aliases frame control",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("lifecycle control aliases descriptor backing");
    test_capture_observable(fixture, &test_observable_storage);
    status = rome2_port_100edd70_run_caller_closure(
        fixture->policy,
        TEST_ARGUMENT1,
        fixture->caller_position2,
        fixture->text_identity,
        fixture->caller_position4,
        &fixture->frame_view,
        (rome2_guest_addr32){fixture->frame_view.guest_base},
        &fixture->text_view,
        fixture->length_units + UINT32_C(1),
        &fixture->selector_view,
        &fixture->temporary_heap_view,
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->dispatch_view,
        fixture->dispatch_receiver,
        fixture->max_poll_calls,
        &fixture->effects,
        &fixture->continuation_effects,
        &fixture->temporary_owner,
        &fixture->persistent_owner,
        (rome2_100f2750_first_use_lifecycle *)
            fixture->persistent_descriptor.bytes,
        &fixture->result);
    failed |= test_expect_tier0(
        "lifecycle control aliases descriptor backing",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_TIER0_BEGIN("frame endpoint overflow");
    fixture->frame_view.guest_base = TEST_FRAME_ENDPOINT_BASE + UINT32_C(1);
    TEST_TIER0_CALL("frame endpoint overflow",
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

#undef TEST_TIER0_CALL
#undef TEST_TIER0_BEGIN
    return failed;
}

static int test_caller_tier0_cases(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

#define TEST_CALLER_TIER0_BEGIN(label) \
    do { \
        test_begin_case(); \
        test_init_fixture(fixture, UINT32_C(3), UINT32_C(3), \
            UINT32_C(0), UINT32_C(1), 0, 0); \
        (void)(label); \
    } while (0)
#define TEST_CALLER_TIER0_CALL(label, expected) \
    do { \
        test_capture_observable(fixture, &test_observable_storage); \
        status = test_call(fixture); \
        failed |= test_expect_tier0(label, fixture, status, expected); \
    } while (0)

    TEST_CALLER_TIER0_BEGIN("invalid policy");
    fixture->policy = UINT32_C(2);
    TEST_CALLER_TIER0_CALL(
        "invalid policy", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("null continuation effects");
    test_capture_observable(fixture, &test_observable_storage);
    status = test_call_with(
        fixture,
        &fixture->dispatch_view,
        &fixture->effects,
        NULL,
        &fixture->result);
    failed |= test_expect_tier0(
        "null continuation effects",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("null continuation callback");
    fixture->continuation_effects.emit_step = NULL;
    TEST_CALLER_TIER0_CALL(
        "null continuation callback", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("null continuation context");
    fixture->continuation_effects.context = NULL;
    TEST_CALLER_TIER0_CALL(
        "null continuation context", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("zero continuation context span");
    fixture->continuation_effects.context_byte_count = UINT64_C(0);
    TEST_CALLER_TIER0_CALL(
        "zero continuation context span", ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("partial continuation context overlap");
    fixture->continuation_effects.context = (uint8_t *)&fixture->trace + 1U;
    fixture->continuation_effects.context_byte_count =
        sizeof(fixture->trace) - UINT64_C(1);
    TEST_CALLER_TIER0_CALL(
        "partial continuation context overlap",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("continuation context overlaps backing");
    fixture->continuation_effects.context = fixture->frame.bytes;
    fixture->continuation_effects.context_byte_count = sizeof(fixture->frame);
    TEST_CALLER_TIER0_CALL(
        "continuation context overlaps backing",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("continuation context overlaps parent effects");
    fixture->continuation_effects.context = &fixture->effects;
    fixture->continuation_effects.context_byte_count = sizeof(fixture->effects);
    TEST_CALLER_TIER0_CALL(
        "continuation context overlaps parent effects",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("continuation context overlaps result");
    fixture->continuation_effects.context = &fixture->result;
    fixture->continuation_effects.context_byte_count = sizeof(fixture->result);
    TEST_CALLER_TIER0_CALL(
        "continuation context overlaps result",
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("continuation context host overflow");
    fixture->continuation_effects.context =
        (void *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)1U);
    fixture->continuation_effects.context_byte_count = UINT64_C(4);
    TEST_CALLER_TIER0_CALL(
        "continuation context host overflow",
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    TEST_CALLER_TIER0_BEGIN("misaligned continuation effects");
    test_capture_observable(fixture, &test_observable_storage);
    status = test_call_with(
        fixture,
        &fixture->dispatch_view,
        &fixture->effects,
        (const rome2_100edd70_caller_closure_effects *)
            ((const uint8_t *)&fixture->continuation_effects + 1U),
        &fixture->result);
    failed |= test_expect_tier0(
        "misaligned continuation effects",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("continuation aliases parent effects");
    test_capture_observable(fixture, &test_observable_storage);
    status = test_call_with(
        fixture,
        &fixture->dispatch_view,
        &fixture->effects,
        (const rome2_100edd70_caller_closure_effects *)&fixture->effects,
        &fixture->result);
    failed |= test_expect_tier0(
        "continuation aliases parent effects",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("result aliases temporary owner");
    test_capture_observable(fixture, &test_observable_storage);
    status = test_call_with(
        fixture,
        &fixture->dispatch_view,
        &fixture->effects,
        &fixture->continuation_effects,
        (rome2_100edd70_caller_closure_result *)&fixture->temporary_owner);
    failed |= test_expect_tier0(
        "result aliases temporary owner",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_CALLER_TIER0_BEGIN("null result");
    test_capture_observable(fixture, &test_observable_storage);
    status = test_call_with(
        fixture,
        &fixture->dispatch_view,
        &fixture->effects,
        &fixture->continuation_effects,
        NULL);
    failed |= test_expect_tier0(
        "null result",
        fixture,
        status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

#undef TEST_CALLER_TIER0_CALL
#undef TEST_CALLER_TIER0_BEGIN
    return failed;
}

static int test_cleanup_escaped_temporary(
    const char *case_name,
    test_fixture *fixture)
{
    uint32_t before = fixture->trace.event_count;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    fixture->trace.require_result_sentinel = UINT32_C(1);
    status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &fixture->frame_view,
        (rome2_guest_addr32){
            fixture->frame_view.guest_base +
                ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET},
        &fixture->temporary_heap_view,
        &fixture->effects.preloop.temporary_owned,
        &fixture->temporary_owner);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK &&
            fixture->temporary_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED &&
            fixture->trace.event_count == before + UINT32_C(2) &&
            fixture->trace.events[before] == TEST_EVENT_RELEASE_TEMPORARY &&
            fixture->trace.events[before + UINT32_C(1)] ==
                TEST_EVENT_HOOK_TEMPORARY,
        case_name,
        "escaped temporary cleanup did not close authority");
    before = fixture->trace.event_count;
    status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &fixture->frame_view,
        (rome2_guest_addr32){
            fixture->frame_view.guest_base +
                ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET},
        &fixture->temporary_heap_view,
        &fixture->effects.preloop.temporary_owned,
        &fixture->temporary_owner);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_ALREADY_CONSUMED &&
            fixture->trace.event_count == before,
        case_name,
        "repeated temporary cleanup emitted an effect");
    return failed;
}

static int test_consume_registered_sentinel(
    const char *case_name,
    test_fixture *fixture)
{
    uint32_t before = fixture->trace.event_count;
    rome2_100f1bb0_owned_status status;

    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects.preloop.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    return test_expect(
        status == ROME2_100F1BB0_OWNED_OK &&
            fixture->persistent_owner.phase == UINT32_C(0) &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED &&
            fixture->trace.event_count == before,
        case_name,
        "registered sentinel teardown emitted an effect");
}

static int test_effect_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t before;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(3), 0U, 1U, 0, 0);
    fixture->trace.temporary_plan.result =
        ROME2_100F1BB0_OWNED_GRANT_DENIED;
    memset(&fixture->trace.temporary_plan.grant, 0,
        sizeof(fixture->trace.temporary_plan.grant));
    status = test_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_ALLOCATION_DENIED &&
            fixture->trace.event_count == UINT32_C(8) &&
            fixture->trace.ordinary_count == UINT32_C(0) &&
            fixture->temporary_owner.phase == UINT32_C(0) &&
            fixture->persistent_owner.phase == UINT32_C(0) &&
            test_result_is_sentinel(&fixture->trace),
        "temporary allocation denial",
        "the temporary denial prefix changed");
    failed |= test_consume_registered_sentinel(
        "temporary allocation denial", fixture);

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(3), 0U, 1U, 0, 0);
    fixture->trace.temporary_plan.result =
        ROME2_100F1BB0_OWNED_GRANT_DENIED;
    status = test_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID &&
            fixture->trace.event_count == UINT32_C(9) &&
            fixture->trace.temporary_release_calls == UINT32_C(1) &&
            fixture->trace.ordinary_count == UINT32_C(0) &&
            test_result_is_sentinel(&fixture->trace),
        "temporary denial with token",
        "temporary compensation changed");
    failed |= test_consume_registered_sentinel(
        "temporary denial with token", fixture);

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(3), 0U, 1U, 0, 0);
    fixture->trace.persistent_plan.result =
        ROME2_100F1BB0_OWNED_GRANT_DENIED;
    memset(&fixture->trace.persistent_plan.grant, 0,
        sizeof(fixture->trace.persistent_plan.grant));
    status = test_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_ALLOCATION_DENIED &&
            fixture->trace.event_count == UINT32_C(20) &&
            fixture->temporary_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
            fixture->persistent_owner.phase == UINT32_C(0) &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL &&
            fixture->trace.ordinary_count == UINT32_C(0) &&
            test_result_is_sentinel(&fixture->trace),
        "persistent allocation denial",
        "the persistent denial escape changed");
    failed |= test_cleanup_escaped_temporary(
        "persistent allocation denial", fixture);
    failed |= test_consume_registered_sentinel(
        "persistent allocation denial", fixture);

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(3), 0U, 1U, 0, 0);
    fixture->trace.persistent_plan.grant.reserved = UINT32_C(1);
    status = test_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID &&
            fixture->trace.event_count == UINT32_C(21) &&
            fixture->trace.persistent_release_calls == UINT32_C(1) &&
            fixture->temporary_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
            fixture->trace.ordinary_count == UINT32_C(0) &&
            test_result_is_sentinel(&fixture->trace),
        "persistent malformed grant",
        "persistent compensation changed");
    failed |= test_cleanup_escaped_temporary(
        "persistent malformed grant", fixture);
    failed |= test_consume_registered_sentinel(
        "persistent malformed grant", fixture);

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(3), 0U, 1U, 0, 0);
    fixture->trace.persistent_plan.grant.token = TEST_TEMPORARY_TOKEN;
    before = fixture->trace.persistent_release_calls;
    status = test_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID &&
            fixture->trace.event_count == UINT32_C(20) &&
            fixture->trace.persistent_release_calls == before &&
            fixture->temporary_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
            fixture->trace.ordinary_count == UINT32_C(0) &&
            test_result_is_sentinel(&fixture->trace),
        "persistent token collision",
        "the source-authority collision rule changed");
    failed |= test_cleanup_escaped_temporary(
        "persistent token collision", fixture);
    failed |= test_consume_registered_sentinel(
        "persistent token collision", fixture);
    return failed;
}

static int test_teardown_cases(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(1), 0U, 1U, 0, 0);
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects.preloop.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK &&
            fixture->persistent_owner.phase == UINT32_C(0) &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED &&
            fixture->trace.event_count == UINT32_C(0) &&
            test_result_is_sentinel(&fixture->trace),
        "registered sentinel teardown",
        "sentinel teardown changed storage or emitted an effect");

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(1), 0U, 1U, 0, 0);
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects.preloop.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK,
        "repeated sentinel teardown",
        "the first sentinel teardown failed");
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects.preloop.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_ALREADY_CONSUMED &&
            fixture->trace.event_count == UINT32_C(0) &&
            test_result_is_sentinel(&fixture->trace),
        "repeated sentinel teardown",
        "a repeated sentinel teardown did not fail closed");
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_run_success(
        "N1 immediate terminal", 1U, 1U, 0U, 0U, 0, 0, TEST_FRAME_BASE);
    failed |= test_run_success(
        "canonical N3 poll three", 3U, 3U, 0U, 1U, 0, 0, TEST_FRAME_BASE);
    failed |= test_run_success(
        "maximum poll transcript", 3U, 64U, 1U, 2U, 0, 0, TEST_FRAME_BASE);
    failed |= test_run_success(
        "fallback dispatch", 3U, 1U, 0U, 3U, 1, 0, TEST_FRAME_BASE);
    failed |= test_run_success(
        "combined effects snapshot", 3U, 3U, 2U, 1U, 0, 1, TEST_FRAME_BASE);
    failed |= test_run_success(
        "maximum text", 32767U, 1U, 3U, 0U, 0, 0, TEST_FRAME_BASE);
    failed |= test_run_success(
        "cross residue pair", 7U, 3U, 2U, 3U, 0, 0, TEST_FRAME_BASE);
    failed |= test_run_success(
        "exact frame endpoint", 3U, 1U, 1U, 2U, 0, 0,
        TEST_FRAME_ENDPOINT_BASE);
    failed |= test_run_policy_success(
        "handler caller packet",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER,
        UINT32_C(3),
        UINT32_C(0),
        UINT32_C(0xffffffff));
    failed |= test_run_policy_success(
        "skip-handler caller packet",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER,
        UINT32_C(1),
        UINT32_C(0x10203040),
        UINT32_C(0x50607080));
    failed |= test_tier0_cases();
    failed |= test_caller_tier0_cases();
    failed |= test_effect_failures();
    failed |= test_teardown_cases();
    failed |= test_expect(
        test_case_count == TEST_EXPECTED_CASES,
        "case registry",
        "the exact 54-case registry changed");

    if (failed != 0) {
        (void)fprintf(stderr,
            "100edd70 caller closure runtime: FAIL (%u/%u cases)\n",
            (unsigned)test_case_count,
            (unsigned)TEST_EXPECTED_CASES);
        return 1;
    }
    (void)printf(
        "100edd70 caller closure runtime: PASS (%u cases)\n",
        (unsigned)test_case_count);
    return 0;
}
